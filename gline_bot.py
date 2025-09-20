#!/usr/bin/env python3
"""
Bot IRC pour UnrealIRCd - Gestion automatique des GLINE
Auteur: Auto-généré
Description: Bot qui surveille #services_infos et applique automatiquement des GLINE sur les IP détectées
"""

import irc.bot
import irc.strings
import threading
import time
import re
import json
import logging
import os
import sys
from typing import Set, Dict, Any

# Configuration du logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('gline_bot.log'),
        logging.StreamHandler()
    ]
)

class GlineBot(irc.bot.SingleServerIRCBot):
    """Bot IRC pour la gestion automatique des GLINE"""
    
    def __init__(self, config: Dict[str, Any]):
        # Extraire les paramètres de configuration
        server = config['server']['host']
        port = config['server']['port']
        nickname = config['server']['nickname']
        
        super().__init__([(server, port)], nickname, nickname)
        
        # Configuration d'encodage robuste pour éviter les crashes UTF-8
        try:
            self.connection.buffer_class.errors = 'replace'
        except AttributeError:
            # Fallback si buffer_class n'est pas accessible
            logging.warning("Impossible de configurer l'encodage sur buffer_class")
        
        # Activer le debugging pour capturer les GLINE
        self.connection.add_global_handler("all_events", self.on_all_raw_messages)
        
        # Configuration du serveur
        self.server = server
        self.port = port
        self.nickname = nickname
        
        # Configuration OPER
        self.oper_user = config['oper']['username']
        self.oper_pass = config['oper']['password']
        
        # Configuration du channel
        self.channel = config['channel']
        
        # Configuration GLINE
        self.gline_config = config.get('gline', {})
        self.gline_duration = self.gline_config.get('duration', 7200)
        
        # Configuration de mise à jour
        self.update_interval = config.get('update_interval', 900)
        
        # Liste locale des IP déjà bannies (GLINE) - vidée au démarrage
        self.glined_ips: Set[str] = set()
        
        # Dictionnaire pour stocker les détails des GLINE (IP -> info GLINE) - vidé au démarrage
        self.gline_details: Dict[str, Dict[str, str]] = {}
        
        # Vider les listes au démarrage pour repartir à zéro
        logging.info("🔄 Démarrage du bot - Remise à zéro des listes de contournements")
        
        # Statut du bot
        self.is_oper = False
        self.is_connected = False
        self.stats_g_requested = False
        self.channel_join_attempted = False
        self.server_gline_check_pending = False
        self.verification_timeout = 30  # Timeout en secondes pour la vérification
        self.verification_start_time = None
        
        # Cooldown anti-spam pour les rebans
        self.reban_cooldown = 60  # Cooldown de 60 secondes
        self.recent_rebans: Dict[str, float] = {}  # IP/nick -> timestamp du dernier reban
        
        # Thread pour la mise à jour automatique des STATS g
        self.update_thread = None
        self.running = True
        
        logging.info(f"Bot initialisé: {nickname} -> {server}:{port}")
    
    def on_welcome(self, connection, event):
        """Appelé lors de la connexion réussie au serveur IRC"""
        logging.info("Connexion IRC établie")
        self.is_connected = True
        
        # Authentification OPER
        logging.info(f"Tentative d'authentification OPER: {self.oper_user}")
        connection.oper(self.oper_user, self.oper_pass)
    
    def on_youreoper(self, connection, event):
        """Appelé quand le bot devient OPER"""
        logging.info("Authentification OPER réussie")
        self.is_oper = True
        
        # Rejoindre le channel (gérer le mode invite-only)
        self.join_invite_channel(connection)
        
        # Lancer la récupération initiale des GLINE
        self.request_stats_g(connection)
        
        # Démarrer le thread de mise à jour automatique
        self.start_update_thread()
    
    def on_join(self, connection, event):
        """Appelé quand quelqu'un rejoint un channel"""
        if event.source.nick == self.nickname:
            logging.info(f"Bot a rejoint {event.target}")
            # Si c'est notre channel cible, remettre le mode +i
            if event.target == self.channel:
                logging.info(f"Remise du mode +i sur {self.channel}")
                connection.send_raw(f"SAMODE {self.channel} +i")
    
    def on_pubmsg(self, connection, event):
        """Appelé lors de la réception d'un message public"""
        try:
            if event.target == self.channel:
                message = event.arguments[0]
                self.process_channel_message(connection, message)
        except (UnicodeDecodeError, UnicodeError) as e:
            logging.warning(f"Erreur d'encodage dans on_pubmsg ignorée: {e}")
        except Exception as e:
            logging.error(f"Erreur inattendue dans on_pubmsg: {e}")
    
    def on_223(self, connection, event):
        """Appelé pour les réponses STATS g (code IRC 223)"""
        if self.stats_g_requested and len(event.arguments) >= 2:
            # Format: ['G', '*@IP/host', 'duration', 'timestamp', 'setter', 'reason']
            if event.arguments[0] == 'G':
                gline_info = " ".join(str(arg) for arg in event.arguments)
                logging.debug(f"GLINE reçue: {gline_info}")
                self.parse_gline_message(gline_info)

    def parse_gline_message(self, message: str):
        """Parse un message contenant des GLINE"""
        # Extraire les détails complets des GLINE avec raison
        # Format UnrealIRCd STATS g: G *@IP duration timestamp setter :reason
        gline_pattern = r'G \*@([\d\.\*]+)\s+(\d+)\s+(\d+)\s+(\S+)\s+:(.+)'
        gline_matches = re.finditer(gline_pattern, message)
        
        for match in gline_matches:
            target, duration, timestamp, setter, reason = match.groups()
            
            # Stocker les détails de la GLINE
            gline_info = {
                'target': target,
                'duration': duration,
                'timestamp': timestamp,
                'setter': setter,
                'reason': reason.strip()
            }
            
            if target not in self.glined_ips:
                self.glined_ips.add(target)
                self.gline_details[target] = gline_info
                logging.debug(f"📥 CHARGEMENT GLINE: {target} - Raison: {reason} - Par: {setter}")
        
        # Fallback: extraire les IP sans détails (ancien comportement)
        ip_matches = re.findall(r'\*@(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', message)
        for ip in ip_matches:
            if ip not in self.glined_ips:
                self.glined_ips.add(ip)
                # Créer une entrée basique si pas de détails
                if ip not in self.gline_details:
                    self.gline_details[ip] = {
                        'target': ip,
                        'reason': 'Non spécifiée',
                        'setter': 'Inconnu'
                    }
                logging.debug(f"📥 CHARGEMENT GLINE IP: {ip}")
        
        # Extraire les patterns /24 (xxx.xxx.xxx.*)
        wildcard_24_matches = re.findall(r'\*@(\d{1,3}\.\d{1,3}\.\d{1,3}\.)\*', message)
        for pattern in wildcard_24_matches:
            base_ip = pattern.rstrip('.')
            pattern_key = f"{base_ip}.*"
            if pattern_key not in self.glined_ips:
                # Pour les /24, générer toutes les IP (0-255)
                for i in range(256):
                    full_ip = f"{base_ip}.{i}"
                    self.glined_ips.add(full_ip)
                self.glined_ips.add(pattern_key)  # Stocker aussi le pattern
                logging.debug(f"📥 CHARGEMENT GLINE /24: {base_ip}.* → +256 IP")
        
        # Extraire les patterns /16 (xxx.xxx.*)  
        wildcard_16_matches = re.findall(r'\*@(\d{1,3}\.\d{1,3}\.)\*', message)
        for pattern in wildcard_16_matches:
            base_ip = pattern.rstrip('.')
            pattern_key = f"{base_ip}.*"
            if pattern_key not in self.glined_ips:
                self.glined_ips.add(pattern_key)
                logging.debug(f"📥 CHARGEMENT GLINE /16: {base_ip}.*")
        
        # Extraire autres patterns wildcard non-standard (ex: 188.188.15*, 88.172*)
        other_wildcards = re.findall(r'\*@(\d{1,3}\.\d{1,3}\.[\d*]+)\*', message)
        for pattern in other_wildcards:
            if not re.match(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', pattern):  # Éviter doublons IP complètes
                pattern_key = f"{pattern}*"
                if pattern_key not in self.glined_ips:
                    self.glined_ips.add(pattern_key)
                    logging.debug(f"📥 CHARGEMENT GLINE wildcard: {pattern}*")

    
    def on_endofstats(self, connection, event):
        """Appelé à la fin de la réponse STATS"""
        if self.stats_g_requested:
            self.stats_g_requested = False
            logging.info(f"Liste GLINE mise à jour: {len(self.glined_ips)} IP bannies")
        
        # Traiter aussi la vérification des GLINE pour les contournements
        if self.server_gline_check_pending and hasattr(self, 'pending_gline_verification'):
            self.process_gline_verification(connection)
    
    def process_gline_verification(self, connection):
        """Traite la vérification des GLINE avec gestion du timeout"""
        verification_data = self.pending_gline_verification
        banned_targets = verification_data['banned_targets']
        
        # Vérifier le timeout
        if self.verification_start_time and (time.time() - self.verification_start_time) > self.verification_timeout:
            logging.warning(f"⏰ Timeout de vérification GLINE ({self.verification_timeout}s) - Annulation")
            self.reset_verification_state()
            return
        
        # Vérifier si au moins une des cibles est toujours bannie sur le serveur
        still_banned = []
        for target in banned_targets:
            if self.is_target_banned(target):  # Vérifier dans notre liste mise à jour
                still_banned.append(target)
        
        if still_banned:
            logging.info(f"✅ GLINE confirmées actives sur serveur: {still_banned}")
            # Enregistrer le reban dans le cooldown
            self.record_reban(verification_data['ip'], verification_data['nick'])
            self.apply_gline(
                connection, 
                verification_data['ip'], 
                verification_data['hostname'], 
                verification_data['nick'],
                verification_data['original_glines']
            )
        else:
            logging.info("❌ Aucune GLINE active trouvée sur serveur - Contournement annulé")
            # Nettoyer notre liste locale des cibles qui ne sont plus bannies
            for target in banned_targets:
                if target in self.glined_ips:
                    self.glined_ips.remove(target)
                    if target in self.gline_details:
                        del self.gline_details[target]
                    logging.info(f"🧹 Nettoyage liste locale: {target} retiré")
        
        # Reset du flag de vérification
        self.reset_verification_state()
    
    def reset_verification_state(self):
        """Remet à zéro l'état de vérification"""
        self.server_gline_check_pending = False
        self.verification_start_time = None
        if hasattr(self, 'pending_gline_verification'):
            delattr(self, 'pending_gline_verification')
    
    def on_error(self, connection, event):
        """Appelé en cas d'erreur"""
        logging.error(f"Erreur IRC: {event.arguments}")
    
    def on_disconnect(self, connection, event):
        """Appelé lors de la déconnexion"""
        logging.warning("Déconnexion du serveur IRC")
        self.is_connected = False
        self.is_oper = False
        self.channel_join_attempted = False
    
    def on_privnotice(self, connection, event):
        """Appelé pour les notices privées du serveur"""
        message = " ".join(event.arguments)
        
        # Détecter les nouveaux GLINE (notices du serveur)
        if "*** GLINE" in message and "added" in message:
            # Format: "*** GLINE for *@IP added by oper (reason)"
            self.parse_gline_notice(message, added=True)
        
        # Détecter les UNGLINE (suppressions de ban)
        elif "*** GLINE" in message and ("removed" in message or "expired" in message):
            # Format: "*** GLINE for *@IP removed by oper" ou "expired"
            self.parse_gline_notice(message, added=False)
    
    def on_serverreply(self, connection, event):
        """Appelé pour toutes les réponses serveur - capture les GLINE/UNGLINE"""
        if len(event.arguments) > 0:
            message = " ".join(str(arg) for arg in event.arguments)
            
            # Formats possibles d'UnrealIRCd pour les GLINE
            if "G-Line added" in message or "G-Line removed" in message:
                logging.debug(f"GLINE notice détectée: {message}")
                if "G-Line added" in message:
                    self.parse_gline_notice(message, added=True)
                else:
                    self.parse_gline_notice(message, added=False)
    
    def on_all_raw_messages(self, connection, event):
        """Capture tous les messages pour debug GLINE"""
        try:
            if len(event.arguments) > 0:
                message = " ".join(str(arg) for arg in event.arguments)
                if "G-Line" in message or "tkl.TKL_ADD" in message or "tkl.TKL_DEL" in message:
                    logging.info(f"🔍 MESSAGE GLINE DÉTECTÉ: Type={event.type}, Args={event.arguments}")
                    if "G-Line added" in message or "tkl.TKL_ADD" in message:
                        self.parse_gline_notice(message, added=True)
                    elif "G-Line removed" in message or "tkl.TKL_DEL" in message:
                        self.parse_gline_notice(message, added=False)
        except (UnicodeDecodeError, UnicodeError) as e:
            logging.warning(f"Erreur d'encodage dans on_all_raw_messages ignorée: {e}")
        except Exception as e:
            logging.error(f"Erreur inattendue dans on_all_raw_messages: {e}")
    
    def parse_gline_notice(self, message: str, added: bool):
        """Parse les notices de GLINE/UNGLINE en temps réel"""
        try:
            logging.debug(f"Parsing GLINE notice: {message}")
            
            # Format UnrealIRCd: G-Line added: '*@target' [reason: ...] [by: ...] [duration: ...]
            gline_matches = re.findall(r"'([^']+)'", message)
            
            for match in gline_matches:
                if match.startswith('*@'):
                    target = match[2:]  # Enlever '*@'
                    
                    if added:  # Nouveau GLINE
                        # Traiter selon le type de target
                        if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', target):
                            # IP complète
                            if target not in self.glined_ips:
                                self.glined_ips.add(target)
                                # Extraire la raison si disponible
                                reason_match = re.search(r'reason: ([^\]]+)', message)
                                setter_match = re.search(r'by: ([^\]]+)', message)
                                reason = reason_match.group(1) if reason_match else 'Auto-ban'
                                setter = setter_match.group(1) if setter_match else 'Système'
                                
                                self.gline_details[target] = {
                                    'target': target,
                                    'reason': reason,
                                    'setter': setter
                                }
                                logging.info(f"⚡ AJOUT GLINE IP dans liste locale: {target} (Total: {len(self.glined_ips)})")
                        elif '*' in target:
                            # Pattern wildcard
                            if target not in self.glined_ips:
                                self.glined_ips.add(target)
                                # Extraire la raison si disponible
                                reason_match = re.search(r'reason: ([^\]]+)', message)
                                setter_match = re.search(r'by: ([^\]]+)', message)
                                reason = reason_match.group(1) if reason_match else 'Auto-ban pattern'
                                setter = setter_match.group(1) if setter_match else 'Système'
                                
                                self.gline_details[target] = {
                                    'target': target,
                                    'reason': reason,
                                    'setter': setter
                                }
                                count_before = len(self.glined_ips)
                                
                                # Si c'est un pattern /24 ou /16, générer les IP comme dans parse_gline_message
                                if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\*$', target):
                                    # Pattern /24: xxx.xxx.xxx.*
                                    base_ip = target[:-2]  # Enlever '.*'
                                    for i in range(256):
                                        full_ip = f"{base_ip}.{i}"
                                        self.glined_ips.add(full_ip)
                                    logging.info(f"⚡ AJOUT GLINE pattern /24: {target} → +256 IP (Total: {len(self.glined_ips)})")
                                elif re.match(r'^\d{1,3}\.\d{1,3}\.\*$', target):
                                    # Pattern /16: xxx.xxx.*
                                    logging.info(f"⚡ AJOUT GLINE pattern /16: {target} (Total: {len(self.glined_ips)})")
                                else:
                                    logging.info(f"⚡ AJOUT GLINE pattern wildcard: {target} (Total: {len(self.glined_ips)})")
                        else:
                            # Hostname ou autre
                            if target not in self.glined_ips:
                                self.glined_ips.add(target)
                                # Extraire la raison si disponible
                                reason_match = re.search(r'reason: ([^\]]+)', message)
                                setter_match = re.search(r'by: ([^\]]+)', message)
                                reason = reason_match.group(1) if reason_match else 'Auto-ban hostname'
                                setter = setter_match.group(1) if setter_match else 'Système'
                                
                                self.gline_details[target] = {
                                    'target': target,
                                    'reason': reason,
                                    'setter': setter
                                }
                                logging.info(f"⚡ AJOUT GLINE hostname: {target} (Total: {len(self.glined_ips)})")
                                
                    else:  # UNGLINE (suppression)
                        if target in self.glined_ips:
                            count_before = len(self.glined_ips)
                            self.glined_ips.remove(target)
                            # Supprimer aussi les détails
                            if target in self.gline_details:
                                del self.gline_details[target]
                            
                            # Si c'était un pattern /24, supprimer aussi toutes les IP générées
                            if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\*$', target):
                                base_ip = target[:-2]
                                removed_count = 0
                                for i in range(256):
                                    full_ip = f"{base_ip}.{i}"
                                    if full_ip in self.glined_ips:
                                        self.glined_ips.remove(full_ip)
                                        removed_count += 1
                                logging.info(f"🗑️ SUPPRESSION GLINE pattern /24: {target} → -{removed_count} IP (Total: {len(self.glined_ips)})")
                            else:
                                logging.info(f"🗑️ SUPPRESSION GLINE: {target} (Total: {len(self.glined_ips)})")
                        else:
                            logging.debug(f"🗑️ Tentative suppression GLINE non trouvée: {target}")
                        
        except Exception as e:
            logging.debug(f"Erreur parsing notice GLINE: {e}")
    
    def process_channel_message(self, connection, message: str):
        """Traite les messages du channel pour extraire les IP et détecter les messages DECONNEXION"""
        try:
            # Détecter les messages DECONNEXION
            if message.startswith("DECONNEXION "):
                self.handle_deconnexion_message(connection, message)
                return
            
            # Parser le message pour extraire IP, hostname et pseudo
            ip = self.extract_ip_from_message(message)
            hostname = self.extract_hostname_from_message(message)
            nick = self.extract_nick_from_message(message)
            
            target_info = []
            banned_targets = []
            
            # Vérifier l'IP
            if ip:
                target_info.append(f"IP: {ip}")
                if self.is_target_banned(ip):
                    banned_targets.append(ip)
            
            # Vérifier le hostname
            if hostname and hostname != ip:  # Éviter doublons si hostname = IP
                target_info.append(f"Hostname: {hostname}")
                if self.is_target_banned(hostname):
                    banned_targets.append(hostname)
            
            if target_info:
                logging.info(f"{', '.join(target_info)}, Pseudo: {nick}")
                
                # Si au moins une cible est bannie = contournement potentiel détecté
                if banned_targets:
                    banned_str = ', '.join(banned_targets)
                    logging.info(f"🚨 CONTOURNEMENT POTENTIEL DÉTECTÉ ! Cible(s) bannie(s): {banned_str}")
                    
                    # Vérifier le cooldown anti-spam
                    if self.is_reban_allowed(ip, nick):
                        # Vérifier d'abord que les GLINE sont toujours actives sur le serveur
                        self.verify_and_apply_gline(connection, ip, hostname, nick, banned_targets)
                    else:
                        logging.info(f"⏳ Cooldown actif - Reban ignoré pour IP:{ip} Nick:{nick}")
                else:
                    logging.debug(f"Cibles légitimes (non bannies), ignorées")
        except Exception as e:
            logging.error(f"Erreur lors du traitement du message: {e}")
    
    def handle_deconnexion_message(self, connection, message: str):
        """Traite les messages DECONNEXION et envoie la réponse OK"""
        try:
            # Extraire le deuxième paramètre du message DECONNEXION
            parts = message.split()
            if len(parts) >= 2:
                second_parameter = parts[1]
                response = f"OK {second_parameter}"
                
                logging.info(f"Message DECONNEXION détecté: {message}")
                logging.info(f"Envoi de la réponse: {response}")
                
                # Envoyer la réponse sur le channel #services_infos
                connection.privmsg(self.channel, response)
            else:
                logging.warning(f"Message DECONNEXION mal formaté (pas assez de paramètres): {message}")
        except Exception as e:
            logging.error(f"Erreur lors du traitement du message DECONNEXION: {e}")
    
    def extract_ip_from_message(self, message: str) -> str:
        """Extrait l'IP du champ publicIPAddressHardware du message"""
        try:
            # Nettoyer le message et essayer de le parser comme du JSON
            cleaned_message = message.strip()
            
            # Remplacer les éléments qui ne sont pas du JSON valide
            cleaned_message = re.sub(r'(\w+):', r'"\1":', cleaned_message)
            cleaned_message = re.sub(r': ([^",}\]]+)([,}])', r': "\1"\2', cleaned_message)
            
            # Si c'est toujours pas du JSON valide, utiliser une regex
            ip_match = re.search(r'publicIPAddressHardware["\s]*:\s*["\s]*(\d+\.\d+\.\d+\.\d+)', message)
            if ip_match:
                return ip_match.group(1)
            
            # Essayer de parser comme JSON
            try:
                data = json.loads(cleaned_message)
                if isinstance(data, dict) and 'publicIPAddressHardware' in data:
                    return data['publicIPAddressHardware']
            except json.JSONDecodeError:
                pass
            
        except Exception as e:
            logging.debug(f"Erreur extraction IP: {e}")
        
        return None
    
    def extract_hostname_from_message(self, message: str) -> str:
        """Extrait le hostname du champ publicHostnameHardware du message"""
        try:
            # Chercher le champ publicHostnameHardware
            hostname_match = re.search(r'publicHostnameHardware["\s]*:\s*["\s]*([^",}\]]+)', message)
            if hostname_match:
                hostname = hostname_match.group(1).strip('"')
                # Éviter de retourner une IP si c'est le même que publicIPAddressHardware
                if not re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', hostname):
                    return hostname
            
            # Essayer de parser comme JSON
            try:
                cleaned_message = message.strip()
                cleaned_message = re.sub(r'(\w+):', r'"\1":', cleaned_message)
                cleaned_message = re.sub(r': ([^",}\]]+)([,}])', r': "\1"\2', cleaned_message)
                
                data = json.loads(cleaned_message)
                if isinstance(data, dict) and 'publicHostnameHardware' in data:
                    hostname = data['publicHostnameHardware']
                    if not re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', hostname):
                        return hostname
            except json.JSONDecodeError:
                pass
            
        except Exception as e:
            logging.debug(f"Erreur extraction hostname: {e}")
        
        return None
    
    def extract_nick_from_message(self, message: str) -> str:
        """Extrait le pseudo du message JSON"""
        try:
            # Chercher le champ nickactuel ou pseudopardefaut
            nick_match = re.search(r'nickactuel["\s]*:\s*["\s]*([^",}\]]+)', message)
            if nick_match:
                return nick_match.group(1).strip('"')
            
            # Fallback sur pseudopardefaut
            pseudo_match = re.search(r'pseudopardefaut["\s]*:\s*["\s]*([^",}\]]+)', message)
            if pseudo_match:
                return pseudo_match.group(1).strip('"')
            
            # Essayer de parser comme JSON
            try:
                # Nettoyer le message et parser
                cleaned_message = message.strip()
                cleaned_message = re.sub(r'(\w+):', r'"\1":', cleaned_message)
                cleaned_message = re.sub(r': ([^",}\]]+)([,}])', r': "\1"\2', cleaned_message)
                
                data = json.loads(cleaned_message)
                if isinstance(data, dict):
                    return data.get('nickactuel') or data.get('pseudopardefaut')
            except json.JSONDecodeError:
                pass
            
        except Exception as e:
            logging.debug(f"Erreur extraction pseudo: {e}")
        
        return None
    
    def is_target_banned(self, target: str) -> bool:
        """Vérifie si une IP ou hostname est déjà bannie (exacte ou par pattern)"""
        # Vérification exacte
        if target in self.glined_ips:
            return True
        
        # Si c'est une IP, vérifier les patterns IP
        if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', target):
            ip_parts = target.split('.')
            # Vérifier pattern /24 (xxx.xxx.xxx.*)
            pattern_24 = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.*"
            if pattern_24 in self.glined_ips:
                return True
            
            # Vérifier pattern /16 (xxx.xxx.*)
            pattern_16 = f"{ip_parts[0]}.{ip_parts[1]}.*"
            if pattern_16 in self.glined_ips:
                return True
        
        # Vérifier patterns wildcard pour IP et hostnames
        for pattern in self.glined_ips:
            if '*' in pattern and pattern.endswith('*'):
                pattern_base = pattern[:-1]  # Enlever le *
                if target.startswith(pattern_base):
                    return True
            
            # Vérifier patterns hostname (ex: *.wanadoo.fr, *.example.com)
            if pattern.startswith('*.') and '.' in target:
                domain_pattern = pattern[2:]  # Enlever *. 
                if target.endswith(domain_pattern):
                    return True
        
        return False
    
    def is_reban_allowed(self, ip: str = None, nick: str = None) -> bool:
        """Vérifie si un reban est autorisé selon le cooldown"""
        current_time = time.time()
        
        # Nettoyer les anciens entries (plus vieux que le cooldown)
        expired_keys = [key for key, timestamp in self.recent_rebans.items() 
                       if current_time - timestamp > self.reban_cooldown]
        for key in expired_keys:
            del self.recent_rebans[key]
        
        # Vérifier le cooldown pour l'IP
        if ip and ip in self.recent_rebans:
            time_left = self.reban_cooldown - (current_time - self.recent_rebans[ip])
            if time_left > 0:
                logging.debug(f"⏳ Cooldown IP {ip}: {time_left:.1f}s restantes")
                return False
        
        # Vérifier le cooldown pour le nick
        if nick and nick in self.recent_rebans:
            time_left = self.reban_cooldown - (current_time - self.recent_rebans[nick])
            if time_left > 0:
                logging.debug(f"⏳ Cooldown Nick {nick}: {time_left:.1f}s restantes")
                return False
        
        return True
    
    def record_reban(self, ip: str = None, nick: str = None):
        """Enregistre un reban dans le système de cooldown"""
        current_time = time.time()
        if ip:
            self.recent_rebans[ip] = current_time
            logging.debug(f"📝 Cooldown enregistré pour IP: {ip}")
        if nick:
            self.recent_rebans[nick] = current_time
            logging.debug(f"📝 Cooldown enregistré pour Nick: {nick}")
    
    def verify_and_apply_gline(self, connection, ip: str = None, hostname: str = None, nick: str = None, banned_targets: list = None):
        """Vérifie sur le serveur que les GLINE sont toujours actives avant de rebannir"""
        if self.is_oper and not self.server_gline_check_pending:
            logging.info("🔍 Vérification serveur des GLINE avant reban...")
            self.server_gline_check_pending = True
            self.verification_start_time = time.time()
            
            # Stocker les données pour le callback
            self.pending_gline_verification = {
                'ip': ip,
                'hostname': hostname,
                'nick': nick,
                'banned_targets': banned_targets,
                'original_glines': []
            }
            
            # Collecter les détails des GLINE originales pour les cibles bannies
            for target in banned_targets:
                if target in self.gline_details:
                    self.pending_gline_verification['original_glines'].append(self.gline_details[target])
            
            # Demander STATS g pour vérification en temps réel
            connection.send_raw("STATS g")
        else:
            logging.warning("Impossible de vérifier les GLINE: pas de privilèges OPER ou vérification en cours")
    
    def is_ip_banned(self, ip: str) -> bool:
        """Alias pour compatibilité - utilise is_target_banned"""
        return self.is_target_banned(ip)
    
    def apply_gline(self, connection, ip: str = None, hostname: str = None, nick: str = None, original_glines: list = None):
        """Applique une GLINE sur l'IP et/ou hostname du BNC ET le pseudo (contournement détecté)"""
        if self.is_oper:
            # GLINE 1: Bannir l'IP du BNC (si disponible)
            if ip:
                ip_reason = self.gline_config.get('ip_reason', 'Auto Gline - BNC IP contournant ban existant')
                gline_ip_command = f"GLINE *@{ip} {self.gline_duration} :{ip_reason}"
                logging.info(f"🔨 GLINE IP BNC: {gline_ip_command}")
                connection.send_raw(gline_ip_command)
                self.glined_ips.add(ip)
            
            # GLINE 2: Bannir le hostname du BNC (si disponible et différent de l'IP)
            if hostname and hostname != ip:
                hostname_reason = self.gline_config.get('hostname_reason', 'Auto Gline - BNC hostname contournant ban existant')
                gline_hostname_command = f"GLINE *@{hostname} {self.gline_duration} :{hostname_reason}"
                logging.info(f"🔨 GLINE HOSTNAME BNC: {gline_hostname_command}")
                connection.send_raw(gline_hostname_command)
                self.glined_ips.add(hostname)
            
            # GLINE 3: Bannir le pseudo
            if nick:
                nick_reason = self.gline_config.get('nick_reason', 'Auto Gline - Pseudo contournant ban via BNC')
                gline_nick_command = f"GLINE {nick}@* {self.gline_duration} :{nick_reason}"
                logging.info(f"🔨 GLINE PSEUDO: {gline_nick_command}")
                connection.send_raw(gline_nick_command)
            else:
                logging.warning("⚠️ Pseudo non détecté")
            
            # Notifier sur #services_infos des actions prises
            self.notify_gline_actions(connection, ip, hostname, nick, original_glines)
            
            # La GLINE déconnecte automatiquement l'utilisateur, pas besoin de KILL
            
        else:
            logging.warning("Impossible d'appliquer GLINE: pas de privilèges OPER")
    
    def notify_gline_actions(self, connection, ip: str = None, hostname: str = None, nick: str = None, original_glines: list = None):
        """Envoie une notification sur #services_infos des actions de GLINE"""
        try:
            actions = []
            targets = []
            
            if ip:
                actions.append(f"IP {ip}")
                targets.append(ip)
            
            if hostname and hostname != ip:
                actions.append(f"hostname {hostname}")
                targets.append(hostname)
            
            if nick:
                actions.append(f"pseudo {nick}")
            
            if actions:
                targets_str = " + ".join(targets) if targets else "cible inconnue"
                actions_str = ", ".join(actions)
                
                duration_hours = self.gline_duration // 3600
                
                # Construire les détails des GLINE originales détectées
                original_info = ""
                if original_glines:
                    gline_details = []
                    for gline in original_glines:
                        detail = f"IP:{gline.get('target', 'Inconnue')} - Raison:\"{gline.get('reason', 'Non spécifiée')}\" - Par:{gline.get('setter', 'Inconnu')}"
                        gline_details.append(detail)
                    if gline_details:
                        original_info = f" | GLINE détectée: {' | '.join(gline_details)}"
                
                notification = f"🤖 GlineBot: Contournement détecté ! GLINE appliquée sur {actions_str} ({duration_hours}h) - Cible: {targets_str}{original_info}"
                
                logging.info(f"📢 Notification sur {self.channel}: {notification}")
                connection.privmsg(self.channel, notification)
                
        except Exception as e:
            logging.error(f"Erreur lors de l'envoi de notification: {e}")
    
    def request_stats_g(self, connection):
        """Demande la liste des GLINE actives"""
        if self.is_oper:
            logging.info("Demande STATS g pour mise à jour de la liste GLINE")
            self.stats_g_requested = True
            connection.send_raw("STATS g")
    
    def join_invite_channel(self, connection):
        """Gère l'entrée dans un salon invite-only"""
        if not self.channel_join_attempted:
            logging.info(f"Tentative de rejoindre le salon invite-only: {self.channel}")
            self.channel_join_attempted = True
            
            # Retirer temporairement le mode +i
            logging.info(f"Suppression temporaire du mode +i sur {self.channel}")
            connection.send_raw(f"SAMODE {self.channel} -i")
            
            # Attendre un peu puis rejoindre
            def delayed_join():
                time.sleep(2)
                logging.info(f"Rejoindre le channel: {self.channel}")
                connection.join(self.channel)
            
            # Lancer le join dans un thread séparé pour éviter de bloquer
            threading.Thread(target=delayed_join, daemon=True).start()
    
    def start_update_thread(self):
        """Démarre le thread de mise à jour automatique des STATS g"""
        if self.update_thread is None or not self.update_thread.is_alive():
            self.update_thread = threading.Thread(target=self.auto_update_stats, daemon=True)
            self.update_thread.start()
            logging.info("Thread de mise à jour automatique démarré")
    
    def auto_update_stats(self):
        """Thread qui met à jour les STATS g automatiquement"""
        while self.running and self.is_connected:
            time.sleep(self.update_interval)
            if self.is_connected and self.is_oper:
                try:
                    connection = self.connection
                    self.request_stats_g(connection)
                except Exception as e:
                    logging.error(f"Erreur lors de la mise à jour automatique: {e}")
    
    def stop(self):
        """Arrête le bot proprement"""
        logging.info("Arrêt du bot...")
        self.running = False
        if self.update_thread and self.update_thread.is_alive():
            self.update_thread.join(timeout=5)
        self.die("Bot arrêté")


def load_config(config_path: str = "config.json") -> Dict[str, Any]:
    """Charge la configuration depuis un fichier JSON"""
    if not os.path.exists(config_path):
        logging.error(f"Fichier de configuration non trouvé: {config_path}")
        logging.error("Copiez config.json.example vers config.json et modifiez les valeurs")
        sys.exit(1)
    
    try:
        with open(config_path, 'r', encoding='utf-8') as f:
            config = json.load(f)
        
        # Validation des champs obligatoires
        required_fields = [
            ['server', 'host'],
            ['server', 'port'], 
            ['server', 'nickname'],
            ['oper', 'username'],
            ['oper', 'password'],
            ['channel']
        ]
        
        for field_path in required_fields:
            current = config
            try:
                for field in field_path:
                    current = current[field]
            except (KeyError, TypeError):
                field_str = '.'.join(field_path)
                logging.error(f"Champ obligatoire manquant dans la configuration: {field_str}")
                sys.exit(1)
        
        logging.info(f"Configuration chargée depuis {config_path}")
        return config
        
    except json.JSONDecodeError as e:
        logging.error(f"Erreur de parsing JSON dans {config_path}: {e}")
        sys.exit(1)
    except Exception as e:
        logging.error(f"Erreur lors du chargement de la configuration: {e}")
        sys.exit(1)


def main():
    """Fonction principale"""
    logging.info("Démarrage du GlineBot...")
    
    # Charger la configuration
    config = load_config()
    
    try:
        # Créer et démarrer le bot
        bot = GlineBot(config)
        bot.start()
    except KeyboardInterrupt:
        logging.info("Interruption clavier détectée")
        bot.stop()
    except Exception as e:
        logging.error(f"Erreur fatale: {e}")
    
    logging.info("GlineBot terminé")


if __name__ == "__main__":
    main()