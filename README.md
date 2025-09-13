# GlineBot - Bot IRC pour gestion automatique des GLINE

Bot IRC pour UnrealIRCd qui surveille le canal `#services_infos` et applique automatiquement des GLINE sur les IP détectées contournant des bans existants.

## Installation

1. Clonez le repository
2. Installez les dépendances:
   ```bash
   pip install -r requirements.txt
   ```

3. Copiez le fichier de configuration d'exemple:
   ```bash
   cp config.json.example config.json
   ```

4. Modifiez `config.json` avec vos paramètres:
   - Serveur IRC (host, port, nickname)
   - Identifiants OPER (username, password)
   - Canal à surveiller
   - Configuration des GLINE (durée, raisons)

## Configuration

Le fichier `config.json` contient toute la configuration sensible:

```json
{
    "server": {
        "host": "irc.example.com",
        "port": 6667,
        "nickname": "GlineBot"
    },
    "oper": {
        "username": "your_oper_username",
        "password": "your_oper_password"
    },
    "channel": "#services_infos",
    "gline": {
        "duration": 7200,
        "ip_reason": "Auto Gline - BNC IP contournant ban existant",
        "hostname_reason": "Auto Gline - BNC hostname contournant ban existant",
        "nick_reason": "Auto Gline - Pseudo contournant ban via BNC"
    },
    "update_interval": 900
}
```

## Utilisation

```bash
python gline_bot.py
```

Le bot va:
1. Se connecter au serveur IRC
2. S'authentifier en tant qu'OPER
3. Rejoindre le canal configuré
4. Surveiller les messages pour détecter les contournements de ban
5. Appliquer automatiquement des GLINE sur les IP/hostnames/pseudos détectés

## Fonctionnalités

- Détection automatique des contournements de ban
- Application de GLINE sur IP, hostname et pseudo
- Mise à jour automatique de la liste des GLINE existantes
- Gestion robuste des erreurs d'encodage
- Logging détaillé des actions

## Sécurité

⚠️ **Important**: Le fichier `config.json` contient des informations sensibles (mots de passe OPER). Ce fichier est automatiquement exclu du versioning via `.gitignore`.

## Logs

Les logs sont sauvegardés dans `gline_bot.log` et affichés dans la console.