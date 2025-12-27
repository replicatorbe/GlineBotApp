#!/bin/bash

# Script de gestion du bot IRC GLINE
# Usage: ./start.sh {start|stop|restart|status}

BOT_NAME="gline_bot"
BOT_SCRIPT="gline_bot.py"
PID_FILE="/home/jerome/ircbotflutter/.gline_bot.pid"
LOG_FILE="/home/jerome/ircbotflutter/gline_bot.log"

# Couleurs pour l'affichage
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

cd /home/jerome/ircbotflutter

get_pid() {
    if [ -f "$PID_FILE" ]; then
        cat "$PID_FILE"
    else
        echo ""
    fi
}

is_running() {
    local pid=$(get_pid)
    if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
        return 0
    else
        return 1
    fi
}

start_bot() {
    if is_running; then
        echo -e "${YELLOW}Le bot est deja en cours d'execution (PID: $(get_pid))${NC}"
        exit 1
    fi

    echo -e "${GREEN}Demarrage du bot $BOT_NAME...${NC}"
    nohup python3 "$BOT_SCRIPT" >> "$LOG_FILE" 2>&1 &
    echo $! > "$PID_FILE"
    sleep 1

    if is_running; then
        echo -e "${GREEN}Bot demarre avec succes (PID: $(get_pid))${NC}"
    else
        echo -e "${RED}Echec du demarrage du bot${NC}"
        rm -f "$PID_FILE"
        exit 1
    fi
}

stop_bot() {
    if ! is_running; then
        echo -e "${YELLOW}Le bot n'est pas en cours d'execution${NC}"
        rm -f "$PID_FILE"
        exit 0
    fi

    local pid=$(get_pid)
    echo -e "${YELLOW}Arret du bot (PID: $pid)...${NC}"
    kill "$pid"

    # Attendre l'arret (max 10 secondes)
    for i in {1..10}; do
        if ! is_running; then
            echo -e "${GREEN}Bot arrete avec succes${NC}"
            rm -f "$PID_FILE"
            return 0
        fi
        sleep 1
    done

    # Force kill si necessaire
    echo -e "${RED}Le bot ne repond pas, arret force...${NC}"
    kill -9 "$pid" 2>/dev/null
    rm -f "$PID_FILE"
    echo -e "${GREEN}Bot arrete${NC}"
}

restart_bot() {
    echo -e "${YELLOW}Redemarrage du bot...${NC}"
    stop_bot
    sleep 2
    start_bot
}

status_bot() {
    if is_running; then
        echo -e "${GREEN}Le bot est en cours d'execution (PID: $(get_pid))${NC}"
    else
        echo -e "${RED}Le bot n'est pas en cours d'execution${NC}"
        rm -f "$PID_FILE" 2>/dev/null
    fi
}

case "$1" in
    start)
        start_bot
        ;;
    stop)
        stop_bot
        ;;
    restart)
        restart_bot
        ;;
    status)
        status_bot
        ;;
    *)
        echo "Usage: $0 {start|stop|restart|status}"
        echo ""
        echo "Commandes:"
        echo "  start   - Demarre le bot en arriere-plan"
        echo "  stop    - Arrete le bot"
        echo "  restart - Redémarre le bot"
        echo "  status  - Affiche l'etat du bot"
        exit 1
        ;;
esac

exit 0
