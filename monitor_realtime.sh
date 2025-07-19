#!/bin/bash

# Monitoramento em tempo real com inotify

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG="$DIR/alertas.log"
ENV_FILE="$DIR/.env"
[[ -f "$ENV_FILE" ]] && source "$ENV_FILE"

DIRS_TO_WATCH=("/tmp" "/dev/shm" "/var/tmp")

log_alert() {
    local msg="[REALTIME] $1"
    echo -e "$(date '+%Y-%m-%d %H:%M:%S') $msg" | tee -a "$LOG"
    [[ "$TELEGRAM_SEND" == "true" ]] && curl -s -X POST "https://api.telegram.org/bot$TELEGRAM_TOKEN/sendMessage" \
        -d chat_id="$TELEGRAM_CHAT_ID" -d text="$msg" > /dev/null
}

echo "[*] Iniciando monitoramento em tempo real..."
inotifywait -m -e create,modify,move "${DIRS_TO_WATCH[@]}" --format '%w%f' 2>/dev/null | while read file; do
    if [[ -x "$file" && -f "$file" ]]; then
        log_alert "Executável criado ou modificado: $file"
    fi
done
