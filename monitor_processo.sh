#!/bin/bash

# ========= CONFIG ========= #

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WHITELIST_FILE="$DIR/processo_whitelist.txt"
HASH_DB="$DIR/hash_db.txt"
LOG="$DIR/alertas.log"
ENV_FILE="$DIR/.env"
HIST_DIR="$DIR/historico"

[[ -f "$ENV_FILE" ]] && source "$ENV_FILE"
mkdir -p "$HIST_DIR"

CPU_THRESHOLD=20.0
MEM_THRESHOLD=30.0
TOP_N=100

SUSPECT_DIRS=("/tmp" "/dev/shm" "/var/tmp" "/home" "/mnt" "/media")
ALERTS_TMP=()
DRY_RUN=false

[[ "$1" == "--dry-run" ]] && DRY_RUN=true

# ========= ATUALIZA O WHATIS ========= #
if [[ "$EUID" -eq 0 ]] && command -v mandb &>/dev/null; then
    echo "[*] Atualizando banco de dados do man..."
    mandb -q
fi

# ========= FUNÇÕES AUXILIARES ========= #

log_alert_once() {
    local msg="[ALERTA] $1"
    if [[ ! " ${ALERTS_TMP[*]} " =~ "$msg" ]]; then
        ALERTS_TMP+=("$msg")
        echo -e "$(date '+%Y-%m-%d %H:%M:%S') $msg" | tee -a "$LOG"

        if [[ "$DRY_RUN" == false ]]; then
            [[ "$TELEGRAM_SEND" == "true" ]] && send_telegram "$msg"
            [[ "$EMAIL_SEND" == "true" ]] && send_email "$msg"
        fi
    fi
}

send_telegram() {
    [[ -z "$TELEGRAM_TOKEN" || -z "$TELEGRAM_CHAT_ID" ]] && return
    curl -s -X POST "https://api.telegram.org/bot$TELEGRAM_TOKEN/sendMessage" \
        -d chat_id="$TELEGRAM_CHAT_ID" -d text="$1" > /dev/null
}

send_email() {
    echo "$1" | mail -s "⚠️ Alerta de Processo Atípico" "$EMAIL_DEST"
}

is_in_whitelist() {
    grep -qx "$1" "$WHITELIST_FILE" 2>/dev/null
}

is_from_suspect_dir() {
    local cmd="$1"
    for dir in "${SUSPECT_DIRS[@]}"; do
        [[ "$cmd" == *"$dir"* ]] && return 0
    done
    return 1
}

check_hash_integrity() {
    local path="$1"
    [[ ! -x "$path" || ! -f "$path" ]] && return 0

    local current_hash
    current_hash=$(sha256sum "$path" | awk '{print $1}')
    local known_hash
    known_hash=$(grep -F "$path" "$HASH_DB" 2>/dev/null | awk '{print $1}')

    if [[ -z "$known_hash" ]]; then
        echo "$current_hash $path" >> "$HASH_DB"
    elif [[ "$current_hash" != "$known_hash" ]]; then
        log_alert_once "🧬 Alteração de binário detectada: $path"
    fi
}

verificar_ocultos() {
    echo "[*] Verificando processos ocultos..."
    if ! command -v unhide &> /dev/null; then
        log_alert_once "🛑 Ferramenta 'unhide' não instalada!"
        return
    fi
    alerta=$(sudo unhide quick 2>/dev/null | grep -i "Hidden")
    [[ -n "$alerta" ]] && log_alert_once "⚠️ Processos ocultos detectados:\n$alerta"
}

verificar_portas_abertas() {
    local conexoes=$(ss -tulpnH | grep -v '127.0.0.1' | grep -v '::1')
    [[ -n "$conexoes" ]] && log_alert_once "⚠️ Processos escutando em rede:\n$conexoes"
}

analisar_rede() {
    conexoes=$(ss -tupnH | awk '{print $5, $6}' | sort | uniq)
    [[ -n "$conexoes" ]] && log_alert_once "🔍 Conexões de rede ativas:\n$conexoes"
}

salvar_historico() {
    ps -eo pid,user,comm,pcpu,pmem,etime,cmd > "$HIST_DIR/processos_$(date +%F_%H-%M-%S).log"
}

mostrar_arvore_processo() {
    local pid="$1"
    if command -v pstree &> /dev/null; then
        arvore=$(pstree -p -s "$pid" 2>/dev/null)
    else
        arvore=$(ps -o pid,ppid,comm -e | awk -v pid="$pid" '$1==pid || $2==pid')
    fi
    [[ -n "$arvore" ]] && log_alert_once "🧩 Árvore do processo $pid:\n$arvore"
}

show_gui_alert() {
    [[ -x "$(command -v zenity)" ]] && zenity --warning --text="$1" --title="Alerta de Processo"
}

compactar_logs_antigos() {
    find "$HIST_DIR" -type f -name "*.log" -mtime +7 -exec gzip {} \;
}

# ========= BLOCO DA EXECUÇÃO ========= #

mapfile -t WHITELIST < "$WHITELIST_FILE"

ps -eo pid,user,comm,pcpu,pmem,etime,cmd --sort=-pcpu | head -n $TOP_N | tail -n +2 | while read -r pid user comm pcpu pmem etime cmd; do
    pcpu=${pcpu/,/.}
    pmem=${pmem/,/.}

    bin_path=$(which "$comm" 2>/dev/null)

    if ! is_in_whitelist "$comm"; then
        log_alert_once "🚫 Processo não reconhecido: $comm (PID: $pid, Usuário: $user)"
        show_gui_alert "Processo não reconhecido: $comm (PID: $pid)"
    fi

    if is_from_suspect_dir "$cmd"; then
        log_alert_once "⚠️ Processo executando de diretório suspeito: $cmd"
    fi

    if [[ "$comm" =~ ^\.+$ || "$comm" =~ ^[a-zA-Z]{1,2}$ || "$comm" =~ [^a-zA-Z0-9._/-] ]]; then
        log_alert_once "🚩 Nome de processo suspeito: $comm (PID: $pid)"
    fi

    if [[ "$cmd" == *"(deleted)"* ]]; then
        log_alert_once "🗑️ Processo executando binário deletado: $cmd (PID: $pid)"
    fi

    if (( $(echo "$pcpu > $CPU_THRESHOLD" | bc -l) )); then
        log_alert_once "🔥 Alto uso de CPU: $comm (PID: $pid, CPU: $pcpu%)"
    fi

    if (( $(echo "$pmem > $MEM_THRESHOLD" | bc -l) )); then
        log_alert_once "💾 Alto uso de memória: $comm (PID: $pid, MEM: $pmem%)"
    fi

    [[ -n "$bin_path" ]] && check_hash_integrity "$bin_path"

    if [[ -f "$bin_path" && ! -L "$bin_path" ]]; then
        if ! pacman -Qo "$bin_path" &>/dev/null; then
            log_alert_once "📦 Binário sem pacote conhecido: $bin_path (comando: $comm, PID: $pid)"
        fi
    fi

    ppid=$(ps -o ppid= -p "$pid")
    pai=$(ps -o comm= -p "$ppid" 2>/dev/null)
    if [[ "$pai" =~ ^(bash|sh|zsh|dash)$ && ! " ${WHITELIST[*]} " =~ " $comm " ]]; then
        log_alert_once "🕵️ Processo iniciado por shell suspeito: $comm (PID: $pid, PPID: $ppid)"
    fi

    mostrar_arvore_processo "$pid"
done

verificar_ocultos
verificar_portas_abertas
analisar_rede
salvar_historico
compactar_logs_antigos

echo "Análise completa."
