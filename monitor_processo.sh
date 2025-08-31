#!/usr/bin/env bash

# ==============================================================================
#           CONFIGURAÇÃO INICIAL E MODO ESTRITO
# ==============================================================================
# Garante que o script pare em erros (-e), trate variáveis não definidas como erro (-u),
set -euo pipefail

# Garante que esta rodando em Bash
if [[ -z "$BASH_VERSION" ]]; then
    echo "ERRO: Este script requer o shell BASH para ser executado." >&2
    exit 1
fi


# ==============================================================================
#           1. CONSTANTES IMUTÁVEIS
# ==============================================================================
readonly DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly ENV_FILE="$DIR/.env"


# ==============================================================================
#           2. CONFIGURAÇÕES PADRÃO (SOBRESCRITAS VIA .env)
# ==============================================================================
# --- Carrega as variáveis do .env se ele existir 
if [[ -f "$ENV_FILE" ]]; then
  set -a; source "$ENV_FILE"; set +a
fi
: "${DEBUG_NETWORK:=0}"
: "${AUTO_UPDATE_YARA_RULES:=true}"

# --- Nomes de Diretórios e Arquivos Globais ---
LOG_DIR_NAME=${LOG_DIR_NAME:-"logs"}
HIST_DIR_NAME=${HIST_DIR_NAME:-"historico"}
BASELINE_DIR_NAME=${BASELINE_DIR_NAME:-"baselines"}
QUARANTINE_DIR_NAME=${QUARANTINE_DIR_NAME:-"quarentena"}
PYTHON_SCRIPTS_DIR_NAME=${PYTHON_SCRIPTS_DIR_NAME:-"scripts"}
PYTHON_NETWORK_SUBDIR=${PYTHON_NETWORK_SUBDIR:-"network_checks"}

# Scripts de log em um subdiretório
PYTHON_LOGGING_SUBDIR=${PYTHON_LOGGING_SUBDIR:-"logs"}

LOG_FILENAME=${LOG_FILENAME:-"alertas.log"}
JSON_LOG_FILENAME=${JSON_LOG_FILENAME:-"alertas.jsonl"}
REVIEWED_ALERTS_FILENAME=${REVIEWED_ALERTS_FILENAME:-"alertas_revisados.sha256"}

# --- Nomes de Scripts Python e Configs ---
ALERT_MANAGER_SCRIPT_NAME=${ALERT_MANAGER_SCRIPT_NAME:-"alert_manager.py"}
ROOTKIT_CHECK_SCRIPT_NAME=${ROOTKIT_CHECK_SCRIPT_NAME:-"rootkit_check.py"}
BROWSER_EXT_CHECK_SCRIPT_NAME=${BROWSER_EXT_CHECK_SCRIPT_NAME:-"check_extensions.py"}
FIND_ARTIFACTS_SCRIPT_NAME=${FIND_ARTIFACTS_SCRIPT_NAME:-"find_artifacts.py"}
NET_DNSBL_SCRIPT_NAME=${NET_DNSBL_SCRIPT_NAME:-"dnsbl_check.py"}
NET_WHOIS_SCRIPT_NAME=${NET_WHOIS_SCRIPT_NAME:-"whois_to_json.py"}
NET_IPCHECKER_SCRIPT_NAME=${NET_IPCHECKER_SCRIPT_NAME:-"ip_checker.py"}
NET_POLICY_FILENAME=${NET_POLICY_FILENAME:-"policy.json"}
PYTHON_LOGGER_FILENAME=${PYTHON_LOGGER_FILENAME:-"log_to_json.py"}

# --- Configurações de Comportamento e Thresholds Globais ---
CPU_THRESHOLD=${CPU_THRESHOLD:-25.0}; MEM_THRESHOLD=${MEM_THRESHOLD:-40.0}
TOP_N=${TOP_N:-150}; RISK_THRESHOLD=${RISK_THRESHOLD:-5}
DRY_RUN=$( [[ "${DRY_RUN:-false}" == "true" ]] && echo "true" || echo "false" )
DEBUG_MODE=$( [[ "${DEBUG_MODE:-false}" == "true" ]] && echo "true" || echo "false" )
TELEGRAM_SEND=$( [[ "${TELEGRAM_SEND:-false}" == "true" ]] && echo "true" || echo "false" )
EMAIL_SEND=$( [[ "${EMAIL_SEND:-false}" == "true" ]] && echo "true" || echo "false" )

# --- Módulo: Monitoramento de Integridade de Arquivos (FIM) ---
HASH_DB_FILENAME=${HASH_DB_FILENAME:-"file_integrity.baseline"}

# --- Módulo: Análise de Processos ---
declare -a SUSPECT_DIRS=("/tmp" "/dev/shm" "/var/tmp" "/run/shm")
declare -a NORMALIZED_SUSPECT_DIRS=()
for dir in "${SUSPECT_DIRS[@]}"; do
    if [[ -d "$dir" ]]; then normalized_dir=$(realpath -s "$dir"); NORMALIZED_SUSPECT_DIRS+=("${normalized_dir%/}/"); fi
done
declare -a MASQUERADING_IGNORELIST=( "java" "python" "python3" "node" "perl" "ruby" "php" "bash" "sh" "zsh" "dash" )

# --- Módulo: Históricos e Comandos ---
PERSISTENCE_BASELINE_FILENAME=${PERSISTENCE_BASELINE_FILENAME:-"persistence.baseline"}
COMMANDS_BASELINE_FILENAME=${COMMANDS_BASELINE_FILENAME:-"suspicious_commands.baseline"}
declare -a SUSPICIOUS_COMMAND_PATTERNS=(
    'wget .* -O - .*\|.*sh' 'curl .* -sL .*\|.*sh' 'bash -i.*>/dev/tcp/' 'nc -l -p [0-9]+ -e'
    'nc -e /bin/(sh|bash)' 'ncat -e /bin/(sh|bash)' 'python[23]? .*socket\.socket' 'perl .*socket'
    'php .*fsockopen' 'eval.*base64_decode' 'echo .*\| *base64 -d *\| *(sh|bash)' 'history -c'
    'mimikatz' 'kerbrute' 'strace -p' 'gdb -p' 'rm -rf / '
)
declare -a HISTORY_FILES_TO_CHECK=(".bash_history" ".history" ".histfile" ".zshhistory")
COMMANDS_CHECK_SCRIPT_NAME=${COMMANDS_CHECK_SCRIPT_NAME:-"command_check.py"}

# --- Módulo: YARA ---
YARA_DIR_NAME=${YARA_DIR_NAME:-"yara-rules"}; YARA_RULES_REPO_DIR_NAME=${YARA_RULES_REPO_DIR_NAME:-"yara-rules-repo"}
YARA_RULES_FILENAME=${YARA_RULES_FILENAME:-"main.yar"}; YARA_RULES_INDEX_FILENAME=${YARA_RULES_INDEX_FILENAME:-"index.yar"}
YARA_SCAN_TIMEOUT=${YARA_SCAN_TIMEOUT:-"10s"}; declare -a YARA_SCAN_OPTS=("-w" "-s")
YARA_RULES_REPO_URL=${YARA_RULES_REPO_URL:-"https://github.com/Yara-Rules/rules.git"}

# Caminhos derivados (baseados na raiz $DIR do seu script)
#YARA_DIR=${YARA_DIR:-"$DIR/$YARA_DIR_NAME"}
#YARA_RULES_REPO_DIR=${YARA_RULES_REPO_DIR:-"$DIR/$YARA_RULES_REPO_DIR_NAME"}
#YARA_RULES_FILE=${YARA_RULES_FILE:-"$YARA_DIR/$YARA_RULES_FILENAME"}

# Build automático do YARA com módulos extras (pode ser desligado via .env)
YARA_AUTO_COMPILE=${YARA_AUTO_COMPILE:-true}
YARA_SOURCE_REPO_URL=${YARA_SOURCE_REPO_URL:-"https://github.com/VirusTotal/yara.git"}
YARA_BUILD_DIR=${YARA_BUILD_DIR:-"$DIR/.build/yara-src"}
YARA_CONFIGURE_FLAGS=${YARA_CONFIGURE_FLAGS:-"--enable-cuckoo --enable-dex --enable-magic --enable-dotnet"}

# --- Módulo: Análise de Rede ---
NET_BASELINE_FILENAME=${NET_BASELINE_FILENAME:-"network_connections.baseline"}
NET_SCAN_OUTBOUND=$( [[ "${NET_SCAN_OUTBOUND:-true}" == "true" ]] && echo "true" || echo "false" )
NET_USE_BASELINE=$( [[ "${NET_USE_BASELINE:-true}" == "true" ]] && echo "true" || echo "false" )
declare -a IP_ALLOWLIST=("127.0.0.1" "::1" "192.168.0.0/16" "10.0.0.0/8" "172.16.0.0/12")

# --- Módulo: Persistência ---
PERSISTENCE_CHECK_SCRIPT_NAME=${PERSISTENCE_CHECK_SCRIPT_NAME:-"persistence_check.py"}

# --- Módulo: Integridade do Sudo ---
SUDOERS_BASELINE_FILENAME=${SUDOERS_BASELINE_FILENAME:-"sudoers_integrity.baseline"}
declare -a SUDOERS_PATHS_TO_CHECK=("/etc/sudoers" "/etc/sudoers.d")

# --- Módulo: Análise de Logins ---
AUTH_LOG_BASELINE_FILENAME=${AUTH_LOG_BASELINE_FILENAME:-"auth_logs.baseline"}
AUTH_BRUTEFORCE_THRESHOLD=${AUTH_BRUTEFORCE_THRESHOLD:-10}
AUTH_SUDO_ROOT_FAILURE_THRESHOLD=${AUTH_SUDO_ROOT_FAILURE_THRESHOLD:-3}
AUTH_INVALID_USER_THRESHOLD=${AUTH_INVALID_USER_THRESHOLD:-10}
AUTH_LOG_LOOKBACK_PERIOD=${AUTH_LOG_LOOKBACK_PERIOD:-"24 hours ago"}
declare -a SERVICE_ACCOUNTS_TO_MONITOR=( "nobody" "www-data" "ftp" "sshd" "mysql" "postgres" "daemon" "nfsnobody" )

# --- Módulo: Web Shells ---
WEB_SHELL_BASELINE_FILENAME=${WEB_SHELL_BASELINE_FILENAME:-"webshells.baseline"}
declare -a WEB_SHELL_PATTERNS=(
  'eval\s*KATEX_INLINE_OPEN\s*base64_decode\s*KATEX_INLINE_OPEN'
  'passthru\s*KATEX_INLINE_OPEN[^)]*\$_POST'
  'shell_exec\s*KATEX_INLINE_OPEN[^)]*\$_GET'
  'system\s*KATEX_INLINE_OPEN[^)]*\$_REQUEST'
  'assert\s*KATEX_INLINE_OPEN[^)]*\$_(POST|GET|REQUEST)'
  'popen\s*KATEX_INLINE_OPEN[^)]*\$_(GET|POST|REQUEST)'
  'proc_open\s*KATEX_INLINE_OPEN[^)]*\$_(GET|POST|REQUEST)'
)
declare -a WEB_ROOT_DIRS=("/var/www" "/srv/http" "/usr/share/nginx/html")
declare -a WEB_SHELL_FILE_EXTENSIONS=("*.php" "*.phtml" "*.php3" "*.php4" "*.php5")

# --- Módulo: Segurança do Docker ---
DOCKER_SECURITY_BASELINE_FILENAME=${DOCKER_SECURITY_BASELINE_FILENAME:-"docker_security.baseline"}
DOCKER_SOCKET_PATH=${DOCKER_SOCKET_PATH:-"/var/run/docker.sock"}
declare -a DOCKER_ALLOWLIST_CONTAINERS=()

# --- Módulo: Rootkit ---
ROOTKIT_BASELINE_FILENAME=${ROOTKIT_BASELINE_FILENAME:-"rootkit_hidden.baseline"}
ROOTKIT_USE_BASELINE=$( [[ "${ROOTKIT_USE_BASELINE:-true}" == "true" ]] && echo "true" || echo "false" )
LKM_BASELINE_FILENAME=${LKM_BASELINE_FILENAME:-"kernel_modules.baseline"}
declare -a LKM_REMOVAL_IGNORELIST=( "usb_storage" "uas" "btusb" "bluetooth" "nfsd" "vboxdrv" )
SOCKET_ANOMALY_BASELINE_FILENAME=${SOCKET_ANOMALY_BASELINE_FILENAME:-"socket_anomalies.baseline"}

# --- Módulo: SUID/SGID ---
SUID_SGID_BASELINE_FILENAME=${SUID_SGID_BASELINE_FILENAME:-"suid_sgid_files.baseline"}
declare -a SUID_SGID_SEARCH_DIRS=("/usr" "/bin" "/sbin" "/lib" "/lib64")

# --- Módulo: Arquivos Imutáveis ---
IMMUTABLE_FILES_BASELINE_FILENAME=${IMMUTABLE_FILES_BASELINE_FILENAME:-"immutable_files.baseline"}
IMMUTABLE_ALLOWLIST_FILENAME=${IMMUTABLE_ALLOWLIST_FILENAME:-"immutable_files.allowlist"}
declare -a IMMUTABLE_CRITICAL_DIRS=("/etc" "/bin" "/sbin" "/usr/bin" "/usr/sbin" "/usr/lib" "/boot")
DEFENSE_EVASION_BASELINE_FILENAME=${DEFENSE_EVASION_BASELINE_FILENAME:-"defense_evasion.baseline"}
TIMESTOMP_BASELINE_FILENAME=${TIMESTOMP_BASELINE_FILENAME:-"timestomping.baseline"}
declare -a TIMESTOMP_IGNORE_DIRS=("/usr/bin" "/usr/sbin" "/bin" "/sbin" "/lib" "/usr/lib")

# --- Modulo: Wi-Fi ---
WIFI_SCAN_ENABLED=$( [[ "${WIFI_SCAN_ENABLED:-true}" == "true" ]] && echo "true" || echo "false" )
WIFI_DEVICES_BASELINE_FILENAME=${WIFI_DEVICES_BASELINE_FILENAME:-"wifi_devices.baseline"}
WIFI_CHECK_SCRIPT_NAME=${WIFI_CHECK_SCRIPT_NAME:-"wifi_check.py"}

# --- Módulo: Remediação ---

declare -gA REMEDIATION_MAP=(

    # --- Processos e Comandos ---
    ["Processo Suspeito"]="remediation_process"
    ["Histórico de Comandos"]="remediation_default" 

    # --- Rede ---
    ["Rede Exposta"]="remediation_exposed_network"
    ["Conexão Externa"]="remediation_netcat" 
    ["Ataque de Força Bruta"]="remediation_brute_force" 
    ["DNSBL"]="remediation_default"
    ["WHOIS"]="remediation_default"
    ["WHOIS Policy"]="remediation_default"

    # --- Integridade de Arquivos e Backdoors ---
    ["Integridade de Arquivo"]="remediation_file_integrity"
    ["Web Shell"]="remediation_web_shell"
    ["Web Shell (YARA)"]="remediation_web_shell"

    # --- Escalação de Privilégio ---
    ["Escalação de Privilégio (SUID/SGID)"]="remediation_privilege_escalation"
    ["Escalação de Privilégio (YARA)"]="remediation_privilege_escalation"
    ["Elevação de Privilégio"]="remediation_privilege_escalation" 
    ["Tentativa de Escalação"]="remediation_privilege_escalation" 

    # --- Rootkits e Evasão de Defesa ---
    ["Rootkit (LKM Adicionado)"]="remediation_lkm_rootkit"
    ["Impair Defenses (LKM Removido)"]="remediation_lkm_rootkit"
    ["Rootkit (Socket)"]="remediation_socket_rootkit"
    ["Evasão de Defesa (Imutabilidade)"]="remediation_file_integrity" 
    ["Evasão de Defesa (Timestomp)"]="remediation_file_integrity"   
    ["Evasão de Defesa"]="remediation_process" 

    # --- Navegadores ---
    ["Extensão (Chromium)"]="remediation_browser_extension"
    ["Extensão (Firefox)"]="remediation_browser_extension"
    ["Preferência (Chromium)"]="remediation_browser_extension"
    ["Preferência (Firefox)"]="remediation_browser_extension"
    ["JavaScript Suspeito"]="remediation_web_shell" 
    ["Native Messaging"]="remediation_browser_extension"
    ["Cookie"]="remediation_default"

    # --- Acesso e Reconhecimento ---
    ["Acesso Anômalo (Serviço)"]="remediation_default"
    ["Acesso Anômalo (Múltiplos IPs)"]="remediation_default"
    ["Reconhecimento"]="remediation_default" 
)

# ==============================================================================
#           3. CONSTRUÇÃO DE CAMINHOS DINÂMICOS (IMUTÁVEIS)
# ==============================================================================

# --- Diretórios Principais ---
readonly LOGS_DIR="$DIR/$LOG_DIR_NAME"
readonly HIST_DIR="$DIR/$HIST_DIR_NAME"
readonly BASELINE_DIR="$DIR/$BASELINE_DIR_NAME"
readonly QUARANTINE_DIR="$DIR/$QUARANTINE_DIR_NAME"
readonly PYTHON_SCRIPTS_DIR="$DIR/$PYTHON_SCRIPTS_DIR_NAME"
readonly YARA_DIR="${YARA_DIR:-"$DIR/$YARA_DIR_NAME"}"
readonly YARA_RULES_REPO_DIR="${YARA_RULES_REPO_DIR:-"$DIR/$YARA_RULES_REPO_DIR_NAME"}"
# --- Arquivos de Log Principais ---
readonly LOG_FILE="$LOGS_DIR/$LOG_FILENAME"
readonly JSON_LOG_FILE="$LOGS_DIR/$JSON_LOG_FILENAME"
readonly REVIEWED_ALERTS_FILE="$LOGS_DIR/$REVIEWED_ALERTS_FILENAME"

# --- Arquivos de Baseline (Agrupados por Módulo) ---
readonly HASH_DB_FILE="$BASELINE_DIR/$HASH_DB_FILENAME"
readonly SUDOERS_BASELINE_FILE="$BASELINE_DIR/$SUDOERS_BASELINE_FILENAME"
readonly LKM_BASELINE_FILE="$BASELINE_DIR/$LKM_BASELINE_FILENAME"
readonly SUID_SGID_BASELINE_FILE="$BASELINE_DIR/$SUID_SGID_BASELINE_FILENAME"
readonly NET_BASELINE_FILE="$BASELINE_DIR/$NET_BASELINE_FILENAME"
readonly ROOTKIT_BASELINE_FILE="$BASELINE_DIR/$ROOTKIT_BASELINE_FILENAME"
readonly PERSISTENCE_BASELINE_FILE="$BASELINE_DIR/$PERSISTENCE_BASELINE_FILENAME"
readonly WEB_SHELL_BASELINE_FILE="$BASELINE_DIR/$WEB_SHELL_BASELINE_FILENAME"
readonly DOCKER_SECURITY_BASELINE_FILE="$BASELINE_DIR/$DOCKER_SECURITY_BASELINE_FILENAME"
readonly COMMANDS_BASELINE_FILE="$BASELINE_DIR/$COMMANDS_BASELINE_FILENAME"
readonly IMMUTABLE_FILES_BASELINE_FILE="$BASELINE_DIR/$IMMUTABLE_FILES_BASELINE_FILENAME"
readonly SOCKET_ANOMALY_BASELINE_FILE="$BASELINE_DIR/$SOCKET_ANOMALY_BASELINE_FILENAME"
readonly AUTH_LOG_BASELINE_FILE="$BASELINE_DIR/$AUTH_LOG_BASELINE_FILENAME"
readonly DEFENSE_EVASION_BASELINE_FILE="$BASELINE_DIR/$DEFENSE_EVASION_BASELINE_FILENAME"
readonly TIMESTOMP_BASELINE_FILE="$BASELINE_DIR/$TIMESTOMP_BASELINE_FILENAME"
if [[ -n "${IMMUTABLE_ALLOWLIST_FILENAME:-}" ]]; then
    readonly IMMUTABLE_ALLOWLIST_FILE="$BASELINE_DIR/$IMMUTABLE_ALLOWLIST_FILENAME"
fi

# --- Arquivos de Regras ---
readonly YARA_RULES_FILE="${YARA_RULES_FILE:-"$YARA_DIR/$YARA_RULES_FILENAME"}"

# --- Caminhos para Scripts e Configurações Python ---

# Scripts que estão na RAIZ do diretório 'scripts/'
readonly ROOTKIT_CHECK_SCRIPT="$PYTHON_SCRIPTS_DIR/$ROOTKIT_CHECK_SCRIPT_NAME"
readonly BROWSER_EXT_CHECK_SCRIPT="$PYTHON_SCRIPTS_DIR/$BROWSER_EXT_CHECK_SCRIPT_NAME"
readonly FIND_ARTIFACTS_SCRIPT="$PYTHON_SCRIPTS_DIR/$FIND_ARTIFACTS_SCRIPT_NAME"
readonly COMMANDS_CHECK_SCRIPT="$PYTHON_SCRIPTS_DIR/$COMMANDS_CHECK_SCRIPT_NAME"
readonly PERSISTENCE_CHECK_SCRIPT="$PYTHON_SCRIPTS_DIR/$PERSISTENCE_CHECK_SCRIPT_NAME"

# Wi-Fi
readonly WIFI_DEVICES_BASELINE_FILE="$BASELINE_DIR/$WIFI_DEVICES_BASELINE_FILENAME"
readonly WIFI_CHECK_SCRIPT="$PYTHON_SCRIPTS_DIR/$PYTHON_NETWORK_SUBDIR/$WIFI_CHECK_SCRIPT_NAME"

# Scripts que estão no subdiretório 'network_checks/'
readonly PYTHON_NETWORK_DIR="$PYTHON_SCRIPTS_DIR/$PYTHON_NETWORK_SUBDIR"
readonly NET_DNSBL_SCRIPT="$PYTHON_NETWORK_DIR/$NET_DNSBL_SCRIPT_NAME"
readonly NET_WHOIS_SCRIPT="$PYTHON_NETWORK_DIR/$NET_WHOIS_SCRIPT_NAME"
readonly NET_IPCHECKER_SCRIPT="$PYTHON_NETWORK_DIR/$NET_IPCHECKER_SCRIPT_NAME"
readonly NET_POLICY_FILE="$PYTHON_NETWORK_DIR/$NET_POLICY_FILENAME"

# Scripts que estão no subdiretório 'logs/'
readonly PYTHON_LOGGING_DIR="$PYTHON_SCRIPTS_DIR/$PYTHON_LOGGING_SUBDIR"
readonly ALERT_MANAGER_SCRIPT="$PYTHON_LOGGING_DIR/$ALERT_MANAGER_SCRIPT_NAME"
readonly PYTHON_LOGGER_SCRIPT="$PYTHON_LOGGING_DIR/$PYTHON_LOGGER_FILENAME"

# ==============================================================================
#           4. VARIÁVEIS DE ESTADO GLOBAIS (MODIFICADAS EM RUNTIME)
# ==============================================================================

# --- Variáveis de Estado do Core ---
declare -i THREATS_FOUND=0
declare -A SEEN_ALERTS=()
declare -A ALERT_DETAILS_MAP=()

# --- Caches em Memória ---
declare -A HASH_BASELINE_DB=()     
declare HASH_DB_LOADED=false       
declare -i NEW_HASHES_ADDED=0      
declare -A _PACKAGE_INFO_CACHE=()
# --- Estado do Sistema Detectado ---
declare PKG_MANAGER=""             

# --- Flags de Dependências (Definidas Dinamicamente na Inicialização) ---

declare GIT_ENABLED=false
declare JQ_ENABLED=false
declare PYTHON3_ENABLED=false
declare YARA_ENABLED=false         
declare YARA_SCAN_ENABLED=false    
declare MAIL_ENABLED=false
declare LSOF_ENABLED=false
declare SS_ENABLED=false
declare JOURNALCTL_ENABLED=false
declare DOCKER_ENABLED=false

# ==============================================================================
#           CONFIGURAÇÃO DE CORES
# ==============================================================================

_supports_color() {
  [[ -t 1 ]] && [[ -z ${NO_COLOR:-} ]] && [[ ${TERM:-} != "dumb" ]]
}

if _supports_color; then
  readonly C_RESET=$'\e[0m'
  readonly C_RED=$'\e[0;31m'       C_GREEN=$'\e[0;32m'
  readonly C_YELLOW=$'\e[0;33m'    C_BLUE=$'\e[0;34m'
  readonly C_MAGENTA=$'\e[0;35m'   C_CYAN=$'\e[0;36m'
  readonly C_WHITE=$'\e[1;37m'     C_GRAY=$'\e[0;90m'
  readonly C_BOLD=$'\e[1m'
else
  readonly C_RESET='' C_RED='' C_GREEN='' C_YELLOW='' C_BLUE=''
  readonly C_MAGENTA='' C_CYAN='' C_WHITE='' C_GRAY='' C_BOLD=''
fi

# ==============================================================================
#           FUNÇÕES DE SETUP E VERIFICAÇÃO INICIAL
# ==============================================================================

check_permissions() {
    if [[ $EUID -ne 0 ]]; then
       echo -e "${C_RED}ERRO: Este script precisa ser executado como root (ou com sudo).${C_RESET}" >&2
       exit 1
    fi
}

check_dependencies() {
    local missing_deps=()
    local optional_deps=(git yara jq mail python3 unhide whois docker journalctl arp-scan nmcli)
    local optional_deps=(yara)
    for cmd in "${critical_deps[@]}"; do
        if ! command -v "$cmd" &>/dev/null; then
            missing_deps+=("$cmd")
        fi
    done
    if [[ ${#missing_deps[@]} -gt 0 ]]; then
        echo -e "${C_RED}ERRO: Dependências essenciais não encontradas: ${missing_deps[*]}.${C_RESET}" >&2
        echo "Por favor, instale-as com o gerenciador de pacotes do seu sistema e tente novamente." >&2
        exit 1
    fi

    if command -v yara &>/dev/null; then
        YARA_SCAN_ENABLED=true
    fi
}

# ==============================================================================
#           FUNÇÃO DE SETUP E VERIFICAÇÃO INICIAL
# ==============================================================================

setup_environment() {
    if ! mkdir -p -m 775 "$LOGS_DIR"; then
        echo "ERRO FATAL: Não foi possível criar o diretório de log em '$LOGS_DIR'." >&2
        exit 1
    fi
    
    if ! touch "$LOG_FILE"; then
        echo "ERRO FATAL: Não foi possível criar o arquivo de log em '$LOG_FILE'." >&2
        exit 1
    fi
    chmod 664 "$LOG_FILE"
    
    log_info "Verificando e criando a estrutura de diretórios em '$DIR'..."

    local -a other_dirs_to_create=(
        "$HIST_DIR" "$BASELINE_DIR" "$QUARANTINE_DIR" "$YARA_DIR"
        "$PYTHON_SCRIPTS_DIR" "$PYTHON_NETWORK_DIR"
    )
    for dir in "${other_dirs_to_create[@]}"; do
        if [[ "$dir" == "$HIST_DIR" ]]; then
            mkdir -p -m 775 "$dir" 
        else
            mkdir -p -m 750 "$dir"
        fi
        if (( $? != 0 )); then log_error "Falha ao criar o diretório '$dir'."; exit 1; fi
    done

    local -a other_files_to_touch=( "$JSON_LOG_FILE" "$REVIEWED_ALERTS_FILE" )
    for file in "${other_files_to_touch[@]}"; do
        if ! touch "$file"; then log_error "Falha ao criar o arquivo essencial '$file'."; exit 1; fi
        # Garante que o log JSON também seja legível pelo grupo.
        chmod 664 "$file"
    done
    
    log_info "Estrutura de diretórios e arquivos verificada com sucesso."
}


detect_package_manager() {
    if [[ -n "${PKG_MANAGER:-}" ]]; then
        if [[ "${PKG_MANAGER_LOGGED:-false}" != "true" ]]; then
            log_info "Gerenciador de pacotes detectado: $PKG_MANAGER"
            PKG_MANAGER_LOGGED=true
        fi
        return 0
    fi

    if command -v pacman &>/dev/null; then PKG_MANAGER="pacman"
    elif command -v apt-get &>/dev/null; then PKG_MANAGER="apt"
    elif command -v dnf &>/dev/null; then PKG_MANAGER="dnf"
    elif command -v yum &>/dev/null; then PKG_MANAGER="yum"
    elif command -v zypper &>/dev/null; then PKG_MANAGER="zypper"
    elif command -v apk &>/dev/null; then PKG_MANAGER="apk"
    else
        PKG_MANAGER="desconhecido"
        log_warn "Nenhum gerenciador de pacotes suportado detectado."
        return 1
    fi

    log_info "Gerenciador de pacotes detectado: $PKG_MANAGER"
    PKG_MANAGER_LOGGED=true
    return 0
}

load_hash_database() {
    if [[ "${HASH_DB_LOADED:-false}" == "true" ]]; then return 0; fi
    log_info "Carregando a baseline de hashes de arquivos para a memória..."

    if [[ ! -f "$HASH_DB_FILE" ]]; then
        log_warn "Arquivo de baseline '$HASH_DB_FILE' não encontrado. Um novo será criado."
        : > "$HASH_DB_FILE" || { log_error "Falha ao criar '$HASH_DB_FILE'."; exit 1; }
    fi
    (
        flock 200
        while IFS= read -r line; do
            [[ -z "$line" ]] && continue
            local path hash
            if [[ "$line" =~ ^([^[:space:]].*[[:graph:]])[[:space:]]+([0-9a-fA-F]{32,})$ ]]; then
                path="${BASH_REMATCH[1]}"; hash="${BASH_REMATCH[2]}"
            elif [[ "$line" =~ ^([0-9a-fA-F]{32,})[[:space:]]+([^[:space:]].*[[:graph:]])$ ]]; then
                hash="${BASH_REMATCH[1]}"; path="${BASH_REMATCH[2]}"
            else
                continue
            fi
            HASH_BASELINE_DB["$path"]="$hash"
        done < "$HASH_DB_FILE"
    ) 200>"$HASH_DB_FILE.lock"

    HASH_DB_LOADED=true
    log_info "Baseline de hashes carregada. Itens na memória: ${#HASH_BASELINE_DB[@]}"
}

check_dependencies() {
    log_info "Verificando dependências de software..."
    local -a critical_deps=(awk bc flock grep lsof ps realpath sha256sum sort ss stat)
    local -a missing_critical=()
    local cmd
    for cmd in "${critical_deps[@]}"; do
        if ! command -v "$cmd" >/dev/null 2>&1; then
            missing_critical+=("$cmd")
        fi
    done
    if ((${#missing_critical[@]})); then
        log_error "Dependências essenciais não encontradas: ${missing_critical[*]}. Abortando."
        log_error "Instale-as com o gerenciador de pacotes do seu sistema."
        exit 1
    fi
    local -a optional_deps=(git yara yarac jq python3 unhide whois docker journalctl arp-scan nmcli curl)
    for cmd in "${optional_deps[@]}"; do
        local flag_name
        flag_name="$(echo "$cmd" | tr '[:lower:]-' '[:upper:]_')_ENABLED"
        if command -v "$cmd" >/dev/null 2>&1; then
            declare -g "$flag_name=true"
        else
            declare -g "$flag_name=false"
            log_warn "Dependência opcional não encontrada: '$cmd'. Funcionalidades relacionadas serão desabilitadas."
        fi
    done

    if [[ "${YARA_ENABLED:-false}" == "true" ]]; then
        if [[ -s "$YARA_RULES_FILE" ]]; then
            YARA_SCAN_ENABLED=true
            log_info "YARA instalado e regras presentes. Análise habilitada."
        else
            log_warn "YARA instalado, mas '$YARA_RULES_FILE' não foi encontrado."
            if [[ "${AUTO_UPDATE_YARA_RULES:-true}" == "true" ]]; then
                if declare -F ensure_yara_ready >/dev/null; then
                    ensure_yara_ready  
                else
                    log_warn "Função 'ensure_yara_ready' não disponível; execute '--update-yara-rules' para baixar as regras."
                    YARA_SCAN_ENABLED=false
                fi
            else
                YARA_SCAN_ENABLED=false
                log_warn "AUTO_UPDATE_YARA_RULES=false; execute '--update-yara-rules' para baixar as regras."
            fi
        fi
    else
        YARA_SCAN_ENABLED=false
    fi

}
_detect_pkg_manager() {
    if command -v apt-get >/dev/null 2>&1; then PKG_MANAGER="apt"; return 0; fi
    if command -v dnf >/dev/null 2>&1;      then PKG_MANAGER="dnf"; return 0; fi
    if command -v yum >/dev/null 2>&1;      then PKG_MANAGER="yum"; return 0; fi
    if command -v pacman >/dev/null 2>&1;   then PKG_MANAGER="pacman"; return 0; fi
    if command -v zypper >/dev/null 2>&1;   then PKG_MANAGER="zypper"; return 0; fi
    if command -v apk >/dev/null 2>&1;      then PKG_MANAGER="apk"; return 0; fi
    PKG_MANAGER=""; return 1
}

_pkg_install() {
    local -a pkgs=( "$@" )
    local sudo_cmd=""
    (( EUID != 0 )) && sudo_cmd="sudo -n"

    case "$PKG_MANAGER" in
        apt)
            $sudo_cmd apt-get update -y >/dev/null 2>&1 || true
            $sudo_cmd apt-get install -y "${pkgs[@]}" ;;
        dnf)    $sudo_cmd dnf install -y "${pkgs[@]}" ;;
        yum)    $sudo_cmd yum install -y "${pkgs[@]}" ;;
        pacman) $sudo_cmd pacman -S --noconfirm --needed "${pkgs[@]}" ;;
        zypper) $sudo_cmd zypper --non-interactive in "${pkgs[@]}" ;;
        apk)    $sudo_cmd apk add --no-cache "${pkgs[@]}" ;;
        *)      return 1 ;;
    esac
}

_ensure_git() {
    if command -v git >/dev/null 2>&1; then GIT_ENABLED=true; return 0; fi
    log_warn "git não encontrado. Tentando instalar..."
    detect_package_manager || { log_error "Sem gerenciador de pacotes."; return 1; }
    local sudo_cmd=""; (( EUID != 0 )) && sudo_cmd="sudo -n"
    case "$PKG_MANAGER" in
        apt)    $sudo_cmd apt-get update -y >/dev/null 2>&1 || true; $sudo_cmd apt-get install -y git ;;
        dnf)    $sudo_cmd dnf install -y git ;;
        yum)    $sudo_cmd yum install -y git ;;
        pacman) $sudo_cmd pacman -S --noconfirm --needed git ;;
        zypper) $sudo_cmd zypper --non-interactive in git ;;
        apk)    $sudo_cmd apk add --no-cache git ;;
        *)      return 1 ;;
    esac
    command -v git >/dev/null 2>&1 && { GIT_ENABLED=true; return 0; }
    log_error "Falha ao instalar git."; return 1
}

# ==============================================================================
#           CONFIGURAÇÃO YARA
# ==============================================================================
_yara_missing_modules() {
    local tmp tmpo m
    local -a missing=()
    tmp=$(mktemp) || return 1
    tmpo=$(mktemp) || { rm -f -- "$tmp"; return 1; }
    for m in "$@"; do
        printf 'import "%s"\nrule __t__ { condition: true }\n' "$m" > "$tmp"
        if ! yarac "$tmp" "$tmpo" >/dev/null 2>&1; then
            missing+=("$m")
        fi
    done
    rm -f -- "$tmp" "$tmpo"
    echo "${missing[*]}"
}

_ensure_yara_build_deps() {
    local -a pkgs=()
    case "$PKG_MANAGER" in
        pacman) pkgs=(base-devel autoconf automake libtool bison flex pkgconf jansson openssl file git) ;;
        apt)    pkgs=(build-essential autoconf automake libtool bison flex pkg-config libjansson-dev libssl-dev libmagic-dev git) ;;
        dnf)    pkgs=(gcc gcc-c++ make autoconf automake libtool bison flex pkgconf jansson-devel openssl-devel file-devel git) ;;
        yum)    pkgs=(gcc gcc-c++ make autoconf automake libtool bison flex pkgconfig jansson-devel openssl-devel file-devel git) ;;
        zypper) pkgs=(gcc gcc-c++ make autoconf automake libtool bison flex pkg-config libjansson-devel libopenssl-devel libmagic-devel git) ;;
        apk)    pkgs=(build-base autoconf automake libtool bison flex pkgconf jansson-dev openssl-dev file-dev git) ;;
        *)      log_warn "Gerenciador de pacotes não suportado para instalar deps de build."; return 1 ;;
    esac
    if declare -F _pkg_install >/dev/null; then
        _pkg_install "${pkgs[@]}"
    else
        log_error "_pkg_install não encontrado para instalar dependências de build."
        return 1
    fi
}

_build_yara_from_source() {
    log_info "Compilando YARA do fonte com módulos: ${YARA_CONFIGURE_FLAGS} ..."
    # Garantir gerenciador e git
    if [[ -z "${PKG_MANAGER:-}" ]]; then
        if declare -F detect_package_manager >/dev/null; then detect_package_manager; fi
        if [[ -z "${PKG_MANAGER:-}" ]] && declare -F _detect_pkg_manager >/dev/null; then _detect_pkg_manager; fi
    fi
    if ! command -v git >/dev/null 2>&1; then
        if declare -F _ensure_git >/dev/null; then
            _ensure_git || { log_error "git é necessário para compilar o YARA."; return 1; }
        else
            _ensure_yara_build_deps || return 1
        fi
    fi
    _ensure_yara_build_deps || { log_error "Falha ao instalar dependências de build."; return 1; }

    mkdir -p -- "$YARA_BUILD_DIR" || { log_error "Não foi possível criar '$YARA_BUILD_DIR'."; return 1; }

    if [[ -d "$YARA_BUILD_DIR/.git" ]]; then
        if ! (cd "$YARA_BUILD_DIR" && git fetch --all --tags --prune && git reset --hard origin/master) >>"$LOG_FILE" 2>&1; then
            log_warn "Falha ao atualizar fonte do YARA; tentando re-clonar..."
            rm -rf -- "$YARA_BUILD_DIR"
        fi
    fi
    if [[ ! -d "$YARA_BUILD_DIR/.git" ]]; then
        if ! git clone --depth 1 "$YARA_SOURCE_REPO_URL" "$YARA_BUILD_DIR" >>"$LOG_FILE" 2>&1; then
            log_error "Falha ao clonar repositório do YARA."
            return 1
        fi
    fi

    local jobs; jobs=${YARA_BUILD_JOBS:-$(getconf _NPROCESSORS_ONLN 2>/dev/null || nproc 2>/dev/null || echo 1)}
    local sudo_cmd=""; (( EUID != 0 )) && sudo_cmd="sudo -n"
    if ! (  cd "$YARA_BUILD_DIR" \
         && ./bootstrap.sh >>"$LOG_FILE" 2>&1 \
         && ./configure ${YARA_CONFIGURE_FLAGS} >>"$LOG_FILE" 2>&1 \
         && make -j"$jobs" >>"$LOG_FILE" 2>&1 \
         && $sudo_cmd make install >>"$LOG_FILE" 2>&1 ); then
        log_error "Falha ao compilar/instalar o YARA (veja $LOG_FILE)."
        return 1
    fi

    $sudo_cmd ldconfig >/dev/null 2>&1 || true
    hash -r || true

    local missing; missing=$(_yara_missing_modules dex cuckoo magic dotnet || true)
    if [[ -n "$missing" ]]; then
        log_warn "YARA instalado, mas ainda faltam módulos: $missing"
    else
        log_info "YARA compilado com sucesso com módulos dex, cuckoo, magic e dotnet."
    fi
    return 0
}

ensure_yara_ready() {
    mkdir -p -- "$YARA_DIR" "$YARA_RULES_REPO_DIR" 2>/dev/null || true

    if ! command -v git >/dev/null 2>&1; then
        if declare -F _ensure_git >/dev/null; then
            _ensure_git || log_warn "git indisponível; atualização automática das regras pode falhar."
        else
            log_warn "Função '_ensure_git' não encontrada; atualização automática das regras pode falhar."
        fi
    else
        GIT_ENABLED=true
    fi

    if ! command -v yara >/dev/null 2>&1; then
        if declare -F _ensure_yara >/dev/null; then
            _ensure_yara || { log_warn "YARA indisponível; varreduras YARA desabilitadas."; YARA_SCAN_ENABLED=false; return 0; }
        else
            log_warn "Função '_ensure_yara' não encontrada e YARA não está instalado; varreduras YARA desabilitadas."
            YARA_SCAN_ENABLED=false
            return 0
        fi
    else
        YARA_ENABLED=true
    fi

    if [[ "${YARA_AUTO_COMPILE:-true}" == "true" ]]; then
        local missing_mods; missing_mods=$(_yara_missing_modules dex cuckoo magic dotnet || true)
        if [[ -n "$missing_mods" ]]; then
            log_warn "Módulos YARA ausentes detectados: $missing_mods. Tentando compilar YARA com módulos extras..."
            if _build_yara_from_source; then
                YARA_ENABLED=true
                hash -r || true
            else
                log_warn "Falha ao compilar YARA com módulos extras; seguindo com fallback de regras se necessário."
            fi
        fi
    fi

    local need_update=0
    if [[ ! -s "$YARA_RULES_FILE" ]]; then
        log_warn "Regras YARA não encontradas em '$YARA_RULES_FILE'."
        need_update=1
    elif ! _validate_yara_rules; then
        log_warn "Arquivo de regras YARA parece inválido: '$YARA_RULES_FILE'. Tentando atualizar..."
        need_update=1
    fi

    if (( need_update )); then
        if [[ "${AUTO_UPDATE_YARA_RULES:-true}" != "true" ]]; then
            log_warn "AUTO_UPDATE_YARA_RULES=false; execute '--update-yara-rules' para baixar."
            YARA_SCAN_ENABLED=false
            return 0
        fi
        if ! update_yara_rules || ! _validate_yara_rules; then
            log_error "Regras YARA inválidas/ausentes e atualização falhou. Desabilitando YARA."
            YARA_SCAN_ENABLED=false
            return 0
        fi
    fi

    YARA_SCAN_ENABLED=true
    log_info "YARA habilitado com regras em '$YARA_RULES_FILE'."
}

_check_yara_latest() {
    command -v yara  >/dev/null 2>&1 || return 0
    command -v curl  >/dev/null 2>&1 || return 0
    command -v jq    >/dev/null 2>&1 || return 0
    local installed latest rc=0
    installed=$(yara --version 2>/dev/null | awk '{print $2}')
    [[ -z "$installed" ]] && return 0
    latest=$(curl -fsSL https://api.github.com/repos/VirusTotal/yara/releases/latest 2>/dev/null \
             | jq -r '.tag_name // empty') || rc=$?
    (( rc != 0 )) && return 0
    latest=${latest#v}
    if [[ -n "$latest" && "$installed" != "$latest" ]]; then
        log_warn "YARA desatualizado (instalado: $installed; último: $latest)."
    else
        log_info "YARA na versão mais recente ($installed)."
    fi
}

_check_rules_up_to_date() {
    local repo="$1"
    command -v git >/dev/null 2>&1 || return 0
    [[ -d "$repo/.git" ]] || return 0
    local branch local_head remote_head
    branch=$(git -C "$repo" rev-parse --abbrev-ref HEAD 2>/dev/null || echo "master")
    local_head=$(git -C "$repo" rev-parse HEAD 2>/dev/null || echo "")
    remote_head=$(git -C "$repo" ls-remote origin -h "refs/heads/$branch" 2>/dev/null | awk '{print $1}')
    if [[ -n "$local_head" && -n "$remote_head" && "$local_head" == "$remote_head" ]]; then
        log_info "Regras YARA já estão atualizadas (HEAD=$local_head)."
    else
        log_warn "Regras YARA podem estar desatualizadas (local=$local_head remote=$remote_head)."
    fi
}

_validate_yara_rules() {
    [[ -s "$YARA_RULES_FILE" ]] || return 1

    if command -v yarac >/dev/null 2>&1; then
        local tmp; tmp=$(mktemp) || return 1
        if yarac "$YARA_RULES_FILE" "$tmp" >/dev/null 2>&1; then
            rm -f -- "$tmp"; return 0
        else
            rm -f -- "$tmp"; return 1
        fi
    fi

    yara -w "$YARA_RULES_FILE" /dev/null >/dev/null 2>&1
    return $?
}

update_yara_rules() {
    log_info "Iniciando a atualização das regras YARA..."

    if ! command -v git >/dev/null 2>&1; then
        log_error "O comando 'git' é necessário para atualizar as regras YARA, mas não foi encontrado."
        return 1
    fi

    if ! mkdir -p "$YARA_RULES_REPO_DIR" "$YARA_DIR"; then
        log_error "Falha ao garantir diretórios YARA ('$YARA_RULES_REPO_DIR', '$YARA_DIR')."
        return 1
    fi

    if [[ ! -d "$YARA_RULES_REPO_DIR/.git" ]]; then
        log_info "Repositório de regras não encontrado. Clonando de '$YARA_RULES_REPO_URL'..."
        if ! git clone --depth 1 "$YARA_RULES_REPO_URL" "$YARA_RULES_REPO_DIR" >>"$LOG_FILE" 2>&1; then
            log_error "Falha ao clonar o repositório de regras YARA."
            return 1
        fi
    else
        log_info "Repositório de regras encontrado. Atualizando via 'git pull'..."
        if ! (cd "$YARA_RULES_REPO_DIR" && git pull --ff-only) >>"$LOG_FILE" 2>&1; then
            log_error "Falha ao atualizar o repositório de regras YARA."
            return 1
        fi
    fi

    local -a candidates=()
    declare -A _seen=()
    local _maybe_add
    _maybe_add() {
        local f="$1"
        [[ -f "$YARA_RULES_REPO_DIR/$f" ]] || return 0
        if [[ -z "${_seen[$f]+x}" ]]; then
            _seen["$f"]=1
            candidates+=("$f")
        fi
    }
    [[ -n "${YARA_RULES_INDEX_FILENAME:-}" ]] && _maybe_add "$YARA_RULES_INDEX_FILENAME"
    _maybe_add "index.yar"
    _maybe_add "index_community.yar"
    _maybe_add "index_light.yar"
    _maybe_add "index_w_mobile.yar"
    while IFS= read -r f; do
        f=$(basename "$f")
        _maybe_add "$f"
    done < <(find "$YARA_RULES_REPO_DIR" -maxdepth 1 -type f -name 'index*.yar' 2>/dev/null | sort)

    local chosen="" tmp rc
    for idx in "${candidates[@]}"; do
        pushd "$YARA_RULES_REPO_DIR" >/dev/null 2>&1 || { log_error "Falha ao entrar em '$YARA_RULES_REPO_DIR'."; return 1; }
        if command -v yarac >/dev/null 2>&1; then
            tmp=$(mktemp) || { popd >/dev/null 2>&1; log_error "Falha ao criar arquivo temporário."; return 1; }
            if yarac "$idx" "$tmp" >>"$LOG_FILE" 2>&1; then
                chosen="$idx"
                rm -f -- "$tmp"
                popd >/dev/null 2>&1
                break
            else
                rc=$?
                rm -f -- "$tmp"
                popd >/dev/null 2>&1
                log_warn "Falha ao compilar '$idx' (rc=$rc). Tentando próximo índice..."
            fi
        else
            if yara -w "$idx" /dev/null >>"$LOG_FILE" 2>&1; then
                chosen="$idx"
                popd >/dev/null 2>&1
                break
            else
                rc=$?
                popd >/dev/null 2>&1
                log_warn "Falha ao carregar '$idx' com 'yara' (rc=$rc). Tentando próximo índice..."
            fi
        fi
    done

    if [[ -n "$chosen" ]]; then
        local index_abs="$YARA_RULES_REPO_DIR/$chosen"
        if command -v realpath >/dev/null 2>&1; then
            index_abs=$(realpath "$index_abs" 2>/dev/null || echo "$index_abs")
        fi
        if ! printf 'include "%s"\n' "$index_abs" > "$YARA_RULES_FILE"; then
            log_error "Falha ao escrever o arquivo principal de regras '$YARA_RULES_FILE'."
            return 1
        fi
        YARA_RULES_INDEX_FILENAME="$chosen"
        local head; head=$(git -C "$YARA_RULES_REPO_DIR" rev-parse HEAD 2>/dev/null || true)
        log_info "Regras YARA atualizadas. Índice selecionado: '$chosen'. Arquivo principal: '$YARA_RULES_FILE'"
        [[ -n "$head" ]] && log_info "Regras YARA atualizadas (HEAD=$head)."
        return 0
    fi

    log_warn "Nenhum índice padrão compilou. Construindo conjunto mínimo de regras compatíveis..."

    local -a test_mods=(pe elf hash math time magic dex dotnet cuckoo)
    local -a missing_mods=() m tmpf tmpo
    tmpf=$(mktemp) || { log_error "Falha ao criar arquivo temporário."; return 1; }
    tmpo=$(mktemp) || { rm -f -- "$tmpf"; log_error "Falha ao criar arquivo temporário."; return 1; }
    for m in "${test_mods[@]}"; do
        printf 'import "%s"\nrule __modtest__ { condition: true }\n' "$m" > "$tmpf"
        if ! yarac "$tmpf" "$tmpo" >/dev/null 2>&1; then
            missing_mods+=("$m")
        fi
    done
    rm -f -- "$tmpf" "$tmpo"
    [[ ${#missing_mods[@]} -gt 0 ]] && log_warn "Módulos ausentes: ${missing_mods[*]}"
    local -a selected=() f miss skip tmpc
    tmpc=$(mktemp) || { log_error "Falha ao criar arquivo temporário."; return 1; }
    while IFS= read -r f; do
        if [[ "$f" =~ /index[^/]*\.yar$ ]]; then continue; fi
        if [[ "$f" =~ \.bak$ ]]; then continue; fi
        if grep -qE '^[[:space:]]*include[[:space:]]+"' "$f"; then continue; fi

        skip=0
        for miss in "${missing_mods[@]}"; do
            if grep -qE "^[[:space:]]*import[[:space:]]+\"$miss\"" "$f"; then
                skip=1; break
            fi
        done
        if (( skip )); then continue; fi

        if yarac "$f" "$tmpc" >/dev/null 2>&1; then
            selected+=("$f")
        fi
    done < <(find "$YARA_RULES_REPO_DIR" -type f -name '*.yar' 2>/dev/null | sort)
    rm -f -- "$tmpc"

    if [[ ${#selected[@]} -eq 0 ]]; then
        log_error "Não foi possível montar um conjunto mínimo de regras compatíveis com o seu YARA."
        log_error "Verifique os erros no log ($LOG_FILE) e considere atualizar o pacote 'yara'."
        return 1
    fi

    {
        for f in "${selected[@]}"; do
            if command -v realpath >/dev/null 2>&1; then
                printf 'include "%s"\n' "$(realpath "$f" 2>/dev/null || echo "$f")"
            else
                printf 'include "%s"\n' "$f"
            fi
        done
    } > "$YARA_RULES_FILE" || { log_error "Falha ao escrever '$YARA_RULES_FILE'."; return 1; }

    local head; head=$(git -C "$YARA_RULES_REPO_DIR" rev-parse HEAD 2>/dev/null || true)
    log_info "Regras YARA geradas com fallback. Total incluído: ${#selected[@]}."
    [[ -n "$head" ]] && log_info "Fallback baseado no repo (HEAD=$head)."

    return 0
}
# ==============================================================================
#           FUNÇÃO PRINCIPAL DE INICIALIZAÇÃO
# ==============================================================================
initialize_script() {
    check_permissions

    # Cria diretórios/arquivos de log antes de ativar o tracing
    setup_environment

    # DEBUG/tracing útil quando DEBUG_MODE=true
    if [[ "${DEBUG_MODE:-false}" == "true" ]]; then
      set -o errtrace
      trap 'rc=$?; log_error "ERR: rc=$rc cmd=\"$BASH_COMMAND\" src=${BASH_SOURCE[0]##*/}:${LINENO}";' ERR
      trap 'rc=$?; log_info "EXIT: rc=$rc (THREATS_FOUND=${THREATS_FOUND:-N/A})"' EXIT

      # Trace detalhado para arquivo (opcional via TRACE_BASH=true)
      : "${TRACE_BASH:=false}"
      if [[ "$TRACE_BASH" == "true" ]]; then
        mkdir -p -- "$LOGS_DIR" 2>/dev/null || true
        exec 9> "$LOGS_DIR/trace.log"
        export BASH_XTRACEFD=9
        export PS4='+ ${BASH_SOURCE##*/}:${LINENO}:${FUNCNAME[0]}: '
        set -x
      fi
    fi

    if declare -F detect_package_manager >/dev/null; then
        detect_package_manager || true
    fi

    log_info "================================================="
    log_info "    Iniciando Script de Caça a Ameaças...          "
    log_info "    Data: $(date)"
    log_info "================================================="

    if declare -F clean_json_log >/dev/null; then
        clean_json_log || log_warn "Falha ao limpar o JSON de alertas; prosseguindo."
    fi

    check_dependencies
    # ...
}
# ==============================================================================
#           SISTEMA DE LOGGING 
# ==============================================================================
log_this() {
    local level="$1"
    local message="$2"
    local color="${C_RESET:-}"
    local log_to_terminal=true
    local level_display="LOG"

    case "$level" in
        INFO)   level_display="INFO "  color="${C_GREEN:-}"   ;;
        AVISO)  level_display="AVISO"  color="${C_YELLOW:-}"  ;;
        ERRO)   level_display="ERRO "  color="${C_RED:-}"     ;;
        ALERTA) level_display="ALERTA" color="${C_MAGENTA:-}" ;;
        DEBUG)
            level_display="DEBUG" color="${C_CYAN:-}"
            [[ "${DEBUG_MODE:-false}" != "true" ]] && log_to_terminal=false
            ;;
        *)      level_display="LOG" ;;
    esac

    if [[ "$log_to_terminal" == true ]]; then
        printf '%s[%-6s]%s [%s] %s\n' "$color" "$level_display" "${C_RESET:-}" "$(date '+%T')" "$message" >&2
    fi
    printf '%s [%-6s] %s\n' "$(date '+%F %T')" "$level_display" "$message" >> "$LOG_FILE"
}

log_info()  { log_this "INFO" "$*"; }
log_warn()  { log_this "AVISO" "$*"; }
log_error() { log_this "ERRO" "$*"; }
log_debug() { [[ "${DEBUG_MODE:-false}" == "true" ]] && log_this "DEBUG" "$*"; }

# --- Funções Auxiliares de Alerta ---
add_alert_detail() {
    local key="$1"
    local value="$2"
    ALERT_DETAILS_MAP["$key"]="$value"
}

# --- Função Principal de Alertas ---
log_alert() {
    local full_message="$1"
    local risk_level="${2:-MÉDIO}"
    local check_type="${3:-INDEFINIDO}"
    local alert_key
    alert_key=$(echo "$full_message|$check_type" | sha256sum | awk '{print $1}')
    if [[ -v SEEN_ALERTS["$alert_key"] ]]; then
        log_debug "Alerta duplicado ignorado: $full_message"
        ALERT_DETAILS_MAP=()  
        return 0
    fi
    SEEN_ALERTS["$alert_key"]=1

    local -a details_for_python=()
    local key
    for key in "${!ALERT_DETAILS_MAP[@]}"; do
        details_for_python+=(--detail "$key: ${ALERT_DETAILS_MAP[$key]}")
    done
    mkdir -p -- "$(dirname -- "$JSON_LOG_FILE")" 2>/dev/null || {
        log_error "Não foi possível preparar diretório do log JSON: $(dirname -- "$JSON_LOG_FILE")"
        ALERT_DETAILS_MAP=()
        return 1
    }

    local persisted=0
    if [[ "${PYTHON3_ENABLED:-false}" == "true" && -f "$PYTHON_LOGGER_SCRIPT" ]]; then
        if python3 "$PYTHON_LOGGER_SCRIPT" "$JSON_LOG_FILE" \
            --message "$full_message" \
            --risk-level "$risk_level" \
            --check-type "$check_type" \
            "${details_for_python[@]}"
        then
            persisted=1
        else
            log_error "Falha ao persistir alerta no JSON via '$PYTHON_LOGGER_SCRIPT'."
        fi
    else
        log_warn "Log JSON pulado: python3 indisponível e/ou logger ausente ('$PYTHON_LOGGER_SCRIPT')."
    fi

    if (( persisted )); then
        (( THREATS_FOUND++ ))
        local alert_number="$THREATS_FOUND"
        log_this "ALERTA" "[$alert_number] Risco: $risk_level | Tipo: $check_type | $full_message"

        if [[ "${DRY_RUN:-false}" == "false" ]]; then
            local formatted_alert="[ALERTA #${alert_number} - Risco: $risk_level] $full_message (Host: $(hostname -f))"
            if [[ "${TELEGRAM_SEND:-false}" == "true" ]]; then send_telegram "$formatted_alert"; fi
            if [[ "${EMAIL_SEND:-false}" == "true" ]]; then send_email "$formatted_alert"; fi
        fi
    else
        log_this "ALERTA" "[NÃO PERSISTIDO] Risco: $risk_level | Tipo: $check_type | $full_message"
    fi

    ALERT_DETAILS_MAP=()
}

# --- Funções de Notificação Externa ---
send_telegram() {
    ( 
        local message="$1"
        if [[ -z "${TELEGRAM_TOKEN:-}" || -z "${TELEGRAM_CHAT_ID:-}" ]]; then
            log_warn "Credenciais do Telegram (TELEGRAM_TOKEN, TELEGRAM_CHAT_ID) não definidas no .env"
            return
        fi
        if ! timeout 10s curl -s --fail -X POST "https://api.telegram.org/bot${TELEGRAM_TOKEN}/sendMessage" \
            -d chat_id="${TELEGRAM_CHAT_ID}" --data-urlencode "text=$message" &>/dev/null; then
            log_warn "Falha ao enviar notificação para o Telegram (timeout ou erro de API)."
        fi
    ) &
}

send_email() {
    ( 
        local message="$1"
        if [[ "$MAIL_ENABLED" != "true" ]]; then
            log_warn "Comando 'mail' não encontrado. Notificação por e-mail desabilitada."
            return
        fi
        if [[ -z "${EMAIL_DEST:-}" ]]; then
            log_warn "Destinatário de e-mail (EMAIL_DEST) não definido no .env"
            return
        fi
        if ! echo "$message" | timeout 15s mail -s "Alerta de Ameaça - Threat Hunter" "$EMAIL_DEST"; then
            log_warn "O comando 'mail' falhou ao enviar o e-mail."
        fi
    ) &
}

# Timeout padrão (segundos). Pode sobrescrever no .env: RUN_CHECK_TIMEOUT=120
: "${RUN_CHECK_TIMEOUT:=120}"

# ==============================================================================
#           FUNÇÃO WRAPPER DE EXECUÇÃO DE VERIFICAÇÕES (com timeout)
# ==============================================================================
run_check() {
    local rc_timeout="$RUN_CHECK_TIMEOUT"
    if [[ "$1" == "--timeout" && -n "$2" ]]; then
        rc_timeout="$2"; shift 2
    fi

    case "$rc_timeout" in
        *s) rc_timeout="${rc_timeout%s}" ;;
        *m) rc_timeout="$(( ${rc_timeout%m} * 60 ))" ;;
    esac
    [[ "$rc_timeout" =~ ^[0-9]+$ ]] || rc_timeout=120

    local description="$1"; shift
    local -a command_and_args=( "$@" )

    local error_file; error_file=$(mktemp -t runcheck_err.XXXXXX) || { echo "mktemp falhou" >&2; return 1; }
    local threats_before=${THREATS_FOUND:-0}

    printf "  ${C_GRAY}┠─ %-65s${C_RESET}" "Executando: $description..."

    local had_e=0 had_u=0 had_pipe=0
    [[ $- == *e* ]] && had_e=1
    [[ $- == *u* ]] && had_u=1
    [[ "$(set -o | awk '$1=="pipefail"{print $2}')" == "on" ]] && had_pipe=1
    set +e; set +u; set +o pipefail 2>/dev/null

    local start_sec=$SECONDS
    local exit_code=0 timed_out=0
    local is_func=0; declare -F -- "${command_and_args[0]}" >/dev/null && is_func=1

    if (( is_func )); then
        ( "${command_and_args[@]}" 2> "$error_file" ) & local child=$!
        local end=$(( SECONDS + rc_timeout ))
        while kill -0 "$child" 2>/dev/null; do
            if (( SECONDS >= end )); then
                timed_out=1
                kill -TERM "$child" 2>/dev/null
                sleep 1
                kill -KILL "$child" 2>/dev/null
                break
            fi
            sleep 0.2
        done
        if (( timed_out )); then
            exit_code=124
        else
            wait "$child"; exit_code=$?
        fi
    else
        if command -v timeout >/dev/null 2>&1; then
            timeout --foreground "${rc_timeout}s" "${command_and_args[@]}" 2> "$error_file"
            exit_code=$?
            [[ $exit_code -eq 124 || $exit_code -eq 137 ]] && timed_out=1
        else
            "${command_and_args[@]}" 2> "$error_file"; exit_code=$?
        fi
    fi

    (( had_pipe )) && set -o pipefail || set +o pipefail 2>/dev/null
    (( had_e )) && set -e || set +e
    (( had_u )) && set -u || set +u

    local threats_after=${THREATS_FOUND:-0}
    local dur=$(( SECONDS - start_sec ))
    local status_color="$C_GREEN" status_text="[  OK  ]"

    if (( exit_code != 0 )); then
        if (( timed_out )); then
            status_color="$C_YELLOW"; status_text="[TIMEOUT]"
            log_warn "Verificação '$description' atingiu timeout (${rc_timeout}s)."
        else
            status_color="$C_RED"; status_text="[FALHOU]"
        fi
    elif (( threats_after > threats_before )); then
        status_color="$C_MAGENTA"; status_text="[ALERTA]"
    fi

    printf "\r  ${C_GRAY}┠─ %-50s${C_RESET} %b (%.1fs)\n" "$description" "${status_color}${status_text}${C_RESET}" "$dur"

    if (( exit_code != 0 )) && [[ -s "$error_file" ]]; then
        log_warn "A verificação '$description' retornou código $exit_code."
        sed -n '1,200p' "$error_file" | while IFS= read -r line; do log_warn "  └─ $line"; done
    fi

    rm -f -- "$error_file"
    return "$exit_code"
}

# ==============================================================================
#           MÓDULO DE VERIFICAÇÃO DE REDE
# ==============================================================================
_net_extract_ip() {
    local addr="$1"
    addr="${addr%:*}"   
    addr="${addr#[}"    
    addr="${addr%]}"    
    echo "$addr"
}

_net_is_public_ip() {
    local ip="$1"
    [[ "$ip" =~ ^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|127\.|::1|fe80:|fc..) ]] && return 1
    return 0
}

_net_run_ss_command() {
    sudo -n "$@" 2>/dev/null || "$@" 2>/dev/null
}

_net_process_ss_line() {
    local line="$1" direction="$2" proto="$3"
    local recvq sendq laddr raddr users
    read -r recvq sendq laddr raddr users <<< "$line"
    if [[ -z "$users" ]]; then
        users=$(sed -n 's/.*users:(KATEX_INLINE_OPEN.*KATEX_INLINE_CLOSE)$/\1/p' <<<"$line")
    else
        users=$(sed -n 's/.*users:(KATEX_INLINE_OPEN.*KATEX_INLINE_CLOSE)$/\1/p' <<<"$users")
    fi

    local comm pid
    comm=$(sed -n 's/.*"KATEX_INLINE_OPEN[^"]*KATEX_INLINE_CLOSE".*/\1/p' <<<"$users")
    [[ -z "$comm" ]] && comm="N/A"
    pid=$(sed -n 's/.*pid=KATEX_INLINE_OPEN[0-9]\+KATEX_INLINE_CLOSE.*/\1/p' <<<"$users")
    [[ -z "$pid" ]] && pid="N/A"
    local key="$direction|$proto|$laddr|$raddr|$comm"
    if [[ "${NET_USE_BASELINE:-true}" == "true" ]]; then
        if grep -Fxq -- "$key" "$NET_BASELINE_FILE"; then
            return 0
        fi
        printf '%s\n' "$key" >> "$NET_BASELINE_FILE"
    fi
    local lhost rhost
    lhost=$(_net_extract_ip "$laddr"); _net_is_public_ip "$lhost" && _NET_PUBLIC_IPS_TO_CHECK["$lhost"]=1
    if [[ "$direction" == "OUTBOUND" ]]; then
        rhost=$(_net_extract_ip "$raddr"); _net_is_public_ip "$rhost" && _NET_PUBLIC_IPS_TO_CHECK["$rhost"]=1
    fi
    add_alert_detail "PID" "$pid"
    add_alert_detail "Processo" "$comm"
    add_alert_detail "Protocolo" "$proto"

    if [[ "$direction" == "LISTEN" ]]; then
        add_alert_detail "Endpoint de Escuta" "$laddr"
        log_alert "Novo serviço escutando na rede: $comm em $laddr" "MÉDIO" "Rede Exposta"
    else
        add_alert_detail "Conexão Local" "$laddr"
        add_alert_detail "Conexão Remota" "$raddr"
        log_alert "Nova conexão externa estabelecida por: $comm para $raddr" "MÉDIO" "Conexão Externa"
    fi
}

# ----------------------------------------------------------
# EChama scripts Python para verificar uma lista de IPs.
# Transforma IPs brutos em alertas (DNSBL + Política/WHOIS).
# -----------------------------------------------------------
_net_enrich_and_alert_ips() {
    local -a ips_to_check=("${!_NET_PUBLIC_IPS_TO_CHECK[@]}")

    if ((${#ips_to_check[@]} == 0)); then
        log_info "Nenhum IP público novo para enriquecimento."
        return 0
    fi
    log_info "Enriquecendo ${#ips_to_check[@]} IPs públicos (DNSBL, WHOIS & Política)..."

    if [[ "${PYTHON3_ENABLED:-false}" != "true" || "${JQ_ENABLED:-false}" != "true" ]]; then
        log_warn "Enriquecimento pulado: python3 e/ou jq não estão disponíveis."
        return 1
    fi
    if [[ ! -f "$NET_DNSBL_SCRIPT" || ! -f "$NET_WHOIS_SCRIPT" ]]; then
        log_warn "Enriquecimento pulado: scripts Python auxiliares não encontrados em '${PYTHON_NETWORK_DIR:-$PYTHON_SCRIPTS_DIR}'."
        return 1
    fi

    local dnsbl_json whois_json
    dnsbl_json=$(python3 "$NET_DNSBL_SCRIPT" "${ips_to_check[@]}" 2>/dev/null || echo "[]")
    whois_json=$(python3 "$NET_WHOIS_SCRIPT" --policy-file "$NET_POLICY_FILE" "${ips_to_check[@]}" 2>/dev/null || echo "[]")
    [[ -z "$whois_json" ]] && whois_json="[]"

    local combined_json
    combined_json=$(jq -s '[ .[] | (if type=="array" then .[] else . end) ]' \
                    <(echo "$dnsbl_json") <(echo "$whois_json") 2>/dev/null)
    [[ -z "$combined_json" ]] && { log_warn "Falha ao combinar resultados do enriquecimento (jq)."; return 1; }

    local alert_count; alert_count=$(jq 'length' <<< "$combined_json" 2>/dev/null || echo 0)
    (( alert_count == 0 )) && { log_info "Enriquecimento concluído. Nenhuma ameaça ou violação de política encontrada."; return 0; }

    log_info "Processando ${alert_count} novo(s) alerta(s) gerado(s) pelo enriquecimento de IPs..."

    local i
    for ((i=0; i<alert_count; i++)); do
        local alert_obj risk type message
        alert_obj=$(jq ".[$i]" <<< "$combined_json")
        risk=$(jq -r '.risk // "MÉDIO"' <<< "$alert_obj")
        type=$(jq -r '.type // "INDEFINIDO"' <<< "$alert_obj")
        message=$(jq -r '.message // "Sem mensagem."' <<< "$alert_obj")

        while IFS= read -r -d $'\0' key && IFS= read -r -d $'\0' value; do
            [[ -z "$key" ]] && continue
            [[ -z "${value//[[:space:]]/}" ]] && continue
            [[ "$value" == "null" ]] && continue
            add_alert_detail "$key" "$value"
        done < <(
            jq -rj '
              (.details // {}) | to_entries[]
              | select(.value != null)
              | .key, "\u0000",
                (if      (.value|type)=="string"  then .value
                 elif    (.value|type)=="object" or (.value|type)=="array" then (.value|tojson)
                 else    (.value|tostring)
                 end),
                "\u0000"
            ' <<< "$alert_obj"
        )

        log_alert "$message" "$risk" "$type"
    done
}

# --- Função Principal de Verificação de Rede ---
verificar_rede() {
    log_info "Iniciando verificação de rede (listeners e conexões externas)..."

    if ! command -v ss >/dev/null 2>&1 && ! command -v netstat >/dev/null 2>&1; then
        log_error "Nem 'ss' (iproute2) nem 'netstat' encontrados. Instale 'iproute2' ou 'net-tools'."
        return 1
    fi

    : "${NET_BASELINE_FILE:=${HIST_DIR:-/var/tmp}/network_connections.baseline}"
    mkdir -p -- "$(dirname -- "$NET_BASELINE_FILE")" 2>/dev/null || {
        log_error "Não foi possível criar diretório da baseline de rede: $(dirname -- "$NET_BASELINE_FILE")"
        return 1
    }
    : > /dev/null >> "$NET_BASELINE_FILE" || {
        log_error "Não foi possível tocar a baseline de rede: $NET_BASELINE_FILE"
        return 1
    }

    (( EUID != 0 )) && log_warn "Executando sem root; 'ss -p' pode ocultar PID/processos."
    : "${NETWORK_SS_TIMEOUT:=8s}"
    : "${NET_SCAN_OUTBOUND:=true}"
    local have_timeout=0; command -v timeout >/dev/null 2>&1 && have_timeout=1

    local -A _NET_PUBLIC_IPS_TO_CHECK=()

    log_info "Analisando listeners TCP..."
    while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        _net_process_ss_line "$line" "LISTEN" "tcp" || true
    done < <(
        if (( have_timeout )); then
            timeout "$NETWORK_SS_TIMEOUT" ss -H -ltnp 2>/dev/null \
            || timeout "$NETWORK_SS_TIMEOUT" sudo -n ss -H -ltnp 2>/dev/null \
            || netstat -ltn 2>/dev/null \
            || true
        else
            ss -H -ltnp 2>/dev/null \
            || sudo -n ss -H -ltnp 2>/dev/null \
            || netstat -ltn 2>/dev/null \
            || true
        fi
    )

    log_info "Analisando listeners UDP..."
    while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        _net_process_ss_line "$line" "LISTEN" "udp" || true
    done < <(
        if (( have_timeout )); then
            timeout "$NETWORK_SS_TIMEOUT" ss -H -lunp 2>/dev/null \
            || timeout "$NETWORK_SS_TIMEOUT" sudo -n ss -H -lunp 2>/dev/null \
            || netstat -lun 2>/dev/null \
            || true
        else
            ss -H -lunp 2>/dev/null \
            || sudo -n ss -H -lunp 2>/dev/null \
            || netstat -lun 2>/dev/null \
            || true
        fi
    )

    if [[ "${NET_SCAN_OUTBOUND,,}" == "true" ]]; then
        log_info "Analisando conexões TCP estabelecidas..."
        while IFS= read -r line; do
            [[ -z "$line" ]] && continue
            _net_process_ss_line "$line" "OUTBOUND" "tcp" || true
        done < <(
            if (( have_timeout )); then
                timeout "$NETWORK_SS_TIMEOUT" ss -H -tnp state established 2>/dev/null \
                || timeout "$NETWORK_SS_TIMEOUT" sudo -n ss -H -tnp state established 2>/dev/null \
                || timeout "$NETWORK_SS_TIMEOUT" ss -H -tn state established 2>/dev/null \
                || netstat -tn 2>/dev/null \
                || true
            else
                ss -H -tnp state established 2>/dev/null \
                || sudo -n ss -H -tnp state established 2>/dev/null \
                || ss -H -tn state established 2>/dev/null \
                || netstat -tn 2>/dev/null \
                || true
            fi
        )

        log_info "Analisando conexões UDP (ativas)..."
        while IFS= read -r line; do
            [[ "$line" =~ \*:\* ]] && continue
            _net_process_ss_line "$line" "OUTBOUND" "udp" || true
        done < <(
            if (( have_timeout )); then
                timeout "$NETWORK_SS_TIMEOUT" ss -H -unp 2>/dev/null \
                || timeout "$NETWORK_SS_TIMEOUT" sudo -n ss -H -unp 2>/dev/null \
                || timeout "$NETWORK_SS_TIMEOUT" ss -H -un 2>/dev/null \
                || true
            else
                ss -H -unp 2>/dev/null \
                || sudo -n ss -H -unp 2>/dev/null \
                || ss -H -un 2>/dev/null \
                || true
            fi
        )
    fi

    _net_enrich_and_alert_ips || true

    unset -v _NET_PUBLIC_IPS_TO_CHECK
    log_info "Verificação de rede concluída."
    return 0
}
# ==============================================================================
# VERIFICAÇÃO DE ROOTKITS E PROCESSOS OCULTOS
# ==============================================================================
verificar_ocultos() {
    # --- 1. Pré-verificações ---
    touch "$ROOTKIT_BASELINE_FILE"

    # --- 2. Execução e Processamento de Alertas ---
    while IFS= read -r alert_json; do
        [[ -z "$alert_json" || "${alert_json:0:1}" != "{" ]] && continue

        if ! jq -e . >/dev/null <<< "$alert_json"; then
            log_warn "Linha de JSON malformada recebida do script de rootkit: $alert_json"
            continue
        fi

        # --- 3. Lógica de Baseline ---
        local baseline_key
        baseline_key=$(jq -r '[
            .check_type, 
            .details.PID, 
            .details.Processo, 
            .details.Module, 
            .details.Path
        ] | map(. // "na") | join("|")' <<< "$alert_json") 

        if [[ "$ROOTKIT_USE_BASELINE" == "true" ]]; then
            if grep -Fxq "$baseline_key" "$ROOTKIT_BASELINE_FILE"; then
                continue
            fi
            echo "$baseline_key" >> "$ROOTKIT_BASELINE_FILE"
        fi

        # --- 4. Extração de Dados e Geração de Alerta ---       
        local message risk type
        message=$(jq -r '.message // "Sem mensagem"' <<< "$alert_json")
        risk=$(jq -r '.risk_level // "MÉDIO"' <<< "$alert_json")
        type=$(jq -r '.check_type // "INDEFINIDO"' <<< "$alert_json")

        while IFS='=' read -r key value; do
            if [[ -n "$key" ]]; then
                add_alert_detail "$key" "$value"
            fi
        done < <(jq -r '.details | to_entries[] | "KATEX_INLINE_OPEN.key)=KATEX_INLINE_OPEN.value)"' <<< "$alert_json")
        log_alert "$message" "$risk" "$type"

    done < <(python3 "$ROOTKIT_CHECK_SCRIPT") 
}

# ==============================================================================
#           MÓDULO DE VERIFICAÇÃO DE EXTENSÕES DE NAVEGADORES
# ==============================================================================
verificar_navegadores() {
    # --- Etapa 1: Pré-verificações ---
    if ! declare -F get_browser_artifacts_paths >/dev/null; then
        log_error "Função auxiliar 'get_browser_artifacts_paths' não foi encontrada. Pulando verificação."
        return 1
    fi

    local -a paths=()
    get_browser_artifacts_paths paths

    if ((${#paths[@]} == 0)); then
        log_info "Nenhum artefato de navegador encontrado para análise."
        return 0 
    fi
    
    # --- Etapa 3: Análise em Lote e Processamento de Alertas ---
    printf "%s\0" "${paths[@]}" |
    sort -zu |
    python3 "$BROWSER_EXT_CHECK_SCRIPT" --baseline-dir "$BASELINE_DIR" |
    jq -c . 2>/dev/null |
    while IFS= read -r alert_json; do
        [[ -z "$alert_json" ]] && continue

        local message risk_level check_type
        message=$(jq -r '.message // "Sem mensagem"' <<< "$alert_json")
        risk_level=$(jq -r '.risk_level // "MÉDIO"' <<< "$alert_json")
        check_type=$(jq -r '.check_type // "Navegador"' <<< "$alert_json")
        while IFS='=' read -r key value; do
            if [[ -n "$key" ]]; then
                add_alert_detail "$key" "$value"
            fi
        done < <(jq -r '.details | to_entries[] | "KATEX_INLINE_OPEN.key)=KATEX_INLINE_OPEN.value)"' <<< "$alert_json")
        log_alert "$message" "$risk_level" "$check_type"
    done
}

# ==============================================================================
#           MÓDULO DE VERIFICAÇÃO DE PERSISTÊNCIA
# ==============================================================================
check_persistence() {
    # Salvaguardas
    if ! declare -p SUSPECT_PERSISTENCE_PATTERNS &>/dev/null; then
        log_warn "Array 'SUSPECT_PERSISTENCE_PATTERNS' não definido. Pulando verificação."
        return 0
    fi
    if [[ -z "${PERSISTENCE_CHECK_SCRIPT:-}" || ! -f "$PERSISTENCE_CHECK_SCRIPT" ]]; then
        log_error "Motor de análise de persistência Python não encontrado. Pulando."
        return 1
    fi
    command -v jq >/dev/null    || { log_error "jq não encontrado."; return 1; }
    command -v python3 >/dev/null || { log_error "python3 não encontrado."; return 1; }

    # Execução e Processamento
    set -o pipefail
    python3 -u "$PERSISTENCE_CHECK_SCRIPT" \
        --baseline-file "$PERSISTENCE_BASELINE_FILE" \
        --patterns "${SUSPECT_PERSISTENCE_PATTERNS[@]}" |
    while IFS= read -r alert_json; do
        [[ -z "$alert_json" ]] && continue

        local message risk_level check_type
        message=$(jq -r '.message // "Alerta"'          <<< "$alert_json")
        risk_level=$(jq -r '.risk_level // "desconhecido"' <<< "$alert_json")
        check_type=$(jq -r '.check_type // "Persistência"' <<< "$alert_json")

        # Extrai detalhes como TSV (chave <TAB> valor) e adiciona ao alerta
        while IFS=$'\t' read -r key value; do
            [[ -n "$key" ]] && add_alert_detail "$key" "$value"
        done < <(jq -r '(.details // {}) | to_entries[] | [.key, (.value|tostring)] | @tsv' <<< "$alert_json")

        log_alert "$message" "$risk_level" "$check_type"
    done
    local ec=${PIPESTATUS[0]}
    set +o pipefail
    return "$ec"
}

# ==============================================================================
#           MÓDULO DE VERIFICAÇÃO DE INTEGRIDADE DO SUDO
# ==============================================================================
check_sudoers_integrity() {
    # --- Salvaguardas ---
    if [[ -z "${SUDOERS_BASELINE_FILE:-}" ]]; then
        log_error "Variável de configuração SUDOERS_BASELINE_FILE não definida. Pulando."
        return 1
    fi
    if ! declare -p SUDOERS_PATHS_TO_CHECK &>/dev/null; then
        log_warn "Array 'SUDOERS_PATHS_TO_CHECK' não definido ou vazio. Pulando verificação de Sudo."
        return 0
    fi
    local current_hashes_file; current_hashes_file=$(mktemp)
    (
        set -e      
        # --- 1. Coleta de Arquivos a Verificar ---
        local -a actual_files_to_check=()
        for path in "${SUDOERS_PATHS_TO_CHECK[@]}"; do
            if [[ -f "$path" ]]; then
                actual_files_to_check+=("$path")
            elif [[ -d "$path" ]]; then
                mapfile -t -O "${#actual_files_to_check[@]}" actual_files_to_check < <(find "$path" -type f)
            fi
        done
        
        if ((${#actual_files_to_check[@]} == 0)); then
            log_warn "Nenhum arquivo de configuração do Sudo encontrado para verificar."
            return 0
        fi        
        # --- 2. Gerenciamento da Baseline ---
        if [[ ! -f "$SUDOERS_BASELINE_FILE" ]]; then
            log_info "Baseline para sudoers não encontrada, criando uma nova..."
            if sudo sha256sum "${actual_files_to_check[@]}" > "$SUDOERS_BASELINE_FILE" 2>/dev/null; then
                log_info "Nova baseline de integridade do Sudo criada com sucesso."
            else
                log_error "Falha ao criar a baseline de sudoers. Verifique as permissões."
                return 1 
            fi
            return 0 
        fi
        # --- 3. Verificação de Integridade ---
        if ! sudo sha256sum "${actual_files_to_check[@]}" > "$current_hashes_file" 2>/dev/null; then
            log_error "Não foi possível calcular os hashes atuais dos arquivos sudoers."
            return 1
        fi

        if ! diff -q "$SUDOERS_BASELINE_FILE" "$current_hashes_file" &>/dev/null; then
            add_alert_detail "Descrição" "A integridade de um ou mais arquivos de configuração do Sudo foi comprometida."
            add_alert_detail "Arquivo de Baseline" "$SUDOERS_BASELINE_FILE"
            add_alert_detail "Diferenças Encontradas" "$(diff -u "$SUDOERS_BASELINE_FILE" "$current_hashes_file")"
            log_alert "Modificação detectada nas configurações do Sudo" "CRÍTICO" "Elevação de Privilégio"
        fi
    )
    local exit_code=$?
    rm -f "$current_hashes_file"
    return "$exit_code"
}

# ==============================================================================
#           MÓDULO DE ANÁLISE DE LOGINS E ACESSO ANÔMALO
# ==============================================================================
_logins_check_service_accounts_interactive() {
    who | while read -r user line rest; do
        local uid; uid=$(id -u "$user" 2>/dev/null)
        if [[ -n "$uid" ]] && (( uid < 1000 && uid != 0 )); then
            add_alert_detail "Descrição" "Login interativo detectado em uma conta de serviço/sistema."
            add_alert_detail "Usuário de Serviço" "$user (UID: $uid)"
            add_alert_detail "Sessão (who)" "$user $line $rest"
            add_alert_detail "Remediação" "Encerre a sessão ('pkill -u $user') e configure o shell para '/sbin/nologin'."
            log_alert "Login suspeito em conta de serviço: $user" "CRÍTICO" "Acesso Anômalo (Serviço)"
        fi
    done
}

# --- Sub-função: Detectar usuários logados de múltiplos IPs ---
_logins_check_multiple_ips() {
    who | awk '
    {
        users[$1]++;
        gsub(/[()]/, "", $5); # Remove parênteses do IP
        ips[$1][$5] = 1;
    }
    END {
        for (user in users) {
            ip_count = 0;
            ip_list = "";
            for (ip in ips[user]) {
                ip_count++;
                ip_list = (ip_list ? ip_list ", " : "") ip;
            }
            if (ip_count > 1) {
                printf "%s|%s\n", user, ip_list;
            }
        }
    }' | while IFS='|' read -r user origins; do
        add_alert_detail "Descrição" "Usuário logado de múltiplos IPs, indicando possível compartilhamento/comprometimento de credenciais."
        add_alert_detail "Usuário" "$user"
        add_alert_detail "IPs de Origem" "$origins"
        log_alert "Usuário logado de múltiplas origens de IP: $user" "MÉDIO" "Acesso Anômalo (Múltiplos IPs)"
    done
}

# --- Sub-função: Verificar último login de contas de serviço importantes ---
_logins_check_service_accounts_lastlog() {
    if ! command -v lastlog &>/dev/null; then
        log_warn "'lastlog' não encontrado, pulando verificação de histórico de login de serviços."
        return
    fi
    
    for user in "${SERVICE_ACCOUNTS_TO_MONITOR[@]}"; do
        if ! id "$user" &>/dev/null; then continue; fi
        local lastlog_line; lastlog_line=$(lastlog -u "$user" 2>/dev/null | tail -n 1)
        if [[ -n "$lastlog_line" && ! "$lastlog_line" =~ \*\*Never\ logged\ in\*\* ]]; then
            add_alert_detail "Descrição" "Conta de serviço crítica registrou um login, um forte indicador de possível comprometimento."
            add_alert_detail "Usuário de Serviço" "$user"
            add_alert_detail "Registro (lastlog)" "$(echo "$lastlog_line" | awk '{$1=""; print $0}' | sed 's/^ *//')"
            add_alert_detail "Remediação" "Bloqueie a conta ('passwd -l $user') e configure o shell para '/sbin/nologin'."
            log_alert "Atividade detectada em conta de serviço inativa: $user" "CRÍTICO" "Acesso Anômalo (Serviço)"
        fi
    done
}

# --- Função Principal de Análise de Logins (Orquestradora) ---
check_user_logins() {
    log_info "  - Verificando logins interativos em contas de serviço..."
    _logins_check_service_accounts_interactive

    log_info "  - Verificando usuários logados de múltiplos IPs..."
    _logins_check_multiple_ips

    log_info "  - Verificando histórico de login de contas de serviço..."
    _logins_check_service_accounts_lastlog
}
# ==============================================================================
#           MÓDULO DE DETECÇÃO DE POSSÍVEIS WEB SHELLS
# ==============================================================================
find_web_shells() {
    touch "$WEB_SHELL_BASELINE_FILE"
    touch "$TIMESTOMP_BASELINE_FILE"
    local grep_pattern; grep_pattern=$(IFS='|'; echo "${WEB_SHELL_PATTERNS[*]}")
    local -a include_args=()
    for ext in "${WEB_SHELL_FILE_EXTENSIONS[@]}"; do
        include_args+=(--include="$ext")
    done

    for root in "${WEB_ROOT_DIRS[@]}"; do
        [[ ! -d "$root" ]] && continue
        grep -lriE --text "$grep_pattern" "${include_args[@]}" "$root" 2>/dev/null | while IFS= read -r suspicious_file; do
            local file_hash; file_hash=$(sha256sum "$suspicious_file" 2>/dev/null | awk '{print $1}')
            local baseline_key="$suspicious_file|$file_hash"
            if grep -Fxq "$baseline_key" "$WEB_SHELL_BASELINE_FILE"; then
                _common_check_timestomping "$suspicious_file"
                continue
            fi
            echo "$baseline_key" >> "$WEB_SHELL_BASELINE_FILE"

            add_alert_detail "Descrição" "Arquivo em diretório web contém padrão de código associado a web shells."
            add_alert_detail "Arquivo Suspeito" "$suspicious_file"
            add_alert_detail "Hash (SHA256)" "$file_hash"
            add_alert_detail "Padrões Detectados" "$(grep -iE --text "$grep_pattern" "$suspicious_file" | head -n 5)"
            add_alert_detail "Remediação" "Analise o arquivo. Se malicioso, coloque em quarentena e revise os logs de acesso do servidor web."
            
            log_alert "Possível web shell detectado: $suspicious_file" "CRÍTICO" "Web Shell"
            
            # --- 2. Integração: Verificações de Enriquecimento ---
            local yara_info; yara_info=$(_common_check_yara_scan "$suspicious_file")
            if [[ -n "$yara_info" ]]; then
                add_alert_detail "Arquivo" "$suspicious_file"
                add_alert_detail "Detalhes da Regra YARA" "$yara_info"
                log_alert "CONFIRMAÇÃO de Web Shell via YARA" "CRÍTICO" "Web Shell (YARA)"
            fi
            # 2b. Verificação de Timestomping
            _common_check_timestomping "$suspicious_file"
        done
    done
}
# ==============================================================================
#           MÓDULO DE VERIFICAÇÃO DE SEGURANÇA DE CONTAINERS DOCKER
# ==============================================================================
_docker_check_privileged() {
    local container_name="$1"
    local inspect_json="$2"
    for allowed_name in "${DOCKER_ALLOWLIST_CONTAINERS[@]}"; do
        [[ "$container_name" == "$allowed_name" ]] && return 0
    done
    if [[ "$(jq -r '.[0].HostConfig.Privileged' <<< "$inspect_json")" != "true" ]]; then
        return 0
    fi
    local baseline_key="$container_name|privileged"
    if grep -Fxq "$baseline_key" "$DOCKER_SECURITY_BASELINE_FILE"; then return 0; fi
    echo "$baseline_key" >> "$DOCKER_SECURITY_BASELINE_FILE"

    add_alert_detail "Descrição" "Container rodando em modo '--privileged', com acesso quase total ao host."
    add_alert_detail "Container" "$container_name"
    add_alert_detail "Remediação" "Evite '--privileged'. Use '--cap-add' para conceder capacidades específicas."
    log_alert "Container Docker rodando em modo privilegiado: $container_name" "CRÍTICO" "Docker Security (Privileged)"
}

# --- Sub-função: Verifica se o socket do Docker está montado ---
_docker_check_socket_mount() {
    local container_name="$1"
    local inspect_json="$2"
    for allowed_name in "${DOCKER_ALLOWLIST_CONTAINERS[@]}"; do
        [[ "$container_name" == "$allowed_name" ]] && return 0
    done
    if ! echo "$inspect_json" | jq -e --arg sock_path "$DOCKER_SOCKET_PATH" \
        '.[0].Mounts | any(.[]; .Source == $sock_path)' &>/dev/null; then
        return 0
    fi
    local baseline_key="$container_name|docker_socket"
    if grep -Fxq "$baseline_key" "$DOCKER_SECURITY_BASELINE_FILE"; then return 0; fi
    echo "$baseline_key" >> "$DOCKER_SECURITY_BASELINE_FILE"
    
    add_alert_detail "Descrição" "O socket do Docker do host está montado, permitindo o controle total do daemon Docker."
    add_alert_detail "Container" "$container_name"
    add_alert_detail "Caminho do Socket" "$DOCKER_SOCKET_PATH"
    add_alert_detail "Remediação" "Remova a montagem do socket. Use um proxy seguro para expor a API se necessário."
    log_alert "Container Docker com socket do Docker montado: $container_name" "CRÍTICO" "Docker Security (Socket Mount)"
}
check_docker_security() {
    if [[ "$DOCKER_ENABLED" != "true" || "$JQ_ENABLED" != "true" ]]; then
        log_debug "Docker ou jq não encontrado. Pulando verificação de segurança de containers."
        return 0
    fi

    touch "$DOCKER_SECURITY_BASELINE_FILE"

    docker ps -q | while read -r container_id; do
        local inspect_json; inspect_json=$(docker inspect "$container_id")
        local container_name; container_name=$(jq -r '.[0].Name' <<< "$inspect_json" | sed 's,^/,,')
        _docker_check_privileged "$container_name" "$inspect_json"
        _docker_check_socket_mount "$container_name" "$inspect_json"
    done
}

check_suspicious_commands() {
  # Salvaguardas
  if [[ -z "${COMMANDS_BASELINE_FILE:-}" ]]; then
      log_error "Var COMMANDS_BASELINE_FILE não definida."
      return 1
  fi
  if [[ -z "${COMMANDS_CHECK_SCRIPT:-}" || ! -f "$COMMANDS_CHECK_SCRIPT" ]]; then
      log_error "Motor Python 'command_check.py' não encontrado. Pulando verificação."
      return 1
  fi
  if ! declare -p SUSPICIOUS_COMMAND_PATTERNS &>/dev/null; then
      log_warn "Array 'SUSPICIOUS_COMMAND_PATTERNS' não definido. Pulando verificação."
      return 0
  fi
  if ! declare -p HISTORY_FILES_TO_CHECK &>/dev/null; then
      log_warn "Array 'HISTORY_FILES_TO_CHECK' não definido. Pulando verificação."
      return 0
  fi
  command -v jq >/dev/null      || { log_error "jq não encontrado."; return 1; }
  command -v python3 >/dev/null || { log_error "python3 não encontrado."; return 1; }

  local -a patterns=( "${SUSPICIOUS_COMMAND_PATTERNS[@]}" )
  local -a history=( "${HISTORY_FILES_TO_CHECK[@]}" )

  # Execução e Processamento
  set -o pipefail
  python3 -u "$COMMANDS_CHECK_SCRIPT" \
    --baseline-file "$COMMANDS_BASELINE_FILE" \
    --patterns "${patterns[@]}" \
    --history-files "${history[@]}" |
  while IFS= read -r alert_json; do
    [[ -z "$alert_json" ]] && continue

    local message risk_level check_type
    message=$(jq -r '.message // "Alerta"'              <<< "$alert_json")
    risk_level=$(jq -r '.risk_level // "desconhecido"'  <<< "$alert_json")
    check_type=$(jq -r '.check_type // "Histórico de Comandos"' <<< "$alert_json")

    # Detalhes em TSV (chave <TAB> valor)
    while IFS=$'\t' read -r key value; do
      [[ -n "$key" ]] && add_alert_detail "$key" "$value"
    done < <(jq -r '(.details // {}) | to_entries[] | [.key, (.value|tostring)] | @tsv' <<< "$alert_json")

    log_alert "$message" "$risk_level" "$check_type"
  done
  local ec=${PIPESTATUS[0]}
  set +o pipefail
  return "$ec"
}
# ==============================================================================
#           MÓDULO DE VERIFICAÇÃO DE ARQUIVOS COM ATRIBUTO DE IMUTABILIDADE (+i)
# ==============================================================================
check_immutable_files() {
    if [[ -z "${IMMUTABLE_FILES_BASELINE_FILE:-}" ]]; then
        log_error "Variável IMMUTABLE_FILES_BASELINE_FILE não definida. Pulando."
        return 1
    fi
    if ! declare -p IMMUTABLE_CRITICAL_DIRS &>/dev/null || ((${#IMMUTABLE_CRITICAL_DIRS[@]} == 0)); then
        log_warn "Array IMMUTABLE_CRITICAL_DIRS não definido ou vazio. Pulando verificação."
        return 0
    fi
    local _baseline="$IMMUTABLE_FILES_BASELINE_FILE"
    local _basedir
    _basedir=$(dirname -- "$_baseline")
    mkdir -p -- "$_basedir" 2>/dev/null || { log_error "Não foi possível criar diretório da baseline: $_basedir"; return 1; }
    touch -- "$_baseline" 2>/dev/null || { log_error "Não foi possível criar/acessar baseline: $_baseline"; return 1; }
    local allowlist_file="${IMMUTABLE_ALLOWLIST_FILE:-}"
    local have_allowlist=0
    [[ -n "$allowlist_file" && -r "$allowlist_file" ]] && have_allowlist=1

    # --- LÓGICA PRINCIPAL ---
    while IFS= read -r file; do
        [[ -n "$file" && -f "$file" ]] || continue
        if (( have_allowlist )) && grep -Fxq -- "$file" "$allowlist_file"; then
            continue
        fi
        if grep -Fxq -- "$file" "$_baseline"; then
            continue
        fi

        add_alert_detail "Descrição" "Arquivo em diretório de sistema crítico marcado como imutável (+i)."
        add_alert_detail "Arquivo Imutável" "$file"
        add_alert_detail "Proprietário" "$(stat -c '%U:%G' -- "$file" 2>/dev/null || echo 'N/A')"
        add_alert_detail "Permissões" "$(stat -c '%a' -- "$file" 2>/dev/null || echo 'N/A')"
        add_alert_detail "Remediação" "Verifique se este atributo foi definido intencionalmente. Se não, analise o arquivo e remova o atributo com: sudo chattr -i \"$file\"."
        log_alert "Arquivo imutável detectado: $(basename -- "$file")" "ALTO" "Evasão de Defesa (Imutabilidade)"
        printf '%s\n' "$file" >> "$_baseline" 2>/dev/null || log_warn "Falha ao gravar na baseline: $_baseline"
    done < <(
        LC_ALL=C find "${IMMUTABLE_CRITICAL_DIRS[@]}" -xdev -type f -print0 2>/dev/null \
        | xargs -0r lsattr -a -- 2>/dev/null \
        | awk '
            # Se o 1º campo (atributos) contém "i", imprime o caminho completo
            $1 ~ /i/ { $1=""; sub(/^ /,""); print }
          ' || true
    )

    return 0
}
# ==============================================================================
#           MÓDULO DE VERIFICAÇÃO DE HISTÓRICOS E PROCESSOS SUSPEITOS
# ==============================================================================
check_suspicious_commands() {
    # --- Salvaguardas ---
    if ! declare -p SUSPICIOUS_COMMAND_PATTERNS &>/dev/null; then
        log_warn "Array 'SUSPICIOUS_COMMAND_PATTERNS' não definido. Pulando verificação."; return 0;
    fi
    if [[ ! -f "$COMMANDS_CHECK_SCRIPT" ]]; then
        log_error "Motor de análise de comandos Python não encontrado. Pulando."; return 1;
    fi
    
    # --- Execução e Processamento ---
    python3 "$COMMANDS_CHECK_SCRIPT" \
        --baseline-file "$COMMANDS_BASELINE_FILE" \
        --patterns "${SUSPICIOUS_COMMAND_PATTERNS[@]}" \
        --history-files "${HISTORY_FILES_TO_CHECK[@]}" |
    while IFS= read -r alert_json; do
        [[ -z "$alert_json" ]] && continue
        local message risk_level check_type
        message=$(jq -r '.message' <<< "$alert_json")
        risk_level=$(jq -r '.risk_level' <<< "$alert_json")
        check_type=$(jq -r '.check_type' <<< "$alert_json")
        while IFS='=' read -r key value; do
            [[ -n "$key" ]] && add_alert_detail "$key" "$value"
        done < <(jq -r '.details | to_entries[] | "KATEX_INLINE_OPEN.key)=KATEX_INLINE_OPEN.value)"' <<< "$alert_json")
        log_alert "$message" "$risk_level" "$check_type"
    done
}

# ==============================================================================
#           MÓDULO DE VERIFICAÇÃO DE DETECÇÃO DE ROOTKIT
# ==============================================================================
find_anomalous_sockets() {
    if [[ "$SS_ENABLED" != "true" || "$LSOF_ENABLED" != "true" ]]; then
        log_debug "'ss' ou 'lsof' não encontrado. Pulando verificação de sockets anômalos."
        return 0
    fi
    if [[ "$EUID" -ne 0 ]]; then
        log_warn "A verificação de sockets anômalos requer privilégios de root. Pulando."
        return 1
    fi
    
    local ss_sockets_file lsof_sockets_file
    ss_sockets_file=$(mktemp)
    lsof_sockets_file=$(mktemp)
    trap 'rm -f "$ss_sockets_file" "$lsof_sockets_file"' RETURN

    touch "$SOCKET_ANOMALY_BASELINE_FILE"

    # --- 2. Coleta e Normalização de Dados ---
    declare -A ss_context_map=()
    ss -ltnp | tail -n +2 | while IFS= read -r line; do
        local socket users
        socket=$(echo "$line" | awk '{print $4}')
        users=$(echo "$line" | awk '{print $6}')
        local normalized_socket; normalized_socket=$(echo "$socket" | sed 's/\*:/0.0.0.0:/')
        ss_context_map["$normalized_socket"]="$users"
        echo "$normalized_socket" >> "$ss_sockets_file"
    done
    sort -u -o "$ss_sockets_file" "$ss_sockets_file" 
    lsof -nPiTCP -sTCP:LISTEN | tail -n +2 | awk '{print $9}' | sed -e 's/localhost/127.0.0.1/' -e 's/\*:/0.0.0.0:/' | sort -u > "$lsof_sockets_file"
    comm -23 "$ss_sockets_file" "$lsof_sockets_file" | while IFS= read -r socket; do
        if lsof -nPiTCP -sTCP:LISTEN | awk '{print $9}' | sed -e 's/localhost/127.0.0.1/' -e 's/\*:/0.0.0.0:/' | grep -qFx "$socket"; then
            log_debug "Discrepância de socket ('$socket') foi um falso positivo de race condition. Ignorando."
            continue
        fi

        local process_info="${ss_context_map[$socket]:-("pname=\"N/A\",pid=N/A")}"
        local process_name; process_name=$(echo "$process_info" | sed -n 's/.*pname="KATEX_INLINE_OPEN[^"]*KATEX_INLINE_CLOSE".*/\1/p')
        local pid; pid=$(echo "$process_info" | sed -n 's/.*pid=KATEX_INLINE_OPEN[0-9]*KATEX_INLINE_CLOSE.*/\1/p')
        [[ -z "$process_name" ]] && process_name="N/A"
        [[ -z "$pid" ]] && pid="N/A"
        local baseline_key="SocketDiscrepancy|ss_only|${process_name}|$socket"
        if grep -Fxq "$baseline_key" "$SOCKET_ANOMALY_BASELINE_FILE"; then continue; fi
        echo "$baseline_key" >> "$SOCKET_ANOMALY_BASELINE_FILE"

        add_alert_detail "Descrição" "Discrepância de socket confirmada: 'ss' listou um socket que 'lsof' não viu."
        add_alert_detail "Socket Anômalo" "$socket"
        add_alert_detail "Processo Associado (via 'ss')" "$process_name (PID: $pid)"
        add_alert_detail "Visto por" "'ss'"
        add_alert_detail "Não visto por" "'lsof' (mesmo após re-verificação)"
        add_alert_detail "Remediação" "Isole a máquina e realize uma análise forense completa."
        log_alert "Discrepância de Socket Confirmada: $socket (Processo: $process_name)" "CRÍTICO" "Rootkit (Socket)"
    done
}

# ==============================================================================
#           MÓDULO DE VERIFICAÇÃO DE MÓDULOS DO KERNEL (LKM)
# ==============================================================================
check_kernel_modules() {
    if [[ -z "${LKM_BASELINE_FILE:-}" ]]; then log_error "Var LKM_BASELINE_FILE não definida."; return 1; fi
    
    # --- Lógica Principal ---
    local current_modules_file; current_modules_file=$(mktemp)
    (
        set -e 
        
        lsmod | tail -n +2 | awk '{print $1}' | sort -u > "$current_modules_file"

        if [[ ! -f "$LKM_BASELINE_FILE" ]]; then
            log_info "Baseline de LKM não encontrada. Criando uma nova..."
            cp "$current_modules_file" "$LKM_BASELINE_FILE"
            return 0
        fi
        comm -13 "$LKM_BASELINE_FILE" "$current_modules_file" | while IFS= read -r module_name; do
            local path signer sha256
            path=$(modinfo -n "$module_name" 2>/dev/null || echo "built-in")
            signer=$(modinfo -F signer "$module_name" 2>/dev/null || echo "Não assinado")
            [[ -f "$path" ]] && sha256=$(sha256sum "$path" 2>/dev/null | awk '{print $1}') || sha256="N/A"
            
            local risk_level="ALTO"
            if [[ "$signer" == "Não assinado" ]]; then risk_level="CRÍTICO"; fi

            add_alert_detail "Descrição" "Módulo de kernel novo foi carregado."
            add_alert_detail "Módulo Novo" "$module_name"; add_alert_detail "Assinatura" "$signer"
            add_alert_detail "SHA256" "$sha256"; add_alert_detail "Caminho" "$path"
            log_alert "Módulo de Kernel novo/desconhecido: $module_name" "$risk_level" "Rootkit (LKM Adicionado)"
        done
        comm -23 "$LKM_BASELINE_FILE" "$current_modules_file" | while IFS= read -r module_name; do
            local ignore=false
            for ignored_module in "${LKM_REMOVAL_IGNORELIST[@]:-}"; do
                if [[ "$module_name" == "$ignored_module" ]]; then
                    ignore=true; log_debug "Módulo ausente '$module_name' na lista de ignorados."; break;
                fi
            done
            if [[ "$ignore" == true ]]; then continue; fi
            
            add_alert_detail "Descrição" "Módulo de kernel da baseline não está mais carregado."
            add_alert_detail "Módulo Ausente" "$module_name"
            log_alert "Módulo de Kernel ausente da baseline: $module_name" "BAIXO" "Impair Defenses (LKM Removido)"
        done
    )
    local exit_code=$?
    rm -f "$current_modules_file"

    return "$exit_code"
}

# ==============================================================================
#           MÓDULO DE VERIFICAÇÃO DE ARQUIVOS SUID/SGID SUSPEITOS
# ==============================================================================
find_suid_sgid_files() {
    if [[ -z "${SUID_SGID_BASELINE_FILE:-}" ]]; then
        log_error "Var SUID_SGID_BASELINE_FILE não definida."
        return 1
    fi
    if ! declare -p SUID_SGID_SEARCH_DIRS &>/dev/null; then
        log_warn "Array SUID_SGID_SEARCH_DIRS não definido."
        return 0
    fi

    local current_files_file
    current_files_file=$(mktemp) || { log_error "mktemp falhou"; return 1; }

    (

        LC_ALL=C find "${SUID_SGID_SEARCH_DIRS[@]}" -xdev -type f -perm /6000 -print 2>/dev/null \
          | LC_ALL=C sort > "$current_files_file" || true

        if [[ ! -f "$SUID_SGID_BASELINE_FILE" ]]; then
            log_info "Baseline para SUID/SGID não encontrada. Criando uma nova..."
            cp "$current_files_file" "$SUID_SGID_BASELINE_FILE" || { log_error "Falha ao criar baseline"; return 1; }
            return 0
        fi
        local baseline_sorted; baseline_sorted=$(mktemp) || { log_error "mktemp falhou"; return 1; }
        LC_ALL=C sort -u "$SUID_SGID_BASELINE_FILE" > "$baseline_sorted"

        comm -13 "$baseline_sorted" "$current_files_file" | while IFS= read -r new_file; do
            [[ ! -f "$new_file" ]] && continue

            local owner perms package_info risk_level
            owner=$(stat -c '%U:%G' "$new_file" 2>/dev/null || echo 'N/A')
            perms=$(stat -c '%A' "$new_file" 2>/dev/null || echo 'N/A')

            if check_binary_package "$new_file"; then
                package_info="Sim (provavelmente de atualização)"; risk_level="MÉDIO"
            else
                package_info="NÃO (ALTAMENTE SUSPEITO)"; risk_level="CRÍTICO"
            fi

            add_alert_detail "Descrição" "Novo arquivo com permissões SUID/SGID detectado."
            add_alert_detail "Arquivo Encontrado" "$new_file"
            add_alert_detail "Permissões" "$perms"
            add_alert_detail "Dono" "$owner"
            add_alert_detail "Pertence a Pacote do Sistema?" "$package_info"
            log_alert "Novo arquivo SUID/SGID suspeito: $new_file" "$risk_level" "Escalação de Privilégio (SUID/SGID)"
            local yara_info
            yara_info=$(_common_check_yara_scan "$new_file" 2>/dev/null || true)
            if [[ -n "$yara_info" ]]; then
                add_alert_detail "Arquivo" "$new_file"
                add_alert_detail "Regra YARA" "$yara_info"
                log_alert "CONFIRMAÇÃO de SUID/SGID malicioso via YARA" "CRÍTICO" "Escalação de Privilégio (YARA)"
            fi

            _common_check_timestomping "$new_file" || true
        done

        rm -f "$baseline_sorted" || true
    )
    local exit_code=$?

    rm -f "$current_files_file" || true
    if (( exit_code != 0 )); then
        log_debug "Normalizando exit_code ($exit_code) para 0: houve detecção, não erro."
        exit_code=0
    fi
    return "$exit_code"
}

# ==============================================================================
#           MÓDULO DE ANÁLISE DE LOGS DE FALHA DE AUTENTICAÇÃO
# ==============================================================================
_auth_check_ssh_bruteforce() {
    journalctl _SYSTEMD_UNIT=sshd.service --since "$AUTH_LOG_LOOKBACK_PERIOD" --no-pager --quiet |
      grep -i "Failed password for" |
      grep -oE 'from ([0-9a-fA-F:.]+)' | awk '{print $2}' |
      sort | uniq -c | sort -nr |
    while read -r count ip; do
        if (( count > AUTH_BRUTEFORCE_THRESHOLD )); then
            local day; day=$(date +%F)
            local baseline_key="BruteForceSSH|$day|$ip"
            if grep -Fxq "$baseline_key" "$AUTH_LOG_BASELINE_FILE"; then continue; fi
            echo "$baseline_key" >> "$AUTH_LOG_BASELINE_FILE"

            add_alert_detail "Descrição" "Múltiplas tentativas de login SSH falharam a partir do mesmo IP."
            add_alert_detail "IP de Origem" "$ip"
            add_alert_detail "Número de Tentativas" "$count (janela: $AUTH_LOG_LOOKBACK_PERIOD)"
            add_alert_detail "Remediação" "Bloqueie o IP (ex.: ufw deny from $ip) e considere 'fail2ban'."
            log_alert "Tentativa de brute-force SSH detectada do IP: $ip" "ALTO" "Ataque de Força Bruta"
        fi
    done
}

_auth_check_sudo_failures() {
    local since="$AUTH_LOG_LOOKBACK_PERIOD"
    local query_results; query_results=$(journalctl _EXE=/usr/bin/sudo --since "$since" --no-pager --quiet | grep -i "authentication failure.*USER=root" || true)
    local failure_count; failure_count=$(printf '%s\n' "$query_results" | sed '/^$/d' | wc -l)

    if (( failure_count > AUTH_SUDO_ROOT_FAILURE_THRESHOLD )); then
        local day; day=$(date +%F)
        local seen=0
        if [[ -f "$AUTH_LOG_BASELINE_FILE" ]]; then
            seen=$(awk -F'|' -v d="$day" -v n="$failure_count" '$1=="SudoRootFailures" && $2==d && $3>=n {print 1; exit}' "$AUTH_LOG_BASELINE_FILE")
        fi
        if [[ "$seen" != "1" ]]; then
            echo "SudoRootFailures|$day|$failure_count" >> "$AUTH_LOG_BASELINE_FILE"
            local users_involved
            users_involved=$(printf '%s\n' "$query_results" | grep -oP 'user=\K[[:alnum:]_.-]+' | sort -u | tr '\n' ' ')
            add_alert_detail "Descrição" "Múltiplas tentativas falhas de usar 'sudo' para se tornar 'root'."
            add_alert_detail "Número de Falhas" "$failure_count (janela: $since)"
            add_alert_detail "Usuários Envolvidos" "${users_involved:-N/A}"
            add_alert_detail "Remediação" "Investigue os usuários citados e endureça políticas de sudo."
            log_alert "Múltiplas falhas de 'sudo' para o usuário root detectadas" "MÉDIO" "Tentativa de Escalação"
        fi
    fi
}

_auth_check_invalid_users() {
    local since="$AUTH_LOG_LOOKBACK_PERIOD"
    local query_results; query_results=$(journalctl _SYSTEMD_UNIT=sshd.service --since "$since" --no-pager --quiet | grep -i "Invalid user" || true)
    local login_attempts; login_attempts=$(printf '%s\n' "$query_results" | sed '/^$/d' | wc -l)

    if (( login_attempts > AUTH_INVALID_USER_THRESHOLD )); then
        local day; day=$(date +%F)
        local baseline_key="InvalidUserLogins|$day"
        if grep -Fxq "$baseline_key" "$AUTH_LOG_BASELINE_FILE"; then return; fi
        echo "$baseline_key" >> "$AUTH_LOG_BASELINE_FILE"

        local top_users
        top_users=$(printf '%s\n' "$query_results" | grep -oP 'Invalid user \K[[:alnum:]_.-]+' | sort | uniq -c | sort -nr | head -n 5 | sed 's/^ *//' | tr '\n' '; ')
        add_alert_detail "Descrição" "Alto volume de tentativas de login SSH com usuários inexistentes."
        add_alert_detail "Número de Tentativas" "$login_attempts (janela: $since)"
        add_alert_detail "Top 5 Usuários Tentados" "${top_users:-N/A}"
        add_alert_detail "Remediação" "Indica varredura ativa. Desabilite senha no SSH e use chaves/2FA."
        log_alert "Alto volume de tentativas de login com usuários inválidos" "BAIXO" "Reconhecimento"
    fi
}

check_auth_failures() {
    if [[ "$JOURNALCTL_ENABLED" != "true" ]]; then
        log_debug "'journalctl' não encontrado. Pulando análise de logs de autenticação."
        return 0
    fi
    touch "$AUTH_LOG_BASELINE_FILE"

    log_info "  - Verificando logs de SSH por ataques de força bruta..."
    _auth_check_ssh_bruteforce

    log_info "  - Verificando logs por falhas de 'sudo' para root..."
    _auth_check_sudo_failures
    
    log_info "  - Verificando logs por tentativas de login com usuários inválidos..."
    _auth_check_invalid_users
}

# ==============================================================================
#           MÓDULO DE MONITORAMENTO DE INTEGRIDADE DE ARQUIVOS (FIM)
# ==============================================================================

load_hash_database() {
    if [[ "$HASH_DB_LOADED" == "true" ]]; then return 0; fi
    log_info "Carregando a baseline de hashes de arquivos para a memória..."

    if [[ ! -f "$HASH_DB_FILE" ]]; then
        log_warn "Arquivo de baseline de integridade ('$HASH_DB_FILE') não encontrado. Será criado ao final da execução."
        # Evite derrubar o fluxo com set -e; apenas logue e siga
        touch "$HASH_DB_FILE" || { log_error "FALHA AO CRIAR '$HASH_DB_FILE'."; return 0; }
    fi

    local delim=$'\x1f'
    (
        flock 200
        while IFS= read -r line; do
            [[ -z "$line" ]] && continue
            local path hash
            if [[ "$line" == *"$delim"* ]]; then
                IFS="$delim" read -r path hash <<< "$line"
            else
                # Compatibilidade com formato antigo: "hash path"
                hash="${line%% *}"; path="${line#* }"
            fi
            [[ -n "$path" && -n "$hash" ]] && HASH_BASELINE_DB["$path"]="$hash"
        done < "$HASH_DB_FILE"
    ) 200>"$HASH_DB_FILE.lock"

    HASH_DB_LOADED=true
    log_info "Baseline de hashes carregada. Itens na memória: ${#HASH_BASELINE_DB[@]}"
    return 0
}

save_hash_database() {
    # Nunca derrube o fluxo nesta fase — apenas logue
    if (( NEW_HASHES_ADDED == 0 )); then
        log_debug "Nenhum novo hash para salvar na baseline de integridade."
        return 0
    fi

    log_info "Salvando ${NEW_HASHES_ADDED} novo(s) hash(es) na baseline de integridade..."
    local delim=$'\x1f'
    local target="$HASH_DB_FILE"
    local dir; dir=$(dirname -- "$target")
    # temp no mesmo dir para evitar rename cross-device
    local temp_db
    temp_db=$(mktemp -p "$dir" ".hashdb.XXXXXX") || { log_error "mktemp falhou (dir='$dir')."; return 0; }

    {
        for path in "${!HASH_BASELINE_DB[@]}"; do
            printf '%s%s%s\n' "$path" "$delim" "${HASH_BASELINE_DB[$path]}"
        done
    } > "$temp_db" || { log_error "Falha ao escrever temp baseline '$temp_db'."; rm -f -- "$temp_db"; return 0; }

    local mv_ok=0
    (
        flock 200
        if mv -f -- "$temp_db" "$target"; then
            mv_ok=1
        fi
        exit 0
    ) 200>"$HASH_DB_FILE.lock" || true

    if (( mv_ok == 1 )); then
        log_info "Baseline de hashes de integridade atualizada com sucesso."
        NEW_HASHES_ADDED=0
    else
        log_warn "Não foi possível atualizar '$target' (lock ocupado ou erro de mv). Mantendo baseline anterior."
        rm -f -- "$temp_db"
    fi
    return 0
}

check_hash_integrity() {
    local file_path="$1"
    local pid="${2:-N/A}"
    if [[ -z "$file_path" || ! -r "$file_path" || -d "$file_path" ]]; then
        return 1
    fi

    local current_hash; current_hash=$(sha256sum "$file_path" 2>/dev/null | awk '{print $1}')
    [[ -z "$current_hash" ]] && return 1

    if [[ -v HASH_BASELINE_DB["$file_path"] ]]; then
        local baseline_hash="${HASH_BASELINE_DB[$file_path]}"
        if [[ "$current_hash" != "$baseline_hash" ]]; then
            add_alert_detail "Descrição" "Um arquivo importante foi modificado desde a última verificação."
            add_alert_detail "Arquivo Modificado" "$file_path"
            add_alert_detail "PID Associado" "$pid"
            add_alert_detail "Hash Esperado" "$baseline_hash"
            add_alert_detail "Hash Atual" "$current_hash"
            log_alert "Alteração de integridade de arquivo: $(basename "$file_path")" "CRÍTICO" "Integridade de Arquivo"
        fi
    else
        log_debug "Novo arquivo adicionado à baseline de hash em memória: $file_path"
        HASH_BASELINE_DB["$file_path"]="$current_hash"
        (( NEW_HASHES_ADDED++ ))
    fi
    return 0
}

# ==============================================================================
#           VERIFICA SE BINÁRIO ESTÁ EM DIRETÓRIOS SUSPEITOS
# ==============================================================================
is_from_suspect_dir() {
    local bin_path="$1"
    [[ -z "$bin_path" ]] && return 1
    local normalized_path
    normalized_path=$(realpath -s "$bin_path" 2>/dev/null)
    [[ -z "$normalized_path" ]] && return 1
    for dir in "${NORMALIZED_SUSPECT_DIRS[@]}"; do
        if [[ "$normalized_path" == "$dir"* ]]; then
            return 0 
        fi
    done
    return 1 
}

# ==============================================================================
#           VERIFICA SE ARQUIVO PERTENCE A UM PACOTE INSTALADO
# ==============================================================================
check_binary_package() {
    local file_path="$1"
    [[ -z "$file_path" || ! -e "$file_path" ]] && return 1
    if [[ -v _PACKAGE_INFO_CACHE["$file_path"] ]]; then
        return "${_PACKAGE_INFO_CACHE[$file_path]}"
    fi
    local result=1 
    case "$PKG_MANAGER" in
        pacman)
            if pacman -Qo "$file_path" &>/dev/null; then result=0; fi
            ;;
        dpkg)
            if dpkg -S "$file_path" &>/dev/null; then result=0; fi
            ;;
        rpm)
            if rpm -qf "$file_path" &>/dev/null; then result=0; fi
            ;;
        *)
            result=0
            ;;
    esac
    _PACKAGE_INFO_CACHE["$file_path"]="$result"
    return "$result"
}

# ==============================================================================
#           MÓDULO DE VERIFICAÇÃO DE SEGURANÇA DE WI-FI
# ==============================================================================
# ==============================================================================
#           MÓDULO DE VERIFICAÇÃO DE SEGURANÇA DE WI-FI
# ==============================================================================
check_wifi_security() {
    # Habilitar/desabilitar via .env
    if [[ "${WIFI_SCAN_ENABLED:-false}" != "true" ]]; then
        log_debug "Verificação de Wi-Fi desabilitada na configuração. Pulando."
        return 0
    fi

    # Motor Python disponível?
    if [[ -z "${WIFI_CHECK_SCRIPT:-}" || ! -f "$WIFI_CHECK_SCRIPT" ]]; then
        log_error "Motor de análise de Wi-Fi Python não encontrado em '$WIFI_CHECK_SCRIPT'. Pulando."
        return 1
    fi
    command -v python3 >/dev/null 2>&1 || { log_warn "python3 ausente. Pulando Wi‑Fi."; return 1; }
    command -v jq >/dev/null 2>&1      || { log_warn "jq ausente. Pulando Wi‑Fi."; return 1; }

    # Existe suporte Wi‑Fi neste host? (nmcli/iw/iwlist)
    local has_wifi=0
    if command -v nmcli >/dev/null 2>&1; then
        # Procura por dispositivos TYPE=wifi
        if nmcli -t -f TYPE device 2>/dev/null | grep -q '^wifi$'; then
            has_wifi=1
        fi
    elif command -v iw >/dev/null 2>&1 || command -v iwlist >/dev/null 2>&1; then
        has_wifi=1
    fi
    if (( has_wifi == 0 )); then
        log_debug "Nenhum dispositivo Wi‑Fi encontrado. Pulando verificação."
        return 0
    fi

    # Timeout configurável
    : "${WIFI_CHECK_TIMEOUT:=20s}"

    # Baseline
    mkdir -p -- "$(dirname -- "$WIFI_DEVICES_BASELINE_FILE")" 2>/dev/null || {
        log_error "Não foi possível criar diretório da baseline Wi‑Fi."
        return 1
    }

    local out_file err_file rc=0
    out_file=$(mktemp -t wifi_out.XXXXXX) || { log_error "mktemp falhou"; return 1; }
    err_file=$(mktemp -t wifi_err.XXXXXX) || { log_error "mktemp falhou"; rm -f -- "$out_file"; return 1; }

    # Executa motor com timeout (não travar o fluxo)
    if command -v timeout >/dev/null 2>&1; then
        if ! timeout --foreground "$WIFI_CHECK_TIMEOUT" \
             python3 "$WIFI_CHECK_SCRIPT" --baseline-file "$WIFI_DEVICES_BASELINE_FILE" \
             >"$out_file" 2>"$err_file"; then
            rc=$?
            if (( rc == 124 || rc == 137 )); then
                log_warn "Motor Wi‑Fi atingiu timeout (${WIFI_CHECK_TIMEOUT}). Prosseguindo sem travar."
            else
                log_warn "Motor Wi‑Fi retornou código $rc."
            fi
            if [[ -s "$err_file" ]]; then
                while IFS= read -r l; do log_warn "  wifi: $l"; done < <(sed -n '1,200p' "$err_file")
            fi
        fi
    else
        if ! python3 "$WIFI_CHECK_SCRIPT" --baseline-file "$WIFI_DEVICES_BASELINE_FILE" \
             >"$out_file" 2>"$err_file"; then
            rc=$?
            log_warn "Motor Wi‑Fi retornou código $rc (sem timeout disponível)."
            if [[ -s "$err_file" ]]; then
                while IFS= read -r l; do log_warn "  wifi: $l"; done < <(sed -n '1,200p' "$err_file")
            fi
        fi
    fi

    # Processa alertas (JSON por linha)
    local alert_json message risk_level check_type
    while IFS= read -r alert_json; do
        [[ -z "$alert_json" ]] && continue
        jq -e 'type=="object"' >/dev/null 2>&1 <<< "$alert_json" || continue

        message=$(jq -r '.message // "Sem mensagem."' <<< "$alert_json")
        risk_level=$(jq -r '.risk_level // "MÉDIO"' <<< "$alert_json")
        check_type=$(jq -r '.check_type // "Wi‑Fi"' <<< "$alert_json")

        # Detalhes: TSV seguro (sem travar)
        while IFS=$'\t' read -r key value; do
            [[ -n "$key" ]] && add_alert_detail "$key" "$value"
        done < <(jq -r '(.details // {}) | to_entries[] | [.key, ( .value|type=="string" ? .value : (.value|tojson) )] | @tsv' <<< "$alert_json")

        log_alert "$message" "$risk_level" "$check_type"
    done < "$out_file"

    rm -f -- "$out_file" "$err_file"
    return 0
}

# ==============================================================================
#           MÓDULO DE DETECÇÃO DE TÉCNICAS DE EVASÃO DE DEFESA
# ==============================================================================
_evasion_check_ld_preload() {
    local pid="$1" environ_file="/proc/$pid/environ"
    [[ -r "$environ_file" ]] && tr '\0' '\n' < "$environ_file" | grep -q '^LD_PRELOAD='
}
_evasion_check_memory_rwx() {
    local pid="$1" maps_file="/proc/$pid/maps"
    [[ -r "$maps_file" ]] && awk '$2 ~ /rwx/' "$maps_file" | grep -q .
}

_evasion_check_fileless_binary() {
    local exe_path="$1"
    [[ "$exe_path" == *" (deleted)"* ]]
}
check_defense_evasion_techniques() {
    if [[ "$LSOF_ENABLED" != "true" ]]; then
        log_debug "'lsof' não encontrado. Pulando verificação de técnicas de evasão."
        return 0
    fi

    touch "$DEFENSE_EVASION_BASELINE_FILE"

    # Lista objetos deletados ainda abertos (+L1) e analisa
    lsof +L1 -n 2>/dev/null | tail -n +2 | while IFS= read -r line; do
        local command pid user fd type name

        # Colunas fixas
        command=$(awk '{print $1}' <<< "$line")
        pid=$(awk '{print $2}' <<< "$line")
        user=$(awk '{print $3}' <<< "$line")
        fd=$(awk '{print $4}' <<< "$line")
        type=$(awk '{print $5}' <<< "$line")
        # NAME pode ter espaços: junta do 9º campo em diante
        name=$(awk '{s=""; for(i=9;i<=NF;i++){s=s (i>9?" ":"") $i} print s}' <<< "$line")

        # Considera apenas arquivos regulares
        [[ "$type" != "REG" ]] && continue

        # Evita alertas repetidos
        local baseline_key="DeletedFile|$command|$pid|$name"
        if grep -Fxq "$baseline_key" "$DEFENSE_EVASION_BASELINE_FILE"; then
            continue
        fi
        echo "$baseline_key" >> "$DEFENSE_EVASION_BASELINE_FILE"

        # Caminho do executável do processo
        local process_path
        process_path=$(readlink -f "/proc/$pid/exe" 2>/dev/null || echo "N/A")

        # Outros indicadores de evasão
        local -a other_indicators=()
        _common_check_process_masquerading "$command" "$process_path" && other_indicators+=("Mascaramento de Processo")
        _evasion_check_fileless_binary "$process_path" && other_indicators+=("Executável Deletado (Fileless)")
        _evasion_check_ld_preload "$pid" && other_indicators+=("LD_PRELOAD Hijacking")
        _evasion_check_memory_rwx "$pid" && other_indicators+=("Memória RWX")

        # Enriquecimento (rede + YARA)
        local network_info; network_info=$(_common_enrich_with_network_details "$pid")
        local yara_info;    yara_info=$(_common_check_yara_scan "$process_path" "$pid")

        # Detalhes do alerta
        add_alert_detail "Descrição" "Processo mantém um arquivo aberto que foi deletado do disco (técnica de evasão)."
        add_alert_detail "Processo" "$command (PID: $pid)"
        add_alert_detail "Usuário" "$user"
        add_alert_detail "Arquivo Apagado" "$name"
        add_alert_detail "Caminho do Executável" "$process_path"

        ((${#other_indicators[@]})) && add_alert_detail "Outros Indicadores de Evasão" "$(IFS=,; echo "${other_indicators[*]}")"
        add_alert_detail "Atividade de Rede" "$network_info"
        [[ -n "$yara_info" ]] && add_alert_detail "Análise YARA" "$yara_info"

        # Sanitiza FD para orientação de remediação
        local fd_num="${fd//[^0-9]/}"
        add_alert_detail "Remediação" "Inspecione '/proc/$pid/fd/${fd_num:-<fd>}' e investigue o processo."

        # Score de risco
        local risk_level="ALTO"
        if ((${#other_indicators[@]})) || [[ -n "$yara_info" ]]; then
            risk_level="CRÍTICO"
        fi

        log_alert "Técnica de evasão detectada: $command (PID: $pid)" "$risk_level" "Evasão de Defesa"
    done
}
# ==============================================================================
# DETECÇÃO DE TIMESTOMPING
# ==============================================================================
_common_check_timestomping() {
    local file_path="$1"
    [[ -r "$file_path" ]] || return 1

    local baseline_key="Timestomp|$file_path"
    if grep -Fxq "$baseline_key" "$TIMESTOMP_BASELINE_FILE" 2>/dev/null; then
        return 0
    fi

    local mtime ctime
    mtime=$(stat -c %Y -- "$file_path" 2>/dev/null || echo 0)
    ctime=$(stat -c %Z -- "$file_path" 2>/dev/null || echo 0)

    # Heurística: ctime > mtime por mais de 2s
    if (( mtime < ctime && (ctime - mtime) > 2 )); then
        # Ignora alguns diretórios de sistema ruidosos
        local d
        for d in "${TIMESTOMP_IGNORE_DIRS[@]}"; do
            [[ "$file_path" == "${d%/}/"* ]] && { log_debug "Ignorando potencial timestomping em: $file_path"; return 0; }
        done

        echo "$baseline_key" >> "$TIMESTOMP_BASELINE_FILE"

        add_alert_detail "Descrição" "Anomalia de timestamp detectada ('Timestomping')."
        add_alert_detail "Arquivo Suspeito" "$file_path"
        add_alert_detail "Modificação (mtime)" "$(date -d "@$mtime" 2>/dev/null || echo "$mtime")"
        add_alert_detail "Mudança (ctime)" "$(date -d "@$ctime" 2>/dev/null || echo "$ctime")"
        add_alert_detail "Remediação" "Investigue a origem e o propósito deste arquivo. A anomalia no timestamp sugere manipulação para evitar detecção."

        log_alert "Suspeita de 'Timestomping' no arquivo: $(basename -- "$file_path")" "ALTO" "Evasão de Defesa (Timestomp)"
    fi
    return 0
}

# ==============================================================================
#       ENRIQUECIMENTO DE ALERTA COM DETALHES DE REDE (REATORADO)
# ==============================================================================
_common_enrich_with_network_details() {
    local pid="$1"
    if ! [[ "$pid" =~ ^[0-9]+$ && -d "/proc/$pid" ]]; then
        echo "Nenhuma atividade de rede detectada."
        return
    fi
    
    local -a output_parts=()

    local connections; connections=$(ss -H -tnp "pid == $pid" 2>/dev/null)
    if [[ -n "$connections" ]]; then
        local formatted_conns="Conexões Ativas (ss):\n"
        formatted_conns+=$(echo "$connections" | awk '{printf "  - Local: %-21s | Remoto: %s\n", $4, $5}')
        output_parts+=("$formatted_conns")
    fi
    local dns_lookups; dns_lookups=$(lsof -p "$pid" -a -nPiUDP -sUDP:domain 2>/dev/null | \
        awk 'NR > 1 {gsub(/.*->|:domain/, "", $9); print $9}' | sort -u | tr '\n' ', ')
    
    dns_lookups="${dns_lookups%, }"
    if [[ -n "$dns_lookups" ]]; then
        output_parts+=("Consultas DNS (lsof): $dns_lookups")
    fi
    if ((${#output_parts[@]} > 0)); then
        printf "%s\n" "${output_parts[@]}"
    else
        echo "Nenhuma atividade de rede notável detectada."
    fi
}
# ==============================================================================
#           FUNÇÃO AUXILIAR COMUM: VERIFICAÇÃO COM YARA
# ==============================================================================
_common_check_yara_scan() {
    local target_path="${1:-}"
    local target_pid="${2:-}"

    # 1) Pré-verificações
    [[ "$YARA_SCAN_ENABLED" == "true" ]] || return 1
    [[ -n "$target_path" || -n "$target_pid" ]] || return 1

    local yara_output=""
    if [[ -n "$target_path" && -f "$target_path" ]]; then
        # Escaneia arquivo
        yara_output=$(timeout "$YARA_SCAN_TIMEOUT" \
                      yara "${YARA_SCAN_OPTS[@]}" "$YARA_RULES_FILE" "$target_path" 2>/dev/null)
    elif [[ -n "$target_pid" && "$EUID" -eq 0 ]]; then
        # Escaneia memória do processo (precisa de -p PID)
        yara_output=$(timeout "$YARA_SCAN_TIMEOUT" \
                      yara "${YARA_SCAN_OPTS[@]}" -p "$target_pid" "$YARA_RULES_FILE" 2>/dev/null)
    fi

    if [[ -n "$yara_output" ]]; then
        echo -e "YARA Match Encontrado:\n$yara_output"
        return 0
    fi
    return 1
}
# ==============================================================================
#           FUNÇÃO AUXILIAR COMUM: DETECÇÃO DE PROCESSOS MASCARADOS
# ==============================================================================
_common_enrich_with_network_details() {
    local pid="$1"
    if ! [[ "$pid" =~ ^[0-9]+$ && -d "/proc/$pid" ]]; then
        echo "Nenhuma atividade de rede detectada."
        return
    fi

    local -a output_parts=()

    # ss: filtra linhas que tenham pid=$pid
    local connections
    connections=$(ss -H -tnp 2>/dev/null | awk -v pid="$pid" '
        /users:KATEX_INLINE_OPENKATEX_INLINE_OPEN"/ {
            if (match($0, /pid=([0-9]+)/, m) && m[1] == pid) print
        }')
    if [[ -n "$connections" ]]; then
        local formatted="Conexões Ativas (ss):\n"
        # imprime Local | Remoto em colunas
        formatted+=$(echo "$connections" | awk '{printf "  - Local: %-22s | Remoto: %s\n", $4, $5}')
        output_parts+=("$formatted")
    fi

    # lsof: DNS (UDP domain)
    local dns_lookups
    dns_lookups=$(lsof -nPiUDP -sUDP:domain -p "$pid" 2>/dev/null \
                  | awk 'NR>1 {gsub(/.*->|:domain/,"",$9); if($9!="") print $9}' \
                  | sort -u | tr '\n' ', ')
    dns_lookups="${dns_lookups%, }"
    [[ -n "$dns_lookups" ]] && output_parts+=("Consultas DNS (lsof): $dns_lookups")

    if ((${#output_parts[@]})); then
        printf "%s\n" "${output_parts[@]}"
    else
        echo "Nenhuma atividade de rede notável detectada."
    fi
}

# ==============================================================================
#           FUNÇÃO AUXILIAR COMUM: DETECÇÃO DE PROCESSOS MASCARADOS
# ==============================================================================
_common_check_process_masquerading() {
    local comm="$1"     
    local exe_path="$2" 
    if [[ -z "$comm" || -z "$exe_path" || "$exe_path" == "N/A" ]]; then
        return 1 
    fi

    local filename; filename=$(basename "$exe_path")

    if [[ "$filename" != "$comm" && "$filename" != "$comm"* ]]; then
        for ignored_comm in "${MASQUERADING_IGNORELIST[@]}"; do
            if [[ "$comm" == "$ignored_comm" ]]; then
                log_debug "Ignorando potencial mascaramento para o interpretador '$comm' (binário: '$filename')."
                return 1 
            fi
        done
        
        return 0 
    fi

    return 1 
}

# ==============================================================================
#           GUIA INTERATIVO DE RESPOSTA A INCIDENTES
# ==============================================================================
list_alerts_with_pid() {
    local alert_file="${1:-$JSON_LOG_FILE}"

    if [[ -z "$alert_file" || ! -e "$alert_file" || ! -s "$alert_file" ]]; then
        echo -e "${C_YELLOW}Nenhum alerta encontrado em '${alert_file:-(não definido)}'.${C_RESET}"
        return 0
    fi

    if ! python3 "$ALERT_MANAGER_SCRIPT" list-for-ir "$alert_file"; then
        log_error "Falha ao listar alertas (list-for-ir)."
        return 1
    fi
}
# ==============================================================================
#           FUNÇÃO DE COLETA DE ARTEFATOS DE NAVEGADORES
# ==============================================================================
get_browser_artifacts_paths() {
    if (( $# < 1 )); then
        log_error "Uso: get_browser_artifacts_paths <array-ref>"
        return 2
    fi

    local -n _paths_ref="$1"
    _paths_ref=()  

    log_info "Coletando caminhos de artefatos de navegadores (motor Python)..."

    local out_file err_file rc
    out_file=$(mktemp -t artifacts_out.XXXXXX) || { log_error "mktemp falhou"; return 1; }
    err_file=$(mktemp -t artifacts_err.XXXXXX) || { log_error "mktemp falhou"; rm -f -- "$out_file"; return 1; }

    if ! python3 "$FIND_ARTIFACTS_SCRIPT" >"$out_file" 2>"$err_file"; then
        rc=$?
        log_warn "Motor de coleta falhou (exit $rc)."
        if [[ -s "$err_file" ]]; then
            sed -n '1,200p' "$err_file" | while IFS= read -r l; do log_warn "    $l"; done
        fi
        rm -f -- "$out_file" "$err_file"
        return "$rc"
    fi

    if LC_ALL=C grep -q $'\x00' "$out_file"; then
        mapfile -d $'\0' -t _paths_ref < "$out_file" || true
    else
        mapfile -t _paths_ref < "$out_file" || true
    fi

    rm -f -- "$out_file" "$err_file"

    if ((${#_paths_ref[@]})); then
        local -A _seen=()
        local -a _uniq=()
        local p
        for p in "${_paths_ref[@]}"; do
            [[ -z "$p" ]] && continue
            if [[ -z "${_seen[$p]:-}" ]]; then
                _seen["$p"]=1
                _uniq+=("$p")
            fi
        done
        _paths_ref=("${_uniq[@]}")
        log_info "Coleta concluída. Total de caminhos de artefatos únicos: ${#_paths_ref[@]}"
    else
        log_info "Nenhum artefato de navegador encontrado."
    fi
}

# ==============================================================================
#           MENU INTERATIVO DE EXTENSÕES E SEGURANÇA DE NAVEGADORES
# ==============================================================================
browser_extensions_menu() {
    local -a BROWSER_ALERT_TYPES=(
        "Extensão (Chromium)" "Extensão (Firefox)" "JavaScript Suspeito"
        "Preferência (Chromium)" "Preferência (Firefox)" "Native Messaging"
        "Web Shell"
    )

    while true; do
        clear
        echo -e "${C_CYAN}=== Menu de Segurança de Navegadores ===${C_RESET}"
        echo -e "\n  ${C_GREEN}1)${C_RESET} Resumo de Alertas de Navegador"
        echo -e "  ${C_GREEN}2)${C_RESET} Investigar por Tipo (apenas os presentes no log)"
        echo -e "  ${C_GREEN}3)${C_RESET} Mostrar Diretórios de Busca de Artefatos"
        echo -e "\n  ${C_YELLOW}q)${C_RESET} Voltar ao menu principal"

        read -rp "Escolha uma opção: " choice
        case "${choice,,}" in
            1)
                clear
                echo -e "\n${C_YELLOW}---[ Resumo de Alertas de Navegador ]---${C_RESET}"
                if ! python3 "$ALERT_MANAGER_SCRIPT" summarize-by-type "$JSON_LOG_FILE" "${BROWSER_ALERT_TYPES[@]}" \
                    | while IFS=$'\x1f' read -r tag key value; do
                        if [[ "$tag" == "HEADER" ]]; then
                            echo -e "\n${C_MAGENTA}Categoria: $key ($value alertas)${C_RESET}"
                        elif [[ "$tag" == "ALERT" ]]; then
                            echo "  - [Risco: $key] $value"
                        fi
                      done
                then
                    log_error "Falha ao gerar resumo de navegador."
                fi
                read -rp $'\n'"Pressione Enter para voltar..."
                ;;
            2)
                local -a all_types=()
                mapfile -t all_types < <(python3 "$ALERT_MANAGER_SCRIPT" list-types "$JSON_LOG_FILE" | awk -F'|' '{print $1}' || true)

                local -a menu_types=() t
                for t in "${BROWSER_ALERT_TYPES[@]}"; do
                    if printf '%s\n' "${all_types[@]}" | grep -Fxq -- "$t"; then
                        menu_types+=("$t")
                    fi
                done

                if ((${#menu_types[@]}==0)); then
                    echo -e "\n${C_GREEN}Nenhum alerta de navegador presente no log.${C_RESET}"
                    read -rp $'\n'"Pressione Enter para voltar..."
                    continue
                fi

                echo -e "\n${C_YELLOW}Tipos disponíveis:${C_RESET}"
                local i
                for i in "${!menu_types[@]}"; do
                    printf " ${C_GREEN}%d)${C_RESET} %s\n" "$((i+1))" "${menu_types[i]}"
                done

                read -rp "Selecione um tipo: " idx
                if [[ "$idx" =~ ^[0-9]+$ ]] && (( idx>=1 && idx<=${#menu_types[@]} )); then
                    alert_viewer "${menu_types[$((idx-1))]}"
                else
                    log_warn "Opção inválida."; sleep 1
                fi
                ;;
            3)
                clear
                echo -e "${C_CYAN}=== Diretórios Pesquisados por Artefatos de Navegador ===${C_RESET}"
                if ! python3 "$FIND_ARTIFACTS_SCRIPT" --list-search-dirs; then
                    log_warn "Falha ao obter diretórios de busca."
                fi
                read -rp $'\n'"Pressione Enter para voltar..."
                ;;
            q) break ;;
            *) log_warn "Opção inválida."; sleep 1 ;;
        esac
    done
}

# ==============================================================================
#           MENU PRINCIPAL INTERATIVO (HELPER DE RESPOSTA A INCIDENTES)
# ==============================================================================
# ==============================================================================
#           MENU PRINCIPAL INTERATIVO (HELPER DE RESPOSTA A INCIDENTES)
# ==============================================================================
incident_response_helper() {
    # Padrões “contém” (case-insensitive), com/sem acento
    local -a _browser_patterns=("extensão" "preferência" "javascript" "native" "native messaging" "cookie")
    # Inclui rede + autenticação + rootkit socket (e variações)
    local -a _network_patterns=(
        "rede exposta" "conexão externa" "conexao externa" "dnsbl" "whois" "whois policy"
        "acesso anômalo (serviço)" "acesso anomalo (servico)"
        "acesso anômalo (múltiplos ips)" "acesso anomalo (multiplos ips)"
        "ataque de força bruta" "ataque de forca bruta"
        "reconhecimento"
        "rootkit (socket)" "socket rootkit" "rootkit socket"
    )

    while true; do
        clear
        echo -e "${C_CYAN:-}#############################################${C_RESET:-}"
        echo -e "${C_CYAN:-}#     THREAT HUNTING & RESPONSE HELPER     #${C_RESET:-}"
        echo -e "${C_CYAN:-}#############################################${C_RESET:-}"

        if [[ ! -s "$JSON_LOG_FILE" ]]; then
            echo -e "\n${C_YELLOW:-}Nenhum alerta encontrado. Execute uma varredura primeiro.${C_RESET:-}"
            read -rp $'\n'"Pressione Enter para voltar..."
            return
        fi

        local out_file err_file rc=0
        out_file=$(mktemp -t mainmenu_out.XXXXXX) || { log_error "mktemp falhou"; return 1; }
        err_file=$(mktemp -t mainmenu_err.XXXXXX) || { log_error "mktemp falhou"; rm -f -- "$out_file"; return 1; }

        # Resumo por tipo via motor Python
        if ! python3 "$ALERT_MANAGER_SCRIPT" summarize-by-type "$JSON_LOG_FILE" >"$out_file" 2>"$err_file"; then
            rc=$?
            echo -e "\n${C_RED:-}ERRO: O motor de alertas Python falhou (exit: $rc).${C_RESET:-}"
            if [[ -s "$err_file" ]]; then sed -n '1,200p' "$err_file"; fi
            rm -f -- "$out_file" "$err_file"
            read -rp $'\n'"Pressione Enter para voltar..."
            return 1
        fi

        # Monta lista geral e marca menus especiais
        local -a gen_types=() gen_counts=()
        local has_browser=0 has_network=0
        local -i browser_total=0 network_total=0
        local tag t c lc_t

        # Primeira passada: classifica, soma contagens e filtra os tipos “especiais”
        while IFS=$'\x1f' read -r tag t c; do
            [[ "$tag" != "HEADER" ]] && continue
            [[ -z "$t" ]] && continue
            [[ -z "$c" ]] && c=0
            lc_t=${t,,}

            # Navegador
            local bp
            for bp in "${_browser_patterns[@]}"; do
                if [[ "$lc_t" == *"$bp"* ]]; then
                    has_browser=1
                    browser_total=$((browser_total + c))
                    t=""; break
                fi
            done
            [[ -z "$t" ]] && continue

            # Rede (inclui brute-force, múltiplos IPs, reconhecimento, rootkit socket)
            local np
            for np in "${_network_patterns[@]}"; do
                if [[ "$lc_t" == *"$np"* ]]; then
                    has_network=1
                    network_total=$((network_total + c))
                    t=""; break
                fi
            done
            [[ -z "$t" ]] && continue

            gen_types+=("$t")
            gen_counts+=("$c")
        done < "$out_file"

        # Segurança extra: reforça flags caso algum tenha passado batido
        if (( has_browser == 0 )); then
            while IFS=$'\x1f' read -r tag t c; do
                [[ "$tag" != "HEADER" ]] && continue
                lc_t=${t,,}
                local bp
                for bp in "${_browser_patterns[@]}"; do
                    if [[ "$lc_t" == *"$bp"* ]]; then has_browser=1; break; fi
                done
                (( has_browser )) && break
            done < "$out_file"
        fi
        if (( has_network == 0 )); then
            while IFS=$'\x1f' read -r tag t c; do
                [[ "$tag" != "HEADER" ]] && continue
                lc_t=${t,,}
                local np
                for np in "${_network_patterns[@]}"; do
                    if [[ "$lc_t" == *"$np"* ]]; then has_network=1; break; fi
                done
                (( has_network )) && break
            done < "$out_file"
        fi

        if [[ -s "$err_file" ]]; then
            log_warn "Mensagens do motor de alertas (stderr):"
            sed -n '1,200p' "$err_file"
        fi
        rm -f -- "$out_file" "$err_file"

        # Ordena alfabeticamente (case-insensitive)
        if ((${#gen_types[@]} > 1)); then
            local -a pairs=() sorted=()
            local i line
            for i in "${!gen_types[@]}"; do
                pairs+=("${gen_types[i]}|${gen_counts[i]}")
            done
            mapfile -t sorted < <(printf '%s\n' "${pairs[@]}" | LC_ALL=C sort -f)
            gen_types=(); gen_counts=()
            for line in "${sorted[@]}"; do
                gen_types+=("${line%%|*}")
                gen_counts+=("${line##*|}")
            done
        fi

        # Renderiza menu
        if ((${#gen_types[@]} == 0)); then
            echo -e "\n${C_GREEN:-}Nenhum alerta geral encontrado. Use os menus especializados.${C_RESET:-}"
        else
            echo -e "\n${C_YELLOW:-}Analisar Alertas por Categoria:${C_RESET:-}"
            local i
            for i in "${!gen_types[@]}"; do
                printf " ${C_GREEN:-}%d)${C_RESET:-} %s (%s)\n" "$((i + 1))" "${gen_types[i]}" "${gen_counts[i]}"
            done
        fi

        echo -e "\n${C_YELLOW:-}Ações Adicionais:${C_RESET:-}"
        (( has_browser )) && echo " a) Menu de Alertas de Navegador (${browser_total})"
        (( has_network )) && echo " n) Menu de Alertas de Rede (${network_total})"
        echo " t) Ver TODOS os alertas (sem filtro de categoria)"
        echo " r) Recarregar"
        echo -e "\n  ${C_YELLOW:-}q)${C_RESET:-} Sair"

        read -rp "Selecione uma categoria, um menu ou 'q': " choice

        case "${choice,,}" in
            q) return 0 ;;
            r) continue ;;
            a)
                if (( has_browser )); then
                    browser_extensions_menu
                else
                    log_warn "Não há alertas de Navegador no momento."; sleep 1
                fi
                ;;
            n)
                if (( has_network )); then
                    network_menu
                else
                    log_warn "Não há alertas de Rede no momento."; sleep 1
                fi
                ;;
            t) alert_viewer "todos" ;;
            *)
                if [[ "$choice" =~ ^[0-9]+$ ]] && (( choice >= 1 && choice <= ${#gen_types[@]} )); then
                    local selected_type="${gen_types[$((choice - 1))]}"
                    # Sanitiza o tipo (remove CR e espaços nas bordas) antes de enviar ao motor Python
                    selected_type="${selected_type//$'\r'/}"
                    selected_type="${selected_type#"${selected_type%%[![:space:]]*}"}"
                    selected_type="${selected_type%"${selected_type##*[![:space:]]}"}"
                    alert_viewer "$selected_type"
                else
                    log_warn "Opção inválida."; sleep 1
                fi
                ;;
        esac
    done
}
# ==============================================================================
#           MENU INTERATIVO DE ANÁLISE DE REDE
# ==============================================================================
_enable_network_trace() {
    (( DEBUG_NETWORK )) || return 0
    mkdir -p -- "$LOGS_DIR" 2>/dev/null || true
    exec 9>"$LOGS_DIR/network_menu.trace"
    export BASH_XTRACEFD=9
    export PS4='+ ${BASH_SOURCE##*/}:${LINENO}:${FUNCNAME[0]:-main}: '
    set -o errtrace
    trap '__dbg_err(){ local ec=$?; echo "ERR rc=$ec at ${BASH_SOURCE[1]}:${BASH_LINENO[0]} in ${FUNCNAME[1]}: ${BASH_COMMAND}" >&9; return $ec; }; __dbg_err' ERR
    set -x
}

_disable_network_trace() {
    (( DEBUG_NETWORK )) || return 0
    set +x
    trap - ERR
    exec 9>&-
    unset BASH_XTRACEFD
}

network_menu() {
    local -A _net_types_lc=(
        ["rede exposta"]=1
        ["conexão externa"]=1
        ["conexao externa"]=1
        ["dnsbl"]=1
        ["whois"]=1
        ["whois policy"]=1
    )

    while true; do
        clear
        echo -e "${C_BLUE}=== Menu de Análise de Rede ===${C_RESET}"
        local out_file err_file rc=0
        out_file=$(mktemp -t nettypes_out.XXXXXX) || { log_error "mktemp falhou"; return 1; }
        err_file=$(mktemp -t nettypes_err.XXXXXX) || { log_error "mktemp falhou"; rm -f -- "$out_file"; return 1; }

        if ! python3 "$ALERT_MANAGER_SCRIPT" list-types "$JSON_LOG_FILE" >"$out_file" 2>"$err_file"; then
            rc=$?
            echo -e "\n${C_RED}ERRO: Motor de alertas Python falhou (exit: $rc).${C_RESET}"
            if [[ -s "$err_file" ]]; then
                echo -e "${C_YELLOW}Detalhes (stderr):${C_RESET}"
                sed -n '1,200p' "$err_file"
            fi
            rm -f -- "$out_file" "$err_file"
            read -rp $'\n'"Pressione Enter para voltar..."
            return 1
        fi
        local -a available_types=()
        local -A seen=()
        local type_value lower

        while IFS='|' read -r type_value _; do
            [[ -z "$type_value" ]] && continue
            type_value=${type_value%$'\r'}
            lower=${type_value,,}
            if [[ -n "${_net_types_lc[$lower]:-}" ]] && [[ -z "${seen[$type_value]:-}" ]]; then
                seen["$type_value"]=1
                available_types+=("$type_value")
            fi
        done < "$out_file"
        if [[ -s "$err_file" ]]; then
            log_warn "Mensagens do motor de alertas (stderr):"
            sed -n '1,200p' "$err_file"
        fi
        rm -f -- "$out_file" "$err_file"

        if ((${#available_types[@]})); then
            mapfile -t available_types < <(printf '%s\n' "${available_types[@]}" | LC_ALL=C sort -f)
        fi

        if ((${#available_types[@]} == 0)); then
            echo -e "\n${C_YELLOW}Nenhum alerta de rede encontrado no log atual.${C_RESET}"
        else
            echo -e "\nSelecione uma categoria de alerta de rede para revisar:"
            local i
            for i in "${!available_types[@]}"; do
                printf "  ${C_GREEN}%d)${C_RESET} %s\n" "$((i + 1))" "${available_types[i]}"
            done
        fi

        echo -e "\nAções:"
        echo -e "  ${C_YELLOW}a)${C_RESET} Executar nova varredura de rede"
        echo -e "  ${C_YELLOW}t)${C_RESET} Ver TODOS os alertas de rede (sequencialmente por tipo)"
        echo -e "  ${C_YELLOW}q)${C_RESET} Voltar ao menu anterior"

        read -rp "Escolha uma opção: " choice
        case "${choice,,}" in
            a)
                log_info "Iniciando verificação de rede manual sob demanda..."
                _enable_network_trace

                local rc2=0
                if ! run_check "Verificação de Rede Manual" verificar_rede; then
                    rc2=$?
                    log_warn "Verificação de rede terminou com código $rc2 (continuando no menu)."
                fi

                _disable_network_trace

                read -rp "Verificação concluída. Pressione Enter para recarregar o menu..."
                continue
                ;;

            t)
                if ((${#available_types[@]} == 0)); then
                    echo -e "\n${C_YELLOW}Nenhum tipo de rede disponível para exibir.${C_RESET}"
                    read -rp $'\n'"Pressione Enter para voltar..."
                else
                    local t
                    for t in "${available_types[@]}"; do
                        alert_viewer "$t" || true
                    done
                fi
                ;;

            q)
                return 0
                ;;

            *)
                if [[ "$choice" =~ ^[0-9]+$ ]] && (( choice >= 1 && choice <= ${#available_types[@]} )); then
                    local selected_type="${available_types[$((choice - 1))]}"
                    alert_viewer "$selected_type"
                else
                    log_warn "Opção inválida."
                    sleep 1
                fi
                ;;
        esac
    done
}


# ==============================================================================
#           VISUALIZADOR DE ALERTAS (INTERFACE PARA O MOTOR PYTHON)
# ==============================================================================
alert_viewer() {
    local type_filter="${1:-todos}"   
    local page_size="${ALERTS_PAGE_SIZE:-10}"
    local page=0

    if ! [[ "$page_size" =~ ^[0-9]+$ ]] || (( page_size <= 0 )); then
        page_size=10
    fi

    : "${ALERT_VIEW_TIMEOUT:=10s}"

    if [[ ! -f "$ALERT_MANAGER_SCRIPT" ]]; then
        log_error "Motor de alertas Python não encontrado em '$ALERT_MANAGER_SCRIPT'."
        sleep 2
        return 1
    fi

    local had_e=0 had_u=0 had_pipe=0
    [[ $- == *e* ]] && had_e=1
    [[ $- == *u* ]] && had_u=1
    [[ "$(set -o | awk '$1=="pipefail"{print $2}')" == "on" ]] && had_pipe=1
    set +e
    set +u
    set +o pipefail 2>/dev/null
    trap - ERR 2>/dev/null || true

    while true; do
        local out_file err_file rc
        out_file=$(mktemp -t av_out.XXXXXX) || { log_error "mktemp falhou"; goto_restore; return 1; }
        err_file=$(mktemp -t av_err.XXXXXX) || { log_error "mktemp falhou"; rm -f -- "$out_file"; goto_restore; return 1; }

        if command -v timeout >/dev/null 2>&1; then
            if ! timeout "$ALERT_VIEW_TIMEOUT" \
                 python3 "$ALERT_MANAGER_SCRIPT" get-page "$JSON_LOG_FILE" "$type_filter" \
                         --page "$page" --page-size "$page_size" >"$out_file" 2>"$err_file"
            then
                rc=$?
                if (( rc == 124 || rc == 137 )); then
                    clear
                    echo -e "\n${C_RED:-}[Tempo limite]${C_RESET:-} Tempo de ${ALERT_VIEW_TIMEOUT} ao carregar a página."
                    rm -f -- "$out_file" "$err_file"
                    read -rp $'\n'"Pressione Enter para tentar novamente..."
                    continue
                fi
            else
                rc=0
            fi
        else
            if ! python3 "$ALERT_MANAGER_SCRIPT" get-page "$JSON_LOG_FILE" "$type_filter" \
                    --page "$page" --page-size "$page_size" >"$out_file" 2>"$err_file"
            then
                rc=$?
            else
                rc=0
            fi
        fi

        if (( rc != 0 )); then
            clear
            echo -e "\n${C_RED:-}Erro ao obter dados do motor de alertas (exit: $rc).${C_RESET:-}"
            if [[ -s "$err_file" ]]; then
                echo -e "${C_YELLOW:-}Detalhes (stderr):${C_RESET:-}"
                sed -n '1,200p' "$err_file"
            fi
            rm -f -- "$out_file" "$err_file"
            read -rp $'\n'"Pressione Enter para tentar novamente..."
            continue
        fi

        local header="" total_alerts=0 total_pages=0 items_on_page=0
        if ! IFS= read -r header < "$out_file"; then
            header=""
        fi

        if [[ -z "$header" ]]; then
            clear
            if [[ ! -s "$JSON_LOG_FILE" ]]; then
                echo -e "\n${C_YELLOW:-}O arquivo de log está vazio. Nenhum alerta para exibir.${C_RESET:-}"
            else
                echo -e "\n${C_RED:-}O motor de alertas Python não retornou dados.${C_RESET:-}"
            fi
            rm -f -- "$out_file" "$err_file"
            read -rp $'\n'"Pressione Enter para tentar novamente..."
            continue
        fi

        IFS=$'\x1f' read -r total_alerts total_pages items_on_page <<< "$header"
        [[ "$total_alerts" =~ ^[0-9]+$ ]] || total_alerts=0
        [[ "$total_pages"  =~ ^[0-9]+$ ]] || total_pages=0
        [[ "$items_on_page" =~ ^[0-9]+$ ]] || items_on_page=0

        if (( total_alerts == 0 )); then
            clear
            echo -e "\n${C_GREEN:-}Nenhum alerta encontrado para o filtro: '${type_filter}'${C_RESET:-}"
            rm -f -- "$out_file" "$err_file"
            read -rp "Pressione Enter..."
            goto_restore
            return 0
        fi

        if (( total_pages > 0 && page >= total_pages )); then
            page=$(( total_pages - 1 ))
            rm -f -- "$out_file" "$err_file"
            continue
        fi
        local -a current_alerts=()
        mapfile -t current_alerts < <(tail -n +2 -- "$out_file")
        rm -f -- "$out_file" "$err_file"
        clear
        echo -e "${C_BLUE:-}=======================================================================${C_RESET:-}"
        printf "${C_YELLOW:-}Exibindo Alertas de: %s${C_RESET:-}\n" "$type_filter"
        printf "Mostrando ${C_GREEN:-}%s${C_RESET:-} de ${C_GREEN:-}%s${C_RESET:-} alertas | Página ${C_CYAN:-}%d${C_RESET:-}/${C_CYAN:-}%s${C_RESET:-}\n" \
               "${items_on_page:-0}" "${total_alerts:-0}" "$((page + 1))" "${total_pages:-0}"
        echo -e "${C_BLUE:-}=======================================================================${C_RESET:-}"

        local i
        for i in "${!current_alerts[@]}"; do
            local pid msg check_type risk_level hostname timestamp full_json
            IFS=$'\x1f' read -r pid msg check_type risk_level hostname timestamp full_json <<< "${current_alerts[i]}"

            local rl_lc="${risk_level,,}"
            local risk_color="${C_YELLOW:-}"
            case "$rl_lc" in
                "crítico"|"critico") risk_color="${C_RED:-}" ;;
                "alto")               risk_color="${C_MAGENTA:-}" ;;
                "médio"|"medio")      risk_color="${C_YELLOW:-}" ;;
                "baixo")              risk_color="${C_GREEN:-}" ;;
            esac

            local formatted_date
            formatted_date=$(date -d"$timestamp" '+%d/%m/%Y %H:%M:%S' 2>/dev/null || echo "$timestamp")

            local alert_number=$((page * page_size + i + 1))
            printf "\n${C_GREEN:-}[%2d]${C_RESET:-} ${risk_color}[%s]${C_RESET:-} %s (${C_CYAN:-}%s${C_RESET:-})\n" \
                   "$alert_number" "$risk_level" "$check_type" "$formatted_date"
            printf "      ${C_WHITE:-}└─ %s${C_RESET:-}\n" "${msg:-Sem mensagem.}"
            printf "      ${C_GRAY:-}   (PID: %s | Host: %s)${C_RESET:-}\n" "${pid:-N/A}" "${hostname:-N/A}"
        done

        echo -e "\n${C_BLUE:-}-----------------------------------------------------------------------${C_RESET:-}"
        echo -e "Use ${C_YELLOW:-}n/p${C_RESET:-} (próxima/anterior), ${C_YELLOW:-}q${C_RESET:-} (voltar)."
        echo -e "Investigar: ${C_GREEN:-}d <nº>${C_RESET:-} (detalhes), ${C_GREEN:-}r <nº>${C_RESET:-} (remediar), ${C_GREEN:-}i <nº>${C_RESET:-} (ignorar)"
        read -rp "Comando: " input
        if [[ "$input" =~ ^(d|r|i)[[:space:]]+([0-9]+)$ ]]; then
            local command_type="${BASH_REMATCH[1]}"
            local alert_number="${BASH_REMATCH[2]}"
            local alert_index_global=$((alert_number - 1))

            if (( alert_index_global < 0 || alert_index_global >= total_alerts )); then
                log_warn "Número de alerta inválido."
                sleep 1
                continue
            fi
            local target_page=$((alert_index_global / page_size))
            if (( target_page != page )); then
                log_info "Carregando alerta #${alert_number} da página $((target_page + 1))..."
                page=$target_page
                sleep 0.4
                continue
            fi

            local alert_index_page=$((alert_index_global % page_size))
            local -a fields=()
            IFS=$'\x1f' read -r -a fields <<< "${current_alerts[alert_index_page]}"
            if (( ${#fields[@]} < 7 )); then
                log_warn "Formato inesperado do motor de alertas (campos insuficientes)."
                sleep 1
                continue
            fi

            local selected_full_json="${fields[6]}"
            local rc_action=0
            case "$command_type" in
                d)
                    ( set +e +u; set +o pipefail 2>/dev/null
                      _show_alert_details "$alert_number" "$selected_full_json"
                    )
                    rc_action=$?
                    (( rc_action != 0 )) && log_warn "Detalhes retornaram código $rc_action."
                    ;;
                r)
                    ( set +e +u; set +o pipefail 2>/dev/null
                      _show_remediation_menu "$alert_number" "$selected_full_json"
                    )
                    rc_action=$?
                    (( rc_action != 0 )) && log_warn "Remediação retornou código $rc_action."
                    ;;
                i)
                    ( set +e +u; set +o pipefail 2>/dev/null
                      _ignore_alert "$selected_full_json"
                    )
                    rc_action=$?
                    (( rc_action != 0 )) && log_warn "Ignorar retornou código $rc_action."
                    ;;
            esac
            read -rp $'\n'"Pressione Enter para voltar à lista de alertas..."
        else
            case "${input,,}" in
                n|next)
                    if (( page < total_pages - 1 )); then
                        ((page++))
                    else
                        log_warn "Já está na última página."
                        sleep 0.8
                    fi
                    ;;
                p|prev)
                    if (( page > 0 )); then
                        ((page--))
                    else
                        log_warn "Já está na primeira página."
                        sleep 0.8
                    fi
                    ;;
                q|quit)
                    break
                    ;;
                *)
                    log_warn "Comando inválido."
                    sleep 1
                    ;;
            esac
        fi
    done
    goto_restore:
    (( had_pipe )) && set -o pipefail || set +o pipefail 2>/dev/null
    (( had_e )) && set -e || set +e
    (( had_u )) && set -u || set +u
}
# ==============================================================================
#           FUNÇÃO AUXILIAR: EXIBIR DETALHES COMPLETOS DE UM ALERTA
# ==============================================================================
_show_alert_details() {
    local alert_number="$1"
    local alert_json="$2"

    clear
    echo -e "${C_YELLOW}================== Detalhes do Alerta #${alert_number} ==================${C_RESET}"

    if ! command -v jq >/dev/null 2>&1; then
        echo -e "${C_RED}jq não encontrado. Exibindo JSON bruto:${C_RESET}\n"
        printf '%s\n' "$alert_json"
        echo -e "\n${C_BLUE}=======================================================================${C_RESET}"
        return 0
    fi

    local DEL=$'\x1f'
    local meta_line
    meta_line=$(jq -r '
        [
          (.check_type // "N/A"),
          (.risk_level // "N/A"),
          (.timestamp  // "N/A"),
          (.hostname   // "N/A"),
          (.message    // "Sem mensagem.")
        ] | join("\u001f")
    ' <<< "$alert_json")

    local check_type risk_level timestamp hostname message
    IFS=$DEL read -r check_type risk_level timestamp hostname message <<< "$meta_line"

    local formatted_date
    formatted_date=$(date -u -d"$timestamp" '+%A, %d de %B de %Y, %H:%M:%S %Z' 2>/dev/null || echo "$timestamp")

    local rl_lc="${risk_level,,}"
    local risk_color="$C_YELLOW"
    case "$rl_lc" in
        "crítico"|"critico") risk_color="$C_RED" ;;
        "alto")               risk_color="$C_MAGENTA" ;;
        "médio"|"medio")      risk_color="$C_YELLOW" ;;
        "baixo")              risk_color="$C_GREEN" ;;
    esac

    printf "\n"
    printf " ${C_WHITE}%-15s:${C_RESET} %s\n"          "Tipo de Alerta" "$check_type"
    printf " ${C_WHITE}%-15s:${C_RESET} %b%s%b\n"      "Nível de Risco" "$risk_color" "$risk_level" "${C_RESET}"
    printf " ${C_WHITE}%-15s:${C_RESET} %s\n"          "Hostname"       "$hostname"
    printf " ${C_WHITE}%-15s:${C_RESET} %s\n"          "Data (UTC)"     "$formatted_date"
    printf " ${C_WHITE}%-15s:${C_RESET} %s\n"          "Mensagem"       "$message"

    echo -e "\n${C_YELLOW}----------------------- Informações Detalhadas ----------------------${C_RESET}\n"

    local had_details=0
    while IFS=$DEL read -r key value; do
        had_details=1
        if [[ "$value" == *$'\n'* ]]; then
            printf "  ${C_CYAN}%s:${C_RESET}\n%s\n" "$key" "$(echo "$value" | sed 's/^/    /')"
        else
            printf "  ${C_CYAN}%-25s:${C_RESET} %s\n" "$key" "$value"
        fi
    done < <(
        jq -r --arg DEL "$DEL" '
          # Sanitiza: remove KaTeX, espaços extras e pontuação nas pontas
          def sanitize:
            tostring
            | gsub("KATEX_[A-Z_]+(\\.[A-Za-z]+)?"; "")
            | gsub("\\s+"; " ")
            | gsub("^[[:space:][:punct:]]+"; "")
            | gsub("[[:space:][:punct:]]+$"; "");

          def to_text(x):
            if x == null then ""
            elif (x|type)=="string" or (x|type)=="number" or (x|type)=="boolean" then (x|tostring)
            else (x|tojson) end;

          # Só processa quando .details é objeto; gera pares já sanitizados
          if (.details|type=="object") then
            .details
            | to_entries[]
            | { k: (.key|sanitize), v: (to_text(.value)|sanitize) }
            # chave não vazia e valor não apenas pontuação/espaço
            | select(.k|length>0)
            | select((.v|length>0) and ((.v|test("^[[:space:][:punct:]]*$"))|not))
            | [ .k, .v ]
            | map(gsub("\u001f"; " "))  # protege o delimitador
            | join($DEL)
          else
            empty
          end
        ' <<< "$alert_json" 2>/dev/null
    )

    if (( ! had_details )); then
        echo "  Nenhum detalhe adicional disponível neste alerta."
    fi

    echo -e "\n${C_YELLOW}--------------------------- JSON Completo ---------------------------${C_RESET}\n"
    if [[ -t 1 ]]; then
        jq -C . <<< "$alert_json"
    else
        jq -M . <<< "$alert_json"
    fi

    echo -e "\n${C_BLUE}=======================================================================${C_RESET}"
}

# ==============================================================================
#           FUNÇÃO AUXILIAR COMUM: VERIFICA SE IP ESTÁ NA ALLOWLIST
# ==============================================================================
_common_is_ip_allowed() {
    local ip_to_check="$1"
    if [[ -z "$ip_to_check" ]]; then return 1; fi

    local -a cidr_list=()
    
    for entry in "${IP_ALLOWLIST[@]}"; do
        if [[ "$entry" == */* ]]; then
            cidr_list+=("$entry")
        elif [[ "$ip_to_check" == "$entry" ]]; then
            log_debug "IP '$ip_to_check' permitido por correspondência exata."
            return 0 
        fi
    done

    if ((${#cidr_list[@]} > 0)); then
        if python3 "$NET_IPCHECKER_SCRIPT" "$ip_to_check" "${cidr_list[@]}"; then
            log_debug "IP '$ip_to_check' permitido por regra CIDR (verificado por Python)."
            return 0 
        fi
    fi

    log_debug "IP '$ip_to_check' não encontrado na allowlist."
    return 1 
}

# ==============================================================================
#           BASE DE CONHECIMENTO E MENU DE REMEDIAÇÃO
# ==============================================================================

_format_command() {
    local RESET="${C_RESET:-$'\e[0m'}"
    local GRAY="${C_GRAY:-$'\e[90m'}"
    local CYAN="${C_CYAN:-$'\e[36m'}"
    [[ ! -t 1 ]] && RESET="" GRAY="" CYAN=""
    # Usa printf para evitar problemas do echo -e
    printf "    %s$ %s%s%s\n" "$GRAY" "$CYAN" "$*" "$RESET"
}

remediation_process() {
    local alert_json="$1"
    local pid
    pid=$(jq -r '(.details.PID // .details.pid // .details.process_id // empty)|tostring' <<< "$alert_json" 2>/dev/null \
          | sed 's/[^0-9].*$//')
    [[ "$pid" =~ ^[0-9]{2,}$ ]] || pid=""

    if [[ -n "$pid" ]]; then
        echo "  1. ${C_BOLD}Analisar o Processo:${C_RESET}"
        _format_command "ps -p $pid -o pid,ppid,uid,gid,cmd"
        _format_command "pstree -p $pid"
        _format_command "lsof -p $pid"

        echo "  2. ${C_BOLD}Inspecionar o Executável:${C_RESET}"
        _format_command "readlink -f /proc/$pid/exe"
        _format_command "sha256sum /proc/$pid/exe"
        _format_command "strings -n 8 /proc/$pid/exe | head -n 50"
    else
        echo "  1. ${C_BOLD}Coletar contexto do sistema:${C_RESET}"
        _format_command "ps aux --sort=-%cpu | head -n 20"
        _format_command "journalctl -p warning --since '-2h'"
    fi
}

remediation_web_shell() {
    local alert_json="$1"
    local file_path
    file_path=$(jq -r '.details["Arquivo Suspeito"] // .details["Arquivo Encontrado"] // empty' <<< "$alert_json")

    if [[ -z "$file_path" ]]; then
        echo "  1. ${C_BOLD}Verificar logs do servidor web:${C_RESET}"
        _format_command "tail -n 200 /var/log/nginx/access.log"
        _format_command "tail -n 200 /var/log/nginx/error.log"
        return 0
    fi

    echo "  1. ${C_BOLD}Inspecionar o Arquivo:${C_RESET}"
    _format_command "file -- '$file_path'"
    _format_command "stat -- '$file_path'"
    _format_command "sha256sum -- '$file_path'"
    _format_command "head -n 50 -- '$file_path'"

    echo "  2. ${C_BOLD}Analisar Logs de Acesso:${C_RESET}"
    _format_command "grep -F \"$(basename -- "$file_path")\" /var/log/nginx/access.log || true"

    echo "  3. ${C_BOLD}Busca de IOCs no arquivo:${C_RESET}"
    _format_command "grep -E \"cmd=|eval\KATEX_INLINE_OPEN|base64|assert\KATEX_INLINE_OPEN|passthru\KATEX_INLINE_OPEN|shell_exec\KATEX_INLINE_OPEN\" -- '$file_path' || true"
}

remediation_default() {
    echo "  - Investigue os detalhes do alerta e os logs do sistema relevantes."
    echo "  - Consulte a documentação do MITRE ATT&CK para a técnica identificada."
}

# ==============================================================================
#           GUIA DE REMEDIAÇÃO PARA UM ALERTA
# ==============================================================================
_show_remediation_menu() {
    local alert_number="$1"
    local alert_json="$2"

    clear
    echo -e "${C_YELLOW}=============== Guia de Remediação | Alerta #${alert_number} ===============${C_RESET}"
    if ! command -v jq >/dev/null 2>&1; then
        echo -e "${C_RED}jq não encontrado. Exibindo JSON bruto:${C_RESET}\n"
        printf '%s\n' "$alert_json"
        echo -e "\n${C_BLUE}=======================================================================${C_RESET}"
        return 0
    fi

    local DEL=$'\x1f'

    local meta_line
    meta_line=$(jq -r '
        [
          (.check_type // "N/A"),
          (.risk_level // "N/A"),
          (.hostname   // "N/A"),
          (.timestamp  // "N/A"),
          (.message    // "Sem mensagem.")
        ] | join("\u001f")
    ' <<< "$alert_json")

    local check_type risk_level hostname timestamp message
    IFS=$DEL read -r check_type risk_level hostname timestamp message <<< "$meta_line"

    local pid
    pid=$(jq -r '(.details.PID // .details.pid // .details.process_id // empty)|tostring' <<< "$alert_json" 2>/dev/null \
          | sed 's/[^0-9].*$//')
    [[ "$pid" =~ ^[0-9]{2,}$ ]] || pid=""

    local RESET="${C_RESET:-$'\e[0m'}"
    local BOLD="${C_BOLD:-$'\e[1m'}"
    local GRAY="${C_GRAY:-$'\e[90m'}"
    local WHITE="${C_WHITE:-$'\e[97m'}"
    local YELLOW="${C_YELLOW:-$'\e[33m'}"
    local MAGENTA="${C_MAGENTA:-$'\e[35m'}"
    local RED="${C_RED:-$'\e[31m'}"
    local GREEN="${C_GREEN:-$'\e[32m'}"
    local CYAN="${C_CYAN:-$'\e[36m'}"
    [[ ! -t 1 ]] && RESET="" BOLD="" GRAY="" WHITE="" YELLOW="" MAGENTA="" RED="" GREEN="" CYAN=""

    local rl_lc="${risk_level,,}"
    local risk_color="$YELLOW"
    case "$rl_lc" in
        "crítico"|"critico") risk_color="$RED" ;;
        "alto")               risk_color="$MAGENTA" ;;
        "médio"|"medio")      risk_color="$YELLOW" ;;
        "baixo")              risk_color="$GREEN" ;;
    esac

    local formatted_date
    formatted_date=$(date -u -d"$timestamp" '+%A, %d de %B de %Y, %H:%M:%S %Z' 2>/dev/null || echo "$timestamp")

    printf "\n"
    printf " %s%-17s:%s %s\n" "$WHITE" "Tipo de Alerta" "$RESET" "$check_type"
    printf " %s%-17s:%s %s%s%s\n" "$WHITE" "Nível de Risco" "$RESET" "$risk_color" "$risk_level" "$RESET"
    printf " %s%-17s:%s %s\n" "$WHITE" "Hostname" "$RESET" "$hostname"
    printf " %s%-17s:%s %s\n" "$WHITE" "Data (UTC)" "$RESET" "$formatted_date"
    printf " %s%-17s:%s %s\n" "$WHITE" "Mensagem" "$RESET" "$message"

    echo -e "\n${YELLOW}-------------------------- DIAGNÓSTICO E SUGESTÕES --------------------------${RESET}\n"

    printf "  1. %sIsolar a Máquina:%s\n" "$BOLD" "$RESET"
    echo   "     Se o risco for ALTO ou CRÍTICO, considere isolar a máquina da rede."
    printf "\n"
    printf "  2. %sAnalisar o Alerta:%s\n" "$BOLD" "$RESET"
    echo   "     Revise Detalhes e JSON Completo para entender o contexto."
    printf "\n"
    printf "  3. %sInvestigar Artefatos (se aplicável):%s\n" "$BOLD" "$RESET"
    echo   "     Colete binário, configs, logs relacionados ao alerta."

    echo -e "\n${YELLOW}--------------------------- SUGESTÕES ESPECÍFICAS ---------------------------${RESET}\n"
    if [[ -n "$pid" ]]; then
        remediation_process "$alert_json"
    elif [[ "${check_type,,}" =~ web[[:space:]]*shell ]]; then
        remediation_web_shell "$alert_json"
    else
        remediation_default
    fi

    echo -e "\n${YELLOW}-------------------------- AÇÕES AUTOMATIZADAS DISPONÍVEIS -------------------${RESET}\n"

    if [[ -n "$pid" && -d "/proc/$pid" ]]; then
        printf "  [k] Matar Processo (PID %s)  - Encerra o processo imediatamente (SIGKILL).\n" "$pid"
    else
        printf "  [k] Matar Processo           - %sIndisponível (sem PID válido)%s\n" "$GRAY" "$RESET"
    fi

    printf "\nSelecione uma ação ou pressione Enter para voltar: "
    local choice
    IFS= read -r choice

    case "${choice,,}" in
        ""|q|quit) return 0 ;;  
        k)
            if [[ -n "$pid" && -d "/proc/$pid" ]]; then
                read -rp "Confirmar kill -9 do PID $pid? [s/N] " ans
                if [[ "${ans,,}" =~ ^s ]]; then
                    if kill -9 "$pid" 2>/dev/null || sudo kill -9 "$pid" 2>/dev/null; then
                        echo -e "${GREEN}Processo $pid encerrado com sucesso.${RESET}"
                    else
                        echo -e "${RED}Falha ao encerrar o processo $pid (permissão ou já finalizado).${RESET}"
                    fi
                else
                    echo "Ação cancelada."
                fi
            else
                echo -e "${YELLOW}PID indisponível para esta remediação.${RESET}"
            fi
            ;;
        *) echo "Opção inválida." ;;
    esac

    return 0
}
# ==============================================================================
#           BASE DE CONHECIMENTO E MENU DE REMEDIAÇÃO
# ==============================================================================
_q() { printf '%q' "$1"; }

_format_command() {
    local RESET="${C_RESET:-$'\e[0m'}"
    local GRAY="${C_GRAY:-$'\e[90m'}"
    local CYAN="${C_CYAN:-$'\e[36m'}"
    [[ ! -t 1 ]] && RESET="" GRAY="" CYAN=""
    printf "    %s$ %s%s%s\n" "$GRAY" "$CYAN" "$*" "$RESET"
}

# ------------------------------------------------------------------------------
# GUIA DE REMEDIAÇÃO PADRÃO 
# ------------------------------------------------------------------------------
remediation_default() {
    local alert_json="$1"
    local pid path cmd
    pid=$(jq -r '(.details.PID // .details.pid // .details.process_id // empty)|tostring' <<< "$alert_json" 2>/dev/null \
          | sed 's/[^0-9].*$//')
    [[ "$pid" =~ ^[0-9]{2,}$ ]] || pid=""

    path=$(jq -r '.details["Arquivo Suspeito"] // .details["Arquivo Encontrado"] // .details["Caminho do Arquivo"] // empty' <<< "$alert_json")
    cmd=$(jq -r '.details["Linha de Comando"] // .details["Comando Encontrado"] // empty' <<< "$alert_json")

    echo "  1. ${C_BOLD}Isolar a Máquina:${C_RESET}"
    echo "     Se o risco for ALTO ou CRÍTICO, considere isolar a máquina da rede para conter a ameaça."
    echo
    echo "  2. ${C_BOLD}Analisar o Alerta:${C_RESET}"
    echo "     Revise todos os campos em 'Detalhes Adicionais' e 'JSON Completo' para entender o contexto."
    echo
    echo "  3. ${C_BOLD}Investigar Artefatos (se aplicável):${C_RESET}"

    if [[ -n "$path" ]]; then
        echo "     - Analise o arquivo:"
        _format_command "stat $(_q "$path")"
        _format_command "sha256sum $(_q "$path")  # (verificar no VirusTotal)"
        _format_command "file $(_q "$path")"
        _format_command "lsattr -a $(_q "$path")"
        _format_command "getcap $(_q "$path") 2>/dev/null || true"
    fi

    if [[ -n "$cmd" ]]; then
        echo "     - Investigue o comando:"
        _format_command "echo $(_q "$cmd")  # (analisar argumentos e ofuscação)"
    fi

    if [[ -n "$pid" && -d "/proc/$pid" ]]; then
        echo "     - Investigue o processo:"
        _format_command "ps -p $pid -o pid,ppid,uid,gid,cmd"
        _format_command "pstree -p $pid"
        _format_command "lsof -p $pid"
        _format_command "tr '\\0' ' ' < /proc/$pid/cmdline"
    fi
}

# ==============================================================================
#           BASE DE CONHECIMENTO DE REMEDIAÇÃO 
# ==============================================================================
remediation_netcat() {
    local alert_json="$1"
    local pid cmd
    pid=$(jq -r '(.details.PID // .details.pid // .details.process_id // empty)|tostring' <<< "$alert_json" 2>/dev/null \
          | sed 's/[^0-9].*$//')
    [[ "$pid" =~ ^[0-9]{2,}$ ]] || pid=""

    cmd=$(jq -r '.details["Linha de Comando"] // .details["Comando Encontrado"] // empty' <<< "$alert_json")

    echo "  ${C_BOLD}Ameaça:${C_RESET} Potencial Reverse Shell ou Exfiltração de Dados."
    echo
    echo "  1. ${C_BOLD}Analisar Conexões de Rede do Processo:${C_RESET}"
    if [[ -n "$pid" && -d "/proc/$pid" ]]; then
        _format_command "ss -tpn | grep -F \"pid=$pid,\" || true"
        _format_command "lsof -nP -a -p $pid -i"
    else
        echo "     PID não disponível para análise de rede."
        _format_command "ss -tpn"
    fi
    echo
    echo "  2. ${C_BOLD}Revisar Comando Completo:${C_RESET}"
    if [[ -n "$cmd" ]]; then
        _format_command "echo $(_q "$cmd")"
    else
        echo "     Comando não informado no alerta."
    fi
    echo
    echo "  3. ${C_BOLD}Ações Recomendadas:${C_RESET}"
    echo "     - Se conexão externa for confirmada, bloqueie o IP/destino temporariamente."
    echo "     - Use as opções do menu para encerrar o processo e/ou quarentenar o executável."
    if [[ -n "$pid" ]]; then
        echo "     - Investigue o processo pai e cadeia de execução."
        _format_command "pstree -p $pid"
    fi
}
remediation_tmp_execution() {
    local alert_json="$1"
    local file_path
    file_path=$(jq -r '.details["Arquivo Suspeito"] // .details["Arquivo Encontrado"] // .details["Caminho do Arquivo"] // empty' <<< "$alert_json")

    if [[ -z "$file_path" ]]; then
        echo "  ${C_YELLOW}Não foi possível determinar o arquivo exato para análise.${C_RESET}"
        return 0
    fi
    local tmp_hint=""
    case "$file_path" in
        /tmp/*|/var/tmp/*|/dev/shm/*|/run/*|/run/user/*) tmp_hint="(diretório temporário)" ;;
    esac

    echo "  ${C_BOLD}Ameaça:${C_RESET} Execução de arquivo em diretório temporário ${tmp_hint} (TTP: T1059.004)."
    echo
    echo "  1. ${C_BOLD}Analisar o Arquivo:${C_RESET}"
    echo "     O arquivo '${C_WHITE}$file_path${C_RESET}' está em um local incomum para executáveis."
    _format_command "stat $(_q "$file_path")"
    _format_command "file $(_q "$file_path")"
    _format_command "sha256sum $(_q "$file_path")  # (verificar hash no VirusTotal)"
    _format_command "lsattr -a $(_q "$file_path")"
    _format_command "getcap $(_q "$file_path") 2>/dev/null || true"
    _format_command "strings -n 8 $(_q "$file_path") | head -n 100"
    echo
    echo "  2. ${C_BOLD}Ações Recomendadas:${C_RESET}"
    echo "     - Determine como o arquivo foi criado/baixado (logs de rede, e-mail, downloads)."
    echo "     - Quarentenar: copie o arquivo e remova o executável original se for malicioso."
    _format_command "cp -a $(_q "$file_path") /root/quarantine/"
    _format_command "chmod 000 $(_q "$file_path")  # (bloquear execução)"
}

remediation_ssh_tunnel() {
    local alert_json="$1"

    local pid cmd
    pid=$(jq -r '(.details.PID // .details.pid // .details.process_id // empty)|tostring' <<< "$alert_json" 2>/dev/null | sed 's/[^0-9].*$//')
    [[ "$pid" =~ ^[0-9]{2,}$ ]] || pid=""

    cmd=$(jq -r '.details["Linha de Comando"] // .details["Comando Encontrado"] // empty' <<< "$alert_json")

    echo "  ${C_BOLD}Ameaça:${C_RESET} Potencial Túnel SSH para C2 ou Exfiltração de Dados."
    echo
    echo "  1. ${C_BOLD}Analisar o Comando:${C_RESET}"
    echo "     Revise o comando completo para identificar as portas e hosts envolvidos:"
    echo "     Comando: ${C_WHITE}${cmd:-(não informado)}${C_RESET}"
    echo
    echo "  2. ${C_BOLD}Verificar Conexões Ativas:${C_RESET}"
    if [[ -n "$pid" && -d "/proc/$pid" ]]; then
        _format_command "ss -tpn | grep -F \"pid=$pid,\" || true"
        _format_command "lsof -nP -a -p $pid -i"
    else
        echo "     PID não disponível para análise de conexões."
        _format_command "ss -tpn"
    fi
    echo
    echo "  3. ${C_BOLD}Ações Recomendadas:${C_RESET}"
    echo "     - Verifique se este túnel é uma atividade administrativa legítima."
    echo "     - Se não for autorizado, encerre o processo e revise as chaves SSH do usuário."
    [[ -n "$pid" ]] && _format_command "pstree -p $pid"
}

# --- Guia para Extensões de Navegador Suspeitas ---
remediation_browser_extension() {
    local alert_json="$1"
    local DEL=$'\x1f'
    local meta_line
    meta_line=$(jq -r '
        [
          (.details.extension_name // "desconhecida"),
          (.details.user           // "desconhecido"),
          (.details.browser        // "desconhecido"),
          (.details.extension_id   // "N/A")
        ] | join("\u001f")
    ' <<< "$alert_json")

    local ext_name user browser ext_id
    IFS=$DEL read -r ext_name user browser ext_id <<< "$meta_line"

    echo "  ${C_BOLD}Ameaça:${C_RESET} Extensão de Navegador Suspeita Detectada."
    echo
    echo "  - ${C_WHITE}Extensão:${C_RESET} '$ext_name' (ID: $ext_id)"
    echo "  - ${C_WHITE}Navegador:${C_RESET} $browser"
    echo "  - ${C_WHITE}Usuário:${C_RESET}   $user"
    echo
    echo "  1. ${C_BOLD}Investigar a Extensão:${C_RESET}"
    echo "     - Pesquise pela ID da extensão ('$ext_id') na loja oficial para verificar reputação."
    echo "     - Revise as permissões listadas nos detalhes do alerta."
    echo
    echo "  2. ${C_BOLD}Ações Recomendadas:${C_RESET}"
    echo "     - Se a extensão não for conhecida/necessária, remova-a imediatamente."
    echo "     - Após a remoção, considere limpar cookies e alterar senhas importantes."
    # Sugestões de caminhos comuns (opcional; com _q para segurança)
    case "${browser,,}" in
        *chromium*|*chrome*)
            _format_command "rm -rf $(_q "/home/$user/.config/chromium/Default/Extensions/$ext_id")"
            ;;
        *firefox*)
            echo "     - Para Firefox, remova do perfil em ~/.mozilla/firefox/<perfil>/extensions/"
            ;;
    esac
}
# --- Guia para Violações de Integridade de Arquivo ---
remediation_file_integrity() {
    local alert_json="$1"
    local DEL=$'\x1f'
    local line
    line=$(jq -r '
        [
          (.details["Arquivo Modificado"] // "desconhecido"),
          (.details["Hash Esperado"]     // "N/A"),
          (.details["Hash Atual"]        // "N/A")
        ] | join("\u001f")
    ' <<< "$alert_json")

    local file_path expected_hash current_hash
    IFS=$DEL read -r file_path expected_hash current_hash <<< "$line"

    echo "  ${C_BOLD}Ameaça:${C_RESET} Alteração de Integridade de Arquivo."
    echo
    echo "  - ${C_WHITE}Arquivo:${C_RESET} '$file_path'"
    echo "  - ${C_WHITE}Hash Esperado (Baseline):${C_RESET} $expected_hash"
    echo "  - ${C_WHITE}Hash Atual:${C_RESET}              $current_hash"
    echo
    echo "  1. ${C_BOLD}Verificar Legitimidade:${C_RESET}"
    echo "     - A mudança pode ter sido causada por uma atualização de sistema?"
    _format_command "dpkg -S $(_q "$file_path") 2>/dev/null || rpm -qf $(_q "$file_path") 2>/dev/null || pacman -Qo $(_q "$file_path") 2>/dev/null || true"
    echo "     - Verifique integridade pelo gerenciador de pacotes:"
    _format_command "debsums -s \$(dpkg -S $(_q "$file_path") | cut -d: -f1) 2>/dev/null || rpm -V \$(rpm -qf $(_q "$file_path")) 2>/dev/null || true"
    echo
    echo "  2. ${C_BOLD}Análise Adicional:${C_RESET}"
    _format_command "stat $(_q "$file_path")"
    _format_command "file $(_q "$file_path")"
    _format_command "sha256sum $(_q "$file_path")"
    _format_command "lsattr -a $(_q "$file_path")"
    _format_command "getcap $(_q "$file_path") 2>/dev/null || true"
    _format_command "strings -n 8 $(_q "$file_path") | head -n 100"
    echo
    echo "  3. ${C_BOLD}Ações Recomendadas:${C_RESET}"
    echo "     - Se a mudança não for autorizada, restaure o arquivo de um backup confiável."
    echo "     - Considere reinstalar o pacote do arquivo (mantendo configs) caso pertença a um pacote."
    _format_command "cp -a $(_q "$file_path") /root/quarantine/  # (quarentena)"
}

# --- Guia para Rootkits LKM (Módulo de Kernel) ---
remediation_lkm_rootkit() {
    local alert_json="$1"

    local module_name
    module_name=$(jq -r '.details["Módulo Novo"] // .details["Módulo Ausente"] // "desconhecido"' <<< "$alert_json")

    echo "  ${C_BOLD}Ameaça:${C_RESET} Potencial Rootkit de Kernel (LKM) Detectado."
    echo
    echo "  - ${C_WHITE}Módulo Suspeito:${C_RESET} '$module_name'"
    echo
    echo "  1. ${C_BOLD}Isolamento e Análise:${C_RESET}"
    echo "     - Isole a máquina da rede. Este é um alerta de altíssimo risco."
    echo "     - Verifique se o módulo está carregado:"
    _format_command "lsmod | awk 'NR>1{print \$1}' | grep -Fx -- $(_q "$module_name") || true"
    _format_command "test -d /sys/module/$(_q "$module_name") && ls -lah /sys/module/$(_q "$module_name") || true"
    _format_command "modinfo -n $(_q "$module_name") 2>/dev/null || true  # (caminho do .ko)"
    echo
    echo "  2. ${C_BOLD}Tentativa de Remoção:${C_RESET}"
    _format_command "sudo rmmod $(_q "$module_name")  # ou 'modprobe -r'"
    echo "     - Falhas ao descarregar aumentam a suspeita (hooks ativos)."
    echo
    echo "  3. ${C_BOLD}Ações Recomendadas:${C_RESET}"
    echo "     - Se a remoção falhar, conduza análise forense completa (memória e disco)."
    echo "     - Procure o arquivo do módulo em '/lib/modules/$(uname -r)/':"
    _format_command "find /lib/modules/\$(uname -r) -type f -name \"$module_name*.ko*\" -ls"
    _format_command "journalctl -k --since '-30m'  # (logs do kernel recentes)"
}

# --- Guia para Rootkits de Socket ---
remediation_socket_rootkit() {
    local alert_json="$1"

    local socket_info seen_by not_seen_by
    socket_info=$(jq -r '.details["Socket Anômalo"] // .details["Socket Anomalo"] // "desconhecido"' <<< "$alert_json")
    seen_by=$(jq -r '.details["Visto por"] // "?"' <<< "$alert_json")
    not_seen_by=$(jq -r '.details["Não visto por"] // .details["Nao visto por"] // "?"' <<< "$alert_json")

    echo "  ${C_BOLD}Ameaça:${C_RESET} Potencial Rootkit de Socket (inconsistência entre ferramentas)."
    echo
    echo "  - ${C_WHITE}Socket Anômalo:${C_RESET} '$socket_info'"
    echo "  - ${C_WHITE}Detectado por:${C_RESET}   $seen_by"
    echo "  - ${C_WHITE}Ocultado de:${C_RESET}    $not_seen_by"
    echo
    echo "  1. ${C_BOLD}Confirmação e Análise:${C_RESET}"
    echo "     - Compare múltiplas fontes para confirmar a anomalia:"
    _format_command "ss -Hltunap | grep -F -- $(_q "$socket_info") || true"
    _format_command "lsof -nPi | grep -F -- $(_q "$socket_info") || true"
    _format_command "netstat -ltunap 2>/dev/null | grep -F -- $(_q "$socket_info") || true"
    echo "     - Se tiver o PID/porta, verifique também /proc:"
    _format_command "grep -R \"$(printf %q "$socket_info")\" /proc/net/ 2>/dev/null || true"
    echo
    echo "  2. ${C_BOLD}Ações Recomendadas:${C_RESET}"
    echo "     - Se a inconsistência persistir, a probabilidade de rootkit é alta."
    echo "     - Isole a máquina e proceda com análise forense (memória e disco)."
}
# --- Guia para Redes Expostas ---
remediation_exposed_network() {
    local alert_json="$1"
    local DEL=$'\x1f' meta endpoint pid proto
    meta=$(jq -r '
        [
          (.details["Endpoint de Escuta"] // .details.Endpoint // "N/A"),
          (.details.PID // ""),
          ((.details.Protocolo // "tcp") | ascii_downcase)
        ] | join("\u001f")
    ' <<< "$alert_json")
    IFS=$DEL read -r endpoint pid proto <<< "$meta"
    local ip_address="N/A" port="N/A"
    if [[ -n "$endpoint" && "$endpoint" != "N/A" ]]; then
        if [[ "$endpoint" =~ ^```math
(.+)```:(.+)$ ]]; then
            ip_address="${BASH_REMATCH[1]}"
            port="${BASH_REMATCH[2]}"
        elif [[ "$endpoint" =~ ^([^:]+):([0-9]+)$ ]]; then
            ip_address="${BASH_REMATCH[1]}"
            port="${BASH_REMATCH[2]}"
        elif [[ "$endpoint" =~ ^\*:(.+)$ ]]; then
            ip_address="*"
            port="${BASH_REMATCH[1]}"
        elif [[ "$endpoint" =~ ^:::(.+)$ ]]; then
            ip_address="::"
            port="${BASH_REMATCH[1]}"
        elif [[ "$endpoint" =~ ^[0-9]+$ ]]; then
            ip_address="0.0.0.0"
            port="$endpoint"
        fi
    fi

    echo "  ${C_BOLD}Ameaça:${C_RESET} Porta de Rede Exposta Inadvertidamente."
    echo
    echo "  - ${C_WHITE}Endpoint:${C_RESET} '$endpoint'"
    echo "  - ${C_WHITE}IP/Host:${C_RESET}  '$ip_address'"
    echo "  - ${C_WHITE}Porta:${C_RESET}    '$port'"
    echo "  - ${C_WHITE}PID:${C_RESET}      '${pid:-N/A}'"
    echo "  - ${C_WHITE}Proto:${C_RESET}    '${proto:-tcp}'"
    echo
    echo "  1. ${C_BOLD}Identificar o Serviço:${C_RESET}"
    _format_command "ps -p ${pid:-0} -o pid,user,comm,cmd --forest"
    _format_command "readlink -f /proc/${pid:-0}/exe 2>/dev/null || true"
    _format_command "sha256sum /proc/${pid:-0}/exe 2>/dev/null || true"
    command -v systemctl >/dev/null 2>&1 && _format_command "systemctl status ${pid:-0} 2>/dev/null || true"
    echo
    echo "  2. ${C_BOLD}Verificar a Escuta (Bind):${C_RESET}"
    _format_command "ss -ltnup | grep -F \":$port\" || true"
    [[ -n "$pid" ]] && _format_command "ss -ltnup | grep -F \"pid=$pid,\" || true"
    _format_command "lsof -nP -i ${proto^^}:$port | grep LISTEN || true"
    echo
    echo "  3. ${C_BOLD}Ações Recomendadas:${C_RESET}"
    echo "     - ${C_YELLOW}Se malicioso:${C_RESET} encerre o processo e remova persistência."
    echo "     - ${C_YELLOW}Se legítimo mas não deve estar exposto:${C_RESET} reconfigure para escutar apenas em 127.0.0.1 ou [::1]."
    echo "     - ${C_YELLOW}Bloqueio temporário no firewall:${C_RESET}"
    _format_command "sudo ufw deny $port/$proto            # (se UFW estiver em uso)"
    _format_command "sudo firewall-cmd --add-port=$port/$proto --zone=block --permanent && sudo firewall-cmd --reload  # firewalld"
    _format_command "sudo nft add rule inet filter input ${proto,,} dport $port drop  # nftables"
    _format_command "sudo iptables -A INPUT -p ${proto,,} --dport $port -j DROP      # iptables (legacy)"
}

# --- Guia para Alertas de Escalação de Privilégio ---
remediation_privilege_escalation() {
    local alert_json="$1"

    local file_path check_type lc
    file_path=$(jq -r '.details["Arquivo Encontrado"] // .details["Arquivo Modificado"] // empty' <<< "$alert_json")
    check_type=$(jq -r '.check_type // ""' <<< "$alert_json")
    lc="${check_type,,}"

    echo "  ${C_BOLD}Ameaça:${C_RESET} Potencial Escalação de Privilégio."
    echo
    echo "  - ${C_WHITE}Vetor Detectado:${C_RESET} $check_type"
    echo "  - ${C_WHITE}Arquivo Afetado:${C_RESET} '${file_path:-desconhecido}'"
    echo
    echo "  1. ${C_BOLD}Contenção Imediata:${C_RESET}"
    echo "     - Considere isolar a máquina para prevenir movimento lateral."
    echo
    echo "  2. ${C_BOLD}Análise do Artefato:${C_RESET}"

    if [[ -n "$file_path" ]]; then
        _format_command "stat $(_q "$file_path")"
        _format_command "file $(_q "$file_path")"
        _format_command "sha256sum $(_q "$file_path")"
        _format_command "lsattr -a $(_q "$file_path")"
        _format_command "getcap $(_q "$file_path") 2>/dev/null || true"
        _format_command "dpkg -S $(_q "$file_path") 2>/dev/null || rpm -qf $(_q "$file_path") 2>/dev/null || pacman -Qo $(_q "$file_path") 2>/dev/null || true"
    fi

    if [[ "$lc" == *"suid/sgid"* ]]; then
        echo "     - Novo binário SUID/SGID pode ser backdoor."
        _format_command "find / -xdev -type f -perm /6000 -printf '%p %m %u:%g\n' 2>/dev/null | sort"
    elif [[ "$lc" == *"sudo"* ]]; then
        echo "     - Verifique configurações do sudo/sudoers."
        _format_command "sudo visudo -c"
        _format_command "sudo -l -U \"\$(stat -c '%U' $(_q "$file_path") 2>/dev/null || echo \"usuário\")\" 2>/dev/null || true"
        _format_command "grep -R \"NOPASSWD\\|!authenticate\" /etc/sudoers /etc/sudoers.d 2>/dev/null || true"
        _format_command "diff -u <(cat_backup $(_q "$file_path")) $(_q "$file_path")  # ajuste 'cat_backup' ao seu ambiente"
    fi

    echo
    echo "  3. ${C_BOLD}Ações Recomendadas:${C_RESET}"
    echo "     - Se mudança maliciosa, restaure de backup confiável ou remova o binário malicioso."
    echo "     - Revise logs de auditoria para atribuir autoria:"
    _format_command "journalctl -u sudo --since '-24h' 2>/dev/null || true"
    _format_command "grep -iE 'sudo|su:|authentication failure' /var/log/auth.log 2>/dev/null || true"
}

# ==============================================================================
#           FUNÇÃO PRINCIPAL DE ANÁLISE DE PROCESSOS EM EXECUÇÃO
# ==============================================================================
_process_is_float_greater() {
    awk -v v1="$1" -v v2="$2" 'BEGIN {exit !(v1 > v2)}'
}
_process_add_risk() {
    local -n _risk_ref="$1"; local -n _reasons_ref="$2"
    local score_to_add="$3"; local reason_text="$4"
    _risk_ref=$((_risk_ref + score_to_add))
    _reasons_ref+=("$reason_text")
}

analyze_top_processes() {
    while IFS= read -r pid user cpu mem comm; do
        if [[ ! -d "/proc/$pid" ]]; then continue; fi
        
        local path cmd
        path=$(readlink -f "/proc/$pid/exe" 2>/dev/null || echo "N/A")
        cmd=$(tr '\0' ' ' < "/proc/$pid/cmdline" 2>/dev/null || echo "$comm")

        printf "${C_GRAY}[ANALISANDO]${C_RESET} PID: %-7s (%s)\r" "$pid" "$comm"

        local risk=0; declare -a risk_reasons=()
        
        local cpu_float=${cpu//,/.}; local mem_float=${mem//,/.};
        if _process_is_float_greater "$cpu_float" "$CPU_THRESHOLD"; then _process_add_risk risk risk_reasons 2 "Alto uso de CPU (${cpu}%)"; fi
        if _process_is_float_greater "$mem_float" "$MEM_THRESHOLD"; then _process_add_risk risk risk_reasons 2 "Alto uso de Memória (${mem}%)"; fi
        
        if ! check_binary_package "$path"; then _process_add_risk risk risk_reasons 6 "Binário não pertence a pacote"; fi
        if is_from_suspect_dir "$path"; then _process_add_risk risk risk_reasons 8 "Executando de diretório suspeito"; fi
        if _common_check_process_masquerading "$comm" "$path"; then _process_add_risk risk risk_reasons 15 "Mascaramento de Processo"; fi
        
        if _evasion_check_fileless_binary "$path"; then _process_add_risk risk risk_reasons 10 "Execução 'fileless'"; fi
        if _evasion_check_ld_preload "$pid"; then _process_add_risk risk risk_reasons 10 "Uso de LD_PRELOAD"; fi
        if _evasion_check_memory_rwx "$pid"; then _process_add_risk risk risk_reasons 8 "Memória RWX"; fi
        
        _common_check_timestomping "$path"
        check_hash_integrity "$path" "$pid"
        
        local yara_info; yara_info=$(_common_check_yara_scan "$path" "$pid")
        if [[ -n "$yara_info" ]]; then _process_add_risk risk risk_reasons 12 "Detecção por YARA"; fi

        if (( risk >= RISK_THRESHOLD )); then
            local risk_level="ALTO"
            if (( risk > 14 )) || [[ -n "$yara_info" ]] || [[ "${risk_reasons[*]}" =~ (Mascaramento|fileless) ]]; then
                risk_level="CRÍTICO"
            fi
            
            add_alert_detail "PID" "$pid"; add_alert_detail "Usuário" "$user"
            add_alert_detail "Score de Risco" "$risk (Limiar: $RISK_THRESHOLD)"
            add_alert_detail "Motivos" "$(IFS=,; echo "${risk_reasons[*]}")"
            add_alert_detail "Caminho do Executável" "$path"
            add_alert_detail "Comando Completo" "$cmd"
            if [[ -n "$yara_info" ]]; then add_alert_detail "Análise YARA" "$(head -c 1024 <<< "$yara_info")"; fi
            add_alert_detail "Atividade de Rede" "$(_common_enrich_with_network_details "$pid")"

            log_alert "Processo com alto score de risco detectado ($comm)" "$risk_level" "Análise de Processo"
        fi

    done < <(ps -eo pid,user,%cpu,%mem,comm --sort=-%cpu,-%mem | tail -n +2 | head -n "$TOP_N")

    echo -ne "\033[2K\r"
}
# ==============================================================================
#           FUNÇÕES DE RESPOSTA ATIVA (AÇÕES DE REMEDIAÇÃO)
# ==============================================================================

_confirm_action() {
    local prompt_message="$1"
    local reply
    local Y="${C_YELLOW:-$'\e[33m'}"
    local R="${C_RESET:-$'\e[0m'}"
    if [[ ! -t 0 ]]; then
        log_warn "Entrada não interativa; assumindo 'N' para: $prompt_message"
        return 1
    fi
    read -r -n 1 -p "$(printf "%b" "${Y}CONFIRMAÇÃO:${R} ${prompt_message} [s/N]: ")" reply
    echo
    [[ "${reply,,}" == "s" ]]
}

# --- Ação: Encerrar um Processo ---
action_kill_process() {
    local pid="$1"
    if ! [[ "$pid" =~ ^[0-9]+$ ]] || (( pid < 2 )) || [[ ! -d "/proc/$pid" ]]; then
        log_error "PID '$pid' inválido ou processo não existe mais. Ação cancelada."
        return 1
    fi

    echo -e "A ação a seguir irá encerrar o processo ${C_WHITE}$pid${C_RESET}."
    pstree -ps "$pid" 2>/dev/null || ps -p "$pid" -o pid,user,start,etime,cmd --forest
    echo

    if _confirm_action "Você tem certeza que deseja encerrar este processo?"; then
        pkill -TERM -P "$pid" 2>/dev/null || true
        log_warn "Enviando SIGTERM para PID $pid..."
        kill -TERM "$pid" 2>/dev/null || sudo kill -TERM "$pid" 2>/dev/null || true
        sleep 1

        if kill -0 "$pid" 2>/dev/null; then
            log_warn "Processo ainda ativo; enviando SIGKILL para PID $pid..."
            kill -KILL "$pid" 2>/dev/null || sudo kill -KILL "$pid" 2>/dev/null || true
            sleep 0.3
        fi

        if kill -0 "$pid" 2>/dev/null; then
            log_warn "O processo $pid ainda está ativo. Pode ser zumbi ou ter respawn."
            return 1
        else
            log_info "${C_GREEN}SUCESSO:${C_RESET} Processo $pid encerrado."
            return 0
        fi
    else
        log_info "Ação cancelada pelo usuário."
        return 0
    fi
}

# --- Ação: Colocar um Arquivo em Quarentena ---
action_quarantine_file() {
    local path_to_quarantine="$1"

    if [[ -z "$path_to_quarantine" || ! -e "$path_to_quarantine" ]]; then
        log_error "Caminho '$path_to_quarantine' inválido ou não encontrado. Ação cancelada."
        return 1
    fi
    : "${QUARANTINE_DIR:=/root/quarantine}"
    if ! sudo install -d -m 700 -o root -g root -- "$QUARANTINE_DIR"; then
        log_error "Não foi possível preparar '$QUARANTINE_DIR'."
        return 1
    fi

    local real
    real=$(readlink -f -- "$path_to_quarantine" 2>/dev/null || printf '%s' "$path_to_quarantine")

    case "$real" in
        "$QUARANTINE_DIR"|"$QUARANTINE_DIR"/*)
            log_error "Item já está em quarentena: $real"
            return 1
            ;;
        "/"|"/bin"|"/sbin"|"/usr"|"/etc"|"/lib"|"/lib64"|"/boot")
            log_error "Recusando quarentena de diretório crítico: $real"
            return 1
            ;;
    esac

    local item_name stamp quarantine_path
    item_name=$(basename -- "$real")
    stamp=$(date +%Y%m%d-%H%M%S)
    quarantine_path="$QUARANTINE_DIR/${item_name}_quarantined_${stamp}"

    echo "A ação a seguir irá mover o item para a quarentena e bloquear permissões:"
    ls -ldh -- "$real"
    echo -e "Destino: ${C_CYAN}$quarantine_path${C_RESET}"
    echo

    if _confirm_action "Você tem certeza que deseja colocar este item em quarentena?"; then
        local sha="N/A"
        sha=$(sha256sum -- "$real" 2>/dev/null | awk '{print $1}') || true

        log_warn "Movendo '$real' para '$quarantine_path'..."
        if sudo mv -- "$real" "$quarantine_path"; then
            log_info "Item movido com sucesso. Aplicando hardening..."
            sudo chmod -R 000 -- "$quarantine_path"
            sudo chown -R root:root -- "$quarantine_path"
            sudo bash -c "{
                echo \"original_path=$real\"
                echo \"quarantine_path=$quarantine_path\"
                echo \"sha256=${sha}\"
                echo \"time=${stamp}\"
            } > \"${quarantine_path}.meta\""

            log_info "${C_GREEN}SUCESSO:${C_RESET} Item colocado em quarentena e protegido."
            return 0
        else
            log_error "Falha ao mover o item para a quarentena. Verifique permissões/uso do arquivo."
            return 1
        fi
    else
        log_info "Ação cancelada pelo usuário."
        return 0
    fi
}

# ==============================================================================
#           MENU INTERATIVO DE ANÁLISE DE PERSISTÊNCIA
# ==============================================================================
persistence_analysis_menu() {
    local remediated_pid="$1"
    if ! [[ "$remediated_pid" =~ ^[0-9]+$ ]] || (( remediated_pid < 2 )); then
        log_warn "PID de processo remediado inválido: '$remediated_pid'."
        return 0
    fi
    local ppid user cmd exe
    ppid=$(ps -o ppid= -p "$remediated_pid" 2>/dev/null | tr -d ' ' || true)
    user=$(ps -o user= -p "$remediated_pid" 2>/dev/null || true)
    if [[ -r "/proc/$remediated_pid/cmdline" ]]; then
        cmd=$(tr '\0' ' ' < "/proc/$remediated_pid/cmdline" 2>/dev/null | sed 's/[[:space:]]\+/ /g' | head -c 200)
    fi
    [[ -z "$cmd" ]] && cmd=$(ps -o cmd= -p "$remediated_pid" 2>/dev/null | head -c 200)

    exe=$(readlink -f "/proc/$remediated_pid/exe" 2>/dev/null || echo "N/A")
    : "${ppid:=N/A}"
    : "${user:=N/A}"
    : "${cmd:=N/A}"
    if ! declare -p SUSPECT_PERSISTENCE_PATTERNS &>/dev/null; then
        local -a SUSPECT_PERSISTENCE_PATTERNS=(curl wget nc bash python perl socat nohup setsid crontab systemctl)
    fi
    local suspect_regex
    if ((${#SUSPECT_PERSISTENCE_PATTERNS[@]} > 0)); then
        suspect_regex=$(IFS='|'; echo "${SUSPECT_PERSISTENCE_PATTERNS[*]}")
    else
        suspect_regex='(curl|wget|nc|bash|python)'
    fi

    while true; do
        clear
        echo -e "${C_CYAN}================== Análise de Persistência (Causa Raiz) ==================${C_RESET}"
        echo -e "Analisando o contexto do processo remediado (PID: ${C_YELLOW}$remediated_pid${C_RESET})"
        echo -e "${C_GRAY}Usuário: $user | Comando: $cmd...${C_RESET}"
        echo -e "${C_BLUE}----------------------------------------------------------------------${C_RESET}"
        echo -e "\n  ${C_YELLOW}Selecione uma heurística para investigar:${C_RESET}"
        echo -e "  ${C_GREEN}1)${C_RESET} Analisar Processo Pai (PPID: ${ppid})"
        echo -e "  ${C_GREEN}2)${C_RESET} Verificar Serviços Systemd (do mesmo usuário)"
        echo -e "  ${C_GREEN}3)${C_RESET} Verificar Cron Jobs (do mesmo usuário)"
        echo -e "  ${C_GREEN}4)${C_RESET} Verificar Arquivos de Shell RC (do mesmo usuário)"
        echo -e "  ${C_GREEN}5)${C_RESET} Procurar pelo Nome do Executável no Disco"
        echo -e "\n  ${C_YELLOW}q)${C_RESET} Concluir análise e voltar"
        
        read -rp "Escolha uma opção: " choice

        clear
        echo -e "${C_BLUE}---[ Resultado da Análise ]---${C_RESET}\n"
        
        case "${choice,,}" in
            1) 
                echo -e "${C_WHITE}Analisando o processo pai (PPID: $ppid)...${C_RESET}"
                if [[ "$ppid" =~ ^[0-9]+$ ]] && [[ -d "/proc/$ppid" ]]; then
                    _format_command "ps -p \"$ppid\" -o pid,ppid,user,comm,cmd --forest"
                    echo -e "\nO processo pai pode ser o responsável por iniciar a ameaça. Investigue-o."
                else
                    echo -e "${C_YELLOW}Processo pai não encontrado. Pode já ter terminado ou ser órfão (init).${C_RESET}"
                fi
                ;;

            2)
                echo -e "${C_WHITE}Procurando por serviços Systemd suspeitos do usuário '$user'...${C_RESET}"
                if command -v systemctl >/dev/null 2>&1; then
                    echo "Serviços (user) habilitados:"
                    _format_command "systemctl --user list-unit-files --state=enabled 2>/dev/null || true"
                    echo -e "\nServiços de sistema que rodam como o usuário (procura por User=):"
                    _format_command "grep -R \"^User=$user\" /etc/systemd/system /lib/systemd/system /etc/systemd/system/*.d 2>/dev/null || true"
                    echo -e "\nUnidades do usuário no disco:"
                    _format_command "find \"\$(getent passwd \"$user\" | cut -d: -f6)\"/.config/systemd/user -type f -name '*.service' -ls 2>/dev/null || true"
                else
                    echo -e "${C_YELLOW}Systemd não detectado. Pule para crons/rc/autostart.${C_RESET}"
                fi
                ;;

            3) 
                echo -e "${C_WHITE}Procurando por Cron Jobs suspeitos do usuário '$user'...${C_RESET}"
                echo "Cron do usuário (se existir):"
                _format_command "sudo crontab -l -u \"$user\" 2>/dev/null || echo '(sem crontab de usuário)'"
                echo -e "\nCrons de sistema que podem executar como o usuário:"
                _format_command "grep -R --line-number -- \"$user\" /etc/cron* /var/spool/cron* 2>/dev/null || true"
                ;;

            4) 
                local home_dir; home_dir=$(getent passwd "$user" | cut -d: -f6)
                echo -e "${C_WHITE}Verificando arquivos de inicialização de shell em '${home_dir:-N/A}'...${C_RESET}"
                if [[ -n "$home_dir" && -d "$home_dir" ]]; then
                    _format_command "grep -Ei -- '$suspect_regex' \"$home_dir\"/.bashrc \"$home_dir\"/.zshrc \"$home_dir\"/.profile \"$home_dir\"/.bash_profile 2>/dev/null || true"
                    _format_command "grep -Ei -- '$suspect_regex' /etc/profile /etc/bash.bashrc /etc/profile.d/*.sh 2>/dev/null || true"
                    _format_command "find \"$home_dir\"/.config/autostart -type f -name '*.desktop' -ls 2>/dev/null || true"
                else
                    echo -e "${C_YELLOW}Diretório home para o usuário '$user' não encontrado.${C_RESET}"
                fi
                ;;

            5) 
                local exe_name; exe_name=$(basename -- "$exe")
                echo -e "${C_WHITE}Procurando por outras instâncias do executável '$exe_name' no disco...${C_RESET}"
                if [[ "$exe" != "N/A" && -n "$exe_name" ]]; then
                    _format_command "sudo find / -xdev -type f -name \"$exe_name\" -ls 2>/dev/null"
                else
                    echo -e "${C_YELLOW}Caminho do executável original não era conhecido.${C_RESET}"
                fi
                ;;

            q)
                return 0 
                ;;
            *)
                log_warn "Opção inválida."
                ;;
        esac
        
        read -rp $'\n'"Pressione Enter para voltar ao menu de análise..."
    done
}
action_remediate_process() {
    local pid="$1"
    local path="$2"

    if ! [[ "$pid" =~ ^[0-9]+$ && -d "/proc/$pid" ]]; then
        log_error "PID inválido ('$pid') ou processo não existe mais. Ação cancelada."
        sleep 2
        return 1
    fi
    if [[ -z "$path" || "$path" == "N/A" ]]; then
        local exe_candidate
        exe_candidate=$(readlink -f "/proc/$pid/exe" 2>/dev/null || true)
        if [[ -n "$exe_candidate" ]]; then
            path="$exe_candidate"
        fi
    fi

    clear
    echo -e "${C_YELLOW}================== Remediação Completa de Processo ==================${C_RESET}"
    echo
    echo "Esta ação orquestrada seguirá um playbook de Resposta a Incidentes:"
    echo
    echo -e "  ${C_CYAN}1. CONTENÇÃO${C_RESET}"
    echo -e "     - O processo com PID ${C_BOLD}$pid${C_RESET} será terminado à força (SIGKILL)."
    echo
    echo -e "  ${C_CYAN}2. ERRADICAÇÃO${C_RESET}"
    echo -e "     - O arquivo executável associado será movido para a quarentena:"
    echo -e "       ${C_GRAY}${path:-Caminho não disponível.}${C_RESET}"
    echo
    echo -e "  ${C_CYAN}3. ANÁLISE PÓS-INCIDENTE${C_RESET}"
    echo -e "     - Você será guiado para analisar como a ameaça obteve persistência."
    echo

    if ! _confirm_action "Deseja iniciar este procedimento de remediação completa?"; then
        log_info "Remediação completa cancelada pelo usuário."
        return 0   
    fi

    local remediation_success=true
    local rc_kill=0 rc_quar=0

    echo
    echo -e "${C_BLUE}--------------------[ FASE 1: CONTENÇÃO ]--------------------${C_RESET}"
    if ! action_kill_process "$pid"; then
        rc_kill=$?
        log_error "Falha na fase de contenção (rc=$rc_kill). O processo não pôde ser terminado."
        remediation_success=false
    fi

    echo
    echo -e "${C_BLUE}-------------------[ FASE 2: ERRADICAÇÃO ]-------------------${C_RESET}"
    if [[ -n "$path" && "$path" != "N/A" ]]; then
        if ! action_quarantine_file "$path"; then
            rc_quar=$?
            log_error "Falha na fase de erradicação (rc=$rc_quar). O arquivo não pôde ser colocado em quarentena."
            remediation_success=false
        fi
    else
        log_warn "Nenhum caminho de arquivo para colocar em quarentena."
    fi

    echo
    echo -e "${C_BLUE}------------------[ FASE 3: ANÁLISE DE PERSISTÊNCIA ]------------------${C_RESET}"
    if [[ "$remediation_success" == "true" ]]; then
        echo "A ameaça imediata foi contida. A causa raiz (mecanismo de persistência)"
        echo "ainda pode existir no sistema."
    else
        echo -e "${C_RED}AVISO: As etapas de remediação anteriores falharam parcialmente.${C_RESET}"
        echo "A análise de persistência é ainda mais crítica agora."
    fi
    echo
    read -rp "Pressione Enter para iniciar a análise de persistência..."

    if declare -F persistence_analysis_menu >/dev/null; then
        persistence_analysis_menu "$pid"
    else
        log_warn "Menu de análise de persistência não implementado. Por favor, investigue manualmente."
    fi

    echo
    log_info "Procedimento de remediação e análise concluído."
    return 0
}


# ==============================================================================
#           AÇÃO: BLOQUEAR ENDEREÇO IP NO FIREWALL
# ==============================================================================
action_block_ip() {
    local ip_address="$1"

    if [[ -z "$ip_address" ]]; then
        log_error "Nenhum endereço IP fornecido para bloquear."
        return 1
    fi
    if ! [[ "$ip_address" =~ (\.|:) ]]; then
        log_error "Endereço IP inválido fornecido: '$ip_address'."
        return 1
    fi

    if _common_is_ip_allowed "$ip_address"; then
        log_warn "O IP '$ip_address' está na lista de permissões. Bloqueio cancelado."
        return 0
    fi

    echo -e "\n${C_YELLOW}---[ Análise do Endereço IP ]---${C_RESET}"
    log_info "Coletando informações para o IP $ip_address..."
    local ip_info; ip_info=$(curl -s --connect-timeout 5 "https://ipinfo.io/${ip_address}/json" || echo "{}")
    local country city org
    country=$(jq -r '.country // "N/A"' <<< "$ip_info"); city=$(jq -r '.city // "N/A"' <<< "$ip_info"); org=$(jq -r '.org // "N/A"' <<< "$ip_info")
    log_info "GeoIP: ${city}, ${country} | Organização: ${org}"
    echo
    echo "A ação a seguir irá adicionar uma regra de ${C_RED}DROP${C_RESET} no firewall para TODA a comunicação de entrada vinda do IP ${C_CYAN}$ip_address${C_RESET}."
    
    if ! _confirm_action "Você tem certeza que deseja bloquear este IP?"; then
        log_info "Bloqueio cancelado pelo usuário."; return 1;
    fi

    local firewall_used="" success=false
    log_warn "Tentando bloquear o IP $ip_address..."
    
    if command -v ufw &>/dev/null && sudo ufw status | grep -q "Status: active"; then
        firewall_used="UFW"
        if sudo ufw insert 1 deny from "$ip_address" to any; then success=true; fi
    elif command -v nft &>/dev/null; then
        firewall_used="nftables"
        if ! sudo nft list ruleset | grep -q "ip saddr $ip_address drop" && \
           ! sudo nft list ruleset | grep -q "ip6 saddr $ip_address drop"; then
            if [[ "$ip_address" =~ \. ]]; then
                sudo nft add rule inet filter input ip saddr "$ip_address" drop
            else
                sudo nft add rule inet filter input ip6 saddr "$ip_address" drop
            fi
        fi
        success=true 
    elif command -v iptables &>/dev/null; then
        if [[ "$ip_address" =~ \. ]]; then
            firewall_used="iptables"
            if ! sudo iptables-save | grep -q -- "-s $ip_address -j DROP"; then
                sudo iptables -I INPUT 1 -s "$ip_address" -j DROP
            fi
        else
            firewall_used="ip6tables"
            if ! sudo ip6tables-save | grep -q -- "-s $ip_address -j DROP"; then
                sudo ip6tables -I INPUT 1 -s "$ip_address" -j DROP
            fi
        fi
        success=true
    else
        log_error "Nenhum firewall suportado (ufw, nftables, iptables) encontrado ou ativo."; return 1;
    fi
    
    if [[ "$success" == true ]]; then
        log_info "${C_GREEN}SUCESSO:${C_RESET} IP $ip_address bloqueado (ou regra já existente) com $firewall_used."
        add_alert_detail "Endereço IP" "$ip_address"; add_alert_detail "Firewall" "$firewall_used"
        add_alert_detail "País" "$country"; add_alert_detail "Organização" "$org"
        log_alert "IP $ip_address bloqueado no firewall." "BAIXO" "Resposta a Incidente"
    else
        log_error "Falha ao bloquear o IP $ip_address com $firewall_used."; return 1;
    fi
}

# ==============================================================================
#           AÇÃO: DESBLOQUEAR ENDEREÇO IP NO FIREWALL
# ==============================================================================
action_unblock_ip() {
    local ip_address="$1"
    if [[ -z "$ip_address" ]]; then log_error "Nenhum IP fornecido para desbloquear."; return 1; fi

    echo -e "\nA ação a seguir irá procurar e ${C_GREEN}remover${C_RESET} as regras de firewall que bloqueiam o IP ${C_CYAN}$ip_address${C_RESET}."
    if ! _confirm_action "Você tem certeza que deseja desbloquear este IP?"; then
        log_info "Desbloqueio cancelado pelo usuário."; return 1;
    fi

    local firewall_used="" success=false
    log_warn "Tentando desbloquear o IP: $ip_address..."

    if command -v ufw &>/dev/null && sudo ufw status | grep -q "Status: active"; then
        firewall_used="UFW"
        while sudo ufw delete deny from "$ip_address" to any &>/dev/null; do
            success=true
        done
    elif command -v nft &>/dev/null; then
        firewall_used="nftables"
        while handle=$(sudo nft --handle list ruleset | grep -o "saddr $ip_address drop # handle [0-9]*" | awk '{print $NF}' | head -n1); [[ -n "$handle" ]]; do
            if sudo nft delete rule inet filter input handle "$handle"; then
                success=true
            else
                break
            fi
        done
    elif command -v iptables &>/dev/null; then
        firewall_used="iptables/ip6tables"
        while sudo iptables -D INPUT -s "$ip_address" -j DROP &>/dev/null; do success=true; done
        while sudo ip6tables -D INPUT -s "$ip_address" -j DROP &>/dev/null; do success=true; done
    fi

    if [[ "$success" == true ]]; then
        log_info "${C_GREEN}SUCESSO:${C_RESET} Regra(s) de bloqueio para o IP $ip_address removida(s)."
        add_alert_detail "Endereço IP" "$ip_address"; add_alert_detail "Firewall Utilizado" "$firewall_used"
        log_alert "IP $ip_address foi desbloqueado." "BAIXO" "Resposta a Incidente"
    else
        log_warn "Nenhuma regra de bloqueio encontrada para o IP '$ip_address' ou falha ao remover."
    fi
}

# ==============================================================================
#           AÇÃO: REMOVER EXTENSÃO DE NAVEGADOR
# ==============================================================================
action_remove_browser_extension() {
    local ext_path="$1"; local ext_name="$2"; local user="$3"; local browser="$4"

    if [[ -z "$ext_path" || -z "$ext_name" ]]; then
        log_error "Informações insuficientes (caminho ou nome da extensão) para a remoção. Ação cancelada."
        return 1
    fi

    clear
    echo -e "${C_YELLOW}---[ Remoção de Extensão de Navegador ]---${C_RESET}"
    echo "  ${C_WHITE}Navegador:${C_RESET} $browser"
    echo "  ${C_WHITE}Usuário:${C_RESET}   $user"
    echo "  ${C_WHITE}Extensão:${C_RESET}  $ext_name"
    echo "----------------------------------------"

    if [[ "$browser" == "Firefox" ]]; then
        echo -e "\n${C_YELLOW}AVISO:${C_RESET} A remoção automática de extensões do Firefox não é segura."
        echo "Por favor, siga estes passos manuais:"
        echo "1. Abra o Firefox como o usuário '$user'."
        echo "2. Digite 'about:addons' na barra de endereço."
        echo "3. Encontre '${C_CYAN}$ext_name${C_RESET}', clique nos '...' e selecione 'Remover'."
        log_warn "Remoção da extensão Firefox '$ext_name' requer intervenção manual."
        return 0
    fi

    if [[ "$browser" =~ (Chrome|Chromium|Edge|Brave|Vivaldi) ]]; then
        if [[ ! -d "$ext_path" ]]; then
            log_error "Diretório da extensão '$ext_path' não encontrado. Pode já ter sido removido."
            return 1
        fi
        
        echo -e "\nA ação irá mover o diretório da extensão para a quarentena."
        if action_quarantine_file "$ext_path"; then
            log_info "A extensão '$ext_name' foi colocada em quarentena."
            echo "RECOMENDAÇÃO: Reinicie o navegador '$browser' para que a mudança tenha efeito."
            add_alert_detail "Extensão" "$ext_name"; add_alert_detail "Navegador" "$browser"
            add_alert_detail "Usuário" "$user"; add_alert_detail "Ação" "Diretório movido para quarentena"
            log_alert "Extensão de navegador '$ext_name' foi removida." "BAIXO" "Resposta a Incidente"
        else
            log_error "Falha ao colocar a extensão em quarentena."
        fi
    else
        log_warn "Navegador '$browser' não suportado para remoção automática."
    fi
}

# ==============================================================================
#           AÇÃO: RESTAURAR ARQUIVO DE UM BACKUP
# ==============================================================================
action_restore_file() {
    local file_path="$1"
    local backup_path="$BACKUP_DIR/${file_path#/}" 
    
    if [[ ! -f "$backup_path" ]]; then
        log_error "Nenhum backup encontrado para '$file_path' em '$BACKUP_DIR'."
        return 1
    fi
    
    echo "A ação a seguir irá ${C_RED}sobrescrever${C_RESET} o arquivo atual:"
    echo -e "  ${C_CYAN}$file_path${C_RESET}"
    echo "com a versão do backup localizado em:"
    echo -e "  ${C_CYAN}$backup_path${C_RESET}"
    echo -e "\nComparando arquivos:"
    diff -u "$backup_path" "$file_path" | head -n 20
    echo ""
    
    if _confirm_action "Deseja restaurar o arquivo do backup?"; then
        log_warn "Restaurando '$file_path'..."
        if sudo cp -p "$backup_path" "$file_path"; then
            log_info "${C_GREEN}SUCESSO:${C_RESET} Arquivo restaurado. Recomenda-se verificar a integridade novamente."
        else
            log_error "Falha ao restaurar o arquivo. Verifique as permissões."
        fi
    else
        log_info "Restauração cancelada pelo usuário."
    fi
}

# ==============================================================================
#           AÇÃO: DESCARREGAR MÓDULO DE KERNEL
# ==============================================================================
action_unload_module() {
    local module_name="$1"
    
    echo "A ação a seguir tentará descarregar o módulo de kernel ${C_RED}$module_name${C_RESET}."
    echo -e "${C_YELLOW}AVISO:${C_RESET} Se este for um componente essencial, isso pode causar instabilidade."
    echo "       Se for um rootkit, a operação pode falhar ou ser ineficaz."
    echo ""
    
    if _confirm_action "Deseja tentar descarregar o módulo?"; then
        log_warn "Executando: sudo modprobe -r $module_name"
        if sudo modprobe -r "$module_name"; then
            log_info "${C_GREEN}SUCESSO:${C_RESET} Módulo '$module_name' descarregado."
            log_info "Recomenda-se investigar a origem do módulo e reiniciar o sistema para garantir a remoção completa."
        else
            log_error "Falha ao descarregar o módulo '$module_name'. Forte indicador de rootkit."
            log_error "AÇÃO RECOMENDADA: Isole a máquina da rede IMEDIATAMENTE e prepare para uma análise forense completa."
        fi
    else
        log_info "Ação cancelada pelo usuário."
    fi
}

# ==============================================================================
#           MENU INTERATIVO DE ANÁLISE DE PERSISTÊNCIA (CAUSA RAIZ)
# ==============================================================================

_run_forensic_command() {
    local description="$1"; shift
    local command_to_run=("$@") 
    
    echo -e "\n${C_YELLOW}---[ ${description} ]---${C_RESET}"
    echo -e "Executando o comando:"
    _format_command "${command_to_run[@]}" 
    echo ""
    if ! "${command_to_run[@]}" | less -RFX; then
        echo -e "${C_GRAY}(O comando não produziu saída ou retornou um erro, o que pode ser normal).${C_RESET}"
    fi
}

persistence_analysis_menu() {
    local remediated_pid="${1:-}" 
    local ppid user cmd exe ppid_name ppid_cmdline
    if [[ "$remediated_pid" =~ ^[0-9]+$ ]]; then
        ppid=$(ps -o ppid= -p "$remediated_pid" 2>/dev/null | tr -d ' ')
        user=$(ps -o user= -p "$remediated_pid" 2>/dev/null)
        cmd=$(ps -o cmd= -p "$remediated_pid" 2>/dev/null | head -c 100)
        exe=$(readlink -f "/proc/$remediated_pid/exe" 2>/dev/null || echo "N/A")
        if [[ "$ppid" =~ ^[0-9]+$ ]]; then
            ppid_name=$(ps -p "$ppid" -o comm= 2>/dev/null)
        fi
    fi

    while true; do
        clear
        echo -e "${C_CYAN}================== Análise de Persistência (Causa Raiz) ==================${C_RESET}"
        if [[ -n "$remediated_pid" ]]; then
            echo -e "Analisando o contexto do processo remediado (PID: ${C_YELLOW}$remediated_pid${C_RESET})"
            echo -e "${C_GRAY}Usuário: $user | Comando: $cmd...${C_RESET}"
        else
            echo -e "Iniciando análise de persistência geral (sem contexto de PID)."
        fi

        if [[ -n "$remediated_pid" ]]; then
            echo -e "\n${C_MAGENTA}Pista Forense Principal:${C_RESET}"
            if [[ "$ppid" -eq 1 ]]; then
                echo -e "  O processo pai era o ${C_BOLD}Systemd (PID 1)${C_RESET}. A persistência é ${C_YELLOW}provavelmente um serviço ou timer${C_RESET}."
                echo -e "  ${C_GREEN}Sugestão: Comece pelas opções 1, 2 e 3.${C_RESET}"
            elif [[ "$ppid_name" == "cron" || "$ppid_name" == "crond" ]]; then
                echo -e "  O processo pai era o ${C_BOLD}Cron${C_RESET}. A persistência é ${C_YELLOW}provavelmente uma tarefa agendada${C_RESET}."
                echo -e "  ${C_GREEN}Sugestão: Comece pela opção 4.${C_RESET}"
            elif [[ -n "$ppid" ]]; then
                echo -e "  O processo pai (PID $ppid, Nome: $ppid_name) parece ser um processo de usuário."
                echo -e "  ${C_GREEN}Sugestão: Comece pela opção 9 para investigar a árvore genealógica.${C_RESET}"
            else
                 echo -e "  Não foi possível determinar o processo pai. Recomenda-se uma verificação geral."
            fi
        fi
        
        echo -e "\n${C_YELLOW}Selecione um vetor de persistência para investigar:${C_RESET}"
        cat << "EOF"
  [Systemd]
    1) Listar Serviços/Timers Habilitados
    2) Inspecionar Arquivos de Unidade Locais
  [Tarefas Agendadas]
    3) Listar Cron Jobs (sistema e usuários)
  [Shell & Login]
    4) Inspecionar Arquivos de Inicialização de Shell
    5) Verificar Arquivos de Autostart da GUI (XDG)
  [Sistema de Baixo Nível]
    6) Listar Módulos de Kernel Carregados
    7) Verificar Regras Udev Personalizadas
  [Análise de Processos (Contexto Geral)]
    8) Exibir Árvore de Processos Completa (pstree)
    9) Listar Conexões de Rede Ativas (ss)
  q) Concluir Análise e Voltar
EOF

        read -rp "Escolha uma opção: " choice
        
        trap 'read -rp $"\n Pressione Enter para voltar ao menu..."' DEBUG
        clear
        echo -e "${C_BLUE}---[ Resultado da Análise para a Opção '$choice' ]---${C_RESET}\n"
        
        case "$choice" in
            1) _run_forensic_command "Serviços Habilitados" systemctl list-unit-files --state=enabled;
               _run_forensic_command "Timers Ativos" systemctl list-timers --all ;;
            2) _run_forensic_command "Unidades de Serviço do Sistema (Locais)" ls -l /etc/systemd/system/ /run/systemd/system/;
               _run_forensic_command "Unidades de Serviço de Usuários (Locais)" ls -l /home/*/.config/systemd/user/ ;;
            3) _run_forensic_command "Cron Jobs do Sistema" "ls -l /etc/cron* && cat /etc/crontab";
               _run_forensic_command "Cron Jobs de Usuários" bash -c 'for user in $(getent passwd | cut -f1 -d:); do echo "### Crontab para $user ###"; sudo crontab -u "$user" -l 2>/dev/null || echo "(nenhum)"; echo; done' ;;
            4) _run_forensic_command "Arquivos de Perfil Globais" grep -vE '^#|^$' /etc/profile /etc/bash.bashrc /etc/profile.d/*;
               _run_forensic_command "Arquivos de Perfil de Usuários" grep -vE '^#|^$' /home/*/{.bashrc,.profile,.bash_profile,.bash_login} ;;
            5) _run_forensic_command "Diretórios de Autostart" ls -l /etc/xdg/autostart/ /home/*/.config/autostart/ ;;
            6) _run_forensic_command "Módulos de Kernel Carregados" lsmod ;;
            7) _run_forensic_command "Regras Udev" ls -l /etc/udev/rules.d/ ;;
            8) _run_forensic_command "Árvore de Processos Completa" pstree -pau ;;
            9) _run_forensic_command "Todas as Conexões de Rede Ativas" ss -tunap ;;
            q|Q) trap - DEBUG; break ;;
            *) log_warn "Opção inválida." ;;
        esac

        trap - DEBUG
    done
}



# ==============================================================================
#           FUNÇÕES DE AJUDA E SETUP INICIAL
# ==============================================================================

show_help() {
    local script_name; script_name=$(basename "$0")
    echo -e "${C_CYAN}Uso: ${script_name} [OPÇÃO]...${C_RESET}"
    echo
    echo "  HIDS (Host-based Intrusion Detection System) e ferramenta de resposta a incidentes"
    echo "  que varre o sistema em busca de indicadores de comprometimento."
    echo
    echo -e "${C_YELLOW}Opções Principais:${C_RESET}"
    echo -e "  ${C_GREEN}--scan-completo${C_RESET}         Executa todas as verificações de segurança. (Padrão)"
    echo -e "  ${C_GREEN}--resposta-apenas${C_RESET}       Inicia diretamente o Guia de Resposta a Incidentes para"
    echo -e "                          revisar os alertas do último scan."
    echo
    echo -e "${C_YELLOW}Opções de Gerenciamento:${C_RESET}"
    echo -e "  ${C_GREEN}--criar-baselines${C_RESET}     Cria ou sobrescreve todos os arquivos de baseline com base no"
    echo -e "                          estado atual do sistema e sai."
    echo -e "  ${C_GREEN}--update-yara-rules${C_RESET}   Atualiza as regras YARA a partir do repositório online e sai."
    echo
    echo -e "${C_YELLOW}Modificadores:${C_RESET}"
    echo -e "  ${C_GREEN}--dry-run${C_RESET}               Executa o scan, mas desativa notificações (Telegram, E-mail)."
    echo -e "  ${C_GREEN}--debug${C_RESET}                 Habilita a saída de logs de depuração detalhados."
    echo -e "  ${C_GREEN}--ajuda${C_RESET}, ${C_GREEN}-h${C_RESET}              Mostra esta mensagem de ajuda e sai."
    echo
    echo -e "${C_YELLOW}Exemplos:${C_RESET}"
    echo -e "  ${C_GRAY}# Executar um scan completo:${C_RESET}"
    echo -e "  sudo ./${script_name}"
    echo -e "  ${C_GRAY}# Apenas revisar os alertas de um scan anterior:${C_RESET}"
    echo -e "  ./${script_name} --resposta-apenas"
    echo -e "  ${C_GRAY}# Criar/confiar no estado atual do sistema como 'limpo':${C_RESET}"
    echo -e "  sudo ./${script_name} --criar-baselines"
}

# ==============================================================================
#           FUNÇÃO DE CRIAÇÃO/RESET DE TODAS AS BASELINES
# ==============================================================================
create_all_baselines() {
    initialize_script
    log_info "--- MODO DE CRIAÇÃO/RESET DE BASELINE ---"
    echo -e "${C_RED}AVISO:${C_RESET} Esta ação irá sobrescrever todas as baselines existentes,"
    echo "confiando no estado atual do sistema como 'limpo'. Proceda com cautela."
    if ! _confirm_action "Você tem certeza que deseja continuar?"; then
        log_info "Criação de baselines cancelada pelo usuário."
        exit 0
    fi

    log_info "Criando baselines de snapshot de estado..."

    local -a sudo_files_to_check=()
    for path in "${SUDOERS_PATHS_TO_CHECK[@]}"; do
        if [[ -f "$path" ]]; then
            sudo_files_to_check+=("$path")
        elif [[ -d "$path" ]]; then
            mapfile -t -O "${#sudo_files_to_check[@]}" sudo_files_to_check < <(find "$path" -type f)
        fi
    done
    if ((${#sudo_files_to_check[@]} > 0)); then
        if sudo sha256sum "${sudo_files_to_check[@]}" > "$SUDOERS_BASELINE_FILE"; then
            log_info "  -> Baseline de Sudo criada com sucesso."
        else
            log_error "  -> Falha ao criar baseline de Sudo."
        fi
    fi

    if lsmod | tail -n +2 | awk '{print $1}' | sort > "$LKM_BASELINE_FILE"; then
        log_info "  -> Baseline de LKM criada com sucesso."
    else
        log_error "  -> Falha ao criar baseline de LKM."
    fi

    if find "${SUID_SGID_SEARCH_DIRS[@]}" -xdev -type f -perm /6000 -print 2>/dev/null | sort > "$SUID_SGID_BASELINE_FILE"; then
        log_info "  -> Baseline de SUID/SGID criada com sucesso."
    else
        log_error "  -> Falha ao criar baseline de SUID/SGID."
    fi
    
    log_info "Inicializando (resetando) baselines de eventos..."
    
    local -a event_baselines=(
        "$PERSISTENCE_BASELINE_FILE"
        "$COMMANDS_BASELINE_FILE"
        "$IMMUTABLE_FILES_BASELINE_FILE"
        "$SOCKET_ANOMALY_BASELINE_FILE"
        "$WEB_SHELL_BASELINE_FILE"
        "$DEFENSE_EVASION_BASELINE_FILE"
        "$DOCKER_SECURITY_BASELINE_FILE"
        "$AUTH_LOG_BASELINE_FILE"
        "$TIMESTOMP_BASELINE_FILE"
    )
    for bfile in "${event_baselines[@]}"; do
        if > "$bfile"; then
            log_info "  -> Baseline de evento resetada: $(basename "$bfile")"
        else
            log_error "  -> Falha ao resetar a baseline de evento: $(basename "$bfile")"
        fi
    done

    log_info "Resetando baselines do analisador de navegadores..."
    find "$BASELINE_DIR" -mindepth 1 -type f -name "*.baseline" -user "$(whoami)" -delete 2>/dev/null
    log_info "  -> Baselines de navegadores removidas. Serão recriadas no próximo scan."

    log_info "Pré-populando a baseline de integridade de arquivos (FIM)..."
    local -a critical_bins=("/bin/bash" "/bin/sh" "/usr/bin/sudo" "/usr/bin/ssh" "/usr/sbin/sshd")
    (
        flock 200 
        > "$HASH_DB_FILE" 
        for bin in "${critical_bins[@]}"; do
            if [[ -f "$bin" ]]; then
                local hash; hash=$(sha256sum "$bin" | awk '{print $1}')
                printf '%s\0%s\n' "$bin" "$hash" >> "$HASH_DB_FILE"
            fi
        done
    ) 200>"$HASH_DB_FILE.lock"
    log_info "  -> Baseline de FIM pré-populada com ${#critical_bins[@]} binários críticos."

    log_info "${C_GREEN}Criação/Reset de todas as baselines concluída.${C_RESET}"
    exit 0
}

clean_json_log() {
    if [[ -z "${JSON_LOG_FILE:-}" ]]; then
        log_error "JSON_LOG_FILE não definido."
        return 1
    fi
    local log="$JSON_LOG_FILE"
    [[ -s "$log" ]] || return 0

    if ! command -v jq >/dev/null 2>&1; then
        log_warn "jq não encontrado; pulando limpeza do log."
        return 0
    fi

    # Arquivos temporários
    local tmp err jqf
    tmp=$(mktemp -t jsonclean.XXXXXX)       || { log_error "mktemp falhou"; return 1; }
    err=$(mktemp -t jsonclean_err.XXXXXX)   || { log_error "mktemp falhou"; rm -f -- "$tmp"; return 1; }
    jqf=$(mktemp -t jsonclean_filter.XXXX)  || { log_error "mktemp falhou"; rm -f -- "$tmp" "$err"; return 1; }

    # Diretório de backup
    local backup_dir="${HIST_DIR:-$(dirname -- "$log")}"
    mkdir -p -- "$backup_dir" 2>/dev/null || { log_error "Não foi possível criar diretório de backup: $backup_dir"; rm -f -- "$tmp" "$err" "$jqf"; return 1; }

    log_debug "Verificando e higienizando o log de alertas JSON..."

    # Filtro jq em arquivo (sem here-doc)
    printf '%s\n' \
'def sanitize:
  tostring
  | gsub("KATEX_[A-Z_]+(\\.[A-Za-z]+)?"; "")
  | gsub("\\s+"; " ")
  | gsub("^[[:space:][:punct:]]+"; "")
  | gsub("[[:space:][:punct:]]+$"; "");' \
'def clean_details:
  if (.details|type=="object") then
    .details |= (
      to_entries
      | map({
          key:   (.key   | sanitize),
          value: (if (.value|type)=="string" then (.value|sanitize) else .value end)
        })
      | map(select(
          (.key|length) > 0 and
          (
            ((.value|type)!="string") or
            ( (.value|length) > 0 and ((.value|test("^[[:space:][:punct:]]*$"))|not) )
          )
        ))
      | from_entries
    )
  else . end;' \
'fromjson? | select(type=="object") | clean_details' > "$jqf"

    # Executa limpeza
    if ! jq -c -R -f "$jqf" -- "$log" >"$tmp" 2>"$err"; then
        log_warn "Erros durante a limpeza (jq)."
        [[ -s "$err" ]] && sed -n '1,200p' "$err" | while IFS= read -r l; do log_warn "  $l"; done
    fi

    # Nada válido?
    if [[ ! -s "$tmp" ]]; then
        log_warn "Nenhuma linha JSON válida encontrada."
        rm -f -- "$tmp" "$err" "$jqf"
        return 0
    fi

    # Evita reescrever se nada mudou
    local old_hash new_hash
    old_hash=$(sha256sum -- "$log" 2>/dev/null | awk '{print $1}')
    new_hash=$(sha256sum -- "$tmp" 2>/dev/null | awk '{print $1}')
    if [[ -n "$old_hash" && "$old_hash" == "$new_hash" ]]; then
        log_debug "Log já está limpo. Nenhuma ação necessária."
        rm -f -- "$tmp" "$err" "$jqf"
        return 0
    fi

    log_info "Aplicando limpeza e gerando backup..."

    # Lock suave no FD 200 (sem variáveis com chaves)
    if command -v flock >/dev/null 2>&1; then
        exec 200>>"$log" || true
        flock -x 200 2>/dev/null || true
    fi

    local backup="$backup_dir/alertas.jsonl.bkp.$(date +%F_%H-%M-%S)"
    if ! cp -- "$log" "$backup"; then
        log_error "Não foi possível criar backup em '$backup'."
        [[ -t 200 ]] && exec 200>&-
        rm -f -- "$tmp" "$err" "$jqf"
        return 1
    fi

    if mv -- "$tmp" "$log"; then
        log_info "Log corrigido. Backup: $backup"
    else
        log_error "Falha ao substituir o log. Original mantido. Backup: $backup"
        [[ -t 200 ]] && exec 200>&-
        rm -f -- "$tmp" "$err" "$jqf"
        return 1
    fi

    [[ -t 200 ]] && exec 200>&-
    rm -f -- "$err" "$jqf"
    return 0
}

# ==============================================================================
#           FUNÇÃO PRINCIPAL E ORQUESTRAÇÃO
# ==============================================================================

main() {
    local run_scan=false
    local run_response=false

    # Sem argumentos: roda scan
    if [[ $# -eq 0 ]]; then
        run_scan=true
    fi

    # Parse de argumentos
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --scan-completo)      run_scan=true; shift ;;
            --resposta-apenas)    run_response=true; run_scan=false; shift ;;
            --criar-baselines)    initialize_script; create_all_baselines; exit 0 ;;
            --update-yara-rules)  initialize_script; update_yara_rules; exit 0 ;;
            --dry-run)            DRY_RUN=true; shift ;;
            --debug)              DEBUG_MODE=true; shift ;;
            -h|--ajuda|--help)    show_help; exit 0 ;;
            *) echo "Erro: Opção desconhecida '$1'" >&2; show_help; exit 1 ;;
        esac
    done

    # Inicializa se necessário
    if [[ "$run_scan" == "true" || "$run_response" == "true" ]]; then
        initialize_script
    fi

    # Varredura
    if [[ "$run_scan" == "true" ]]; then
        log_info "--- INICIANDO VARREDURA GERAL DO SISTEMA ---"
        load_hash_database
        THREATS_FOUND=0
        [[ -f "$JSON_LOG_FILE" ]] || : > "$JSON_LOG_FILE"

        local __log_lines_before __total_in_log __new_alerts
        __log_lines_before=$(wc -l < "$JSON_LOG_FILE" 2>/dev/null || echo 0)

        # Checks (com timeouts)
        if ! run_check --timeout 45  "Analisando processos com alto consumo de recursos"           analyze_top_processes;            then :; fi
        if ! run_check --timeout 60  "Verificando múltiplos vetores de persistência"               check_persistence;                then :; fi
        if ! run_check --timeout 60  "Verificando históricos e processos suspeitos"                check_suspicious_commands;        then :; fi
        if ! run_check --timeout 30  "Verificando a integridade dos arquivos Sudo"                 check_sudoers_integrity;          then :; fi
        if ! run_check --timeout 60  "Analisando logins e acessos anômalos"                        check_user_logins;                then :; fi
        if ! run_check --timeout 60  "Procurando possíveis web shells"                             find_web_shells;                  then :; fi
        if ! run_check --timeout 60  "Verificando arquivos SUID/SGID suspeitos"                    find_suid_sgid_files;             then :; fi
        if ! run_check --timeout 45  "Verificando arquivos com atributo de imutabilidade"          check_immutable_files;            then :; fi
        if ! run_check --timeout 60  "Verificando sockets anômalos (detecção de rootkit)"          find_anomalous_sockets;           then :; fi
        if ! run_check --timeout 60  "Verificando a integridade dos módulos do kernel"             check_kernel_modules;             then :; fi
        if ! run_check --timeout 60  "Verificando técnicas de evasão de defesa"                    check_defense_evasion_techniques; then :; fi
        if ! run_check --timeout 60  "Verificando configurações de segurança de containers Docker" check_docker_security;            then :; fi
        if ! run_check --timeout 800 "Verificando extensões e artefatos de navegadores"            verificar_navegadores;            then :; fi
        if ! run_check --timeout 30  "Verificando a segurança da rede Wi-Fi"                       check_wifi_security;              then :; fi

        # Salvar baseline e finalizar (blindado contra set -e)
        set +e

        log_debug "DEBUG_FLOW: chamando save_hash_database..."
        if ! save_hash_database; then
            log_error "save_hash_database falhou. Prosseguindo."
        fi

        log_debug "DEBUG_FLOW: chamando sync..."
        if ! sync; then
            log_warn "sync retornou código não-zero."
        fi

        # Limpa o JSON por último
        if declare -F clean_json_log >/dev/null; then
            log_debug "DEBUG_FLOW: chamando clean_json_log..."
            if ! clean_json_log; then
                log_warn "Falha ao limpar o JSON de alertas; prosseguindo."
            fi
        fi

        # Métricas finais
        __total_in_log=$(wc -l < "$JSON_LOG_FILE" 2>/dev/null || echo 0)
        __new_alerts=${THREATS_FOUND:-0}
        log_debug "DEBUG_FLOW: total_in_log=${__total_in_log}, threats_found=${__new_alerts}"

        set -e

        echo
        log_info "================================================="
        log_info "  Varredura Concluída."
        log_info "  Ameaças NOVAS nesta varredura: ${C_YELLOW}${__new_alerts}${C_RESET}"
        log_info "  Total de alertas no log:       ${C_YELLOW}${__total_in_log}${C_RESET}"
        log_info "================================================="
        echo

        # Política de prompt: new|any|always|never (default=any)
        local _mode="${RESPONSE_PROMPT_MODE:-any}" prompt=false
        case "$_mode" in
          new)    (( __new_alerts   > 0 )) && prompt=true ;;
          any)    (( __total_in_log > 0 )) && prompt=true ;;
          always) prompt=true ;;
          never)  prompt=false ;;
          *)      prompt=false ;;
        esac
        if [[ "$prompt" == "true" ]]; then
            run_response=true
        fi
    fi  # fim do bloco de varredura

    # Guia de Resposta a Incidentes
    if [[ "$run_response" == "true" ]]; then
        if [[ ! -s "$JSON_LOG_FILE" ]]; then
            log_warn "O arquivo de log de alertas está vazio. Não há nada para responder."
        elif [[ -t 0 ]]; then
            # Sessão interativa: pergunta “sim/não”
            if ! _confirm_action "Deseja iniciar o Guia de Resposta a Incidentes agora?"; then
                log_info "Guia de Resposta não iniciado. Execute com '--resposta-apenas' para revisar mais tarde."
            else
                incident_response_helper
            fi
        else
            # Sem TTY: abre diretamente o guia
            incident_response_helper
        fi
    elif [[ "$run_scan" == "true" ]]; then
        log_info "${C_GREEN:-}Nenhuma ameaça encontrada nesta varredura.${C_RESET:-}"
    fi
}

# ==============================================================================
#           PONTO DE ENTRADA DO SCRIPT
# ==============================================================================
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
    if (( ${THREATS_FOUND:-0} > 0 )); then
        exit 1
    else
        exit 0
    fi
fi
# sudo pacman -Syu --noconfirm lsof unhide whois coreutils gawk grep inetutils lastlog psmisc bc jq sqlite
# 

