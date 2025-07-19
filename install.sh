#!/bin/bash

set -e

# ========= CONFIGURAÇÃO ========= #

PROJETO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SERVICE_DIR="$PROJETO_DIR/service"
SYSTEMD_DIR="/etc/systemd/system"
ARQUIVOS_OBRIGATORIOS=("processo_whitelist.txt" "hash_db.txt" "alertas.log" ".env")
DIRS_OBRIGATORIOS=("historico")
PACOTES=(
    bc curl mailutils inotify-tools unhide zenity
    coreutils procps-ng inetutils psmisc man-db util-linux iproute2
    gnome-terminal
)

# ========= FUNÇÕES ========= #

instalar_pacotes() {
    echo "📦 Instalando pacotes necessários..."
    sudo pacman -S --needed "${PACOTES[@]}"
}

criar_estrutura() {
    echo "📁 Criando diretórios e arquivos obrigatórios..."

    for dir in "${DIRS_OBRIGATORIOS[@]}"; do
        mkdir -p "$PROJETO_DIR/$dir"
    done

    for arq in "${ARQUIVOS_OBRIGATORIOS[@]}"; do
        touch "$PROJETO_DIR/$arq"
    done

    chmod +x "$PROJETO_DIR"/monitor_*.sh
}

instalar_services() {
    echo "⚙️ Instalando serviços no systemd..."

    shopt -s nullglob 2>/dev/null || true  # compatível com bash
    service_files=("$SERVICE_DIR"/*.service)
    timer_files=("$SERVICE_DIR"/*.timer)

    for file in "${service_files[@]}" "${timer_files[@]}"; do
        if [[ -f "$file" ]]; then
            echo "➡️ Instalando: $(basename "$file")"
            sudo cp "$file" "$SYSTEMD_DIR/"
        fi
    done

    sudo systemctl daemon-reexec
    sudo systemctl daemon-reload
}

ativar_services() {
    echo "🚀 Ativando monitoramento automático..."

    if [[ -f "$SYSTEMD_DIR/monitor_processo.timer" ]]; then
        sudo systemctl enable --now monitor_processo.timer
    fi

    if [[ -f "$SYSTEMD_DIR/monitor_realtime.service" ]]; then
        sudo systemctl enable --now monitor_realtime.service
    fi
}

atualizar_mandb() {
    echo "📚 Atualizando banco de dados do man..."
    if command -v mandb &>/dev/null; then
        sudo mandb -q
    else
        echo "⚠️ mandb não encontrado. Você pode instalá-lo com: sudo pacman -S man-db"
    fi
}

mostrar_readme() {
    if [[ -f "$PROJETO_DIR/README.md" ]]; then
        echo "📖 Exibindo instruções de uso..."
        less "$PROJETO_DIR/README.md"
    else
        echo "ℹ️ README.md não encontrado, mas a instalação foi concluída."
    fi
}

# ========= EXECUÇÃO ========= #

echo "🔧 Iniciando instalação do Monitor de Processos..."

instalar_pacotes
criar_estrutura
instalar_services
ativar_services
atualizar_mandb
mostrar_readme

echo "✅ Instalação concluída com sucesso!"
