#!/bin/bash

# ========= CONFIGURAÇÕES ========= #

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCRIPT="$DIR/monitor_processo.sh"
WHITELIST_FILE="$DIR/processo_whitelist.txt"
LOG="$DIR/alertas.log"
HIST_DIR="$DIR/historico"

# ========= FUNÇÕES ========= #

# Menu principal
show_menu() {
    zenity --list \
        --title="🛡️ Monitor de Processos" \
        --column="Ação" --height=500 --width=500 \
        "Análisar " \
        "Análise em Modo de Teste" \
        "Últimos Alertas" \
        "Adicionar Processo à Whitelist" \
        "Processos na Whitelist" \
        "Editar Whitelist Manualmente" \
        "Histórico de Processos" \
        "Limpar Log de Alertas" \
        "Obter ajuda sobre um processo" \
        "Visualizar Log Completo" \
        "Sair"
}

# Executa o script principal
rodar_analise() {
    bash "$SCRIPT"
    zenity --info --text="✅ Análise concluída!" --title="Monitor de Processos"
}

# Executa o script principal em modo de teste
rodar_analise_teste() {
    bash "$SCRIPT" --dry-run
    zenity --info --text="✅ Análise (modo de teste) concluída!" --title="Monitor de Processos"
}

# Mostra os últimos alertas
ver_alertas() {
    if [[ ! -s "$LOG" ]]; then
        zenity --info --text="Nenhum alerta registrado." --title="Alertas"
    else
        tail -n 20 "$LOG" | zenity --text-info --title="Últimos Alertas" --width=700 --height=400
    fi
}

# Adiciona um processo à whitelist
adicionar_whitelist() {
    proc=$(zenity --entry --title="Adicionar à Whitelist" --text="Digite o nome do processo:")
    [[ -z "$proc" ]] && return
    if grep -qx "$proc" "$WHITELIST_FILE"; then
        zenity --info --text="Esse processo já está na whitelist." --title="Whitelist"
    else
        echo "$proc" >> "$WHITELIST_FILE"
        zenity --info --text="Processo '$proc' adicionado com sucesso!" --title="Whitelist"
    fi
}

# Mostra todos os itens da whitelist
ver_whitelist() {
    if [[ ! -s "$WHITELIST_FILE" ]]; then
        zenity --info --text="A whitelist está vazia." --title="Whitelist"
    else
        cat "$WHITELIST_FILE" | zenity --text-info --title="Processos na Whitelist" --width=500 --height=400
    fi
}

# Edita a whitelist com editor externo (ex: nano)
editar_whitelist() {
    editor="${EDITOR:-nano}"
    gnome-terminal -- "$editor" "$WHITELIST_FILE" &
}

# Mostra o histórico de snapshots
ver_historico() {
    local hist_files=($(ls -1t "$HIST_DIR"/*.log 2>/dev/null))
    [[ ${#hist_files[@]} -eq 0 ]] && {
        zenity --info --text="Nenhum histórico disponível." --title="Histórico"
        return
    }

    local escolha=$(zenity --list --title="Selecione um Arquivo de Histórico" \
        --column="Arquivos" "${hist_files[@]}" --height=400 --width=600)

    [[ -n "$escolha" ]] && zenity --text-info --filename="$escolha" --title="Histórico de Processos"
}

# Limpa o log de alertas
limpar_log() {
    zenity --question --text="Tem certeza que deseja limpar o log de alertas?" --title="Confirmação"
    [[ $? -eq 0 ]] && > "$LOG" && zenity --info --text="Log limpo com sucesso." --title="Limpeza de Log"
}

# Ajuda sobre um processo
ajuda_processo() {
    proc=$(zenity --entry --title="Ajuda sobre Processo" --text="Digite o nome do processo:")
    [[ -z "$proc" ]] && return

    caminho=$(command -v "$proc" 2>/dev/null)
    [[ -z "$caminho" ]] && caminho="(não encontrado no PATH)"

    if command -v whatis &>/dev/null; then
        desc=$(whatis "$proc" 2>/dev/null)
    else
        desc=$(man -f "$proc" 2>/dev/null | head -n 1)
    fi
    [[ -z "$desc" ]] && desc="(sem descrição disponível)"

    link="https://wiki.archlinux.org/index.php?search=$proc"

    zenity --info --title="Ajuda: $proc" --width=500 --text="
<b>🔍 Nome:</b> $proc
<b>📄 Descrição:</b> $desc
<b>📁 Caminho:</b> $caminho

<b>🌐 Arch Wiki:</b>
$link
"

    zenity --question --text="Deseja abrir a Arch Wiki sobre '$proc' no navegador?" --title="Abrir Wiki"
    [[ $? -eq 0 ]] && xdg-open "$link" &>/dev/null
}

# ========= LOOP PRINCIPAL ========= #

while true; do
    escolha=$(show_menu)
    case "$escolha" in
        "Análisar ") rodar_analise ;;
        "Análise em Modo de Teste") rodar_analise_teste ;;
        "Últimos Alertas") ver_alertas ;;
        "Adicionar Processo à Whitelist") adicionar_whitelist ;;
        "Processos na Whitelist") ver_whitelist ;;
        "Editar Whitelist Manualmente") editar_whitelist ;;
        "Histórico de Processos") ver_historico ;;
        "Limpar Log de Alertas") limpar_log ;;
        "Obter ajuda sobre um processo") ajuda_processo ;;
        "Visualizar Log Completo") zenity --text-info --filename="$LOG" --title="Log Completo" --width=700 --height=500 ;;
        "Sair") exit 0 ;;
        *) exit 0 ;;
    esac
done
