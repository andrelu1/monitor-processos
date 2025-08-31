#!/usr/bin/env python3
# scripts/logs/alert_manager.py
"""
Motor de dados para a interface de alertas (Threat Hunter).

Lê o arquivo JSONL (um JSON por linha) e fornece:
- list-types: lista de tipos únicos (com exclusões opcionais)
- get-page: paginação de alertas para a UI do Bash
- list-for-ir: lista numerada com PID (para guia de IR)
- summarize-by-type: resumo por tipo com contagens
"""

import sys
import re
import json
import os
import argparse
from pathlib import Path
from typing import List, Dict, Any

DELIMITER = "\x1f"
DEFAULT_PAGE_SIZE = 10

# Extrai PID de forma flexível
PID_REGEX = re.compile(r'"(?:PID|Processo|pid)"\s*:\s*"?(\d{2,7})"?', re.IGNORECASE)


# ------------------------------------------------------------------------------
# Normalização de rótulos de tipo (sinônimos e variações)
# ------------------------------------------------------------------------------

def normalize_type_label(s: str) -> str:
    """
    Retorna um rótulo canônico legível para o tipo (check_type),
    unificando variações (acentos/sem acentos, sinônimos).
    """
    if not s:
        return "INDEFINIDO"
    t = str(s).strip()
    k = t.casefold()

    synonyms = {
        # Processo
        "análise de processo": "Processo Suspeito",
        "analise de processo": "Processo Suspeito",
        "processo suspeito": "Processo Suspeito",

        # Rede
        "conexão externa": "Conexão Externa",
        "conexao externa": "Conexão Externa",
        "rede exposta": "Rede Exposta",
        "dnsbl": "DNSBL",
        "whois": "WHOIS",
        "whois policy": "WHOIS Policy",
        "acesso anômalo (serviço)": "Acesso Anômalo (Serviço)",
        "acesso anomalo (servico)": "Acesso Anômalo (Serviço)",
        "acesso anômalo (múltiplos ips)": "Acesso Anômalo (Múltiplos IPs)",
        "acesso anomalo (multiplos ips)": "Acesso Anômalo (Múltiplos IPs)",
        "reconhecimento": "Reconhecimento",
        "ataque de força bruta": "Ataque de Força Bruta",
        "ataque de forca bruta": "Ataque de Força Bruta",

        # Rootkit / LKM
        "rootkit (socket)": "Rootkit (Socket)",
        "socket rootkit": "Rootkit (Socket)",
        "rootkit socket": "Rootkit (Socket)",
        "rootkit (lkm adicionado)": "Rootkit (LKM Adicionado)",
        "lkm adicionado": "Rootkit (LKM Adicionado)",
        "módulo de kernel novo": "Rootkit (LKM Adicionado)",
        "modulo de kernel novo": "Rootkit (LKM Adicionado)",
        "impair defenses (lkm removido)": "Impair Defenses (LKM Removido)",
        "lkm removido": "Impair Defenses (LKM Removido)",

        # Evasão de Defesa
        "evasão de defesa (imutabilidade)": "Evasão de Defesa (Imutabilidade)",
        "evasao de defesa (imutabilidade)": "Evasão de Defesa (Imutabilidade)",
        "evasão de defesa (timestomp)": "Evasão de Defesa (Timestomp)",
        "evasao de defesa (timestomp)": "Evasão de Defesa (Timestomp)",
        "evasão de defesa": "Evasão de Defesa",
        "evasao de defesa": "Evasão de Defesa",

        # Escalação/Elevação de privilégio
        "escalação de privilégio (suid/sgid)": "Escalação de Privilégio (SUID/SGID)",
        "escalacao de privilegio (suid/sgid)": "Escalação de Privilégio (SUID/SGID)",
        "elevação de privilégio (suid/sgid)": "Escalação de Privilégio (SUID/SGID)",
        "elevacao de privilegio (suid/sgid)": "Escalação de Privilégio (SUID/SGID)",
        "escalação de privilégio (yara)": "Escalação de Privilégio (YARA)",
        "escalacao de privilegio (yara)": "Escalação de Privilégio (YARA)",
        "elevação de privilégio (yara)": "Escalação de Privilégio (YARA)",
        "elevacao de privilegio (yara)": "Escalação de Privilégio (YARA)",
        "elevação de privilégio": "Elevação de Privilégio",
        "elevacao de privilegio": "Elevação de Privilégio",
        "tentativa de escalação": "Tentativa de Escalação",
        "tentativa de escalacao": "Tentativa de Escalação",

        # Web / Navegador
        "web shell": "Web Shell",
        "web shell (yara)": "Web Shell (YARA)",
        "extensão (chromium)": "Extensão (Chromium)",
        "extensao (chromium)": "Extensão (Chromium)",
        "extensão (firefox)": "Extensão (Firefox)",
        "extensao (firefox)": "Extensão (Firefox)",
        "preferência (chromium)": "Preferência (Chromium)",
        "preferencia (chromium)": "Preferência (Chromium)",
        "preferência (firefox)": "Preferência (Firefox)",
        "preferencia (firefox)": "Preferência (Firefox)",
        "javascript suspeito": "JavaScript Suspeito",
        "native messaging": "Native Messaging",
        "cookie": "Cookie",

        # Docker
        "docker security (privileged)": "Docker Security (Privileged)",
        "docker security (socket mount)": "Docker Security (Socket Mount)",

        # Histórico / Integridade
        "histórico de comandos": "Histórico de Comandos",
        "historico de comandos": "Histórico de Comandos",
        "commands_history": "Histórico de Comandos",
        "integridade de arquivo": "Integridade de Arquivo",
        "file integrity": "Integridade de Arquivo",
    }
    return synonyms.get(k, t)


# --- Funções Auxiliares de Processamento de Dados ---

def load_alerts(path: Path) -> List[Dict[str, Any]]:
    """
    Carrega alertas de um arquivo JSON Lines (um JSON por linha).
    Retorna a lista com os alertas mais recentes primeiro.
    """
    if not path.exists():
        return []

    alerts: List[Dict[str, Any]] = []
    try:
        with path.open('r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    alert = json.loads(line)
                    if isinstance(alert, dict):
                        alerts.append(alert)
                except json.JSONDecodeError:
                    continue
    except (IOError, PermissionError, OSError) as e:
        print(f"Erro de I/O ao ler o arquivo '{path}': {e}", file=sys.stderr)
        sys.exit(1)
    return alerts[::-1]


def filter_by_type(alerts: List[Dict[str, Any]], alert_type: str) -> List[Dict[str, Any]]:
    """Filtra uma lista de alertas por tipo (case-insensitive) com normalização."""
    if not alert_type or alert_type.lower().strip() in ('todos', 'all'):
        return alerts
    key = normalize_type_label(alert_type).lower()
    return [a for a in alerts
            if normalize_type_label(a.get('check_type', '')).lower() == key]


def _extract_pid_from_alert(alert: Dict[str, Any]) -> str:
    """
    Tenta extrair um PID de forma flexível de várias partes do alerta.
    """
    details = alert.get("details", {}) or {}

    for key in ("PID", "pid", "process_id"):
        if key in details and details[key] not in (None, ""):
            return str(details[key])

    alert_str = json.dumps(alert, ensure_ascii=False)
    match = PID_REGEX.search(alert_str)
    if match:
        return match.group(1)

    return "N/A"


def format_alert_message(alert: Dict[str, Any]) -> str:
    """Formata a mensagem do alerta com base no seu tipo para maior clareza."""
    check_type = normalize_type_label(alert.get('check_type') or 'INDEFINIDO').lower()
    details = alert.get('details', {}) or {}

    if check_type == 'rede exposta':
        process = details.get('Processo', '?')
        endpoint = details.get('Endpoint de Escuta', '?')
        return f"Serviço '{process}' exposto em '{endpoint}'"
    elif check_type == 'conexão externa' or check_type == 'conexao externa':
        process = details.get('Processo', '?')
        remote = details.get('Conexão Remota', details.get('Conexao Remota', '?'))
        return f"Conexão externa de '{process}' para '{remote}'"

    return alert.get('message', 'Sem mensagem.')


# ------------------------------------------------------------------------------
# Leitura reversa de arquivo para paginação eficiente
# ------------------------------------------------------------------------------

def _iter_lines_reverse(path: Path, chunk_size: int = 64 * 1024):
    """Itera as linhas do arquivo do fim para o início, sem carregar tudo.
    Retorna linhas como str (utf-8), sem quebras de linha."""
    with path.open('rb') as f:
        f.seek(0, os.SEEK_END)
        buf = b""
        pos = f.tell()
        while pos > 0:
            read_size = chunk_size if pos >= chunk_size else pos
            pos -= read_size
            f.seek(pos, os.SEEK_SET)
            chunk = f.read(read_size)
            buf = chunk + buf
            lines = buf.split(b'\n')
            buf = lines[0]
            for line in lines[-1:0:-1]:
                if not line:
                    continue
                try:
                    yield line.decode('utf-8', 'replace').strip()
                except UnicodeDecodeError:
                    yield line.decode('utf-8', 'ignore').strip()
        if buf:
            try:
                s = buf.decode('utf-8', 'replace').strip()
            except UnicodeDecodeError:
                s = buf.decode('utf-8', 'ignore').strip()
            if s:
                yield s


# ------------------------------------------------------------------------------
# Handlers da CLI
# ------------------------------------------------------------------------------

def _handle_list_types(args: argparse.Namespace) -> None:
    """
    Lê todos os alertas, extrai os tipos únicos (normalizados), aplica exclusões
    e imprime 'valor|label'.
    """
    alerts = load_alerts(args.file_path)

    exclude_set = {normalize_type_label(t).casefold() for t in (args.exclude or [])}
    types_map: Dict[str, str] = {}  # key (casefold) -> canonical label

    for alert in alerts:
        raw = alert.get('check_type')
        if not raw:
            continue
        label = normalize_type_label(raw)
        key = label.casefold()
        if key in exclude_set:
            continue
        if key not in types_map:
            types_map[key] = label

    for t in sorted(types_map.values(), key=str.casefold):
        print(f"{t}|{t}")


def _handle_get_page(args: argparse.Namespace) -> None:
    """Filtra, pagina e formata alertas para a UI, lendo o arquivo de trás para frente."""
    path: Path = args.file_path
    alert_type = normalize_type_label(args.alert_type or "todos").lower()
    page = max(0, int(args.page))
    page_size = max(1, int(args.page_size))
    page_size = min(page_size, 500)

    if not path.exists():
        print(DELIMITER.join(map(str, [0, 0, 0])))
        return

    total_items = 0
    offset = page * page_size
    collected: List[Dict[str, Any]] = []

    def type_match(a: Dict[str, Any]) -> bool:
        if alert_type in ("todos", "all"):
            return True
        t = normalize_type_label(a.get("check_type") or "").lower()
        return t == alert_type

    for line in _iter_lines_reverse(path):
        if not line:
            continue
        try:
            alert = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(alert, dict):
            continue

        if not type_match(alert):
            continue

        total_items += 1

        if total_items <= offset:
            continue
        if len(collected) < page_size:
            collected.append(alert)
        else:
            continue

    total_pages = 0 if total_items == 0 else (total_items + page_size - 1) // page_size
    items_on_page = len(collected)

    print(DELIMITER.join(map(str, [total_items, total_pages, items_on_page])))

    for alert in collected:
        full_details_str = json.dumps(alert, ensure_ascii=False)
        fields = [
            _extract_pid_from_alert(alert),
            format_alert_message(alert),
            normalize_type_label(alert.get('check_type', 'INDEFINIDO')),
            alert.get('risk_level', 'N/A'),
            alert.get('hostname', 'N/A'),
            alert.get('timestamp', 'N/A'),
            full_details_str
        ]
        print(DELIMITER.join(map(str, fields)))


def _handle_list_for_ir(args: argparse.Namespace) -> None:
    """Lê todos os alertas e imprime uma lista numerada com PID para o guia de IR."""
    alerts = load_alerts(args.file_path)
    if not alerts:
        print("Nenhum alerta encontrado no arquivo de log.")
        return

    for idx, alert in enumerate(alerts, 1):
        pid = _extract_pid_from_alert(alert)
        message = alert.get("message", "Sem mensagem.")
        print(f"{idx}) PID: {pid:<10} - {message}")


def _handle_summarize_by_type(args: argparse.Namespace) -> None:
    """
    Agrupa todos os alertas por tipo (normalizado) e imprime um resumo para o menu do Bash.
    Aceita uma lista de tipos para focar, se fornecida.
    """
    alerts = load_alerts(args.file_path)

    wanted_cf = None
    if args.types:
        wanted_cf = {normalize_type_label(t).lower() for t in args.types}

    if not alerts:
        return

    summary: Dict[str, List[Dict[str, Any]]] = {}
    for alert in alerts:
        ct = normalize_type_label(alert.get('check_type', 'INDEFINIDO'))
        if wanted_cf is not None and ct.lower() not in wanted_cf:
            continue
        summary.setdefault(ct, []).append(alert)

    for check_type in sorted(summary.keys(), key=str.casefold):
        alert_list = summary[check_type]
        print(f"HEADER{DELIMITER}{check_type}{DELIMITER}{len(alert_list)}")
        for alert in alert_list:
            risk = alert.get('risk_level', 'N/A')
            message = alert.get('message', 'Sem mensagem.')
            print(f"ALERT{DELIMITER}{risk}{DELIMITER}{message}")


# ==============================================================================
#           ORQUESTRADOR PRINCIPAL DA CLI
# ==============================================================================

def main() -> None:
    """
    Define a CLI, parseia os argumentos e despacha para o handler correspondente.
    """
    parser = argparse.ArgumentParser(
        description="Motor de dados para a UI de Alertas do Threat Hunter.",
        formatter_class=argparse.RawTextHelpFormatter
    )

    subparsers = parser.add_subparsers(
        dest="command",
        required=True,
        help="O comando a ser executado."
    )

    parser_list_types = subparsers.add_parser(
        "list-types",
        help="Lista tipos de alerta únicos, com opção de exclusão."
    )
    parser_list_types.add_argument(
        "file_path",
        type=Path,
        help="Caminho para o arquivo de log (alertas.jsonl)"
    )
    parser_list_types.add_argument(
        "--exclude",
        nargs="+",
        default=[],
        help="Tipos de alerta a serem excluídos (case-insensitive; normalizados)."
    )

    parser_get_page = subparsers.add_parser(
        "get-page",
        help="Obtém uma página de alertas formatados para exibição."
    )
    parser_get_page.add_argument(
        "file_path",
        type=Path,
        help="Caminho para o arquivo de log (alertas.jsonl)"
    )
    parser_get_page.add_argument(
        "alert_type",
        nargs="?",
        default="todos",
        help="Filtra por tipo de alerta (normalizado)."
    )
    parser_get_page.add_argument(
        "--page",
        type=int,
        default=0,
        help="Número da página (base 0)."
    )
    parser_get_page.add_argument(
        "--page-size",
        type=int,
        default=DEFAULT_PAGE_SIZE,
        help="Itens por página."
    )

    parser_list_ir = subparsers.add_parser(
        "list-for-ir",
        help="Lista todos os alertas com PID extraído para o guia de IR."
    )
    parser_list_ir.add_argument(
        "file_path",
        type=Path,
        help="Caminho para o arquivo de log (alertas.jsonl)"
    )

    parser_summary = subparsers.add_parser(
        "summarize-by-type",
        help="Agrupa alertas por tipo (normalizado) e imprime um resumo."
    )
    parser_summary.add_argument(
        "file_path",
        type=Path,
        help="Caminho para o arquivo de log (alertas.jsonl)"
    )
    parser_summary.add_argument(
        "types",
        nargs="*",
        help="Tipos de alerta específicos para incluir no resumo (normalizados)."
    )

    args = parser.parse_args()

    if args.command == "list-types":
        _handle_list_types(args)
    elif args.command == "get-page":
        _handle_get_page(args)
    elif args.command == "list-for-ir":
        _handle_list_for_ir(args)
    elif args.command == "summarize-by-type":
        _handle_summarize_by_type(args)
    else:
        parser.error("Comando inválido.")


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(f"Erro inesperado no alert_manager.py: {e}", file=sys.stderr)
        sys.exit(1)