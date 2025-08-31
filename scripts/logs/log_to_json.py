#!/usr/bin/env python3
# scripts/logs/log_to_json.py
"""
Constrói e registra um alerta JSON completo no arquivo de log.

Recebe os componentes do alerta como argumentos e monta o objeto JSON final,
adicionando automaticamente o timestamp e o hostname. Sanitiza detalhes para
remover tokens KaTeX acidentais.
"""
import sys
import json
import os
import re
import argparse
import socket
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any

# Bloqueio POSIX (opcional)
if sys.platform != 'win32':
    import fcntl  # type: ignore
else:
    fcntl = None

KATEX_RE = re.compile(r'KATEX_[A-Z_]+(?:\.[A-Za-z]+)?')

def _sanitize_text(s: str) -> str:
    # remove marcadores KaTeX e aparas pontuação/espacos nas pontas
    s = KATEX_RE.sub('', s)
    s = re.sub(r'\s+', ' ', s).strip(' .()[]{}"\t\r\n')
    return s

def create_alert_payload(args: argparse.Namespace) -> Dict[str, Any]:
    """Constrói o dicionário do alerta a partir dos argumentos da linha de comando."""
    details_obj: Dict[str, str] = {}
    if args.detail:
        for item in args.detail:
            if ':' in item:
                key, value = item.split(':', 1)
                key = _sanitize_text(key.strip())
                value = _sanitize_text(value.strip())
                if key:
                    details_obj[key] = value

    return {
        "timestamp": datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z'),
        "hostname": socket.getfqdn(),
        "risk_level": args.risk_level,
        "check_type": args.check_type,
        "message": args.message,
        "details": details_obj
    }

def write_log_entry(log_file: Path, alert: Dict[str, Any]) -> None:
    """Escreve o alerta no arquivo de log com bloqueio de arquivo (file lock)."""
    try:
        log_file.parent.mkdir(parents=True, exist_ok=True)

        with open(log_file, 'a', encoding='utf-8') as f:
            if fcntl:
                fcntl.flock(f, fcntl.LOCK_EX)

            f.write(json.dumps(alert, ensure_ascii=False) + '\n')
            f.flush()
            # Opcional para durabilidade: os.fsync(f.fileno())

            if fcntl:
                fcntl.flock(f, fcntl.LOCK_UN)

    except (IOError, OSError) as e:
        print(f"Erro ao escrever no arquivo '{log_file}': {e}", file=sys.stderr)
        sys.exit(1)

def main() -> None:
    """Função principal: parseia argumentos e orquestra a criação e escrita do log."""
    parser = argparse.ArgumentParser(
        description="Construtor e Logger de Alertas JSON.",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("log_file_path", help="Caminho para o arquivo de log .jsonl")
    parser.add_argument("--message", required=True, help="A mensagem principal do alerta.")
    parser.add_argument("--risk-level", default="MÉDIO",
                        choices=["BAIXO", "MÉDIO", "ALTO", "CRÍTICO"],
                        help="Nível de risco do alerta.")
    parser.add_argument("--check-type", default="INDEFINIDO", help="Tipo de verificação que gerou o alerta.")
    parser.add_argument("--detail", action='append', dest='detail',
                        help="Detalhe do alerta no formato 'Chave: Valor'. Pode ser usado várias vezes.")

    args = parser.parse_args()
    log_file = Path(args.log_file_path)
    final_alert = create_alert_payload(args)
    write_log_entry(log_file, final_alert)

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(f"Erro inesperado no log_to_json.py: {e}", file=sys.stderr)
        sys.exit(1)