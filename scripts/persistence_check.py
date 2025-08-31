#!/usr/bin/env python3
"""
Motor de detecção de comandos suspeitos. Escaneia históricos de shell e
processos em execução contra uma lista de padrões regex, comparando com uma
baseline para encontrar apenas novos achados.
"""
import os
import re
import sys
import json
import subprocess
import argparse
from pathlib import Path
from typing import Set, Iterator, Dict, Any

def log_stderr(*args, **kwargs):
    print(f"command_check.py [AVISO]:", *args, file=sys.stderr, **kwargs)

def load_baseline(path: Path) -> Set[str]:
    """Carrega a baseline do disco para um set em memória."""
    if not path.exists(): return set()
    try:
        with path.open("r", encoding="utf-8") as f:
            return {line.strip() for line in f if line.strip()}
    except IOError: return set()

def get_user_from_path(path: Path) -> str:
    try: return path.owner()
    except (KeyError, FileNotFoundError): return "desconhecido"

# --- Módulos de Detecção ---

def check_history_files(pattern: re.Pattern, baseline: set, history_filenames: list[str]):
    """Escaneia uma lista de arquivos de histórico com uma regex."""
    search_paths: Set[Path] = set()
    
    # Busca por arquivos de histórico em /root e /home
    for home_dir_str in ["/root", "/home"]:
        home_dir = Path(home_dir_str)
        if not home_dir.is_dir(): continue
        for user_dir in home_dir.iterdir():
             if not user_dir.is_dir(): continue
             for hf_name in history_filenames:
                 hist_file = user_dir / hf_name
                 if hist_file.is_file():
                    search_paths.add(hist_file)

    for path in search_paths:
        try:
            content = path.read_text(encoding="utf-8", errors="ignore")
            for i, line in enumerate(content.splitlines(), 1):
                if pattern.search(line):
                    line = line.strip()
                    baseline_key = f"History|{path}|{line}"
                    if baseline_key not in baseline:
                        yield {
                            "message": f"Comando suspeito no histórico de '{path.name}'",
                            "risk_level": "MÉDIO",
                            "check_type": "Histórico de Comandos",
                            "details": {
                                "Usuário": get_user_from_path(path),
                                "Arquivo": str(path),
                                "Linha": str(i),
                                "Comando Encontrado": line
                            }
                        }
                        baseline.add(baseline_key)
        except (IOError, PermissionError) as e:
            log_stderr(f"Não foi possível ler '{path}': {e}")
            continue

def check_running_processes(pattern: re.Pattern, baseline: set):
    """Escaneia processos em execução."""
    try:
        # ps com formato customizado para fácil parsing
        output = subprocess.check_output(["ps", "-eo", "pid,user,comm,args"], text=True, stderr=subprocess.DEVNULL)
        for line in output.splitlines()[1:]: # Pula o cabeçalho
            if pattern.search(line):
                parts = line.strip().split(maxsplit=3)
                if len(parts) < 4: continue
                pid, user, comm, cmd = parts
                
                baseline_key = f"Process|{user}|{cmd}"
                if baseline_key not in baseline:
                    yield {
                        "message": f"Processo suspeito em execução (PID: {pid})",
                        "risk_level": "ALTO",
                        "check_type": "Processo Suspeito",
                        "details": { "PID": pid, "Usuário": user, "Nome do Processo (comm)": comm, "Linha de Comando": cmd }
                    }
                    baseline.add(baseline_key)
    except (FileNotFoundError, subprocess.CalledProcessError) as e:
        log_stderr(f"Falha ao executar 'ps': {e}")

# --- Orquestrador Principal do Python ---

def main():
    parser = argparse.ArgumentParser(description="Motor de detecção de comandos suspeitos.")
    parser.add_argument("--baseline-file", required=True, type=Path, help="Caminho para o arquivo de baseline.")
    parser.add_argument("--patterns", nargs='+', required=True, help="Padrões de regex para procurar.")
    parser.add_argument("--history-files", nargs='*', default=[], help="Lista de nomes de arquivos de histórico a procurar.")
    args = parser.parse_args()

    baseline = load_baseline(args.baseline_file)
    initial_baseline_size = len(baseline)
    
    try:
        suspect_pattern = re.compile("|".join(args.patterns), re.IGNORECASE)
    except re.error as e:
        log_stderr(f"Regex inválida nos padrões: {e}"); sys.exit(1)

    all_findings = []
    all_findings.extend(check_history_files(suspect_pattern, baseline, args.history_files))
    all_findings.extend(check_running_processes(suspect_pattern, baseline))
    
    for finding in all_findings:
        print(json.dumps(finding, ensure_ascii=False))
        
    if len(baseline) > initial_baseline_size:
        try:
            with args.baseline_file.open("a", encoding="utf-8") as f:
                new_entries = sorted(list(baseline - load_baseline(args.baseline_file)))
                for entry in new_entries:
                    f.write(entry + "\n")
        except IOError as e:
            log_stderr(f"Falha ao atualizar a baseline '{args.baseline_file}': {e}")

if __name__ == "__main__":
    main()