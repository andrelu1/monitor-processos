#!/usr/bin/env python3
import os, re, sys, json, subprocess, argparse, itertools, glob
from pathlib import Path
from typing import Set, List

def log_stderr(*args, **kwargs):
    print("command_check.py [AVISO]:", *args, file=sys.stderr, **kwargs)

def load_baseline(path: Path) -> Set[str]:
    if not path.exists(): return set()
    try:
        with path.open("r", encoding="utf-8") as f:
            return {line.strip() for line in f if line.strip()}
    except IOError:
        return set()

def get_user_from_path(path: Path) -> str:
    try: return path.owner()
    except Exception: return "desconhecido"

def discover_history_paths(history_files: List[str]) -> List[Path]:
    paths = []
    # Expande caminhos/globs fornecidos pelo usuário
    for spec in history_files:
        for m in glob.glob(spec, recursive=True):
            p = Path(m)
            if p.is_file():
                paths.append(p)
    # Defaults comuns (rápidos, sem rglob)
    for home in Path("/home").glob("*/"):
        for name in [".bash_history", ".zsh_history", ".history"]:
            p = home / name
            if p.is_file():
                paths.append(p)
    for p in [Path("/root/.bash_history"), Path("/root/.zsh_history"), Path("/root/.history")]:
        if p.is_file():
            paths.append(p)
    # Remove duplicatas
    return list({p.resolve() for p in paths})

def check_history_files(pattern: re.Pattern, baseline: Set[str], history_files: List[str]):
    for path in discover_history_paths(history_files):
        try:
            for i, line in enumerate(path.read_text(encoding="utf-8", errors="ignore").splitlines(), 1):
                if pattern.search(line):
                    line = line.strip()
                    key = f"History|{path}|{line}"
                    if key not in baseline:
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
                        baseline.add(key)
        except (IOError, PermissionError) as e:
            log_stderr(f"Não foi possível ler '{path}': {e}")

def check_running_processes(pattern: re.Pattern, baseline: Set[str]):
    try:
        # Sem cabeçalho (mais simples de parsear)
        output = subprocess.check_output(["ps", "-eo", "pid=,user=,args="], text=True)
        for line in output.splitlines():
            if not line.strip(): continue
            if pattern.search(line):
                parts = line.strip().split(maxsplit=2)
                if len(parts) < 3: continue
                pid, user, cmd = parts
                key = f"Process|{user}|{cmd}"
                if key not in baseline:
                    yield {
                        "message": f"Processo suspeito em execução (PID: {pid})",
                        "risk_level": "ALTO",
                        "check_type": "Processo Suspeito",
                        "details": {"PID": pid, "Usuário": user, "Linha de Comando": cmd}
                    }
                    baseline.add(key)
    except (FileNotFoundError, subprocess.CalledProcessError) as e:
        log_stderr(f"Falha ao executar 'ps': {e}")

def main():
    parser = argparse.ArgumentParser(description="Motor de detecção de comandos suspeitos.")
    parser.add_argument("--baseline-file", required=True, type=Path)
    parser.add_argument("--patterns", nargs='+', required=True)
    parser.add_argument("--history-files", nargs='*', default=[])
    args = parser.parse_args()

    baseline = load_baseline(args.baseline_file)
    initial_size = len(baseline)

    try:
        suspect_pattern = re.compile("|".join(args.patterns), re.IGNORECASE)
    except re.error as e:
        log_stderr(f"Regex inválida nos padrões: {e}")
        sys.exit(1)

    # Streaming: imprime conforme encontra
    for finding in itertools.chain(
        check_history_files(suspect_pattern, baseline, args.history_files),
        check_running_processes(suspect_pattern, baseline),
    ):
        print(json.dumps(finding, ensure_ascii=False), flush=True)

    # Atualiza baseline no final (append só do novo)
    if len(baseline) > initial_size:
        try:
            existing = load_baseline(args.baseline_file)
            new_entries = sorted(list(baseline - existing))
            with args.baseline_file.open("a", encoding="utf-8") as f:
                for entry in new_entries:
                    f.write(entry + "\n")
        except IOError as e:
            log_stderr(f"Falha ao atualizar a baseline '{args.baseline_file}': {e}")

if __name__ == "__main__":
    main()