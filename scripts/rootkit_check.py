#!/usr/bin/env python3
# scripts/rootkit_helpers/rootkit_check.py
"""
Executa uma série de verificações para detectar sinais de rootkits, como
processos ocultos, módulos de kernel escondidos e arquivos suspeitos.

Produz uma stream de objetos JSON (um por linha) para cada achado.
"""
import os
import sys
import json
import subprocess
from typing import Iterator, Dict, Any, Set

# --- Constantes e Configuração ---
REMEDIATION_TEXT = "ALERTA CRÍTICO: SUSPEITA DE ROOTKIT. Isolar máquina, não reiniciar, coletar imagens forenses."
SUSPICIOUS_DIRS = ['/tmp', '/dev/shm', '/var/tmp']

# --- Funções Auxiliares ---

def log_stderr(*args, **kwargs) -> None:
    """Imprime mensagens de log no stderr para não poluir a saída JSON."""
    print(f"rootkit_check.py [AVISO]:", *args, file=sys.stderr, **kwargs)

def run_command(cmd: list[str]) -> Set[str]:
    """Executa um comando e retorna as linhas de sua saída como um set."""
    try:
        # 'text=True' é o mesmo que 'encoding="utf-8"' e 'decode()'
        result = subprocess.check_output(cmd, text=True, stderr=subprocess.DEVNULL)
        # Retorna um set de linhas não vazias
        return {line.strip() for line in result.splitlines() if line.strip()}
    except FileNotFoundError:
        log_stderr(f"Comando '{cmd[0]}' não encontrado. Pulando verificação associada.")
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
        log_stderr(f"Comando '{cmd[0]}' falhou: {e}")
    return set()

# --- Módulos de Verificação (Geradores de Alertas) ---

def check_unhide() -> Iterator[Dict[str, Any]]:
    """Técnica 1: Usa a ferramenta 'unhide' para encontrar processos ocultos."""
    if os.geteuid() != 0:
        log_stderr("'unhide' requer privilégios de root.")
        return

    unhide_output = run_command(['unhide', 'proc'])
    if unhide_output:
        yield {
            "message": "Rootkit: processos ocultos detectados pelo 'unhide'",
            "risk_level": "CRÍTICO",
            "check_type": "Rootkit (unhide)",
            "details": {
                "Técnica": "unhide",
                "Saída Bruta": "\n".join(unhide_output),
                "Remediação": REMEDIATION_TEXT
            }
        }

def check_proc_ps_discrepancy() -> Iterator[Dict[str, Any]]:
    """Técnica 2: Compara a listagem de PIDs do /proc com a saída do comando 'ps'."""
    try:
        proc_pids = {pid for pid in os.listdir('/proc') if pid.isdigit()}
    except FileNotFoundError:
        log_stderr("Diretório /proc não encontrado. Impossível comparar com 'ps'.")
        return

    ps_output = run_command(['ps', '-eo', 'pid'])
    # Ignora o cabeçalho "PID"
    ps_pids = {line.strip() for line in ps_output if line.strip().isdigit()}

    hidden_from_ps = proc_pids - ps_pids
    hidden_from_proc = ps_pids - proc_pids # Menos comum, mas possível

    if hidden_from_ps or hidden_from_proc:
        yield {
            "message": "Rootkit: discrepância de PIDs entre /proc e 'ps'",
            "risk_level": "CRÍTICO",
            "check_type": "Rootkit (proc/ps)",
            "details": {
                "PIDs_em_proc_nao_em_ps": sorted(list(hidden_from_ps)),
                "PIDs_em_ps_nao_em_proc": sorted(list(hidden_from_proc)),
                "Remediação": REMEDIATION_TEXT
            }
        }

def check_kernel_modules() -> Iterator[Dict[str, Any]]:
    """Técnica 3: Compara a saída de 'lsmod' com o conteúdo de /sys/module."""
    try:
        sys_modules = set(os.listdir('/sys/module'))
    except FileNotFoundError:
        log_stderr("Diretório /sys/module não encontrado. Impossível checar módulos ocultos.")
        return

    lsmod_output = run_command(['lsmod'])
    # Ignora o cabeçalho e pega apenas o nome do módulo da primeira coluna
    lsmod_modules = {line.split()[0] for line in lsmod_output if not line.startswith("Module")}

    hidden_modules = sys_modules - lsmod_modules
    if hidden_modules:
        yield {
            "message": f"Rootkit: {len(hidden_modules)} módulo(s) de kernel oculto(s) detectado(s)",
            "risk_level": "CRÍTICO",
            "check_type": "Rootkit (LKM)",
            "details": {
                "Módulos Ocultos": sorted(list(hidden_modules)),
                "Remediação": REMEDIATION_TEXT
            }
        }

def check_suspicious_files() -> Iterator[Dict[str, Any]]:
    """Técnica 4: Procura por arquivos ocultos ou sockets em diretórios temporários."""
    for directory in SUSPICIOUS_DIRS:
        try:
            for filename in os.listdir(directory):
                # Procura por arquivos que começam com '.' (ocultos) ou terminam com '.sock' (potencialmente maliciosos)
                if filename.startswith('.') or filename.endswith(('.sock', '.socket')):
                    full_path = os.path.join(directory, filename)
                    yield {
                        "message": f"Arquivo/Socket suspeito encontrado: {full_path}",
                        "risk_level": "ALTO",
                        "check_type": "Arquivo Oculto/Suspeito",
                        "details": { "Caminho": full_path }
                    }
        except (FileNotFoundError, PermissionError) as e:
            log_stderr(f"Não foi possível listar o diretório '{directory}': {e}")
            continue

# --- Orquestrador Principal ---

def main() -> None:
    """
    Executa todos os módulos de verificação e imprime os alertas JSON resultantes
    em uma stream para stdout.
    """
    # Lista de todas as funções de verificação a serem executadas.
    # Fácil de adicionar ou remover checagens no futuro.
    all_checks = [
        check_unhide,
        check_proc_ps_discrepancy,
        check_kernel_modules,
        check_suspicious_files
    ]

    for check_function in all_checks:
        try:
            # Cada função retorna um 'gerador'. Iteramos sobre ele.
            for alert in check_function():
                # Imprime cada alerta como uma linha JSON assim que é encontrado.
                print(json.dumps(alert, ensure_ascii=False))
        except Exception as e:
            # Captura erros inesperados dentro de uma função de verificação
            # para que o script principal não pare.
            log_stderr(f"Erro inesperado durante a execução de '{check_function.__name__}': {e}")

if __name__ == "__main__":
    main()