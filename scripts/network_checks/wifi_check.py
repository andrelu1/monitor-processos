#!/usr/bin/env python3
"""
Motor de análise de segurança de Wi‑Fi, sem dependências Python externas.

Funcionalidades:
- Verifica a segurança da rede Wi‑Fi atual (nmcli).
- Detecta novos dispositivos na LAN (arp-scan) e atualiza baseline de MACs.
- Escaneia o ambiente e lista redes abertas próximas (nmcli).

Saída:
- Imprime um JSON por linha (um "finding" por evento).
- Mensagens de log vão para stderr.

Requisitos de sistema:
- nmcli (NetworkManager)
- arp-scan (opcional; requer root para melhor cobertura)
"""

import os
import re
import sys
import json
import argparse
import subprocess
from pathlib import Path
from shutil import which
from typing import Set, Iterator, Dict, Any, List, Optional

def log_stderr(*args, **kwargs):
    print("wifi_check.py:", *args, file=sys.stderr, **kwargs)

def run_command(cmd: List[str], timeout: float = 20.0) -> str:
    try:
        return subprocess.check_output(cmd, text=True, stderr=subprocess.DEVNULL, timeout=timeout)
    except (FileNotFoundError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
        log_stderr(f"Comando '{cmd[0]}' falhou: {e}")
        return ""

def load_baseline(path: Path) -> Set[str]:
    if not path.exists():
        return set()
    try:
        with path.open("r", encoding="utf-8") as f:
            return {line.strip().upper() for line in f if line.strip()}
    except IOError:
        return set()

def save_new_mac_entries(path: Path, current: Set[str], previous: Set[str]) -> None:
    new_entries = sorted(list(current - previous))
    if not new_entries:
        return
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as f:
            for mac in new_entries:
                f.write(mac + "\n")
    except IOError as e:
        log_stderr(f"Falha ao atualizar a baseline '{path}': {e}")

# ---------------- Descoberta/checagens ----------------

def get_connected_wifi_iface(timeout: float) -> Optional[str]:
    """
    Retorna a interface Wi-Fi conectada (ex.: 'wlan0'), usando nmcli.
    """
    if not which("nmcli"):
        return None
    # Campos: DEVICE:TYPE:STATE
    out = run_command(["nmcli", "-t", "-f", "DEVICE,TYPE,STATE", "device"], timeout=timeout)
    for line in out.splitlines():
        # Ex.: wlp2s0:wifi:connected
        parts = line.strip().split(":")
        if len(parts) < 3:
            continue
        device, dev_type, state = parts[0], parts[1].lower(), parts[2].lower()
        if dev_type == "wifi" and state == "connected":
            return device
    return None

def check_current_connection(timeout: float) -> Iterator[Dict[str, Any]]:
    """
    Verifica a segurança da conexão Wi‑Fi atual usando nmcli.
    """
    if not which("nmcli"):
        return
    # ACTIVE:SECURITY:SSID (split limitado para preservar SSID com ':')
    out = run_command(["nmcli", "-t", "-f", "ACTIVE,SECURITY,SSID", "device", "wifi", "list", "--rescan", "no"], timeout=timeout)
    for line in out.splitlines():
        line = line.strip()
        if not line:
            continue
        # Segue o formato yes/no:SECURITY:SSID
        parts = line.split(":", 2)
        if len(parts) < 3:
            continue
        active, security, ssid = parts[0].lower(), parts[1], parts[2]
        if active != "yes":
            continue

        if not security or security == "--":
            yield {
                "message": f"Conectado a uma rede Wi‑Fi ABERTA e insegura: '{ssid}'",
                "risk_level": "CRÍTICO",
                "check_type": "Configuração Insegura (Wi‑Fi)",
                "details": {"SSID": ssid, "Criptografia": "Nenhuma"}
            }
        elif security.upper().startswith("WEP"):
            yield {
                "message": f"Conectado a uma rede Wi‑Fi com criptografia FRACA (WEP): '{ssid}'",
                "risk_level": "ALTO",
                "check_type": "Configuração Insegura (Wi‑Fi)",
                "details": {"SSID": ssid, "Criptografia": "WEP (Obsoleta)"}
            }
        # Encontrou a conexão ativa; pode encerrar.
        break

def check_new_devices(iface: str, baseline: Set[str], timeout: float) -> Iterator[Dict[str, Any]]:
    """
    Escaneia a rede local em busca de novos dispositivos usando arp-scan.
    Requer root para melhor cobertura (sem root, arp-scan pode falhar).
    """
    if not iface or not which("arp-scan"):
        return

    out = run_command(["arp-scan", "--localnet", "--interface", iface, "--quiet", "--ignoredups"], timeout=timeout)
    mac_pattern = re.compile(r"([0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5})")

    for line in out.splitlines():
        # Formato típico: <IP>\t<MAC>\t<VENDOR...>
        parts = line.strip().split()
        if len(parts) < 2:
            continue

        ip_address = parts[0]
        mac_match = mac_pattern.search(parts[1])
        if not mac_match:
            continue
        mac = mac_match.group(1).upper()
        # Fabricante: junta o resto se existir
        manufacturer = " ".join(parts[2:]) if len(parts) > 2 else "Desconhecido"

        if mac not in baseline:
            yield {
                "message": "Novo dispositivo detectado na rede Wi‑Fi",
                "risk_level": "MÉDIO",
                "check_type": "Dispositivo Desconhecido (Wi‑Fi)",
                "details": {
                    "Endereço MAC": mac,
                    "Endereço IP": ip_address,
                    "Fabricante": manufacturer or "Desconhecido",
                    "Interface": iface
                }
            }
            baseline.add(mac)

def check_wifi_environment(timeout: float) -> Iterator[Dict[str, Any]]:
    """
    Escaneia o ambiente em busca de redes Wi‑Fi abertas próximas (nmcli).
    """
    if not which("nmcli"):
        return
    out = run_command(["nmcli", "-t", "-f", "SECURITY,SSID", "device", "wifi", "list", "--rescan", "yes"], timeout=timeout)
    seen = set()
    for line in out.splitlines():
        line = line.strip()
        if not line:
            continue
        parts = line.split(":", 1)  # SECURITY:SSID (divide só uma vez)
        if len(parts) < 2:
            continue
        security, ssid = parts[0], parts[1]
        if not ssid or ssid in seen:
            continue
        seen.add(ssid)

        if not security or security == "--":
            yield {
                "message": f"Rede Wi‑Fi aberta detectada nas proximidades: '{ssid}'",
                "risk_level": "BAIXO",
                "check_type": "Ambiente Inseguro (Wi‑Fi)",
                "details": {
                    "SSID da Rede Aberta": ssid,
                    "Descrição": "Redes abertas podem ser usadas para ataques de 'Evil Twin' ou sniffing de tráfego."
                }
            }

# ---------------- Orquestrador ----------------

def main():
    parser = argparse.ArgumentParser(description="Motor de análise de segurança Wi‑Fi (sem deps Python).")
    parser.add_argument("--baseline-file", required=True, type=Path, help="Caminho do arquivo de baseline de MACs.")
    parser.add_argument("--iface", help="Interface Wi‑Fi (ex.: wlan0). Se omitido, detecta automaticamente.")
    parser.add_argument("--timeout", type=float, default=20.0, help="Timeout por comando (segundos).")
    parser.add_argument("--skip-arp-scan", action="store_true", help="Não executar varredura de dispositivos (arp-scan).")
    parser.add_argument("--skip-env-scan", action="store_true", help="Não escanear redes abertas no ambiente.")
    args = parser.parse_args()

    # Checagem de dependências
    if not which("nmcli"):
        log_stderr("Comando 'nmcli' não encontrado. Instale NetworkManager/nmcli.")
        sys.exit(1)

    # Root é recomendado para arp-scan, mas não obrigatório para nmcli
    is_root = (os.geteuid() == 0)
    if not is_root and not args.skip_arp_scan:
        log_stderr("Executando sem root; 'arp-scan' pode falhar. Use --skip-arp-scan para pular ou rode como root.")

    # Baseline
    try:
        args.baseline_file.parent.mkdir(parents=True, exist_ok=True)
    except Exception as e:
        log_stderr(f"Não foi possível criar diretório da baseline: {e}")
        sys.exit(1)
    baseline_before = load_baseline(args.baseline_file)
    baseline = set(baseline_before)  # cópia mutável

    # 1) Rede atual
    findings: List[Dict[str, Any]] = list(check_current_connection(timeout=args.timeout))

    # 2) Interface Wi‑Fi
    iface = args.iface or get_connected_wifi_iface(timeout=args.timeout)
    if not iface:
        log_stderr("Interface Wi‑Fi conectada não encontrada (nmcli). Verifique se há conexão Wi‑Fi ativa.")
    else:
        # 3) Novos dispositivos (arp-scan)
        if not args.skip_arp_scan and which("arp-scan"):
            findings.extend(check_new_devices(iface, baseline, timeout=args.timeout))

    # 4) Ambiente (redes abertas)
    if not args.skip_env_scan:
        findings.extend(check_wifi_environment(timeout=args.timeout))

    # Emite resultados (um JSON por linha)
    for f in findings:
        print(json.dumps(f, ensure_ascii=False))

    # Atualiza baseline se houve novos MACs
    if len(baseline) > len(baseline_before):
        save_new_mac_entries(args.baseline_file, baseline, baseline_before)

if __name__ == "__main__":
    main()
