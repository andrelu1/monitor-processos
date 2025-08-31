#!/usr/bin/env python3
# scripts/monitor-processos/network_helpers/dnsbl_check.py
"""
Verifica IPs contra DNSBLs (blacklists DNS).
- Aceita múltiplos IPs e imprime um array JSON de alertas para IPs listados.
- Opcionalmente usa dnspython (dns.resolver) para controle de timeout e nameservers.
- Pula IPs privados/locais (por padrão), deduplica entradas e controla paralelismo.
"""

import sys
import json
import socket
import argparse
import ipaddress
from concurrent.futures import ThreadPoolExecutor
from typing import List, Dict, Optional, Any

# Tenta usar dnspython para timeouts/nameservers finos
try:
    import dns.resolver  # type: ignore
    HAVE_DNSPYTHON = True
except Exception:
    dns = None
    HAVE_DNSPYTHON = False

# --- Constantes ---
DNSBL_V4 = [
    "zen.spamhaus.org",
    "bl.spamcop.net",
    "dnsbl.sorbs.net",
    "b.barracudacentral.org",
]
DNSBL_V6 = ["zen.spamhaus.org"]  # Spamhaus também suporta IPv6
DEFAULT_MAX_WORKERS = 10
DEFAULT_TIMEOUT = 3.0  # segundos

# --- Helpers de log ---
def log_stderr(*args, **kwargs) -> None:
    print(*args, file=sys.stderr, **kwargs)

# --- Helpers de transformação ---
def reverse_v4(ip: str) -> str:
    return ".".join(reversed(ip.split(".")))

def reverse_v6_nibble(ip: str) -> str:
    try:
        ip6 = ipaddress.IPv6Address(ip)
        # reverse_pointer -> '<nibbles>.ip6.arpa'
        ptr = ip6.reverse_pointer
        if ptr.endswith(".ip6.arpa"):
            ptr = ptr[:-9]
        return ptr
    except ipaddress.AddressValueError:
        return ""

def is_skippable_ip(ip_obj: ipaddress._BaseAddress) -> bool:
    # Pula IPs que não fazem sentido em DNSBL público
    return any([
        ip_obj.is_private,
        ip_obj.is_loopback,
        ip_obj.is_multicast,
        ip_obj.is_link_local,
        ip_obj.is_reserved,
        ip_obj.is_unspecified,
    ])

def risk_from_count(n: int) -> str:
    # Ajusta risco com base na quantidade de listas
    if n >= 3:
        return "CRÍTICO"
    if n == 2:
        return "ALTO"
    return "MÉDIO"  # 1 lista

# --- Resolvedores DNSBL ---
def listed_with_dnspython(query: str, timeout: float, nameservers: Optional[List[str]]) -> bool:
    assert HAVE_DNSPYTHON
    try:
        r = dns.resolver.Resolver()
        r.lifetime = timeout
        r.timeout = timeout
        if nameservers:
            r.nameservers = nameservers
        # Consultamos tipo A (DNSBL usualmente retorna 127.0.0.x)
        r.resolve(query, "A")
        return True
    except dns.resolver.NXDOMAIN:
        return False
    except dns.resolver.NoAnswer:
        return False
    except dns.resolver.Timeout:
        log_stderr(f"[AVISO] Timeout ao consultar '{query}'")
        return False
    except Exception as e:
        log_stderr(f"[AVISO] Erro dnspython ao consultar '{query}': {e}")
        return False

def listed_with_socket(query: str) -> bool:
    # Fallback stdlib: usa resolver do SO; sem controle fino de timeout
    try:
        socket.gethostbyname(query)
        return True
    except socket.gaierror:
        return False
    except Exception as e:
        log_stderr(f"[AVISO] Erro de socket ao consultar '{query}': {e}")
        return False

def check_single_ip(ip: str, timeout: float, nameservers: Optional[List[str]], skip_private: bool) -> Optional[Dict[str, Any]]:
    """
    Verifica um único IP e retorna um dicionário de alerta se listado.
    Retorna None se limpo/ignorado.
    """
    try:
        ip_obj = ipaddress.ip_address(ip)
    except ValueError:
        log_stderr(f"[AVISO] Ignorando IP inválido: {ip}")
        return None

    if skip_private and is_skippable_ip(ip_obj):
        return None

    is_ipv6 = ip_obj.version == 6
    reversed_label = reverse_v6_nibble(ip) if is_ipv6 else reverse_v4(ip)
    if not reversed_label:  # IPv6 inválido para reverse nibble
        return None

    servers_to_check = DNSBL_V6 if is_ipv6 else DNSBL_V4

    listed_in: List[str] = []
    for dnsbl_server in servers_to_check:
        query = f"{reversed_label}.{dnsbl_server}"
        if HAVE_DNSPYTHON:
            listed = listed_with_dnspython(query, timeout, nameservers)
        else:
            listed = listed_with_socket(query)
        if listed:
            listed_in.append(dnsbl_server)

    if listed_in:
        n = len(listed_in)
        return {
            "risk": risk_from_count(n),
            "type": "DNSBL",
            "message": f"DNSBL: IP {ip} listado em {n} blacklist(s)",
            "details": {
                "IP": ip,
                "IP_Version": "IPv6" if is_ipv6 else "IPv4",
                "Total_Listas": str(n),
                "Listas": ", ".join(listed_in),
            },
        }
    return None

# --- Função Principal ---
def main() -> None:
    parser = argparse.ArgumentParser(description="Verifica IPs contra servidores DNSBL.")
    parser.add_argument("ips", nargs="*", help="Um ou mais endereços IP para verificar.")
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT, help="Timeout por consulta DNS (segundos).")
    parser.add_argument("--workers", type=int, default=DEFAULT_MAX_WORKERS, help="Número de threads paralelas.")
    parser.add_argument("--skip-private", action="store_true", default=True, help="Ignorar IPs privados/locais (padrão).")
    parser.add_argument("--no-skip-private", dest="skip_private", action="store_false", help="Não ignorar IPs privados/locais.")
    parser.add_argument("--nameserver", action="append", dest="nameservers",
                        help="Nameserver para usar (pode repetir). Requer dnspython.")
    args = parser.parse_args()

    if not args.ips:
        return

    # Deduplica mantendo ordem
    seen: Dict[str, None] = {}
    ips_ordered: List[str] = []
    for ip in args.ips:
        if ip not in seen:
            seen[ip] = None
            ips_ordered.append(ip)

    alerts: List[Dict[str, Any]] = []
    with ThreadPoolExecutor(max_workers=max(1, args.workers)) as executor:
        futures = [executor.submit(check_single_ip, ip, args.timeout, args.nameservers, args.skip_private)
                   for ip in ips_ordered]
        for fut in futures:
            try:
                res = fut.result()
                if res:
                    alerts.append(res)
            except Exception as e:
                log_stderr(f"[AVISO] Exceção ao processar IP: {e}")

    if alerts:
        print(json.dumps(alerts, ensure_ascii=False))

if __name__ == "__main__":
    main()