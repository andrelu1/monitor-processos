#!/usr/bin/env python3
# scripts/monitor-processos/network_helpers/whois_to_json.py
"""
Realiza consultas WHOIS em lote, analisa os resultados e verifica
contra uma política de rede (JSON). Emite um array JSON de alertas.

- Aceita múltiplos IPs.
- WHOIS com timeout configurável.
- Política: blocked_countries, allowed_countries, blocked_orgs, blocked_asns.
"""

import sys
import json
import subprocess
import re
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import List, Dict, Any, Optional, Set

# --- Config padrão ---
DEFAULT_MAX_WORKERS = 8
DEFAULT_TIMEOUT = 5.0  # segundos
ASN_RE = re.compile(r'\bAS(\d{1,10})\b', re.IGNORECASE)

# Mapeamento de chaves comuns em WHOIS
WHOIS_KEY_MAP = {
    "org": ("orgname", "organisation", "organization", "org-name", "descr", "netname"),
    "country": ("country", "country-code", "c"),
    "netrange": ("netrange", "inetnum", "inet6num", "cidr"),
    "abuse_email": ("orgabuseemail", "abuse-mailbox", "org-abuse-mailbox", "abuse-mail"),
    "asn": ("origin", "origin-as", "aut-num"),
}

def log_stderr(*args, **kwargs) -> None:
    print("whois_to_json.py:", *args, file=sys.stderr, **kwargs)

def parse_whois_text(output: str) -> Dict[str, Optional[str]]:
    """Analisa a saída WHOIS e extrai campos padronizados."""
    details: Dict[str, Optional[str]] = {k: None for k in WHOIS_KEY_MAP}
    for raw in output.splitlines():
        line = raw.strip()
        # ASN pode aparecer em linhas sem "chave:"
        if ":" not in line:
            if details.get("asn") is None:
                m = ASN_RE.search(line)
                if m:
                    details["asn"] = "AS" + m.group(1)
            continue

        key_raw, value = map(str.strip, line.split(":", 1))
        key_lower = key_raw.lower()

        for standard_key, possible in WHOIS_KEY_MAP.items():
            if details.get(standard_key) is None and key_lower in possible:
                if standard_key == "asn":
                    m = ASN_RE.search(value)
                    if m:
                        details["asn"] = "AS" + m.group(1)
                else:
                    details[standard_key] = value
                break

    # Normalizações
    if details.get("country"):
        details["country"] = str(details["country"]).upper()
    if details.get("org"):
        details["org"] = str(details["org"]).strip()
    if details.get("asn"):
        # Garante prefixo AS
        asn_val = str(details["asn"]).upper()
        if not asn_val.startswith("AS"):
            asn_val = "AS" + asn_val.lstrip("AS")
        details["asn"] = asn_val

    return details

def query_single_ip(ip: str, timeout: float) -> Dict[str, Any]:
    """Consulta WHOIS para um IP e retorna dicionário com campos padronizados."""
    result: Dict[str, Any] = {"ip": ip, "org": None, "country": None, "netrange": None, "abuse_email": None, "asn": None}
    try:
        output = subprocess.check_output(["whois", ip], text=True, stderr=subprocess.DEVNULL, timeout=timeout)
        whois_details = parse_whois_text(output)
        result.update({k: whois_details.get(k) for k in result.keys() if k in whois_details})
    except FileNotFoundError:
        log_stderr("Comando 'whois' não encontrado. WHOIS para", ip, "pulado.")
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
        log_stderr(f"Falha WHOIS para {ip}: {e}")
    except Exception as e:
        log_stderr(f"Erro inesperado WHOIS para {ip}: {e}")
    return result

def load_policy(policy_path: Optional[Path]) -> Dict[str, Any]:
    """Carrega JSON de política. Converte listas em conjuntos onde aplicável."""
    if not policy_path:
        return {}
    try:
        with policy_path.open("r", encoding="utf-8") as f:
            policy = json.load(f)
    except Exception as e:
        log_stderr(f"Falha ao ler política '{policy_path}': {e}")
        return {}

    # Normaliza estruturas
    blocked_countries = set(map(str.upper, policy.get("blocked_countries", [])))
    allowed_countries = set(map(str.upper, policy.get("allowed_countries", [])))
    blocked_orgs_ci = [s.lower() for s in policy.get("blocked_orgs", [])]

    # ASNs: aceita "ASNNNN" ou número; normaliza para "ASNNNN"
    blocked_asns_norm: Set[str] = set()
    for a in policy.get("blocked_asns", []):
        s = str(a).strip().upper()
        if not s.startswith("AS"):
            s = "AS" + s.lstrip("AS")
        blocked_asns_norm.add(s)

    return {
        "blocked_countries": blocked_countries,
        "allowed_countries": allowed_countries,
        "blocked_orgs_ci": blocked_orgs_ci,
        "blocked_asns_norm": blocked_asns_norm,
    }

def check_policy(ip_details: Dict[str, Any], policy: Dict[str, Any], require_allowed: bool) -> List[str]:
    """Retorna lista de motivos de violação ('triggers')."""
    triggers: List[str] = []
    org = (ip_details.get("org") or "").lower()
    country = (ip_details.get("country") or "").upper()
    asn = (ip_details.get("asn") or "").upper()

    if country and country in policy.get("blocked_countries", set()):
        triggers.append(f"blocked_country:{country}")

    if require_allowed and policy.get("allowed_countries"):
        if country and country not in policy["allowed_countries"]:
            triggers.append(f"not_allowed_country:{country}")

    for bad in policy.get("blocked_orgs_ci", []):
        if bad and bad in org:
            triggers.append(f"blocked_org:{bad}")
            break

    if asn and asn.split()[0] in policy.get("blocked_asns_norm", set()):
        triggers.append(f"blocked_asn:{asn.split()[0]}")

    return triggers

def main() -> None:
    parser = argparse.ArgumentParser(description="WHOIS em lote com verificação de política.")
    parser.add_argument("ips", nargs="*", help="Um ou mais endereços IP para verificar.")
    parser.add_argument("--policy-file", dest="policy_file", type=Path, help="Caminho para o arquivo de política (JSON).")
    parser.add_argument("--policy", dest="policy_file", type=Path, help="Alias de --policy-file.")
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT, help="Timeout WHOIS (segundos).")
    parser.add_argument("--workers", type=int, default=DEFAULT_MAX_WORKERS, help="Threads para WHOIS.")
    parser.add_argument("--require-allowed", action="store_true", help="Bloquear países fora de allowed_countries.")
    args = parser.parse_args()

    if not args.ips:
        return

    # Dedup mantendo ordem
    seen: Dict[str, None] = {}
    ips: List[str] = []
    for ip in args.ips:
        if ip not in seen:
            seen[ip] = None
            ips.append(ip)

    policy = load_policy(args.policy_file) if args.policy_file else {}
    all_alerts: List[Dict[str, Any]] = []

    # WHOIS em paralelo
    with ThreadPoolExecutor(max_workers=max(1, args.workers)) as executor:
        futures = {executor.submit(query_single_ip, ip, args.timeout): ip for ip in ips}
        for fut in as_completed(futures):
            ip = futures[fut]
            try:
                details = fut.result()
            except Exception as e:
                log_stderr(f"Exceção WHOIS para {ip}: {e}")
                continue

            # Remove campos nulos/“null” dos detalhes
            details_clean = {k: v for k, v in details.items() if v not in (None, "null", "")}

            # Alerta informativo de WHOIS (BAIXO)
            if details_clean.get("org") or details_clean.get("country"):
                all_alerts.append({
                    "risk": "BAIXO",
                    "type": "WHOIS",
                    "message": f"WHOIS do IP {ip} — Org: {details_clean.get('org') or 'N/A'}, País: {details_clean.get('country') or 'N/A'}",
                    "details": details_clean
                })

            # Política (se carregada)
            if policy:
                triggers = check_policy(details_clean, policy, args.require_allowed)
                if triggers:
                    risk = "ALTO" if any(t.startswith("blocked_") for t in triggers) else "MÉDIO"
                    all_alerts.append({
                        "risk": risk,
                        "type": "WHOIS Policy",
                        "message": f"Violação de política para {ip}: {', '.join(triggers)}",
                        "details": {**details_clean, "Triggers": ", ".join(triggers)}
                    })

    if all_alerts:
        print(json.dumps(all_alerts, ensure_ascii=False))


if __name__ == "__main__":
    main()