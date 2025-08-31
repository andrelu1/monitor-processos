#!/usr/bin/env python3
# scripts/network_helpers/ip_policy_check.py
"""
Verifica um IP contra uma política (countries/orgs/ASNs) e imprime um alerta JSON se houver match.
Usa ip-api.com para metadados (sem chave; rate-limit público ~45 req/min).

Uso:
  python3 ip_policy_check.py --policy policy.json <IP>
Opções:
  --timeout 3.0      Timeout HTTP (segundos)
  --require-allowed  Se definido, bloqueia IPs cujo país não esteja em allowed_countries
"""

import sys
import json
import argparse
import urllib.request
import urllib.error
from typing import Any, Dict, Optional

def load_policy(path: str) -> Dict[str, Any]:
    with open(path, 'r', encoding='utf-8') as f:
        policy = json.load(f)
    # normaliza listas
    for k in ("blocked_countries", "allowed_countries", "blocked_orgs", "blocked_asns"):
        if k not in policy or not isinstance(policy[k], list):
            policy[k] = []
    # normaliza case/formatos
    policy["blocked_countries"] = [c.upper() for c in policy["blocked_countries"]]
    policy["allowed_countries"] = [c.upper() for c in policy["allowed_countries"]]
    policy["blocked_orgs_ci"] = [s.lower() for s in policy["blocked_orgs"]]
    # ASNs: aceita "ASNNNN" ou número; normaliza para "ASNNNN"
    norm_asn = []
    for a in policy["blocked_asns"]:
        a = str(a).strip().upper()
        if not a.startswith("AS"):
            a = "AS" + a.lstrip("AS")
        norm_asn.append(a)
    policy["blocked_asns_norm"] = norm_asn
    return policy

def fetch_ip_meta(ip: str, timeout: float = 3.0) -> Optional[Dict[str, Any]]:
    url = f"http://ip-api.com/json/{ip}?fields=status,countryCode,as,org,isp,query"
    req = urllib.request.Request(url, headers={"User-Agent": "ip_policy_check/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8", "replace"))
            if data.get("status") != "success":
                return None
            return data
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError):
        return None
    except Exception:
        return None

def main() -> None:
    parser = argparse.ArgumentParser(description="Verifica um IP contra políticas (pais/ASN/org).")
    parser.add_argument("--policy", required=True, help="Caminho do JSON de política.")
    parser.add_argument("ip", help="Endereço IP a verificar.")
    parser.add_argument("--timeout", type=float, default=3.0, help="Timeout HTTP (segundos).")
    parser.add_argument("--require-allowed", action="store_true",
                        help="Se definido, bloqueia países fora de allowed_countries.")
    args = parser.parse_args()

    policy = load_policy(args.policy)
    meta = fetch_ip_meta(args.ip, timeout=args.timeout)
    if not meta:
        # Sem metadados; não retorna alerta (outra camada decide o que fazer)
        return

    cc = (meta.get("countryCode") or "").upper()
    asn = (meta.get("as") or "").upper()      # ex.: "AS15169 Google LLC"
    org = (meta.get("org") or "").lower()
    isp = (meta.get("isp") or "").lower()

    hits = []

    # 1) País bloqueado
    if cc and cc in policy["blocked_countries"]:
        hits.append(f"País bloqueado: {cc}")

    # 2) ASN bloqueado
    if asn:
        asn_code = asn.split()[0]  # "ASNNNN"
        if asn_code in policy["blocked_asns_norm"]:
            hits.append(f"ASN bloqueado: {asn_code}")

    # 3) Org/ISP bloqueados (substring case-insensitive)
    text = f"{org} {isp}".strip()
    for bad in policy["blocked_orgs_ci"]:
        if bad and bad in text:
            hits.append(f"Org/ISP bloqueado: {bad}")
            break

    # 4) Fora de allowed_countries (se exigido)
    if args.require_allowed and policy["allowed_countries"]:
        if cc and cc not in policy["allowed_countries"]:
            hits.append(f"País não permitido (policy allowlist): {cc}")

    if not hits:
        return

    # Risco (simples): mais hits -> mais alto
    if len(hits) >= 2:
        risk = "ALTO"
    else:
        risk = "MÉDIO"

    alert = {
        "risk": risk,
        "type": "WHOIS Policy",
        "message": f"IP {args.ip} viola política: {', '.join(hits)}",
        "details": {
            "IP": args.ip,
            "Country": cc,
            "ASN": asn,
            "Org": meta.get("org") or "",
            "ISP": meta.get("isp") or "",
            "Hits": "; ".join(hits),
        }
    }
    print(json.dumps(alert, ensure_ascii=False))

if __name__ == "__main__":
    main()
