#!/usr/bin/env python3
# scripts/network_helpers/ip_checker.py
"""
Verifica se um IP pertence a uma ou mais redes CIDR.

Uso:
  python3 ip_checker.py <IP> <CIDR_1> [CIDR_2 ...]
  python3 ip_checker.py <IP> --file cidrs.txt
  echo "192.168.0.0/16" | python3 ip_checker.py 192.168.1.10 -

Retorno:
  0 = IP pertence a pelo menos uma rede
  1 = IP não pertence a nenhuma rede (ou entrada inválida)
"""

import sys
import argparse
import ipaddress
from typing import List, Iterable

def iter_cidrs(args: argparse.Namespace) -> Iterable[str]:
    # via arquivo
    if args.file:
        with open(args.file, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    yield line
    # via stdin (-)
    if args.cidr_networks and len(args.cidr_networks) == 1 and args.cidr_networks[0] == '-':
        for line in sys.stdin:
            line = line.strip()
            if line and not line.startswith('#'):
                yield line
    # via args posicionais
    else:
        for c in args.cidr_networks:
            if c != '-':
                yield c

def main() -> None:
    parser = argparse.ArgumentParser(description="Verifica se um IP pertence a uma ou mais redes CIDR.")
    parser.add_argument("ip_address", help="Endereço IP a verificar (IPv4 ou IPv6).")
    parser.add_argument("cidr_networks", nargs='*', help="Redes no formato CIDR (ex.: 192.168.1.0/24). Use '-' para stdin.")
    parser.add_argument("--file", help="Arquivo com uma rede CIDR por linha (pode usar comentários com #).")
    args = parser.parse_args()

    try:
        ip_to_check = ipaddress.ip_address(args.ip_address)
    except ValueError:
        print(f"ip_checker.py [AVISO]: IP inválido '{args.ip_address}'", file=sys.stderr)
        sys.exit(1)

    matched = False
    for cidr_str in iter_cidrs(args):
        try:
            # strict=False permite 'host/prefix'
            network = ipaddress.ip_network(cidr_str, strict=False)
        except ValueError:
            # CIDR inválido: ignore
            continue
        # Ignora redes de versão diferente
        if ip_to_check.version != network.version:
            continue
        if ip_to_check in network:
            matched = True
            break

    sys.exit(0 if matched else 1)

if __name__ == "__main__":
    main()