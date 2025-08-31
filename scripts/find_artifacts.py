#!/usr/bin/env python3
"""
Encontra e imprime caminhos para artefatos de navegador em sistemas Linux.
Este script lida com a complexidade de encontrar perfis em instalações
nativas, Flatpak e Snap para múltiplos navegadores e, em seguida, localiza
os arquivos de artefato específicos dentro desses perfis.
"""
import os
import sys
import argparse
import configparser
from pathlib import Path
from typing import Set, List

def get_home_dirs() -> List[Path]:
    """Obtém uma lista de todos os diretórios home de usuários, incluindo /root."""
    home_dirs: Set[Path] = {Path.home()}
    try:
        if os.geteuid() == 0:
            home_dirs.add(Path("/root"))
        with open("/etc/passwd", "r") as f:
            for line in f:
                parts = line.strip().split(":")
                if len(parts) > 5 and parts[5] and parts[5] != "/":
                    home_dirs.add(Path(parts[5]))
    except (FileNotFoundError, PermissionError):
        pass
    return [d for d in home_dirs if d.is_dir()]

def find_firefox_profiles(base_dir: Path) -> List[Path]:
    """Encontra perfis do Firefox dentro de um diretório base."""
    profiles: Set[Path] = set()
    profiles_ini = base_dir / "profiles.ini"
    if profiles_ini.is_file():
        try:
            parser = configparser.ConfigParser()
            parser.read(profiles_ini)
            for section in parser.sections():
                if parser.has_option(section, "Path"):
                    profile_path = base_dir / parser.get(section, "Path")
                    if profile_path.is_dir():
                        profiles.add(profile_path)
        except configparser.Error:
            pass
    # Fallback para nomes de perfil comuns
    for profile in base_dir.glob("*.default*"):
        if profile.is_dir():
            profiles.add(profile)
    return list(profiles)

# ==============================================================================
#           ORQUESTRADOR PRINCIPAL DA CLI
# ==============================================================================

def main() -> None:
    """
    Função principal para encontrar e imprimir todos os caminhos de artefatos
    de navegador, ou opcionalmente, listar os diretórios de busca.
    """
    # 1. Definição da Interface de Linha de Comando (CLI)
    parser = argparse.ArgumentParser(
        description="Encontra e imprime caminhos para artefatos de navegador em sistemas Linux."
    )
    parser.add_argument(
        "--list-search-dirs", 
        action="store_true", 
        help="Em vez de artefatos, imprime os diretórios de perfil e base que seriam pesquisados."
    )
    args = parser.parse_args()

    # 2. Definições de Padrões de Busca
    # Facilmente extensível: para adicionar um novo navegador, basta adicionar seu caminho aqui.
    CHROMIUM_PATHS = [
        ".config/google-chrome", ".config/chromium", ".config/microsoft-edge",
        ".config/BraveSoftware/Brave-Browser", ".config/vivaldi", ".config/opera",
        # Flatpak
        ".var/app/com.google.Chrome/config/google-chrome",
        ".var/app/com.brave.Browser/config/BraveSoftware/Brave-Browser",
        # Snap
        "snap/chromium/common/chromium", "snap/brave/current/.config/BraveSoftware/Brave-Browser"
    ]
    FIREFOX_PATHS = [
        ".mozilla/firefox", ".librewolf", ".waterfox",
        # Flatpak
        ".var/app/org.mozilla.firefox/.mozilla/firefox"
    ]
    JS_ROOTS = [".config", ".mozilla", ".local/share", ".cache", "Downloads", "Desktop", "Documents"]
    NM_SYSTEM_PATHS = ["/etc/opt/chrome/native-messaging-hosts", "/usr/lib/mozilla/native-messaging-hosts"]
    ARTIFACT_FILENAMES = [
        "manifest.json", "extensions.json", "Cookies", "cookies.sqlite",
        "Preferences", "Secure Preferences", "Local State", "prefs.js", "user.js"
    ]

    # 3. Coleta de Diretórios de Perfil e Raízes de Busca
    home_dirs = get_home_dirs()
    # Usamos sets para deduplicação automática e eficiente.
    chromium_profiles: Set[Path] = set()
    firefox_profiles: Set[Path] = set()
    js_search_roots: Set[Path] = set()
    nm_search_dirs: Set[Path] = set()

    for home in home_dirs:
        # Encontra perfis Chromium-based
        for browser_path in CHROMIUM_PATHS:
            base_dir = home / browser_path
            if base_dir.is_dir():
                for profile_name in ["Default", "System Profile"] + [p.name for p in base_dir.glob("Profile *")]:
                    if (base_dir / profile_name).is_dir():
                        chromium_profiles.add(base_dir / profile_name)
        
        # Encontra perfis Firefox-based
        for browser_path in FIREFOX_PATHS:
            base_dir = home / browser_path
            if base_dir.is_dir():
                firefox_profiles.update(find_firefox_profiles(base_dir))

        # Adiciona raízes para busca de JS
        for root in JS_ROOTS:
            if (home / root).is_dir():
                js_search_roots.add(home / root)

    for nm_path in NM_SYSTEM_PATHS:
        if Path(nm_path).is_dir():
            nm_search_dirs.add(Path(nm_path))

    # 4. Lógica de Despacho com Base nos Argumentos
    if args.list_search_dirs:
        # Se a flag foi passada, imprime as listas de diretórios e sai.
        print("--- Perfis Chromium ---")
        for p in sorted(chromium_profiles): print(p)
        print("\n--- Perfis Firefox ---")
        for p in sorted(firefox_profiles): print(p)
        print("\n--- Raízes de Busca de JS ---")
        for p in sorted(js_search_roots): print(p)
        print("\n--- Diretórios de Native Messaging ---")
        for p in sorted(nm_search_dirs): print(p)
        return # Fim da execução para esta opção.

    # 5. Busca Final pelos Arquivos de Artefatos
    search_roots = chromium_profiles | firefox_profiles | js_search_roots | nm_search_dirs
    final_paths: Set[str] = set()
    
    for root in search_roots:
        # Busca por artefatos de configuração e extensões
        for artifact_name in ARTIFACT_FILENAMES:
            for found_file in root.rglob(artifact_name):
                final_paths.add(str(found_file))
        
        # Busca por arquivos de Native Messaging Hosts
        for nm_file in root.glob("*.json"):
            final_paths.add(str(nm_file))

        # Busca por arquivos JS (limitando a busca para performance)
        for js_file in root.rglob("*.js"):
             try:
                if js_file.stat().st_size < 500_000:
                    final_paths.add(str(js_file))
             except FileNotFoundError:
                continue

    # 6. Saída Padrão (para o pipeline do Bash)
    # Imprime todos os caminhos únicos encontrados, separados por NUL.
    if final_paths:
        print("\0".join(sorted(list(final_paths))), end="\0")


# Ponto de entrada padrão para um script Python
if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        # Captura qualquer exceção inesperada para evitar que o script quebre silenciosamente.
        print(f"Erro inesperado no find_artifacts.py: {e}", file=sys.stderr)
        sys.exit(1)