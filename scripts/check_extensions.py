#!/usr/bin/env python3
# scripts/check_extensions.py
"""
Motor de análise de artefatos de navegador.
Lê uma lista de caminhos de arquivo (separados por NUL) do stdin,
identifica o tipo de cada artefato e o analisa em busca de anomalias
usando um framework de analisadores modulares.
"""
import sys
import os
import json
import argparse
import hashlib
import re
import stat
import urllib.parse
from pathlib import Path
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Iterator, Dict, Any, Set, Optional, Tuple, Type

# Tenta importar fcntl, mas não quebra no Windows
try:
    import fcntl
except ImportError:
    fcntl = None

# ==============================================================================
#           CONFIGURAÇÃO E CONSTANTES
# ==============================================================================

# --- Permissões de Extensão ---
RISKY_PERMS = {
    "<all_urls>", "http://*/*", "https://*/*", "file://*/*", "activeTab", "bookmarks",
    "browsingData", "chrome://*/*", "clipboardRead", "cookies", "debugger",
    "declarativeNetRequest", "declarativeWebRequest", "downloads", "history",
    "management", "nativeMessaging", "notifications", "privacy", "proxy",
    "scripting", "tabs", "webNavigation", "webRequest", "webRequestBlocking",
}
HIGH_RISK_PERMS = {"<all_urls>", "nativeMessaging", "proxy", "debugger", "management", "scripting"}

# --- Regex para JavaScript Suspeito ---
# MUDANÇA: Corrigido o 'KATEX_INLINE_OPEN' para parênteses reais.
JS_REGEX = re.compile(
    r"eval\s*KATEX_INLINE_OPEN|Function\s*KATEX_INLINE_OPEN|fromCharCode\s*KATEX_INLINE_OPEN|atob\s*KATEX_INLINE_OPEN|"
    r"XMLHttpRequest\s*KATEX_INLINE_OPEN|fetch\s*KATEX_INLINE_OPEN|WebSocket\s*KATEX_INLINE_OPEN|"
    r"document\.write\s*KATEX_INLINE_OPEN|window\.location\s*=|"
    r"crypto\.subtle|document\.cookie",
    re.IGNORECASE | re.MULTILINE
)
JS_EXTS = {".js", ".mjs", ".cjs"}

# --- Regras de Preferências Padrão ---
DEFAULT_PREFS_RULES = {
    "score_threshold": 2, "allow_enterprise_roots": False, "enterprise_env": False,
    "allowed_search_hosts": ["google.com", "duckduckgo.com", "bing.com"],
    "allowed_homepage_hosts": ["google.com", "duckduckgo.com", "bing.com"],
    "allowed_ext_update_hosts": ["google.com", "microsoft.com", "opera.com", "mozilla.org"],
}

# ==============================================================================
#           UTILITÁRIOS GLOBAIS
# ==============================================================================
# Funções auxiliares de propósito geral usadas por várias classes de analisadores.

from pathlib import Path
from typing import Dict, Any, Set

def log_stderr(*args, **kwargs) -> None:
    """Imprime mensagens de log no stderr para não poluir a saída JSON em stdout."""
    print(f"check_extensions.py [AVISO]:", *args, file=sys.stderr, **kwargs)

def sha256_file(path: Path, max_bytes: int = 500_000) -> str:
    """Calcula o hash SHA256 dos primeiros 'max_bytes' de um arquivo."""
    h = hashlib.sha256()
    try:
        # Usa pathlib para ler os bytes do arquivo.
        h.update(path.read_bytes()[:max_bytes])
        return h.hexdigest()
    except IOError as e:
        log_stderr(f"Não foi possível ler o arquivo para hashing '{path}': {e}")
        # Retorna um fallback útil para a baseline em caso de erro.
        return f"error_hashing_{path.name}"

def get_user_from_path(path: Path) -> str:
    """Extrai o nome de usuário de um caminho de arquivo, suportando /home e /root."""
    # .parts quebra o caminho em seus componentes (ex: '/', 'home', 'user', 'file')
    parts = path.parts
    if "home" in parts:
        try:
            # O nome do usuário é o próximo componente depois de 'home'.
            return parts[parts.index("home") + 1]
        except (ValueError, IndexError):
            pass  # 'home' pode estar no nome de um arquivo.
    
    # .is_relative_to() é uma forma segura de checar se um caminho está dentro de outro.
    if path.is_relative_to("/root"):
        return "root"
    
    return "desconhecido"

def get_browser_from_path(path: Path) -> str:
    """Identifica o nome do navegador com base em padrões no caminho do arquivo."""
    # Converte o caminho completo para minúsculas para uma correspondência insensível a maiúsculas.
    path_lower = str(path).lower()
    
    # A ordem é importante: padrões mais específicos devem vir primeiro.
    patterns = [
        ("google-chrome-dev", "Google Chrome Dev"),
        ("google-chrome-beta", "Google Chrome Beta"),
        ("google-chrome", "Google Chrome"),
        ("microsoft-edge-dev", "Microsoft Edge Dev"),
        ("microsoft-edge-beta", "Microsoft Edge Beta"),
        ("microsoft-edge", "Microsoft Edge"),
        ("firefox", "Firefox"),
        ("brave", "Brave"),
        ("vivaldi", "Vivaldi"),
        ("chromium", "Chromium"),
        # Adicione outros navegadores aqui
    ]
    
    for key, name in patterns:
        if key in path_lower:
            return name
            
    return "Desconhecido"

def is_world_writable(path: Path) -> bool:
    """Verifica se um arquivo ou diretório tem permissão de escrita para 'outros'."""
    try:
        # stat.S_IWOTH é a constante para a flag 'write' para 'others'.
        return bool(path.stat().st_mode & stat.S_IWOTH)
    except OSError:
        # Ocorre se o arquivo não existir ou houver um problema de permissão para ler os metadados.
        return False

def url_host(url: str) -> str:
    """Extrai o host (domínio) de uma URL de forma segura."""
    try:
        parsed = urllib.parse.urlparse(url)
        # .netloc pode conter 'user:pass@host:port'.
        # Esta linha lida com todos esses casos para extrair apenas o host.
        return (parsed.netloc or "").split("@")[-1].split(":")[0].lower()
    except Exception:
        return ""

def host_matches_any(host: str, allow_list: Set[str]) -> bool:
    """Verifica se um host ou um de seus subdomínios está em uma lista de permissão."""
    host_lower = host.lower()
    for domain in allow_list:
        # Verifica se é uma correspondência exata ou um subdomínio.
        if host_lower == domain or host_lower.endswith("." + domain):
            return True
    return False

def load_config(baseline_dir: Path) -> Dict[str, Any]:
    """
    Carrega e mescla a configuração de regras a partir de padrões, um arquivo JSON
    e variáveis de ambiente, seguindo uma clara hierarquia de prioridades.
    """
    # 1. Começa com as regras padrão (menor prioridade).
    rules = DEFAULT_PREFS_RULES.copy()
    
    # 2. Sobrescreve com o arquivo prefs_rules.json, se existir.
    config_file = baseline_dir / "prefs_rules.json"
    if config_file.is_file():
        try:
            config_from_file = json.loads(config_file.read_text(encoding="utf-8"))
            rules.update(config_from_file)
        except (json.JSONDecodeError, IOError) as e:
            log_stderr(f"Falha ao carregar o arquivo de configuração '{config_file}': {e}")

    # 3. Sobrescreve com variáveis de ambiente (maior prioridade).
    # --- Valores simples (inteiros e booleanos) ---
    if threshold_env := os.getenv("MONITOR_PREFS_SCORE_THRESHOLD"):
        try:
            rules["score_threshold"] = int(threshold_env)
        except ValueError:
            log_stderr(f"Valor inválido para MONITOR_PREFS_SCORE_THRESHOLD: '{threshold_env}'")

    if roots_env := os.getenv("MONITOR_ENTERPRISE_ROOTS_ALLOWED"):
        rules["allow_enterprise_roots"] = roots_env.lower() in ("1", "true", "yes")

    if enterprise_env := os.getenv("MONITOR_ENTERPRISE_ENV"):
        rules["enterprise_env"] = enterprise_env.lower() in ("1", "true", "yes")

    # --- Listas (comma-separated strings) ---
    # Mapeia nomes de variáveis de ambiente para chaves de regras.
    env_lists_map = {
        "MONITOR_ALLOWED_SEARCH_HOSTS": "allowed_search_hosts",
        "MONITOR_ALLOWED_HOMEPAGE_HOSTS": "allowed_homepage_hosts",
        "MONITOR_ALLOWED_EXT_UPDATE_HOSTS": "allowed_ext_update_hosts",
    }

    for env_var, rule_key in env_lists_map.items():
        if value_str := os.getenv(env_var):
            # Converte a string "google.com, bing.com" em um set {'google.com', 'bing.com'}
            rules[rule_key] = {item.strip() for item in value_str.split(',') if item.strip()}
    
    # Finalmente, garante que todas as listas sejam sets para buscas rápidas.
    for key, value in rules.items():
        if isinstance(value, list):
            rules[key] = set(value)
            
    return rules

# ==============================================================================
#           FRAMEWORK DE ANALISADORES DE ARTEFATOS
# ==============================================================================

class ArtifactAnalyzer:
    """
    Classe base para todos os analisadores. Gerencia a lógica de baseline.

    Uma subclasse precisa definir `artifact_type` e implementar o método `analyze`.
    """
    artifact_type: str = "GENERIC"
    
    def __init__(self, baseline_dir: Path, config: Dict[str, Any]):
        self.baseline_dir = baseline_dir
        self.config = config
        self.baseline_path = self.baseline_dir / f"{self.artifact_type}.baseline"
        # Carrega a baseline uma vez na inicialização.
        self.baseline = self._load_baseline()
        # Coleta novas entradas para salvar de uma vez no final.
        self.new_ids_to_save: Set[str] = set()

    def _load_baseline(self) -> Set[str]:
        """Carrega a baseline do disco para a memória de forma segura."""
        if not self.baseline_path.exists():
            return set()
        try:
            with self.baseline_path.open("r", encoding="utf-8") as f:
                if fcntl: fcntl.flock(f, fcntl.LOCK_SH)
                data = {line.strip() for line in f if line.strip()}
                if fcntl: fcntl.flock(f, fcntl.LOCK_UN)
                return data
        except IOError:
            return set()

    def save_new_baseline_entries(self):
        """Salva todas as novas entradas de baseline coletadas de uma vez."""
        if not self.new_ids_to_save:
            return
        try:
            with self.baseline_path.open("a", encoding="utf-8") as f:
                if fcntl: fcntl.flock(f, fcntl.LOCK_EX)
                for entry_id in sorted(list(self.new_ids_to_save)):
                    f.write(f"{entry_id}\n")
                if fcntl: fcntl.flock(f, fcntl.LOCK_UN)
        except IOError as e:
            log_stderr(f"Erro ao gravar baseline '{self.baseline_path}': {e}")

    def analyze(self, path: Path) -> Iterator[Dict[str, Any]]:
        """
        Método principal de análise. As subclasses DEVEM implementar isso.
        Ele deve usar `yield` para retornar zero ou mais dicionários de alerta.
        """
        raise NotImplementedError
        yield # Isso torna a função um gerador para fins de tipagem.


# --- Analisador de Extensões do Chromium (manifest.json) ---
class ChromiumExtensionAnalyzer(ArtifactAnalyzer):
    artifact_type = "CHROMIUM_EXTENSION"
    
    def analyze(self, path: Path) -> Iterator[Dict[str, Any]]:
        ext_dir = path.parent
        ext_id = ext_dir.parent.name
        if ext_id in self.baseline: return

        try:
            manifest = json.loads(path.read_text(encoding="utf-8"))
        except (IOError, json.JSONDecodeError): return

        perms = set(manifest.get("permissions", []))
        host_perms = set(manifest.get("host_permissions", []))
        risky = (perms & RISKY_PERMS) | (host_perms & RISKY_PERMS)

        if not risky or (not (risky & HIGH_RISK_PERMS) and len(risky) < 2): return
        
        name = manifest.get("name", ext_id)
        self.new_ids_to_save.add(ext_id)
        yield {
            "message": f"NOVA extensão Chromium ('{name}') com permissões sensíveis.",
            "risk_level": "ALTO" if (risky & HIGH_RISK_PERMS) else "MÉDIO",
            "check_type": "Extensão (Chromium)",
            "details": { "user": get_user_from_path(path), "browser": get_browser_from_path(path),
                         "extension_name": name, "extension_id": ext_id,
                         "risky_permissions": ", ".join(sorted(risky)), "file_path": str(ext_dir) }
        }

# --- Analisador de Extensões do Firefox (extensions.json) ---
class FirefoxExtensionAnalyzer(ArtifactAnalyzer):
    artifact_type = "FIREFOX_EXTENSION"

    def analyze(self, path: Path) -> Iterator[Dict[str, Any]]:
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (IOError, json.JSONDecodeError): return

        for addon in data.get("addons", []):
            if addon.get("type") != "extension" or not addon.get("active", False): continue
            
            eid = addon.get("id")
            if not eid or eid in self.baseline: continue

            perms = set(addon.get("permissions", [])) | set(addon.get("optionalPermissions", []))
            origins = set((addon.get("userPermissions") or {}).get("origins", []))
            risky = (perms & RISKY_PERMS) | (origins & RISKY_PERMS)

            if not risky or (not (risky & HIGH_RISK_PERMS) and len(risky) < 2): continue

            self.new_ids_to_save.add(eid)
            yield {
                "message": f"NOVA extensão Firefox ('{addon.get('name', eid)}') com permissões sensíveis.",
                "risk_level": "ALTO" if (risky & HIGH_RISK_PERMS) else "MÉDIO",
                "check_type": "Extensão (Firefox)",
                "details": { "user": get_user_from_path(path), "browser": "Firefox",
                             "extension_name": addon.get("name", "Nome Desconhecido"), "extension_id": eid,
                             "risky_permissions": ", ".join(sorted(risky)), "file_path": str(path.parent) }
            }

# --- Analisador de Cookies ---
class CookieAnalyzer(ArtifactAnalyzer):
    artifact_type = "BROWSER_COOKIE"

    def analyze(self, path: Path) -> Iterator[Dict[str, Any]]:
        entry_id = str(path)
        if entry_id in self.baseline: return

        try:
            stat_info = path.stat()
        except IOError: return
        
        self.new_ids_to_save.add(entry_id)
        yield {
            "message": f"Arquivo de cookies do navegador detectado: {path.name}",
            "risk_level": "BAIXO",
            "check_type": "Cookie",
            "details": {
                "user": get_user_from_path(path), "browser": get_browser_from_path(path),
                "file_path": str(path), "size_bytes": stat_info.st_size,
                "modified": datetime.fromtimestamp(stat_info.st_mtime).isoformat()
            }
        }

# --- Analisador de Preferências do Chromium ---
class ChromiumPrefsAnalyzer(ArtifactAnalyzer):
    artifact_type = "CHROMIUM_PREFERENCE"

    def analyze(self, path: Path) -> Iterator[Dict[str, Any]]:
        entry_id = sha256_file(path, max_bytes=200_000)
        if entry_id in self.baseline: return

        try:
            prefs = json.loads(path.read_text(encoding="utf-8", errors="ignore"))
        except (IOError, json.JSONDecodeError): return

        issues: list[tuple[str, int]] = []
        def add_issue(code: str, severity: int = 1): issues.append((code, severity))

        if (proxy_mode := (prefs.get("proxy", {}) or {}).get("mode", "").lower()) \
           and proxy_mode not in ("system", "direct"):
            add_issue(f"proxy_mode={proxy_mode}", 2)
        
        # ... (Sua lógica completa para homepage, startup_urls, safebrowsing, etc. iria aqui) ...

        score = sum(s for _, s in issues)
        has_high_severity = any(s >= 2 for _, s in issues)
        if not issues or (score < self.config["score_threshold"] and not has_high_severity): return

        self.new_ids_to_save.add(entry_id)
        risk_level = "ALTO" if has_high_severity or score >= self.config["score_threshold"] + 2 else "MÉDIO"
        yield {
            "message": f"Alterações suspeitas no arquivo de preferências '{path.name}'.",
            "risk_level": risk_level, "check_type": "Preferência (Chromium)",
            "details": { "user": get_user_from_path(path), "file_path": str(path),
                         "issues": ", ".join(code for code, _ in issues),
                         "score": score, "threshold": self.config["score_threshold"] }
        }

# --- Analisador de Preferências do Firefox ---
class FirefoxPrefsAnalyzer(ArtifactAnalyzer):
    artifact_type = "FIREFOX_PREFERENCE"
    _PREF_LINE_RE = re.compile(r'^\s*user_prefKATEX_INLINE_OPEN\s*"([^"]+)"\s*,\s*(.+?)\s*KATEX_INLINE_CLOSE\s*;\s*$')

    def _parse_prefs_js(self, path: Path) -> Dict[str, Any]:
        # (Implementação completa do parser aqui)
        prefs = {}
        try:
            content = path.read_text(encoding="utf-8", errors="ignore")
            for line in content.splitlines():
                if match := self._PREF_LINE_RE.match(line):
                    key, raw_value = match.groups()
                    value_str = raw_value.strip()
                    if value_str.lower() == "true": parsed_value = True
                    elif value_str.lower() == "false": parsed_value = False
                    elif value_str.startswith('"') and value_str.endswith('"'):
                        parsed_value = value_str[1:-1].encode("utf-8").decode("unicode_escape", "ignore")
                    else:
                        try: parsed_value = int(value_str)
                        except ValueError: parsed_value = value_str
                    prefs[key] = parsed_value
        except IOError: pass
        return prefs

    def analyze(self, path: Path) -> Iterator[Dict[str, Any]]:
        entry_id = sha256_file(path, max_bytes=100_000)
        if entry_id in self.baseline: return

        prefs = self._parse_prefs_js(path)
        if not prefs: return
            
        issues: list[tuple[str, int]] = []
        def add_issue(code: str, severity: int = 1): issues.append((code, severity))

        # (Sua lógica completa para proxy, remote debugging, xpinstall, etc. iria aqui)
        if prefs.get("network.proxy.type", 0) != 0: add_issue("proxy_enabled", 2)
        if prefs.get("devtools.debugger.remote-enabled") is True: add_issue("remote_debugging", 2)
        
        score = sum(s for _, s in issues)
        has_high_severity = any(s >= 2 for _, s in issues)
        if not issues or (score < self.config["score_threshold"] and not has_high_severity): return

        self.new_ids_to_save.add(entry_id)
        risk_level = "ALTO" if has_high_severity or score >= self.config["score_threshold"] + 2 else "MÉDIO"
        yield {
            "message": f"Alterações suspeitas no arquivo de preferências '{path.name}'.",
            "risk_level": risk_level, "check_type": "Preferência (Firefox)",
            "details": { "user": get_user_from_path(path), "file_path": str(path),
                         "issues": ", ".join(code for code, _ in issues),
                         "score": score, "threshold": self.config["score_threshold"] }
        }

# --- Analisador de JavaScript Suspeito ---
class SuspiciousJsAnalyzer(ArtifactAnalyzer):
    artifact_type = "JAVASCRIPT_SUSPICIOUS"
    
    def analyze(self, path: Path) -> Iterator[Dict[str, Any]]:
        try:
            f_size = path.stat().st_size
            f_hash = hashlib.sha256(path.read_bytes()[:500_000]).hexdigest()
            entry_id = f"{f_hash}:{f_size}"
        except IOError: return

        if entry_id in self.baseline: return

        try:
            content = path.read_text(encoding="utf-8", errors="ignore")[:50_000]
        except IOError: return

        matches = JS_REGEX.findall(content)
        if len(matches) < 2 and not any("eval" in m.lower() for m in matches): return
            
        self.new_ids_to_save.add(entry_id)
        is_high_risk = any("eval" in m.lower() for m in matches)
        yield {
            "message": f"Possível JavaScript malicioso em '{path.name}'.",
            "risk_level": "ALTO" if is_high_risk else "MÉDIO",
            "check_type": "JavaScript Suspeito",
            "details": { "user": get_user_from_path(path), "file_path": str(path),
                         "patterns_matched": ", ".join(sorted({m.replace('(', '') for m in matches})) }
        }
        
# --- Analisador de Native Messaging Hosts ---
class NativeMessagingHostAnalyzer(ArtifactAnalyzer):
    artifact_type = "NATIVE_MESSAGING_HOST"

    def analyze(self, path: Path) -> Iterator[Dict[str, Any]]:
        entry_id = path.name
        if entry_id in self.baseline: return
            
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            bin_path = Path(data.get("path", "")) if data.get("path") else None
        except (IOError, json.JSONDecodeError): return

        is_suspicious = (
            (bin_path and (bin_path.is_relative_to(Path.home()) or "/tmp" in str(bin_path))) or
            is_world_writable(path) or (bin_path and is_world_writable(bin_path))
        )
        if not is_suspicious: return
        
        self.new_ids_to_save.add(entry_id)
        yield {
            "message": f"Novo/suspeito Native Messaging Host: '{data.get('name', entry_id)}'",
            "risk_level": "ALTO", "check_type": "Native Messaging",
            "details": { "user": get_user_from_path(path), "browser": get_browser_from_path(path),
                         "file_path": str(path), "binary_path": data.get("path", "") }
        }

# ==============================================================================
#           REGISTRO E DESPACHANTE DE ANALISADORES
# ==============================================================================
# Esta lista atua como um roteador. Ela mapeia padrões de nomes de arquivo
# (usando expressões regulares) para a classe de Analisador correspondente.
# O motor principal irá iterar sobre esta lista para cada caminho de arquivo e
# usará a *primeira* correspondência que encontrar.

# A ordem é importante: padrões mais específicos devem vir antes de padrões mais gerais.
# Por exemplo, a verificação de 'manifest.json' deve vir antes da verificação genérica de '.json'.

ANALYZER_REGISTRY: list[tuple[re.Pattern, Type[ArtifactAnalyzer]]] = [
    # 1. Arquivos de manifesto de extensão (muito específicos)
    (re.compile(r'manifest\.json$'), ChromiumExtensionAnalyzer),
    (re.compile(r'extensions\.json$'), FirefoxExtensionAnalyzer),
    
    # 2. Arquivos de preferências (nomes específicos)
    (re.compile(r'/(Preferences|Secure Preferences|Local State)$'), ChromiumPrefsAnalyzer),
    (re.compile(r'/(prefs\.js|user\.js)$'), FirefoxPrefsAnalyzer),
    
    # 3. Arquivos de cookies (nomes específicos)
    (re.compile(r'/(Cookies|cookies\.sqlite)$'), CookieAnalyzer),
    
    # 4. Arquivos de configuração de Native Messaging (padrão de caminho específico)
    (re.compile(r'native-messaging-hosts/.*\.json$'), NativeMessagingHostAnalyzer),
    
    # 5. Arquivos JavaScript (padrão genérico de extensão)
    # Colocado no final porque é o padrão mais amplo.
    # Evita que ele capture arquivos como 'extensions.json' por engano.
    (re.compile(r'\.(js|mjs|cjs)$'), SuspiciousJsAnalyzer),
]

# ==============================================================================
#           ORQUESTRADOR PRINCIPAL
# ==============================================================================
# A função 'main' atua como o motor do script. Ela gerencia a execução,
# delega tarefas para os analisadores corretos usando um pool de threads e
# formata a saída final.

def main() -> None:
    """
    Orquestra a análise completa: lê caminhos, despacha para analisadores,
    executa em paralelo, salva baselines e imprime alertas em JSON.
    """
    # 1. Inicialização e Configuração
    parser = argparse.ArgumentParser(
        description="Analisa artefatos de navegador a partir de uma lista de caminhos do stdin."
    )
    parser.add_argument(
        "--baseline-dir", required=True, type=Path,
        help="Diretório para ler e salvar os arquivos de baseline."
    )
    args = parser.parse_args()
    
    # Garante que o diretório de baseline exista.
    args.baseline_dir.mkdir(exist_ok=True)
    # Carrega a configuração global (padrões -> JSON -> ENV vars).
    config = load_config(args.baseline_dir)

    # 2. Leitura dos Dados de Entrada
    # Lê todos os caminhos de arquivo do stdin, que são separados por NUL (\0)
    # pelo script Bash para lidar com nomes de arquivo complexos de forma segura.
    try:
        raw_input = sys.stdin.buffer.read().decode(errors="surrogateescape")
        paths_to_check = [Path(p) for p in raw_input.split("\0") if p]
    except Exception as e:
        log_stderr(f"Erro ao ler caminhos do stdin: {e}")
        return

    if not paths_to_check:
        return # Sai silenciosamente se não houver nada a fazer.

    # 3. Despacho e Execução Paralela
    # Dicionário para armazenar uma única instância de cada analisador,
    # evitando carregar a mesma baseline várias vezes.
    analyzer_instances: Dict[Type[ArtifactAnalyzer], ArtifactAnalyzer] = {}

    def get_analyzer_instance(cls: Type[ArtifactAnalyzer]) -> ArtifactAnalyzer:
        """Cria ou retorna uma instância em cache de uma classe de analisador."""
        if cls not in analyzer_instances:
            analyzer_instances[cls] = cls(args.baseline_dir, config)
        return analyzer_instances[cls]
    
    all_alerts = []
    # Usa um ThreadPoolExecutor para executar as análises em paralelo.
    with ThreadPoolExecutor(max_workers=os.cpu_count() or 4) as executor:
        # Mapeia cada 'future' (tarefa em execução) ao caminho que ela está processando.
        # Isso é crucial para um bom logging de erros.
        future_to_path = {}
        
        for path in paths_to_check:
            # Itera sobre o registro para encontrar o analisador correto.
            for pattern, analyzer_class in ANALYZER_REGISTRY:
                if pattern.search(str(path)):
                    instance = get_analyzer_instance(analyzer_class)
                    # Submete a tarefa de análise para o pool de threads.
                    # list() consome o gerador 'analyze' e retorna uma lista de alertas.
                    future = executor.submit(list, instance.analyze(path))
                    future_to_path[future] = path
                    break  # Usa o primeiro analisador que corresponder.

        # Coleta os resultados à medida que são concluídos.
        for future in as_completed(future_to_path):
            path = future_to_path[future]
            try:
                # .result() obtém a lista de alertas ou levanta uma exceção se a tarefa falhou.
                alerts_from_path = future.result()
                all_alerts.extend(alerts_from_path)
            except Exception as e:
                # Se uma análise falhar, loga o erro e continua com as outras.
                log_stderr(f"Erro inesperado ao processar o caminho '{path}': {e}")

    # 4. Persistência de Estado
    # Após todas as análises, salva todas as novas entradas de baseline de uma vez.
    for instance in analyzer_instances.values():
        instance.save_new_baseline_entries()
        
    # 5. Saída de Dados
    # Imprime cada alerta coletado como uma linha JSON para o script Bash consumir.
    for alert in all_alerts:
        print(json.dumps(alert, ensure_ascii=False))


if __name__ == "__main__":
    main()        