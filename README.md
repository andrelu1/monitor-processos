# Threat Hunter for Linux

![Versão](https://img.shields.io/badge/versão-2.0-blue)
![Licença](https://img.shields.io/badge/licença-MIT-green)
![Shell](https://img.shields.io/badge/shell-Bash-lightgrey)
![Compatibilidade](https://img.shields.io/badge/compatibilidade-Arch%20Linux-blueviolet)

Script de Caça a Ameaças (Threat Hunting) e Resposta a Incidentes para Linux (foco em Arch Linux), combinando orquestração em Bash com análise em Python para oferecer uma solução de linha de comando eficaz e informativa.

## Funcionalidades

- Análise de Processos:
  - Monitoramento de processos com maior consumo de CPU/Memória.
  - Risk Scoring (pontuação de risco) a partir de múltiplas heurísticas.
  - Detecção de mascaramento, execução “fileless” (binário deletado) e abuso de LD_PRELOAD.
- Análise de Rede:
  - Identificação de listeners novos/não autorizados.
  - Monitoramento de conexões externas (outbound).
  - Enriquecimento com inteligência:
    - DNSBL: IPs públicos em blacklists.
    - WHOIS: dados de registro de IPs suspeitos.
  - Políticas de rede (bloqueio/liberação por país, organização, ASN).
- Persistência:
  - Cron (sistema/usuário), serviços systemd habilitados.
  - Arquivos de inicialização de Shell (.bashrc, .profile, etc.).
  - Novas chaves SSH autorizadas.
- Escalação de Privilégios e Evasão:
  - Integridade de arquivos críticos (ex.: /etc/sudoers).
  - Novos arquivos SUID/SGID.
  - Arquivos imutáveis (+i) em diretórios de sistema.
  - Timestomping.
- Rootkits:
  - Baseline de módulos do kernel (LKM).
  - Detecção de sockets ocultos (comparando ss e lsof).
- Forense:
  - Históricos de comandos (padrões maliciosos).
  - Assinaturas de web shells em diretórios web.
- Guia de Resposta a Incidentes:
  - Menu interativo para revisar alertas.
  - Ações rápidas: matar processos, quarentena de arquivos, bloqueio de IPs.

## Requisitos

- Bash e sudo
- Suporte a gerenciadores: pacman, apt, dnf, yum, zypper, apk
- Dependências opcionais são detectadas automaticamente (yara, git, jq, python3, etc.). O script tenta instalar quando possível ou ajusta funcionalidades.

## Instalação Rápida

1) Clone o repositório:
```bash
git clone https://github.com/andrelu1/monitor-processos.git
cd monitor-processos
chmod +x monitor_processo.sh

    Rode a primeira vez (cria toda a estrutura automaticamente):

Bash

sudo ./monitor_processo.sh

Notas:

    Na primeira execução, o script cria logs/, baselines/, quarentena/, etc.
    O módulo YARA baixa as regras e, se necessário, compila o YARA do fonte com módulos extras (dex, cuckoo, magic, dotnet). Isso pode levar alguns minutos.

Uso

    Varredura completa (padrão):

Bash

sudo ./monitor_processo.sh

    Guia de Resposta a Incidentes (sem nova varredura):

Bash

sudo ./monitor_processo.sh --resposta-apenas

    Outras opções:
    | Flag | Descrição      |
    |-----------------------|---------------------------------------------------------------------------|
    | --scan-completo       | Executa a varredura completa (padrão).                                    |
    | --resposta-apenas     | Pula a varredura e abre o menu de análise de alertas anteriores.          |
    | --criar-baselines     | Cria/recria arquivos de baseline (hashes, LKM, etc.) e sai.               |
    | --dry-run             | Executa a varredura sem enviar notificações externas.                     |
    | -h, --ajuda           | Exibe a ajuda.                                                            |

Configuração (.env)

Crie um .env na raiz para personalizar o comportamento. Exemplo:

ini

# Notificações
TELEGRAM_SEND=true
TELEGRAM_TOKEN="seu_token"
TELEGRAM_CHAT_ID="seu_chat_id"
EMAIL_SEND=false

# Thresholds (descomente para sobrescrever)
# RISK_THRESHOLD=5
# CPU_THRESHOLD=25.0
# MEM_THRESHOLD=40.0

# Rede
# NET_USE_BASELINE=true
# NET_SCAN_OUTBOUND=true

# YARA
AUTO_UPDATE_YARA_RULES=true              # baixa/atualiza regras automaticamente
YARA_AUTO_COMPILE=true                   # compila YARA com módulos extras se necessário
# YARA_RULES_INDEX_FILENAME="index.yar"  # força um índice específico (opcional)

# Tempo/execução
# RUN_CHECK_TIMEOUT=120                  # timeout global por verificação (segundos)
# BROWSER_TIMEOUT=180                    # timeout específico do módulo de navegadores
# PRE_CLEAN_JSON=false                   # limpar JSON antes da execução (limpeza sempre ocorre ao final)
# EXIT_ON_THREATS=true                   # se true, retorna exit 1 quando houver novas ameaças

# Prompt do Response Helper ao final da varredura:
# new    -> pergunta se houver alertas novos nesta execução
# any    -> pergunta se existir qualquer alerta no log (padrão)
# always -> pergunta sempre ao final, mesmo sem alertas
# never  -> nunca pergunta automaticamente
# RESPONSE_PROMPT_MODE=any

Módulo YARA — como funciona

    Regras:
        Baixa/atualiza o repositório oficial: https://github.com/Yara-Rules/rules.git
        Tenta compilar índices padrão (index.yar, index_community.yar, etc.).
        Se falhar, constrói automaticamente um conjunto mínimo de regras compatíveis com seu YARA (fallback).
    Módulos extras:
        Se faltarem módulos (dex, cuckoo, magic, dotnet) e YARA_AUTO_COMPILE=true, o script compila o YARA do fonte com:
            ./configure --enable-cuckoo --enable-dex --enable-magic --enable-dotnet
        Alternativa (Arch/Manjaro): use o AUR (ex.: yara-git) caso não queira compilar na hora.
    Pastas criadas:
        yara-rules/: wrapper main.yar com includes absolutos.
        yara-rules-repo/: repositório clonado (regras).

Estrutura criada automaticamente

    logs/: alertas.log, alertas.jsonl
    baselines/: diversas baselines (hashes, LKM, rede, sudoers, etc.)
    quarentena/: arquivos isolados
    yara-rules/, yara-rules-repo/
    historico/, scripts/

Dicas e Troubleshooting

    Primeira execução demorando:
        Normal se o YARA for compilado com módulos extras. Acompanhe pelo logs/alertas.log.
    YARA “fallback”:
        Se os índices não compilarem, o script ativa um conjunto compatível automaticamente (exibe contagem de regras incluídas).
    Forçar atualização de regras YARA:
        Apague o main.yar e rode novamente:

Bash

rm -f ./yara-rules/main.yar
sudo ./monitor_processo.sh

    Verificar módulos do YARA:

Bash

echo -e 'import "dex"\nrule t{condition:true}' > /tmp/d.yar
yarac /tmp/d.yar /dev/null && echo "DEX OK" || echo "DEX FALHOU"

Contribuições

Contribuições são bem-vindas! Abra uma Issue ou envie um Pull Request com melhorias, novas técnicas de detecção, correções de bugs ou otimizações.
Licença

MIT — veja LICENSE.
Desenvolvedor

André
GitHub: https://github.com/andrelu1/monitor-processos