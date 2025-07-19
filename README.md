# Monitor de Processos - Arch Linux

Sistema completo para monitoramento de processos atípicos, com:

- Análise periódica
- Monitoramento em tempo real (inotify)
- Interface gráfica com Zenity
- Integração com Telegram e e-mail
- Histórico de processos e hash de binários

---

## Estrutura do Projeto

monitor-processos/
├── monitor_processo.sh          # Script principal de escaneamento
├── monitor_gui.sh               # Interface gráfica com Zenity
├── monitor_realtime.sh          # Monitoramento de /tmp e similares com inotify
├── processo_whitelist.txt       # Lista de processos confiáveis
├── hash_db.txt                  # Hashes dos binários verificados
├── alertas.log                  # Log de alertas
├── .env                         # Cadastro para envio de e-mail e Telegram
├── historico/                   # Snapshots dos processos
├── requisitos.txt               # Lista de pacotes necessários 
├── install.sh                   # Script de instalação 
└── service/                     # Arquivos para o systemd
├── monitor_processo.service
├── monitor_processo.timer
└── monitor_realtime.service


---

## Instalação (Automática)

### 1. Dê permissão e execute:

```bash
chmod +x install.sh
./install.sh

    O script irá:

        Instalar os pacotes necessários
        Criar arquivos e pastas obrigatórios
        Copiar e ativar os serviços systemd
        Atualizar o banco de dados do man
        Mostrar este README no final

 Instalação manual de pacotes

sudo pacman -S --needed $(< requisitos.txt)

Ou:

sudo pacman -S bc curl mailutils inotify-tools unhide zenity coreutils procps-ng inetutils psmisc man-db util-linux iproute2 gnome-terminal

 Configuração do .env

Crie o arquivo .env com as variáveis de alerta:

TELEGRAM_SEND=true
TELEGRAM_TOKEN=123456:ABC-DEF
TELEGRAM_CHAT_ID=12345678

EMAIL_SEND=true
EMAIL_DEST=seuemail@dominio.com

    Configure apenas o que desejar usar (ambos são opcionais).

Ativar monitoramento automático com systemd

O sistema usa o systemd para rodar os monitoramentos automaticamente:

    monitor_processo.timer: roda o monitor_processo.sh a cada 10 minutos
    monitor_realtime.service: monitora diretórios como /tmp com inotify

Opção 1: Se os arquivos .service e .timer EXISTIREM

sudo cp service/*.service /etc/systemd/system/
sudo cp service/*.timer /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now monitor_processo.timer
sudo systemctl enable --now monitor_realtime.service

Opção 2: Criar os arquivos manualmente (caso não existam)
1. Crie o diretório:

mkdir -p service

2. Crie service/monitor_processo.service:

[Unit]
Description=Análise periódica de processos
After=network.target

[Service]
Type=oneshot
ExecStart=/home/SEU_USUARIO/monitor-processos/monitor_processo.sh
WorkingDirectory=/home/SEU_USUARIO/monitor-processos

3. Crie service/monitor_processo.timer:

[Unit]
Description=Executa o monitoramento de processos a cada 10 minutos

[Timer]
OnBootSec=1min
OnUnitActiveSec=10min
Unit=monitor_processo.service

[Install]
WantedBy=timers.target

4. Copie para o systemd:

sudo cp service/monitor_processo.* /etc/systemd/system/

5. Recarregue e ative:

sudo systemctl daemon-reexec
sudo systemctl daemon-reload
sudo systemctl enable --now monitor_processo.timer

6. Verifique:

systemctl status monitor_processo.timer

Ativar o monitoramento em tempo real
1. Crie service/monitor_realtime.service:

[Unit]
Description=Monitoramento em tempo real com inotify
After=network.target

[Service]
Type=simple
ExecStart=/home/SEU_USUARIO/monitor-processos/monitor_realtime.sh
WorkingDirectory=/home/SEU_USUARIO/monitor-processos
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target

2. Copie e ative:

sudo cp service/monitor_realtime.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now monitor_realtime.service

Interface gráfica (Zenity)

Execute com:

./monitor_gui.sh

Permite:

    Rodar análise manual ou em modo de teste
    Ver alertas recentes
    Gerenciar whitelist
    Ver histórico de snapshots
    Obter ajuda sobre qualquer processo
    Limpar o log de alertas

Teste manual
Análise principal:

./monitor_processo.sh

Modo de teste (sem Telegram/e-mail):

./monitor_processo.sh --dry-run

Monitoramento em tempo real:

./monitor_realtime.sh

Arquivos importantes
Arquivo / Pasta 	Função
processo_whitelist.txt 	Lista de comandos confiáveis (um por linha)
hash_db.txt     	Hashes SHA256 dos binários monitorados
alertas.log     	Log principal de alertas
historico/      	Snapshot de todos os processos analisados
.env 	                Configurações de alerta por Telegram e/ou e-mail

Alertas detectados

O sistema detecta automaticamente:

    Processos fora da whitelist
    Execução em /tmp, /dev/shm, etc
    Nomes de processos suspeitos
    Processos iniciados por shell
    Binários deletados
    Alto uso de CPU ou memória
    Binários modificados (hash alterado)
    Binários não pertencentes a pacotes
    Conexões de rede externas
    Processos ocultos (via unhide)

Manutenção automática

    Logs antigos do diretório historico/ são compactados após 7 dias
    Alertas duplicados são ignorados por execução
    O banco man é atualizado automaticamente com mandb -q

Requisitos Necessarios para a execução

    Arch Linux
    Pacotes: veja requisitos.txt

Autor

André

Licença
MIT

Este projeto está licenciado sob os termos da [Licença MIT](LICENSE).


