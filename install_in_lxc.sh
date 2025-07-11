#!/bin/bash
#
# MikroTik Backup Manager - In-LXC Installer
#
set -e

# Funkcie pre farebný výstup
function msg_info() { echo -e "\\033[1;34mINFO\\033[0m: $1"; }
function msg_ok() { echo -e "\\033[1;32mSUCCESS\\033[0m: $1"; }

# Premenné
REPO_URL="https://github.com/spekulanter/mikrotik-manager.git"
APP_DIR="/opt/mikrotik-manager"
DATA_DIR="/var/lib/mikrotik-manager"

# Aktualizácia systému a inštalácia závislostí
msg_info "Aktualizujem systém a inštalujem potrebné balíčky..."
apt-get update &>/dev/null
apt-get install -y git python3-pip python3-venv &>/dev/null
msg_ok "Systémové závislosti sú nainštalované."

# Vytvorenie adresárov
msg_info "Vytváram adresáre aplikácie a pre dáta..."
mkdir -p ${APP_DIR}
mkdir -p ${DATA_DIR}/data/backups
chown -R root:root ${APP_DIR}
chown -R root:root ${DATA_DIR}
msg_ok "Adresáre sú pripravené."

# Klonovanie repozitára
msg_info "Sťahujem aplikáciu z ${REPO_URL}..."
git clone ${REPO_URL} ${APP_DIR} &>/dev/null
msg_ok "Aplikácia stiahnutá."

# Vytvorenie Python Virtual Environment
msg_info "Vytváram izolované Python prostredie (venv)..."
python3 -m venv ${APP_DIR}/venv
msg_ok "Virtual environment vytvorené."

# Inštalácia Python knižníc
msg_info "Inštalujem potrebné Python knižnice..."
source ${APP_DIR}/venv/bin/activate
pip install -r ${APP_DIR}/requirements.txt &>/dev/null
deactivate
msg_ok "Knižnice nainštalované."

# Vytvorenie a nastavenie systemd služby
SERVICE_FILE="/etc/systemd/system/mbm.service"
msg_info "Vytváram systemd službu pre automatické spúšťanie..."
cat << EOF > ${SERVICE_FILE}
[Unit]
Description=MikroTik Backup Manager
After=network.target

[Service]
Type=simple
User=root
Group=root
WorkingDirectory=${APP_DIR}
ExecStart=${APP_DIR}/venv/bin/gunicorn --workers 3 --bind 0.0.0.0:5000 "app:app"
Restart=always
RestartSec=10
Environment="DATA_DIR=${DATA_DIR}/data"

[Install]
WantedBy=multi-user.target
EOF
msg_ok "Súbor pre službu vytvorený."

# Vytvorenie nového update skriptu
UPDATE_SCRIPT_PATH="${APP_DIR}/update.sh"
msg_info "Vytváram nový aktualizačný skript..."
cat << 'EOF' > ${UPDATE_SCRIPT_PATH}
#!/bin/bash
set -e
echo "🔄 Aktualizujem MikroTik Backup Manager..."
systemctl stop mbm.service
cd /opt/mikrotik-manager
git pull origin main
source venv/bin/activate
pip install -r requirements.txt
deactivate
systemctl start mbm.service
echo "✅ Aplikácia bola úspešne aktualizovaná."
EOF
chmod +x ${UPDATE_SCRIPT_PATH}
msg_ok "Nový update.sh vytvorený."

# Povolenie a spustenie služby
msg_info "Povoľujem a spúšťam službu MikroTik Backup Manager..."
systemctl daemon-reload
systemctl enable --now mbm.service &>/dev/null
msg_ok "Služba mbm.service je aktívna a beží."

echo -e "\\n\\n🎉 Inštalácia v LXC dokončená! 🎉"