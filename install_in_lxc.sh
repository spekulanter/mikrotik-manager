#!/bin/bash
#
# MikroTik Backup Manager - Smart Installer/Updater
# Deteguje existujúcu inštaláciu a spustí buď inštaláciu alebo update
#
set -e

# Funkcie pre farebný výstup
function msg_info() { echo -e "\\033[1;34mINFO\\033[0m: $1"; }
function msg_ok() { echo -e "\\033[1;32mSUCCESS\\033[0m: $1"; }
function msg_warn() { echo -e "\\033[1;33mWARNING\\033[0m: $1"; }

# Premenné
REPO_URL="https://github.com/spekulanter/mikrotik-manager.git"
APP_DIR="/opt/mikrotik-manager"
DATA_DIR="/var/lib/mikrotik-manager"
SERVICE_FILE="/etc/systemd/system/mbm.service"

# Kontrola, či už existuje inštalácia
if [ -d "${APP_DIR}" ] && [ -f "${SERVICE_FILE}" ] && systemctl is-enabled mbm.service &>/dev/null; then
    echo "🔄 Detegovaná existujúca inštalácia - spúšťam aktualizáciu..."
    
    # UPDATE PROCES
    msg_info "Zastavujem službu MikroTik Backup Manager..."
    systemctl stop mbm.service &>/dev/null
    msg_ok "Služba zastavená."
    
    msg_info "Zálohujem aktuálnu konfiguráciu..."
    # Záloha databázy a konfiguračných súborov
    if [ -d "${DATA_DIR}/data" ]; then
        cp -r ${DATA_DIR}/data ${DATA_DIR}/data.backup.$(date +%Y%m%d_%H%M%S) 2>/dev/null || true
    fi
    msg_ok "Konfigurácia zálohovaná."
    
    msg_info "Sťahujem najnovšie zmeny z ${REPO_URL}..."
    cd ${APP_DIR}
    # Resetuj na najnovší main branch (prepíše lokálne zmeny)
    git fetch origin
    git reset --hard origin/main
    msg_ok "Kód aktualizovaný."
    
    msg_info "Aktualizujem Python závislosti..."
    source ${APP_DIR}/venv/bin/activate
    pip install -r ${APP_DIR}/requirements.txt &>/dev/null
    deactivate
    msg_ok "Závislosti aktualizované."
    
    msg_info "Spúšťam službu..."
    systemctl start mbm.service &>/dev/null
    msg_ok "Služba spustená."
    
    echo "✅ Aktualizácia dokončená!"
    echo "🌐 Aplikácia je dostupná na: http://$(hostname -I | awk '{print $1}'):5000"
    
else
    echo "🆕 Spúšťam čerstvú inštaláciu..."
    
    # INŠTALAČNÝ PROCES
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
ExecStart=/opt/mikrotik-manager/venv/bin/gunicorn --worker-class eventlet -w 1 --bind 0.0.0.0:5000 "app:app"
Restart=always
RestartSec=10
Environment="DATA_DIR=${DATA_DIR}/data"

[Install]
WantedBy=multi-user.target
EOF
    msg_ok "Súbor pre službu vytvorený."
    
    # Povolenie a spustenie služby
    msg_info "Povoľujem a spúšťam službu MikroTik Backup Manager..."
    systemctl daemon-reload
    systemctl enable --now mbm.service &>/dev/null
    msg_ok "Služba mbm.service je aktívna a beží."
    
    echo "🎉 Inštalácia dokončená!"
    echo "🌐 Aplikácia je dostupná na: http://$(hostname -I | awk '{print $1}'):5000"
    echo "📋 Prvé prihlásenie: vytvorte si účet cez registračný formulár"
    
fi

echo ""
echo "📖 Užitočné príkazy:"
echo "   Reštart služby:    systemctl restart mbm.service"
echo "   Stav služby:       systemctl status mbm.service"  
echo "   Logy služby:       journalctl -u mbm.service -f"
echo "   Manuálny update:   cd ${APP_DIR} && ./update.sh"