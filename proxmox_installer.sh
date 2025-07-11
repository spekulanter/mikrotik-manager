#!/bin/bash
#
# MikroTik Backup Manager - Proxmox VE Helper Script v4.4
# Inšpirované filozofiou tteck.io - s automatickou inštaláciou jq a správnym odkazom
#
set -e

# Funkcie pre farebný výstup
function msg_info() { echo -e "\\033[1;34mINFO\\033[0m: $1"; }
function msg_ok() { echo -e "\\033[1;32mSUCCESS\\033[0m: $1"; }
function msg_error() { echo -e "\\033[1;31mERROR\\033[0m: $1"; }

# Premenné
REPO_URL="https://github.com/spekulanter/mikrotik-manager.git"
APP_DIR="/opt/mikrotik-manager"

# --- Kontrola a inštalácia `jq` na Proxmox hostiteľovi ---
if ! command -v jq &> /dev/null; then
    msg_info "Požadovaný nástroj 'jq' nebol nájdený. Spúšťam inštaláciu..."
    apt-get update >/dev/null
    apt-get install -y jq >/dev/null
    msg_ok "'jq' bol úspešne nainštalovaný."
fi

# --- Interaktívna časť pre novú inštaláciu ---
msg_info "Spúšťam interaktívny inštalátor MikroTik Backup Manager..."

STORAGE_TYPE=$(pvesm status -content images | awk 'NR>1 {print $2}' | head -n 1)
DEFAULT_ID=$(pvesh get /cluster/nextid)
DEFAULT_HOSTNAME="mikrotik-manager"
DEFAULT_DISK="10"
DEFAULT_CORES="1"
DEFAULT_RAM="1024"
DEFAULT_BRIDGE=$(pvesh get /nodes/$(hostname)/network --output-format json | jq -r '.[] | select(.type=="bridge") | .iface')
DEFAULT_GW=$(ip r | grep default | awk '{print $3}')

read -p "Zadajte ID pre nový LXC kontajner [${DEFAULT_ID}]: " CTID
CTID=${CTID:-$DEFAULT_ID}

read -p "Zadajte Hostname pre kontajner [${DEFAULT_HOSTNAME}]: " CT_HOSTNAME
CT_HOSTNAME=${CT_HOSTNAME:-$DEFAULT_HOSTNAME}

read -p "Zadajte veľkosť disku v GB [${DEFAULT_DISK}]: " DISK_SIZE
DISK_SIZE=${DISK_SIZE:-$DEFAULT_DISK}

read -p "Zadajte počet CPU jadier [${DEFAULT_CORES}]: " CORE_COUNT
CORE_COUNT=${CORE_COUNT:-$DEFAULT_CORES}

read -p "Zadajte veľkosť RAM v MB [${DEFAULT_RAM}]: " RAM_SIZE
RAM_SIZE=${RAM_SIZE:-$DEFAULT_RAM}

read -p "Zadajte názov sieťového mosta (bridge) [${DEFAULT_BRIDGE}]: " BRIDGE
BRIDGE=${BRIDGE:-$DEFAULT_BRIDGE}

IP_TYPE=""
while [[ $IP_TYPE != "dhcp" && $IP_TYPE != "static" ]]; do
  read -p "Použiť DHCP alebo Statickú IP? (dhcp/static): " IP_TYPE
done

if [ "$IP_TYPE" == "static" ]; then
  read -p "Zadajte Statickú IP adresu s maskou (napr. 192.168.1.250/24): " STATIC_IP
  read -p "Zadajte Gateway (bránu) [${DEFAULT_GW}]: " GW
  GW=${GW:-$DEFAULT_GW}
  NET_CONFIG="ip=${STATIC_IP},gw=${GW}"
else
  NET_CONFIG="ip=dhcp"
fi

# --- Inštalácia ---
msg_info "Sťahujem Debian 12 LXC šablónu (ak je potrebná)..."
pveam download local debian-12-standard &>/dev/null

msg_info "Vytváram LXC kontajner (ID: ${CTID}) s vašimi nastaveniami..."
pct create $CTID local:vztmpl/debian-12-standard*.tar.zst \
    --hostname $CT_HOSTNAME \
    --password $(openssl rand -base64 12) \
    --cores $CORE_COUNT \
    --memory $RAM_SIZE \
    --swap 512 \
    --rootfs $STORAGE_TYPE:$DISK_SIZE \
    --net0 name=eth0,bridge=$BRIDGE,${NET_CONFIG} \
    --onboot 1 \
    --start 1 &>/dev/null
msg_ok "LXC kontajner ${CTID} vytvorený a spustený."

msg_info "Čakám na sieťové pripojenie..."
sleep 5
while [ -z "$(pct exec $CTID -- ip -4 a s eth0 | grep -oP '(?<=inet\s)\d+(\.\d+){3}')" ]; do
  sleep 1
done
IP_ADDRESS=$(pct exec $CTID -- ip -4 a s eth0 | grep -oP '(?<=inet\s)\d+(\.\d+){3}')
msg_ok "Kontajner má IP adresu: ${IP_ADDRESS}"

msg_info "Spúšťam inštaláciu aplikácie vnútri LXC..."
pct exec $CTID -- bash -c ' \
    apt-get update && apt-get install -y git python3-pip python3-venv &>/dev/null; \
    DATA_DIR="/var/lib/mikrotik-manager"; \
    mkdir -p '"$APP_DIR"'; \
    mkdir -p ${DATA_DIR}/data/backups; \
    git clone '"$REPO_URL"' '"$APP_DIR"'; \
    python3 -m venv '"$APP_DIR"'/venv; \
    source '"$APP_DIR"'/venv/bin/activate; \
    pip install -r '"$APP_DIR"'/requirements.txt &>/dev/null; \
    deactivate; \
    cat << EOF > /etc/systemd/system/mbm.service
[Unit]
Description=MikroTik Backup Manager
After=network.target
[Service]
Type=simple
User=root
Group=root
WorkingDirectory='"$APP_DIR"'
ExecStart='"$APP_DIR"'/venv/bin/gunicorn --workers 3 --bind 0.0.0.0:5000 "app:app"
Restart=always
RestartSec=10
Environment="DATA_DIR=${DATA_DIR}/data"
[Install]
WantedBy=multi-user.target
EOF
    cat << '"'"'EOF'"'"' > '"$APP_DIR"'/update.sh
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
    chmod +x '"$APP_DIR"'/update.sh; \
    systemctl daemon-reload; \
    systemctl enable --now mbm.service &>/dev/null; \
'
msg_ok "Inštalácia aplikácie v LXC dokončená."

# Finálne informácie
echo -e "\\n\\n🎉 Inštalácia dokončená! 🎉"
echo -e "Aplikácia MikroTik Backup Manager je dostupná na adrese:"
echo -e "   🌐 http://${IP_ADDRESS}:5000"
echo
echo -e "Užitočné príkazy:"
echo -e "   - Prihlásenie do kontajnera: pct enter ${CTID}"
echo -e "   - Zobrazenie logov: journalctl -u mbm.service -f (po prihlásení do LXC)"
echo -e "   - Aktualizácia: /opt/mikrotik-manager/update.sh (po prihlásení do LXC)"
echo