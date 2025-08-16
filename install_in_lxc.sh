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
SERVICE_FILE="/etc/systemd/system/mikrotik-manager.service"

# Kontrola, či už existuje inštalácia
if [ -d "${APP_DIR}" ] && [ -f "${SERVICE_FILE}" ] && systemctl is-enabled mikrotik-manager.service &>/dev/null; then
    echo "🔄 Detegovaná existujúca inštalácia - spúšťam aktualizáciu..."
    
    # UPDATE PROCES
    msg_info "Zastavujem službu MikroTik Backup Manager..."
    systemctl stop mikrotik-manager.service &>/dev/null
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
    systemctl start mikrotik-manager.service &>/dev/null
    msg_ok "Služba spustená."
    
    echo "✅ Aktualizácia dokončená!"
    echo "🌐 Aplikácia je dostupná na: http://$(hostname -I | awk '{print $1}'):5000"
    
else
    echo "🆕 Spúšťam čerstvú inštaláciu..."
    
    # INŠTALAČNÝ PROCES
    # Aktualizácia systému a inštalácia závislostí
    msg_info "Aktualizujem systém a inštalujem potrebné balíčky..."
    apt-get update &>/dev/null
    apt-get install -y git python3-pip python3-venv curl wget unzip openjdk-17-jdk &>/dev/null
    msg_ok "Systémové závislosti sú nainštalované."
    
    # Inštalácia Node.js 18.x
    msg_info "Inštalujem Node.js 18.x pre Android development..."
    curl -fsSL https://deb.nodesource.com/setup_18.x | bash - &>/dev/null
    apt-get install -y nodejs &>/dev/null
    msg_ok "Node.js nainštalované: $(node -v)"
    
    # Inštalácia Android SDK
    msg_info "Inštalujem Android SDK pre APK building..."
    mkdir -p /opt/android-sdk
    cd /tmp
    wget -q https://dl.google.com/android/repository/commandlinetools-linux-11076708_latest.zip
    unzip -q commandlinetools-linux-11076708_latest.zip -d /opt/android-sdk/
    mv /opt/android-sdk/cmdline-tools /opt/android-sdk/cmdline-tools-temp
    mkdir -p /opt/android-sdk/cmdline-tools/latest
    mv /opt/android-sdk/cmdline-tools-temp/* /opt/android-sdk/cmdline-tools/latest/
    rmdir /opt/android-sdk/cmdline-tools-temp
    rm commandlinetools-linux-11076708_latest.zip
    
    # Nastavenie Android SDK environment
    export ANDROID_HOME=/opt/android-sdk
    export ANDROID_SDK_ROOT=/opt/android-sdk
    export PATH=${PATH}:${ANDROID_HOME}/cmdline-tools/latest/bin:${ANDROID_HOME}/platform-tools
    
    # Inštalácia Android SDK komponentov
    yes | /opt/android-sdk/cmdline-tools/latest/bin/sdkmanager --licenses &>/dev/null
    /opt/android-sdk/cmdline-tools/latest/bin/sdkmanager "platform-tools" "platforms;android-35" "build-tools;35.0.0" &>/dev/null
    msg_ok "Android SDK nainštalované."
    
    # Inštalácia Gradle
    msg_info "Inštalujem Gradle build system..."
    wget -q https://services.gradle.org/distributions/gradle-8.13-bin.zip -O /tmp/gradle.zip
    unzip -q /tmp/gradle.zip -d /opt/
    mv /opt/gradle-8.13 /opt/gradle
    rm /tmp/gradle.zip
    export PATH=${PATH}:/opt/gradle/bin
    msg_ok "Gradle nainštalované: $(gradle -v | head -n1)"
    
    # Inštalácia Cordova CLI
    msg_info "Inštalujem Cordova CLI pre mobile app development..."
    npm install -g cordova &>/dev/null
    msg_ok "Cordova nainštalované: $(cordova -v)"
    
    # Vytvorenie environment setup file
    msg_info "Vytváram environment setup súbor..."
    cat << 'ENVEOF' > /etc/environment
ANDROID_HOME=/opt/android-sdk
ANDROID_SDK_ROOT=/opt/android-sdk
PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/opt/android-sdk/cmdline-tools/latest/bin:/opt/android-sdk/platform-tools:/opt/gradle/bin"
JAVA_HOME=/usr/lib/jvm/java-17-openjdk-amd64
ENVEOF
    
    # Vytvorenie profile setup
    cat << 'PROFEOF' > /etc/profile.d/android-dev.sh
export ANDROID_HOME=/opt/android-sdk
export ANDROID_SDK_ROOT=/opt/android-sdk
export PATH=${PATH}:${ANDROID_HOME}/cmdline-tools/latest/bin:${ANDROID_HOME}/platform-tools:/opt/gradle/bin
export JAVA_HOME=/usr/lib/jvm/java-17-openjdk-amd64
PROFEOF
    chmod +x /etc/profile.d/android-dev.sh
    msg_ok "Android development prostredie nastavené."
    
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
    systemctl enable --now mikrotik-manager.service &>/dev/null
    msg_ok "Služba mikrotik-manager.service je aktívna a beží."
    
    echo "🎉 Inštalácia dokončená!"
    echo "🌐 Web aplikácia je dostupná na: http://$(hostname -I | awk '{print $1}'):5000"
    echo "📋 Prvé prihlásenie: vytvorte si účet cez registračný formulár"
    echo ""
    echo "📱 Android Development Tools nainštalované:"
    echo "   • Node.js $(node -v 2>/dev/null || echo 'N/A')"
    echo "   • Java $(java -version 2>&1 | head -n1 | cut -d'"' -f2 2>/dev/null || echo 'N/A')"
    echo "   • Android SDK v35.0.0"
    echo "   • Gradle $(gradle -v 2>/dev/null | head -n1 | awk '{print $2}' || echo 'N/A')"
    echo "   • Cordova $(cordova -v 2>/dev/null || echo 'N/A')"
    echo ""
    echo "🛠️  APK Building:"
    echo "   cd /opt/mikrotik-manager-app && cordova build android"
    
fi

echo ""
echo "📖 Užitočné príkazy:"
echo "   Reštart služby:    systemctl restart mikrotik-manager.service"
echo "   Stav služby:       systemctl status mikrotik-manager.service"  
echo "   Logy služby:       journalctl -u mikrotik-manager.service -f"
echo "   Manuálny update:   cd ${APP_DIR} && ./update.sh"
echo ""
echo "📱 Android APK Development:"
echo "   Build APK:         cd ${APP_DIR} && ./build-apk.sh"
echo "   Cordova projekt:   /opt/mikrotik-manager-app/"
echo "   Finálny APK:       /opt/MikroTikManager.apk"