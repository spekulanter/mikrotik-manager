#!/bin/bash
#
# MikroTik Manager - Smart Installer/Updater v2.0
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
if [ -d "${APP_DIR}/.git" ]; then
    echo "🔄 Detegovaná existujúca inštalácia - spúšťam aktualizáciu..."

    # Nastavenie časovej zóny
    if [ "$(timedatectl show --property=Timezone --value 2>/dev/null)" != "Europe/Bratislava" ]; then
        msg_info "Nastavujem časovú zónu na Europe/Bratislava..."
        timedatectl set-timezone Europe/Bratislava 2>/dev/null || true
        msg_ok "Časová zóna nastavená."
    fi

    # UPDATE PROCES
    msg_info "Zastavujem službu MikroTik Manager..."
    systemctl stop mikrotik-manager.service 2>/dev/null || true
    systemctl kill mikrotik-manager.service 2>/dev/null || true
    sleep 1
    msg_ok "Služba zastavená."
    
    msg_info "Zálohujem aktuálnu konfiguráciu..."
    # Záloha databázy a konfiguračných súborov
    if [ -d "${DATA_DIR}/data" ]; then
        cp -r ${DATA_DIR}/data ${DATA_DIR}/data.backup.$(date +%Y%m%d_%H%M%S) 2>/dev/null || true
    fi
    msg_ok "Konfigurácia zálohovaná."
    
    msg_info "Sťahujem najnovšie zmeny z ${REPO_URL}..."
    cd ${APP_DIR}
    # Jednoduchý a spoľahlivý update
    git fetch origin >/dev/null 2>&1
    git reset --hard origin/main >/dev/null 2>&1
    git clean -fd >/dev/null 2>&1
    git pull origin main >/dev/null 2>&1
    msg_ok "Kód aktualizovaný na najnovšiu verziu."
    
    # Kontrola a vytvorenie Python Virtual Environment ak neexistuje
    if [ ! -d "${APP_DIR}/venv" ]; then
        msg_info "Vytváram chýbajúce Python Virtual Environment..."
        python3 -m venv ${APP_DIR}/venv
        msg_ok "Virtual environment vytvorené."
    fi
    
    msg_info "Aktualizujem Python závislosti..."
    source ${APP_DIR}/venv/bin/activate
    pip install --quiet -r ${APP_DIR}/requirements.txt >/dev/null 2>&1
    deactivate
    msg_ok "Závislosti aktualizované."

    # Kontrola a aktualizácia Android development nástrojov
    msg_info "Kontrolujem Android development nástroje..."

    # Node.js 18.x check
    if ! command -v node &> /dev/null || [[ "$(node -v)" != "v18."* ]]; then
        msg_info "Aktualizujem Node.js na verziu 18.x..."
        curl -fsSL https://deb.nodesource.com/setup_18.x | bash - >/dev/null 2>&1 || true
        apt-get install -y nodejs >/dev/null 2>&1 || true
    fi
    
    # Android SDK check
    if [ ! -d "/opt/android-sdk/cmdline-tools" ]; then
        msg_info "Inštalujem chýbajúce Android SDK..."
        mkdir -p /opt/android-sdk
        cd /tmp
        wget -q https://dl.google.com/android/repository/commandlinetools-linux-11076708_latest.zip 2>/dev/null || true
        unzip -q commandlinetools-linux-11076708_latest.zip -d /opt/android-sdk/ 2>/dev/null || true
        mv /opt/android-sdk/cmdline-tools /opt/android-sdk/cmdline-tools-temp 2>/dev/null || true
        mkdir -p /opt/android-sdk/cmdline-tools/latest
        mv /opt/android-sdk/cmdline-tools-temp/* /opt/android-sdk/cmdline-tools/latest/ 2>/dev/null || true
        rmdir /opt/android-sdk/cmdline-tools-temp 2>/dev/null || true
        rm commandlinetools-linux-11076708_latest.zip 2>/dev/null || true
        cd ${APP_DIR}
    fi
    
    # Gradle check
    if [ ! -d "/opt/gradle" ]; then
        msg_info "Inštalujem chýbajúci Gradle..."
        cd /tmp
        wget -q https://services.gradle.org/distributions/gradle-8.13-bin.zip -O /tmp/gradle-8.13-bin.zip 2>/dev/null || true
        unzip -q /tmp/gradle-8.13-bin.zip 2>/dev/null || true
        mv gradle-8.13 /opt/gradle 2>/dev/null || true
        rm -f /tmp/gradle-8.13-bin.zip 2>/dev/null || true
        cd ${APP_DIR}
    fi
    
    # Environment setup check
    if [ ! -f "/etc/profile.d/android-dev.sh" ]; then
        msg_info "Aktualizujem environment setup..."
        cat << 'PROFEOF' > /etc/profile.d/android-dev.sh
export ANDROID_HOME=/opt/android-sdk
export ANDROID_SDK_ROOT=/opt/android-sdk
export PATH=${PATH}:${ANDROID_HOME}/cmdline-tools/latest/bin:${ANDROID_HOME}/platform-tools:/opt/gradle/bin
export JAVA_HOME=/usr/lib/jvm/java-17-openjdk-amd64
PROFEOF
        chmod +x /etc/profile.d/android-dev.sh
    fi
    
    msg_ok "Android development nástroje skontrolované."
    
    # Vytvorenie adresárov ak neexistujú
    msg_info "Kontrolujem adresáre..."
    mkdir -p ${DATA_DIR}/data/backups 2>/dev/null || true
    chown -R root:root ${APP_DIR} 2>/dev/null || true
    chown -R root:root ${DATA_DIR} 2>/dev/null || true
    msg_ok "Adresáre skontrolované."
    
    # Aktualizácia systemd service súboru (možné zmeny)
    msg_info "Kontrolujem systemd službu..."
    cat << EOF > ${SERVICE_FILE}
[Unit]
Description=MikroTik Manager
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
    systemctl daemon-reload 2>/dev/null || true
    msg_ok "Systemd služba skontrolovaná."
    
    # APK building info
    msg_info "Native Android APK build je dostupný cez:"
    msg_info "  cd ${APP_DIR} && bash build-apk.sh"
    
    # Automatické skopírovanie pre-built APK
    if [ ! -f "/opt/MT Manager.apk" ] && [ -f "${APP_DIR}/MT Manager.apk" ]; then
        msg_info "Kopírujem pre-built Android APK..."
        cp "${APP_DIR}/MT Manager.apk" "/opt/MT Manager.apk"
        rm -f "${APP_DIR}/MT Manager.apk"
        msg_ok "APK skopírovaný z repozitára: /opt/MT Manager.apk"
    elif [ -f "/opt/MT Manager.apk" ]; then
        msg_info "Android APK už existuje: /opt/MT Manager.apk"
        # Vymaž APK z repozitára ak existuje
        rm -f "${APP_DIR}/MT Manager.apk"
    else
        msg_warn "APK nenájdený. Pre vytvorenie spusti: cd /opt/mikrotik-manager && bash build-apk.sh"
    fi
    
    # Kontrola a doainštalácia Android build-tools ak potrebné
    if [ -d "/opt/android-sdk" ]; then
        msg_info "Kontrolujem Android build-tools..."
        export ANDROID_HOME=/opt/android-sdk
        export ANDROID_SDK_ROOT=/opt/android-sdk
        export PATH=${PATH}:${ANDROID_HOME}/cmdline-tools/latest/bin:${ANDROID_HOME}/platform-tools
        if [ ! -d "/opt/android-sdk/build-tools/34.0.0" ]; then
            msg_info "Inštalujem chýbajúce Android build-tools 34.0.0..."
            /opt/android-sdk/cmdline-tools/latest/bin/sdkmanager "build-tools;34.0.0" >/dev/null 2>&1
            msg_ok "Android build-tools 34.0.0 nainštalované."
        else
            msg_info "Android build-tools 34.0.0 už sú nainštalované."
        fi
    fi
    
    # Vymazanie Python cache pre zaručené načítanie nového kódu
    msg_info "Čistím Python cache..."
    find ${APP_DIR} -name "*.pyc" -delete 2>/dev/null || true
    find ${APP_DIR} -name "__pycache__" -type d -exec rm -rf {} + 2>/dev/null || true
    msg_ok "Cache vymazaná."
    
    msg_info "Spúšťam službu..."
    systemctl enable mikrotik-manager.service 2>/dev/null || true
    systemctl start mikrotik-manager.service 2>/dev/null || true
    sleep 2
    msg_ok "Služba spustená."
    
    echo "✅ Aktualizácia dokončená!"
    echo "🌐 Aplikácia je dostupná na: http://$(hostname -I | awk '{print $1}'):5000"
    
else
    echo "🆕 Spúšťam čerstvú inštaláciu..."

    # Nastavenie časovej zóny
    if [ "$(timedatectl show --property=Timezone --value 2>/dev/null)" != "Europe/Bratislava" ]; then
        msg_info "Nastavujem časovú zónu na Europe/Bratislava..."
        timedatectl set-timezone Europe/Bratislava 2>/dev/null || true
        msg_ok "Časová zóna nastavená."
    fi

    # INŠTALAČNÝ PROCES
    # Aktualizácia systému a inštalácia závislostí
    msg_info "Aktualizujem systém a inštalujem potrebné balíčky..."
    apt-get update >/dev/null 2>&1
    apt-get install -y git python3-pip python3-venv curl wget unzip openjdk-17-jdk >/dev/null 2>&1
    msg_ok "Systémové závislosti sú nainštalované."
    
    # Inštalácia Node.js 18.x
    msg_info "Inštalujem Node.js 18.x pre Android development..."
    if ! command -v node &> /dev/null || [[ "$(node -v)" != "v18."* ]]; then
        curl -fsSL https://deb.nodesource.com/setup_18.x | bash - >/dev/null 2>&1
        apt-get install -y nodejs >/dev/null 2>&1
    else
        msg_info "Node.js 18.x už je nainštalované, preskakujem..."
    fi
    msg_ok "Node.js nainštalované: $(node -v 2>/dev/null || echo 'ready')"
    
    # Inštalácia Android SDK
    msg_info "Inštalujem Android SDK pre APK building..."
    if [ ! -d "/opt/android-sdk/cmdline-tools" ]; then
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
        yes | /opt/android-sdk/cmdline-tools/latest/bin/sdkmanager --licenses >/dev/null 2>&1
        /opt/android-sdk/cmdline-tools/latest/bin/sdkmanager "platform-tools" "platforms;android-35" "build-tools;35.0.0" "build-tools;34.0.0" >/dev/null 2>&1
    else
        msg_info "Android SDK už je nainštalované, kontrolujem build-tools..."
        export ANDROID_HOME=/opt/android-sdk
        export ANDROID_SDK_ROOT=/opt/android-sdk
        export PATH=${PATH}:${ANDROID_HOME}/cmdline-tools/latest/bin:${ANDROID_HOME}/platform-tools
        # Doainštaluj chýbajúce build-tools ak potrebné
        if [ ! -d "/opt/android-sdk/build-tools/34.0.0" ]; then
            msg_info "Inštalujem chýbajúce Android build-tools 34.0.0..."
            /opt/android-sdk/cmdline-tools/latest/bin/sdkmanager "build-tools;34.0.0" >/dev/null 2>&1
        fi
    fi
    msg_ok "Android SDK nainštalované."
    
    # Inštalácia Gradle
    msg_info "Inštalujem Gradle build system..."
    if [ ! -d "/opt/gradle" ]; then
        # Vymaž staré Gradle súbory ak existujú
        rm -rf /opt/gradle-8.13 2>/dev/null || true
        rm -f /tmp/gradle.zip 2>/dev/null || true
        
        wget -q https://services.gradle.org/distributions/gradle-8.13-bin.zip -O /tmp/gradle.zip
        cd /tmp
        unzip -q gradle.zip
        mv gradle-8.13 /opt/gradle
        rm -f gradle.zip
    else
        msg_info "Gradle už je nainštalované, preskakujem..."
    fi
    export PATH=${PATH}:/opt/gradle/bin
    msg_ok "Gradle nainštalované: $(gradle -v 2>/dev/null | head -n1 || echo 'Gradle ready')"
    
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
    git clone ${REPO_URL} ${APP_DIR} >/dev/null 2>&1
    msg_ok "Aplikácia stiahnutá."
    
    # APK building info
    msg_info "Native Android APK build je dostupný cez:"
    msg_info "  cd ${APP_DIR} && bash build-apk.sh"
    msg_ok "Android template pripravený."
    
    # Stiahnutie Android APK z repozitára
    msg_info "Pripravujem Android APK..."
    if [ ! -f "/opt/MT Manager.apk" ]; then
        if [ -f "${APP_DIR}/MT Manager.apk" ]; then
            cp "${APP_DIR}/MT Manager.apk" "/opt/MT Manager.apk"
            rm -f "${APP_DIR}/MT Manager.apk"
            msg_ok "APK skopírovaný z repozitára: /opt/MT Manager.apk"
        else
            msg_warn "Pre-built APK nenájdený v repozitári. Na vytvorenie APK spusti manuálne: bash build-apk.sh"
        fi
    else
        msg_ok "APK už existuje: /opt/MT Manager.apk"
    fi
    
    # Vytvorenie Python Virtual Environment
    msg_info "Vytváram izolované Python prostredie (venv)..."
    python3 -m venv ${APP_DIR}/venv
    msg_ok "Virtual environment vytvorené."
    
    # Inštalácia Python knižníc
    msg_info "Inštalujem potrebné Python knižnice..."
    source ${APP_DIR}/venv/bin/activate
    pip install --quiet -r ${APP_DIR}/requirements.txt >/dev/null 2>&1
    deactivate
    msg_ok "Knižnice nainštalované."
    
    # Vytvorenie a nastavenie systemd služby
    msg_info "Vytváram systemd službu pre automatické spúšťanie..."
    cat << EOF > ${SERVICE_FILE}
[Unit]
Description=MikroTik Manager
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
    msg_info "Povoľujem a spúšťam službu MikroTik Manager..."
    systemctl daemon-reload
    systemctl enable --now mikrotik-manager.service >/dev/null 2>&1
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
    echo ""
    echo "🛠️  APK Building:"
    echo "   cd ${APP_DIR} && bash build-apk.sh"
    
fi

echo ""
echo "📖 Užitočné príkazy:"
echo "   Reštart služby:    systemctl restart mikrotik-manager.service"
echo "   Stav služby:       systemctl status mikrotik-manager.service"  
echo "   Logy služby:       journalctl -u mikrotik-manager.service -f"
echo "   Manuálny update:   cd ${APP_DIR} && ./update.sh"
echo ""
echo "📱 Native Android APK Development:"
echo "   Build APK:         cd ${APP_DIR} && bash build-apk.sh"
echo "   Android template:  ${APP_DIR}/template/"
echo "   Finálny APK:       /opt/MT Manager.apk"
