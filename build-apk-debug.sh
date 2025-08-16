#!/bin/bash
#
# MikroTik Manager - APK Build Diagnostika
# Pre debugging APK build problémov
#
set -e

echo "🔍 APK Build Diagnostika"
echo "========================="

# Kontrola prostredia
echo "📋 Environment:"
echo "   ANDROID_HOME: ${ANDROID_HOME:-'❌ nie je nastavené'}"
echo "   ANDROID_SDK_ROOT: ${ANDROID_SDK_ROOT:-'❌ nie je nastavené'}"  
echo "   JAVA_HOME: ${JAVA_HOME:-'❌ nie je nastavené'}"
echo "   PATH obsahuje android tools: $(echo $PATH | grep -q android && echo '✅ áno' || echo '❌ nie')"

echo ""
echo "🛠️  Nástroje:"
echo "   Java: $(java -version 2>&1 | head -n1 | cut -d'"' -f2 2>/dev/null || echo '❌ nenájdená')"
echo "   Node.js: $(node -v 2>/dev/null || echo '❌ nenájdený')"
echo "   NPM: $(npm -v 2>/dev/null || echo '❌ nenájdený')"
echo "   Cordova: $(cordova -v 2>/dev/null || echo '❌ nenájdený')"
echo "   Gradle: $(gradle -v 2>/dev/null | head -n1 | awk '{print $2}' 2>/dev/null || echo '❌ nenájdený')"

echo ""
echo "📁 Adresáre:"
echo "   /opt/android-sdk: $([ -d /opt/android-sdk ] && echo '✅ existuje' || echo '❌ neexistuje')"
echo "   /opt/gradle: $([ -d /opt/gradle ] && echo '✅ existuje' || echo '❌ neexistuje')"
echo "   /opt/mikrotik-manager-app: $([ -d /opt/mikrotik-manager-app ] && echo '✅ existuje' || echo '❌ neexistuje')"

if [ -d "/opt/mikrotik-manager-app" ]; then
    echo ""
    echo "📱 Cordova projekt:"
    cd /opt/mikrotik-manager-app
    echo "   Platformy: $(cordova platform list 2>/dev/null | grep android || echo '❌ Android platforma nie je pridaná')"
    echo "   Plugins: $(cordova plugin list 2>/dev/null | wc -l) nainštalovaných"
    
    echo ""
    echo "🔧 Pokus o build (s verbose výstupom):"
    echo "=================================="
    
    # Load environment
    source /etc/profile.d/android-dev.sh 2>/dev/null || true
    export ANDROID_HOME=/opt/android-sdk
    export ANDROID_SDK_ROOT=/opt/android-sdk
    export PATH=${PATH}:${ANDROID_HOME}/cmdline-tools/latest/bin:${ANDROID_HOME}/platform-tools:/opt/gradle/bin
    export JAVA_HOME=/usr/lib/jvm/java-17-openjdk-amd64
    
    cordova build android --verbose || echo "❌ Build zlyhal!"
else
    echo "❌ Cordova projekt neexistuje v /opt/mikrotik-manager-app"
    echo "   Spusti najprv installation script"
fi

echo ""
echo "✅ Diagnostika dokončená!"
echo "📄 Pre detailný log spusti: bash build-apk-debug.sh > debug.log 2>&1"
