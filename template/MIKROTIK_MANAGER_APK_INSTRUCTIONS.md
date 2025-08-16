# MikroTik Manager - Android APK Instructions

## 📱 Android Application

Aplikácia **MikroTik Manager** je teraz dostupná aj ako natívna Android aplikácia!

### 🚀 Inštalácia APK

1. **Stiahnite APK súbor** z tohto servera:
   - Súbor: `/opt/MikroTikManager.apk`
   - Veľkosť: ~3.6MB

2. **Povoľte neznáme zdroje** na vašom Android zariadení:
   - Nastavenia → Bezpečnosť → Neznáme zdroje ✓

3. **Nainštalujte aplikáciu**:
   - Otvorte súbor `MikroTikManager.apk`
   - Kliknite na "Inštalovať"

### 📋 Funkcionalita

✅ **Natívna Android aplikácia** s Material Design  
✅ **InAppBrowser** - plná funkcionalita web rozhrania  
✅ **Smart Login Memory** - pamätá si server URL  
✅ **Instant Launch** - rýchle pripojenie k serveru  
✅ **Offline Ready** - funguje bez internetového pripojenia  

### 🔧 Prvé spustenie

1. **Otvorte aplikáciu** "MikroTik Manager"
2. **Zadajte URL servera** (napr.: `http://192.168.1.100:5000`)
3. **Kliknite "Pripojiť sa"** - otvorí sa web rozhranie
4. Pri ďalších spusteniach sa **automaticky pripojí** k uloženému serveru

### 🛠️ Pre vývojárov

**Build proces:**
```bash
cd /opt/mikrotik-manager-app
cordova build android
```

**Výsledok:** `/opt/MikroTikManager.apk`

**Technické špecifikácie:**
- Apache Cordova framework
- cordova-plugin-inappbrowser
- Material Design UI
- Smart localStorage management
- Support pre Android 7.0+ (API 24+)

### 🌐 Web prístup

Aplikácia slúži ako **wrapper** pre web rozhranie. Všetky funkcie webovej verzie sú plne dostupné:

- 🔐 Správa používateľov a 2FA
- 📊 Real-time monitoring
- 💾 Automatické zálohovanie
- ⚙️ Konfigurácia zariadení
- 📈 Grafy a štatistiky

---

**GitHub:** https://github.com/spekulanter/mikrotik-manager  
**Verzia:** Android APK Template  
**Posledná aktualizácia:** $(date '+%d.%m.%Y')
