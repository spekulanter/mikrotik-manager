## 📦 Inštalácia

**Odporúčané prostredie:** LXC kontajner v Proxmox VE  
**Testované na:** `debian-12-standard_12.7-1_amd64.tar.zst`

### 🛠️ Odporúčaná LXC konfigurácia:
- **CPU:** 2 cores
- **RAM:** 6 GB  
- **Disk:** 10 GB

```bash
bash -c "$(wget -qLO - https://raw.githubusercontent.com/spekulanter/mikrotik-manager/main/install-mikrotik-manager.sh)"
```

## 📱 Buildovanie Native Android APK

Po úspešnej inštalácii môžete vytvoriť Native Android APK súbor:

```bash
cd /opt/mikrotik-manager
bash build-apk.sh
```

Poznámka: Build skript používa Android SDK 35 a Gradle 8.13 (targetSdk 35), optimalizované pre Android 15.

APK súbor bude vytvorený ako `/opt/MT Manager.apk`

⚡ Native Android: Aplikácia je postavená na natívnej Android Kotlin WebView s optimalizovaným splash screen, vlastnou network-themed ikonou a eliminovanými prebliknutiami pri spúšťaní (optimalizované pre Android 15).

📦 APK vlastnosti:
- **Veľkosť:** 6.2 MB (optimalizovaná splash screen knižnica)
- **Ikona:** Vlastná network-themed ikona s MikroTik zariadeniami
- **Splash screen:** Rýchly tmavý splash bez prebliknutí
- **Kompatibilita:** Android 7+ (API 24+), optimalizované pre Android 15

### 🎨 Úprava Android APK

Pre úpravu vzhľadu alebo funkcionality upravte súbory v template adresári:

```bash
# Upraviť názov aplikácie
nano /opt/mikrotik-manager/template/res/values/strings.xml

# Upraviť Android Manifest (permissions, konfigurácia)  
nano /opt/mikrotik-manager/template/AndroidManifest.xml

# Upraviť hlavnú Activity (status bar, WebView nastavenia)
nano /opt/mikrotik-manager/template/MainActivity.kt

# Vytvorenie novej APK s upravenými template súbormi
cd /opt/mikrotik-manager
bash build-apk.sh
```

### 📋 Native Android Template súbory

- `template/MainActivity.kt` - Hlavná aktivita s WebView a status bar handling
- `template/SetupActivity.kt` - Setup obrazovka pre konfiguráciu
- `template/AndroidManifest.xml` - Android manifest s permissions
- `template/activity_main.xml` - Layout pre hlavnú obrazovku
- `template/activity_setup.xml` - Layout pre setup obrazovku
- `template/res/values/strings.xml` - Názov aplikácie a texty
- `template/res/values/styles.xml` - Android témy a štýly
- `template/build.gradle` - Android build konfigurácia

### 🔄 Aktualizácia systému

Pre aktualizáciu na najnovšiu verziu:

```bash
cd /opt/mikrotik-manager
bash update.sh
```

**Automatická detekcia:** Inštalačný script automaticky rozpozná existujúcu inštaláciu a spustí aktualizačný proces namiesto novej inštalácie.

## 📖 Dokumentácia

**Kompletný užívateľský manuál:** [manual.md](manual.md)

Manuál obsahuje detailné informácie o:
- Inštalácii a konfigurácii systému
- Používaní webového rozhrania a mobilnej aplikácie
- Správe zariadení a zálohovaní
- Monitoringu a grafoch
- Bezpečnostných nastaveniach a 2FA
- Riešení problémov a FAQ