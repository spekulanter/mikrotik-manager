## 📦 Inštalácia

```bash
bash -c "$(wget -qLO - https://raw.githubusercontent.com/spekulanter/mikrotik-manager/main/install-mikrotik-manager.sh)"
```

## 📱 Buildovanie Android APK

Po úspešnej inštalácii môžete vytvoriť Android APK súbor:

```bash
cd /opt/mikrotik-manager
./build-apk.sh
```

APK súbor bude vytvorený v `/opt/MikroTikManager.apk`

### 🔄 Aktualizácia APK template

Pre úpravu vzhľadu alebo funkcionality APK upravte súbory v template adresári:

```bash
# Upraviť obsah a dizajn APK
nano /opt/mikrotik-manager/template/index.html

# Upraviť konfiguráciu APK (názov, verzia, ikony)  
nano /opt/mikrotik-manager/template/config.xml

# Vytvorenie novej APK s upravenými template súbormi
cd /opt/mikrotik-manager
./build-apk.sh
```

### 📋 Template súbory

- `template/index.html` - Hlavný obsah a UI aplikácie
- `template/config.xml` - Konfigurácia aplikácie (názov, verzia, permissions)
- `template/res/` - Ikony a splash screen obrázky
- `template/MIKROTIK_MANAGER_APK_INSTRUCTIONS.md` - Inštrukcie pre APK

### 🔄 Synchronizácia zmien

Ak chcete skopírovať zmeny z Cordova projektu späť do template:

```bash
cd /opt/mikrotik-manager
./sync-template.sh
```