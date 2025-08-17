## 📦 Inštalácia

**Odporúčané prostredie:** LXC kontajner v Proxmox VE  
**Testované na:** `debian-12-standard_12.7-1_amd64.tar.zst`

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

**⚡ Automatická aktualizácia:** Build script automaticky skopíruje najnovšie template súbory do Cordova projektu pred buildovaním, takže APK bude vždy obsahovať aktuálne zmeny z template adresára.

### 🔄 Aktualizácia APK template

Pre úpravu vzhľadu alebo funkcionality APK upravte súbory v template adresári:

```bash
# Upraviť obsah a dizajn APK
nano /opt/mikrotik-manager/template/index.html

# Upraviť konfiguráciu APK (názov, verzia, ikony)  
nano /opt/mikrotik-manager/template/config.xml

# Vytvorenie novej APK s upravenými template súbormi
# (automaticky skopíruje template → Cordova → build APK)
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