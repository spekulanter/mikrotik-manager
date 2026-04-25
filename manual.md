# MikroTik Manager - Užívateľský manuál

## Obsah

1. [Úvod](#úvod)
2. [Inštalácia](#inštalácia)
3. [Prvé prihlásenie a nastavenie](#prvé-prihlásenie-a-nastavenie)
4. [Webové rozhranie](#webové-rozhranie)
5. [Mobilná aplikácia (APK)](#mobilná-aplikácia-native-android-apk)
6. [Správa zariadení](#správa-zariadení)
7. [Zálohovanie](#zálohovanie)
8. [Monitoring a grafy](#monitoring-a-grafy)
9. [Updater - aktualizácie RouterOS](#updater---aktualizácie-routeros)
10. [Export a import (migrácia)](#export-a-import-migrácia)
11. [Nastavenia systému](#nastavenia-systému)
12. [Bezpečnosť a 2FA](#bezpečnosť-a-2fa)
13. [Riešenie problémov](#riešenie-problémov)
14. [Často kladené otázky](#často-kladené-otázky)
15. [Záver](#záver)

---

## Úvod

**MikroTik Manager** je komplexný webový nástroj pre správu, zálohovanie a monitoring MikroTik zariadení. Umožňuje centralizovanú správu viacerých RouterOS zariadení s možnosťou automatického zálohovania, real-time monitoringu a vzdialeného prístupu cez webové rozhranie alebo mobilnú aplikáciu.

### Hlavné funkcie:

- **Centralizovaná správa zariadení** – Pridávanie, úprava a správa MikroTik zariadení vrátane koša so soft-delete
- **Automatické zálohovanie** – Pravidelné vytváranie a sťahovanie .backup a .rsc súborov
- **Real-time monitoring** – Sledovanie dostupnosti, CPU, teploty, pamäte a latencie
- **SNMP monitoring** – Detailné sledovanie výkonu zariadení cez SNMPv2c
- **Ping monitoring** – Kontinuálne sledovanie dostupnosti siete
- **Updater** – Vzdialená aktualizácia RouterOS a firmware, správa TLS certifikátov
- **Webové aj mobilné rozhranie** – Prístup cez prehliadač alebo Android aplikáciu
- **Bezpečnostné funkcie** – Povinná 2FA autentifikácia, šifrovanie hesiel (Fernet), hašovanie hesiel (Werkzeug)
- **Notifikácie** – Pushover notifikácie pre rôzne udalosti (výpadky, zálohy, prahy, bezpečnosť)
- **FTP upload** – Automatické nahrávanie záloh na FTP server
- **Export/Import** – Migrácia celej inštalácie medzi servermi cez ZIP

---

## Inštalácia

### Automatická inštalácia (odporúčané)

1. **Stiahnutie inštalačného skriptu:**
```bash
wget https://raw.githubusercontent.com/spekulanter/mikrotik-manager/main/install-mikrotik-manager.sh
chmod +x install-mikrotik-manager.sh
```

2. **Spustenie inštalácie:**
```bash
sudo ./install-mikrotik-manager.sh
```

Skript automaticky:
- Nainštaluje všetky potrebné závislosti (Python 3.11+, potrebné systémové balíčky)
- Naklonuje repozitár z GitHub
- Nastaví Python virtuálne prostredie
- Nainštaluje Python balíčky
- Vytvorí systemd službu
- Spustí aplikáciu na porte 5000

### Manuálna inštalácia

1. **Inštalácia závislostí:**
```bash
sudo apt update
sudo apt install -y python3 python3-pip python3-venv git
```

2. **Klonovanie repozitára:**
```bash
git clone https://github.com/spekulanter/mikrotik-manager.git /opt/mikrotik-manager
cd /opt/mikrotik-manager
```

3. **Vytvorenie virtuálneho prostredia:**
```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

4. **Spustenie aplikácie:**
```bash
python app.py
```

### Systémové požiadavky

- **Operačný systém:** Linux (testované na Debian 12, Ubuntu)
- **RAM:** Minimálne 512 MB (odporúčané 1 GB)
- **Disk:** 500 MB voľného miesta + miesto pre zálohy
- **Python:** 3.11 alebo novší
- **Sieť:** Prístup k MikroTik zariadeniam cez SSH (port 22) a SNMP (UDP port 161)

### Adresárová štruktúra po inštalácii

```
/opt/mikrotik-manager/         # Aplikačný kód
├── app.py                     # Hlavná Flask aplikácia
├── requirements.txt
├── *.html                     # Šablóny (Jinja2)
├── static/js/                 # Frontend JavaScript
├── template/                  # Súbory pre Android APK build
├── venv/                      # Python virtuálne prostredie
├── build-apk.sh
└── install-mikrotik-manager.sh

/var/lib/mikrotik-manager/data/  # Runtime dáta (mimo git)
├── mikrotik_manager.db          # SQLite databáza
├── secret.key                   # Flask SESSION key (chmod 600)
├── encryption.key               # Fernet šifrovací kľúč (chmod 600)
└── backups/                     # Zálohy zariadení
    └── 192.168.1.1/
        ├── backup_*.backup
        └── export_*.rsc
```

---

## Prvé prihlásenie a nastavenie

### 1. Prístup k aplikácii

Po úspešnej inštalácii je aplikácia dostupná na:
- **Webové rozhranie:** `http://IP_SERVERA:5000`
- **Mobilná aplikácia:** Nainštalujte APK súbor z `/opt/MT Manager.apk`

### 2. Vytvorenie účtu alebo import

Pri prvom prístupe (prázdna databáza) sa zobrazí stránka s dvomi možnosťami:

**A) Vytvoriť nový účet:**
1. Záložka **"Nová inštalácia"**
2. Zadajte používateľské meno (4–50 znakov) a heslo (minimálne 8 znakov)
3. Kliknite **"Vytvoriť účet"**
4. **Ihneď nastavte 2FA** (systém vás presmeruje automaticky)

**B) Importovať zo ZIP (migrácia zo starej inštalácie):**
1. Záložka **"Importovať zo ZIP"**
2. Vyberte exportovaný ZIP súbor zo starej inštalácie
3. Potvrďte import – aplikácia sa automaticky reštartuje
4. Prihláste sa pôvodnými prihlasovacími údajmi vrátane TOTP

⚠️ **DÔLEŽITÉ:** Systém podporuje len jeden používateľský účet. Po vytvorení je povinné nastaviť 2FA.

### 3. Prvé prihlásenie

1. Zadajte používateľské meno a heslo
2. Kliknite **"Prihlásiť sa"**
3. Ak je aktivované 2FA, zadajte 6-ciferný kód z autentifikačnej aplikácie

### 4. Nastavenie 2FA (povinné)

1. Po registrácii vás systém automaticky presmeruje na nastavenie 2FA
2. Naskenujte QR kód pomocou autentifikačnej aplikácie (Google Authenticator, Authy, Bitwarden a pod.)
3. Zadajte overovací kód a potvrďte aktiváciu
4. **Uložte si záložné kódy na bezpečné miesto** – sú potrebné pri strate prístupu k autentifikačnej aplikácii

---

## Webové rozhranie

### Hlavná stránka (Dashboard)

#### Horná lišta

- **Logo** – MikroTik Manager
- **Navigačné tlačidlá:** Monitoring, Zálohy, Updater, Nastavenia
- **Používateľské menu:** Upraviť (zmena mena/hesla/2FA), Odhlásiť sa

#### Správa zariadení

**Pridanie nového zariadenia:**
1. Kliknite **"Pridať zariadenie"**
2. Vyplňte formulár:
   - **IP adresa** zariadenia
   - **Názov** (popisný, napr. "Hlavný router")
   - **Používateľské meno** – SSH používateľ (obvykle `admin`)
   - **Heslo** – SSH heslo (ukladá sa šifrované)
   - **Low Memory Mode** – pre zariadenia s obmedzenou pamäťou
   - **SNMP Community** – obvykle `public` (ukladá sa šifrované)
3. Kliknite **"Pridať zariadenie"**

> Ak IP adresa patrí zariadeniu v koši, systém to oznámi a ponúkne možnosť obnovenia namiesto pridania duplicitu.

**Zoznam zariadení – stavy:**
- 🟢 **Online** – zariadenie je dostupné
- 🔴 **Offline** – zariadenie nie je dostupné
- ⚪ **Unknown** – stav neznámy (monitoring ešte neprebehol)
- ⏸️ **Paused** – monitoring je pozastavený

**Akcie pre zariadenia:**
- **Zálohovať** – vytvorí okamžitú zálohu
- **SNMP** – zobrazí aktuálne SNMP údaje
- **Upraviť** – zmení nastavenia zariadenia
- **Zmazať** – presunie zariadenie do koša (soft-delete)

#### Kôš zariadení

Odstránené zariadenia sa nepresúvajú priamo do databázy – zachovávajú sa v koši po nastaviteľný počet dní, potom sa automaticky vymažú.

**Funkcie koša:**
- **Zobraziť kôš** – zobrazí zoznam soft-deleted zariadení
- **Obnoviť** – zariadenie sa vráti do aktívneho zoznamu vrátane histórie monitoringu
- **Trvalo vymazať** – okamžité úplné vymazanie zariadenia vrátane záloh a monitoringovej histórie
- **Automatické vymazanie** – každé zariadenie v koši sa automaticky vymaže po uplynutí nastavenej doby uchovávania (predvolene 7 dní)

#### Bočný panel – Logy

- **Info** – informačné správy
- **Warning** – varovania
- **Error** – chybové hlásenia

Logy sa aktualizujú v reálnom čase cez WebSocket.

### Responsívny dizajn

Webové rozhranie je optimalizované pre Desktop, Tablet aj Mobile.

---

## Mobilná aplikácia (Native Android APK)

### Generovanie APK

```bash
cd /opt/mikrotik-manager
bash build-apk.sh
```

APK súbor sa vytvorí ako `/opt/MT Manager.apk`.

**Vlastnosti build procesu:**
- Android SDK 35 (targetSdk 35, Android 15)
- Gradle 8.13, AGP 8.7.3, Kotlin 2.0.21
- Gradle inštalácia: `/opt/gradle`

### Inštalácia APK

1. Skopírujte `/opt/MT Manager.apk` na Android zariadenie
2. Na zariadení povolte inštaláciu z neznámych zdrojov
3. Otvorte APK a potvrďte inštaláciu

### Vlastnosti aplikácie

**Technické vlastnosti:**
- Native Android Kotlin WebView
- Veľkosť: ~6.2 MB
- Kompatibilita: Android 7+ (API 24+), optimalizované pre Android 15
- Edge-to-edge status bar s theme-aware farbami (tmavá: `#111827` / svetlá: `#cddbf2`)

**Ikona:**
- Network-themed ikona (sieťová topológia – routery prepojené káblami)
- Sky blue téma (`#38bdf8`, `#0ea5e9`, `#60a5fa`) na tmavom pozadí (`#0f172a`)

**Splash screen:**
- Tmavé pozadie konzistentné s webovou aplikáciou
- Eliminované biele blikania pri štarte (Android 15 kompatibilita)

### Použitie

1. **Prvé spustenie:** Zadajte IP adresu alebo doménu servera na setup obrazovke
2. **Prihlásenie:** Rovnaké údaje ako vo webovom rozhraní vrátane 2FA
3. **Funkcie:** Plná funkcionalita webového rozhrania vrátane real-time aktualizácií cez WebSocket

### Rozdiely oproti webovému rozhraniu

**Výhody Native APK:**
- Rýchlejšie spustenie a lepšia výkonnosť
- Automatické prepínanie dark/light témy podľa systému
- Optimalizovaný splash screen
- Lepšia integrácia s Android systémom

**Obmedzenia:**
- Vyžaduje sieťové pripojenie k serveru
- Na menšej obrazovke môžu byť komplexné grafy menej pohodlné

---

## Správa zariadení

### Požiadavky na MikroTik zariadenie

**SSH prístup:**
```bash
/ip service set ssh port=22 disabled=no
```

**SNMP prístup:**
```bash
/snmp set enabled=yes
/snmp community set public name=public
```

Používateľ musí mať admin práva pre zálohovanie (SSH príkazy `/system backup save`, `/export`).

### Úprava zariadenia

Kliknite na ikonu ceruzky – môžete zmeniť:
- Názov, IP adresu, prihlasovacie údaje
- SNMP community string
- Individuálne monitoring intervaly (ping, SNMP) – 0 = použiť globálne nastavenie

### Soft-delete a kôš

**Zmazanie zariadenia** ho nepresunie do koša okamžite – nastaví mu `deleted_at` timestamp a vypočíta dátum automatického vymazania (`purge_after = deleted_at + nastavená doba uchovávania`).

Počas pobytu v koši:
- Monitoring zariadenia je zastavený
- História monitoringu a zálohy sú zachované
- Zariadenie sa nezobrazuje v aktívnom zozname

**Automatické vymazanie** prebieha na pozadí každých 60 sekúnd a kontroluje, či uplynula doba uchovávania. Pri automatickom vymazaní príde Pushover notifikácia (ak je povolená).

**Trvalé vymazanie** (manuálne z koša) okamžite odstráni:
- Všetky záznamy monitoringu (ping, SNMP história)
- Všetky lokálne zálohy
- Zálohy na FTP (ak sú nastavené)
- Záznam zariadenia v databáze

### Monitorovanie zariadení

**Ping monitoring:**
- Konfigurovateľný interval per-device (0 = globálny)
- Linux: `ping -c 4 -W 5 {ip}` → priemerná latencia, strata paketov
- Retry logika: 3 neúspešné pokusy pred označením ako offline

**SNMP monitoring:**
- Konfigurovateľný interval per-device (0 = globálny)
- SNMPv2c, timeout 2s, 1 retry
- Bulk požiadavka pre všetky OID naraz (minimálna záťaž siete)

**Pozastavenie monitoringu:**
- Tlačidlo Pauza/Obnoviť na monitoring stránke (per-device)
- Monitoring sa zastaví bez vymazania histórie

---

## Zálohovanie

### Automatické zálohovanie

**Nastavenie plánu:**
1. Nastavenia → sekcia **Zálohovanie**
2. Typ plánu: `daily` (denné), `weekly` (týždenné), `custom`
3. Čas spustenia (HH:MM)
4. Počet uchovaných záloh (predvolene 10)
5. Oneskorenie medzi zariadeniami (predvolene 30 s)

### Priebeh zálohovania

1. SSH pripojenie na zariadenie (Paramiko)
2. Vytvorenie `.backup` súboru: `/system backup save`
3. Export konfigurácie: `/export file=export`
4. Stiahnutie súborov cez SFTP
5. Uloženie do `/var/lib/mikrotik-manager/data/backups/{ip}/`
6. Upload na FTP (ak je nastavený)
7. Vyčistenie starých záloh podľa `backup_retention_count`
8. Pushover notifikácia (ak je povolená)

Systém porovnáva nový `.rsc` export s predchádzajúcim a loguje zmeny v konfigurácii (diff).

### Manuálne zálohovanie

- **Jednotlivé zariadenie:** Tlačidlo "Zálohovať" v zozname zariadení
- **Všetky zariadenia:** Tlačidlo "Zálohovať všetky" – zariadenia sa spracúvajú postupne s nastaveným oneskorením

### Správa backup súborov

**Stránka Zálohy** (odkaz v hornej lište):
- Zoznam všetkých backup súborov zoradených podľa zariadenia
- Dátum, čas, veľkosť, typ (`.backup` / `.rsc`)

**Akcie:**
- **Stiahnuť** – stiahne súbor na lokálny počítač
- **Zobraziť obsah** – náhľad `.rsc` súborov priamo v prehliadači
- **Zmazať** – odstráni konkrétny súbor

### FTP upload

**Nastavenie (Nastavenia → FTP):**
- Server (IP/hostname), port (predvolene 21)
- Používateľské meno a heslo (ukladá sa šifrované)
- Cieľový priečinok

Každá úspešná záloha sa automaticky nahrá na FTP. Pri chybe FTP sa záloha uloží len lokálne a chyba sa zaloguje.

---

## Monitoring a grafy

### Prístup

Kliknite na **Monitoring** v hornej lište.

### Výber zariadenia

- Rozbaľovacie menu s výberom zariadenia
- Každé zariadenie zobrazuje aktuálny stav (emoji + meno + IP)
- Výber sa uloží do localStorage – pri ďalšom otvorení sa obnoví

### Časové rozsahy

Tlačidlá pre výber časového okna: **30m, 3h, 6h, 12h, 24h, 7d, 30d, 90d, 1y**

Predvolený rozsah: **24h**. Výber sa uloží do localStorage.

### Typy grafov

Stránka zobrazuje štyri grafy v mriežke 2×2 (na mobile 1 stĺpec):

**1. Ping Latencia**
- Online segmenty: zelená čiara s plôškou
- Offline segmenty: červená plôška (vizualizuje výpadok)
- Tooltip: latencia v ms + strata paketov

**2. CPU Load**
- Modrá čiara, os Y 0–100 %
- Inteligentná os Y: ak max ≤ 50 %, zobrazí sa škála 0–50 %

**3. Teplota**
- Červená čiara, os Y centrovaná okolo skutočného rozsahu hodnôt
- Ak je teplota konštantná: ±5 °C okraj

**4. Memory Usage**
- Dve dátové série: Použitá pamäť (červená) + Celková pamäť (modrá)
- Celková pamäť sa dopĺňa dopredu (forward-fill) pre súvislé zobrazenie
- Tooltip: Použitá, Celková, Voľná pamäť, Percentá

### Stavové karty

Nad grafmi sú 4 stavové karty:
- **Ping stav** – Online/Offline s animovaným indikátorom
- **Priemerná latencia** – váhovaný priemer v aktuálnom časovom okne
- **Uptime** – percento dostupnosti (farebné kódovanie: ≥95 % zelená, ≥80 % žltá, <80 % červená)
- **Posledný ping** – čas poslednej kontroly

Pri priblížení (zoom) sa uptime a priemerná latencia automaticky prepočítavajú pre zobrazené okno.

### Ovládanie grafov

**Zoom in:**
- Kliknite a ťahajte myšou (alebo prstom na mobile) po grafe pre výber oblasti

**Zoom out:**
- Tlačidlo s lupou na každom grafe
- Dvojklik (alebo dvojité ťuknutie na mobile) priamo na grafe
- Progresívny zoom-out: každý krok rozšíri pohľad 2,5×; po dosiahnutí maxima dát sa automaticky načítajú dáta z väčšieho časového rozsahu

**Zoom režim:**
- **Individuálny** (predvolený) – zoom ovplyvní len kliknutý graf
- **Globálny** – zoom sa synchronizuje na všetky 4 grafy súčasne
- Prepínanie tlačidlom v záhlaví stránky (sivé = individuálny, oranžové = globálny), nastavenie sa uloží

**Aktualizácia:**
- Tlačidlo **Obnoviť** – manuálne načíta aktuálne dáta
- Real-time aktualizácie cez WebSocket (nové ping/SNMP hodnoty sa pridávajú priebežne)

### Individuálne nastavenia zariadenia

Tlačidlo **Intervaly** otvorí modal pre per-device nastavenia:
- **Ping interval** (s) – 0 = použiť globálny
- **Retry interval** (s) – interval počas výpadku
- **SNMP interval** (min) – 0 = použiť globálny

### Debug terminál

V pravom dolnom rohu je skrytý debug terminál (zapnutie: `Ctrl+D` alebo v Nastaveniach → `debug_terminal`). Zobrazuje technické logy v reálnom čase.

---

## Updater - aktualizácie RouterOS

### Prístup

Kliknite na **Updater** v hornej lište.

### Prehľad zariadení v Updateri

Pre každé zariadenie sa zobrazuje:
- **Stav pripojenia** (online/offline cez MikroTik REST API)
- **Aktuálna verzia RouterOS** a dostupná nová verzia
- **Aktuálna verzia Firmware** a dostupná nová verzia
- **TLS/SSL stav** – či zariadenie má platný TLS certifikát
- **Expirácia certifikátu** (badge: zelená >30 dní, oranžová 8–30 dní, červená 1–7 dní, červená = expirovaný)

### Aktualizácia RouterOS a Firmware

**Kompletná aktualizácia (odporúčané):**

Tlačidlo **"Aktualizovať MikroTik"** spustí 7-krokový proces:
1. Kontrola a inštalácia novej verzie RouterOS
2. Čakanie na odpojenie zariadenia (reboot)
3. Čakanie na opätovné pripojenie
4. Stabilizačná pauza (120 s – preskočí sa pri VM/CHR)
5. Kontrola a inštalácia novej verzie Firmware
6. Pauza pred záverečným rebootom
7. Záverečný reboot + čakanie na online

Priebeh sa zobrazuje v modálnom okne s progress indikátorom.

**Čiastočné aktualizácie** (dropdown pri hlavnom tlačidle):
- Len RouterOS
- Len Firmware
- Reštartovať zariadenie

**VM/CHR zariadenia:** Firmware fázy sa automaticky preskočia (CHR/VM nemajú hardware firmware).

### Plánované aktualizácie

**Plánovanie jednotlivého zariadenia:**
1. Kliknite na tlačidlo kalendára pri zariadení
2. Vyberte dátum a čas
3. Potvrďte – plán sa uloží v databáze

**Hromadné plánovanie:**
1. Označte viaceré zariadenia checkboxom
2. Kliknite **"Naplánovať vybrané"**
3. Vyberte čas – zariadenia sa budú aktualizovať postupne s nastaveným oneskorením

**Správa plánov:**
- Aktívne plány zobrazujú fialový badge pri zariadení
- Plán je možné zrušiť kliknutím na badge alebo v zozname plánov

Stav plánov prežije reload stránky (F5) – systém obnoví zobrazenie z databázy.

### Hromadná aktualizácia (okamžitá)

1. Označte zariadenia checkboxom
2. Kliknite **"Aktualizovať vybrané"**
3. Zariadenia sa aktualizujú postupne (jedno po druhom) s nastaveným oneskorením

Stav čakajúcich zariadení (⟳ Čaká...) prežije reload stránky.

### TLS certifikát

Zariadenia bez TLS certifikátu zobrazujú varovanie **"⚠️ Bez TLS certifikátu"**.

**Vytvorenie/obnovenie certifikátu:**
1. Kliknite **"Vytvoriť TLS Cert ⚠️"** (alebo **"Obnoviť TLS Cert"** ak certifikát existuje)
2. Systém cez HTTP REST API:
   - Odstráni starý certifikát (ak existuje)
   - Vytvorí nový self-signed certifikát (`WebCert`)
   - Podpíše ho
   - Priradí ho na `www-ssl` službu
3. Po dokončení zariadenie funguje cez HTTPS

> Poznámka: Celý proces prebieha cez HTTP (port 80), pretože nahradenie certifikátu by dočasne prerušilo HTTPS.

**Automatická obnova certifikátov:**
- Denná kontrola o 09:00
- Certifikáty s platnosťou ≤ `cert_expiry_warning_days` dní sa automaticky obnovia
- Pushover notifikácia pri automatickej obnove

**Nastavenie platnosti certifikátu:**
- Globálne: Nastavenia → `cert_auto_renewal_days` (predvolene 365 dní)
- Per-device: Tlačidlo nastavenia pri certifikáte → vlastná hodnota pre dané zariadenie

### RSS changelog

Updater automaticky načíta RSS feed z mikrotik.com a zobrazuje changelog k najnovšej stabilnej verzii RouterOS. Výsledok sa ukladá do cache (nie je potrebné opakovane načítavať pri každom F5).

---

## Export a import (migrácia)

### Export celej inštalácie

**Účel:** Záloha celej inštalácie alebo migrácia na nový server/LXC kontajner.

**Postup:**
1. Nastavenia → sekcia **Admin / Migrácia**
2. Kliknite **"Exportovať ZIP"**
3. Voliteľne zaškrtnite **"Zahrnúť zálohy zariadení"**
4. Stiahnite ZIP súbor

**Obsah ZIP:**
- `mikrotik_manager.db` – celá databáza (zariadenia, používatelia, TOTP, nastavenia, história)
- `encryption.key` – Fernet šifrovací kľúč
- `secret.key` – Flask session kľúč
- `backups/` – zálohy zariadení (voliteľne)

⚠️ **DÔLEŽITÉ:** ZIP obsahuje šifrovacie kľúče – uložte ho na bezpečné miesto!

### Import na novej inštalácii

**Podmienka:** Import je možný len na inštalácii bez existujúceho používateľského účtu (prázdna databáza = čerstvá inštalácia).

**Postup:**
1. Nainštalujte MikroTik Manager na novom serveri
2. Otvorte webové rozhranie – zobrazí sa registračná stránka
3. Kliknite záložku **"Importovať zo ZIP"**
4. Nahrajte ZIP súbor zo starej inštalácie
5. Systém nahradí databázu, kľúče a zálohy, potom sa automaticky reštartuje
6. Prihláste sa pôvodnými prihlasovacími údajmi (vrátane TOTP z pôvodnej aplikácie)

---

## Nastavenia systému

### Prístup

Kliknite na **Nastavenia** v hornej lište.

### Zálohovanie

| Nastavenie | Predvolená hodnota | Popis |
|---|---|---|
| Automatické zálohovanie | vypnuté | Zapnutie/vypnutie plánovaných záloh |
| Typ plánu | `daily` | daily / weekly / custom |
| Čas zálohovania | `02:00` | HH:MM |
| Počet uchovaných záloh | 10 | Na zariadenie, rozsah 1–100 |
| Oneskorenie medzi zariadeniami | 30 s | Predchádzanie preťaženiu siete |
| Detailné logovanie záloh | zapnuté | Logovanie diff zmien |

### Monitoring

| Nastavenie | Predvolená hodnota | Popis |
|---|---|---|
| Ping monitoring | zapnutý | Zapnutie/vypnutie ping monitoringu |
| Ping interval | 30 s | Globálny interval pre všetky zariadenia |
| Ping timeout | 5 s | Timeout jedného pingu |
| Ping retries | 3 | Pokusy pred offline označením |
| Uchovávanie ping histórie | 30 dní | Automatické mazanie starých dát |
| SNMP monitoring | zapnutý | Zapnutie/vypnutie SNMP |
| SNMP interval | 10 min | Globálny interval pre všetky zariadenia |
| Uchovávanie SNMP histórie | 30 dní | Automatické mazanie starých dát |

### FTP

| Nastavenie | Popis |
|---|---|
| FTP server | IP alebo hostname FTP servera |
| Port | Predvolene 21 |
| Používateľské meno | FTP prihlasovacie meno |
| Heslo | FTP heslo (ukladá sa šifrované) |
| Priečinok | Cieľový priečinok na FTP (predvolene `/`) |

### Pushover notifikácie

**Nastavenie:**
- **App Key** – Pushover API kľúč aplikácie (ukladá sa šifrované)
- **User Key** – Pushover používateľský kľúč (ukladá sa šifrované)
- Tlačidlo **"Otestovať"** – overí funkčnosť nastavenia

**Dostupné typy notifikácií:**

| Typ | Popis |
|---|---|
| Zariadenie offline | Pri výpadku dostupnosti |
| Zariadenie online | Pri obnovení dostupnosti |
| Záloha úspešná | Po úspešnom zálohovaní |
| Záloha neúspešná | Pri chybe zálohovania |
| Kritická teplota | Teplota presiahla prah |
| Kritické CPU | CPU zaťaženie presiahlo prah |
| Kritická pamäť | Využitie pamäte presiahlo prah |
| Reboot zariadenia | Detekcia reštartu (zmena uptime) |
| Zmena verzie RouterOS | Detekcia aktualizácie firmvéru |
| Expirácia TLS certifikátu | Automatická obnova certifikátu |
| Nová verzia RouterOS | Dostupná nová verzia (RSS) |
| Neúspešné prihlásenie | Nesprávne heslo pri prihlásení |
| Neúspešné 2FA | Nesprávny 2FA kód |
| Neúspešná obnova hesla | Pokus o obnovu hesla zlyhal |
| Automatické vymazanie zariadenia | Zariadenie vymazané z koša |

**Prahy pre notifikácie:**
- CPU kritický prah: 80 %
- Pamäť kritický prah: 80 %
- Teplota kritický prah: 70 °C

### Tichá hodina (Quiet Hours)

Možnosť nastavenia časového okna, počas ktorého sa Pushover notifikácie neodosielajú.

### Kôš zariadení

| Nastavenie | Predvolená hodnota | Popis |
|---|---|---|
| Doba uchovávania | 7 dní | Po uplynutí sa zariadenie automaticky vymaže (rozsah 1–90 dní) |

### Updater

| Nastavenie | Predvolená hodnota | Popis |
|---|---|---|
| Záloha pred aktualizáciou | zapnuté | Spustí zálohu pred aktualizáciou |
| Oneskorenie medzi zariadeniami (bulk) | 60 s | Pauza medzi zariadeniami pri hromadnej aktualizácii |
| Oneskorenie po zálohe | 10 s | Čakanie po dokončení zálohy |
| Stabilizačná pauza | 120 s | Čakanie po reboote pred firmware fázou |
| Pauza pred záverečným rebootom | 20 s | Čakanie po firmware upgrade |

### TLS certifikáty

| Nastavenie | Predvolená hodnota | Popis |
|---|---|---|
| Platnosť certifikátu | 365 dní | Globálna platnosť nových certifikátov |
| Varovanie pred expiráciou | 30 dní | Pri ≤ N dňoch sa certifikát automaticky obnoví |

### Debug

- **Debug terminál** – zapnutie/vypnutie debug panelu v monitoringu (Ctrl+D)

---

## Bezpečnosť a 2FA

### Dvojfaktorová autentifikácia (2FA)

2FA je povinné pre všetky účty. Bez nastavenej 2FA nie je možné sa prihlásiť.

#### Aktivácia 2FA

1. Po registrácii vás systém automaticky presmeruje na nastavenie 2FA
2. Naskenujte QR kód pomocou autentifikačnej aplikácie

**Podporované aplikácie:**
- Google Authenticator
- Microsoft Authenticator
- Authy
- 1Password
- Bitwarden

3. Zadajte 6-ciferný kód a potvrďte aktiváciu

#### Záložné kódy

- Automaticky sa vygeneruje 10 záložných kódov
- Každý kód je jednorazový (po použití sa označí ako spotrebovaný)
- **Uložte si ich na bezpečné miesto** – sú jediným spôsobom prístupu ak stratíte autentifikačnú aplikáciu
- Nové kódy: Nastavenia → Upraviť → záložka 2FA → "Generovať nové záložné kódy"

#### Prihlásenie s 2FA

1. Zadajte meno a heslo → "Prihlásiť sa"
2. Zadajte 6-ciferný kód z aplikácie **alebo** záložný kód
3. Po správnom zadaní ste presmerovaný na hlavnú stránku

#### Vypnutie 2FA

2FA je možné vypnúť v Nastaveniach → Upraviť → záložka 2FA. Vyžaduje zadanie aktuálneho hesla a platného 2FA kódu.

⚠️ Vypnutie 2FA sa **neodporúča** – znižuje bezpečnosť účtu.

### Obnova hesla

Ak zabudnete heslo, je možná obnova cez Pushover:

**Podmienky:**
- Pushover musí byť nakonfigurovaný a funkčný
- Musíte mať prístup k záložným kódom pre overenie identity

**Postup:**
1. Na prihlasovacej stránke kliknite **"Zabudnuté heslo"**
2. Systém odošle jednorazový kód cez Pushover notifikáciu
3. Zadajte kód a záložný 2FA kód
4. Po overení nastavte nové heslo

### Správa používateľského účtu

Prístup: Horná lišta → **"Upraviť"** vedľa mena → modálne okno s troma záložkami

#### Zmena používateľského mena

1. Záložka **"Používateľské meno"**
2. Zadajte nové meno (3–50 znakov, povolené: `a-z`, `A-Z`, `0-9`, `_`, `-`)
3. Overte aktuálnym heslom
4. Po zmene zostanete prihlásení pod novým menom

#### Zmena hesla

1. Záložka **"Heslo"**
2. Zadajte staré heslo, nové heslo (min. 8 znakov) a potvrdenie
3. Po zmene zostanete prihlásení

### Šifrovanie a hašovanie

| Typ dát | Metóda |
|---|---|
| SSH heslá zariadení | Fernet (AES 128-bit CBC + HMAC SHA256) |
| SNMP community strings | Fernet |
| TOTP secret | Fernet |
| Pushover kľúče, FTP heslo | Fernet |
| Používateľské heslá | Werkzeug (PBKDF2-SHA256) |
| Záložné 2FA kódy | Werkzeug hash |
| Tokeny obnovy hesla | Werkzeug hash |

Fernet kľúč: `/var/lib/mikrotik-manager/data/encryption.key` (44 bytes, chmod 600)

### Session Management

**Persistent SECRET_KEY:**
- Uložený v `/var/lib/mikrotik-manager/data/secret.key` (32 bytes, chmod 600)
- Sessions zostávajú platné aj po reštarte služby

**Platnosť session:** 1 rok (365 dní) od prihlásenia

**Správanie:**

| Scenár | Výsledok |
|---|---|
| Reštart služby | Stále prihlásený |
| Zatvorenie prehliadača | Stále prihlásený |
| Reštart zariadenia | Stále prihlásený |
| Vymazanie cookies / app dát | Vyžaduje nový login |
| Po 1 roku | Vyžaduje nový login |
| Manuálny logout | Okamžité odhlásenie |

**Reset všetkých sessions (ak je potrebný):**
```bash
systemctl stop mikrotik-manager
rm /var/lib/mikrotik-manager/data/secret.key
systemctl start mikrotik-manager
```

### Databázová štruktúra

**Umiestnenie:** `/var/lib/mikrotik-manager/data/mikrotik_manager.db`

Databáza obsahuje tieto tabuľky:

- **`devices`** – zariadenia, prihlasovacie údaje (šifrované), monitoring stav, soft-delete (`deleted_at`, `purge_after`)
- **`users`** – používateľské účty, hash hesla, TOTP secret (šifrovaný)
- **`backup_codes`** – záložné 2FA kódy (hašované), stav použitia
- **`password_recovery_tokens`** – jednorazové tokeny obnovy hesla (hašované), expirácia
- **`ping_history`** – história ping monitoringu (timestamp, latencia, strata paketov, status)
- **`snmp_history`** – história SNMP dát (CPU, teplota, pamäť, uptime)
- **`update_schedule`** – plánované a prebiehajúce aktualizácie RouterOS
- **`logs`** – systémové logy (info/warning/error)
- **`settings`** – konfiguračné nastavenia (key-value)

**Záloha databázy:**
```bash
systemctl stop mikrotik-manager
cp /var/lib/mikrotik-manager/data/mikrotik_manager.db /backup/mikrotik_db_$(date +%Y%m%d).db
systemctl start mikrotik-manager
```

---

## Riešenie problémov

### Aplikácia sa nespustí

```bash
# Kontrola stavu služby
systemctl status mikrotik-manager
journalctl -u mikrotik-manager -f

# Kontrola Python verzie (potrebná 3.11+)
/opt/mikrotik-manager/venv/bin/python --version

# Kontrola závislostí
cd /opt/mikrotik-manager
source venv/bin/activate
pip install -r requirements.txt

# Kontrola portu
ss -tlnp | grep :5000
```

### Zariadenie sa nezálohovuje

**Príznaky:** "SSH connection failed", "Authentication failed", timeout

```bash
# Manuálny test SSH
ssh admin@192.168.1.1

# MikroTik – kontrola SSH služby
/ip service print
/ip firewall filter print where dst-port=22
```

**Najčastejšie príčiny:**
- Nesprávne SSH prihlasovacie údaje
- SSH služba vypnutá na MikroTik
- Firewall blokuje port 22

### SNMP monitoring nefunguje

**Príznaky:** "SNMP timeout", prázdne grafy, N/A hodnoty

```bash
# Test SNMP z príkazového riadku
snmpwalk -v2c -c public 192.168.1.1 1.3.6.1.2.1.1.1
```

**Na MikroTik:**
```bash
/snmp set enabled=yes
/snmp community print
```

**Kontrolný zoznam:**
- Správny community string (predvolene `public`)
- Port 161 UDP otvorený
- SNMP verzia 2c

### Updater – zariadenie nie je dostupné cez REST API

**Príznaky:** Updater zobrazuje zariadenie ako offline napriek tomu, že ping funguje

**Kontrola:**
- MikroTik REST API musí byť zapnuté: `/ip service set www port=80 disabled=no` alebo `/ip service set www-ssl port=443 disabled=no`
- Správne prihlasovacie údaje v MikroTik Manager
- Firewall nesmie blokovať port 80/443

### WebSocket / real-time aktualizácie nefungujú

**Pri použití reverse proxy (nginx)** je nutné nastaviť WebSocket upgrade:

```nginx
proxy_http_version 1.1;
proxy_set_header Upgrade $http_upgrade;
proxy_set_header Connection "upgrade";
proxy_read_timeout 86400;
```

### Native Android APK sa nepripojí

1. Skontrolujte IP adresu/doménu na setup obrazovke aplikácie
2. Overte dostupnosť portu 5000 (alebo 443 cez nginx):
   ```bash
   ufw allow 5000
   ```
3. Skontrolujte, či je server dostupný zo siete mobilného zariadenia

### Database problémy

```bash
# Kontrola integrity
sqlite3 /var/lib/mikrotik-manager/data/mikrotik_manager.db "PRAGMA integrity_check;"

# Optimalizácia
sqlite3 /var/lib/mikrotik-manager/data/mikrotik_manager.db "VACUUM; REINDEX;"
```

### Čítanie logov

```bash
# Logy systemd služby
journalctl -u mikrotik-manager -f

# Posledných 100 riadkov
journalctl -u mikrotik-manager -n 100
```

---

## Často kladené otázky

### Všeobecné

**Q: Aké MikroTik zariadenia sú podporované?**

A: Všetky zariadenia s RouterOS v6.x a v7.x s dostupným SSH. Testované na hEX, CRS, CCR, RB, wAP sériách. Pre Updater je potrebné zapnuté REST API (HTTP/HTTPS).

**Q: Môžem používať aplikáciu cez internet?**

A: Áno, ale odporúčame:
- HTTPS cez reverse proxy (nginx)
- VPN prístup pre vyššiu bezpečnosť
- Silné heslo + povinná 2FA

**Q: Koľko zariadení môže aplikácia spravovať?**

A: Testované na 50+ zariadeniach. Limit závisí od výkonu servera a nastavených monitorovacích intervalov.

### Zálohovanie

**Q: Ako obnoviť zálohu na MikroTik?**

A: Dvoma spôsobmi:
1. `.backup` súbor – nahrať cez Winbox / WebFig → Files → obnoviť
2. `.rsc` súbor – importovať cez `/import file=export.rsc` v termináli

**Q: Kde sa ukladajú zálohy?**

A: Lokálne v `/var/lib/mikrotik-manager/data/backups/{ip}/` a voliteľne na FTP server.

### Monitoring

**Q: Prečo sa nezobrazujú SNMP dáta?**

A: Najčastejšie príčiny: SNMP nie je zapnuté na zariadení, nesprávny community string, firewall blokuje UDP port 161, zariadenie nie je dostupné.

**Q: Ako dlho sa uchovávajú monitoring dáta?**

A: Predvolene 30 dní pre ping aj SNMP históriu. Konfigurovateľné v Nastaveniach.

**Q: Prečo sa uptime a latencia menia pri zoom?**

A: Metriky sa dynamicky prepočítavajú pre viditeľné časové okno – zobrazujú presné hodnoty pre zoomovaný výsek, nie celý rozsah.

### Updater

**Q: Čo sa stane ak aktualizácia zlyhá?**

A: Systém loguje chybu a odošle Pushover notifikáciu (ak je nakonfigurovaná). Zariadenie sa označí ako "failed" v zozname plánov.

**Q: Môžem aktualizovať zariadenie bez zálohy?**

A: Áno, zálohu pred aktualizáciou je možné vypnúť v Nastaveniach → Updater → `updater_backup_before_update`.

**Q: Ako funguje aktualizácia CHR/VM?**

A: Systém automaticky detekuje VM/CHR zariadenia a preskočí firmware fázy (krok 4, 5, 6, 7). Vykoná sa len RouterOS aktualizácia a reboot.

### Bezpečnosť

**Q: Sú heslá zariadení bezpečne uložené?**

A: Áno – SSH heslá, SNMP community strings, FTP heslo a Pushover kľúče sú šifrované Fernet šifrovaním. Kľúč je v `/var/lib/mikrotik-manager/data/encryption.key` (chmod 600).

**Q: Je 2FA povinné?**

A: Áno, 2FA je povinné pre prihlásenie. Je možné ho vypnúť, ale neodporúčame to – znižuje bezpečnosť.

**Q: Čo sa stane ak stratím autentifikačnú aplikáciu?**

A: Použite záložný kód. Ak nemáte ani záložné kódy, je možná obnova cez Pushover (funkcia "Zabudnuté heslo" na prihlasovacej stránke) – vyžaduje funkčný Pushover.

**Q: Ako dlho zostávam prihlásený?**

A: Session platí 1 rok. Reštart služby, zatvorenie prehliadača ani reštart počítača session nezruší – je uložená ako persistent cookie.

**Q: Ako zrušiť všetky aktívne sessions?**

A: Odstrán `secret.key` a reštartuj službu:
```bash
systemctl stop mikrotik-manager
rm /var/lib/mikrotik-manager/data/secret.key
systemctl start mikrotik-manager
```

### Migrácia

**Q: Ako migrovať MikroTik Manager na nový server?**

A: Použite funkciu Export/Import:
1. Starý server: Nastavenia → Exportovať ZIP
2. Nový server: Nainštalovať MikroTik Manager
3. Nový server: Registračná stránka → záložka "Importovať zo ZIP" → nahrať ZIP
4. Prihlásiť sa pôvodnými údajmi

**Q: Môžem zmeniť používateľské meno po migrácii?**

A: Áno – Horná lišta → Upraviť → záložka "Používateľské meno".

### Technické

**Q: Aké sú systémové požiadavky?**

A: Minimálne: RAM 512 MB (odporúčané 1 GB), CPU 1 jadro, Disk 500 MB + miesto pre zálohy, Python 3.11+, Linux (Ubuntu/Debian).

**Q: Podporuje aplikácia SSL/HTTPS?**

A: Áno, cez reverse proxy. Príklad nginx konfigurácia:

```nginx
server {
    listen 443 ssl;
    server_name yourdomain.com;

    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/key.pem;

    location / {
        proxy_pass http://localhost:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_read_timeout 86400;
    }
}
```

**Q: Aká je štruktúra databázy?**

A: SQLite databáza s 9 tabuľkami – `devices`, `users`, `backup_codes`, `password_recovery_tokens`, `ping_history`, `snmp_history`, `update_schedule`, `logs`, `settings`.

**Q: Funguje aplikácia na Windows?**

A: Nie je primárne testovaná na Windows. Odporúčame Linux (Debian/Ubuntu) – napr. LXC kontajner na Proxmox.

---

## Záver

MikroTik Manager je komplexné riešenie pre správu MikroTik infraštruktúry. Kombinuje jednoduché používanie s pokročilými funkciami monitoringu, automatizácie a vzdialenej aktualizácie zariadení.

### Kľúčové výhody:

- **Centralizovaná správa** viacerých zariadení vrátane koša a obnovy
- **Automatické zálohovanie** s flexibilným plánovaním a FTP uploadom
- **Real-time monitoring** s interaktívnymi grafmi a WebSocket aktualizáciami
- **Vzdialené aktualizácie** RouterOS, firmware a TLS certifikátov
- **Mobilný prístup** cez Native Android aplikáciu
- **Bezpečnostné funkcie** – povinná 2FA, Fernet šifrovanie, session persistence
- **Migrácia** cez Export/Import ZIP

### Ďalšie kroky:

1. **Inštalácia** podľa tohto manuálu
2. **Registrácia** účtu a nastavenie 2FA
3. **Pridanie zariadení** do správy
4. **Nastavenie monitoringu** a Pushover notifikácií
5. **Nakonfigurovanie Updatera** pre plánované aktualizácie
6. **Pravidelné zálohovanie** kritických konfigurácií

---

*Manuál pre MikroTik Manager – github.com/spekulanter/mikrotik-manager*
