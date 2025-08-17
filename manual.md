# MikroTik Manager - Užívateľský manuál

## Obsah

1. [Úvod](#úvod)
2. [Inštalácia](#inštalácia)
3. [Prvé prihlásenie a nastavenie](#prvé-prihlásenie-a-nastavenie)
4. [Webové rozhranie](#webové-rozhranie)
5. [Mobilná aplikácia (APK)](#mobilná-aplikácia-apk)
6. [Správa zariadení](#správa-zariadení)
7. [Zálohovanie](#zálohovanie)
8. [Monitoring a grafy](#monitoring-a-grafy)
9. [Nastavenia systému](#nastavenia-systému)
10. [Bezpečnosť a 2FA](#bezpečnosť-a-2fa)
11. [Riešenie problémov](#riešenie-problémov)
12. [Často kladené otázky](#často-kladené-otázky)

---

## Úvod

**MikroTik Manager** je komplexný webový nástroj pre správu, zálohovanie a monitoring MikroTik zariadení. Umožňuje centralizovanú správu viacerých RouterOS zariadení s možnosťou automatického zálohovania, real-time monitoringu a vzdialeneho prístupu cez webové rozhranie alebo mobilnú aplikáciu.

### Hlavné funkcie:

- **Centralizovaná správa zariadení** - Pridávanie, úprava a správa MikroTik zariadení
- **Automatické zálohovanie** - Pravidelné vytváranie a sťahovanie backup súborov
- **Real-time monitoring** - Sledovanie stavu zariadení, CPU, teploty, pamäte a dostupnosti
- **SNMP monitoring** - Detailné sledovanie výkonu zariadení
- **Ping monitoring** - Kontinuálne sledovanie dostupnosti siete
- **Webové aj mobilné rozhranie** - Prístup cez prehliadač alebo Android aplikáciu
- **Bezpečnostné funkcie** - 2FA autentifikácia, šifrovanie hesiel
- **Notifikácie** - Pushover notifikácie pri problémech
- **FTP upload** - Automatické nahrávanie záloh na FTP server

---

## Inštalácia

### Automatická inštalácia (odporúčané)

1. **Stiahnutie inštalačného skriptu:**
```bash
wget https://raw.githubusercontent.com/your-repo/mikrotik-manager/main/install-mikrotik-manager.sh
chmod +x install-mikrotik-manager.sh
```

2. **Spustenie inštalácie:**
```bash
sudo ./install-mikrotik-manager.sh
```

Skript automaticky:
- Nainštaluje všetky potrebné závislosti (Python, Node.js, Android SDK)
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
git clone https://github.com/your-repo/mikrotik-manager.git
cd mikrotik-manager
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
- **Disk:** 500 MB voľného miesta
- **Python:** 3.8 alebo novší
- **Sieť:** Prístup k MikroTik zariadeniam cez SSH a SNMP

---

## Prvé prihlásenie a nastavenie

### 1. Prístup k aplikácii

Po úspešnej inštalácii je aplikácia dostupná na:
- **Webové rozhranie:** `http://IP_SERVERA:5000`
- **Mobilná aplikácia:** Nainštalujte APK súbor z `/opt/MikroTikManager.apk`

### 2. Vytvorenie prvého účtu

1. Otvorte webové rozhranie
2. Kliknite na **"Vytvoriť nový účet"**
3. Zadajte:
   - **Používateľské meno** (4-50 znakov)
   - **Heslo** (minimálne 8 znakov)
4. Kliknite **"Vytvoriť účet"**

### 3. Prvé prihlásenie

1. Zadajte vytvorené používateľské meno a heslo
2. Kliknite **"Prihlásiť sa"**
3. Budete presmerovaní na hlavnú stránku

### 4. Nastavenie 2FA (odporúčané)

1. Prejdite do **Nastavenia**
2. V sekcii **"Bezpečnosť"** kliknite **"Nastaviť 2FA"**
3. Naskenujte QR kód pomocou aplikácie ako Google Authenticator
4. Zadajte overovací kód a potvrďte
5. Uložte si záložné kódy na bezpečné miesto

---

## Webové rozhranie

### Hlavná stránka (Dashboard)

Hlavná stránka obsahuje:

#### Horná lišta
- **Logo a verzia** - MikroTik Manager
- **Navigačné tlačidlá:**
  - **Monitoring** - Grafy a real-time sledovanie
  - **Zálohy** - História a správa backup súborov
  - **Nastavenia** - Konfigurácia systému
- **Užívateľské menu:**
  - Zmena hesla
  - Nastavenie 2FA
  - Odhlásenie

#### Stredná časť - Správa zariadení

**Pridanie nového zariadenia:**
1. Kliknite **"Pridať zariadenie"**
2. Vyplňte formulár:
   - **IP adresa** - IP adresa MikroTik zariadenia
   - **Názov** - Popisný názov (napr. "Hlavný router")
   - **Používateľské meno** - SSH používateľ (obvykle "admin")
   - **Heslo** - SSH heslo
   - **Low Memory Mode** - Zaškrtnite pre zariadenia s malou pamäťou
   - **SNMP Community** - Obvykle "public"
3. Kliknite **"Pridať zariadenie"**

**Zoznam zariadení:**
- **Zelený status** - Zariadenie je online a dostupné
- **Červený status** - Zariadenie je offline alebo nedostupné
- **Žltý status** - Neznámy stav alebo problémy s pripojením

**Akcie pre zariadenia:**
- **Zálohovať** - Vytvorí okamžitú zálohu
- **SNMP** - Zobrazí aktuálne SNMP údaje
- **Upraviť** - Zmení nastavenia zariadenia
- **Zmazať** - Odstráni zariadenie zo systému

#### Spodná časť - Ovládanie systému

**Hromadné operácie:**
- **Zálohovať všetky** - Spustí zálohovanie všetkých zariadení
- **Obnoviť SNMP údaje** - Aktualizuje SNMP informácie pre všetky zariadenia

**Stavové informácie:**
- **SNMP Timer Status** - Stav automatického SNMP monitoringu
- **Počet aktívnych záloh** - Aktuálne prebiehajúce zálohy
- **Posledná aktivita** - Časové pečiatky posledných operácií

#### Bočný panel - Logy a debug

**Real-time logy:**
- **Info** - Informačné správy (zelené)
- **Warning** - Varovania (žlté)
- **Error** - Chybové hlásenia (červené)

**Debug panel** (ak je zapnutý):
- Detailné technické informácie
- Websocket komunikácia
- SNMP requesty a odpovede

### Responsívny dizajn

Webové rozhranie je optimalizované pre:
- **Desktop** - Plná funkcionalita na veľkých obrazovkách
- **Tablet** - Prispôsobené rozloženie pre stredné obrazovky
- **Mobile** - Kompaktné rozhranie pre telefóny

---

## Mobilná aplikácia (APK)

### Inštalácia APK

1. **Stiahnutie:**
   - APK súbor sa nachádza v `/opt/MikroTikManager.apk`
   - Veľkosť: približne 3.4 MB

2. **Inštalácia na Android:**
   - Povolte inštaláciu z neznámych zdrojov
   - Otvorte APK súbor a potvrďte inštaláciu

### Použitie mobilnej aplikácie

1. **Spustenie aplikácie:**
   - Aplikácia sa automaticky pripojí na server
   - Zadajte IP adresu servera pri prvom spustení

2. **Prihlásenie:**
   - Použite rovnaké prihlasovacie údaje ako vo webovom rozhraní
   - Podporuje 2FA autentifikáciu

3. **Funkcie:**
   - Plná funkcionalita webového rozhrania
   - Optimalizované pre dotykové ovládanie
   - Offline režim pre základné informácie

### Rozdiely oproti webovému rozhraniu

**Výhody mobilnej aplikácie:**
- Rychlejšie spustenie
- Lepšia optimalizácia pre dotykovú obrazovku
- Možnosť push notifikácií
- Integrované s natívnymi Android funkciami

**Obmedzenia:**
- Vyžaduje internetové pripojenie
- Závislá na dostupnosti servera
- Menšia obrazovka môže obmedziť zobrazenie komplexných grafov

---

## Správa zariadení

### Pridávanie zariadení

#### Požiadavky na MikroTik zariadenie

1. **SSH prístup:**
   - Zapnutá SSH služba
   - Vytvorený používateľ s admin právami
   - Nastavené heslo

2. **SNMP prístup:**
   - Zapnutá SNMP služba
   - Nastavená SNMP community (obvykle "public")
   - SNMP verzia 2c

#### Konfigurácia MikroTik zariadenia

```bash
# SSH konfigurácia
/ip service set ssh port=22 disabled=no

# SNMP konfigurácia
/snmp set enabled=yes contact="admin@example.com" location="Data Center"
/snmp community set public name=public
```

#### Pridanie do MikroTik Manager

1. V hlavnom rozhraní kliknite **"Pridať zariadenie"**
2. Vyplňte všetky povinné polia
3. **Testovanie pripojenia:**
   - Systém automaticky testuje SSH pripojenie
   - Overí SNMP dostupnosť
   - Zobrazí výsledok testu

### Správa existujúcich zariadení

#### Upravenie zariadenia

1. Kliknite na **ikonu ceruzky** vedľa zariadenia
2. Môžete zmeniť:
   - Názov zariadenia
   - IP adresu
   - Prihlasovacie údaje
   - SNMP nastavenia
   - Monitoring intervaly

#### Odstránenie zariadenia

1. Kliknite na **ikonu koša** vedľa zariadenia
2. Potvrďte odstránenie
3. **Pozor:** Odstránia sa aj všetky súvisiace zálohy a monitoring dáta

### Stavy zariadení

#### Indikátory stavu

- **🟢 Online** - Zariadenie je dostupné a funguje správne
- **🔴 Offline** - Zariadenie nie je dostupné
- **🟡 Unknown** - Neznámy stav alebo chyba pripojenia
- **⏸️ Paused** - Monitoring je pozastavený

#### Automatické sledovanie stavu

Systém pravidelně kontroluje:
- **Ping dostupnosť** - Každé 30 sekúnd (predvolene)
- **SSH pripojenie** - Pri každej zálohe
- **SNMP odpoveď** - Podľa nastaveného intervalu

---

## Zálohovanie

### Automatické zálohovanie

#### Nastavenie automatického zálohovania

1. V **Nastaveniach** prejdite do sekcie **"Zálohovanie"**
2. Nastavte:
   - **Interval zálohovania** (hodiny/dni)
   - **Počet uchovaných záloh** (predvolene 10)
   - **Oneskorenie medzi zariadeniami** (predvolene 30s)

#### Proces automatického zálohovania

1. **Spustenie:** Podľa nastaveného plánu
2. **Pripojenie:** SSH na MikroTik zariadenie
3. **Export:** Vytvorenie .backup a .rsc súborov
4. **Stiahnutie:** Prenos súborov na server
5. **Uloženie:** Organizácia do priečinkov podľa IP adresy
6. **Cleanup:** Odstránenie starých záloh podľa nastavenia

### Manuálne zálohovanie

#### Záloha jednotlivého zariadenia

1. V zozname zariadení kliknite **"Zálohovať"**
2. Systém zobrazí progress bar
3. Po dokončení sa zobrazí výsledok

#### Hromadná záloha

1. Kliknite **"Zálohovať všetky"** v spodnej časti
2. Systém postupne zálohuje všetky zariadenia
3. Sledujte progress v real-time

### Správa backup súborov

#### Priečinková štruktúra

```
backups/
├── 192.168.1.1/
│   ├── backup_2024-01-15_10-30-00.backup
│   ├── export_2024-01-15_10-30-00.rsc
│   └── ...
├── 192.168.1.2/
│   └── ...
```

#### Stránka Zálohy

1. Prejdite na **Zálohy** v hornej lište
2. Zobrazenie:
   - Zoznam všetkých backup súborov
   - Dátum a čas vytvorenia
   - Veľkosť súboru
   - Typ súboru (.backup/.rsc)

3. **Akcie:**
   - **Stiahnuť** - Download súboru na lokálny počítač
   - **Zobraziť obsah** - Náhľad .rsc súborov
   - **Zmazať** - Odstránenie súboru

### FTP upload záloh

#### Nastavenie FTP

1. V **Nastaveniach** nájdite sekciu **"FTP nastavenia"**
2. Vyplňte:
   - **FTP server** - IP alebo hostname
   - **Používateľské meno**
   - **Heslo**
   - **Priečinok** (voliteľné)

#### Automatický upload

- Každá úspešná záloha sa automaticky nahraje na FTP
- V logoch vidíte potvrdenie úspešného uploadu
- Pri chybe FTP sa záloha uloží lokálne

---

## Monitoring a grafy

### Stránka Monitoring

Prístup cez **Monitoring** tlačidlo v hornej lište.

#### Výber zariadenia

- Dropdown menu s výberom zariadenia
- Automatické načítanie dát po výbere
- Zobrazenie aktuálneho stavu zariadenia

#### Typy grafov

**1. Ping Latency Graf**
- **Osa Y:** Latencia v milisekundách
- **Osa X:** Čas
- **Farby:**
  - Zelená: Nízka latencia (< 50ms)
  - Žltá: Stredná latencia (50-100ms)
  - Červená: Vysoká latencia (> 100ms)
- **Červené body:** Stratené pakety

**2. CPU Load Graf**
- **Osa Y:** Zaťaženie v percentách (0-100%)
- **Osa X:** Čas
- **Farby:**
  - Zelená: Nízke zaťaženie (< 50%)
  - Žltá: Stredné zaťaženie (50-80%)
  - Červená: Vysoké zaťaženie (> 80%)

**3. Teplota Graf**
- **Osa Y:** Teplota v stupňoch Celzia
- **Osa X:** Čas
- **Farebné zóny:**
  - Zelená: Normálna teplota (< 60°C)
  - Žltá: Zvýšená teplota (60-70°C)
  - Červená: Kritická teplota (> 70°C)

**4. Memory Usage Graf**
- **Osa Y:** Využitie pamäte v percentách
- **Osa X:** Čas
- **Detaily:**
  - Používaná pamäť
  - Celková pamäť
  - Percentuálne využitie

#### Ovládanie grafov

**Zoom funkcie:**
- **Zoom in:** Krúženie myšou alebo dotyk
- **Zoom out:** Dvojklik alebo tlačidlo
- **Pan:** Ťahanie po zoomovaní
- **Reset:** Tlačidlo "Zoom out" pre pôvodný pohľad

**Časové rozsahy:**
- **1 hodina** - Detailný pohľad
- **6 hodín** - Krátke trendy
- **24 hodín** - Denný prehľad
- **7 dní** - Týždenné trendy
- **30 dní** - Mesačný prehľad

**Automatické obnovenie:**
- Dáta sa automaticky aktualizujú každých 30 sekúnd
- Možnosť pozastavenia auto-refresh
- Manuálne obnovenie tlačidlom

### SNMP Monitoring

#### Nastavenie SNMP intervalov

1. **Globálne nastavenie:**
   - V **Nastaveniach** → **SNMP Monitor**
   - Predvolený interval: 10 minút

2. **Per-device nastavenie:**
   - Pri úprave zariadenia
   - Override globálneho nastavenia
   - 0 = vypnuté SNMP monitoring

#### SNMP údaje

**Získavané informácie:**
- **System Info:** Identita, verzia, model
- **Performance:** CPU, pamäť, teplota
- **Network:** Interfaces, traffic
- **Uptime:** Doba behu zariadenia

**Úloženie dát:**
- SQLite databáza
- Kompresné algoritmy pre efektívnosť
- Automatické čistenie starých dát

### Ping Monitoring

#### Konfigurácia ping monitoringu

1. **Interval:** Predvolene 30 sekúnd
2. **Timeout:** 5 sekúnd na ping
3. **Packet count:** 4 pakety na test
4. **Retry logic:** 3 pokusy pred označením ako offline

#### Notifications pri výpadkoch

**Pushover notifikácie:**
- Okamžite pri zistení výpadku
- Potvrdenie obnovenia pripojenia
- Konfigurovateľné v Nastaveniach

---

## Nastavenia systému

### Prístup k nastaveniam

Kliknite na **Nastavenia** v hornej lište hlavnej stránky.

### Sekcie nastavení

#### 1. Zálohovanie

**Počet uchovaných záloh:**
- Predvolene: 10 záloh na zariadenie
- Rozsah: 1-100
- Automatické mazanie najstarších

**Oneskorenie medzi zariadeniami:**
- Predvolene: 30 sekúnd
- Účel: Predchádzanie preťaženiu siete
- Rozsah: 5-300 sekúnd

**Automatické zálohovanie:**
- Zapnutie/vypnutie automatického režimu
- Nastavenie času spustenia
- Výber dní v týždni

#### 2. SNMP Monitor

**Interval kontroly:**
- Predvolene: 10 minút
- Globálne nastavenie pre všetky zariadenia
- Možnosť override na úrovni zariadenia

**Timeout nastavenia:**
- SNMP timeout: 10 sekúnd
- Retry count: 2 pokusy
- Port: 161 (štandardný SNMP port)

#### 3. FTP nastavenia

**Server informácie:**
- **Hostname/IP:** FTP server adresa
- **Port:** Predvolene 21
- **Username:** FTP prihlasovacie meno
- **Password:** FTP heslo (šifrované uloženie)

**Upload nastavenia:**
- **Remote directory:** Cieľový priečinok na FTP
- **Passive mode:** Odporúčané pre firewall
- **SSL/TLS:** Podpora pre bezpečný prenos

#### 4. Pushover notifikácie

**API nastavenia:**
- **App Key:** Pushover aplikačný kľúč
- **User Key:** Váš Pushover používateľský kľúč
- **Test tlačidlo:** Overenie funkčnosti

**Typy notifikácií:**
- Device offline/online
- Backup úspešné/neúspešné
- SNMP chyby
- Systémové upozornenia

#### 5. Logy a Debug

**Log retention:**
- Počet dní uchovávania logov
- Predvolene: 30 dní
- Automatické čistenie

**Debug módy:**
- **Terminal debug:** Detailné logy operácií
- **WebSocket debug:** Komunikácia s frontendom
- **SNMP debug:** SNMP requesty a odpovede

**Export funkcionalita:**
- Stiahnuť logy ako textový súbor
- Filtrovanie podľa dátumu a typu
- Kompresný format pre veľké súbory

#### 6. Bezpečnosť

**Zmena hesla:**
1. Zadajte aktuálne heslo
2. Zadajte nové heslo (min. 8 znakov)
3. Potvrďte nové heslo
4. Kliknite "Zmeniť heslo"

**2FA nastavenie:**
- QR kód pre Google Authenticator
- Záložné kódy (uložte si ich!)
- Vypnutie 2FA (vyžaduje aktuálne heslo)

### Uloženie nastavení

1. **Automatické uloženie:** Zmeny sa ukladajú okamžite
2. **Validácia:** Systém kontroluje správnosť údajov
3. **Restart služieb:** Niektoré zmeny vyžadujú restart SNMP timers

---

## Bezpečnosť a 2FA

### Dvojfaktorová autentifikácia (2FA)

#### Aktivácia 2FA

1. **Prístup k nastaveniam:**
   - Prihláste sa do systému
   - Kliknite na používateľské menu → "Nastavenia"

2. **Nastavenie 2FA:**
   - V sekcii "Bezpečnosť" kliknite "Nastaviť 2FA"
   - Naskenujte QR kód pomocou autentifikačnej aplikácie

3. **Podporované aplikácie:**
   - Google Authenticator
   - Microsoft Authenticator
   - Authy
   - 1Password
   - Bitwarden

4. **Potvrdenie aktivácie:**
   - Zadajte 6-ciferný kód z aplikácie
   - Kliknite "Potvrdiť a aktivovať"

#### Záložné kódy

**Generovanie kódov:**
- Automaticky sa vygeneruje 10 záložných kódov
- Každý kód môžete použiť iba raz
- Uložte si ich na bezpečné miesto

**Použitie záložných kódov:**
- Pri prihlásení zadajte záložný kód namiesto 2FA
- Kód sa po použití označí ako použitý
- Odporúčame generovať nové kódy po použití

**Obnova kódov:**
1. Prihláste sa do systému
2. Prejdite do Nastavení → Bezpečnosť
3. Kliknite "Generovať nové záložné kódy"
4. Stiahnite si nové kódy

#### Prihlásenie s 2FA

1. **Štandardné prihlásenie:**
   - Zadajte používateľské meno a heslo
   - Kliknite "Prihlásiť sa"

2. **2FA overenie:**
   - Budete presmerovaní na 2FA stránku
   - Zadajte 6-ciferný kód z autentifikačnej aplikácie
   - Alebo použite záložný kód

3. **Úspešné prihlásenie:**
   - Po správnom zadaní budete presmerovaní na hlavnú stránku

#### Vypnutie 2FA

1. **Bezpečnostné overenie:**
   - Zadajte aktuálne heslo
   - Zadajte aktuálny 2FA kód

2. **Potvrdenie:**
   - Kliknite "Vypnúť 2FA"
   - Všetky záložné kódy sa deaktivujú

### Šifrovanie hesiel

#### Automatické šifrovanie

Systém automaticky šifruje:
- **SSH heslá zariadení** - Fernet encryption
- **FTP heslá** - AES encryption
- **Používateľské heslá** - bcrypt hashing

#### Migrácia starých hesiel

Pri prvom spustení novej verzie:
1. Systém detekuje nešifrované heslá
2. Automaticky ich zašifruje
3. Zapíše log o migrácii
4. Staré heslá sa prepíšu šifrovanými

### Session management

#### Bezpečnosť sessions

- **Flask sessions** s náhodným secret key
- **Automatické vypršanie** po 24 hodinách nečinnosti
- **Secure cookies** pri HTTPS pripojení

#### Logout funkcie

- **Manuálny logout** - Tlačidlo "Odhlásiť sa"
- **Automatický logout** - Po vypršaní session
- **Global logout** - Zrušenie všetkých aktívnych sessions

---

## Riešenie problémov

### Časté problémy a riešenia

#### 1. Aplikácia sa nespustí

**Príznaky:**
- Chyba pri spustení `python app.py`
- Port 5000 nie je dostupný
- Import errors

**Riešenie:**
```bash
# Kontrola Python verzie
python3 --version  # Minimálne 3.8

# Kontrola virtuálneho prostredia
source venv/bin/activate
pip list

# Inštalácia chýbajúcich balíčkov
pip install -r requirements.txt

# Kontrola portov
sudo netstat -tlnp | grep :5000
```

#### 2. Zariadenie sa nezálohovuje

**Príznaky:**
- "SSH connection failed"
- "Authentication failed"
- Timeout chyby

**Riešenie:**
```bash
# Manuálny test SSH pripojenia
ssh admin@192.168.1.1

# Kontrola MikroTik nastavení
/ip service print
/user print

# Firewall kontrola
/ip firewall filter print where dst-port=22
```

**Časté príčiny:**
- Nesprávne SSH credentials
- SSH služba vypnutá na MikroTik
- Firewall blokuje port 22
- Sieťové problémy

#### 3. SNMP monitoring nefunguje

**Príznaky:**
- "SNMP timeout"
- Prázdne SNMP údaje
- N/A hodnoty v grafoch

**Riešenie:**
```bash
# Test SNMP z príkazového riadku
snmpwalk -v2c -c public 192.168.1.1 1.3.6.1.2.1.1.1

# MikroTik SNMP konfigurácia
/snmp set enabled=yes
/snmp community print
```

**Kontrola:**
- SNMP community name (predvolene "public")
- SNMP port 161 otvorený
- SNMP verzia 2c

#### 4. Webové rozhranie sa nenačíta

**Príznaky:**
- Blank stránka
- JavaScript errors
- 404/500 chyby

**Riešenie:**
```bash
# Kontrola logov aplikácie
journalctl -u mikrotik-manager -f

# Kontrola disk space
df -h

# Kontrola pamäte
free -h

# Restart aplikácie
sudo systemctl restart mikrotik-manager
```

#### 5. Database problémy

**Príznaky:**
- "Database locked"
- Corrupt database errors
- Pomalé načítavanie

**Riešenie:**
```bash
# Kontrola databázy
sqlite3 mikrotik_manager.db ".schema"

# Backup databázy
cp mikrotik_manager.db mikrotik_manager.db.backup

# Repair database
sqlite3 mikrotik_manager.db "PRAGMA integrity_check;"
```

#### 6. APK aplikácia sa nepripojí

**Príznaky:**
- Connection timeout
- SSL certificate errors
- Network unreachable

**Riešenie:**
1. **Kontrola IP adresy servera**
2. **Firewall nastavenia:**
   ```bash
   # Otvorenie portu 5000
   sudo ufw allow 5000
   ```
3. **SSL certifikát** (ak používate HTTPS)
4. **Android network permissions**

### Debug a logging

#### Zapnutie debug režimu

1. **V web rozhraní:**
   - Nastavenia → Logy a Debug
   - Zapnite "Terminal debug"
   - Zapnite "WebSocket debug"

2. **V aplikácii:**
   ```python
   # V app.py
   DEBUG = True
   logger.setLevel(logging.DEBUG)
   ```

#### Čítanie logov

**Systémové logy:**
```bash
# Journalctl logs
sudo journalctl -u mikrotik-manager -f

# Aplikačné logy
tail -f /opt/mikrotik-manager/app.log
```

**Web logy:**
- Real-time v debug paneli
- Export cez Nastavenia → Logy
- Filtrovanie podľa typu a dátumu

#### Diagnostické nástroje

**Network connectivity:**
```bash
# Ping test
ping -c 4 192.168.1.1

# Port connectivity
telnet 192.168.1.1 22
telnet 192.168.1.1 161
```

**SNMP testing:**
```bash
# Inštalácia SNMP utils
sudo apt install snmp snmp-mibs-downloader

# Test SNMP
snmpget -v2c -c public 192.168.1.1 1.3.6.1.2.1.1.1.0
```

### Performance optimization

#### Database optimization

```sql
-- Vacuum database
VACUUM;

-- Reindex
REINDEX;

-- Analyze statistics
ANALYZE;
```

#### Memory optimization

**Pre nízko-pamäťové zariadenia:**
- Zapnite "Low Memory Mode"
- Znížte SNMP interval
- Obmedzte počet uchovaných záloh

**Server optimalizácia:**
```bash
# Zvýšenie swap
sudo swapon --show
sudo fallocate -l 1G /swapfile
sudo chmod 600 /swapfile
sudo mkswap /swapfile
sudo swapon /swapfile
```

---

## Často kladené otázky

### Všeobecné otázky

**Q: Aké MikroTik zariadenia sú podporované?**

A: Všetky zariadenia s RouterOS v6.x a v7.x. Testované na:
- hEX series
- CRS series  
- CCR series
- RB series
- wAP series

**Q: Môžem používať aplikáciu cez internet?**

A: Áno, ale odporúčame:
- Použitie HTTPS (SSL certifikát)
- Zmenu predvoleného portu 5000
- Firewall konfiguráciu
- VPN prístup pre vyššiu bezpečnosť

**Q: Koľko zariadení môže aplikácia spravovať?**

A: Testované do 50 zariadení. Limit závisí od:
- Výkonu servera
- Dostupnej pamäte  
- Sieťovej konektivity
- SNMP intervalov

### Zálohovanie

**Q: Ako často sa vytvárajú zálohy?**

A: Záleží na nastavení:
- Manuálne zálohy: na požiadanie
- Automatické zálohy: podľa nastaveného plánu
- Doporučený interval: denne až týždenne

**Q: Kde sa ukladajú backup súbory?**

A: Lokálne v priečinku `backups/` a voliteľne na FTP server. Štruktúra:
```
backups/
├── 192.168.1.1/
│   ├── backup_2024-01-15_10-30-00.backup
│   └── export_2024-01-15_10-30-00.rsc
```

**Q: Môžem obnoviť zálohu?**

A: Áno, dvoma spôsobmi:
1. Stiahnuť backup súbor a nahrať cez Winbox/WebFig
2. Použiť .rsc súbor pre import nastavení

### Monitoring

**Q: Ako dlho sa uchovávajú monitoring dáta?**

A: Predvolene:
- Ping history: 30 dní
- SNMP history: 30 dní  
- Logy: 30 dní
- Konfigurovateľné v nastaveniach

**Q: Prečo sa nezobrazujú SNMP dáta?**

A: Najčastejšie príčiny:
- SNMP nie je zapnuté na MikroTik
- Nesprávna SNMP community
- Firewall blokuje port 161
- Zariadenie nie je dostupné

**Q: Môžem pridať vlastné SNMP OID?**

A: Momentálne nie, ale je to na roadmape. Aktuálne podporované:
- CPU load
- Memory usage
- Temperature  
- Uptime
- System info

### Bezpečnosť

**Q: Sú heslá bezpečne uložené?**

A: Áno:
- SSH heslá: Fernet encryption
- Používateľské heslá: bcrypt hashing
- Database: SQLite s šifrovanými stĺpcami
- Session: Flask sessions s náhodným kľúčom

**Q: Je 2FA povinné?**

A: Nie, ale silne odporúčané, especially pre:
- Internet prístup
- Produkčné prostredie
- Správu kritických zariadení

**Q: Môžem používať LDAP/Active Directory?**

A: Momentálne nie, iba lokálne používateľské účty. LDAP integrácia je plánovaná v budúcej verzii.

### Technické otázky

**Q: Aké sú systémové požiadavky?**

A: Minimálne:
- RAM: 512 MB (doporučené 1 GB)
- CPU: 1 core (doporučené 2 cores)
- Disk: 500 MB + miesto pre zálohy
- OS: Linux (Ubuntu/Debian testované)

**Q: Môžem spustiť aplikáciu v Dockeri?**

A: Áno, Docker support je dostupný. Dockerfile v repozitári:
```bash
docker build -t mikrotik-manager .
docker run -p 5000:5000 -v $(pwd)/data:/app/data mikrotik-manager
```

**Q: Podporuje aplikácia SSL/HTTPS?**

A: Áno, konfigurácia cez reverse proxy (nginx):
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
    }
}
```

### Mobilná aplikácia

**Q: Je dostupná iOS aplikácia?**

A: Momentálne iba Android APK. iOS verzia je v pláne.

**Q: Ako aktualizovať mobilnú aplikáciu?**

A: Stiahnuť novú APK verziu a preinštalovať. Dáta sa uchovávajú na serveri.

**Q: Funguje aplikácia offline?**

A: Čiastočne - zobrazuje posledné známe dáta, ale vyžaduje pripojenie pre aktuálne informácie.

### Podpora a vývoj

**Q: Kde môžem nahlásiť bug alebo požiadať o novú funkciu?**

A: GitHub Issues: https://github.com/your-repo/mikrotik-manager/issues

**Q: Je aplikácia open source?**

A: Áno, MIT licencia. Príspevky sú vítané.

**Q: Aká je roadmapa vývoja?**

A: Plánované funkcie:
- iOS aplikácia
- LDAP integrácia  
- Dashboard customization
- API pre tretie strany
- Rozšírenie SNMP monitoring
- Scheduled reports

**Q: Môžem upraviť zdrojový kód?**

A: Áno, pod MIT licenciou. Doporučujeme:
- Fork repozitára
- Vytvorenie feature branch
- Pull request s popisom zmien
- Testovanie pred submission

---

## Záver

MikroTik Manager je komplexné riešenie pre správu MikroTik infraštruktúry. Kombinuje jednoduché používanie s pokročilými funkciami monitoringu a automatizácie.

### Kľúčové výhody:

- **Centralizovaná správa** viacerých zariadení
- **Automatické zálohovanie** s flexible scheduling
- **Real-time monitoring** s grafickými reportmi
- **Mobilný prístup** cez Android aplikáciu
- **Bezpečnostné funkcie** s 2FA podporou
- **Open source** riešenie s aktívnym vývojom

### Ďalšie kroky:

1. **Inštalácia** podľa tohto manuálu
2. **Konfigurácia** základných nastavení
3. **Pridanie zariadení** do správy
4. **Nastavenie monitoringu** a notifikácií
5. **Pravidelné zálohovanie** kritických konfigurácií

Pre technickú podporu a aktualizácie navštívte GitHub repozitár alebo kontaktujte vývojový tím.

---

*Manuál pre MikroTik Manager - Verzia 1.0 - Január 2024*
