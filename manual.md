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
    - [Dvojfaktorová autentifikácia](#dvojfaktorová-autentifikácia-2fa)
    - [Správa používateľského účtu](#správa-používateľského-účtu)
    - [Session Management a Cookie Persistence](#session-management-a-cookie-persistence)
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
- **Bezpečnostné funkcie** - Povinná 2FA autentifikácia, šifrovanie hesiel
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
- **Mobilná aplikácia:** Nainštalujte APK súbor z `/opt/MT Manager.apk`

### 2. Vytvorenie účtu

⚠️ **DÔLEŽITÉ:** Systém podporuje len jeden účet. Po vytvorení musíte povinne nastaviť 2FA.

1. Otvorte webové rozhranie
2. Kliknite na **"Vytvoriť nový účet"**
3. Zadajte:
   - **Používateľské meno** (4-50 znakov)
   - **Heslo** (minimálne 8 znakov)
4. Kliknite **"Vytvoriť účet"**
5. **Ihneď nastavte 2FA** (povinné)

### 3. Prvé prihlásenie

1. Zadajte vytvorené používateľské meno a heslo
2. Kliknite **"Prihlásiť sa"**
3. Budete presmerovaní na hlavnú stránku

### 4. Nastavenie 2FA (povinné)

⚠️ **DÔLEŽITÉ:** 2FA je povinné pre všetky účty a nedá sa vypnúť po aktivácii.

1. Prejdite do **Nastavenia**
2. V sekcii **"Bezpečnosť"** kliknite **"Nastaviť 2FA"**
3. Naskenujte QR kód pomocou aplikácie ako Google Authenticator
4. Zadajte overovací kód a potvrďte
5. **Uložte si záložné kódy na bezpečné miesto** - sú potrebné pre obnovenie prístupu

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

## Mobilná aplikácia (Native Android APK)

### Generovanie APK

1. **Automatické buildovanie:**
   ```bash
   cd /opt/mikrotik-manager
   bash build-apk.sh
   ```
   - APK súbor sa vytvorí ako `/opt/MT Manager.apk`
   - Veľkosť: 6.2 MB (obsahuje optimalizovanú splash screen knižnicu)
   - Kompatibilita: Android 7+ (API 24+), optimalizované pre Android 15

### Inštalácia APK

1. **Stiahnutie:**
   - APK súbor sa nachádza v `/opt/MT Manager.apk`
   - Native Android aplikácia s Kotlin WebView

2. **Inštalácia na Android:**
   - Povolte inštaláciu z neznámych zdrojov
   - Otvorte APK súbor a potvrďte inštaláciu

### Ikona aplikácie

Aplikácia má vlastnú **network-themed ikonu** navrhnutú špeciálne pre MikroTik Manager:

**Charakteristiky ikony:**
- **Sieťová topológia** - Zobrazuje tri sieťové zariadenia (routery/switche) prepojené káblami
- **Sky blue téma** - Farby zosúladené s webovou verziou (#38bdf8, #0ea5e9, #60a5fa)
- **Tmavé pozadie** - Moderný dark theme (#0f172a)
- **Profesionálny dizajn** - Čisté línie a connection points
- **Android optimalizácia** - 108dp rozlíšenie pre adaptive icons

**Vizuálna reprezentácia:**
- Vrchné zariadenia reprezentujú edge routery/switche
- Spodné zariadenie reprezentuje core switch/router  
- Modré káble znázorňují network connections
- Junction body označujú connection points v topológii

Ikona vizuálne reprezentuje účel aplikácie - správu MikroTik sieťových zariadení a ich prepojenú topológiu.

### Optimalizovaný splash screen

Aplikácia používa **moderný splash screen** optimalizovaný pre Android 12+ a Android 15:

**Vlastnosti splash screen:**
- **Tmavé pozadie** - Konzistentné s webovou aplikáciou (#111827)
- **Žiadna ikona** - Čistý tmavý splash screen bez prebliknutí
- **Rýchle spustenie** - Animácia 200ms pre okamžité zobrazenie
- **Eliminované blikania** - Žiadne biele flashy počas načítavania
- **Android 15 kompatibilita** - Testované na OnePlus 13

**Technické optimalizácie:**
- Používa oficiálnu `androidx.core:core-splashscreen` knižnicu
- WebView sa zobrazí až po úplnom načítaní obsahu
- Konzistentné tmavé pozadie cez všetky aktivity
- Optimalizované pre najnovšie Android zariadenia

### Použitie mobilnej aplikácie

1. **Spustenie aplikácie:**
   - Aplikácia sa automaticky pripojí na server
   - Zadajte IP adresu servera pri prvom spustení

2. **Prihlásenie:**
   - Použite rovnaké prihlasovacie údaje ako vo webovom rozhraní
   - Podporuje 2FA autentifikáciu

3. **Native Android funkcie:**
   - Automatická detekcia témy (dark/light mode)
   - Optimalizovaný splash screen bez prebliknutí
   - Vlastná network-themed ikona aplikácie
   - Natívne Android WebView s lepšou výkonnosťou
   - Správne zobrazenie na všetkých Android verziách (7+)
   - Android 15 kompatibilita a optimalizácie

### Rozdiely oproti webovému rozhraniu

**Výhody Native Android aplikácie:**
- Rýchlejšie spustenie a lepšia výkonnosť
- Automatické prepínanie dark/light témy podľa systému
- Optimalizovaný splash screen pre hladké spúšťanie
- Vlastná network-themed ikona reprezentujúca sieťovú topológiu
- Eliminované biele blikania počas načítavania (Android 15 fix)
- Lepšia integrácia s Android systémom
- Natívne Android WebView namiesto browser wrappera

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
- ⚠️ **2FA sa nedá vypnúť** (je povinné pre všetky účty)

### Uloženie nastavení

1. **Automatické uloženie:** Zmeny sa ukladajú okamžite
2. **Validácia:** Systém kontroluje správnosť údajov
3. **Restart služieb:** Niektoré zmeny vyžadujú restart SNMP timers

---

## Bezpečnosť a 2FA

### Dvojfaktorová autentifikácia (2FA)

⚠️ **DÔLEŽITÉ UPOZORNENIE:**
- **2FA je povinné pre každý účet** (systém podporuje len jeden účet)
- **2FA sa nedá vypnúť po aktivácii**
- **Bez 2FA nie je možné používať aplikáciu**
- **Záložné kódy sú jediný spôsob obnovenia prístupu**

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

### Správa používateľského účtu

**Prístup k správe účtu:**
1. Prihláste sa do systému
2. V hornej časti kliknite na **"Upraviť"** vedľa vášho používateľského mena
3. Otvorí sa modálne okno s troma záložkami: **Používateľské meno**, **Heslo** a **2FA**

#### Zmena používateľského mena

**Kedy použiť:**
- Pri migrácii databázy medzi LXC kontajnermi
- Zmena identity administrátora
- Zjednotenie názvu účtu

**Postup zmeny:**
1. **Otvorte správu účtu:** Kliknite na "Upraviť" → záložka "Používateľské meno"
2. **Zadanie nových údajov:**
   - **Aktuálne meno** - Zobrazí sa automaticky (len na čítanie)
   - **Nové meno** - Zadajte nové používateľské meno (3-50 znakov)
   - **Potvrdenie hesla** - Zadajte vaše aktuálne heslo na overenie
3. **Validácia:**
   - Povolené znaky: písmená (a-z, A-Z), číslice (0-9), podčiarkovník (_), pomlčka (-)
   - Minimálne 3 znaky, maximálne 50 znakov
   - Nové meno nesmie už existovať v systéme
4. **Úspešná zmena:**
   - Používateľské meno sa okamžite aktualizuje
   - Zostanete prihlásení pod novým menom
   - Zobrazí sa potvrdzovacie hlásenie

#### Zmena hesla

**Postup zmeny:**
1. **Otvorte správu účtu:** Kliknite na "Upraviť" → záložka "Heslo"
2. **Zadanie hesiel:**
   - **Staré heslo** - Aktuálne heslo na overenie
   - **Nové heslo** - Nové heslo (minimálne 8 znakov)
   - **Potvrdenie** - Zopakujte nové heslo
3. **Úspešná zmena:**
   - Heslo sa okamžite aktualizuje
   - Zostanete prihlásení
   - Zobrazí sa potvrdzovacie hlásenie

#### Správa 2FA

**Prístup k 2FA nastaveniam:**
1. **Otvorte správu účtu:** Kliknite na "Upraviť" → záložka "2FA"
2. **Dostupné funkcie:**
   - Zobrazenie počtu zostávajúcich záložných kódov
   - Regenerovanie nových záložných kódov
   - Správa 2FA nastavení

**Praktické použitie pri LXC migrácii:**
```bash
# 1. Záloha databázy na starom LXC
cp /opt/mikrotik-manager/mikrotik_manager.db /root/backup.db

# 2. Inštalácia na novom LXC
bash install_in_lxc.sh

# 3. Kopírovanie databázy
cp /root/backup.db /opt/mikrotik-manager/mikrotik_manager.db
sudo chown mikrotik-manager:mikrotik-manager /opt/mikrotik-manager/mikrotik_manager.db

# 4. Reštart služby
sudo systemctl restart mikrotik-manager

# 5. Zmena používateľského mena cez webové rozhranie
# Prihláste sa → "Upraviť" → "Používateľské meno" → Zadajte nové meno
```

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

### Session Management a Cookie Persistence

#### Persistent SECRET_KEY

**Nové vylepšenie bezpečnosti:**
- Systém teraz používa **persistent SECRET_KEY** uložený v súbore
- Kľúč sa ukladá do `/var/lib/mikrotik-manager/data/secret.key`
- **Výhoda:** Sessions zostávajú platné aj po reštarte služby

**Predchádzajúci problém:**
```python
# STARÝ SYSTÉM (problematický):
app.config['SECRET_KEY'] = os.urandom(32)  # ❌ Nový kľúč pri každom reštarte
```

**Nové riešenie:**
```python
# NOVÝ SYSTÉM (bezpečný):
app.config['SECRET_KEY'] = get_or_create_secret_key()  # ✅ Persistent kľúč
```

#### Session Lifetime

**Nastavenie platnosti:**
- **Platnosť cookie:** 1 rok (365 dní)
- **Remember Me:** Automaticky zapnuté pre všetky prihlásenia
- **Persistent sessions:** Prežijú reštart služby aj zariadenia

#### Správanie v rôznych scenároch

**🖥️ Web Browser:**
```
✅ Prihlásenie → platné 1 rok
✅ Reštart služby → stále prihlásený
✅ Zatvorenie prehliadača → stále prihlásený
✅ Reštart počítača → stále prihlásený
❌ Vymazanie cookies → nový login potrebný
❌ Po 1 roku → nový login potrebný
```

**📱 Android APK:**
```
✅ Prihlásenie → platné 1 rok
✅ Reštart služby → stále prihlásený
✅ Zatvorenie aplikácie → stále prihlásený
✅ Reštart telefónu → stále prihlásený
❌ Vymazanie app dát → nový login potrebný
❌ Po 1 roku → nový login potrebný
```

#### Bezpečnostné aspekty

**Výhody persistent sessions:**
- Pohodlie pre používateľov (žiadne náhodné logoutovania)
- Stabilné fungovanie mobilnej aplikácie
- Predvídateľné správanie systému
- Žiadne interruption služieb pri maintenance

**Bezpečnostné opatrenia:**
- **2FA povinnosť** - Aj pri dlhých sessions je nutná 2FA
- **Silné heslá** - Požiadavka na kvalitné heslá
- **Automatické vypršanie** - Sessions sa invalidujú po 1 roku
- **Secure file permissions** - SECRET_KEY súbor má práva 600 (read/write owner only)

#### Technické detaily

**Súbory a umiestnenia:**
```bash
# SECRET_KEY storage
/var/lib/mikrotik-manager/data/secret.key

# Android WebView cookies
/data/data/com.mikrotik.manager/app_webview/Cookies
/data/data/com.mikrotik.manager/app_webview/Local Storage/

# Práva na SECRET_KEY súbor
chmod 600 /var/lib/mikrotik-manager/data/secret.key
```

**Cookie parametry:**
```python
# Session konfigurácia
PERMANENT_SESSION_LIFETIME = timedelta(days=365)  # 1 rok
SESSION_COOKIE_SECURE = True  # Len cez HTTPS
SESSION_COOKIE_HTTPONLY = False  # WebView compatibility
SESSION_COOKIE_SAMESITE = 'Lax'  # CSRF protection
```

#### Riešenie problémov s sessions

**Ak sa sessions invalidujú:**
1. Skontrolujte existenciu SECRET_KEY súboru
2. Overte práva na súbor (600)
3. Reštartujte službu pre vytvorenie nového kľúča

**Pre reset sessions (ak je potrebný):**
```bash
# Zastavenie služby
sudo systemctl stop mikrotik-manager

# Odstránenie SECRET_KEY (vytvorí sa nový)
sudo rm /var/lib/mikrotik-manager/data/secret.key

# Spustenie služby
sudo systemctl start mikrotik-manager
```

**Monitoring session aktivít:**
```bash
# Kontrola logov
sudo journalctl -u mikrotik-manager -f

# Sledovanie SECRET_KEY súboru
ls -la /var/lib/mikrotik-manager/data/secret.key
```

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

#### 6. Native Android APK aplikácia sa nepripojí

**Príznaky:**
- Connection timeout  
- SSL certificate errors
- Network unreachable
- Setup obrazovka sa nezobrazuje správne

**Riešenie:**
1. **Kontrola IP adresy servera v setup obrazovke**
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

**Q: Aké typy autentifikácie sú podporované?**

A: Aplikácia podporuje lokálne používateľské účty s možnosťou 2FA autentifikácie.

### Session Management a Prihlasovanie

**Q: Prečo ma vyhodilo po reštarte služby?**

A: V starších verziách sa SECRET_KEY generoval náhodne pri každom štarte. **Nová verzia** používa persistent SECRET_KEY, takže sessions zostávajú platné aj po reštarte.

**Q: Ako dlho zostávam prihlásený?**

A: Sessions majú platnosť **1 rok** a prežijú:
- Reštart služby ✅
- Zatvorenie prehliadača/APK ✅  
- Reštart počítača/telefónu ✅
- Invalidujú sa len po 1 roku alebo manuálnom logoute ❌

**Q: Prečo sa mobilná aplikácia nepamätá login?**

A: V novej verzii je implementovaný pokročilý cookie persistence systém pre Android WebView. Ak stále nefunguje:
1. Vymaž dáta aplikácie v nastaveniach Android
2. Prihláš sa znovu
3. APK si už bude pamätať login

**Q: Je 1-ročná session bezpečná?**

A: Áno, pri správnej konfigurácii:
- Požaduje sa 2FA ✅
- Silné heslá sú povinné ✅  
- SECRET_KEY je chránený (chmod 600) ✅
- HTTPS komunikácia odporúčaná ✅

**Q: Môžem zmeniť dĺžku session?**

A: Áno, v súbore `app.py`:
```python
# Pre kratšie sessions (napr. 24 hodín):
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=24)

# Pre dlhšie sessions (napr. 2 roky):
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=730)
```

**Q: Kde sa ukladá SECRET_KEY?**

A: V súbore `/var/lib/mikrotik-manager/data/secret.key` s právami 600 (len owner read/write).

**Q: Ako resetovať všetky sessions?**

A: Odstráň SECRET_KEY súbor a reštartuj službu:
```bash
sudo systemctl stop mikrotik-manager
sudo rm /var/lib/mikrotik-manager/data/secret.key
sudo systemctl start mikrotik-manager
```

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

**Štandardný nginx:**
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
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_redirect off;
    }
}
```

**Nginx Proxy Manager - Custom headers:**
```
proxy_set_header Upgrade $http_upgrade;
proxy_set_header Connection "upgrade";
proxy_set_header X-Forwarded-Proto $scheme;
proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
proxy_set_header Host $host;
proxy_redirect off;
```

### Mobilná aplikácia

**Q: Aké mobilné platformy sú podporované?**

A: Momentálne je dostupná Native Android APK aplikácia s Kotlin WebView.

**Q: Ako aktualizovať mobilnú aplikáciu?**

A: Regenerovať APK cez `bash build-apk.sh` a preinštalovať. Dáta sa uchovávajú na serveri.

**Q: Aký je rozdiel medzi Native Android APK a webovým rozhraním?**

A: Native Android APK poskytuje lepšiu výkonnosť, automatickú detekciu témy a optimalizovaný status bar handling pre Android.

**Q: Funguje aplikácia offline?**

A: Čiastočne - zobrazuje posledné známe dáta, ale vyžaduje pripojenie pre aktuálne informácie.

### Podpora a vývoj

**Q: Aké sú plánované funkcie?**

A: Roadmapa vývoja zahŕňa:
- Dashboard customization
- API pre tretie strany
- Rozšírenie SNMP monitoring
- Scheduled reports
- Performance optimizations

---

## Záver

MikroTik Manager je komplexné riešenie pre správu MikroTik infraštruktúry. Kombinuje jednoduché používanie s pokročilými funkciami monitoringu a automatizácie.

### Kľúčové výhody:

- **Centralizovaná správa** viacerých zariadení
- **Automatické zálohovanie** s flexible scheduling
- **Real-time monitoring** s grafickými reportmi
- **Mobilný prístup** cez Android aplikáciu
- **Bezpečnostné funkcie** s 2FA podporou
- **Profesionálne riešenie** s aktívnym vývojom

### Ďalšie kroky:

1. **Inštalácia** podľa tohto manuálu
2. **Konfigurácia** základných nastavení
3. **Pridanie zariadení** do správy
4. **Nastavenie monitoringu** a notifikácií
5. **Pravidelné zálohovanie** kritických konfigurácií

---

*Manuál pre MikroTik Manager*
