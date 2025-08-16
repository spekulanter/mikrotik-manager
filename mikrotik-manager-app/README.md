# MikroTik Manager - Android App

Toto je Apache Cordova projekt pre Android aplikáciu MikroTik Manager.

## Funkcionalita

- **Jednoduchá konfigurácia**: Pri prvom spustení zadáte URL vášho MikroTik Manager servera
- **WebView prístup**: Aplikácia načíta vašu webovú aplikáciu v plnohodnotnom WebView
- **Offline ukladanie**: URL servera sa uloží pre ďalšie použitie
- **Android Back button**: Podporuje návrat a zatvorenie aplikácie
- **Responzívny dizajn**: Optimalizované pre mobilné zariadenia

## Ako vytvoriť APK

### Metóda 1: Lokálne (vyžaduje Android Studio)

1. Nainštalujte Android Studio a Cordova:
```bash
npm install -g cordova
```

2. Pridajte Android platform:
```bash
cordova platform add android
```

3. Vytvorte APK:
```bash
cordova build android --release
```

### Metóda 2: Online Build Service

1. Nahrajte projekt na [PhoneGap Build](https://build.phonegap.com/)
2. Alebo použite [Monaca](https://monaca.io/)
3. Alebo [Ionic Appflow](https://ionicframework.com/appflow)

### Metóda 3: Použiť priložený build script

```bash
./build-apk.sh
```

## Štruktúra projektu

```
mikrotik-manager-app/
 www/
   └── index.html          # Hlavná aplikácia
 config.xml              # Cordova konfigurácia
 build-apk.sh            # Build script
 README.md               # Tento súbor
```

## Konfigurácia

### V aplikácii:
- Pri prvom spustení zadajte URL vášho servera (napr. `https://mikrotik.example.com:5000`)
- URL sa uloží a bude použitá pri ďalších spusteniach

### V config.xml:
- Zmeňte `widget id` pre vlastn package name
- Upravte `name` a `description` podľa potreby
- Nastavte vlastné ikony v `res/` prieinku

## Používanie

1. Nainštalujte APK na Android zariadenie
2. Spustite aplikáciu
3. Zadajte URL vášho MikroTik Manager servera
4. Aplikácia sa pripojí a zobrazí webové rozhranie
5. Všetky funkcie webovej aplikácie budú dostupné

## Bezpečnosť

- Aplikácia podporuje HTTP aj HTTPS
- Pre produkčné použitie odporúčame HTTPS
- Self-signed certifikáty môžu vyžadovať dodatočnú konfiguráciu

## Podpora

- Android 5.1+ (API level 22+)
- Všetky rozlíšenia obrazovky
- Portrait aj landscape orientácia

## Prispôsobenie

Môžete upraviť:
- Farby a vzhľad v `www/index.html` (CSS sekcia)
- App ikony v `res/icon/` priečinku  
- Splash screen v `res/splash/` priečinku
- Názov a popis v `config.xml`

## Testovanie

Pre testovanie v prehliadači otvorte `www/index.html` - všetky funkcie okrem Cordova API budú fungovať.
