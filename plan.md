# Plan: Záloha pred aktualizáciou (Backup Before Update)

## Kontext

Pred aktualizáciou MikroTik zariadenia (Update MikroTik, Update RouterOS, Upgrade Firmware) sa momentálne nekontroluje, či existuje aktuálna záloha konfigurácie. Cieľom je pridať automatický krok zálohovania **pred** každým aktualizačným procesom, ktorý využije existujúcu zálohovaciu logiku (`run_backup_logic()` v app.py). Zálohovač sám rozhodne, či zálohu vykoná (zmenená konfigurácia) alebo preskočí (bez zmien). Ak záloha zlyhá, aktualizácia sa nespustí.

**Kľúčová požiadavka:** Aktualizátor NESMIE mať vlastnú zálohovaciu logiku. Vždy sa volá existujúci `run_backup_logic()`, ktorý je plne funkčný a vie sám rozhodnúť, či má zálohu vytvoriť alebo preskočiť.

---

## Súbory na úpravu

1. `/opt/mikrotik-manager/app.py` — backend logika
2. `/opt/mikrotik-manager/updater.html` — frontend inline progress UI
3. `/opt/mikrotik-manager/settings.html` — nový toggle v nastaveniach

---

## Detailný implementačný plán

### 1. app.py — Nový boolean setting

**Riadok ~55-62** — Pridať do `BOOLEAN_SETTING_KEYS`:

```python
BOOLEAN_SETTING_KEYS = {
    ...existujúce položky...,
    'updater_backup_before_update'    # ← PRIDAŤ
}
```

**Riadok ~64 (`SETTING_LABELS`)** — Pridať:

```python
'updater_backup_before_update': 'Záloha pred aktualizáciou',
```

**Riadok ~183 (`DEFAULT_SETTING_VALUES`)** — Pridať:

```python
'updater_backup_before_update': 'true',
```

---

### 2. app.py — Rozšíriť `run_backup_logic()` o `status` v `result_holder`

Funkcia je na **riadku 1054**. Má parameter `result_holder` (dict). Pridať doň kľúč `'status'` na 3 miestach:

**a) Riadok ~1116** — skip (žiadne zmeny v konfigurácii):
```python
# PO riadku: socketio.emit('backup_status', {'ip': ip, 'id': device['id'], 'status': 'skipped'})
# PRIDAŤ:
if result_holder is not None:
    result_holder['status'] = 'skipped'
```

**b) Riadok ~1182** — success (záloha vytvorená):
```python
# PO riadku: socketio.emit('backup_status', {'ip': ip, 'id': device['id'], 'status': 'success', ...})
# PRIDAŤ:
if result_holder is not None:
    result_holder['status'] = 'success'
```

**c) Riadok ~1217** — error (záloha zlyhala):
```python
# PO riadku: socketio.emit('backup_status', {'ip': ip, 'id': device['id'], 'status': 'error', ...})
# PRIDAŤ:
if result_holder is not None:
    result_holder['status'] = 'error'
```

Toto je spätne kompatibilné — existujúci kód kľúč `'status'` v result_holder nekontroluje.

---

### 3. app.py — Nová helper funkcia `_run_backup_before_update()`

Umiestniť **pred** funkciu `run_device_update` (riadok ~4628).

```python
def _run_backup_before_update(device_id, device_ip, device_name, _emit, _step_done, _fail):
    """
    Krok 1 aktualizácie: Záloha konfigurácie pred update.
    Volá existujúci run_backup_logic() synchronne.
    Vracia True ak má update pokračovať, False ak zlyhal/má sa zrušiť.
    """
    # Skontroluj setting
    with get_db_connection() as conn:
        settings = {r['key']: r['value'] for r in conn.execute('SELECT key, value FROM settings').fetchall()}

    enabled = settings.get('updater_backup_before_update', 'true').lower() == 'true'

    if not enabled:
        add_log('info', f'Záloha pred update [{device_name}]: preskočená (vypnuté v nastaveniach)', device_ip)
        _step_done(1)
        return True

    _emit('step_active', step=1, msg='Vytváram zálohu konfigurácie...')

    # Počkaj ak už beží záloha pre toto zariadenie (max 300s)
    waited = 0
    while device_ip in backup_tasks and waited < 300:
        time.sleep(5)
        waited += 5
    if device_ip in backup_tasks:
        _emit('step_error', step=1)
        _fail('Záloha pre toto zariadenie už prebieha príliš dlho (timeout 300s)')
        return False

    # Načítaj zariadenie z DB
    with get_db_connection() as conn:
        device = conn.execute('SELECT * FROM devices WHERE id = ?', (device_id,)).fetchone()
    if not device:
        _emit('step_error', step=1)
        _fail('Zariadenie nenájdené v databáze')
        return False

    # Spusti zálohu synchronne (run_backup_logic v finally bloku vymaže backup_tasks[ip])
    backup_tasks[device_ip] = True
    result_holder = {'backup_performed': False, 'ftp_uploaded': False, 'status': None}

    try:
        run_backup_logic(dict(device), is_sequential=True, result_holder=result_holder)
    except Exception as e:
        _emit('step_error', step=1)
        _fail(f'Záloha zlyhala s výnimkou: {e}')
        return False

    status = result_holder.get('status')

    if status == 'error':
        _emit('step_error', step=1)
        _fail('Záloha konfigurácie zlyhala — aktualizácia zrušená')
        return False
    elif status == 'skipped':
        add_log('info', f'Záloha pred update [{device_name}]: žiadne zmeny v konfigurácii', device_ip)
        _step_done(1)
        return True
    elif status == 'success':
        add_log('info', f'Záloha pred update [{device_name}]: záloha vytvorená', device_ip)
        _step_done(1)
        return True
    else:
        # Neočakávaný stav — pokračuj opatrne
        add_log('warning', f'Záloha pred update [{device_name}]: neznámy status ({status})', device_ip)
        _step_done(1)
        return True
```

---

### 4. app.py — Upraviť `run_device_update()` (riadok 4628, full 7-step update)

**a) Vložiť volanie backup helpera** — po riadku 4698 (`_emit('start', msg=f'Manuálny update: {device_name}')`), pred riadkom 4700 (VM pre-check):

```python
# NOVÉ — Krok 1: Záloha
if not _run_backup_before_update(device_id, device_ip, device_name, _emit, _step_done, _fail):
    return
```

**b) Prečíslovať VŠETKY existujúce kroky +1:**

Každý výskyt `step=1` → `step=2`, `step=2` → `step=3`, ... `step=7` → `step=8`.
Rovnako `_step_done(1)` → `_step_done(2)`, `_step_done(2)` → `_step_done(3)`, atď.

Prehľad prečíslovania:
| Pôvodný krok | Nový krok | Popis |
|---|---|---|
| (nový) | 1 | Záloha konfigurácie |
| 1 | 2 | Check/install RouterOS |
| 2 | 3 | Wait offline |
| 3 | 4 | Wait online |
| 4 | 5 | Stabilization delay |
| 5 | 6 | Check/install Firmware |
| 6 | 7 | Pre-reboot delay |
| 7 | 8 | Final reboot + wait online |

---

### 5. app.py — Upraviť `run_scheduled_update()` (riadok 4339)

Úplne rovnaká logika ako bod 4:

**a)** Vložiť backup volanie po riadku 4420 (`_emit('start', msg=f'Naplánovaný update: {device_name}')`), pred riadkom 4422 (VM pre-check).

**b)** Prečíslovať všetky kroky +1 (rovnaká tabuľka ako bod 4).

---

### 6. app.py — Upraviť `run_device_update_os()` (riadok 4860, OS-only)

**a)** Vložiť backup volanie po `_emit('start', ...)`:

```python
if not _run_backup_before_update(device_id, device_ip, device_name, _emit, _step_done, _fail):
    return
```

**b)** Prečíslovať kroky:
| Pôvodný | Nový | Popis |
|---|---|---|
| (nový) | 1 | Záloha |
| 1 | 2 | Check/install RouterOS |
| 2 | 3 | Wait offline |
| 3 | 4 | Wait online |

---

### 7. app.py — Upraviť `run_device_update_firmware()` (riadok 5000, FW-only)

**a)** Vložiť backup volanie po `_emit('start', ...)`.

**b)** Prečíslovať kroky:
| Pôvodný | Nový | Popis |
|---|---|---|
| (nový) | 1 | Záloha |
| 1 | 2 | Check/install Firmware |
| 2 | 3 | Pre-reboot delay |
| 3 | 4 | Final reboot |

---

### 8. updater.html — Aktualizovať STEP_LABELS (riadok 2700)

```javascript
// PÔVODNÉ:
let STEP_LABELS = ['', 'Update RouterOS', 'Čakám na reštart', 'Čakám na boot',
    `${_updaterStabilizationDelay}s pauza`, 'Update Firmware',
    `${_updaterPreRebootDelay}s pauza`, 'Finálny reštart'];

// NOVÉ:
let STEP_LABELS = ['', 'Záloha', 'Update RouterOS', 'Čakám na reštart', 'Čakám na boot',
    `${_updaterStabilizationDelay}s pauza`, 'Update Firmware',
    `${_updaterPreRebootDelay}s pauza`, 'Finálny reštart'];
```

---

### 9. updater.html — Aktualizovať `startInlineUpdate()` (riadok 2703)

V tejto funkcii sa nastavuje `stepLabels` a `stepCount` podľa `updateType`:

```javascript
function startInlineUpdate(id, updateType) {
    updateType = updateType || 'full';

    let stepLabels, stepCount;
    if (updateType === 'os') {
        // PÔVODNÉ: stepLabels = ['', 'Update RouterOS', 'Čakám na reštart', 'Čakám na boot'];
        // PÔVODNÉ: stepCount = 3;
        // NOVÉ:
        stepLabels = ['', 'Záloha', 'Update RouterOS', 'Čakám na reštart', 'Čakám na boot'];
        stepCount = 4;
    } else if (updateType === 'firmware') {
        const delay = _updaterPreRebootDelay || 20;
        // PÔVODNÉ: stepLabels = ['', 'Update Firmware', `${delay}s pauza`, 'Finálny reštart'];
        // PÔVODNÉ: stepCount = 3;
        // NOVÉ:
        stepLabels = ['', 'Záloha', 'Update Firmware', `${delay}s pauza`, 'Finálny reštart'];
        stepCount = 4;
    } else {
        stepLabels = STEP_LABELS;
        // PÔVODNÉ: stepCount = 7;
        // NOVÉ:
        stepCount = 8;
    }
    // ... zvyšok funkcie bez zmien
}
```

---

### 10. updater.html — Aktualizovať dynamické indexy delay labels

Niekde v `_loadBulkDelay()` alebo obdobnej funkcii sa dynamicky menia STEP_LABELS indexy pre stabilization a pre-reboot delay. Tieto indexy treba posunúť o +1:

```javascript
// PÔVODNÉ:
STEP_LABELS[4] = `${_updaterStabilizationDelay}s pauza`;
STEP_LABELS[6] = `${_updaterPreRebootDelay}s pauza`;

// NOVÉ:
STEP_LABELS[5] = `${_updaterStabilizationDelay}s pauza`;
STEP_LABELS[7] = `${_updaterPreRebootDelay}s pauza`;
```

**POZOR:** Vyhľadaj všetky výskyty `STEP_LABELS[4]` a `STEP_LABELS[6]` v celom updater.html a zmeň na `STEP_LABELS[5]` resp. `STEP_LABELS[7]`.

---

### 11. settings.html — Nový toggle v sekcii "Mikrotik Aktualizátor"

**Riadok ~991** — PRED existujúcim `<!-- Hromadná aktualizácia -->` (riadok 992) vložiť novú podsekciu:

```html
<!-- Záloha pred aktualizáciou -->
<div class="mb-8">
    <h3 class="text-lg font-semibold text-emerald-400 mb-4">
        <i class="fas fa-shield-alt mr-2"></i>Bezpečnostná záloha
    </h3>
    <div class="flex items-center justify-between p-4 bg-gray-800/50 rounded-lg border border-gray-700">
        <div>
            <label for="updater_backup_before_update" class="font-medium cursor-pointer">
                Záloha pred aktualizáciou
            </label>
            <small class="text-gray-400 block mt-1">
                Automaticky vytvoriť zálohu konfigurácie pred každou aktualizáciou.
                Ak záloha zlyhá, aktualizácia sa nespustí. Ak neboli žiadne zmeny v konfigurácii,
                záloha sa preskočí a aktualizácia pokračuje.
            </small>
        </div>
        <label class="toggle-switch ml-4">
            <input type="checkbox" id="updater_backup_before_update"
                   name="updater_backup_before_update">
            <span class="toggle-slider"></span>
        </label>
    </div>
</div>
```

**Poznámka:** Existujúci JavaScript v settings.html už genericky handluje boolean settings (checkbox → `true`/`false` pri save, checkbox checked pri load). Žiadna ďalšia JS zmena v settings.html nie je potrebná.

---

## Prehľad nových krokov

| Krok | Full update (8) | OS-only (4) | FW-only (4) | Scheduled (8) |
|------|----------------|-------------|-------------|----------------|
| 1 | **Záloha** | **Záloha** | **Záloha** | **Záloha** |
| 2 | Update RouterOS | Update RouterOS | Update Firmware | Update RouterOS |
| 3 | Čakám na reštart | Čakám na reštart | Pauza | Čakám na reštart |
| 4 | Čakám na boot | Čakám na boot | Finálny reštart | Čakám na boot |
| 5 | Stabilizačná pauza | — | — | Stabilizačná pauza |
| 6 | Update Firmware | — | — | Update Firmware |
| 7 | Pauza pred reštartom | — | — | Pauza pred reštartom |
| 8 | Finálny reštart | — | — | Finálny reštart |

---

## Edge cases

- **Low-memory zariadenie (16MB):** Záloha môže trvať 3+ min (180s export wait). Update thread je daemon bez timeout — OK.
- **Už beží záloha:** Helper čaká max 300s na uvoľnenie `backup_tasks[ip]`, potom failne.
- **Bulk update:** `run_manual_bulk_update()` volá `run_device_update()` per zariadenie — každé dostane svoju zálohu automaticky.
- **Setting vypnuté:** Step 1 sa ihneď označí ako done, update pokračuje.
- **Záloha preskočená (žiadne zmeny):** Toto NIE JE chyba — update pokračuje normálne.
- **F5 recovery:** Backend posiela nové čísla krokov, frontend `restoreRunningUpdates()` ich správne zobrazí.

---

## Dôležité technické detaily

### Ako funguje `run_backup_logic()` (riadok 1054 v app.py)

```python
def run_backup_logic(device, is_sequential=False, result_holder=None):
```

- `device` = dict s kľúčmi: id, ip, username, password (šifrované Fernet), name, low_memory
- `is_sequential` = True pre sekvenčné/batch operácie
- `result_holder` = dict, po skončení obsahuje: `backup_performed` (bool), `ftp_uploaded` (bool), `status` (nový: 'success'/'skipped'/'error')
- Funkcia emituje SocketIO event `backup_status` s payload `{ip, id, status}`
- V `finally` bloku (riadok 1232-1235) vždy: aktualizuje result_holder, zavrie SSH, vymaže `backup_tasks[ip]`
- **Caller MUSÍ** pred volaním nastaviť `backup_tasks[device_ip] = True`

### Ako fungujú `_emit` a `_step_done` v update funkciách

Každá update funkcia (`run_device_update`, `run_scheduled_update`, atď.) definuje lokálne closures:

```python
def _emit(state, step=0, msg=''):
    # Aktualizuje tracking dict + emituje SocketIO 'scheduled_update_progress'
    socketio.emit('scheduled_update_progress', {
        'device_id': device_id,
        'schedule_id': 0,  # 0 pre manuálne, >0 pre scheduled
        'state': state,    # 'start', 'step_active', 'step_done', 'step_error', 'done', 'failed'
        'step': step,
        'msg': msg,
        'update_type': 'full'  # alebo 'os' / 'firmware'
    })

def _step_done(step_num):
    # Pridá step do steps_done listu + volá _emit('step_done', step=step_num)

def _fail(msg):
    # Zaloguje chybu + volá _emit('failed', msg=msg) + cleanup
```

Helper `_run_backup_before_update()` prijíma tieto callbacks ako parametre, čím sa vyhne duplicite kódu.

---

## Verifikácia po implementácii

1. `systemctl restart mikrotik-manager`
2. Settings → Mikrotik Aktualizátor → toggle "Záloha pred aktualizáciou" musí byť viditeľný a default zapnutý
3. Updater → spustiť "Update MikroTik" → inline UI musí mať 8 krokov, prvý = "Záloha"
4. Updater → dropdown → "Update RouterOS" → 4 kroky, prvý = "Záloha"
5. Updater → dropdown → "Upgrade Firmware" → 4 kroky, prvý = "Záloha"
6. Ak konfigurácia nebola zmenená → krok Záloha sa dokončí s "žiadne zmeny", update pokračuje
7. Vypnúť toggle v Settings → krok Záloha sa ihneď preskočí
8. Počas behu update stlačiť F5 → inline UI sa obnoví so správnym počtom krokov
9. Vybrať 2+ zariadenia → bulk update → každé musí mať svoju zálohu
