# MikroTik Manager - Claude AI Guide

## Project Overview

**MikroTik Manager** is a comprehensive web-based management system for MikroTik RouterOS devices. It provides centralized device management, automated backups, real-time monitoring, and remote access through both web interface and native Android application.

### Key Features
- **Device Management**: Centralized management of multiple MikroTik RouterOS devices
- **Automated Backups**: Scheduled backup creation with FTP upload support
- **Real-time Monitoring**: ICMP ping and SNMP-based monitoring with historical graphs
- **Security**: Mandatory 2FA authentication, hashed app-user password storage, encrypted device/settings secrets (Fernet)
- **Mobile Support**: Native Android APK with Kotlin WebView
- **Notifications**: Pushover notifications for availability, backup, SNMP thresholds, and auth security events

### Technology Stack
- **Backend**: Python 3.11, Flask, Flask-SocketIO, Eventlet
- **Frontend**: HTML, JavaScript (vanilla), Chart.js for graphs
- **Database**: SQLite3 with encrypted secret fields (device SSH password + selected settings)
- **Authentication**: Flask-Login, PyOTP (TOTP), Werkzeug password hashing
- **Networking**: Paramiko (SSH), PySNMP, Python FTP
- **Encryption**: Cryptography (Fernet), Werkzeug password hashing
- **Mobile**: Android (Kotlin), WebView-based native app

## Project Structure

```
/opt/mikrotik-manager/
├── app.py                          # Main Flask application (200+ KB)
├── requirements.txt                # Python dependencies
├── *.html                          # Jinja2 templates (index, monitoring, backups, settings, login, etc.)
├── static/
│   └── js/                         # Frontend JavaScript files
├── template/                       # Android APK template files
│   ├── MainActivity.kt             # Android main activity
│   ├── SetupActivity.kt            # Android setup screen
│   ├── AndroidManifest.xml         # Android manifest
│   └── res/                        # Android resources
├── venv/                           # Python virtual environment
├── build-apk.sh                    # Android APK build script
├── install-mikrotik-manager.sh     # Installation script
├── update.sh                       # Update script
├── README.md                       # Installation guide
└── manual.md                       # Comprehensive user manual (1600+ lines)

/var/lib/mikrotik-manager/data/     # Runtime data directory
├── mikrotik_manager.db             # SQLite database
├── secret.key                      # Flask session SECRET_KEY (32 bytes, chmod 600)
├── encryption.key                  # Fernet encryption key (44 bytes, chmod 600)
└── backups/                        # Backup files organized by IP
    └── 192.168.1.1/
        ├── backup_*.backup         # MikroTik binary backups
        └── export_*.rsc            # MikroTik config exports
```

## Architecture

### Application Components

**Flask Application (app.py)**
- Single-file monolithic architecture (~6000 lines)
- SocketIO for real-time communication with frontend
- Background thread pools for SNMP and ping monitoring
- Scheduled backup jobs using `schedule` library

**Authentication System**
- Flask-Login for session management
- Mandatory 2FA (PyOTP TOTP) for all accounts
- Single-user system (one account per installation)
- Backup codes for 2FA recovery (10 codes, single-use)
- Persistent SECRET_KEY with 1-year session lifetime

**Monitoring System**
1. **Ping Monitor**: Background thread with configurable intervals
2. **SNMP Health Check**: Scheduled SNMP data collection
3. **Database Storage**: Historical ping/SNMP data in SQLite

### Database Schema

**SQLite Database: `mikrotik_manager.db`**

```sql
-- Device configuration
CREATE TABLE devices (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip TEXT UNIQUE NOT NULL,
    name TEXT NOT NULL,
    username TEXT NOT NULL,
    password TEXT NOT NULL,              -- Encrypted with Fernet (device SSH password)
    low_memory BOOLEAN DEFAULT 0,
    snmp_community TEXT DEFAULT 'public', -- Encrypted with Fernet
    status TEXT DEFAULT 'unknown',
    last_backup TIMESTAMP,
    last_snmp_data TEXT,                 -- JSON blob
    snmp_interval_minutes INTEGER DEFAULT 0,
    last_snmp_check TIMESTAMP,
    ping_interval_seconds INTEGER DEFAULT 0,
    monitoring_paused BOOLEAN DEFAULT 0
);

-- User accounts (single-user system)
CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,              -- Werkzeug password hash (generate_password_hash)
    totp_secret TEXT,                    -- Encrypted with Fernet
    totp_enabled BOOLEAN NOT NULL DEFAULT 0
);

-- 2FA backup codes
CREATE TABLE backup_codes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    code TEXT NOT NULL,                  -- Werkzeug password hash
    created_at TIMESTAMP NOT NULL,
    used BOOLEAN NOT NULL DEFAULT 0,
    used_at TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users (id)
);

-- Password recovery tokens (one-time)
CREATE TABLE password_recovery_tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    token_hash TEXT NOT NULL,            -- Werkzeug password hash
    created_at TIMESTAMP NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    used BOOLEAN NOT NULL DEFAULT 0,
    used_at TIMESTAMP,
    request_ip TEXT,
    FOREIGN KEY (user_id) REFERENCES users (id)
);

-- Ping monitoring history
CREATE TABLE ping_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id INTEGER NOT NULL,
    timestamp DATETIME NOT NULL,
    avg_latency REAL,
    packet_loss INTEGER NOT NULL DEFAULT 0,
    status TEXT NOT NULL,
    FOREIGN KEY (device_id) REFERENCES devices (id)
);

-- SNMP monitoring history
CREATE TABLE snmp_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id INTEGER NOT NULL,
    timestamp DATETIME NOT NULL,
    cpu_load INTEGER,
    temperature INTEGER,
    memory_usage INTEGER,
    uptime INTEGER,
    total_memory INTEGER,
    free_memory INTEGER,
    FOREIGN KEY (device_id) REFERENCES devices (id)
);

-- Activity logs
CREATE TABLE logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp DATETIME NOT NULL,
    level TEXT NOT NULL,                 -- info/warning/error
    message TEXT NOT NULL,
    device_ip TEXT DEFAULT NULL
);

-- System settings (key-value store)
CREATE TABLE settings (
    key TEXT PRIMARY KEY,
    value TEXT
);
```

## Security Implementation

### Encryption & Hashing

**Secrets Encryption (Fernet)**
```python
# Encryption key: /var/lib/mikrotik-manager/data/encryption.key
# - 44 bytes (Fernet key, urlsafe base64)
# - chmod 600 (owner read/write only)
# - Used for:
#   - devices.password (SSH password)
#   - devices.snmp_community
#   - users.totp_secret
#   - settings keys in SENSITIVE_SETTINGS
#     ('ftp_password', 'pushover_app_key', 'pushover_user_key')

def encrypt_password(password):
    return b64.b64encode(cipher.encrypt(password.encode())).decode()

def decrypt_password(encrypted_password):
    return cipher.decrypt(b64.b64decode(encrypted_password.encode())).decode()
```

**Sensitive Settings**
```python
SENSITIVE_SETTINGS = {'ftp_password', 'pushover_app_key', 'pushover_user_key'}
```

**User Password Hashing (Werkzeug)**
```python
from werkzeug.security import generate_password_hash, check_password_hash

# Stored in users.password column
password_hash = generate_password_hash(password)
```

**Backup Code Hashing (Werkzeug)**
```python
# backup_codes.code is stored as hash
backup_code_hash = generate_password_hash(backup_code)
check_password_hash(backup_code_hash, backup_code)
```

**Session Management**
```python
# Persistent SECRET_KEY: /var/lib/mikrotik-manager/data/secret.key
# - 32 bytes random key
# - chmod 600
# - Session lifetime: 365 days
# - Survives service restarts

app.config['SECRET_KEY'] = get_or_create_secret_key()
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=365)
```

### 2FA (Two-Factor Authentication)

**Implementation**
- TOTP (Time-based One-Time Password) using PyOTP
- QR code generation for authenticator apps
- 10 single-use backup codes per user (stored hashed)
- Password recovery via one-time Pushover code + backup code verification
- Mandatory for all accounts (cannot be disabled once activated)

**Supported Authenticator Apps**
- Google Authenticator
- Microsoft Authenticator
- Authy
- 1Password
- Bitwarden

## API Endpoints & Routes

### Authentication Routes
```python
@app.route('/register', methods=['GET', 'POST'])  # User registration (single user)
@app.route('/login', methods=['GET', 'POST'])     # Login with username/password
@app.route('/password-recovery', methods=['GET', 'POST']) # Recovery flow (Pushover code + backup code)
@app.route('/login/2fa', methods=['GET', 'POST']) # 2FA verification
@app.route('/setup_2fa', methods=['GET'])         # 2FA setup page
@app.route('/verify_2fa', methods=['POST'])       # 2FA activation
@app.route('/logout')                             # User logout
```

### Device Management
```python
@app.route('/api/devices', methods=['GET', 'POST'])       # List/create devices
@app.route('/api/devices/<id>', methods=['DELETE', 'PUT'])# Delete/update device
@app.route('/api/devices/<id>/backup', methods=['POST'])  # Trigger backup
@app.route('/api/devices/<id>/snmp', methods=['GET'])     # Get SNMP data
```

### Monitoring & Data
```python
@app.route('/api/monitoring/<device_id>/ping')    # Ping history data
@app.route('/api/monitoring/<device_id>/snmp')    # SNMP history data
@app.route('/api/monitoring/<device_id>/status')  # Current device status
```

### Settings & Configuration
```python
@app.route('/api/settings', methods=['GET', 'POST'])      # Get/update settings
@app.route('/api/user/change_password', methods=['POST']) # Change password
@app.route('/api/user/change_username', methods=['POST']) # Change username
@app.route('/api/user/backup_codes', methods=['GET', 'POST']) # Manage 2FA codes
@app.route('/api/user/disable_2fa', methods=['POST'])     # Disable 2FA
```

### Backups
```python
@app.route('/backups')                            # Backups page
@app.route('/api/backups')                        # List backup files
@app.route('/api/backups/<filename>')             # Download backup
@app.route('/api/backups/<filename>', methods=['DELETE']) # Delete backup
```

### SocketIO Events
```python
socketio.on('connect')                  # WebSocket connection
socketio.emit('log', data)              # Real-time log messages
socketio.emit('backup_status', data)    # Backup progress updates
socketio.emit('device_status', data)    # Device status changes
socketio.emit('snmp_update', data)      # SNMP data updates
```

## Key Functions & Logic

### Backup System

**Backup Process Flow**
```python
def run_backup_logic(device, is_sequential=False, result_holder=None):
    # 1. Establish SSH connection (Paramiko)
    # 2. Create .backup file on MikroTik: /system backup save
    # 3. Create .rsc export: /export file=export
    # 4. Download files via SSH/SFTP
    # 5. Save to /var/lib/mikrotik-manager/data/backups/{ip}/
    # 6. Upload to FTP (if configured)
    # 7. Cleanup old backups (retention policy)
    # 8. Send Pushover notification (if enabled)
```

**Backup Comparison (diff)**
```python
def compare_with_local_backup(ip, remote_content, detailed_logging=True):
    # Uses difflib.unified_diff to compare .rsc exports
    # Detects configuration changes between backups
    # Returns: (has_changes: bool, diff_lines: list)
```

### SNMP Monitoring

**SNMP OIDs**
```python
SNMP_OIDS = {
    'sysDescr': '1.3.6.1.2.1.1.1.0',
    'sysUpTime': '1.3.6.1.2.1.1.3.0',
    'sysName': '1.3.6.1.2.1.1.5.0',
    'cpuLoad': '1.3.6.1.2.1.25.3.3.1.2',
    'memTotal': '1.3.6.1.2.1.25.2.3.1.5',
    'memUsed': '1.3.6.1.2.1.25.2.3.1.6',
    'temperature': '1.3.6.1.4.1.14988.1.1.3.10.0',  # MikroTik specific
}

def get_snmp_data(ip, community='public'):
    # Timeout: 10 seconds
    # Retries: 2
    # Returns: dict with system info and metrics
```

**SNMP Health Check Thread**
```python
def snmp_health_check_thread():
    # Background thread running every N minutes (configurable)
    # Iterates through all devices with snmp_interval_minutes > 0
    # Stores results in snmp_history table
    # Triggers notifications on threshold breaches
```

### Ping Monitoring

**Ping Monitor Thread**
```python
def ping_monitor_thread():
    # Background thread running every N seconds (configurable)
    # Uses platform.system() to detect OS (Windows/Linux)
    # Parses ping output for latency and packet loss
    # Stores results in ping_history table
    # Triggers online/offline notifications
```

**Ping Logic**
```python
# Linux: ping -c 4 -W 5 {ip}
# Windows: ping -n 4 -w 5000 {ip}
# Parses: avg latency (ms), packet loss (%)
# Retry logic: 3 failed pings before marking offline
```

## Settings System

### Boolean Settings
```python
BOOLEAN_SETTING_KEYS = {
    'ping_monitor_enabled',
    'snmp_health_check_enabled',
    'backup_schedule_enabled',
    'backup_detailed_logging',
    'notify_backup_success',
    'notify_backup_failure',
    'notify_device_offline',
    'notify_device_online',
    'notify_temp_critical',
    'notify_cpu_critical',
    'notify_memory_critical',
    'notify_reboot_detected',
    'notify_version_change',
    'notify_failed_login',
    'notify_failed_2fa',
    'quiet_hours_enabled',
    'availability_monitoring_enabled',
    'debug_terminal'
}
```

### Important Settings
```python
# Backup settings
backup_retention_count: int = 10           # Number of backups to keep
backup_delay_seconds: int = 30             # Delay between device backups
backup_schedule_enabled: bool = False
backup_schedule_type: str = 'daily'        # daily/weekly/custom
backup_schedule_time: str = '02:00'        # HH:MM format

# SNMP settings
snmp_check_interval_minutes: int = 10      # Global SNMP interval
snmp_health_check_enabled: bool = True
snmp_retention_days: int = 30
# snmp_community is per-device in devices table (encrypted)

# Ping settings
ping_monitor_enabled: bool = True
ping_heartbeat_interval: int = 30          # seconds
ping_retention_days: int = 30
ping_timeout: int = 5                      # seconds
ping_retries: int = 3

# Notification thresholds
cpu_critical_threshold: int = 80           # %
memory_critical_threshold: int = 80        # %
temp_critical_threshold: int = 70          # °C

# FTP upload
ftp_server: str = ''
ftp_port: int = 21
ftp_username: str = ''
ftp_password: str = ''                     # Encrypted
ftp_directory: str = '/'

# Pushover notifications
pushover_app_key: str = ''                 # Encrypted (SENSITIVE_SETTINGS)
pushover_user_key: str = ''                # Encrypted (SENSITIVE_SETTINGS)
```

## Monitoring System - Frontend & Charts

The monitoring system is the most complex frontend component with ~8000 lines of code (monitoring.html + monitoring.js). It provides real-time device monitoring with interactive charts, custom zoom functionality, and comprehensive SNMP/ping visualization.

### Overview

**Files:**
- `monitoring.html` - ~4200 lines (HTML, embedded CSS, embedded JavaScript for zoom)
- `static/js/monitoring.js` - ~3800 lines (main monitoring logic)

**Key Features:**
- Real-time ping latency monitoring with offline detection
- SNMP metrics (CPU, Temperature, Memory) with historical graphs
- Custom zoom system (drag-to-zoom-in, progressive zoom-out)
- Optimized data loading (partial + full load strategy)
- Duration-based uptime calculation (not just sample count)
- Intelligent Y-axis optimization (Uptime Kuma-inspired)
- Dark/Light theme support with instant switching
- Advanced mobile optimizations
- WebSocket real-time updates
- Per-device monitoring intervals
- Pause/resume monitoring

### monitoring.html Structure

#### Head Section (Lines 1-1275)

**CDN Dependencies:**
```html
<!-- CSS Framework -->
<script src="https://cdn.tailwindcss.com"></script>

<!-- Icons -->
<link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">

<!-- Real-time Communication -->
<script src="https://cdn.socket.io/4.4.1/socket.io.min.js"></script>

<!-- Charts & Date Handling -->
<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
<script src="https://cdn.jsdelivr.net/npm/date-fns@2.29.3/index.min.js"></script>
<script src="https://cdn.jsdelivr.net/npm/chartjs-adapter-date-fns@2.0.0/dist/chartjs-adapter-date-fns.bundle.min.js"></script>

<!-- Typography -->
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap">
```

**CSS Variables:**
```css
:root {
    --header-btn-height: 40px;
    --header-btn-font: 13px;
    --header-btn-pad-y: 6px;
    --header-btn-pad-x: 14px;
    --header-icon-font: 14px;
    --header-btn-strong-weight: 600;
}
```

**Theme System:**

*Dark Theme (Default):*
- Background: `#111827` to `#1f2937` gradient
- Cards: Gray-900/800 gradient with `#374151` borders
- Text: White/gray-400
- Ping online: `#10b981` (emerald-500)
- Ping offline: `#ef4444` (red-500)
- CPU: `#3b82f6` (blue-500)
- Temperature: `#ef4444` (red-500)
- Memory: `#ef4444` (used), `#3b82f6` (total)

*Light Theme (`.light-theme` class):*
- Background: `#cddbf2` (light blue)
- Cards: `#e4edfa` to `#d7e5f8` gradient
- Text: Dark gray (`#1f2937`)
- Accent: Sky blue (`#0369a1`)
- Ping online: `#0ea5a3` (teal-600)
- Ping offline: `#dc2626` (red-600)
- CPU: `#1d4ed8` (blue-700)
- Temperature: `#dc2626` (red-600)
- Memory: `#dc2626` (used), `#1d4ed8` (total)

**Key CSS Components:**
- **Ping Status Indicators**: Animated pulsing dots (12px diameter, 2s pulse animation)
- **Chart Containers**: 300px height, responsive width
- **Time Range Buttons**: Uptime Kuma-inspired pill-style with active states
- **Custom Dropdown**: Advanced device selector with smooth animations
- **Zoom Controls**: Overlay buttons (desktop) + inline (mobile)
- **Mobile Optimizations**: Chart shift left (-20px), right thumb zone (6px), gradient scroll indicators

#### Body Structure (Lines 1276-1602)

**Header Components (Lines 1279-1327):**

1. **App Title:**
   ```html
   <h1 class="text-xl font-semibold">
     <i class="fas fa-chart-line text-orange-500"></i>
     MikroTik Monitoring
   </h1>
   ```

2. **Custom Device Selector:**
   - Button-style dropdown with chevron icon
   - Shows: Status emoji + Device name (IP)
   - Status emojis: 🟢 Online, 🔴 Offline, ⚪ Unknown, ⏸️ Paused
   - Desktop: 320-600px width, max 600px height
   - Mobile: Full width, max 80vh height

3. **Time Range Controls (9 options):**
   - 30m, 3h, 6h, 12h, 24h, 7d, 30d, 90d, 1y
   - Default: 24h
   - Desktop: Horizontal row with flex wrap
   - Mobile: Horizontal scrollable with gradient fade indicators
   - Active button: Blue background, white text
   - Hover: Light blue background

4. **Action Buttons:**
   - **Refresh** (`#refreshBtn`): Manual data reload, triggers optimized load
   - **Settings**: Navigate to `/settings.html`
   - **Theme Toggle**: Switch light/dark mode (localStorage persistence)
   - **Back**: Return to home (`/`)

**Device Info Panel (Lines 1330-1394):**

*Header (Lines 1331-1347):*
- Device name (h2, weight: 700)
- Model info: Board name + RouterOS version
- Device IP (mobile only)
- **Pause/Resume Button**: Toggle `monitoring_paused` flag
- **Intervals Button**: Open device settings modal

*Status Cards (4-column grid, 2x2 on mobile):*

1. **Ping Status Card:**
   - Animated indicator dot (online: green pulsing, offline: red pulsing)
   - Status text: Online/Offline/Loading
   - WiFi icon (`fa-wifi`)

2. **Average Latency Card:**
   - Duration-weighted average (not simple mean)
   - Calculated from current time range data
   - Displayed in ms with 1 decimal
   - Stopwatch icon (`fa-stopwatch`)

3. **Uptime Card:**
   - Dynamic label: "Uptime (24h)", "Uptime (7d)", etc.
   - Percentage based on online duration vs total duration
   - Color-coded:
     - Green (≥95%): `text-green-500`
     - Yellow (≥80%): `text-yellow-500`
     - Red (<80%): `text-red-500`
   - Clock icon (`fa-clock`)

4. **Last Ping Card:**
   - Timestamp of most recent ping check
   - Slovak locale format: `dd.MM.yyyy HH:mm:ss`
   - Clock icon (`fa-history`)

**Charts Grid (Lines 1397-1497) - 2x2 layout (1 column on mobile):**

1. **Ping Latency Chart** (`#pingChart`):
   - Line chart with filled areas
   - Online segments: Green line with light green fill
   - Offline segments: Transparent bottom line + red filled area (shows offline "height")
   - Separate dataset for each continuous online/offline period
   - Shows packet loss in tooltip
   - Zoom controls: Overlay (desktop) + inline button (mobile)

2. **CPU Load Chart** (`#cpuChart`):
   - Single blue line chart
   - Y-axis: 0-100% (optimized based on actual usage)
   - Smart ceiling: If max ≤50%, show 0-50% instead of 0-100%
   - Icon: `fa-microchip text-blue-500`

3. **Temperature Chart** (`#temperatureChart`):
   - Single red line chart
   - Y-axis: Centered around actual temp range
   - If constant temp: ±5°C padding
   - Icon: `fa-thermometer-half text-red-500`

4. **Memory Usage Chart** (`#memoryChart`):
   - Two datasets:
     - Used Memory (red, filled)
     - Total Memory (blue, filled)
   - Total Memory uses forward-fill (prevents truncation when not reported)
   - Tooltip shows: Used, Total, Free, Percentage
   - Icon: `fa-memory text-purple-500`

**Chart Subtitle System:**
- Default: "Označte oblasť pre zoom, dvojité kliknutie pre zoom out"
- Zoomed: "Postupný zoom out - kliknite znovu pre ďalší krok"
- Optimized view: "Optimalizované zobrazenie - dostupné Xh dát" (green)
- Partial data: "Zobrazený 7d horizont - dostupné 3d z 7d" (yellow)
- Full data: "Zobrazené všetky dostupné dáta za 24h" (gray)
- Loading: "Načítavam všetky dostupné dáta pre 30d..." (blue)
- Error: "Chyba pri načítaní dát - skúste znovu" (red)

**Empty/Loading States (Lines 1500-1511):**
- **No Device Selected**: Large chart icon + "Vyberte zariadenie pre zobrazenie grafov"
- **Loading**: Animated spinner + "Načítavam dáta..."

**Device Settings Modal (Lines 1515-1587):**

Form fields for per-device intervals:
- **Ping Interval (seconds)**: Range 0 (use global), 20-86400, validation function
- **Retry Interval (seconds)**: Range 0 (use global), 5-120, used during outages
- **SNMP Interval (minutes)**: Range 0 (use global), 1-1440 (24 hours)

Buttons: Close (X), Cancel, Save (POST to API)

**Debug Terminal Panel (Lines 1589-1600):**
- Fixed position bottom-right corner
- 450px width, 300px max height
- Green monospace text on black background
- Toggle: Ctrl+D keyboard shortcut
- Features: Clear, Copy, Minimize, Close buttons
- Auto-scroll to newest entries
- Limit: 100 recent log entries
- Enabled via `debug_terminal` setting in database

### monitoring.js Structure

#### Global Variables (Lines 1-368)

**Debug System:**
```javascript
let debugSettings = {};
let debugPanelEnabled = false;
let debugLogs = [];
const maxDebugLogs = 500;
```

**State Variables:**
```javascript
let currentDeviceId = null;
let currentTimeRange = '24h';
let charts = {};  // Chart.js instances
let socket = null;  // Socket.IO connection
let isLoadingData = false;  // Prevent concurrent loads
let lastTotalMemoryValue = null;  // For forward-fill
let lastPingHistory = [];  // Cached ping data for uptime calc
let pendingFullPingHistory = false;  // Block metric updates during partial load
let lastPingHistoryTimestamp = 0;
let lastSnmpDataTimestamp = null;
let lastSnmpIntervalEstimateMs = null;
```

**Constants:**
```javascript
const SNMP_GAP_MIN_MS = 5 * 60 * 1000;          // 5 minutes
const SNMP_GAP_DEFAULT_MS = 15 * 60 * 1000;     // 15 minutes
const SNMP_GAP_MAX_MS = 60 * 60 * 1000;         // 1 hour
const SNMP_INTERVAL_MIN_GUESS_MS = 60 * 1000;   // 1 minute
const SHORT_RANGES = new Set(['30m','recent','3h','6h','12h','24h']);
```

#### Utility Functions (Lines 369-649)

**Device Status Management:**
```javascript
getStatusIndicator(status, isPaused)
// Returns: 🟢 (online), 🔴 (offline), ⚪ (unknown), ⏸️ (paused)

updateDeviceStatus(deviceId, status)
// Updates cached status and selector dropdown

updateDeviceStatusInSelector()
// Batch update all device statuses in dropdown
```

**State Persistence:**
```javascript
saveState()  // Save to localStorage: deviceId, timeRange
loadState()  // Restore from localStorage
persistZoomRange(range)  // Save zoom-out expansion range
```

**Offline Interval Detection:**
```javascript
getOfflineIntervalsFromPingHistory()
// Scans lastPingHistory for continuous offline periods
// Returns: [{start: timestampMs, end: timestampMs}, ...]
// Used to prevent SNMP gap insertion during known outages
```

**SNMP Gap Detection:**
```javascript
estimateSnmpIntervalMs(history)
// Calculate median interval between SNMP samples
// Returns estimated interval in ms

getGapThresholdFromInterval(intervalMs)
// Scale gap threshold: 4x interval, clamped 5min-60min

doesOfflineOverlapRange(offlineStart, offlineEnd, rangeStart, rangeEnd)
// Check if offline period overlaps time window

shouldInsertSnmpGap(prevTs, curTs, offlineIntervals, rangeStart, rangeEnd)
// Decide if gap marker needed:
//   - Offline overlap OR exceeded threshold
// Prevents visual confusion when data missing due to outage

pushGapMarker(dataArray, timestampMs)
// Insert {x: timestamp, y: null} to break chart line
```

**API Helper:**
```javascript
const api = {
  _handleResponse: async (res) => {
    if (res.status === 401) window.location.href = '/login';
    return res.json();
  },
  get: async (endpoint) => { /* GET request */ },
  post: async (endpoint, data) => { /* POST with JSON */ }
};
```

#### WebSocket & Real-Time Updates (Lines 652-686)

```javascript
const initializeSocket = () => {
  socket = io();

  socket.on('connect', () => { /* Connected */ });
  socket.on('disconnect', () => { /* Disconnected */ });

  socket.on('ping_update', (data) => {
    // Update device status in selector (always)
    updateDeviceStatus(data.device_id, data.status);

    // Update charts only if:
    // - Page is visible (document.visibilityState === 'visible')
    // - Correct device selected
    if (visible && data.device_id === currentDeviceId) {
      updatePingStatus(data);  // Update status card
      updatePingChart(data);   // Append to chart
      updateHeaderMetrics();   // Recalculate uptime/latency
    }
  });

  socket.on('snmp_update', (data) => {
    // Update SNMP charts if page visible and correct device
    if (visible && data.device_id === currentDeviceId) {
      updateSNMPCharts(data);
      // Update device model if board_name/version present
    }
  });
};
```

**Page Visibility Integration:**
- All real-time updates check `document.visibilityState === 'visible'`
- Y-axis optimization stops when page hidden (battery saving)
- Device status updates occur regardless (for dropdown indicators)

#### Data Loading Functions (Lines 689-911)

**Load Devices:**
```javascript
const loadDevices = async () => {
  const devices = await api.get('devices');

  // Populate custom dropdown
  devices.forEach(device => {
    const statusIndicator = getStatusIndicator(device.status, device.monitoring_paused);
    const optionText = `${statusIndicator} ${device.name} (${device.ip})`;
    // Add to dropdown with data attributes
  });
};
```

**Update Ping Status:**
```javascript
const updatePingStatus = (pingData) => {
  // Use cached DOM elements for performance
  const indicator = domCache.pingIndicator;
  const statusText = domCache.pingStatusText;
  const lastPingElement = domCache.lastPing;

  // Update indicator class: online/offline
  // Update status text: "Online" / "Offline"
  // Update last ping timestamp

  // Batch DOM updates with requestAnimationFrame
  requestAnimationFrame(() => {
    indicator.className = `ping-indicator ${status}`;
    statusText.textContent = statusLabel;
    lastPingElement.textContent = timestamp;
  });
};
```

**Uptime Calculation (Duration-Based):**
```javascript
const computeUptimeForRange = (rangeKey) => {
  const {history, rangeMs, nowTs} = getHistoryWindowForRange(rangeKey);

  let onlineDuration = 0;

  // Calculate online duration between samples
  for (let i = 0; i < history.length - 1; i++) {
    const cur = history[i];
    const next = history[i + 1];
    const curTs = new Date(cur.timestamp).getTime();
    const nextTs = new Date(next.timestamp).getTime();
    const segment = nextTs - curTs;

    if (cur.status === 'online') {
      onlineDuration += segment;
    }
  }

  // Add duration from last sample to now if online
  if (history.length > 0) {
    const last = history[history.length - 1];
    const lastTs = new Date(last.timestamp).getTime();
    if (last.status === 'online') {
      onlineDuration += (nowTs - lastTs);
    }
  }

  const totalDuration = rangeMs;
  const percent = (onlineDuration / totalDuration) * 100;
  return Math.min(100, Math.max(0, percent));
};
```

**Average Latency Calculation (Weight-Based):**
```javascript
const computeAverageLatencyForRange = (rangeKey) => {
  // Weight latency by segment duration
  let weightedLatency = 0;
  let onlineDuration = 0;

  for (let i = 0; i < history.length - 1; i++) {
    const cur = history[i];
    const next = history[i + 1];
    const curTs = new Date(cur.timestamp).getTime();
    const nextTs = new Date(next.timestamp).getTime();
    const segment = nextTs - curTs;

    if (cur.status === 'online' && cur.avg_latency) {
      const latency = parseFloat(cur.avg_latency);
      weightedLatency += latency * segment;
      onlineDuration += segment;
    }
  }

  if (onlineDuration === 0) return 0;
  return weightedLatency / onlineDuration;
};
```

**Dynamic Header Updates:**
```javascript
updateDynamicUptime()  // Refresh uptime % and label
updateAverageLatency()  // Refresh weighted average
updateHeaderMetrics()  // Trigger both + color coding
```

#### Time Formatting (Lines 913-1015)

Progressive granularity based on time range:

```javascript
const getTimeFormats = (timeRange) => {
  switch (timeRange) {
    case '30m':
      return {
        displayFormats: { minute: 'HH:mm' },
        tooltipFormat: 'dd/MM/yyyy HH:mm',
        unit: 'minute',
        stepSize: 10,
        maxTicksLimit: 8
      };

    case '24h':
      return {
        displayFormats: { hour: 'dd/MM HH:mm' },
        tooltipFormat: 'dd/MM/yyyy HH:mm',
        unit: 'hour',
        stepSize: 2,
        maxTicksLimit: 10
      };

    case '7d':
      return {
        displayFormats: { day: 'dd/MM' },
        tooltipFormat: 'dd/MM/yyyy',
        unit: 'day',
        stepSize: 1,
        maxTicksLimit: 8
      };

    case '30d':
      return {
        displayFormats: { day: 'dd/MM' },
        tooltipFormat: 'dd/MM/yyyy',
        unit: 'day',
        stepSize: 3,
        maxTicksLimit: 12
      };

    case '1y':
      return {
        displayFormats: { month: 'MM/yy' },
        tooltipFormat: 'dd/MM/yyyy',
        unit: 'month',
        stepSize: 1,
        maxTicksLimit: 12
      };
  }
};
```

#### Chart Initialization (Lines 1017-1603)

**Chart.js Base Configuration:**
```javascript
const getChartOptions = (timeRange = currentTimeRange) => {
  const timeFormats = getTimeFormats(timeRange);

  return {
    responsive: true,
    maintainAspectRatio: false,
    interaction: {
      intersect: false,
      mode: 'index'
    },
    plugins: {
      legend: {
        display: true,
        labels: {
          color: '#d1d5db',
          font: { size: 12 }
        }
      },
      subtitle: {
        display: true,
        text: 'Kliknite a ťahajte pre zoom, dvojité kliknutie pre zoom out',
        color: '#9ca3af',
        font: { size: 11, style: 'italic' },
        padding: { top: 5, bottom: 10 }
      },
      tooltip: {
        enabled: true,
        mode: 'index',
        intersect: false
      }
    },
    scales: {
      x: {
        type: 'time',
        time: {
          displayFormats: timeFormats.displayFormats,
          tooltipFormat: timeFormats.tooltipFormat,
          unit: timeFormats.unit,
          stepSize: timeFormats.stepSize
        },
        ticks: {
          color: '#9ca3af',
          maxTicksLimit: timeFormats.maxTicksLimit
        },
        grid: {
          color: '#374151',
          drawBorder: false
        }
      },
      y: {
        beginAtZero: true,
        ticks: {
          color: '#9ca3af'
        },
        grid: {
          color: '#374151',
          drawBorder: false
        }
      }
    }
  };
};
```

**Y-Axis Optimization System (Uptime Kuma-Inspired):**

Intelligently adjusts Y-axis to position data optimally in chart area:

```javascript
const optimizeYAxisRange = (data, chartType) => {
  const values = data.filter(v => v !== null && !isNaN(v));
  if (values.length === 0) return null;

  const min = Math.min(...values);
  const max = Math.max(...values);
  const range = max - min;

  switch (chartType) {
    case 'ping':
      return optimizePingYAxis(min, max, range);
    case 'cpu':
      return optimizeCpuYAxis(min, max, range);
    case 'temperature':
      return optimizeTemperatureYAxis(min, max, range);
    case 'memory':
      return optimizeMemoryYAxis(min, max, range);
  }
};
```

**Ping Y-Axis Optimization:**
```javascript
const optimizePingYAxis = (min, max, range) => {
  // More bottom padding (30%), less top padding (20%)
  // Positions data higher in chart for better visibility
  const bottomPadding = range * 0.30;
  const topPadding = range * 0.20;

  let suggestedMin = Math.max(0, min - bottomPadding);
  let suggestedMax = max + topPadding;

  // Never go below 0
  if (suggestedMin < 0) suggestedMin = 0;

  // Special handling for stable low latency
  if (range < 5 && max < 50) {
    suggestedMin = Math.max(0, min - 5);
    suggestedMax = max + 5;
  }

  return { suggestedMin, suggestedMax };
};
```

**CPU Y-Axis Optimization:**
```javascript
const optimizeCpuYAxis = (min, max, range) => {
  // Always start at 0%
  let suggestedMin = 0;
  let suggestedMax = 100;

  if (max <= 50) {
    // Low CPU usage: Show 0-50% scale
    suggestedMax = 50;
  } else if (max <= 80) {
    // Medium usage: Show with 15% headroom
    suggestedMax = max * 1.15;
  } else {
    // High usage: Show full 0-100% scale
    suggestedMax = 100;
  }

  return { suggestedMin, suggestedMax };
};
```

**Temperature Y-Axis Optimization:**
```javascript
const optimizeTemperatureYAxis = (min, max, range) => {
  // Center around actual range
  if (range < 1) {
    // Constant temperature: ±5°C padding
    return {
      suggestedMin: min - 5,
      suggestedMax: max + 5
    };
  }

  if (min > 30 && range < 15) {
    // High stable temp: Optimize to center data
    const padding = Math.max(3, range * 0.15);
    return {
      suggestedMin: min - padding,
      suggestedMax: max + padding
    };
  }

  // Normal range: Minimum 3°C padding
  const padding = Math.max(3, range * 0.10);
  return {
    suggestedMin: min - padding,
    suggestedMax: max + padding
  };
};
```

**Memory Y-Axis Optimization:**
```javascript
const optimizeMemoryYAxis = (min, max, range) => {
  // Always start at 0 MB
  const suggestedMin = 0;

  // Max = actualMax * 1.1 (10% headroom)
  const suggestedMax = max * 1.1;

  return { suggestedMin, suggestedMax };
};
```

**Periodic Y-Axis Optimization:**
```javascript
// Every 30 seconds when page visible
const startYAxisOptimization = () => {
  const optimizationInterval = setInterval(() => {
    if (document.visibilityState === 'visible' && currentDeviceId) {
      optimizeAllChartsYAxes();
    }
  }, 30000);

  // Stop on visibility change
  document.addEventListener('visibilitychange', () => {
    if (document.visibilityState === 'hidden') {
      clearInterval(optimizationInterval);
    }
  });
};
```

**Chart Instances:**

1. **Ping Chart:**
```javascript
charts.ping = new Chart('pingChart', {
  type: 'line',
  data: {
    datasets: [{
      label: 'Ping Latencia (ms)',
      data: [],
      borderColor: pingColors.onlineBorder,
      backgroundColor: pingColors.onlineBackground,
      fill: true,
      tension: 0.12,
      spanGaps: false,
      borderWidth: 2.5,
      pointRadius: 0,
      pointHoverRadius: 0
    }]
  },
  options: {
    ...getChartOptions(),
    plugins: {
      legend: {
        display: true,
        labels: {
          generateLabels: () => [
            {
              text: 'Online',
              fillStyle: pingColors.onlineBackground,
              strokeStyle: pingColors.onlineBorder
            },
            {
              text: 'Offline',
              fillStyle: pingColors.offlineBackground,
              strokeStyle: pingColors.offlineBorder
            }
          ]
        }
      },
      tooltip: {
        filter: (tooltipItem) => {
          // Show only online dataset in tooltip
          return tooltipItem.dataset.label.includes('Online');
        }
      }
    }
  }
});
```

2. **CPU Chart:**
```javascript
charts.cpu = new Chart('cpuChart', {
  type: 'line',
  data: {
    datasets: [{
      label: 'CPU Load (%)',
      data: [],
      borderColor: cpuColor,
      backgroundColor: cpuBackgroundColor,
      fill: false,
      tension: 0.12,
      spanGaps: false,
      borderWidth: 2,
      pointRadius: 0,
      pointHoverRadius: 0
    }]
  },
  options: getChartOptions()
});
```

3. **Temperature Chart:**
```javascript
charts.temperature = new Chart('temperatureChart', {
  type: 'line',
  data: {
    datasets: [{
      label: 'Teplota (°C)',
      data: [],
      borderColor: tempColor,
      backgroundColor: tempBackgroundColor,
      fill: false,
      tension: 0.12,
      spanGaps: false,
      borderWidth: 2,
      pointRadius: 0,
      pointHoverRadius: 0
    }]
  },
  options: getChartOptions()
});
```

4. **Memory Chart:**
```javascript
charts.memory = new Chart('memoryChart', {
  type: 'line',
  data: {
    datasets: [
      {
        label: 'Used Memory (MB)',
        data: [],
        borderColor: memUsedColor,
        backgroundColor: memUsedBackgroundColor,
        fill: true,
        tension: 0.12,
        spanGaps: false,
        borderWidth: 2,
        pointRadius: 0,
        pointHoverRadius: 0,
        order: 2
      },
      {
        label: 'Total Memory (MB)',
        data: [],
        borderColor: memTotalColor,
        backgroundColor: memTotalBackgroundColor,
        fill: true,
        tension: 0.12,
        spanGaps: false,
        borderWidth: 2,
        pointRadius: 0,
        pointHoverRadius: 0,
        order: 1
      }
    ]
  },
  options: {
    ...getChartOptions(),
    plugins: {
      tooltip: {
        callbacks: {
          afterBody: (tooltipItems) => {
            // Show free memory and percentage
            const usedMem = tooltipItems[0].parsed.y;
            const totalMem = tooltipItems[1].parsed.y;
            const freeMem = totalMem - usedMem;
            const percentage = ((usedMem / totalMem) * 100).toFixed(1);
            return [
              `Free: ${freeMem.toFixed(2)} MB`,
              `Usage: ${percentage}%`
            ];
          }
        }
      }
    }
  }
});
```

**Mobile Tooltip Handling:**
```javascript
const setupMobileTooltipDismiss = () => {
  // Tap outside charts: Hide all tooltips
  document.addEventListener('touchstart', (e) => {
    if (!e.target.closest('.chart-container')) {
      Object.values(charts).forEach(ch => {
        ch.options.plugins.tooltip.enabled = false;
        ch.update('none');
      });
    }
  });

  // Auto-hide after 6 seconds
  let tooltipTimeout;
  document.querySelectorAll('canvas').forEach(canvas => {
    canvas.addEventListener('touchstart', () => {
      clearTimeout(tooltipTimeout);
      tooltipTimeout = setTimeout(() => {
        Object.values(charts).forEach(ch => {
          ch.options.plugins.tooltip.enabled = false;
          ch.update('none');
        });
      }, 6000);
    });
  });
};
```

#### Chart Update Functions (Lines 1706-2515)

**Update Ping Chart:**

*Historical Data (Array):*
```javascript
if (pingData.history && Array.isArray(pingData.history)) {
  lastPingHistory = pingData.history.slice(); // Cache for uptime calc

  const datasets = [];
  let currentOnlineSegment = [];
  let currentOfflineSegment = [];
  let onlineSegments = [];
  let offlineSegments = [];
  let minOnlineLatency = Infinity;

  // Separate into continuous online/offline segments
  pingData.history.forEach((point, index) => {
    const timestampMs = new Date(point.timestamp).getTime();
    const isOnline = point.status === 'online';
    const latency = parseFloat(point.avg_latency) || 0;

    if (isOnline) {
      minOnlineLatency = Math.min(minOnlineLatency, latency);

      // Close offline segment if exists
      if (currentOfflineSegment.length > 0) {
        offlineSegments.push([...currentOfflineSegment]);
        currentOfflineSegment = [];
      }

      // Add to online segment
      currentOnlineSegment.push({ x: timestampMs, y: latency });
    } else {
      // Close online segment if exists
      if (currentOnlineSegment.length > 0) {
        onlineSegments.push([...currentOnlineSegment]);
        currentOnlineSegment = [];
      }

      // Add to offline segment
      currentOfflineSegment.push({ x: timestampMs, y: null });
    }
  });

  // Close final segments
  if (currentOnlineSegment.length > 0) {
    onlineSegments.push(currentOnlineSegment);
  }
  if (currentOfflineSegment.length > 0) {
    offlineSegments.push(currentOfflineSegment);
  }

  // Create dataset for each online segment
  onlineSegments.forEach((segment, index) => {
    datasets.push({
      label: index === 0 ? 'Online' : `Online ${index + 1}`,
      data: segment,
      borderColor: pingColors.onlineBorder,
      backgroundColor: pingColors.onlineBackground,
      fill: true,
      tension: 0.12,
      spanGaps: false,
      borderWidth: 2.5,
      pointRadius: 0,
      pointHoverRadius: 0
    });
  });

  // Create dataset pair for each offline segment
  offlineSegments.forEach((segment, index) => {
    const offlineHeight = minOnlineLatency || 1;

    // Invisible bottom line at minOnlineLatency
    datasets.push({
      label: `Offline Bottom ${index + 1}`,
      data: segment.map(p => ({ x: p.x, y: offlineHeight })),
      borderColor: 'transparent',
      backgroundColor: 'transparent',
      fill: false,
      pointRadius: 0,
      pointHoverRadius: 0
    });

    // Top line that fills to bottom line (red fill)
    datasets.push({
      label: index === 0 ? 'Offline' : `Offline ${index + 1}`,
      data: segment.map(p => ({ x: p.x, y: offlineHeight })),
      borderColor: pingColors.offlineBorder,
      backgroundColor: pingColors.offlineBackground,
      fill: '-1',  // Fill to previous dataset
      borderWidth: 0,
      pointRadius: 0,
      pointHoverRadius: 0
    });
  });

  // Update chart
  charts.ping.data.datasets = datasets;
  applyYAxisOptimization(charts.ping, 'ping');
  charts.ping.update('none');
}
```

*Real-Time Data (Single Point):*
```javascript
else {
  lastPingHistory.push(pingData); // Add to cache

  const nowMs = Date.now();
  const isOnline = pingData.status === 'online';
  const latency = parseFloat(pingData.avg_latency) || 0;

  // Find or create appropriate dataset
  let targetDataset = null;

  if (isOnline) {
    // Find last online dataset or create new
    for (let i = charts.ping.data.datasets.length - 1; i >= 0; i--) {
      const ds = charts.ping.data.datasets[i];
      if (ds.label.includes('Online')) {
        targetDataset = ds;
        break;
      }
    }

    if (!targetDataset) {
      targetDataset = {
        label: 'Online',
        data: [],
        borderColor: pingColors.onlineBorder,
        backgroundColor: pingColors.onlineBackground,
        fill: true,
        // ... rest of config
      };
      charts.ping.data.datasets.push(targetDataset);
    }

    targetDataset.data.push({ x: nowMs, y: latency });
  } else {
    // Calculate offline height based on existing online data
    let offlineHeight = 1;
    charts.ping.data.datasets.forEach(ds => {
      if (ds.label.includes('Online')) {
        ds.data.forEach(point => {
          if (point.y && point.y > 0) {
            offlineHeight = Math.min(offlineHeight, point.y);
          }
        });
      }
    });

    // Create offline dataset pair (bottom + top)
    const bottomDataset = {
      label: 'Offline Bottom',
      data: [{ x: nowMs, y: offlineHeight }],
      borderColor: 'transparent',
      // ...
    };

    const topDataset = {
      label: 'Offline',
      data: [{ x: nowMs, y: offlineHeight }],
      borderColor: pingColors.offlineBorder,
      backgroundColor: pingColors.offlineBackground,
      fill: '-1',
      // ...
    };

    charts.ping.data.datasets.push(bottomDataset, topDataset);
  }

  // Limit dataset size (500 points max)
  charts.ping.data.datasets.forEach(ds => {
    if (ds.data.length > 500) {
      ds.data.shift();
    }
  });

  charts.ping.update('none');
}

// Always update metrics after ping chart update
updateHeaderMetrics();
```

**Update SNMP Charts:**

*Historical Data Processing:*
```javascript
if (snmpData.history && Array.isArray(snmpData.history)) {
  const cpuData = [];
  const tempData = [];
  const usedMemData = [];
  const totalMemData = [];
  let lastTotalMem = null; // For forward-fill

  // Get offline intervals from ping history
  const offlineIntervals = getOfflineIntervalsFromPingHistory();
  const rangeMs = getTimeRangeMs(currentTimeRange);
  const nowTs = Date.now();
  const rangeStart = nowTs - rangeMs;
  const rangeEnd = nowTs;

  // Estimate SNMP interval for gap detection
  const estimatedIntervalMs = estimateSnmpIntervalMs(snmpData.history);
  const gapThreshold = getGapThresholdFromInterval(estimatedIntervalMs);

  snmpData.history.forEach((point, index) => {
    const timestamp = new Date(point.timestamp).getTime();

    // CPU
    if (point.cpu_load !== null) {
      const cpuValue = parseInt(point.cpu_load);

      // Check if gap needed before this point
      if (index > 0) {
        const prevTs = new Date(snmpData.history[index - 1].timestamp).getTime();
        if (shouldInsertSnmpGap(prevTs, timestamp, offlineIntervals, rangeStart, rangeEnd, gapThreshold)) {
          pushGapMarker(cpuData, prevTs + 1000);
        }
      }

      cpuData.push({ x: timestamp, y: cpuValue });
    }

    // Temperature
    if (point.temperature !== null) {
      const tempValue = parseInt(point.temperature);

      if (index > 0) {
        const prevTs = new Date(snmpData.history[index - 1].timestamp).getTime();
        if (shouldInsertSnmpGap(prevTs, timestamp, offlineIntervals, rangeStart, rangeEnd, gapThreshold)) {
          pushGapMarker(tempData, prevTs + 1000);
        }
      }

      tempData.push({ x: timestamp, y: tempValue });
    }

    // Memory (independent datasets)
    if (point.used_memory !== null) {
      const usedMem = parseFloat(point.used_memory);

      if (index > 0) {
        const prevTs = new Date(snmpData.history[index - 1].timestamp).getTime();
        if (shouldInsertSnmpGap(prevTs, timestamp, offlineIntervals, rangeStart, rangeEnd, gapThreshold)) {
          pushGapMarker(usedMemData, prevTs + 1000);
          pushGapMarker(totalMemData, prevTs + 1000);
        }
      }

      usedMemData.push({ x: timestamp, y: usedMem });
    }

    // Total Memory with forward-fill
    if (point.total_memory !== null) {
      lastTotalMem = parseFloat(point.total_memory);
      totalMemData.push({ x: timestamp, y: lastTotalMem });
    } else if (lastTotalMem && point.used_memory !== null) {
      // Forward-fill to prevent truncation
      totalMemData.push({ x: timestamp, y: lastTotalMem });
    }
  });

  // Batch update all charts
  requestAnimationFrame(() => {
    charts.cpu.data.datasets[0].data = cpuData;
    charts.temperature.data.datasets[0].data = tempData;
    charts.memory.data.datasets[0].data = usedMemData;
    charts.memory.data.datasets[1].data = totalMemData;

    // Apply optimizations
    autoAlignChartTimeRange(charts.cpu);
    adjustPointSizes(charts.cpu, cpuData.length, currentTimeRange);
    applyYAxisOptimization(charts.cpu, 'cpu');

    autoAlignChartTimeRange(charts.temperature);
    adjustPointSizes(charts.temperature, tempData.length, currentTimeRange);
    applyYAxisOptimization(charts.temperature, 'temperature');

    autoAlignChartTimeRange(charts.memory);
    adjustPointSizes(charts.memory, usedMemData.length, currentTimeRange);
    applyYAxisOptimization(charts.memory, 'memory');

    // Update with no animation
    charts.cpu.update('none');
    charts.temperature.update('none');
    charts.memory.update('none');
  });
}
```

*Real-Time SNMP Update:*
```javascript
else {
  const now = new Date();

  // Update device model if available
  if (snmpData.board_name || snmpData.version) {
    const board = snmpData.board_name || 'Unknown';
    const version = snmpData.version || 'Unknown';
    deviceModel.textContent = `${board} - RouterOS ${version}`;
  }

  // Check if gap needed (time since last SNMP > threshold)
  const timeSinceLastSnmp = now.getTime() - (lastSnmpDataTimestamp || 0);
  const threshold = lastSnmpIntervalEstimateMs * 4 || SNMP_GAP_DEFAULT_MS;
  const realtimeGapNeeded = timeSinceLastSnmp > threshold;

  requestAnimationFrame(() => {
    // Insert gap markers if needed
    if (realtimeGapNeeded && lastSnmpDataTimestamp) {
      Object.values(charts).forEach(ch => {
        if (ch.canvas.id !== 'pingChart') {
          ch.data.datasets.forEach(ds => {
            if (ds.data.length > 0) {
              pushGapMarker(ds.data, lastSnmpDataTimestamp + 1000);
            }
          });
        }
      });
    }

    // Append new points
    if (snmpData.cpu_load !== null) {
      const cpuValue = parseInt(snmpData.cpu_load);
      charts.cpu.data.datasets[0].data.push({ x: now, y: cpuValue });

      // Limit size
      if (charts.cpu.data.datasets[0].data.length > 1000) {
        charts.cpu.data.datasets[0].data.shift();
      }

      charts.cpu.update('none');
    }

    if (snmpData.temperature !== null) {
      const tempValue = parseInt(snmpData.temperature);
      charts.temperature.data.datasets[0].data.push({ x: now, y: tempValue });

      if (charts.temperature.data.datasets[0].data.length > 1000) {
        charts.temperature.data.datasets[0].data.shift();
      }

      charts.temperature.update('none');
    }

    // Memory with forward-fill
    if (snmpData.used_memory !== null) {
      const usedMemValue = parseFloat(snmpData.used_memory);
      charts.memory.data.datasets[0].data.push({ x: now, y: usedMemValue });

      if (charts.memory.data.datasets[0].data.length > 1000) {
        charts.memory.data.datasets[0].data.shift();
      }
    }

    if (snmpData.total_memory !== null) {
      lastTotalMemoryValue = parseFloat(snmpData.total_memory);
      charts.memory.data.datasets[1].data.push({ x: now, y: lastTotalMemoryValue });
    } else if (lastTotalMemoryValue && snmpData.used_memory !== null) {
      // Forward-fill
      charts.memory.data.datasets[1].data.push({ x: now, y: lastTotalMemoryValue });
    }

    if (charts.memory.data.datasets[1].data.length > 1000) {
      charts.memory.data.datasets[1].data.shift();
    }

    charts.memory.update('none');

    // Update timestamp
    lastSnmpDataTimestamp = now.getTime();
  });
}
```

#### Time Range Management (Lines 2558-2898)

**Time Range to Milliseconds:**
```javascript
const getTimeRangeMs = (timeRange) => {
  const conversions = {
    '30m': 30 * 60 * 1000,
    '3h': 3 * 60 * 60 * 1000,
    '6h': 6 * 60 * 60 * 1000,
    '12h': 12 * 60 * 60 * 1000,
    '24h': 24 * 60 * 60 * 1000,
    '7d': 7 * 24 * 60 * 60 * 1000,
    '30d': 30 * 24 * 60 * 60 * 1000,
    '90d': 90 * 24 * 60 * 60 * 1000,
    '1y': 365 * 24 * 60 * 60 * 1000
  };
  return conversions[timeRange] || conversions['24h'];
};
```

**Short Range Axis Stabilization:**

Problem: On refresh, charts briefly flicker old time windows or lose grid lines.

Solution: Single consolidated axis update after data load:

```javascript
const stabilizeShortRangeTimeAxis = (range = currentTimeRange) => {
  if (!SHORT_RANGES.has(range)) return; // Only 30m-24h

  const rangeMs = getTimeRangeMs(range);

  Object.values(charts).forEach(ch => {
    const chartRange = getChartTimeRange(ch);
    const maxTs = chartRange.max;
    const minTs = Math.max(chartRange.max - rangeMs, chartRange.min);

    // Force time axis settings
    ch.options.scales.x.type = 'time';
    ch.options.scales.x.min = minTs;
    ch.options.scales.x.max = maxTs;
    ch.options.scales.x.offset = false;

    // Reapply time formats
    const tf = getTimeFormats(range);
    Object.assign(ch.options.scales.x.time, tf);
  });

  // Batch update
  requestAnimationFrame(() => {
    Object.values(charts).forEach(ch => ch.update('none'));
  });
};
```

**Animation Control:**
```javascript
let disableRangeAnimations = true; // Master switch

const disableChartAnimationsForRangeChange = () => {
  Object.values(charts).forEach(ch => {
    ch.options.animation.duration = 0;
    ch.options.animation.easing = 'linear';
  });
};

const animateZoomIn = (charts) => {
  // Scale 1.02 -> 1 animation
  // Smooth zoom-in effect
};

const animateZoomOut = (charts) => {
  // Scale 0.98 -> 1 animation
  // Smooth zoom-out effect
};
```

**Time Range Button Management:**
```javascript
const setActiveTimeRange = (timeRange) => {
  // Check if blocked during single chart expansion
  if (window._blockGlobalTimeRangeChanges) return;

  // Remove active from all, add to selected
  document.querySelectorAll('.time-range-btn').forEach(btn => {
    btn.classList.remove('active');
  });
  document.querySelector(`[data-range="${timeRange}"]`).classList.add('active');

  currentTimeRange = timeRange;
  window.currentTimeRange = timeRange; // Export for zoom functions

  // Preventive: Reset X-axis limits for short ranges
  const rangeMs = getTimeRangeMs(timeRange);
  const nowTs = Date.now();

  Object.values(charts).forEach(ch => {
    if (SHORT_RANGES.has(timeRange)) {
      ch.options.scales.x.min = nowTs - rangeMs;
      ch.options.scales.x.max = nowTs;
    } else {
      delete ch.options.scales.x.min;
      delete ch.options.scales.x.max;
    }
  });

  updateChartTimeFormats(timeRange);
  updateHeaderMetrics();

  if (disableRangeAnimations) {
    disableChartAnimationsForRangeChange();
    unifyTimeAxis();
    stabilizeShortRangeTimeAxis(timeRange);
  }

  saveState();
};
```

#### Data Loading & Refresh (Lines 2963-3829)

**Load Historical Data:**

This is the most complex function with advanced optimization logic:

```javascript
const loadHistoricalData = async (deviceId, showLoadingAnimation = true, isRefreshOperation = false) => {
  // Guard: Prevent multiple simultaneous loads
  if (isLoadingData) return;
  isLoadingData = true;

  try {
    // 1. Show loading animation
    if (showLoadingAnimation) {
      addChartLoadingAnimation(); // Sweep effect
    }

    // 2. Determine optimized range
    const rangeParam = currentTimeRange === '30m' ? 'recent' : currentTimeRange;

    // Use optimized loading for refresh on short ranges
    const useOptimized = isRefreshOperation && SHORT_RANGES.has(currentTimeRange);

    const apiUrl = `/api/monitoring/history/${deviceId}?range=${rangeParam}${useOptimized ? '&optimized=1' : ''}`;

    // 3. Fetch data
    const response = await fetch(apiUrl);
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    const data = await response.json();

    // 4. Process ping data
    if (data.ping_data && data.ping_data.length > 0) {
      updatePingChart({ history: data.ping_data });
    }

    // 5. Process SNMP data
    if (data.snmp_data && data.snmp_data.length > 0) {
      updateSNMPCharts({ history: data.snmp_data });
    }

    // 6. Update latest status
    if (data.latest_ping) {
      updatePingStatus(data.latest_ping);
    }

    // 7. Y-axis optimization
    setTimeout(() => {
      optimizeAllChartsYAxes();
    }, 100);

    // 8. Apply time range (unless user zoomed)
    if (!window._userZoomActive) {
      applyFullTimeRangeToAllCharts();
    }

    // 9. Stabilize short ranges
    if (SHORT_RANGES.has(currentTimeRange)) {
      setTimeout(() => {
        stabilizeShortRangeTimeAxis(currentTimeRange);
      }, 100);
    }

    // 10. Schedule full data load if optimized was used
    if (useOptimized) {
      pendingFullPingHistory = true;

      setTimeout(() => {
        // Full load in background
        loadHistoricalData(deviceId, false, false);
        pendingFullPingHistory = false;
      }, 1500);
    }

  } catch (error) {
    console.error('Load historical data failed:', error);
    // Show error to user
  } finally {
    isLoadingData = false;
  }
};
```

**Optimized Loading Strategy:**

For refresh on short ranges (30m-24h):
1. **First load**: `&optimized=1` parameter → Backend returns last ~100 points
2. **UI updates instantly** with partial data (no freeze)
3. **1.5 seconds later**: Full dataset loaded in background
4. **Metrics blocked** during partial load via `pendingFullPingHistory` flag
5. **Result**: Instant UI feedback, complete data shortly after

**Loading Animation:**
```javascript
const addChartLoadingAnimation = () => {
  const chartContainers = document.querySelectorAll('.chart-container');

  requestAnimationFrame(() => {
    chartContainers.forEach(container => {
      container.classList.add('updating'); // Sweep animation
    });

    setTimeout(() => {
      requestAnimationFrame(() => {
        chartContainers.forEach(container => {
          container.classList.remove('updating');
          container.classList.add('chart-fade-in'); // Fade in
        });

        setTimeout(() => {
          chartContainers.forEach(container => {
            container.classList.remove('chart-fade-in');
          });
        }, 800);
      });
    }, 300);
  });
};
```

#### Custom Zoom Functionality (monitoring.html Lines 1660-2365)

The application implements custom zoom **without** Chart.js zoom plugin.

**Core Zoom Functions:**

**1. Reset Zoom (Progressive Zoom-Out):**

```javascript
function resetZoom(chartId) {
  // Debouncing (400ms minimum between resets)
  const now = Date.now();
  const timeSinceLastReset = now - (window._lastZoomResetTime || 0);
  if (timeSinceLastReset < 400) return;
  window._lastZoomResetTime = now;

  const chart = Chart.getChart(chartId);
  const hasActiveZoom = chart.options.scales.x.min !== undefined;

  // Check per-chart time range
  let currentTimeRange = window._chartTimeRanges.get(chartId) || window.currentTimeRange;

  if (hasActiveZoom) {
    // Detect actual current range from axis
    const currentMin = chart.options.scales.x.min;
    const currentMax = chart.options.scales.x.max;
    const actualRange = currentMax - currentMin;

    // Find data range
    let dataMin = Infinity;
    let dataMax = -Infinity;
    chart.data.datasets.forEach(ds => {
      ds.data.forEach(point => {
        if (point.x) {
          dataMin = Math.min(dataMin, point.x);
          dataMax = Math.max(dataMax, point.x);
        }
      });
    });

    const fullDataRange = dataMax - dataMin;

    // Check if it's a real zoom (vs full time range display)
    const timeRangeMs = getTimeRangeMs(currentTimeRange);
    const isRealZoom = (currentMax - currentMin) < (timeRangeMs * 0.8);

    if (isRealZoom) {
      // Progressive zoom out (2.5x expansion per click)
      const currentCenter = (currentMin + currentMax) / 2;
      const newRange = Math.min(actualRange * 2.5, fullDataRange);

      if (newRange <= actualRange) {
        // Can't expand within current data, load larger range
        const nextRange = getNextLargerRange(currentTimeRange);

        if (nextRange !== currentTimeRange) {
          window._chartTimeRanges.set(chartId, nextRange);
          chart.options.scales.x.min = undefined;
          chart.options.scales.x.max = undefined;

          if (startRangeExpansionLoad(chart, chartId, nextRange)) {
            return; // Async loading started
          }
        }
      }

      // Apply progressive zoom
      const newMin = Math.max(dataMin, currentCenter - newRange / 2);
      const newMax = Math.min(dataMax, currentCenter + newRange / 2);

      // Check if near full range
      const tolerance = fullDataRange * 0.05;
      const isNearFullRange = (newMax - newMin) >= (fullDataRange - tolerance);

      if (isNearFullRange) {
        // Show full data range
        chart.options.scales.x.min = undefined;
        chart.options.scales.x.max = undefined;

        const subtitle = chart.options.plugins.subtitle;
        subtitle.text = 'Zobrazené všetky dostupné dáta - ďalší zoom out načíta viac dát';
        subtitle.color = '#9ca3af';

        restoreOriginalVisualTimeRange();
      } else {
        // Progressive zoom step
        chart.options.scales.x.min = newMin;
        chart.options.scales.x.max = newMax;

        const subtitle = chart.options.plugins.subtitle;
        subtitle.text = 'Postupný zoom out - kliknite znovu pre ďalší krok';
        subtitle.color = '#fbbf24';

        updateSingleChartTimeFormat(chart, newMin, newMax);
        updateVisualTimeRangeIndicatorForZoomOut(newMin, newMax);
      }
    } else {
      // No real zoom, try to load larger time range
      const nextRange = getNextLargerRange(currentTimeRange);

      if (nextRange !== currentTimeRange) {
        if (startRangeExpansionLoad(chart, chartId, nextRange)) {
          return; // Async loading started
        }
      }
    }
  }

  chart.update('active');
}
```

**2. Reset All Charts:**

```javascript
function resetAllChartsZoom() {
  // Clear per-chart tracking
  if (window._chartTimeRanges) window._chartTimeRanges.clear();
  if (window._expandedCharts) window._expandedCharts.clear();

  ['pingChart', 'cpuChart', 'temperatureChart', 'memoryChart'].forEach(chartId => {
    const chart = Chart.getChart(chartId);

    // Clear zoom
    chart.options.scales.x.min = undefined;
    chart.options.scales.x.max = undefined;

    // Reset subtitle
    const subtitle = chart.options.plugins.subtitle;
    subtitle.text = 'Označte oblasť pre zoom, dvojité kliknutie pre zoom out';
    subtitle.color = '#9ca3af';

    // Apply full time range horizon
    const currentTimeRange = window.currentTimeRange || '24h';
    const timeRangeMs = getTimeRangeMs(currentTimeRange);
    const now = Date.now();

    // Find data range
    let dataMin = Infinity;
    let dataMax = -Infinity;
    chart.data.datasets.forEach(ds => {
      ds.data.forEach(point => {
        if (point.x) {
          dataMin = Math.min(dataMin, point.x);
          dataMax = Math.max(dataMax, point.x);
        }
      });
    });

    const isShortRange = SHORT_RANGES.has(currentTimeRange);

    let requestedMin, requestedMax;

    if (isShortRange && dataMin !== Infinity && dataMax !== -Infinity) {
      const dataDuration = dataMax - dataMin;

      if (dataDuration < timeRangeMs) {
        // Show data-centric view with padding
        const padding = Math.max(dataDuration * 0.05, 2 * 60 * 1000);
        requestedMin = dataMin - padding;
        requestedMax = dataMax + padding;
      } else {
        // Show full range ending at latest data
        requestedMin = dataMax - timeRangeMs;
        requestedMax = dataMax;
      }
    } else {
      // Long ranges: show full horizon
      requestedMax = now;
      requestedMin = now - timeRangeMs;
    }

    chart.options.scales.x.min = requestedMin;
    chart.options.scales.x.max = requestedMax;

    updateSingleChartTimeFormat(chart, requestedMin, requestedMax);
    restoreOriginalVisualTimeRange();

    chart.update('none');
  });
}
```

**3. Start Range Expansion Load:**

Asynchronous data loading when user zooms out beyond available data:

```javascript
function startRangeExpansionLoad(chart, chartId, targetRange) {
  const subtitle = chart.options.plugins.subtitle;

  // Update subtitle to show loading
  subtitle.text = `Načítavam všetky dostupné dáta pre ${targetRange}...`;
  subtitle.color = '#3b82f6';
  chart.update('none');

  const deviceId = window.currentDeviceId;
  const apiRange = targetRange === '30m' ? 'recent' : targetRange;

  // Fetch data
  fetch(`/api/monitoring/history/${deviceId}?range=${apiRange}`)
    .then(response => response.json())
    .then(apiResponse => {
      // Parse response based on chart type
      let data = null;

      if (chartId === 'pingChart' && apiResponse.ping_data) {
        data = apiResponse.ping_data;
      } else if (['cpuChart', 'temperatureChart', 'memoryChart'].includes(chartId) && apiResponse.snmp_data) {
        data = apiResponse.snmp_data;
      }

      if (!data || data.length === 0) {
        subtitle.text = 'Žiadne dáta pre tento časový rozsah';
        subtitle.color = '#ef4444';
        chart.update('none');
        return;
      }

      const targetChart = Chart.getChart(chartId);

      // Process data based on chart type
      let newData = [];

      if (chartId === 'pingChart') {
        newData = data.map(item => ({
          x: new Date(item.timestamp).getTime(),
          y: parseFloat(item.avg_latency) || 0
        }));
      } else if (chartId === 'cpuChart') {
        newData = data.map(item => ({
          x: new Date(item.timestamp).getTime(),
          y: parseInt(item.cpu_load) || 0
        }));
      } else if (chartId === 'temperatureChart') {
        newData = data.map(item => ({
          x: new Date(item.timestamp).getTime(),
          y: parseInt(item.temperature) || 0
        }));
      } else if (chartId === 'memoryChart') {
        // Handle both datasets
        const usedMemData = [];
        const totalMemData = [];
        let lastTotalMem = null;

        data.forEach(item => {
          const timestamp = new Date(item.timestamp).getTime();

          if (item.used_memory !== null) {
            usedMemData.push({ x: timestamp, y: parseFloat(item.used_memory) });
          }

          if (item.total_memory !== null) {
            lastTotalMem = parseFloat(item.total_memory);
            totalMemData.push({ x: timestamp, y: lastTotalMem });
          } else if (lastTotalMem && item.used_memory !== null) {
            totalMemData.push({ x: timestamp, y: lastTotalMem });
          }
        });

        targetChart.data.datasets[0].data = usedMemData;
        targetChart.data.datasets[1].data = totalMemData;
        newData = [...usedMemData, ...totalMemData];
      }

      // Filter valid points
      newData = newData.filter(point => point.y !== null && !isNaN(point.y));

      if (newData.length === 0) {
        subtitle.text = 'Žiadne platné dáta pre tento rozsah';
        subtitle.color = '#ef4444';
        targetChart.update('none');
        return;
      }

      // Set data (except memory which was already set)
      if (chartId !== 'memoryChart') {
        targetChart.data.datasets[0].data = newData;
      }

      // Apply time axis optimization
      const targetRangeMs = getTimeRangeMs(targetRange);
      const now = Date.now();

      let dataMin = Math.min(...newData.map(p => p.x));
      let dataMax = Math.max(...newData.map(p => p.x));

      const isShortRange = SHORT_RANGES.has(targetRange);

      let requestedMin, requestedMax;

      if (isShortRange && dataMin && dataMax) {
        const dataDuration = dataMax - dataMin;

        if (dataDuration < targetRangeMs) {
          const padding = Math.max(dataDuration * 0.05, 2 * 60 * 1000);
          requestedMin = dataMin - padding;
          requestedMax = dataMax + padding;
        } else {
          requestedMin = dataMax - targetRangeMs;
          requestedMax = dataMax;
        }
      } else {
        requestedMax = Math.max(dataMax, now);
        requestedMin = requestedMax - targetRangeMs;
      }

      targetChart.options.scales.x.min = requestedMin;
      targetChart.options.scales.x.max = requestedMax;

      updateSingleChartTimeFormat(targetChart, requestedMin, requestedMax);

      // Update subtitle based on data coverage
      const dataDuration = dataMax - dataMin;
      const dataDays = Math.ceil(dataDuration / (1000 * 60 * 60 * 24));
      const requestedDays = Math.ceil(targetRangeMs / (1000 * 60 * 60 * 24));

      if (isShortRange && dataDays < requestedDays) {
        if (dataDays < 1) {
          const dataHours = Math.ceil(dataDuration / (1000 * 60 * 60));
          subtitle.text = `Optimalizované zobrazenie - dostupné ${dataHours}h dát`;
        } else {
          subtitle.text = `Optimalizované zobrazenie - dostupné ${dataDays}d dát`;
        }
        subtitle.color = '#10b981';
      } else if (!isShortRange && dataDays < requestedDays) {
        subtitle.text = `Zobrazený ${getTimeRangeLabel(targetRange)} horizont - dostupné ${dataDays}d z ${requestedDays}d`;
        subtitle.color = '#fbbf24';
      } else {
        subtitle.text = `Zobrazené všetky dostupné dáta za ${getTimeRangeLabel(targetRange)}`;
        subtitle.color = '#9ca3af';
      }

      // Mark as permanently expanded
      if (!window._expandedCharts) window._expandedCharts = new Set();
      window._expandedCharts.add(chartId);

      // Update visual time range indicator
      updateVisualTimeRangeIndicator(targetRange);

      targetChart.update('active');
    })
    .catch(error => {
      console.error('Range expansion load failed:', error);
      subtitle.text = 'Chyba pri načítaní dát - skúste znovu';
      subtitle.color = '#ef4444';
      targetChart.update('none');
    });

  return true; // Async loading started
}
```

### API Endpoints for Monitoring

**Device Settings:**
```python
GET /api/monitoring/device/<device_id>/settings
Returns:
{
  "device_id": int,
  "ping_interval_seconds": int,      # 0 = use global
  "ping_retry_interval_seconds": int,
  "snmp_interval_minutes": int,
  "monitoring_paused": bool,
  "global_ping_interval": int,
  "global_ping_retry_interval": int,
  "global_snmp_interval": int
}

POST /api/monitoring/device/<device_id>/settings
Body: {
  "ping_interval_seconds": int,
  "ping_retry_interval_seconds": int,
  "snmp_interval_minutes": int
}
Returns: {"status": "success"}
```

**Pause/Resume:**
```python
POST /api/monitoring/device/<device_id>/pause
Toggles monitoring_paused flag
Emits device_status WebSocket event
Returns: {"status": "success", "paused": bool}
```

**Historical Data:**
```python
GET /api/monitoring/history/<device_id>?range=<timeRange>&optimized=<0|1>

Query Parameters:
- range: recent, 3h, 6h, 12h, 24h, 7d, 30d, 90d, 1y
- optimized: If 1, return limited dataset for fast UI (short ranges only)

Returns:
{
  "ping_data": [
    {
      "timestamp": str (ISO),
      "avg_latency": float,
      "status": str ("online"/"offline"),
      "packet_loss": int
    }
  ],
  "snmp_data": [
    {
      "timestamp": str (ISO),
      "cpu_load": int,
      "temperature": int,
      "used_memory": int,
      "total_memory": int,
      "free_memory": int,
      "uptime": int
    }
  ],
  "latest_ping": {
    "timestamp": str,
    "avg_latency": float,
    "status": str
  },
  "device_info": {
    "id": int,
    "name": str,
    "ip": str,
    "status": str,
    "monitoring_paused": bool
  }
}

Optimized Loading:
if optimized and time_range in ['recent', '3h', '6h', '12h', '24h']:
    ping_data = ping_data[-100:]  # Last 100 points
    snmp_data = snmp_data[-100:]  # Last 100 points
```

### Data Flow

**Initial Load:**
1. User opens monitoring.html
2. DOMContentLoaded → Initialize JavaScript
3. Load devices → Populate dropdown
4. Restore state from localStorage
5. If device selected: Initialize charts, load historical data
6. Initialize Socket.IO → Connect WebSocket
7. Start Y-axis optimization (every 30s)

**Device Selection:**
1. User clicks device in dropdown
2. Update currentDeviceId
3. Load historical data: `/api/monitoring/history/<id>?range=24h`
4. Process ping data → Update ping chart
5. Process SNMP data → Update CPU/temp/memory charts
6. Apply Y-axis optimizations
7. Apply full time range to all charts
8. Update header metrics (uptime, latency)

**Time Range Change:**
1. User clicks time range button (e.g., "7d")
2. Update active button state
3. Reset X-axis limits for short ranges
4. Update chart time formats
5. Reload data: `/api/monitoring/history/<id>?range=7d`
6. Apply full time range to all charts
7. Stabilize axis (short ranges only)
8. Save state to localStorage

**Real-Time Updates (WebSocket):**
```
Backend emits ping_update:
  1. Update device status in selector (always)
  2. If page visible AND device selected:
     - Update ping status card
     - Append to ping chart
     - Recalculate uptime/latency

Backend emits snmp_update:
  1. If page visible AND device selected:
     - Append to CPU/temp/memory charts
     - Update device model (if present)
     - Limit datasets to 1000 points
```

**Refresh Button:**
1. User clicks Refresh
2. Check if optimized load applicable (short range + refresh operation)
3. With optimized:
   - Fetch last ~100 points → Instant UI update
   - Schedule full load 1.5s later
   - Block metric updates during partial load
4. Without optimized:
   - Fetch full dataset
5. Show loading animation (sweep + fade)

**Chart Zoom:**

*Zoom In (Drag Selection):*
1. User drags on chart
2. Selection box drawn during drag
3. On mouseup:
   - Calculate selected time range
   - Set chart.options.scales.x.min/max
   - Update time format for zoom level
   - Update subtitle
4. Chart updates with zoomed view

*Zoom Out (Progressive):*
1. User clicks zoom-out button or double-clicks
2. Check zoom state:
   - If real zoom: Expand by 2.5x around center
   - If full range: Load next larger time range
3. Progressive zoom:
   - Apply new min/max
   - Update format
   - Check if reached data limits
4. Load larger range:
   - Fetch next range (30m→3h→6h→...→1y)
   - Update chart data
   - Mark as "permanently expanded"

### Performance Optimizations

**DOM Operations:**
- Cache frequently-used elements in `domCache`
- Batch updates with `requestAnimationFrame`
- Group all mutations in single frame

**Chart Rendering:**
- `chart.update('none')`: No animation (instant)
- `pointRadius = 0`: No visible points (cleaner, faster)
- `pointHoverRadius = 0`: No hover points (prevents lag)
- Y-axis optimization: Only every 30s when visible

**Data Loading:**
- Optimized refresh: Partial + full load strategy
- WebSocket updates: Only if page visible
- Dataset size limits: 500-1000 points max
- Automatic shifting of old data

**Memory Management:**
- Debug logging: Limited to 500 entries, disabled when off
- Chart data: Auto-shift old points
- Cached ping history: Limited to 2000 points
- State persistence: Minimal localStorage usage

### Mobile vs Desktop Differences

| Feature | Desktop | Mobile |
|---------|---------|--------|
| **Chart Grid** | 2 columns | 1 column |
| **Status Cards** | 4 columns | 2x2 grid |
| **Header** | Horizontal row | Vertical stack |
| **Time Range** | Inline buttons | Horizontal scroll |
| **Action Buttons** | Full text | Icons (<480px) |
| **Chart Height** | 300px | 300px (shifted -20px) |
| **Zoom Controls** | Overlay | Inline button |
| **Fonts** | 13-14px | 11-13px |
| **Padding** | Standard | Reduced |
| **Tooltip** | Hover | Tap + 6s timeout |

### Technical Summary

**Lines of Code:** ~8000 total
- monitoring.html: ~4200 lines
- monitoring.js: ~3800 lines

**Dependencies (CDN):**
- Tailwind CSS, Font Awesome 6.0
- Socket.IO 4.4.1
- Chart.js + date-fns + chartjs-adapter-date-fns

**Performance:**
- Initial load: 1-2s
- Refresh: <500ms (optimized)
- Real-time update: <50ms
- WebSocket latency: 20-100ms
- Memory: ~30-50MB heap

**Key Innovations:**
1. Custom zoom system with progressive zoom-out
2. Optimized refresh (partial + full load)
3. Smart Y-axis positioning algorithms
4. Intelligent SNMP gap detection
5. Duration-based uptime/latency calculation
6. Forward-fill memory to prevent truncation
7. Per-chart independent time ranges
8. Complete dark/light theme system
9. Advanced mobile optimizations

---

## Development Guidelines

### Code Conventions

**Python Style**
- Follow PEP 8 style guide
- Use type hints where appropriate
- Function names: `snake_case`
- Class names: `PascalCase`
- Constants: `UPPER_SNAKE_CASE`

**Database Queries**
- Use context managers for database connections: `with get_db_connection() as conn`
- Always use parameterized queries to prevent SQL injection
- Close cursors explicitly

**Error Handling**
- Catch specific exceptions, not bare `except:`
- Log errors with `add_log('error', message, device_ip)`
- Emit SocketIO events for frontend notifications

**Logging**
```python
# Use add_log() function for database logging
add_log('info', 'Backup started', device_ip)
add_log('warning', 'High CPU detected', device_ip)
add_log('error', 'Connection failed', device_ip)

# Use debug_log() for debug-level logging
debug_log('terminal', 'SSH command executed')
debug_log('snmp', 'SNMP query sent')
```

### Testing

**Manual Testing Checklist**
1. Device addition/deletion/editing
2. Backup creation (manual and scheduled)
3. SNMP data retrieval
4. Ping monitoring status changes
5. 2FA setup and login flow
6. Password/username changes
7. FTP upload functionality
8. Pushover notifications
9. Backup file download/deletion
10. Settings persistence

**Database Migration**
```bash
# Backup database before changes
cp /var/lib/mikrotik-manager/data/mikrotik_manager.db backup.db

# Test migration on backup
sqlite3 backup.db < migration.sql

# Apply to production
sqlite3 /var/lib/mikrotik-manager/data/mikrotik_manager.db < migration.sql
```

## Deployment

### Production Deployment

**Systemd Service**
```ini
# /etc/systemd/system/mikrotik-manager.service
[Unit]
Description=MikroTik Manager
After=network.target

[Service]
Type=simple
User=mikrotik-manager
WorkingDirectory=/opt/mikrotik-manager
Environment="PATH=/opt/mikrotik-manager/venv/bin"
ExecStart=/opt/mikrotik-manager/venv/bin/python app.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

**Nginx Reverse Proxy (HTTPS)**
```nginx
server {
    listen 443 ssl;
    server_name mikrotik.example.com;

    ssl_certificate /etc/letsencrypt/live/mikrotik.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/mikrotik.example.com/privkey.pem;

    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        # WebSocket support
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_read_timeout 86400;
    }
}
```

### Update Procedure
```bash
# 1. Stop service
sudo systemctl stop mikrotik-manager

# 2. Backup database and keys
cp -r /var/lib/mikrotik-manager/data /backup/

# 3. Pull latest code
cd /opt/mikrotik-manager
git pull origin main

# 4. Update dependencies
source venv/bin/activate
pip install -r requirements.txt --upgrade

# 5. Start service
sudo systemctl start mikrotik-manager

# 6. Check status
sudo systemctl status mikrotik-manager
journalctl -u mikrotik-manager -f
```

## Android APK Build

**Build Process**
```bash
cd /opt/mikrotik-manager
bash build-apk.sh

# Output: /opt/MT Manager.apk (6.2 MB)
# - Native Android Kotlin WebView
# - Optimized splash screen
# - Network-themed icon
# - Android 7+ (API 24+) compatible
# - Android 15 optimized
```

**Template Files**
```
template/
├── MainActivity.kt          # WebView activity with status bar handling
├── SetupActivity.kt         # Server URL configuration
├── AndroidManifest.xml      # Permissions and app config
├── activity_main.xml        # Main layout
├── activity_setup.xml       # Setup layout
├── build.gradle             # Android build configuration
└── res/
    ├── values/strings.xml   # App name and strings
    ├── values/styles.xml    # Android themes
    └── mipmap-*/            # App icons
```

## Troubleshooting

### Common Issues

**Database locked errors**
- Cause: Multiple threads accessing SQLite without proper connection management
- Solution: Use `with get_db_connection() as conn` context manager

**SSH timeout errors**
- Cause: Network issues, firewall, or SSH service disabled
- Solution: Test with `ssh user@device-ip` manually, check MikroTik `/ip service`

**SNMP timeout**
- Cause: SNMP service disabled, wrong community, firewall blocking UDP 161
- Solution: Enable SNMP on MikroTik, verify community string

**WebSocket connection failed**
- Cause: Reverse proxy not configured for WebSocket upgrade
- Solution: Add `proxy_set_header Upgrade` and `Connection "upgrade"` headers

**Session invalidation after restart**
- Cause: Missing or corrupted secret.key file
- Solution: File is auto-created, check permissions (chmod 600)

## Important Notes for AI Assistants

### When Making Changes

**Database Modifications**
- Always create backup before schema changes
- Test migrations on backup copy first
- Update `init_database()` function for new tables/columns

**Security Changes**
- Never weaken encryption or authentication
- Test 2FA flow thoroughly after changes
- Verify password encryption/decryption after key changes

**Monitoring Changes**
- Consider impact on database size (history tables)
- Test background threads don't block main thread
- Verify SocketIO events reach frontend

**Frontend Changes**
- Maintain responsiveness (mobile/tablet/desktop)
- Test WebSocket reconnection logic
- Verify chart.js graph rendering

### Files to Avoid Modifying
- `secret.key` - Flask session key (auto-generated)
- `encryption.key` - Password encryption key (auto-generated)
- `mikrotik_manager.db` - Database (modify only via SQL)
- Template files - Android build dependencies

### Files Safe to Modify
- `app.py` - Main application logic
- HTML templates - UI changes
- `static/js/*` - Frontend JavaScript
- `requirements.txt` - Python dependencies
- Settings via web interface - Stored in settings table

## Additional Resources

- **README.md**: Installation and setup instructions
- **manual.md**: Comprehensive 1600+ line user manual (SK language)
- **Repository**: https://github.com/spekulanter/mikrotik-manager
- **MikroTik RouterOS**: https://help.mikrotik.com/docs/

## Environment Variables

```bash
# Optional environment variable
DATA_DIR=/var/lib/mikrotik-manager/data  # Default if not set

# Affects:
# - DB_PATH = ${DATA_DIR}/mikrotik_manager.db
# - BACKUP_DIR = ${DATA_DIR}/backups
# - secret.key = ${DATA_DIR}/secret.key
# - encryption.key = ${DATA_DIR}/encryption.key
```

## License & Contact

- **License**: Check repository for license information
- **Author**: spekulanter (GitHub)
- **Language**: Slovak (SK) - User-facing content
- **Code Language**: English - Code comments and variables

---

**Last Updated**: 2026-02-15
**Version**: Based on app.py analysis, manual.md documentation, and comprehensive monitoring system analysis
