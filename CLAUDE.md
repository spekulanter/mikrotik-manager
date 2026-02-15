# MikroTik Manager - Claude AI Guide

## Project Overview

**MikroTik Manager** is a comprehensive web-based management system for MikroTik RouterOS devices. It provides centralized device management, automated backups, real-time monitoring, and remote access through both web interface and native Android application.

### Key Features
- **Device Management**: Centralized management of multiple MikroTik RouterOS devices
- **Automated Backups**: Scheduled backup creation with FTP upload support
- **Real-time Monitoring**: ICMP ping and SNMP-based monitoring with historical graphs
- **Security**: Mandatory 2FA authentication, encrypted password storage (Fernet AES-128)
- **Mobile Support**: Native Android APK with Kotlin WebView
- **Notifications**: Pushover notifications for device status and backup events

### Technology Stack
- **Backend**: Python 3.11, Flask, Flask-SocketIO, Eventlet
- **Frontend**: HTML, JavaScript (vanilla), Chart.js for graphs
- **Database**: SQLite3 with encrypted password columns
- **Authentication**: Flask-Login, PyOTP (TOTP), bcrypt
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
    password TEXT NOT NULL,              -- Encrypted with Fernet
    low_memory BOOLEAN DEFAULT 0,
    snmp_community TEXT DEFAULT 'public',
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
    password TEXT NOT NULL,              -- bcrypt hash
    totp_secret TEXT,
    totp_enabled BOOLEAN NOT NULL DEFAULT 0
);

-- 2FA backup codes
CREATE TABLE backup_codes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    code TEXT NOT NULL,
    created_at TIMESTAMP NOT NULL,
    used BOOLEAN NOT NULL DEFAULT 0,
    used_at TIMESTAMP,
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

**Password Encryption (Fernet AES-128)**
```python
# Encryption key: /var/lib/mikrotik-manager/data/encryption.key
# - 44 bytes (32 bytes key + 12 bytes nonce)
# - chmod 600 (owner read/write only)
# - Used for: SSH passwords, FTP passwords

def encrypt_password(password):
    cipher = Fernet(get_encryption_key())
    return cipher.encrypt(password.encode()).decode()

def decrypt_password(encrypted_password):
    cipher = Fernet(get_encryption_key())
    return cipher.decrypt(encrypted_password.encode()).decode()
```

**User Password Hashing (bcrypt)**
```python
from werkzeug.security import generate_password_hash, check_password_hash

# Cost factor: 12 (default)
# Stored in users.password column
password_hash = generate_password_hash(password)
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
- 10 single-use backup codes per user
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
pushover_app_key: str = ''
pushover_user_key: str = ''
```

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

**Last Updated**: 2026-02-14
**Version**: Based on app.py analysis and manual.md documentation
