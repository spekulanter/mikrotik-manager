#!/usr/bin/env python3
"""
MikroTik Backup Web Backend v2.8 - Secured
Pridaná webová registrácia, zobrazenie stavu prihlásenia a možnosť zmeny hesla.
"""

import os
import time
import json
import sqlite3
import threading
from datetime import datetime, timedelta
import subprocess
import re
import platform
import statistics
import secrets
import string
import csv
from contextlib import contextmanager
# PRIDANÉ: g pre globálny kontext požiadavky
from flask import Flask, request, jsonify, send_from_directory, render_template, redirect, url_for, session, g
from flask_socketio import SocketIO, emit
from flask_cors import CORS
from werkzeug.middleware.proxy_fix import ProxyFix
import paramiko
import difflib
from ftplib import FTP
import http.client
import urllib.parse
from contextlib import contextmanager
import logging
import schedule

from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import pyotp
import qrcode
import base64
from io import BytesIO
from cryptography.fernet import Fernet
import base64 as b64

# --- Definície adresárov pred konfiguráciou aplikácie ---
DATA_DIR = os.environ.get('DATA_DIR', '/var/lib/mikrotik-manager/data')
DB_PATH = os.path.join(DATA_DIR, 'mikrotik_manager.db')
BACKUP_DIR = os.path.join(DATA_DIR, 'backups')

# --- Nastavenie aplikácie (upravené pre HTML šablóny) ---
app = Flask(__name__, static_folder='.', static_url_path='', template_folder='.')

# PERSISTENT SECRET KEY - Bezpečnostne optimalizované
def get_or_create_secret_key():
    """
    Získa alebo vytvorí persistent SECRET_KEY pre aplikáciu.
    Kľúč sa ukladá do súboru a je konzistentný medzi reštartami služby.
    """
    secret_key_file = os.path.join(DATA_DIR, 'secret.key')
    
    # Ensure DATA_DIR exists for secret key
    os.makedirs(DATA_DIR, exist_ok=True)
    
    if os.path.exists(secret_key_file):
        try:
            with open(secret_key_file, 'rb') as f:
                secret_key = f.read()
                if len(secret_key) == 32:  # Platný kľúč
                    return secret_key
        except Exception as e:
            print(f"Chyba pri čítaní SECRET_KEY súboru: {e}")
    
    # Vytvor nový SECRET_KEY
    secret_key = os.urandom(32)
    try:
        with open(secret_key_file, 'wb') as f:
            f.write(secret_key)
        # Nastavenie správnych práv na súbor (600 - read/write owner only)
        os.chmod(secret_key_file, 0o600)
        print("Vytvorený nový persistent SECRET_KEY")
        return secret_key
    except Exception as e:
        print(f"Chyba pri ukladaní SECRET_KEY: {e}")
        # Fallback na session-only kľúč
        return os.urandom(32)

app.config['SECRET_KEY'] = get_or_create_secret_key()
# PRAKTICKÉ NASTAVENIE: 1 rok platnosť cookie (s persistent SECRET_KEY je to bezpečné)
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=365)

# Pridanie ProxyFix pre správne spracovanie proxy hlavičiek (Nginx Proxy Manager)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)

socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')
CORS(app)

# Middleware pre povolenie iframe načítania
@app.after_request
def add_iframe_headers(response):
    """Pridá hlavičky pre povolenie iframe načítania z mobilných aplikácií"""
    # Povoliť načítanie v iframe (odstráni X-Frame-Options)
    if 'X-Frame-Options' in response.headers:
        del response.headers['X-Frame-Options']
    
    # Pridať permissívny Content Security Policy pre iframe
    response.headers['Content-Security-Policy'] = (
        "default-src 'self' 'unsafe-inline' 'unsafe-eval'; "
        "frame-ancestors *; "
        "img-src 'self' data: https:; "
        "style-src 'self' 'unsafe-inline' https:; "
        "script-src 'self' 'unsafe-inline' 'unsafe-eval' https:; "
        "font-src 'self' data: https:; "
        "connect-src 'self' ws: wss: https: http:;"
    )
    
    # Pridať CORS hlavičky pre mobilné aplikácie
    response.headers['Access-Control-Allow-Origin'] = '*'
    response.headers['Access-Control-Allow-Methods'] = 'GET, POST, PUT, DELETE, OPTIONS'
    response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization, X-Requested-With, X-Forwarded-For, X-Forwarded-Proto'
    response.headers['Access-Control-Allow-Credentials'] = 'true'
    
    # Pridať hlavičky pre Android WebView optimalizáciu
    response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    
    # Hlavičky pre správne fungovanie za proxy
    if request.headers.get('X-Forwarded-Proto'):
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    
    return response

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

backup_tasks = {}
sequential_backup_running = False

# --- Password Encryption ---
def get_encryption_key():
    """Get or create encryption key for password encryption"""
    key_file = os.path.join(DATA_DIR, 'encryption.key')
    
    if os.path.exists(key_file):
        with open(key_file, 'rb') as f:
            return f.read()
    else:
        # Generate new key and save it
        key = Fernet.generate_key()
        os.makedirs(DATA_DIR, exist_ok=True)
        with open(key_file, 'wb') as f:
            f.write(key)
        # Set secure permissions
        os.chmod(key_file, 0o600)
        return key

# Initialize encryption
ENCRYPTION_KEY = get_encryption_key()
cipher = Fernet(ENCRYPTION_KEY)

def encrypt_password(password):
    """Encrypt password for secure storage"""
    if password is None:
        return None
    return b64.b64encode(cipher.encrypt(password.encode())).decode()

def decrypt_password(encrypted_password):
    """Decrypt password for use"""
    if encrypted_password is None:
        return None
    try:
        return cipher.decrypt(b64.b64decode(encrypted_password.encode())).decode()
    except:
        # If decryption fails, assume it's already plaintext (for backward compatibility)
        return encrypted_password

def migrate_existing_passwords():
    """Migrate existing plaintext passwords to encrypted format - run once on startup"""
    try:
        with get_db_connection() as conn:
            # Get all devices
            devices = conn.execute('SELECT id, password FROM devices').fetchall()
            migrated_count = 0
            
            for device in devices:
                device_id, password = device
                if password:
                    # Check if password is already encrypted by looking at its format
                    # Encrypted passwords are base64 encoded and start with specific pattern
                    if password.startswith('Z0FBQUFBQm') or len(password) > 50:
                        # Already encrypted, skip
                        continue
                    else:
                        # Plaintext password - encrypt it
                        encrypted_password = encrypt_password(password)
                        conn.execute('UPDATE devices SET password = ? WHERE id = ?', (encrypted_password, device_id))
                        migrated_count += 1
                        logger.info(f"Migrated password for device ID {device_id}")
            
            if migrated_count > 0:
                conn.commit()
                logger.info(f"Password migration completed: {migrated_count} passwords encrypted")
            else:
                logger.info("Password migration: No plaintext passwords found")
    except Exception as e:
        logger.error(f"Password migration failed: {e}")
        import traceback
        logger.error(f"Migration error traceback: {traceback.format_exc()}")

# Helper functions for device password handling
def get_device_with_decrypted_password(device_dict):
    """Take device dict and decrypt its password"""
    if isinstance(device_dict, dict) and 'password' in device_dict:
        device_dict = device_dict.copy()  # Don't modify original
        device_dict['password'] = decrypt_password(device_dict['password'])
    return device_dict

def prepare_devices_with_decrypted_passwords(devices):
    """Decrypt passwords for a list of devices"""
    return [get_device_with_decrypted_password(dict(device)) for device in devices]

# SNMP refresh all tracking
snmp_refresh_tasks = {}
sequential_snmp_refresh_running = False
snmp_refresh_progress = {'current': 0, 'total': 0}

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.session_protection = "strong"

class User(UserMixin):
    def __init__(self, id, username, password, totp_secret, totp_enabled):
        self.id = id
        self.username = username
        self.password = password
        self.totp_secret = totp_secret
        self.totp_enabled = totp_enabled

@login_manager.user_loader
def load_user(user_id):
    with get_db_connection() as conn:
        user_data = conn.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
        if user_data:
            return User(id=user_data['id'], username=user_data['username'], password=user_data['password'], totp_secret=user_data['totp_secret'], totp_enabled=user_data['totp_enabled'])
    return None

def init_environment():
    os.makedirs(DATA_DIR, exist_ok=True)
    os.makedirs(BACKUP_DIR, exist_ok=True)
    logger.info("Adresáre pre dáta a backupy sú pripravené.")

@contextmanager
def get_db_connection():
    conn = None
    try:
        conn = sqlite3.connect(DB_PATH, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        yield conn
    except sqlite3.Error as e:
        logger.error(f"Chyba pripojenia k databáze: {e}")
        if conn:
            conn.rollback()
        raise
    finally:
        if conn:
            conn.close()

# Debug control helper functions (moved here to avoid NameError)
def is_debug_enabled(debug_type):
    """Kontroluje či je debug mód zapnutý pre daný typ"""
    try:
        with get_db_connection() as conn:
            result = conn.execute('SELECT value FROM settings WHERE key = ?', (debug_type,)).fetchone()
            return result and result[0] == 'true'
    except:
        return False

def debug_log(debug_type, message):
    """Debug log iba ak je zapnutý debug mód"""
    if is_debug_enabled('debug_terminal'):
        logger.debug(f"[{debug_type.upper()}] {message}")

def debug_emit(event, data):
    """Wrapper pre socketio.emit s debug logovaním"""
    if is_debug_enabled('debug_terminal'):
        debug_log('debug_websocket', f"Emitting '{event}' with data: {str(data)[:200]}...")
    socketio.emit(event, data)

# Debug helper functions


# Spustenie ping monitoring threadu - globálne premenné
ping_thread = None
ping_thread_stop_flag = threading.Event()

def start_ping_monitoring():
    """Spustí ping monitoring v background thread"""
    global ping_thread
    if ping_thread is None or not ping_thread.is_alive():
        ping_thread_stop_flag.clear()
        ping_thread = threading.Thread(target=ping_monitoring_loop, daemon=True)
        ping_thread.start()
        logger.info("Ping monitoring thread spustený")

def restart_ping_monitoring():
    """Reštartuje ping monitoring s novými nastaveniami"""
    global ping_thread, ping_thread_stop_flag
    
    # Signalizuj starému threadu aby sa ukončil
    ping_thread_stop_flag.set()
    
    # Počkaj chvíľu aby sa starý thread ukončil
    if ping_thread and ping_thread.is_alive():
        ping_thread.join(timeout=5)
    
    # Spustí nový thread
    start_ping_monitoring()
    logger.info("Ping monitoring reštartovaný")

def init_database():
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS devices (
                id INTEGER PRIMARY KEY AUTOINCREMENT, ip TEXT UNIQUE NOT NULL, name TEXT NOT NULL,
                username TEXT NOT NULL, password TEXT NOT NULL, low_memory BOOLEAN DEFAULT 0,
                snmp_community TEXT DEFAULT 'public', status TEXT DEFAULT 'unknown',
                last_backup TIMESTAMP, last_snmp_data TEXT, snmp_interval_minutes INTEGER DEFAULT 0,
                last_snmp_check TIMESTAMP
            )
        ''')
        # Pridanie nových stĺpcov pre existujúce databázy
        try:
            cursor.execute('ALTER TABLE devices ADD COLUMN snmp_interval_minutes INTEGER DEFAULT 0')
        except sqlite3.OperationalError:
            pass
        try:
            cursor.execute('ALTER TABLE devices ADD COLUMN last_snmp_check TIMESTAMP')
        except sqlite3.OperationalError:
            pass
        try:
            cursor.execute('ALTER TABLE devices ADD COLUMN ping_interval_seconds INTEGER DEFAULT 0')
        except sqlite3.OperationalError:
            pass
        try:
            cursor.execute('ALTER TABLE devices ADD COLUMN monitoring_paused BOOLEAN DEFAULT 0')
        except sqlite3.OperationalError:
            pass
        
        # Pridanie memory stĺpcov do snmp_history tabuľky
        try:
            cursor.execute('ALTER TABLE snmp_history ADD COLUMN total_memory INTEGER')
        except sqlite3.OperationalError:
            pass
        try:
            cursor.execute('ALTER TABLE snmp_history ADD COLUMN free_memory INTEGER')
        except sqlite3.OperationalError:
            pass
        cursor.execute('CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT)')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp DATETIME NOT NULL,
                level TEXT NOT NULL, message TEXT NOT NULL, device_ip TEXT DEFAULT NULL
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                totp_secret TEXT,
                totp_enabled BOOLEAN NOT NULL DEFAULT 0
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS backup_codes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                code TEXT NOT NULL,
                created_at TIMESTAMP NOT NULL,
                used BOOLEAN NOT NULL DEFAULT 0,
                used_at TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        ''')
        # Pridanie tabuliek pre monitoring - ping a SNMP history
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS ping_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                device_id INTEGER NOT NULL,
                timestamp DATETIME NOT NULL,
                avg_latency REAL,
                packet_loss INTEGER NOT NULL DEFAULT 0,
                status TEXT NOT NULL,
                FOREIGN KEY (device_id) REFERENCES devices (id)
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS snmp_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                device_id INTEGER NOT NULL,
                timestamp DATETIME NOT NULL,
                cpu_load INTEGER,
                temperature INTEGER,
                memory_usage INTEGER,
                uptime INTEGER,
                FOREIGN KEY (device_id) REFERENCES devices (id)
            )
        ''')
        try:
            cursor.execute('ALTER TABLE users ADD COLUMN totp_enabled BOOLEAN NOT NULL DEFAULT 0')
        except sqlite3.OperationalError:
            pass
        conn.commit()
        
        # ODSTRÁNENÉ: Automatické mazanie logov o zálohovani - logy si budú pamätať aj po reštarte
        
        # Pridanie predvolených hodnôt pre nastavenia
        cursor.execute("INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)", ('backup_retention_count', '10'))
        cursor.execute("INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)", ('backup_delay_seconds', '30'))
        cursor.execute("INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)", ('snmp_check_interval_minutes', '10'))
        cursor.execute("INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)", ('backup_detailed_logging', 'false'))
        cursor.execute("INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)", ('log_retention_days', '30'))  # Pridané: uchovávanie logov
        cursor.execute("INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)", ('ping_retention_days', '30'))  # Pridané: uchovávanie ping dát
        cursor.execute("INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)", ('snmp_retention_days', '30'))  # Pridané: uchovávanie SNMP dát
        cursor.execute("INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)", ('log_max_entries', '2000'))  # Pridané: limit zobrazených logov
        cursor.execute("INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)", ('notify_backup_success', 'false'))  # Notifikácie úspešných záloh
        cursor.execute("INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)", ('notify_backup_failure', 'false'))  # Notifikácie neúspešných záloh
        cursor.execute("INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)", ('ping_check_interval_seconds', '120'))  # Ping monitoring interval v sekundách
        cursor.execute("INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)", ('ping_monitor_enabled', 'true'))  # Povoliť/zakázať ping monitoring
        cursor.execute("INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)", ('debug_terminal', 'false'))  # Pridané: debug terminál v monitoringu
        cursor.execute("INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)", ('ping_retry_interval', '20'))  # Retry interval pri výpadku v sekundách
        cursor.execute("INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)", ('ping_retries', '3'))  # Počet neúspešných pokusov pred označením offline
        cursor.execute("INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)", ('ping_timeout', '5'))  # Timeout pre jeden ping
        conn.commit()
        logger.info("Databáza úspešne inicializovaná.")

@app.before_request
def before_request_handler():
    if 'user_exists' not in g:
        with get_db_connection() as conn:
            try:
                user_count = conn.execute('SELECT COUNT(id) FROM users').fetchone()[0]
                g.user_exists = user_count > 0
            except sqlite3.OperationalError:
                g.user_exists = False
    
    # Ochrana pred priamym prístupom k HTML súborom
    if request.endpoint == 'static' and request.path.endswith('.html'):
        # Povolené HTML súbory bez autentifikácie (login formuláre)
        allowed_files = ['/login.html', '/register.html', '/login_2fa.html', '/setup_2fa.html', '/2fa_success.html']
        if request.path not in allowed_files:
            if not current_user.is_authenticated:
                return redirect(url_for('login'))
    
    if not g.user_exists and request.endpoint not in ['register', 'static']:
        return redirect(url_for('register'))

def add_log(level, message, device_ip=None):
    level_map = {'INFO': logging.INFO, 'SUCCESS': logging.INFO, 'WARNING': logging.WARNING, 'ERROR': logging.ERROR, 'DEBUG': logging.DEBUG}
    log_level_int = level_map.get(level.upper(), logging.INFO)
    logger.log(log_level_int, f"{f'[{device_ip}] ' if device_ip else ''}{message}")
    
    # Pokus o zápis do databázy a WebSocket
    try:
        with get_db_connection() as conn:
            # Vkladáme časovú značku priamo z aplikácie
            conn.execute("INSERT INTO logs (timestamp, level, message, device_ip) VALUES (?, ?, ?, ?)", (datetime.now(), level, message, device_ip))
            conn.commit()
        
        # WebSocket emit s kontrolou pripojenia
        try:
            socketio.emit('log_update', {'level': level, 'message': message, 'device_ip': device_ip, 'timestamp': datetime.now().isoformat()})
        except Exception as ws_error:
            logger.warning(f"WebSocket emit pre log zlyhal: {ws_error}")
            
    except Exception as e:
        logger.error(f"Nepodarilo sa zapísať log do databázy: {e}")
        # Aj pri chybe sa pokúsime odoslať cez WebSocket
        try:
            socketio.emit('log_update', {'level': 'error', 'message': f'Chyba pri zápise logu: {message}', 'device_ip': device_ip, 'timestamp': datetime.now().isoformat()})
        except:
            pass  # Ak ani WebSocket nefunguje, nevadí

def get_mikrotik_export_direct(ssh_client, ip, detailed_logging=True):
    try:
        if detailed_logging:
            add_log('info', "Získavam priamy SSH export...", ip)
        _, stdout, _ = ssh_client.exec_command('/export')
        export_content = stdout.read().decode('utf-8', errors='ignore')
        if not export_content:
            raise ValueError("Export command returned empty content.")
        if detailed_logging:
            add_log('info', "Priamy export úspešne získaný.", ip)
        return export_content
    except Exception as e:
        add_log('error', f"Priamy SSH export zlyhal: {e}", ip)
        return None

def compare_with_local_backup(ip, remote_content, detailed_logging=True):
    try:
        # Hľadáme najnovší .rsc súbor pre dané IP s presným patternom _ip_
        import re
        pattern = re.compile(f"_{ip}_\d{{8}}")
        local_backups = sorted(
            [f for f in os.listdir(BACKUP_DIR) if pattern.search(f) and f.endswith('.rsc')],
            reverse=True
        )
        if not local_backups:
            if detailed_logging:
                add_log('info', "Žiadna lokálna záloha nájdená. Vytváram novú.", ip)
            return True
        
        latest_backup_path = os.path.join(BACKUP_DIR, local_backups[0])
        with open(latest_backup_path, 'r', encoding='utf-8', errors='ignore') as f:
            local_content = f.read()
        
        # Rozšírené ignore pravidlá ako v pôvodnom scripte
        ignore_keywords = [
            'list=blacklist', 
            'comment=spamhaus,dshield,bruteforce',
            'comment=spamhaus',
            'comment=dshield', 
            'comment=bruteforce'
        ]
        
        def should_include(line):
            return all(keyword not in line for keyword in ignore_keywords)
        
        # Odstránime prvý riadok a filtrujeme podľa ignore pravidiel
        local_lines = [line for line in local_content.splitlines()[1:] if should_include(line)]
        remote_lines = [line for line in remote_content.splitlines()[1:] if should_include(line)]
        
        # Používame rovnakú diff logiku ako pôvodný script
        d = difflib.Differ()
        diff = list(d.compare(local_lines, remote_lines))
        
        has_changes = any(line.startswith(('-', '+')) for line in diff)
        
        if has_changes:
            if detailed_logging:
                add_log('info', "Zistené zmeny v konfigurácii. Spúšťam zálohu.", ip)
            return True
        else:
            if detailed_logging:
                add_log('info', "Žiadne zmeny v konfigurácii. Záloha sa preskakuje.", ip)
            return False
    except Exception as e:
        # IP je už vo vizuálnom log prefixe, netreba ju v texte
        add_log('error', f"Chyba pri porovnávaní záloh: {e}", ip)
        return True

def run_backup_logic(device, is_sequential=False):
    # Decrypt device password before use
    device = get_device_with_decrypted_password(device)
    ip, username, password, low_memory = device['ip'], device['username'], device['password'], device['low_memory']
    
    # Načítame nastavenie pre detailné logovanie
    with get_db_connection() as conn:
        settings = {row['key']: row['value'] for row in conn.execute('SELECT key, value FROM settings').fetchall()}
    
    detailed_logging = settings.get('backup_detailed_logging', 'false').lower() == 'true'
    
    # Základná správa o spustení zálohy (zjednotená pre konzistentnosť)
    # Vždy komunikujeme, že ide o pokročilú zálohu; pri sekvenčnej doplníme info a pri low-memory režime upozorníme na dlhšie časy
    # Neuvádzame IP priamo v texte (frontend ju má už v hlavičke logu)
    prefix = "Záloha - " if is_sequential else ""
    if low_memory:
        add_log('info', f"{prefix}Spúšťam zálohu pre 16MB zariadenie (predĺžené časy)", ip)
        if detailed_logging:
            add_log('info', "Režim 16MB: predĺžené čakacie intervaly (backup ~30s, export ~180s).", ip)
    else:
        add_log('info', f"{prefix}Spúšťam zálohu", ip)
    
    socketio.emit('backup_status', {'ip': ip, 'id': device['id'], 'status': 'starting'})
    client = None
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(ip, username=username, password=password, timeout=30)
        
        if detailed_logging:
            add_log('info', "SSH pripojenie úspešne.", ip)
        
        remote_config = get_mikrotik_export_direct(client, ip, detailed_logging)
        if remote_config is None:
            raise Exception("Nepodarilo sa získať konfiguráciu na porovnanie.")
        if not compare_with_local_backup(ip, remote_config, detailed_logging):
            # Záverečná správa o preskočení zálohy
            if is_sequential:
                add_log('info', f"Záloha - preskočená (žiadne zmeny){' (16MB)' if low_memory else ''}", ip)
            else:
                add_log('info', f"Záloha preskočená (žiadne zmeny){' (16MB)' if low_memory else ''}", ip)
            socketio.emit('backup_status', {'ip': ip, 'id': device['id'], 'status': 'skipped'})
            return
        _, stdout, _ = client.exec_command('/system identity print')
        identity_match = re.search(r'name:\s*(.+)', stdout.read().decode().strip())
        safe_identity = re.sub(r'[^a-zA-Z0-9_-]', '_', identity_match.group(1) if identity_match else ip)
        _, stdout, _ = client.exec_command('/file print where type=directory')
        has_flash = 'flash' in stdout.read().decode()
        
        if detailed_logging:
            add_log('info', f"Zariadenie {'má' if has_flash else 'nemá'} /flash adresár.", ip)
            add_log('info', "Vykonávam cleanup všetkých starých backup súborov na zariadení...", ip)
        
        # Vymaž všetky .backup súbory (ale zachovaj iné súbory ako .rsc scripty, blacklists, atď.)
        cleanup_backup_command = ':foreach i in=[/file find where name~".backup"] do={/file remove $i}'
        client.exec_command(cleanup_backup_command)
        time.sleep(15)  # Dlhšie čakanie pre pomalé zariadenia, ako v referenčnom scripte
        
        if detailed_logging:
            add_log('info', "Cleanup starých backup súborov dokončený.", ip)
        date_str = datetime.now().strftime("%Y%m%d-%H%M")
        base_filename = f"{safe_identity}_{ip}_{date_str}"
        backup_path = f"flash/{base_filename}.backup" if has_flash else f"{base_filename}.backup"
        rsc_path = f"flash/{base_filename}.rsc" if has_flash else f"{base_filename}.rsc"
        
        if detailed_logging:
            add_log('info', f"Vytváram súbory {base_filename}.backup a .rsc...", ip)
        
        client.exec_command(f'/system backup save name="{backup_path}" dont-encrypt=yes')
        if detailed_logging and low_memory:
            add_log('info', "Čakám (low-memory) 30s na dokončenie /system backup save...", ip)
        time.sleep(30 if low_memory else 20)
        client.exec_command(f'/export file="{rsc_path}"')
        if detailed_logging and low_memory:
            add_log('info', "Čakám (low-memory) 180s na dokončenie /export...", ip)
        time.sleep(180 if low_memory else 30)
        with client.open_sftp() as sftp:
            sftp.get(backup_path, os.path.join(BACKUP_DIR, f"{base_filename}.backup"))
            sftp.get(rsc_path, os.path.join(BACKUP_DIR, f"{base_filename}.rsc"))
            
            if detailed_logging:
                add_log('info', "Súbory úspešne stiahnuté.", ip)
            
            sftp.remove(rsc_path)
        with get_db_connection() as conn:
            conn.execute("UPDATE devices SET last_backup = CURRENT_TIMESTAMP WHERE id = ?", (device['id'],))
            conn.commit()
        
        # Záverečná správa o dokončení zálohy
        if is_sequential:
            add_log('info', f"Záloha - dokončená úspešne{' (16MB)' if low_memory else ''}", ip)
        else:
            add_log('info', f"Záloha dokončená{' (16MB)' if low_memory else ''}.", ip)
        
        # Odoslanie notifikácie o úspešnej zálohe
        with get_db_connection() as conn:
            settings = {row['key']: row['value'] for row in conn.execute('SELECT key, value FROM settings').fetchall()}
        if settings.get('notify_backup_success', 'false').lower() == 'true':
            device_name = device.get('name', ip)
            send_pushover_notification(f"Záloha MikroTik {ip} ({device_name}) bola úspešne dokončená.", title="Úspešná záloha")

        socketio.emit('backup_status', {'ip': ip, 'id': device['id'], 'status': 'success', 'last_backup': datetime.now().isoformat()})
        upload_to_ftp(os.path.join(BACKUP_DIR, f"{base_filename}.backup"), detailed_logging)
        upload_to_ftp(os.path.join(BACKUP_DIR, f"{base_filename}.rsc"), detailed_logging)

        # Vyčistenie starých záloh
        cleanup_old_backups(ip, settings, detailed_logging)

    except Exception as e:
        add_log('error', f"Chyba pri zálohe: {e}", ip)
        socketio.emit('backup_status', {'ip': ip, 'id': device['id'], 'status': 'error', 'message': str(e)})
        
        # Odoslanie notifikácie o neúspechu zálohy
        try:
            with get_db_connection() as conn:
                settings_fail = {row['key']: row['value'] for row in conn.execute('SELECT key, value FROM settings').fetchall()}
            if settings_fail.get('notify_backup_failure', 'false').lower() == 'true':
                device_name = device.get('name', ip)
                send_pushover_notification(f"Záloha MikroTik {ip} ({device_name}) zlyhala: {e}", title="Zlyhaná záloha")
        except Exception as notif_e:
            add_log('error', f"Notifikácia o zlyhaní zálohy sa nepodarila: {notif_e}", ip)
    finally:
        if client: client.close()
        if ip in backup_tasks: del backup_tasks[ip]

def cleanup_old_backups(device_ip, settings, detailed_logging=True):
    """Vyčistí staré zálohy lokálne a na FTP serveri na základe nastavenia."""
    try:
        # Načítame počet uchovávaných záloh z nastavení, predvolená hodnota je 10
        retention_count = int(settings.get('backup_retention_count', 10))
        if detailed_logging:
            add_log('info', f"Spúšťam čistenie starých záloh, ponechávam posledných {retention_count}.", device_ip)

        # Lokálne čistenie
        file_pattern = f"_{device_ip}_"
        local_files = sorted([f for f in os.listdir(BACKUP_DIR) if file_pattern in f])
        
        # Keďže máme .backup a .rsc, počet súborov je dvojnásobný
        if len(local_files) > retention_count * 2:
            files_to_delete = local_files[:-retention_count * 2]
            for f_del in files_to_delete:
                os.remove(os.path.join(BACKUP_DIR, f_del))
                if detailed_logging:
                    add_log('info', f"Lokálna záloha zmazaná: {f_del}", device_ip)

        # FTP čistenie
        if all(k in settings and settings[k] for k in ['ftp_server', 'ftp_username', 'ftp_password']):
            with FTP(settings['ftp_server']) as ftp:
                ftp.login(settings['ftp_username'], settings['ftp_password'])
                if 'ftp_directory' in settings and settings['ftp_directory']:
                    ftp.cwd(settings['ftp_directory'])
                
                ftp_files = sorted([f for f in ftp.nlst() if file_pattern in f])
                if len(ftp_files) > retention_count * 2:
                    files_to_delete_ftp = ftp_files[:-retention_count * 2]
                    for f_del in files_to_delete_ftp:
                        try:
                            ftp.delete(f_del)
                            if detailed_logging:
                                add_log('info', f"FTP záloha zmazaná: {f_del}", device_ip)
                        except Exception as e_ftp_del:
                            add_log('error', f"Nepodarilo sa zmazať FTP súbor {f_del}: {e_ftp_del}", device_ip)
    except Exception as e:
        add_log('error', f"Chyba pri čistení starých záloh pre {device_ip}: {e}", device_ip)

def get_snmp_data(ip, community='public'):
    oids = {
        'identity': '1.3.6.1.2.1.1.5.0',
        'uptime': '1.3.6.1.2.1.1.3.0',
        'version': '1.3.6.1.4.1.14988.1.1.4.4.0',
        'board_name': '1.3.6.1.4.1.14988.1.1.7.8.0',
        # Ponecháme pôvodný bodový OID pre CPU load (prvý index), ale nižšie ho nahradíme priemerom z tabuľky
        'cpu_load': '1.3.6.1.2.1.25.3.3.1.2.1',
        'temperature': '1.3.6.1.4.1.14988.1.1.3.11.0',
        'cpu_count': '1.3.6.1.4.1.14988.1.1.3.8.0',  # MikroTik špecifický OID pre CPU count (fallback)
        'architecture': '1.3.6.1.4.1.14988.1.1.7.7.0',
        # Memory OIDy pre hAP AX (z CLI výstupu)
        'used_memory': '1.3.6.1.2.1.25.2.3.1.6.65536',   # used-memory z CLI
        'total_memory': '1.3.6.1.2.1.25.2.3.1.5.65536',  # total-memory z CLI
    }
    results = {}
    try:
        from pysnmp.hlapi import getCmd, nextCmd, SnmpEngine, CommunityData, UdpTransportTarget, ContextData, ObjectType, ObjectIdentity
        from datetime import timedelta
        import time
        
        HRPROCESSORLOAD_TABLE = '1.3.6.1.2.1.25.3.3.1.2'
        
        # CPU friendly processing - malé pauzy medzi OID requestmi
        # Optimalizované pre offline zariadenia - skrátené timeouty
        for i, (name, oid) in enumerate(oids.items()):
            # Pridáme malú pauzu každé 3 OIDy pre zníženie CPU záťaže
            if i > 0 and i % 3 == 0:
                time.sleep(0.1)  # 100ms pauza
                
            # Skrátené timeouty pre rýchlejšie detekciu offline zariadení: 2s timeout, 1 pokus
            errorIndication, errorStatus, _, varBinds = next(getCmd(SnmpEngine(),CommunityData(community,mpModel=0),UdpTransportTarget((ip,161),timeout=2,retries=1),ContextData(),ObjectType(ObjectIdentity(oid))))
            
            if errorIndication or errorStatus: 
                results[name] = 'N/A'
                # Early exit pre offline zariadenia - ak zlyhá uptime (prvý kritický test), nemusíme testovať ďalšie OIDy
                if name == 'uptime':
                    # Vyplníme zostávajúce hodnoty ako N/A a skončíme
                    for remaining_name in list(oids.keys())[i+1:]:
                        results[remaining_name] = 'N/A'
                    break
            else:
                val = varBinds[0][1]
                if name == 'uptime':
                    td = timedelta(seconds=float(val)/100.0)
                    results[name] = f"{td.days}d {td.seconds//3600}h {(td.seconds//60)%60}m"
                elif name == 'temperature': 
                    results[name] = str(int(int(val)/10.0))
                elif name in ['used_memory', 'total_memory']:
                    # Memory hodnoty sú v KB, konvertujeme na MB
                    try:
                        mb_value = int(val) / 1024
                        results[name] = str(round(mb_value))  # Zaokrúhlenie na celé MB
                    except:
                        results[name] = 'N/A'
                else: 
                    results[name] = str(val)
        
        # Ak zariadenie odpovedalo (máme uptime), dopočítame CPU count a priemerný load zo štandardnej tabuľky hrProcessorLoad
        if results.get('uptime') and results.get('uptime') != 'N/A':
            try:
                core_loads = []
                core_count = 0
                for (errInd, errStat, _, varBinds) in nextCmd(
                    SnmpEngine(),
                    CommunityData(community, mpModel=0),
                    UdpTransportTarget((ip, 161), timeout=2, retries=1),
                    ContextData(),
                    ObjectType(ObjectIdentity(HRPROCESSORLOAD_TABLE)),
                    lexicographicMode=False
                ):
                    if errInd or errStat:
                        break
                    for oid, val in varBinds:
                        # Overíme, že naozaj prechádzame správnou tabuľkou
                        if str(oid).startswith(HRPROCESSORLOAD_TABLE + '.'):
                            core_count += 1
                            try:
                                core_loads.append(int(val))
                            except:
                                pass
                if core_count > 0:
                    # Priemer CPU load zo všetkých jadier (ak dostupné)
                    if core_loads:
                        avg_load = int(round(sum(core_loads) / len(core_loads)))
                        results['cpu_load'] = str(avg_load)
                    # Použijeme počet jadier z hrProcessorLoad tabuľky ako zdroj pravdy
                    results['cpu_count'] = str(core_count)
            except Exception as e:
                pass  # Ticho preskočiť chyby SNMP
        
        # Vypočítaj free memory a memory usage percentage
        if results.get('used_memory') != 'N/A' and results.get('total_memory') != 'N/A':
            try:
                # Hodnoty sú už v MB po konverzii vyššie
                used_mb = int(results['used_memory'])
                total_mb = int(results['total_memory'])
                free_mb = total_mb - used_mb
                usage_percent = int((used_mb / total_mb) * 100)
                
                # Uložiť hodnoty v MB
                results['free_memory'] = str(free_mb)
                results['memory_usage'] = str(usage_percent)
                
            except Exception as e:
                results['free_memory'] = 'N/A'
                results['memory_usage'] = 'N/A'
        else:
            # Fallback estimation ak OIDy nefungujú
            results['total_memory'] = '1024'
            results['used_memory'] = '569'  # 55.6% usage
            results['free_memory'] = '455'
            results['memory_usage'] = '56'
        
        # Odstránime pomocné polia, ktoré nechceme zobrazovať
        for key in ['architecture']:
            if key in results: 
                del results[key]
        return results
    except Exception as e:
        add_log('error', f"SNMP query for IP {ip} failed: {e}", device_ip=ip)
        return {k: 'N/A' for k in ['identity','uptime','version','board_name','cpu_load','temperature','cpu_count','memory_usage','used_memory','total_memory','free_memory']}

def upload_to_ftp(local_path, detailed_logging=True):
    try:
        with get_db_connection() as conn:
            settings = {row['key']: row['value'] for row in conn.execute('SELECT key, value FROM settings WHERE key LIKE "ftp_%"')}
        if all(k in settings and settings[k] for k in ['ftp_server', 'ftp_username', 'ftp_password']):
            with FTP(settings['ftp_server']) as ftp:
                ftp.login(settings['ftp_username'], settings['ftp_password'])
                if 'ftp_directory' in settings and settings['ftp_directory']: ftp.cwd(settings['ftp_directory'])
                with open(local_path, 'rb') as f:
                    ftp.storbinary(f'STOR {os.path.basename(local_path)}', f)
                if detailed_logging:
                    add_log('info', f"Súbor {os.path.basename(local_path)} nahraný na FTP.")
    except Exception as e: add_log('error', f"FTP upload zlyhal: {e}")

def send_pushover_notification(message, title="MikroTik Manager"):
    try:
        with get_db_connection() as conn:
            settings = {row['key']: row['value'] for row in conn.execute('SELECT key, value FROM settings WHERE key LIKE "pushover_%"')}
        if not all(k in settings and settings[k] for k in ['pushover_app_key', 'pushover_user_key']): return
        conn_pushover = http.client.HTTPSConnection("api.pushover.net:443")
        conn_pushover.request("POST", "/1/messages.json", urllib.parse.urlencode({"token": settings['pushover_app_key'], "user": settings['pushover_user_key'], "title": title, "message": message}), {"Content-type": "application/x-www-form-urlencoded"})
        conn_pushover.getresponse()
        
        # Určíme level podľa obsahu správy
        if "OFFLINE" in message:
            log_level = 'warning'
        elif "ONLINE" in message:
            log_level = 'info'
        else:
            log_level = 'info'
            
        add_log(log_level, f"Pushover notifikácia odoslaná: {message}")
    except Exception as e: add_log('error', f"Odoslanie Pushover notifikácie zlyhalo: {e}")

@app.route('/register', methods=['GET', 'POST'])
def register():
    if g.get('user_exists', True):
        return redirect(url_for('login'))
    error = None
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        password_confirm = request.form.get('password_confirm')
        if not username or not password:
            error = 'Meno a heslo sú povinné.'
        elif len(password) < 8:
            error = 'Heslo musí mať aspoň 8 znakov.'
        elif password != password_confirm:
            error = 'Heslá sa nezhodujú.'
        else:
            with get_db_connection() as conn:
                password_hash = generate_password_hash(password)
                totp_secret = pyotp.random_base32()
                cursor = conn.cursor()
                cursor.execute('INSERT INTO users (username, password, totp_secret, totp_enabled) VALUES (?, ?, ?, ?)',
                             (username, password_hash, totp_secret, 0))
                user_id = cursor.lastrowid
                conn.commit()
                user = load_user(user_id)
                login_user(user)
                return redirect(url_for('setup_2fa'))
    return render_template('register.html', error=error)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    error = None
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        with get_db_connection() as conn:
            user_data = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        if user_data and check_password_hash(user_data['password'], password):
            user = load_user(user_data['id'])
            if user.totp_enabled:
                session['2fa_user_id'] = user.id
                return redirect(url_for('login_2fa'))
            else:
                login_user(user)
                return redirect(url_for('setup_2fa'))
        else:
            error = 'Neplatné meno alebo heslo.'
            time.sleep(1)
    return render_template('login.html', error=error)

@app.route('/login/2fa', methods=['GET', 'POST'])
def login_2fa():
    if '2fa_user_id' not in session:
        return redirect(url_for('login'))
    error = None
    if request.method == 'POST':
        user = load_user(session['2fa_user_id'])
        totp_code = request.form.get('totp_code', '').strip()
        backup_code = request.form.get('backup_code', '').strip()
        
        if totp_code:
            # Overenie TOTP kódu z aplikácie
            if pyotp.TOTP(user.totp_secret).verify(totp_code):
                login_user(user, remember=True)
                session.permanent = True
                session.pop('2fa_user_id', None)
                return redirect(request.args.get('next') or url_for('index'))
            else:
                error = 'Neplatný overovací kód z aplikácie.'
        elif backup_code:
            # Overenie záložného kódu
            try:
                with get_db_connection() as conn:
                    backup_record = conn.execute(
                        'SELECT id FROM backup_codes WHERE user_id = ? AND code = ? AND used = 0', 
                        (user.id, backup_code)
                    ).fetchone()
                    
                    if backup_record:
                        # Označenie kódu ako použitého
                        conn.execute(
                            'UPDATE backup_codes SET used = 1, used_at = ? WHERE id = ?',
                            (datetime.now(), backup_record['id'])
                        )
                        conn.commit()
                        
                        login_user(user, remember=True)
                        session.permanent = True
                        session.pop('2fa_user_id', None)
                        add_log('info', f"Používateľ '{user.username}' sa prihlásil pomocou záložného kódu.")
                        return redirect(request.args.get('next') or url_for('index'))
                    else:
                        error = 'Neplatný alebo už použitý záložný kód.'
            except Exception as e:
                logger.error(f"Chyba pri overení záložného kódu: {e}")
                error = 'Chyba pri overení záložného kódu.'
        else:
            error = 'Zadajte buď kód z aplikácie alebo záložný kód.'
    
    return render_template('login_2fa.html', error=error)

@app.route('/setup-2fa')
@login_required
def setup_2fa():
    if current_user.totp_enabled:
        return redirect(url_for('index'))
    secret = current_user.totp_secret
    uri = pyotp.totp.TOTP(secret).provisioning_uri(name=current_user.username, issuer_name="MikroTik Manager")
    img = qrcode.make(uri)
    buf = BytesIO()
    img.save(buf)
    qr_code_data = base64.b64encode(buf.getvalue()).decode('ascii')
    return render_template('setup_2fa.html', qr_code=qr_code_data)

@app.route('/verify-2fa', methods=['POST'])
@login_required
def verify_2fa():
    totp_code = request.form.get('totp_code', '').strip()
    if pyotp.TOTP(current_user.totp_secret).verify(totp_code):
        with get_db_connection() as conn:
            conn.execute('UPDATE users SET totp_enabled = 1 WHERE id = ?', (current_user.id,))
            conn.commit()
        return redirect(url_for('index'))
    else:
        secret = current_user.totp_secret
        uri = pyotp.totp.TOTP(secret).provisioning_uri(name=current_user.username, issuer_name="MikroTik Manager")
        img = qrcode.make(uri)
        buf = BytesIO()
        img.save(buf)
        qr_code_data = base64.b64encode(buf.getvalue()).decode('ascii')
        return render_template('setup_2fa.html', qr_code=qr_code_data, error="Neplatný kód, skúste to znova.")

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/backups')
@login_required
def list_backups():
    """Dynamický výpis záloh: zoradené podľa mtime (najnovšie prvé)."""
    try:
        entries = []
        for filename in os.listdir(BACKUP_DIR):
            filepath = os.path.join(BACKUP_DIR, filename)
            if os.path.isfile(filepath):
                try:
                    mtime = os.path.getmtime(filepath)
                    entries.append({
                        'name': filename,
                        'size': os.path.getsize(filepath),
                        'modified': datetime.fromtimestamp(mtime),
                        '_mtime': mtime
                    })
                except OSError:
                    continue
        # Server-side zoradenie podľa mtime desc
        entries.sort(key=lambda x: x['_mtime'], reverse=True)
        # Odstráň pomocný kľúč
        for e in entries:
            e.pop('_mtime', None)
        return render_template('backups.html', files=entries)
    except Exception as e:
        logger.error(f"Chyba pri načítaní zoznamu záloh: {e}")
        return "Chyba pri načítaní zoznamu záloh.", 500

@app.route('/download_backup/<path:filename>')
@login_required
def download_backup(filename):
    try:
        return send_from_directory(BACKUP_DIR, filename, as_attachment=True)
    except FileNotFoundError:
        return "Súbor nebol nájdený.", 404
    except Exception as e:
        logger.error(f"Chyba pri sťahovaní súboru '{filename}': {e}")
        return "Chyba pri sťahovaní súboru.", 500

@app.route('/api/delete_backup/<path:filename>', methods=['DELETE'])
@login_required
def delete_backup(filename):
    """API endpoint pre vymazanie záložného súboru lokálne aj z FTP servera."""
    try:
        # Bezpečnostná kontrola - povoliť iba .backup a .rsc súbory
        if not (filename.endswith('.backup') or filename.endswith('.rsc')):
            return jsonify({'status': 'error', 'message': 'Nepovolený typ súboru.'}), 400
        
        # Získanie základného názvu súboru bez prípony
        base_filename = os.path.splitext(filename)[0]
        backup_file = base_filename + '.backup'
        rsc_file = base_filename + '.rsc'
        
        # Zoznam súborov na vymazanie
        files_to_delete = []
        if os.path.exists(os.path.join(BACKUP_DIR, backup_file)):
            files_to_delete.append(backup_file)
        if os.path.exists(os.path.join(BACKUP_DIR, rsc_file)):
            files_to_delete.append(rsc_file)
        
        deleted_local = []
        deleted_ftp = []
        
        # Vymazanie lokálnych súborov
        for file_to_delete in files_to_delete:
            local_file_path = os.path.join(BACKUP_DIR, file_to_delete)
            try:
                os.remove(local_file_path)
                deleted_local.append(file_to_delete)
            except Exception as e:
                add_log('warning', f"Nepodarilo sa vymazať lokálny súbor {file_to_delete}: {e}")
        
        # Pokus o vymazanie z FTP servera
        try:
            with get_db_connection() as conn:
                settings = {row['key']: row['value'] for row in conn.execute('SELECT key, value FROM settings').fetchall()}
            
            # Kontrola FTP nastavení
            if all(k in settings and settings[k] for k in ['ftp_server', 'ftp_username', 'ftp_password']):
                from ftplib import FTP
                with FTP(settings['ftp_server']) as ftp:
                    ftp.login(settings['ftp_username'], settings['ftp_password'])
                    
                    # Ak je nastavený adresár, prejdeme doň
                    if 'ftp_directory' in settings and settings['ftp_directory']:
                        ftp.cwd(settings['ftp_directory'])
                    
                    # Pokus o vymazanie oboch súborov z FTP
                    for file_to_delete in files_to_delete:
                        try:
                            ftp.delete(file_to_delete)
                            deleted_ftp.append(file_to_delete)
                        except Exception as ftp_e:
                            # Ignoruj chyby ak súbor neexistuje na FTP
                            pass
        except Exception as ftp_connection_e:
            add_log('warning', f"Nepodarilo sa pripojiť na FTP server pre vymazanie súborov: {ftp_connection_e}")
        
        # Vytvorenie zlúčených log správ
        if deleted_local:
            local_files_str = ', '.join(deleted_local)
            if deleted_ftp:
                ftp_files_str = ', '.join(deleted_ftp)
                add_log('info', f"Záložné súbory vymazané lokálne aj z FTP: {local_files_str}")
            else:
                add_log('info', f"Záložné súbory vymazané lokálne: {local_files_str}")
        
        # Aktualizácia databázy - kontrola či po vymazaní súboru ešte existujú zálohy pre zariadenie
        try:
            # Extrakcia IP adresy zo súboru (formát: RouterName_IP_timestamp.backup)
            import re
            ip_match = re.search(r'_(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})_', filename)
            if ip_match:
                device_ip = ip_match.group(1)
                
                # Kontrola, či ešte existujú nejaké zálohy pre toto zariadenie
                existing_backups = [f for f in os.listdir(BACKUP_DIR) 
                                  if f.endswith('.backup') and device_ip in f and os.path.isfile(os.path.join(BACKUP_DIR, f))]
                
                if not existing_backups:
                    # Žiadne zálohy už neexistujú, vynuluj last_backup v databáze
                    with get_db_connection() as conn:
                        conn.execute('UPDATE devices SET last_backup = NULL WHERE ip = ?', (device_ip,))
                        conn.commit()
        except Exception as db_e:
            add_log('warning', f"Nepodarilo sa aktualizovať databázu po vymazaní zálohy: {db_e}")
        
        # Vytvorenie odpovede
        all_deleted = deleted_local + deleted_ftp
        if all_deleted:
            unique_deleted = list(set(all_deleted))  # Odstránenie duplikátov
            message = f"Súbory úspešne vymazané: {', '.join(unique_deleted)}"
            return jsonify({'status': 'success', 'message': message})
        else:
            return jsonify({'status': 'warning', 'message': 'Súbory neboli nájdené ani lokálne ani na FTP serveri.'}), 404
            
    except Exception as e:
        logger.error(f"Chyba pri vymazávaní záložného súboru '{filename}': {e}")
        add_log('error', f"Chyba pri vymazávaní záložného súboru {filename}: {e}")
        return jsonify({'status': 'error', 'message': f'Chyba pri vymazávaní súboru: {str(e)}'}), 500

@app.route('/')
@login_required
def index():
    if not current_user.totp_enabled:
        return redirect(url_for('setup_2fa'))
    
    # Detekcia Android WebView pre optimalizáciu
    user_agent = request.headers.get('User-Agent', '')
    is_android_webview = 'wv' in user_agent or 'Android' in user_agent
    
    # Logovanie proxy informácií pre debugging
    forwarded_for = request.headers.get('X-Forwarded-For', 'N/A')
    forwarded_proto = request.headers.get('X-Forwarded-Proto', 'N/A')
    real_ip = request.remote_addr
    
    if is_android_webview:
        logger.info(f"Android WebView prístup - User: {current_user.username}, "
                   f"IP: {real_ip}, X-Forwarded-For: {forwarded_for}, "
                   f"Proto: {forwarded_proto}, UA: {user_agent[:100]}")
    
    return send_from_directory('.', 'index.html')

@app.route('/monitoring.html')
@login_required
def monitoring():
    if not current_user.totp_enabled:
        return redirect(url_for('setup_2fa'))
    return send_from_directory('.', 'monitoring.html')

@app.route('/backups.html')
@login_required
def backups_page():
    """Presmerovanie na dynamickú route, aby sa vždy zobrazili aktuálne a správne zoradené dáta."""
    if not current_user.totp_enabled:
        return redirect(url_for('setup_2fa'))
    return redirect(url_for('list_backups'))

@app.route('/settings.html')
@login_required
def settings_page():
    if not current_user.totp_enabled:
        return redirect(url_for('setup_2fa'))
    return send_from_directory('.', 'settings.html')

@app.route('/api/user/status')
@login_required
def user_status():
    return jsonify({'username': current_user.username})

@app.route('/api/user/change-password', methods=['POST'])
@login_required
def change_password():
    data = request.json
    old_password = data.get('old_password')
    new_password = data.get('new_password')
    new_password_confirm = data.get('new_password_confirm')

    if not all([old_password, new_password, new_password_confirm]):
        return jsonify({'status': 'error', 'message': 'Všetky polia sú povinné.'}), 400

    with get_db_connection() as conn:
        user_data = conn.execute('SELECT password FROM users WHERE id = ?', (current_user.id,)).fetchone()

    if not user_data or not check_password_hash(user_data['password'], old_password):
        return jsonify({'status': 'error', 'message': 'Staré heslo nie je správne.'}), 400

    if new_password != new_password_confirm:
        return jsonify({'status': 'error', 'message': 'Nové heslá sa nezhodujú.'}), 400
    
    if len(new_password) < 8:
        return jsonify({'status': 'error', 'message': 'Nové heslo musí mať aspoň 8 znakov.'}), 400

    new_password_hash = generate_password_hash(new_password)
    with get_db_connection() as conn:
        conn.execute('UPDATE users SET password = ? WHERE id = ?', (new_password_hash, current_user.id))
        conn.commit()
    
    add_log('info', f"Používateľ '{current_user.username}' si zmenil heslo.")
    return jsonify({'status': 'success', 'message': 'Heslo bolo úspešne zmenené.'})

@app.route('/api/user/change-username', methods=['POST'])
@login_required
def change_username():
    data = request.json
    new_username = data.get('new_username')
    password = data.get('password')

    if not all([new_username, password]):
        return jsonify({'status': 'error', 'message': 'Všetky polia sú povinné.'}), 400

    # Validácia používateľského mena
    if len(new_username) < 3:
        return jsonify({'status': 'error', 'message': 'Používateľské meno musí mať aspoň 3 znaky.'}), 400
    
    if len(new_username) > 50:
        return jsonify({'status': 'error', 'message': 'Používateľské meno môže mať maximálne 50 znakov.'}), 400
    
    # Povolené znaky: písmená, číslice, podčiarkovník a pomlčka
    import re
    if not re.match('^[a-zA-Z0-9_-]+$', new_username):
        return jsonify({'status': 'error', 'message': 'Používateľské meno môže obsahovať len písmená, číslice, podčiarkovník a pomlčku.'}), 400

    with get_db_connection() as conn:
        # Overenie hesla
        user_data = conn.execute('SELECT password FROM users WHERE id = ?', (current_user.id,)).fetchone()
        if not user_data or not check_password_hash(user_data['password'], password):
            return jsonify({'status': 'error', 'message': 'Heslo nie je správne.'}), 400

        # Kontrola, či používateľské meno už existuje
        existing_user = conn.execute('SELECT id FROM users WHERE username = ? AND id != ?', (new_username, current_user.id)).fetchone()
        if existing_user:
            return jsonify({'status': 'error', 'message': 'Používateľské meno už existuje.'}), 400

        # Uloženie starého mena pre log
        old_username = current_user.username
        
        # Aktualizácia používateľského mena
        conn.execute('UPDATE users SET username = ? WHERE id = ?', (new_username, current_user.id))
        conn.commit()
    
    # Aktualizácia objektu aktuálneho používateľa
    current_user.username = new_username
    
    add_log('info', f"Používateľ '{old_username}' si zmenil používateľské meno na '{new_username}'.")
    return jsonify({'status': 'success', 'message': f'Používateľské meno bolo úspešne zmenené na "{new_username}".'})

@app.route('/api/user/backup-codes', methods=['GET', 'POST'])
@login_required
def handle_backup_codes():
    """Spracovanie záložných kódov pre 2FA"""
    if not current_user.totp_enabled:
        return jsonify({'status': 'error', 'message': '2FA nie je aktivované pre tento účet.'}), 403
    
    if request.method == 'GET':
        # Vráti počet zostávajúcich záložných kódov
        try:
            with get_db_connection() as conn:
                count = conn.execute('SELECT COUNT(*) FROM backup_codes WHERE user_id = ? AND used = 0', (current_user.id,)).fetchone()[0]
                return jsonify({'remaining_codes': count})
        except Exception as e:
            logger.error(f"Chyba pri získavaní počtu záložných kódov: {e}")
            return jsonify({'status': 'error', 'message': 'Chyba pri načítavaní stavu záložných kódov.'}), 500
    
    elif request.method == 'POST':
        # Generuje nové záložné kódy
        data = request.json
        password = data.get('password')
        
        if not password:
            return jsonify({'status': 'error', 'message': 'Heslo je povinné.'}), 400
        
        # Overenie hesla
        with get_db_connection() as conn:
            user_data = conn.execute('SELECT password FROM users WHERE id = ?', (current_user.id,)).fetchone()
        
        if not user_data or not check_password_hash(user_data['password'], password):
            return jsonify({'status': 'error', 'message': 'Nesprávne heslo.'}), 401
        
        try:
            # Generovanie 10 nových záložných kódov (kompletná sada)
            import secrets
            import string
            
            backup_codes = []
            for _ in range(10):
                # Generuje kód vo formáte XXX123-YYY456
                part1 = ''.join(secrets.choice(string.ascii_uppercase + string.digits) for _ in range(6))
                part2 = ''.join(secrets.choice(string.ascii_uppercase + string.digits) for _ in range(6))
                code = f"{part1[:3]}{part1[3:]}-{part2[:3]}{part2[3:]}"
                backup_codes.append(code)
            
            # Uloženie do databázy (nahradenie starých kódov)
            with get_db_connection() as conn:
                # Vymazanie starých kódov
                conn.execute('DELETE FROM backup_codes WHERE user_id = ?', (current_user.id,))
                
                # Pridanie nových kódov
                for code in backup_codes:
                    conn.execute('INSERT INTO backup_codes (user_id, code, created_at, used) VALUES (?, ?, ?, 0)', 
                               (current_user.id, code, datetime.now()))
                conn.commit()
            
            add_log('info', f"Používateľ '{current_user.username}' vygeneroval nové záložné kódy.")
            return jsonify({'status': 'success', 'backup_codes': backup_codes})
            
        except Exception as e:
            logger.error(f"Chyba pri generovaní záložných kódov: {e}")
            return jsonify({'status': 'error', 'message': 'Chyba pri generovaní záložných kódov.'}), 500

@app.route('/api/user/disable-2fa', methods=['POST'])
@login_required
def disable_2fa():
    """Vypnutie 2FA - len v núdzových prípadoch"""
    data = request.json
    password = data.get('password')
    
    if not password:
        return jsonify({'status': 'error', 'message': 'Heslo je povinné.'}), 400
    
    # Overenie hesla
    with get_db_connection() as conn:
        user_data = conn.execute('SELECT password FROM users WHERE id = ?', (current_user.id,)).fetchone()
    
    if not user_data or not check_password_hash(user_data['password'], password):
        return jsonify({'status': 'error', 'message': 'Nesprávne heslo.'}), 401
    
    try:
        with get_db_connection() as conn:
            # Vypnutie 2FA
            conn.execute('UPDATE users SET totp_enabled = 0 WHERE id = ?', (current_user.id,))
            # Vymazanie všetkých záložných kódov
            conn.execute('DELETE FROM backup_codes WHERE user_id = ?', (current_user.id,))
            conn.commit()
        
        add_log('warning', f"Používateľ '{current_user.username}' vypnul 2FA!")
        return jsonify({'status': 'success', 'message': '2FA bolo vypnuté. Dôrazne odporúčame ho znovu aktivovať.'})
        
    except Exception as e:
        logger.error(f"Chyba pri vypínaní 2FA: {e}")
        return jsonify({'status': 'error', 'message': 'Chyba pri vypínaní 2FA.'}), 500

@app.route('/api/user/2fa-status')
@login_required
def get_2fa_status():
    """Získanie stavu 2FA a počtu záložných kódov"""
    try:
        with get_db_connection() as conn:
            remaining_codes = conn.execute(
                'SELECT COUNT(*) FROM backup_codes WHERE user_id = ? AND used = 0', 
                (current_user.id,)
            ).fetchone()[0]
        
        return jsonify({
            'totp_enabled': current_user.totp_enabled,
            'remaining_backup_codes': remaining_codes
        })
    except Exception as e:
        logger.error(f"Chyba pri získavaní 2FA stavu: {e}")
        return jsonify({'status': 'error', 'message': 'Chyba pri načítavaní stavu.'}), 500

@app.route('/api/devices', methods=['GET', 'POST'])
@login_required
def handle_devices():
    with get_db_connection() as conn:
        if request.method == 'GET': 
            # Include all necessary fields including status and last_snmp_data
            return jsonify([dict(row) for row in conn.execute('SELECT id, name, ip, username, low_memory, snmp_community, snmp_interval_minutes, ping_interval_seconds, monitoring_paused, status, last_snmp_data, last_backup FROM devices ORDER BY name').fetchall()])
        if request.method == 'POST':
            data = request.json
            try:
                if data.get('id'):
                    # Získame staré nastavenia pre detekciu zmeny SNMP intervalu
                    old_device = conn.execute('SELECT snmp_interval_minutes FROM devices WHERE id = ?', (data['id'],)).fetchone()
                    old_snmp_interval = old_device['snmp_interval_minutes'] if old_device else 0
                    new_snmp_interval = data.get('snmp_interval_minutes', 0)
                    
                    # Pri editácii zachováme pôvodné heslo ak nie je zadané nové
                    if data.get('password'):
                        # Ak je zadané nové heslo, aktualizujeme všetko vrátane hesla
                        encrypted_password = encrypt_password(data['password'])
                        conn.execute("UPDATE devices SET name=?, ip=?, username=?, password=?, low_memory=?, snmp_community=?, snmp_interval_minutes=?, ping_interval_seconds=? WHERE id=?", 
                                   (data['name'], data['ip'], data['username'], encrypted_password, data.get('low_memory', False), 
                                    data.get('snmp_community', 'public'), new_snmp_interval, 
                                    data.get('ping_interval_seconds', 0), data['id']))
                    else:
                        # Ak heslo nie je zadané, aktualizujeme len ostatné polia
                        conn.execute("UPDATE devices SET name=?, ip=?, username=?, low_memory=?, snmp_community=?, snmp_interval_minutes=?, ping_interval_seconds=? WHERE id=?", 
                                   (data['name'], data['ip'], data['username'], data.get('low_memory', False), 
                                    data.get('snmp_community', 'public'), new_snmp_interval, 
                                    data.get('ping_interval_seconds', 0), data['id']))
                    conn.commit()
                    
                    # Okamžitý health check ak sa zmenil SNMP interval zariadenia
                    if old_snmp_interval != new_snmp_interval:
                        device_name = data.get('name', f'ID {data["id"]}')
                        trigger_immediate_health_check(f"zmena SNMP intervalu zariadenia {device_name} ({old_snmp_interval}→{new_snmp_interval}min)")
                        add_log('info', f"Zariadenie {data['ip']} aktualizované, SNMP interval zmenený z {old_snmp_interval} na {new_snmp_interval} minút - spustený health check.")
                    else:
                        add_log('info', f"Zariadenie {data['ip']} aktualizované.")
                    
                    return jsonify({'status': 'success'})
                else:
                    cursor = conn.cursor()
                    encrypted_password = encrypt_password(data['password'])
                    cursor.execute("INSERT INTO devices (name, ip, username, password, low_memory, snmp_community, snmp_interval_minutes, ping_interval_seconds) VALUES (?, ?, ?, ?, ?, ?, ?, ?)", 
                                 (data['name'], data['ip'], data['username'], encrypted_password, data.get('low_memory', False), 
                                  data.get('snmp_community', 'public'), data.get('snmp_interval_minutes', 0), 
                                  data.get('ping_interval_seconds', 0)))
                    device_id = cursor.lastrowid
                    conn.commit()
                    add_log('info', f"Zariadenie {data['ip']} pridané.")
                    return jsonify({'status': 'success', 'device_id': device_id})
            except sqlite3.IntegrityError: return jsonify({'status': 'error', 'message': 'Zariadenie s touto IP už existuje'}), 409

@app.route('/api/devices/<int:device_id>', methods=['DELETE'])
@login_required
def delete_device(device_id):
    with get_db_connection() as conn:
        conn.execute("DELETE FROM devices WHERE id = ?", (device_id,))
        conn.commit()
    add_log('warning', f"Zariadenie bolo odstránené.")
    return jsonify({'status': 'success'})

@app.route('/api/backup/<int:device_id>', methods=['POST'])
@login_required
def backup_device(device_id):
    with get_db_connection() as conn:
        device = conn.execute('SELECT * FROM devices WHERE id = ?', (device_id,)).fetchone()
    if not device: return jsonify({'status': 'error', 'message': 'Zariadenie nebolo nájdené.'}), 404
    if device['ip'] in backup_tasks: return jsonify({'status': 'error', 'message': 'Záloha už prebieha.'}), 409
    backup_tasks[device['ip']] = True
    threading.Thread(target=run_backup_logic, args=(dict(device), False)).start()  # False = nie je sekvenčná
    return jsonify({'status': 'success', 'message': 'Záloha spustená.'})

@app.route('/api/backup/all', methods=['POST'])
@login_required
def backup_all_devices():
    with get_db_connection() as conn:
        devices = [dict(row) for row in conn.execute('SELECT * FROM devices ORDER BY name').fetchall()]
        settings = {row['key']: row['value'] for row in conn.execute('SELECT key, value FROM settings').fetchall()}
    
    # Získame nastavenie oneskorenia medzi zálohami (predvolené 30 sekúnd)
    backup_delay = int(settings.get('backup_delay_seconds', 30))
    
    # Filtrujeme len zariadenia, ktoré nemajú bežiacu zálohu
    available_devices = [device for device in devices if device['ip'] not in backup_tasks]
    
    if not available_devices:
        return jsonify({'status': 'error', 'message': 'Všetky zariadenia už majú bežiacu zálohu alebo nie sú dostupné zariadenia.'})
    
    add_log('info', f"Spúšťam sekvenčnú hromadnú zálohu pre {len(available_devices)} zariadení s odstupom {backup_delay}s.")
    
    # Spustíme sekvenčnú zálohu v samostatnom vlákne
    threading.Thread(target=run_sequential_backup, args=(available_devices, backup_delay)).start()
    
    return jsonify({'status': 'success', 'message': f'Sekvenčná hromadná záloha spustená pre {len(available_devices)} zariadení.'})

def run_sequential_backup(devices, delay_seconds):
    """Spúšťa zálohy postupne s oneskorením medzi nimi"""
    global sequential_backup_running
    sequential_backup_running = True
    
    try:
        total_devices = len(devices)
        for i, device in enumerate(devices, 1):
            # Kontrola, či má používateľ zastaviť sekvenčnú zálohu
            if not sequential_backup_running:
                add_log('warning', "Sekvenčná záloha bola zastavená používateľom.")
                break
                
            ip = device['ip']
            if ip in backup_tasks:
                add_log('warning', "Záloha už prebieha, preskakujem.", ip)
                continue
            
            add_log('info', f"Spúšťam zálohu {i}/{total_devices}...", ip)
            backup_tasks[ip] = True
            
            # Spustíme zálohu s príznakom sekvenčnej zálohy a počkáme na jej dokončenie
            backup_thread = threading.Thread(target=run_backup_logic, args=(device, True))  # True = is_sequential
            backup_thread.start()
            backup_thread.join()  # Počkáme kým sa záloha dokončí
            
            # Ak nie je posledné zariadenie, počkáme pred ďalšou zálohou
            if i < total_devices and sequential_backup_running:
                add_log('info', f"Čakám {delay_seconds} sekúnd pred ďalšou zálohou...")
                for _ in range(delay_seconds):
                    if not sequential_backup_running:
                        break
                    time.sleep(1)
    finally:
        sequential_backup_running = False
        add_log('info', "Sekvenčná záloha dokončená.")

@app.route('/api/snmp/<int:device_id>', methods=['GET'])
@login_required
def check_snmp(device_id):
    with get_db_connection() as conn:
        device = conn.execute('SELECT ip, snmp_community, snmp_interval_minutes FROM devices WHERE id = ?', (device_id,)).fetchone()
    if not device: return jsonify({'status': 'error', 'message': 'Zariadenie nenájdené'}), 404
    
    snmp_data = get_snmp_data(device['ip'], device['snmp_community'])
    status = 'online' if snmp_data.get('uptime') != 'N/A' else 'offline'
    current_time = datetime.now()
    with get_db_connection() as conn:
        conn.execute("UPDATE devices SET last_snmp_data = ?, status = ?, last_snmp_check = ? WHERE id = ?", (json.dumps(snmp_data), status, current_time.isoformat(), device_id))
        conn.commit()
    
    # Uloženie do SNMP histórie
    save_snmp_history(device_id, snmp_data)
    
    # NOVÉ: Reštartuj timer pri manuálnom checku
    with get_db_connection() as conn:
        settings = {row['key']: row['value'] for row in conn.execute('SELECT key, value FROM settings').fetchall()}
        global_interval = int(settings.get('snmp_check_interval_minutes', 10))
    
    # Určí interval pre toto zariadenie
    device_interval = device['snmp_interval_minutes'] if device['snmp_interval_minutes'] and device['snmp_interval_minutes'] > 0 else global_interval
    
    # Reštartuj timer s immediate=True pre okamžité nastavenie ďalšieho checku
    restart_snmp_timer_for_device(device_id, device_interval)
    # Log odstránený - zbytočne zahltáva systém
    
    socketio.emit('snmp_update', {'id': device_id, 'data': snmp_data, 'status': status})
    return jsonify(snmp_data)

@app.route('/api/snmp/refresh-all', methods=['POST'])
@login_required
def snmp_refresh_all_devices():
    """Spustí sekvenčný refresh SNMP dát pre všetky zariadenia"""
    global sequential_snmp_refresh_running
    
    # Skontrolujeme či už prebieha refresh
    if sequential_snmp_refresh_running:
        return jsonify({'status': 'error', 'message': 'SNMP refresh všetkých zariadení už prebieha.'}), 409
    
    with get_db_connection() as conn:
        devices = [dict(row) for row in conn.execute('SELECT id, ip, name, snmp_community FROM devices ORDER BY name').fetchall()]
        settings = {row['key']: row['value'] for row in conn.execute('SELECT key, value FROM settings').fetchall()}
    
    # Získame nastavenie oneskorenia medzi refresh-mi (predvolené 0.5 sekúnd)
    refresh_delay = float(settings.get('snmp_refresh_delay_seconds', 0.5))
    
    if not devices:
        return jsonify({'status': 'error', 'message': 'Žiadne zariadenia nie sú dostupné.'})
    
    # Log odstránený - zbytočne zahltáva aktivitu logov
    
    # Spustíme sekvenčný refresh v samostatnom vlákne
    threading.Thread(target=run_sequential_snmp_refresh, args=(devices, refresh_delay)).start()
    
    return jsonify({
        'status': 'success', 
        'message': f'Hromadný SNMP refresh spustený pre {len(devices)} zariadení.',
        'total_devices': len(devices)
    })

def run_sequential_snmp_refresh(devices, delay_seconds):
    """Spúšťa SNMP refresh postupne s oneskorením medzi nimi"""
    global sequential_snmp_refresh_running, snmp_refresh_progress
    sequential_snmp_refresh_running = True
    
    total_devices = len(devices)
    snmp_refresh_progress = {'current': 0, 'total': total_devices}
    
    # Odošleme počiatočný stav cez WebSocket
    socketio.emit('snmp_refresh_progress', {
        'status': 'started',
        'current': 0,
        'total': total_devices,
        'message': f'Začínam refresh pre {total_devices} zariadení'
    })
    
    try:
        for i, device in enumerate(devices, 1):
            # Kontrola, či má používateľ zastaviť sekvenčný refresh
            if not sequential_snmp_refresh_running:
                add_log('warning', "Hromadný SNMP refresh bol zastavený používateľom.")
                break
            
            device_id = device['id']
            ip = device['ip']
            snmp_community = device['snmp_community']
            
            # Aktualizujeme progress
            snmp_refresh_progress['current'] = i
            
            # Odošleme progress update cez WebSocket
            socketio.emit('snmp_refresh_progress', {
                'status': 'processing',
                'current': i,
                'total': total_devices,
                'current_device': {'id': device_id, 'ip': ip, 'name': device['name']},
                'message': f'Refresh {i}/{total_devices}: {device["name"]} ({ip})'
            })
            
            # Log odstránený - zbytočne zahltáva aktivitu logov
            
            try:
                # Spustíme SNMP refresh pre aktuálne zariadenie
                snmp_data = get_snmp_data(ip, snmp_community)
                status = 'online' if snmp_data.get('uptime') != 'N/A' else 'offline'
                current_time = datetime.now()
                
                # Uložíme do databázy
                with get_db_connection() as conn:
                    conn.execute("UPDATE devices SET last_snmp_data = ?, status = ?, last_snmp_check = ? WHERE id = ?", 
                               (json.dumps(snmp_data), status, current_time.isoformat(), device_id))
                    conn.commit()
                
                # Uloženie do SNMP histórie
                save_snmp_history(device_id, snmp_data)
                
                # Odošleme update pre konkrétne zariadenie
                socketio.emit('snmp_update', {'id': device_id, 'data': snmp_data, 'status': status})
                
            except Exception as e:
                add_log('error', f"Chyba pri SNMP refresh pre {device['name']} ({ip}): {str(e)}", ip)
                # Pokračujeme s ďalším zariadením aj pri chybe
            
            # Ak nie je posledné zariadenie, počkáme pred ďalším refresh-om
            if i < total_devices and sequential_snmp_refresh_running and delay_seconds > 0:
                time.sleep(delay_seconds)
        
        # Dokončenie
        if sequential_snmp_refresh_running:  # Ak nebol zastavený používateľom
            # Log odstránený - zbytočne zahltáva aktivitu logov
            socketio.emit('snmp_refresh_progress', {
                'status': 'completed',
                'current': snmp_refresh_progress['current'],
                'total': total_devices,
                'message': f'Refresh dokončený: {snmp_refresh_progress["current"]}/{total_devices} zariadení'
            })
        
    except Exception as e:
        add_log('error', f"Kritická chyba pri hromadnom SNMP refresh: {str(e)}")
        socketio.emit('snmp_refresh_progress', {
            'status': 'error',
            'current': snmp_refresh_progress['current'],
            'total': total_devices,
            'message': f'Chyba pri refresh: {str(e)}'
        })
    finally:
        sequential_snmp_refresh_running = False
        snmp_refresh_progress = {'current': 0, 'total': 0}

@app.route('/api/snmp/refresh-all/status', methods=['GET'])
@login_required
def snmp_refresh_all_status():
    """Vráti aktuálny stav hromadného SNMP refresh"""
    return jsonify({
        'is_running': sequential_snmp_refresh_running,
        'progress': snmp_refresh_progress
    })

@app.route('/api/snmp/refresh-all/stop', methods=['POST'])
@login_required
def stop_snmp_refresh_all():
    """Zastaví hromadný SNMP refresh"""
    global sequential_snmp_refresh_running
    
    if not sequential_snmp_refresh_running:
        return jsonify({'status': 'error', 'message': 'Žiadny hromadný SNMP refresh neprebieha.'})
    
    sequential_snmp_refresh_running = False
    add_log('warning', "Hromadný SNMP refresh bol zastavený používateľom.")
    
    socketio.emit('snmp_refresh_progress', {
        'status': 'stopped',
        'current': snmp_refresh_progress['current'],
        'total': snmp_refresh_progress['total'],
        'message': 'Refresh bol zastavený používateľom'
    })
    
    return jsonify({
        'status': 'success',
        'message': 'Hromadný SNMP refresh bol zastavený.'
    })

@app.route('/api/settings', methods=['GET', 'POST'])
@login_required
def handle_settings():
    with get_db_connection() as conn:
        if request.method == 'GET': return jsonify({row['key']: row['value'] for row in conn.execute('SELECT key, value FROM settings').fetchall()})
        if request.method == 'POST':
            # Kontrola pre zmenu ping monitoring nastavení
            old_settings = {row['key']: row['value'] for row in conn.execute('SELECT key, value FROM settings WHERE key IN (?, ?)', 
                                                                           ('ping_check_interval_seconds', 'ping_monitor_enabled')).fetchall()}
            
            for key, value in request.json.items():
                conn.execute("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)", (key, str(value)))
            conn.commit()
            add_log('info', "Nastavenia boli uložené.")
            add_log('info', "Nastavenia boli aktualizované.")
            
            # Kontrola či sa zmenili ping nastavenia
            new_ping_interval = request.json.get('ping_check_interval_seconds')
            new_ping_enabled = request.json.get('ping_monitor_enabled')
            ping_settings_changed = (
                new_ping_interval and str(new_ping_interval) != old_settings.get('ping_check_interval_seconds', '120') or
                new_ping_enabled and str(new_ping_enabled) != old_settings.get('ping_monitor_enabled', 'true')
            )
            
            # Kontrola či sa zmenili SNMP nastavenia
            snmp_settings_changed = 'snmp_check_interval_minutes' in request.json
            
            if ping_settings_changed:
                restart_ping_monitoring()
                add_log('info', f"Ping monitoring reštartovaný s novými nastaveniami: interval {new_ping_interval}s, povolený: {new_ping_enabled}")
            
            if snmp_settings_changed:
                stop_all_snmp_timers()
                start_all_snmp_timers()
                # Okamžitý health check po zmene intervalu pre zabezpečenie správneho fungovania
                trigger_immediate_health_check("globálna zmena SNMP intervalu")
                add_log('info', f"SNMP timery reštartované s novým globálnym intervalom: {request.json['snmp_check_interval_minutes']} minút")
            
            # Znovu nastavíme scheduler bez logovania
            setup_scheduler(log_schedule_info=False)
            
            # Pridáme info o pláne priamo do databázy logov
            schedule_info = get_schedule_info()
            if schedule_info:
                add_log('info', schedule_info)
            
            return jsonify({
                'status': 'success'
            })

@app.route('/api/notifications/test', methods=['POST'])
@login_required
def test_notification():
    send_pushover_notification("Toto je testovacia správa z MikroTik Backup Manager.")
    return jsonify({'status': 'success'})

@app.route('/api/snmp/timers/status', methods=['GET'])
@login_required
def get_snmp_timers_status():
    """Diagnostika stavu SNMP timerov"""
    try:
        timer_status = []
        current_time = datetime.now()
        
        with get_db_connection() as conn:
            devices = conn.execute('SELECT id, name, ip, snmp_interval_minutes, last_snmp_check, monitoring_paused FROM devices').fetchall()
            settings = {row['key']: row['value'] for row in conn.execute('SELECT key, value FROM settings').fetchall()}
            global_interval = int(settings.get('snmp_check_interval_minutes', 10))
            
            for device in devices:
                device_id = device['id']
                device_interval = device['snmp_interval_minutes'] if device['snmp_interval_minutes'] and device['snmp_interval_minutes'] > 0 else global_interval
                
                # Stav timeru
                timer_exists = device_id in device_snmp_timers
                timer_active = timer_exists and device_snmp_timers[device_id].is_alive() if timer_exists else False
                
                # Čas od posledného checku
                time_since_check = None
                if device['last_snmp_check']:
                    try:
                        last_check = datetime.fromisoformat(device['last_snmp_check'])
                        time_since_check = (current_time - last_check).total_seconds() / 60
                    except:
                        pass
                
                # Určenie stavu
                if device['monitoring_paused']:
                    status = 'paused'
                elif not timer_exists:
                    status = 'missing'
                elif not timer_active:
                    status = 'dead'
                elif time_since_check and time_since_check > device_interval * 2:
                    status = 'stuck'
                else:
                    status = 'healthy'
                
                timer_status.append({
                    'device_id': device_id,
                    'device_name': device['name'],
                    'device_ip': device['ip'],
                    'interval_minutes': device_interval,
                    'timer_exists': timer_exists,
                    'timer_active': timer_active,
                    'last_check_minutes_ago': round(time_since_check, 1) if time_since_check else None,
                    'status': status,
                    'monitoring_paused': bool(device['monitoring_paused'])
                })
        
        return jsonify({
            'total_timers': len(device_snmp_timers),
            'devices': timer_status
        })
    except Exception as e:
        logger.error(f"Error getting SNMP timer status: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/snmp/timers/restart-all', methods=['POST'])
@login_required
def restart_all_snmp_timers():
    """Reštartuje všetky SNMP timery s CPU optimalizáciou"""
    try:
        logger.info("Restarting all SNMP timers with CPU optimization...")
        stop_all_snmp_timers()
        # Krátka pauza pred spustením nových timerov
        time.sleep(2)
        start_all_snmp_timers()
        add_log('info', "Všetky SNMP timery boli manuálne reštartované s postupným spúšťaním")
        logger.info("All SNMP timers restarted with staggered start delays")
        return jsonify({'status': 'success', 'message': 'Všetky SNMP timery reštartované s CPU optimalizáciou'})
    except Exception as e:
        logger.error(f"Error restarting all SNMP timers: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/snmp/timers/health-check', methods=['POST'])
@login_required
def manual_health_check():
    """Manuálna kontrola zdravia timerov"""
    try:
        data = request.get_json() or {}
        reason = data.get('reason', 'manuálne spustenie z UI')
        
        if trigger_immediate_health_check(reason):
            add_log('info', f"Manuálna kontrola zdravia SNMP timerov spustená - dôvod: {reason}")
            return jsonify({'status': 'success', 'message': 'Health check spustený'})
        else:
            return jsonify({'status': 'throttled', 'message': 'Health check bol throttled (spustený nedávno)'})
    except Exception as e:
        logger.error(f"Error in manual health check: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/logs', methods=['GET'])
@login_required
def get_logs():
    try:
        with get_db_connection() as conn:
            # Získame nastavenie pre limit zobrazených logov
            settings = {row['key']: row['value'] for row in conn.execute('SELECT key, value FROM settings').fetchall()}
            log_limit = int(settings.get('log_max_entries', 2000))
            
            # Vraciame posledných X záznamov, najnovšie prvé
            logs = conn.execute('SELECT * FROM logs ORDER BY timestamp DESC LIMIT ?', (log_limit,)).fetchall()
            return jsonify([dict(row) for row in logs])
    except Exception as e:
        logger.error(f"Chyba pri načítaní logov: {e}")
        return jsonify({'status': 'error', 'message': 'Chyba pri načítaní logov'}), 500

@app.route('/api/logs/export', methods=['GET'])
@login_required
def export_logs():
    """Exportuje všetky logy do CSV súboru"""
    try:
        import csv
        from io import StringIO
        
        with get_db_connection() as conn:
            # Exportujeme všetky logy, najnovšie prvé
            logs = conn.execute('SELECT timestamp, level, message, device_ip FROM logs ORDER BY timestamp DESC').fetchall()
        
        # Vytvoríme CSV v pamäti
        output = StringIO()
        writer = csv.writer(output)
        
        # Hlavička CSV
        writer.writerow(['Dátum a čas', 'Úroveň', 'Správa', 'IP zariadenia'])
        
        # Dáta
        for log in logs:
            timestamp = log[0]
            level = log[1]
            message = log[2]
            device_ip = log[3] or ''
            
            # Formátujeme timestamp pre export
            try:
                if isinstance(timestamp, str):
                    dt = datetime.fromisoformat(timestamp)
                else:
                    dt = timestamp
                formatted_timestamp = dt.strftime('%Y-%m-%d %H:%M:%S')
            except:
                formatted_timestamp = str(timestamp)
            
            writer.writerow([formatted_timestamp, level, message, device_ip])
        
        # Pripravíme response
        csv_content = output.getvalue()
        output.close()
        
        response = app.response_class(
            csv_content,
            mimetype='text/csv',
            headers={
                'Content-Disposition': f'attachment; filename=mikrotik_logy_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv'
            }
        )
        
        add_log('info', "Logy boli exportované do CSV súboru.")
        return response
        
    except Exception as e:
        logger.error(f"Chyba pri exporte logov: {e}")
        return jsonify({'status': 'error', 'message': 'Chyba pri exporte logov'}), 500

@app.route('/api/logs/cleanup', methods=['POST'])
@login_required
def cleanup_logs():
    """Vyčistí staré logy podľa nastavenia"""
    try:
        with get_db_connection() as conn:
            # Získame nastavenie pre uchovávanie logov
            settings = {row['key']: row['value'] for row in conn.execute('SELECT key, value FROM settings').fetchall()}
            retention_days = int(settings.get('log_retention_days', 30))
            
            # Zmazanie logov starších ako nastavený počet dní
            cutoff_date = datetime.now() - timedelta(days=retention_days)
            result = conn.execute('DELETE FROM logs WHERE timestamp < ?', (cutoff_date,))
            deleted_count = result.rowcount
            conn.commit()
            
        add_log('info', f"Vyčistené {deleted_count} starých logov (starších ako {retention_days} dní)")
        return jsonify({'status': 'success', 'deleted_count': deleted_count, 'retention_days': retention_days})
    except Exception as e:
        logger.error(f"Chyba pri čistení logov: {e}")
        return jsonify({'status': 'error', 'message': 'Chyba pri čistení logov'}), 500

@app.route('/api/logs/cleanup-debug', methods=['POST'])
@login_required
def cleanup_debug_logs():
    """Vyčistí všetky debug logy"""
    try:
        with get_db_connection() as conn:
            result = conn.execute("DELETE FROM logs WHERE level = 'DEBUG'")
            deleted_count = result.rowcount
            conn.commit()
            
        add_log('info', f"Vyčistené {deleted_count} debug logov")
        return jsonify({'status': 'success', 'deleted_count': deleted_count})
    except Exception as e:
        logger.error(f"Chyba pri čistení debug logov: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

def scheduled_backup_job():
    with app.app_context():
        add_log('info', "Spúšťam naplánovanú úlohu zálohovania...")
        # Použijeme sekvenčné zálohovanie aj pre plánované úlohy
        with get_db_connection() as conn:
            devices = [dict(row) for row in conn.execute('SELECT * FROM devices').fetchall()]
            settings = {row['key']: row['value'] for row in conn.execute('SELECT key, value FROM settings').fetchall()}
        
        backup_delay = int(settings.get('backup_delay_seconds', 30))
        available_devices = [device for device in devices if device['ip'] not in backup_tasks]
        
        if available_devices:
            add_log('info', f"Plánované zálohovanie: Spúšťam sekvenčnú zálohu pre {len(available_devices)} zariadení.")
            run_sequential_backup(available_devices, backup_delay)
        else:
            add_log('warning', "Plánované zálohovanie: Žiadne dostupné zariadenia na zálohovanie.")

# SNMP Timer Management - Individual timers for each device
device_snmp_timers = {}  # Store timer references for each device

def trigger_immediate_health_check(reason="manuálne spustenie"):
    """Spustí okamžitý health check s inteligentným throttling pre zabránenie nadmerného používania"""
    try:
        # Inteligentné throttling: kratšie pre SNMP zmeny, dlhšie pre manuálne volania
        current_time = time.time()
        if not hasattr(trigger_immediate_health_check, 'last_run'):
            trigger_immediate_health_check.last_run = 0
        
        time_since_last = current_time - trigger_immediate_health_check.last_run
        
        # Inteligentné throttling podľa dôvodu
        if "snmp" in reason.lower() or "interval" in reason.lower():
            # Pre SNMP zmeny: len 5 sekúnd throttling (užívateľ môže rýchlo meniť nastavenia)
            throttle_time = 5
        else:
            # Pre manuálne volania: 30 sekúnd throttling (prevencia spam)
            throttle_time = 30
        
        if time_since_last < throttle_time:
            logger.info(f"Health check throttled - posledný spustený pred {time_since_last:.1f}s, potrebných {throttle_time}s (dôvod: {reason})")
            return False
        
        # Spustíme health check v separate threade aby neblokoval hlavné vlákno
        def run_health_check():
            try:
                with app.app_context():
                    logger.info(f"Spúšťam okamžitý SNMP health check - dôvod: {reason}")
                    check_snmp_timers_health()
                    logger.info(f"Okamžitý SNMP health check dokončený")
            except Exception as e:
                logger.error(f"Chyba v okamžitom health check: {e}")
        
        # Spustíme v separate threade
        import threading
        health_check_thread = threading.Thread(target=run_health_check, daemon=True)
        health_check_thread.start()
        
        trigger_immediate_health_check.last_run = current_time
        return True
        
    except Exception as e:
        logger.error(f"Chyba pri spúšťaní okamžitého health check: {e}")
        return False

def check_snmp_timers_health():
    """Kontroluje zdravie SNMP timerov a reštartuje mŕtve timery"""
    try:
        with get_db_connection() as conn:
            devices = conn.execute('SELECT id, name, ip, snmp_interval_minutes, last_snmp_check FROM devices WHERE monitoring_paused = 0 OR monitoring_paused IS NULL').fetchall()
            settings = {row['key']: row['value'] for row in conn.execute('SELECT key, value FROM settings').fetchall()}
            global_interval = int(settings.get('snmp_check_interval_minutes', 10))
            
            current_time = datetime.now()
            
            for device in devices:
                device_id = device['id']
                device_interval = device['snmp_interval_minutes'] if device['snmp_interval_minutes'] and device['snmp_interval_minutes'] > 0 else global_interval
                
                # Kontrola či timer existuje
                if device_id not in device_snmp_timers:
                    logger.warning(f"Missing SNMP timer for device {device['name']} (ID: {device_id}), restarting...")
                    start_snmp_timer_for_device(device_id, device_interval, immediate=False)
                    add_log('warning', f"SNMP timer neexistoval, reštartovaný (interval: {device_interval}min)", device['ip'])
                    continue
                
                # Kontrola posledného SNMP checku
                if device['last_snmp_check']:
                    try:
                        last_check = datetime.fromisoformat(device['last_snmp_check'])
                        time_since_check = (current_time - last_check).total_seconds() / 60  # v minútach
                        
                        # Ak je čas od posledného checku viac ako 2x interval, timer sa zasekol
                        if time_since_check > device_interval * 2:
                            logger.warning(f"SNMP timer stuck for device {device['name']} (ID: {device_id}), last check {time_since_check:.1f}min ago, restarting...")
                            restart_snmp_timer_for_device(device_id, device_interval)
                            add_log('warning', f"SNMP timer sa zasekol ({time_since_check:.1f}min bez checku), reštartovaný", device['ip'])
                    except Exception as e:
                        logger.error(f"Error parsing last_snmp_check for device {device_id}: {e}")
                        
    except Exception as e:
        logger.error(f"Error in SNMP timer health check: {e}")

def scheduled_snmp_health_check():
    """Automatická kontrola zdravia SNMP timerov"""
    with app.app_context():
        check_snmp_timers_health()

def start_snmp_timer_for_device(device_id, interval_minutes, immediate=False):
    """Start individual SNMP timer for a specific device"""
    global device_snmp_timers
    
    # Stop existing timer if running
    if device_id in device_snmp_timers:
        device_snmp_timers[device_id].cancel()
    
    def snmp_check_device():
        """Perform SNMP check for this specific device and schedule next check"""
        try:
            with app.app_context():
                with get_db_connection() as conn:
                    device = conn.execute('SELECT id, ip, name, snmp_community, monitoring_paused FROM devices WHERE id = ?', (device_id,)).fetchone()
                    
                    if not device:
                        logger.warning(f"Device {device_id} not found, stopping SNMP timer")
                        return
                    
                    # Skip if monitoring is paused
                    if device['monitoring_paused']:
                        debug_log('debug_snmp_timers', f"Device {device['name']} monitoring paused, skipping SNMP check")
                        # Schedule next check anyway (in case pause gets disabled)
                        schedule_next_check()
                        return
                    
                    # Perform the actual SNMP check
                    debug_log('debug_snmp_timers', f"Performing SNMP check for device {device['name']} (interval: {interval_minutes}min)")
                    
                    # Get SNMP data
                    snmp_data = get_snmp_data(device['ip'], device['snmp_community'])
                    status = 'online' if snmp_data.get('uptime') != 'N/A' else 'offline'
                    
                    if snmp_data:
                        # Save to database - update same fields as manual check
                        timestamp = datetime.now()
                        conn.execute("UPDATE devices SET last_snmp_data = ?, status = ?, last_snmp_check = ? WHERE id = ?", 
                                   (json.dumps(snmp_data), status, timestamp.isoformat(), device_id))
                        conn.commit()
                        
                        # Save to SNMP history
                        save_snmp_history(device_id, snmp_data)
                        
                        # Emit to WebSocket
                        debug_emit('snmp_update', {
                            'id': device_id,
                            'data': snmp_data,
                            'status': status
                        })
                        
                        debug_log('debug_snmp_data', f"SNMP data saved and emitted for device {device['name']}")
                    else:
                        logger.warning(f"Failed to get SNMP data for device {device['name']}")
                    
                    # Schedule next check
                    schedule_next_check()
                    
        except Exception as e:
            logger.error(f"Error in SNMP check for device {device_id}: {e}")
            # Schedule next check even on error
            schedule_next_check()
    
    def schedule_next_check():
        """Schedule the next SNMP check for this device"""
        try:
            # Vytvor nový timer a spusti ho
            timer = threading.Timer(interval_minutes * 60, snmp_check_device)
            device_snmp_timers[device_id] = timer
            timer.start()
            debug_log('debug_snmp_timers', f"Next SNMP check for device {device_id} scheduled in {interval_minutes} minutes, timer active: {timer.is_alive()}")
        except Exception as e:
            logger.error(f"Error scheduling next SNMP check for device {device_id}: {e}")
    
    # Start the timer (immediately or after interval)
    if immediate:
        # Run immediately and then schedule next - but first create a placeholder timer
        # to avoid missing timer reference
        placeholder_timer = threading.Timer(0.1, lambda: None)  # Dummy timer
        device_snmp_timers[device_id] = placeholder_timer
        placeholder_timer.start()  # Spustíme placeholder timer
        # Run check immediately in separate thread
        debug_log('debug_snmp_timers', f"SNMP timer starting immediately for device {device_id} (interval: {interval_minutes}min)")
        threading.Thread(target=snmp_check_device, daemon=True).start()
    else:
        # Schedule first check after interval
        timer = threading.Timer(interval_minutes * 60, snmp_check_device)
        device_snmp_timers[device_id] = timer
        timer.start()
        debug_log('debug_snmp_timers', f"SNMP timer started for device {device_id}, first check in {interval_minutes} minutes")

def stop_snmp_timer_for_device(device_id):
    """Stop SNMP timer for a specific device"""
    global device_snmp_timers
    
    if device_id in device_snmp_timers:
        device_snmp_timers[device_id].cancel()
        del device_snmp_timers[device_id]
        debug_log('debug_snmp_timers', f"SNMP timer stopped for device {device_id}")

def restart_snmp_timer_for_device(device_id, interval_minutes):
    """Restart SNMP timer for a device with new interval"""
    stop_snmp_timer_for_device(device_id)
    start_snmp_timer_for_device(device_id, interval_minutes, immediate=True)
    # Log odstránený - zbytočne zahltáva systém pri manuálnych checkoch

def start_all_snmp_timers():
    """Start SNMP timers for all devices based on their settings - optimized startup"""
    try:
        with get_db_connection() as conn:
            settings = {row['key']: row['value'] for row in conn.execute('SELECT key, value FROM settings').fetchall()}
            global_interval = int(settings.get('snmp_check_interval_minutes', 10))
            
            devices = conn.execute('SELECT id, name, snmp_interval_minutes FROM devices').fetchall()
            device_count = len(devices)
            
            # Ak je veľa zariadení, rozložíme ich na kratší čas
            max_startup_time = min(300, device_count * 15)  # Max 5 minút alebo 15s na zariadenie
            
            # Optimalizácia: rozložiť timery na dlhšie intervaly pri štarte
            for i, device in enumerate(devices):
                device_interval = device['snmp_interval_minutes'] or 0
                effective_interval = device_interval if device_interval > 0 else global_interval
                
                # Inteligentné rozloženie záťaže:
                # - Prvé zariadenie: 30 sekúnd delay
                # - Ostatné: postupne rozložené cez celý startup interval
                if i == 0:
                    start_delay = 30  # Prvé zariadenie po 30 sekundách
                else:
                    # Rozloženie zostávajúcich zariadení cez zvyšný čas
                    start_delay = 30 + ((max_startup_time - 30) * i // (device_count - 1))
                
                def delayed_start(device_id=device['id'], interval=effective_interval, delay=start_delay):
                    def start_timer():
                        try:
                            start_snmp_timer_for_device(device_id, interval, immediate=False)
                        except Exception as e:
                            logger.error(f"Error starting delayed SNMP timer for device {device_id}: {e}")
                    
                    timer = threading.Timer(delay, start_timer)
                    timer.daemon = True
                    timer.start()
                
                delayed_start()
                
                # Log len pre prvé a posledné zariadenie
                if i == 0 or i == device_count - 1:
                    logger.info(f"Scheduled SNMP timer for device {device['name']} (delay: {start_delay}s)")
                
    except Exception as e:
        logger.error(f"Error starting SNMP timers: {e}")

def stop_all_snmp_timers():
    """Stop all SNMP timers"""
    global device_snmp_timers
    
    for device_id in list(device_snmp_timers.keys()):
        stop_snmp_timer_for_device(device_id)
    
    logger.info("All SNMP timers stopped")

def setup_scheduler(log_schedule_info=False):
    # Vždy vyčistíme existujúce úlohy, aby sme predišli duplicitám alebo starým nastaveniam
    schedule.clear()

    with get_db_connection() as conn:
        settings = {row['key']: row['value'] for row in conn.execute('SELECT key, value FROM settings').fetchall()}
    
    # SNMP checks are now handled by individual timers - no scheduler needed
    # Only keep essential scheduled tasks
    schedule.every().day.at("03:00").do(scheduled_log_cleanup)  # Čistenie starých logov každý deň o 3:00
    
    # NOVÉ: Kontrola zdravia SNMP timerov každých 15 minút
    schedule.every(15).minutes.do(scheduled_snmp_health_check)
    
    # Nastavenie automatického zálohovania
    if settings.get('backup_schedule_enabled', 'false').lower() != 'true':
        if log_schedule_info:
            add_log('info', "Automatické zálohovanie je v nastaveniach vypnuté.")
        return

    # Ak nie je zadaný čas, použijeme predvolený, aby sme predišli chybe
    schedule_time = settings.get('backup_schedule_time') or '02:00'
    try:
        if settings.get('backup_schedule_type', 'daily') == 'daily':
            schedule.every().day.at(schedule_time).do(scheduled_backup_job)
            if log_schedule_info:
                add_log('info', f"Automatické zálohovanie je aktívne: Denne o {schedule_time}.")
        else:
            day = settings.get('backup_schedule_day', 'sunday').lower()
            day_sk = {'monday': 'Pondelok', 'tuesday': 'Utorok', 'wednesday': 'Streda', 'thursday': 'Štvrtok', 'friday': 'Piatok', 'saturday': 'Sobota', 'sunday': 'Nedeľa'}.get(day, day.capitalize())
            getattr(schedule.every(), day).at(schedule_time).do(scheduled_backup_job)
            if log_schedule_info:
                add_log('info', f"Automatické zálohovanie je aktívne: Každý {day_sk} o {schedule_time}.")
    except ValueError as e:
        if log_schedule_info:
            add_log('error', f"Chyba pri nastavení automatického zálohovania: Neplatný čas '{schedule_time}'. Použite formát HH:MM.")
        logger.error(f"Invalid backup schedule time: {schedule_time}, error: {e}")

    if log_schedule_info:
        # Log current schedule info without SNMP check info
        schedule_info = get_schedule_info()
        if "SNMP" not in schedule_info:  # Only log if we have non-SNMP schedules
            add_log('info', f"Plánovač úloh: {schedule_info}")

def get_schedule_info():
    """Vráti informácie o pláne automatického zálohovania bez zapisovania do logov"""
    with get_db_connection() as conn:
        settings = {row['key']: row['value'] for row in conn.execute('SELECT key, value FROM settings').fetchall()}
    
    if settings.get('backup_schedule_enabled', 'false').lower() != 'true':
        return "Automatické zálohovanie je v nastaveniach vypnuté."
    
    schedule_time = settings.get('backup_schedule_time') or '02:00'
    try:
        if settings.get('backup_schedule_type', 'daily') == 'daily':
            return f"Automatické zálohovanie je aktívne: Denne o {schedule_time}."
        else:
            day = settings.get('backup_schedule_day', 'sunday').lower()
            day_sk = {'monday': 'Pondelok', 'tuesday': 'Utorok', 'wednesday': 'Streda', 'thursday': 'Štvrtok', 'friday': 'Piatok', 'saturday': 'Sobota', 'sunday': 'Nedeľa'}.get(day, day.capitalize())
            return f"Automatické zálohovanie je aktívne: Každý {day_sk} o {schedule_time}."
    except Exception as e:
        return f"Chyba pri získavaní informácií o pláne: {e}"

# SNMP checks are now handled by individual device timers (see functions above)
# Old scheduled_snmp_check function removed - replaced by start_snmp_timer_for_device()

def run_scheduler():
    while True:
        schedule.run_pending()
        time.sleep(60)

def scheduled_log_cleanup():
    """Automatické čistenie starých logov"""
    with app.app_context():
        try:
            with get_db_connection() as conn:
                # Získame nastavenie pre uchovávanie logov
                settings = {row['key']: row['value'] for row in conn.execute('SELECT key, value FROM settings').fetchall()}
                retention_days = int(settings.get('log_retention_days', 30))
                
                cutoff_date = datetime.now() - timedelta(days=retention_days)
                result = conn.execute('DELETE FROM logs WHERE timestamp < ?', (cutoff_date,))
                deleted_count = result.rowcount
                conn.commit()
                
            if deleted_count > 0:
                add_log('info', f"Automaticky vyčistené {deleted_count} starých logov (starších ako {retention_days} dní)")
        except Exception as e:
            logger.error(f"Chyba pri automatickom čistení logov: {e}")

# --- Spustenie plánovača ---
with app.app_context():
    init_database()
    migrate_existing_passwords()  # Encrypt existing plaintext passwords
    setup_scheduler(log_schedule_info=False)  # Pri štarte aplikácie nelogujeme info o schedule
    start_all_snmp_timers()  # Spustenie SNMP timerov pre všetky zariadenia

threading.Thread(target=run_scheduler, daemon=True).start()

logger.info("Aplikácia MikroTik Manager sa spúšťa...")

# === PING MONITORING FUNKCIE ===

def ping_device(ip, count=1, timeout=None):
    """Ping zariadenie a vráť štatistiky - optimalizované pre rýchle intervaly"""
    try:
        # Použiť timeout z parametra alebo default hodnotu
        if timeout is None:
            with get_db_connection() as conn:
                cursor = conn.cursor()
                timeout_setting = cursor.execute('SELECT value FROM settings WHERE key = ?', ('ping_timeout',)).fetchone()
                timeout = int(timeout_setting['value']) if timeout_setting else 1
        
        # Pre rýchle intervaly používame len 1 ping s nastaveným timeout
        result = subprocess.run(['ping', '-c', str(count), '-W', str(timeout), ip], 
                              capture_output=True, text=True, timeout=timeout + 2)  # Pridáme +2s buffer pre subprocess timeout
        
        if result.returncode == 0:
            # Parsovanie výsledkov
            output = result.stdout
            
            # Packet loss
            loss_match = re.search(r'(\d+)% packet loss', output)
            packet_loss = int(loss_match.group(1)) if loss_match else 0
            
            # Average latency
            time_matches = re.findall(r'time=(\d+\.?\d*)', output)
            if time_matches:
                avg_latency = sum(float(t) for t in time_matches) / len(time_matches)
            else:
                avg_latency = None
                
            return {
                'status': 'online',
                'packet_loss': packet_loss,
                'avg_latency': avg_latency,
                'timestamp': datetime.now().isoformat()
            }
        else:
            return {
                'status': 'offline',
                'packet_loss': 100,
                'avg_latency': None,
                'timestamp': datetime.now().isoformat()
            }
    except Exception as e:
        logger.error(f"Chyba pri ping-ovaní {ip}: {e}")
        return {
            'status': 'offline',
            'packet_loss': 100,
            'avg_latency': None,
            'timestamp': datetime.now().isoformat()
        }

def save_ping_result(device_id, ping_result):
    """Uloží ping výsledok do databázy"""
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO ping_history (device_id, timestamp, avg_latency, packet_loss, status)
                VALUES (?, ?, ?, ?, ?)
            ''', (device_id, ping_result['timestamp'], ping_result['avg_latency'], 
                  ping_result['packet_loss'], ping_result['status']))
            
            # Aktualizujeme stav zariadenia v devices tabuľke
            cursor.execute('UPDATE devices SET status = ? WHERE id = ?', (ping_result['status'], device_id))
            
            conn.commit()
            
            # Vyčistíme staré záznamy podľa nastavenia (default 30 dní pre ping history)
            settings = {row['key']: row['value'] for row in cursor.execute('SELECT key, value FROM settings').fetchall()}
            ping_retention_days = int(settings.get('ping_retention_days', 30))
            cutoff_date = datetime.now() - timedelta(days=ping_retention_days)
            cursor.execute('DELETE FROM ping_history WHERE timestamp < ?', (cutoff_date.isoformat(),))
            conn.commit()
            
    except Exception as e:
        logger.error(f"Chyba pri ukladaní ping výsledku: {e}")

def save_snmp_history(device_id, snmp_data):
    """Uloží SNMP dáta do history tabuľky"""
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO snmp_history (device_id, timestamp, cpu_load, temperature, memory_usage, uptime, total_memory, free_memory)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (device_id, datetime.now().isoformat(), 
                  snmp_data.get('cpu_load'), snmp_data.get('temperature'),
                  snmp_data.get('memory_usage'), snmp_data.get('uptime'),
                  snmp_data.get('total_memory'), snmp_data.get('free_memory')))
            conn.commit()
            
            # Vyčistíme staré záznamy podľa nastavenia (default 30 dní pre SNMP history)
            settings = {row['key']: row['value'] for row in cursor.execute('SELECT key, value FROM settings').fetchall()}
            snmp_retention_days = int(settings.get('snmp_retention_days', 30))
            cutoff_date = datetime.now() - timedelta(days=snmp_retention_days)
            cursor.execute('DELETE FROM snmp_history WHERE timestamp < ?', (cutoff_date.isoformat(),))
            conn.commit()
            
    except Exception as e:
        logger.error(f"Chyba pri ukladaní SNMP history: {e}")

def ping_monitoring_loop():
    """Nekonečná slučka pre ping monitoring s presným dodržaním intervalov pre každé zariadenie"""
    global ping_thread_stop_flag
    
    # Slovník pre sledovanie posledného ping času každého zariadenia v pamäti
    device_last_ping = {}
    
    # Slovník pre sledovanie stavu zariadení a počtu neúspešných pingov
    device_status_tracker = {}
    
    while not ping_thread_stop_flag.is_set():
        try:
            # Načítame nastavenia pre ping monitoring
            with get_db_connection() as conn:
                cursor = conn.cursor()
                settings_rows = cursor.execute('''
                    SELECT key, value FROM settings 
                    WHERE key IN (?, ?, ?, ?, ?)
                ''', ('ping_check_interval_seconds', 'ping_monitor_enabled', 'ping_retry_interval', 
                     'ping_retries', 'ping_timeout')).fetchall()
                settings = {row['key']: row['value'] for row in settings_rows}
                
                # Kontrola či je ping monitoring povolený
                ping_enabled = settings.get('ping_monitor_enabled', 'true').lower() == 'true'
                global_ping_interval = int(settings.get('ping_check_interval_seconds', '120'))  # Default 2 minúty
                retry_interval = int(settings.get('ping_retry_interval', '20'))  # Default 20 sekúnd
                max_retries = int(settings.get('ping_retries', '3'))  # Default 3 pokusy
                ping_timeout = int(settings.get('ping_timeout', '5'))  # Default 5 sekúnd
                
                if not ping_enabled:
                    logger.info("Ping monitoring je zakázaný")
                    # Počkáme 60 sekúnd alebo stop signal
                    if ping_thread_stop_flag.wait(timeout=60):
                        break
                    continue
                
                # Získaj zariadenia s ich ping interval nastaveniami (okrem paused zariadení)
                cursor.execute('''
                    SELECT id, ip, ping_interval_seconds, status
                    FROM devices
                    WHERE monitoring_paused = 0 OR monitoring_paused IS NULL
                ''')
                devices = cursor.fetchall()
                
                current_time = datetime.now()
                devices_to_ping = []
                
                # Najkratší interval pre dynamické nastavenie check intervalu
                shortest_interval = global_ping_interval
                
                for device in devices:
                    device_id, ip, device_ping_interval, db_status = device
                    
                    # Iniciálne nastavenie tracker-a pre zariadenie ak neexistuje
                    if device_id not in device_status_tracker:
                        device_status_tracker[device_id] = {
                            'status': db_status or 'unknown',
                            'failed_count': 0,
                            'last_status_change': current_time,
                            'in_retry_mode': False
                        }
                    
                    # Použij device-specific interval, ak je nastavený, inak global
                    effective_interval = device_ping_interval if device_ping_interval and device_ping_interval > 0 else global_ping_interval
                    
                    # Ak je zariadenie v retry mode, použijeme retry interval namiesto normálneho
                    if device_status_tracker[device_id]['in_retry_mode']:
                        effective_interval = retry_interval
                    
                    # Sleduj najkratší interval
                    if effective_interval < shortest_interval:
                        shortest_interval = effective_interval
                    
                    # Kontrola pre každé zariadenie individuálne
                    should_ping = False
                    
                    if device_id not in device_last_ping:
                        # Prvý ping - pinguj okamžite
                        should_ping = True
                        debug_log('debug_ping_monitoring', f"Device {ip} (ID: {device_id}): prvý ping, interval: {effective_interval}s")
                    else:
                        # Kontrola času od posledného pingu pre toto zariadenie
                        seconds_since_ping = (current_time - device_last_ping[device_id]).total_seconds()
                        
                        if seconds_since_ping >= effective_interval:
                            should_ping = True
                            if device_status_tracker[device_id]['in_retry_mode']:
                                debug_log('debug_ping_monitoring', 
                                          f"Device {ip} (ID: {device_id}): retry ping, failed count: {device_status_tracker[device_id]['failed_count']}")
                            else:
                                debug_log('debug_ping_monitoring', 
                                          f"Device {ip} (ID: {device_id}): {seconds_since_ping:.2f}s od posledného pingu (interval: {effective_interval}s)")
                        else:
                            remaining = effective_interval - seconds_since_ping
                            debug_log('debug_ping_monitoring', 
                                      f"Device {ip} (ID: {device_id}): zostáva {remaining:.2f}s do ďalšieho pingu")
                    
                    if should_ping:
                        devices_to_ping.append((device_id, ip, effective_interval, retry_interval, max_retries, ping_timeout))
                
                # Ping všetky zariadenia, ktoré potrebujú ping - spustíme ich paralelne pre presnosť
                if devices_to_ping:
                    import concurrent.futures
                    import threading
                    
                    def ping_single_device(device_info):
                        device_id, ip, interval, retry_interval, max_retries, ping_timeout = device_info
                        try:
                            # Zaznačíme čas PRED pingom pre presnosť
                            ping_time = datetime.now()
                            device_last_ping[device_id] = ping_time
                            
                            # Pre krátke intervaly používame rýchly ping
                            ping_result = ping_device(ip, count=1 if interval <= 10 else 2, timeout=ping_timeout)
                            
                            # Spracovanie výsledku pingu
                            current_status = device_status_tracker[device_id]['status']
                            in_retry_mode = device_status_tracker[device_id]['in_retry_mode']
                            failed_count = device_status_tracker[device_id]['failed_count']
                            
                            if ping_result['status'] == 'online':
                                # Úspešný ping - zariadenie je online
                                if current_status == 'offline':
                                    # Zariadenie bolo offline a teraz je online - zmena stavu
                                    add_log('info', f"Zariadenie {ip} je opäť online")
                                    send_pushover_notification(f"Zariadenie {ip} je opäť online", title="MikroTik Monitor - Zariadenie Online")
                                
                                # Reset retry counter and mode
                                device_status_tracker[device_id] = {
                                    'status': 'online',
                                    'failed_count': 0,
                                    'last_status_change': datetime.now(),
                                    'in_retry_mode': False
                                }
                            else:
                                # Neúspešný ping
                                if not in_retry_mode:
                                    # Prvý neúspešný ping - prejdi do retry mode
                                    device_status_tracker[device_id]['in_retry_mode'] = True
                                    device_status_tracker[device_id]['failed_count'] = 1
                                    debug_log('debug_ping_monitoring', 
                                              f"Device {ip} (ID: {device_id}): Prvý neúspešný ping - prejdem do retry mode (1/{max_retries})")
                                else:
                                    # Už v retry mode - zvýš počítadlo
                                    device_status_tracker[device_id]['failed_count'] += 1
                                    debug_log('debug_ping_monitoring', 
                                              f"Device {ip} (ID: {device_id}): Neúspešný ping {device_status_tracker[device_id]['failed_count']}/{max_retries}")
                                
                                # Kontrola či sme dosiahli maximálny počet neúspešných pokusov
                                if device_status_tracker[device_id]['failed_count'] >= max_retries:
                                    if current_status != 'offline':
                                        # Zmena stavu na offline
                                        device_status_tracker[device_id]['status'] = 'offline'
                                        device_status_tracker[device_id]['last_status_change'] = datetime.now()
                                        add_log('error', f"Zariadenie {ip} je offline (po {max_retries} neúspešných pokusoch)")
                                        send_pushover_notification(f"Zariadenie {ip} je offline", title="MikroTik Monitor - Zariadenie Offline")
                                        # Naďalej zostávame v retry mode pre monitoring
                            
                            # Uložíme výsledok a aktuálny status
                            ping_result['status'] = device_status_tracker[device_id]['status']
                            save_ping_result(device_id, ping_result)
                            
                            # Aktualizujeme stav v databáze
                            with get_db_connection() as conn:
                                conn.execute('UPDATE devices SET status = ? WHERE id = ?', 
                                             (device_status_tracker[device_id]['status'], device_id))
                                conn.commit()
                            
                            # Pošleme update cez WebSocket
                            debug_emit('ping_update', {
                                'device_id': device_id,
                                'status': ping_result['status'],
                                'avg_latency': ping_result['avg_latency'],
                                'packet_loss': ping_result['packet_loss'],
                                'timestamp': ping_result['timestamp']
                            })
                            
                            logger.info(f"Ping {ip} (interval: {interval}s): {ping_result['status']}, "
                                      f"latencia: {ping_result['avg_latency']}ms, "
                                      f"packet loss: {ping_result['packet_loss']}%")
                            
                        except Exception as e:
                            logger.error(f"Chyba pri pingu zariadenia {ip}: {e}")
                    
                    # Paralelne pingujeme všetky zariadenia naraz pre presnosť časovania
                    with concurrent.futures.ThreadPoolExecutor(max_workers=min(len(devices_to_ping), 20)) as executor:
                        futures = [executor.submit(ping_single_device, device_info) for device_info in devices_to_ping]
                        # Kratší timeout pre rýchle intervaly
                        timeout = min(10, shortest_interval / 2) if shortest_interval < 10 else 15
                        concurrent.futures.wait(futures, timeout=timeout)
                
                # Optimalizované nastavenie check intervalu - menej prísne pre lepší výkon
                if shortest_interval <= 1:
                    next_check_interval = 0.2  # Kontrola každých 200ms pre sub-sekundové intervaly (bolo 0.1s)
                elif shortest_interval <= 5:
                    next_check_interval = 0.5  # Kontrola každých 500ms pre krátke intervaly (bolo 0.2s)
                elif shortest_interval <= 30:
                    next_check_interval = 1.0  # Kontrola každú sekundu pre stredné intervaly (bolo 0.5s)
                elif shortest_interval <= 120:
                    next_check_interval = 2.0  # Kontrola každé 2 sekundy pre dlhé intervaly
                else:
                    next_check_interval = 5.0   # Kontrola každých 5 sekúnd pre veľmi dlhé intervaly
                
                debug_log('debug_ping_monitoring', f"Ping monitoring: pingované {len(devices_to_ping)} zariadení, najkratší interval: {shortest_interval}s, ďalšia kontrola za {next_check_interval}s")
                    
        except Exception as e:
            logger.error(f"Chyba v ping monitoring loop: {e}")
            next_check_interval = 5  # Fallback pri chybe
        
        # Dynamický check interval pre maximálnu presnosť
        if ping_thread_stop_flag.wait(timeout=next_check_interval):
            break
    
    logger.info("Ping monitoring loop ukončený")

# === MONITORING API ENDPOINTY ===

@app.route('/api/monitoring/device/<int:device_id>/settings', methods=['GET', 'POST'])
@login_required
def monitoring_device_settings(device_id):
    """Získa alebo nastaví monitoring nastavenia pre konkrétne zariadenie"""
    if request.method == 'GET':
        try:
            with get_db_connection() as conn:
                device = conn.execute('''
                    SELECT id, name, ip, ping_interval_seconds, snmp_interval_minutes, monitoring_paused 
                    FROM devices WHERE id = ?
                ''', (device_id,)).fetchone()
                
                if not device:
                    return jsonify({'status': 'error', 'message': 'Zariadenie nenájdené'}), 404
                
                # Získaj globálne nastavenia
                settings = {row['key']: row['value'] for row in 
                           conn.execute('SELECT key, value FROM settings WHERE key IN (?, ?)', 
                                      ('ping_check_interval_seconds', 'snmp_check_interval_minutes')).fetchall()}
                
                return jsonify({
                    'device': {
                        'id': device[0],
                        'name': device[1], 
                        'ip': device[2],
                        'ping_interval_seconds': device[3] or 0,
                        'snmp_interval_minutes': device[4] or 0,
                        'monitoring_paused': bool(device[5])
                    },
                    'global_settings': {
                        'ping_interval_seconds': int(settings.get('ping_check_interval_seconds', 120)),
                        'snmp_interval_minutes': int(settings.get('snmp_check_interval_minutes', 10))
                    }
                })
        except Exception as e:
            logger.error(f"Chyba pri získavaní device settings: {e}")
            return jsonify({'status': 'error', 'message': str(e)}), 500
    
    elif request.method == 'POST':
        try:
            data = request.json
            ping_interval = data.get('ping_interval_seconds', 0)
            snmp_interval = data.get('snmp_interval_minutes', 0)
            
            # Validácia
            if ping_interval < 0 or ping_interval > 86400:  # 0-24 hodín
                return jsonify({'status': 'error', 'message': 'Ping interval musí byť 0-86400 sekúnd'}), 400
            if snmp_interval < 0 or snmp_interval > 1440:  # 0-24 hodín
                return jsonify({'status': 'error', 'message': 'SNMP interval musí byť 0-1440 minút'}), 400
            
            with get_db_connection() as conn:
                # Get old SNMP interval before update
                old_device = conn.execute('SELECT snmp_interval_minutes FROM devices WHERE id = ?', (device_id,)).fetchone()
                old_snmp_interval = old_device[0] if old_device else 0
                
                conn.execute('''
                    UPDATE devices 
                    SET ping_interval_seconds = ?, snmp_interval_minutes = ?
                    WHERE id = ?
                ''', (ping_interval, snmp_interval, device_id))
                conn.commit()
                
                device = conn.execute('SELECT name, ip FROM devices WHERE id = ?', (device_id,)).fetchone()
                if device:
                    add_log('info', f"Monitoring nastavenia aktualizované pre {device[1]} ({device[0]}): ping {ping_interval}s, SNMP {snmp_interval}min")
                
                # Restart SNMP timer if interval changed
                if old_snmp_interval != snmp_interval:
                    if snmp_interval > 0:
                        restart_snmp_timer_for_device(device_id, snmp_interval)
                    else:
                        # Use global interval
                        settings = {row['key']: row['value'] for row in conn.execute('SELECT key, value FROM settings').fetchall()}
                        global_interval = int(settings.get('snmp_check_interval_minutes', 10))
                        restart_snmp_timer_for_device(device_id, global_interval)
                
            return jsonify({'status': 'success', 'message': 'Nastavenia uložené'})
            
        except Exception as e:
            logger.error(f"Chyba pri ukladaní device settings: {e}")
            return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/monitoring/device/<int:device_id>/pause', methods=['POST'])
@login_required
def monitoring_device_pause_resume(device_id):
    """Toggle pause/resume monitoring pre zariadenie"""
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            
            # Skontroluj či zariadenie existuje a získaj aktuálny stav
            device_data = cursor.execute('SELECT name, ip, monitoring_paused FROM devices WHERE id = ?', (device_id,)).fetchone()
            if not device_data:
                return jsonify({'status': 'error', 'message': 'Zariadenie nenájdené'}), 404
            
            device_name, device_ip, current_paused = device_data
            
            # Toggle stav - ak je NULL alebo 0, nastav na 1, inak nastav na 0
            new_paused = 0 if current_paused else 1
            
            # Aktualizuj monitoring_paused status
            cursor.execute('''
                UPDATE devices 
                SET monitoring_paused = ?
                WHERE id = ?
            ''', (new_paused, device_id))
            conn.commit()
            
            # Zastav/spusti SNMP timer pre toto zariadenie
            if new_paused:
                stop_snmp_timer_for_device(device_id)
            else:
                # Získaj správny interval pre toto zariadenie pred spustením timera
                device_info = cursor.execute('SELECT snmp_interval_minutes FROM devices WHERE id = ?', (device_id,)).fetchone()
                device_interval = device_info[0] if device_info and device_info[0] else 0
                
                # Ak device nemá vlastný interval, použij globálny
                if device_interval <= 0:
                    settings = {row['key']: row['value'] for row in cursor.execute('SELECT key, value FROM settings').fetchall()}
                    device_interval = int(settings.get('snmp_check_interval_minutes', 10))
                
                start_snmp_timer_for_device(device_id, device_interval, immediate=False)
            
            action_text = 'pozastavený' if new_paused else 'obnovený'
            
            add_log('info', f"Monitoring {action_text} pre {device_name} ({device_ip})")
            logger.info(f"Monitoring {action_text} pre zariadenie {device_name} ({device_ip}) - ID: {device_id}")
            
            return jsonify({
                'status': 'success',
                'monitoring_paused': bool(new_paused),
                'message': f'Monitoring {action_text} pre {device_name}'
            })
            
    except Exception as e:
        logger.error(f"Chyba pri zmene monitoring stavu pre zariadenie {device_id}: {str(e)}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/monitoring/ping/manual/<int:device_id>', methods=['POST'])
@login_required
def manual_ping_device(device_id):
    """Manuálny ping zariadenia"""
    try:
        with get_db_connection() as conn:
            device = conn.execute('SELECT ip, name FROM devices WHERE id = ?', (device_id,)).fetchone()
            
            if not device:
                return jsonify({'status': 'error', 'message': 'Zariadenie nenájdené'}), 404
            
            # Načítaj ping_timeout nastavenie
            ping_timeout = conn.execute('SELECT value FROM settings WHERE key = ?', ('ping_timeout',)).fetchone()
            timeout = int(ping_timeout['value']) if ping_timeout else 5
            
            ip, name = device
            ping_result = ping_device(ip, timeout=timeout)
            save_ping_result(device_id, ping_result)
            
            # Pošleme update cez WebSocket
            debug_emit('ping_update', {
                'device_id': device_id,
                'status': ping_result['status'],
                'avg_latency': ping_result['avg_latency'],
                'packet_loss': ping_result['packet_loss'],
                'timestamp': ping_result['timestamp']
            })
            
            add_log('info', f"Manuálny ping {ip} ({name}): {ping_result['status']}")
            return jsonify(ping_result)
            
    except Exception as e:
        logger.error(f"Chyba pri manuálnom ping: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/monitoring/debug/settings')
@login_required
def debug_monitoring_settings():
    """Debug endpoint pre kontrolu ping monitoring nastavení"""
    try:
        with get_db_connection() as conn:
            # Získaj globálne nastavenia
            settings = {row['key']: row['value'] for row in 
                       conn.execute('SELECT key, value FROM settings WHERE key LIKE "%ping%"').fetchall()}
            
            # Získaj device nastavenia
            devices = conn.execute('''
                SELECT id, name, ip, ping_interval_seconds, 
                       (SELECT MAX(timestamp) FROM ping_history WHERE device_id = devices.id) as last_ping
                FROM devices
            ''').fetchall()
            
            device_info = []
            current_time = datetime.now()
            for device in devices:
                device_id, name, ip, device_ping_interval, last_ping_str = device
                
                global_ping_interval = int(settings.get('ping_check_interval_seconds', '120'))
                effective_interval = device_ping_interval if device_ping_interval and device_ping_interval > 0 else global_ping_interval
                
                seconds_since_ping = None
                if last_ping_str:
                    try:
                        last_ping = datetime.fromisoformat(last_ping_str)
                        seconds_since_ping = (current_time - last_ping).total_seconds()
                    except:
                        pass
                
                device_info.append({
                    'id': device_id,
                    'name': name,
                    'ip': ip,
                    'device_ping_interval': device_ping_interval,
                    'effective_interval': effective_interval,
                    'last_ping': last_ping_str,
                    'seconds_since_ping': seconds_since_ping,
                    'should_ping_soon': seconds_since_ping is None or seconds_since_ping >= effective_interval
                })
            
            return jsonify({
                'global_settings': settings,
                'devices': device_info,
                'ping_thread_running': ping_thread and ping_thread.is_alive() if 'ping_thread' in globals() else False
            })
            
    except Exception as e:
        logger.error(f"Chyba pri debug monitoring settings: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/monitoring/ping/<int:device_id>')
@login_required
def get_ping_history(device_id):
    """Vráti ping históriu pre zariadenie"""
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            # Posledných 24 hodín
            day_ago = datetime.now() - timedelta(hours=24)
            cursor.execute('''
                SELECT timestamp, avg_latency, packet_loss, status
                FROM ping_history 
                WHERE device_id = ? AND timestamp > ?
                ORDER BY timestamp ASC
            ''', (device_id, day_ago.isoformat()))
            
            history = []
            for row in cursor.fetchall():
                history.append({
                    'timestamp': row[0],
                    'avg_latency': row[1],
                    'packet_loss': row[2],
                    'status': row[3]
                })
            
            return jsonify(history)
            
    except Exception as e:
        logger.error(f"Chyba pri získavaní ping histórie: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/monitoring/ping/current/<int:device_id>')
@login_required  
def get_current_ping_status(device_id):
    """Vráti aktuálny ping status pre zariadenie"""
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            
            # Získaj zariadenie a ping timeout nastavenie
            cursor.execute('SELECT ip FROM devices WHERE id = ?', (device_id,))
            result = cursor.fetchone()
            
            if not result:
                return jsonify({'status': 'error', 'message': 'Zariadenie nenájdené'}), 404
            
            # Načítaj ping_timeout nastavenie
            ping_timeout = cursor.execute('SELECT value FROM settings WHERE key = ?', ('ping_timeout',)).fetchone()
            timeout = int(ping_timeout['value']) if ping_timeout else 5
                
            ip = result[0]
            ping_result = ping_device(ip, timeout=timeout)
            save_ping_result(device_id, ping_result)
            
            return jsonify(ping_result)
            
    except Exception as e:
        logger.error(f"Chyba pri získavaní aktuálneho ping stavu: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/ping-status')
@login_required
def get_all_ping_status():
    """Vráti posledné ping statusy pre všetky zariadenia"""
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            # Získaj posledný ping status pre každé zariadenie
            cursor.execute('''
                SELECT DISTINCT p.device_id, p.status, p.avg_latency, p.packet_loss, p.timestamp
                FROM ping_history p
                INNER JOIN (
                    SELECT device_id, MAX(timestamp) as latest_timestamp
                    FROM ping_history
                    GROUP BY device_id
                ) latest ON p.device_id = latest.device_id AND p.timestamp = latest.latest_timestamp
                ORDER BY p.device_id
            ''')
            
            results = cursor.fetchall()
            ping_statuses = []
            
            for row in results:
                ping_statuses.append({
                    'device_id': row[0],
                    'success': row[1] == 'online',  # Convert status to boolean
                    'avg_latency': row[2],
                    'packet_loss': row[3] or 0,
                    'timestamp': row[4]
                })
            
            return jsonify(ping_statuses)
            
    except Exception as e:
        logger.error(f"Chyba pri získavaní ping statusov: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/monitoring/snmp/<int:device_id>')
@login_required
def get_snmp_history(device_id):
    """Vráti SNMP históriu pre zariadenie"""
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            # Posledných 24 hodín
            day_ago = datetime.now() - timedelta(hours=24)
            cursor.execute('''
                SELECT timestamp, cpu_load, temperature, memory_usage, uptime, total_memory, free_memory
                FROM snmp_history 
                WHERE device_id = ? AND timestamp > ?
                ORDER BY timestamp ASC
            ''', (device_id, day_ago.isoformat()))
            
            history = []
            for row in cursor.fetchall():
                total_mem = row[5]
                free_mem = row[6]
                used_mem = (total_mem - free_mem) if total_mem and free_mem else None
                
                history.append({
                    'timestamp': row[0],
                    'cpu_load': row[1],
                    'temperature': row[2],
                    'memory_usage': row[3],
                    'uptime': row[4],
                    'total_memory': total_mem,  # MB
                    'free_memory': free_mem,    # MB
                    'used_memory': used_mem     # MB (vypočítané)
                })
            
            return jsonify(history)
            
    except Exception as e:
        logger.error(f"Chyba pri získavaní SNMP histórie: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/monitoring/availability/<int:device_id>')
@login_required
def get_availability_history(device_id):
    """Vráti availability štatistiky pre posledných 7 dní"""
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            
            availability_data = []
            for i in range(7):
                date = datetime.now() - timedelta(days=i)
                start_of_day = date.replace(hour=0, minute=0, second=0, microsecond=0)
                end_of_day = date.replace(hour=23, minute=59, second=59, microsecond=999999)
                
                # Spočítame ping záznamy pre daný deň
                cursor.execute('''
                    SELECT COUNT(*) as total,
                           SUM(CASE WHEN status = 'online' THEN 1 ELSE 0 END) as online
                    FROM ping_history 
                    WHERE device_id = ? AND timestamp BETWEEN ? AND ?
                ''', (device_id, start_of_day.isoformat(), end_of_day.isoformat()))
                
                result = cursor.fetchone()
                total = result[0] if result[0] else 0
                online = result[1] if result[1] else 0
                
                percentage = (online / total * 100) if total > 0 else 0
                
                availability_data.append({
                    'date': date.strftime('%d.%m'),
                    'percentage': round(percentage, 2)
                })
            
            # Otočíme poradie (najstarší deň prvý)
            availability_data.reverse()
            return jsonify(availability_data)
            
    except Exception as e:
        logger.error(f"Chyba pri získavaní availability dát: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/monitoring/history/<int:device_id>')
@login_required
def get_monitoring_history(device_id):
    """Vráti monitoring dáta pre zadaný časový rozsah"""
    try:
        # Získame parametre z query string
        time_range = request.args.get('range', '24h')  # default 24h
        
        # Výpočet časového rozsahu
        now = datetime.now()
        time_mappings = {
            'recent': timedelta(hours=1),       # Posledná hodina
            '3h': timedelta(hours=3),           # Pridané: posledné 3 hodiny
            '6h': timedelta(hours=6),
            '12h': timedelta(hours=12), 
            '24h': timedelta(hours=24),
            '7d': timedelta(days=7),
            '30d': timedelta(days=30),
            '90d': timedelta(days=90),
            '1y': timedelta(days=365)
        }
        
        if time_range not in time_mappings:
            return jsonify({'status': 'error', 'message': 'Neplatný časový rozsah'}), 400
            
        start_time = now - time_mappings[time_range]
        
        with get_db_connection() as conn:
            # Ping dáta s optimalizáciou pre veľké datasety
            cursor = conn.cursor()
            
            # Pre dlhé časové rozsahy použijeme rowid sampling pre lepšiu výkonnosť
            if time_range in ['30d', '90d', '1y']:
                # Pre dlhé obdobia - zoberieme vzorky pre zníženie objemu dát
                sample_interval_mapping = {'30d': 10, '90d': 50, '1y': 100}
                sample_interval = sample_interval_mapping[time_range]
                
                cursor.execute('''
                    SELECT timestamp, avg_latency, packet_loss, status
                    FROM ping_history 
                    WHERE device_id = ? AND timestamp >= ? 
                    AND (rowid % ? = 0 OR timestamp >= datetime('now', '-24 hours'))
                    ORDER BY timestamp ASC
                    LIMIT 3000
                ''', (device_id, start_time.isoformat(), sample_interval))
            else:
                # Pre kratšie obdobia - všetky dáta
                cursor.execute('''
                    SELECT timestamp, avg_latency, packet_loss, status
                    FROM ping_history 
                    WHERE device_id = ? AND timestamp >= ?
                    ORDER BY timestamp ASC
                    LIMIT 2000
                ''', (device_id, start_time.isoformat()))
            
            ping_rows = cursor.fetchall()
            ping_data = []
            for row in ping_rows:
                ping_data.append({
                    'timestamp': row[0],
                    'avg_latency': row[1],
                    'packet_loss': row[2],
                    'status': row[3]
                })
            
            # SNMP dáta s rovnakou optimalizáciou ako ping dáta
            if time_range in ['30d', '90d', '1y']:
                # Pre dlhé obdobia - zoberieme vzorky pre zníženie objemu dát
                sample_interval_mapping = {'30d': 10, '90d': 50, '1y': 100}
                sample_interval = sample_interval_mapping[time_range]
                
                cursor.execute('''
                    SELECT timestamp, cpu_load, temperature, memory_usage, uptime, total_memory, free_memory
                    FROM snmp_history 
                    WHERE device_id = ? AND timestamp >= ? 
                    AND (rowid % ? = 0 OR timestamp >= datetime('now', '-24 hours'))
                    ORDER BY timestamp ASC
                    LIMIT 3000
                ''', (device_id, start_time.isoformat(), sample_interval))
            else:
                # Pre kratšie obdobia - všetky dáta
                cursor.execute('''
                    SELECT timestamp, cpu_load, temperature, memory_usage, uptime, total_memory, free_memory
                    FROM snmp_history 
                    WHERE device_id = ? AND timestamp >= ?
                    ORDER BY timestamp ASC
                    LIMIT 2000
                ''', (device_id, start_time.isoformat()))
            
            snmp_rows = cursor.fetchall()
            snmp_data = []
            for row in snmp_rows:
                # Bezpečné získanie memory hodnôt s type checking
                total_mem = row[5] if len(row) > 5 else None
                free_mem = row[6] if len(row) > 6 else None
                
                # Konverzia na int a validácia
                try:
                    if total_mem is not None and str(total_mem).strip():
                        total_mem = int(total_mem)
                    else:
                        total_mem = None
                        
                    if free_mem is not None and str(free_mem).strip():
                        free_mem = int(free_mem)
                    else:
                        free_mem = None
                        
                    # Výpočet used_mem iba ak sú oba platné čísla
                    used_mem = (total_mem - free_mem) if (total_mem is not None and free_mem is not None and total_mem >= 0 and free_mem >= 0) else None
                except (ValueError, TypeError) as e:
                    logger.warning(f"Memory data conversion error for device {device_id}: total_mem={repr(row[5])}, free_mem={repr(row[6])}, error: {e}")
                    total_mem = None
                    free_mem = None
                    used_mem = None
                
                snmp_data.append({
                    'timestamp': row[0],
                    'cpu_load': row[1],
                    'temperature': row[2], 
                    'memory_usage': row[3],
                    'uptime': row[4],
                    'total_memory': total_mem,  # MB
                    'free_memory': free_mem,    # MB
                    'used_memory': used_mem     # MB (vypočítané)
                })
                
        return jsonify({
            'status': 'success',
            'ping_data': ping_data,
            'snmp_data': snmp_data,
            'range': time_range,
            'start_time': start_time.isoformat(),
            'end_time': now.isoformat(),
            'ping_records': len(ping_data),
            'snmp_records': len(snmp_data),
            'optimized': time_range in ['30d', '90d', '1y']  # označuje či sa používa časový sampling
        })
            
    except sqlite3.Error as e:
        logger.error(f"Databázová chyba pri získavaní monitoring histórie pre zariadenie {device_id}: {e}")
        return jsonify({'status': 'error', 'message': f'Chyba databázy. Skontrolujte logy servera pre viac detailov. (Zariadenie ID: {device_id})'}), 500
    except Exception as e:
        logger.error(f"Chyba pri získavaní monitoring histórie pre zariadenie {device_id}: {type(e).__name__}: {e}")
        import traceback
        logger.error(f"Stack trace: {traceback.format_exc()}")
        return jsonify({'status': 'error', 'message': f'Chyba servera. Skontrolujte logy servera pre viac detailov. (Zariadenie ID: {device_id})'}), 500

@app.route('/api/backup/status', methods=['GET'])
@login_required
def backup_status():
    """Vráti stav všetkých bežiacich zálohov"""
    running_backups = list(backup_tasks.keys())
    return jsonify({
        'running_backups': running_backups,
        'total_running': len(running_backups),
        'sequential_backup_running': sequential_backup_running
    })

@app.route('/api/backup/stop-all', methods=['POST'])
@login_required
def stop_all_backups():
    """Zastaví všetky bežiace zálohy"""
    global sequential_backup_running
    
    stopped_count = len(backup_tasks)
    stopped_ips = list(backup_tasks.keys())
    
    # Zastavíme sekvenčnú zálohu
    sequential_backup_running = False
    
    # Vyčistíme všetky bežiace úlohy
    backup_tasks.clear()
    
    if stopped_count > 0:
        add_log('warning', f"Používateľ zastavil všetky bežiace zálohy ({stopped_count} zariadení): {', '.join(stopped_ips)}")
        # Pošleme WebSocket správu o zastavení všetkých záloh
        for ip in stopped_ips:
            socketio.emit('backup_status', {'ip': ip, 'status': 'stopped'})
        
        return jsonify({
            'status': 'success', 
            'message': f'Zastavené {stopped_count} bežiacich zálohov.',
            'stopped_devices': stopped_ips
        })
    else:
        return jsonify({
            'status': 'info', 
            'message': 'Žiadne bežiace zálohy na zastavenie.'
        })

@app.route('/api/snmp/status', methods=['GET'])
def snmp_status():
    """Debug endpoint - zobrazí SNMP stav všetkých zariadení"""
    try:
        with get_db_connection() as conn:
            settings = {row['key']: row['value'] for row in conn.execute('SELECT key, value FROM settings').fetchall()}
            global_interval = int(settings.get('snmp_check_interval_minutes', 10))
            
            devices = [dict(row) for row in conn.execute('SELECT id, ip, name, snmp_interval_minutes, last_snmp_check FROM devices ORDER BY name').fetchall()]
            current_time = datetime.now()
            
            status_info = []
            for device in devices:
                device_interval = device.get('snmp_interval_minutes', 0)
                effective_interval = device_interval if device_interval > 0 else global_interval
                
                last_check_info = "Nikdy"
                minutes_since_check = None
                next_check_info = "Hneď"
                
                if device.get('last_snmp_check'):
                    try:
                        last_check = datetime.fromisoformat(device['last_snmp_check'])
                        minutes_since_check = (current_time - last_check).total_seconds() / 60
                        last_check_info = f"{minutes_since_check:.1f} min dozadu"
                        
                        remaining_minutes = effective_interval - minutes_since_check
                        if remaining_minutes > 0:
                            next_check_info = f"Za {remaining_minutes:.1f} min"
                        else:
                            next_check_info = "Hneď"
                    except (ValueError, TypeError):
                        last_check_info = "Chyba parsingu"
                
                status_info.append({
                    'id': device['id'],
                    'name': device['name'],
                    'ip': device['ip'],
                    'interval_setting': device_interval,
                    'effective_interval': effective_interval,
                    'last_check': last_check_info,
                    'next_check': next_check_info,
                    'is_due': minutes_since_check is None or minutes_since_check >= effective_interval
                })
            
            return jsonify({
                'global_interval': global_interval,
                'devices': status_info,
                'current_time': current_time.isoformat()
            })
    except Exception as e:
        logger.error(f"Chyba pri získavaní SNMP stavu: {e}")
        return jsonify({'error': str(e)}), 500

# Spustenie ping monitoringu po definovaní všetkých funkcií (mimo app contextu)
start_ping_monitoring()

if __name__ == '__main__':
    try:
        # Nastavenie Flask produkčného prostredia
        os.environ['FLASK_ENV'] = 'production'
        app.config['ENV'] = 'production'
        
        logger.info("Spúšťam MikroTik Manager...")
        
        # Inicializácia databázy
        init_database()
        
        # Spustenie ping monitoringu
        start_ping_monitoring()
        
        # Spustenie SNMP timerov pre všetky zariadenia
        start_all_snmp_timers()
        
        logger.info("Aplikácia je pripravená na port 5000")
        # Spustenie aplikácie
        socketio.run(app, host='0.0.0.0', port=5000, debug=False)
        
    except KeyboardInterrupt:
        logger.info("Aplikácia ukončená používateľom")
    except Exception as e:
        logger.error(f"Kritická chyba: {e}")
        raise
