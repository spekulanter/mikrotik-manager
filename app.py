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
# PRIDANÉ: g pre globálny kontext požiadavky
from flask import Flask, request, jsonify, send_from_directory, render_template, redirect, url_for, session, g
from flask_socketio import SocketIO
from flask_cors import CORS
import paramiko
import re
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

# --- Nastavenie aplikácie (upravené pre HTML šablóny) ---
app = Flask(__name__, static_folder='.', static_url_path='', template_folder='.')
app.config['SECRET_KEY'] = os.urandom(32)
# Nastavíme platnosť "remember me" cookie na 365 dní pre prakticky trvalé prihlásenie.
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=365)
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')
CORS(app)

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

DATA_DIR = os.environ.get('DATA_DIR', '/var/lib/mikrotik-manager/data')
DB_PATH = os.path.join(DATA_DIR, 'mikrotik_backup.db')
BACKUP_DIR = os.path.join(DATA_DIR, 'backups')

backup_tasks = {}
sequential_backup_running = False

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
    try:
        conn = sqlite3.connect(DB_PATH, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        yield conn
    except sqlite3.Error as e:
        logger.error(f"Chyba pripojenia k databáze: {e}")
        raise
    finally:
        if conn:
            conn.close()

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
        try:
            cursor.execute('ALTER TABLE users ADD COLUMN totp_enabled BOOLEAN NOT NULL DEFAULT 0')
        except sqlite3.OperationalError:
            pass
        conn.commit()
        
        # Vyčistíme staré správy o automatickom zálohovaní z logov
        cursor.execute("DELETE FROM logs WHERE message LIKE '%Automatické zálohovanie je aktívne:%'")
        cursor.execute("DELETE FROM logs WHERE message LIKE '%Automatické zálohovanie je v nastaveniach vypnuté%'")
        conn.commit()
        
        # Pridanie predvolených hodnôt pre nastavenia
        cursor.execute("INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)", ('backup_retention_count', '10'))
        cursor.execute("INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)", ('backup_delay_seconds', '30'))
        cursor.execute("INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)", ('snmp_check_interval_minutes', '10'))
        cursor.execute("INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)", ('backup_detailed_logging', 'false'))
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
            add_log('info', f"Získavam priamy SSH export z {ip}...", ip)
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
                add_log('info', f"Žiadna lokálna záloha pre {ip} nájdená. Vytváram novú.", ip)
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
                add_log('info', f"Zistené zmeny v konfigurácii pre {ip}. Spúšťam zálohu.", ip)
            return True
        else:
            if detailed_logging:
                add_log('info', f"Žiadne zmeny v konfigurácii pre {ip}. Záloha sa preskakuje.", ip)
            return False
    except Exception as e:
        add_log('error', f"Chyba pri porovnávaní záloh pre {ip}: {e}", ip)
        return True

def run_backup_logic(device, is_sequential=False):
    ip, username, password, low_memory = device['ip'], device['username'], device['password'], device['low_memory']
    
    # Načítame nastavenie pre detailné logovanie
    with get_db_connection() as conn:
        settings = {row['key']: row['value'] for row in conn.execute('SELECT key, value FROM settings').fetchall()}
    
    detailed_logging = settings.get('backup_detailed_logging', 'false').lower() == 'true'
    
    # Základná správa o spustení zálohy
    if is_sequential:
        add_log('info', f"Záloha {ip} - spúšťam", ip)
    else:
        add_log('info', f"Spúšťam pokročilú zálohu pre {ip}", ip)
    
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
            socketio.emit('backup_status', {'ip': ip, 'id': device['id'], 'status': 'skipped'})
            return
        _, stdout, _ = client.exec_command('/system identity print')
        identity_match = re.search(r'name:\s*(.+)', stdout.read().decode().strip())
        safe_identity = re.sub(r'[^a-zA-Z0-9_-]', '_', identity_match.group(1) if identity_match else ip)
        _, stdout, _ = client.exec_command('/file print where type=directory')
        has_flash = 'flash' in stdout.read().decode()
        
        if detailed_logging:
            add_log('info', f"Zariadenie {'má' if has_flash else 'nemá'} /flash adresár.", ip)
            add_log('info', "Vykonávam cleanup starých súborov na zariadení...", ip)
        
        safe_cleanup_command = f':foreach i in=[/file find where (name~".backup" or name~".rsc") and name~"_{ip}_"] do={{/file remove $i}}'
        client.exec_command(safe_cleanup_command)
        time.sleep(5)
        date_str = datetime.now().strftime("%Y%m%d-%H%M%S")
        base_filename = f"{safe_identity}_{ip}_{date_str}"
        backup_path = f"flash/{base_filename}.backup" if has_flash else f"{base_filename}.backup"
        rsc_path = f"flash/{base_filename}.rsc" if has_flash else f"{base_filename}.rsc"
        
        if detailed_logging:
            add_log('info', f"Vytváram súbory {base_filename}.backup a .rsc...", ip)
        
        client.exec_command(f'/system backup save name="{backup_path}" dont-encrypt=yes')
        time.sleep(30 if low_memory else 20)
        client.exec_command(f'/export file="{rsc_path}"')
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
            add_log('success', f"Záloha {ip} - dokončená úspešne", ip)
        else:
            add_log('success', f"Záloha pre {ip} dokončená.", ip)
        
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
    finally:
        if client: client.close()
        if ip in backup_tasks: del backup_tasks[ip]

def cleanup_old_backups(device_ip, settings, detailed_logging=True):
    """Vyčistí staré zálohy lokálne a na FTP serveri na základe nastavenia."""
    try:
        # Načítame počet uchovávaných záloh z nastavení, predvolená hodnota je 10
        retention_count = int(settings.get('backup_retention_count', 10))
        if detailed_logging:
            add_log('info', f"Spúšťam čistenie starých záloh, ponechávam posledných {retention_count} pre {device_ip}.", device_ip)

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
        'cpu_load': '1.3.6.1.2.1.25.3.3.1.2.1',
        'temperature': '1.3.6.1.4.1.14988.1.1.3.11.0',
        'cpu_count': '1.3.6.1.4.1.14988.1.1.3.8.0',  # MikroTik špecifický OID pre CPU count
        'architecture': '1.3.6.1.4.1.14988.1.1.7.7.0'
    }
    results = {}
    try:
        from pysnmp.hlapi import getCmd, SnmpEngine, CommunityData, UdpTransportTarget, ContextData, ObjectType, ObjectIdentity
        from datetime import timedelta
        for name, oid in oids.items():
            errorIndication, errorStatus, _, varBinds = next(getCmd(SnmpEngine(),CommunityData(community,mpModel=0),UdpTransportTarget((ip,161),timeout=2,retries=1),ContextData(),ObjectType(ObjectIdentity(oid))))
            if errorIndication or errorStatus: 
                results[name] = 'N/A'
            else:
                val = varBinds[0][1]
                if name == 'uptime':
                    td = timedelta(seconds=float(val)/100.0)
                    results[name] = f"{td.days}d {td.seconds//3600}h {(td.seconds//60)%60}m"
                elif name == 'temperature': 
                    results[name] = str(int(int(val)/10.0))
                else: 
                    results[name] = str(val)
        
        # Odstránime pomocné polia, ktoré nechceme zobrazovať
        for key in ['architecture']:
            if key in results: 
                del results[key]
        return results
    except Exception as e:
        add_log('error', f"SNMP query for IP {ip} failed: {e}", device_ip=ip)
        return {k: 'N/A' for k in ['identity','uptime','version','board_name','cpu_load','temperature','cpu_count']}

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
        add_log('info', f"Pushover notifikácia odoslaná: {message}")
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
    try:
        files_with_details = []
        for filename in sorted(os.listdir(BACKUP_DIR), reverse=True):
            filepath = os.path.join(BACKUP_DIR, filename)
            if os.path.isfile(filepath):
                files_with_details.append({
                    'name': filename,
                    'size': os.path.getsize(filepath),
                    'modified': datetime.fromtimestamp(os.path.getmtime(filepath))
                })
        return render_template('backups.html', files=files_with_details)
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

@app.route('/')
@login_required
def index():
    if not current_user.totp_enabled:
        return redirect(url_for('setup_2fa'))
    return send_from_directory('.', 'index.html')

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
        if request.method == 'GET': return jsonify([dict(row) for row in conn.execute('SELECT * FROM devices ORDER BY name').fetchall()])
        if request.method == 'POST':
            data = request.json
            try:
                if data.get('id'):
                    # Pri editácii zachováme pôvodné heslo ak nie je zadané nové
                    if data.get('password'):
                        # Ak je zadané nové heslo, aktualizujeme všetko vrátane hesla
                        conn.execute("UPDATE devices SET name=?, ip=?, username=?, password=?, low_memory=?, snmp_community=?, snmp_interval_minutes=? WHERE id=?", (data['name'], data['ip'], data['username'], data['password'], data.get('low_memory', False), data.get('snmp_community', 'public'), data.get('snmp_interval_minutes', 0), data['id']))
                    else:
                        # Ak heslo nie je zadané, aktualizujeme len ostatné polia
                        conn.execute("UPDATE devices SET name=?, ip=?, username=?, low_memory=?, snmp_community=?, snmp_interval_minutes=? WHERE id=?", (data['name'], data['ip'], data['username'], data.get('low_memory', False), data.get('snmp_community', 'public'), data.get('snmp_interval_minutes', 0), data['id']))
                    conn.commit()
                    add_log('info', f"Zariadenie {data['ip']} aktualizované.")
                    return jsonify({'status': 'success'})
                else:
                    cursor = conn.cursor()
                    cursor.execute("INSERT INTO devices (name, ip, username, password, low_memory, snmp_community, snmp_interval_minutes) VALUES (?, ?, ?, ?, ?, ?, ?)", (data['name'], data['ip'], data['username'], data['password'], data.get('low_memory', False), data.get('snmp_community', 'public'), data.get('snmp_interval_minutes', 0)))
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
        devices = [dict(row) for row in conn.execute('SELECT * FROM devices').fetchall()]
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
                add_log('warning', f"Záloha pre {ip} už prebieha, preskakujem.", ip)
                continue
            
            add_log('info', f"Spúšťam zálohu {i}/{total_devices} pre {ip}...", ip)
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
        device = conn.execute('SELECT ip, snmp_community FROM devices WHERE id = ?', (device_id,)).fetchone()
    if not device: return jsonify({'status': 'error', 'message': 'Zariadenie nenájdené'}), 404
    snmp_data = get_snmp_data(device['ip'], device['snmp_community'])
    status = 'online' if snmp_data.get('uptime') != 'N/A' else 'offline'
    current_time = datetime.now()
    with get_db_connection() as conn:
        conn.execute("UPDATE devices SET last_snmp_data = ?, status = ?, last_snmp_check = ? WHERE id = ?", (json.dumps(snmp_data), status, current_time.isoformat(), device_id))
        conn.commit()
    socketio.emit('snmp_update', {'id': device_id, 'data': snmp_data, 'status': status})
    return jsonify(snmp_data)

@app.route('/api/settings', methods=['GET', 'POST'])
@login_required
def handle_settings():
    with get_db_connection() as conn:
        if request.method == 'GET': return jsonify({row['key']: row['value'] for row in conn.execute('SELECT key, value FROM settings').fetchall()})
        if request.method == 'POST':
            for key, value in request.json.items():
                conn.execute("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)", (key, str(value)))
            conn.commit()
            add_log('info', "Nastavenia boli aktualizované.")
            
            # Znovu nastavíme scheduler bez logovania
            setup_scheduler(log_schedule_info=False)
            
            # Vrátime info o pláne priamo v odpovedi namiesto do logov
            schedule_info = get_schedule_info()
            return jsonify({
                'status': 'success',
                'schedule_info': schedule_info
            })

@app.route('/api/notifications/test', methods=['POST'])
@login_required
def test_notification():
    send_pushover_notification("Toto je testovacia správa z MikroTik Backup Manager.")
    return jsonify({'status': 'success'})

@app.route('/api/logs', methods=['GET'])
@login_required
def get_logs():
    try:
        with get_db_connection() as conn:
            # Vraciame posledných 100 záznamov, najnovšie prvé
            logs = conn.execute('SELECT * FROM logs ORDER BY timestamp DESC LIMIT 100').fetchall()
            return jsonify([dict(row) for row in logs])
    except Exception as e:
        logger.error(f"Chyba pri načítaní logov: {e}")
        return jsonify({'status': 'error', 'message': 'Chyba pri načítaní logov'}), 500

@app.route('/api/logs/cleanup', methods=['POST'])
@login_required
def cleanup_logs():
    """Vyčistí staré logy starší ako 30 dní"""
    try:
        with get_db_connection() as conn:
            # Zmazanie logov starších ako 30 dní
            cutoff_date = datetime.now() - timedelta(days=30)
            result = conn.execute('DELETE FROM logs WHERE timestamp < ?', (cutoff_date,))
            deleted_count = result.rowcount
            conn.commit()
            
        add_log('info', f"Vyčistené {deleted_count} starých logov (starších ako 30 dní)")
        return jsonify({'status': 'success', 'deleted_count': deleted_count})
    except Exception as e:
        logger.error(f"Chyba pri čistení logov: {e}")
        return jsonify({'status': 'error', 'message': 'Chyba pri čistení logov'}), 500

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

def setup_scheduler(log_schedule_info=False):
    # Vždy vyčistíme existujúce úlohy, aby sme predišli duplicitám alebo starým nastaveniam
    schedule.clear()

    with get_db_connection() as conn:
        settings = {row['key']: row['value'] for row in conn.execute('SELECT key, value FROM settings').fetchall()}
    
    # Znovu nastavíme SNMP kontrolu s aktuálnymi nastaveniami
    schedule.every(1).minutes.do(scheduled_snmp_check)  # Kontrola každú minútu pre presnosť individuálnych intervalov
    schedule.every().day.at("03:00").do(scheduled_log_cleanup)  # Čistenie starých logov každý deň o 3:00
    
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
                add_log('success', f"Automatické zálohovanie je aktívne: Denne o {schedule_time}.")
        else:
            day = settings.get('backup_schedule_day', 'sunday').lower()
            day_sk = {'monday': 'Pondelok', 'tuesday': 'Utorok', 'wednesday': 'Streda', 'thursday': 'Štvrtok', 'friday': 'Piatok', 'saturday': 'Sobota', 'sunday': 'Nedeľa'}.get(day, day.capitalize())
            getattr(schedule.every(), day).at(schedule_time).do(scheduled_backup_job)
            if log_schedule_info:
                add_log('success', f"Automatické zálohovanie je aktívne: Každý {day_sk} o {schedule_time}.")
    except Exception as e:
        add_log('error', f"Chyba pri nastavovaní plánovača: {e}")

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

def scheduled_snmp_check():
    try:
        with app.app_context():
            with get_db_connection() as conn:
                settings = {row['key']: row['value'] for row in conn.execute('SELECT key, value FROM settings').fetchall()}
                notify_offline = settings.get('notify_device_offline', 'false').lower() == 'true'
                notify_online = settings.get('notify_device_online', 'false').lower() == 'true'
                global_interval = int(settings.get('snmp_check_interval_minutes', 10))
                
                # Získame všetky zariadenia s ich nastaveniami
                devices = [dict(row) for row in conn.execute('SELECT id, ip, name, snmp_community, status, snmp_interval_minutes, last_snmp_check FROM devices').fetchall()]
                current_time = datetime.now()
                
                devices_to_check = []
                
                for device in devices:
                    # Určíme interval pre zariadenie (individuálny alebo globálny)
                    device_interval = device.get('snmp_interval_minutes', 0)
                    effective_interval = device_interval if device_interval > 0 else global_interval
                    
                    # Kontrola, či je čas na SNMP check
                    should_check = True
                    if device.get('last_snmp_check'):
                        try:
                            last_check = datetime.fromisoformat(device['last_snmp_check'])
                            minutes_since_check = (current_time - last_check).total_seconds() / 60
                            should_check = minutes_since_check >= effective_interval
                        except (ValueError, TypeError):
                            should_check = True  # Ak nie je možné parsovať čas, vykonáme check
                    
                    if should_check:
                        devices_to_check.append((device, effective_interval))
                
                # Len ak sú zariadenia na kontrolu, spustíme monitoring
                if devices_to_check:
                    # Nelogujeme bežné kontroly, len problémy
                    for device, interval in devices_to_check:
                        try:
                            # Vykonáme SNMP check
                            snmp_data = get_snmp_data(device['ip'], device.get('snmp_community', 'public'))
                            status = 'online' if snmp_data.get('uptime') != 'N/A' else 'offline'
                            
                            # Zistiť, či došlo k zmene stavu
                            if device['status'] != status:
                                conn.execute("UPDATE devices SET last_snmp_data = ?, status = ?, last_snmp_check = ? WHERE id = ?", (json.dumps(snmp_data), status, current_time.isoformat(), device['id']))
                                conn.commit()
                                socketio.emit('snmp_update', {'id': device['id'], 'data': snmp_data, 'status': status})
                                
                                if status == 'offline' and notify_offline:
                                    send_pushover_notification(f"Zariadenie {device['ip']} ({device.get('name', device['ip'])}) je OFFLINE!", title="MikroTik SNMP výpadok")
                                if status == 'online' and notify_online:
                                    send_pushover_notification(f"Zariadenie {device['ip']} ({device.get('name', device['ip'])}) je ONLINE!", title="MikroTik SNMP stav")
                            else:
                                # Aktualizuj len SNMP dáta a čas poslednej kontroly
                                conn.execute("UPDATE devices SET last_snmp_data = ?, last_snmp_check = ? WHERE id = ?", (json.dumps(snmp_data), current_time.isoformat(), device['id']))
                                conn.commit()
                                socketio.emit('snmp_update', {'id': device['id'], 'data': snmp_data, 'status': status})
                        except Exception as device_error:
                            add_log('error', f"SNMP monitoring: Chyba pri kontrole zariadenia {device['ip']}: {device_error}", device['ip'])
    except Exception as e:
        add_log('error', f"SNMP monitoring: Kritická chyba pri plánovanej kontrole: {e}")

def run_scheduler():
    while True:
        schedule.run_pending()
        time.sleep(60)

def scheduled_log_cleanup():
    """Automatické čistenie starých logov"""
    with app.app_context():
        try:
            with get_db_connection() as conn:
                cutoff_date = datetime.now() - timedelta(days=30)
                result = conn.execute('DELETE FROM logs WHERE timestamp < ?', (cutoff_date,))
                deleted_count = result.rowcount
                conn.commit()
                
            if deleted_count > 0:
                add_log('info', f"Automaticky vyčistené {deleted_count} starých logov (starších ako 30 dní)")
        except Exception as e:
            logger.error(f"Chyba pri automatickom čistení logov: {e}")

# --- Spustenie plánovača ---
with app.app_context():
    init_database()
    setup_scheduler(log_schedule_info=False)  # Pri štarte aplikácie nelogujeme info o schedule

threading.Thread(target=run_scheduler, daemon=True).start()
logger.info("Aplikácia MikroTik Backup Manager sa spúšťa...")

if __name__ == '__main__':
    logger.info("Server sa spúšťa v režime pre vývoj na http://0.0.0.0:5000")
    socketio.run(app, host='0.0.0.0', port=5000, allow_unsafe_werkzeug=True)

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
@login_required
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
        return jsonify({'status': 'error', 'message': str(e)}), 500
