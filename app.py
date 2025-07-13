#!/usr/bin/env python3
"""
MikroTik Backup Web Backend v2.4 - Secured
Flask server s WebSocket a SNMP podporou, integrovaná pokročilá logika.
Pridané povinné prihlasovanie a 2FA (TOTP) so správnym setup flow.
"""

import os
import time
import json
import sqlite3
import threading
from datetime import datetime
from flask import Flask, request, jsonify, send_from_directory, render_template, redirect, url_for, session
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

app = Flask(__name__, static_folder='.', static_url_path='', template_folder='.')
app.config['SECRET_KEY'] = os.urandom(32)
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')
CORS(app)

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

DATA_DIR = os.environ.get('DATA_DIR', '/var/lib/mikrotik-manager/data')
DB_PATH = os.path.join(DATA_DIR, 'mikrotik_backup.db')
BACKUP_DIR = os.path.join(DATA_DIR, 'backups')

backup_tasks = {}

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
        # Pôvodné tabuľky
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS devices (
                id INTEGER PRIMARY KEY AUTOINCREMENT, ip TEXT UNIQUE NOT NULL, name TEXT NOT NULL,
                username TEXT NOT NULL, password TEXT NOT NULL, low_memory BOOLEAN DEFAULT 0,
                snmp_community TEXT DEFAULT 'public', status TEXT DEFAULT 'unknown',
                last_backup TIMESTAMP, last_snmp_data TEXT
            )
        ''')
        cursor.execute('CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT)')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                level TEXT NOT NULL, message TEXT NOT NULL, device_ip TEXT
            )
        ''')
        # Upravená tabuľka pre používateľov
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                totp_secret TEXT,
                totp_enabled BOOLEAN NOT NULL DEFAULT 0
            )
        ''')
        # Pridanie stĺpca, ak chýba v existujúcej DB
        try:
            cursor.execute('ALTER TABLE users ADD COLUMN totp_enabled BOOLEAN NOT NULL DEFAULT 0')
            logger.info("Pridaný stĺpec 'totp_enabled' do tabuľky users.")
        except sqlite3.OperationalError:
            pass # Stĺpec už existuje
        conn.commit()
        logger.info("Databáza úspešne inicializovaná.")

def create_admin_user_if_not_exists():
    with get_db_connection() as conn:
        admin = conn.execute('SELECT * FROM users WHERE username = ?', ('admin',)).fetchone()
        if not admin:
            ADMIN_PASSWORD = "change-this-super-strong-password-now"
            password_hash = generate_password_hash(ADMIN_PASSWORD)
            totp_secret = pyotp.random_base32()
            conn.execute('INSERT INTO users (username, password, totp_secret, totp_enabled) VALUES (?, ?, ?, ?)',
                         ('admin', password_hash, totp_secret, 0))
            conn.commit()
            logger.warning("Vytvorený predvolený administrátorský účet.")

# --- Pôvodné funkcie zostávajú nedotknuté ---
def add_log(level, message, device_ip=None):
    log_level = level.upper()
    logger.log(logging.getLevelName(log_level), f"{f'[{device_ip}] ' if device_ip else ''}{message}")
    try:
        with get_db_connection() as conn:
            conn.execute("INSERT INTO logs (level, message, device_ip) VALUES (?, ?, ?)", (level, message, device_ip))
            conn.commit()
        socketio.emit('log_update', {'level': level, 'message': message, 'device_ip': device_ip, 'timestamp': datetime.now().isoformat()})
    except Exception as e:
        logger.error(f"Nepodarilo sa zapísať log do databázy: {e}")

def get_mikrotik_export_direct(ssh_client, ip):
    try:
        add_log('info', f"Získavam priamy SSH export z {ip}...", ip)
        _, stdout, _ = ssh_client.exec_command('/export')
        export_content = stdout.read().decode('utf-8', errors='ignore')
        if not export_content:
            raise ValueError("Export command returned empty content.")
        add_log('info', "Priamy export úspešne získaný.", ip)
        return export_content
    except Exception as e:
        add_log('error', f"Priamy SSH export zlyhal: {e}", ip)
        return None

def compare_with_local_backup(ip, remote_content):
    try:
        local_backups = sorted(
            [f for f in os.listdir(BACKUP_DIR) if ip in f and f.endswith('.rsc')],
            reverse=True
        )
        if not local_backups:
            add_log('info', f"Žiadna lokálna záloha pre {ip} nájdená. Vytváram novú.", ip)
            return True

        latest_backup_path = os.path.join(BACKUP_DIR, local_backups[0])
        with open(latest_backup_path, 'r', encoding='utf-8', errors='ignore') as f:
            local_content = f.read()

        ignore_keywords = ['list=blacklist', 'comment=spamhaus']
        local_lines = [line for line in local_content.splitlines() if not any(kw in line for kw in ignore_keywords)]
        remote_lines = [line for line in remote_content.splitlines() if not any(kw in line for kw in ignore_keywords)]
        
        diff = list(difflib.unified_diff(local_lines, remote_lines))
        
        if len(diff) > 2:
            add_log('info', f"Zistené zmeny v konfigurácii pre {ip}. Spúšťam zálohu.", ip)
            return True
        else:
            add_log('info', f"Žiadne zmeny v konfigurácii pre {ip}. Záloha sa preskakuje.", ip)
            return False
    except Exception as e:
        add_log('error', f"Chyba pri porovnávaní záloh pre {ip}: {e}", ip)
        return True

def run_backup_logic(device):
    ip, username, password, low_memory = device['ip'], device['username'], device['password'], device['low_memory']
    add_log('info', f"Spúšťam pokročilú zálohu pre {ip}", ip)
    socketio.emit('backup_status', {'ip': ip, 'id': device['id'], 'status': 'starting'})
    
    client = None
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(ip, username=username, password=password, timeout=30)
        add_log('info', "SSH pripojenie úspešne.", ip)

        remote_config = get_mikrotik_export_direct(client, ip)
        if remote_config is None:
            raise Exception("Nepodarilo sa získať konfiguráciu na porovnanie.")
        
        if not compare_with_local_backup(ip, remote_config):
            socketio.emit('backup_status', {'ip': ip, 'id': device['id'], 'status': 'skipped'})
            return

        _, stdout, _ = client.exec_command('/system identity print')
        identity_match = re.search(r'name:\s*(.+)', stdout.read().decode().strip())
        safe_identity = re.sub(r'[^a-zA-Z0-9_-]', '_', identity_match.group(1) if identity_match else ip)
        
        _, stdout, _ = client.exec_command('/file print where type=directory')
        has_flash = 'flash' in stdout.read().decode()
        add_log('info', f"Zariadenie {'má' if has_flash else 'nemá'} /flash adresár.", ip)

        add_log('info', "Vykonávam cleanup starých súborov na zariadení...", ip)
        safe_cleanup_command = f':foreach i in=[/file find where (name~".backup" or name~".rsc") and name~"_{ip}_"] do={{/file remove $i}}'
        client.exec_command(safe_cleanup_command)
        time.sleep(5)

        date_str = datetime.now().strftime("%Y%m%d-%H%M%S")
        base_filename = f"{safe_identity}_{ip}_{date_str}"
        backup_path = f"flash/{base_filename}.backup" if has_flash else f"{base_filename}.backup"
        rsc_path = f"flash/{base_filename}.rsc" if has_flash else f"{base_filename}.rsc"
        
        add_log('info', f"Vytváram súbory {base_filename}.backup a .rsc...", ip)
        client.exec_command(f'/system backup save name="{backup_path}" dont-encrypt=yes')
        time.sleep(15 if low_memory else 10)
        client.exec_command(f'/export file="{rsc_path}"')
        time.sleep(20 if low_memory else 15)

        with client.open_sftp() as sftp:
            sftp.get(backup_path, os.path.join(BACKUP_DIR, f"{base_filename}.backup"))
            sftp.get(rsc_path, os.path.join(BACKUP_DIR, f"{base_filename}.rsc"))
            add_log('info', "Súbory úspešne stiahnuté.", ip)
            sftp.remove(rsc_path)

        with get_db_connection() as conn:
            conn.execute("UPDATE devices SET last_backup = CURRENT_TIMESTAMP WHERE id = ?", (device['id'],))
            conn.commit()

        add_log('success', f"Záloha pre {ip} dokončená.", ip)
        socketio.emit('backup_status', {'ip': ip, 'id': device['id'], 'status': 'success', 'last_backup': datetime.now().isoformat()})
        
        upload_to_ftp(os.path.join(BACKUP_DIR, f"{base_filename}.backup"))
        upload_to_ftp(os.path.join(BACKUP_DIR, f"{base_filename}.rsc"))

    except Exception as e:
        add_log('error', f"Chyba pri zálohe: {e}", ip)
        socketio.emit('backup_status', {'ip': ip, 'id': device['id'], 'status': 'error', 'message': str(e)})
    finally:
        if client: client.close()
        if ip in backup_tasks: del backup_tasks[ip]

def get_snmp_data(ip, community='public'):
    oids = {
        'identity': '1.3.6.1.2.1.1.5.0','uptime': '1.3.6.1.2.1.1.3.0','version': '1.3.6.1.4.1.14988.1.1.4.4.0',
        'board_name': '1.3.6.1.4.1.14988.1.1.7.8.0','cpu_load': '1.3.6.1.2.1.25.3.3.1.2.1','temperature': '1.3.6.1.4.1.14988.1.1.3.11.0',
        'cpu_count': '1.3.6.1.2.1.25.3.3.1.0','cpu_frequency': '1.3.6.1.4.1.14988.1.1.3.14.0','total_memory': '1.3.6.1.2.1.25.2.2.0',
        'architecture': '1.3.6.1.4.1.14988.1.1.7.7.0'
    }
    results = {}
    try:
        from pysnmp.hlapi import getCmd, SnmpEngine, CommunityData, UdpTransportTarget, ContextData, ObjectType, ObjectIdentity
        from datetime import timedelta
        for name, oid in oids.items():
            errorIndication, errorStatus, _, varBinds = next(getCmd(SnmpEngine(),CommunityData(community, mpModel=0),UdpTransportTarget((ip, 161), timeout=2, retries=1),ContextData(),ObjectType(ObjectIdentity(oid))))
            if errorIndication or errorStatus:
                results[name] = 'N/A'
            else:
                val = varBinds[0][1]
                if name == 'uptime':
                    td = timedelta(seconds=float(val) / 100.0)
                    results[name] = f"{td.days}d {td.seconds//3600}h {(td.seconds//60)%60}m"
                elif name == 'temperature': results[name] = str(int(int(val) / 10.0))
                else: results[name] = str(val)
        if 'cpu_count' in results and results['cpu_count'] != 'N/A': results['free_memory'] = results['cpu_count']
        else: results['free_memory'] = 'N/A'
        for key in ['cpu_count', 'cpu_frequency', 'total_memory', 'architecture']:
            if key in results: del results[key]
        return results
    except Exception as e:
        add_log('error', f"SNMP query for IP {ip} failed: {e}", device_ip=ip)
        return {k: 'N/A' for k in ['identity', 'uptime', 'version', 'board_name', 'cpu_load', 'temperature', 'free_memory']}

def upload_to_ftp(local_path):
    try:
        with get_db_connection() as conn:
            settings = {row['key']: row['value'] for row in conn.execute('SELECT key, value FROM settings WHERE key LIKE "ftp_%"')}
        if all(k in settings and settings[k] for k in ['ftp_server', 'ftp_username', 'ftp_password']):
            with FTP(settings['ftp_server']) as ftp:
                ftp.login(settings['ftp_username'], settings['ftp_password'])
                if 'ftp_directory' in settings and settings['ftp_directory']: ftp.cwd(settings['ftp_directory'])
                with open(local_path, 'rb') as f:
                    ftp.storbinary(f'STOR {os.path.basename(local_path)}', f)
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

# --- Opravená logika prihlasovania ---
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
        if pyotp.TOTP(user.totp_secret).verify(totp_code):
            login_user(user, remember=True)
            session.pop('2fa_user_id', None)
            return redirect(request.args.get('next') or url_for('index'))
        else:
            error = 'Neplatný overovací kód.'
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
        # Ak je kód nesprávny, zobrazíme znova setup stránku s chybovou hláškou
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

# --- Ochrana pôvodných rout ---
@app.route('/')
@login_required
def index():
    if not current_user.totp_enabled:
        return redirect(url_for('setup_2fa'))
    return send_from_directory('.', 'index.html')

# Všetky API routy musia byť chránené
@app.route('/api/devices', methods=['GET', 'POST'])
@login_required
def handle_devices():
    with get_db_connection() as conn:
        if request.method == 'GET': return jsonify([dict(row) for row in conn.execute('SELECT * FROM devices ORDER BY name').fetchall()])
        if request.method == 'POST':
            data = request.json
            try:
                if data.get('id'):
                     conn.execute("UPDATE devices SET name=?, ip=?, username=?, password=?, low_memory=?, snmp_community=? WHERE id=?", (data['name'], data['ip'], data['username'], data['password'], data.get('low_memory', False), data.get('snmp_community', 'public'), data['id']))
                else:
                    conn.execute("INSERT INTO devices (name, ip, username, password, low_memory, snmp_community) VALUES (?, ?, ?, ?, ?, ?)", (data['name'], data['ip'], data['username'], data['password'], data.get('low_memory', False), data.get('snmp_community', 'public')))
                conn.commit()
                add_log('info', f"Zariadenie {data['ip']} uložené.")
                return jsonify({'status': 'success'})
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
    threading.Thread(target=run_backup_logic, args=(dict(device),)).start()
    return jsonify({'status': 'success', 'message': 'Záloha spustená.'})

@app.route('/api/backup/all', methods=['POST'])
@login_required
def backup_all_devices():
    with get_db_connection() as conn:
        devices = [dict(row) for row in conn.execute('SELECT * FROM devices').fetchall()]
    count = sum(1 for d in devices if d['ip'] not in backup_tasks and (backup_tasks.update({d['ip']:True}) or True) and (threading.Thread(target=run_backup_logic, args=(d,)).start() or True))
    add_log('info', f"Spustená hromadná záloha pre {count} zariadení.")
    return jsonify({'status': 'success', 'message': f'Hromadná záloha spustená pre {count} zariadení.'})

@app.route('/api/snmp/<int:device_id>', methods=['GET'])
@login_required
def check_snmp(device_id):
    with get_db_connection() as conn:
        device = conn.execute('SELECT ip, snmp_community FROM devices WHERE id = ?', (device_id,)).fetchone()
    if not device: return jsonify({'status': 'error', 'message': 'Zariadenie nenájdené'}), 404
    snmp_data = get_snmp_data(device['ip'], device['snmp_community'])
    status = 'online' if snmp_data.get('uptime') != 'N/A' else 'offline'
    with get_db_connection() as conn:
        conn.execute("UPDATE devices SET last_snmp_data = ?, status = ? WHERE id = ?", (json.dumps(snmp_data), status, device_id))
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
            setup_scheduler()
            return jsonify({'status': 'success'})

@app.route('/api/notifications/test', methods=['POST'])
@login_required
def test_notification():
    send_pushover_notification("Toto je testovacia správa z MikroTik Backup Manager.")
    return jsonify({'status': 'success'})

def scheduled_backup_job():
    with app.app_context():
        add_log('info', "Spúšťam naplánovanú úlohu zálohovania...")
        backup_all_devices()

def setup_scheduler():
    schedule.clear()
    with get_db_connection() as conn:
        settings = {row['key']: row['value'] for row in conn.execute('SELECT key, value FROM settings').fetchall()}
    if settings.get('backup_schedule_enabled', 'false').lower() != 'true':
        add_log('info', "Automatické zálohovanie je vypnuté.")
        return
    schedule_time = settings.get('backup_schedule_time', '02:00')
    if settings.get('backup_schedule_type', 'daily') == 'daily':
        schedule.every().day.at(schedule_time).do(scheduled_backup_job)
    else:
        day = settings.get('backup_schedule_day', 'sunday').lower()
        getattr(schedule.every(), day).at(schedule_time).do(scheduled_backup_job)
    add_log('info', f"Plánovač nastavený: {schedule.get_jobs()}")

def run_scheduler():
    while True:
        schedule.run_pending()
        time.sleep(60)

# --- Upravená inicializácia ---
with app.app_context():
    init_database()
    create_admin_user_if_not_exists()
    setup_scheduler()

threading.Thread(target=run_scheduler, daemon=True).start()
logger.info("Aplikácia MikroTik Backup Manager sa spúšťa...")

if __name__ == '__main__':
    logger.info("Server sa spúšťa v režime pre vývoj na http://0.0.0.0:5000")
    socketio.run(app, host='0.0.0.0', port=5000, allow_unsafe_werkzeug=True)