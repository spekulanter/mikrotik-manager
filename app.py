#!/usr/bin/env python3
"""
MikroTik Backup Web Backend v2.3 - Secured
Flask server s WebSocket a SNMP podporou, integrovaná pokročilá logika.
Pridané povinné prihlasovanie a 2FA (TOTP).
"""

import os
import time
import json
import sqlite3
import threading
from datetime import datetime
# --- PRIDANÉ PRE LOGIN ---
# Pridali sme render_template pre zobrazovanie HTML šablón a session pre udržanie stavu prihlásenia
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

# --- PRIDANÉ PRE LOGIN ---
# Nové importy pre prihlasovanie, hashovanie hesiel a 2FA
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import pyotp
import qrcode
import base64
from io import BytesIO

# --- Základné nastavenie ---
# Upravené, aby Flask vedel, kde hľadať HTML šablóny (login.html, atď.)
app = Flask(__name__, static_folder='.', static_url_path='', template_folder='.')
app.config['SECRET_KEY'] = os.urandom(32) # Dôležité pre session a Flask-Login
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')
CORS(app)

# Logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Cesty k súborom a adresárom (zostáva pôvodné)
DATA_DIR = os.environ.get('DATA_DIR', '/var/lib/mikrotik-manager/data')
DB_PATH = os.path.join(DATA_DIR, 'mikrotik_backup.db')
BACKUP_DIR = os.path.join(DATA_DIR, 'backups')

# Globálne premenné (zostáva pôvodné)
backup_tasks = {}

# --- PRIDANÉ PRE LOGIN ---
# Kompletné nastavenie Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login' # Stránka, na ktorú presmeruje, ak používateľ nie je prihlásený
login_manager.session_protection = "strong"

class User(UserMixin):
    """Jednoduchý model používateľa pre Flask-Login."""
    def __init__(self, id, username, password, totp_secret):
        self.id = id
        self.username = username
        self.password = password
        self.totp_secret = totp_secret

@login_manager.user_loader
def load_user(user_id):
    """Načíta používateľa z databázy podľa jeho ID."""
    with get_db_connection() as conn:
        user_data = conn.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
        if user_data:
            return User(id=user_data['id'], username=user_data['username'], password=user_data['password'], totp_secret=user_data['totp_secret'])
    return None

# --- Inicializácia --- (zostáva pôvodné)
def init_environment():
    os.makedirs(DATA_DIR, exist_ok=True)
    os.makedirs(BACKUP_DIR, exist_ok=True)
    logger.info("Adresáre pre dáta a backupy sú pripravené.")

@contextmanager
def get_db_connection():
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        yield conn
    except sqlite3.Error as e:
        logger.error(f"Chyba pripojenia k databáze: {e}")
        raise
    finally:
        if conn:
            conn.close()

def init_database():
    """Inicializuje databázu a pridá novú tabuľku 'users'."""
    try:
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
            # --- PRIDANÉ PRE LOGIN ---
            # Nová tabuľka pre používateľov
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    password TEXT NOT NULL,
                    totp_secret TEXT
                )
            ''')
            conn.commit()
            logger.info("Databáza úspešne inicializovaná.")
    except sqlite3.Error as e:
        logger.error(f"Chyba pri inicializácii databázy: {e}")

# --- PRIDANÉ PRE LOGIN ---
def create_admin_user_if_not_exists():
    """Vytvorí predvoleného administrátora, ak v databáze žiadny neexistuje."""
    with get_db_connection() as conn:
        admin = conn.execute('SELECT * FROM users WHERE username = ?', ('admin',)).fetchone()
        if not admin:
            # ===================================================================
            # === DÔLEŽITÉ: ZMEŇTE TOTO HESLO PRED PRVÝM SPUSTENÍM! ===
            # ===================================================================
            ADMIN_PASSWORD = "change-this-super-strong-password-now"
            
            password_hash = generate_password_hash(ADMIN_PASSWORD)
            totp_secret = pyotp.random_base32()
            
            conn.execute('INSERT INTO users (username, password, totp_secret) VALUES (?, ?, ?)',
                         ('admin', password_hash, totp_secret))
            conn.commit()
            logger.warning("Vytvorený predvolený administrátorský účet.")
            logger.warning("Prihláste sa s menom 'admin' a heslom, ktoré ste nastavili v app.py.")
            logger.warning("Následne budete vyzvaný na nastavenie 2FA.")

# --- Pôvodné funkcie (zostávajú nezmenené) ---
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
    """Získa obsah konfigurácie priamo cez SSH bez ukladania súboru na MikroTiku."""
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

# ... (Všetky ostatné vaše funkcie ako `compare_with_local_backup`, `run_backup_logic`, `get_snmp_data`, atď. tu pokračujú bez zmeny)
# Pre prehľadnosť ich tu neskracujem, ale vo finálnom súbore musia byť.
def compare_with_local_backup(ip, remote_content):
    # ... (celý kód funkcie)
    pass
def run_backup_logic(device):
    # ... (celý kód funkcie)
    pass
def get_snmp_data(ip, community='public'):
    # ... (celý kód funkcie)
    pass
def upload_to_ftp(local_path):
    # ... (celý kód funkcie)
    pass
def send_pushover_notification(message, title="MikroTik Manager"):
    # ... (celý kód funkcie)
    pass


# --- PRIDANÉ PRE LOGIN ---
# Nové routy pre prihlasovanie, odhlasovanie a nastavenie 2FA
@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))

    error = None
    two_factor_required = '2fa_user_id' in session

    if request.method == 'POST':
        if '2fa_user_id' in session:
            user = load_user(session['2fa_user_id'])
            if not user:
                session.pop('2fa_user_id', None)
                return redirect(url_for('login'))

            totp_code = request.form.get('totp_code', '').strip()
            if pyotp.TOTP(user.totp_secret).verify(totp_code):
                login_user(user, remember=True)
                session.pop('2fa_user_id', None)
                return redirect(request.args.get('next') or url_for('index'))
            else:
                error = 'Neplatný overovací kód.'
        else:
            username = request.form.get('username')
            password = request.form.get('password')
            with get_db_connection() as conn:
                user_data = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
            
            if user_data and check_password_hash(user_data['password'], password):
                session['2fa_user_id'] = user_data['id']
                return redirect(url_for('login'))
            else:
                error = 'Neplatné meno alebo heslo.'
                time.sleep(1)

    return render_template('login.html', error=error, two_factor_required=two_factor_required)

@app.route('/setup-2fa')
@login_required
def setup_2fa():
    secret = current_user.totp_secret
    uri = pyotp.totp.TOTP(secret).provisioning_uri(name=current_user.username, issuer_name="MikroTik Manager")
    
    img = qrcode.make(uri)
    buf = BytesIO()
    img.save(buf)
    qr_code_data = base64.b64encode(buf.getvalue()).decode('ascii')

    return render_template('setup_2fa.html', qr_code=qr_code_data)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

# --- Ochrana pôvodných rout ---
# Hlavná stránka aplikácie je teraz chránená
@app.route('/')
@login_required
def index():
    # Ak používateľ pri prvom prihlásení ešte nenastavil 2FA, presmerujeme ho
    if current_user.is_authenticated and not current_user.totp_secret:
         return redirect(url_for('setup_2fa'))
    return send_from_directory('.', 'index.html')

# Všetky API routy musia byť chránené dekorátorom @login_required
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

# --- Pôvodné funkcie pre plánovač (zostávajú nezmenené) ---
def scheduled_backup_job():
    add_log('info', "Spúšťam naplánovanú úlohu zálohovania...")
    socketio.emit('log_update', {'level': 'info', 'message': 'Spúšťa sa automatická úloha zálohovania...'})
    with app.app_context(): # Dôležité pre beh v threade
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

# --- Upravená inicializácia na konci súboru ---
init_environment()
# Používame app_context, aby sme mali prístup k aplikácii pri inicializácii
with app.app_context():
    init_database()
    create_admin_user_if_not_exists()
    setup_scheduler()

threading.Thread(target=run_scheduler, daemon=True).start()
logger.info("Aplikácia MikroTik Backup Manager sa spúšťa...")

# Tento blok sa použije len pre lokálny vývoj (zostáva pôvodný)
if __name__ == '__main__':
    logger.info("Server sa spúšťa v režime pre vývoj na http://0.0.0.0:5000")
    socketio.run(app, host='0.0.0.0', port=5000, allow_unsafe_werkzeug=True)