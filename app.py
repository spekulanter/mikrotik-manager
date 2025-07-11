#!/usr/bin/env python3
"""
MikroTik Backup Web Backend v2.1
Flask server s WebSocket a SNMP podporou, integrovaná pokročilá logika
z pôvodného skriptu mikrotik_backup_v9_no_login.py.
"""

import os
import time
import json
import sqlite3
import threading
from datetime import datetime
from flask import Flask, request, jsonify, send_from_directory
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

# --- Základné nastavenie ---
app = Flask(__name__, static_folder='.', static_url_path='')
app.config['SECRET_KEY'] = os.urandom(24)
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')
CORS(app)

# Logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Cesty k súborom a adresárom
DATA_DIR = os.environ.get('DATA_DIR', '/var/lib/mikrotik-manager/data')
DB_PATH = os.path.join(DATA_DIR, 'mikrotik_backup.db')
BACKUP_DIR = os.path.join(DATA_DIR, 'backups')

# Globálne premenné
backup_tasks = {} # Sleduje bežiace backup úlohy

# --- Inicializácia ---
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
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
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
            conn.commit()
            logger.info("Databáza úspešne inicializovaná.")
    except sqlite3.Error as e:
        logger.error(f"Chyba pri inicializácii databázy: {e}")

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

# --- Pokročilá logika zálohovania (z pôvodného skriptu) ---

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

def compare_with_local_backup(ip, remote_content):
    """Porovná vzdialenú konfiguráciu s poslednou lokálnou zálohou."""
    try:
        # Nájdi najnovší lokálny .rsc súbor pre danú IP
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

        # Porovnanie s ignorovaním dynamických častí
        ignore_keywords = ['list=blacklist', 'comment=spamhaus']
        local_lines = [line for line in local_content.splitlines() if not any(kw in line for kw in ignore_keywords)]
        remote_lines = [line for line in remote_content.splitlines() if not any(kw in line for kw in ignore_keywords)]
        
        diff = list(difflib.unified_diff(local_lines, remote_lines))
        
        if len(diff) > 2: # unified_diff always has header lines, so > 2 means changes
            add_log('info', f"Zistené zmeny v konfigurácii pre {ip}. Spúšťam zálohu.", ip)
            return True
        else:
            add_log('info', f"Žiadne zmeny v konfigurácii pre {ip}. Záloha sa preskakuje.", ip)
            return False
    except Exception as e:
        add_log('error', f"Chyba pri porovnávaní záloh pre {ip}: {e}", ip)
        return True # V prípade chyby radšej zálohovať

def run_backup_logic(device):
    """Hlavná logika pre vytvorenie zálohy, teraz s pokročilými kontrolami."""
    ip, username, password, low_memory = device['ip'], device['username'], device['password'], device['low_memory']
    add_log('info', f"Spúšťam pokročilú zálohu pre {ip}", ip)
    socketio.emit('backup_status', {'ip': ip, 'id': device['id'], 'status': 'starting'})
    
    client = None
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(ip, username=username, password=password, timeout=30)
        add_log('info', "SSH pripojenie úspešne.", ip)

        # 1. Porovnanie konfigurácie
        remote_config = get_mikrotik_export_direct(client, ip)
        if remote_config is None:
            raise Exception("Nepodarilo sa získať konfiguráciu na porovnanie.")
        
        if not compare_with_local_backup(ip, remote_config):
            socketio.emit('backup_status', {'ip': ip, 'id': device['id'], 'status': 'skipped'})
            return # Koniec, ak nie sú zmeny

        # 2. Získanie identity a detekcia /flash
        _, stdout, _ = client.exec_command('/system identity print')
        identity_match = re.search(r'name:\s*(.+)', stdout.read().decode().strip())
        safe_identity = re.sub(r'[^a-zA-Z0-9_-]', '_', identity_match.group(1) if identity_match else ip)
        
        _, stdout, _ = client.exec_command('/file print where type=directory')
        has_flash = 'flash' in stdout.read().decode()
        add_log('info', f"Zariadenie {'má' if has_flash else 'nemá'} /flash adresár.", ip)

        # 3. Dôkladný cleanup
        add_log('info', "Vykonávam cleanup starých súborov na zariadení...", ip)
        client.exec_command(':foreach i in=[/file find where name~".backup" or name~".rsc"] do={/file remove $i}')
        time.sleep(5)

        # 4. Vytvorenie záloh
        date_str = datetime.now().strftime("%Y%m%d-%H%M%S")
        base_filename = f"{safe_identity}_{ip}_{date_str}"
        backup_path = f"flash/{base_filename}.backup" if has_flash else f"{base_filename}.backup"
        rsc_path = f"flash/{base_filename}.rsc" if has_flash else f"{base_filename}.rsc"
        
        add_log('info', f"Vytváram súbory {base_filename}.backup a .rsc...", ip)
        client.exec_command(f'/system backup save name="{backup_path}" dont-encrypt=yes')
        time.sleep(15 if low_memory else 10)
        client.exec_command(f'/export file="{rsc_path}"')
        time.sleep(20 if low_memory else 15)

        # 5. Sťahovanie a finálny cleanup
        with client.open_sftp() as sftp:
            sftp.get(backup_path, os.path.join(BACKUP_DIR, f"{base_filename}.backup"))
            sftp.get(rsc_path, os.path.join(BACKUP_DIR, f"{base_filename}.rsc"))
            add_log('info', "Súbory úspešne stiahnuté.", ip)
            sftp.remove(backup_path)
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

# --- Ostatné funkcie (SNMP, FTP, Pushover, API) ---
def get_snmp_data(ip, community='public'):
    oids = {'identity': '1.3.6.1.2.1.1.5.0', 'uptime': '1.3.6.1.2.1.1.3.0', 'version': '1.3.6.1.4.1.14988.1.1.4.4.0', 'board_name': '1.3.6.1.4.1.14988.1.1.7.3.0', 'cpu_load': '1.3.6.1.4.1.14988.1.1.3.14.0', 'temperature': '1.3.6.1.4.1.14988.1.1.3.10.0', 'voltage': '1.3.6.1.4.1.14988.1.1.3.8.0', 'free_memory': '1.3.6.1.4.1.14988.1.1.1.1.0'}
    results = {}
    try:
        from pysnmp.hlapi import getCmd, SnmpEngine, CommunityData, UdpTransportTarget, ContextData, ObjectType, ObjectIdentity
        for name, oid in oids.items():
            errorIndication, errorStatus, _, varBinds = next(getCmd(SnmpEngine(), CommunityData(community, mpModel=0), UdpTransportTarget((ip, 161), timeout=2, retries=1), ContextData(), ObjectType(ObjectIdentity(oid))))
            if errorIndication or errorStatus: results[name] = 'N/A'
            else:
                val = varBinds[0][1]
                if name == 'uptime': results[name] = str(datetime.fromtimestamp(time.time() - int(val) / 100).strftime('%jd %Hh %Mm'))
                elif name in ['temperature', 'voltage']: results[name] = f"{float(val) / 10:.1f}"
                elif name == 'free_memory': results[name] = f"{int(val) / 1024 / 1024:.2f} MB"
                else: results[name] = str(val)
        return results
    except Exception: return {key: 'N/A' for key in oids}

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
        add_log('success', f"Pushover notifikácia odoslaná: {message}")
    except Exception as e: add_log('error', f"Odoslanie Pushover notifikácie zlyhalo: {e}")

@app.route('/')
def index(): return send_from_directory('.', 'index.html')

@app.route('/api/devices', methods=['GET', 'POST'])
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
                add_log('success', f"Zariadenie {data['ip']} uložené.")
                return jsonify({'status': 'success'})
            except sqlite3.IntegrityError: return jsonify({'status': 'error', 'message': 'Zariadenie s touto IP už existuje'}), 409

@app.route('/api/devices/<int:device_id>', methods=['DELETE'])
def delete_device(device_id):
    with get_db_connection() as conn:
        conn.execute("DELETE FROM devices WHERE id = ?", (device_id,))
        conn.commit()
    add_log('warning', f"Zariadenie bolo odstránené.")
    return jsonify({'status': 'success'})

@app.route('/api/backup/<int:device_id>', methods=['POST'])
def backup_device(device_id):
    with get_db_connection() as conn:
        device = conn.execute('SELECT * FROM devices WHERE id = ?', (device_id,)).fetchone()
    if not device: return jsonify({'status': 'error', 'message': 'Zariadenie nebolo nájdené.'}), 404
    if device['ip'] in backup_tasks: return jsonify({'status': 'error', 'message': 'Záloha už prebieha.'}), 409
    backup_tasks[device['ip']] = True
    threading.Thread(target=run_backup_logic, args=(dict(device),)).start()
    return jsonify({'status': 'success', 'message': 'Záloha spustená.'})

@app.route('/api/backup/all', methods=['POST'])
def backup_all_devices():
    with get_db_connection() as conn:
        devices = [dict(row) for row in conn.execute('SELECT * FROM devices').fetchall()]
    count = sum(1 for d in devices if d['ip'] not in backup_tasks and (backup_tasks.update({d['ip']:True}) or True) and (threading.Thread(target=run_backup_logic, args=(d,)).start() or True))
    add_log('info', f"Spustená hromadná záloha pre {count} zariadení.")
    return jsonify({'status': 'success', 'message': f'Hromadná záloha spustená pre {count} zariadení.'})

@app.route('/api/snmp/<int:device_id>', methods=['GET'])
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
def handle_settings():
    with get_db_connection() as conn:
        if request.method == 'GET': return jsonify({row['key']: row['value'] for row in conn.execute('SELECT key, value FROM settings').fetchall()})
        if request.method == 'POST':
            for key, value in request.json.items():
                conn.execute("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)", (key, str(value)))
            conn.commit()
            add_log('success', "Nastavenia boli aktualizované.")
            setup_scheduler()
            return jsonify({'status': 'success'})

@app.route('/api/notifications/test', methods=['POST'])
def test_notification():
    send_pushover_notification("Toto je testovacia správa z MikroTik Backup Manager.")
    return jsonify({'status': 'success'})

def scheduled_backup_job():
    add_log('info', "Spúšťam naplánovanú úlohu zálohovania...")
    socketio.emit('log_update', {'level': 'info', 'message': 'Spúšťa sa automatická úloha zálohovania...'})
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

if __name__ == '__main__':
    init_environment()
    init_database()
    setup_scheduler()
    threading.Thread(target=run_scheduler, daemon=True).start()
    logger.info("Server sa spúšťa na http://0.0.0.0:5000")
    socketio.run(app, host='0.0.0.0', port=5000, allow_unsafe_werkzeug=True)