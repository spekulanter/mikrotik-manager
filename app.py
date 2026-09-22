#!/usr/bin/env python3
"""
MikroTik Manager - Secured
Pridaná webová registrácia, zobrazenie stavu prihlásenia a možnosť zmeny hesla.
"""

import os
import time
import json
import sqlite3
import threading
from datetime import datetime, timedelta, timezone
import subprocess
import re
import platform
import statistics
import secrets
import hashlib
import socket
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
from ftplib import FTP, error_perm
import http.client
import urllib.parse
from html import unescape
from contextlib import contextmanager
import logging
import schedule
import heapq
import itertools
from concurrent.futures import ThreadPoolExecutor
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import pyotp
import qrcode
import base64
from io import BytesIO
from cryptography.fernet import Fernet
import base64 as b64
import requests
import xml.etree.ElementTree as ET
import ipaddress

# --- Definície adresárov pred konfiguráciou aplikácie ---
DATA_DIR = os.environ.get('DATA_DIR', '/var/lib/mikrotik-manager/data')
DB_PATH = os.path.join(DATA_DIR, 'mikrotik_manager.db')
BACKUP_DIR = os.path.join(DATA_DIR, 'backups')
BOOLEAN_SETTING_KEYS = {
    'ping_monitor_enabled', 'snmp_health_check_enabled', 'backup_schedule_enabled',
    'backup_detailed_logging', 'notify_backup_success', 'notify_backup_failure',
    'notify_device_offline', 'notify_device_online', 'notify_temp_critical',
    'notify_cpu_critical', 'notify_memory_critical', 'notify_reboot_detected',
    'notify_version_change', 'notify_failed_login', 'notify_failed_2fa', 'notify_password_recovery_failure', 'quiet_hours_enabled', 'availability_monitoring_enabled',
    'debug_terminal', 'notify_cert_expiry', 'notify_new_routeros_version',
    'updater_backup_before_update', 'notify_device_purged',
    'notify_ssh_host_key_change'
}

SETTING_LABELS = {
    'availability_monitoring_enabled': 'Povoliť monitorovanie dostupnosti zariadení',
    'backup_delay_seconds': 'Oneskorenie medzi zálohami (sekundy)',
    'backup_detailed_logging': 'Detailné logovanie zálohového procesu',
    'backup_retention_count': 'Počet uchovávaných záloh (na zariadenie)',
    'backup_schedule_day': 'Deň v týždni',
    'backup_schedule_enabled': 'Povoliť automatické zálohovanie',
    'backup_schedule_time': 'Čas zálohovania (HH:MM)',
    'backup_schedule_type': 'Interval zálohovania',
    'cpu_critical_threshold': 'CPU (%)',
    'debug_terminal': 'Debug Terminal',
    'ftp_directory': 'FTP Adresár',
    'ftp_password': 'FTP Heslo',
    'ftp_port': 'FTP Port',
    'ftp_server': 'FTP Server',
    'ftp_timeout_seconds': 'FTP timeout',
    'ftp_username': 'FTP Používateľ',
    'log_max_entries': 'Max zobrazených logov v okne',
    'log_retention_days': 'Uchovávanie aktivity logov (dni)',
    'memory_critical_threshold': 'Pamäť (%)',
    'ping_check_interval_seconds': 'Ping interval (sekundy)',
    'ping_heartbeat_interval': 'Globálny ping interval (sekundy)',
    'ping_monitor_enabled': 'Ping monitoring (globálny prepínač)',
    'ping_retention_days': 'ICMP ping dáta (dni)',
    'ping_retries': 'Počet neúspešných pokusov',
    'ping_retry_interval': 'Retry interval pri výpadku (sekundy)',
    'ping_timeout': 'Timeout pre jeden ping (sekundy)',
    'pushover_app_key': 'Pushover App Key/Token',
    'pushover_user_key': 'Pushover User Key',
    'quiet_hours_enabled': 'Povoliť \"Quiet Hours\" (tichý režim)',
    'quiet_hours_end': 'Tichý režim do',
    'quiet_hours_start': 'Tichý režim od',
    'snmp_check_interval_minutes': 'Globálny interval SNMP zberu dát (minúty)',
    'snmp_health_check_enabled': 'Automatický SNMP health check',
    'snmp_health_check_interval_minutes': 'Frekvencia health checku (minúty)',
    'snmp_retention_days': 'SNMP výkonnostné dáta (dni)',
    'temp_critical_threshold': 'Teplota (°C)',
    'notify_device_offline': 'Notifikácia: zariadenie offline (ICMP)',
    'notify_device_online': 'Notifikácia: zariadenie online (ICMP)',
    'notify_backup_success': 'Notifikácia: úspešná záloha',
    'notify_backup_failure': 'Notifikácia: neúspešná záloha',
    'notify_temp_critical': 'Notifikácia: kritická teplota (SNMP)',
    'notify_cpu_critical': 'Notifikácia: kritická záťaž CPU (SNMP)',
    'notify_memory_critical': 'Notifikácia: kritická pamäť (SNMP)',
    'notify_reboot_detected': 'Notifikácia: detekovaný reštart',
    'notify_version_change': 'Notifikácia: zmena verzie OS',
    'notify_failed_login': 'Notifikácia: neúspešné prihlásenie do aplikácie',
    'notify_failed_2fa': 'Notifikácia: neúspešné 2FA overenie',
    'notify_password_recovery_failure': 'Notifikácia: neúspešná obnova hesla',
    'notify_new_routeros_version': 'Notifikácia: nová verzia RouterOS (RSS)',
    'notify_device_purged': 'Notifikácia: zariadenie automaticky vymazané z koša',
    'notify_ssh_host_key_change': 'Notifikácia: SSH kľúč vyžaduje potvrdenie',
    'updater_backup_before_update': 'Záloha pred aktualizáciou',
    'updater_post_backup_delay': 'Pauza po zálohe pred aktualizáciou',
    'cert_www_port': 'Port služby www (HTTP)',
    'cert_www_ssl_port': 'Port služby www-ssl (HTTPS)',
    'viewport': 'Režim zobrazenia',
    'deleted_device_retention_days': 'Uchovávanie zmazaných zariadení (dni)'
}

SENSITIVE_SETTINGS = {'ftp_password', 'pushover_app_key', 'pushover_user_key'}

SETTING_VALUE_SUFFIXES = {
    'ping_check_interval_seconds': ' s',
    'ping_retry_interval': ' s',
    'ping_timeout': ' s',
    'ping_heartbeat_interval': ' s',
    'ping_retention_days': ' dní',
    'ping_retries': ' pokusov',
    'backup_delay_seconds': ' s',
    'ftp_timeout_seconds': ' s',
    'updater_post_backup_delay': ' s',
    'backup_retention_count': ' ks',
    'snmp_check_interval_minutes': ' min',
    'snmp_health_check_interval_minutes': ' min',
    'snmp_retention_days': ' dní',
    'log_retention_days': ' dní',
    'log_max_entries': ' záznamov',
    'cpu_critical_threshold': ' %',
    'memory_critical_threshold': ' %',
    'temp_critical_threshold': ' °C',
    'deleted_device_retention_days': ' dní'
}

SCHEDULE_TYPE_LABELS = {
    'daily': 'denne',
    'weekly': 'týždenne',
    'monthly': 'mesačne',
    'custom': 'vlastný plán'
}

SCHEDULE_DAY_LABELS = {
    'monday': 'pondelok',
    'tuesday': 'utorok',
    'wednesday': 'streda',
    'thursday': 'štvrtok',
    'friday': 'piatok',
    'saturday': 'sobota',
    'sunday': 'nedeľa'
}

VIEWPORT_LABELS = {
    'desktop': 'Desktop režim',
    'mobile': 'Mobilný režim',
    'auto': 'Automaticky'
}

def get_setting_label(key):
    """Vráti čitateľný názov nastavenia"""
    return SETTING_LABELS.get(key, key.replace('_', ' ').capitalize())

def format_setting_value(key, value):
    """Formátovanie hodnoty nastavenia pre logy"""
    if value is None or value == '':
        return 'nenastavené'
    value_str = str(value)
    lower_value = value_str.lower()
    bool_like = key in BOOLEAN_SETTING_KEYS or key.startswith('notify_') or key.endswith('_enabled')
    if bool_like:
        return 'zapnuté' if lower_value == 'true' else 'vypnuté'
    if key == 'backup_schedule_type':
        return SCHEDULE_TYPE_LABELS.get(lower_value, value_str)
    if key == 'backup_schedule_day':
        return SCHEDULE_DAY_LABELS.get(lower_value, value_str)
    if key == 'viewport':
        return VIEWPORT_LABELS.get(lower_value, value_str)
    suffix = SETTING_VALUE_SUFFIXES.get(key)
    if suffix:
        return f"{value_str}{suffix}"
    return value_str

def sync_ping_interval_alias(conn):
    """Synchronize legacy settings.html ping key with the key used by monitoring."""
    legacy_row = conn.execute("SELECT value FROM settings WHERE key = ?", ('ping_heartbeat_interval',)).fetchone()
    if not legacy_row or legacy_row['value'] in (None, ''):
        return

    legacy_value = str(legacy_row['value'])
    try:
        legacy_int = int(legacy_value)
    except (ValueError, TypeError):
        return

    if legacy_int < 20 or legacy_int > 86400:
        return

    current_row = conn.execute("SELECT value FROM settings WHERE key = ?", ('ping_check_interval_seconds',)).fetchone()
    current_value = str(current_row['value']) if current_row and current_row['value'] is not None else None
    if current_value != legacy_value:
        conn.execute(
            "INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)",
            ('ping_check_interval_seconds', legacy_value)
        )
        conn.commit()

DEFAULT_SETTING_VALUES = {
    'ping_check_interval_seconds': '120',
    'ping_monitor_enabled': 'true',
    'snmp_check_interval_minutes': '10',
    'snmp_health_check_enabled': 'true',
    'snmp_health_check_interval_minutes': '15',
    'backup_schedule_enabled': 'false',
    'backup_schedule_type': 'daily',
    'backup_schedule_day': 'sunday',
    'backup_schedule_time': '02:00',
    'backup_retention_count': '10',
    'backup_delay_seconds': '30',
    'backup_detailed_logging': 'false',
    'ftp_port': '21',
    'ftp_timeout_seconds': '15',
    'updater_backup_before_update': 'true',
    'updater_post_backup_delay': '10',
    'updater_stabilization_delay': '120',
    'updater_pre_reboot_delay': '20',
    'notify_ssh_host_key_change': 'true',
    'cert_www_port': '80',
    'cert_www_ssl_port': '443'
}

PASSWORD_RECOVERY_CODE_LENGTH = 8
PASSWORD_RECOVERY_EXPIRY_MINUTES = 10
PASSWORD_RECOVERY_REQUEST_COOLDOWN_SECONDS = 60

# --- Nastavenie aplikácie (upravené pre HTML šablóny) ---
app = Flask(__name__, static_folder='.', static_url_path='', template_folder='.')

def create_private_file(path, data):
    """Create a new file atomically with owner-only permissions."""
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, 'O_NOFOLLOW'):
        flags |= os.O_NOFOLLOW

    fd = os.open(path, flags, 0o600)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, 'wb') as f:
            fd = None
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
    except Exception:
        if fd is not None:
            os.close(fd)
        try:
            os.unlink(path)
        except OSError:
            pass
        raise

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
        create_private_file(secret_key_file, secret_key)
        print("Vytvorený nový persistent SECRET_KEY")
        return secret_key
    except FileExistsError:
        # Iný proces mohol kľúč vytvoriť medzi kontrolou a zápisom.
        try:
            with open(secret_key_file, 'rb') as f:
                existing_key = f.read()
            if len(existing_key) == 32:
                return existing_key
        except Exception as e:
            print(f"Chyba pri čítaní súbežne vytvoreného SECRET_KEY: {e}")
        return os.urandom(32)
    except Exception as e:
        print(f"Chyba pri ukladaní SECRET_KEY: {e}")
        # Fallback na session-only kľúč
        return os.urandom(32)

app.config['SECRET_KEY'] = get_or_create_secret_key()
# PRAKTICKÉ NASTAVENIE: 1 rok platnosť cookie (s persistent SECRET_KEY je to bezpečné)
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=365)
app.config['MAX_CONTENT_LENGTH'] = 512 * 1024 * 1024  # 512 MB – ochrana pred ZIP bomb

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
        "style-src 'self' 'unsafe-inline'; "
        "script-src 'self' 'unsafe-inline' 'unsafe-eval'; "
        "font-src 'self' data:; "
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
# Tracking for sequential backup progress so frontend can show e.g. 1/16
sequential_backup_total = 0
sequential_backup_current = 0

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
        try:
            create_private_file(key_file, key)
            return key
        except FileExistsError:
            # Another process created the key after the existence check.
            with open(key_file, 'rb') as f:
                return f.read()

# Initialize encryption
ENCRYPTION_KEY = get_encryption_key()
cipher = Fernet(ENCRYPTION_KEY)

def encrypt_password(password):
    """Encrypt password for secure storage"""
    if password is None:
        return None
    return b64.b64encode(cipher.encrypt(password.encode())).decode()

def decrypt_password_strict(encrypted_password):
    """Decrypt password and raise on invalid ciphertext."""
    if encrypted_password is None:
        return None
    return cipher.decrypt(b64.b64decode(encrypted_password.encode())).decode()

def decrypt_password(encrypted_password):
    """Decrypt password for use"""
    if encrypted_password is None:
        return None
    try:
        return decrypt_password_strict(encrypted_password)
    except:
        # If decryption fails, assume it's already plaintext (for backward compatibility)
        return encrypted_password

def is_encrypted_secret(value):
    """Check if value looks like ciphertext produced by encrypt_password()."""
    if value in (None, ''):
        return False
    try:
        decrypt_password_strict(str(value))
        return True
    except Exception:
        return False

def is_password_hash(value):
    """Check if value appears to be a Werkzeug password hash."""
    if value in (None, ''):
        return False
    value_str = str(value)
    return value_str.startswith('scrypt:') or value_str.startswith('pbkdf2:')

def verify_backup_code(stored_code, provided_code):
    """Verify backup code against hashed (preferred) or plaintext (legacy) storage."""
    if stored_code in (None, '') or provided_code in (None, ''):
        return False
    stored_code_str = str(stored_code)
    provided_code_str = str(provided_code)

    if is_password_hash(stored_code_str):
        try:
            return check_password_hash(stored_code_str, provided_code_str)
        except Exception:
            return False

    # Legacy fallback for old plaintext backup codes.
    return secrets.compare_digest(stored_code_str, provided_code_str)

def parse_db_datetime(value):
    """Parse DB datetime string/timestamp into datetime object."""
    if value is None:
        return None
    if isinstance(value, datetime):
        return value
    value_str = str(value).strip()
    if not value_str:
        return None
    try:
        return datetime.fromisoformat(value_str.replace(' ', 'T'))
    except Exception:
        return None

def find_matching_backup_code_record(conn, user_id, provided_code):
    """Find matching active backup code record for user."""
    backup_records = conn.execute(
        'SELECT id, code FROM backup_codes WHERE user_id = ? AND used = 0',
        (user_id,)
    ).fetchall()
    for record in backup_records:
        if verify_backup_code(record['code'], provided_code):
            return record
    return None

def issue_password_recovery_code(user_id, source_ip):
    """Create one-time password recovery code and store only its hash."""
    now = datetime.now()
    with get_db_connection() as conn:
        latest = conn.execute(
            'SELECT created_at FROM password_recovery_tokens WHERE user_id = ? ORDER BY created_at DESC LIMIT 1',
            (user_id,)
        ).fetchone()
        if latest:
            latest_created = parse_db_datetime(latest['created_at'])
            if latest_created and (now - latest_created).total_seconds() < PASSWORD_RECOVERY_REQUEST_COOLDOWN_SECONDS:
                return None, 'cooldown'

        conn.execute(
            'UPDATE password_recovery_tokens SET used = 1, used_at = ? WHERE user_id = ? AND used = 0',
            (now, user_id)
        )
        recovery_code = ''.join(secrets.choice(string.digits) for _ in range(PASSWORD_RECOVERY_CODE_LENGTH))
        recovery_code_hash = generate_password_hash(recovery_code)
        conn.execute(
            'INSERT INTO password_recovery_tokens (user_id, token_hash, created_at, expires_at, used, request_ip) VALUES (?, ?, ?, ?, 0, ?)',
            (user_id, recovery_code_hash, now, now + timedelta(minutes=PASSWORD_RECOVERY_EXPIRY_MINUTES), source_ip)
        )
        conn.commit()
    return recovery_code, 'ok'

def find_matching_recovery_token_record(conn, user_id, provided_code):
    """Find matching active recovery token record for user."""
    now = datetime.now()
    token_records = conn.execute(
        'SELECT id, token_hash, expires_at FROM password_recovery_tokens WHERE user_id = ? AND used = 0 ORDER BY created_at DESC',
        (user_id,)
    ).fetchall()
    for record in token_records:
        expires_at = parse_db_datetime(record['expires_at'])
        if expires_at and expires_at < now:
            continue
        try:
            if check_password_hash(record['token_hash'], provided_code):
                return record
        except Exception:
            continue
    return None

def encrypt_setting_value_if_sensitive(key, value):
    """Encrypt sensitive setting values before storing in DB."""
    value_str = '' if value is None else str(value)
    if key not in SENSITIVE_SETTINGS or value_str == '':
        return value_str
    if is_encrypted_secret(value_str):
        return value_str
    return encrypt_password(value_str)

def decrypt_setting_value_if_sensitive(key, value):
    """Decrypt sensitive setting values when reading from DB."""
    value_str = '' if value is None else str(value)
    if key in SENSITIVE_SETTINGS and value_str:
        return decrypt_password(value_str)
    return value_str

def decrypt_sensitive_settings_map(settings):
    """Return a copy of settings dict with sensitive keys decrypted."""
    if not settings:
        return {}
    decrypted = dict(settings)
    for key in SENSITIVE_SETTINGS:
        if key in decrypted:
            decrypted[key] = decrypt_setting_value_if_sensitive(key, decrypted[key])
    return decrypted

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

def migrate_sensitive_settings():
    """Migrate plaintext sensitive settings to encrypted format."""
    try:
        with get_db_connection() as conn:
            placeholders = ','.join('?' for _ in SENSITIVE_SETTINGS)
            rows = conn.execute(
                f'SELECT key, value FROM settings WHERE key IN ({placeholders})',
                tuple(SENSITIVE_SETTINGS)
            ).fetchall()
            migrated_count = 0

            for row in rows:
                key = row['key']
                value = row['value']
                if value in (None, '') or is_encrypted_secret(value):
                    continue

                conn.execute(
                    'UPDATE settings SET value = ? WHERE key = ?',
                    (encrypt_password(value), key)
                )
                migrated_count += 1

            if migrated_count > 0:
                conn.commit()
                logger.info(f"Sensitive settings migration completed: {migrated_count} values encrypted")
            else:
                logger.info("Sensitive settings migration: No plaintext sensitive values found")
    except Exception as e:
        logger.error(f"Sensitive settings migration failed: {e}")
        import traceback
        logger.error(f"Sensitive settings migration traceback: {traceback.format_exc()}")

def migrate_snmp_communities():
    """Migrate plaintext SNMP communities in devices table to encrypted format."""
    try:
        with get_db_connection() as conn:
            devices = conn.execute('SELECT id, snmp_community FROM devices').fetchall()
            migrated_count = 0

            for device in devices:
                device_id = device['id']
                snmp_community = device['snmp_community']
                if snmp_community in (None, '') or is_encrypted_secret(snmp_community):
                    continue

                conn.execute(
                    'UPDATE devices SET snmp_community = ? WHERE id = ?',
                    (encrypt_password(snmp_community), device_id)
                )
                migrated_count += 1

            if migrated_count > 0:
                conn.commit()
                logger.info(f"SNMP community migration completed: {migrated_count} values encrypted")
            else:
                logger.info("SNMP community migration: No plaintext values found")
    except Exception as e:
        logger.error(f"SNMP community migration failed: {e}")
        import traceback
        logger.error(f"SNMP community migration traceback: {traceback.format_exc()}")

def migrate_totp_secrets():
    """Migrate plaintext TOTP secrets in users table to encrypted format."""
    try:
        with get_db_connection() as conn:
            users = conn.execute('SELECT id, totp_secret FROM users').fetchall()
            migrated_count = 0

            for user in users:
                user_id = user['id']
                totp_secret = user['totp_secret']
                if totp_secret in (None, '') or is_encrypted_secret(totp_secret):
                    continue

                conn.execute(
                    'UPDATE users SET totp_secret = ? WHERE id = ?',
                    (encrypt_password(totp_secret), user_id)
                )
                migrated_count += 1

            if migrated_count > 0:
                conn.commit()
                logger.info(f"TOTP secret migration completed: {migrated_count} values encrypted")
            else:
                logger.info("TOTP secret migration: No plaintext values found")
    except Exception as e:
        logger.error(f"TOTP secret migration failed: {e}")
        import traceback
        logger.error(f"TOTP secret migration traceback: {traceback.format_exc()}")

def migrate_backup_codes_to_hashes():
    """Migrate plaintext backup codes to password hashes."""
    try:
        with get_db_connection() as conn:
            backup_codes = conn.execute('SELECT id, code FROM backup_codes').fetchall()
            migrated_count = 0

            for backup_code in backup_codes:
                record_id = backup_code['id']
                code_value = backup_code['code']
                if code_value in (None, '') or is_password_hash(code_value):
                    continue

                conn.execute(
                    'UPDATE backup_codes SET code = ? WHERE id = ?',
                    (generate_password_hash(code_value), record_id)
                )
                migrated_count += 1

            if migrated_count > 0:
                conn.commit()
                logger.info(f"Backup code migration completed: {migrated_count} values hashed")
            else:
                logger.info("Backup code migration: No plaintext values found")
    except Exception as e:
        logger.error(f"Backup code migration failed: {e}")
        import traceback
        logger.error(f"Backup code migration traceback: {traceback.format_exc()}")

# Helper functions for device secret handling
def get_device_with_decrypted_password(device_dict):
    """Take device dict and decrypt supported secret fields."""
    if isinstance(device_dict, dict):
        device_dict = device_dict.copy()  # Don't modify original
        if 'password' in device_dict:
            device_dict['password'] = decrypt_password(device_dict['password'])
        if 'snmp_community' in device_dict and device_dict['snmp_community'] is not None:
            device_dict['snmp_community'] = decrypt_password(device_dict['snmp_community'])
        for secret_field in ('snmp_v3_auth_password', 'snmp_v3_priv_password'):
            if secret_field in device_dict and device_dict[secret_field] is not None:
                device_dict[secret_field] = decrypt_password(device_dict[secret_field])
    return device_dict

def prepare_devices_with_decrypted_passwords(devices):
    """Decrypt passwords for a list of devices"""
    return [get_device_with_decrypted_password(dict(device)) for device in devices]

# SNMP refresh all tracking
snmp_refresh_tasks = {}
sequential_snmp_refresh_running = False
snmp_refresh_progress = {'current': 0, 'total': 0}
# Gunicorn/Eventlet greenlets share one OS thread. PySNMP owns short-lived
# asyncio loops, which must not overlap in that thread.
snmp_asyncio_lock = threading.Lock()

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
            decrypted_totp_secret = decrypt_password(user_data['totp_secret']) if user_data['totp_secret'] else user_data['totp_secret']
            return User(id=user_data['id'], username=user_data['username'], password=user_data['password'], totp_secret=decrypted_totp_secret, totp_enabled=user_data['totp_enabled'])
    return None

def init_environment():
    os.makedirs(DATA_DIR, exist_ok=True)
    os.makedirs(BACKUP_DIR, exist_ok=True)
    logger.info("Adresáre pre dáta a backupy sú pripravené.")

@contextmanager
def get_db_connection():
    conn = None
    try:
        conn = sqlite3.connect(DB_PATH, check_same_thread=False, timeout=30)
        conn.execute("PRAGMA journal_mode=WAL")
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
            CREATE TABLE IF NOT EXISTS sites (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT COLLATE NOCASE NOT NULL UNIQUE,
                description TEXT DEFAULT NULL
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS devices (
                id INTEGER PRIMARY KEY AUTOINCREMENT, ip TEXT UNIQUE NOT NULL, name TEXT NOT NULL,
                name_source TEXT NOT NULL DEFAULT 'local',
                site_id INTEGER DEFAULT NULL,
                site_update_order INTEGER DEFAULT NULL,
                username TEXT NOT NULL, password TEXT NOT NULL, low_memory BOOLEAN DEFAULT 0,
                snmp_community TEXT DEFAULT 'public', status TEXT DEFAULT 'unknown',
                last_backup TIMESTAMP, last_snmp_data TEXT, snmp_interval_minutes INTEGER DEFAULT 0,
                last_snmp_check TIMESTAMP, ping_interval_seconds INTEGER DEFAULT 0,
                ping_retry_interval_seconds INTEGER DEFAULT 0, monitoring_paused BOOLEAN DEFAULT 0,
                cert_www_port INTEGER DEFAULT 0, cert_www_ssl_port INTEGER DEFAULT 0,
                routeros_update_channel TEXT DEFAULT NULL,
                snmp_version TEXT NOT NULL DEFAULT '2c',
                snmp_v3_username TEXT DEFAULT NULL,
                snmp_v3_security_level TEXT DEFAULT 'authPriv',
                snmp_v3_auth_protocol TEXT DEFAULT 'SHA1',
                snmp_v3_auth_password TEXT DEFAULT NULL,
                snmp_v3_priv_protocol TEXT DEFAULT 'AES',
                snmp_v3_priv_password TEXT DEFAULT NULL,
                snmp_allowed_address TEXT DEFAULT NULL,
                snmp_location TEXT DEFAULT NULL
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS ssh_host_keys (
                device_id INTEGER PRIMARY KEY,
                trusted_host TEXT,
                trusted_key_type TEXT,
                trusted_key_data TEXT,
                trusted_fingerprint TEXT,
                trusted_at TIMESTAMP,
                pending_key_type TEXT,
                pending_key_data TEXT,
                pending_fingerprint TEXT,
                pending_detected_at TIMESTAMP,
                notified_pending_fingerprint TEXT,
                FOREIGN KEY (device_id) REFERENCES devices (id)
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
            cursor.execute('ALTER TABLE devices ADD COLUMN ping_retry_interval_seconds INTEGER DEFAULT 0')
        except sqlite3.OperationalError:
            pass
        try:
            cursor.execute('ALTER TABLE devices ADD COLUMN monitoring_paused BOOLEAN DEFAULT 0')
        except sqlite3.OperationalError:
            pass
        try:
            cursor.execute('ALTER TABLE devices ADD COLUMN cert_www_port INTEGER DEFAULT 0')
        except sqlite3.OperationalError:
            pass
        try:
            cursor.execute('ALTER TABLE devices ADD COLUMN cert_www_ssl_port INTEGER DEFAULT 0')
        except sqlite3.OperationalError:
            pass
        try:
            cursor.execute('ALTER TABLE devices ADD COLUMN deleted_at TIMESTAMP DEFAULT NULL')
        except sqlite3.OperationalError:
            pass
        try:
            cursor.execute('ALTER TABLE devices ADD COLUMN purge_after TIMESTAMP DEFAULT NULL')
        except sqlite3.OperationalError:
            pass
        try:
            cursor.execute('ALTER TABLE devices ADD COLUMN routeros_update_channel TEXT DEFAULT NULL')
        except sqlite3.OperationalError:
            pass
        try:
            cursor.execute('ALTER TABLE devices ADD COLUMN site_id INTEGER DEFAULT NULL')
        except sqlite3.OperationalError:
            pass
        try:
            cursor.execute('ALTER TABLE devices ADD COLUMN site_update_order INTEGER DEFAULT NULL')
        except sqlite3.OperationalError:
            pass
        snmp_v3_columns = (
            ("snmp_version", "TEXT NOT NULL DEFAULT '2c'"),
            ("snmp_v3_username", "TEXT DEFAULT NULL"),
            ("snmp_v3_security_level", "TEXT DEFAULT 'authPriv'"),
            ("snmp_v3_auth_protocol", "TEXT DEFAULT 'SHA1'"),
            ("snmp_v3_auth_password", "TEXT DEFAULT NULL"),
            ("snmp_v3_priv_protocol", "TEXT DEFAULT 'AES'"),
            ("snmp_v3_priv_password", "TEXT DEFAULT NULL"),
            ("snmp_allowed_address", "TEXT DEFAULT NULL"),
            ("snmp_location", "TEXT DEFAULT NULL"),
            ("name_source", "TEXT NOT NULL DEFAULT 'local'"),
        )
        for column_name, column_definition in snmp_v3_columns:
            try:
                cursor.execute(f'ALTER TABLE devices ADD COLUMN {column_name} {column_definition}')
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
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS password_recovery_tokens (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                token_hash TEXT NOT NULL,
                created_at TIMESTAMP NOT NULL,
                expires_at TIMESTAMP NOT NULL,
                used BOOLEAN NOT NULL DEFAULT 0,
                used_at TIMESTAMP,
                request_ip TEXT,
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
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS update_schedule (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                device_id INTEGER NOT NULL,
                scheduled_time TIMESTAMP NOT NULL,
                status TEXT DEFAULT 'pending',
                created_at TIMESTAMP NOT NULL,
                started_at TIMESTAMP,
                completed_at TIMESTAMP,
                result_message TEXT,
                update_channel TEXT NOT NULL DEFAULT 'stable',
                FOREIGN KEY (device_id) REFERENCES devices (id)
            )
        ''')
        try:
            cursor.execute('ALTER TABLE users ADD COLUMN totp_enabled BOOLEAN NOT NULL DEFAULT 0')
        except sqlite3.OperationalError:
            pass
        # Bulk schedule support
        try:
            cursor.execute('ALTER TABLE update_schedule ADD COLUMN bulk_group_id TEXT DEFAULT NULL')
        except sqlite3.OperationalError:
            pass
        try:
            cursor.execute('ALTER TABLE update_schedule ADD COLUMN bulk_sequence INTEGER DEFAULT 0')
        except sqlite3.OperationalError:
            pass
        try:
            cursor.execute("ALTER TABLE update_schedule ADD COLUMN update_channel TEXT NOT NULL DEFAULT 'stable'")
        except sqlite3.OperationalError:
            pass

        # Indexy zrýchľujú per-device grafy, retention a definitívne mazanie.
        # CREATE INDEX IF NOT EXISTS je bezpečné aj pre existujúce databázy.
        for index_sql in (
            'CREATE INDEX IF NOT EXISTS idx_ping_history_device_timestamp ON ping_history (device_id, timestamp)',
            'CREATE INDEX IF NOT EXISTS idx_snmp_history_device_timestamp ON snmp_history (device_id, timestamp)',
            'CREATE INDEX IF NOT EXISTS idx_logs_device_ip ON logs (device_ip)',
            'CREATE INDEX IF NOT EXISTS idx_update_schedule_device_id ON update_schedule (device_id)',
            'CREATE INDEX IF NOT EXISTS idx_devices_deleted_purge ON devices (purge_after) WHERE deleted_at IS NOT NULL',
            'CREATE INDEX IF NOT EXISTS idx_devices_site_id ON devices (site_id)',
        ):
            cursor.execute(index_sql)
        conn.commit()
        
        # ODSTRÁNENÉ: Automatické mazanie logov o zálohovani - logy si budú pamätať aj po reštarte
        
        # Pridanie predvolených hodnôt pre nastavenia
        cursor.execute("INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)", ('backup_retention_count', '10'))
        cursor.execute("INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)", ('backup_delay_seconds', '30'))
        cursor.execute("INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)", ('snmp_check_interval_minutes', '10'))
        cursor.execute("INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)", ('snmp_health_check_enabled', 'true'))
        cursor.execute("INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)", ('snmp_health_check_interval_minutes', '15'))
        cursor.execute("INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)", ('backup_detailed_logging', 'false'))
        cursor.execute("INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)", ('ftp_timeout_seconds', '15'))
        cursor.execute("INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)", ('log_retention_days', '30'))  # Pridané: uchovávanie logov
        cursor.execute("INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)", ('ping_retention_days', '30'))  # Pridané: uchovávanie ping dát
        cursor.execute("INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)", ('snmp_retention_days', '30'))  # Pridané: uchovávanie SNMP dát
        cursor.execute("INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)", ('log_max_entries', '2000'))  # Pridané: limit zobrazených logov
        cursor.execute("INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)", ('notify_backup_success', 'true'))  # Notifikácie úspešných záloh
        cursor.execute("INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)", ('notify_backup_failure', 'true'))  # Notifikácie neúspešných záloh
        cursor.execute("INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)", ('ping_check_interval_seconds', '120'))  # Ping monitoring interval v sekundách
        cursor.execute("INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)", ('ping_monitor_enabled', 'true'))  # Povoliť/zakázať ping monitoring
        cursor.execute("INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)", ('debug_terminal', 'false'))  # Pridané: debug terminál v monitoringu
        cursor.execute("INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)", ('ping_retry_interval', '20'))  # Retry interval pri výpadku v sekundách
        cursor.execute("INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)", ('bulk_update_delay_seconds', '60'))  # Oneskorenie medzi zariadeniami pri hromadnej aktualizácii
        cursor.execute("INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)", ('updater_backup_before_update', 'true'))  # Záloha pred aktualizáciou
        cursor.execute("INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)", ('updater_post_backup_delay', '10'))  # Pauza po zálohe pred aktualizáciou
        cursor.execute("INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)", ('updater_stabilization_delay', '120'))  # Pauza po reštarte OS (krok 6)
        cursor.execute("INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)", ('updater_pre_reboot_delay', '20'))  # Pauza pred finálnym reštartom (krok 8)
        cursor.execute("INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)", ('cert_www_port', '80'))  # HTTP port služby www pre Updater/certifikáty
        cursor.execute("INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)", ('cert_www_ssl_port', '443'))  # HTTPS port služby www-ssl pre Updater
        cursor.execute("INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)", ('ping_retries', '3'))  # Počet neúspešných pokusov pred označením offline
        cursor.execute("INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)", ('ping_timeout', '5'))  # Timeout pre jeden ping
        additional_defaults = {
            'notify_device_offline': 'true',
            'notify_device_online': 'true',
            'notify_temp_critical': 'true',
            'notify_cpu_critical': 'true',
            'notify_memory_critical': 'true',
            'notify_reboot_detected': 'true',
            'notify_version_change': 'true',
            'notify_failed_login': 'true',
            'notify_failed_2fa': 'true',
            'notify_password_recovery_failure': 'true',
            'notify_new_routeros_version': 'true',
            'notify_device_purged': 'true',
            'notify_ssh_host_key_change': 'true',
            'temp_critical_threshold': '75',
            'cpu_critical_threshold': '85',
            'memory_critical_threshold': '90',
            'quiet_hours_enabled': 'false',
            'quiet_hours_start': '',
            'quiet_hours_end': '',
            'deleted_device_retention_days': '7'
        }
        for key, value in additional_defaults.items():
            cursor.execute("INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)", (key, value))
        sync_ping_interval_alias(conn)
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
    
    if not g.user_exists and request.endpoint not in ['register', 'static', 'bootstrap_import']:
        return redirect(url_for('register'))

SENSITIVE_LOG_PATTERNS = [
    re.compile(
        r"(?i)(\b(?:password|passwd|pwd|secret|token|api[_-]?key|encryption[_-]?key|private[_-]?key|"
        r"snmp[_-]?community|snmp[_-]?v3[_-]?(?:auth|priv)[_-]?password|ftp[_-]?password|totp|recovery[_-]?code|backup[_-]?code)\b"
        r"[\"']?\s*[:=]\s*)([\"'])[^\r\n]*?\2"
    ),
    re.compile(
        r"(?i)(\b(?:password|passwd|pwd|secret|token|api[_-]?key|encryption[_-]?key|private[_-]?key|"
        r"snmp[_-]?community|snmp[_-]?v3[_-]?(?:auth|priv)[_-]?password|ftp[_-]?password|totp|recovery[_-]?code|backup[_-]?code)\b"
        r"[\"']?\s*[:=]\s*)(?![\"'])[^\s,;}&]+"
    ),
    re.compile(r"(?i)(ftp|sftp|http|https)://([^:\s/@]+):([^@\s/]+)@"),
    re.compile(r"(?i)(\bauthorization\s*:\s*(?:basic|bearer)\s+)[^\s,;]+"),
]


def sanitize_log_message(message):
    """Mask likely secrets before writing to persistent logs or sockets."""
    if message is None:
        return ''

    sanitized = str(message)
    for pattern in SENSITIVE_LOG_PATTERNS:
        if pattern.groups == 3:
            sanitized = pattern.sub(lambda m: f"{m.group(1)}://{m.group(2)}:[REDACTED]@", sanitized)
        elif pattern.groups == 2:
            sanitized = pattern.sub(lambda m: f"{m.group(1)}{m.group(2)}[REDACTED]{m.group(2)}", sanitized)
        else:
            sanitized = pattern.sub(lambda m: f"{m.group(1)}[REDACTED]", sanitized)
    return sanitized


def safe_ftp_error(error):
    """Return useful FTP diagnostics without logging server-controlled text."""
    if isinstance(error, error_perm):
        return "FTP server odmietol operáciu."
    if isinstance(error, socket.gaierror):
        return "FTP server sa nepodarilo nájsť cez DNS."
    if isinstance(error, (TimeoutError, socket.timeout)):
        return "FTP server neodpovedal v časovom limite."
    if isinstance(error, ConnectionRefusedError):
        return "FTP server odmietol spojenie."
    if isinstance(error, OSError):
        return "FTP sieťová operácia zlyhala."
    return "FTP operácia zlyhala."


def add_log(level, message, device_ip=None):
    level_map = {'INFO': logging.INFO, 'SUCCESS': logging.INFO, 'WARNING': logging.WARNING, 'ERROR': logging.ERROR, 'DEBUG': logging.DEBUG}
    log_level_int = level_map.get(level.upper(), logging.INFO)
    safe_message = sanitize_log_message(message)
    logger.log(log_level_int, f"{f'[{device_ip}] ' if device_ip else ''}{safe_message}")
    
    # Pokus o zápis do databázy a WebSocket
    try:
        with get_db_connection() as conn:
            # Vkladáme časovú značku priamo z aplikácie
            conn.execute("INSERT INTO logs (timestamp, level, message, device_ip) VALUES (?, ?, ?, ?)", (datetime.now(), level, safe_message, device_ip))
            conn.commit()
        
        # WebSocket emit s kontrolou pripojenia
        try:
            socketio.emit('log_update', {'level': level, 'message': safe_message, 'device_ip': device_ip, 'timestamp': datetime.now().isoformat()})
        except Exception as ws_error:
            logger.warning(f"WebSocket emit pre log zlyhal: {ws_error}")
            
    except Exception as e:
        logger.error(f"Nepodarilo sa zapísať log do databázy: {e}")
        # Aj pri chybe sa pokúsime odoslať cez WebSocket
        try:
            socketio.emit('log_update', {'level': 'error', 'message': f'Chyba pri zápise logu: {safe_message}', 'device_ip': device_ip, 'timestamp': datetime.now().isoformat()})
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


class SSHHostKeyVerificationRequired(paramiko.SSHException):
    """SSH server identity must be explicitly approved before authentication."""


def ssh_host_key_fingerprint(key):
    """Return the OpenSSH-style SHA-256 fingerprint for a Paramiko public key."""
    digest = hashlib.sha256(key.asbytes()).digest()
    return f"SHA256:{base64.b64encode(digest).decode('ascii').rstrip('=')}"


def _ssh_host_key_details(key):
    return key.get_name(), key.get_base64(), ssh_host_key_fingerprint(key)


def get_ssh_host_key_state(device_id, device_ip=None):
    """Return public SSH trust metadata without exposing the stored key material."""
    with get_db_connection() as conn:
        row = conn.execute(
            '''SELECT trusted_host, trusted_key_type, trusted_fingerprint, trusted_at,
                      pending_key_type, pending_fingerprint, pending_detected_at
               FROM ssh_host_keys WHERE device_id = ?''',
            (device_id,)
        ).fetchone()

    if not row:
        return {'status': 'unverified'}

    state = dict(row)
    trusted_for_host = bool(state.get('trusted_fingerprint')) and (
        device_ip is None or state.get('trusted_host') == device_ip
    )
    if state.get('pending_fingerprint'):
        state['status'] = 'changed' if trusted_for_host else 'pending'
    elif trusted_for_host:
        state['status'] = 'trusted'
    else:
        state['status'] = 'unverified'
    state.pop('trusted_host', None)
    return state


def remember_pending_ssh_host_key(device_id, expected_ip, key):
    """Persist an untrusted key and return whether it already matches the trusted pin."""
    key_type, key_data, fingerprint = _ssh_host_key_details(key)
    now = datetime.now(timezone.utc).isoformat()

    with get_db_connection() as conn:
        device = conn.execute(
            'SELECT id, name, ip FROM devices WHERE id = ? AND deleted_at IS NULL',
            (device_id,)
        ).fetchone()
        if not device or device['ip'] != expected_ip:
            raise SSHHostKeyVerificationRequired('Zariadenie alebo jeho IP adresa sa počas SSH overovania zmenili.')

        existing = conn.execute(
            'SELECT * FROM ssh_host_keys WHERE device_id = ?',
            (device_id,)
        ).fetchone()
        existing = dict(existing) if existing else {}
        trusted = (
            existing.get('trusted_host') == expected_ip
            and existing.get('trusted_key_type') == key_type
            and existing.get('trusted_key_data')
            and secrets.compare_digest(existing['trusted_key_data'], key_data)
        )
        if trusted:
            if existing.get('pending_fingerprint'):
                conn.execute(
                    '''UPDATE ssh_host_keys
                       SET pending_key_type = NULL, pending_key_data = NULL,
                           pending_fingerprint = NULL, pending_detected_at = NULL,
                           notified_pending_fingerprint = NULL
                       WHERE device_id = ?''',
                    (device_id,)
                )
                conn.commit()
            return {'trusted': True, 'fingerprint': fingerprint, 'new_pending': False}

        same_pending = (
            existing.get('pending_key_type') == key_type
            and existing.get('pending_key_data')
            and secrets.compare_digest(existing['pending_key_data'], key_data)
        )
        if not same_pending:
            conn.execute(
                '''INSERT INTO ssh_host_keys (
                       device_id, pending_key_type, pending_key_data,
                       pending_fingerprint, pending_detected_at,
                       notified_pending_fingerprint
                   ) VALUES (?, ?, ?, ?, ?, NULL)
                   ON CONFLICT(device_id) DO UPDATE SET
                       pending_key_type = excluded.pending_key_type,
                       pending_key_data = excluded.pending_key_data,
                       pending_fingerprint = excluded.pending_fingerprint,
                       pending_detected_at = excluded.pending_detected_at,
                       notified_pending_fingerprint = NULL''',
                (device_id, key_type, key_data, fingerprint, now)
            )
            conn.commit()

        return {
            'trusted': False,
            'fingerprint': fingerprint,
            'new_pending': not same_pending,
            'already_notified': existing.get('notified_pending_fingerprint') == fingerprint,
            'changed': bool(existing.get('trusted_fingerprint')),
            'device_name': device['name'],
            'device_ip': device['ip']
        }


def notify_pending_ssh_host_key(observation):
    """Send one Pushover alert per observed pending fingerprint."""
    if observation.get('trusted') or observation.get('already_notified'):
        return

    change_text = 'zmenil sa' if observation.get('changed') else 'zatiaľ nie je potvrdený'
    sent = send_pushover_notification(
        f"🛡️ SSH kľúč zariadenia {observation['device_name']} "
        f"({observation['device_ip']}) {change_text}.\n"
        f"Fingerprint: {observation['fingerprint']}\n"
        "Záloha je zablokovaná, kým kľúč nepotvrdíte v aplikácii.",
        title='MikroTik Manager - potvrdenie SSH kľúča',
        notification_key='notify_ssh_host_key_change',
        ignore_quiet_hours=True
    )
    if not sent:
        return

    with get_db_connection() as conn:
        conn.execute(
            '''UPDATE ssh_host_keys SET notified_pending_fingerprint = ?
               WHERE device_id = ? AND pending_fingerprint = ?''',
            (observation['fingerprint'], observation['device_id'], observation['fingerprint'])
        )
        conn.commit()


class PinnedSSHHostKeyPolicy(paramiko.MissingHostKeyPolicy):
    """Allow only the exact SSH key explicitly trusted for this device."""

    def __init__(self, device_id, device_ip):
        self.device_id = device_id
        self.device_ip = device_ip

    def missing_host_key(self, client, hostname, key):
        observation = remember_pending_ssh_host_key(self.device_id, self.device_ip, key)
        observation['device_id'] = self.device_id
        if observation['trusted']:
            return

        notify_pending_ssh_host_key(observation)
        socketio.emit('ssh_host_key_status', {
            'id': self.device_id,
            'ip': self.device_ip,
            'status': 'changed' if observation.get('changed') else 'pending'
        })
        raise SSHHostKeyVerificationRequired(
            f"SSH fingerprint {observation['fingerprint']} vyžaduje potvrdenie v aplikácii."
        )


def probe_ssh_host_key(ip, timeout=10):
    """Read the SSH server key without sending device credentials."""
    sock = None
    transport = None
    try:
        sock = socket.create_connection((ip, 22), timeout=timeout)
        transport = paramiko.Transport(sock)
        transport.banner_timeout = timeout
        transport.start_client(timeout=timeout)
        key = transport.get_remote_server_key()
        if key is None:
            raise paramiko.SSHException('SSH server neposkytol host key.')
        return key
    finally:
        if transport is not None:
            transport.close()
        elif sock is not None:
            sock.close()


def ssh_probe_failure_message(ip, error):
    """Return an actionable, user-facing explanation for an SSH probe failure."""
    detail = str(error).strip() or error.__class__.__name__
    return (
        f"Nepodarilo sa pripojiť k SSH službe na {ip}:22. "
        "Skontrolujte, či je na MikroTiku povolená služba SSH, používa port 22 "
        f"a spojenie neblokuje firewall. Detail: {detail}"
    )


def trust_initial_ssh_host_key(device_id, expected_ip, key):
    """Pin the first SSH host key as part of an authenticated device creation."""
    key_type, key_data, fingerprint = _ssh_host_key_details(key)
    trusted_at = datetime.now(timezone.utc).isoformat()

    with get_db_connection() as conn:
        device = conn.execute(
            'SELECT id, ip FROM devices WHERE id = ? AND deleted_at IS NULL',
            (device_id,)
        ).fetchone()
        if not device or device['ip'] != expected_ip:
            raise SSHHostKeyVerificationRequired(
                'Zariadenie alebo jeho IP adresa sa počas SSH overovania zmenili.'
            )

        # This path is intentionally valid only for a newly created device. Never
        # replace an existing pin here; later key/IP changes require manual approval.
        existing = conn.execute(
            'SELECT 1 FROM ssh_host_keys WHERE device_id = ?',
            (device_id,)
        ).fetchone()
        if existing:
            raise SSHHostKeyVerificationRequired(
                'SSH identita zariadenia už bola zaznamenaná a vyžaduje štandardné overenie.'
            )

        conn.execute(
            '''INSERT INTO ssh_host_keys (
                   device_id, trusted_host, trusted_key_type, trusted_key_data,
                   trusted_fingerprint, trusted_at
               ) VALUES (?, ?, ?, ?, ?, ?)''',
            (device_id, expected_ip, key_type, key_data, fingerprint, trusted_at)
        )
        conn.commit()

    return fingerprint


BACKUP_COMPARE_MAX_BYTES = 16 * 1024 * 1024
BACKUP_COMPARE_MAX_LINES = 200000
BACKUP_COMPARE_MAX_ROWS = 10000
BACKUP_COMPARE_CONTEXTS = {3, 10, 25}
BACKUP_COMPARE_MODES = {'normalized', 'exact'}
BACKUP_DIFF_IGNORE_KEYWORDS = (
    'list=blacklist',
    'comment=spamhaus,dshield,bruteforce',
)
ROUTEROS_EXPORT_TIMESTAMP_RE = re.compile(
    r'^(#\s*)\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}(\s+by\s+RouterOS\b.*)$'
)


def normalize_routeros_export(content, mode='normalized'):
    """Return (source line number, comparable text) records for an export.

    ``legacy`` intentionally preserves the historical backup-skip behaviour:
    every comment line is ignored. The UI's ``normalized`` mode only masks the
    volatile timestamp so a RouterOS version change in the same header remains
    visible. Both normalized modes keep the existing blacklist noise filters.
    """
    if mode not in {'legacy', 'normalized', 'exact'}:
        raise ValueError('Neplatný režim porovnania.')

    records = []
    skip_indented = False
    for line_number, raw_line in enumerate(content.splitlines(), start=1):
        stripped = raw_line.strip()

        if mode == 'exact':
            records.append((line_number, raw_line))
            continue

        if mode == 'legacy' and stripped.startswith('#'):
            continue

        if skip_indented:
            if not stripped or raw_line[:1].isspace():
                if not raw_line.rstrip().endswith('\\'):
                    skip_indented = False
                continue
            skip_indented = False

        if any(keyword in raw_line for keyword in BACKUP_DIFF_IGNORE_KEYWORDS):
            skip_indented = raw_line.rstrip().endswith('\\')
            continue

        comparable_line = raw_line
        if mode == 'normalized':
            timestamp_match = ROUTEROS_EXPORT_TIMESTAMP_RE.match(raw_line)
            if timestamp_match:
                comparable_line = (
                    f'{timestamp_match.group(1)}<timestamp ignored>'
                    f'{timestamp_match.group(2)}'
                )
        records.append((line_number, comparable_line))

    return records


def compare_with_local_backup(ip, remote_content, detailed_logging=True):
    try:
        # Hľadáme najnovší .rsc súbor pre dané IP s presným patternom _ip_
        import re
        pattern = re.compile(f"_{ip}_\d{{8}}")
        local_backups = sorted(
            [f for f in os.listdir(BACKUP_DIR) if pattern.search(f) and f.endswith('.rsc')],
            key=_backup_sort_key, reverse=True
        )
        if not local_backups:
            if detailed_logging:
                add_log('info', "Žiadna lokálna záloha nájdená. Vytváram novú.", ip)
            return True
        
        latest_backup_path = os.path.join(BACKUP_DIR, local_backups[0])
        with open(latest_backup_path, 'r', encoding='utf-8', errors='ignore') as f:
            local_content = f.read()
        
        # Zachovaj presne pôvodné pravidlá rozhodovania o novej zálohe.
        local_lines = [line for _, line in normalize_routeros_export(local_content, mode='legacy')]
        remote_lines = [line for _, line in normalize_routeros_export(remote_content, mode='legacy')]
        
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


def _is_manager_remote_backup(filename, ip):
    """Match only backup artifacts created by this application."""
    basename = str(filename).rsplit('/', 1)[-1]
    return bool(re.fullmatch(
        rf'.*_{re.escape(str(ip))}_\d{{8}}-\d{{4}}(?:\d{{2}})?\.backup',
        basename,
    ))


def _cleanup_manager_remote_backups(sftp, ip, keep_path=None):
    """Remove app-owned remote binary backups without touching user files."""
    removed = []
    normalized_keep = str(keep_path or '').lstrip('/')
    for directory in ('.', 'flash'):
        try:
            names = sftp.listdir(directory)
        except (IOError, OSError):
            continue
        for name in names:
            remote_path = name if directory == '.' else f'{directory}/{name}'
            if remote_path.lstrip('/') == normalized_keep or not _is_manager_remote_backup(name, ip):
                continue
            try:
                sftp.remove(remote_path)
                removed.append(remote_path)
            except (IOError, OSError):
                # A disappearing file is harmless; a still-present one will make
                # the following backup command fail with a useful RouterOS error.
                pass
    return removed


def _wait_for_remote_file(sftp, remote_path, timeout_seconds, poll_seconds=2):
    """Wait until a remote file exists, is non-empty and has a stable size."""
    deadline = time.monotonic() + timeout_seconds
    previous_size = None
    stable_observations = 0
    while time.monotonic() < deadline:
        try:
            size = int(sftp.stat(remote_path).st_size)
        except (IOError, OSError):
            size = 0
        if size > 0 and size == previous_size:
            stable_observations += 1
            if stable_observations >= 2:
                return size
        else:
            stable_observations = 0
        previous_size = size
        time.sleep(poll_seconds)
    raise TimeoutError(f'Vzdialený súbor {remote_path} nebol dokončený do {timeout_seconds} s.')


def _write_text_atomic(path, content):
    partial_path = f'{path}.part'
    try:
        with open(partial_path, 'w', encoding='utf-8', newline='') as output:
            output.write(content)
            output.flush()
            os.fsync(output.fileno())
        if os.path.getsize(partial_path) <= 0:
            raise ValueError('Lokálny export je prázdny.')
        os.replace(partial_path, path)
    except Exception:
        try:
            os.remove(partial_path)
        except FileNotFoundError:
            pass
        raise


def _backup_sort_key(filename):
    """Order backups by their embedded creation timestamp, not by raw name.

    A device rename changes the filename prefix; plain lexical sorting would
    then treat a freshly created backup as the oldest one and retention would
    purge it instead of the genuinely oldest files.
    """
    match = re.search(r'_(\d{8}-\d{4}(?:\d{2})?)\.', str(filename))
    return (match.group(1) if match else '', str(filename))

def run_backup_logic(device, is_sequential=False, result_holder=None):
    """Vykoná zálohu daného zariadenia s pokročilým logovaním a kontrolou."""
    backup_performed = False  # či sme vytvorili novú zálohu a ťahali ju z routera
    ftp_upload_success = False  # kumulatívny výsledok oboch uploadov na FTP
    ftp_upload_error = None

    def update_results():
        if result_holder is not None:
            result_holder['backup_performed'] = backup_performed
            result_holder['ftp_uploaded'] = ftp_upload_success
            result_holder['ftp_upload_error'] = ftp_upload_error

    # Decrypt device password before use
    device = get_device_with_decrypted_password(device)
    ip, username, password, low_memory = device['ip'], device['username'], device['password'], device['low_memory']
    
    # Načítame nastavenie pre detailné logovanie
    with get_db_connection() as conn:
        settings = {row['key']: row['value'] for row in conn.execute('SELECT key, value FROM settings').fetchall()}
    
    detailed_logging = settings.get('backup_detailed_logging', 'false').lower() == 'true'

    # Zistíme názov zariadenia (pre logy + notifikácie)
    device_name = device.get('name')
    if not device_name:
        try:
            with get_db_connection() as conn:
                row = conn.execute('SELECT name FROM devices WHERE ip = ? AND deleted_at IS NULL', (ip,)).fetchone()
                if row:
                    device_name = row['name']
        except Exception:
            device_name = None
    name_suffix = f" ({device_name})" if device_name else ""
    
    # Základná správa o spustení zálohy (zjednotená pre konzistentnosť)
    # Vždy komunikujeme, že ide o pokročilú zálohu; pri sekvenčnej doplníme info a pri low-memory režime upozorníme na dlhšie časy
    # Neuvádzame IP priamo v texte (frontend ju má už v hlavičke logu)
    prefix = "Záloha - " if is_sequential else ""
    if low_memory:
        add_log('info', f"{prefix}Spúšťam zálohu{name_suffix} pre 16MB zariadenie (predĺžené časy)", ip)
        if detailed_logging:
            add_log('info', "Režim 16MB: predĺžené čakacie intervaly (backup ~30s, export ~180s).", ip)
    else:
        add_log('info', f"{prefix}Spúšťam zálohu{name_suffix}", ip)
    
    socketio.emit('backup_status', {'ip': ip, 'id': device['id'], 'status': 'starting'})
    client = None
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(PinnedSSHHostKeyPolicy(device['id'], ip))
        client.connect(
            ip,
            username=username,
            password=password,
            timeout=30,
            banner_timeout=30,
            auth_timeout=30
        )
        
        if detailed_logging:
            add_log('info', "SSH pripojenie úspešne.", ip)
        
        remote_config = get_mikrotik_export_direct(client, ip, detailed_logging)
        if remote_config is None:
            raise Exception("Nepodarilo sa získať konfiguráciu na porovnanie.")
        if not compare_with_local_backup(ip, remote_config, detailed_logging):
            # Aj pri nezmenenej konfigurácii doplníme zálohy, ktoré lokálne vznikli
            # počas nedostupnosti FTP. Ide len o výpis názvov a upload chýbajúcich súborov.
            ftp_sync = sync_missing_backups_to_ftp(ip, settings)
            ftp_upload_success = ftp_sync['success']
            ftp_upload_error = '; '.join(ftp_sync['errors']) or None
            if ftp_sync['uploaded']:
                add_log('info', f"FTP synchronizácia doplnila {ftp_sync['uploaded']} starších záloh.", ip)
            elif ftp_sync['errors'] and detailed_logging:
                add_log('warning', f"FTP synchronizácia záloh neprebehla: {ftp_upload_error}", ip)
            # Záverečná správa o preskočení zálohy
            if is_sequential:
                add_log('info', f"Záloha - preskočená{name_suffix} (žiadne zmeny){' (16MB)' if low_memory else ''}", ip)
            else:
                add_log('info', f"Záloha preskočená{name_suffix} (žiadne zmeny){' (16MB)' if low_memory else ''}", ip)
            socketio.emit('backup_status', {'ip': ip, 'id': device['id'], 'status': 'skipped'})
            if result_holder is not None:
                result_holder['status'] = 'skipped'
            update_results()
            return
        device_display_name = str(device.get('name') or '').strip() or ip
        safe_identity = device_display_name.replace(' - ', '_')            # " - " → "_" (inak by vzniklo _-_)
        safe_identity = re.sub(r'[^a-zA-Z0-9_-]', '_', safe_identity)     # ostatné znaky (pôvodná logika)
        _, stdout, _ = client.exec_command('/file print where type=directory')
        has_flash = 'flash' in stdout.read().decode()
        
        if detailed_logging:
            add_log('info', f"Zariadenie {'má' if has_flash else 'nemá'} /flash adresár.", ip)
        date_str = datetime.now().strftime("%Y%m%d-%H%M")
        base_filename = f"{safe_identity}_{ip}_{date_str}"
        backup_path = f"flash/{base_filename}.backup" if has_flash else f"{base_filename}.backup"
        local_backup_path = os.path.join(BACKUP_DIR, f"{base_filename}.backup")
        local_export_path = os.path.join(BACKUP_DIR, f"{base_filename}.rsc")
        local_backup_partial = f'{local_backup_path}.part'

        with client.open_sftp() as sftp:
            if low_memory:
                removed = _cleanup_manager_remote_backups(sftp, ip)
                if detailed_logging:
                    add_log(
                        'info',
                        f"16 MB režim: pred vytvorením novej zálohy odstránené staré aplikačné backupy: {len(removed)}.",
                        ip,
                    )
            elif detailed_logging:
                add_log(
                    'info',
                    'Existujúci vzdialený backup zostáva zachovaný až do overenia nového.',
                    ip,
                )
            if detailed_logging:
                add_log('info', f"Vytváram binárny backup {base_filename}.backup; .rsc zostane iba v aplikácii.", ip)

            try:
                _, stdout, stderr = client.exec_command(
                    f'/system backup save name="{backup_path}" dont-encrypt=yes'
                )
                command_output = stdout.read().decode('utf-8', errors='ignore').strip()
                command_error = stderr.read().decode('utf-8', errors='ignore').strip()
                if command_error:
                    raise RuntimeError(command_error)

                expected_size = _wait_for_remote_file(
                    sftp, backup_path, 240 if low_memory else 120
                )
                sftp.get(backup_path, local_backup_partial)
                downloaded_size = os.path.getsize(local_backup_partial)
                if downloaded_size <= 0 or downloaded_size != expected_size:
                    raise IOError(
                        f'Neúplný binárny backup: lokálne {downloaded_size} B, vzdialene {expected_size} B.'
                    )

                final_export = get_mikrotik_export_direct(client, ip, detailed_logging)
                if final_export is None:
                    raise RuntimeError('Nepodarilo sa získať finálny textový export.')
                _write_text_atomic(local_export_path, final_export)
                os.replace(local_backup_partial, local_backup_path)

                # Bežnému zariadeniu ponecháme posledný binárny backup aj lokálne
                # na routeri. Iba 16 MB zariadenia ho po overenom stiahnutí odstránia,
                # pretože potrebujú okamžite uvoľniť obmedzenú flash.
                if low_memory:
                    try:
                        sftp.remove(backup_path)
                    except (IOError, OSError) as cleanup_error:
                        add_log(
                            'warning',
                            f'Lokálna záloha je overená, ale dočasný backup na 16 MB zariadení sa nepodarilo odstrániť: {cleanup_error}',
                            ip,
                        )
                else:
                    # Nový backup už existuje lokálne aj na routeri. Teraz môžeme
                    # bezpečne odstrániť staršie aplikačné backupy a ponechať nový.
                    removed = _cleanup_manager_remote_backups(
                        sftp, ip, keep_path=backup_path
                    )
                    if detailed_logging:
                        add_log(
                            'info',
                            f'Staršie vzdialené aplikačné backupy odstránené po overení nového: {len(removed)}.',
                            ip,
                        )
                if detailed_logging:
                    detail = f" ({command_output})" if command_output else ''
                    remote_state = (
                        'Vzdialený backup bol kvôli 16 MB flash odstránený.'
                        if low_memory else 'Posledný binárny backup zostal aj na zariadení.'
                    )
                    add_log('info', f"Backup aj priamy export boli overené a uložené lokálne{detail} {remote_state}", ip)
            except Exception:
                for partial_path in (
                    local_backup_partial, f'{local_export_path}.part',
                    local_backup_path, local_export_path,
                ):
                    try:
                        os.remove(partial_path)
                    except FileNotFoundError:
                        pass
                try:
                    sftp.remove(backup_path)
                except (IOError, OSError):
                    pass
                raise
        backup_performed = True
        with get_db_connection() as conn:
            conn.execute("UPDATE devices SET last_backup = CURRENT_TIMESTAMP WHERE id = ? AND deleted_at IS NULL", (device['id'],))
            conn.commit()
        
        # Záverečná správa o dokončení zálohy
        if is_sequential:
            add_log('info', f"Lokálna záloha - dokončená{name_suffix} úspešne{' (16MB)' if low_memory else ''}", ip)
        else:
            add_log('info', f"Lokálna záloha dokončená{name_suffix}{' (16MB)' if low_memory else ''}.", ip)
        
        # Odoslanie notifikácie o úspešnej zálohe
        with get_db_connection() as conn:
            settings = {row['key']: row['value'] for row in conn.execute('SELECT key, value FROM settings').fetchall()}
        if settings.get('notify_backup_success', 'false').lower() == 'true':
            device_name = device.get('name', ip)
            send_pushover_notification(
                f"💾 Záloha MikroTik {ip} ({device_name}) bola úspešne dokončená.",
                title="Úspešná záloha",
                notification_key='notify_backup_success'
            )

        socketio.emit('backup_status', {'ip': ip, 'id': device['id'], 'status': 'success', 'last_backup': datetime.now(timezone.utc).isoformat()})
        if result_holder is not None:
            result_holder['status'] = 'success'
        # Jeden FTP prístup porovná lokálne a vzdialené názvy a prenesie iba chýbajúce
        # súbory vrátane prípadných starších záloh po predchádzajúcom výpadku FTP.
        ftp_sync = sync_missing_backups_to_ftp(ip, settings)
        ftp_upload_success = ftp_sync['success']
        if not ftp_upload_success:
            # Pushover upozornenie na zlyhanie uploadu (aj pri hromadných zálohách)
            try:
                error_details = '; '.join(ftp_sync['errors'])
                error_details = error_details or 'neznáma chyba'
                ftp_upload_error = error_details
                if settings.get('notify_backup_failure', 'false').lower() == 'true':
                    send_pushover_notification(
                        f"❌ FTP upload zálohy zlyhal pre {ip}{name_suffix}: {error_details}",
                        title="Zlyhaný FTP upload",
                        notification_key='notify_backup_failure'
                    )
            except Exception as e_push:
                add_log('error', f"Pushover notifikácia pre zlyhaný FTP upload zlyhala: {e_push}", ip)
        if not is_sequential and ftp_upload_success:
            if ftp_sync['uploaded']:
                add_log('info', f"Záloha{name_suffix} nahratá na FTP server; doplnených súborov: {ftp_sync['uploaded']}.", ip)
            elif detailed_logging:
                add_log('info', f"FTP server už obsahuje všetky lokálne zálohy{name_suffix}.", ip)

        # Lokálne súbory nemažeme, kým FTP nie je úplne zosynchronizované.
        if ftp_upload_success or not ftp_sync['configured']:
            cleanup_old_backups(ip, settings, detailed_logging)
        else:
            add_log('warning', "Čistenie starých záloh preskočené, aby sa zachovali súbory čakajúce na FTP synchronizáciu.", ip)

    except Exception as e:
        host_key_blocked = isinstance(e, SSHHostKeyVerificationRequired)
        add_log('error', f"Chyba pri zálohe: {e}", ip)
        socketio.emit('backup_status', {'ip': ip, 'id': device['id'], 'status': 'error', 'message': str(e)})
        if result_holder is not None:
            result_holder['status'] = 'error'
        
        # Odoslanie notifikácie o neúspechu zálohy
        try:
            with get_db_connection() as conn:
                settings_fail = {row['key']: row['value'] for row in conn.execute('SELECT key, value FROM settings').fetchall()}
            if not host_key_blocked and settings_fail.get('notify_backup_failure', 'false').lower() == 'true':
                device_name = device.get('name', ip)
                send_pushover_notification(
                    f"❌ Záloha MikroTik {ip} ({device_name}) zlyhala: {e}",
                    title="Zlyhaná záloha",
                    notification_key='notify_backup_failure'
                )
        except Exception as notif_e:
            add_log('error', f"Notifikácia o zlyhaní zálohy sa nepodarila: {notif_e}", ip)
    finally:
        update_results()
        if client: client.close()
        if ip in backup_tasks: del backup_tasks[ip]

def cleanup_old_backups(device_ip, settings, detailed_logging=True):
    """Vyčistí staré zálohy lokálne a na FTP serveri na základe nastavenia."""
    try:
        settings = decrypt_sensitive_settings_map(settings)

        # Načítame počet uchovávaných záloh z nastavení, predvolená hodnota je 10
        retention_count = int(settings.get('backup_retention_count', 10))
        if detailed_logging:
            add_log('info', f"Spúšťam čistenie starých záloh, ponechávam posledných {retention_count}.", device_ip)

        # Lokálne čistenie
        file_pattern = f"_{device_ip}_"
        local_files = sorted([f for f in os.listdir(BACKUP_DIR) if file_pattern in f], key=_backup_sort_key)
        
        # Keďže máme .backup a .rsc, počet súborov je dvojnásobný
        if len(local_files) > retention_count * 2:
            files_to_delete = local_files[:-retention_count * 2]
            for f_del in files_to_delete:
                os.remove(os.path.join(BACKUP_DIR, f_del))
                if detailed_logging:
                    add_log('info', f"Lokálna záloha zmazaná: {f_del}", device_ip)

        # FTP čistenie
        if all(k in settings and settings[k] for k in ['ftp_server', 'ftp_username', 'ftp_password']):
            try:
                ftp_port = int(settings.get('ftp_port', 21))
            except (TypeError, ValueError):
                ftp_port = 21
            try:
                ftp_timeout = int(settings.get('ftp_timeout_seconds', 15))
            except (TypeError, ValueError):
                ftp_timeout = 15
            if not 5 <= ftp_timeout <= 120:
                ftp_timeout = 15
            with FTP(timeout=ftp_timeout) as ftp:
                ftp.connect(settings['ftp_server'], ftp_port, timeout=ftp_timeout)
                ftp.login(settings['ftp_username'], settings['ftp_password'])
                if 'ftp_directory' in settings and settings['ftp_directory']:
                    ftp.cwd(settings['ftp_directory'])
                
                ftp_files = sorted([f for f in ftp.nlst() if file_pattern in f], key=_backup_sort_key)
                if len(ftp_files) > retention_count * 2:
                    files_to_delete_ftp = ftp_files[:-retention_count * 2]
                    for f_del in files_to_delete_ftp:
                        try:
                            ftp.delete(f_del)
                            if detailed_logging:
                                add_log('info', f"FTP záloha zmazaná: {f_del}", device_ip)
                        except Exception as e_ftp_del:
                            add_log('error', f"Nepodarilo sa zmazať FTP súbor {f_del}: {safe_ftp_error(e_ftp_del)}", device_ip)
    except Exception:
        add_log('error', f"Chyba pri čistení starých záloh pre {device_ip}.", device_ip)


def migrate_backups_for_ip_change(old_ip, new_ip, settings):
    """Premenuje zálohy po zmene IP, aby fungoval retention aj purge zariadenia."""
    old_marker = f"_{old_ip}_"
    new_marker = f"_{new_ip}_"
    result = {'local': 0, 'ftp': 0, 'skipped': 0, 'errors': []}

    try:
        for filename in os.listdir(BACKUP_DIR):
            if old_marker not in filename or not filename.endswith(ALLOWED_BACKUP_EXTENSIONS):
                continue
            try:
                # `new_ip` originates in the device-edit request.  Resolve both
                # paths through the same containment check used for backup downloads
                # so a malformed value cannot escape BACKUP_DIR.
                source_path = resolve_backup_file_path(filename)
                new_filename = filename.replace(old_marker, new_marker, 1)
                target_path = resolve_backup_file_path(new_filename)
            except ValueError as e:
                result['skipped'] += 1
                result['errors'].append(f"nepovolený názov lokálnej zálohy {filename}: {e}")
                continue
            if not os.path.isfile(source_path):
                continue
            if os.path.exists(target_path):
                result['skipped'] += 1
                result['errors'].append(f"lokálny súbor {new_filename} už existuje")
                continue
            os.rename(source_path, target_path)
            result['local'] += 1
    except Exception as e:
        result['errors'].append(f"lokálne zálohy: {e}")

    try:
        settings = decrypt_sensitive_settings_map(settings)
        if not all(settings.get(key) for key in ('ftp_server', 'ftp_username', 'ftp_password')):
            return result
        try:
            ftp_port = int(settings.get('ftp_port', 21))
        except (TypeError, ValueError):
            ftp_port = 21
        try:
            ftp_timeout = int(settings.get('ftp_timeout_seconds', 15))
        except (TypeError, ValueError):
            ftp_timeout = 15
        ftp_timeout = ftp_timeout if 5 <= ftp_timeout <= 120 else 15

        with FTP(timeout=ftp_timeout) as ftp:
            ftp.connect(settings['ftp_server'], ftp_port, timeout=ftp_timeout)
            ftp.login(settings['ftp_username'], settings['ftp_password'])
            if settings.get('ftp_directory'):
                ftp.cwd(settings['ftp_directory'])
            ftp_files = set(ftp.nlst())
            for filename in sorted(ftp_files):
                if old_marker not in filename or not filename.endswith(ALLOWED_BACKUP_EXTENSIONS):
                    continue
                new_filename = filename.replace(old_marker, new_marker, 1)
                if new_filename in ftp_files:
                    result['skipped'] += 1
                    result['errors'].append(f"FTP súbor {new_filename} už existuje")
                    continue
                ftp.rename(filename, new_filename)
                ftp_files.add(new_filename)
                result['ftp'] += 1
    except Exception as e:
        result['errors'].append(f"FTP zálohy: {safe_ftp_error(e)}")

    return result

SNMP_VERSIONS = {'2c', '3'}
SNMP_V3_SECURITY_LEVELS = {'authNoPriv', 'authPriv'}
SNMP_V3_AUTH_PROTOCOLS = {'SHA1', 'MD5'}
SNMP_V3_PRIV_PROTOCOLS = {'AES', 'DES'}


def validate_snmp_config(config, require_secrets=True):
    """Normalize and validate a per-device SNMP configuration."""
    config = dict(config or {})
    version = str(config.get('snmp_version') or '2c')
    normalized = {
        'snmp_version': version,
        'snmp_community': str(config.get('snmp_community') or ''),
        'snmp_v3_username': str(config.get('snmp_v3_username') or '').strip(),
        'snmp_v3_security_level': str(config.get('snmp_v3_security_level') or 'authPriv'),
        'snmp_v3_auth_protocol': str(config.get('snmp_v3_auth_protocol') or 'SHA1').upper(),
        'snmp_v3_auth_password': str(config.get('snmp_v3_auth_password') or ''),
        'snmp_v3_priv_protocol': str(config.get('snmp_v3_priv_protocol') or 'AES').upper(),
        'snmp_v3_priv_password': str(config.get('snmp_v3_priv_password') or ''),
        'snmp_allowed_address': str(config.get('snmp_allowed_address') or '').strip(),
    }
    if version not in SNMP_VERSIONS:
        return None, 'SNMP verzia musí byť 2c alebo 3.'
    if normalized['snmp_allowed_address']:
        try:
            ipaddress.ip_network(normalized['snmp_allowed_address'], strict=False)
        except ValueError:
            return None, 'Povolená SNMP adresa musí byť platná IP sieť v CIDR formáte.'
    if version == '2c':
        if require_secrets and not normalized['snmp_community']:
            return None, 'SNMPv2c community je povinná.'
        return normalized, None
    if not normalized['snmp_v3_username']:
        return None, 'SNMPv3 používateľské meno je povinné.'
    if normalized['snmp_v3_security_level'] not in SNMP_V3_SECURITY_LEVELS:
        return None, 'Nepodporovaná bezpečnostná úroveň SNMPv3.'
    if normalized['snmp_v3_auth_protocol'] not in SNMP_V3_AUTH_PROTOCOLS:
        return None, 'SNMPv3 autentifikácia musí byť SHA1 alebo MD5.'
    if require_secrets and len(normalized['snmp_v3_auth_password']) < 8:
        return None, 'SNMPv3 autentifikačné heslo musí mať aspoň 8 znakov.'
    if normalized['snmp_v3_security_level'] == 'authPriv':
        if normalized['snmp_v3_priv_protocol'] not in SNMP_V3_PRIV_PROTOCOLS:
            return None, 'SNMPv3 šifrovanie musí byť AES alebo DES.'
        if require_secrets and len(normalized['snmp_v3_priv_password']) < 8:
            return None, 'SNMPv3 šifrovacie heslo musí mať aspoň 8 znakov.'
    return normalized, None


def build_snmp_credentials(config):
    """Create the PySNMP authentication object for SNMPv2c or SNMPv3."""
    from pysnmp.hlapi.v3arch.asyncio import (
        CommunityData, UsmUserData, USM_AUTH_HMAC96_MD5,
        USM_AUTH_HMAC96_SHA, USM_PRIV_CBC56_DES, USM_PRIV_CFB128_AES,
    )
    normalized, error = validate_snmp_config(config, require_secrets=True)
    if error:
        raise ValueError(error)
    if normalized['snmp_version'] == '2c':
        return CommunityData(normalized['snmp_community'], mpModel=1)
    auth_protocol = {
        'MD5': USM_AUTH_HMAC96_MD5,
        'SHA1': USM_AUTH_HMAC96_SHA,
    }[normalized['snmp_v3_auth_protocol']]
    if normalized['snmp_v3_security_level'] == 'authNoPriv':
        return UsmUserData(
            normalized['snmp_v3_username'],
            authKey=normalized['snmp_v3_auth_password'],
            authProtocol=auth_protocol,
        )
    priv_protocol = {
        'DES': USM_PRIV_CBC56_DES,
        'AES': USM_PRIV_CFB128_AES,
    }[normalized['snmp_v3_priv_protocol']]
    return UsmUserData(
        normalized['snmp_v3_username'],
        authKey=normalized['snmp_v3_auth_password'],
        privKey=normalized['snmp_v3_priv_password'],
        authProtocol=auth_protocol,
        privProtocol=priv_protocol,
    )


def merge_device_snmp_config(data, existing=None, new_device=False):
    """Merge submitted SNMP fields with stored secrets and return validated config."""
    existing = get_device_with_decrypted_password(dict(existing)) if existing else {}
    # API callers that predate SNMPv3 keep the historical v2c behavior. The
    # current device form explicitly submits v3 for newly-created devices.
    version_default = '2c' if new_device else (existing.get('snmp_version') or '2c')
    merged = {}
    for field, default in (
        ('snmp_version', version_default),
        ('snmp_community', 'public' if new_device else ''),
        ('snmp_v3_username', 'mikrotik-manager'),
        ('snmp_v3_security_level', 'authPriv'),
        ('snmp_v3_auth_protocol', 'SHA1'),
        ('snmp_v3_auth_password', ''),
        ('snmp_v3_priv_protocol', 'AES'),
        ('snmp_v3_priv_password', ''),
        ('snmp_allowed_address', ''),
    ):
        submitted = data.get(field)
        if field in {'snmp_community', 'snmp_v3_auth_password', 'snmp_v3_priv_password'}:
            merged[field] = submitted if submitted not in (None, '') else existing.get(field, default)
        else:
            merged[field] = submitted if submitted is not None else existing.get(field, default)
    return validate_snmp_config(merged, require_secrets=True)


def encrypted_snmp_values(config):
    return {
        'snmp_community': encrypt_password(config['snmp_community']) if config['snmp_community'] else None,
        'snmp_v3_auth_password': encrypt_password(config['snmp_v3_auth_password']) if config['snmp_v3_auth_password'] else None,
        'snmp_v3_priv_password': encrypt_password(config['snmp_v3_priv_password']) if config['snmp_v3_priv_password'] else None,
    }


def get_snmp_data(ip, config=None, diagnostic=False):
    if isinstance(config, str):
        config = {'snmp_version': '2c', 'snmp_community': config}
    config = config or {'snmp_version': '2c', 'snmp_community': 'public'}
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
        import asyncio
        import socket
        from pysnmp.hlapi.v3arch.asyncio import (
            ContextData, ObjectIdentity, ObjectType, SnmpEngine,
            UdpTransportTarget, get_cmd, walk_cmd,
        )
        from datetime import timedelta
        
        HRPROCESSORLOAD_TABLE = '1.3.6.1.2.1.25.3.3.1.2'
        
        object_types = [ObjectType(ObjectIdentity(oid)) for oid in oids.values()]
        credentials = build_snmp_credentials(config)

        class SyncDnsUdpTransportTarget(UdpTransportTarget):
            """Resolve synchronously because this function owns a short-lived event loop."""

            async def _resolve_address(self, address):
                return socket.getaddrinfo(
                    address[0], address[1], family=socket.AF_INET,
                    type=socket.SOCK_DGRAM, proto=socket.IPPROTO_UDP,
                )[0][4][:2]

        async def snmp_get():
            snmp_engine = SnmpEngine()
            try:
                transport = await SyncDnsUdpTransportTarget.create(
                    (ip, 161), timeout=2, retries=1
                )
                return await get_cmd(
                    snmp_engine,
                    credentials,
                    transport,
                    ContextData(),
                    *object_types,
                )
            finally:
                snmp_engine.close_dispatcher()

        async def snmp_walk_cpu_load():
            snmp_engine = SnmpEngine()
            try:
                transport = await SyncDnsUdpTransportTarget.create(
                    (ip, 161), timeout=2, retries=1
                )
                rows = []
                async for response in walk_cmd(
                    snmp_engine,
                    credentials,
                    transport,
                    ContextData(),
                    ObjectType(ObjectIdentity(HRPROCESSORLOAD_TABLE)),
                    lexicographicMode=False,
                ):
                    rows.append(response)
                return rows
            finally:
                snmp_engine.close_dispatcher()

        def run_snmp_async(coroutine_factory):
            # Create the coroutine only after acquiring the lock. Otherwise a
            # rejected overlapping asyncio.run() would leak an un-awaited
            # coroutine and produce an additional RuntimeWarning.
            with snmp_asyncio_lock:
                return asyncio.run(coroutine_factory())
        
        # Jeden hromadný SNMPv2c (mpModel=1) dopyt pre všetky hodnoty naraz
        # Odstránená umelá pauza, prenos letí v 1 balíku
        errorIndication, errorStatus, errorIndex, varBinds = run_snmp_async(snmp_get)
        
        if errorIndication or errorStatus:
            diagnostic_error = str(errorIndication or errorStatus)
            # Handler pre offline zariadenie (alebo blokovaný SNMP)
            for name in oids.keys():
                results[name] = 'N/A'
            results['uptime_seconds'] = '0'
        else:
            for i, (name, oid) in enumerate(oids.items()):
                val = varBinds[i][1]
                val_str = str(val)
                # V SNMPv2c môže chýbajúce OID (napr. chýbajúci senzor teploty) vrátiť NoSuchInstance
                if 'NoSuch' in val_str or val_str == '':
                    results[name] = 'N/A'
                    if name == 'uptime':
                        results['uptime_seconds'] = '0'
                    continue
                
                try:
                    if name == 'uptime':
                        seconds = int(float(val) / 100.0)
                        td = timedelta(seconds=seconds)
                        results[name] = f"{td.days}d {td.seconds//3600}h {(td.seconds//60)%60}m"
                        results['uptime_seconds'] = str(seconds)
                    elif name == 'temperature': 
                        results[name] = str(int(int(val)/10.0))
                    elif name in ['used_memory', 'total_memory']:
                        mb_value = int(val) / 1024
                        results[name] = str(round(mb_value))
                    else: 
                        results[name] = str(val)
                except Exception:
                    results[name] = 'N/A'
                    if name == 'uptime':
                        results['uptime_seconds'] = '0'
        
        # Ak zariadenie odpovedalo (máme uptime), dopočítame CPU count a priemerný load zo štandardnej tabuľky hrProcessorLoad
        if results.get('uptime') and results.get('uptime') != 'N/A':
            try:
                core_loads = []
                core_count = 0
                for (errInd, errStat, _, varBinds) in run_snmp_async(snmp_walk_cpu_load):
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
            # Fallback estimation ak OIDy nefungujú - ale len pre online zariadenia
            if results.get('uptime') and results.get('uptime') != 'N/A':
                try:
                    total_mb = int(results.get('total_memory')) if results.get('total_memory') not in [None, 'N/A'] else 1024
                except (ValueError, TypeError):
                    total_mb = 1024
                try:
                    used_mb = int(results.get('used_memory')) if results.get('used_memory') not in [None, 'N/A'] else 569
                except (ValueError, TypeError):
                    used_mb = 569
                free_mb = max(total_mb - used_mb, 0)
                usage_percent = int((used_mb / total_mb) * 100) if total_mb else 0
                
                results['total_memory'] = str(total_mb)
                results['used_memory'] = str(used_mb)
                results['free_memory'] = str(free_mb)
                results['memory_usage'] = str(usage_percent)
            else:
                # Offline zariadenia - ponecháme N/A, aby sa nevytvárali falošné body
                results['total_memory'] = 'N/A'
                results['used_memory'] = 'N/A'
                results['free_memory'] = 'N/A'
                results['memory_usage'] = 'N/A'
        
        # Odstránime pomocné polia, ktoré nechceme zobrazovať
        for key in ['architecture']:
            if key in results: 
                del results[key]
        if 'uptime_seconds' not in results:
            results['uptime_seconds'] = '0'
        if diagnostic and 'diagnostic_error' in locals():
            results['_error'] = diagnostic_error
        return results
    except Exception as e:
        add_log('error', f"SNMP query for IP {ip} failed: {e}", device_ip=ip)
        fallback = {k: 'N/A' for k in ['identity','uptime','version','board_name','cpu_load','temperature','cpu_count','memory_usage','used_memory','total_memory','free_memory']}
        fallback['uptime_seconds'] = '0'
        if diagnostic:
            fallback['_error'] = str(e)
        return fallback

def sync_missing_backups_to_ftp(device_ip, settings):
    """Doplní na FTP iba lokálne zálohy daného zariadenia, ktoré tam chýbajú."""
    result = {'success': False, 'configured': False, 'uploaded': 0, 'errors': []}
    try:
        settings = decrypt_sensitive_settings_map(settings)
        if not all(settings.get(key) for key in ('ftp_server', 'ftp_username', 'ftp_password')):
            result['errors'].append('Chýbajú FTP nastavenia (server/používateľ/heslo).')
            return result
        result['configured'] = True

        marker = f"_{device_ip}_"
        local_files = sorted(
            filename for filename in os.listdir(BACKUP_DIR)
            if marker in filename
            and filename.endswith(ALLOWED_BACKUP_EXTENSIONS)
            and os.path.isfile(os.path.join(BACKUP_DIR, filename))
        )
        try:
            ftp_port = int(settings.get('ftp_port', 21))
        except (TypeError, ValueError):
            ftp_port = 21
        try:
            ftp_timeout = int(settings.get('ftp_timeout_seconds', 15))
        except (TypeError, ValueError):
            ftp_timeout = 15
        ftp_timeout = ftp_timeout if 5 <= ftp_timeout <= 120 else 15

        with FTP(timeout=ftp_timeout) as ftp:
            ftp.connect(settings['ftp_server'], ftp_port, timeout=ftp_timeout)
            ftp.login(settings['ftp_username'], settings['ftp_password'])
            if settings.get('ftp_directory'):
                ftp.cwd(settings['ftp_directory'])
            remote_files = set(ftp.nlst())
            for filename in local_files:
                if filename in remote_files:
                    continue
                with open(os.path.join(BACKUP_DIR, filename), 'rb') as backup_file:
                    ftp.storbinary(f'STOR {filename}', backup_file)
                remote_files.add(filename)
                result['uploaded'] += 1
        result['success'] = True
    except Exception as e:
        result['errors'].append(safe_ftp_error(e))
    return result


def upload_to_ftp(local_path, detailed_logging=True, device_ip=None, log_success_entries=True):
    def parse_int(value, default):
        try:
            return int(value)
        except (TypeError, ValueError):
            return default

    def attempt_upload(settings):
        try:
            server = settings.get('ftp_server')
            username = settings.get('ftp_username')
            password = settings.get('ftp_password')
            if not (server and username and password):
                return False, "Chýbajú FTP nastavenia (server/používateľ/heslo)."
            port = parse_int(settings.get('ftp_port'), 21)
            timeout = parse_int(settings.get('ftp_timeout_seconds'), 15)
            if not 5 <= timeout <= 120:
                timeout = 15
            with FTP(timeout=timeout) as ftp:
                ftp.connect(server, port, timeout=timeout)
                ftp.login(username, password)
                if settings.get('ftp_directory'):
                    ftp.cwd(settings['ftp_directory'])
                with open(local_path, 'rb') as f:
                    ftp.storbinary(f'STOR {os.path.basename(local_path)}', f)
            return True, None
        except Exception as e:
            return False, safe_ftp_error(e)

    with get_db_connection() as conn:
        settings = {row['key']: row['value'] for row in conn.execute('SELECT key, value FROM settings WHERE key LIKE \"ftp_%\"')}
    settings = decrypt_sensitive_settings_map(settings)

    success, error_msg = attempt_upload(settings)
    if success:
        if log_success_entries:
            add_log('info', f"Súbor {os.path.basename(local_path)} nahratý na FTP server.", device_ip)
        return True, None

    add_log('error', f"FTP upload zlyhal: {error_msg}", device_ip)
    return False, error_msg

def send_pushover_notification(
    message,
    title="MikroTik Manager",
    notification_key=None,
    default_enabled=True,
    log_message=True,
    ignore_quiet_hours=False
):
    try:
        queried_keys = ['pushover_app_key', 'pushover_user_key', 'quiet_hours_enabled', 'quiet_hours_start', 'quiet_hours_end']
        if notification_key:
            queried_keys.append(notification_key)
        with get_db_connection() as conn:
            cursor = conn.cursor()
            placeholders = ','.join('?' for _ in queried_keys)
            settings_rows = cursor.execute(f'SELECT key, value FROM settings WHERE key IN ({placeholders})', queried_keys).fetchall()
            settings = {row['key']: row['value'] for row in settings_rows}
            settings = decrypt_sensitive_settings_map(settings)
            
            enabled = True
            if notification_key:
                raw_value = settings.get(notification_key)
                if raw_value is None:
                    cursor.execute("INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)", (notification_key, 'true' if default_enabled else 'false'))
                    conn.commit()
                    enabled = default_enabled
                else:
                    enabled = raw_value.lower() == 'true'
                if not enabled:
                    debug_log('debug_notifications', f"Notification '{notification_key}' potlačená - vypnutá v nastaveniach.")
                    return False
            
            # Quiet hours support
            quiet_enabled = settings.get('quiet_hours_enabled', 'false').lower() == 'true'
            if quiet_enabled:
                start = settings.get('quiet_hours_start')
                end = settings.get('quiet_hours_end')
                if start and end:
                    try:
                        start_time = datetime.strptime(start, "%H:%M").time()
                        end_time = datetime.strptime(end, "%H:%M").time()
                        now_time = datetime.now().time()
                        in_quiet_hours = False
                        if start_time <= end_time:
                            in_quiet_hours = start_time <= now_time < end_time
                        else:
                            in_quiet_hours = now_time >= start_time or now_time < end_time
                        if in_quiet_hours and not ignore_quiet_hours:
                            debug_log('debug_notifications', f"Notification '{notification_key}' potlačená - quiet hours.")
                            return False
                    except Exception as time_e:
                        debug_log('debug_notifications', f"Quiet hours parsing error: {time_e}")
            
            app_key = settings.get('pushover_app_key')
            user_key = settings.get('pushover_user_key')
            if not app_key or not user_key:
                debug_log('debug_notifications', "Pushover notifikácia neodoslaná - chýba app key alebo user key.")
                return False
        
        conn_pushover = http.client.HTTPSConnection("api.pushover.net:443", timeout=15)
        conn_pushover.request(
            "POST",
            "/1/messages.json",
            urllib.parse.urlencode({"token": app_key, "user": user_key, "title": title, "message": message}),
            {"Content-type": "application/x-www-form-urlencoded"}
        )
        pushover_response = conn_pushover.getresponse()
        pushover_response.read()
        conn_pushover.close()
        if not 200 <= pushover_response.status < 300:
            raise RuntimeError(f"Pushover API vrátilo HTTP {pushover_response.status}")
        
        level_map = {
            'notify_device_offline': 'warning',
            'notify_backup_failure': 'error',
            'notify_failed_login': 'warning',
            'notify_failed_2fa': 'warning',
            'notify_password_recovery_failure': 'warning',
            'notify_ssh_host_key_change': 'warning'
        }
        log_level = level_map.get(notification_key, 'info')
        if log_message:
            add_log(log_level, f"Pushover notifikácia odoslaná: {message}")
        else:
            add_log(log_level, "Pushover notifikácia odoslaná (citlivý obsah skrytý).")
        return True
    except Exception as e:
        add_log('error', f"Odoslanie Pushover notifikácie zlyhalo: {e}")
        return False

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
                encrypted_totp_secret = encrypt_password(totp_secret)
                cursor = conn.cursor()
                cursor.execute('INSERT INTO users (username, password, totp_secret, totp_enabled) VALUES (?, ?, ?, ?)',
                             (username, password_hash, encrypted_totp_secret, 0))
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
            attempted_username = (username or '').strip() or '(prázdne meno)'
            source_ip = request.remote_addr or 'unknown'
            add_log('warning', f"Neúspešné prihlásenie do aplikácie. Používateľ: {attempted_username}, IP: {source_ip}")
            send_pushover_notification(
                f"🔐 Neúspešné prihlásenie do aplikácie. Používateľ: {attempted_username}, IP: {source_ip}",
                title="MikroTik Manager - Security",
                notification_key='notify_failed_login'
            )
            error = 'Neplatné meno alebo heslo.'
            time.sleep(1)
    return render_template('login.html', error=error)

@app.route('/password-recovery', methods=['GET', 'POST'])
def password_recovery():
    if current_user.is_authenticated:
        return redirect(url_for('index'))

    error = None
    info = None
    username = (request.form.get('username') or '').strip() if request.method == 'POST' else ''

    if request.method == 'POST':
        action = (request.form.get('action') or '').strip()
        source_ip = request.remote_addr or 'unknown'
        
        def notify_recovery_failure(reason):
            attempted_username = username if username else '(nezadané)'
            send_pushover_notification(
                f"🚨 Neúspešná obnova hesla: {reason}. Používateľ: {attempted_username}, IP: {source_ip}",
                title="MikroTik Manager - Security",
                notification_key='notify_password_recovery_failure',
                log_message=False,
                ignore_quiet_hours=True
            )

        if action == 'send_code':
            if not username:
                error = 'Zadajte používateľské meno.'
                notify_recovery_failure("chýbajúce používateľské meno")
            else:
                generic_info = f"Ak účet existuje a Pushover je nastavený, recovery kód bol odoslaný. Kód platí {PASSWORD_RECOVERY_EXPIRY_MINUTES} minút."
                with get_db_connection() as conn:
                    user_data = conn.execute('SELECT id FROM users WHERE username = ?', (username,)).fetchone()

                if not user_data:
                    add_log('warning', f"Obnova hesla - požiadavka pre neexistujúce meno '{username}', IP: {source_ip}")
                    notify_recovery_failure("požiadavka pre neexistujúce používateľské meno")
                    time.sleep(1)
                    info = generic_info
                else:
                    recovery_code, issue_status = issue_password_recovery_code(user_data['id'], source_ip)
                    if issue_status == 'cooldown':
                        info = f"Recovery kód bol odoslaný nedávno. Skúste to znova o {PASSWORD_RECOVERY_REQUEST_COOLDOWN_SECONDS} sekúnd."
                        add_log('warning', f"Obnova hesla - príliš častá požiadavka pre používateľa '{username}', IP: {source_ip}")
                        notify_recovery_failure("príliš častá požiadavka (cooldown)")
                    elif recovery_code:
                        sent = send_pushover_notification(
                            (
                                f"🔑 Recovery kód pre reset hesla: {recovery_code}\n"
                                f"Platnosť: {PASSWORD_RECOVERY_EXPIRY_MINUTES} minút.\n"
                                "Ak ste o reset nežiadali, ignorujte túto správu."
                            ),
                            title="MikroTik Manager - Recovery",
                            log_message=False,
                            ignore_quiet_hours=True
                        )
                        if sent:
                            info = generic_info
                            add_log('warning', f"Obnova hesla - recovery kód odoslaný pre používateľa '{username}', IP: {source_ip}")
                        else:
                            add_log('error', f"Obnova hesla - odoslanie recovery kódu zlyhalo pre používateľa '{username}', IP: {source_ip}")
                            info = generic_info
                    else:
                        add_log('error', f"Obnova hesla - generovanie recovery kódu zlyhalo pre používateľa '{username}', IP: {source_ip}")
                        info = generic_info

        elif action == 'reset_password':
            recovery_code = (request.form.get('recovery_code') or '').strip().replace(' ', '')
            backup_code = (request.form.get('backup_code') or '').strip().upper()
            new_password = request.form.get('new_password') or ''
            new_password_confirm = request.form.get('new_password_confirm') or ''

            if not username or not recovery_code or not backup_code or not new_password or not new_password_confirm:
                error = 'Všetky polia sú povinné.'
                notify_recovery_failure("nekompletné vstupné údaje")
            elif len(new_password) < 8:
                error = 'Nové heslo musí mať aspoň 8 znakov.'
                notify_recovery_failure("heslo nespĺňa minimálnu dĺžku")
            elif new_password != new_password_confirm:
                error = 'Nové heslá sa nezhodujú.'
                notify_recovery_failure("nesúlad potvrdenia nového hesla")
            else:
                with get_db_connection() as conn:
                    user_data = conn.execute('SELECT id FROM users WHERE username = ?', (username,)).fetchone()

                    if not user_data:
                        error = 'Neplatné údaje pre obnovu hesla.'
                        add_log('warning', f"Obnova hesla - reset pre neexistujúce meno '{username}', IP: {source_ip}")
                        notify_recovery_failure("reset pre neexistujúce používateľské meno")
                        time.sleep(1)
                    else:
                        user_id = user_data['id']
                        now = datetime.now()
                        conn.execute(
                            'UPDATE password_recovery_tokens SET used = 1, used_at = ? WHERE user_id = ? AND used = 0 AND expires_at < ?',
                            (now, user_id, now)
                        )
                        token_record = find_matching_recovery_token_record(conn, user_id, recovery_code)
                        backup_record = find_matching_backup_code_record(conn, user_id, backup_code)

                        if not token_record or not backup_record:
                            error = 'Neplatný recovery kód alebo záložný kód.'
                            add_log('warning', f"Obnova hesla - neplatný recovery/backup kód pre používateľa '{username}', IP: {source_ip}")
                            notify_recovery_failure("neplatný recovery alebo záložný kód")
                        else:
                            new_password_hash = generate_password_hash(new_password)
                            conn.execute('UPDATE users SET password = ? WHERE id = ?', (new_password_hash, user_id))
                            conn.execute(
                                'UPDATE password_recovery_tokens SET used = 1, used_at = ? WHERE user_id = ? AND used = 0',
                                (now, user_id)
                            )
                            conn.execute(
                                'UPDATE backup_codes SET used = 1, used_at = ? WHERE id = ?',
                                (now, backup_record['id'])
                            )
                            conn.commit()

                            send_pushover_notification(
                                "✅ Heslo bolo úspešne resetované cez recovery flow.",
                                title="MikroTik Manager - Security",
                                log_message=False,
                                ignore_quiet_hours=True
                            )
                            add_log('warning', f"Obnova hesla úspešná pre používateľa '{username}'. IP: {source_ip}")
                            info = 'Heslo bolo úspešne obnovené. Teraz sa môžete prihlásiť.'
        else:
            error = 'Neplatná požiadavka.'
            notify_recovery_failure("neplatný parameter action")

    return render_template(
        'password_recovery.html',
        error=error,
        info=info,
        username=username,
        recovery_code_length=PASSWORD_RECOVERY_CODE_LENGTH,
        recovery_expiry_minutes=PASSWORD_RECOVERY_EXPIRY_MINUTES
    )

@app.route('/login/2fa', methods=['GET', 'POST'])
def login_2fa():
    if '2fa_user_id' not in session:
        return redirect(url_for('login'))
    error = None
    if request.method == 'POST':
        user = load_user(session['2fa_user_id'])
        if not user:
            session.pop('2fa_user_id', None)
            return redirect(url_for('login'))
        source_ip = request.remote_addr or 'unknown'
        attempted_username = user.username if user else '(unknown user)'
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
                message = f"🛡️ Neúspešné 2FA overenie (TOTP). Používateľ: {attempted_username}, IP: {source_ip}"
                add_log('warning', message)
                send_pushover_notification(
                    message,
                    title="MikroTik Manager - Security",
                    notification_key='notify_failed_2fa'
                )
                error = 'Neplatný overovací kód z aplikácie.'
        elif backup_code:
            # Overenie záložného kódu
            try:
                with get_db_connection() as conn:
                    matched_record = find_matching_backup_code_record(conn, user.id, backup_code)

                    if matched_record:
                        # Označenie kódu ako použitého
                        conn.execute(
                            'UPDATE backup_codes SET used = 1, used_at = ? WHERE id = ?',
                            (datetime.now(), matched_record['id'])
                        )
                        conn.commit()
                        
                        login_user(user, remember=True)
                        session.permanent = True
                        session.pop('2fa_user_id', None)
                        add_log('info', f"Používateľ '{user.username}' sa prihlásil pomocou záložného kódu.")
                        return redirect(request.args.get('next') or url_for('index'))
                    else:
                        message = f"🛡️ Neúspešné 2FA overenie (záložný kód). Používateľ: {attempted_username}, IP: {source_ip}"
                        add_log('warning', message)
                        send_pushover_notification(
                            message,
                            title="MikroTik Manager - Security",
                            notification_key='notify_failed_2fa'
                        )
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
    if not secret:
        new_secret = pyotp.random_base32()
        encrypted_secret = encrypt_password(new_secret)
        with get_db_connection() as conn:
            conn.execute('UPDATE users SET totp_secret = ? WHERE id = ?', (encrypted_secret, current_user.id,))
            conn.commit()
        secret = new_secret
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
    if not current_user.totp_secret:
        return redirect(url_for('setup_2fa'))
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
    next_page = request.args.get('next', '')
    if next_page == 'password-recovery':
        return redirect(url_for('password_recovery'))
    return redirect(url_for('login'))

@app.route('/backups')
@login_required
def list_backups():
    """Dynamický výpis záloh: zoradené podľa mtime (najnovšie prvé)."""
    try:
        entries = []
        device_names = {}
        with get_db_connection() as conn:
            device_names = {
                device['ip']: device['name']
                for device in conn.execute(
                    'SELECT ip, name FROM devices WHERE deleted_at IS NULL'
                ).fetchall()
            }
        for filename in os.listdir(BACKUP_DIR):
            filepath = os.path.join(BACKUP_DIR, filename)
            if os.path.isfile(filepath):
                try:
                    mtime = os.path.getmtime(filepath)
                    ip_match = re.search(r'_(\d{1,3}(?:\.\d{1,3}){3})_', filename)
                    device_ip = ip_match.group(1) if ip_match else ''
                    entries.append({
                        'name': filename,
                        'size': os.path.getsize(filepath),
                        'modified': datetime.fromtimestamp(mtime),
                        'device_ip': device_ip,
                        'device_name': device_names.get(device_ip, device_ip or 'Neznáme zariadenie'),
                        '_mtime': mtime
                    })
                except OSError:
                    continue
        # Server-side zoradenie podľa mtime desc
        entries.sort(key=lambda x: x['_mtime'], reverse=True)
        # Jedinečné zariadenia so zálohami, zoradené podľa zobrazovaného názvu A–Z.
        device_filters = {}
        for entry in entries:
            if entry['device_ip']:
                device_filters[entry['device_ip']] = entry['device_name']
        device_filters = sorted(
            device_filters.items(), key=lambda device: device[1].casefold()
        )
        # Odstráň pomocný kľúč
        for e in entries:
            e.pop('_mtime', None)
        return render_template('backups.html', files=entries, device_filters=device_filters)
    except Exception as e:
        logger.error(f"Chyba pri načítaní zoznamu záloh: {e}")
        return "Chyba pri načítaní zoznamu záloh.", 500

ALLOWED_BACKUP_EXTENSIONS = ('.backup', '.rsc')

def validate_backup_filename(filename):
    if not filename or os.path.isabs(filename) or filename != os.path.basename(filename):
        raise ValueError("Nepovolený názov súboru.")
    if not filename.endswith(ALLOWED_BACKUP_EXTENSIONS):
        raise ValueError("Nepovolený typ súboru.")
    return filename

def resolve_backup_file_path(filename):
    """Return a validated path for a backup file directly under BACKUP_DIR."""
    safe_filename = validate_backup_filename(filename)

    backup_root = os.path.realpath(BACKUP_DIR)
    candidate_path = os.path.realpath(os.path.join(backup_root, safe_filename))
    if os.path.commonpath([backup_root, candidate_path]) != backup_root:
        raise ValueError("Nepovolená cesta k súboru.")
    return candidate_path


def backup_device_ip_from_filename(filename):
    """Extract and validate the device IP from a timestamped .rsc filename."""
    match = re.search(
        r'_(\d{1,3}(?:\.\d{1,3}){3})_\d{8}-\d{4}\.rsc$',
        filename,
    )
    if not match:
        return None
    try:
        return str(ipaddress.ip_address(match.group(1)))
    except ValueError:
        return None


def read_backup_export_for_compare(filename, mode):
    """Read one bounded export and return its metadata and normalized records."""
    safe_filename = validate_backup_filename(filename)
    if not safe_filename.endswith('.rsc'):
        raise ValueError('Porovnávať je možné iba textové .rsc exporty.')

    path = resolve_backup_file_path(safe_filename)
    if not os.path.isfile(path):
        raise FileNotFoundError(safe_filename)

    stat_result = os.stat(path)
    if stat_result.st_size > BACKUP_COMPARE_MAX_BYTES:
        raise OverflowError(
            f'Export {safe_filename} prekračuje limit 16 MiB.'
        )

    with open(path, 'rb') as export_file:
        content_bytes = export_file.read(BACKUP_COMPARE_MAX_BYTES + 1)
    if len(content_bytes) > BACKUP_COMPARE_MAX_BYTES:
        raise OverflowError(
            f'Export {safe_filename} prekračuje limit 16 MiB.'
        )
    content = content_bytes.decode('utf-8', errors='replace')

    source_line_count = len(content.splitlines())
    if source_line_count > BACKUP_COMPARE_MAX_LINES:
        raise OverflowError(
            f'Export {safe_filename} prekračuje limit 200 000 riadkov.'
        )

    return {
        'filename': safe_filename,
        'size': stat_result.st_size,
        'modified': datetime.fromtimestamp(
            stat_result.st_mtime, timezone.utc
        ).isoformat(),
        'line_count': source_line_count,
        'records': normalize_routeros_export(content, mode=mode),
    }


def build_backup_diff(left_records, right_records, context_lines):
    """Build bounded, aligned diff hunks and complete change statistics."""
    left_text = [line for _, line in left_records]
    right_text = [line for _, line in right_records]
    matcher = difflib.SequenceMatcher(None, left_text, right_text)
    opcodes = matcher.get_opcodes()

    summary = {'added': 0, 'removed': 0, 'modified': 0, 'total': 0}
    for tag, left_start, left_end, right_start, right_end in opcodes:
        left_count = left_end - left_start
        right_count = right_end - right_start
        if tag == 'insert':
            summary['added'] += right_count
        elif tag == 'delete':
            summary['removed'] += left_count
        elif tag == 'replace':
            paired = min(left_count, right_count)
            summary['modified'] += paired
            summary['removed'] += left_count - paired
            summary['added'] += right_count - paired
    summary['total'] = summary['added'] + summary['removed'] + summary['modified']

    def line_payload(record):
        if record is None:
            return None
        return {'number': record[0], 'text': record[1]}

    hunks = []
    returned_rows = 0
    truncated = False
    for group in matcher.get_grouped_opcodes(n=context_lines):
        hunk_rows = []
        for tag, left_start, left_end, right_start, right_end in group:
            left_slice = left_records[left_start:left_end]
            right_slice = right_records[right_start:right_end]

            if tag == 'equal':
                pairs = zip(left_slice, right_slice)
                row_kind = 'equal'
            elif tag == 'delete':
                pairs = ((record, None) for record in left_slice)
                row_kind = 'removed'
            elif tag == 'insert':
                pairs = ((None, record) for record in right_slice)
                row_kind = 'added'
            else:
                pair_count = max(len(left_slice), len(right_slice))
                pairs = (
                    (
                        left_slice[index] if index < len(left_slice) else None,
                        right_slice[index] if index < len(right_slice) else None,
                    )
                    for index in range(pair_count)
                )
                row_kind = 'modified'

            for left_record, right_record in pairs:
                if returned_rows >= BACKUP_COMPARE_MAX_ROWS:
                    truncated = True
                    break
                effective_kind = row_kind
                if row_kind == 'modified':
                    if left_record is None:
                        effective_kind = 'added'
                    elif right_record is None:
                        effective_kind = 'removed'
                hunk_rows.append({
                    'kind': effective_kind,
                    'left': line_payload(left_record),
                    'right': line_payload(right_record),
                })
                returned_rows += 1
            if truncated:
                break

        if hunk_rows:
            hunks.append({'rows': hunk_rows})
        if truncated:
            break

    return {
        'summary': summary,
        'hunks': hunks,
        'returned_rows': returned_rows,
        'truncated': truncated,
    }


def backup_compare_response(payload, status=200):
    response = jsonify(payload)
    response.headers['Cache-Control'] = 'no-store, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    return response, status


@app.route('/api/backups/compare')
@login_required
def compare_backup_exports():
    left_filename = request.args.get('left', '')
    right_filename = request.args.get('right', '')
    mode = request.args.get('mode', 'normalized')
    context_value = request.args.get('context', '3')

    if mode not in BACKUP_COMPARE_MODES:
        return backup_compare_response({
            'status': 'error', 'message': 'Neplatný režim porovnania.'
        }, 400)
    try:
        context_lines = int(context_value)
    except (TypeError, ValueError):
        context_lines = None
    if context_lines not in BACKUP_COMPARE_CONTEXTS:
        return backup_compare_response({
            'status': 'error', 'message': 'Kontext musí mať 3, 10 alebo 25 riadkov.'
        }, 400)
    if not left_filename or not right_filename or left_filename == right_filename:
        return backup_compare_response({
            'status': 'error', 'message': 'Vyberte dva rozdielne .rsc exporty.'
        }, 400)

    try:
        left_ip = backup_device_ip_from_filename(left_filename)
        right_ip = backup_device_ip_from_filename(right_filename)
        if not left_ip or not right_ip:
            raise ValueError('Názov exportu nemá podporovaný formát.')
        if left_ip != right_ip:
            raise ValueError('Porovnať je možné iba exporty rovnakého zariadenia.')

        left_export = read_backup_export_for_compare(left_filename, mode)
        right_export = read_backup_export_for_compare(right_filename, mode)
        diff_result = build_backup_diff(
            left_export.pop('records'),
            right_export.pop('records'),
            context_lines,
        )
        return backup_compare_response({
            'status': 'success',
            'mode': mode,
            'context': context_lines,
            'device_ip': left_ip,
            'left': left_export,
            'right': right_export,
            **diff_result,
        })
    except ValueError as error:
        return backup_compare_response({
            'status': 'error', 'message': str(error)
        }, 400)
    except FileNotFoundError:
        return backup_compare_response({
            'status': 'error', 'message': 'Vybraný export nebol nájdený.'
        }, 404)
    except OverflowError as error:
        return backup_compare_response({
            'status': 'error', 'message': str(error)
        }, 413)
    except OSError as error:
        logger.warning(
            'Nepodarilo sa prečítať export pre diff: %s',
            error.__class__.__name__,
        )
        return backup_compare_response({
            'status': 'error', 'message': 'Export sa nepodarilo prečítať.'
        }, 500)
    except Exception as error:
        logger.error(
            'Chyba pri vytváraní diffu záloh: %s',
            error.__class__.__name__,
        )
        return backup_compare_response({
            'status': 'error', 'message': 'Porovnanie exportov zlyhalo.'
        }, 500)

@app.route('/download_backup/<path:filename>')
@login_required
def download_backup(filename):
    try:
        safe_filename = validate_backup_filename(filename)
        resolve_backup_file_path(safe_filename)
        return send_from_directory(BACKUP_DIR, safe_filename, as_attachment=True)
    except ValueError as e:
        return str(e), 400
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
        try:
            safe_filename = validate_backup_filename(filename)
            resolve_backup_file_path(safe_filename)
        except ValueError as e:
            return jsonify({'status': 'error', 'message': str(e)}), 400
        
        # Získanie základného názvu súboru bez prípony
        base_filename = os.path.splitext(safe_filename)[0]
        backup_file = base_filename + '.backup'
        rsc_file = base_filename + '.rsc'
        
        # Zoznam súborov na vymazanie
        files_to_delete = []
        backup_file_path = resolve_backup_file_path(backup_file)
        rsc_file_path = resolve_backup_file_path(rsc_file)
        if os.path.exists(backup_file_path):
            files_to_delete.append(backup_file)
        if os.path.exists(rsc_file_path):
            files_to_delete.append(rsc_file)
        
        deleted_local = []
        deleted_ftp = []
        
        # Vymazanie lokálnych súborov
        for file_to_delete in files_to_delete:
            local_file_path = resolve_backup_file_path(file_to_delete)
            try:
                os.remove(local_file_path)
                deleted_local.append(file_to_delete)
            except Exception as e:
                add_log('warning', f"Nepodarilo sa vymazať lokálny súbor {file_to_delete}: {e}")
        
        # Pokus o vymazanie z FTP servera
        try:
            with get_db_connection() as conn:
                settings = {row['key']: row['value'] for row in conn.execute('SELECT key, value FROM settings').fetchall()}
            settings = decrypt_sensitive_settings_map(settings)
            
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
            add_log('warning', f"Nepodarilo sa pripojiť na FTP server pre vymazanie súborov: {safe_ftp_error(ftp_connection_e)}")
        
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
                candidate_files = []
                device_marker = f'_{device_ip}_'
                for f in os.listdir(BACKUP_DIR):
                    if not f.endswith('.backup') or device_marker not in f:
                        continue
                    full_path = os.path.join(BACKUP_DIR, f)
                    if os.path.isfile(full_path):
                        candidate_files.append((f, full_path, os.path.getmtime(full_path)))

                with get_db_connection() as conn:
                    if not candidate_files:
                        conn.execute('UPDATE devices SET last_backup = NULL WHERE ip = ? AND deleted_at IS NULL', (device_ip,))
                    else:
                        latest_name, latest_path, latest_mtime = max(candidate_files, key=lambda item: item[2])
                        latest_mtime = datetime.fromtimestamp(latest_mtime)
                        conn.execute('UPDATE devices SET last_backup = ? WHERE ip = ? AND deleted_at IS NULL', (latest_mtime, device_ip,))
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

# --- UPDATER FUNCTIONS ---

RSS_CACHE = {'timestamp': 0, 'data': None}
RSS_CACHE_DURATION = 3600 # 1 hour
MIKROTIK_STABLE_RSS_URL = 'https://cdn.mikrotik.com/routeros/latest-stable.rss'
MIKROTIK_CHANGELOGS_URL = 'https://mikrotik.com/download/changelogs'
ROUTEROS_UPDATE_CHANNELS = ('long-term', 'stable', 'testing', 'development')
ROUTEROS_VERSION_MAX_LENGTH = 32
ROUTEROS_VERSION_PATTERN = re.compile(
    r'[0-9]+\.[0-9]+(?:\.[0-9]+)?(?:(?:alpha|beta|rc)[0-9]+)?',
    re.IGNORECASE
)
CHANGELOG_HISTORY_LIMIT = 1000  # Prakticky neobmedzená história RouterOS vydaní
CHANGELOG_HISTORY_CACHE = {}
CHANGELOG_DETAIL_CACHE = {}


def is_valid_routeros_version(value):
    """Validuje RouterOS verziu s pevnou hranicou pre vstup do regexu."""
    return (
        isinstance(value, str)
        and 0 < len(value) <= ROUTEROS_VERSION_MAX_LENGTH
        and ROUTEROS_VERSION_PATTERN.fullmatch(value) is not None
    )


def normalize_routeros_channel(value, default=None):
    """Normalizuje a validuje RouterOS update channel."""
    channel = str(value or '').strip().lower()
    if channel == 'longterm':
        channel = 'long-term'
    return channel if channel in ROUTEROS_UPDATE_CHANNELS else default


def get_device_update_channel(device_id, fallback='stable'):
    """Vráti efektívny kanál; individuálne nastavenie má prednosť pred globálnym."""
    fallback = normalize_routeros_channel(fallback, 'stable')
    with get_db_connection() as conn:
        row = conn.execute(
            'SELECT routeros_update_channel FROM devices WHERE id = ? AND deleted_at IS NULL',
            (device_id,)
        ).fetchone()
    override = normalize_routeros_channel(row['routeros_update_channel']) if row else None
    return override or fallback, override


def fetch_mikrotik_changelog_history(channel='stable', limit=CHANGELOG_HISTORY_LIMIT):
    """Načíta vydania zvoleného RouterOS kanála z oficiálneho archívu."""
    channel = normalize_routeros_channel(channel, 'stable')
    now = time.time()
    channel_cache = CHANGELOG_HISTORY_CACHE.setdefault(channel, {
        'timestamp': 0,
        'data': None,
        'snapshot': None,
        'csrf_token': None,
        'update_url': None,
        'cookies': None
    })
    cached = channel_cache.get('data')
    if cached and now - channel_cache.get('timestamp', 0) < RSS_CACHE_DURATION:
        return cached[:limit]

    try:
        source_session = requests.Session()
        response = source_session.get(
            MIKROTIK_CHANGELOGS_URL,
            params={'channelFilter': channel},
            headers={'User-Agent': 'MikroTik-Manager/1.0'},
            timeout=15
        )
        response.raise_for_status()

        matches = list(re.finditer(r'data-changelog-version="([^"]+)"', response.text))
        releases = []
        seen = set()
        for index, match in enumerate(matches):
            version = match.group(1).strip()
            if version in seen or not is_valid_routeros_version(version):
                continue

            block_end = matches[index + 1].start() if index + 1 < len(matches) else len(response.text)
            block = response.text[match.start():block_end]
            date_match = re.search(r'<span class="mtk-text-xs">\s*(\d{4}-\d{2}-\d{2})\s*</span>', block)
            releases.append({
                'version': version,
                'release_date': date_match.group(1) if date_match else '',
                'channel': channel
            })
            seen.add(version)
            if len(releases) >= limit:
                break

        if releases:
            snapshot_match = re.search(
                r'<div[^>]+wire:snapshot="([^"]+)"[^>]+wire:name="components\.software\.changelogs"',
                response.text
            )
            csrf_match = re.search(r'data-csrf="([^"]+)"', response.text)
            update_url_match = re.search(r'data-update-uri="([^"]+)"', response.text)
            channel_cache.update({
                'timestamp': now,
                'data': releases,
                'snapshot': unescape(snapshot_match.group(1)) if snapshot_match else None,
                'csrf_token': csrf_match.group(1) if csrf_match else None,
                'update_url': urllib.parse.urljoin(response.url, update_url_match.group(1)) if update_url_match else None,
                'cookies': source_session.cookies.get_dict()
            })
            return releases
    except Exception as e:
        logger.warning(f"Failed to fetch MikroTik {channel} changelog history: {e}")

    return cached[:limit] if cached else []


def fetch_mikrotik_changelog_detail(version, channel='stable'):
    """Načíta konkrétny changelog zvoleného kanála z oficiálneho MikroTik archívu."""
    channel = normalize_routeros_channel(channel, 'stable')
    if not is_valid_routeros_version(version):
        return None

    cache_key = (channel, version)
    cached = CHANGELOG_DETAIL_CACHE.get(cache_key)
    if cached:
        return cached

    # Načítanie zoznamu zároveň pripraví Livewire snapshot a session cookie archívu.
    available_versions = {item['version'] for item in fetch_mikrotik_changelog_history(channel)}
    if version not in available_versions:
        return None

    channel_cache = CHANGELOG_HISTORY_CACHE.get(channel) or {}
    snapshot = channel_cache.get('snapshot')
    csrf_token = channel_cache.get('csrf_token')
    update_url = channel_cache.get('update_url')
    if not all((snapshot, csrf_token, update_url)):
        return None

    try:
        payload = {
            '_token': csrf_token,
            'components': [{
                'snapshot': snapshot,
                'updates': {},
                'calls': [{
                    'path': '',
                    'method': 'getChangelogs',
                    'params': [[version]]
                }]
            }]
        }
        detail_response = requests.post(
            update_url,
            json=payload,
            cookies=channel_cache.get('cookies') or {},
            headers={
                'User-Agent': 'MikroTik-Manager/1.0',
                'X-Livewire': 'true',
                'Referer': MIKROTIK_CHANGELOGS_URL
            },
            timeout=20
        )
        detail_response.raise_for_status()
        components = detail_response.json().get('components', [])
        returns = components[0].get('effects', {}).get('returns', []) if components else []
        changelogs = returns[0] if returns and isinstance(returns[0], dict) else {}
        description = str(changelogs.get(version, '')).replace('\r', '').strip()
        if not description:
            return None

        result = {
            'version': version,
            'description': description[:60000],
            'channel': channel,
            'source_url': f'{MIKROTIK_CHANGELOGS_URL}?channelFilter={urllib.parse.quote(channel)}&versionFilter={urllib.parse.quote(version)}'
        }
        CHANGELOG_DETAIL_CACHE[cache_key] = result
        return result
    except Exception as e:
        logger.warning(f"Failed to fetch MikroTik {channel} changelog {version}: {e}")
        return None


def get_managed_routeros_major_versions():
    """Vráti major verzie RouterOS z posledných SNMP údajov spravovaných zariadení."""
    major_versions = set()
    try:
        with get_db_connection() as conn:
            rows = conn.execute(
                'SELECT last_snmp_data FROM devices WHERE deleted_at IS NULL AND last_snmp_data IS NOT NULL'
            ).fetchall()
        for row in rows:
            try:
                snmp_data = json.loads(row['last_snmp_data'])
                version_match = re.match(r'^(\d+)\.', str(snmp_data.get('version', '')))
                if version_match:
                    major_versions.add(int(version_match.group(1)))
            except (TypeError, ValueError, json.JSONDecodeError):
                continue
    except Exception as e:
        logger.warning(f"Failed to determine managed RouterOS versions: {e}")

    if not major_versions:
        latest = (RSS_CACHE.get('data') or {}).get('latest') or {}
        version_match = re.match(r'^(\d+)\.', str(latest.get('version', '')))
        major_versions.add(int(version_match.group(1)) if version_match else 7)

    return sorted(major_versions, reverse=True)

def fetch_mikrotik_rss():
    global RSS_CACHE
    now = time.time()
    if now - RSS_CACHE['timestamp'] < RSS_CACHE_DURATION and RSS_CACHE['data']:
        return RSS_CACHE['data']
        
    try:
        response = requests.get(MIKROTIK_STABLE_RSS_URL, timeout=10)
        response.raise_for_status()
        root = ET.fromstring(response.text)
        
        namespaces = {'content': 'http://purl.org/rss/1.0/modules/content/'}
        items = []
        for item in root.findall('./channel/item'):
            title_el = item.find('title')
            desc_el = item.find('description')
            content_el = item.find('content:encoded', namespaces)
            
            if title_el is not None:
                title = title_el.text or ''
                stable_release = re.search(r'\[[^\]]*\bstable\b[^\]]*\]', title, re.IGNORECASE)
                if stable_release:
                    version_match = re.search(r'RouterOS\s+([\d.]+)', title, re.IGNORECASE)
                    version = version_match.group(1) if version_match else title
                    
                    desc = ''
                    if content_el is not None and content_el.text:
                        desc = content_el.text
                    elif desc_el is not None and desc_el.text:
                        desc = desc_el.text
                        
                    release_date = ''
                    release_date_match = re.search(r"What's new in [\d\.]+\s*\((\d{4}-\w{3}-\d{2}\s+[\d:]+)\)", desc)
                    if release_date_match:
                        release_date = release_date_match.group(1)

                    items.append({
                        'title': title,
                        'version': version,
                        'description': desc,
                        'pubDate': item.find('pubDate').text if item.find('pubDate') is not None else '',
                        'release_date': release_date
                    })
        
        latest = items[0] if items else None
        
        result = {'items': items, 'latest': latest}
        RSS_CACHE['data'] = result
        RSS_CACHE['timestamp'] = now
        
        # Oznámenie cez Pushover ak je nová verzia
        if latest and latest.get('version'):
            current_latest = latest['version']
            with get_db_connection() as conn:
                setting_row = conn.execute("SELECT value FROM settings WHERE key = 'last_seen_routeros_version'").fetchone()
                last_seen = setting_row['value'] if setting_row else None
                
                if last_seen != current_latest:
                    conn.execute("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)", ('last_seen_routeros_version', current_latest))
                    conn.commit()
                    
                    if last_seen is not None:
                        settings_dict = {row['key']: row['value'] for row in conn.execute("SELECT key, value FROM settings WHERE key = 'notify_new_routeros_version'").fetchall()}
                        if settings_dict.get('notify_new_routeros_version', 'false').lower() == 'true':
                            add_log('info', f"Nová verzia RouterOS z RSS feedu: {current_latest}")
                            send_pushover_notification(
                                f"📣 Nová verzia RouterOS!\nVerzia: {current_latest}\nDátum: {latest.get('release_date') or latest.get('pubDate', '')}",
                                notification_key='notify_new_routeros_version'
                            )

        return result
    except Exception as e:
        logger.error(f"Failed to fetch MikroTik RSS: {e}")
        return None


def fetch_mikrotik_channel_feed(channel='stable'):
    """Vráti najnovšie vydanie vo formáte RSS endpointu pre ľubovoľný kanál."""
    channel = normalize_routeros_channel(channel, 'stable')
    if channel == 'stable':
        data = fetch_mikrotik_rss()
        if data and data.get('latest'):
            data['latest']['channel'] = channel
        return data

    history = fetch_mikrotik_changelog_history(channel)
    if not history:
        return None

    latest_release = history[0]
    detail = fetch_mikrotik_changelog_detail(latest_release['version'], channel)
    latest = {
        'title': f"RouterOS {latest_release['version']} [{channel}]",
        'version': latest_release['version'],
        'description': detail.get('description', '') if detail else '',
        'pubDate': latest_release.get('release_date', ''),
        'release_date': latest_release.get('release_date', ''),
        'channel': channel
    }
    return {'items': [latest], 'latest': latest}

def parse_int_setting(value, default, min_value=None, max_value=None):
    try:
        parsed = int(value)
        if min_value is not None and parsed < min_value:
            return default
        if max_value is not None and parsed > max_value:
            return default
        return parsed
    except (TypeError, ValueError):
        return default


def parse_port_setting(value, default):
    return parse_int_setting(value, default, 1, 65535)


def get_mapping_value(mapping, key, default=None):
    try:
        if mapping is None:
            return default
        if hasattr(mapping, 'keys') and key in mapping.keys():
            return mapping[key]
        if isinstance(mapping, dict):
            return mapping.get(key, default)
    except Exception:
        pass
    return default


def get_updater_web_ports(settings=None, device=None):
    if settings is None:
        with get_db_connection() as conn:
            rows = conn.execute(
                "SELECT key, value FROM settings WHERE key IN (?, ?)",
                ('cert_www_port', 'cert_www_ssl_port')
            ).fetchall()
            settings = {row['key']: row['value'] for row in rows}

    http_port = parse_port_setting(settings.get('cert_www_port'), 80)
    https_port = parse_port_setting(settings.get('cert_www_ssl_port'), 443)

    device_http_port = parse_int_setting(get_mapping_value(device, 'cert_www_port'), 0, 0, 65535)
    device_https_port = parse_int_setting(get_mapping_value(device, 'cert_www_ssl_port'), 0, 0, 65535)
    if device_http_port > 0:
        http_port = device_http_port
    if device_https_port > 0:
        https_port = device_https_port

    return http_port, https_port


def routeros_rest_url(scheme, ip, endpoint, http_port=None, https_port=None):
    port = https_port if scheme == 'https' else http_port
    return f"{scheme}://{ip}:{port}/rest/{endpoint.lstrip('/')}"


def mk_api(device_id, method, endpoint, payload=None, timeout_val=20):
    with get_db_connection() as conn:
        device = conn.execute('SELECT * FROM devices WHERE id = ? AND deleted_at IS NULL', (device_id,)).fetchone()
    if not device:
        return None, {'status': 'error', 'message': 'Zariadenie nenájdené.'}, 404
        
    device = get_device_with_decrypted_password(dict(device))
    ip = device['ip']
    username = device['username']
    password = device['password']
    http_port, https_port = get_updater_web_ports(device=device)
    
    # Skúsime najprv HTTPS, ak zlyhá (napr. zariadenie nemá certifikát), fallback na HTTP
    for scheme in ['https', 'http']:
        url = routeros_rest_url(scheme, ip, endpoint, http_port, https_port)
        try:
            response = requests.request(
                method=method,
                url=url,
                auth=(username, password),
                json=payload,
                verify=False,
                timeout=timeout_val
            )
            if response.status_code in [200, 201, 202]:
                try:
                    return response.json(), None, response.status_code
                except:
                    return response.text, None, response.status_code
            else:
                err_msg = response.text
                try:
                    err_json = response.json()
                    if 'detail' in err_json:
                        err_msg = err_json['detail']
                except:
                    pass
                if response.status_code in (401, 403):
                    return None, {
                        'status': 'error',
                        'message': (
                            f'RouterOS REST API odmietlo prihlásenie ({response.status_code}). '
                            'Skontrolujte používateľské meno, heslo a oprávnenia účtu.'
                        )
                    }, response.status_code
                return None, {'status': 'error', 'message': f'Chyba API ({response.status_code}): {err_msg}'}, response.status_code
        except Exception as e:
            if scheme == 'https':
                continue  # HTTPS zlyhalo, skúsime HTTP
            detail = str(e).strip() or e.__class__.__name__
            return None, {
                'status': 'error',
                'message': (
                    f'Nepodarilo sa pripojiť k RouterOS REST API na {ip}. '
                    f'Skontrolujte dostupnosť zariadenia, služby www (port {http_port}) '
                    f'a www-ssl (port {https_port}) a pravidlá firewallu. Detail: {detail}'
                )
            }, 500
    
    return None, {'status': 'error', 'message': 'Zariadenie nedostupné cez HTTPS ani HTTP.'}, 500


def set_routeros_update_channel(device_id, channel):
    """Nastaví overený update channel priamo na RouterOS zariadení."""
    channel = normalize_routeros_channel(channel)
    if not channel:
        return None, {'status': 'error', 'message': 'Neplatný RouterOS kanál.'}, 400
    return mk_api(
        device_id,
        'POST',
        'system/package/update/set',
        {'channel': channel}
    )


def check_routeros_updates(device_id, channel='stable'):
    """Nastaví channel a až potom skontroluje dostupnú RouterOS verziu."""
    channel = normalize_routeros_channel(channel, 'stable')
    _, err, code = set_routeros_update_channel(device_id, channel)
    if err:
        return None, err, code
    return mk_api(device_id, 'POST', 'system/package/update/check-for-updates')


def parse_mikrotik_date(date_str):
    """Parsuje MikroTik formát dátumu napr. 'jan/01/2025 12:34:56' alebo ISO varianty."""
    if not date_str:
        return None
    date_str = date_str.strip()
    # Normalize: 'jan/01/2025 ...' → 'Jan/01/2025 ...' pre strptime %b
    if '/' in date_str:
        parts = date_str.split('/', 1)
        date_str = parts[0].capitalize() + '/' + parts[1]
    for fmt in ['%b/%d/%Y %H:%M:%S', '%Y-%m-%d %H:%M:%S', '%Y-%m-%dT%H:%M:%SZ']:
        try:
            return datetime.strptime(date_str, fmt)
        except ValueError:
            continue
    return None


# In-memory tracking to avoid repeated daily auto-renewal per device
_cert_expiry_notified = {}

# Certificate renewal can be triggered by the daily job and manually from the
# Updater at the same time. Keep one in-process operation per device/IP so the
# two flows cannot remove or create WebCert underneath each other.
_certificate_renewal_locks_guard = threading.Lock()
_certificate_renewal_locks = {}

# In-memory tracking of manually started (non-scheduled) updates per device
# device_id -> {device_name, device_ip, started_at, current_step, steps_done, current_msg}
_running_manual_updates = {}

# In-memory tracking of scheduled updates currently running (for F5 restore)
# device_id -> {device_name, device_ip, schedule_id, started_at, current_step, steps_done, current_msg}
_running_scheduled_updates = {}

# In-memory tracking of manual bulk update groups (for F5 restore of waiting devices)
# bulk_group_id -> {device_ids, remaining_ids, current_device_id}
_manual_bulk_groups = {}

# A device may participate in only one active update flow. Reservations close
# the short race between accepting an API request and the worker registering
# itself in the running-state dictionaries.
_update_state_lock = threading.RLock()
_reserved_update_devices = {}  # device_id -> owner token
_active_scheduled_bulk_groups = set()

# One-time suppression set: device_ids that completed an update via manager.
# Suppresses the first SNMP reboot/version-change detection after the update.
# Consumed (cleared) once SNMP processes the post-update cycle.
_recent_updates: set = set()


def _reserve_update_devices(device_ids, owner):
    normalized = list(dict.fromkeys(int(device_id) for device_id in device_ids))
    with _update_state_lock:
        busy = [
            device_id for device_id in normalized
            if device_id in _reserved_update_devices
            or device_id in _running_manual_updates
            or device_id in _running_scheduled_updates
        ]
        if busy:
            return False, busy
        for device_id in normalized:
            _reserved_update_devices[device_id] = owner
    return True, []


def _release_update_devices(device_ids, owner=None):
    with _update_state_lock:
        for device_id in device_ids:
            if owner is None or _reserved_update_devices.get(device_id) == owner:
                _reserved_update_devices.pop(device_id, None)


def _partition_devices_by_site(conn, device_ids):
    """Return selected active devices grouped by site and ordered by site priority."""
    ordered_ids = list(dict.fromkeys(int(device_id) for device_id in device_ids))
    if not ordered_ids:
        return []
    placeholders = ','.join('?' for _ in ordered_ids)
    rows = conn.execute(f'''
        SELECT d.id, d.name, d.site_id, d.site_update_order, d.routeros_update_channel,
               COALESCE(s.name, 'Bez lokality') AS site_name
        FROM devices d
        LEFT JOIN sites s ON s.id = d.site_id
        WHERE d.id IN ({placeholders}) AND d.deleted_at IS NULL
    ''', ordered_ids).fetchall()
    by_id = {row['id']: dict(row) for row in rows}
    groups = {}
    for device_id in ordered_ids:
        device = by_id.get(device_id)
        if not device:
            continue
        key = device['site_id']
        if key not in groups:
            groups[key] = {
                'site_id': key,
                'site_name': device['site_name'],
                'devices': []
            }
        groups[key]['devices'].append(device)
    input_position = {device_id: index for index, device_id in enumerate(ordered_ids)}
    for group in groups.values():
        group['devices'].sort(key=lambda device: (
            device['site_update_order'] is None,
            device['site_update_order'] if device['site_update_order'] is not None else input_position[device['id']],
            input_position[device['id']],
        ))
    return list(groups.values())


def _do_renew_certificate(ip, username, password, days, http_port=None, low_memory=False):
    """Obnoví TLS certifikát WebCert na MikroTik zariadení cez HTTP službu www.
    Vracia (success: bool, message: str)."""
    if http_port is None:
        http_port, _ = get_updater_web_ports()

    with _certificate_renewal_locks_guard:
        renewal_lock = _certificate_renewal_locks.setdefault(str(ip), threading.Lock())
    if not renewal_lock.acquire(blocking=False):
        return False, 'Obnova TLS certifikátu na tomto zariadení už prebieha.'

    attempt_id = datetime.now().strftime('%Y%m%d-%H%M%S-%f')[:-3]

    def cert_log(level, message):
        add_log(level, f'TLS obnova [{attempt_id}]: {message}', device_ip=ip)

    def http_api(method, endpoint, payload=None, timeout=20):
        url = routeros_rest_url('http', ip, endpoint, http_port=http_port)
        try:
            r = requests.request(method, url, auth=(username, password), json=payload, timeout=timeout)
            if 200 <= r.status_code < 300:
                try:
                    return r.json(), None, r.status_code
                except Exception:
                    return r.text, None, r.status_code
            else:
                err_msg = r.text
                try:
                    ej = r.json()
                    if 'detail' in ej:
                        err_msg = ej['detail']
                except Exception:
                    pass
                return None, f'API chyba ({r.status_code}): {err_msg}', r.status_code
        except Exception as e:
            return None, f'Chyba spojenia: {str(e)}', None

    def webcert_from_response(response):
        if not isinstance(response, list):
            return None
        return next((item for item in response if item.get('name') == 'WebCert'), None)

    def format_space(value):
        try:
            value = int(value)
        except (TypeError, ValueError):
            return 'neznáme'
        if value < 1024:
            return f'{value} B'
        return f'{value / 1024:.0f} KiB'

    try:
        mode = '16MB' if low_memory else 'bežný'
        cert_log('info', f'Začiatok procesu, režim={mode}, požadovaná platnosť={days} dní.')

        # Storage is diagnostic only. Low free space must never block a renewal
        # that RouterOS itself is still able to complete.
        resource, resource_err, _ = http_api('GET', 'system/resource', timeout=10)
        if not resource_err:
            if isinstance(resource, list):
                resource = resource[0] if resource else {}
            if isinstance(resource, dict):
                cert_log(
                    'info',
                    'RouterOS úložisko: '
                    f"voľné={format_space(resource.get('free-hdd-space'))}, "
                    f"celkom={format_space(resource.get('total-hdd-space'))}."
                )
        else:
            cert_log('warning', f'Nepodarilo sa načítať stav úložiska (obnovu to neblokuje): {resource_err}')

        certs, certs_err, _ = http_api('GET', 'certificate?name=WebCert', timeout=10)
        if certs_err:
            return False, f'Nepodarilo sa overiť existujúci certifikát: {certs_err}'
        existing_cert = webcert_from_response(certs)

        if existing_cert:
            existing_id = existing_cert.get('.id')
            if not existing_id:
                return False, 'Existujúci WebCert nemá interné ID; obnova bola bezpečne zastavená.'
            cert_log(
                'info',
                f"Existujúci WebCert: id={existing_id}, platnosť-do={existing_cert.get('invalid-after', 'neznáma')}."
            )

            removal_confirmed = False
            last_remove_error = None
            poll_attempts = 15 if low_memory else 6
            for remove_attempt in range(2):
                target_id = existing_cert.get('.id')
                _, remove_err, remove_status = http_api(
                    'POST', 'certificate/remove', {'numbers': target_id}, timeout=30
                )
                last_remove_error = remove_err
                if remove_err:
                    cert_log(
                        'warning',
                        f'Odstránenie id={target_id} vrátilo chybu: {remove_err}. Overujem skutočný stav.'
                    )
                else:
                    cert_log('info', f'Odstránenie id={target_id} prijaté (HTTP {remove_status}).')

                for poll_attempt in range(1, poll_attempts + 1):
                    time.sleep(2)
                    certs, poll_err, _ = http_api('GET', 'certificate?name=WebCert', timeout=10)
                    if poll_err:
                        last_remove_error = poll_err
                        continue
                    existing_cert = webcert_from_response(certs)
                    if not existing_cert:
                        cert_log('info', f'Odstránenie potvrdené po {poll_attempt * 2} s.')
                        removal_confirmed = True
                        break

                if removal_confirmed:
                    break
                if remove_attempt == 0 and existing_cert and existing_cert.get('.id'):
                    cert_log(
                        'warning',
                        f"WebCert id={existing_cert.get('.id')} stále existuje; vykonávam posledný kontrolovaný pokus."
                    )

            if not removal_confirmed:
                detail = last_remove_error or 'RouterOS nepotvrdil odstránenie v časovom limite.'
                return False, f'Pôvodný WebCert sa nepodarilo potvrdene odstrániť: {detail}'
        else:
            cert_log('info', 'WebCert neexistuje; pokračujem priamo vytvorením.')

        _, err, add_status = http_api('POST', 'certificate/add', {
            'name': 'WebCert',
            'common-name': 'WebCert',
            'days-valid': str(days)
        }, timeout=30)
        if err:
            certs_after_error, inspect_err, _ = http_api('GET', 'certificate?name=WebCert', timeout=10)
            found = webcert_from_response(certs_after_error) if not inspect_err else None
            found_detail = f"; nájdený WebCert id={found.get('.id')}" if found else ''
            cert_log('error', f'Vytvorenie zlyhalo: {err}{found_detail}.')
            return False, f'Chyba pri pridaní certifikátu: {err}{found_detail}'
        cert_log('info', f'Vytvorenie WebCert prijaté (HTTP {add_status}).')

        # REST API requires the internal .id for signing instead of the name.
        cert_id = None
        id_poll_attempts = 10 if low_memory else 5
        for _ in range(id_poll_attempts):
            time.sleep(2)
            certs, err, _ = http_api('GET', 'certificate?name=WebCert', timeout=10)
            new_cert = webcert_from_response(certs) if not err else None
            cert_id = new_cert.get('.id') if new_cert else None
            if cert_id:
                break

        if not cert_id:
            return False, 'Nepodarilo sa získať ID nového certifikátu na podpísanie.'
        cert_log('info', f'Nový WebCert je dostupný ako id={cert_id}.')

        _, sign_err, sign_status = http_api(
            'POST', 'certificate/sign', {'number': cert_id}, timeout=30
        )
        if sign_err:
            return False, f'Chyba pri podpísaní certifikátu id={cert_id}: {sign_err}'
        cert_log('info', f'Podpísanie id={cert_id} prijaté (HTTP {sign_status}).')

        signed = False
        signed_cert = None
        sign_poll_attempts = 15 if low_memory else 10
        for _ in range(sign_poll_attempts):
            time.sleep(3)
            signed_cert, poll_err, _ = http_api('GET', f'certificate/{cert_id}', timeout=10)
            if not poll_err and isinstance(signed_cert, dict) and signed_cert.get('trusted') == 'true':
                signed = True
                break

        if not signed:
            return False, 'Certifikát sa nepodarilo podpísať v časovom limite.'
        cert_log(
            'info',
            f"Podpis potvrdený, platnosť-do={signed_cert.get('invalid-after', 'neznáma')}."
        )

        err = None
        service_status = None
        for attempt in range(3):
            _, err, service_status = http_api('POST', 'ip/service/set', {
                'numbers': 'www-ssl',
                'certificate': 'WebCert',
                'disabled': 'no'
            }, timeout=45)
            if not err:
                break
            cert_log('warning', f'Nastavenie www-ssl, pokus {attempt + 1}/3, zlyhalo: {err}')
            if attempt < 2:
                time.sleep(5)

        if err:
            return False, f'Chyba pri nastavení služby www-ssl: {err}'

        cert_log('info', f'www-ssl používa WebCert (HTTP {service_status}); proces dokončený.')
        return True, f'Certifikát úspešne vygenerovaný ({days} dní) a aplikovaný.'
    finally:
        renewal_lock.release()


def check_certificates_expiry():
    """Skontroluje certifikáty na všetkých zariadeniach a automaticky obnoví tie, ktorým čoskoro vyprší platnosť."""
    with app.app_context():
        try:
            with get_db_connection() as conn:
                settings = {row['key']: row['value'] for row in conn.execute('SELECT key, value FROM settings').fetchall()}
                devices = conn.execute('SELECT * FROM devices WHERE deleted_at IS NULL').fetchall()

            if settings.get('notify_cert_expiry', 'false').lower() != 'true':
                return

            try:
                warning_days = int(settings.get('cert_expiry_warning_days', 30))
            except (TypeError, ValueError):
                warning_days = 30

            try:
                renewal_days = int(settings.get('cert_auto_renewal_days', 365))
            except (TypeError, ValueError):
                renewal_days = 365

            today_str = datetime.now().strftime('%Y-%m-%d')

            for device_row in devices:
                device = dict(device_row)
                http_port, https_port = get_updater_web_ports(settings, device)
                device_id = device['id']
                device_name = device['name']
                ip = device['ip']
                
                device_renewal_days = device.get('cert_auto_renewal_days')
                final_renewal_days = int(device_renewal_days) if device_renewal_days else renewal_days

                # Skip if already processed today for this device
                if _cert_expiry_notified.get(device_id) == today_str:
                    continue

                device_dec = get_device_with_decrypted_password(device)
                username = device_dec['username']
                password = device_dec['password']

                # Check device reachability (HTTPS verify=False → HTTP fallback)
                device_reachable = False
                for scheme in ['https', 'http']:
                    try:
                        r = requests.get(
                            routeros_rest_url(scheme, ip, 'system/identity', http_port, https_port),
                            auth=(username, password),
                            verify=False,
                            timeout=3
                        )
                        if r.status_code == 200:
                            device_reachable = True
                            break
                    except Exception:
                        if scheme == 'https':
                            continue
                        break

                if not device_reachable:
                    continue

                # Fetch cert via HTTP (consistent with cert renewal flow)
                try:
                    r = requests.get(
                        routeros_rest_url('http', ip, 'certificate', http_port=http_port),
                        params={'name': 'WebCert'},
                        auth=(username, password),
                        timeout=5
                    )
                    if r.status_code != 200:
                        continue
                    certs = r.json()
                    if not isinstance(certs, list) or len(certs) == 0:
                        continue
                    cert = certs[0]
                    invalid_after = cert.get('invalid-after')
                    if not invalid_after:
                        continue
                    expiry_dt = parse_mikrotik_date(invalid_after)
                    if not expiry_dt:
                        continue
                    days_remaining = -(-int((expiry_dt - datetime.now()).total_seconds()) // 86400)
                except Exception:
                    continue

                if days_remaining <= warning_days:
                    logger.info(f"Auto-renewing cert for {device_name} ({ip}), {days_remaining} days remaining.")
                    success, message = _do_renew_certificate(
                        ip,
                        username,
                        password,
                        final_renewal_days,
                        http_port=http_port,
                        low_memory=bool(device.get('low_memory'))
                    )

                    if success:
                        add_log('info', f'Certifikát automaticky obnovený ({final_renewal_days} dní). Zostatok bol {days_remaining} dní.', device_ip=ip)
                        send_pushover_notification(
                            f"🔐 Certifikát na zariadení {device_name} bol automaticky obnovený ({final_renewal_days} dní).",
                            notification_key='notify_cert_expiry'
                        )
                    else:
                        add_log('error', f'Chyba pri automatickej obnove certifikátu: {message}', device_ip=ip)
                        send_pushover_notification(
                            f"⚠️ Chyba pri automatickej obnove certifikátu na {device_name}: {message}",
                            notification_key='notify_cert_expiry'
                        )

                    _cert_expiry_notified[device_id] = today_str

        except Exception as e:
            logger.error(f"check_certificates_expiry error: {e}")


@app.route('/updater.html')
@login_required
def updater_page():
    if not current_user.totp_enabled:
        return redirect(url_for('setup_2fa'))
    return send_from_directory('.', 'updater.html')

@app.route('/api/updater/rss')
@login_required
def api_updater_rss():
    channel = normalize_routeros_channel(request.args.get('channel', 'stable'))
    if not channel:
        return jsonify({'status': 'error', 'message': 'Neplatný RouterOS kanál.'}), 400
    data = fetch_mikrotik_channel_feed(channel)
    if data:
        return jsonify({'status': 'success', 'data': data, 'channel': channel})
    return jsonify({'status': 'error', 'message': f'Nepodarilo sa načítať kanál {channel}.'}), 500


@app.route('/api/updater/changelog-history')
@login_required
def api_updater_changelog_history():
    channel = normalize_routeros_channel(request.args.get('channel', 'stable'))
    if not channel:
        return jsonify({'status': 'error', 'message': 'Neplatný RouterOS kanál.'}), 400
    major_versions = get_managed_routeros_major_versions()
    items = [
        item for item in fetch_mikrotik_changelog_history(channel)
        if int(item['version'].split('.', 1)[0]) in major_versions
    ]
    return jsonify({
        'status': 'success',
        'items': items,
        'major_versions': major_versions,
        'channel': channel
    })


@app.route('/api/updater/changelog/<version>')
@login_required
def api_updater_changelog_detail(version):
    channel = normalize_routeros_channel(request.args.get('channel', 'stable'))
    if not channel:
        return jsonify({'status': 'error', 'message': 'Neplatný RouterOS kanál.'}), 400
    if not is_valid_routeros_version(version):
        return jsonify({'status': 'error', 'message': 'Neplatná verzia RouterOS.'}), 400

    data = fetch_mikrotik_changelog_detail(version, channel)
    if not data:
        return jsonify({'status': 'error', 'message': 'Changelog sa nepodarilo načítať.'}), 502
    return jsonify({'status': 'success', 'data': data})

@app.route('/api/updater/ping/<int:device_id>')
@login_required
def api_updater_ping(device_id):
    """Rýchla kontrola dostupnosti zariadenia pre polling počas full-update procesu."""
    with get_db_connection() as conn:
        device = conn.execute('SELECT * FROM devices WHERE id = ? AND deleted_at IS NULL', (device_id,)).fetchone()
    if not device:
        return jsonify({'status': 'error', 'message': 'Zariadenie nenájdené.'}), 404

    device_dec = get_device_with_decrypted_password(dict(device))
    ip = device_dec['ip']
    username = device_dec['username']
    password = device_dec['password']
    http_port, https_port = get_updater_web_ports(device=device_dec)

    for scheme in ['https', 'http']:
        try:
            r = requests.get(
                routeros_rest_url(scheme, ip, 'system/identity', http_port, https_port),
                auth=(username, password),
                verify=False,
                timeout=2
            )
            if r.status_code == 200:
                return jsonify({'status': 'online'})
        except Exception:
            if scheme == 'https':
                continue
            break

    return jsonify({'status': 'offline'})

@app.route('/api/updater/schedules', methods=['GET'])
@login_required
def api_updater_schedules():
    """Vráti všetky naplánované updaty s info o zariadení."""
    with get_db_connection() as conn:
        rows = conn.execute('''
            SELECT us.id, us.device_id, us.scheduled_time, us.status,
                   us.created_at, us.started_at, us.completed_at, us.result_message,
                   us.bulk_group_id, us.update_channel,
                   d.name AS device_name, d.ip AS device_ip, d.site_id,
                   COALESCE(s.name, 'Bez lokality') AS site_name
            FROM update_schedule us
            JOIN devices d ON d.id = us.device_id AND d.deleted_at IS NULL
            LEFT JOIN sites s ON s.id = d.site_id
            ORDER BY us.scheduled_time DESC
        ''').fetchall()
        result = [dict(r) for r in rows]

    # Determine which bulk groups are still "active":
    # A group is active if it has a 'running' entry, OR if it has both a finished
    # entry ('done'/'failed'/'cancelled') AND a still-pending entry (= delay between devices).
    from collections import defaultdict
    group_statuses = defaultdict(set)
    for r in result:
        gid = r.get('bulk_group_id')
        if gid:
            group_statuses[gid].add(r['status'])

    # A group counts as "between devices" only if a device actually ran (done/failed),
    # not if it was merely cancelled by the user before running started.
    RAN_STATUSES = {'done', 'failed', 'completed', 'running'}
    active_groups = set()
    for gid, statuses in group_statuses.items():
        if 'pending' in statuses and (statuses & RAN_STATUSES):
            # Running now, OR previous device finished and next is still pending
            active_groups.add(gid)

    for r in result:
        gid = r.get('bulk_group_id')
        r['bulk_group_active'] = bool(gid and gid in active_groups)

    return jsonify(result)

@app.route('/api/updater/schedule/<int:device_id>', methods=['POST'])
@login_required
def api_updater_schedule_create(device_id):
    """Vytvorí nový naplánovaný update pre zariadenie."""
    with get_db_connection() as conn:
        device = conn.execute('SELECT id, name FROM devices WHERE id = ? AND deleted_at IS NULL', (device_id,)).fetchone()
    if not device:
        return jsonify({'status': 'error', 'message': 'Zariadenie nenájdené.'}), 404
    data = request.get_json(silent=True) or {}
    scheduled_time_str = data.get('scheduled_time', '')
    bulk_group_id = data.get('bulk_group_id', None)
    bulk_sequence = data.get('bulk_sequence', 0)
    requested_channel = normalize_routeros_channel(data.get('channel', 'stable'))
    if not requested_channel:
        return jsonify({'status': 'error', 'message': 'Neplatný RouterOS kanál.'}), 400
    update_channel, _ = get_device_update_channel(device_id, requested_channel)
    try:
        scheduled_time = datetime.fromisoformat(scheduled_time_str)
    except (ValueError, TypeError):
        return jsonify({'status': 'error', 'message': 'Neplatný formát dátumu a času.'}), 400
    if scheduled_time <= datetime.now():
        return jsonify({'status': 'error', 'message': 'Čas musí byť v budúcnosti.'}), 400
    with get_db_connection() as conn:
        cursor = conn.execute(
            'INSERT INTO update_schedule (device_id, scheduled_time, status, created_at, bulk_group_id, bulk_sequence, update_channel) VALUES (?, ?, ?, ?, ?, ?, ?)',
            (device_id, scheduled_time, 'pending', datetime.now(), bulk_group_id, bulk_sequence, update_channel)
        )
        new_id = cursor.lastrowid
        conn.commit()
    add_log('info', f"Naplánovaný update zariadenia {device['name']}: {scheduled_time.strftime('%d.%m.%Y %H:%M')} (kanál {update_channel})")
    return jsonify({'status': 'success', 'id': new_id})


@app.route('/api/updater/schedule/bulk', methods=['POST'])
@login_required
def api_updater_schedule_bulk():
    """Vytvorí paralelné site fronty, sekvenčné v rámci každej lokality."""
    data = request.get_json(silent=True) or {}
    try:
        device_ids = list(dict.fromkeys(int(value) for value in data.get('device_ids', [])))
    except (TypeError, ValueError):
        return jsonify({'status': 'error', 'message': 'Neplatné ID zariadení.'}), 400
    scheduled_time_str = data.get('scheduled_time', '')
    requested_channel = normalize_routeros_channel(data.get('channel', 'stable'))
    if not requested_channel:
        return jsonify({'status': 'error', 'message': 'Neplatný RouterOS kanál.'}), 400
    if not device_ids:
        return jsonify({'status': 'error', 'message': 'Žiadne zariadenia.'}), 400
    try:
        scheduled_time = datetime.fromisoformat(scheduled_time_str)
    except (ValueError, TypeError):
        return jsonify({'status': 'error', 'message': 'Neplatný formát dátumu a času.'}), 400
    if scheduled_time <= datetime.now():
        return jsonify({'status': 'error', 'message': 'Čas musí byť v budúcnosti.'}), 400

    import uuid
    created_ids = []
    response_groups = []
    with get_db_connection() as conn:
        site_groups = _partition_devices_by_site(conn, device_ids)
        if sum(len(group['devices']) for group in site_groups) != len(device_ids):
            return jsonify({'status': 'error', 'message': 'Niektoré zariadenia neexistujú alebo sú v koši.'}), 400
        for site_group in site_groups:
            bulk_group_id = str(uuid.uuid4())
            group_ids = []
            for seq, device in enumerate(site_group['devices']):
                update_channel = normalize_routeros_channel(device['routeros_update_channel']) or requested_channel
                cursor = conn.execute(
                    'INSERT INTO update_schedule (device_id, scheduled_time, status, created_at, bulk_group_id, bulk_sequence, update_channel) VALUES (?, ?, ?, ?, ?, ?, ?)',
                    (device['id'], scheduled_time, 'pending', datetime.now(), bulk_group_id, seq, update_channel)
                )
                created_ids.append(cursor.lastrowid)
                group_ids.append(cursor.lastrowid)
            response_groups.append({
                'bulk_group_id': bulk_group_id,
                'site_id': site_group['site_id'],
                'site_name': site_group['site_name'],
                'schedule_ids': group_ids,
                'device_ids': [device['id'] for device in site_group['devices']]
            })
        conn.commit()
    add_log('info', f"Naplánovaný update: {len(created_ids)} zariadení v {len(response_groups)} paralelných site frontách.")
    response = {'status': 'success', 'ids': created_ids, 'groups': response_groups}
    if len(response_groups) == 1:
        response['bulk_group_id'] = response_groups[0]['bulk_group_id']
    return jsonify(response)

@app.route('/api/updater/schedule/<int:schedule_id>', methods=['DELETE'])
@login_required
def api_updater_schedule_delete(schedule_id):
    """Zruší pending naplánovaný update."""
    with get_db_connection() as conn:
        row = conn.execute(
            'SELECT us.id, us.status, d.name FROM update_schedule us JOIN devices d ON d.id = us.device_id AND d.deleted_at IS NULL WHERE us.id = ?',
            (schedule_id,)
        ).fetchone()
    if not row:
        return jsonify({'status': 'error', 'message': 'Plán nenájdený.'}), 404
    if row['status'] not in ('pending',):
        return jsonify({'status': 'error', 'message': 'Zrušiť možno iba čakajúce plány.'}), 400
    with get_db_connection() as conn:
        conn.execute(
            "UPDATE update_schedule SET status='cancelled', completed_at=? WHERE id=?",
            (datetime.now(), schedule_id)
        )
        conn.commit()
    add_log('info', f"Naplánovaný update zariadenia {row['name']} zrušený.")
    return jsonify({'status': 'success'})

@app.route('/api/updater/device/<int:device_id>')
@login_required
def api_updater_device(device_id):
    requested_channel = normalize_routeros_channel(request.args.get('channel', 'stable'))
    if not requested_channel:
        return jsonify({'status': 'error', 'message': 'Neplatný RouterOS kanál.'}), 400
    with get_db_connection() as conn:
        device = conn.execute('SELECT * FROM devices WHERE id = ? AND deleted_at IS NULL', (device_id,)).fetchone()
        settings = {row['key']: row['value'] for row in conn.execute('SELECT key, value FROM settings').fetchall()}
    if not device:
        return jsonify({'status': 'error', 'message': 'Zariadenie nenájdené.'}), 404
    channel_override = normalize_routeros_channel(dict(device).get('routeros_update_channel'))
    channel = channel_override or requested_channel
    # OS Version Check
    os_data, err, code = check_routeros_updates(device_id, channel)
    if err: return jsonify(err), code
    
    os_info = {}
    if isinstance(os_data, list) and len(os_data) > 0:
        os_info = os_data[-1]
    elif isinstance(os_data, dict):
        os_info = os_data
        
    # Firmware Version Check
    fw_data, err2, code2 = mk_api(device_id, 'GET', 'system/routerboard')
    fw_info = {}
    if not err2:
        if isinstance(fw_data, list) and len(fw_data) > 0:
            fw_info = fw_data[0]
        elif isinstance(fw_data, dict):
            fw_info = fw_data
    
    # Kontrola HTTPS dostupnosti (či zariadenie má platný certifikát)
    ssl_ok = False
    cert_expiry = None
    http_port, https_port = get_updater_web_ports(settings, device)
    if device:
        device_dec = get_device_with_decrypted_password(dict(device))
        try:
            requests.get(routeros_rest_url('https', device_dec['ip'], 'system/identity', https_port=https_port),
                        auth=(device_dec['username'], device_dec['password']),
                        verify=False, timeout=3)
            ssl_ok = True
        except Exception:
            pass

        # Načítanie platnosti certifikátu cez HTTP (konzistentné s cert flow)
        try:
            r = requests.get(
                routeros_rest_url('http', device_dec['ip'], 'certificate', http_port=http_port),
                params={'name': 'WebCert'},
                auth=(device_dec['username'], device_dec['password']),
                timeout=5
            )
            if r.status_code == 200:
                certs = r.json()
                if isinstance(certs, list) and len(certs) > 0:
                    invalid_after = certs[0].get('invalid-after')
                    if invalid_after:
                        expiry_dt = parse_mikrotik_date(invalid_after)
                        if expiry_dt:
                            days_remaining = -(-int((expiry_dt - datetime.now()).total_seconds()) // 86400)
                            cert_expiry = {
                                'days_remaining': days_remaining,
                                'invalid_after': invalid_after
                            }
        except Exception:
            pass

    
    # Pridanie dynamických nastavení z databázy
    cert_expiry_warning_days = parse_int_setting(settings.get('cert_expiry_warning_days'), 10, 1, 365)
    cert_auto_renewal_days = parse_int_setting(settings.get('cert_auto_renewal_days'), 180, 1, 3650)

    if device and dict(device).get('cert_auto_renewal_days'):
        final_cert_days = int(dict(device)['cert_auto_renewal_days'])
        is_custom_cert_days = True
    else:
        final_cert_days = cert_auto_renewal_days
        is_custom_cert_days = False

    os_relation = _version_relation(
        os_info.get('installed-version'), os_info.get('latest-version')
    )
    fw_relation = _version_relation(
        fw_info.get('current-firmware'), fw_info.get('upgrade-firmware')
    )
    try:
        snmp_info = json.loads(device['last_snmp_data'] or '{}')
        dashboard_board_name = str(snmp_info.get('board_name') or 'N/A')
    except (TypeError, ValueError, json.JSONDecodeError):
        dashboard_board_name = 'N/A'

    return jsonify({
        'status': 'success',
        'ssl_ok': ssl_ok,
        'cert_expiry': cert_expiry,
        'cert_auto_renewal_days': final_cert_days,
        'is_custom_cert_days': is_custom_cert_days,
        'cert_expiry_warning_days': cert_expiry_warning_days,
        'cert_www_port': http_port,
        'cert_www_ssl_port': https_port,
        'update_channel_override': channel_override,
        'effective_update_channel': channel,
        'os': {
            'installed-version': os_info.get('installed-version', 'N/A'),
            'latest-version': os_info.get('latest-version', 'N/A'),
            'status': os_info.get('status', 'N/A'),
            'channel': os_info.get('channel', channel),
            'update-available': os_relation is not None and os_relation < 0,
            'offered-version-older': os_relation is not None and os_relation > 0
        },
        'firmware': {
            'current-firmware': fw_info.get('current-firmware', 'N/A'),
            'upgrade-firmware': fw_info.get('upgrade-firmware', 'N/A'),
            'model': fw_info.get('model', 'N/A'),
            'board-name': fw_info.get('board-name', 'N/A'),
            'display-model': dashboard_board_name,
            'update-available': fw_relation is not None and fw_relation < 0,
            'offered-version-older': fw_relation is not None and fw_relation > 0
        }
    })


@app.route('/api/updater/device/<int:device_id>/channel', methods=['POST'])
@login_required
def api_updater_device_channel(device_id):
    """Uloží alebo zruší individuálny RouterOS kanál a aplikuje ho na zariadenie."""
    payload = request.get_json(silent=True) or {}
    global_channel = normalize_routeros_channel(payload.get('global_channel', 'stable'))
    if not global_channel:
        return jsonify({'status': 'error', 'message': 'Neplatný globálny RouterOS kanál.'}), 400

    raw_channel = payload.get('channel')
    channel_override = None if raw_channel in (None, '', 'global') else normalize_routeros_channel(raw_channel)
    if raw_channel not in (None, '', 'global') and not channel_override:
        return jsonify({'status': 'error', 'message': 'Neplatný RouterOS kanál.'}), 400

    with get_db_connection() as conn:
        device = conn.execute(
            'SELECT id, name, ip FROM devices WHERE id = ? AND deleted_at IS NULL',
            (device_id,)
        ).fetchone()
        if not device:
            return jsonify({'status': 'error', 'message': 'Zariadenie nenájdené.'}), 404
        conn.execute(
            'UPDATE devices SET routeros_update_channel = ? WHERE id = ? AND deleted_at IS NULL',
            (channel_override, device_id)
        )
        conn.commit()

    effective_channel = channel_override or global_channel
    _, err, code = set_routeros_update_channel(device_id, effective_channel)
    mode = 'individuálny' if channel_override else 'globálny'
    add_log(
        'info' if not err else 'warning',
        f"RouterOS kanál pre {device['name']}: {effective_channel} ({mode}).",
        device_ip=device['ip']
    )
    if err:
        return jsonify({
            'status': 'warning',
            'message': 'Nastavenie sa uložilo, ale zariadenie je momentálne nedostupné. Kanál sa aplikuje pri najbližšej kontrole.',
            'channel': effective_channel,
            'channel_override': channel_override
        }), 202
    return jsonify({
        'status': 'success',
        'message': f'Kanál zariadenia bol nastavený na {effective_channel}.',
        'channel': effective_channel,
        'channel_override': channel_override
    })


@app.route('/api/updater/install-os/<int:device_id>', methods=['POST'])
@login_required
def api_updater_install_os(device_id):
    payload = request.get_json(silent=True) or {}
    requested_channel = normalize_routeros_channel(payload.get('channel', 'stable'))
    if not requested_channel:
        return jsonify({'status': 'error', 'message': 'Neplatný RouterOS kanál.'}), 400
    channel, _ = get_device_update_channel(device_id, requested_channel)
    _, err, code = set_routeros_update_channel(device_id, channel)
    if err:
        return jsonify(err), code
    data, err, code = mk_api(device_id, 'POST', 'system/package/update/install')
    # 500 = connection error – device started updating and rebooted before responding
    if err and code != 500:
        return jsonify(err), code
    with get_db_connection() as conn:
        device = conn.execute('SELECT ip FROM devices WHERE id = ? AND deleted_at IS NULL', (device_id,)).fetchone()
    if device:
        add_log('INFO', 'Spustená aktualizácia RouterOS.', device_ip=device['ip'])
    
    return jsonify({'status': 'success', 'message': 'Aktualizácia OS spustená. Zariadenie sa reštartuje.'})

@app.route('/api/updater/install-firmware/<int:device_id>', methods=['POST'])
@login_required
def api_updater_install_firmware(device_id):
    data, err, code = mk_api(device_id, 'POST', 'system/routerboard/upgrade')
    if err: return jsonify(err), code
    
    with get_db_connection() as conn:
        device = conn.execute('SELECT ip FROM devices WHERE id = ? AND deleted_at IS NULL', (device_id,)).fetchone()
    if device:
        add_log('INFO', 'Správa o upgrade firmvéru odoslaná, čaká sa na ručný reštart.', device_ip=device['ip'])
        
    return jsonify({'status': 'success', 'message': 'Firmware upgrade pripravený v pamäti. Následne vykonajte reštart.'})

@app.route('/api/updater/reboot/<int:device_id>', methods=['POST'])
@login_required
def api_updater_reboot(device_id):
    data, err, code = mk_api(device_id, 'POST', 'system/reboot')
    # 4xx = device rejected the command (real error)
    # 500 = connection error – device started rebooting before responding, treat as success
    if err and code != 500:
        return jsonify(err), code

    with get_db_connection() as conn:
        device = conn.execute('SELECT ip FROM devices WHERE id = ? AND deleted_at IS NULL', (device_id,)).fetchone()
    if device:
        add_log('INFO', 'Príkaz na reštart úspešne odoslaný.', device_ip=device['ip'])

    return jsonify({'status': 'success', 'message': 'Príkaz na reštart úspešne odoslaný.'})

@app.route('/api/updater/certificate/<int:device_id>', methods=['POST'])
@login_required
def api_updater_certificate(device_id):
    data = request.json or {}
    days = data.get('days', 180)

    logger.info(f"[{device_id}] Starting SSL certificate regeneration for {days} days.")

    with get_db_connection() as conn:
        device = conn.execute('SELECT * FROM devices WHERE id = ? AND deleted_at IS NULL', (device_id,)).fetchone()
    if not device:
        return jsonify({'status': 'error', 'message': 'Zariadenie nenájdené.'}), 404

    device_dec = get_device_with_decrypted_password(dict(device))
    ip = device_dec['ip']
    username = device_dec['username']
    password = device_dec['password']
    http_port, _ = get_updater_web_ports(device=device_dec)

    success, message = _do_renew_certificate(
        ip,
        username,
        password,
        days,
        http_port=http_port,
        low_memory=bool(device_dec.get('low_memory'))
    )

    if success:
        add_log('info', f'Nový TLS certifikát vygenerovaný ({days} dní) a aplikovaný na www-ssl.', device_ip=ip)
        return jsonify({'status': 'success', 'message': message})
    else:
        add_log('error', f'Chyba pri vytváraní TLS certifikátu: {message}', device_ip=ip)
        send_pushover_notification(
            f'⚠️ Chyba pri vytváraní TLS certifikátu na {ip}: {message}',
            title='MikroTik – Chyba TLS certifikátu',
            notification_key='notify_cert_expiry'
        )
        return jsonify({'status': 'error', 'message': message}), 500


@app.route('/api/updater/certificate/save_settings/<int:device_id>', methods=['POST'])
@login_required
def api_updater_certificate_save_settings(device_id):
    data = request.json or {}
    days = data.get('days', 180)
    save_for_device = data.get('save_for_device', False)

    with get_db_connection() as conn:
        device = conn.execute('SELECT * FROM devices WHERE id = ? AND deleted_at IS NULL', (device_id,)).fetchone()
        if not device:
            return jsonify({'status': 'error', 'message': 'Zariadenie nenájdené.'}), 404
        
        if save_for_device:
            conn.execute('UPDATE devices SET cert_auto_renewal_days = ? WHERE id = ? AND deleted_at IS NULL', (days, device_id))
        else:
            conn.execute('UPDATE devices SET cert_auto_renewal_days = NULL WHERE id = ? AND deleted_at IS NULL', (device_id,))
        conn.commit()

    return jsonify({'status': 'success', 'message': 'Nastavenia uložené.'})


@app.route('/api/updater/run-update/<int:device_id>', methods=['POST'])
@login_required
def api_updater_run_update(device_id):
    """Spustí manuálny full update zariadenia ako server-side daemon thread."""
    payload = request.get_json(silent=True) or {}
    requested_channel = normalize_routeros_channel(payload.get('channel', 'stable'))
    if not requested_channel:
        return jsonify({'status': 'error', 'message': 'Neplatný RouterOS kanál.'}), 400
    channel, _ = get_device_update_channel(device_id, requested_channel)
    with get_db_connection() as conn:
        device = conn.execute('SELECT id, name FROM devices WHERE id = ? AND deleted_at IS NULL', (device_id,)).fetchone()
    if not device:
        return jsonify({'status': 'error', 'message': 'Zariadenie nenájdené.'}), 404
    owner = f'manual:{device_id}:{secrets.token_hex(8)}'
    reserved, _ = _reserve_update_devices([device_id], owner)
    if not reserved:
        return jsonify({'status': 'error', 'message': 'Aktualizácia pre toto zariadenie už prebieha.'}), 409
    threading.Thread(target=run_device_update, args=(device_id, channel, owner), daemon=True).start()
    return jsonify({'status': 'success', 'message': 'Aktualizácia spustená.'})


@app.route('/api/updater/run-update-os/<int:device_id>', methods=['POST'])
@login_required
def api_updater_run_update_os(device_id):
    """Spustí manuálny RouterOS-only update (kroky 1–5) ako server-side daemon thread."""
    payload = request.get_json(silent=True) or {}
    requested_channel = normalize_routeros_channel(payload.get('channel', 'stable'))
    if not requested_channel:
        return jsonify({'status': 'error', 'message': 'Neplatný RouterOS kanál.'}), 400
    channel, _ = get_device_update_channel(device_id, requested_channel)
    with get_db_connection() as conn:
        device = conn.execute('SELECT id, name FROM devices WHERE id = ? AND deleted_at IS NULL', (device_id,)).fetchone()
    if not device:
        return jsonify({'status': 'error', 'message': 'Zariadenie nenájdené.'}), 404
    owner = f'manual-os:{device_id}:{secrets.token_hex(8)}'
    reserved, _ = _reserve_update_devices([device_id], owner)
    if not reserved:
        return jsonify({'status': 'error', 'message': 'Aktualizácia pre toto zariadenie už prebieha.'}), 409
    threading.Thread(target=run_device_update_os, args=(device_id, channel, owner), daemon=True).start()
    return jsonify({'status': 'success', 'message': 'Aktualizácia RouterOS spustená.'})


@app.route('/api/updater/run-update-firmware/<int:device_id>', methods=['POST'])
@login_required
def api_updater_run_update_firmware(device_id):
    """Spustí manuálny Firmware-only update (kroky 1–5) ako server-side daemon thread."""
    with get_db_connection() as conn:
        device = conn.execute('SELECT id, name FROM devices WHERE id = ? AND deleted_at IS NULL', (device_id,)).fetchone()
    if not device:
        return jsonify({'status': 'error', 'message': 'Zariadenie nenájdené.'}), 404
    owner = f'manual-fw:{device_id}:{secrets.token_hex(8)}'
    reserved, _ = _reserve_update_devices([device_id], owner)
    if not reserved:
        return jsonify({'status': 'error', 'message': 'Aktualizácia pre toto zariadenie už prebieha.'}), 409
    threading.Thread(target=run_device_update_firmware, args=(device_id, owner), daemon=True).start()
    return jsonify({'status': 'success', 'message': 'Aktualizácia Firmware spustená.'})


@app.route('/api/updater/running-updates')
@login_required
def api_updater_running_updates():
    """Vráti zoznam manuálnych aktualizácií práve prebehajúcich na serveri (pre obnovu UI po F5)."""
    result = []
    for dev_id, info in list(_running_manual_updates.items()):
        result.append({
            'device_id': dev_id,
            'device_name': info.get('device_name', ''),
            'current_step': info.get('current_step', 0),
            'steps_done': info.get('steps_done', []),
            'current_msg': info.get('current_msg', ''),
            'started_at': info.get('started_at', ''),
            'update_type': info.get('update_type', 'full'),
            'channel': info.get('channel', 'stable')
        })
    return jsonify({'running': result})


@app.route('/api/updater/running-scheduled-updates')
@login_required
def api_updater_running_scheduled_updates():
    """Vráti zoznam naplánovaných aktualizácií práve bežiacich na serveri (pre obnovu UI po F5)."""
    result = []
    for dev_id, info in list(_running_scheduled_updates.items()):
        result.append({
            'device_id': dev_id,
            'device_name': info.get('device_name', ''),
            'schedule_id': info.get('schedule_id', 0),
            'current_step': info.get('current_step', 0),
            'steps_done': info.get('steps_done', []),
            'current_msg': info.get('current_msg', ''),
            'started_at': info.get('started_at', ''),
            'update_type': info.get('update_type', 'full'),
            'channel': info.get('channel', 'stable')
        })
    return jsonify({'running': result})


@app.route('/api/updater/run-bulk-update', methods=['POST'])
@login_required
def api_updater_run_bulk_update():
    """Spustí jednu sekvenčnú frontu na lokalitu; lokality bežia paralelne."""
    import uuid
    data = request.json or {}
    channel = normalize_routeros_channel(data.get('channel', 'stable'))
    if not channel:
        return jsonify({'status': 'error', 'message': 'Neplatný RouterOS kanál.'}), 400
    try:
        device_ids = [int(x) for x in data.get('device_ids', [])]
    except (TypeError, ValueError):
        return jsonify({'status': 'error', 'message': 'Neplatné ID zariadení.'}), 400
    if not device_ids:
        return jsonify({'status': 'error', 'message': 'Žiadne zariadenia.'}), 400
    device_ids = list(dict.fromkeys(device_ids))
    with get_db_connection() as conn:
        site_groups = _partition_devices_by_site(conn, device_ids)
    if sum(len(group['devices']) for group in site_groups) != len(device_ids):
        return jsonify({'status': 'error', 'message': 'Niektoré zariadenia neexistujú alebo sú v koši.'}), 400

    reservations = []
    for group in site_groups:
        group['bulk_group_id'] = str(uuid.uuid4())
        ids = [device['id'] for device in group['devices']]
        reserved, busy = _reserve_update_devices(ids, group['bulk_group_id'])
        if not reserved:
            for reserved_ids, owner in reservations:
                _release_update_devices(reserved_ids, owner)
            return jsonify({
                'status': 'error',
                'message': f'Niektoré zariadenia sa už aktualizujú: {", ".join(map(str, busy))}.'
            }), 409
        reservations.append((ids, group['bulk_group_id']))

    response_groups = []
    for group in site_groups:
        ids = [device['id'] for device in group['devices']]
        bulk_group_id = group['bulk_group_id']
        _manual_bulk_groups[bulk_group_id] = {
            'device_ids': ids,
            'remaining_ids': ids[1:],
            'current_device_id': ids[0],
            'channel': channel,
            'site_id': group['site_id'],
            'site_name': group['site_name'],
            'cancelled_ids': set()
        }
        response_groups.append({
            'bulk_group_id': bulk_group_id,
            'site_id': group['site_id'],
            'site_name': group['site_name'],
            'current_device_id': ids[0],
            'remaining_ids': ids[1:]
        })
        threading.Thread(target=run_manual_bulk_update, args=(ids, bulk_group_id, channel), daemon=True).start()

    response = {
        'status': 'success',
        'groups': response_groups,
        'queued_ids': [device_id for group in response_groups for device_id in group['remaining_ids']]
    }
    if len(response_groups) == 1:
        response['bulk_group_id'] = response_groups[0]['bulk_group_id']
    return jsonify(response)


@app.route('/api/updater/running-bulk-queue')
@login_required
def api_updater_running_bulk_queue():
    """Vráti čakajúce zariadenia v manuálnych hromadných skupinách (pre obnovu ⟳ Čaká... po F5)."""
    groups = []
    for group_id, group in list(_manual_bulk_groups.items()):
        groups.append({
            'bulk_group_id': group_id,
            'remaining_ids': list(group.get('remaining_ids', [])),
            'current_device_id': group.get('current_device_id'),
            'channel': group.get('channel', 'stable'),
            'site_id': group.get('site_id'),
            'site_name': group.get('site_name', 'Bez lokality')
        })
    return jsonify({'groups': groups})


@app.route('/api/updater/bulk-cancel/<int:device_id>', methods=['DELETE'])
@login_required
def api_updater_bulk_cancel(device_id):
    """Zruší čakajúce zariadenie z manuálnej hromadnej bulk fronty."""
    for group_id, group in list(_manual_bulk_groups.items()):
        remaining = group.get('remaining_ids', [])
        if device_id in remaining:
            group.setdefault('cancelled_ids', set()).add(device_id)
            group['remaining_ids'] = [d for d in remaining if d != device_id]
            _release_update_devices([device_id], group_id)
            return jsonify({'status': 'success', 'device_id': device_id})
    return jsonify({'status': 'error', 'message': 'Zariadenie nie je v čakajúcom fronte'}), 404


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
                    code_hash = generate_password_hash(code)
                    conn.execute('INSERT INTO backup_codes (user_id, code, created_at, used) VALUES (?, ?, ?, 0)', 
                               (current_user.id, code_hash, datetime.now()))
                conn.commit()
            
            add_log('info', f"Používateľ '{current_user.username}' vygeneroval nové záložné kódy.")
            return jsonify({'status': 'success', 'backup_codes': backup_codes})
            
        except Exception as e:
            logger.error(f"Chyba pri generovaní záložných kódov: {e}")
            return jsonify({'status': 'error', 'message': 'Chyba pri generovaní záložných kódov.'}), 500

@app.route('/api/user/reset-2fa', methods=['POST'])
@login_required
def reset_2fa():
    """Reset 2FA - vymaže TOTP secret a záložné kódy, používateľ musí nastaviť 2FA znovu"""
    data = request.json
    password = data.get('password')

    if not password:
        return jsonify({'status': 'error', 'message': 'Heslo je povinné.'}), 400

    with get_db_connection() as conn:
        user_data = conn.execute('SELECT password FROM users WHERE id = ?', (current_user.id,)).fetchone()

    if not user_data or not check_password_hash(user_data['password'], password):
        return jsonify({'status': 'error', 'message': 'Nesprávne heslo.'}), 401

    try:
        new_secret = pyotp.random_base32()
        encrypted_secret = encrypt_password(new_secret)
        with get_db_connection() as conn:
            conn.execute('UPDATE users SET totp_secret = ?, totp_enabled = 0 WHERE id = ?', (encrypted_secret, current_user.id,))
            conn.execute('DELETE FROM backup_codes WHERE user_id = ?', (current_user.id,))
            conn.commit()

        add_log('warning', f"Používateľ '{current_user.username}' resetoval 2FA – vyžaduje nové nastavenie.")
        return jsonify({'status': 'success', 'message': '2FA bolo resetované. Nastavte nové 2FA.'})

    except Exception as e:
        logger.error(f"Chyba pri resete 2FA: {e}")
        return jsonify({'status': 'error', 'message': 'Chyba pri resete 2FA.'}), 500


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

def _validate_site_payload(data):
    """Validate and normalize a site create/update payload."""
    name = str((data or {}).get('name') or '').strip()
    description = str((data or {}).get('description') or '').strip()
    if not name:
        return None, 'Názov lokality je povinný.'
    if len(name) > 100:
        return None, 'Názov lokality môže mať najviac 100 znakov.'
    if len(description) > 500:
        return None, 'Opis lokality môže mať najviac 500 znakov.'
    return {'name': name, 'description': description or None}, None


def _site_name_exists(conn, name, exclude_id=None):
    folded = name.casefold()
    rows = conn.execute('SELECT id, name FROM sites').fetchall()
    return any(
        row['id'] != exclude_id and str(row['name']).casefold() == folded
        for row in rows
    )


def _parse_device_site_id(conn, value):
    """Return a normalized nullable site id, or an API error tuple."""
    if value in (None, '', 'null'):
        return None, None
    try:
        site_id = int(value)
    except (TypeError, ValueError):
        return None, (jsonify({'status': 'error', 'message': 'Neplatná lokalita.'}), 400)
    if site_id <= 0 or not conn.execute('SELECT id FROM sites WHERE id = ?', (site_id,)).fetchone():
        return None, (jsonify({'status': 'error', 'message': 'Lokalita neexistuje.'}), 400)
    return site_id, None


@app.route('/api/sites', methods=['GET', 'POST'])
@login_required
def handle_sites():
    with get_db_connection() as conn:
        if request.method == 'GET':
            rows = conn.execute('''
                SELECT s.id, s.name, s.description,
                       COUNT(CASE WHEN d.deleted_at IS NULL THEN 1 END) AS device_count
                FROM sites s
                LEFT JOIN devices d ON d.site_id = s.id
                GROUP BY s.id, s.name, s.description
                ORDER BY s.name COLLATE NOCASE
            ''').fetchall()
            return jsonify([dict(row) for row in rows])

        payload, error = _validate_site_payload(request.get_json(silent=True) or {})
        if error:
            return jsonify({'status': 'error', 'message': error}), 400
        if _site_name_exists(conn, payload['name']):
            return jsonify({'status': 'error', 'message': 'Lokalita s týmto názvom už existuje.'}), 409
        try:
            cursor = conn.execute(
                'INSERT INTO sites (name, description) VALUES (?, ?)',
                (payload['name'], payload['description'])
            )
            conn.commit()
        except sqlite3.IntegrityError:
            return jsonify({'status': 'error', 'message': 'Lokalita s týmto názvom už existuje.'}), 409
    add_log('info', f"Lokalita '{payload['name']}' bola vytvorená.")
    return jsonify({'status': 'success', 'site': {
        'id': cursor.lastrowid, 'name': payload['name'],
        'description': payload['description'], 'device_count': 0
    }}), 201


@app.route('/api/sites/<int:site_id>', methods=['PUT', 'DELETE'])
@login_required
def handle_site(site_id):
    with get_db_connection() as conn:
        existing = conn.execute('SELECT id, name FROM sites WHERE id = ?', (site_id,)).fetchone()
        if not existing:
            return jsonify({'status': 'error', 'message': 'Lokalita nebola nájdená.'}), 404

        if request.method == 'PUT':
            payload, error = _validate_site_payload(request.get_json(silent=True) or {})
            if error:
                return jsonify({'status': 'error', 'message': error}), 400
            if _site_name_exists(conn, payload['name'], exclude_id=site_id):
                return jsonify({'status': 'error', 'message': 'Lokalita s týmto názvom už existuje.'}), 409
            try:
                conn.execute(
                    'UPDATE sites SET name = ?, description = ? WHERE id = ?',
                    (payload['name'], payload['description'], site_id)
                )
                conn.commit()
            except sqlite3.IntegrityError:
                return jsonify({'status': 'error', 'message': 'Lokalita s týmto názvom už existuje.'}), 409
            old_name = existing['name']
        else:
            unassigned_count = conn.execute(
                'SELECT COUNT(*) FROM devices WHERE site_id = ?', (site_id,)
            ).fetchone()[0]
            conn.execute(
                'UPDATE devices SET site_id = NULL, site_update_order = NULL WHERE site_id = ?',
                (site_id,)
            )
            conn.execute('DELETE FROM sites WHERE id = ?', (site_id,))
            conn.commit()

    if request.method == 'PUT':
        add_log('info', f"Lokalita '{old_name}' bola upravená na '{payload['name']}'.")
        return jsonify({'status': 'success', 'site': {
            'id': site_id, 'name': payload['name'], 'description': payload['description']
        }})

    add_log('warning', f"Lokalita '{existing['name']}' bola zmazaná; {unassigned_count} zariadení je bez lokality.")
    return jsonify({'status': 'success', 'unassigned_device_count': unassigned_count})


@app.route('/api/sites/<int:site_id>/device-order', methods=['GET', 'PUT'])
@login_required
def handle_site_device_order(site_id):
    """Read or atomically replace the dense updater priority within one site."""
    with get_db_connection() as conn:
        site = conn.execute('SELECT id, name FROM sites WHERE id = ?', (site_id,)).fetchone()
        if not site:
            return jsonify({'status': 'error', 'message': 'Lokalita nebola nájdená.'}), 404

        rows = conn.execute('''
            SELECT id, name, ip, site_update_order
            FROM devices
            WHERE site_id = ? AND deleted_at IS NULL
            ORDER BY site_update_order IS NULL, site_update_order, LOWER(name), id
        ''', (site_id,)).fetchall()

        if request.method == 'GET':
            return jsonify({
                'site': {'id': site['id'], 'name': site['name']},
                'devices': [
                    {'id': row['id'], 'name': row['name'], 'ip': row['ip'], 'order': index}
                    for index, row in enumerate(rows, start=1)
                ]
            })

        data = request.get_json(silent=True) or {}
        raw_ids = data.get('device_ids')
        if not isinstance(raw_ids, list):
            return jsonify({'status': 'error', 'message': 'device_ids musí byť zoznam.'}), 400
        try:
            device_ids = [int(device_id) for device_id in raw_ids]
        except (TypeError, ValueError):
            return jsonify({'status': 'error', 'message': 'Poradie obsahuje neplatné ID zariadenia.'}), 400

        current_ids = {row['id'] for row in rows}
        if len(device_ids) != len(set(device_ids)) or set(device_ids) != current_ids:
            return jsonify({
                'status': 'error',
                'message': 'Zoznam musí obsahovať každé aktívne zariadenie lokality práve raz.'
            }), 400

        for order, device_id in enumerate(device_ids, start=1):
            conn.execute(
                'UPDATE devices SET site_update_order = ? WHERE id = ? AND site_id = ? AND deleted_at IS NULL',
                (order, device_id, site_id)
            )
        conn.commit()

    add_log('info', f"Poradie aktualizácií v lokalite '{site['name']}' bolo uložené.")
    return jsonify({'status': 'success', 'device_ids': device_ids})


@app.route('/api/devices', methods=['GET', 'POST'])
@login_required
def handle_devices():
    with get_db_connection() as conn:
        if request.method == 'GET':
            # Include all necessary fields including status and last_snmp_data
            devices = []
            for row in conn.execute('''
                SELECT d.id, d.name, d.name_source, d.site_id, s.name AS site_name,
                       d.ip, d.username, d.low_memory,
                       d.password, d.snmp_community,
                       d.snmp_version, d.snmp_v3_username, d.snmp_v3_security_level,
                       d.snmp_v3_auth_protocol, d.snmp_v3_auth_password,
                       d.snmp_v3_priv_protocol, d.snmp_v3_priv_password,
                       d.snmp_allowed_address, d.snmp_location,
                       d.snmp_interval_minutes, d.ping_interval_seconds,
                       d.ping_retry_interval_seconds, d.cert_www_port,
                       d.cert_www_ssl_port, d.monitoring_paused, d.status,
                       d.last_snmp_data, d.last_backup,
                       k.trusted_host AS ssh_trusted_host,
                       k.trusted_key_type AS ssh_trusted_key_type,
                       k.trusted_fingerprint AS ssh_trusted_fingerprint,
                       k.trusted_at AS ssh_trusted_at,
                       k.pending_key_type AS ssh_pending_key_type,
                       k.pending_fingerprint AS ssh_pending_fingerprint,
                       k.pending_detected_at AS ssh_pending_detected_at
                FROM devices d
                LEFT JOIN sites s ON s.id = d.site_id
                LEFT JOIN ssh_host_keys k ON k.device_id = d.id
                WHERE d.deleted_at IS NULL
                ORDER BY LOWER(d.name)
            ''').fetchall():
                device = dict(row)
                for secret_field, api_prefix in (
                    ('password', 'password'),
                    ('snmp_community', 'snmp_community'),
                    ('snmp_v3_auth_password', 'snmp_v3_auth_password'),
                    ('snmp_v3_priv_password', 'snmp_v3_priv_password'),
                ):
                    encrypted_value = device.pop(secret_field, None)
                    device[f'{api_prefix}_configured'] = bool(encrypted_value)
                    try:
                        device[f'{api_prefix}_length'] = len(decrypt_password_strict(encrypted_value)) if encrypted_value else 0
                    except Exception:
                        device[f'{api_prefix}_length'] = 0
                trusted_for_current_ip = bool(device.get('ssh_trusted_fingerprint')) and (
                    device.get('ssh_trusted_host') == device['ip']
                )
                if device.get('ssh_pending_fingerprint'):
                    device['ssh_host_key_status'] = 'changed' if trusted_for_current_ip else 'pending'
                elif trusted_for_current_ip:
                    device['ssh_host_key_status'] = 'trusted'
                else:
                    device['ssh_host_key_status'] = 'unverified'
                device.pop('ssh_trusted_host', None)
                # Convert last_backup to ISO format with UTC timezone for consistent parsing across browsers
                if device.get('last_backup'):
                    try:
                        # SQLite CURRENT_TIMESTAMP returns UTC time in format '2026-02-15 12:22:02'
                        dt = datetime.fromisoformat(device['last_backup'].replace(' ', 'T'))
                        # Mark as UTC by adding timezone info
                        device['last_backup'] = dt.replace(tzinfo=timezone.utc).isoformat()
                    except:
                        pass  # Keep original value if conversion fails
                devices.append(device)
            return jsonify(devices)
        if request.method == 'POST':
            data = request.json or {}

            site_id, site_error = _parse_device_site_id(conn, data.get('site_id'))
            if site_error:
                return site_error

            def parse_device_port_override(key, label):
                raw_value = data.get(key, 0)
                if raw_value in (None, ''):
                    raw_value = 0
                try:
                    port = int(raw_value)
                except (ValueError, TypeError):
                    return None, jsonify({'status': 'error', 'message': f'Neplatná hodnota pre {label}'}), 400
                if port < 0 or port > 65535:
                    return None, jsonify({'status': 'error', 'message': f'{label} musí byť 0 (globálne) alebo 1-65535'}), 400
                return port, None, None

            new_cert_www_port, error_response, error_code = parse_device_port_override('cert_www_port', 'Port služby www (HTTP)')
            if error_response:
                return error_response, error_code
            new_cert_www_ssl_port, error_response, error_code = parse_device_port_override('cert_www_ssl_port', 'Port služby www-ssl (HTTPS)')
            if error_response:
                return error_response, error_code

            try:
                if data.get('id'):
                    # Získame staré nastavenia pre detekciu zmien intervalov
                    old_device = conn.execute('SELECT * FROM devices WHERE id = ? AND deleted_at IS NULL', (data['id'],)).fetchone()
                    if not old_device:
                        return jsonify({'status': 'error', 'message': 'Zariadenie nenájdené'}), 404
                    # Preserve the assignment for older API clients that do not
                    # know about sites yet. An explicit null still unassigns it.
                    if 'site_id' not in data:
                        site_id = old_device['site_id']
                    site_changed = site_id != old_device['site_id']
                    old_ip = old_device['ip']
                    ip_changed = old_ip != data['ip']
                    old_snmp_interval = old_device['snmp_interval_minutes'] if old_device else 0
                    old_ping_interval = old_device['ping_interval_seconds'] if old_device else 0
                    old_ping_retry_interval = old_device['ping_retry_interval_seconds'] if old_device else 0
                    old_cert_www_port = old_device['cert_www_port'] if old_device else 0
                    old_cert_www_ssl_port = old_device['cert_www_ssl_port'] if old_device else 0
                    new_snmp_interval = data.get('snmp_interval_minutes', 0)
                    new_ping_interval = data.get('ping_interval_seconds', 0)
                    new_ping_retry_interval = data.get('ping_retry_interval_seconds', 0)
                    new_snmp_location = str(data.get('snmp_location', old_device['snmp_location'] or '') or '').strip()
                    if len(new_snmp_location) > 255:
                        return jsonify({'status': 'error', 'message': 'SNMP Location môže mať najviac 255 znakov.'}), 400
                    snmp_config, snmp_error = merge_device_snmp_config(data, old_device)
                    if snmp_error:
                        return jsonify({'status': 'error', 'message': snmp_error}), 400
                    old_snmp_config, _ = validate_snmp_config(
                        get_device_with_decrypted_password(dict(old_device)), require_secrets=True
                    )
                    snmp_config_changed = old_snmp_config != snmp_config
                    snmp_secrets = encrypted_snmp_values(snmp_config)
                    
                    # Pri editácii zachováme pôvodné heslo ak nie je zadané nové
                    # Názov je voliteľný: frontend sa ho pokúsi načítať zo SNMP
                    # sysName (MikroTik Identity), IP je bezpečný posledný fallback.
                    submitted_name = str(data.get('name') or '').strip()
                    device_name = submitted_name or str(data.get('ip') or '').strip()
                    requested_name_source = str(data.get('name_source') or '').strip()
                    if not submitted_name:
                        device_name_source = 'local'
                    elif requested_name_source in {'local', 'snmp'}:
                        device_name_source = requested_name_source
                    else:
                        device_name_source = old_device['name_source'] or 'local'
                    if data.get('password'):
                        # Ak je zadané nové heslo, aktualizujeme všetko vrátane hesla
                        encrypted_password = encrypt_password(data['password'])
                        conn.execute("UPDATE devices SET name=?, name_source=?, site_id=?, ip=?, username=?, password=?, low_memory=?, snmp_community=?, snmp_version=?, snmp_v3_username=?, snmp_v3_security_level=?, snmp_v3_auth_protocol=?, snmp_v3_auth_password=?, snmp_v3_priv_protocol=?, snmp_v3_priv_password=?, snmp_allowed_address=?, snmp_location=?, snmp_interval_minutes=?, ping_interval_seconds=?, ping_retry_interval_seconds=?, cert_www_port=?, cert_www_ssl_port=? WHERE id=? AND deleted_at IS NULL",
                                   (device_name, device_name_source, site_id, data['ip'], data['username'], encrypted_password, data.get('low_memory', False),
                                    snmp_secrets['snmp_community'], snmp_config['snmp_version'], snmp_config['snmp_v3_username'],
                                    snmp_config['snmp_v3_security_level'], snmp_config['snmp_v3_auth_protocol'],
                                    snmp_secrets['snmp_v3_auth_password'], snmp_config['snmp_v3_priv_protocol'],
                                    snmp_secrets['snmp_v3_priv_password'], snmp_config['snmp_allowed_address'] or None,
                                    new_snmp_location or None, new_snmp_interval,
                                    new_ping_interval, new_ping_retry_interval,
                                    new_cert_www_port, new_cert_www_ssl_port, data['id']))
                    else:
                        # Ak heslo nie je zadané, aktualizujeme len ostatné polia
                        conn.execute("UPDATE devices SET name=?, name_source=?, site_id=?, ip=?, username=?, low_memory=?, snmp_community=?, snmp_version=?, snmp_v3_username=?, snmp_v3_security_level=?, snmp_v3_auth_protocol=?, snmp_v3_auth_password=?, snmp_v3_priv_protocol=?, snmp_v3_priv_password=?, snmp_allowed_address=?, snmp_location=?, snmp_interval_minutes=?, ping_interval_seconds=?, ping_retry_interval_seconds=?, cert_www_port=?, cert_www_ssl_port=? WHERE id=? AND deleted_at IS NULL",
                                   (device_name, device_name_source, site_id, data['ip'], data['username'], data.get('low_memory', False),
                                    snmp_secrets['snmp_community'], snmp_config['snmp_version'], snmp_config['snmp_v3_username'],
                                    snmp_config['snmp_v3_security_level'], snmp_config['snmp_v3_auth_protocol'],
                                    snmp_secrets['snmp_v3_auth_password'], snmp_config['snmp_v3_priv_protocol'],
                                    snmp_secrets['snmp_v3_priv_password'], snmp_config['snmp_allowed_address'] or None,
                                    new_snmp_location or None, new_snmp_interval,
                                    new_ping_interval, new_ping_retry_interval,
                                    new_cert_www_port, new_cert_www_ssl_port, data['id']))
                    if site_changed:
                        # V novej lokalite sa zariadenie zaradí na koniec, kým používateľ
                        # explicitne neuloží nové poradie cez správu lokalít.
                        conn.execute('UPDATE devices SET site_update_order = NULL WHERE id = ?', (data['id'],))
                    if ip_changed:
                        # A pinned key belongs to a network endpoint. A new IP must be
                        # explicitly enrolled instead of inheriting the previous pin.
                        conn.execute('DELETE FROM ssh_host_keys WHERE device_id = ?', (data['id'],))
                    conn.commit()

                    backup_migration = None
                    if ip_changed:
                        migration_settings = {
                            row['key']: row['value']
                            for row in conn.execute('SELECT key, value FROM settings').fetchall()
                        }
                        backup_migration = migrate_backups_for_ip_change(old_ip, data['ip'], migration_settings)
                    
                    change_messages = []
                    if ip_changed:
                        change_messages.append(
                            f"IP {old_ip}→{data['ip']}; presunuté zálohy: "
                            f"lokálne {backup_migration['local']}, FTP {backup_migration['ftp']}"
                        )
                        if backup_migration['errors']:
                            add_log(
                                'warning',
                                f"Zmena IP {old_ip}→{data['ip']}: " + '; '.join(backup_migration['errors']),
                                data['ip']
                            )
                    # Okamžitý health check ak sa zmenil SNMP interval zariadenia
                    if old_snmp_interval != new_snmp_interval or snmp_config_changed:
                        device_name = data.get('name', f'ID {data["id"]}')
                        trigger_immediate_health_check(f"zmena SNMP nastavenia zariadenia {device_name}")
                        if old_snmp_interval != new_snmp_interval:
                            change_messages.append(f"SNMP interval {old_snmp_interval}→{new_snmp_interval} min")
                        if snmp_config_changed:
                            change_messages.append(f"SNMP konfigurácia → v{snmp_config['snmp_version']}")
                    if old_ping_interval != new_ping_interval:
                        change_messages.append(f"Ping interval {old_ping_interval}→{new_ping_interval} s")
                    if old_ping_retry_interval != new_ping_retry_interval:
                        change_messages.append(f"Retry interval {old_ping_retry_interval}→{new_ping_retry_interval} s")
                    if old_cert_www_port != new_cert_www_port:
                        change_messages.append(f"www port {old_cert_www_port}→{new_cert_www_port}")
                    if old_cert_www_ssl_port != new_cert_www_ssl_port:
                        change_messages.append(f"www-ssl port {old_cert_www_ssl_port}→{new_cert_www_ssl_port}")

                    if change_messages:
                        add_log('info', f"Zariadenie {data['ip']} aktualizované: " + ", ".join(change_messages))
                    
                    return jsonify({'status': 'success', 'backup_migration': backup_migration})
                else:
                    # Skontroluj či IP nepatrí zariadeniu v koši
                    existing_deleted = conn.execute(
                        'SELECT id, name FROM devices WHERE ip = ? AND deleted_at IS NOT NULL', (data['ip'],)
                    ).fetchone()
                    if existing_deleted:
                        return jsonify({
                            'status': 'error',
                            'error': 'ip_in_trash',
                            'device_id': existing_deleted['id'],
                            'message': f"Zariadenie s IP {data['ip']} je v koši ({existing_deleted['name']}). Obnovte ho alebo počkajte na vymazanie."
                        }), 409

                    cursor = conn.cursor()
                    encrypted_password = encrypt_password(data['password'])
                    snmp_config, snmp_error = merge_device_snmp_config(data, new_device=True)
                    if snmp_error:
                        return jsonify({'status': 'error', 'message': snmp_error}), 400
                    snmp_secrets = encrypted_snmp_values(snmp_config)
                    new_snmp_location = str(data.get('snmp_location') or '').strip()
                    if len(new_snmp_location) > 255:
                        return jsonify({'status': 'error', 'message': 'SNMP Location môže mať najviac 255 znakov.'}), 400
                    device_name = str(data.get('name') or '').strip() or str(data.get('ip') or '').strip()
                    device_name_source = 'snmp' if (
                        str(data.get('name_source') or '').strip() == 'snmp' and str(data.get('name') or '').strip()
                    ) else 'local'
                    cursor.execute("INSERT INTO devices (name, name_source, site_id, ip, username, password, low_memory, snmp_community, snmp_version, snmp_v3_username, snmp_v3_security_level, snmp_v3_auth_protocol, snmp_v3_auth_password, snmp_v3_priv_protocol, snmp_v3_priv_password, snmp_allowed_address, snmp_location, snmp_interval_minutes, ping_interval_seconds, ping_retry_interval_seconds, cert_www_port, cert_www_ssl_port) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                                 (device_name, device_name_source, site_id, data['ip'], data['username'], encrypted_password, data.get('low_memory', False),
                                  snmp_secrets['snmp_community'], snmp_config['snmp_version'], snmp_config['snmp_v3_username'],
                                  snmp_config['snmp_v3_security_level'], snmp_config['snmp_v3_auth_protocol'],
                                  snmp_secrets['snmp_v3_auth_password'], snmp_config['snmp_v3_priv_protocol'],
                                  snmp_secrets['snmp_v3_priv_password'], snmp_config['snmp_allowed_address'] or None,
                                  new_snmp_location or None,
                                  data.get('snmp_interval_minutes', 0),
                                  data.get('ping_interval_seconds', 0), data.get('ping_retry_interval_seconds', 0),
                                  new_cert_www_port, new_cert_www_ssl_port))
                    device_id = cursor.lastrowid
                    conn.commit()
                    add_log('info', f"Zariadenie {data['ip']} pridané.")
                    try:
                        key = probe_ssh_host_key(data['ip'])
                        fingerprint = trust_initial_ssh_host_key(device_id, data['ip'], key)
                        add_log(
                            'info',
                            f"SSH fingerprint {fingerprint} bol automaticky potvrdený pri pridaní zariadenia.",
                            data['ip']
                        )
                        socketio.emit('ssh_host_key_status', {
                            'id': device_id,
                            'ip': data['ip'],
                            'status': 'trusted'
                        })
                        return jsonify({
                            'status': 'success',
                            'device_id': device_id,
                            'ssh_auto_trusted': True,
                            'ssh_host_key': get_ssh_host_key_state(device_id, data['ip']),
                            'message': 'Zariadenie bolo pridané a jeho SSH identita automaticky overená.'
                        })
                    except (OSError, paramiko.SSHException) as e:
                        error_message = str(e) or e.__class__.__name__
                        user_message = ssh_probe_failure_message(data['ip'], e)
                        add_log(
                            'warning',
                            f"Zariadenie bolo pridané, ale automatické overenie SSH fingerprintu zlyhalo: {error_message}",
                            data['ip']
                        )
                        return jsonify({
                            'status': 'success',
                            'device_id': device_id,
                            'ssh_auto_trusted': False,
                            'ssh_host_key': {'status': 'unverified'},
                            'message': f'Zariadenie bolo pridané, ale SSH identita nebola overená. {user_message}'
                        })
            except sqlite3.IntegrityError: return jsonify({'status': 'error', 'message': 'Zariadenie s touto IP už existuje'}), 409


@app.route('/api/devices/<int:device_id>/secrets/reveal', methods=['POST'])
@login_required
def reveal_device_secret(device_id):
    """Reveal one explicitly requested device secret without exposing it in list APIs."""
    source_url = request.headers.get('Origin') or request.headers.get('Referer')
    if not source_url:
        return jsonify({'status': 'error', 'message': 'Požiadavka nemá overiteľný pôvod.'}), 403
    parsed_source = urllib.parse.urlsplit(source_url)
    if parsed_source.scheme.lower() != request.scheme.lower() or parsed_source.netloc.lower() != request.host.lower():
        return jsonify({'status': 'error', 'message': 'Požiadavka z cudzieho pôvodu bola zablokovaná.'}), 403
    data = request.get_json(silent=True) or {}
    field = str(data.get('field') or '')
    allowed_fields = {
        'password': 'SSH heslo',
        'snmp_community': 'SNMP community',
        'snmp_v3_auth_password': 'SNMPv3 autentifikačné heslo',
        'snmp_v3_priv_password': 'SNMPv3 šifrovacie heslo',
    }
    if field not in allowed_fields:
        return jsonify({'status': 'error', 'message': 'Nepodporované tajomstvo.'}), 400
    with get_db_connection() as conn:
        row = conn.execute(
            f'SELECT ip, {field} AS secret_value FROM devices WHERE id = ? AND deleted_at IS NULL',
            (device_id,)
        ).fetchone()
    if not row:
        return jsonify({'status': 'error', 'message': 'Zariadenie nenájdené.'}), 404
    if not row['secret_value']:
        return jsonify({'status': 'error', 'message': 'Tajomstvo nie je nastavené.'}), 404
    try:
        value = decrypt_password_strict(row['secret_value'])
    except Exception:
        logger.error(f'Odhalenie uloženého tajomstva zariadenia {device_id} zlyhalo pri dešifrovaní.')
        return jsonify({'status': 'error', 'message': 'Uložené tajomstvo sa nepodarilo dešifrovať.'}), 500
    audit_username = getattr(current_user, 'username', 'prihlásený používateľ')
    add_log('info', f"Používateľ '{audit_username}' zobrazil {allowed_fields[field]} zariadenia.", row['ip'])
    response = jsonify({'status': 'success', 'value': value})
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, private'
    response.headers['Pragma'] = 'no-cache'
    return response


@app.route('/api/devices/<int:device_id>/ssh-host-key/probe', methods=['POST'])
@login_required
def probe_device_ssh_host_key(device_id):
    with get_db_connection() as conn:
        device = conn.execute(
            'SELECT id, name, ip FROM devices WHERE id = ? AND deleted_at IS NULL',
            (device_id,)
        ).fetchone()
    if not device:
        return jsonify({'status': 'error', 'message': 'Zariadenie nenájdené.'}), 404

    try:
        key = probe_ssh_host_key(device['ip'])
        observation = remember_pending_ssh_host_key(device_id, device['ip'], key)
        state = get_ssh_host_key_state(device_id, device['ip'])
        if observation['trusted']:
            message = 'SSH fingerprint zodpovedá potvrdenému kľúču.'
        else:
            message = 'SSH fingerprint bol načítaný a čaká na vaše potvrdenie.'
            add_log(
                'warning',
                f"SSH fingerprint {observation['fingerprint']} čaká na potvrdenie používateľom.",
                device['ip']
            )
        socketio.emit('ssh_host_key_status', {
            'id': device_id,
            'ip': device['ip'],
            'status': state['status']
        })
        return jsonify({'status': 'success', 'message': message, 'ssh_host_key': state})
    except (OSError, paramiko.SSHException) as e:
        error_message = str(e) or e.__class__.__name__
        add_log('warning', f"Načítanie SSH fingerprintu zlyhalo: {error_message}", device['ip'])
        return jsonify({
            'status': 'error',
            'message': ssh_probe_failure_message(device['ip'], e)
        }), 400


@app.route('/api/devices/<int:device_id>/ssh-host-key/approve', methods=['POST'])
@login_required
def approve_device_ssh_host_key(device_id):
    data = request.get_json(silent=True) or {}
    requested_fingerprint = str(data.get('fingerprint') or '')
    if not requested_fingerprint:
        return jsonify({'status': 'error', 'message': 'Chýba fingerprint na potvrdenie.'}), 400

    with get_db_connection() as conn:
        row = conn.execute(
            '''SELECT d.name, d.ip, k.pending_key_type, k.pending_key_data,
                      k.pending_fingerprint
               FROM devices d
               LEFT JOIN ssh_host_keys k ON k.device_id = d.id
               WHERE d.id = ? AND d.deleted_at IS NULL''',
            (device_id,)
        ).fetchone()
        if not row:
            return jsonify({'status': 'error', 'message': 'Zariadenie nenájdené.'}), 404
        if not row['pending_fingerprint']:
            return jsonify({'status': 'error', 'message': 'Zariadenie nemá SSH kľúč čakajúci na potvrdenie.'}), 409
        if not secrets.compare_digest(row['pending_fingerprint'], requested_fingerprint):
            return jsonify({
                'status': 'error',
                'message': 'Čakajúci fingerprint sa medzitým zmenil. Obnovte údaje a skontrolujte ho znova.'
            }), 409

        approved_at = datetime.now(timezone.utc).isoformat()
        conn.execute(
            '''UPDATE ssh_host_keys SET
                   trusted_host = ?,
                   trusted_key_type = pending_key_type,
                   trusted_key_data = pending_key_data,
                   trusted_fingerprint = pending_fingerprint,
                   trusted_at = ?,
                   pending_key_type = NULL,
                   pending_key_data = NULL,
                   pending_fingerprint = NULL,
                   pending_detected_at = NULL,
                   notified_pending_fingerprint = NULL
               WHERE device_id = ? AND pending_fingerprint = ?''',
            (row['ip'], approved_at, device_id, requested_fingerprint)
        )
        conn.commit()

    add_log(
        'warning',
        f"Používateľ '{current_user.username}' potvrdil SSH fingerprint {requested_fingerprint}.",
        row['ip']
    )
    state = get_ssh_host_key_state(device_id, row['ip'])
    socketio.emit('ssh_host_key_status', {
        'id': device_id,
        'ip': row['ip'],
        'status': state['status']
    })
    return jsonify({
        'status': 'success',
        'message': 'SSH kľúč bol potvrdený. Ďalšie zálohy môžu pokračovať.',
        'ssh_host_key': state
    })

@app.route('/api/devices/<int:device_id>', methods=['DELETE'])
@login_required
def delete_device(device_id):
    with get_db_connection() as conn:
        device = conn.execute('SELECT id, name, ip FROM devices WHERE id = ? AND deleted_at IS NULL', (device_id,)).fetchone()
        if not device:
            return jsonify({'status': 'error', 'message': 'Zariadenie nenájdené'}), 404

        device_name = device['name']
        device_ip = device['ip']

        # Skontrolovať bežiace operácie
        if device_ip in backup_tasks:
            return jsonify({'status': 'error', 'message': 'Prebieha záloha tohto zariadenia'}), 409
        if device_id in _running_manual_updates:
            return jsonify({'status': 'error', 'message': 'Prebieha manuálna aktualizácia'}), 409
        if device_id in _running_scheduled_updates:
            return jsonify({'status': 'error', 'message': 'Prebieha naplánovaná aktualizácia'}), 409
        if device_id in _reserved_update_devices:
            return jsonify({'status': 'error', 'message': 'Zariadenie je rezervované pre aktualizačnú frontu'}), 409
        for group in _manual_bulk_groups.values():
            if device_id == group.get('current_device_id') or device_id in group.get('remaining_ids', []):
                return jsonify({'status': 'error', 'message': 'Zariadenie je súčasťou hromadnej aktualizácie'}), 409

        # Zrušiť pending updater schedules
        conn.execute("UPDATE update_schedule SET status = 'cancelled' WHERE device_id = ? AND status = 'pending'", (device_id,))

        # Vypočítať purge_after
        retention_row = conn.execute("SELECT value FROM settings WHERE key = 'deleted_device_retention_days'").fetchone()
        retention_days = int(retention_row['value'] if retention_row else 7)
        now = datetime.now(timezone.utc)
        purge_after = now + timedelta(days=retention_days)

        # Soft-delete
        conn.execute("UPDATE devices SET deleted_at = ?, purge_after = ?, site_update_order = NULL WHERE id = ?",
                     (now.isoformat(), purge_after.isoformat(), device_id))
        conn.commit()

    # Vyčistiť SNMP in-memory stav
    with snmp_task_lock:
        snmp_task_state.pop(device_id, None)

    # Vyčistiť ostatné in-memory štruktúry
    _cert_expiry_notified.pop(device_id, None)
    _recent_updates.discard(device_id)

    add_log('warning', f"Zariadenie {device_name} ({device_ip}) bolo presunuté do koša", device_ip)
    return jsonify({'status': 'success', 'purge_after': purge_after.isoformat()})


@app.route('/api/devices/deleted', methods=['GET'])
@login_required
def get_deleted_devices():
    with get_db_connection() as conn:
        rows = conn.execute('''
            SELECT d.id, d.name, d.ip, d.site_id, s.name AS site_name,
                   d.deleted_at, d.purge_after
            FROM devices d
            LEFT JOIN sites s ON s.id = d.site_id
            WHERE d.deleted_at IS NOT NULL
            ORDER BY d.deleted_at DESC
        ''').fetchall()
        devices = []
        now = datetime.now(timezone.utc)
        for row in rows:
            try:
                purge_dt = datetime.fromisoformat(row['purge_after'])
                if purge_dt.tzinfo is None:
                    purge_dt = purge_dt.replace(tzinfo=timezone.utc)
                remaining = max(0, (purge_dt - now).total_seconds())
            except Exception:
                remaining = 0
            devices.append({
                'id': row['id'],
                'name': row['name'],
                'ip': row['ip'],
                'site_id': row['site_id'],
                'site_name': row['site_name'],
                'deleted_at': row['deleted_at'],
                'purge_after': row['purge_after'],
                'remaining_seconds': int(remaining)
            })
    return jsonify(devices)


@app.route('/api/devices/<int:device_id>/restore', methods=['POST'])
@login_required
def restore_device(device_id):
    with get_db_connection() as conn:
        device = conn.execute(
            'SELECT id, name, ip, snmp_interval_minutes, monitoring_paused FROM devices WHERE id = ? AND deleted_at IS NOT NULL',
            (device_id,)
        ).fetchone()
        if not device:
            return jsonify({'status': 'error', 'message': 'Zariadenie nenájdené v koši'}), 404

        conn.execute("UPDATE devices SET deleted_at = NULL, purge_after = NULL WHERE id = ?", (device_id,))

        global_interval_row = conn.execute("SELECT value FROM settings WHERE key = 'snmp_check_interval_minutes'").fetchone()
        global_interval = int(global_interval_row['value'] if global_interval_row else 10)
        conn.commit()

    device_name = device['name']
    device_ip = device['ip']

    # Obnoviť SNMP scheduling — rovnaká logika ako start_all_snmp_timers()
    if not device['monitoring_paused']:
        device_interval = device['snmp_interval_minutes'] or 0
        effective_interval = device_interval if device_interval > 0 else global_interval
        effective_interval = max(effective_interval, 1)
        schedule_snmp_task(device_id, effective_interval, delay_seconds=30, reason="restore_from_trash")
    else:
        pause_snmp_task(device_id, reason="restore_paused")

    add_log('info', f"Zariadenie {device_name} ({device_ip}) bolo obnovené z koša", device_ip)
    return jsonify({'status': 'success'})


def purge_device(device_id, manual=False):
    """Definitívne vymaže zariadenie a všetky súvisiace dáta. Vracia True ak úspešné."""
    started_at = time.monotonic()
    try:
        with get_db_connection() as conn:
            device = conn.execute('SELECT id, name, ip FROM devices WHERE id = ?', (device_id,)).fetchone()
            if not device:
                return True  # Už neexistuje, idempotentné

            device_name = device['name']
            device_ip = device['ip']
            retention_row = conn.execute("SELECT value FROM settings WHERE key = 'deleted_device_retention_days'").fetchone()
            retention_days = int(retention_row['value'] if retention_row else 7)
            settings = {row['key']: row['value'] for row in conn.execute('SELECT key, value FROM settings').fetchall()}

            # 1. DB cleanup
            conn.execute('DELETE FROM ping_history WHERE device_id = ?', (device_id,))
            conn.execute('DELETE FROM snmp_history WHERE device_id = ?', (device_id,))
            conn.execute('DELETE FROM update_schedule WHERE device_id = ?', (device_id,))
            conn.execute('DELETE FROM ssh_host_keys WHERE device_id = ?', (device_id,))
            conn.execute('DELETE FROM logs WHERE device_ip = ?', (device_ip,))
            conn.execute('DELETE FROM devices WHERE id = ?', (device_id,))
            conn.commit()

        db_elapsed_ms = int((time.monotonic() - started_at) * 1000)

        # 2. Lokálne backup súbory — už mimo DB transakcie.
        file_pattern = f"_{device_ip}_"
        local_deleted = 0
        try:
            if os.path.isdir(BACKUP_DIR):
                for filename in os.listdir(BACKUP_DIR):
                    if file_pattern in filename:
                        os.remove(os.path.join(BACKUP_DIR, filename))
                        local_deleted += 1
        except Exception as e:
            add_log('error', f"Purge: chyba pri mazaní lokálnych backupov pre {device_ip}: {e}", device_ip)

        # 3. FTP backup súbory sú best-effort a nesmú blokovať HTTP worker.
        def cleanup_ftp_backups():
            ftp_started_at = time.monotonic()
            try:
                ftp_settings = decrypt_sensitive_settings_map(settings)
                if not all(ftp_settings.get(key) for key in ('ftp_server', 'ftp_username', 'ftp_password')):
                    return
                try:
                    ftp_port = int(ftp_settings.get('ftp_port', 21))
                except (TypeError, ValueError):
                    ftp_port = 21
                try:
                    ftp_timeout = int(ftp_settings.get('ftp_timeout_seconds', 15))
                except (TypeError, ValueError):
                    ftp_timeout = 15
                ftp_timeout = ftp_timeout if 5 <= ftp_timeout <= 120 else 15

                deleted_count = 0
                failed_count = 0
                from ftplib import FTP
                with FTP(timeout=ftp_timeout) as ftp:
                    ftp.connect(ftp_settings['ftp_server'], ftp_port, timeout=ftp_timeout)
                    ftp.login(ftp_settings['ftp_username'], ftp_settings['ftp_password'])
                    if ftp_settings.get('ftp_directory'):
                        ftp.cwd(ftp_settings['ftp_directory'])
                    ftp_files = [name for name in ftp.nlst() if file_pattern in name]
                    for filename in ftp_files:
                        try:
                            ftp.delete(filename)
                            deleted_count += 1
                        except Exception as e:
                            failed_count += 1
                            logger.warning(
                                "Purge FTP: súbor pre %s sa nepodarilo vymazať: %s",
                                device_ip, safe_ftp_error(e)
                            )
                logger.info(
                    "Purge FTP pre %s dokončený: vymazané=%s, zlyhané=%s, trvanie=%sms",
                    device_ip, deleted_count, failed_count,
                    int((time.monotonic() - ftp_started_at) * 1000)
                )
            except Exception as e:
                add_log('warning', f"Purge: FTP mazanie zlyhalo pre {device_ip}: {safe_ftp_error(e)}", device_ip)
                logger.warning(
                    "Purge FTP pre %s zlyhal po %sms",
                    device_ip, int((time.monotonic() - ftp_started_at) * 1000)
                )

        try:
            threading.Thread(
                target=cleanup_ftp_backups,
                name=f"purge-ftp-{device_id}",
                daemon=True
            ).start()
        except Exception as e:
            # DB purge je už bezpečne commitnutý; zlyhanie best-effort FTP
            # cleanupu preto nesmie zmeniť úspešnú HTTP odpoveď na chybu.
            add_log(
                'warning',
                f"Purge: FTP cleanup sa nepodarilo spustiť pre {device_ip}: {safe_ftp_error(e)}",
                device_ip
            )

        # 4. In-memory cleanup
        with snmp_task_lock:
            snmp_task_state.pop(device_id, None)
        _cert_expiry_notified.pop(device_id, None)
        _running_manual_updates.pop(device_id, None)
        _running_scheduled_updates.pop(device_id, None)
        _recent_updates.discard(device_id)
        backup_tasks.pop(device_ip, None)

        # 5. Pushover notifikácia — len pri automatickom purge po lehote
        if not manual:
            send_pushover_notification(
                f"🗑️ Zariadenie {device_name} ({device_ip}) bolo definitívne odstránené po {retention_days}-dňovej lehote",
                title="MikroTik Manager - Zariadenie vymazané",
                notification_key='notify_device_purged'
            )

        add_log('info', f"Zariadenie {device_name} ({device_ip}) bolo definitívne vymazané (purge)")
        logger.info(
            "Purge zariadenia %s dokončený bez čakania na FTP: DB=%sms, lokálne_súbory=%s, spolu=%sms",
            device_ip, db_elapsed_ms, local_deleted,
            int((time.monotonic() - started_at) * 1000)
        )
        return True

    except Exception as e:
        add_log('error', f"Purge zariadenia {device_id} zlyhal: {e}")
        return False


@app.route('/api/devices/<int:device_id>/purge', methods=['DELETE'])
@login_required
def purge_device_endpoint(device_id):
    with get_db_connection() as conn:
        device = conn.execute(
            'SELECT id FROM devices WHERE id = ? AND deleted_at IS NOT NULL',
            (device_id,)
        ).fetchone()
        if not device:
            return jsonify({'status': 'error', 'message': 'Zariadenie nenájdené v koši'}), 404

    success = purge_device(device_id, manual=True)
    if success:
        return jsonify({'status': 'success'})
    else:
        return jsonify({'status': 'error', 'message': 'Purge čiastočne zlyhal, skúste znova'}), 500


@app.route('/api/backup/<int:device_id>', methods=['POST'])
@login_required
def backup_device(device_id):
    with get_db_connection() as conn:
        device = conn.execute('SELECT * FROM devices WHERE id = ? AND deleted_at IS NULL', (device_id,)).fetchone()
    if not device: return jsonify({'status': 'error', 'message': 'Zariadenie nebolo nájdené.'}), 404
    if device['ip'] in backup_tasks: return jsonify({'status': 'error', 'message': 'Záloha už prebieha.'}), 409
    backup_tasks[device['ip']] = True
    threading.Thread(target=run_backup_logic, args=(dict(device), False)).start()  # False = nie je sekvenčná
    return jsonify({'status': 'success', 'message': 'Záloha spustená.'})

@app.route('/api/backup/all', methods=['POST'])
@login_required
def backup_all_devices():
    with get_db_connection() as conn:
        devices = [dict(row) for row in conn.execute('SELECT * FROM devices WHERE deleted_at IS NULL ORDER BY name').fetchall()]
        settings = {row['key']: row['value'] for row in conn.execute('SELECT key, value FROM settings').fetchall()}
    
    # Získame nastavenie oneskorenia medzi zálohami (predvolené 30 sekúnd)
    backup_delay = parse_int_setting(settings.get('backup_delay_seconds'), 30, 5, 300)
    
    # Filtrujeme len zariadenia, ktoré nemajú bežiacu zálohu
    available_devices = [device for device in devices if device['ip'] not in backup_tasks]
    
    if not available_devices:
        return jsonify({'status': 'error', 'message': 'Všetky zariadenia už majú bežiacu zálohu alebo nie sú dostupné zariadenia.'})
    
    total_devices = len(available_devices)
    add_log('info', f"Spúšťam sekvenčnú hromadnú zálohu pre {total_devices} zariadení s odstupom {backup_delay}s.")
    
    # Spustíme sekvenčnú zálohu v samostatnom vlákne
    threading.Thread(target=run_sequential_backup, args=(available_devices, backup_delay)).start()
    
    return jsonify({
        'status': 'success', 
        'message': f'Sekvenčná hromadná záloha spustená pre {total_devices} zariadení.',
        'total_devices': total_devices
    })

def run_sequential_backup(devices, delay_seconds):
    """Spúšťa zálohy postupne s oneskorením medzi nimi"""
    global sequential_backup_running, sequential_backup_total, sequential_backup_current
    sequential_backup_running = True
    sequential_backup_total = len(devices)
    sequential_backup_current = 0
    device_results = []
    stopped_early = False
    
    try:
        total_devices = len(devices)
        for i, device in enumerate(devices, 1):
            # Kontrola, či má používateľ zastaviť sekvenčnú zálohu
            if not sequential_backup_running:
                add_log('warning', "Sekvenčná záloha bola zastavená používateľom.")
                stopped_early = True
                break

            sequential_backup_current = i
            ip = device['ip']
            if ip in backup_tasks:
                add_log('warning', "Záloha už prebieha, preskakujem.", ip)
                continue
            
            add_log('info', f"Spúšťam zálohu {i}/{total_devices}...", ip)
            backup_tasks[ip] = True
            
            # Spustíme zálohu s príznakom sekvenčnej zálohy a počkáme na jej dokončenie
            result_holder = {'backup_performed': False, 'ftp_uploaded': False}
            backup_thread = threading.Thread(target=run_backup_logic, args=(device, True, result_holder))  # True = is_sequential
            backup_thread.start()
            backup_thread.join()  # Počkáme kým sa záloha dokončí
            device_results.append(result_holder)
            
            # Ak nie je posledné zariadenie, počkáme pred ďalšou zálohou
            if i < total_devices and sequential_backup_running:
                add_log('info', f"Čakám {delay_seconds} sekúnd pred ďalšou zálohou...")
                for _ in range(delay_seconds):
                    if not sequential_backup_running:
                        break
                    time.sleep(1)
    finally:
        sequential_backup_running = False
        sequential_backup_current = 0
        sequential_backup_total = 0
        if device_results and not stopped_early:
            performed = [res for res in device_results if res.get('backup_performed')]
            if performed:
                if all(res.get('ftp_uploaded') for res in performed):
                    add_log('info', "Všetky vytvorené zálohy boli úspešne nahraté na FTP server.")
                else:
                    add_log('warning', "Niektoré vytvorené zálohy sa nepodarilo nahrať na FTP server. Skontrolujte logy zariadení.")
        add_log('info', "Sekvenčná záloha dokončená.")

@app.route('/api/snmp/<int:device_id>', methods=['GET'])
@login_required
def check_snmp(device_id):
    result = perform_snmp_poll(device_id, reason="manual")

    # Zvládnutie stavov podľa výsledku
    if result.get('status') == 'missing':
        return jsonify({'status': 'error', 'message': 'Zariadenie nenájdené'}), 404
    if result.get('error'):
        return jsonify({
            'status': 'error',
            'message': (
                'SNMP kontrola zlyhala. Skontrolujte, či je na MikroTiku povolené SNMP, '
                'či sedia poverenia a bezpečnostné protokoly a či firewall povoľuje UDP port 161. '
                f"Detail: {result['error']}"
            )
        }), 500

    device = result.get('device')
    if not device:
        with get_db_connection() as conn:
            device = conn.execute(
                'SELECT id, snmp_interval_minutes FROM devices WHERE id = ? AND deleted_at IS NULL',
                (device_id,)
            ).fetchone()
            if not device:
                return jsonify({'status': 'error', 'message': 'Zariadenie nenájdené'}), 404
    
    with get_db_connection() as conn:
        settings = {row['key']: row['value'] for row in conn.execute('SELECT key, value FROM settings').fetchall()}
        global_interval = int(settings.get('snmp_check_interval_minutes', 10))
    
    # Určí interval pre toto zariadenie
    try:
        snmp_interval_value = device['snmp_interval_minutes']
    except (KeyError, TypeError):
        if isinstance(device, (tuple, list)) and len(device) > 1:
            snmp_interval_value = device[1]
        else:
            snmp_interval_value = 0
    device_interval = snmp_interval_value if snmp_interval_value and snmp_interval_value > 0 else global_interval
    
    # Reštartuj timer s immediate=True pre okamžité nastavenie ďalšieho checku
    restart_snmp_timer_for_device(device_id, device_interval)
    
    snmp_data = result.get('snmp_data') or {}
    return jsonify(snmp_data)


def snmp_diagnostic_message(error_text):
    text = str(error_text or '').lower()
    if 'unknownuser' in text or 'unknown user' in text:
        return 'MikroTik nepozná zadaného SNMPv3 používateľa.'
    if 'wrongdigest' in text or 'authentication' in text:
        return 'SNMPv3 autentifikácia zlyhala. Skontrolujte heslo a protokol SHA1/MD5.'
    if 'decryption' in text or 'privacy' in text:
        return 'SNMPv3 šifrovanie zlyhalo. Skontrolujte privacy heslo a protokol AES/DES.'
    if 'timeout' in text or 'no snmp response' in text:
        return 'SNMP neodpovedalo v časovom limite. Skontrolujte službu SNMP, UDP/161 a povolenú zdrojovú adresu.'
    return 'SNMP test zlyhal. Skontrolujte verziu, poverenia, bezpečnostné protokoly a firewall UDP/161.'


def load_snmp_test_config(data):
    device_id = data.get('device_id')
    existing = None
    if device_id:
        with get_db_connection() as conn:
            existing = conn.execute(
                'SELECT * FROM devices WHERE id = ? AND deleted_at IS NULL',
                (device_id,)
            ).fetchone()
        if not existing:
            return None, None, 'Zariadenie nenájdené.'
    config, error = merge_device_snmp_config(data, existing, new_device=not bool(existing))
    ip = str(data.get('ip') or (existing['ip'] if existing else '')).strip()
    if not ip:
        return None, None, 'IP adresa zariadenia je povinná.'
    return ip, config, error


@app.route('/api/snmp/test', methods=['POST'])
@login_required
def test_snmp_configuration():
    data = request.get_json(silent=True) or {}
    ip, config, error = load_snmp_test_config(data)
    if error:
        return jsonify({'status': 'error', 'message': error}), 400
    started = time.monotonic()
    snmp_data = get_snmp_data(ip, config, diagnostic=True)
    elapsed_ms = int((time.monotonic() - started) * 1000)
    diagnostic_error = snmp_data.pop('_error', None)
    if snmp_data.get('uptime') == 'N/A':
        return jsonify({
            'status': 'error',
            'message': snmp_diagnostic_message(diagnostic_error),
            'response_ms': elapsed_ms,
        }), 400
    return jsonify({
        'status': 'success',
        'message': 'SNMP spojenie je funkčné.',
        'identity': snmp_data.get('identity'),
        'routeros_version': snmp_data.get('version'),
        'board_name': snmp_data.get('board_name'),
        'response_ms': elapsed_ms,
    })


@app.route('/api/snmp/detect-source', methods=['POST'])
@login_required
def detect_snmp_source_address():
    data = request.get_json(silent=True) or {}
    target = str(data.get('ip') or '').strip()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # Bez zadaného zariadenia zistíme adresu primárneho rozhrania
        # Managera cez systémovú routovaciu tabuľku. UDP connect neposiela dáta.
        sock.connect((target, 161) if target else ('1.1.1.1', 53))
        source_ip = sock.getsockname()[0]
        return jsonify({'status': 'success', 'source_ip': source_ip, 'cidr': f'{source_ip}/32'})
    except (OSError, socket.gaierror):
        message = (
            'Zdrojovú IP voči zariadeniu sa nepodarilo zistiť.'
            if target else
            'IP adresu MikroTik Managera sa nepodarilo automaticky zistiť.'
        )
        return jsonify({'status': 'error', 'message': message}), 400
    finally:
        sock.close()


def routeros_quote(value):
    """Quote untrusted text as a RouterOS string literal."""
    escaped = []
    for char in str(value):
        code = ord(char)
        if char in {'\\', '"', '$'}:
            escaped.append('\\' + char)
        elif code < 32 or code == 127:
            escaped.append(f'\\{code:02X}')
        else:
            escaped.append(char)
    return '"' + ''.join(escaped) + '"'


def execute_routeros_ssh(device, command, timeout=20):
    client = paramiko.SSHClient()
    try:
        client.set_missing_host_key_policy(PinnedSSHHostKeyPolicy(device['id'], device['ip']))
        client.connect(
            device['ip'], username=device['username'], password=device['password'],
            timeout=timeout, banner_timeout=timeout, auth_timeout=timeout,
        )
        _, stdout, stderr = client.exec_command(command, timeout=timeout)
        output = stdout.read().decode('utf-8', errors='replace').strip()
        error = stderr.read().decode('utf-8', errors='replace').strip()
        exit_status = stdout.channel.recv_exit_status()
        if exit_status != 0 or error:
            raise RuntimeError('RouterOS odmietol SNMP konfiguráciu.')
        return output
    finally:
        client.close()


@app.route('/api/devices/<int:device_id>/snmp/provision', methods=['POST'])
@login_required
def provision_device_snmp(device_id):
    data = request.get_json(silent=True) or {}
    with get_db_connection() as conn:
        row = conn.execute(
            'SELECT * FROM devices WHERE id = ? AND deleted_at IS NULL', (device_id,)
        ).fetchone()
    if not row:
        return jsonify({'status': 'error', 'message': 'Zariadenie nenájdené.'}), 404
    device = get_device_with_decrypted_password(dict(row))
    config, error = validate_snmp_config(device, require_secrets=True)
    if error:
        return jsonify({'status': 'error', 'message': error}), 400
    if get_ssh_host_key_state(device_id, device['ip']).get('status') != 'trusted':
        return jsonify({
            'status': 'error',
            'error': 'ssh_host_key_untrusted',
            'message': 'SSH fingerprint zariadenia musí byť pred provisioningom potvrdený.'
        }), 409

    version_label = 'SNMPv3' if config['snmp_version'] == '3' else 'SNMPv2c'
    account_name = config['snmp_v3_username'] if config['snmp_version'] == '3' else config['snmp_community']
    username = routeros_quote(account_name)
    check_command = (
        f':local mmNamed [/snmp community find where name={username}]; '
        ':local mmDefault [/snmp community find where default=yes]; '
        ':if ([:len $mmNamed] > 0) do={'
        f':if (([:len $mmDefault] = 1) && ([/snmp community get $mmDefault name] != {username})) '
        'do={:put "MM_EXISTS_WITH_DEFAULT"} else={:put "MM_EXISTS"}'
        '} else={:if ([:len $mmDefault] = 1) '
        'do={:put "MM_REUSE_DEFAULT"} else={:put "MM_MISSING"}}'
    )
    try:
        target_state = execute_routeros_ssh(device, check_command)
        consolidate_default = 'MM_EXISTS_WITH_DEFAULT' in target_state
        exists = consolidate_default or 'MM_EXISTS' in target_state
        reuse_default = 'MM_REUSE_DEFAULT' in target_state
        if not exists and not reuse_default and 'MM_MISSING' not in target_state:
            raise RuntimeError('RouterOS nevrátil stav SNMP community.')
        if exists and not data.get('overwrite'):
            return jsonify({
                'status': 'conflict', 'error': 'snmp_account_exists',
                'message': (
                    'SNMP community/účet s týmto menom už existuje vedľa systémového defaultu. '
                    'Potvrdením sa duplicitný nesystémový záznam odstráni a jeho nastavenie sa prenesie na default.'
                    if consolidate_default else
                    'SNMP community/účet s týmto menom už na MikroTiku existuje. Potvrďte jeho aktualizáciu.'
                ),
                'account': account_name,
            }), 409

        address = routeros_quote(config['snmp_allowed_address'] or '0.0.0.0/0')
        if config['snmp_version'] == '2c':
            properties = (
                f'name={username} address={address} read-access=yes write-access=no security=none'
            )
        else:
            auth_password = routeros_quote(config['snmp_v3_auth_password'])
            properties = (
                f'name={username} address={address} read-access=yes write-access=no '
                f'security={"private" if config["snmp_v3_security_level"] == "authPriv" else "authorized"} '
                f'authentication-protocol={config["snmp_v3_auth_protocol"]} '
                f'authentication-password={auth_password}'
            )
            if config['snmp_v3_security_level'] == 'authPriv':
                properties += (
                    f' encryption-protocol={config["snmp_v3_priv_protocol"]} '
                    f'encryption-password={routeros_quote(config["snmp_v3_priv_password"])}'
                )
        snmp_service_properties = 'enabled=yes'
        snmp_location = str(device.get('snmp_location') or '').strip()
        if snmp_location:
            snmp_service_properties += f' location={routeros_quote(snmp_location)}'
        if consolidate_default:
            configure_command = (
                f':local mmTarget [/snmp community find where name={username}]; '
                ':local mmDefault [/snmp community find where default=yes]; '
                '/snmp community remove $mmTarget; '
                f'/snmp community set $mmDefault {properties}; /snmp set {snmp_service_properties}'
            )
        elif exists:
            properties_without_name = properties.split(' ', 1)[1]
            configure_command = (
                f':local mmIds [/snmp community find where name={username}]; '
                f'/snmp community set $mmIds {properties_without_name}; /snmp set {snmp_service_properties}'
            )
        elif reuse_default:
            configure_command = (
                ':local mmIds [/snmp community find where default=yes]; '
                f'/snmp community set $mmIds {properties}; /snmp set {snmp_service_properties}'
            )
        else:
            configure_command = f'/snmp community add {properties}; /snmp set {snmp_service_properties}'
        execute_routeros_ssh(device, configure_command)

        tested = get_snmp_data(device['ip'], config, diagnostic=True)
        diagnostic_error = tested.pop('_error', None)
        if tested.get('uptime') == 'N/A':
            add_log('warning', f'{version_label} provisioning pre {device["name"]} bol zapísaný, ale test zlyhal.', device['ip'])
            return jsonify({
                'status': 'error', 'configured': True,
                'message': f'Nastavenie bolo zapísané, ale následný {version_label} test zlyhal. ' + snmp_diagnostic_message(diagnostic_error)
            }), 502

        identity = str(tested.get('identity') or '').strip()
        identity_updated = False
        if (
            data.get('update_identity') is True
            and identity
            and identity != 'N/A'
            and device.get('name_source') == 'local'
            and device.get('name') == device.get('ip')
        ):
            with get_db_connection() as conn:
                conn.execute(
                    "UPDATE devices SET name = ?, name_source = 'snmp' WHERE id = ? AND deleted_at IS NULL",
                    (identity, device_id),
                )
                conn.commit()
            device['name'] = identity
            identity_updated = True

        add_log('info', f'{version_label} provisioning pre {device["name"]} bol úspešne dokončený.', device['ip'])
        return jsonify({
            'status': 'success', 'message': f'{version_label} bolo nastavené a úspešne otestované.',
            'identity': identity or None,
            'identity_updated': identity_updated,
            'default_community_reused': reuse_default or consolidate_default,
            'duplicate_community_consolidated': consolidate_default,
        })
    except SSHHostKeyVerificationRequired as exc:
        return jsonify({'status': 'error', 'error': 'ssh_host_key_untrusted', 'message': str(exc)}), 409
    except (OSError, paramiko.SSHException, RuntimeError):
        add_log('error', f'{version_label} provisioning pre {device["name"]} cez SSH zlyhal.', device['ip'])
        return jsonify({
            'status': 'error',
            'message': f'{version_label} sa nepodarilo nastaviť cez SSH. Skontrolujte fingerprint, SSH prístup a oprávnenia read/write/sensitive.'
        }), 400

@app.route('/api/snmp/refresh-all', methods=['POST'])
@login_required
def snmp_refresh_all_devices():
    """Spustí sekvenčný refresh SNMP dát pre všetky zariadenia"""
    global sequential_snmp_refresh_running
    
    # Skontrolujeme či už prebieha refresh
    if sequential_snmp_refresh_running:
        return jsonify({'status': 'error', 'message': 'SNMP refresh všetkých zariadení už prebieha.'}), 409
    
    with get_db_connection() as conn:
        devices = [
            dict(row)
            for row in conn.execute('SELECT id, ip, name FROM devices WHERE deleted_at IS NULL ORDER BY name').fetchall()
        ]
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
                perform_snmp_poll(device_id, reason="bulk")
                
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
        if request.method == 'GET':
            sync_ping_interval_alias(conn)
            settings = {row['key']: row['value'] for row in conn.execute('SELECT key, value FROM settings').fetchall()}
            return jsonify(decrypt_sensitive_settings_map(settings))
        if request.method == 'POST':
            request_data = dict(request.get_json(silent=True) or {})
            if 'ping_heartbeat_interval' in request_data and 'ping_check_interval_seconds' not in request_data:
                request_data['ping_check_interval_seconds'] = request_data['ping_heartbeat_interval']
            if 'ping_check_interval_seconds' in request_data:
                request_data['ping_heartbeat_interval'] = request_data['ping_check_interval_seconds']

            # Validácia ping_check_interval_seconds
            ping_interval = request_data.get('ping_check_interval_seconds')
            if ping_interval is not None:
                try:
                    ping_interval_int = int(ping_interval)
                    if ping_interval_int < 20 or ping_interval_int > 86400:
                        return jsonify({'status': 'error', 'message': 'Globálny ping interval musí byť 20-86400 sekúnd'}), 400
                except (ValueError, TypeError):
                    return jsonify({'status': 'error', 'message': 'Neplatná hodnota pre ping interval'}), 400

            # Validácia intervalu SNMP health checku
            health_interval = request_data.get('snmp_health_check_interval_minutes')
            if health_interval is not None:
                try:
                    health_interval_int = int(health_interval)
                    if health_interval_int < 1 or health_interval_int > 1440:
                        return jsonify({'status': 'error', 'message': 'SNMP health check interval musí byť 1-1440 minút'}), 400
                except (ValueError, TypeError):
                    return jsonify({'status': 'error', 'message': 'Neplatná hodnota pre SNMP health check interval'}), 400

            # Validácia timeoutu FTP spojenia
            ftp_timeout = request_data.get('ftp_timeout_seconds')
            if ftp_timeout is not None:
                try:
                    ftp_timeout_int = int(ftp_timeout)
                    if ftp_timeout_int < 5 or ftp_timeout_int > 120:
                        return jsonify({'status': 'error', 'message': 'FTP timeout musí byť 5-120 sekúnd'}), 400
                except (ValueError, TypeError):
                    return jsonify({'status': 'error', 'message': 'Neplatná hodnota pre FTP timeout'}), 400

            # Validácia uchovávania zmazaných zariadení
            deleted_retention = request_data.get('deleted_device_retention_days')
            if deleted_retention is not None:
                try:
                    deleted_retention_int = int(deleted_retention)
                    if deleted_retention_int < 1 or deleted_retention_int > 90:
                        return jsonify({'status': 'error', 'message': 'Uchovávanie zmazaných zariadení musí byť 1-90 dní'}), 400
                except (ValueError, TypeError):
                    return jsonify({'status': 'error', 'message': 'Neplatná hodnota pre uchovávanie zmazaných zariadení'}), 400

            # Server-side hranice musia zodpovedať poliam v Settings; HTML min/max
            # nie je bezpečnostná ani konzistenčná validácia API.
            for timer_key, timer_label, minimum, maximum in (
                ('backup_retention_count', 'Počet uchovávaných záloh', 1, 100),
                ('backup_delay_seconds', 'Oneskorenie medzi zálohami', 5, 300),
                ('bulk_update_delay_seconds', 'Oneskorenie medzi aktualizáciami', 10, 3600),
                ('updater_post_backup_delay', 'Pauza po zálohe', 0, 600),
                ('updater_stabilization_delay', 'Interval stabilizácie', 10, 600),
                ('updater_pre_reboot_delay', 'Pauza pred reštartom', 5, 300),
            ):
                timer_value = request_data.get(timer_key)
                if timer_value is None:
                    continue
                try:
                    timer_int = int(timer_value)
                except (ValueError, TypeError):
                    return jsonify({'status': 'error', 'message': f'Neplatná hodnota: {timer_label}'}), 400
                if not minimum <= timer_int <= maximum:
                    return jsonify({
                        'status': 'error',
                        'message': f'{timer_label}: povolený rozsah je {minimum}-{maximum}.'
                    }), 400

            # Validácia portov MikroTik web služieb používaných Updaterom
            for port_key, port_label in (
                ('cert_www_port', 'Port služby www (HTTP)'),
                ('cert_www_ssl_port', 'Port služby www-ssl (HTTPS)')
            ):
                port_value = request_data.get(port_key)
                if port_value is not None:
                    try:
                        port_int = int(port_value)
                        if port_int < 1 or port_int > 65535:
                            return jsonify({'status': 'error', 'message': f'{port_label} musí byť 1-65535'}), 400
                    except (ValueError, TypeError):
                        return jsonify({'status': 'error', 'message': f'Neplatná hodnota pre {port_label}'}), 400
            
            # Načítame pôvodné nastavenia pre porovnanie zmien
            old_settings = {row['key']: row['value'] for row in conn.execute('SELECT key, value FROM settings').fetchall()}

            def normalize_setting_value(key, value):
                if value is None:
                    return ''
                value_str = str(value)
                if key in SENSITIVE_SETTINGS:
                    return decrypt_setting_value_if_sensitive(key, value_str)
                if key in BOOLEAN_SETTING_KEYS:
                    return value_str.lower()
                return value_str

            def old_value(key):
                stored = old_settings.get(key)
                if stored is None or stored == '':
                    stored = DEFAULT_SETTING_VALUES.get(key, '')
                return normalize_setting_value(key, stored)

            def request_value(key):
                return normalize_setting_value(key, request_data.get(key))

            def setting_changed(key):
                if key not in request_data:
                    return False
                return request_value(key) != old_value(key)

            def new_value(key):
                return request_value(key) if key in request_data else old_value(key)
            
            for key, value in request_data.items():
                stored_value = encrypt_setting_value_if_sensitive(key, value)
                conn.execute("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)", (key, stored_value))
            conn.commit()
            add_log('info', "Globálne nastavenia uložené používateľom.")
            
            changed_keys = sorted(key for key in request_data.keys() if setting_changed(key))
            for key in changed_keys:
                label = get_setting_label(key)
                if key in SENSITIVE_SETTINGS:
                    add_log('info', f"{label} bolo aktualizované (hodnota je skrytá).")
                else:
                    previous_value = format_setting_value(key, old_value(key))
                    current_value = format_setting_value(key, new_value(key))
                    add_log('info', f"{label} zmenené z {previous_value} na {current_value}.")
            
            # Kontrola či sa zmenili ping nastavenia
            ping_settings_changed = setting_changed('ping_check_interval_seconds') or setting_changed('ping_monitor_enabled')
            
            # Kontrola či sa zmenili SNMP nastavenia
            snmp_interval_changed = setting_changed('snmp_check_interval_minutes')
            snmp_health_changed = setting_changed('snmp_health_check_enabled') or setting_changed('snmp_health_check_interval_minutes')
            backup_schedule_keys = ('backup_schedule_enabled', 'backup_schedule_type', 'backup_schedule_day', 'backup_schedule_time')
            backup_schedule_changed = any(setting_changed(key) for key in backup_schedule_keys)
            
            if ping_settings_changed:
                restart_ping_monitoring()
                add_log('info', f"Ping monitoring reštartovaný s novými nastaveniami: interval {new_value('ping_check_interval_seconds')}s, povolený: {new_value('ping_monitor_enabled')}")
            
            if snmp_interval_changed:
                stop_all_snmp_timers()
                start_all_snmp_timers()
                # Okamžitý health check po zmene intervalu pre zabezpečenie správneho fungovania
                trigger_immediate_health_check("globálna zmena SNMP intervalu")
                add_log('info', f"SNMP timery reštartované s novým globálnym intervalom: {new_value('snmp_check_interval_minutes')} minút")

            if snmp_health_changed:
                details = []
                if setting_changed('snmp_health_check_enabled'):
                    is_enabled = new_value('snmp_health_check_enabled') == 'true'
                    details.append(f"stav: {'zapnutý' if is_enabled else 'vypnutý'}")
                if setting_changed('snmp_health_check_interval_minutes'):
                    details.append(f"interval: {new_value('snmp_health_check_interval_minutes')} minút")
                detail_text = f" ({', '.join(details)})" if details else ""
                add_log('info', f"SNMP health check nastavenia aktualizované{detail_text}.")
            
            backup_general_changes = []
            if setting_changed('backup_delay_seconds'):
                backup_general_changes.append(f"oneskorenie medzi zálohami: {new_value('backup_delay_seconds')}s")
            if setting_changed('backup_retention_count'):
                backup_general_changes.append(f"retencia záloh: {new_value('backup_retention_count')} ks")
            if setting_changed('backup_detailed_logging'):
                backup_general_changes.append(f"detailné logovanie: {'zapnuté' if new_value('backup_detailed_logging') == 'true' else 'vypnuté'}")
            if setting_changed('ftp_timeout_seconds'):
                backup_general_changes.append(f"FTP timeout: {new_value('ftp_timeout_seconds')}s")
            if backup_general_changes:
                add_log('info', f"Automatické zálohovanie — upravené nastavenia ({'; '.join(backup_general_changes)}).")
            
            # Znovu nastavíme scheduler bez logovania
            setup_scheduler(log_schedule_info=False)
            
            # Pridáme info o pláne len ak sa zmenilo nastavenie automatických záloh
            if backup_schedule_changed:
                schedule_info = get_schedule_info()
                if schedule_info:
                    add_log('info', schedule_info)
            
            return jsonify({
                'status': 'success'
            })

@app.route('/api/settings/ftp/test', methods=['POST'])
@login_required
def test_ftp_settings():
    data = request.get_json(silent=True) or {}
    server = str(data.get('ftp_server') or '').strip()
    username = str(data.get('ftp_username') or '').strip()
    password = str(data.get('ftp_password') or '')
    directory = str(data.get('ftp_directory') or '').strip()
    port_value = data.get('ftp_port') or DEFAULT_SETTING_VALUES.get('ftp_port', '21')
    timeout_value = data.get('ftp_timeout_seconds') or DEFAULT_SETTING_VALUES.get('ftp_timeout_seconds', '15')

    if not server:
        return jsonify({'status': 'error', 'message': 'FTP server je povinný.'}), 400
    if not username:
        return jsonify({'status': 'error', 'message': 'FTP používateľ je povinný.'}), 400
    if not password:
        return jsonify({'status': 'error', 'message': 'FTP heslo je povinné.'}), 400

    try:
        port = int(port_value)
        if port < 1 or port > 65535:
            return jsonify({'status': 'error', 'message': 'FTP port musí byť 1-65535.'}), 400
    except (TypeError, ValueError):
        return jsonify({'status': 'error', 'message': 'Neplatná hodnota pre FTP port.'}), 400

    try:
        timeout = int(timeout_value)
        if timeout < 5 or timeout > 120:
            return jsonify({'status': 'error', 'message': 'FTP timeout musí byť 5-120 sekúnd.'}), 400
    except (TypeError, ValueError):
        return jsonify({'status': 'error', 'message': 'Neplatná hodnota pre FTP timeout.'}), 400

    try:
        with FTP(timeout=timeout) as ftp:
            ftp.connect(server, port, timeout=timeout)
            ftp.login(username, password)
            if directory:
                ftp.cwd(directory)
            ftp.voidcmd('NOOP')

        add_log('info', f"FTP spojenie úspešne otestované ({server}:{port}).")
        return jsonify({
            'status': 'success',
            'message': 'FTP spojenie je funkčné.'
        })
    except Exception as e:
        error_message = safe_ftp_error(e)
        add_log('warning', f"Test FTP spojenia zlyhal ({server}:{port}): {error_message}")
        if isinstance(e, error_perm):
            tip = 'Skontrolujte používateľské meno, heslo a oprávnenie k zadanému FTP adresáru.'
        elif isinstance(e, socket.gaierror):
            tip = 'Skontrolujte názov alebo IP adresu FTP servera a DNS.'
        elif isinstance(e, (TimeoutError, socket.timeout)):
            tip = 'Server neodpovedal včas. Skontrolujte jeho dostupnosť, FTP port a firewall.'
        elif isinstance(e, ConnectionRefusedError):
            tip = 'Server spojenie odmietol. Skontrolujte, či FTP služba beží a počúva na zadanom porte.'
        else:
            tip = 'Skontrolujte adresu servera, FTP port, prihlasovacie údaje, adresár a firewall.'
        return jsonify({
            'status': 'error',
            'message': f'FTP spojenie zlyhalo. {tip} Detail: {error_message}'
        }), 400

@app.route('/api/notifications/test', methods=['POST'])
@login_required
def test_notification():
    data = request.get_json(silent=True) or {}
    notif_type = data.get('type', 'general')

    test_messages = {
        'general':                      ("🔔 Toto je testovacia správa z MikroTik Manager.", "Test – MikroTik Manager"),
        'notify_device_offline':        ("🔴 Test: Zariadenie offline\nZariadenie: Router-Test (192.168.1.1)\nPosledný úspešný ping: pred 35 sekundami.", "Test – Zariadenie Offline"),
        'notify_device_online':         ("✅ Test: Zariadenie online\nZariadenie: Router-Test (192.168.1.1)\nZariadenie je opäť dostupné.", "Test – Zariadenie Online"),
        'notify_backup_success':        ("✅ Test: Záloha úspešná\nZariadenie: Router-Test (192.168.1.1)\nSúbory: backup_test.backup, export_test.rsc", "Test – Úspešná Záloha"),
        'notify_backup_failure':        ("❌ Test: Záloha zlyhala\nZariadenie: Router-Test (192.168.1.1)\nChyba: SSH connection timeout", "Test – Neúspešná Záloha"),
        'notify_failed_login':          ("🔐 Test: Neúspešné prihlásenie\nIP: 10.0.0.1\nPokus o prihlásenie s nesprávnym heslom.", "Test – Neúspešné Prihlásenie"),
        'notify_failed_2fa':            ("🛡️ Test: Neúspešné 2FA overenie\nIP: 10.0.0.1\nNesprávny TOTP kód.", "Test – Neúspešné 2FA"),
        'notify_password_recovery_failure': ("🚨 Test: Neúspešná obnova hesla\nIP: 10.0.0.1\nNeplatný kód alebo záložný kód.", "Test – Neúspešná Obnova Hesla"),
        'notify_ssh_host_key_change':  ("🛡️ Test: SSH kľúč vyžaduje potvrdenie\nZariadenie: Router-Test (192.168.1.1)\nFingerprint: SHA256:TEST", "Test – Potvrdenie SSH Kľúča"),
        'notify_temp_critical':         ("🌡️ Test: Kritická teplota\nZariadenie: Router-Test (192.168.1.1)\nTeplota: 78°C (prah: 75°C)", "Test – Kritická Teplota"),
        'notify_cpu_critical':          ("🖥️ Test: Kritická záťaž CPU\nZariadenie: Router-Test (192.168.1.1)\nCPU: 92% (prah: 80%)", "Test – Kritická CPU"),
        'notify_memory_critical':       ("💾 Test: Kritická pamäť\nZariadenie: Router-Test (192.168.1.1)\nPamäť: 87% (prah: 80%)", "Test – Kritická Pamäť"),
        'notify_reboot_detected':       ("🔄 Test: Reboot detekovaný\nZariadenie: Router-Test (192.168.1.1)\nUptime reset na 00:00:05.", "Test – Reboot Detekovaný"),
        'notify_version_change':        ("🆕 Test: Zmena verzie OS\nZariadenie: Router-Test (192.168.1.1)\nStarý: 7.21 → Nový: 7.22", "Test – Zmena Verzie OS"),
        'notify_cert_expiry':           ("🔐 Test: TLS certifikát expiruje\nZariadenie: Router-Test (192.168.1.1)\nCertifikát expiruje za 5 dní.", "Test – TLS Certifikát"),
        'notify_new_routeros_version':  ("📣 Test: Nová verzia RouterOS\nVerzia: 7.22\nDátum: 09.03.2026 10:38", "Test – Nová Verzia RouterOS"),
        'notify_device_purged':         ("🗑️ Test: Zariadenie definitívne odstránené\nZariadenie: Router-Test (192.168.1.1) bolo definitívne odstránené po 7-dňovej lehote", "Test – Zariadenie Vymazané z Koša"),
    }

    if notif_type == 'notify_device_purged':
        with get_db_connection() as conn:
            row = conn.execute("SELECT value FROM settings WHERE key='deleted_device_retention_days'").fetchone()
            retention_days = int(row['value'] if row else 7)
        msg = f"🗑️ Test: Zariadenie definitívne odstránené\nZariadenie: Router-Test (192.168.1.1) bolo definitívne odstránené po {retention_days}-dňovej lehote"
        title = "Test – Zariadenie Vymazané z Koša"
    else:
        msg, title = test_messages.get(notif_type, test_messages['general'])
    send_pushover_notification(msg, title=title)
    return jsonify({'status': 'success'})

@app.route('/api/snmp/timers/status', methods=['GET'])
@login_required
def get_snmp_timers_status():
    """Diagnostika stavu SNMP timerov"""
    try:
        with get_db_connection() as conn:
            devices = conn.execute('SELECT id, name, ip, snmp_interval_minutes, last_snmp_check, monitoring_paused FROM devices WHERE deleted_at IS NULL').fetchall()
            settings = {row['key']: row['value'] for row in conn.execute('SELECT key, value FROM settings').fetchall()}
            global_interval = int(settings.get('snmp_check_interval_minutes', 10))

        current_time = datetime.now()
        now_ts = time.time()

        with snmp_task_lock:
            queue_length = len(snmp_task_queue)
            state_snapshot = {device_id: dict(state) for device_id, state in snmp_task_state.items()}

        timer_status = []
        for device in devices:
            device_id = device['id']
            effective_interval = device['snmp_interval_minutes'] if device['snmp_interval_minutes'] and device['snmp_interval_minutes'] > 0 else global_interval
            effective_interval = max(effective_interval, 1)

            state = state_snapshot.get(device_id)
            next_run_minutes = None
            running = False
            paused_state = False

            if state:
                paused_state = state.get('paused', False)
                running = state.get('running', False)
                next_run = state.get('next_run')
                if next_run:
                    next_run_minutes = round(max(0.0, (next_run - now_ts) / 60), 2)

            last_check_minutes = None
            if device['last_snmp_check']:
                try:
                    last_check = datetime.fromisoformat(device['last_snmp_check'])
                    last_check_minutes = (current_time - last_check).total_seconds() / 60
                except Exception as e:
                    logger.error(f"Error parsing last_snmp_check for device {device_id}: {e}")

            if device['monitoring_paused']:
                status = 'paused'
            elif not state:
                status = 'missing'
            elif paused_state:
                status = 'paused'
            elif running:
                status = 'running'
            elif last_check_minutes and last_check_minutes > effective_interval * 2:
                status = 'overdue'
            else:
                status = 'scheduled'

            timer_status.append({
                'device_id': device_id,
                'device_name': device['name'],
                'device_ip': device['ip'],
                'interval_minutes': effective_interval,
                'status': status,
                'monitoring_paused': bool(device['monitoring_paused']),
                'next_run_minutes': next_run_minutes,
                'last_check_minutes_ago': round(last_check_minutes, 1) if last_check_minutes is not None else None,
                'running': running
            })

        return jsonify({
            'queue_length': queue_length,
            'tracked_devices': len(state_snapshot),
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

@app.route('/api/admin/export', methods=['GET'])
@login_required
def export_config():
    """Exportuje celú konfiguráciu (DB, kľúče, voliteľne zálohy) do ZIP súboru"""
    import zipfile, io as _io
    from flask import send_file
    include_backups = request.args.get('include_backups') == '1'
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')

    secret_key_file = os.path.join(DATA_DIR, 'secret.key')
    encryption_key_file = os.path.join(DATA_DIR, 'encryption.key')

    zip_buffer = _io.BytesIO()
    with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zf:
        zf.write(DB_PATH, 'mikrotik_manager.db')
        if os.path.exists(encryption_key_file):
            zf.write(encryption_key_file, 'encryption.key')
        if os.path.exists(secret_key_file):
            zf.write(secret_key_file, 'secret.key')
        if include_backups and os.path.exists(BACKUP_DIR):
            for root, dirs, files in os.walk(BACKUP_DIR):
                for file in files:
                    full_path = os.path.join(root, file)
                    arc_name = 'backups/' + os.path.relpath(full_path, BACKUP_DIR)
                    zf.write(full_path, arc_name)

    zip_buffer.seek(0)
    add_log('info', f"Konfigurácia exportovaná do ZIP {'(vrátane záloh)' if include_backups else ''}")
    return send_file(
        zip_buffer,
        mimetype='application/zip',
        as_attachment=True,
        download_name=f'mikrotik-manager-export-{timestamp}.zip'
    )


@app.route('/api/admin/bootstrap-import', methods=['POST'])
def bootstrap_import():
    """Importuje konfiguráciu zo ZIP — povolené LEN keď neexistuje žiadny user (nová inštalácia)"""
    import zipfile, io as _io
    try:
        with get_db_connection() as conn:
            user_count = conn.execute('SELECT COUNT(*) FROM users').fetchone()[0]
    except Exception:
        user_count = 0

    if user_count > 0:
        return jsonify({'error': 'Import je povolený len pri prázdnej inštalácii (žiadny používateľ v DB)'}), 403

    zip_file = request.files.get('file')
    if not zip_file:
        return jsonify({'error': 'Žiadny súbor nebol nahraný'}), 400
    if not zip_file.filename.lower().endswith('.zip'):
        return jsonify({'error': 'Neplatný formát súboru, očakáva sa .zip'}), 400

    try:
        with zipfile.ZipFile(zip_file) as zf:
            names = set(zf.namelist())
            required = {'mikrotik_manager.db', 'encryption.key', 'secret.key'}
            missing = required - names
            if missing:
                return jsonify({'error': f'Neúplný export ZIP, chýbajú: {", ".join(missing)}'}), 400

            # Nahraď DB a kľúče
            for fname in ['mikrotik_manager.db', 'encryption.key', 'secret.key']:
                dest = os.path.join(DATA_DIR, fname)
                with zf.open(fname) as src, open(dest, 'wb') as dst:
                    dst.write(src.read())

            # Oprav permissions na kľúčoch
            os.chmod(os.path.join(DATA_DIR, 'encryption.key'), 0o600)
            os.chmod(os.path.join(DATA_DIR, 'secret.key'), 0o600)

            # Zálohy (ak existujú v ZIP) — path traversal ochrana cez realpath
            import time as _time
            data_dir_real = os.path.realpath(DATA_DIR)
            backup_entries = [n for n in names if n.startswith('backups/') and not n.endswith('/')]
            for entry in backup_entries:
                dest_path = os.path.realpath(os.path.join(DATA_DIR, entry))
                if not dest_path.startswith(data_dir_real + os.sep):
                    logger.warning(f"Bootstrap import: odmietnutá podozrivá cesta: {entry}")
                    continue
                os.makedirs(os.path.dirname(dest_path), exist_ok=True)
                info = zf.getinfo(entry)
                with zf.open(entry) as src, open(dest_path, 'wb') as dst:
                    dst.write(src.read())
                # Obnov pôvodný čas vytvorenia súboru zo ZIP metadát
                mtime = _time.mktime(info.date_time + (0, 0, -1))
                os.utime(dest_path, (mtime, mtime))

        logger.info(f"Bootstrap import: DB + kľúče nahradené, {len(backup_entries)} záloha súborov")

        # Reštartuj službu po 2s aby sa stihol odoslať response
        def delayed_restart():
            import time as _time
            _time.sleep(2)
            subprocess.run(['systemctl', 'restart', 'mikrotik-manager'], check=False)

        threading.Thread(target=delayed_restart, daemon=True).start()

        return jsonify({'status': 'ok', 'restarting': True, 'backup_files': len(backup_entries)})

    except zipfile.BadZipFile:
        return jsonify({'error': 'Poškodený ZIP súbor'}), 400
    except Exception as e:
        logger.error(f"Chyba pri bootstrap importe: {e}")
        return jsonify({'error': f'Chyba pri importe: {str(e)}'}), 500


def scheduled_backup_job():
    with app.app_context():
        add_log('info', "Spúšťam naplánovanú úlohu zálohovania...")
        # Použijeme sekvenčné zálohovanie aj pre plánované úlohy
        with get_db_connection() as conn:
            devices = [dict(row) for row in conn.execute('SELECT * FROM devices WHERE deleted_at IS NULL').fetchall()]
            settings = {row['key']: row['value'] for row in conn.execute('SELECT key, value FROM settings').fetchall()}

        backup_delay = parse_int_setting(settings.get('backup_delay_seconds'), 30, 5, 300)
        available_devices = [device for device in devices if device['ip'] not in backup_tasks]
        
        if available_devices:
            add_log('info', f"Plánované zálohovanie: Spúšťam sekvenčnú zálohu pre {len(available_devices)} zariadení.")
            run_sequential_backup(available_devices, backup_delay)
        else:
            add_log('warning', "Plánované zálohovanie: Žiadne dostupné zariadenia na zálohovanie.")

# SNMP Scheduler - centralized management of SNMP polling
SNMP_MAX_WORKERS = int(os.environ.get('SNMP_MAX_WORKERS', '3'))
snmp_executor = ThreadPoolExecutor(max_workers=SNMP_MAX_WORKERS)
snmp_scheduler_thread = None
snmp_scheduler_stop = threading.Event()
snmp_scheduler_wakeup = threading.Event()
snmp_task_queue = []
snmp_task_state = {}
snmp_task_lock = threading.Lock()
snmp_task_counter = itertools.count()

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

        def run_health_check():
            try:
                with app.app_context():
                    logger.info(f"Spúšťam okamžitý SNMP health check - dôvod: {reason}")
                    check_snmp_timers_health()
                    logger.info("Okamžitý SNMP health check dokončený")
            except Exception as e:
                logger.error(f"Chyba v okamžitom health check: {e}")

        health_check_thread = threading.Thread(target=run_health_check, daemon=True)
        health_check_thread.start()

        trigger_immediate_health_check.last_run = current_time
        return True

    except Exception as e:
        logger.error(f"Chyba pri spúšťaní okamžitého health check: {e}")
        return False

def ensure_snmp_scheduler_running():
    """Spustí scheduler thread ak ešte nebeží."""
    global snmp_scheduler_thread
    if snmp_scheduler_thread and snmp_scheduler_thread.is_alive():
        return
    snmp_scheduler_stop.clear()
    snmp_scheduler_wakeup.clear()
    snmp_scheduler_thread = threading.Thread(target=snmp_scheduler_loop, daemon=True, name="snmp_scheduler")
    snmp_scheduler_thread.start()
    debug_log('debug_snmp_timers', "SNMP scheduler thread started")

def schedule_snmp_task(device_id, interval_minutes, delay_seconds=0, reason="manual_schedule"):
    """Pridá alebo aktualizuje SNMP úlohu pre zariadenie."""
    ensure_snmp_scheduler_running()
    interval = max(int(interval_minutes), 1)
    delay = max(float(delay_seconds), 0.0)
    next_run = time.time() + delay
    with snmp_task_lock:
        current = snmp_task_state.get(device_id, {})
        version = current.get('version', 0) + 1
        running = current.get('running', False)
        snmp_task_state[device_id] = {
            'interval': interval,
            'paused': False,
            'next_run': next_run,
            'version': version,
            'running': running
        }
        heapq.heappush(snmp_task_queue, (next_run, next(snmp_task_counter), device_id, version))
    snmp_scheduler_wakeup.set()
    debug_log('debug_snmp_timers', f"Scheduled SNMP task for device {device_id} in {delay:.1f}s (interval {interval}min, reason: {reason})")

def pause_snmp_task(device_id, reason="pause"):
    """Pozastaví SNMP úlohu pre zariadenie."""
    with snmp_task_lock:
        current = snmp_task_state.get(device_id, {})
        version = current.get('version', 0) + 1
        interval = current.get('interval', 1)
        snmp_task_state[device_id] = {
            'interval': interval,
            'paused': True,
            'next_run': None,
            'version': version,
            'running': False
        }
    snmp_scheduler_wakeup.set()
    debug_log('debug_snmp_timers', f"Paused SNMP task for device {device_id} (reason: {reason})")

def snmp_scheduler_loop():
    """Hlavný loop scheduleru využívajúci priority queue."""
    logger.info("SNMP scheduler loop started")
    while not snmp_scheduler_stop.is_set():
        with snmp_task_lock:
            if snmp_task_queue:
                next_run, counter, device_id, version = snmp_task_queue[0]
            else:
                next_run = None

        if next_run is None:
            snmp_scheduler_wakeup.wait(timeout=1.0)
            snmp_scheduler_wakeup.clear()
            continue

        now = time.time()
        wait_time = max(0.0, next_run - now)
        if snmp_scheduler_wakeup.wait(timeout=wait_time):
            snmp_scheduler_wakeup.clear()
            continue

        if snmp_scheduler_stop.is_set():
            break

        with snmp_task_lock:
            if not snmp_task_queue:
                continue
            due_time, counter, device_id, version = heapq.heappop(snmp_task_queue)
            state = snmp_task_state.get(device_id)
            if not state:
                continue
            if state.get('version') != version or state.get('paused'):
                state['running'] = False
                continue
            now = time.time()
            if due_time > now:
                heapq.heappush(snmp_task_queue, (due_time, counter, device_id, version))
                continue
            if state.get('running'):
                reschedule_time = now + 1.0
                state['next_run'] = reschedule_time
                heapq.heappush(snmp_task_queue, (reschedule_time, next(snmp_task_counter), device_id, version))
                continue
            state['running'] = True
            state['next_run'] = now

        snmp_executor.submit(run_snmp_job, device_id, version)

    logger.info("SNMP scheduler loop stopped")

def mark_snmp_task_complete(device_id, version):
    """Označí úlohu ako dokončenú a naplánuje ďalší interval."""
    with snmp_task_lock:
        state = snmp_task_state.get(device_id)
        if not state:
            return
        state['running'] = False
        if state.get('version') != version or state.get('paused'):
            return
        interval = max(state.get('interval', 1), 1)
        next_run = time.time() + interval * 60
        state['next_run'] = next_run
        heapq.heappush(snmp_task_queue, (next_run, next(snmp_task_counter), device_id, version))
    snmp_scheduler_wakeup.set()

def perform_snmp_poll(device_id, reason="scheduler"):
    """Vykoná SNMP dotaz pre zariadenie vrátane uloženia dát a notifikácií."""
    try:
        with get_db_connection() as conn:
            device_row = conn.execute(
                '''SELECT id, name, ip, snmp_community, snmp_version,
                          snmp_v3_username, snmp_v3_security_level,
                          snmp_v3_auth_protocol, snmp_v3_auth_password,
                          snmp_v3_priv_protocol, snmp_v3_priv_password,
                          snmp_allowed_address, monitoring_paused,
                          last_snmp_data, snmp_interval_minutes
                   FROM devices WHERE id = ? AND deleted_at IS NULL''',
                (device_id,)
            ).fetchone()

        if not device_row:
            logger.warning(f"SNMP poll skipped - device {device_id} not found (reason: {reason})")
            with snmp_task_lock:
                snmp_task_state.pop(device_id, None)
            return {'status': 'missing', 'snmp_data': None, 'device': None}
        device = get_device_with_decrypted_password(dict(device_row))

        if device['monitoring_paused'] and reason != "manual":
            debug_log('debug_snmp_timers', f"SNMP poll skipped - device {device['name']} monitoring paused (reason: {reason})")
            return {'status': 'paused', 'snmp_data': None, 'device': device}

        previous_data = {}
        if device['last_snmp_data']:
            try:
                previous_data = json.loads(device['last_snmp_data'])
            except Exception as decode_error:
                debug_log('debug_snmp_data', f"Nepodarilo sa dekódovať predchádzajúce SNMP dáta ({device['name']}): {decode_error}")
                previous_data = {}

        snmp_data = get_snmp_data(device['ip'], device)
        has_valid_metrics = snmp_data.get('uptime') != 'N/A'
        status = 'online' if has_valid_metrics else 'offline'
        timestamp = datetime.now()

        with get_db_connection() as conn:
            if has_valid_metrics:
                conn.execute(
                    "UPDATE devices SET last_snmp_data = ?, status = ?, last_snmp_check = ? WHERE id = ? AND deleted_at IS NULL",
                    (json.dumps(snmp_data), status, timestamp.isoformat(), device_id)
                )
            else:
                conn.execute(
                    "UPDATE devices SET status = ?, last_snmp_check = ? WHERE id = ? AND deleted_at IS NULL",
                    (status, timestamp.isoformat(), device_id)
                )
            conn.commit()

        save_snmp_history(device_id, snmp_data)
        debug_emit('snmp_update', {'id': device_id, 'data': snmp_data, 'status': status})

        if has_valid_metrics:
            evaluate_snmp_notifications(
                device,
                snmp_data,
                previous_data if previous_data.get('uptime') != 'N/A' else {}
            )
            debug_log('debug_snmp_data', f"SNMP data saved for {device['name']} (reason: {reason})")
        else:
            logger.warning(f"SNMP dáta pre {device['name']} neobsahovali platný uptime (reason: {reason})")

        return {
            'status': status,
            'snmp_data': snmp_data,
            'device': device,
            'has_valid': has_valid_metrics,
            'previous_data': previous_data
        }
    except Exception as e:
        logger.error(f"Error during SNMP poll for device {device_id}: {e}")
        device_ip = None
        try:
            device_ip = device['ip']  # type: ignore[name-defined]
        except Exception:
            device_ip = None
        add_log('error', f"SNMP query for device {device_id} failed: {e}", device_ip=device_ip)
        return {'status': 'error', 'error': str(e), 'snmp_data': None, 'device': None}

def run_snmp_job(device_id, version):
    """Worker funkcia vykonaná vo thread poole."""
    try:
        with app.app_context():
            perform_snmp_poll(device_id, reason="scheduler")
    finally:
        mark_snmp_task_complete(device_id, version)

def trigger_immediate_snmp_check_for_device(device_id, reason="ping_observed_online"):
    """Spustí okamžitý SNMP check pre jedno zariadenie a reštartuje jeho timer."""
    try:
        with get_db_connection() as conn:
            device = conn.execute(
                'SELECT name, ip, snmp_interval_minutes, monitoring_paused FROM devices WHERE id = ? AND deleted_at IS NULL',
                (device_id,)
            ).fetchone()
            if not device:
                logger.warning(f"Immediate SNMP trigger skipped - device {device_id} not found (reason: {reason})")
                return False
            settings = {
                row['key']: row['value']
                for row in conn.execute(
                    'SELECT key, value FROM settings WHERE key = ?',
                    ('snmp_check_interval_minutes',)
                ).fetchall()
            }
        if device['monitoring_paused']:
            debug_log('debug_snmp_timers', f"Immediate SNMP trigger skipped - device {device['name']} is paused")
            return False
        global_interval = int(settings.get('snmp_check_interval_minutes', 10))
        interval_minutes = device['snmp_interval_minutes'] if device['snmp_interval_minutes'] and device['snmp_interval_minutes'] > 0 else global_interval
        schedule_snmp_task(device_id, interval_minutes, delay_seconds=0, reason=reason)
        return True
    except Exception as e:
        logger.error(f"Failed to trigger immediate SNMP check for device {device_id} ({reason}): {e}")
        return False

def check_snmp_timers_health():
    """Kontroluje zdravie SNMP úloh a reštartuje chýbajúce alebo zaseknuté."""
    try:
        with get_db_connection() as conn:
            devices = conn.execute('SELECT id, name, ip, snmp_interval_minutes, last_snmp_check, monitoring_paused FROM devices WHERE deleted_at IS NULL').fetchall()
            settings = {row['key']: row['value'] for row in conn.execute('SELECT key, value FROM settings').fetchall()}
            global_interval = int(settings.get('snmp_check_interval_minutes', 10))
        ensure_snmp_scheduler_running()
        recovered = 0
        current_time = datetime.now()
        for device in devices:
            device_id = device['id']
            paused_db = bool(device['monitoring_paused'])
            effective_interval = device['snmp_interval_minutes'] if device['snmp_interval_minutes'] and device['snmp_interval_minutes'] > 0 else global_interval
            effective_interval = max(effective_interval, 1)
            with snmp_task_lock:
                state = snmp_task_state.get(device_id)
            if paused_db:
                pause_snmp_task(device_id, reason="health_check_pause_sync")
                continue
            if not state or state.get('paused'):
                schedule_snmp_task(device_id, effective_interval, delay_seconds=0, reason="health_check_missing")
                add_log('warning', f"SNMP plán obnovený - chýbal aktívny záznam (interval {effective_interval}min)", device['ip'])
                recovered += 1
                continue
            last_check_minutes = None
            if device['last_snmp_check']:
                try:
                    last_check = datetime.fromisoformat(device['last_snmp_check'])
                    last_check_minutes = (current_time - last_check).total_seconds() / 60
                except Exception as e:
                    logger.error(f"Error parsing last_snmp_check for device {device_id}: {e}")
            if last_check_minutes is None or last_check_minutes > effective_interval * 2:
                schedule_snmp_task(device_id, effective_interval, delay_seconds=0, reason="health_check_overdue")
                if last_check_minutes is None:
                    add_log('warning', "SNMP plán obnovený - neznámy čas posledného checku", device['ip'])
                else:
                    add_log('warning', f"SNMP plán obnovený - posledný check pred {last_check_minutes:.1f} min", device['ip'])
                recovered += 1
        return recovered
    except Exception as e:
        logger.error(f"Error in SNMP timer health check: {e}")

def scheduled_snmp_health_check():
    """Automatická kontrola zdravia SNMP timerov"""
    with app.app_context():
        check_snmp_timers_health()

def start_snmp_timer_for_device(device_id, interval_minutes, immediate=False):
    """Zabezpečí plánovanie SNMP úlohy pre dané zariadenie."""
    delay = 0 if immediate else max(int(interval_minutes), 1) * 60
    schedule_snmp_task(device_id, interval_minutes, delay_seconds=delay, reason="start_device")

def stop_snmp_timer_for_device(device_id):
    """Stop SNMP timer for a specific device"""
    pause_snmp_task(device_id, reason="manual_stop")

def restart_snmp_timer_for_device(device_id, interval_minutes):
    """Restart SNMP timer for a device with new interval"""
    schedule_snmp_task(device_id, interval_minutes, delay_seconds=0, reason="restart")

def start_all_snmp_timers():
    """Start SNMP timers for all devices based on their settings - optimized startup"""
    try:
        with get_db_connection() as conn:
            settings = {row['key']: row['value'] for row in conn.execute('SELECT key, value FROM settings').fetchall()}
            global_interval = int(settings.get('snmp_check_interval_minutes', 10))
            devices = conn.execute('SELECT id, name, snmp_interval_minutes, monitoring_paused FROM devices WHERE deleted_at IS NULL').fetchall()
        ensure_snmp_scheduler_running()
        device_count = len(devices)
        if device_count == 0:
            logger.info("No devices found for SNMP scheduling")
            return
        max_startup_time = min(300, device_count * 15)
        for i, device in enumerate(devices):
            device_interval = device['snmp_interval_minutes'] or 0
            effective_interval = device_interval if device_interval > 0 else global_interval
            effective_interval = max(effective_interval, 1)
            if device['monitoring_paused']:
                pause_snmp_task(device['id'], reason="startup_paused")
                continue
            if device_count == 1:
                start_delay = 30
            else:
                if i == 0:
                    start_delay = 30
                else:
                    start_delay = 30 + ((max_startup_time - 30) * i // (device_count - 1))
            schedule_snmp_task(device['id'], effective_interval, delay_seconds=start_delay, reason="startup")
            if i == 0 or i == device_count - 1:
                logger.info(f"Scheduled SNMP task for device {device['name']} (delay: {start_delay}s)")
    except Exception as e:
        logger.error(f"Error starting SNMP scheduler tasks: {e}")

def stop_all_snmp_timers():
    """Stop all SNMP timers"""
    global snmp_scheduler_thread
    snmp_scheduler_stop.set()
    snmp_scheduler_wakeup.set()
    if snmp_scheduler_thread and snmp_scheduler_thread.is_alive():
        snmp_scheduler_thread.join(timeout=5)
    snmp_scheduler_thread = None
    with snmp_task_lock:
        snmp_task_queue.clear()
        snmp_task_state.clear()
    logger.info("SNMP scheduler stopped")

def setup_scheduler(log_schedule_info=False):
    # Vždy vyčistíme existujúce úlohy, aby sme predišli duplicitám alebo starým nastaveniam
    schedule.clear()

    with get_db_connection() as conn:
        settings = {row['key']: row['value'] for row in conn.execute('SELECT key, value FROM settings').fetchall()}
    
    # SNMP checks are now handled by individual timers - no scheduler needed
    # Only keep essential scheduled tasks
    schedule.every().day.at("03:00").do(scheduled_log_cleanup)  # Čistenie starých logov každý deň o 3:00
    schedule.every().day.at("10:00").do(fetch_mikrotik_rss)  # Denná kontrola novej verzie RouterOS z RSS feedu
    schedule.every().day.at("09:00").do(check_certificates_expiry)  # Denná kontrola a automatická obnova SSL certifikátov
    
    snmp_health_enabled = settings.get('snmp_health_check_enabled', 'true').lower() == 'true'
    try:
        snmp_health_interval = int(settings.get('snmp_health_check_interval_minutes', 15))
    except (TypeError, ValueError):
        snmp_health_interval = 15
    snmp_health_interval = max(1, min(snmp_health_interval, 1440))

    if snmp_health_enabled:
        schedule.every(snmp_health_interval).minutes.do(scheduled_snmp_health_check)
        if log_schedule_info:
            add_log('info', f"SNMP health check je aktívny: každých {snmp_health_interval} minút.")
    elif log_schedule_info:
        add_log('info', "SNMP health check je v nastaveniach vypnutý.")
    
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

# SNMP checks sú spracované centrálnym schedulerom (pozri funkcie vyššie)

def _wait_device_offline(device_id, timeout=240, interval=3, confirmations=2):
    """Require consecutive failures so a transient REST error is not a reboot."""
    deadline = time.monotonic() + timeout
    failed_checks = 0
    while time.monotonic() < deadline:
        data, err, _ = mk_api(device_id, 'GET', 'system/identity', timeout_val=2)
        if err:
            failed_checks += 1
            if failed_checks >= confirmations:
                return True
        else:
            failed_checks = 0
        time.sleep(interval)
    return False

def _wait_device_online(device_id, timeout=300, interval=5, confirmations=3):
    """Require multiple successful identity/resource checks after a reboot."""
    deadline = time.monotonic() + timeout
    successful_checks = 0
    while time.monotonic() < deadline:
        _, identity_err, _ = mk_api(device_id, 'GET', 'system/identity', timeout_val=3)
        _, resource_err, _ = mk_api(device_id, 'GET', 'system/resource', timeout_val=3)
        if not identity_err and not resource_err:
            successful_checks += 1
            if successful_checks >= confirmations:
                return True
        else:
            successful_checks = 0
        time.sleep(interval)
    return False


def _routeros_version_key(version):
    """Return a comparable RouterOS key supporting beta/rc/final versions."""
    match = re.match(r'^\s*(\d+(?:\.\d+)*)(?:(beta|rc)(\d+))?', str(version or ''), re.IGNORECASE)
    if not match:
        return None
    numbers = [int(part) for part in match.group(1).split('.')]
    numbers = (numbers + [0] * 4)[:4]
    stage = {'beta': 0, 'rc': 1, None: 2}[match.group(2).lower() if match.group(2) else None]
    stage_number = int(match.group(3) or 0)
    return tuple(numbers + [stage, stage_number])


def _version_relation(installed, offered):
    """Return -1 for upgrade, 0 for equal, 1 for downgrade, None if unknown."""
    installed_key = _routeros_version_key(installed)
    offered_key = _routeros_version_key(offered)
    if installed_key is None or offered_key is None:
        return None
    return (installed_key > offered_key) - (installed_key < offered_key)


def _api_error_message(error):
    if isinstance(error, dict):
        return str(error.get('message') or error)
    return str(error)


def _get_routerboard_state(device_id, retries=3):
    """Distinguish a confirmed unsupported routerboard endpoint from transport errors."""
    last_error = None
    for attempt in range(retries):
        data, error, code = mk_api(device_id, 'GET', 'system/routerboard', timeout_val=8)
        if not error:
            info = data[0] if isinstance(data, list) and data else (data if isinstance(data, dict) else {})
            current = str(info.get('current-firmware') or '')
            return {
                'supported': bool(current and current != 'N/A'),
                'info': info,
                'error': None,
            }
        last_error = error
        error_text = _api_error_message(error).lower()
        explicitly_unsupported = code == 404 or (
            code == 400 and any(marker in error_text for marker in (
                'no such', 'not supported', 'unsupported', 'not implemented',
                'does not exist', 'unknown command',
            ))
        )
        if explicitly_unsupported:
            return {'supported': False, 'info': {}, 'error': None}
        if attempt < retries - 1:
            time.sleep(3)
    return {'supported': None, 'info': {}, 'error': _api_error_message(last_error)}


def _wait_routeros_version(device_id, expected_version, timeout=120, interval=5):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        data, error, _ = mk_api(device_id, 'GET', 'system/resource', timeout_val=5)
        if not error:
            info = data[0] if isinstance(data, list) and data else (data if isinstance(data, dict) else {})
            actual = str(info.get('version') or '')
            if _version_relation(actual, expected_version) == 0:
                return True, actual
        time.sleep(interval)
    return False, actual if 'actual' in locals() else ''


def _wait_routerboard_firmware(device_id, expected_version, timeout=120, interval=5):
    deadline = time.monotonic() + timeout
    last_actual = ''
    while time.monotonic() < deadline:
        state = _get_routerboard_state(device_id, retries=1)
        if state['supported'] is True:
            last_actual = str(state['info'].get('current-firmware') or '')
            if _version_relation(last_actual, expected_version) == 0:
                return True, last_actual
        time.sleep(interval)
    return False, last_actual


def _wait_services_stable(device_id, stable_seconds, interval=5):
    """Actively verify REST services for the configured stabilization period."""
    stable_seconds = max(0, int(stable_seconds))
    if stable_seconds == 0:
        return True
    deadline = time.monotonic() + stable_seconds + 120
    stable_since = None
    while time.monotonic() < deadline:
        _, identity_err, _ = mk_api(device_id, 'GET', 'system/identity', timeout_val=5)
        _, resource_err, _ = mk_api(device_id, 'GET', 'system/resource', timeout_val=5)
        now = time.monotonic()
        if not identity_err and not resource_err:
            stable_since = stable_since or now
            if now - stable_since >= stable_seconds:
                return True
        else:
            stable_since = None
        time.sleep(interval)
    return False

def _run_post_backup_delay(delay_seconds, device_name, device_ip, _emit, _step_done):
    """Samostatný krok pauzy medzi zálohou a spustením aktualizácie."""
    if delay_seconds <= 0:
        _step_done(2, msg='Pauza po zálohe je vypnutá.')
        return

    for remaining in range(delay_seconds, 0, -1):
        if remaining == delay_seconds or remaining <= 5 or remaining % 5 == 0:
            _emit('step_active', step=2, msg=f'Čakám {remaining}s po zálohe pred spustením aktualizácie...')
        time.sleep(1)
    _step_done(2, msg='Pauza po zálohe dokončená, pokračujem aktualizáciou...')

def _run_backup_before_update(device_id, device_ip, device_name, _emit, _step_done, _fail):
    """Spustí existujúcu logiku zálohy ako prvý krok aktualizácie."""
    with get_db_connection() as conn:
        settings = {row['key']: row['value'] for row in conn.execute('SELECT key, value FROM settings').fetchall()}

    enabled = settings.get('updater_backup_before_update', 'true').lower() == 'true'
    try:
        post_backup_delay = parse_int_setting(settings.get('updater_post_backup_delay'), 10, 0, 600)
    except (TypeError, ValueError):
        post_backup_delay = 10
    if not enabled:
        add_log('info', f'Záloha pred update [{device_name}]: preskočená (vypnuté v nastaveniach)', device_ip)
        _step_done(1, msg='Záloha pred aktualizáciou je vypnutá.')
        _step_done(2, msg='Pauza po zálohe preskočená, keďže záloha je vypnutá.')
        return True

    _emit('step_active', step=1, msg='Vytváram zálohu konfigurácie...')

    waited = 0
    while device_ip in backup_tasks and waited < 300:
        time.sleep(5)
        waited += 5
    if device_ip in backup_tasks:
        _emit('step_error', step=1)
        _fail('Záloha pre toto zariadenie už prebieha príliš dlho (timeout 300s)')
        return False

    with get_db_connection() as conn:
        device = conn.execute('SELECT * FROM devices WHERE id = ? AND deleted_at IS NULL', (device_id,)).fetchone()
    if not device:
        _emit('step_error', step=1)
        _fail('Zariadenie nenájdené v databáze')
        return False

    backup_tasks[device_ip] = True
    result_holder = {'backup_performed': False, 'ftp_uploaded': False, 'ftp_upload_error': None, 'status': None}

    try:
        run_backup_logic(dict(device), is_sequential=True, result_holder=result_holder)
    except Exception as e:
        _emit('step_error', step=1)
        _fail(f'Záloha zlyhala s výnimkou: {e}')
        return False

    status = result_holder.get('status')
    if status == 'error':
        _emit('step_error', step=1)
        _fail('Záloha konfigurácie zlyhala, aktualizácia bola zrušená')
        return False
    if status == 'skipped':
        add_log('info', f'Záloha pred update [{device_name}]: žiadne zmeny v konfigurácii', device_ip)
        _step_done(1, msg='Záloha preskočená, konfigurácia je bez zmien.')
        _step_done(2, msg='Pauza po zálohe preskočená, keďže nebolo čo zálohovať.')
        return True
    if status == 'success':
        if result_holder.get('ftp_uploaded'):
            add_log('info', f'Záloha pred update [{device_name}]: lokálna aj FTP záloha vytvorená', device_ip)
            _step_done(1, msg='Lokálna aj FTP záloha konfigurácie dokončená.')
        else:
            ftp_error = result_holder.get('ftp_upload_error') or 'neznáma chyba'
            add_log('warning', f'Záloha pred update [{device_name}]: lokálna záloha vytvorená, FTP kópia zlyhala: {ftp_error}', device_ip)
            _step_done(1, msg='Lokálna záloha je hotová, FTP kópia zlyhala; aktualizácia pokračuje.')
        _run_post_backup_delay(post_backup_delay, device_name, device_ip, _emit, _step_done)
        return True

    add_log('warning', f'Záloha pred update [{device_name}]: neznámy status ({status})', device_ip)
    _step_done(1, msg='Záloha dokončená, status nebol špecifikovaný.')
    _step_done(2, msg='Pauza po zálohe preskočená, status zálohy nie je jednoznačný.')
    return True

def run_scheduled_update(schedule_id, reservation_owner=None):
    """Vykoná naplánovaný full update (OS + Firmware + Reboot) pre zariadenie."""
    with app.app_context():
        device_id = None
        try:
            with get_db_connection() as conn:
                row = conn.execute(
                    'SELECT us.*, d.ip, d.name FROM update_schedule us JOIN devices d ON d.id = us.device_id AND d.deleted_at IS NULL WHERE us.id = ?',
                    (schedule_id,)
                ).fetchone()
            if not row:
                return
            device_id = row['device_id']
            device_ip = row['ip']
            device_name = row['name']
            update_channel = normalize_routeros_channel(row['update_channel'], 'stable')

            def _upd_sched(step=None, msg=None, steps_done_add=None):
                entry = _running_scheduled_updates.get(device_id, {})
                if step is not None:
                    entry['current_step'] = step
                if msg is not None:
                    entry['current_msg'] = msg
                if steps_done_add is not None:
                    steps = entry.get('steps_done', [])
                    if steps_done_add not in steps:
                        steps.append(steps_done_add)
                    entry['steps_done'] = steps
                _running_scheduled_updates[device_id] = entry

            def _emit(state, step=0, msg=''):
                if state in ('step_active',):
                    _upd_sched(step=step, msg=msg)
                elif state in ('step_done',):
                    _upd_sched(steps_done_add=step, msg=msg)
                elif state in ('done', 'failed'):
                    _running_scheduled_updates.pop(device_id, None)
                socketio.emit('scheduled_update_progress', {
                    'device_id': device_id,
                    'schedule_id': schedule_id,
                    'state': state,
                    'step': step,
                    'msg': msg,
                    'update_type': 'full'
                })

            def _step_done(step, msg=''):
                _emit('step_done', step=step, msg=msg)

            def _fail(msg):
                add_log('error', f'Naplánovaný update [{device_name}]: {msg}', device_ip)
                _emit('failed', msg=f'❌ {msg}')
                with get_db_connection() as c:
                    c.execute(
                        'UPDATE update_schedule SET status=?, completed_at=?, result_message=? WHERE id=?',
                        ('failed', datetime.now(), msg, schedule_id)
                    )
                    c.commit()
                send_pushover_notification(
                    f'❌ Naplánovaný update zariadenia {device_name} ({device_ip}) ZLYHAL: {msg}',
                    title='MikroTik Update – Chyba',
                    notification_key='notify_backup_failure'
                )

            # Načítaj konfigurovateľné pauzy zo settings
            try:
                with get_db_connection() as _sc:
                    _sett = {r['key']: r['value'] for r in _sc.execute('SELECT key, value FROM settings').fetchall()}
                stabilization_delay = parse_int_setting(_sett.get('updater_stabilization_delay'), 120, 10, 600)
                pre_reboot_delay = parse_int_setting(_sett.get('updater_pre_reboot_delay'), 20, 5, 300)
            except Exception:
                stabilization_delay = 120
                pre_reboot_delay = 20

            # Init tracking state
            _running_scheduled_updates[device_id] = {
                'device_name': device_name,
                'device_ip': device_ip,
                'schedule_id': schedule_id,
                'started_at': datetime.now().isoformat(),
                'current_step': 0,
                'steps_done': [],
                'current_msg': '',
                'update_type': 'full',
                'channel': update_channel
            }

            add_log('info', f'Naplánovaný update [{device_name}]: Spúšťam (kanál {update_channel})...', device_ip)
            _emit('start', msg=f'Naplánovaný update: {device_name}')

            if not _run_backup_before_update(device_id, device_ip, device_name, _emit, _step_done, _fail):
                return

            routerboard = _get_routerboard_state(device_id)
            if routerboard['supported'] is None:
                _fail(f"Kontrola routerboardu zlyhala: {routerboard['error']}")
                return
            is_vm = not routerboard['supported']

            # Krok 3: Zisti dostupnosť OS update
            _emit('step_active', step=3, msg='Kontrolujem dostupnosť RouterOS aktualizácie...')
            os_data, err, _ = check_routeros_updates(device_id, update_channel)
            if err:
                _emit('step_error', step=3)
                _fail(f'Zariadenie nedostupné: {err}')
                return

            os_info = {}
            if isinstance(os_data, list) and os_data:
                os_info = os_data[-1]
            elif isinstance(os_data, dict):
                os_info = os_data

            installed = os_info.get('installed-version', '')
            latest = os_info.get('latest-version', '')
            os_relation = _version_relation(installed, latest)
            if os_relation is None:
                _emit('step_error', step=3)
                _fail(f'Neplatná verzia RouterOS (nainštalovaná: {installed or "?"}, dostupná: {latest or "?"})')
                return
            has_os_update = os_relation < 0

            if has_os_update:
                _emit('step_active', step=3, msg=f'Inštalujem RouterOS {installed} → {latest}...')
                _, err, code = mk_api(device_id, 'POST', 'system/package/update/install')
                # 500 = connection error – device started updating and rebooted before responding
                if err and code != 500:
                    _emit('step_error', step=3)
                    _fail(f'Chyba inštalácie OS: {err}')
                    return
                _step_done(3)

                # Krok 4: Čakaj offline
                _emit('step_active', step=4, msg='Čakám na reštart zariadenia...')
                if not _wait_device_offline(device_id, timeout=240):
                    _emit('step_error', step=4)
                    _fail('Zariadenie sa nereštartovalo po aktualizácii OS (timeout 240s)')
                    return
                _step_done(4)

                # Krok 5: Čakaj online
                _emit('step_active', step=5, msg='Čakám kým zariadenie nabootuje...')
                if not _wait_device_online(device_id, timeout=300):
                    _emit('step_error', step=5)
                    _fail('Zariadenie sa nespustilo po aktualizácii OS (timeout 300s)')
                    return
                verified, actual_version = _wait_routeros_version(device_id, latest)
                if not verified:
                    _emit('step_error', step=5)
                    _fail(f'RouterOS po reštarte nemá očakávanú verziu {latest} (zistené: {actual_version or "neznáme"})')
                    return
                _step_done(5)

                # VM/CHR – žiadny routerboard, preskočiť kroky 6-7-8-9
                if is_vm:
                    _step_done(6)
                    _step_done(7)
                    _step_done(8)
                    _step_done(9, msg='VM/CHR – firmware preskočený.')
                    fw_summary = 'bez routerboardu (VM/CHR)'
                    msg = f'RouterOS: {installed} → {latest} | Firmware: {fw_summary}'
                    add_log('info', f'Naplánovaný update [{device_name}]: Dokončený. {msg}', device_ip)
                    with get_db_connection() as c:
                        c.execute(
                            'UPDATE update_schedule SET status=?, completed_at=?, result_message=? WHERE id=?',
                            ('done', datetime.now(), msg, schedule_id)
                        )
                        c.commit()
                    _emit('done', msg=f'✅ Naplánovaná aktualizácia dokončená! {msg}')
                    send_pushover_notification(
                        f'✅ Naplánovaný update zariadenia {device_name} ({device_ip}) dokončený. {msg}',
                        title='MikroTik Update – Hotovo',
                        notification_key='notify_backup_success'
                    )
                    record_update_completion(device_id)
                    return

                # Krok 6: stabilizácia (iba pre zariadenia s routerboardom)
                _emit('step_active', step=6, msg=f'Overujem stabilitu služieb počas {stabilization_delay}s...')
                if not _wait_services_stable(device_id, stabilization_delay):
                    _emit('step_error', step=6)
                    _fail('Služby RouterOS neboli počas stabilizačného intervalu stabilné')
                    return
                _step_done(6)
            else:
                _step_done(3)
                _step_done(4)
                _step_done(5)
                _step_done(6, msg=f'RouterOS {installed} je aktuálny.')

            # VM/CHR bez OS update – preskočiť firmware kroky
            if is_vm:
                _step_done(7)
                _step_done(8)
                _step_done(9, msg='VM/CHR – firmware nie je dostupný.')
                fw_summary = 'bez routerboardu (VM/CHR)'
                msg = f'RouterOS: {installed} ({"aktualizovaný" if has_os_update else "aktuálny"}) | Firmware: {fw_summary}'
                add_log('info', f'Naplánovaný update [{device_name}]: Dokončený. {msg}', device_ip)
                with get_db_connection() as c:
                    c.execute(
                        'UPDATE update_schedule SET status=?, completed_at=?, result_message=? WHERE id=?',
                        ('done', datetime.now(), msg, schedule_id)
                    )
                    c.commit()
                _emit('done', msg=f'✅ Naplánovaná aktualizácia dokončená! {msg}')
                send_pushover_notification(
                    f'✅ Naplánovaný update zariadenia {device_name} ({device_ip}) dokončený. {msg}',
                    title='MikroTik Update – Hotovo',
                    notification_key='notify_backup_success'
                )
                record_update_completion(device_id)
                return

            # Krok 7: Zisti dostupnosť firmware update
            _emit('step_active', step=7, msg='Kontrolujem verzie firmware...')
            routerboard = _get_routerboard_state(device_id)
            if routerboard['supported'] is None:
                _emit('step_error', step=7)
                _fail(f"Kontrola firmware zlyhala: {routerboard['error']}")
                return
            if not routerboard['supported']:
                _emit('step_error', step=7)
                _fail('Routerboard bol pred aktualizáciou dostupný, po reštarte však chýba')
                return
            fw_info = routerboard['info']

            fw_current = fw_info.get('current-firmware', '')
            fw_upgrade = fw_info.get('upgrade-firmware', '')
            fw_relation = _version_relation(fw_current, fw_upgrade)
            if fw_relation is None:
                _emit('step_error', step=7)
                _fail(f'Neplatná verzia firmware (aktuálna: {fw_current or "?"}, upgrade: {fw_upgrade or "?"})')
                return
            has_fw_update = fw_relation < 0

            if has_fw_update:
                _emit('step_active', step=7, msg=f'Inštalujem Firmware {fw_current} → {fw_upgrade}...')
                _, err, _ = mk_api(device_id, 'POST', 'system/routerboard/upgrade')
                if err:
                    _emit('step_error', step=7)
                    _fail(f'Chyba inštalácie firmware: {err}')
                    return
                _step_done(7)

                # Krok 8: čakanie pred finálnym reštartom
                _emit('step_active', step=8, msg=f'Čakám {pre_reboot_delay}s pred finálnym reštartom...')
                time.sleep(pre_reboot_delay)
                _step_done(8)

                # Krok 9: Finálny reštart
                _emit('step_active', step=9, msg='Odosielam príkaz na finálny reštart...')
                _, reboot_err, reboot_code = mk_api(device_id, 'POST', 'system/reboot')
                if reboot_err and reboot_code != 500:
                    _emit('step_error', step=9)
                    _fail(f'Príkaz na reštart zlyhal: {_api_error_message(reboot_err)}')
                    return
                if not _wait_device_offline(device_id, timeout=120):
                    _emit('step_error', step=9)
                    _fail('Zariadenie po firmware upgrade neprešlo do offline stavu (timeout 120s)')
                    return
                if not _wait_device_online(device_id, timeout=300):
                    _emit('step_error', step=9)
                    _fail('Zariadenie sa nespustilo po finálnom reštarte (timeout 300s)')
                    return
                verified, actual_firmware = _wait_routerboard_firmware(device_id, fw_upgrade)
                if not verified:
                    _emit('step_error', step=9)
                    _fail(f'Firmware po reštarte nemá očakávanú verziu {fw_upgrade} (zistené: {actual_firmware or "neznáme"})')
                    return
                _step_done(9)
            else:
                _step_done(7)
                _step_done(8)
                _step_done(9, msg='Firmware je aktuálny.')

            # Hotovo
            if not fw_current:
                fw_summary = 'bez routerboardu (VM/CHR)'
            elif has_fw_update:
                fw_summary = f'{fw_current} → {fw_upgrade}'
            else:
                fw_summary = f'{fw_current} (aktuálny)'
            msg = f'RouterOS: {installed} → {latest if has_os_update else installed} | Firmware: {fw_summary}'
            add_log('info', f'Naplánovaný update [{device_name}]: Dokončený. {msg}', device_ip)
            with get_db_connection() as c:
                c.execute(
                    'UPDATE update_schedule SET status=?, completed_at=?, result_message=? WHERE id=?',
                    ('done', datetime.now(), msg, schedule_id)
                )
                c.commit()
            _emit('done', msg=f'✅ Naplánovaná aktualizácia dokončená! {msg}')
            send_pushover_notification(
                f'✅ Naplánovaný update zariadenia {device_name} ({device_ip}) dokončený. {msg}',
                title='MikroTik Update – Hotovo',
                notification_key='notify_backup_success'
            )
            record_update_completion(device_id)

        except Exception as e:
            add_log('error', f'Naplánovaný update [schedule_id={schedule_id}]: Neočakávaná chyba: {e}')
            try:
                socketio.emit('scheduled_update_progress', {
                    'device_id': device_id or 0,
                    'schedule_id': schedule_id,
                    'state': 'failed',
                    'step': 0,
                    'msg': f'❌ Neočakávaná chyba: {e}',
                    'update_type': 'full'
                })
            except Exception:
                pass
            try:
                with get_db_connection() as c:
                    c.execute(
                        'UPDATE update_schedule SET status=?, completed_at=?, result_message=? WHERE id=?',
                        ('failed', datetime.now(), str(e), schedule_id)
                    )
                    c.commit()
            except Exception:
                pass

        finally:
            if device_id is not None and reservation_owner:
                _release_update_devices([device_id], reservation_owner)

def run_device_update(device_id, update_channel='stable', reservation_owner=None):
    """Vykoná manuálny full update (OS + Firmware + Reboot) pre zariadenie (server-side daemon thread)."""
    with app.app_context():
        try:
            update_channel = normalize_routeros_channel(update_channel, 'stable')
            with get_db_connection() as conn:
                device = conn.execute('SELECT * FROM devices WHERE id = ? AND deleted_at IS NULL', (device_id,)).fetchone()
            if not device:
                _running_manual_updates.pop(device_id, None)
                return

            device_ip = device['ip']
            device_name = device['name']

            def _upd(step=None, msg=None):
                entry = _running_manual_updates.get(device_id, {})
                if step is not None:
                    entry['current_step'] = step
                if msg is not None:
                    entry['current_msg'] = msg
                _running_manual_updates[device_id] = entry

            def _emit(state, step=0, msg=''):
                _upd(step=step if step > 0 else None, msg=msg if msg else None)
                socketio.emit('scheduled_update_progress', {
                    'device_id': device_id,
                    'schedule_id': 0,
                    'state': state,
                    'step': step,
                    'msg': msg,
                    'update_type': 'full'
                })

            def _step_done(step, msg=''):
                entry = _running_manual_updates.get(device_id, {})
                steps = entry.get('steps_done', [])
                if step not in steps:
                    steps.append(step)
                entry['steps_done'] = steps
                _running_manual_updates[device_id] = entry
                _emit('step_done', step=step, msg=msg)

            def _fail(msg):
                add_log('error', f'Manuálny update [{device_name}]: {msg}', device_ip)
                _emit('failed', msg=f'❌ {msg}')
                send_pushover_notification(
                    f'❌ Manuálny update zariadenia {device_name} ({device_ip}) ZLYHAL: {msg}',
                    title='MikroTik Update – Chyba',
                    notification_key='notify_backup_failure'
                )

            # Načítaj konfigurovateľné pauzy zo settings
            try:
                with get_db_connection() as _sc:
                    _sett = {r['key']: r['value'] for r in _sc.execute('SELECT key, value FROM settings').fetchall()}
                stabilization_delay = parse_int_setting(_sett.get('updater_stabilization_delay'), 120, 10, 600)
                pre_reboot_delay = parse_int_setting(_sett.get('updater_pre_reboot_delay'), 20, 5, 300)
            except Exception:
                stabilization_delay = 120
                pre_reboot_delay = 20

            # Init tracking state
            _running_manual_updates[device_id] = {
                'device_name': device_name,
                'device_ip': device_ip,
                'started_at': datetime.now().isoformat(),
                'current_step': 0,
                'steps_done': [],
                'current_msg': '',
                'update_type': 'full',
                'channel': update_channel
            }

            add_log('info', f'Manuálny update [{device_name}]: Spúšťam (kanál {update_channel})...', device_ip)
            _emit('start', msg=f'Manuálny update: {device_name}')

            if not _run_backup_before_update(device_id, device_ip, device_name, _emit, _step_done, _fail):
                return

            routerboard = _get_routerboard_state(device_id)
            if routerboard['supported'] is None:
                _fail(f"Kontrola routerboardu zlyhala: {routerboard['error']}")
                return
            is_vm = not routerboard['supported']

            # Krok 3: Zisti dostupnosť OS update
            _emit('step_active', step=3, msg='Kontrolujem dostupnosť RouterOS aktualizácie...')
            os_data, err, _ = check_routeros_updates(device_id, update_channel)
            if err:
                _emit('step_error', step=3)
                _fail(f'Zariadenie nedostupné: {err}')
                return

            os_info = {}
            if isinstance(os_data, list) and os_data:
                os_info = os_data[-1]
            elif isinstance(os_data, dict):
                os_info = os_data

            installed = os_info.get('installed-version', '')
            latest = os_info.get('latest-version', '')
            os_relation = _version_relation(installed, latest)
            if os_relation is None:
                _emit('step_error', step=3)
                _fail(f'Neplatná verzia RouterOS (nainštalovaná: {installed or "?"}, dostupná: {latest or "?"})')
                return
            has_os_update = os_relation < 0

            if has_os_update:
                _emit('step_active', step=3, msg=f'Inštalujem RouterOS {installed} → {latest}...')
                _, err, code = mk_api(device_id, 'POST', 'system/package/update/install')
                if err and code != 500:
                    _emit('step_error', step=3)
                    _fail(f'Chyba inštalácie OS: {err}')
                    return
                _step_done(3)

                # Krok 4: Čakaj offline
                _emit('step_active', step=4, msg='Čakám na reštart zariadenia...')
                if not _wait_device_offline(device_id, timeout=240):
                    _emit('step_error', step=4)
                    _fail('Zariadenie sa nereštartovalo po aktualizácii OS (timeout 240s)')
                    return
                _step_done(4)

                # Krok 5: Čakaj online
                _emit('step_active', step=5, msg='Čakám kým zariadenie nabootuje...')
                if not _wait_device_online(device_id, timeout=300):
                    _emit('step_error', step=5)
                    _fail('Zariadenie sa nespustilo po aktualizácii OS (timeout 300s)')
                    return
                verified, actual_version = _wait_routeros_version(device_id, latest)
                if not verified:
                    _emit('step_error', step=5)
                    _fail(f'RouterOS po reštarte nemá očakávanú verziu {latest} (zistené: {actual_version or "neznáme"})')
                    return
                _step_done(5)

                if is_vm:
                    # VM/CHR – no routerboard, skip stabilisation + firmware steps
                    for s in [6, 7, 8, 9]:
                        _step_done(s)
                    msg = f'RouterOS: {installed} → {latest} | Firmware: bez routerboardu (VM/CHR)'
                    add_log('info', f'Manuálny update [{device_name}]: Dokončený. {msg}', device_ip)
                    _emit('done', msg=f'✅ Aktualizácia dokončená! {msg}')
                    send_pushover_notification(
                        f'✅ Manuálny update zariadenia {device_name} ({device_ip}) dokončený. {msg}',
                        title='MikroTik Update – Hotovo',
                        notification_key='notify_backup_success'
                    )
                    record_update_completion(device_id)
                    return

                # Krok 6: stabilizácia
                _emit('step_active', step=6, msg=f'Overujem stabilitu služieb počas {stabilization_delay}s...')
                if not _wait_services_stable(device_id, stabilization_delay):
                    _emit('step_error', step=6)
                    _fail('Služby RouterOS neboli počas stabilizačného intervalu stabilné')
                    return
                _step_done(6)
            else:
                _step_done(3, msg=f'RouterOS {installed} je aktuálny.')
                for s in [4, 5, 6]:
                    _step_done(s)

            # Krok 7: Zisti dostupnosť firmware update
            _emit('step_active', step=7, msg='Kontrolujem verzie firmware...')
            routerboard = _get_routerboard_state(device_id)
            if routerboard['supported'] is None:
                _emit('step_error', step=7)
                _fail(f"Kontrola firmware zlyhala: {routerboard['error']}")
                return
            if not routerboard['supported']:
                _emit('step_error', step=7)
                _fail('Routerboard bol pred aktualizáciou dostupný, po reštarte však chýba')
                return
            fw_info = routerboard['info']

            fw_current = fw_info.get('current-firmware', '')
            fw_upgrade = fw_info.get('upgrade-firmware', '')
            fw_relation = _version_relation(fw_current, fw_upgrade)
            if fw_relation is None:
                _emit('step_error', step=7)
                _fail(f'Neplatná verzia firmware (aktuálna: {fw_current or "?"}, upgrade: {fw_upgrade or "?"})')
                return
            has_fw_update = fw_relation < 0

            if has_fw_update:
                _emit('step_active', step=7, msg=f'Inštalujem Firmware {fw_current} → {fw_upgrade}...')
                _, err, _ = mk_api(device_id, 'POST', 'system/routerboard/upgrade')
                if err:
                    _emit('step_error', step=7)
                    _fail(f'Chyba inštalácie firmware: {err}')
                    return
                _step_done(7)

                # Krok 8: čakanie pred finálnym reštartom
                _emit('step_active', step=8, msg=f'Čakám {pre_reboot_delay}s pred finálnym reštartom...')
                time.sleep(pre_reboot_delay)
                _step_done(8)

                # Krok 9: Finálny reštart
                _emit('step_active', step=9, msg='Odosielam príkaz na finálny reštart...')
                _, reboot_err, reboot_code = mk_api(device_id, 'POST', 'system/reboot')
                if reboot_err and reboot_code != 500:
                    _emit('step_error', step=9)
                    _fail(f'Príkaz na reštart zlyhal: {_api_error_message(reboot_err)}')
                    return
                if not _wait_device_offline(device_id, timeout=120):
                    _emit('step_error', step=9)
                    _fail('Zariadenie po firmware upgrade neprešlo do offline stavu (timeout 120s)')
                    return
                if not _wait_device_online(device_id, timeout=300):
                    _emit('step_error', step=9)
                    _fail('Zariadenie sa nespustilo po finálnom reštarte (timeout 300s)')
                    return
                verified, actual_firmware = _wait_routerboard_firmware(device_id, fw_upgrade)
                if not verified:
                    _emit('step_error', step=9)
                    _fail(f'Firmware po reštarte nemá očakávanú verziu {fw_upgrade} (zistené: {actual_firmware or "neznáme"})')
                    return
                _step_done(9)
            else:
                _step_done(7, msg='Firmware je aktuálny.')
                for s in [8, 9]:
                    _step_done(s)

            # Hotovo
            if is_vm or not fw_current:
                fw_summary = 'bez routerboardu (VM/CHR)'
            elif has_fw_update:
                fw_summary = f'{fw_current} → {fw_upgrade}'
            else:
                fw_summary = f'{fw_current} (aktuálny)'
            msg = f'RouterOS: {installed} → {latest if has_os_update else installed} | Firmware: {fw_summary}'
            add_log('info', f'Manuálny update [{device_name}]: Dokončený. {msg}', device_ip)
            _emit('done', msg=f'✅ Aktualizácia dokončená! {msg}')
            send_pushover_notification(
                f'✅ Manuálny update zariadenia {device_name} ({device_ip}) dokončený. {msg}',
                title='MikroTik Update – Hotovo',
                notification_key='notify_backup_success'
            )
            record_update_completion(device_id)

        except Exception as e:
            add_log('error', f'Manuálny update [device_id={device_id}]: Neočakávaná chyba: {e}')
            try:
                socketio.emit('scheduled_update_progress', {
                    'device_id': device_id or 0,
                    'schedule_id': 0,
                    'state': 'failed',
                    'step': 0,
                    'msg': f'❌ Neočakávaná chyba: {e}',
                    'update_type': 'full'
                })
            except Exception:
                pass
        finally:
            _running_manual_updates.pop(device_id, None)
            if reservation_owner:
                _release_update_devices([device_id], reservation_owner)


def run_device_update_os(device_id, update_channel='stable', reservation_owner=None):
    """Vykoná manuálny RouterOS-only update (kroky 1–5) pre zariadenie (server-side daemon thread)."""
    with app.app_context():
        try:
            update_channel = normalize_routeros_channel(update_channel, 'stable')
            with get_db_connection() as conn:
                device = conn.execute('SELECT * FROM devices WHERE id = ? AND deleted_at IS NULL', (device_id,)).fetchone()
            if not device:
                _running_manual_updates.pop(device_id, None)
                return

            device_ip = device['ip']
            device_name = device['name']

            def _upd(step=None, msg=None):
                entry = _running_manual_updates.get(device_id, {})
                if step is not None:
                    entry['current_step'] = step
                if msg is not None:
                    entry['current_msg'] = msg
                _running_manual_updates[device_id] = entry

            def _emit(state, step=0, msg=''):
                _upd(step=step if step > 0 else None, msg=msg if msg else None)
                socketio.emit('scheduled_update_progress', {
                    'device_id': device_id,
                    'schedule_id': 0,
                    'state': state,
                    'step': step,
                    'msg': msg,
                    'update_type': 'os'
                })

            def _step_done(step, msg=''):
                entry = _running_manual_updates.get(device_id, {})
                steps = entry.get('steps_done', [])
                if step not in steps:
                    steps.append(step)
                entry['steps_done'] = steps
                _running_manual_updates[device_id] = entry
                _emit('step_done', step=step, msg=msg)

            def _fail(msg):
                add_log('error', f'RouterOS update [{device_name}]: {msg}', device_ip)
                _emit('failed', msg=f'❌ {msg}')
                send_pushover_notification(
                    f'❌ RouterOS update zariadenia {device_name} ({device_ip}) ZLYHAL: {msg}',
                    title='MikroTik Update – Chyba',
                    notification_key='notify_backup_failure'
                )

            _running_manual_updates[device_id] = {
                'device_name': device_name,
                'device_ip': device_ip,
                'started_at': datetime.now().isoformat(),
                'current_step': 0,
                'steps_done': [],
                'current_msg': '',
                'update_type': 'os',
                'channel': update_channel
            }

            add_log('info', f'RouterOS update [{device_name}]: Spúšťam (kanál {update_channel})...', device_ip)
            _emit('start', msg=f'RouterOS update: {device_name}')

            if not _run_backup_before_update(device_id, device_ip, device_name, _emit, _step_done, _fail):
                return

            # Krok 3: Zisti dostupnosť OS update
            _emit('step_active', step=3, msg='Kontrolujem dostupnosť RouterOS aktualizácie...')
            os_data, err, _ = check_routeros_updates(device_id, update_channel)
            if err:
                _emit('step_error', step=3)
                _fail(f'Zariadenie nedostupné: {err}')
                return

            os_info = {}
            if isinstance(os_data, list) and os_data:
                os_info = os_data[-1]
            elif isinstance(os_data, dict):
                os_info = os_data

            installed = os_info.get('installed-version', '')
            latest = os_info.get('latest-version', '')
            os_relation = _version_relation(installed, latest)
            if os_relation is None:
                _emit('step_error', step=3)
                _fail(f'Neplatná verzia RouterOS (nainštalovaná: {installed or "?"}, dostupná: {latest or "?"})')
                return
            has_os_update = os_relation < 0

            if has_os_update:
                _emit('step_active', step=3, msg=f'Inštalujem RouterOS {installed} → {latest}...')
                _, err, code = mk_api(device_id, 'POST', 'system/package/update/install')
                if err and code != 500:
                    _emit('step_error', step=3)
                    _fail(f'Chyba inštalácie OS: {err}')
                    return
                _step_done(3)

                # Krok 4: Čakaj offline
                _emit('step_active', step=4, msg='Čakám na reštart zariadenia...')
                if not _wait_device_offline(device_id, timeout=240):
                    _emit('step_error', step=4)
                    _fail('Zariadenie sa nereštartovalo po aktualizácii OS (timeout 240s)')
                    return
                _step_done(4)

                # Krok 5: Čakaj online
                _emit('step_active', step=5, msg='Čakám kým zariadenie nabootuje...')
                if not _wait_device_online(device_id, timeout=300):
                    _emit('step_error', step=5)
                    _fail('Zariadenie sa nespustilo po aktualizácii OS (timeout 300s)')
                    return
                verified, actual_version = _wait_routeros_version(device_id, latest)
                if not verified:
                    _emit('step_error', step=5)
                    _fail(f'RouterOS po reštarte nemá očakávanú verziu {latest} (zistené: {actual_version or "neznáme"})')
                    return
                _step_done(5)
            else:
                _step_done(3, msg=f'RouterOS {installed} je aktuálny.')
                for s in [4, 5]:
                    _step_done(s)

            msg = f'RouterOS: {installed} → {latest if has_os_update else installed}'
            add_log('info', f'RouterOS update [{device_name}]: Dokončený. {msg}', device_ip)
            _emit('done', msg=f'✅ RouterOS update dokončený! {msg}')
            send_pushover_notification(
                f'✅ RouterOS update zariadenia {device_name} ({device_ip}) dokončený. {msg}',
                title='MikroTik Update – Hotovo',
                notification_key='notify_backup_success'
            )
            record_update_completion(device_id)

        except Exception as e:
            add_log('error', f'RouterOS update [device_id={device_id}]: Neočakávaná chyba: {e}')
            try:
                socketio.emit('scheduled_update_progress', {
                    'device_id': device_id or 0,
                    'schedule_id': 0,
                    'state': 'failed',
                    'step': 0,
                    'msg': f'❌ Neočakávaná chyba: {e}',
                    'update_type': 'os'
                })
            except Exception:
                pass
        finally:
            _running_manual_updates.pop(device_id, None)
            if reservation_owner:
                _release_update_devices([device_id], reservation_owner)


def run_device_update_firmware(device_id, reservation_owner=None):
    """Vykoná manuálny Firmware-only update (kroky 1–5, mapované z krokov 7–9) pre zariadenie."""
    with app.app_context():
        try:
            with get_db_connection() as conn:
                device = conn.execute('SELECT * FROM devices WHERE id = ? AND deleted_at IS NULL', (device_id,)).fetchone()
            if not device:
                _running_manual_updates.pop(device_id, None)
                return

            device_ip = device['ip']
            device_name = device['name']

            def _upd(step=None, msg=None):
                entry = _running_manual_updates.get(device_id, {})
                if step is not None:
                    entry['current_step'] = step
                if msg is not None:
                    entry['current_msg'] = msg
                _running_manual_updates[device_id] = entry

            def _emit(state, step=0, msg=''):
                _upd(step=step if step > 0 else None, msg=msg if msg else None)
                socketio.emit('scheduled_update_progress', {
                    'device_id': device_id,
                    'schedule_id': 0,
                    'state': state,
                    'step': step,
                    'msg': msg,
                    'update_type': 'firmware'
                })

            def _step_done(step, msg=''):
                entry = _running_manual_updates.get(device_id, {})
                steps = entry.get('steps_done', [])
                if step not in steps:
                    steps.append(step)
                entry['steps_done'] = steps
                _running_manual_updates[device_id] = entry
                _emit('step_done', step=step, msg=msg)

            def _fail(msg):
                add_log('error', f'Firmware update [{device_name}]: {msg}', device_ip)
                _emit('failed', msg=f'❌ {msg}')
                send_pushover_notification(
                    f'❌ Firmware update zariadenia {device_name} ({device_ip}) ZLYHAL: {msg}',
                    title='MikroTik Update – Chyba',
                    notification_key='notify_backup_failure'
                )

            try:
                with get_db_connection() as _sc:
                    _sett = {r['key']: r['value'] for r in _sc.execute('SELECT key, value FROM settings').fetchall()}
                pre_reboot_delay = parse_int_setting(_sett.get('updater_pre_reboot_delay'), 20, 5, 300)
            except Exception:
                pre_reboot_delay = 20

            _running_manual_updates[device_id] = {
                'device_name': device_name,
                'device_ip': device_ip,
                'started_at': datetime.now().isoformat(),
                'current_step': 0,
                'steps_done': [],
                'current_msg': '',
                'update_type': 'firmware'
            }

            add_log('info', f'Firmware update [{device_name}]: Spúšťam...', device_ip)
            _emit('start', msg=f'Firmware update: {device_name}')

            if not _run_backup_before_update(device_id, device_ip, device_name, _emit, _step_done, _fail):
                return

            # Krok 3 (≡ pôv. krok 7): Zisti dostupnosť firmware update
            _emit('step_active', step=3, msg='Kontrolujem verzie firmware...')
            routerboard = _get_routerboard_state(device_id)
            if routerboard['supported'] is None:
                _emit('step_error', step=3)
                _fail(f"Kontrola routerboardu zlyhala: {routerboard['error']}")
                return
            fw_info = routerboard['info']

            fw_current = fw_info.get('current-firmware', '')
            fw_upgrade = fw_info.get('upgrade-firmware', '')
            fw_relation = _version_relation(fw_current, fw_upgrade) if routerboard['supported'] else 0
            if routerboard['supported'] and fw_relation is None:
                _emit('step_error', step=3)
                _fail(f'Neplatná verzia firmware (aktuálna: {fw_current or "?"}, upgrade: {fw_upgrade or "?"})')
                return
            has_fw_update = routerboard['supported'] and fw_relation < 0

            if not routerboard['supported']:
                # VM/CHR – žiadny routerboard
                _step_done(3, msg='Firmware nie je podporovaný (VM/CHR).')
                for s in [4, 5]:
                    _step_done(s)
                _emit('done', msg='✅ Firmware update dokončený! (VM/CHR – bez routerboardu)')
                send_pushover_notification(
                    f'✅ Firmware update zariadenia {device_name} ({device_ip}) dokončený. VM/CHR – bez routerboardu.',
                    title='MikroTik Update – Hotovo',
                    notification_key='notify_backup_success'
                )
                record_update_completion(device_id)
                return

            if has_fw_update:
                _emit('step_active', step=3, msg=f'Inštalujem Firmware {fw_current} → {fw_upgrade}...')
                _, err, _ = mk_api(device_id, 'POST', 'system/routerboard/upgrade')
                if err:
                    _emit('step_error', step=3)
                    _fail(f'Chyba inštalácie firmware: {err}')
                    return
                _step_done(3)

                # Krok 4 (≡ pôv. krok 8): čakanie pred finálnym reštartom
                _emit('step_active', step=4, msg=f'Čakám {pre_reboot_delay}s pred finálnym reštartom...')
                time.sleep(pre_reboot_delay)
                _step_done(4)

                # Krok 5 (≡ pôv. krok 9): Finálny reštart
                _emit('step_active', step=5, msg='Odosielam príkaz na finálny reštart...')
                _, reboot_err, reboot_code = mk_api(device_id, 'POST', 'system/reboot')
                if reboot_err and reboot_code != 500:
                    _emit('step_error', step=5)
                    _fail(f'Príkaz na reštart zlyhal: {_api_error_message(reboot_err)}')
                    return
                if not _wait_device_offline(device_id, timeout=120):
                    _emit('step_error', step=5)
                    _fail('Zariadenie po firmware upgrade neprešlo do offline stavu (timeout 120s)')
                    return
                if not _wait_device_online(device_id, timeout=300):
                    _emit('step_error', step=5)
                    _fail('Zariadenie sa nespustilo po finálnom reštarte (timeout 300s)')
                    return
                verified, actual_firmware = _wait_routerboard_firmware(device_id, fw_upgrade)
                if not verified:
                    _emit('step_error', step=5)
                    _fail(f'Firmware po reštarte nemá očakávanú verziu {fw_upgrade} (zistené: {actual_firmware or "neznáme"})')
                    return
                _step_done(5)
            else:
                _step_done(3, msg=f'Firmware {fw_current} je aktuálny.')
                for s in [4, 5]:
                    _step_done(s)

            fw_summary = f'{fw_current} → {fw_upgrade}' if has_fw_update else f'{fw_current} (aktuálny)'
            msg = f'Firmware: {fw_summary}'
            add_log('info', f'Firmware update [{device_name}]: Dokončený. {msg}', device_ip)
            _emit('done', msg=f'✅ Firmware update dokončený! {msg}')
            send_pushover_notification(
                f'✅ Firmware update zariadenia {device_name} ({device_ip}) dokončený. {msg}',
                title='MikroTik Update – Hotovo',
                notification_key='notify_backup_success'
            )
            record_update_completion(device_id)

        except Exception as e:
            add_log('error', f'Firmware update [device_id={device_id}]: Neočakávaná chyba: {e}')
            try:
                socketio.emit('scheduled_update_progress', {
                    'device_id': device_id or 0,
                    'schedule_id': 0,
                    'state': 'failed',
                    'step': 0,
                    'msg': f'❌ Neočakávaná chyba: {e}',
                    'update_type': 'firmware'
                })
            except Exception:
                pass
        finally:
            _running_manual_updates.pop(device_id, None)
            if reservation_owner:
                _release_update_devices([device_id], reservation_owner)


def run_manual_bulk_update(device_ids, bulk_group_id, update_channel='stable'):
    """Vykoná sekvenčnú hromadnú manuálnu aktualizáciu – rovnaký vzor ako run_scheduled_update_bulk.
    Beží ako daemon thread, volá run_device_update() blokujúco pre každé zariadenie."""
    with app.app_context():
        try:
            with get_db_connection() as conn:
                settings = {r['key']: r['value'] for r in conn.execute('SELECT key, value FROM settings').fetchall()}
            delay = parse_int_setting(settings.get('bulk_update_delay_seconds'), 60, 10, 3600)
        except Exception:
            delay = 60
        try:
            for i, device_id in enumerate(device_ids):
                cancelled = _manual_bulk_groups[bulk_group_id].get('cancelled_ids', set())
                if device_id in cancelled:
                    _release_update_devices([device_id], bulk_group_id)
                    _manual_bulk_groups[bulk_group_id]['remaining_ids'] = [
                        d for d in device_ids[i + 1:] if d not in cancelled
                    ]
                    continue
                _manual_bulk_groups[bulk_group_id]['current_device_id'] = device_id
                _manual_bulk_groups[bulk_group_id]['remaining_ids'] = [
                    d for d in device_ids[i + 1:] if d not in cancelled
                ]
                device_channel, _ = get_device_update_channel(device_id, update_channel)
                run_device_update(device_id, device_channel, bulk_group_id)
                if i < len(device_ids) - 1:
                    time.sleep(delay)
        finally:
            _release_update_devices(device_ids, bulk_group_id)
            _manual_bulk_groups.pop(bulk_group_id, None)


def check_update_schedules():
    """Skontroluje DB na splatné naplánované updaty a spustí ich (bulk skupiny sekvenčne)."""
    try:
        now = datetime.now()
        with get_db_connection() as conn:
            due = conn.execute(
                "SELECT id, device_id, bulk_group_id, bulk_sequence FROM update_schedule WHERE status='pending' AND scheduled_time <= ? ORDER BY bulk_sequence ASC",
                (now,)
            ).fetchall()

        # Separate individual and bulk-group items
        bulk_groups = {}  # bulk_group_id -> sorted list of rows
        individual = []
        for row in due:
            if row['bulk_group_id']:
                bulk_groups.setdefault(row['bulk_group_id'], []).append(dict(row))
            else:
                individual.append(dict(row))

        # Start individual schedules immediately
        for row in individual:
            owner = f"schedule:{row['id']}"
            reserved, _ = _reserve_update_devices([row['device_id']], owner)
            if not reserved:
                continue
            with get_db_connection() as conn:
                updated = conn.execute(
                    "UPDATE update_schedule SET status='running', started_at=? WHERE id=? AND status='pending'",
                    (now, row['id'])
                ).rowcount
                conn.commit()
            if updated:
                threading.Thread(target=run_scheduled_update, args=(row['id'], owner), daemon=True).start()
            else:
                _release_update_devices([row['device_id']], owner)

        # Start bulk groups sequentially (one thread per group)
        for group_id, rows in bulk_groups.items():
            rows_sorted = sorted(rows, key=lambda r: r['bulk_sequence'])
            with _update_state_lock:
                if group_id in _active_scheduled_bulk_groups:
                    continue
            # Only start a group if no device in it is already running
            with get_db_connection() as conn:
                running_in_group = conn.execute(
                    "SELECT COUNT(*) FROM update_schedule WHERE bulk_group_id=? AND status='running'",
                    (group_id,)
                ).fetchone()[0]
            if running_in_group == 0:
                owner = f'scheduled-group:{group_id}'
                group_device_ids = [row['device_id'] for row in rows_sorted]
                reserved, _ = _reserve_update_devices(group_device_ids, owner)
                if not reserved:
                    continue
                # Start the first pending item in the group
                first = next((r for r in rows_sorted if r['id'] in [d['id'] for d in due]), None)
                if first:
                    with get_db_connection() as conn:
                        updated = conn.execute(
                            "UPDATE update_schedule SET status='running', started_at=? WHERE id=? AND status='pending'",
                            (now, first['id'])
                        ).rowcount
                        conn.commit()
                    if updated:
                        with _update_state_lock:
                            _active_scheduled_bulk_groups.add(group_id)
                        threading.Thread(
                            target=run_scheduled_update_bulk,
                            args=(first['id'], group_id, rows_sorted, owner),
                            daemon=True
                        ).start()
                    else:
                        _release_update_devices(group_device_ids, owner)
                else:
                    _release_update_devices(group_device_ids, owner)
    except Exception as e:
        logger.error(f"check_update_schedules error: {e}")


def run_scheduled_update_bulk(schedule_id, group_id, all_rows_sorted, reservation_owner=None):
    """Spustí sekvenčný bulk scheduled update – po každom zariadení čaká na delay a potom spustí ďalšie."""
    with app.app_context():
        try:
            with get_db_connection() as conn:
                settings = {r['key']: r['value'] for r in conn.execute('SELECT key, value FROM settings').fetchall()}
            delay = parse_int_setting(settings.get('bulk_update_delay_seconds'), 60, 10, 3600)
        except Exception:
            delay = 60

        try:
            # Run the first item
            run_scheduled_update(schedule_id, reservation_owner)

            # After completing, find the next pending item in the group
            for row in all_rows_sorted:
                if row['id'] == schedule_id:
                    continue
                with get_db_connection() as conn:
                    status = conn.execute(
                        "SELECT status FROM update_schedule WHERE id=?", (row['id'],)
                    ).fetchone()
                if status and status['status'] == 'pending':
                    logger.info(f"Bulk update skupiny {group_id}: čakám {delay}s pred ďalším zariadením (schedule {row['id']})")
                    time.sleep(delay)
                    now2 = datetime.now()
                    with get_db_connection() as conn:
                        updated = conn.execute(
                            "UPDATE update_schedule SET status='running', started_at=? WHERE id=? AND status='pending'",
                            (now2, row['id'])
                        ).rowcount
                        conn.commit()
                    if updated:
                        run_scheduled_update(row['id'], reservation_owner)
        finally:
            _release_update_devices([row['device_id'] for row in all_rows_sorted], reservation_owner)
            with _update_state_lock:
                _active_scheduled_bulk_groups.discard(group_id)

def check_deleted_devices_for_purge():
    """Skontroluje soft-deleted zariadenia a spustí purge pre expirované."""
    try:
        now = datetime.now(timezone.utc).isoformat()
        with get_db_connection() as conn:
            expired = conn.execute(
                'SELECT id, name, ip FROM devices WHERE deleted_at IS NOT NULL AND purge_after <= ?',
                (now,)
            ).fetchall()
        for device in expired:
            debug_log('terminal', f"Purge: zariadenie {device['name']} ({device['ip']}) - lehota uplynula")
            purge_device(device['id'])
    except Exception as e:
        logger.error(f"check_deleted_devices_for_purge error: {e}")


def run_scheduler():
    while True:
        schedule.run_pending()
        check_update_schedules()
        check_deleted_devices_for_purge()
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
    migrate_sensitive_settings()  # Encrypt plaintext sensitive values in settings
    migrate_snmp_communities()  # Encrypt plaintext SNMP community values in devices
    migrate_totp_secrets()  # Encrypt plaintext TOTP secrets in users
    migrate_backup_codes_to_hashes()  # Hash plaintext backup codes
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
        # ping odosiela pakety približne v sekundových rozostupoch; procesný limit
        # preto musí okrem timeoutu poslednej odpovede zohľadniť aj počet paketov.
        process_timeout = timeout + max(count - 1, 0) + 2
        result = subprocess.run(['ping', '-c', str(count), '-W', str(timeout), ip],
                              capture_output=True, text=True, timeout=process_timeout)
        
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
            cursor.execute('UPDATE devices SET status = ? WHERE id = ? AND deleted_at IS NULL', (ping_result['status'], device_id))
            
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
        # Offline alebo prázdne SNMP dáta by nemali vytvárať falošné zápisy
        if not snmp_data or snmp_data.get('uptime') in (None, 'N/A'):
            return
        
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

def _safe_int(value):
    try:
        if value is None:
            return None
        if isinstance(value, (int, float)):
            return int(float(value))
        text = str(value).strip()
        if not text or text.upper() == 'N/A':
            return None
        text = text.replace('%', '').replace(',', '.')
        return int(float(text))
    except (ValueError, TypeError):
        return None

def _format_duration_from_seconds(seconds):
    try:
        total_seconds = int(seconds)
    except (TypeError, ValueError):
        return "0m"
    minutes, _ = divmod(total_seconds, 60)
    hours, minutes = divmod(minutes, 60)
    days, hours = divmod(hours, 24)
    parts = []
    if days:
        parts.append(f"{days}d")
    if hours or days:
        parts.append(f"{hours}h")
    parts.append(f"{minutes}m")
    return ' '.join(parts)

def record_update_completion(device_id: int):
    """Zaznamená dokončenie updatu cez manager – potlačí nasledujúci SNMP reboot/version-change cyklus."""
    _recent_updates.add(device_id)


def evaluate_snmp_notifications(device, snmp_data, previous_data):
    """Vyhodnotí SNMP notifikácie podľa kritických limitov a zmien."""
    try:
        with get_db_connection() as conn:
            keys = ['temp_critical_threshold', 'cpu_critical_threshold', 'memory_critical_threshold']
            placeholders = ','.join('?' for _ in keys)
            rows = conn.execute(f'SELECT key, value FROM settings WHERE key IN ({placeholders})', keys).fetchall()
            settings = {row['key']: row['value'] for row in rows}
    except Exception as e:
        add_log('warning', f"Nepodarilo sa načítať nastavenia SNMP notifikácií: {e}", device['ip'])
        return

    # One-time suppression flag: True if update is running OR just completed via manager (consume-once)
    _dev_id = device['id']
    _suppress_update_noise = (
        _dev_id in _running_manual_updates
        or _dev_id in _running_scheduled_updates
        or _dev_id in _recent_updates
    )

    temperature_threshold = _safe_int(settings.get('temp_critical_threshold'))
    cpu_threshold = _safe_int(settings.get('cpu_critical_threshold'))
    memory_threshold = _safe_int(settings.get('memory_critical_threshold'))

    current_temperature = _safe_int(snmp_data.get('temperature'))
    previous_temperature = _safe_int((previous_data or {}).get('temperature'))
    if (
        temperature_threshold is not None
        and current_temperature is not None
        and current_temperature >= temperature_threshold
        and (previous_temperature is None or previous_temperature < temperature_threshold)
    ):
        message = (
            f"🌡️ MikroTik {device['name']} ({device['ip']}) prekročil kritickú teplotu: "
            f"{current_temperature}°C (limit {temperature_threshold}°C)"
        )
        add_log('warning', message, device['ip'])
        send_pushover_notification(
            message,
            title="SNMP Monitor - Teplota",
            notification_key='notify_temp_critical'
        )

    current_cpu = _safe_int(snmp_data.get('cpu_load'))
    previous_cpu = _safe_int((previous_data or {}).get('cpu_load'))
    if (
        cpu_threshold is not None
        and current_cpu is not None
        and current_cpu >= cpu_threshold
        and (previous_cpu is None or previous_cpu < cpu_threshold)
    ):
        message = (
            f"🖥️ MikroTik {device['name']} ({device['ip']}) prekročil kritické vyťaženie CPU: "
            f"{current_cpu}% (limit {cpu_threshold}%)"
        )
        add_log('warning', message, device['ip'])
        send_pushover_notification(
            message,
            title="SNMP Monitor - CPU",
            notification_key='notify_cpu_critical'
        )

    current_memory = _safe_int(snmp_data.get('memory_usage'))
    previous_memory = _safe_int((previous_data or {}).get('memory_usage'))
    if (
        memory_threshold is not None
        and current_memory is not None
        and current_memory >= memory_threshold
        and (previous_memory is None or previous_memory < memory_threshold)
    ):
        message = (
            f"💾 MikroTik {device['name']} ({device['ip']}) prekročil kritické využitie pamäte: "
            f"{current_memory}% (limit {memory_threshold}%)"
        )
        add_log('warning', message, device['ip'])
        send_pushover_notification(
            message,
            title="SNMP Monitor - Pamäť",
            notification_key='notify_memory_critical'
        )

    current_uptime = _safe_int(snmp_data.get('uptime_seconds')) if snmp_data.get('uptime') != 'N/A' else None
    previous_uptime = _safe_int((previous_data or {}).get('uptime_seconds'))
    if (
        previous_uptime is not None
        and current_uptime is not None
        and previous_uptime > current_uptime + 300
        and previous_uptime > 600
    ):
        uptime_human = _format_duration_from_seconds(current_uptime)
        message = (
            f"🔄 MikroTik {device['name']} ({device['ip']}) bol reštartovaný "
            f"(aktuálny uptime {uptime_human})"
        )
        add_log('warning', message, device['ip'])
        if _suppress_update_noise:
            debug_log('snmp', f"[reboot] Potlačená SNMP reboot notifikácia pre {device['ip']} – update prebieha alebo práve dokončený cez manager")
        else:
            send_pushover_notification(
                message,
                title="SNMP Monitor - Reboot",
                notification_key='notify_reboot_detected'
            )

    current_version = snmp_data.get('version')
    previous_version = (previous_data or {}).get('version')
    if (
        previous_version
        and current_version
        and previous_version != 'N/A'
        and current_version != 'N/A'
        and previous_version != current_version
    ):
        message = (
            f"🆕 MikroTik {device['name']} ({device['ip']}) má novú verziu RouterOS: "
            f"{previous_version} ➜ {current_version}"
        )
        add_log('info', message, device['ip'])
        if _suppress_update_noise:
            debug_log('snmp', f"[version_change] Potlačená SNMP verzia notifikácia pre {device['ip']} – update prebieha alebo práve dokončený cez manager")
        else:
            send_pushover_notification(
                message,
                title="SNMP Monitor - Verzia OS",
                notification_key='notify_version_change'
            )
        # Consume one-time flag after processing version change (last update-related check)
        _recent_updates.discard(_dev_id)
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
                    SELECT id, name, ip, ping_interval_seconds, ping_retry_interval_seconds, status
                    FROM devices
                    WHERE (monitoring_paused = 0 OR monitoring_paused IS NULL) AND deleted_at IS NULL
                ''')
                devices = cursor.fetchall()
                
                current_time = datetime.now()
                devices_to_ping = []
                
                # Najkratší interval pre dynamické nastavenie check intervalu
                shortest_interval = global_ping_interval
                
                for device in devices:
                    device_id, device_name, ip, device_ping_interval, device_ping_retry_interval, db_status = device
                    
                    # Iniciálne nastavenie tracker-a pre zariadenie ak neexistuje
                    if device_id not in device_status_tracker:
                        device_status_tracker[device_id] = {
                            'name': device_name,
                            'status': db_status or 'unknown',
                            'failed_count': 0,
                            'last_status_change': current_time,
                            'in_retry_mode': False
                        }
                    else:
                        device_status_tracker[device_id]['name'] = device_name
                    
                    # Použij device-specific interval, ak je nastavený, inak global
                    effective_interval = device_ping_interval if device_ping_interval and device_ping_interval > 0 else global_ping_interval
                    device_effective_retry = device_ping_retry_interval if device_ping_retry_interval and device_ping_retry_interval > 0 else retry_interval
                    
                    # Ak je zariadenie v retry mode, použijeme retry interval namiesto normálneho
                    if device_status_tracker[device_id]['in_retry_mode']:
                        effective_interval = device_effective_retry
                    
                    # Sleduj najkratší interval
                    if effective_interval < shortest_interval:
                        shortest_interval = effective_interval
                    
                    # Kontrola pre každé zariadenie individuálne
                    should_ping = False
                    
                    if device_id not in device_last_ping:
                        # Prvý ping - pinguj okamžite
                        should_ping = True
                        debug_log('debug_ping_monitoring', f"Device {ip} ({device_name}) (ID: {device_id}): prvý ping, interval: {effective_interval}s")
                    else:
                        # Kontrola času od posledného pingu pre toto zariadenie
                        seconds_since_ping = (current_time - device_last_ping[device_id]).total_seconds()
                        
                        if seconds_since_ping >= effective_interval:
                            should_ping = True
                            if device_status_tracker[device_id]['in_retry_mode']:
                                debug_log('debug_ping_monitoring', 
                                          f"Device {ip} ({device_name}) (ID: {device_id}): retry ping, failed count: {device_status_tracker[device_id]['failed_count']}")
                            else:
                                debug_log('debug_ping_monitoring', 
                                          f"Device {ip} ({device_name}) (ID: {device_id}): {seconds_since_ping:.2f}s od posledného pingu (interval: {effective_interval}s)")
                        else:
                            remaining = effective_interval - seconds_since_ping
                            debug_log('debug_ping_monitoring', 
                                      f"Device {ip} ({device_name}) (ID: {device_id}): zostáva {remaining:.2f}s do ďalšieho pingu")
                    
                    if should_ping:
                        devices_to_ping.append((device_id, device_name, ip, effective_interval, device_effective_retry, max_retries, ping_timeout))
                
                # Ping všetky zariadenia, ktoré potrebujú ping - spustíme ich paralelne pre presnosť
                if devices_to_ping:
                    import concurrent.futures
                    import threading
                    
                    def ping_single_device(device_info):
                        device_id, device_name, ip, interval, retry_interval, max_retries, ping_timeout = device_info
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
                                if current_status != 'online':
                                    # Zariadenie bolo offline a teraz je online - zmena stavu
                                    add_log('info', f"MikroTik {device_name} ({ip}) je opäť online")
                                    send_pushover_notification(
                                        f"🟢 MikroTik {device_name} ({ip}) je opäť online",
                                        title="MikroTik Monitor - Zariadenie Online",
                                        notification_key='notify_device_online'
                                    )
                                    trigger_immediate_snmp_check_for_device(device_id, reason="ping_online_recovery")
                                
                                # Reset retry counter and mode
                                device_status_tracker[device_id] = {
                                    'name': device_name,
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
                                        add_log('error', f"MikroTik {device_name} ({ip}) je offline (po {max_retries} neúspešných pokusoch)")
                                        send_pushover_notification(
                                            f"🔴 MikroTik {device_name} ({ip}) je offline",
                                            title="MikroTik Monitor - Zariadenie Offline",
                                            notification_key='notify_device_offline'
                                        )
                                        # Naďalej zostávame v retry mode pre monitoring
                            
                            # Uložíme výsledok a aktuálny status
                            ping_result['status'] = device_status_tracker[device_id]['status']
                            save_ping_result(device_id, ping_result)
                            
                            # Aktualizujeme stav v databáze
                            with get_db_connection() as conn:
                                conn.execute('UPDATE devices SET status = ? WHERE id = ? AND deleted_at IS NULL',
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
                    SELECT id, name, ip, ping_interval_seconds, ping_retry_interval_seconds, snmp_interval_minutes, monitoring_paused
                    FROM devices WHERE id = ? AND deleted_at IS NULL
                ''', (device_id,)).fetchone()
                
                if not device:
                    return jsonify({'status': 'error', 'message': 'Zariadenie nenájdené'}), 404
                
                # Získaj globálne nastavenia
                settings = {row['key']: row['value'] for row in 
                           conn.execute('SELECT key, value FROM settings WHERE key IN (?, ?, ?)', 
                                      ('ping_check_interval_seconds', 'ping_retry_interval', 'snmp_check_interval_minutes')).fetchall()}
                
                return jsonify({
                    'device': {
                        'id': device[0],
                        'name': device[1], 
                        'ip': device[2],
                        'ping_interval_seconds': device[3] or 0,
                        'ping_retry_interval_seconds': device[4] or 0,
                        'snmp_interval_minutes': device[5] or 0,
                        'monitoring_paused': bool(device[6])
                    },
                    'global_settings': {
                        'ping_interval_seconds': int(settings.get('ping_check_interval_seconds', 120)),
                        'ping_retry_interval_seconds': int(settings.get('ping_retry_interval', 20)),
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
            ping_retry_interval = data.get('ping_retry_interval_seconds', 0)
            snmp_interval = data.get('snmp_interval_minutes', 0)
            
            # Validácia
            if ping_interval < 0 or ping_interval > 86400:  # 0-24 hodín
                return jsonify({'status': 'error', 'message': 'Ping interval musí byť 0-86400 sekúnd'}), 400
            if ping_interval > 0 and ping_interval < 20:
                return jsonify({'status': 'error', 'message': 'Ping interval musí byť 0 (globálne) alebo minimálne 20 sekúnd'}), 400
            if ping_retry_interval < 0 or ping_retry_interval > 120:
                return jsonify({'status': 'error', 'message': 'Retry interval musí byť 0 (globálne) alebo 5-120 sekúnd'}), 400
            if 0 < ping_retry_interval < 5:
                return jsonify({'status': 'error', 'message': 'Retry interval musí byť 0 (globálne) alebo 5-120 sekúnd'}), 400
            if snmp_interval < 0 or snmp_interval > 1440:  # 0-24 hodín
                return jsonify({'status': 'error', 'message': 'SNMP interval musí byť 0-1440 minút'}), 400
            
            with get_db_connection() as conn:
                # Get old SNMP interval before update
                old_device = conn.execute('SELECT snmp_interval_minutes FROM devices WHERE id = ? AND deleted_at IS NULL', (device_id,)).fetchone()
                old_snmp_interval = old_device[0] if old_device else 0

                conn.execute('''
                    UPDATE devices
                    SET ping_interval_seconds = ?, ping_retry_interval_seconds = ?, snmp_interval_minutes = ?
                    WHERE id = ? AND deleted_at IS NULL
                ''', (ping_interval, ping_retry_interval, snmp_interval, device_id))
                conn.commit()

                device = conn.execute('SELECT name, ip FROM devices WHERE id = ? AND deleted_at IS NULL', (device_id,)).fetchone()
                if device:
                    add_log('info', f"Monitoring nastavenia aktualizované pre {device[1]} ({device[0]}): ping {ping_interval}s, retry {ping_retry_interval}s, SNMP {snmp_interval}min")
                
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
            device_data = cursor.execute('SELECT name, ip, monitoring_paused FROM devices WHERE id = ? AND deleted_at IS NULL', (device_id,)).fetchone()
            if not device_data:
                return jsonify({'status': 'error', 'message': 'Zariadenie nenájdené'}), 404

            device_name, device_ip, current_paused = device_data

            # Toggle stav - ak je NULL alebo 0, nastav na 1, inak nastav na 0
            new_paused = 0 if current_paused else 1

            # Aktualizuj monitoring_paused status
            cursor.execute('''
                UPDATE devices
                SET monitoring_paused = ?
                WHERE id = ? AND deleted_at IS NULL
            ''', (new_paused, device_id))
            conn.commit()

            # Zastav/spusti SNMP timer pre toto zariadenie
            if new_paused:
                stop_snmp_timer_for_device(device_id)
            else:
                # Získaj správny interval pre toto zariadenie pred spustením timera
                device_info = cursor.execute('SELECT snmp_interval_minutes FROM devices WHERE id = ? AND deleted_at IS NULL', (device_id,)).fetchone()
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
    """Manuálny test dostupnosti zariadenia pomocou ICMP pingov."""
    try:
        request_data = request.get_json(silent=True) or {}
        try:
            test_count = int(request_data.get('count', 1))
        except (TypeError, ValueError):
            return jsonify({'status': 'error', 'message': 'Neplatný počet pingov'}), 400

        if test_count < 1 or test_count > 5:
            return jsonify({'status': 'error', 'message': 'Počet pingov musí byť od 1 do 5'}), 400

        with get_db_connection() as conn:
            device = conn.execute('SELECT ip FROM devices WHERE id = ? AND deleted_at IS NULL', (device_id,)).fetchone()

            if not device:
                return jsonify({'status': 'error', 'message': 'Zariadenie nenájdené'}), 404
            
            # Načítaj ping_timeout nastavenie
            ping_timeout = conn.execute('SELECT value FROM settings WHERE key = ?', ('ping_timeout',)).fetchone()
            timeout = int(ping_timeout['value']) if ping_timeout else 5
            
            ip = device['ip']
            ping_result = ping_device(ip, count=test_count, timeout=timeout)
            packet_loss = int(ping_result.get('packet_loss', 100))
            ping_result['packets_sent'] = test_count
            ping_result['packets_received'] = max(
                0,
                min(test_count, round(test_count * (100 - packet_loss) / 100))
            )
            save_ping_result(device_id, ping_result)
            
            # Pošleme update cez WebSocket
            debug_emit('ping_update', {
                'device_id': device_id,
                'status': ping_result['status'],
                'avg_latency': ping_result['avg_latency'],
                'packet_loss': ping_result['packet_loss'],
                'timestamp': ping_result['timestamp']
            })
            
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
                SELECT id, name, ip, ping_interval_seconds, ping_retry_interval_seconds,
                       (SELECT MAX(timestamp) FROM ping_history WHERE device_id = devices.id) as last_ping
                FROM devices WHERE deleted_at IS NULL
            ''').fetchall()
            
            device_info = []
            current_time = datetime.now()
            for device in devices:
                device_id, name, ip, device_ping_interval, device_retry_interval, last_ping_str = device
                
                global_ping_interval = int(settings.get('ping_check_interval_seconds', '120'))
                effective_interval = device_ping_interval if device_ping_interval and device_ping_interval > 0 else global_ping_interval
                global_retry_interval = int(settings.get('ping_retry_interval', '20'))
                effective_retry_interval = device_retry_interval if device_retry_interval and device_retry_interval > 0 else global_retry_interval
                
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
                    'device_retry_interval': device_retry_interval,
                    'effective_interval': effective_interval,
                    'effective_retry_interval': effective_retry_interval,
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
            # Overiť že zariadenie nie je v koši
            if not cursor.execute('SELECT id FROM devices WHERE id = ? AND deleted_at IS NULL', (device_id,)).fetchone():
                return jsonify({'status': 'error', 'message': 'Zariadenie nenájdené'}), 404
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
            cursor.execute('SELECT ip FROM devices WHERE id = ? AND deleted_at IS NULL', (device_id,))
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
            # Overiť že zariadenie nie je v koši
            if not cursor.execute('SELECT id FROM devices WHERE id = ? AND deleted_at IS NULL', (device_id,)).fetchone():
                return jsonify({'status': 'error', 'message': 'Zariadenie nenájdené'}), 404
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
            # Overiť že zariadenie nie je v koši
            if not cursor.execute('SELECT id FROM devices WHERE id = ? AND deleted_at IS NULL', (device_id,)).fetchone():
                return jsonify({'status': 'error', 'message': 'Zariadenie nenájdené'}), 404

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
            cursor = conn.cursor()
            # Overiť že zariadenie nie je v koši
            if not cursor.execute('SELECT id FROM devices WHERE id = ? AND deleted_at IS NULL', (device_id,)).fetchone():
                return jsonify({'status': 'error', 'message': 'Zariadenie nenájdené'}), 404

            # Ping dáta s optimalizáciou pre veľké datasety

            # Pokročilý sampling pre extrémne veľké datasety (až 365 dní s 1s intervalmi)
            # PROBLÉM: rowid % sampling je neefektívny pre milióny záznamov
            # RIEŠENIE: časovo-based sampling + inteligentná hustota pre rôzne časti rozsahu

            # Najprv zistíme celkový počet záznamov v rozsahu
            cursor.execute('''
                SELECT COUNT(*) FROM ping_history 
                WHERE device_id = ? AND timestamp >= ?
            ''', (device_id, start_time.isoformat()))
            total_count = cursor.fetchone()[0] or 0
            
            if time_range in ['30d', '90d', '1y']:
                # Pre najdlhšie rozsahy: časovo-based sampling pre masívne datasety
                target_points = {'30d': 6000, '90d': 8000, '1y': 12000}[time_range]
                
                if total_count <= target_points:
                    # Ak je málo dát, zoberie všetko
                    cursor.execute('''
                        SELECT timestamp, avg_latency, packet_loss, status
                        FROM ping_history
                        WHERE device_id = ? AND timestamp >= ?
                        ORDER BY timestamp ASC
                    ''', (device_id, start_time.isoformat()))
                elif total_count > 100000:  # Pre masívne datasety (>100k záznamov)
                    # Časovo-based sampling: rozdel rozsah na segmenty a zoberie vzorky z každého
                    days_in_range = {'30d': 30, '90d': 90, '1y': 365}[time_range]
                    samples_per_day = target_points // days_in_range
                    
                    # Stratifikovaný sampling - vzorky z každého dňa
                    cursor.execute('''
                        WITH daily_samples AS (
                            SELECT timestamp, avg_latency, packet_loss, status,
                                   ROW_NUMBER() OVER (
                                       PARTITION BY DATE(timestamp) 
                                       ORDER BY timestamp
                                   ) as rn,
                                   COUNT(*) OVER (PARTITION BY DATE(timestamp)) as daily_count
                            FROM ping_history
                            WHERE device_id = ? AND timestamp >= ?
                        )
                        SELECT timestamp, avg_latency, packet_loss, status
                        FROM daily_samples
                        WHERE rn % MAX(1, daily_count / ?) = 0
                           OR timestamp >= datetime('now', '-24 hours')
                        ORDER BY timestamp ASC
                    ''', (device_id, start_time.isoformat(), samples_per_day))
                else:
                    # Stredne veľké datasety: adaptívny rowid sampling
                    dynamic_interval = max(1, total_count // target_points)
                    cursor.execute('''
                        SELECT timestamp, avg_latency, packet_loss, status
                        FROM ping_history
                        WHERE device_id = ? AND timestamp >= ? 
                          AND (rowid % ? = 0 OR timestamp >= datetime('now', '-24 hours'))
                        ORDER BY timestamp ASC
                    ''', (device_id, start_time.isoformat(), dynamic_interval))
            elif time_range in ['24h', '7d']:
                # Pre stredné rozsahy: optimalizované limity
                target_points = {'24h': 4000, '7d': 6000}[time_range]
                
                if total_count <= target_points:
                    cursor.execute('''
                        SELECT timestamp, avg_latency, packet_loss, status
                        FROM ping_history
                        WHERE device_id = ? AND timestamp >= ?
                        ORDER BY timestamp ASC
                    ''', (device_id, start_time.isoformat()))
                else:
                    dynamic_interval = max(1, total_count // target_points)
                    cursor.execute('''
                        SELECT timestamp, avg_latency, packet_loss, status
                        FROM ping_history
                        WHERE device_id = ? AND timestamp >= ? 
                          AND (rowid % ? = 0 OR timestamp >= datetime('now', '-2 hours'))
                        ORDER BY timestamp ASC
                    ''', (device_id, start_time.isoformat(), dynamic_interval))
            else:
                # Pre kratšie rozsahy: všetky dáta (ale s limitom pre bezpečnosť)
                cursor.execute('''
                    SELECT timestamp, avg_latency, packet_loss, status
                    FROM ping_history
                    WHERE device_id = ? AND timestamp >= ?
                    ORDER BY timestamp ASC
                    LIMIT 50000
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
            
            # SNMP dáta s rovnakou pokročilou logikou
            cursor.execute('''
                SELECT COUNT(*) FROM snmp_history 
                WHERE device_id = ? AND timestamp >= ?
            ''', (device_id, start_time.isoformat()))
            total_snmp_count = cursor.fetchone()[0] or 0
            
            if time_range in ['30d', '90d', '1y']:
                target_points = {'30d': 6000, '90d': 8000, '1y': 12000}[time_range]
                
                if total_snmp_count <= target_points:
                    cursor.execute('''
                        SELECT timestamp, cpu_load, temperature, memory_usage, uptime, total_memory, free_memory
                        FROM snmp_history
                        WHERE device_id = ? AND timestamp >= ?
                        ORDER BY timestamp ASC
                    ''', (device_id, start_time.isoformat()))
                elif total_snmp_count > 100000:  # Masívne SNMP datasety
                    days_in_range = {'30d': 30, '90d': 90, '1y': 365}[time_range]
                    samples_per_day = target_points // days_in_range
                    
                    cursor.execute('''
                        WITH daily_samples AS (
                            SELECT timestamp, cpu_load, temperature, memory_usage, uptime, total_memory, free_memory,
                                   ROW_NUMBER() OVER (
                                       PARTITION BY DATE(timestamp) 
                                       ORDER BY timestamp
                                   ) as rn,
                                   COUNT(*) OVER (PARTITION BY DATE(timestamp)) as daily_count
                            FROM snmp_history
                            WHERE device_id = ? AND timestamp >= ?
                        )
                        SELECT timestamp, cpu_load, temperature, memory_usage, uptime, total_memory, free_memory
                        FROM daily_samples
                        WHERE rn % MAX(1, daily_count / ?) = 0
                           OR timestamp >= datetime('now', '-24 hours')
                        ORDER BY timestamp ASC
                    ''', (device_id, start_time.isoformat(), samples_per_day))
                else:
                    dynamic_interval = max(1, total_snmp_count // target_points)
                    cursor.execute('''
                        SELECT timestamp, cpu_load, temperature, memory_usage, uptime, total_memory, free_memory
                        FROM snmp_history
                        WHERE device_id = ? AND timestamp >= ? 
                          AND (rowid % ? = 0 OR timestamp >= datetime('now', '-24 hours'))
                        ORDER BY timestamp ASC
                    ''', (device_id, start_time.isoformat(), dynamic_interval))
            elif time_range in ['24h', '7d']:
                target_points = {'24h': 4000, '7d': 6000}[time_range]
                
                if total_snmp_count <= target_points:
                    cursor.execute('''
                        SELECT timestamp, cpu_load, temperature, memory_usage, uptime, total_memory, free_memory
                        FROM snmp_history
                        WHERE device_id = ? AND timestamp >= ?
                        ORDER BY timestamp ASC
                    ''', (device_id, start_time.isoformat()))
                else:
                    dynamic_interval = max(1, total_snmp_count // target_points)
                    cursor.execute('''
                        SELECT timestamp, cpu_load, temperature, memory_usage, uptime, total_memory, free_memory
                        FROM snmp_history
                        WHERE device_id = ? AND timestamp >= ? 
                          AND (rowid % ? = 0 OR timestamp >= datetime('now', '-2 hours'))
                        ORDER BY timestamp ASC
                    ''', (device_id, start_time.isoformat(), dynamic_interval))
            else:
                cursor.execute('''
                    SELECT timestamp, cpu_load, temperature, memory_usage, uptime, total_memory, free_memory
                    FROM snmp_history
                    WHERE device_id = ? AND timestamp >= ?
                    ORDER BY timestamp ASC
                    LIMIT 50000
                ''', (device_id, start_time.isoformat()))
            
            snmp_rows = cursor.fetchall()
            snmp_data = []
            for row in snmp_rows:
                if row[4] in (None, 'N/A'):
                    # Preskoč offline/pokazené SNMP záznamy, aby sa nevykresľovali ako aktívne dáta
                    continue
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
            'optimized': time_range in ['24h', '7d', '30d', '90d', '1y']  # označuje či sa používa časový sampling
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
        'sequential_backup_running': sequential_backup_running,
        'sequential_backup_total': sequential_backup_total,
        'sequential_backup_current': sequential_backup_current
    })

@app.route('/api/backup/stop-all', methods=['POST'])
@login_required
def stop_all_backups():
    """Zastaví všetky bežiace zálohy"""
    global sequential_backup_running, sequential_backup_total, sequential_backup_current
    
    stopped_count = len(backup_tasks)
    stopped_ips = list(backup_tasks.keys())
    
    # Zastavíme sekvenčnú zálohu – aktuálne prebiehajúce úlohy necháme bezpečne dobehnúť
    sequential_backup_running = False
    sequential_backup_total = 0
    sequential_backup_current = 0
    
    if stopped_count > 0:
        add_log('warning', f"Používateľ požiadal o zastavenie záloh ({stopped_count} zariadení): {', '.join(stopped_ips)}")
        for ip in stopped_ips:
            socketio.emit('backup_status', {'ip': ip, 'status': 'stop_requested'})
        
        return jsonify({
            'status': 'success', 
            'message': 'Zastavenie záloh bolo požadované. Prebiehajúce úlohy sa dokončia a nové sa nespustia.',
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
            
            devices = [dict(row) for row in conn.execute('SELECT id, ip, name, snmp_interval_minutes, last_snmp_check FROM devices WHERE deleted_at IS NULL ORDER BY name').fetchall()]
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
