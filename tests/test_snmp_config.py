import os
import tempfile
import unittest
from unittest import mock


TEST_DATA_DIR = tempfile.mkdtemp(prefix='mikrotik-manager-snmp-tests-')
os.environ['DATA_DIR'] = TEST_DATA_DIR

import app  # noqa: E402


class SnmpConfigTests(unittest.TestCase):
    @classmethod
    def tearDownClass(cls):
        app.ping_thread_stop_flag.set()
        app.snmp_scheduler_stop.set()
        app.snmp_scheduler_wakeup.set()

    def test_v2c_credentials(self):
        credentials = app.build_snmp_credentials({
            'snmp_version': '2c', 'snmp_community': 'monitoring'
        })
        self.assertEqual(credentials.__class__.__name__, 'CommunityData')

    def test_database_contains_migration_safe_snmp_columns(self):
        with app.get_db_connection() as conn:
            columns = {row['name']: row for row in conn.execute('PRAGMA table_info(devices)').fetchall()}
            indexes = {row['name'] for row in conn.execute(
                "SELECT name FROM sqlite_master WHERE type = 'index'"
            ).fetchall()}
        for name in (
            'snmp_version', 'snmp_v3_username', 'snmp_v3_security_level',
            'snmp_v3_auth_protocol', 'snmp_v3_auth_password',
            'snmp_v3_priv_protocol', 'snmp_v3_priv_password', 'snmp_allowed_address',
            'snmp_location', 'name_source'
        ):
            self.assertIn(name, columns)
        self.assertEqual(columns['snmp_version']['dflt_value'], "'2c'")
        self.assertTrue({
            'idx_ping_history_device_timestamp',
            'idx_snmp_history_device_timestamp',
            'idx_logs_device_ip',
            'idx_update_schedule_device_id',
            'idx_devices_deleted_purge',
        }.issubset(indexes))

    def test_v3_supported_protocol_combinations(self):
        for auth_protocol in ('SHA1', 'MD5'):
            for priv_protocol in ('AES', 'DES'):
                with self.subTest(auth=auth_protocol, privacy=priv_protocol):
                    credentials = app.build_snmp_credentials({
                        'snmp_version': '3',
                        'snmp_v3_username': 'manager',
                        'snmp_v3_security_level': 'authPriv',
                        'snmp_v3_auth_protocol': auth_protocol,
                        'snmp_v3_auth_password': 'auth-passphrase',
                        'snmp_v3_priv_protocol': priv_protocol,
                        'snmp_v3_priv_password': 'priv-passphrase',
                    })
                    self.assertEqual(credentials.__class__.__name__, 'UsmUserData')

    def test_v3_auth_no_priv(self):
        credentials = app.build_snmp_credentials({
            'snmp_version': '3',
            'snmp_v3_username': 'manager',
            'snmp_v3_security_level': 'authNoPriv',
            'snmp_v3_auth_protocol': 'SHA1',
            'snmp_v3_auth_password': 'auth-passphrase',
        })
        self.assertEqual(credentials.__class__.__name__, 'UsmUserData')

    def test_validation_rejects_short_password_and_bad_cidr(self):
        _, password_error = app.validate_snmp_config({
            'snmp_version': '3', 'snmp_v3_username': 'manager',
            'snmp_v3_auth_password': 'short',
        })
        self.assertIn('8 znakov', password_error)
        _, cidr_error = app.validate_snmp_config({
            'snmp_version': '2c', 'snmp_community': 'public',
            'snmp_allowed_address': 'not-a-network',
        })
        self.assertIn('CIDR', cidr_error)

    def test_edit_preserves_encrypted_secrets(self):
        existing = {
            'snmp_version': '3', 'snmp_v3_username': 'manager',
            'snmp_v3_security_level': 'authPriv', 'snmp_v3_auth_protocol': 'SHA1',
            'snmp_v3_auth_password': app.encrypt_password('stored-auth'),
            'snmp_v3_priv_protocol': 'AES',
            'snmp_v3_priv_password': app.encrypt_password('stored-privacy'),
            'snmp_community': app.encrypt_password('stored-community'),
            'snmp_allowed_address': '192.0.2.1/32',
        }
        merged, error = app.merge_device_snmp_config({
            'snmp_version': '3', 'snmp_v3_auth_password': '',
            'snmp_v3_priv_password': ''
        }, existing)
        self.assertIsNone(error)
        self.assertEqual(merged['snmp_v3_auth_password'], 'stored-auth')
        self.assertEqual(merged['snmp_v3_priv_password'], 'stored-privacy')

    def test_purge_commits_database_cleanup_and_defers_ftp(self):
        device_id = 50
        device_ip = '192.0.2.50'
        with app.get_db_connection() as conn:
            conn.execute(
                '''INSERT OR REPLACE INTO devices
                   (id, name, ip, username, password, snmp_community, deleted_at, purge_after)
                   VALUES (?, 'Purge test', ?, 'admin', ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)''',
                (
                    device_id, device_ip,
                    app.encrypt_password('ssh-password'),
                    app.encrypt_password('community'),
                )
            )
            conn.execute(
                "INSERT INTO ping_history (device_id, timestamp, packet_loss, status) VALUES (?, CURRENT_TIMESTAMP, 0, 'online')",
                (device_id,)
            )
            conn.execute(
                "INSERT INTO snmp_history (device_id, timestamp) VALUES (?, CURRENT_TIMESTAMP)",
                (device_id,)
            )
            conn.execute(
                "INSERT INTO logs (timestamp, level, message, device_ip) VALUES (CURRENT_TIMESTAMP, 'info', 'test', ?)",
                (device_ip,)
            )
            conn.commit()

        with mock.patch.object(app.threading, 'Thread') as thread_class:
            thread = thread_class.return_value
            self.assertTrue(app.purge_device(device_id, manual=True))
            thread.start.assert_called_once_with()
            self.assertTrue(thread_class.call_args.kwargs['daemon'])

        with app.get_db_connection() as conn:
            self.assertIsNone(conn.execute('SELECT id FROM devices WHERE id = ?', (device_id,)).fetchone())
            self.assertEqual(conn.execute(
                'SELECT COUNT(*) FROM ping_history WHERE device_id = ?', (device_id,)
            ).fetchone()[0], 0)
            self.assertEqual(conn.execute(
                'SELECT COUNT(*) FROM snmp_history WHERE device_id = ?', (device_id,)
            ).fetchone()[0], 0)
            self.assertEqual(conn.execute(
                'SELECT COUNT(*) FROM logs WHERE device_ip = ?', (device_ip,)
            ).fetchone()[0], 0)

    def test_routeros_quoting_blocks_script_interpolation(self):
        quoted = app.routeros_quote('a"b\\c$d\n')
        self.assertEqual(quoted, '"a\\"b\\\\c\\$d\\0A"')

    def test_log_sanitizer_masks_snmp_v3_passwords(self):
        message = 'snmp_v3_auth_password="secret-value" snmp_v3_priv_password=other-secret'
        sanitized = app.sanitize_log_message(message)
        self.assertNotIn('secret-value', sanitized)
        self.assertNotIn('other-secret', sanitized)

    def test_device_api_persists_v3_and_never_returns_secrets(self):
        with app.get_db_connection() as conn:
            conn.execute(
                "INSERT OR IGNORE INTO users (id, username, password, totp_enabled) VALUES (1, 'tester', 'hash', 1)"
            )
            conn.execute(
                '''INSERT OR IGNORE INTO devices
                   (id, name, ip, username, password, snmp_community)
                   VALUES (1, 'Router', '192.0.2.1', 'admin', ?, ?)''',
                (app.encrypt_password('ssh-password'), app.encrypt_password('public'))
            )
            conn.commit()
        app.app.config['LOGIN_DISABLED'] = True
        client = app.app.test_client()
        with client.session_transaction() as session:
            session['_user_id'] = '1'
            session['_fresh'] = True
        with mock.patch.object(app, 'trigger_immediate_health_check'):
            response = client.post('/api/devices', json={
                'id': 1, 'name': 'Router', 'name_source': 'snmp', 'ip': '192.0.2.1', 'username': 'admin',
                'password': '', 'snmp_version': '3', 'snmp_v3_username': 'manager',
                'snmp_v3_security_level': 'authPriv', 'snmp_v3_auth_protocol': 'SHA1',
                'snmp_v3_auth_password': 'auth-secret', 'snmp_v3_priv_protocol': 'AES',
                'snmp_v3_priv_password': 'privacy-secret', 'snmp_allowed_address': '192.0.2.2/32',
                'snmp_location': 'Serverovňa 1',
                'snmp_interval_minutes': 0, 'ping_interval_seconds': 0,
                'ping_retry_interval_seconds': 0, 'cert_www_port': 0,
                'cert_www_ssl_port': 0, 'low_memory': False,
            })
        self.assertEqual(response.status_code, 200, response.get_data(as_text=True))
        devices = client.get('/api/devices').get_json()
        serialized = str(devices)
        self.assertNotIn('auth-secret', serialized)
        self.assertNotIn('privacy-secret', serialized)
        self.assertNotIn('public', serialized)
        self.assertEqual(devices[0]['password_length'], len('ssh-password'))
        self.assertEqual(devices[0]['snmp_community_length'], len('public'))
        self.assertEqual(devices[0]['snmp_v3_auth_password_length'], len('auth-secret'))
        self.assertEqual(devices[0]['snmp_v3_priv_password_length'], len('privacy-secret'))
        self.assertTrue(devices[0]['snmp_v3_auth_password_configured'])
        self.assertTrue(devices[0]['snmp_v3_priv_password_configured'])
        self.assertEqual(devices[0]['snmp_location'], 'Serverovňa 1')
        self.assertEqual(devices[0]['name_source'], 'snmp')
        reveal_headers = {'Origin': 'http://localhost'}
        reveal = client.post('/api/devices/1/secrets/reveal', json={'field': 'password'}, headers=reveal_headers)
        self.assertEqual(reveal.status_code, 200)
        self.assertEqual(reveal.get_json()['value'], 'ssh-password')
        self.assertIn('no-store', reveal.headers['Cache-Control'])
        rejected = client.post('/api/devices/1/secrets/reveal', json={'field': 'username'}, headers=reveal_headers)
        self.assertEqual(rejected.status_code, 400)
        cross_origin = client.post(
            '/api/devices/1/secrets/reveal', json={'field': 'password'},
            headers={'Origin': 'https://attacker.example'}
        )
        self.assertEqual(cross_origin.status_code, 403)

        with mock.patch.object(app, 'trigger_immediate_health_check'):
            blank_name = client.post('/api/devices', json={
                'id': 1, 'name': '   ', 'ip': '192.0.2.1', 'username': 'admin',
                'password': '', 'snmp_version': '3', 'snmp_v3_username': 'manager',
                'snmp_v3_security_level': 'authPriv', 'snmp_v3_auth_protocol': 'SHA1',
                'snmp_v3_auth_password': '', 'snmp_v3_priv_protocol': 'AES',
                'snmp_v3_priv_password': '', 'snmp_allowed_address': '192.0.2.2/32',
                'snmp_location': 'Serverovňa 1', 'snmp_interval_minutes': 0,
                'ping_interval_seconds': 0, 'ping_retry_interval_seconds': 0,
                'cert_www_port': 0, 'cert_www_ssl_port': 0, 'low_memory': False,
            })
        self.assertEqual(blank_name.status_code, 200, blank_name.get_data(as_text=True))
        updated_devices = client.get('/api/devices').get_json()
        updated_device = next(device for device in updated_devices if device['id'] == 1)
        self.assertEqual(updated_device['name'], '192.0.2.1')
        self.assertEqual(updated_device['name_source'], 'local')

    def test_provision_requires_conflict_confirmation_and_can_update_existing_account(self):
        with app.get_db_connection() as conn:
            conn.execute(
                "INSERT OR IGNORE INTO users (id, username, password, totp_enabled) VALUES (1, 'tester', 'hash', 1)"
            )
            conn.execute(
                '''INSERT OR REPLACE INTO devices
                   (id, name, ip, username, password, snmp_community, snmp_version,
                    snmp_v3_username, snmp_v3_security_level, snmp_v3_auth_protocol,
                    snmp_v3_auth_password, snmp_v3_priv_protocol, snmp_v3_priv_password)
                   VALUES (2, 'Provision Router', '192.0.2.2', 'admin', ?, ?, '3',
                           'manager', 'authPriv', 'SHA1', ?, 'AES', ?)''',
                tuple(app.encrypt_password(value) for value in (
                    'ssh-password', 'public', 'auth-secret', 'privacy-secret'
                ))
            )
            conn.commit()
        app.app.config['LOGIN_DISABLED'] = True
        client = app.app.test_client()
        with mock.patch.object(app, 'get_ssh_host_key_state', return_value={'status': 'trusted'}), \
             mock.patch.object(app, 'execute_routeros_ssh', return_value='MM_EXISTS'):
            conflict = client.post('/api/devices/2/snmp/provision', json={})
        self.assertEqual(conflict.status_code, 409)
        self.assertEqual(conflict.get_json()['error'], 'snmp_account_exists')

        valid_result = {'identity': 'router-2', 'uptime': '1d', 'version': '7.20'}
        with mock.patch.object(app, 'get_ssh_host_key_state', return_value={'status': 'trusted'}), \
             mock.patch.object(app, 'execute_routeros_ssh', side_effect=['MM_EXISTS', '']) as ssh, \
             mock.patch.object(app, 'get_snmp_data', return_value=valid_result):
            success = client.post('/api/devices/2/snmp/provision', json={'overwrite': True})
        self.assertEqual(success.status_code, 200, success.get_data(as_text=True))
        self.assertFalse(success.get_json()['default_community_reused'])
        self.assertEqual(ssh.call_count, 2)

    def test_v3_provision_reuses_system_default_community(self):
        with app.get_db_connection() as conn:
            conn.execute(
                '''INSERT OR REPLACE INTO devices
                   (id, name, ip, username, password, snmp_community, snmp_version,
                    snmp_v3_username, snmp_v3_security_level, snmp_v3_auth_protocol,
                    snmp_v3_auth_password, snmp_v3_priv_protocol, snmp_v3_priv_password)
                   VALUES (2, 'Provision Router', '192.0.2.2', 'admin', ?, ?, '3',
                           'manager', 'authPriv', 'SHA1', ?, 'AES', ?)''',
                tuple(app.encrypt_password(value) for value in (
                    'ssh-password', 'public', 'auth-secret', 'privacy-secret'
                ))
            )
            conn.commit()
        app.app.config['LOGIN_DISABLED'] = True
        client = app.app.test_client()
        valid_result = {'identity': 'router-2', 'uptime': '1d', 'version': '7.20'}
        with mock.patch.object(app, 'get_ssh_host_key_state', return_value={'status': 'trusted'}), \
             mock.patch.object(app, 'execute_routeros_ssh', side_effect=['MM_REUSE_DEFAULT', '']) as ssh, \
             mock.patch.object(app, 'get_snmp_data', return_value=valid_result):
            response = client.post('/api/devices/2/snmp/provision', json={})
        self.assertEqual(response.status_code, 200, response.get_data(as_text=True))
        self.assertTrue(response.get_json()['default_community_reused'])
        configure_command = ssh.call_args_list[1].args[1]
        self.assertIn('find where default=yes', configure_command)
        self.assertIn('name="manager"', configure_command)
        self.assertIn('security=private', configure_command)

    def test_v2c_provision_updates_routeros_community_address(self):
        with app.get_db_connection() as conn:
            conn.execute(
                '''INSERT OR REPLACE INTO devices
                   (id, name, ip, username, password, snmp_community, snmp_version,
                    snmp_allowed_address, snmp_location)
                   VALUES (3, 'V2 Router', '192.0.2.3', 'admin', ?, ?, '2c', '192.0.2.10/32', 'Rack "A"')''',
                (app.encrypt_password('ssh-password'), app.encrypt_password('monitoring'))
            )
            conn.commit()
        app.app.config['LOGIN_DISABLED'] = True
        client = app.app.test_client()
        valid_result = {'identity': 'v2-router', 'uptime': '1d', 'version': '7.20'}
        with mock.patch.object(app, 'get_ssh_host_key_state', return_value={'status': 'trusted'}), \
             mock.patch.object(app, 'execute_routeros_ssh', side_effect=['MM_REUSE_DEFAULT', '']) as ssh, \
             mock.patch.object(app, 'get_snmp_data', return_value=valid_result):
            response = client.post('/api/devices/3/snmp/provision', json={})
        self.assertEqual(response.status_code, 200, response.get_data(as_text=True))
        self.assertTrue(response.get_json()['default_community_reused'])
        configure_command = ssh.call_args_list[1].args[1]
        self.assertIn('find where default=yes', configure_command)
        self.assertIn('name="monitoring"', configure_command)
        self.assertIn('address="192.0.2.10/32"', configure_command)
        self.assertIn('security=none', configure_command)
        self.assertIn('write-access=no', configure_command)
        self.assertIn('/snmp set enabled=yes location="Rack \\"A\\""', configure_command)

    def test_provision_consolidates_existing_duplicate_into_system_default(self):
        with app.get_db_connection() as conn:
            conn.execute(
                '''INSERT OR REPLACE INTO devices
                   (id, name, ip, username, password, snmp_community, snmp_version)
                   VALUES (4, 'Duplicate Router', '192.0.2.4', 'admin', ?, ?, '2c')''',
                (app.encrypt_password('ssh-password'), app.encrypt_password('monitoring'))
            )
            conn.commit()
        app.app.config['LOGIN_DISABLED'] = True
        client = app.app.test_client()

        with mock.patch.object(app, 'get_ssh_host_key_state', return_value={'status': 'trusted'}), \
             mock.patch.object(app, 'execute_routeros_ssh', return_value='MM_EXISTS_WITH_DEFAULT'):
            conflict = client.post('/api/devices/4/snmp/provision', json={})
        self.assertEqual(conflict.status_code, 409)
        self.assertIn('duplicitný nesystémový záznam', conflict.get_json()['message'])

        valid_result = {'identity': 'router-4', 'uptime': '1d', 'version': '7.20'}
        with mock.patch.object(app, 'get_ssh_host_key_state', return_value={'status': 'trusted'}), \
             mock.patch.object(app, 'execute_routeros_ssh', side_effect=['MM_EXISTS_WITH_DEFAULT', '']) as ssh, \
             mock.patch.object(app, 'get_snmp_data', return_value=valid_result):
            response = client.post('/api/devices/4/snmp/provision', json={'overwrite': True})
        self.assertEqual(response.status_code, 200, response.get_data(as_text=True))
        self.assertTrue(response.get_json()['duplicate_community_consolidated'])
        configure_command = ssh.call_args_list[1].args[1]
        self.assertIn('find where name="monitoring"', configure_command)
        self.assertIn('find where default=yes', configure_command)
        self.assertIn('/snmp community remove $mmTarget', configure_command)
        self.assertIn('/snmp community set $mmDefault name="monitoring"', configure_command)


if __name__ == '__main__':
    unittest.main()
