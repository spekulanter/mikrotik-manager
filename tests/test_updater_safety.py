import atexit
import os
import shutil
import tempfile
import unittest
from types import SimpleNamespace
from unittest import mock


TEST_DATA_DIR = tempfile.mkdtemp(prefix='mikrotik-manager-updater-safety-tests-')
atexit.register(shutil.rmtree, TEST_DATA_DIR, ignore_errors=True)
os.environ['DATA_DIR'] = TEST_DATA_DIR

import app  # noqa: E402


class UpdaterSafetyTests(unittest.TestCase):
    def test_backup_step_finishes_without_legacy_post_backup_pause(self):
        device_id = 9901
        device_ip = '192.0.2.201'
        with app.get_db_connection() as conn:
            conn.execute('DELETE FROM devices WHERE id = ?', (device_id,))
            conn.execute(
                '''INSERT INTO devices
                   (id, name, ip, username, password, snmp_community)
                   VALUES (?, 'Updater timer test', ?, 'admin', ?, ?)''',
                (
                    device_id,
                    device_ip,
                    app.encrypt_password('ssh-password'),
                    app.encrypt_password('public'),
                )
            )
            conn.execute(
                "INSERT OR REPLACE INTO settings (key, value) VALUES ('updater_backup_before_update', 'true')"
            )
            conn.execute(
                "INSERT OR REPLACE INTO settings (key, value) VALUES ('updater_post_backup_delay', '600')"
            )
            conn.commit()

        emitted = []
        completed = []
        failures = []

        def complete_backup(device, is_sequential=False, result_holder=None):
            self.assertTrue(is_sequential)
            result_holder.update(status='success', ftp_uploaded=True)
            app.backup_tasks.pop(device_ip, None)

        try:
            with mock.patch.object(app, 'run_backup_logic', side_effect=complete_backup), \
                    mock.patch.object(app.time, 'sleep') as sleep:
                result = app._run_backup_before_update(
                    device_id,
                    device_ip,
                    'Updater timer test',
                    lambda state, **payload: emitted.append((state, payload)),
                    lambda step, msg='': completed.append((step, msg)),
                    failures.append,
                )
            self.assertTrue(result)
            self.assertEqual([step for step, _ in completed], [1])
            self.assertEqual([payload['step'] for _, payload in emitted], [1])
            self.assertEqual(failures, [])
            sleep.assert_not_called()
        finally:
            app.backup_tasks.pop(device_ip, None)
            with app.get_db_connection() as conn:
                conn.execute('DELETE FROM devices WHERE id = ?', (device_id,))
                conn.commit()

    def test_legacy_post_backup_setting_is_hidden_and_ignored(self):
        with app.get_db_connection() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO settings (key, value) VALUES ('updater_post_backup_delay', '99')"
            )
            conn.commit()

        with mock.patch.dict(app.app.config, {'LOGIN_DISABLED': True}):
            client = app.app.test_client()
            payload = client.get('/api/settings').get_json()
            response = client.post('/api/settings', json={'updater_post_backup_delay': '77'})

        self.assertNotIn('updater_post_backup_delay', payload)
        self.assertEqual(response.status_code, 200)
        with app.get_db_connection() as conn:
            value = conn.execute(
                "SELECT value FROM settings WHERE key = 'updater_post_backup_delay'"
            ).fetchone()['value']
        self.assertEqual(value, '99')

    def test_full_update_reports_dense_eight_step_sequence(self):
        device_id = 9902
        with app.get_db_connection() as conn:
            conn.execute('DELETE FROM devices WHERE id = ?', (device_id,))
            conn.execute(
                '''INSERT INTO devices
                   (id, name, ip, username, password, snmp_community)
                   VALUES (?, 'Eight step test', '192.0.2.202', 'admin', ?, ?)''',
                (
                    device_id,
                    app.encrypt_password('ssh-password'),
                    app.encrypt_password('public'),
                )
            )
            conn.execute(
                "INSERT OR REPLACE INTO settings (key, value) VALUES ('updater_backup_before_update', 'false')"
            )
            conn.commit()

        events = []
        routerboard_state = {
            'supported': True,
            'info': {'current-firmware': '7.25beta5', 'upgrade-firmware': '7.24.4'},
            'error': None,
        }
        try:
            with mock.patch.object(app.socketio, 'emit', side_effect=lambda event, payload: events.append((event, payload))), \
                    mock.patch.object(app, '_get_routerboard_state', return_value=routerboard_state), \
                    mock.patch.object(
                        app,
                        'check_routeros_updates',
                        return_value=([{'installed-version': '7.25beta5', 'latest-version': '7.24.4'}], None, 200),
                    ), \
                    mock.patch.object(app, 'mk_api', return_value=({}, None, 200)) as os_api, \
                    mock.patch.object(app, '_wait_device_offline', return_value=True), \
                    mock.patch.object(app, '_wait_device_online', return_value=True), \
                    mock.patch.object(app, '_wait_routeros_version', return_value=(True, '7.24.4')), \
                    mock.patch.object(app, '_wait_services_stable', return_value=True), \
                    mock.patch.object(app, '_wait_routerboard_firmware', return_value=(True, '7.24.4')), \
                    mock.patch.object(app.time, 'sleep'), \
                    mock.patch.object(app, 'send_pushover_notification'), \
                    mock.patch.object(app, 'record_update_completion'), \
                    mock.patch.object(app, 'add_log'):
                app.run_device_update(device_id)

            completed_steps = [
                payload['step']
                for event, payload in events
                if event == 'scheduled_update_progress' and payload.get('state') == 'step_done'
            ]
            self.assertEqual(completed_steps, list(range(1, 9)))
            self.assertFalse(any(step > 8 for step in completed_steps))
            os_api.assert_any_call(device_id, 'POST', 'system/package/update/install')
            os_api.assert_any_call(device_id, 'POST', 'system/routerboard/upgrade')
        finally:
            with app.get_db_connection() as conn:
                conn.execute('DELETE FROM devices WHERE id = ?', (device_id,))
                conn.execute(
                    "INSERT OR REPLACE INTO settings (key, value) VALUES ('updater_backup_before_update', 'true')"
                )
                conn.commit()

    def test_component_updates_report_dense_four_step_sequences(self):
        device_id = 9903
        with app.get_db_connection() as conn:
            conn.execute('DELETE FROM devices WHERE id = ?', (device_id,))
            conn.execute(
                '''INSERT INTO devices
                   (id, name, ip, username, password, snmp_community)
                   VALUES (?, 'Four step test', '192.0.2.203', 'admin', ?, ?)''',
                (
                    device_id,
                    app.encrypt_password('ssh-password'),
                    app.encrypt_password('public'),
                )
            )
            conn.execute(
                "INSERT OR REPLACE INTO settings (key, value) VALUES ('updater_backup_before_update', 'false')"
            )
            conn.commit()

        def completed_steps(events):
            return [
                payload['step']
                for event, payload in events
                if event == 'scheduled_update_progress' and payload.get('state') == 'step_done'
            ]

        try:
            os_events = []
            with mock.patch.object(app.socketio, 'emit', side_effect=lambda event, payload: os_events.append((event, payload))), \
                    mock.patch.object(
                        app,
                        'check_routeros_updates',
                        return_value=([{'installed-version': '7.19', 'latest-version': '7.20'}], None, 200),
                    ), \
                    mock.patch.object(app, 'mk_api', return_value=({}, None, 200)), \
                    mock.patch.object(app, '_wait_device_offline', return_value=True), \
                    mock.patch.object(app, '_wait_device_online', return_value=True), \
                    mock.patch.object(app, '_wait_routeros_version', return_value=(True, '7.20')), \
                    mock.patch.object(app, 'send_pushover_notification'), \
                    mock.patch.object(app, 'record_update_completion'), \
                    mock.patch.object(app, 'add_log'):
                app.run_device_update_os(device_id)
            self.assertEqual(completed_steps(os_events), list(range(1, 5)))

            firmware_events = []
            routerboard_state = {
                'supported': True,
                'info': {'current-firmware': '7.25beta5', 'upgrade-firmware': '7.24.4'},
                'error': None,
            }
            with mock.patch.object(app.socketio, 'emit', side_effect=lambda event, payload: firmware_events.append((event, payload))), \
                    mock.patch.object(app, '_get_routerboard_state', return_value=routerboard_state), \
                    mock.patch.object(app, 'mk_api', return_value=({}, None, 200)) as firmware_api, \
                    mock.patch.object(app, '_wait_device_offline', return_value=True), \
                    mock.patch.object(app, '_wait_device_online', return_value=True), \
                    mock.patch.object(app, '_wait_routerboard_firmware', return_value=(True, '7.24.4')), \
                    mock.patch.object(app.time, 'sleep'), \
                    mock.patch.object(app, 'send_pushover_notification'), \
                    mock.patch.object(app, 'record_update_completion'), \
                    mock.patch.object(app, 'add_log'):
                app.run_device_update_firmware(device_id)
            self.assertEqual(completed_steps(firmware_events), list(range(1, 5)))
            firmware_api.assert_any_call(device_id, 'POST', 'system/routerboard/upgrade')
        finally:
            with app.get_db_connection() as conn:
                conn.execute('DELETE FROM devices WHERE id = ?', (device_id,))
                conn.execute(
                    "INSERT OR REPLACE INTO settings (key, value) VALUES ('updater_backup_before_update', 'true')"
                )
                conn.commit()

    def test_routeros_version_order_handles_beta_rc_final_and_downgrade(self):
        self.assertLess(app._version_relation('7.21beta6', '7.21rc1'), 0)
        self.assertLess(app._version_relation('7.21rc2', '7.21'), 0)
        self.assertLess(app._version_relation('7.20.6', '7.21beta1'), 0)
        self.assertEqual(app._version_relation('7.24', '7.24.0'), 0)
        self.assertGreater(app._version_relation('7.24.1', '7.24'), 0)
        self.assertGreater(app._version_relation('7.25beta5', '7.24.4'), 0)
        self.assertIsNone(app._version_relation('', '7.24'))

    def test_offline_wait_requires_consecutive_failures(self):
        responses = [
            ({}, None, 200),
            (None, {'message': 'temporary'}, 500),
            ({}, None, 200),
            (None, {'message': 'offline'}, 500),
            (None, {'message': 'offline'}, 500),
        ]
        with mock.patch.object(app, 'mk_api', side_effect=responses) as api, \
                mock.patch.object(app.time, 'sleep'):
            self.assertTrue(app._wait_device_offline(1, timeout=5, interval=0))
        self.assertEqual(api.call_count, 5)

    def test_online_wait_requires_identity_and_resource_to_be_stable(self):
        with mock.patch.object(app, 'mk_api', return_value=({}, None, 200)) as api, \
                mock.patch.object(app.time, 'sleep'):
            self.assertTrue(app._wait_device_online(1, timeout=5, interval=0, confirmations=3))
        self.assertEqual(api.call_count, 6)

    def test_routerboard_transport_error_is_not_classified_as_vm(self):
        transport_error = (None, {'message': 'timeout'}, 500)
        with mock.patch.object(app, 'mk_api', return_value=transport_error), \
                mock.patch.object(app.time, 'sleep'):
            state = app._get_routerboard_state(1)
        self.assertIsNone(state['supported'])
        self.assertIn('timeout', state['error'])

        with mock.patch.object(app, 'mk_api', return_value=(None, {'message': 'not found'}, 404)):
            state = app._get_routerboard_state(1)
        self.assertFalse(state['supported'])
        self.assertIsNone(state['error'])

        with mock.patch.object(app, 'mk_api', return_value=(None, {'message': 'bad request'}, 400)), \
                mock.patch.object(app.time, 'sleep'):
            state = app._get_routerboard_state(1)
        self.assertIsNone(state['supported'])


class BackupArtifactTests(unittest.TestCase):
    def test_remote_cleanup_removes_all_backups_and_only_related_exports(self):
        class FakeSftp:
            def __init__(self):
                self.removed = []

            def listdir(self, directory):
                return {
                    '.': [
                        'AP_Katka_192.0.2.7_20260921-0203.backup',
                        'AP_Katka_192.0.2.7_20260921-0203.rsc',
                        'manual.backup',
                        'manual.rsc',
                        'notes.rsc',
                        'script.rsc',
                    ],
                    'flash': [
                        'other_192.0.2.8_20260922-0304.backup',
                        'other_192.0.2.8_20260922-0304.rsc',
                        'orphan_192.0.2.9_20260920-0102.rsc',
                        'keep-this.txt',
                    ],
                }[directory]

            def remove(self, path):
                self.removed.append(path)

        sftp = FakeSftp()
        removed = app._cleanup_remote_backup_artifacts(sftp)
        self.assertEqual(removed, [
            'AP_Katka_192.0.2.7_20260921-0203.backup',
            'AP_Katka_192.0.2.7_20260921-0203.rsc',
            'manual.backup',
            'manual.rsc',
            'flash/other_192.0.2.8_20260922-0304.backup',
            'flash/other_192.0.2.8_20260922-0304.rsc',
            'flash/orphan_192.0.2.9_20260920-0102.rsc',
        ])
        self.assertNotIn('notes.rsc', sftp.removed)
        self.assertNotIn('script.rsc', sftp.removed)
        self.assertNotIn('flash/keep-this.txt', sftp.removed)

    def test_remote_cleanup_can_keep_new_validated_backup(self):
        class FakeSftp:
            def __init__(self):
                self.removed = []

            def listdir(self, directory):
                if directory == '.':
                    return [
                        'Router_192.0.2.7_20260921-0203.backup',
                        'Router_192.0.2.7_20260921-0203.rsc',
                        'Router_192.0.2.7_20260922-030405.backup',
                        'Router_192.0.2.7_20260922-030405.rsc',
                    ]
                return []

            def remove(self, path):
                self.removed.append(path)

        sftp = FakeSftp()
        newest = 'Router_192.0.2.7_20260922-030405.backup'
        removed = app._cleanup_remote_backup_artifacts(
            sftp, keep_path=newest
        )
        self.assertEqual(removed, [
            'Router_192.0.2.7_20260921-0203.backup',
            'Router_192.0.2.7_20260921-0203.rsc',
        ])
        self.assertNotIn(newest, sftp.removed)
        self.assertNotIn('Router_192.0.2.7_20260922-030405.rsc', sftp.removed)

    def test_remote_file_waits_for_nonempty_stable_size(self):
        sizes = iter([0, 1024, 2048, 2048, 2048])

        class FakeSftp:
            def stat(self, _path):
                return SimpleNamespace(st_size=next(sizes))

        with mock.patch.object(app.time, 'sleep'):
            size = app._wait_for_remote_file(FakeSftp(), 'backup.backup', 5, poll_seconds=0)
        self.assertEqual(size, 2048)


if __name__ == '__main__':
    unittest.main()
