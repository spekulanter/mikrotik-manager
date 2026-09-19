import atexit
import os
import shutil
import tempfile
import unittest
from datetime import datetime, timedelta
from unittest import mock

TEST_DATA_DIR = tempfile.mkdtemp(prefix='mikrotik-manager-sites-tests-')
atexit.register(shutil.rmtree, TEST_DATA_DIR, ignore_errors=True)
os.environ['DATA_DIR'] = TEST_DATA_DIR

import app


class SitesTests(unittest.TestCase):
    SITE_IDS = (701, 702)
    DEVICE_IDS = (701, 702, 703)

    @classmethod
    def setUpClass(cls):
        app.app.config['LOGIN_DISABLED'] = True
        with app.get_db_connection() as conn:
            conn.execute(
                "INSERT OR IGNORE INTO users (id, username, password, totp_enabled) "
                "VALUES (9701, 'sites-test', 'hash', 1)"
            )
            conn.commit()

    def setUp(self):
        self.client = app.app.test_client()
        app._manual_bulk_groups.clear()
        app._running_manual_updates.clear()
        app._running_scheduled_updates.clear()
        app._reserved_update_devices.clear()
        app._active_scheduled_bulk_groups.clear()
        with app.get_db_connection() as conn:
            placeholders = ','.join('?' for _ in self.DEVICE_IDS)
            conn.execute(f'DELETE FROM update_schedule WHERE device_id IN ({placeholders})', self.DEVICE_IDS)
            conn.execute(f'DELETE FROM devices WHERE id IN ({placeholders})', self.DEVICE_IDS)
            site_placeholders = ','.join('?' for _ in self.SITE_IDS)
            conn.execute(f'DELETE FROM sites WHERE id IN ({site_placeholders})', self.SITE_IDS)
            conn.execute(
                "INSERT INTO sites (id, name, description) VALUES (701, 'Bratislava', 'Centrála')"
            )
            conn.execute(
                "INSERT INTO sites (id, name, description) VALUES (702, 'Košice', NULL)"
            )
            for device_id, name, ip, site_id in (
                (701, 'Router A', '192.0.2.71', 701),
                (702, 'Router B', '192.0.2.72', 702),
                (703, 'Router C', '192.0.2.73', None),
            ):
                conn.execute(
                    '''INSERT INTO devices
                       (id, name, ip, username, password, snmp_community, site_id)
                       VALUES (?, ?, ?, 'admin', ?, ?, ?)''',
                    (
                        device_id, name, ip,
                        app.encrypt_password('ssh-password'),
                        app.encrypt_password('public'), site_id,
                    )
                )
            conn.commit()

    def tearDown(self):
        app._manual_bulk_groups.clear()
        app._running_manual_updates.clear()
        app._running_scheduled_updates.clear()
        app._reserved_update_devices.clear()
        app._active_scheduled_bulk_groups.clear()

    def test_schema_contains_sites_and_device_index(self):
        with app.get_db_connection() as conn:
            columns = {row['name'] for row in conn.execute('PRAGMA table_info(devices)').fetchall()}
            indexes = {row['name'] for row in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='index'"
            ).fetchall()}
        self.assertIn('site_id', columns)
        self.assertIn('idx_devices_site_id', indexes)

    def test_sites_api_requires_login(self):
        with mock.patch.dict(app.app.config, {'LOGIN_DISABLED': False}):
            response = self.client.get('/api/sites')
        self.assertEqual(response.status_code, 302)
        self.assertIn('/login', response.headers['Location'])

    def test_site_crud_validation_and_case_insensitive_uniqueness(self):
        response = self.client.post('/api/sites', json={'name': '  Žilina  ', 'description': ' Pobočka '})
        self.assertEqual(response.status_code, 201, response.get_data(as_text=True))
        site_id = response.get_json()['site']['id']
        self.assertEqual(response.get_json()['site']['name'], 'Žilina')

        duplicate = self.client.post('/api/sites', json={'name': 'žilina'})
        self.assertEqual(duplicate.status_code, 409)
        self.assertEqual(self.client.post('/api/sites', json={'name': ''}).status_code, 400)
        self.assertEqual(self.client.post('/api/sites', json={'name': 'x' * 101}).status_code, 400)

        updated = self.client.put(f'/api/sites/{site_id}', json={'name': 'Žilina-sever', 'description': ''})
        self.assertEqual(updated.status_code, 200)
        self.assertEqual(updated.get_json()['site']['name'], 'Žilina-sever')

    def test_delete_site_unassigns_active_and_deleted_devices(self):
        with app.get_db_connection() as conn:
            conn.execute(
                "UPDATE devices SET deleted_at=CURRENT_TIMESTAMP, purge_after=CURRENT_TIMESTAMP WHERE id=702"
            )
            conn.execute('UPDATE devices SET site_id=701 WHERE id=702')
            conn.commit()
        response = self.client.delete('/api/sites/701')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()['unassigned_device_count'], 2)
        with app.get_db_connection() as conn:
            values = [row['site_id'] for row in conn.execute(
                'SELECT site_id FROM devices WHERE id IN (701,702) ORDER BY id'
            ).fetchall()]
        self.assertEqual(values, [None, None])

    def test_device_api_round_trips_site_assignment(self):
        with mock.patch.object(app, 'trigger_immediate_health_check'):
            response = self.client.post('/api/devices', json={
                'id': 703, 'name': 'Router C', 'name_source': 'local',
                'site_id': 701, 'ip': '192.0.2.73', 'username': 'admin', 'password': '',
                'snmp_version': '2c', 'snmp_community': '', 'snmp_interval_minutes': 0,
                'ping_interval_seconds': 0, 'ping_retry_interval_seconds': 0,
                'cert_www_port': 0, 'cert_www_ssl_port': 0,
            })
        self.assertEqual(response.status_code, 200, response.get_data(as_text=True))
        devices = self.client.get('/api/devices').get_json()
        device = next(item for item in devices if item['id'] == 703)
        self.assertEqual(device['site_id'], 701)
        self.assertEqual(device['site_name'], 'Bratislava')

    def test_partition_preserves_order_and_unassigned_group(self):
        with app.get_db_connection() as conn:
            groups = app._partition_devices_by_site(conn, [703, 701, 702, 701])
        self.assertEqual([group['site_name'] for group in groups], ['Bez lokality', 'Bratislava', 'Košice'])
        self.assertEqual([[d['id'] for d in group['devices']] for group in groups], [[703], [701], [702]])

    def test_scheduled_bulk_creates_one_group_per_site(self):
        scheduled_time = (datetime.now() + timedelta(hours=1)).isoformat(timespec='minutes')
        response = self.client.post('/api/updater/schedule/bulk', json={
            'device_ids': [701, 703, 702],
            'scheduled_time': scheduled_time,
            'channel': 'stable',
        })
        payload = response.get_json()
        self.assertEqual(response.status_code, 200, response.get_data(as_text=True))
        self.assertEqual(len(payload['groups']), 3)
        self.assertEqual(len({group['bulk_group_id'] for group in payload['groups']}), 3)
        with app.get_db_connection() as conn:
            rows = conn.execute(
                'SELECT device_id, bulk_group_id FROM update_schedule WHERE device_id IN (701,702,703)'
            ).fetchall()
        self.assertEqual(len(rows), 3)
        self.assertEqual(len({row['bulk_group_id'] for row in rows}), 3)

    def test_manual_bulk_starts_parallel_site_workers_and_reserves_devices(self):
        with mock.patch.object(app.threading, 'Thread') as thread_class:
            response = self.client.post('/api/updater/run-bulk-update', json={
                'device_ids': [701, 703, 702], 'channel': 'stable'
            })
        payload = response.get_json()
        self.assertEqual(response.status_code, 200, response.get_data(as_text=True))
        self.assertEqual(len(payload['groups']), 3)
        self.assertEqual(thread_class.call_count, 3)
        self.assertEqual(set(app._reserved_update_devices), {701, 702, 703})

        conflict = self.client.post('/api/updater/run-update/701', json={'channel': 'stable'})
        self.assertEqual(conflict.status_code, 409)

    def test_scheduler_starts_site_group_once_and_defers_busy_group(self):
        with app.get_db_connection() as conn:
            conn.execute('UPDATE devices SET site_id=701 WHERE id=703')
            due = datetime.now() - timedelta(minutes=1)
            conn.execute(
                '''INSERT INTO update_schedule
                   (device_id, scheduled_time, status, created_at, bulk_group_id, bulk_sequence)
                   VALUES (701, ?, 'pending', ?, 'site-test-group', 0)''',
                (due, due)
            )
            conn.execute(
                '''INSERT INTO update_schedule
                   (device_id, scheduled_time, status, created_at, bulk_group_id, bulk_sequence)
                   VALUES (703, ?, 'pending', ?, 'site-test-group', 1)''',
                (due, due)
            )
            conn.commit()

        with mock.patch.object(app.threading, 'Thread') as thread_class:
            app.check_update_schedules()
            app.check_update_schedules()
        self.assertEqual(thread_class.call_count, 1)
        self.assertIn('site-test-group', app._active_scheduled_bulk_groups)

        app._active_scheduled_bulk_groups.clear()
        app._release_update_devices([701, 703])
        with app.get_db_connection() as conn:
            conn.execute("UPDATE update_schedule SET status='pending', started_at=NULL WHERE bulk_group_id='site-test-group'")
            conn.commit()
        reserved, _ = app._reserve_update_devices([701], 'manual-test')
        self.assertTrue(reserved)
        with mock.patch.object(app.threading, 'Thread') as thread_class:
            app.check_update_schedules()
        self.assertEqual(thread_class.call_count, 0)
        with app.get_db_connection() as conn:
            statuses = {row['status'] for row in conn.execute(
                "SELECT status FROM update_schedule WHERE bulk_group_id='site-test-group'"
            ).fetchall()}
        self.assertEqual(statuses, {'pending'})


if __name__ == '__main__':
    unittest.main()
