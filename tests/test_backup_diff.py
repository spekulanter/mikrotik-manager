import atexit
import os
import shutil
import tempfile
import unittest
from unittest import mock


TEST_DATA_DIR = tempfile.mkdtemp(prefix='mikrotik-manager-backup-diff-tests-')
atexit.register(shutil.rmtree, TEST_DATA_DIR, ignore_errors=True)
os.environ['DATA_DIR'] = TEST_DATA_DIR

import app  # noqa: E402


class BackupDiffTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        app.app.config['LOGIN_DISABLED'] = True
        with app.get_db_connection() as conn:
            conn.execute(
                "INSERT OR IGNORE INTO users (id, username, password, totp_enabled) "
                "VALUES (901, 'backup-diff-test', 'hash', 1)"
            )
            conn.commit()

    def setUp(self):
        self.backup_dir = tempfile.mkdtemp(prefix='exports-', dir=TEST_DATA_DIR)
        self.original_backup_dir = app.BACKUP_DIR
        app.BACKUP_DIR = self.backup_dir
        self.client = app.app.test_client()

    def tearDown(self):
        app.BACKUP_DIR = self.original_backup_dir
        shutil.rmtree(self.backup_dir, ignore_errors=True)

    def write_export(self, filename, content):
        with open(os.path.join(self.backup_dir, filename), 'w', encoding='utf-8') as export_file:
            export_file.write(content)

    def test_normalized_timestamp_is_ignored_but_version_change_remains(self):
        first = '# 2026-09-13 02:00:00 by RouterOS 7.24.1\n/interface bridge\n'
        same_version = '# 2026-09-14 03:30:00 by RouterOS 7.24.1\n/interface bridge\n'
        new_version = '# 2026-09-14 03:30:00 by RouterOS 7.24.2\n/interface bridge\n'

        first_lines = app.normalize_routeros_export(first, mode='normalized')
        same_lines = app.normalize_routeros_export(same_version, mode='normalized')
        new_lines = app.normalize_routeros_export(new_version, mode='normalized')
        self.assertEqual([line for _, line in first_lines], [line for _, line in same_lines])
        self.assertNotEqual([line for _, line in first_lines], [line for _, line in new_lines])
        self.assertIn('RouterOS 7.24.2', new_lines[0][1])

    def test_normalized_mode_filters_known_multiline_blacklist_noise(self):
        export = (
            '/ip firewall address-list\n'
            'add list=blacklist address=192.0.2.5 \\\n'
            '    comment=generated-entry\n'
            'add list=trusted address=192.0.2.10\n'
        )
        normalized = app.normalize_routeros_export(export, mode='normalized')
        text = '\n'.join(line for _, line in normalized)
        self.assertNotIn('192.0.2.5', text)
        self.assertNotIn('generated-entry', text)
        self.assertIn('192.0.2.10', text)

    def test_exact_mode_keeps_timestamp_and_blacklist_lines(self):
        export = (
            '# 2026-09-14 02:00:00 by RouterOS 7.24.2\n'
            'add list=blacklist address=192.0.2.5\n'
        )
        exact = app.normalize_routeros_export(export, mode='exact')
        self.assertEqual([line for _, line in exact], export.splitlines())

    def test_compare_endpoint_returns_aligned_summary_and_no_store(self):
        left = 'router_192.0.2.1_20260913-1200.rsc'
        right = 'router_192.0.2.1_20260914-1200.rsc'
        self.write_export(
            left,
            '# 2026-09-13 12:00:00 by RouterOS 7.24.1\n'
            '/interface bridge\nadd name=bridge-old\n',
        )
        self.write_export(
            right,
            '# 2026-09-14 12:00:00 by RouterOS 7.24.2\n'
            '/interface bridge\nadd name=bridge-new\nadd name=guest\n',
        )

        response = self.client.get('/api/backups/compare', query_string={
            'left': left, 'right': right, 'mode': 'normalized', 'context': 3,
        })
        payload = response.get_json()
        self.assertEqual(response.status_code, 200, response.get_data(as_text=True))
        self.assertIn('no-store', response.headers['Cache-Control'])
        self.assertEqual(payload['summary'], {
            'added': 1, 'removed': 0, 'modified': 2, 'total': 3,
        })
        self.assertEqual(payload['device_ip'], '192.0.2.1')
        self.assertTrue(payload['hunks'])

    def test_compare_endpoint_requires_login(self):
        with mock.patch.dict(app.app.config, {'LOGIN_DISABLED': False}):
            response = self.client.get('/api/backups/compare', query_string={
                'left': 'router_192.0.2.1_20260913-1200.rsc',
                'right': 'router_192.0.2.1_20260914-1200.rsc',
            })
        self.assertEqual(response.status_code, 302)
        self.assertIn('/login', response.headers['Location'])

    def test_exact_mode_reports_timestamp_only_change(self):
        left = 'router_192.0.2.2_20260913-1200.rsc'
        right = 'router_192.0.2.2_20260914-1200.rsc'
        self.write_export(left, '# 2026-09-13 12:00:00 by RouterOS 7.24.1\n/system clock\n')
        self.write_export(right, '# 2026-09-14 12:00:00 by RouterOS 7.24.1\n/system clock\n')

        normalized = self.client.get('/api/backups/compare', query_string={
            'left': left, 'right': right, 'mode': 'normalized', 'context': 3,
        }).get_json()
        exact = self.client.get('/api/backups/compare', query_string={
            'left': left, 'right': right, 'mode': 'exact', 'context': 3,
        }).get_json()
        self.assertEqual(normalized['summary']['total'], 0)
        self.assertEqual(exact['summary']['modified'], 1)

    def test_compare_endpoint_rejects_invalid_inputs(self):
        first = 'router_192.0.2.3_20260913-1200.rsc'
        other = 'router_192.0.2.4_20260914-1200.rsc'
        backup = 'router_192.0.2.3_20260913-1200.backup'
        self.write_export(first, '/system identity\n')
        self.write_export(other, '/system identity\n')
        self.write_export(backup, 'binary-placeholder')

        cases = (
            ({'left': first, 'right': other}, 400),
            ({'left': first, 'right': first}, 400),
            ({'left': backup, 'right': first}, 400),
            ({'left': '../' + first, 'right': first}, 400),
            ({'left': first, 'right': 'router_192.0.2.3_20260914-1200.rsc'}, 404),
            ({'left': first, 'right': other, 'mode': 'unknown'}, 400),
            ({'left': first, 'right': other, 'context': '100'}, 400),
        )
        for query, expected_status in cases:
            query.setdefault('mode', 'normalized')
            query.setdefault('context', '3')
            with self.subTest(query=query):
                response = self.client.get('/api/backups/compare', query_string=query)
                self.assertEqual(response.status_code, expected_status)
                self.assertEqual(response.get_json()['status'], 'error')

    def test_compare_endpoint_enforces_size_and_line_limits(self):
        left = 'router_192.0.2.5_20260913-1200.rsc'
        right = 'router_192.0.2.5_20260914-1200.rsc'
        self.write_export(left, '123456789\n')
        self.write_export(right, 'one\ntwo\nthree\n')

        with mock.patch.object(app, 'BACKUP_COMPARE_MAX_BYTES', 8):
            response = self.client.get('/api/backups/compare', query_string={
                'left': left, 'right': right, 'mode': 'normalized', 'context': 3,
            })
        self.assertEqual(response.status_code, 413)

        with mock.patch.object(app, 'BACKUP_COMPARE_MAX_LINES', 2):
            response = self.client.get('/api/backups/compare', query_string={
                'left': right, 'right': left, 'mode': 'normalized', 'context': 3,
            })
        self.assertEqual(response.status_code, 413)

    def test_compare_endpoint_rejects_symlink_outside_backup_directory(self):
        left = 'router_192.0.2.7_20260913-1200.rsc'
        linked = 'router_192.0.2.7_20260914-1200.rsc'
        self.write_export(left, '/system identity\n')
        outside_path = os.path.join(TEST_DATA_DIR, 'outside-export.rsc')
        with open(outside_path, 'w', encoding='utf-8') as export_file:
            export_file.write('/system identity\n')
        os.symlink(outside_path, os.path.join(self.backup_dir, linked))

        response = self.client.get('/api/backups/compare', query_string={
            'left': left, 'right': linked, 'mode': 'normalized', 'context': 3,
        })
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.get_json()['status'], 'error')

    def test_diff_rows_are_bounded_and_marked_truncated(self):
        left_records = [(index, f'old-{index}') for index in range(1, 6)]
        right_records = [(index, f'new-{index}') for index in range(1, 6)]
        with mock.patch.object(app, 'BACKUP_COMPARE_MAX_ROWS', 2):
            result = app.build_backup_diff(left_records, right_records, 3)
        self.assertTrue(result['truncated'])
        self.assertEqual(result['returned_rows'], 2)
        self.assertEqual(result['summary']['modified'], 5)

    def test_legacy_backup_change_detection_behaviour_is_preserved(self):
        filename = 'router_192.0.2.6_20260913-1200.rsc'
        self.write_export(filename, '# old header\n/interface bridge\nadd name=main\n')
        comments_only = '# new header\n/interface bridge\nadd name=main\n'
        changed = '# new header\n/interface bridge\nadd name=guest\n'
        self.assertFalse(app.compare_with_local_backup('192.0.2.6', comments_only, False))
        self.assertTrue(app.compare_with_local_backup('192.0.2.6', changed, False))


if __name__ == '__main__':
    unittest.main()
