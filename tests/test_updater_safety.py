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
    def test_routeros_version_order_handles_beta_rc_final_and_downgrade(self):
        self.assertLess(app._version_relation('7.21beta6', '7.21rc1'), 0)
        self.assertLess(app._version_relation('7.21rc2', '7.21'), 0)
        self.assertLess(app._version_relation('7.20.6', '7.21beta1'), 0)
        self.assertEqual(app._version_relation('7.24', '7.24.0'), 0)
        self.assertGreater(app._version_relation('7.24.1', '7.24'), 0)
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
