import atexit
import os
import shutil
import tempfile
import unittest
from unittest import mock


TEST_DATA_DIR = tempfile.mkdtemp(prefix='mikrotik-manager-certificate-tests-')
atexit.register(shutil.rmtree, TEST_DATA_DIR, ignore_errors=True)
os.environ['DATA_DIR'] = TEST_DATA_DIR

import app  # noqa: E402


class FakeResponse:
    def __init__(self, status_code=200, data=None, text=''):
        self.status_code = status_code
        self._data = data
        self.text = text

    def json(self):
        if self._data is None:
            raise ValueError('No JSON response')
        return self._data


class CertificateRouter:
    def __init__(self, removal_delay=0, remove_error=None, sign_error=None):
        self.removal_delay = removal_delay
        self.remove_error = remove_error
        self.sign_error = sign_error
        self.old_present = True
        self.new_present = False
        self.remove_requested = False
        self.remove_polls = 0
        self.calls = []

    def request(self, method, url, auth=None, json=None, timeout=None):
        endpoint = url.split('/rest/', 1)[1]
        self.calls.append((method, endpoint, json))

        if method == 'GET' and endpoint == 'system/resource':
            return FakeResponse(data={
                'free-hdd-space': '65536',
                'total-hdd-space': '16777216',
            })

        if method == 'POST' and endpoint == 'certificate/remove':
            if self.remove_error:
                return FakeResponse(500, {'detail': self.remove_error}, self.remove_error)
            self.remove_requested = True
            self.remove_polls = 0
            return FakeResponse(data={})

        if method == 'GET' and endpoint == 'certificate?name=WebCert':
            if self.old_present:
                if self.remove_requested and not self.remove_error:
                    self.remove_polls += 1
                    if self.remove_polls > self.removal_delay:
                        self.old_present = False
                if self.old_present:
                    return FakeResponse(data=[{
                        '.id': '*7',
                        'name': 'WebCert',
                        'invalid-after': '2026-10-01 09:00:00',
                    }])
            if self.new_present:
                return FakeResponse(data=[{'.id': '*8', 'name': 'WebCert'}])
            return FakeResponse(data=[])

        if method == 'POST' and endpoint == 'certificate/add':
            self.new_present = True
            return FakeResponse(201, {})

        if method == 'POST' and endpoint == 'certificate/sign':
            if self.sign_error:
                return FakeResponse(500, {'detail': self.sign_error}, self.sign_error)
            return FakeResponse(data={})

        if method == 'GET' and endpoint == 'certificate/*8':
            return FakeResponse(data={
                '.id': '*8',
                'name': 'WebCert',
                'trusted': 'true',
                'invalid-after': '2027-03-21 09:00:00',
            })

        if method == 'POST' and endpoint == 'ip/service/set':
            return FakeResponse(data={})

        raise AssertionError(f'Unexpected request: {method} {endpoint}')


class CertificateRenewalTests(unittest.TestCase):
    def setUp(self):
        app._certificate_renewal_locks.clear()

    def run_renewal(self, router, low_memory=True):
        with mock.patch.object(app.requests, 'request', side_effect=router.request), \
                mock.patch.object(app.time, 'sleep'), \
                mock.patch.object(app, 'add_log') as add_log:
            result = app._do_renew_certificate(
                '192.0.2.10', 'api-user', 'secret', 180,
                http_port=80, low_memory=low_memory,
            )
        return result, add_log

    def test_low_free_space_is_logged_but_does_not_block_renewal(self):
        router = CertificateRouter()

        (success, message), add_log = self.run_renewal(router)

        self.assertTrue(success, message)
        self.assertTrue(any(
            call[0][0] == 'info' and 'voľné=64 KiB' in call[0][1]
            for call in add_log.call_args_list
        ))
        self.assertIn(('POST', 'certificate/remove', {'numbers': '*7'}), router.calls)
        self.assertTrue(any(call[1] == 'certificate/add' for call in router.calls))

    def test_slow_low_memory_removal_is_polled_before_add(self):
        router = CertificateRouter(removal_delay=4)

        (success, message), add_log = self.run_renewal(router)

        self.assertTrue(success, message)
        remove_index = next(i for i, call in enumerate(router.calls) if call[1] == 'certificate/remove')
        add_index = next(i for i, call in enumerate(router.calls) if call[1] == 'certificate/add')
        polls_between = [
            call for call in router.calls[remove_index + 1:add_index]
            if call[1] == 'certificate?name=WebCert'
        ]
        self.assertEqual(len(polls_between), 5)
        self.assertTrue(any(
            'Odstránenie potvrdené po 10 s.' in call[0][1]
            for call in add_log.call_args_list
        ))

    def test_remove_failure_never_attempts_add(self):
        router = CertificateRouter(remove_error='not enough storage space available')

        (success, message), _ = self.run_renewal(router)

        self.assertFalse(success)
        self.assertIn('not enough storage space available', message)
        self.assertEqual(
            sum(call[1] == 'certificate/remove' for call in router.calls),
            2,
        )
        self.assertFalse(any(call[1] == 'certificate/add' for call in router.calls))

    def test_sign_failure_is_reported_and_service_is_not_changed(self):
        router = CertificateRouter(sign_error='signing failed')

        (success, message), _ = self.run_renewal(router)

        self.assertFalse(success)
        self.assertIn('signing failed', message)
        self.assertFalse(any(call[1] == 'ip/service/set' for call in router.calls))

    def test_parallel_renewal_is_rejected_without_router_call(self):
        lock = app._certificate_renewal_locks.setdefault('192.0.2.10', app.threading.Lock())
        lock.acquire()
        try:
            with mock.patch.object(app.requests, 'request') as request:
                success, message = app._do_renew_certificate(
                    '192.0.2.10', 'api-user', 'secret', 180,
                    http_port=80, low_memory=True,
                )
        finally:
            lock.release()

        self.assertFalse(success)
        self.assertIn('už prebieha', message)
        request.assert_not_called()


if __name__ == '__main__':
    unittest.main()
