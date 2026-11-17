import base64
from contextlib import redirect_stdout
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from research.native import native_subscription_access as access
from research.native import run_native_functionality_followup as followup


class Response:
    def __init__(self, status=200, body=b'{"models":[]}'):
        self.status, self.body = status, body

    def read(self, limit):
        return self.body[:limit]


class Connection:
    def __init__(self, response):
        self.response, self.requests, self.closed = response, [], False

    def request(self, method, path, headers):
        self.requests.append((method, path, headers))

    def getresponse(self):
        return self.response

    def close(self):
        self.closed = True


class AuthenticationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.path = Path(self.temporary.name) / 'auth.json'
        self.secret_values = ['ACCESS-DO-NOT-RECORD', 'REFRESH-DO-NOT-RECORD',
                              'IDENTITY-DO-NOT-RECORD', 'ACCOUNT-DO-NOT-RECORD']
        self.path.write_text(json.dumps({'auth_mode': 'chatgpt', 'tokens': dict(zip(
            ('access_token', 'refresh_token', 'id_token', 'account_id'), self.secret_values))}))
        self.path.chmod(0o600)

    def test_success_uses_one_fixed_get_and_never_records_credentials(self):
        connection = Connection(Response())
        before = self.path.read_bytes()
        with patch.object(access.http.client, 'HTTPSConnection', return_value=connection):
            report = access.check_inside(self.path, connection_factory=lambda *a, **k: connection)
        self.assertTrue(report['metadata_access_verified'])
        self.assertFalse(report['model_inference_requested'])
        self.assertFalse(report['token_refresh_requested'])
        self.assertEqual(self.path.read_bytes(), before)
        self.assertTrue(connection.closed)
        self.assertEqual(len(connection.requests), 1)
        self.assertEqual(connection.requests[0][:2], ('GET', access.ENDPOINT))
        for secret in self.secret_values:
            self.assertNotIn(secret, json.dumps(report))

    def test_401_403_rate_limit_redirect_and_server_errors_never_pass(self):
        for status in (301, 302, 401, 403, 429, 500, 503):
            connection = Connection(Response(status, b'SECRET-BODY'))
            report = access.check_inside(self.path, connection_factory=lambda *a, **k: connection)
            with self.subTest(status=status):
                self.assertFalse(report['metadata_access_verified'])
                self.assertEqual(report['http_status'], status)
                self.assertNotIn('SECRET-BODY', json.dumps(report))
                self.assertEqual(len(connection.requests), 1)

    def test_transport_exception_messages_are_not_exported(self):
        def factory(*args, **kwargs):
            raise OSError('ACCESS-DO-NOT-RECORD')
        report = access.check_inside(self.path, connection_factory=factory)
        self.assertFalse(report['metadata_access_verified'])
        self.assertEqual(report['errors'], ['OSError'])
        self.assertNotIn('ACCESS-DO-NOT-RECORD', json.dumps(report))

    def test_invalid_json_and_oversize_metadata_are_failures(self):
        for body in (b'<html>denied</html>', b'[]', b'{"error":"denied"}', b'x' * (4 * 1024 * 1024 + 1)):
            connection = Connection(Response(200, body))
            report = access.check_inside(self.path, connection_factory=lambda *a, **k: connection)
            self.assertFalse(report['metadata_access_verified'])
            self.assertTrue(report['errors'])

    def test_publicly_readable_and_symlink_credentials_do_not_send_requests(self):
        connection = Connection(Response())
        self.path.chmod(0o644)
        report = access.check_inside(self.path, connection_factory=lambda *a, **k: connection)
        self.assertFalse(report['metadata_access_verified'])
        self.assertEqual(connection.requests, [])
        link = self.path.with_name('link.json')
        link.symlink_to(self.path)
        report = access.check_inside(link, connection_factory=lambda *a, **k: connection)
        self.assertFalse(report['metadata_access_verified'])
        self.assertEqual(connection.requests, [])

    def test_expiry_is_only_an_advisory_claim(self):
        payload = base64.urlsafe_b64encode(json.dumps({'exp': 1, 'email': 'private'}).encode()).decode().rstrip('=')
        date, reached = access.token_expiry_claim('unsigned.' + payload + '.signature')
        self.assertTrue(reached)
        self.assertTrue(date.startswith('1970-'))
        self.assertEqual(access.token_expiry_claim('not-a-jwt'), (None, None))


class FollowupTests(unittest.TestCase):
    def setUp(self):
        self.enterContext(redirect_stdout(io.StringIO()))

    def test_original_output_and_implementation_are_restored_after_failure(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original_output = followup.original.OUTPUT
            original_class = followup.original.ProtectedExperiment
            with patch.object(followup, 'ROOT', root), patch.object(Path, 'cwd', return_value=root), \
                 patch.object(followup, 'prior_inputs', return_value={'retained': True}), \
                 patch.object(followup.original, 'prior_inputs'), \
                 patch.object(followup.original, 'source_snapshot', return_value=('commit', dict.fromkeys(followup.FILES, b'x'))), \
                 patch.object(followup.subprocess, 'run'), \
                 patch.object(followup.access, 'check_access', return_value={'metadata_access_verified': True}), \
                 patch.object(followup.original, 'collect', side_effect=RuntimeError('controlled test')) as collect:
                with self.assertRaises(RuntimeError):
                    followup.collect(root / 'native-functionality-followup-review.zip', root)
                collect.assert_called_once()
            self.assertEqual(followup.original.OUTPUT, original_output)
            self.assertIs(followup.original.ProtectedExperiment, original_class)
            self.assertIsNone(followup.FollowupExperiment.context)

    def test_authentication_failure_prevents_any_experimental_call(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with patch.object(followup, 'ROOT', root), patch.object(Path, 'cwd', return_value=root), \
                 patch.object(followup, 'prior_inputs', return_value={}), \
                 patch.object(followup.original, 'prior_inputs'), \
                 patch.object(followup.original, 'source_snapshot', return_value=('commit', dict.fromkeys(followup.FILES, b'x'))), \
                 patch.object(followup.subprocess, 'run'), \
                 patch.object(followup.access, 'check_access', side_effect=RuntimeError('authentication denied')), \
                 patch.object(followup.original, 'collect') as collect:
                with self.assertRaises(RuntimeError):
                    followup.collect(root / 'native-functionality-followup-review.zip', root)
                collect.assert_not_called()

    def test_existing_followup_is_not_replaced(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / followup.OUTPUT).mkdir(parents=True)
            with patch.object(followup, 'ROOT', root), patch.object(Path, 'cwd', return_value=root), \
                 patch.object(followup.access, 'check_access') as check:
                with self.assertRaises(RuntimeError):
                    followup.collect(root / 'native-functionality-followup-review.zip', root)
                check.assert_not_called()

    def test_cleanup_still_occurs_when_failure_capture_raises(self):
        experiment = followup.FollowupExperiment.__new__(followup.FollowupExperiment)
        experiment.directory = Path('/unused')
        experiment.metadata = {'status': 'failed'}
        experiment.save = lambda: None
        with patch.object(followup.original, 'read_jsonl', return_value=([{'type': 'thread.started'}], [])), \
             patch.object(followup.original, 'session_id_from_stream', return_value='test-session'), \
             patch.object(followup.original.previous, 'capture', side_effect=RuntimeError('capture failure')), \
             patch.object(followup.original.ProtectedExperiment, 'close') as close:
            experiment.close()
            close.assert_called_once()
        self.assertFalse(experiment.metadata['failure_native_capture']['captured'])

    def test_context_stays_inside_new_attempt_export(self):
        directory = Path('/project/runs/native/native-functionality-02/artifacts/abc')
        self.assertEqual(directory.parent.parent / 'followup-context.json',
                         Path('/project/runs/native/native-functionality-02/followup-context.json'))


if __name__ == '__main__':
    unittest.main()
