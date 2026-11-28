import base64
import copy
import hashlib
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

from research.native import native_functionality_capture as capture
from research.native import native_identity_capture as original_capture
from research.native import run_native_functionality as runner

SESSION = '01234567-1234-1234-1234-0123456789ab'
TOKEN = 'MEMORY-fixture-token'


def context(**changes):
    value = {'approval_policy': 'never', 'sandbox_policy': {'type': 'workspace-write',
             'writable_roots': [], 'network_access': False}, 'model': runner.MODEL, 'cwd': '/workspace'}
    value.update(changes)
    return {'type': 'turn_context', 'payload': value}


def rpc_fixture():
    responses = [('initialize', {}), ('thread/read', {'thread': {'id': SESSION}}),
                 ('thread/turns/list', {'data': [{'text': TOKEN}], 'nextCursor': None}),
                 ('thread/items/list', {'data': [{'text': TOKEN}], 'nextCursor': None})]
    return {'requests': [{'method': m, 'response': {'result': v}} for m, v in responses],
            'errors': [], 'forced_stop': False, 'process_exit_code': 0}


def captured_fixture():
    return {'local_read_rpc': rpc_fixture(), 'missing_databases': [], 'capture_errors': [],
            'original_files_unchanged': True}


class PermissionCommandTests(unittest.TestCase):
    def test_initial_and_resume_select_explicit_workspace_with_never_approval(self):
        args = runner.previous.experiment_args(Path('/tmp/unused'))
        for session in (None, SESSION):
            command = runner.native_command(args, session)
            self.assertEqual(command.count('default_permissions=":workspace"'), 1)
            self.assertIn('approval_policy="never"', command)
            self.assertFalse(any('sandbox_mode=' in v for v in command))
            self.assertNotIn('--dangerously-bypass-approvals-and-sandbox', command)
            self.assertEqual(command[-1], '-')
            if session:
                self.assertEqual(command[:3], ['codex', 'exec', 'resume'])
                self.assertEqual(command[-2], session)

    def test_command_generation_rejects_changed_parent_contract(self):
        with patch.object(runner.cli, 'native_command', return_value=['codex', 'exec']):
            with self.assertRaises(RuntimeError):
                runner.native_command(object())

    def test_actual_policy_not_just_requested_argv_is_required(self):
        self.assertTrue(runner.policy_check([context()])['verified'])
        self.assertFalse(runner.policy_check([])['verified'])
        for value in (None, {}, {'type': 'danger-full-access'},
                      {'type': 'workspace-write', 'network_access': True},
                      {'type': 'workspace-write', 'writable_roots': ['/home/agent']},
                      {'type': 'workspace-write', 'writable_roots': ['/']}):
            with self.subTest(value=value):
                self.assertFalse(runner.policy_check([context(sandbox_policy=value)])['verified'])
        self.assertFalse(runner.policy_check([context(approval_policy='on-request')])['verified'])
        self.assertFalse(runner.policy_check([context(model='different-model')])['verified'])

    def test_both_turn_contexts_are_checked(self):
        self.assertFalse(runner.policy_check([context(), context(sandbox_policy={'type': 'danger-full-access'})])['verified'])

    def test_exception_only_on_disposable_agent_container(self):
        obj = runner.ProtectedExperiment.__new__(runner.ProtectedExperiment)
        with patch.object(runner.previous.ObservedExperiment, 'start_container', return_value='name') as start:
            obj.start_container('agent', '--network', 'none')
            self.assertEqual(start.call_args.args[:3], ('agent', '--security-opt', 'seccomp=unconfined'))
            obj.start_container('gateway', '--network', 'bridge')
            self.assertNotIn('seccomp=unconfined', start.call_args.args)


class HistoryInterpretationTests(unittest.TestCase):
    def test_real_data_and_complete_pages_pass(self):
        self.assertTrue(runner.read_visibility(captured_fixture(), SESSION, TOKEN)['history_visible'])

    def test_metadata_only_does_not_count_as_conversation_history(self):
        value = captured_fixture()
        for row in value['local_read_rpc']['requests'][2:]:
            row['response']['result']['data'] = []
        result = runner.read_visibility(value, SESSION, TOKEN)
        self.assertTrue(result['metadata_found'])
        self.assertFalse(result['history_visible'])

    def test_partial_pages_missing_database_and_changed_sources_do_not_pass(self):
        for mutation in ('cursor', 'missing', 'changed', 'token', 'error', 'forced', 'snapshot'):
            value = captured_fixture()
            if mutation == 'cursor':
                value['local_read_rpc']['requests'][3]['response']['result']['nextCursor'] = 'more'
            elif mutation == 'missing':
                value['missing_databases'] = ['thread_history_1.sqlite']
            elif mutation == 'changed':
                value['original_files_unchanged'] = False
            elif mutation == 'token':
                value['local_read_rpc']['requests'][3]['response']['result']['data'] = [{'text': 'other'}]
            elif mutation == 'error':
                value['local_read_rpc']['requests'][3]['response'] = {'error': {'code': -32601}}
            elif mutation == 'forced':
                value['local_read_rpc']['forced_stop'] = True
            else:
                value['capture_errors'] = ['corrupt snapshot']
            with self.subTest(mutation=mutation):
                self.assertFalse(runner.read_visibility(value, SESSION, TOKEN)['history_visible'])

    def test_unfamiliar_resume_error_is_not_reclassified_as_benign(self):
        stream = [{'type': 'thread.started'}, {'type': 'item.completed',
                  'item': {'id': 'x', 'type': 'error', 'message': 'connection failed'}},
                  {'type': 'turn.started'}, {'type': 'turn.completed'}]
        self.assertFalse(runner.review.review_resume_events(stream, runner.MODEL)['no_tool_activity_verified'])

    def test_monotonic_coverage_survives_wall_clock_rollback(self):
        rows = [{'kind': 'observer_started', 'monotonic_ns': 10, 'observed_ns': 100},
                {'kind': 'process_sample', 'monotonic_ns': 15, 'observed_ns': 99,
                 'errors': [], 'process_table_truncated': False},
                {'kind': 'observer_finished', 'monotonic_ns': 20, 'observed_ns': 98,
                 'reason': 'controller_stop', 'samples': 1}]
        runner.validate_observation(rows, [], 11, 19)
        with self.assertRaises(RuntimeError):
            runner.validate_observation(rows, [], 9, 19)
        rows[-1]['reason'] = 'duration_limit'
        with self.assertRaises(RuntimeError):
            runner.validate_observation(rows, [], 11, 19)

    def test_readiness_requires_all_independent_functionality_controls(self):
        value = {'collection_complete': True, 'cleanup_verified': True, 'cleanup_errors': [], 'errors': [],
                 'source_and_prior_unchanged': True, 'filesystem_observation': {'complete': True},
                 'coding_control': {'passed': True}, 'tool_control': {'passed': True},
                 'native_policy': {'verified': True}, 'history': {'same_session_file_extended': True},
                 'resume': {'passed': True}, 'coding_history': {'history_visible': True},
                 'resumed_history': {'history_visible': True}}
        self.assertTrue(runner.assess(value))
        for key in value:
            if key not in {'errors', 'cleanup_errors'}:
                altered = copy.deepcopy(value)
                del altered[key]
                with self.subTest(key=key):
                    self.assertFalse(runner.assess(altered))


class SQLiteCaptureTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.source = self.root / 'source'
        self.native = self.source / '.codex'
        self.native.mkdir(parents=True)
        self.home = self.root / 'home'
        self.home.mkdir()
        self.workspace = self.root / 'workspace'
        self.workspace.mkdir()
        path = self.native / 'sessions' / ('rollout-' + SESSION + '.jsonl')
        path.parent.mkdir()
        path.write_text(json.dumps({'type': 'session_meta', 'payload': {'id': SESSION}}) + '\n')
        (self.native / 'auth.json').write_text('DO-NOT-COPY-CREDENTIALS')
        self.connections = []
        for name in capture.DATABASES:
            connection = sqlite3.connect(self.native / name)
            connection.execute('PRAGMA journal_mode=WAL')
            connection.execute('PRAGMA wal_autocheckpoint=0')
            connection.execute('CREATE TABLE entries (thread_id TEXT, value TEXT)')
            connection.execute('INSERT INTO entries VALUES (?,?)', (SESSION, TOKEN))
            connection.commit()
            self.connections.append(connection)
            self.addCleanup(connection.close)

    def collect(self, rpc=None):
        with patch.object(capture.os, 'getuid', return_value=1000), patch.object(capture.os, 'getgid', return_value=1000):
            return capture.run(SESSION, original_capture.read_regular, rpc or (lambda *a: rpc_fixture()),
                               '/unused/binary', self.source, self.home, self.workspace, self.root)

    def test_wal_rows_survive_snapshot_and_auth_is_never_copied(self):
        hashes = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in self.native.iterdir() if p.is_file()}
        result = self.collect()
        self.assertTrue(result['original_files_unchanged'])
        self.assertEqual(result['capture_errors'], [])
        self.assertFalse((self.home / '.codex' / 'auth.json').exists())
        self.assertNotIn('auth.json', result['original_files'])
        self.assertEqual(len(result['database_snapshots']), 2)
        for name in capture.DATABASES:
            self.assertIn(name + '-wal', result['original_files'])
            self.assertEqual(result['database_metadata'][name]['tables']['entries']['session_rows'], 1)
            with sqlite3.connect(self.home / '.codex' / name) as db:
                self.assertEqual(db.execute('SELECT value FROM entries').fetchone()[0], TOKEN)
        self.assertEqual(hashes, {p.name: hashlib.sha256(p.read_bytes()).hexdigest()
                                for p in self.native.iterdir() if p.is_file()})

    def test_api_mutations_are_confined_to_copies(self):
        def reader(binary, home, workspace):
            with sqlite3.connect(home / '.codex' / capture.DATABASES[0]) as db:
                db.execute('DELETE FROM entries')
            return rpc_fixture()
        result = self.collect(reader)
        self.assertTrue(result['original_files_unchanged'])
        self.assertEqual(self.connections[0].execute('SELECT count(*) FROM entries').fetchone()[0], 1)
        raw = base64.b64decode(result['database_snapshots'][capture.DATABASES[0]]['content_b64'])
        path = self.root / 'saved-before-rpc.sqlite'
        path.write_bytes(raw)
        with sqlite3.connect(path) as db:
            self.assertEqual(db.execute('SELECT count(*) FROM entries').fetchone()[0], 1)

    def test_corrupt_database_retains_raw_files_and_skips_reads(self):
        for connection in self.connections:
            connection.close()
        (self.native / capture.DATABASES[0]).write_bytes(b'not a sqlite database')
        called = []
        result = self.collect(lambda *a: called.append(True))
        self.assertTrue(result['capture_errors'])
        self.assertIn(capture.DATABASES[0], result['original_files'])
        self.assertEqual(called, [])

    def test_changed_original_is_not_treated_as_verified(self):
        def reader(*args):
            with self.connections[0]:
                self.connections[0].execute('INSERT INTO entries VALUES (?,?)', (SESSION, 'later'))
            return rpc_fixture()
        result = self.collect(reader)
        self.assertFalse(result['original_files_unchanged'])
        self.assertTrue(result['capture_errors'])

    def test_source_symlink_is_rejected_without_reading_target(self):
        for connection in self.connections:
            connection.close()
        path = self.native / capture.DATABASES[0]
        path.unlink()
        path.symlink_to(self.native / 'auth.json')
        with self.assertRaises(OSError):
            self.collect()


if __name__ == '__main__':
    unittest.main()
