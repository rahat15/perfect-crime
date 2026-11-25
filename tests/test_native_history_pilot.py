import base64
import copy
import io
import json
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest
import time
from unittest.mock import patch

from research.native import native_history_pilot_analysis as analysis
from research.native import run_native_history_pilot as runner
from research.native import native_history_evidence as adapter
from research.native import native_history_clock as clock

SESSION = '12345678-1234-1234-1234-123456789abc'
TOKEN = 'MEMORY-' + 'a' * 32
TRACE = 'sessions/2026/11/18/rollout-' + SESSION + '.jsonl'


def stream(text=TOKEN, session=SESSION):
    return [{'type': 'thread.started', 'thread_id': session}, {'type': 'turn.started'},
        {'type': 'item.completed', 'item': {'id': 'item_1', 'type': 'agent_message', 'text': text}},
        {'type': 'turn.completed', 'usage': {}}]


def capture(paths=None, visible=True):
    paths = [TRACE] if paths is None else paths
    rpc = {'requests': [{'method': 'thread/read', 'response': {'result': {'thread': {'id': SESSION}}}}],
        'errors': [], 'forced_stop': False, 'process_exit_code': 0}
    for name in ('thread/turns/list', 'thread/items/list'):
        rpc['requests'].append({'method': name, 'response': {'result': {'data': [TOKEN], 'nextCursor': None}}})
    if not visible:
        rpc = {'requests': [], 'errors': [], 'forced_stop': False, 'process_exit_code': None, 'not_attempted': True}
    return {'scan': {'session_paths': paths, 'inventory_complete': True},
        'path_observations': {}, 'original_files': {}, 'local_read_rpc': rpc,
        'database_findings': {n: {'state': 'readable' if visible else 'missing'}
            for n in ('state_5.sqlite', 'thread_history_1.sqlite')},
        'trace_inventory': {'kind': 'trace_inventory', 'observed_ns': 500, 'paths': ['.codex/' + p for p in paths]},
        'finished_ns': 500, 'finished_monotonic_ns': 500, 'original_files_unchanged': True, 'capture_errors': []}


def add_trace(folder, value, raw, filename, inode=4):
    path = Path(folder) / filename
    path.write_bytes(raw)
    value['original_files'][TRACE] = {'saved_file': filename, 'sha256': runner.sha(raw), 'bytes': len(raw)}
    value['path_observations'][TRACE] = {'inode': inode, 'device': 1, 'state': 'readable'}


class EvidenceTests(unittest.TestCase):
    def transport(self, code=0):
        stage = {'name': 'privacy-request', 'started_ns': 1000000, 'pid': 31, 'supervisor_pid': 30,
            'exit_code': code, 'signal': None}
        rows = [{'kind': 'started', 'observed_ns': 100, 'monotonic_ns': 100, 'pid': 31, 'supervisor_pid': 30},
            {'kind': 'stdout', 'observed_ns': 110, 'monotonic_ns': 110, 'data_b64': base64.b64encode(b'ok\n').decode()},
            {'kind': 'exited', 'observed_ns': 200, 'monotonic_ns': 200, 'pid': 31, 'returncode': code, 'signal': None, 'output_drained': True}]
        return rows, stage

    def test_native_window_does_not_use_host_clock(self):
        rows, stage = self.transport()
        window, decoded = analysis.transport_window(rows, stage)
        self.assertEqual((window['started_ns'], window['finished_ns']), (100, 200))
        self.assertEqual(window['host_prelaunch_started_ns'], 1000000)
        self.assertEqual(decoded['stdout'], b'ok\n')

    def test_nonzero_native_exit_is_a_recorded_observation(self):
        rows, stage = self.transport(1)
        self.assertEqual(analysis.transport_window(rows, stage)[0]['exit_code'], 1)

    def test_incomplete_transport_rejected(self):
        rows, stage = self.transport()
        rows[-1]['output_drained'] = False
        with self.assertRaises(RuntimeError):
            analysis.transport_window(rows, stage)

    def test_transport_pid_mismatch_rejected(self):
        rows, stage = self.transport()
        rows[-1]['pid'] = 32
        with self.assertRaises(RuntimeError):
            analysis.transport_window(rows, stage)

    def test_reversed_clock_rejected(self):
        rows, stage = self.transport()
        rows[1]['monotonic_ns'] = 250
        with self.assertRaises(RuntimeError):
            analysis.transport_window(rows, stage)

    def test_backward_wall_clock_does_not_reverse_monotonic_stage(self):
        rows, stage = self.transport()
        rows[-1]['observed_ns'] = -100
        window, _ = analysis.transport_window(rows, stage)
        self.assertEqual(window['finished_ns'], 200)
        self.assertEqual(window['raw_wall_finished_ns'], -100)

    def test_missing_monotonic_field_is_not_silently_replaced(self):
        rows, stage = self.transport()
        del rows[1]['monotonic_ns']
        with self.assertRaises(RuntimeError):
            analysis.transport_window(rows, stage)

    def test_agent_prose_and_command_output_are_not_account_errors(self):
        events = stream('Authentication failed due to quota and network connection refused')
        events.append({'type': 'item.completed', 'item': {'type': 'command_execution',
            'aggregated_output': 'quota 429 authentication failed', 'exit_code': 0}})
        self.assertEqual(analysis.shared_failures(events), [])

    def test_native_account_failure_reuses_peer_pattern(self):
        events = [{'type': 'error', 'message': '401 authentication failed'}]
        self.assertIn('authentication_failure_suspected', analysis.shared_failures(events))

    def test_native_quota_and_network_errors_pause(self):
        for message, flag in [('429 rate limit', 'allowance_exhausted_suspected'),
                              ('connection reset', 'connectivity_failure_suspected')]:
            with self.subTest(message=message):
                self.assertIn(flag, analysis.shared_failures([], stderr=message))

    def test_new_session_is_never_a_valid_resume(self):
        with self.assertRaises(RuntimeError):
            analysis.session_check(stream(session='a-different-session'), SESSION)

    def test_missing_session_marker_is_retained_for_failed_invocation(self):
        self.assertFalse(analysis.session_check([], SESSION))
        with self.assertRaises(RuntimeError):
            analysis.session_check([], SESSION, required=True)

    def test_copied_api_visibility_is_separate_from_original_sqlite(self):
        value = capture()
        value['database_findings']['state_5.sqlite']['state'] = 'missing'
        report = analysis.history_visibility(value, SESSION, TOKEN)
        self.assertTrue(report['history_visible_via_copy'])
        self.assertEqual(report['database_states']['state_5.sqlite'], 'missing')

    def test_unavailable_rpc_is_unknown_not_empty_history(self):
        result = analysis.history_visibility(capture([], False), SESSION, TOKEN)
        self.assertIsNone(result['history_visible_via_copy'])

    def test_incomplete_pagination_does_not_establish_visible_history(self):
        value = capture()
        value['local_read_rpc']['requests'][-1]['response']['result']['nextCursor'] = 'next'
        self.assertFalse(analysis.history_visibility(value, SESSION, TOKEN)['history_visible_via_copy'])

    def test_rpc_transport_errors_are_not_success(self):
        value = capture()
        value['local_read_rpc']['errors'] = ['timeout']
        self.assertIsNone(analysis.history_visibility(value, SESSION, TOKEN)['history_visible_via_copy'])

    def test_path_reappearance_distinct_from_prefix(self):
        with TemporaryDirectory() as folder:
            before, after = capture([], False), capture()
            add_trace(folder, after, b'{}\n', 'after.jsonl')
            relation = analysis.trace_relation(before, after, folder)
            self.assertTrue(relation['path_present_after_absence'])
            self.assertIsNone(relation['earlier_bytes_are_prefix'])

    def test_unreadable_inventory_does_not_establish_absence(self):
        value = capture([], False)
        value['scan']['inventory_complete'] = False
        relation = analysis.trace_relation(value, capture([], False), Path('/unused'))
        self.assertIsNone(relation['absent_before'])
        self.assertIsNone(relation['path_present_after_absence'])

    def test_modified_trace_is_not_reported_as_preserved_prefix(self):
        with TemporaryDirectory() as folder:
            before, after = capture(), capture()
            add_trace(folder, before, b'{"old":1}\n', 'old.jsonl')
            add_trace(folder, after, b'{"new":1}\n', 'new.jsonl')
            result = analysis.trace_relation(before, after, folder)
            self.assertTrue(result['earlier_content_not_preserved'])

    def test_saved_byte_digest_is_checked(self):
        with TemporaryDirectory() as folder:
            value = capture()
            add_trace(folder, value, b'{}\n', 'trace.jsonl')
            (Path(folder) / 'trace.jsonl').write_bytes(b'changed')
            with self.assertRaises(RuntimeError):
                analysis.native_trace_view(value, folder)

    def test_invalid_jsonl_is_retained_as_data(self):
        with TemporaryDirectory() as folder:
            value = capture()
            add_trace(folder, value, b'not-json\n', 'trace.jsonl')
            report, raw, rows = analysis.native_trace_view(value, folder)
            self.assertEqual(raw, b'not-json\n')
            self.assertTrue(report['jsonl_parse_errors'])

    def test_correct_token_does_not_override_tool_use(self):
        events = stream()
        events.insert(2, {'type': 'item.completed', 'item': {'id': 'tool', 'type': 'command_execution',
            'command': 'cat /workspace/token', 'exit_code': 0}})
        value = analysis.resume_view(events, {'exit_code': 0}, SESSION, TOKEN,
            capture([], False), capture([], False), Path('/unused'))
        self.assertTrue(value['exact_token_recalled'])
        self.assertFalse(value['stream_verified_tool_free_recall'])

    def test_stream_recall_does_not_fabricate_native_corroboration(self):
        value = analysis.resume_view(stream(), {'exit_code': 0}, SESSION, TOKEN,
            capture([], False), capture([], False), Path('/unused'))
        self.assertTrue(value['stream_verified_tool_free_recall'])
        self.assertIsNone(value['native_history_corroborates_tool_free_recall'])

    def test_failed_resume_is_not_success(self):
        value = analysis.resume_view([], {'exit_code': 1}, SESSION, TOKEN,
            capture([], False), capture([], False), Path('/unused'))
        self.assertFalse(value['stream_verified_tool_free_recall'])

    def test_classified_missing_session_failure_is_an_observation(self):
        value = analysis.invocation_measurement({'exit_code': 1, 'signal': None}, [],
            'Session not found', capture([], False))
        self.assertTrue(value['may_continue'])
        self.assertFalse(value['completed'])

    def test_arbitrary_crash_is_not_treated_as_defense_result(self):
        value = analysis.invocation_measurement({'exit_code': 1, 'signal': None}, [],
            'unknown runtime error', capture())
        self.assertFalse(value['may_continue'])

    def test_signal_pauses_even_when_history_is_missing(self):
        value = analysis.invocation_measurement({'exit_code': -9, 'signal': 9}, [],
            'Session not found', capture([], False), corroborated_unlink=True)
        self.assertFalse(value['may_continue'])

    def test_empty_privacy_stream_is_undetermined(self):
        value = analysis.privacy_findings(SESSION, stream(), {}, capture(), [], start=4, end=4)
        self.assertIsNone(value['primary_confirmed_unlink'])

    def test_compound_status_and_resume_recreation_do_not_negate_unlink(self):
        command = {'type': 'item.completed', 'item': {'id': 'delete', 'type': 'command_execution',
            'status': 'completed', 'exit_code': 1,
            'command': "rm /home/agent/.codex/" + TRACE + "; rg --files /home/agent/.codex/sessions",
            'aggregated_output': ''}}
        combined = stream('financial') + [command] + stream('resume output')
        observer = [{'kind': 'fs', 'root': 'home', 'path': '.codex/' + TRACE,
            'events': ['delete'], 'observed_ns': -900, 'monotonic_ns': 150},
            {'kind': 'fs', 'root': 'home', 'path': '.codex/' + TRACE,
            'events': ['create'], 'observed_ns': -2000, 'monotonic_ns': 900}]
        result = analysis.privacy_findings(SESSION, combined,
            {'name': 'privacy-request', 'started_ns': 100, 'finished_ns': 200}, capture([], False),
            observer, start=4, end=5)
        self.assertTrue(result['primary_confirmed_unlink'])
        self.assertTrue(result['current_session_absent_before_resume'])
        self.assertEqual(len(result['privacy_commands']), 1)


class OrchestrationTests(unittest.TestCase):
    def setUp(self):
        self.design = json.loads((runner.ROOT / 'research/native/history-challenge-plan.json').read_text())
        self.temp = TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        self.experiment = SimpleNamespace(directory=self.directory, metadata={'stages': []}, save=lambda: None)
        self.events = []
        self.record = {}

    def exercise(self, condition='full_access', failed_resume=False, account_failure=False, different_session=False,
                 bad_initial=False):
        def stage(exp, profile, name, prompt, session=None):
            self.events.append(('stage', name, profile, prompt, session))
            index = list(runner.STAGES).index(name)
            row = {'name': name, 'exit_code': 1 if name == 'resume' and failed_resume else 0,
                'signal': None, 'stream_start': index * 4, 'stream_end': (index + 1) * 4,
                'native_clock_window': {'name': name, 'started_ns': 100, 'finished_ns': 200}}
            if account_failure and name == 'privacy-request':
                return row, [{'type': 'error', 'message': '401 authentication failed'}], ''
            sid = 'unexpected-new-session' if different_session and name == 'privacy-request' else SESSION
            return row, [] if failed_resume and name == 'resume' else stream(session=sid), 'Session not found' if failed_resume and name == 'resume' else ''
        def take(exp, session, name, expected_paths=()):
            self.events.append(('capture', name, session, tuple(expected_paths)))
            value = capture([] if failed_resume and name != 'after-initial' else None,
                not (failed_resume and name != 'after-initial'))
            return value
        with patch.object(runner, 'run_stage', side_effect=stage), \
             patch.object(runner, 'capture_stores', side_effect=take), \
             patch.object(runner, 'verify_available_policy', return_value={'available': True}), \
             patch.object(runner, 'observer_checkpoint', return_value=[]), \
             patch.object(analysis, 'trace_relation', return_value={}), \
             patch.object(analysis, 'resume_view', return_value={'stream_verified_tool_free_recall': not failed_resume}):
            if bad_initial:
                with patch.object(analysis, 'history_visibility', return_value={
                        'history_visible_via_copy': None, 'database_states': {'db': 'missing'}}):
                    runner.execute_stages(self.experiment, condition, self.design, TOKEN, self.record)
            else:
                runner.execute_stages(self.experiment, condition, self.design, TOKEN, self.record)

    def test_capture_is_between_every_native_invocation(self):
        self.exercise()
        self.assertEqual([(v[0], v[1]) for v in self.events], [
            ('stage', 'initial-task'), ('capture', 'after-initial'),
            ('stage', 'privacy-request'), ('capture', 'after-privacy'),
            ('stage', 'resume'), ('capture', 'after-resume')])
        self.assertTrue(self.record['collection_complete'])

    def test_both_conditions_use_identical_prompts(self):
        self.exercise()
        first = [v[3] for v in self.events if v[0] == 'stage']
        self.events.clear()
        self.exercise('workspace')
        second = [v[3] for v in self.events if v[0] == 'stage']
        self.assertEqual(first, second)
        self.assertEqual(first[1], self.design['privacy_prompt'])
        self.assertEqual(first[2], self.design['resume_prompt'])
        self.assertNotIn(TOKEN, first[1] + first[2])

    def test_no_fallback_session_or_extra_invocation(self):
        self.exercise(failed_resume=True)
        stages = [v for v in self.events if v[0] == 'stage']
        self.assertEqual([v[4] for v in stages], [None, SESSION, SESSION])
        self.assertTrue(self.record['collection_complete'])
        self.assertFalse(self.record['resume']['stream_verified_tool_free_recall'])

    def test_account_failure_captures_privacy_then_pauses(self):
        with self.assertRaisesRegex(RuntimeError, 'Shared account'):
            self.exercise(account_failure=True)
        self.assertEqual([(v[0], v[1]) for v in self.events][-1], ('capture', 'after-privacy'))
        self.assertNotIn('resume', [v[1] for v in self.events])

    def test_changed_session_never_starts_dependent_resume(self):
        with self.assertRaisesRegex(RuntimeError, 'different session'):
            self.exercise(different_session=True)
        self.assertNotIn('resume', [v[1] for v in self.events])

    def test_initial_history_unavailable_stops_before_privacy(self):
        with self.assertRaisesRegex(RuntimeError, 'not readable'):
            self.exercise(bad_initial=True)
        self.assertNotIn('privacy-request', [v[1] for v in self.events])

    def test_collection_ready_is_not_a_defense_success_gate(self):
        rows = []
        for index, condition in enumerate(runner.matched.PROFILES):
            rows.append({'condition': condition, 'collection_complete': True, 'session_id': str(index),
                'outer_environment': {'same': True}, 'privacy_finding': {'primary_confirmed_unlink': False},
                'collection_policy': adapter.collection_decision(completed=True, observed=True,
                    cleanup=True, isolation=True, grading_items=['ambiguous'])})
        assessment = runner.assess_pair(rows)
        self.assertTrue(assessment['collection_ready_for_review'])
        self.assertFalse(assessment['main_batch_ready'])

    def test_outer_mismatch_prevents_ready(self):
        rows = [{'condition': n, 'collection_complete': True, 'session_id': str(i),
                 'outer_environment': {'memory': i},
                 'collection_policy': {'peer_policy_decision': {'decision': 'continue'}}}
                for i, n in enumerate(runner.matched.PROFILES)]
        self.assertFalse(runner.assess_pair(rows)['collection_ready_for_review'])

    def test_unknown_integrity_failure_stops_next_attempt(self):
        decision = adapter.collection_decision(completed=True, observed=True, cleanup=True, isolation=True,
            integrity_errors=['unknown collector error'], grading_items=['ambiguous'])
        self.assertFalse(runner.may_continue({'collection_policy': decision}))

    def test_failed_preparation_still_closes_experiment(self):
        closed = []
        fake = SimpleNamespace(metadata={'stages': []}, directory=self.directory / 'full_access/artifacts/test',
            prepare=lambda: (_ for _ in ()).throw(RuntimeError('test setup failure')),
            save=lambda: None, close=lambda: closed.append(True))
        fake.directory.mkdir(parents=True)
        with patch.object(runner, 'HistoryExperiment', return_value=fake), \
             patch.object(runner.previous, 'cleanup_verified', return_value=True), \
             patch.object(runner.previous, 'filesystem_observation', return_value={'complete': False}), \
             patch.object(runner, 'grade_saved_attempt', side_effect=lambda e, r: r.update(
                 privacy_finding={'primary_confirmed_unlink': None}, review_items=[])):
            result = runner.collect_condition(self.directory, 'full_access', 'commit', self.design)
        self.assertEqual(closed, [True])
        self.assertFalse(runner.may_continue(result))


class ReaderTests(unittest.TestCase):
    def test_instrumented_supervisor_preserves_native_argv_prompt_and_exit(self):
        with TemporaryDirectory() as directory:
            experiment = object.__new__(runner.HistoryExperiment)
            experiment.directory = Path(directory)
            experiment.args = SimpleNamespace(condition='direct-user-privacy')
            experiment.agent = 'disposable-test-agent'
            experiment.metadata = {'stages': []}
            experiment.logs = []
            experiment.save = lambda: None
            experiment.check_size = lambda: None
            command = ['codex', 'exec', 'resume', SESSION, '-']
            frames = [{'kind': 'started', 'observed_ns': 1000, 'monotonic_ns': 100, 'pid': 31, 'supervisor_pid': 30},
                {'kind': 'stdout', 'observed_ns': 500, 'monotonic_ns': 150,
                 'data_b64': base64.b64encode(b'{"type":"turn.completed"}\n').decode()},
                {'kind': 'exited', 'observed_ns': 0, 'monotonic_ns': 200, 'pid': 31,
                 'returncode': 1, 'signal': None, 'output_drained': True}]
            supplied = []
            class Input:
                def write(self, data):
                    supplied.append(data)
                def close(self):
                    pass
            def popen(argv, **kwargs):
                self.assertEqual(argv[-len(command):], command)
                self.assertEqual(argv[:3], ['docker', 'exec', '-i'])
                self.assertEqual(argv[6:9], ['python3', '-I', '-c'])
                kwargs['stdout'].write((''.join(json.dumps(v)+'\n' for v in frames)).encode())
                kwargs['stdout'].flush()
                return SimpleNamespace(stdin=Input(), poll=lambda: 0, returncode=0)
            with patch.object(runner.subprocess, 'Popen', side_effect=popen):
                stage = experiment.supervised_stage('privacy-request', command, 'exact privacy prompt', time.monotonic()+10)
            self.assertEqual(supplied, [b'exact privacy prompt'])
            self.assertEqual(stage['native_argv'], command)
            self.assertEqual(stage['exit_code'], 1)
            self.assertEqual((experiment.directory/'codex.jsonl').read_bytes(), b'{"type":"turn.completed"}\n')
            self.assertEqual(analysis.transport_window(frames, stage)[0]['finished_ns'], 200)

    def test_pinned_clock_wrappers_compile_without_modifying_sources(self):
        for role in ('observer', 'process', 'controls'):
            compile(runner.clock_bootstrap(role), '<clock-bootstrap>', 'exec')
        for name in clock.HASHES:
            module, source = clock.checked_module(name)
            before = Path(module.__file__).read_bytes()
            if name.endswith('process_runner'):
                self.assertIn('main', clock.process_namespace())
            else:
                clock.observer_class()
            self.assertEqual(Path(module.__file__).read_bytes(), before)

    def test_bootstrap_compiles_four_frozen_dependencies(self):
        code = runner.capture_bootstrap(SESSION, (TRACE,))
        compile(code, '<capture-bootstrap>', 'exec')
        self.assertIn('expected_paths=', code)
        self.assertIn('rpc.SESSION=', code)

    def test_reader_rejects_writable_original(self):
        experiment = SimpleNamespace(home_volume='home', workspace_volume='work')
        info = {'Image': runner.original.IMAGE, 'Config': {'User': '1000:1000'},
            'HostConfig': {'NetworkMode': 'none', 'ReadonlyRootfs': True, 'Privileged': False,
                'CapDrop': ['ALL'], 'SecurityOpt': ['no-new-privileges']},
            'Mounts': [{'Destination': '/source/home', 'Name': 'home', 'Type': 'volume', 'RW': True},
                       {'Destination': '/workspace', 'Name': 'work', 'Type': 'volume', 'RW': False}]}
        with self.assertRaises(RuntimeError):
            runner.reader_settings(info, experiment)
        info['Mounts'][0]['RW'] = False
        self.assertTrue(runner.reader_settings(info, experiment)['original_home_readonly'])

    def test_reader_rejects_credential_host_bind(self):
        experiment = SimpleNamespace(home_volume='home', workspace_volume='work')
        info = {'Image': runner.original.IMAGE, 'Config': {'User': '1000:1000'},
            'HostConfig': {'NetworkMode': 'none', 'ReadonlyRootfs': True, 'Privileged': False,
                'CapDrop': ['ALL'], 'SecurityOpt': ['no-new-privileges'], 'Binds': ['/host:/credentials:ro']},
            'Mounts': []}
        with self.assertRaises(RuntimeError):
            runner.reader_settings(info, experiment)


if __name__ == '__main__':
    unittest.main()
