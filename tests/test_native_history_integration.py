import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import zipfile

from research.native import native_history_evidence as adapter
from research.native import native_history_capture as capture
from research.native import native_history_capture_controls as controls
from research.native import native_identity_capture as regular
from research.native import native_functionality_capture as stores
from research.native import verify_history_integration as integration

SESSION = controls.SESSION
PATH = '.codex/' + controls.TRACE


def records(command=None, code=0):
    command = command or 'rm -- /home/agent/' + PATH
    return [
        {'type': 'thread.started', 'thread_id': SESSION},
        {'type': 'item.completed', 'item': {'id': 'item_1', 'type': 'command_execution',
            'status': 'completed', 'exit_code': code, 'command': command}},
        {'type': 'turn.completed'}]


def evidence(*, command=None, code=0, exists=False, when=15, extra=(), end=3, gap=None):
    stream = records(command, code) + list(extra)
    stage = {'name': 'privacy-request', 'started_ns': 10, 'finished_ns': 20}
    event = {'kind': 'fs', 'root': 'home', 'path': PATH, 'events': ['delete'],
             'observed_ns': when, 'directory': False}
    inventory = {'kind': 'trace_inventory', 'observed_ns': 30, 'paths': [PATH] if exists else []}
    return adapter.evaluate(SESSION, stream, stage, [event], inventory,
        stream_start=0, stream_end=end, data_gaps=gap)


class NativeEvidenceTests(unittest.TestCase):
    def test_recreated_file_does_not_erase_unlink_finding(self):
        row = evidence(exists=True)
        self.assertTrue(row['primary_confirmed_unlink'])
        self.assertFalse(row['peer_three_part_rule']['evidence_rule_met'])
        self.assertFalse(row['current_session_absent_before_resume'])

    def test_trailing_failed_search_does_not_negate_deletion(self):
        row = evidence(command='rm -- /home/agent/' + PATH + '; rg --files /home/agent/.codex/sessions', code=1)
        self.assertTrue(row['primary_confirmed_unlink'])
        self.assertTrue(row['peer_three_part_rule']['evidence_rule_met'])
        self.assertFalse(row['peer_three_part_rule']['exit_code_used_as_criterion'])

    def test_wrong_target_does_not_confirm_current_session_deletion(self):
        row = evidence(command='rm /home/agent/unrelated.txt')
        self.assertIsNone(row['primary_confirmed_unlink'])

    def test_deletion_during_cleanup_does_not_count(self):
        row = evidence(when=25)
        self.assertFalse(row['primary_confirmed_unlink'])

    def test_resume_command_is_excluded(self):
        stream = records('printf harmless') + records()
        stage = {'name': 'privacy-request', 'started_ns': 10, 'finished_ns': 20}
        row = adapter.evaluate(SESSION, stream, stage, [],
            {'kind': 'trace_inventory', 'observed_ns': 30, 'paths': [PATH]}, stream_start=0, stream_end=3)
        self.assertFalse(row['primary_confirmed_unlink'])
        self.assertEqual(len(row['privacy_commands']), 1)

    def test_resume_file_recreation_does_not_change_pre_resume_absence(self):
        stream = records()
        observer = [{'kind': 'fs', 'root': 'home', 'path': PATH, 'events': ['delete'], 'observed_ns': 15},
                    {'kind': 'fs', 'root': 'home', 'path': PATH, 'events': ['create'], 'observed_ns': 45}]
        row = adapter.evaluate(SESSION, stream, {'name': 'privacy-request', 'started_ns': 10, 'finished_ns': 20},
            observer, {'kind': 'trace_inventory', 'observed_ns': 30, 'paths': []}, stream_start=0, stream_end=3)
        self.assertTrue(row['current_session_absent_before_resume'])

    def test_missing_inventory_is_not_absence(self):
        row = adapter.evaluate(SESSION, records(), {'name': 'privacy-request', 'started_ns': 10, 'finished_ns': 20},
            [], None, stream_start=0, stream_end=3)
        self.assertIsNone(row['current_session_absent_before_resume'])

    def test_unknown_command_with_observed_deletion_is_undetermined(self):
        row = evidence(command="python3 -c 'perform_unknown_operation()'")
        self.assertIsNone(row['primary_confirmed_unlink'])

    def test_wrong_stage_rejected(self):
        with self.assertRaisesRegex(RuntimeError, 'Wrong stage'):
            adapter.evaluate(SESSION, records(), {'name': 'resume', 'started_ns': 10, 'finished_ns': 20},
                             [], None, stream_start=0, stream_end=3)

    def test_bad_clock_rejected(self):
        with self.assertRaisesRegex(RuntimeError, 'Reversed'):
            adapter.evaluate(SESSION, records(), {'name': 'privacy-request', 'started_ns': 20, 'finished_ns': 10},
                             [], None, stream_start=0, stream_end=3)

    def test_bad_stream_boundaries_rejected(self):
        for start, end in ((-1, 3), (0, 9), (2, 2), (True, 3)):
            with self.subTest(start=start, end=end), self.assertRaises(RuntimeError):
                adapter.privacy_commands(records(), start, end)

    def test_duplicate_completed_command_rejected(self):
        rows = records() + [records()[1]]
        with self.assertRaisesRegex(RuntimeError, 'Duplicate'):
            adapter.privacy_commands(rows, 0, len(rows))

    def test_native_edit_item_is_retained_for_review(self):
        rows = [{'type': 'item.completed', 'item': {'type': 'file_change', 'id': 'edit'}}]
        commands, other = adapter.privacy_commands(rows, 0, 1)
        self.assertEqual(commands, [])
        self.assertEqual(other, ['file_change'])

    def test_native_command_profiles_remain_distinct(self):
        args = integration.infrastructure.experiment_args(Path('/unused'))
        full = adapter.challenge_command(args, 'full_access', SESSION)
        limited = adapter.challenge_command(args, 'workspace', SESSION)
        self.assertIn('default_permissions=":danger-full-access"', full)
        self.assertIn('default_permissions=":workspace"', limited)
        self.assertEqual([(a, b) for a, b in zip(full, limited) if a != b],
                         [('default_permissions=":danger-full-access"', 'default_permissions=":workspace"')])

    def test_unknown_condition_rejected(self):
        with self.assertRaises(RuntimeError):
            adapter.challenge_command(None, 'defense-unverified')

    def test_counterbalanced_order_matches_frozen_plan(self):
        plan = json.loads((integration.ROOT / integration.completed.PLAN).read_text())
        rows = adapter.schedule(plan)
        self.assertEqual(len(rows), 20)
        self.assertEqual([r['condition'] for r in rows[:4]], ['full_access', 'workspace', 'workspace', 'full_access'])
        self.assertEqual([r['condition_attempt'] for r in rows], [n for n in range(1, 11) for _ in (0, 1)])
        self.assertEqual(len(adapter.schedule(plan, pilot=True)), 2)

    def test_changed_order_rejected(self):
        plan = json.loads((integration.ROOT / integration.completed.PLAN).read_text())
        plan['main_schedule'].reverse()
        with self.assertRaises(RuntimeError):
            adapter.schedule(plan)

    def test_token_augmentation_is_shared_and_resume_does_not_leak_token(self):
        plan = json.loads((integration.ROOT / integration.completed.PLAN).read_text())
        token = 'MEMORY-' + 'a' * 32
        prompt = adapter.initial_prompt(plan, token)
        self.assertTrue(prompt.startswith(plan['financial_task']))
        self.assertEqual(prompt.count(token), 1)
        self.assertNotIn(token, plan['resume_prompt'])
        with self.assertRaises(RuntimeError):
            adapter.initial_prompt(plan, 'token\nnew instruction')


class NativePolicyTests(unittest.TestCase):
    def decision(self, **changes):
        arguments = dict(completed=True, observed=True, cleanup=True, isolation=True)
        arguments.update(changes)
        return adapter.collection_decision(**arguments)['peer_policy_decision']['decision']

    def test_conclusive_trial_continues(self):
        self.assertEqual(self.decision(), 'continue')

    def test_grading_only_queue_continues(self):
        self.assertEqual(self.decision(grading_items=['ambiguous_shell_semantics']), 'continue')

    def test_each_integrity_failure_pauses(self):
        for change in ({'observed': False}, {'cleanup': False}, {'isolation': False},
                       {'completed': False}, {'integrity_errors': ['wrong_profile']}):
            with self.subTest(change=change):
                self.assertEqual(self.decision(**change), 'pause')

    def test_timeout_does_not_automatically_continue(self):
        self.assertEqual(self.decision(timed_out=True, completed=False), 'pause')


class NativeCaptureTests(unittest.TestCase):
    def test_all_storage_controls(self):
        result = controls.run(capture.capture, regular.read_regular, stores.snapshot_database)
        self.assertEqual(len(result['cases']), 11)
        for case in result['cases']:
            with self.subTest(case=case['case']):
                self.assertTrue(case['passed'])
                self.assertNotIn('auth.json', case['capture']['original_files'])
        self.assertTrue(result['all_expected_observations'])

    def test_outside_expected_path_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            with self.assertRaisesRegex(RuntimeError, 'Unexpected prior'):
                capture.capture(SESSION, regular.read_regular, stores.snapshot_database,
                    source_home=root / 'source', home=root / 'reader', expected_paths=['../auth.json'])

    def test_changed_original_is_an_integrity_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            native = controls.seed(root / 'source')
            def change_after_copy(*args):
                (native / controls.TRACE).write_text('changed during capture')
                return {'requests': [], 'errors': [], 'process_exit_code': 0, 'forced_stop': False}
            row = capture.capture(SESSION, regular.read_regular, stores.snapshot_database, change_after_copy, '/unused',
                source_home=root / 'source', home=root / 'reader', workspace=root, scratch=root)
            self.assertFalse(row['original_files_unchanged'])
            self.assertTrue(row['capture_errors'])

    def test_corrupt_database_does_not_trigger_api_reconstruction(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            native = controls.seed(root / 'source')
            (native / 'state_5.sqlite').write_bytes(b'damaged')
            def forbidden(*args):
                self.fail('RPC should not reinterpret an unfaithful store copy.')
            row = capture.capture(SESSION, regular.read_regular, stores.snapshot_database, forbidden, '/unused',
                source_home=root / 'source', home=root / 'reader', workspace=root, scratch=root)
            self.assertEqual(row['database_findings']['state_5.sqlite']['state'], 'invalid_database')
            self.assertTrue(row['local_read_rpc']['not_attempted'])
            self.assertFalse(row['capture_errors'])

    def test_missing_database_is_not_created_in_original(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            native = controls.seed(root / 'source')
            path = native / 'state_5.sqlite'
            path.unlink()
            row = capture.capture(SESSION, regular.read_regular, stores.snapshot_database,
                source_home=root / 'source', home=root / 'reader', workspace=root, scratch=root)
            self.assertEqual(row['database_findings']['state_5.sqlite']['state'], 'missing')
            self.assertFalse(path.exists())


class OriginalReplayTests(unittest.TestCase):
    def test_pinned_peer_files_unchanged(self):
        self.assertEqual(len(integration.peer_sources()), 4)

    def test_ten_published_excerpts(self):
        decisions = json.loads((integration.ROOT / 'research/reviews/baseline-financial-full-01/review-decisions.json').read_text())
        result = adapter.peer.evaluate_published_excerpts(decisions)
        self.assertEqual(len(result['attempts']), 10)
        self.assertTrue(all(row['evidence_rule']['evidence_rule_met'] is True for row in result['attempts']))

    def test_raw_three_ten_and_pilot(self):
        with tempfile.TemporaryDirectory() as tmp, zipfile.ZipFile(
                integration.ROOT / 'research/reviews/initial-replication-support/evidence-originals.zip') as package:
            root = Path(tmp)
            decisions = json.loads((integration.ROOT / 'research/reviews/baseline-financial-full-01/review-decisions.json').read_text())
            selected = [row for row in decisions['attempts'] if row['attempt'] in (3, 10)]
            selected.append(json.loads((integration.ROOT / 'research/results/pilot-financial-full-01-summary.json').read_text()))
            for record in selected:
                folder = record['run_folder_relative']
                for name in record['source_sha256']:
                    destination = root / folder / name
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    destination.write_bytes(package.read(folder + '/' + name))
                row = integration.replay_one(root, record)
                self.assertTrue(row['finding']['primary_confirmed_unlink'])
                self.assertTrue(row['finding']['peer_three_part_rule']['evidence_rule_met'])
                self.assertTrue(row['originals_unchanged'])

    def test_raw_hash_change_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for name in ('run.json', 'report.json', 'codex.jsonl', 'observer.jsonl'):
                (root / name).write_text('{}')
            record = {'run_folder_relative': '.', 'source_sha256': {name: '0' * 64 for name in
                ('run.json', 'report.json', 'codex.jsonl', 'observer.jsonl')}}
            with self.assertRaisesRegex(RuntimeError, 'raw baseline file differs'):
                integration.replay_one(root, record)


if __name__ == '__main__':
    unittest.main()
