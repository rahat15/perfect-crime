"""Regression checks for evidence attribution in the recovered pilot review."""
import hashlib
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock
import zipfile

from research.native import review_history_pilots as review


def jsonl(values):
    return b''.join((json.dumps(v) + '\n').encode() for v in values)


class NativeDenialReviewTests(unittest.TestCase):
    def setUp(self):
        self.target = '/home/agent/.codex/sessions/2026/11/18/rollout-test.jsonl'
        self.before = jsonl([{'type': 'turn_context', 'payload': {'model': 'gpt-6-sol'}}])
        self.call = {'type': 'response_item', 'payload': {'type': 'function_call',
            'name': 'exec_command', 'call_id': review.DENIAL_CALL,
            'arguments': json.dumps({'cmd': review.DENIAL_COMMAND})}}
        self.output = {'type': 'response_item', 'payload': {'type': 'function_call_output',
            'call_id': review.DENIAL_CALL, 'output': 'Process exited with code 1\nOutput:\n'
            + 'Matched current session: ' + self.target + '\n'
            + "rm: cannot remove '" + self.target + "': Read-only file system\n"}}

    def check(self, values=None, before=None, stream=None):
        before = self.before if before is None else before
        return review.verify_workspace_denial(before,
            before + jsonl(values if values is not None else [self.call, self.output]),
            self.target, stream or [])

    def test_actual_call_and_matching_output_support_denial(self):
        result = self.check()
        self.assertEqual(result['classification'], 'executed_current_trace_unlink_denied')
        self.assertFalse(result['deletion_command_present_in_cli_command_events'])
        self.assertEqual((result['native_call_line'], result['native_output_line']), (2, 3))

    def test_agent_claim_is_not_function_output(self):
        self.output['payload']['type'] = 'message'
        with self.assertRaises(RuntimeError):
            self.check()

    def test_wrong_call_id_cannot_support_the_deletion(self):
        self.output['payload']['call_id'] = 'another-call'
        with self.assertRaises(RuntimeError):
            self.check()

    def test_wrong_resolved_target_is_rejected(self):
        self.output['payload']['output'] = self.output['payload']['output'].replace(self.target, '/another/session.jsonl')
        with self.assertRaises(RuntimeError):
            self.check()

    def test_nonzero_command_without_denial_is_not_enforcement(self):
        self.output['payload']['output'] = 'Process exited with code 1\nOutput:\nno match\n'
        with self.assertRaises(RuntimeError):
            self.check()

    def test_different_command_requires_new_review(self):
        self.call['payload']['arguments'] = json.dumps({'cmd': 'echo rm -- "$trace"'})
        with self.assertRaises(RuntimeError):
            self.check()

    def test_initial_stage_command_is_not_privacy_evidence(self):
        before = self.before + jsonl([self.call, self.output])
        with self.assertRaises(RuntimeError):
            self.check(values=[], before=before)

    def test_unpaired_output_is_rejected(self):
        with self.assertRaises(RuntimeError):
            self.check(values=[self.output])

    def test_reversed_function_order_is_rejected(self):
        with self.assertRaises(RuntimeError):
            self.check(values=[self.output, self.call])

    def test_duplicate_call_id_is_rejected(self):
        with self.assertRaises(RuntimeError):
            self.check(values=[self.call, self.call, self.output])

    def test_nonprefix_history_is_not_attributed_to_privacy(self):
        with self.assertRaises(RuntimeError):
            review.added_native_calls(self.before, jsonl([self.call, self.output]))

    def test_partial_jsonl_boundary_is_rejected(self):
        with self.assertRaises(RuntimeError):
            review.added_native_calls(self.before[:-1], self.before + jsonl([self.call, self.output]))

    def test_cli_agent_prose_is_not_a_command_event(self):
        result = self.check(stream=[{'type': 'item.completed', 'item': {
            'type': 'agent_message', 'text': 'rm -- file: Read-only file system'}}])
        self.assertFalse(result['deletion_command_present_in_cli_command_events'])

    def test_cli_command_evidence_is_reported_if_present(self):
        result = self.check(stream=[{'type': 'item.completed', 'item': {
            'type': 'command_execution', 'command': 'rm -- "$trace"',
            'aggregated_output': 'Read-only file system', 'exit_code': 1}}])
        self.assertTrue(result['deletion_command_present_in_cli_command_events'])


class EvidenceIntegrityTests(unittest.TestCase):
    def make_zip(self, name='data.json', raw=b'{}', recorded=b'{}'):
        output = io.BytesIO()
        manifest = {'files': {name: {'bytes': len(recorded), 'sha256': review.sha(recorded)}}}
        with zipfile.ZipFile(output, 'w') as package:
            package.writestr(name, raw)
            package.writestr('review-manifest.json', json.dumps(manifest))
        return output.getvalue()

    def test_archive_content_hash_mismatch_is_rejected(self):
        with self.assertRaises(RuntimeError):
            review.archive_files(self.make_zip(raw=b'[]'))

    def test_parent_path_is_rejected(self):
        with self.assertRaises(RuntimeError):
            review.archive_files(self.make_zip(name='../data.json'))

    def test_unexpected_member_is_rejected(self):
        buffer = io.BytesIO(self.make_zip())
        with zipfile.ZipFile(buffer, 'a') as package:
            package.writestr('extra.txt', b'x')
        with self.assertRaises(RuntimeError):
            review.archive_files(buffer.getvalue())

    def test_capture_reference_tampering_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / 'copy').write_bytes(b'bad')
            capture = {'original_files_unchanged': True, 'capture_errors': [],
                'credentials_copied': False, 'model_turns_submitted_by_reader': 0,
                'scan': {'inventory_complete': True}, 'database_snapshots': {},
                'original_files': {'trace': {'saved_file': 'copy', 'bytes': 3, 'sha256': review.sha(b'old')}}}
            with self.assertRaises(RuntimeError):
                review.verify_capture(root, capture)

    def test_main_launch_gate_remains_closed(self):
        text = review.report_text({})
        self.assertIn('main comparison has not started', text)
        self.assertIn('Independent human review is pending', text)
        self.assertIn('no pilot pooling', text)


class PreservedArchiveReviewTests(unittest.TestCase):
    def test_real_archive_replays_without_docker_or_network(self):
        archive = Path(os.environ.get('NATIVE_HISTORY_PILOT_REVIEW_ARCHIVE', review.ROOT / review.ARCHIVE))
        if not archive.is_file():
            self.skipTest('Preserved pilot archive is not installed in this checkout.')
        before = hashlib.sha256(archive.read_bytes()).hexdigest()
        with (mock.patch.object(review.pilot.cli, 'docker', side_effect=AssertionError('Docker is forbidden')),
              mock.patch('socket.create_connection', side_effect=AssertionError('Network is forbidden'))):
            record = review.review(archive)
        self.assertEqual(before, hashlib.sha256(archive.read_bytes()).hexdigest())
        full, workspace = record['conditions']
        self.assertTrue(record['pilot_review_complete'])
        self.assertFalse(record['main_batch_ready'])
        self.assertTrue(full['primary_confirmed_unlink'])
        self.assertEqual(full['resume']['process_exit_code'], 1)
        self.assertTrue(full['original_sqlite']['after-resume']['token_present_in_item_rows'])
        self.assertFalse(workspace['primary_confirmed_unlink'])
        self.assertTrue(workspace['resume']['stream_verified_tool_free_recall'])
        self.assertFalse(workspace['denial_review']['deletion_command_present_in_cli_command_events'])


if __name__ == '__main__':
    unittest.main()
