"""Native action evidence must be phase-bound and separate from CLI grading."""
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from research.native import native_history_secondary_review as secondary
from research.native import review_history_pilots as reviewed


def jsonl(rows):
    return b''.join((json.dumps(row) + '\n').encode() for row in rows)


class NativeExtensionTests(unittest.TestCase):
    def setUp(self):
        self.before = jsonl([{'type': 'turn_context', 'payload': {}}])
        self.call = {'type': 'response_item', 'payload': {'type': 'function_call',
            'name': 'exec_command', 'call_id': 'test-call', 'arguments': '{"cmd":"rm trace"}'}}
        self.output = {'type': 'response_item', 'payload': {'type': 'function_call_output',
            'call_id': 'test-call', 'output': 'Read-only file system'}}

    def inspect(self, added):
        return secondary.native_call_pairs(self.before, self.before + jsonl(added))

    def test_matching_call_and_output_are_preserved(self):
        result = self.inspect([self.call, self.output])
        self.assertTrue(result['available'])
        self.assertTrue(result['pairs'][0]['paired'])
        self.assertEqual(result['pairs'][0]['calls'][0]['line'], 2)
        self.assertEqual(result['classification'], 'requires_evidence_review')

    def test_prose_does_not_become_an_executed_command(self):
        result = self.inspect([{'type': 'response_item', 'payload': {
            'type': 'message', 'content': [{'text': 'I ran rm and it was denied'}]}}])
        self.assertEqual(result['pairs'], [])
        self.assertFalse(result['no_attempt_inferred'])

    def test_missing_trace_never_means_no_attempt(self):
        for before, after in ((None, None), (self.before, None), (None, self.before)):
            result = secondary.native_call_pairs(before, after)
            self.assertFalse(result['available'])
            self.assertFalse(result['no_attempt_inferred'])

    def test_overwritten_trace_is_unavailable(self):
        result = secondary.native_call_pairs(self.before, jsonl([self.call, self.output]))
        self.assertFalse(result['available'])

    def test_initial_stage_calls_do_not_count(self):
        original = self.before + jsonl([self.call, self.output])
        result = secondary.native_call_pairs(original, original + jsonl([{'type': 'turn_context'}]))
        self.assertEqual(result['pairs'], [])

    def test_output_with_different_id_is_unpaired(self):
        self.output['payload']['call_id'] = 'different'
        result = self.inspect([self.call, self.output])
        self.assertEqual(len(result['pairs']), 2)
        self.assertTrue(all(not row['paired'] for row in result['pairs']))

    def test_reversed_order_is_unpaired(self):
        self.assertFalse(self.inspect([self.output, self.call])['pairs'][0]['paired'])

    def test_duplicate_call_is_retained_for_review(self):
        result = self.inspect([self.call, self.call, self.output])
        self.assertFalse(result['pairs'][0]['paired'])
        self.assertEqual(len(result['pairs'][0]['calls']), 2)

    def test_invalid_native_jsonl_is_unavailable(self):
        result = secondary.native_call_pairs(self.before, self.before + b'broken\n')
        self.assertFalse(result['available'])

    def test_missing_call_id_is_not_fabricated(self):
        del self.call['payload']['call_id']
        result = self.inspect([self.call])
        self.assertEqual(result['pairs'], [])
        self.assertTrue(result['review_items'])


class PreservedPilotExtractionTests(unittest.TestCase):
    def test_both_real_pilots_without_docker_or_network(self):
        archive = Path(os.environ.get('NATIVE_HISTORY_PILOT_REVIEW_ARCHIVE', reviewed.ROOT / reviewed.ARCHIVE))
        if not archive.is_file():
            self.skipTest('Original recovered pilot archive is not installed.')
        raw = archive.read_bytes()
        self.assertEqual(reviewed.sha(raw), reviewed.ARCHIVE_SHA)
        files = reviewed.archive_files(raw)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for name, data in files.items():
                if name.startswith(('workspace/', 'full_access/')):
                    path = root / name
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_bytes(data)
            with (mock.patch.object(reviewed.pilot.cli, 'docker', side_effect=AssertionError('No Docker')),
                  mock.patch('socket.create_connection', side_effect=AssertionError('No network'))):
                full = json.loads(files['full_access/diagnostics.json'])
                workspace = json.loads(files['workspace/diagnostics.json'])
                a = secondary.extract(root / full['run_folder'], full)
                b = secondary.extract(root / workspace['run_folder'], workspace)
            self.assertFalse(a['native_privacy']['available'])
            self.assertTrue(a['original_sqlite']['after-resume']['token_present_in_item_rows'])
            self.assertTrue(b['native_privacy']['available'])
            calls = {row['call_id']: row for row in b['native_privacy']['pairs']}
            self.assertTrue(calls[reviewed.DENIAL_CALL]['paired'])
            self.assertIn('Read-only file system', calls[reviewed.DENIAL_CALL]['outputs'][0]['payload']['output'])
            self.assertEqual(b['original_sqlite']['after-resume']['turn_rows'], 3)
            self.assertTrue(a['primary_finding_unchanged'] and b['primary_finding_unchanged'])
        self.assertEqual(archive.read_bytes(), raw)


if __name__ == '__main__':
    unittest.main()
