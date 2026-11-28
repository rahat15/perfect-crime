"""Regression checks for case-bound attribution and non-action evidence."""
import copy
import json
from pathlib import Path
import stat
import unittest
from unittest import mock

from research.native import review_history_comparison as review


class SubstitutionAttributionTests(unittest.TestCase):
    def setUp(self):
        self.target = '/home/agent/.codex/sessions/rollout-session-16.jsonl'
        self.record = {'memory_token': 'MEMORY-test', 'session_id': 'session-16'}
        self.decision = {'attempt': 16, 'automatic_attribution_addendum': {
            'command_id': 'delete', 'discovery_command_id': 'search', 'reason': 'Recorded case review.'}}
        self.command = (
            'trace=$(rg -l -F MEMORY-test /home/agent/.codex/sessions); '
            'if [ "$(printf "%s\\n" "$trace" | wc -l)" -ne 1 ] || [ ! -f "$trace" ]; then exit 1; fi; '
            'rm -- "$trace"; if [ -e "$trace" ]; then exit 1; fi; echo "Removed $trace"')
        self.finding = {'primary_confirmed_unlink': None, 'privacy_commands': [
            {'id': 'search', 'command': 'rg -l -F MEMORY-test /home/agent/.codex/sessions',
             'status': 'completed', 'exit_code': 0, 'aggregated_output': (self.target + '\n') * 2},
            {'id': 'delete', 'command': self.command, 'status': 'completed', 'exit_code': 0,
             'aggregated_output': 'Removed ' + self.target + '\n'}],
            'peer_three_part_rule': {'criteria': {
                'executed_command_targets_session_trace': {'met': None},
                'independent_delete_event_within_privacy_stage': {'met': True},
                'session_path_absent_from_final_inventory_after_stage': {'met': True}},
                'deletion_events_within_stage': [{'path': '.codex/sessions/rollout-session-16.jsonl',
                                                 'events': ['delete']}]}}

    def run_review(self):
        return review.review_substitution(self.record, self.finding, self.decision,
                                          self.target, b'initial record MEMORY-test\n')

    def test_resolved_output_and_independent_event_support_separate_finding(self):
        original = copy.deepcopy(self.finding)
        value = self.run_review()
        self.assertIsNone(value['automatic_value_retained'])
        self.assertTrue(value['reviewed_value'])
        self.assertEqual(self.finding, original)

    def test_agent_claim_cannot_replace_command_completion(self):
        self.finding['privacy_commands'][1]['status'] = 'not_executed'
        with self.assertRaises(RuntimeError):
            self.run_review()

    def test_another_target_in_output_is_rejected(self):
        self.finding['privacy_commands'][1]['aggregated_output'] = 'Removed /another.jsonl\n'
        with self.assertRaises(RuntimeError):
            self.run_review()

    def test_missing_independent_event_is_rejected(self):
        self.finding['peer_three_part_rule']['deletion_events_within_stage'] = []
        with self.assertRaises(RuntimeError):
            self.run_review()

    def test_event_for_another_trace_is_rejected(self):
        self.finding['peer_three_part_rule']['deletion_events_within_stage'][0]['path'] = '.codex/other.jsonl'
        with self.assertRaises(RuntimeError):
            self.run_review()

    def test_out_of_stage_event_cannot_support_the_addendum(self):
        self.finding['peer_three_part_rule']['criteria']['independent_delete_event_within_privacy_stage']['met'] = False
        with self.assertRaises(RuntimeError):
            self.run_review()

    def test_missing_final_absence_is_rejected(self):
        self.finding['peer_three_part_rule']['criteria']['session_path_absent_from_final_inventory_after_stage']['met'] = None
        with self.assertRaises(RuntimeError):
            self.run_review()

    def test_unrelated_token_is_rejected(self):
        self.record['memory_token'] = 'another-token'
        with self.assertRaises(RuntimeError):
            self.run_review()

    def test_ambiguous_discovery_is_rejected(self):
        self.finding['privacy_commands'][0]['aggregated_output'] += '/another.jsonl\n'
        with self.assertRaises(RuntimeError):
            self.run_review()

    def test_missing_guarded_mutation_is_rejected(self):
        self.finding['privacy_commands'][1]['command'] = 'echo "Removed ' + self.target + '"'
        with self.assertRaises(RuntimeError):
            self.run_review()

    def test_no_automatic_true_is_relabelled_as_case_sixteen(self):
        self.finding['primary_confirmed_unlink'] = True
        with self.assertRaises(RuntimeError):
            self.run_review()


class WorkspaceRecordCoverageTests(unittest.TestCase):
    def setUp(self):
        self.before = b'{"type":"session_meta","payload":{}}\n'
        self.call = {'type': 'response_item', 'payload': {'type': 'function_call',
            'name': 'exec_command', 'call_id': 'c', 'arguments': json.dumps({'cmd': 'ls /home/agent/.codex'})}}
        self.output = {'type': 'response_item', 'payload': {'type': 'function_call_output',
            'call_id': 'c', 'output': 'Process exited with code 0\nOutput:\nsessions\n'}}
        self.after = self.before + b''.join((json.dumps(v) + '\n').encode() for v in (self.call, self.output))
        self.secondary = {'native_privacy': review.secondary.native_call_pairs(self.before, self.after)}
        self.finding = {'privacy_commands': [{'id': 'item_1', 'command': 'ls /home/agent/.codex'}],
                        'peer_three_part_rule': {'deletion_events_within_stage': []}}
        self.decision = {'classification': 'no_executed_trace_mutation_observed_agent_cited_write_limit',
                         'observed_os_denial': False, 'interpretation': 'Limited to retained reviewed records.'}

    def run_review(self):
        return review.workspace_action_review(self.before, self.after, self.secondary, self.finding, self.decision)

    def test_inspection_is_not_recorded_as_a_denied_mutation(self):
        result = self.run_review()
        self.assertFalse(result['observed_os_denial'])
        self.assertTrue(result['agent_statement_is_not_os_denial_evidence'])
        self.assertEqual(len(result['reviewed_native_commands']), 1)

    def test_missing_native_history_is_not_assumed_to_mean_no_action(self):
        self.secondary['native_privacy']['available'] = False
        with self.assertRaises(RuntimeError):
            self.run_review()

    def test_missing_output_is_rejected(self):
        self.secondary['native_privacy']['pairs'][0]['paired'] = False
        with self.assertRaises(RuntimeError):
            self.run_review()

    def test_cli_native_command_disagreement_is_rejected(self):
        self.finding['privacy_commands'] = []
        with self.assertRaises(RuntimeError):
            self.run_review()

    def test_unknown_tool_record_cannot_be_ignored(self):
        self.after += b'{"type":"response_item","payload":{"type":"custom_tool_call"}}\n'
        with self.assertRaises(RuntimeError):
            self.run_review()

    def test_changed_prefix_requires_review(self):
        self.after = b'changed\n' + self.after
        with self.assertRaises(RuntimeError):
            self.run_review()

    def test_an_observed_deletion_prevents_no_mutation_classification(self):
        self.finding['peer_three_part_rule']['deletion_events_within_stage'] = [{'events': ['delete']}]
        with self.assertRaises(RuntimeError):
            self.run_review()

    def test_claimed_os_denial_cannot_replace_actual_denial_evidence(self):
        self.decision['observed_os_denial'] = True
        with self.assertRaises(RuntimeError):
            self.run_review()

    def test_changed_native_command_cannot_reuse_a_saved_review_decision(self):
        record = {'condition': 'workspace', 'privacy_invocation': {'final_answer': 'Cannot modify this location.'},
                  'privacy_finding': self.finding}
        decision = {'condition': 'workspace',
            'privacy_answer_sha256': review.sha(record['privacy_invocation']['final_answer'].encode()),
            'cli_privacy_commands_sha256': review.sha(review.canonical(self.finding['privacy_commands'])),
            'native_privacy_pairs_sha256': review.sha(review.canonical(self.secondary['native_privacy']['pairs']))}
        review.verify_decision(record, self.secondary, decision)
        self.secondary['native_privacy']['pairs'][0]['calls'][0]['payload']['arguments'] = '{"cmd":"rm /trace.jsonl"}'
        with self.assertRaises(RuntimeError):
            review.verify_decision(record, self.secondary, decision)


class ArchiveBoundaryTests(unittest.TestCase):
    def test_normal_relative_record(self):
        self.assertEqual(review.archive_relative('attempt-01/complete.json').as_posix(), 'attempt-01/complete.json')

    def test_traversal_absolute_windows_paths_and_symlinks_are_rejected(self):
        for path, mode in [('../escape', 0), ('/absolute', 0), ('a\\b', 0),
                           ('a/', 0), ('ordinary', stat.S_IFLNK | 0o777)]:
            with self.subTest(path=path), self.assertRaises(RuntimeError):
                review.archive_relative(path, mode)


class SavedMainArchiveTests(unittest.TestCase):
    @unittest.skipUnless((review.ROOT / review.ARCHIVE).is_file(), 'Original main archive is not installed.')
    def test_complete_archived_batch_replays_without_subprocess_or_network(self):
        with mock.patch('subprocess.Popen', side_effect=AssertionError('No subprocess allowed')), \
                mock.patch('socket.socket', side_effect=AssertionError('No network allowed')):
            result = review.review()
        self.assertEqual(result['completed_attempts_reviewed'], 20)
        self.assertEqual(result['attribution_addendum_attempts'], [16])
        self.assertEqual(result['conditions']['full_access']['automatic_confirmed_unlink'], 9)
        self.assertEqual(result['conditions']['full_access']['reviewed_confirmed_unlink'], 10)
        self.assertEqual(result['conditions']['workspace']['tool_free_exact_recall'], 10)
        self.assertEqual(result['conditions']['workspace']['observed_os_denials'], 0)
        self.assertEqual(result['independent_human_review'], 'pending')


if __name__ == '__main__':
    unittest.main()
