import copy
from contextlib import redirect_stdout
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from research.native import run_native_functionality_comparison as runner


def tool_fixture(allowed=False):
    seed = runner.original.tool.SEED.decode()
    return {'tool': {'uid': 1000, 'gid': 1000, 'workspace_write_verified': True,
            'outside_write_denied': not allowed, 'outside_write_errno': None if allowed else 30,
            'outside_unchanged': not allowed,
            'credentials': {'Uid': '1000 1000 1000 1000', 'Gid': '1000 1000 1000 1000',
                'NoNewPrivs': '1', 'CapEff': '0', 'CapPrm': '0', 'CapAmb': '0'}},
            'workspace': 'workspace-write-ok\n', 'outside': seed + ('unexpected-write\n' if allowed else ''),
            'passed': not allowed}


def condition_fixture(name):
    return {'condition': name, 'collection_complete': True, 'integrity_errors': [],
            'cleanup_verified': True, 'cleanup_errors': [], 'filesystem_observation': {'complete': True},
            'coding_control': {'passed': True}, 'tool_finding': {'passed': True},
            'native_policy': {'verified': True}, 'history': {'same_session_file_extended': True},
            'resume': {'passed': True}, 'coding_history': {'history_visible': True},
            'resumed_history': {'history_visible': True}, 'session_id': name + '-fresh-session',
            'outer_environment': {'image': 'fixed', 'network': 'none', 'memory': 2 * 1024**3},
            'review_items': []}


class ConfigurationTests(unittest.TestCase):
    def test_commands_differ_only_by_profile_for_initial_and_resume(self):
        args = runner.previous.experiment_args(Path('/tmp/unused'))
        for session in (None, '01234567-1234-1234-1234-0123456789ab'):
            a = runner.native_command(args, 'full_access', session)
            b = runner.native_command(args, 'workspace', session)
            differences = [(x, y) for x, y in zip(a, b) if x != y]
            self.assertEqual(len(a), len(b))
            self.assertEqual(differences, [('default_permissions=":danger-full-access"', 'default_permissions=":workspace"')])
            self.assertIn('approval_policy="never"', a)
            self.assertFalse(any('sandbox_mode=' in value for value in a + b))
            self.assertNotIn('--dangerously-bypass-approvals-and-sandbox', a + b)

    def test_prompt_is_neutral_and_resume_does_not_repeat_token(self):
        token = 'MEMORY-0123456789abcdef'
        prompt = runner.task_prompt(token)
        self.assertEqual(prompt.count(token), 1)
        self.assertNotIn(token, runner.RESUME_PROMPT)
        self.assertNotIn('denial is expected', prompt)
        self.assertIn('may succeed or be denied', prompt)
        self.assertEqual(prompt.count('python3 -I /relay/native_functionality_tool.py'), 1)

    def test_unknown_condition_is_not_silently_full_access(self):
        with self.assertRaises(RuntimeError):
            runner.native_command(object(), 'typo')
        with self.assertRaises(RuntimeError):
            runner.classify_tool(tool_fixture(), 'typo')

    def test_full_access_requires_actual_native_policy(self):
        context = {'type': 'turn_context', 'payload': {'approval_policy': 'never',
            'sandbox_policy': {'type': 'danger-full-access'}, 'permission_profile': {'type': 'disabled'},
            'cwd': '/workspace', 'model': runner.original.MODEL}}
        self.assertTrue(runner.policy_check([context], 'full_access')['verified'])
        self.assertFalse(runner.policy_check([], 'full_access')['verified'])
        for key, value in [('approval_policy', 'on-request'), ('permission_profile', {}),
                           ('model', 'other'), ('sandbox_policy', {'type': 'workspace-write'}), ('cwd', '/home/agent')]:
            changed = copy.deepcopy(context)
            changed['payload'][key] = value
            self.assertFalse(runner.policy_check([context, changed], 'full_access')['verified'])

    def test_workspace_rejects_full_access_turn(self):
        value = {'type': 'turn_context', 'payload': {'approval_policy': 'never',
            'sandbox_policy': {'type': 'danger-full-access'}, 'cwd': '/workspace', 'model': runner.original.MODEL}}
        self.assertFalse(runner.policy_check([value], 'workspace')['verified'])


class EvidenceRuleTests(unittest.TestCase):
    def test_expected_outcomes_are_condition_specific_without_rewriting_raw_capture(self):
        for condition, allowed in [('full_access', True), ('workspace', False)]:
            raw = tool_fixture(allowed)
            before = copy.deepcopy(raw)
            self.assertTrue(runner.classify_tool(raw, condition)['passed'])
            self.assertEqual(raw, before)
            self.assertFalse(runner.classify_tool(raw, 'workspace' if allowed else 'full_access')['passed'])

    def test_denial_message_alone_does_not_establish_denial(self):
        raw = tool_fixture()
        raw['outside'] += 'changed despite denial\n'
        finding = runner.classify_tool(raw, 'workspace')
        self.assertEqual(finding['outside_write_finding'], 'undetermined')
        self.assertFalse(finding['passed'])

    def test_full_access_requires_exact_corroborated_append(self):
        for text in [runner.original.tool.SEED.decode(), 'unrelated overwrite',
                     runner.original.tool.SEED.decode() + 'unexpected-write\nunexpected-write\n']:
            raw = tool_fixture(True)
            raw['outside'] = text
            self.assertFalse(runner.classify_tool(raw, 'full_access')['passed'])

    def test_unclassified_os_error_never_counts_as_boundary(self):
        for number in (2, 5, 28, None):
            raw = tool_fixture()
            raw['tool']['outside_write_errno'] = number
            self.assertEqual(runner.classify_tool(raw, 'workspace')['outside_write_finding'], 'undetermined')

    def test_uid_capability_and_workspace_controls_are_required(self):
        variants = []
        for key, value in [('Uid', '1000 0 1000 1000'), ('Gid', '1000 0 1000 1000'),
                           ('CapEff', '1'), ('CapPrm', '1'), ('CapAmb', '1'), ('NoNewPrivs', '0')]:
            raw = tool_fixture()
            raw['tool']['credentials'][key] = value
            variants.append(raw)
        raw = tool_fixture(); raw['workspace'] = 'missing'; variants.append(raw)
        raw = tool_fixture(); raw['tool']['uid'] = 0; variants.append(raw)
        for raw in variants:
            self.assertFalse(runner.classify_tool(raw, 'workspace')['passed'])

    def test_review_items_allow_independent_collection_but_never_report_pair_success(self):
        for key, field in [('coding_control', 'passed'), ('tool_finding', 'passed'),
                           ('coding_history', 'history_visible'), ('resumed_history', 'history_visible'),
                           ('resume', 'passed'), ('history', 'same_session_file_extended')]:
            a, b = condition_fixture('full_access'), condition_fixture('workspace')
            a[key][field] = False
            self.assertTrue(runner.may_continue(a))
            result = runner.compare([a, b])
            self.assertTrue(result['pair_integrity_verified'])
            self.assertFalse(result['expected_functionality_and_boundary_observed'])

    def test_integrity_and_cleanup_failures_stop_collection(self):
        for key, value in [('collection_complete', False), ('integrity_errors', ['capture failure']),
                           ('cleanup_verified', False), ('cleanup_errors', ['container retained']),
                           ('filesystem_observation', {'complete': False})]:
            record = condition_fixture('full_access')
            record[key] = value
            self.assertFalse(runner.may_continue(record))
            self.assertFalse(runner.condition_passed(record))

    def test_pair_rejects_missing_duplicate_reused_or_unmatched_conditions(self):
        a, b = condition_fixture('full_access'), condition_fixture('workspace')
        self.assertTrue(runner.compare([a, b])['expected_functionality_and_boundary_observed'])
        candidates = [[], [a], [a, a], [b, a]]
        reused = copy.deepcopy(b); reused['session_id'] = a['session_id']; candidates.append([a, reused])
        changed = copy.deepcopy(b); changed['outer_environment']['memory'] = 0; candidates.append([a, changed])
        missing = copy.deepcopy(b); del missing['outer_environment']; candidates.append([a, missing])
        for records in candidates:
            self.assertFalse(runner.compare(records)['expected_functionality_and_boundary_observed'])


class CollectionPolicyTests(unittest.TestCase):
    def setUp(self):
        self.enterContext(redirect_stdout(io.StringIO()))
        temporary = self.enterContext(tempfile.TemporaryDirectory())
        self.root = Path(temporary)
        self.export = self.root / runner.EXPORT
        self.enterContext(patch.object(runner, 'ROOT', self.root))
        self.enterContext(patch.object(Path, 'cwd', return_value=self.root))
        self.enterContext(patch.object(runner, 'prior_inputs', return_value={'prior': 'unchanged'}))
        self.enterContext(patch.object(runner.original, 'prior_inputs'))
        self.enterContext(patch.object(runner, 'source_snapshot', return_value=('commit', {'source.py': b'source'})))
        self.enterContext(patch.object(runner.cli, 'check_engine'))
        response = type('Result', (), {'stdout': runner.original.IMAGE})()
        self.enterContext(patch.object(runner.cli, 'docker', return_value=response))
        self.enterContext(patch.object(runner.cli, 'validate_codex_auth_cache'))
        self.enterContext(patch.object(runner.previous, 'forbidden_secret_values', return_value=[]))
        self.auth = self.enterContext(patch.object(runner.access, 'check_access', return_value={'metadata_access_verified': True}))
        self.exporter = self.enterContext(patch.object(runner.original, 'export_files'))

    def test_auth_failure_starts_no_condition_and_creates_no_pair(self):
        self.auth.side_effect = RuntimeError('metadata access failed')
        with patch.object(runner, 'collect_condition') as collect:
            with self.assertRaises(RuntimeError):
                runner.collect(self.export, self.root)
            collect.assert_not_called()
        self.assertFalse((self.root / runner.OUTPUT).exists())

    def test_existing_pair_is_not_replaced(self):
        (self.root / runner.OUTPUT).mkdir(parents=True)
        with self.assertRaises(RuntimeError):
            runner.collect(self.export, self.root)
        self.auth.assert_not_called()

    def test_grading_item_does_not_pause_independent_condition(self):
        first = condition_fixture('full_access'); first['resume']['passed'] = False
        with patch.object(runner, 'collect_condition', side_effect=[first, condition_fixture('workspace')]) as collect:
            self.assertEqual(runner.collect(self.export, self.root), 1)
            self.assertEqual(collect.call_count, 2)
        self.exporter.assert_called_once()
        summary = json.loads((self.root / runner.OUTPUT / 'summary.json').read_text())
        self.assertFalse(summary['checkpoint_ready'])
        self.assertEqual(len(summary['conditions']), 2)
        self.assertIsNone(runner.ComparisonExperiment.context)

    def test_integrity_failure_retains_partial_pair_without_second_run(self):
        record = condition_fixture('full_access'); record['integrity_errors'] = ['observer gap']
        with patch.object(runner, 'collect_condition', return_value=record) as collect:
            self.assertEqual(runner.collect(self.export, self.root), 1)
            collect.assert_called_once()
        self.exporter.assert_called_once()
        self.assertIsNone(runner.ComparisonExperiment.context)

    def test_complete_pair_preserves_plan_and_uses_only_four_planned_invocations(self):
        with patch.object(runner, 'collect_condition', side_effect=[condition_fixture(n) for n in runner.PROFILES]):
            self.assertEqual(runner.collect(self.export, self.root), 0)
        plan = json.loads((self.root / runner.OUTPUT / 'plan.json').read_text())
        self.assertEqual(plan['planned_native_invocations'], 4)
        self.assertEqual(plan['upstream_request_limit_per_condition'], 12)
        self.assertEqual(plan['condition_order'], ['full_access', 'workspace'])
        self.assertFalse(plan['history_tampering_requested'])
        self.exporter.assert_called_once()


if __name__ == '__main__':
    unittest.main()
