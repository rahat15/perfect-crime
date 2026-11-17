import copy
import errno
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

from research.native import native_boundary_fixture as f
from research.native import run_native_boundary as r


def credentials():
    return {'Uid': '1000 1000 1000 1000', 'Gid': '1000 1000 1000 1000',
            'CapInh': '0000', 'CapPrm': '0000', 'CapEff': '0000',
            'CapAmb': '0000', 'CapBnd': '0000', 'NoNewPrivs': '1'}


def record(denied=False):
    before = {'exists': True, 'bytes': len(f.SEED), 'sha256': f.sha(f.SEED)}
    return {'profile': 'workspace' if denied else 'full_access', 'operation': 'session_unlink',
            'work': '/workspace/control', 'before': before,
            'after': copy.deepcopy(before) if denied else {'exists': False},
            'execution': {'exit_code': 0, 'timed_out': False, 'output_truncated': False},
            'child': {'marker': 'native-boundary-child-v1', 'operation': 'session_unlink',
                      'uid': 1000, 'gid': 1000, 'cwd': '/workspace/control',
                      'credentials': credentials(), 'workspace_control': True,
                      'operation_result': {'returned_success': not denied, 'errno': errno.EACCES if denied else None}},
            'workspace_file_present': True, 'trusted_parent_append': True}


class EvidenceClassificationTests(unittest.TestCase):
    def test_full_access_needs_observed_mutation(self):
        row = record()
        self.assertEqual(f.classify(row), 'mutation_observed')
        row['after'] = row['before']
        self.assertEqual(f.classify(row), 'unresolved')

    def test_denial_needs_independent_unchanged_target(self):
        row = record(True)
        self.assertEqual(f.classify(row), 'permission_denial_observed')
        row['after'] = {'exists': False}
        self.assertEqual(f.classify(row), 'mutation_observed')

    def test_unclassified_error_is_not_a_denial(self):
        for code in (errno.ENOENT, errno.EIO, errno.ENOSPC, None):
            with self.subTest(code=code):
                row = record(True); row['child']['operation_result']['errno'] = code
                self.assertEqual(f.classify(row), 'unresolved')

    def test_sqlite_readonly_is_distinct_from_lock(self):
        row = record(True); row['child']['operation_result'] = {'returned_success': False, 'sqlite_errorcode': sqlite3.SQLITE_READONLY | (3 << 8)}
        self.assertEqual(f.classify(row), 'permission_denial_observed')
        row['child']['operation_result']['sqlite_errorcode'] = sqlite3.SQLITE_BUSY
        self.assertEqual(f.classify(row), 'unresolved')

    def test_process_failures_are_not_security_success(self):
        for key, value in (('exit_code', 1), ('timed_out', True), ('output_truncated', True)):
            with self.subTest(key=key):
                row = record(True); row['execution'][key] = value
                self.assertEqual(f.classify(row), 'unresolved')

    def test_missing_child_is_unresolved(self):
        row = record(True); row.pop('child')
        self.assertEqual(f.classify(row), 'unresolved')

    def test_wrong_identity_or_capabilities_block_claim(self):
        for key, value in (('CapEff', '1'), ('CapBnd', '1'), ('NoNewPrivs', '0'), ('Uid', '0 0 0 0')):
            with self.subTest(key=key):
                row = record(True); row['child']['credentials'][key] = value
                self.assertEqual(f.classify(row), 'unresolved')

    def test_workspace_and_controller_controls_required(self):
        for key in ('workspace_file_present', 'trusted_parent_append'):
            row = record(True); row[key] = False
            self.assertEqual(f.classify(row), 'unresolved')
        row = record(True); row['child']['workspace_control'] = False
        self.assertEqual(f.classify(row), 'unresolved')

    def test_missing_before_or_after_is_unresolved(self):
        for key in ('before', 'after'):
            row = record(True); row.pop(key)
            self.assertEqual(f.classify(row), 'unresolved')

    def test_observations_are_not_mutated_by_classification(self):
        row = record(True); original = copy.deepcopy(row)
        f.classify(row)
        self.assertEqual(row, original)


class FixtureOperationTests(unittest.TestCase):
    def test_every_control_has_observable_effect_without_sandbox(self):
        with tempfile.TemporaryDirectory() as tmp:
            for i, op in enumerate(f.OPERATIONS):
                with self.subTest(operation=op):
                    home, work = Path(tmp) / str(i) / 'home', Path(tmp) / str(i) / 'work'
                    native = f.setup_case(home, work)
                    before = f.snapshot(native, work, op)
                    f.mutate(native, work, op)
                    after = f.snapshot(native, work, op)
                    self.assertTrue(f.effect_observed(op, before, after))

    def test_sqlite_reader_does_not_change_database(self):
        with tempfile.TemporaryDirectory() as tmp:
            home, work = Path(tmp) / 'home', Path(tmp) / 'work'
            native = f.setup_case(home, work)
            path = native / 'state_5.sqlite'; before = path.read_bytes()
            for _ in range(2):
                self.assertEqual(f.snapshot(native, work, 'state_sqlite_delete')['values'], ['retain'])
            self.assertEqual(path.read_bytes(), before)

    def test_symlink_case_reaches_outside_workspace(self):
        with tempfile.TemporaryDirectory() as tmp:
            home, work = Path(tmp) / 'home', Path(tmp) / 'work'
            native = f.setup_case(home, work)
            self.assertEqual((work / 'history-link').resolve(), native / 'sessions/boundary-fixture/fixture.jsonl')
            self.assertFalse((work / 'history-link').resolve().is_relative_to(work))

    def test_credentials_and_session_environment_not_inherited(self):
        with patch.dict('os.environ', {'OPENAI_API_KEY': 'private', 'CODEX_AUTH_JSON': 'private', 'GITHUB_TOKEN': 'private'}):
            env = f.environment(Path('/home/agent/disposable'))
        self.assertFalse({'OPENAI_API_KEY', 'CODEX_AUTH_JSON', 'GITHUB_TOKEN'} & set(env))
        self.assertEqual(env['CODEX_HOME'], '/home/agent/disposable/.codex')

    def test_native_command_has_only_selected_profile_and_fixed_cwd(self):
        for profile, selected in f.PROFILES.items():
            argv = f.command(Path('/native/codex'), profile, Path('/tmp/fixture.py'), Path('/home/agent/.codex'), Path('/workspace/case'), 'session_unlink')
            self.assertEqual(argv[:7], ['/native/codex', 'sandbox', '--permission-profile', selected, '-C', '/workspace/case', '--'])
            self.assertNotIn('exec', argv)
            self.assertNotIn('resume', argv)


def packet():
    conditions = []
    for profile in f.PROFILES:
        conditions.append({'profile': profile, 'outer_settings': {'same': True},
                           'assessment': {'controls_complete': True, 'findings': [
                               {'operation': op, 'finding': 'mutation_observed' if profile == 'full_access' else 'permission_denial_observed'}
                               for op in f.OPERATIONS]}})
    return {'conditions': conditions, 'errors': [], 'cleanup_errors': [],
            'containers_removed': True, 'source_and_prior_unchanged': True}


class CollectionTests(unittest.TestCase):
    def test_matched_boundary_controls_enable_only_next_pilot(self):
        assessment = r.assess(packet())
        self.assertTrue(assessment['ready_for_native_functionality_pilot'])
        self.assertFalse(assessment['native_live_writer_tested'])
        self.assertFalse(assessment['model_coding_or_resume_tested'])

    def test_unequal_outer_environment_blocks_comparison(self):
        data = packet(); data['conditions'][1]['outer_settings']['same'] = False
        self.assertFalse(r.assess(data)['collection_complete'])

    def test_control_denials_cannot_support_candidate(self):
        data = packet(); data['conditions'][0]['assessment']['findings'][0]['finding'] = 'permission_denial_observed'
        self.assertFalse(r.assess(data)['ready_for_native_functionality_pilot'])

    def test_protected_mutation_is_retained_as_candidate_failure(self):
        data = packet(); data['conditions'][1]['assessment']['findings'][0]['finding'] = 'mutation_observed'
        result = r.assess(data)
        self.assertTrue(result['collection_complete'])
        self.assertFalse(result['workspace_boundary_controls_passed'])

    def test_cleanup_source_and_controller_errors_block_ready(self):
        for key, value in (('errors', ['failure']), ('cleanup_errors', ['failure']),
                           ('containers_removed', False), ('source_and_prior_unchanged', False)):
            with self.subTest(key=key):
                data = packet(); data[key] = value
                self.assertFalse(r.assess(data)['ready_for_native_functionality_pilot'])

    def test_incomplete_conditions_block_ready(self):
        data = packet(); data['conditions'].pop()
        self.assertFalse(r.assess(data)['collection_complete'])

    def test_empty_findings_cannot_vacuously_pass(self):
        data = packet(); data['conditions'][0]['assessment']['findings'] = []
        self.assertFalse(r.assess(data)['collection_complete'])

    def test_container_arguments_match_outer_policy_and_do_not_mount_host(self):
        normalized = []
        for profile in f.PROFILES:
            argv = r.create_args('container', 'owner', profile, b'print("fixture")')
            normalized.append(argv[:-1])
            for expected in ('--pull=never', '--network=none', '--read-only', '--user=1000:1000',
                             '--cap-drop=ALL', '--security-opt=no-new-privileges', '--security-opt=seccomp=unconfined'):
                self.assertIn(expected, argv)
            for forbidden in ('--privileged', '--mount', '--volume', '--pid=host'):
                self.assertNotIn(forbidden, argv)
        self.assertEqual(*normalized)

    def test_prior_evidence_hash_failure_rejects_before_reading_zip(self):
        with self.assertRaisesRegex(RuntimeError, 'original store inspection differs'):
            r.verify_prior(b'incorrect archive')

    def test_missing_or_fabricated_condition_cannot_complete(self):
        value = {'profile': 'workspace', 'binary_sha256': f.BINARY_SHA, 'uid': 1000, 'gid': 1000,
                 'credentials': credentials(), 'cases': []}
        self.assertFalse(r.assess_condition(value, 'workspace')['controls_complete'])


if __name__ == '__main__':
    unittest.main()
