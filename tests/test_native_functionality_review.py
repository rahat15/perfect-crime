import copy
import hashlib
import io
import json
from pathlib import Path
import unittest
import zipfile

from research.native import review_functionality_comparison as reviewer
from research.native import run_native_functionality_comparison as pair


def archive(contents, manifest=None, extra=None):
    manifest = manifest if manifest is not None else {
        n: {'bytes': len(v), 'sha256': hashlib.sha256(v).hexdigest()} for n, v in contents.items()}
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, 'w') as z:
        for n, v in contents.items():
            z.writestr(n, v)
        z.writestr('review-manifest.json', json.dumps({'files': manifest}))
        if extra:
            z.writestr(*extra)
    return buffer.getvalue()


class ArchiveIntegrityTests(unittest.TestCase):
    def test_original_bytes_are_returned_unchanged(self):
        files = {'a.json': b'{"x": 1}\n', 'b.bin': b'\x00\xff\x01'}
        self.assertEqual(reviewer.archive_files(archive(files)), files)

    def test_changed_size_or_digest_is_rejected(self):
        for entry in ({'bytes': 2, 'sha256': hashlib.sha256(b'x').hexdigest()},
                      {'bytes': 1, 'sha256': '0' * 64}):
            with self.assertRaises(RuntimeError):
                reviewer.archive_files(archive({'file': b'x'}, {'file': entry}))

    def test_unlisted_member_and_path_traversal_are_rejected(self):
        with self.assertRaises(RuntimeError):
            reviewer.archive_files(archive({'file': b'x'}, extra=('extra', b'y')))
        with self.assertRaises(RuntimeError):
            reviewer.archive_files(archive({'../file': b'x'}))


class ContractTests(unittest.TestCase):
    def setUp(self):
        self.token = 'MEMORY-' + 'a' * 32
        self.session = '01234567-1234-1234-1234-0123456789ab'
        self.plan = {'coding_prompt_template': pair.task_prompt('MEMORY-<fresh-random-token>'),
                     'resume_prompt': pair.RESUME_PROMPT}
        args = pair.previous.experiment_args(Path('/unused'))
        self.run = {'status': 'finished', 'exit_code': 0, 'controller_intervened': False,
            'cleanup_errors': [], 'session_id': self.session, 'stages': [
                {'name': 'coding', 'prompt': pair.task_prompt(self.token),
                 'native_argv': pair.native_command(args, 'workspace')},
                {'name': 'resume', 'prompt': pair.RESUME_PROMPT,
                 'native_argv': pair.native_command(args, 'workspace', self.session)}]}

    def test_saved_contract_is_verified(self):
        self.assertEqual(reviewer.check_contract(self.run, 'workspace', self.plan), self.token)

    def test_wrong_profile_or_approval_override_is_rejected(self):
        with self.assertRaises(RuntimeError):
            reviewer.check_contract(self.run, 'full_access', self.plan)
        changed = copy.deepcopy(self.run)
        changed['stages'][0]['native_argv'].extend(['-c', 'approval_policy="on-request"'])
        with self.assertRaises(RuntimeError):
            reviewer.check_contract(changed, 'workspace', self.plan)

    def test_repeated_token_in_resume_is_rejected(self):
        self.run['stages'][1]['prompt'] += self.token
        with self.assertRaises(RuntimeError):
            reviewer.check_contract(self.run, 'workspace', self.plan)

    def test_incomplete_or_intervened_run_is_rejected(self):
        for key, value in [('status', 'failed'), ('exit_code', 1), ('controller_intervened', True),
                           ('cleanup_errors', ['remaining container'])]:
            changed = copy.deepcopy(self.run); changed[key] = value
            with self.assertRaises(RuntimeError):
                reviewer.check_contract(changed, 'workspace', self.plan)


class ChallengeDesignTests(unittest.TestCase):
    def setUp(self):
        self.plan = json.loads((reviewer.ROOT / reviewer.PLAN).read_text())

    def test_plan_is_design_only_and_counterbalanced(self):
        self.assertTrue(reviewer.validate_plan(self.plan))
        schedule = self.plan['main_schedule']
        self.assertEqual(sum(v['condition'] == 'full_access' for v in schedule), 10)
        self.assertEqual(sum(v['condition'] == 'workspace' for v in schedule), 10)

    def test_pilot_pooling_replacements_and_premature_readiness_are_rejected(self):
        for key, value in [('pilot_included_in_main', True), ('automatic_replacements', True),
                           ('launch_authorized_by_this_document', True), ('peer_integration_verified', True),
                           ('status', 'ready')]:
            changed = copy.deepcopy(self.plan); changed[key] = value
            with self.assertRaises(RuntimeError):
                reviewer.validate_plan(changed)

    def test_prompt_schedule_and_resource_drift_are_rejected(self):
        for key, value in [('financial_task', 'other'), ('privacy_prompt', 'other'),
                           ('main_schedule', list(reversed(self.plan['main_schedule']))),
                           ('upstream_request_limit_per_attempt', 999), ('requested_model', 'other'),
                           ('approval_policy', 'on-request'), ('stage_deadline_seconds', 0)]:
            changed = copy.deepcopy(self.plan); changed[key] = value
            with self.assertRaises(RuntimeError):
                reviewer.validate_plan(changed)


if __name__ == '__main__':
    unittest.main()
