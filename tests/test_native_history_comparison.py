"""Exercise main collection scheduling, persistence, stops, and exports offline."""
import copy
import errno
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock
import zipfile

from research.native import run_native_history_comparison as runner


class ComparisonFilesystemTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.folder = self.root / 'batch'
        self.folder.mkdir()
        design = json.loads((runner.ROOT / 'research/native/history-challenge-plan.json').read_text())
        self.plan = {'schema': 'native-history-main-plan-v1', 'source_commit': 'synthetic-commit',
            'frozen_design': design, 'schedule': runner.pilot.adapter.schedule(design),
            'source_sha256': {}, 'prerequisite_sha256': {},
            'primary_endpoint': design['primary_endpoint'],
            'pilot_review_archive_sha256': runner.reviewed.ARCHIVE_SHA,
            'maximum_native_invocations': 60, 'maximum_upstream_requests': 360}
        runner.save_once(self.folder / 'plan.json', self.plan)
        self.started = []
        self.modify = lambda item, record: None

    def collect(self, destination, item, plan):
        self.started.append(item['attempt'])
        profile = item['condition']
        artifacts = destination / profile / 'artifacts' / ('case-' + str(item['attempt']))
        artifacts.mkdir(parents=True)
        (artifacts / 'raw.txt').write_text('synthetic raw record for ' + str(item['attempt']))
        record = {'condition': profile, 'session_id': 'new-session-' + str(item['attempt']),
            'run_folder': artifacts.relative_to(destination).as_posix(),
            'outer_environment': {'image': 'same', 'memory': 2},
            'collection_complete': True, 'isolation_verified': True, 'cleanup_verified': True,
            'integrity_errors': [], 'cleanup_errors': [],
            'privacy_finding': {'primary_confirmed_unlink': (True, False, None)[item['attempt'] % 3]},
            'resume': {'stream_verified_tool_free_recall': item['attempt'] % 2 == 0},
            'collection_policy': runner.pilot.adapter.collection_decision(
                completed=True, observed=True, cleanup=True, isolation=True, grading_items=['interpretation'])}
        self.modify(item, record)
        runner.save_once(destination / profile / 'diagnostics.json', record)
        return record

    def execute(self, stop_after=None, verify=lambda: None):
        with mock.patch('builtins.print'):
            return runner.continue_schedule(self.folder, self.plan, self.collect,
                lambda directory, record: {'synthetic_secondary': True}, verify, stop_after)

    def destinations(self, suffix='review'):
        return [self.root / name / (suffix + '.zip') for name in ('project', 'downloads', 'backups')]

    def test_twenty_attempts_have_real_immutable_checkpoints(self):
        summary = self.execute()
        self.assertTrue(summary['collection_complete'])
        self.assertEqual(self.started, list(range(1, 21)))
        self.assertEqual(len(list((self.folder / 'checkpoints').glob('after-*.json'))), 20)
        self.assertFalse((self.folder / 'summary.json').exists())
        for value in summary['conditions'].values():
            self.assertEqual(value['started'], 10)
        self.assertEqual(len(runner.load_attempts(self.folder, self.plan)), 20)

    def test_counterbalanced_schedule_matches_frozen_design(self):
        pairs = [self.plan['schedule'][i:i+2] for i in range(0, 20, 2)]
        for i, pair in enumerate(pairs, 1):
            self.assertEqual([v['condition'] for v in pair],
                ['full_access', 'workspace'] if i % 2 else ['workspace', 'full_access'])

    def test_between_attempt_resume_never_repeats_finished_attempts(self):
        first = self.execute(stop_after=3)
        self.assertFalse(first['collection_complete'])
        before = runner.file_manifest(self.folder / 'attempt-01')
        self.assertTrue(self.execute()['collection_complete'])
        self.assertEqual(self.started, list(range(1, 21)))
        self.assertEqual(runner.file_manifest(self.folder / 'attempt-01'), before)

    def test_repeating_finished_schedule_does_not_collect(self):
        self.execute()
        self.assertTrue(self.execute()['collection_complete'])
        self.assertEqual(len(self.started), 20)

    def test_ambiguous_grading_is_queued_without_stopping(self):
        self.modify = lambda item, record: record['privacy_finding'].update(primary_confirmed_unlink=None)
        self.assertTrue(self.execute()['collection_complete'])
        self.assertTrue(all(v['record']['collection_policy']['peer_policy_decision']['queue_for_review']
            for v in runner.load_attempts(self.folder, self.plan)))

    def test_known_resume_failure_is_not_replaced(self):
        def change(item, record):
            record['resume'] = {'stream_verified_tool_free_recall': False, 'process_exit_code': 1,
                'completion_measurement': {'classification': 'recorded_history_related_failure', 'may_continue': True}}
        self.modify = change
        self.assertTrue(self.execute()['collection_complete'])
        self.assertEqual(self.started, list(range(1, 21)))

    def test_integrity_failure_pauses_before_next_attempt(self):
        def change(item, record):
            if item['attempt'] == 3:
                record['collection_policy'] = runner.pilot.adapter.collection_decision(
                    completed=True, observed=False, cleanup=True, isolation=True)
        self.modify = change
        summary = self.execute()
        self.assertEqual(self.started, [1, 2, 3])
        self.assertEqual(summary['paused_attempts'], [3])
        with self.assertRaises(RuntimeError):
            self.execute()
        self.assertEqual(self.started, [1, 2, 3])

    def test_partial_attempt_is_retained_and_not_restarted(self):
        self.execute(stop_after=1)
        original = self.collect
        def interrupt(destination, item, plan):
            original(destination, item, plan)
            raise KeyboardInterrupt()
        with mock.patch.object(self, 'collect', side_effect=interrupt), self.assertRaises(KeyboardInterrupt):
            self.execute()
        self.assertTrue((self.folder / 'attempt-02/start.json').is_file())
        self.assertFalse((self.folder / 'attempt-02/complete.json').exists())
        with self.assertRaises(RuntimeError):
            self.execute()
        self.assertEqual(self.started, [1, 2])

    def test_changed_raw_evidence_blocks_resume(self):
        self.execute(stop_after=1)
        next((self.folder / 'attempt-01').rglob('raw.txt')).write_text('changed')
        with self.assertRaises(RuntimeError):
            self.execute()
        self.assertEqual(self.started, [1])

    def test_duplicate_session_pauses(self):
        self.modify = lambda item, record: record.update(session_id='same-session')
        summary = self.execute()
        self.assertEqual(summary['paused_attempts'], [2])
        self.assertEqual(self.started, [1, 2])

    def test_different_outer_environment_pauses(self):
        def change(item, record):
            record['outer_environment']['memory'] = item['attempt']
        self.modify = change
        self.assertEqual(self.execute()['paused_attempts'], [2])

    def test_source_change_after_attempt_is_recorded_and_pauses(self):
        count = 0
        def verify():
            nonlocal count
            count += 1
            if count == 2:
                raise RuntimeError('changed source')
        summary = self.execute(verify=verify)
        self.assertEqual(summary['paused_attempts'], [1])
        self.assertTrue((self.folder / 'attempt-01/complete.json').is_file())

    def test_source_change_before_attempt_starts_nothing(self):
        def fail():
            raise RuntimeError('changed source')
        with self.assertRaises(RuntimeError):
            self.execute(verify=fail)
        self.assertEqual(self.started, [])

    def test_secondary_integrity_failure_pauses(self):
        with mock.patch('builtins.print'):
            summary = runner.continue_schedule(self.folder, self.plan, self.collect,
                mock.Mock(side_effect=RuntimeError('capture hash mismatch')), lambda: None)
        self.assertEqual(summary['paused_attempts'], [1])

    def test_twenty_attempt_export_preserves_all_raw_files_and_repeats(self):
        self.execute()
        destinations = self.destinations()
        first = runner.export_archive(self.folder, self.plan, destinations)
        second = runner.export_archive(self.folder, self.plan, destinations)
        self.assertEqual(first, second)
        self.assertTrue(first['summary']['collection_complete'])
        self.assertEqual(len({p.read_bytes() for p in destinations}), 1)
        with zipfile.ZipFile(destinations[0]) as archive:
            names = archive.namelist()
            self.assertEqual(len([n for n in names if n.endswith('/raw.txt')]), 20)
            for path in self.folder.rglob('raw.txt'):
                self.assertEqual(archive.read(path.relative_to(self.folder).as_posix()), path.read_bytes())

    def test_partial_and_final_exports_are_separate(self):
        self.execute(stop_after=2)
        partial = self.destinations('partial')
        runner.export_archive(self.folder, self.plan, partial)
        old = partial[0].read_bytes()
        self.execute()
        runner.export_archive(self.folder, self.plan, self.destinations('final'))
        self.assertEqual(partial[0].read_bytes(), old)

    def test_export_never_collects_or_calls_docker(self):
        self.execute(stop_after=1)
        with (mock.patch.object(runner, 'collect_live', side_effect=AssertionError('No collection')),
              mock.patch.object(runner.pilot.cli, 'docker', side_effect=AssertionError('No Docker'))):
            runner.export_archive(self.folder, self.plan, self.destinations())

    def test_export_withheld_before_writes_if_secret_is_present(self):
        self.execute(stop_after=1)
        with self.assertRaises(RuntimeError):
            runner.export_archive(self.folder, self.plan, self.destinations(), [b'synthetic raw record'])
        self.assertTrue(all(not p.exists() for p in self.destinations()))

    def test_different_existing_export_is_not_overwritten(self):
        self.execute(stop_after=1)
        paths = self.destinations()
        paths[2].parent.mkdir(); paths[2].write_bytes(b'existing unrelated data')
        with self.assertRaises(RuntimeError):
            runner.export_archive(self.folder, self.plan, paths)
        self.assertEqual(paths[2].read_bytes(), b'existing unrelated data')
        self.assertFalse(paths[0].exists())

    def test_export_fallback_for_mount_without_hardlinks(self):
        self.execute(stop_after=1)
        with mock.patch.object(runner.os, 'link', side_effect=OSError(errno.EOPNOTSUPP, 'not supported')):
            runner.export_archive(self.folder, self.plan, self.destinations())
        self.assertEqual(len({p.read_bytes() for p in self.destinations()}), 1)

    def test_incomplete_attempt_can_be_exported_for_diagnosis(self):
        item = self.plan['schedule'][0]
        runner.save_once(self.folder / 'attempt-01/start.json', {'schedule_entry': item,
            'source_commit': self.plan['source_commit'], 'plan_sha256': runner.sha((self.folder / 'plan.json').read_bytes())})
        exported = runner.export_archive(self.folder, self.plan, self.destinations())
        self.assertEqual(exported['summary']['paused_attempts'], [1])

    def test_same_checkpoint_is_idempotent_but_changed_one_is_refused(self):
        path = self.root / 'immutable.json'
        runner.save_once(path, {'a': 1}); runner.save_once(path, {'a': 1})
        with self.assertRaises(RuntimeError):
            runner.save_once(path, {'a': 2})
        self.assertEqual(runner.read(path), {'a': 1})

    def test_extra_schedule_position_is_rejected(self):
        plan = copy.deepcopy(self.plan)
        plan['schedule'].append(dict(plan['schedule'][-1], attempt=21))
        with self.assertRaises(RuntimeError):
            runner.validate_plan(plan)

    def test_exclusive_batch_lock_prevents_concurrent_command(self):
        with runner.batch_lock(self.root):
            with self.assertRaises(RuntimeError):
                with runner.batch_lock(self.root):
                    pass

    def test_frozen_source_mismatch_is_rejected(self):
        self.plan['source_sha256'] = {'code.py': runner.sha(b'original')}
        with mock.patch.object(runner, 'current_source', return_value=('synthetic-commit', {'code.py': b'changed'})):
            with self.assertRaises(RuntimeError):
                runner.verify_frozen(self.folder, self.plan)

    def test_saved_source_mismatch_is_rejected(self):
        self.plan['source_sha256'] = {'code.py': runner.sha(b'original')}
        (self.folder / 'source').mkdir(); (self.folder / 'source/code.py').write_bytes(b'changed')
        with mock.patch.object(runner, 'current_source', return_value=('synthetic-commit', {'code.py': b'original'})):
            with self.assertRaises(RuntimeError):
                runner.verify_frozen(self.folder, self.plan)


class CollectorMetadataAdapterTests(unittest.TestCase):
    def test_only_main_metadata_changes_and_class_is_restored(self):
        saved = []
        class Fake:
            def __init__(self):
                self.metadata = {'scenario_type': 'native_history_challenge_pilot',
                    'stages': [{'native_argv': ['codex', 'exec'], 'prompt': 'unchanged'}]}
            def save(self):
                saved.append(copy.deepcopy(self.metadata))
        item = {'attempt': 1, 'pair': 1, 'condition': 'full_access', 'condition_attempt': 1}
        def collect(*args):
            runner.pilot.HistoryExperiment().save()
            return {'retained': True}
        with (mock.patch.object(runner.pilot, 'HistoryExperiment', Fake),
              mock.patch.object(runner.pilot, 'collect_condition', side_effect=collect)):
            result = runner.collect_live(Path('/unused'), item, {'source_commit': 'c', 'frozen_design': {}})
            self.assertIs(runner.pilot.HistoryExperiment, Fake)
        self.assertEqual(result, {'retained': True})
        self.assertEqual(saved[0]['scenario_type'], 'native_history_challenge_main')
        self.assertEqual(saved[0]['stages'], [{'native_argv': ['codex', 'exec'], 'prompt': 'unchanged'}])

    def test_class_is_restored_after_collector_error(self):
        before = runner.pilot.HistoryExperiment
        with mock.patch.object(runner.pilot, 'collect_condition', side_effect=RuntimeError('test')):
            with self.assertRaises(RuntimeError):
                runner.collect_live(Path('/unused'), {'condition': 'workspace'}, {'source_commit': 'c', 'frozen_design': {}})
        self.assertIs(runner.pilot.HistoryExperiment, before)


if __name__ == '__main__':
    unittest.main()
