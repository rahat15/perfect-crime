"""Integrity and skipped-coverage checks for the published review support."""
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import zipfile

from research.tools import verify_review_support as review


class ReviewSupportTests(unittest.TestCase):
    def test_real_archives_and_frozen_source_match(self):
        result = review.verify()
        self.assertEqual(result['original_stream_files_anchored'], 12)
        self.assertEqual(result['docker_executed_cells'], 439)

    def test_modified_archive_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / 'changed.zip'
            path.write_bytes(b'changed')
            with self.assertRaisesRegex(ValueError, 'Archive bytes differ'):
                review.archive_files(path, review.DOCKER_ARCHIVE_SHA)

    def test_archive_traversal_is_rejected_without_extraction(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / 'fixture.zip'
            with zipfile.ZipFile(path, 'w') as target:
                target.writestr('../outside', b'content')
            with self.assertRaisesRegex(ValueError, 'Unexpected archive path'):
                review.archive_files(path, review.digest(path.read_bytes()))
            self.assertFalse((Path(temp).parent / 'outside').exists())

    def test_missing_manifest_member_is_rejected(self):
        files = {'manifest.json': json.dumps({'files': {'missing': {'bytes': 1, 'sha256': 'x'}}}).encode()}
        with self.assertRaisesRegex(ValueError, 'Archive inventory differs'):
            review.verify_inventory(files, 'manifest.json')

    def test_skipped_fill_is_not_counted_as_executed(self):
        observations = {'rows': [{'verdict': 'permission_denial_observed'}],
                        'legit_controls': [{'outcome': 'passed'}], 'descriptor_controls': [],
                        'suppression_controls': [{'operation': 'fill_filesystem_then_recorder_append',
                                                  'verdict': 'not_run'}]}
        counts = review.coverage_counts(observations)
        self.assertEqual(counts['executed_cells'], 2)
        self.assertEqual(counts['not_run_cells'], 1)
        self.assertEqual(counts['disk_fill_cells_executed_in_docker'], 0)

    def test_summary_cannot_turn_skipped_cells_into_success(self):
        original = review.read
        def changed(path):
            value = original(path)
            if path.name == 'coverage-assessment.json':
                value['both_suppression_operations_resisted'] = 'passed'
            return value
        with patch.object(review, 'read', side_effect=changed):
            with self.assertRaisesRegex(ValueError, 'Skipped disk-fill'):
                review.verify()


if __name__ == '__main__':
    unittest.main()
