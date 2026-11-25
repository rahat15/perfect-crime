"""Local backup/export checks using synthetic files, without Docker or network."""
from contextlib import redirect_stdout
import hashlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import zipfile

from research.native import save_checkpoint as checkpoint


class NativeCheckpointTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        base = Path(self.temporary.name)
        self.root, self.backups, self.downloads = base / 'repo', base / 'backups', base / 'downloads'
        self.downloads.mkdir()
        for name, content in {
            'research/tools/pause_checkpoint.py': b'original checkpoint source',
            'research/manifests/initial-replication.json': b'{}',
            'research/native/fixture.py': b'synthetic source',
            'runs/native/observer-calibration-01/diagnostics.json': b'{"control":"synthetic"}',
            'runs/native/setup/observer-calibration-01.log': b'synthetic console log',
        }.items():
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(content)
        for name in checkpoint.NATIVE_TESTS:
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(b'synthetic test')
        self.export = self.downloads / 'observer-review.zip'

    def save(self):
        with patch.object(checkpoint, 'ROOT', self.root), \
             patch.object(checkpoint, 'validate_repository'), \
             patch.object(checkpoint.sys, 'argv', ['save_checkpoint.py', '--label', 'synthetic',
                          '--backup-dir', str(self.backups), '--export', str(self.export)]), \
             patch.object(checkpoint.subprocess, 'check_output', return_value='synthetic\n'), \
             redirect_stdout(io.StringIO()):
            checkpoint.main()

    def test_verified_export_has_identical_local_and_backup_copies(self):
        self.save()
        data = self.export.read_bytes()
        self.assertEqual((self.backups / self.export.name).read_bytes(), data)
        self.assertEqual((self.root / 'runs/native/exports' / self.export.name).read_bytes(), data)
        self.assertEqual(len(list(self.backups.glob('native-synthetic-*.tar.gz'))), 1)
        with zipfile.ZipFile(self.export) as package:
            manifest = json.loads(package.read('review-manifest.json'))
            self.assertIn('runs/native/observer-calibration-01/diagnostics.json', manifest['files'])
            self.assertIn('runs/native/setup/observer-calibration-01.log', manifest['files'])
            for name, record in manifest['files'].items():
                self.assertEqual(hashlib.sha256(package.read(name)).hexdigest(), record['sha256'])

    def test_different_download_is_preserved(self):
        self.export.write_bytes(b'earlier result')
        with self.assertRaisesRegex(RuntimeError, 'different review ZIP'):
            self.save()
        self.assertEqual(self.export.read_bytes(), b'earlier result')

    def test_source_symlink_is_rejected(self):
        path = self.root / 'tests/test_native_checkpoint.py'
        path.unlink()
        path.symlink_to(self.root / 'research/native/fixture.py')
        with self.assertRaisesRegex(RuntimeError, 'symbolic link'):
            self.save()


if __name__ == '__main__':
    unittest.main()
