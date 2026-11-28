import contextlib
import copy
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from research.native import native_history_clock as clock
from research.native import run_native_history_pilot as runner


class DummyLauncherTests(unittest.TestCase):
    def setUp(self):
        self.temp = TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.target = self.root / 'disposable.jsonl'
        self.target.write_text('disposable\n')
        self.script = self.root / 'child.py'
        self.script.write_text('import sys\nfrom pathlib import Path\n'
            'Path(sys.argv[1]).unlink()\nprint("DUMMY_CONFIRMED",flush=True)\nsys.exit(1)\n')
        self.script.chmod(0o400)
        self.launcher = clock.DummyChildLauncher(self.script, self.target)
        self.addCleanup(self.launcher.close)
        self.kwargs = dict(stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    def test_nonexecutable_script_runs_through_absolute_interpreter(self):
        child = self.launcher.Popen(['codex', str(self.target)], **self.kwargs)
        stdout, stderr = child.communicate(b'', timeout=5)
        self.assertEqual(child.returncode, 1)
        self.assertEqual(stdout, b'DUMMY_CONFIRMED\n')
        self.assertEqual(stderr, b'')
        self.assertFalse(self.target.exists())
        self.assertEqual(self.script.stat().st_mode & 0o111, 0)
        self.assertEqual(self.launcher.calls[0]['executed_argv'],
            [str(Path(sys.executable).resolve()), '-I', str(self.script), str(self.target)])

    def test_poisoned_path_cannot_select_another_codex(self):
        trap = self.root / 'codex'
        marker = self.root / 'WRONG_EXECUTABLE'
        trap.write_text('#!' + sys.executable + '\nfrom pathlib import Path\nPath(' + repr(str(marker)) + ').touch()\n')
        trap.chmod(0o500)
        with patch.dict(os.environ, {'PATH': str(self.root)}):
            child = self.launcher.Popen(['codex', str(self.target)], **self.kwargs)
            stdout, stderr = child.communicate(b'', timeout=5)
        self.assertEqual(stdout, b'DUMMY_CONFIRMED\n')
        self.assertFalse(marker.exists())
        self.assertEqual(child.returncode, 1)

    def test_unexpected_command_cannot_launch(self):
        with patch.object(clock.subprocess, 'Popen') as popen:
            with self.assertRaises(RuntimeError):
                self.launcher.Popen(['codex', 'login'], **self.kwargs)
            popen.assert_not_called()

    def test_second_child_is_rejected(self):
        child = self.launcher.Popen(['codex', str(self.target)], **self.kwargs)
        child.communicate(b'', timeout=5)
        with patch.object(clock.subprocess, 'Popen') as popen:
            with self.assertRaises(RuntimeError):
                self.launcher.Popen(['codex', str(self.target)], **self.kwargs)
            popen.assert_not_called()

    def test_changed_script_cannot_launch(self):
        self.script.chmod(0o600)
        self.script.write_text('print("changed")\n')
        with patch.object(clock.subprocess, 'Popen') as popen:
            with self.assertRaises(RuntimeError):
                self.launcher.Popen(['codex', str(self.target)], **self.kwargs)
            popen.assert_not_called()

    def test_executable_or_environment_override_is_rejected(self):
        for extra in ({'executable': '/usr/bin/codex'}, {'env': {'PATH': '/usr/bin'}}):
            with self.subTest(extra=extra), patch.object(clock.subprocess, 'Popen') as popen:
                with self.assertRaises(RuntimeError):
                    self.launcher.Popen(['codex', str(self.target)], **self.kwargs, **extra)
                popen.assert_not_called()

    def test_pinned_supervisor_uses_control_adapter_and_preserves_frames(self):
        namespace = clock.process_namespace()
        namespace['subprocess'] = self.launcher
        namespace['sys'] = SimpleNamespace(argv=['control', 'codex', str(self.target)],
            stdin=SimpleNamespace(buffer=io.BytesIO(b'')))
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            namespace['main']()
        frames = [json.loads(v) for v in output.getvalue().splitlines()]
        self.assertEqual(frames[0]['kind'], 'started')
        self.assertEqual(frames[-1]['kind'], 'exited')
        self.assertEqual(frames[-1]['returncode'], 1)
        self.assertEqual(frames[0]['pid'], frames[-1]['pid'])
        self.assertTrue(frames[-1]['output_drained'])
        self.assertTrue(all(isinstance(v.get('monotonic_ns'), int) for v in frames))
        # A new production namespace still invokes the original subprocess module.
        self.assertIs(clock.process_namespace()['subprocess'], subprocess)


class ClockGateTests(unittest.TestCase):
    def value(self):
        return {'schema': 'native-history-clock-checkpoint-v2', 'source_commit': 'committed',
            'passed': True, 'cleanup_verified': True, 'errors': [],
            'clock_source_sha256': runner.sha(b'current-clock'), 'previous_control_unchanged': True,
            'previous_control': {'raw_sha256': 'retained'},
            'observations': {'dummy_child_verified': True, 'native_cli_executable_invoked': False}}

    def gate(self, value):
        with patch.object(runner.integration.startup, 'safe_read', return_value=json.dumps(value).encode()), \
             patch.object(runner, 'previous_clock_failure', return_value={'raw_sha256': 'retained'}):
            return runner.verified_clock_controls('committed', {'research/native/native_history_clock.py': b'current-clock'})

    def test_verified_dummy_is_required_before_live_calls(self):
        self.assertEqual(self.gate(self.value())['passed'], True)
        for change in ('old_schema', 'unverified_dummy', 'native_cli', 'changed_source', 'changed_prior'):
            value = self.value()
            if change == 'old_schema': value['schema'] = 'native-history-clock-checkpoint-v1'
            if change == 'unverified_dummy': value['observations']['dummy_child_verified'] = False
            if change == 'native_cli': value['observations']['native_cli_executable_invoked'] = True
            if change == 'changed_source': value['source_commit'] = 'different'
            if change == 'changed_prior': value['previous_control'] = {'raw_sha256': 'different'}
            with self.subTest(change=change), self.assertRaises(RuntimeError):
                self.gate(value)

    def test_original_failed_record_is_checked_without_rewriting(self):
        value = {'source_commit': 'original', 'passed': False, 'cleanup_verified': True}
        raw = (json.dumps(value, indent=2)+'\n').encode()
        expected = runner.sha(json.dumps(value,sort_keys=True,separators=(',',':')).encode())
        with patch.object(runner.integration.startup, 'safe_read', return_value=raw), \
             patch.object(runner, 'FAILED_CLOCK_CANONICAL_SHA', expected):
            result = runner.previous_clock_failure()
            self.assertEqual(result['raw_sha256'], hashlib.sha256(raw).hexdigest())
            self.assertFalse(result['original_passed'])
        with patch.object(runner.integration.startup, 'safe_read', return_value=raw):
            with self.assertRaises(RuntimeError):
                runner.previous_clock_failure()


if __name__ == '__main__':
    unittest.main()
