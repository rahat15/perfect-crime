"""Collection, retention and cleanup checks with a simulated Docker API."""
import copy
import hashlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch

from research.native import run_observer_calibration as runner
from tests.test_native_observer_calibration import controlled_evidence, credentials


class ObserverCollectionTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        for name in runner.SOURCES:
            destination = self.root / name
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes((runner.ROOT / name).read_bytes())
        preflight = self.root / 'runs/native/environment-inventory-01/environment.json'
        preflight.parent.mkdir(parents=True)
        preflight.write_bytes(b'synthetic inventory control')
        self.preflight_sha = hashlib.sha256(preflight.read_bytes()).hexdigest()
        self.fixture, self.events = controlled_evidence()
        self.containers = {}
        self.calls = []
        self.fail_fixture = False

    def command(self, argv, **kwargs):
        self.calls.append(argv)
        if argv[:3] == ['docker', 'image', 'inspect']:
            return json.dumps([{'Id': runner.IMAGE, 'Config': {}}])
        if argv[:2] == ['docker', 'create']:
            name = argv[argv.index('--name') + 1]
            label = argv[argv.index('--label') + 1].split('=', 1)[1]
            observer = '--user=0:0' in argv
            pid = next((x.partition('=')[2] for x in argv if x.startswith('--pid=')), '')
            self.containers[name] = {
                'Image': runner.IMAGE,
                'Config': {'User': '0:0' if observer else '1000:1000',
                           'Labels': {runner.LABEL: label}, 'Env': []},
                'HostConfig': {
                    'CapAdd': ['SYS_PTRACE', 'DAC_READ_SEARCH'] if observer else [],
                    'CapDrop': ['ALL'], 'NetworkMode': 'none', 'ReadonlyRootfs': True,
                    'Privileged': False, 'PidMode': pid, 'PidsLimit': 64,
                    'Memory': 512 * 1024 * 1024, 'NanoCpus': 1_000_000_000,
                    'Tmpfs': {} if observer else {'/tmp': '', '/home/agent': '', '/workspace': ''},
                    'SecurityOpt': ['no-new-privileges'] + (
                        ['seccomp=unconfined'] if '--security-opt=seccomp=unconfined' in argv else [])},
                'Mounts': [], 'State': {'ExitCode': 0, 'OOMKilled': False}}
            return name
        if argv[:2] == ['docker', 'inspect']:
            return json.dumps([self.containers[argv[-1]]])
        if argv[:2] in (['docker', 'start'], ['docker', 'stop']):
            return argv[-1]
        if argv[:2] == ['docker', 'exec']:
            if kwargs['input'] == (self.root / runner.FIXTURE).read_text():
                if self.fail_fixture:
                    raise RuntimeError('synthetic fixture execution failure')
                return json.dumps(self.fixture)
            return json.dumps({'environment_status': credentials(), 'probes': [
                {'name': 'version', 'exit_code': 0, 'stdout': 'codex-cli 0.154.0\n',
                 'child_started': False},
                {'name': 'plain_python', 'exit_code': 0, 'child_started': True},
                {'name': 'user_namespace', 'exit_code': 1, 'child_started': False},
                {'name': 'codex_sandbox', 'exit_code': 1, 'child_started': False}]})
        if argv[:2] == ['docker', 'rm']:
            self.containers.pop(argv[-1])
            return argv[-1]
        if argv[:2] == ['docker', 'ps']:
            self.assertIn('--filter', argv)
            self.assertTrue(argv[argv.index('--filter') + 1].startswith('label=' + runner.LABEL + '='))
            return '\n'.join(self.containers)
        self.fail('Unexpected Docker command: ' + str(argv))

    def popen(self, argv, **kwargs):
        self.assertEqual(argv[:4], ['docker', 'start', '--attach', '--interactive'])
        kwargs['stdout'].write(''.join(json.dumps(e) + '\n' for e in self.events))
        kwargs['stdout'].flush()
        class Attachment:
            stdin = io.StringIO()
            def poll(self): return None
            def wait(self, timeout): return 0
        return Attachment()

    def collect(self):
        with patch.object(runner, 'ROOT', self.root), \
             patch.object(runner, 'PREFLIGHT_SHA', self.preflight_sha), \
             patch.object(runner, 'committed_source', return_value='1' * 40), \
             patch.object(runner, 'command', side_effect=self.command), \
             patch.object(runner.subprocess, 'Popen', side_effect=self.popen), \
             redirect_stdout(io.StringIO()):
            return runner.run_collection()

    def test_nonzero_sandbox_results_are_retained_while_collection_finishes(self):
        packet = self.collect()
        self.assertTrue(packet['ready_for_native_observation'])
        self.assertEqual(len(packet['sandbox_conditions']), 2)
        self.assertEqual(packet['sandbox_conditions'][1]['probes'][-1]['exit_code'], 1)
        self.assertTrue(packet['cleanup_verified'])
        self.assertEqual(self.containers, {})
        self.assertIn('observer.jsonl', packet['artifacts_sha256'])
        for name, expected in packet['artifacts_sha256'].items():
            self.assertEqual(hashlib.sha256((self.root / runner.OUTPUT / name).read_bytes()).hexdigest(), expected)

    def test_grading_failure_keeps_both_independent_conditions(self):
        self.fixture['cases'][1]['contents_match_control'] = False
        packet = self.collect()
        self.assertTrue(packet['collection_complete'])
        self.assertFalse(packet['ready_for_native_observation'])
        self.assertEqual(len(packet['sandbox_conditions']), 2)
        self.assertTrue(packet['cleanup_verified'])

    def test_controller_failure_keeps_partial_evidence_and_cleans_own_containers(self):
        self.fail_fixture = True
        packet = self.collect()
        self.assertFalse(packet['collection_complete'])
        self.assertTrue(packet['errors'])
        self.assertTrue(packet['cleanup_verified'])
        self.assertEqual(self.containers, {})
        saved = json.loads((self.root / runner.OUTPUT / 'diagnostics.json').read_text())
        self.assertEqual(saved, packet)

    def test_second_call_reuses_verified_evidence_without_docker_calls(self):
        first = self.collect()
        count = len(self.calls)
        second = self.collect()
        self.assertEqual(first, second)
        self.assertEqual(len(self.calls), count)

    def test_changed_raw_artifact_is_not_silently_reexported(self):
        self.collect()
        path = self.root / runner.OUTPUT / 'observer.jsonl'
        path.write_text('changed evidence\n')
        with self.assertRaisesRegex(RuntimeError, 'artifact differs'):
            self.collect()
        self.assertEqual(path.read_text(), 'changed evidence\n')


if __name__ == '__main__':
    unittest.main()
