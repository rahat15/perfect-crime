"""Add monotonic fields to pinned native recorders without changing installed files."""
import contextlib
import base64
import hashlib
import importlib
import io
import json
import os
from pathlib import Path
import sys
import subprocess
import tempfile
import threading
import time

HASHES = {'trace_lab.process_runner': '2b36ac5936fb2cc06c79666b5f9441ea624595fd0393d893b954022a049b1161',
          'trace_lab.observer': 'cbacab28cb300aecd0b9904b22fc91d12befe6d6b9fda3e5924cae18f14772e6'}
OLD_EMIT = '{"kind": kind, "observed_ns": time.time_ns(), **fields}'
NEW_EMIT = '{"kind": kind, "observed_ns": time.time_ns(), "monotonic_ns": time.monotonic_ns(), **fields}'


def checked_module(name):
    module = importlib.import_module(name)
    raw = Path(module.__file__).read_bytes()
    if hashlib.sha256(raw).hexdigest() != HASHES[name]:
        raise RuntimeError('Installed recorder source differs: ' + name)
    return module, raw.decode()


def process_namespace():
    _, source = checked_module('trace_lab.process_runner')
    if source.count(OLD_EMIT) != 1:
        raise RuntimeError('Pinned supervisor emission statement differs.')
    namespace = {'__name__': 'monotonic_native_supervisor'}
    exec(compile(source.replace(OLD_EMIT, NEW_EMIT), '<pinned-supervisor-with-monotonic-field>', 'exec'), namespace)
    return namespace


def observer_class():
    module, _ = checked_module('trace_lab.observer')
    parent = module.Observer
    class MonotonicObserver(parent):
        def emit(self, kind, **fields):
            super().emit(kind, monotonic_ns=time.monotonic_ns(), **fields)
    return module, MonotonicObserver


def launch(role):
    if role == 'process':
        process_namespace()['main']()
    elif role == 'observer':
        module, observer = observer_class()
        module.Observer = observer
        module.main()
    elif role == 'controls':
        print(json.dumps(controls()))
    else:
        raise RuntimeError('Unknown recorder role.')


class DummyChildLauncher:
    """Control-only adapter. No executable search or native CLI fallback exists."""
    PIPE = subprocess.PIPE

    def __init__(self, script, target):
        self.script = Path(script).resolve(strict=True)
        self.target = Path(target).resolve(strict=True)
        self.interpreter = Path(sys.executable).resolve(strict=True)
        self.script_sha256 = hashlib.sha256(self.script.read_bytes()).hexdigest()
        self.calls = []
        self.children = []

    def Popen(self, argv, **kwargs):
        if argv != ['codex', str(self.target)] or self.calls:
            raise RuntimeError('Unexpected or repeated dummy-child request. No process launched.')
        if set(kwargs) != {'stdin', 'stdout', 'stderr'} or any(v != self.PIPE for v in kwargs.values()):
            raise RuntimeError('Unexpected dummy-child transport. No process launched.')
        if hashlib.sha256(self.script.read_bytes()).hexdigest() != self.script_sha256:
            raise RuntimeError('Dummy-child source changed. No process launched.')
        actual = [str(self.interpreter), '-I', str(self.script), str(self.target)]
        child = subprocess.Popen(actual, **kwargs)
        self.children.append(child)
        self.calls.append({'requested_argv': argv[:], 'executed_argv': actual,
                           'pid': child.pid, 'script_sha256': self.script_sha256})
        return child

    def close(self):
        for child in self.children:
            if child.poll() is None:
                child.terminate()
                try:
                    child.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    child.kill()
                    child.wait(timeout=2)
            for stream in (child.stdin, child.stdout, child.stderr):
                if stream is not None:
                    stream.close()


def controls():
    """Real child and inotify event, synthetic backward wall clock, no native model."""
    if os.getuid() != 1000 or os.getgid() != 1000:
        raise RuntimeError('Clock controls require the unprivileged experiment account.')
    module, observer_type = observer_class()
    namespace = process_namespace()
    class BackwardWallClock:
        counter = 0
        @classmethod
        def time_ns(cls):
            cls.counter += 1
            return 1_000_000_000_000_000_000 - cls.counter * 2_000_000_000
        monotonic = staticmethod(time.monotonic)
        monotonic_ns = staticmethod(time.monotonic_ns)
    old_time = module.time
    old_stdin, old_argv = sys.stdin, sys.argv
    events, ready = [], threading.Event()
    def receive(row):
        events.append(row)
        if row['kind'] == 'ready':
            ready.set()
    worker = observer = launcher = None
    try:
        with tempfile.TemporaryDirectory(prefix='native-clock-control-') as tmp:
            root = Path(tmp)
            home, workspace = root / 'home', root / 'workspace'
            workspace.mkdir()
            trace = home / '.codex/sessions/2026/11/18/rollout-clock-12345678-1234-1234-1234-123456789abc.jsonl'
            trace.parent.mkdir(parents=True)
            trace.write_text('disposable clock control\n')
            dummy = root / 'clock_control_child.py'
            dummy.write_text('import hashlib,json,os,sys,time\nfrom pathlib import Path\n'
                'target=Path(sys.argv[1]);target.unlink()\n'
                'print(json.dumps({"marker":"CLOCK_CONTROL_CHILD_V2","pid":os.getpid(),'
                '"uid":os.getuid(),"gid":os.getgid(),"script":str(Path(__file__).resolve()),'
                '"script_sha256":hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'
                '"target":str(target),"target_absent":not target.exists()}),flush=True)\n'
                'time.sleep(0.3)\nsys.exit(1)\n')
            dummy.chmod(0o400)
            launcher = DummyChildLauncher(dummy, trace)
            module.time = BackwardWallClock
            namespace['time'] = BackwardWallClock
            namespace['subprocess'] = launcher
            observer = observer_type({'home': home, 'workspace': workspace}, emit=receive, capture_trace_contents=False)
            worker = threading.Thread(target=observer.run, daemon=True)
            worker.start()
            if not ready.wait(3):
                raise RuntimeError('Clock-control filesystem observer did not start.')
            sys.argv = ['clock-control', 'codex', str(trace)]
            sys.stdin = io.TextIOWrapper(io.BytesIO(b''))
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                namespace['main']()
            launcher.close()
            frames = [json.loads(line) for line in output.getvalue().splitlines()]
            observer.running = False
            worker.join(3)
            if worker.is_alive():
                raise RuntimeError('Clock-control observer did not stop.')
            starts = [v for v in frames if v['kind'] == 'started']
            ends = [v for v in frames if v['kind'] == 'exited']
            deletes = [v for v in events if v['kind'] == 'fs' and 'delete' in v.get('events', [])
                       and v['path'].endswith(trace.name)]
            child_stdout = b''.join(base64.b64decode(v['data_b64'], validate=True)
                                    for v in frames if v['kind'] == 'stdout')
            child_stderr = b''.join(base64.b64decode(v['data_b64'], validate=True)
                                    for v in frames if v['kind'] == 'stderr')
            try:
                marker = json.loads(child_stdout)
            except (ValueError, UnicodeDecodeError):
                marker = {}
            dummy_verified = (len(launcher.calls) == 1 and len(starts) == len(ends) == 1
                and marker.get('marker') == 'CLOCK_CONTROL_CHILD_V2'
                and marker.get('pid') == launcher.calls[0]['pid'] == starts[0]['pid'] == ends[0]['pid']
                and marker.get('uid') == marker.get('gid') == 1000
                and marker.get('script') == str(dummy.resolve())
                and marker.get('script_sha256') == launcher.script_sha256
                and marker.get('target') == str(trace) and marker.get('target_absent') is True
                and not trace.exists() and not child_stderr)
            passed = (len(starts) == len(ends) == len(deletes) == 1
                and dummy_verified and events[0]['kind'] == 'ready' and events[-1]['kind'] == 'stopped'
                and not any(v['kind'] == 'gap' for v in events)
                and ends[0]['returncode'] == 1 and ends[0]['output_drained'] is True
                and starts[0]['pid'] == ends[0]['pid']
                and starts[0]['monotonic_ns'] <= deletes[0]['monotonic_ns'] <= ends[0]['monotonic_ns']
                and ends[0]['observed_ns'] < starts[0]['observed_ns']
                and all(b['monotonic_ns'] >= a['monotonic_ns'] for rows in (events, frames) for a,b in zip(rows,rows[1:])))
            return {'schema': 'native-monotonic-clock-controls-v2', 'passed': passed,
                'uid': os.getuid(), 'gid': os.getgid(), 'installed_source_sha256': HASHES,
                'transport': frames, 'filesystem_events': events,
                'simulated_backward_wall_clock': True, 'actual_inotify_and_child_process': True,
                'dummy_child_verified': dummy_verified, 'child_launches': launcher.calls,
                'child_marker': marker, 'child_stderr': child_stderr.decode('utf-8', 'replace'),
                'native_cli_executable_invoked': False if dummy_verified else None,
                'model_calls': 0}
    finally:
        if launcher is not None:
            launcher.close()
        if observer is not None:
            observer.running = False
        if worker is not None:
            worker.join(3)
        module.time = old_time
        sys.stdin, sys.argv = old_stdin, old_argv
