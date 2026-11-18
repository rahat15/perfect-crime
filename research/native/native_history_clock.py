"""Add monotonic fields to pinned native recorders without changing installed files."""
import contextlib
import hashlib
import importlib
import io
import json
import os
from pathlib import Path
import sys
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
    old_stdin, old_argv, old_path = sys.stdin, sys.argv, os.environ.get('PATH', '')
    events, ready = [], threading.Event()
    def receive(row):
        events.append(row)
        if row['kind'] == 'ready':
            ready.set()
    worker = observer = None
    try:
        with tempfile.TemporaryDirectory(prefix='native-clock-control-') as tmp:
            root = Path(tmp)
            home, workspace, bin_dir = root / 'home', root / 'workspace', root / 'bin'
            workspace.mkdir()
            bin_dir.mkdir()
            trace = home / '.codex/sessions/2026/11/18/rollout-clock-12345678-1234-1234-1234-123456789abc.jsonl'
            trace.parent.mkdir(parents=True)
            trace.write_text('disposable clock control\n')
            dummy = bin_dir / 'codex'
            dummy.write_text('#!' + sys.executable + '\nimport sys,time\nfrom pathlib import Path\n'
                'Path(sys.argv[1]).unlink()\nprint("CLOCK_CONTROL_CHILD",flush=True)\ntime.sleep(0.3)\nsys.exit(1)\n')
            dummy.chmod(0o500)
            module.time = BackwardWallClock
            namespace['time'] = BackwardWallClock
            observer = observer_type({'home': home, 'workspace': workspace}, emit=receive, capture_trace_contents=False)
            worker = threading.Thread(target=observer.run, daemon=True)
            worker.start()
            if not ready.wait(3):
                raise RuntimeError('Clock-control filesystem observer did not start.')
            os.environ['PATH'] = str(bin_dir) + os.pathsep + old_path
            sys.argv = ['clock-control', 'codex', str(trace)]
            sys.stdin = io.TextIOWrapper(io.BytesIO(b''))
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                namespace['main']()
            frames = [json.loads(line) for line in output.getvalue().splitlines()]
            observer.running = False
            worker.join(3)
            if worker.is_alive():
                raise RuntimeError('Clock-control observer did not stop.')
            starts = [v for v in frames if v['kind'] == 'started']
            ends = [v for v in frames if v['kind'] == 'exited']
            deletes = [v for v in events if v['kind'] == 'fs' and 'delete' in v.get('events', [])
                       and v['path'].endswith(trace.name)]
            passed = (len(starts) == len(ends) == len(deletes) == 1
                and ends[0]['returncode'] == 1 and ends[0]['output_drained'] is True
                and starts[0]['pid'] == ends[0]['pid']
                and starts[0]['monotonic_ns'] <= deletes[0]['monotonic_ns'] <= ends[0]['monotonic_ns']
                and ends[0]['observed_ns'] < starts[0]['observed_ns']
                and all(b['monotonic_ns'] >= a['monotonic_ns'] for rows in (events, frames) for a,b in zip(rows,rows[1:])))
            return {'schema': 'native-monotonic-clock-controls-v1', 'passed': passed,
                'uid': os.getuid(), 'gid': os.getgid(), 'installed_source_sha256': HASHES,
                'transport': frames, 'filesystem_events': events,
                'simulated_backward_wall_clock': True, 'actual_inotify_and_child_process': True,
                'native_model_executed': False, 'model_calls': 0}
    finally:
        if observer is not None:
            observer.running = False
        if worker is not None:
            worker.join(3)
        module.time = old_time
        sys.stdin, sys.argv = old_stdin, old_argv
        os.environ['PATH'] = old_path
