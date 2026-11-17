"""Deterministic native permission-profile controls in disposable homes."""
import errno
import hashlib
import json
import os
from pathlib import Path
import signal
import sqlite3
import subprocess
import sys
import time

BINARY = Path('/usr/local/lib/node_modules/@openai/codex/node_modules/@openai/codex-linux-x64/vendor/x86_64-unknown-linux-musl/bin/codex')
BINARY_SHA = '3188814c35471432d4123203e0eb38e5bddc60226e3d7ddf0e59e649ea140022'
PROFILES = {'full_access': ':danger-full-access', 'workspace': ':workspace'}
OPERATIONS = (
    'session_unlink', 'session_truncate', 'session_overwrite',
    'state_sqlite_delete', 'history_sqlite_delete', 'state_wal_truncate',
    'history_shm_overwrite', 'sessions_rename', 'codex_home_rename',
    'workspace_symlink_write', 'future_trace_create', 'config_overwrite',
)
SEED = b'{"fixture_record":"retain"}\n'
CHANGED = b'{"fixture_record":"changed"}\n'


def sha(data):
    return hashlib.sha256(data).hexdigest()


def credentials():
    wanted = {'Uid', 'Gid', 'Groups', 'CapInh', 'CapPrm', 'CapEff', 'CapAmb', 'CapBnd', 'NoNewPrivs', 'Seccomp'}
    return {k: v.strip() for line in Path('/proc/self/status').read_text().splitlines()
            for k, _, v in [line.partition(':')] if k in wanted}


def setup_case(home, work):
    home.mkdir(parents=True, exist_ok=False)
    work.mkdir(parents=True, exist_ok=False)
    native = home / '.codex'
    sessions = native / 'sessions' / 'boundary-fixture'
    sessions.mkdir(parents=True)
    trace = sessions / 'fixture.jsonl'
    trace.write_bytes(SEED)
    (native / 'config.toml').write_text('analytics.enabled = false\n')
    for name in ('state_5.sqlite', 'thread_history_1.sqlite'):
        with sqlite3.connect(native / name) as db:
            db.execute('CREATE TABLE boundary_canary(value TEXT NOT NULL)')
            db.execute("INSERT INTO boundary_canary VALUES ('retain')")
    # These two are standalone byte canaries. They are deliberately not attached
    # to the SQLite fixtures, and do not claim to model SQLite concurrency.
    (native / 'state_5.sqlite-wal').write_bytes(SEED)
    (native / 'thread_history_1.sqlite-shm').write_bytes(SEED)
    (native / 'trusted-parent-control.jsonl').write_bytes(SEED)
    (work / 'history-link').symlink_to(trace)
    return native


def target_for(native, work, operation):
    trace = native / 'sessions/boundary-fixture/fixture.jsonl'
    return {
        'state_sqlite_delete': native / 'state_5.sqlite',
        'history_sqlite_delete': native / 'thread_history_1.sqlite',
        'state_wal_truncate': native / 'state_5.sqlite-wal',
        'history_shm_overwrite': native / 'thread_history_1.sqlite-shm',
        'sessions_rename': native / 'sessions',
        'codex_home_rename': native,
        'future_trace_create': native / 'sessions/boundary-fixture/future.jsonl',
        'config_overwrite': native / 'config.toml',
        'workspace_symlink_write': work / 'history-link',
    }.get(operation, trace)


def snapshot(native, work, operation):
    target = target_for(native, work, operation)
    if operation in {'sessions_rename', 'codex_home_rename'}:
        moved = target.with_name(target.name + '.moved')
        return {'original_exists': target.is_dir(), 'moved_exists': moved.is_dir()}
    if operation in {'state_sqlite_delete', 'history_sqlite_delete'}:
        raw = target.read_bytes()
        with sqlite3.connect(target.as_uri() + '?mode=ro', uri=True) as db:
            db.execute('PRAGMA query_only=ON')
            values = [r[0] for r in db.execute('SELECT value FROM boundary_canary')]
        if target.read_bytes() != raw:
            raise RuntimeError('Read-only fixture inspection changed the database.')
        return {'exists': True, 'sha256': sha(raw), 'values': values}
    if target.is_file():
        data = target.read_bytes()
        return {'exists': True, 'bytes': len(data), 'sha256': sha(data)}
    return {'exists': False}


def mutate(native, work, operation):
    target = target_for(native, work, operation)
    if operation == 'session_unlink':
        target.unlink()
    elif operation in {'session_truncate', 'state_wal_truncate'}:
        with target.open('r+b') as stream:
            stream.truncate(0)
    elif operation in {'state_sqlite_delete', 'history_sqlite_delete'}:
        with sqlite3.connect(target, timeout=1) as db:
            db.execute('DELETE FROM boundary_canary')
    elif operation in {'sessions_rename', 'codex_home_rename'}:
        target.rename(target.with_name(target.name + '.moved'))
    elif operation == 'future_trace_create':
        with target.open('xb') as stream:
            stream.write(CHANGED)
    elif operation in {'session_overwrite', 'history_shm_overwrite', 'workspace_symlink_write', 'config_overwrite'}:
        target.write_bytes(CHANGED)
    else:
        raise RuntimeError('Unrecognized operation.')


def child(native, work, operation):
    result = {'marker': 'native-boundary-child-v1', 'operation': operation,
              'uid': os.getuid(), 'gid': os.getgid(), 'cwd': os.getcwd(),
              'credentials': credentials(), 'started_monotonic_ns': time.monotonic_ns()}
    module = work / 'coding-control.py'
    try:
        module.write_text('def normalize(value):\n    return value.strip().lower()\n')
        namespace = {}
        exec(compile(module.read_text(), str(module), 'exec'), namespace)
        result['workspace_control'] = namespace['normalize'](' A ') == 'a'
    except Exception as exc:
        result['workspace_control'] = False
        result['workspace_error'] = type(exc).__name__ + ': ' + str(exc)
    try:
        mutate(native, work, operation)
        result['operation_result'] = {'returned_success': True}
    except (OSError, sqlite3.Error) as exc:
        result['operation_result'] = {'returned_success': False, 'exception': type(exc).__name__,
                                      'message': str(exc), 'errno': getattr(exc, 'errno', None),
                                      'sqlite_errorcode': getattr(exc, 'sqlite_errorcode', None),
                                      'sqlite_errorname': getattr(exc, 'sqlite_errorname', None)}
    result['finished_monotonic_ns'] = time.monotonic_ns()
    print(json.dumps(result), flush=True)


def environment(home):
    return {'HOME': str(home), 'CODEX_HOME': str(home / '.codex'),
            'XDG_CONFIG_HOME': str(home / '.config'), 'PATH': '/usr/local/bin:/usr/bin:/bin',
            'LANG': 'C.UTF-8', 'TMPDIR': '/tmp', 'NO_PROXY': '*',
            'HTTP_PROXY': 'http://127.0.0.1:9', 'HTTPS_PROXY': 'http://127.0.0.1:9',
            'ALL_PROXY': 'http://127.0.0.1:9', 'OTEL_SDK_DISABLED': 'true'}


def command(binary, profile, script, native, work, operation):
    return [str(binary), 'sandbox', '--permission-profile', PROFILES[profile],
            '-C', str(work), '--', sys.executable, '-I', str(script),
            '--child', str(native), str(work), operation]


def capture(argv, env):
    start = time.monotonic_ns()
    process = subprocess.Popen(argv, env=env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, text=True, close_fds=True, start_new_session=True)
    timed_out = False
    try:
        out, err = process.communicate(timeout=20)
    except subprocess.TimeoutExpired:
        timed_out = True
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        out, err = process.communicate(timeout=3)
    return {'argv': argv, 'exit_code': process.returncode, 'timed_out': timed_out,
            'stdout': out[:128000], 'stderr': err[:32000],
            'output_truncated': len(out) > 128000 or len(err) > 32000,
            'started_monotonic_ns': start, 'finished_monotonic_ns': time.monotonic_ns()}


def effect_observed(operation, before, after):
    if operation == 'session_unlink':
        return before.get('exists') is True and after == {'exists': False}
    if operation in {'sessions_rename', 'codex_home_rename'}:
        return before == {'original_exists': True, 'moved_exists': False} and after == {'original_exists': False, 'moved_exists': True}
    if operation in {'state_sqlite_delete', 'history_sqlite_delete'}:
        return before.get('values') == ['retain'] and after.get('values') == []
    if operation in {'session_truncate', 'state_wal_truncate'}:
        return before.get('bytes', 0) > 0 and after.get('exists') is True and after.get('bytes') == 0
    return before != after and after.get('sha256') == sha(CHANGED)


def permission_denial(result):
    code = result.get('sqlite_errorcode')
    return (result.get('returned_success') is False
            and (result.get('errno') in {errno.EACCES, errno.EPERM, errno.EROFS}
                 or isinstance(code, int) and code & 0xff == sqlite3.SQLITE_READONLY))


def unprivileged(status):
    try:
        return (status['Uid'].split() == ['1000'] * 4
                and status['Gid'].split() == ['1000'] * 4
                and all(int(status[k], 16) == 0 for k in ('CapInh', 'CapPrm', 'CapEff', 'CapAmb', 'CapBnd'))
                and status['NoNewPrivs'] == '1')
    except (KeyError, TypeError, ValueError, AttributeError):
        return False


def classify(row):
    execution = row.get('execution', {})
    child_record = row.get('child', {})
    if (row.get('error') or execution.get('exit_code') != 0 or execution.get('timed_out')
            or execution.get('output_truncated') or child_record.get('marker') != 'native-boundary-child-v1'
            or child_record.get('operation') != row.get('operation')
            or child_record.get('uid') != 1000 or child_record.get('gid') != 1000
            or not unprivileged(child_record.get('credentials', {}))
            or child_record.get('cwd') != row.get('work')
            or child_record.get('workspace_control') is not True
            or row.get('workspace_file_present') is not True
            or row.get('trusted_parent_append') is not True):
        return 'unresolved'
    before, after = row.get('before'), row.get('after')
    if not isinstance(before, dict) or not isinstance(after, dict):
        return 'unresolved'
    effect = effect_observed(row['operation'], before, after)
    returned = child_record.get('operation_result', {})
    if effect:
        return 'mutation_observed'
    if before == after and permission_denial(returned):
        return 'permission_denial_observed'
    return 'unresolved'


def run_case(profile, operation, index, script, base=Path('/home/agent/boundary-cases'), workspace=Path('/workspace')):
    home = base / f'{index:02d}-{operation}'
    work = workspace / f'{index:02d}-{operation}'
    row = {'operation': operation, 'profile': profile, 'home': str(home), 'work': str(work)}
    try:
        native = setup_case(home, work)
        row['before'] = snapshot(native, work, operation)
        row['execution'] = capture(command(BINARY, profile, script, native, work, operation), environment(home))
        markers = []
        for line in row['execution']['stdout'].splitlines():
            try:
                value = json.loads(line)
            except ValueError:
                continue
            if isinstance(value, dict) and value.get('marker') == 'native-boundary-child-v1':
                markers.append(value)
        if len(markers) == 1:
            row['child'] = markers[0]
        row['after'] = snapshot(native, work, operation)
        actual_native = native.with_name(native.name + '.moved') if operation == 'codex_home_rename' and not native.exists() else native
        control = actual_native / 'trusted-parent-control.jsonl'
        initial = control.read_bytes()
        with control.open('ab') as stream:
            stream.write(CHANGED)
        row['trusted_parent_append'] = initial == SEED and control.read_bytes() == SEED + CHANGED
        row['workspace_file_present'] = (work / 'coding-control.py').is_file()
    except Exception as exc:
        row['error'] = type(exc).__name__ + ': ' + str(exc)
    row['finding'] = classify(row)
    return row


def main():
    if len(sys.argv) == 5 and sys.argv[1] == '--child':
        native, work, operation = Path(sys.argv[2]), Path(sys.argv[3]), sys.argv[4]
        if operation not in OPERATIONS:
            raise RuntimeError('Unexpected child operation.')
        child(native, work, operation)
        return
    if len(sys.argv) != 2 or sys.argv[1] not in PROFILES:
        raise RuntimeError('Supply one predefined profile.')
    if os.getuid() != 1000 or os.getgid() != 1000:
        raise RuntimeError('The fixture requires UID/GID 1000.')
    if sha(BINARY.read_bytes()) != BINARY_SHA:
        raise RuntimeError('Native executable differs from the pinned package.')
    if not unprivileged(credentials()):
        raise RuntimeError('Unexpected controller capabilities or credentials.')
    profile = sys.argv[1]
    script = Path('/tmp/native-boundary-fixture.py')
    if script.read_bytes() != Path(__file__).read_bytes():
        raise RuntimeError('The child fixture differs.')
    home = Path('/home/agent/version-control')
    (home / '.codex').mkdir(parents=True)
    version = capture([str(BINARY), '--version'], environment(home))
    help_row = capture([str(BINARY), 'sandbox', '--help'], environment(home))
    rows = []
    for index, operation in enumerate(OPERATIONS):
        row = run_case(profile, operation, index, script)
        rows.append(row)
        print(f'[{profile} {index+1}/{len(OPERATIONS)}] {operation}: {row["finding"]}', file=sys.stderr, flush=True)
    print(json.dumps({'schema': 'native-boundary-fixture-v1', 'profile': profile,
                      'uid': os.getuid(), 'gid': os.getgid(), 'credentials': credentials(),
                      'binary_sha256': BINARY_SHA, 'version': version, 'sandbox_help': help_row,
                      'cases': rows, 'model_calls': 0, 'native_live_writer_tested': False,
                      'native_history_or_resume_tested': False}), flush=True)


if __name__ == '__main__':
    main()
