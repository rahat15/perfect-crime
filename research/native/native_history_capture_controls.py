"""Offline missing, unreadable and damaged-store controls for the challenge collector."""
import json
import os
from pathlib import Path
import shutil
import sqlite3
import tempfile

SESSION = '12345678-1234-5678-9012-123456789abc'
TRACE = 'sessions/2026/11/18/rollout-control-' + SESSION + '.jsonl'
CASES = ('intact', 'trace_missing', 'database_missing', 'native_home_missing',
         'corrupt_database', 'empty_database', 'unreadable_database', 'unreadable_sessions',
         'trace_symlink', 'sessions_symlink', 'reader_io_failure')


def seed(home):
    native = home / '.codex'
    path = native / TRACE
    path.parent.mkdir(parents=True)
    path.write_text(json.dumps({'type': 'session_meta', 'payload': {'id': SESSION}}) + '\n')
    (native / 'auth.json').write_text('CREDENTIAL-CONTROL-NEVER-CAPTURE')
    for name in ('state_5.sqlite', 'thread_history_1.sqlite'):
        with sqlite3.connect(native / name) as db:
            db.execute('CREATE TABLE threads (id TEXT PRIMARY KEY, value TEXT)')
            db.execute('INSERT INTO threads VALUES (?,?)', (SESSION, 'offline-control'))
    return native


def run(capture, read_regular, snapshot_database):
    if os.getuid() != 1000 or os.getgid() != 1000:
        raise RuntimeError('Controls require UID/GID 1000.')
    results = []
    for case in CASES:
        with tempfile.TemporaryDirectory(prefix='native-history-control-') as temporary:
            root = Path(temporary)
            source = root / 'source'
            native = seed(source)
            workspace = root / 'workspace'
            workspace.mkdir()
            reader = read_regular
            if case == 'trace_missing':
                (native / TRACE).unlink()
            elif case == 'database_missing':
                (native / 'thread_history_1.sqlite').unlink()
            elif case == 'native_home_missing':
                shutil.rmtree(native)
            elif case == 'corrupt_database':
                (native / 'thread_history_1.sqlite').write_bytes(b'not a sqlite database')
            elif case == 'empty_database':
                (native / 'thread_history_1.sqlite').write_bytes(b'')
            elif case == 'unreadable_database':
                (native / 'thread_history_1.sqlite').chmod(0)
            elif case == 'unreadable_sessions':
                (native / 'sessions').chmod(0)
            elif case == 'trace_symlink':
                (native / TRACE).unlink()
                (native / TRACE).symlink_to(native / 'auth.json')
            elif case == 'sessions_symlink':
                (native / 'sessions').rename(source / 'moved-sessions')
                (native / 'sessions').symlink_to(source / 'moved-sessions', target_is_directory=True)
            elif case == 'reader_io_failure':
                def reader(path, limit):
                    if Path(path).name == 'thread_history_1.sqlite':
                        raise OSError(5, 'Injected read I/O failure')
                    return read_regular(path, limit)
            try:
                value = capture(SESSION, reader, snapshot_database, source_home=source,
                    home=root / 'reader', workspace=workspace, scratch=root, expected_paths=[TRACE])
                states = {name: row['state'] for name, row in value['path_observations'].items()}
                db = value['database_findings']['thread_history_1.sqlite']['state']
                inventory = value['trace_inventory']
                expected = {
                    'intact': states[TRACE] == 'readable' and db == 'readable',
                    'trace_missing': states[TRACE] == 'missing' and inventory is not None and inventory['paths'] == [],
                    'database_missing': db == 'missing' and states[TRACE] == 'readable',
                    'native_home_missing': value['scan']['root']['state'] == 'missing' and inventory is not None and inventory['paths'] == [],
                    'corrupt_database': db == 'invalid_database',
                    'empty_database': db == 'empty_file',
                    'unreadable_database': db == 'unreadable',
                    'unreadable_sessions': states[TRACE] == 'unreadable' and inventory is None,
                    'trace_symlink': states[TRACE] == 'unsafe_path' and inventory is not None and len(inventory['paths']) == 1,
                    'sessions_symlink': states[TRACE] == 'unsafe_path' and inventory is None,
                    'reader_io_failure': db == 'capture_error' and bool(value['capture_errors']),
                }[case]
                expected_errors = bool(value['capture_errors']) == (case == 'reader_io_failure')
                secret_not_captured = ('auth.json' not in value['original_files']
                    and all(item['sha256'] != __import__('hashlib').sha256(b'CREDENTIAL-CONTROL-NEVER-CAPTURE').hexdigest()
                            for item in value['original_files'].values()))
                passed = expected and expected_errors and secret_not_captured and value['original_files_unchanged']
                results.append({'case': case, 'passed': bool(passed), 'capture': value})
            finally:
                if case == 'unreadable_sessions':
                    (native / 'sessions').chmod(0o700)
                if case == 'unreadable_database':
                    (native / 'thread_history_1.sqlite').chmod(0o600)
    return {'schema': 'native-history-capture-controls-v1', 'uid': os.getuid(), 'gid': os.getgid(),
            'cases': results, 'all_expected_observations': all(row['passed'] for row in results),
            'model_calls': 0, 'credentials_used': False,
            'scope': 'Synthetic store-state controls, not live agent challenges or a defense result.'}
