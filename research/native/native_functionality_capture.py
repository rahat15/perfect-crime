"""Snapshot real native history stores and read isolated copies without credentials."""
import base64
from contextlib import closing
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import tempfile
import time

DATABASES = ('state_5.sqlite', 'thread_history_1.sqlite')
MAX_FILE = 16 * 1024 * 1024
MAX_TOTAL = 48 * 1024 * 1024


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def encoded(raw, info=None):
    result = {'sha256': sha(raw), 'bytes': len(raw), 'content_b64': base64.b64encode(raw).decode('ascii')}
    if info is not None:
        result.update(inode=info.st_ino, device=info.st_dev, uid=info.st_uid, gid=info.st_gid)
    return result


def snapshot_database(source, destination, session):
    """The source is a private copy of a quiescent main/WAL/SHM set, never the original."""
    with closing(sqlite3.connect(source)) as connection, closing(sqlite3.connect(destination)) as output:
        connection.execute('PRAGMA query_only=ON')
        connection.backup(output)
        output.commit()
        check = [row[0] for row in output.execute('PRAGMA quick_check')]
        require(check == ['ok'], 'Snapshot SQLite integrity check failed.')
        output.execute('PRAGMA query_only=ON')
        tables = [row[0] for row in output.execute(
            "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")]
        counts = {}
        for table in tables:
            quoted = '"' + table.replace('"', '""') + '"'
            columns = [row[1] for row in output.execute('PRAGMA table_info(' + quoted + ')')]
            row = {'total_rows': output.execute('SELECT count(*) FROM ' + quoted).fetchone()[0]}
            field = 'thread_id' if 'thread_id' in columns else 'id' if table == 'threads' and 'id' in columns else None
            if field:
                row['session_rows'] = output.execute('SELECT count(*) FROM ' + quoted +
                                                    ' WHERE "' + field + '"=?', (session,)).fetchone()[0]
            counts[table] = row
    return {'quick_check': check, 'tables': counts}


def run(session, read_regular, rpc_reads, binary, source_home=Path('/source/home'),
        home=Path('/home/agent'), workspace=Path('/workspace'), scratch=Path('/tmp')):
    require(re.fullmatch(r'[A-Za-z0-9-]{16,80}', session) is not None, 'Invalid session ID.')
    require(os.getuid() == 1000 and os.getgid() == 1000, 'Unprivileged capture account required.')
    native = source_home / '.codex'
    require(native.is_dir() and not native.is_symlink(), 'Original native store is missing.')
    destination = home / '.codex'
    destination.mkdir(parents=True, exist_ok=False)
    originals, snapshots, metadata, errors = {}, {}, {}, []
    started = time.monotonic_ns()
    traces = sorted(native.glob('sessions/**/*-' + session + '.jsonl'))
    require(1 <= len(traces) <= 4, 'Current-session rollout count is outside the protocol.')
    selected = traces[:]
    present_databases = []
    for name in DATABASES:
        path = native / name
        if path.exists() or path.is_symlink():
            present_databases.append(name)
            selected.extend(p for p in (path, native / (name + '-wal'), native / (name + '-shm'))
                            if p.exists() or p.is_symlink())
    for path in selected:
        raw, info = read_regular(path, MAX_FILE)
        name = path.relative_to(native).as_posix()
        originals[name] = encoded(raw, info)
    require(sum(v['bytes'] for v in originals.values()) <= MAX_TOTAL, 'Native capture exceeded its bound.')
    with tempfile.TemporaryDirectory(dir=scratch, prefix='history-copy-') as temporary:
        copied = Path(temporary)
        for name, item in originals.items():
            raw = base64.b64decode(item['content_b64'], validate=True)
            target = (destination if name.startswith('sessions/') else copied) / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(raw)
        for name in present_databases:
            try:
                metadata[name] = snapshot_database(copied / name, destination / name, session)
                snapshots[name] = encoded((destination / name).read_bytes())
            except (OSError, sqlite3.Error, RuntimeError) as exc:
                errors.append(name + ': ' + type(exc).__name__ + ': ' + str(exc))
    # No credentials or user configuration are copied. Only local read RPCs are permitted.
    reads = (rpc_reads(Path(binary), home, workspace) if not errors else
             {'requests': [], 'errors': ['Snapshot failed; API reads were not attempted.'],
              'forced_stop': False, 'process_exit_code': None})
    unchanged = True
    for path in selected:
        try:
            raw, info = read_regular(path, MAX_FILE)
            old = originals[path.relative_to(native).as_posix()]
            require(sha(raw) == old['sha256'] and info.st_ino == old['inode']
                    and info.st_dev == old['device'], 'Original native store changed during capture.')
        except (OSError, RuntimeError) as exc:
            unchanged = False
            errors.append(str(exc))
    if sorted(native.glob('sessions/**/*-' + session + '.jsonl')) != traces:
        unchanged = False
        errors.append('Current-session rollout membership changed during capture.')
    current = [name for name in DATABASES if (native / name).exists()]
    if current != present_databases:
        unchanged = False
        errors.append('Native database membership changed during capture.')
    return {'schema': 'native-functionality-stores-v1', 'session_id': session,
            'uid': os.getuid(), 'gid': os.getgid(), 'started_monotonic_ns': started,
            'finished_monotonic_ns': time.monotonic_ns(), 'original_files': originals,
            'database_snapshots': snapshots, 'database_metadata': metadata,
            'missing_databases': [name for name in DATABASES if name not in present_databases],
            'local_read_rpc': reads, 'original_files_unchanged': unchanged, 'capture_errors': errors,
            'credentials_copied': False, 'model_turns_submitted_by_reader': 0,
            'scope': 'Per-database SQLite backup snapshots from byte-verified, quiescent copies including WAL. '
                     'Native reads use disposable copies at the original absolute paths. '
                     'No atomic transaction across different databases or remote-store coverage is claimed.'}
