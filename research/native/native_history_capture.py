"""Bounded, read-only history capture that distinguishes missing and damaged stores."""
import base64
import errno
import hashlib
import os
from pathlib import Path
import re
import sqlite3
import stat
import tempfile
import time

DATABASES = ('state_5.sqlite', 'thread_history_1.sqlite')
MAX_FILE = 16 * 1024 * 1024
MAX_TOTAL = 48 * 1024 * 1024
MAX_ENTRIES = 512


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def error_state(exc):
    if isinstance(exc, FileNotFoundError):
        return 'missing'
    if isinstance(exc, PermissionError):
        return 'unreadable'
    if isinstance(exc, OSError) and exc.errno in {errno.ELOOP, errno.ENOTDIR}:
        return 'unsafe_path'
    return 'capture_error'


def metadata(info):
    return {'inode': info.st_ino, 'device': info.st_dev, 'uid': info.st_uid, 'gid': info.st_gid,
            'mode': stat.S_IMODE(info.st_mode), 'bytes': info.st_size, 'mtime_ns': info.st_mtime_ns}


def encoded(raw):
    return {'sha256': sha(raw), 'bytes': len(raw), 'content_b64': base64.b64encode(raw).decode('ascii')}


def directory_state(path):
    """Open each directory component without following links, including ancestors."""
    descriptor = None
    try:
        descriptor = os.open(path.anchor, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        for component in path.parts[1:]:
            child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        with os.scandir(descriptor) as entries:
            list(entries)
        return {'state': 'directory', **metadata(os.fstat(descriptor))}
    except OSError as exc:
        return {'state': error_state(exc), 'errno': exc.errno}
    finally:
        if descriptor is not None:
            os.close(descriptor)


def discover(native, session):
    root = directory_state(native)
    result = {'root': root, 'entries': [], 'session_paths': [], 'scan_findings': []}
    if root['state'] != 'directory':
        result['inventory_complete'] = root['state'] == 'missing'
        return result
    pending = [native]
    while pending:
        folder = pending.pop()
        try:
            with os.scandir(folder) as scan:
                entries = sorted(scan, key=lambda item: item.name)
            for entry in entries:
                path = Path(entry.path)
                name = path.relative_to(native).as_posix()
                if name == 'auth.json':
                    continue  # Do not collect credential contents or hashes.
                info = entry.stat(follow_symlinks=False)
                kind = ('directory' if stat.S_ISDIR(info.st_mode) else
                        'file' if stat.S_ISREG(info.st_mode) else
                        'symlink' if stat.S_ISLNK(info.st_mode) else 'special')
                result['entries'].append({'path': name, 'kind': kind, **metadata(info)})
                require(len(result['entries']) <= MAX_ENTRIES, 'Native inventory exceeds entry limit.')
                if kind == 'directory':
                    pending.append(path)
                elif name.startswith('sessions/') and entry.name.endswith('-' + session + '.jsonl'):
                    result['session_paths'].append(name)
                elif kind == 'symlink' and (name == 'sessions' or name.startswith('sessions/')):
                    result['scan_findings'].append({'path': name, 'state': 'unsafe_path', 'errno': None})
        except OSError as exc:
            result['scan_findings'].append({'path': folder.relative_to(native).as_posix(),
                'state': error_state(exc), 'errno': exc.errno})
    result['entries'].sort(key=lambda row: row['path'])
    result['session_paths'].sort()
    require(len(result['session_paths']) <= 4, 'Too many current-session paths.')
    result['inventory_complete'] = not result['scan_findings']
    return result


def observe_file(path, read_regular):
    try:
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode):
            return {'state': 'unsafe_path', **metadata(info)}, None
        if info.st_size > MAX_FILE:
            return {'state': 'capture_error', 'reason': 'File exceeds capture limit', **metadata(info)}, None
        raw, info = read_regular(path, MAX_FILE)
        return {'state': 'readable', **metadata(info), 'sha256': sha(raw), 'bytes': len(raw)}, raw
    except (OSError, RuntimeError) as exc:
        return {'state': error_state(exc), 'errno': getattr(exc, 'errno', None),
                'error_type': type(exc).__name__}, None


def capture(session, read_regular, snapshot_database, rpc_reads=None, binary=None, *,
            source_home=Path('/source/home'), home=Path('/home/agent'), workspace=Path('/workspace'),
            scratch=Path('/tmp'), expected_paths=()):
    require(re.fullmatch(r'[A-Za-z0-9-]{16,80}', session) is not None, 'Invalid session identifier.')
    require(os.getuid() == os.getgid() == 1000, 'Unprivileged capture account required.')
    require(source_home.is_absolute() and home.is_absolute() and source_home != home,
            'Original and disposable homes must be distinct absolute paths.')
    native = source_home / '.codex'
    started_ns, started_monotonic_ns = time.time_ns(), time.monotonic_ns()
    scan = discover(native, session)
    selected = set(scan['session_paths'])
    for name in expected_paths:
        p = Path(name)
        require(not p.is_absolute() and '..' not in p.parts and name.startswith('sessions/')
                and p.name.endswith('-' + session + '.jsonl'), 'Unexpected prior session path.')
        selected.add(name)
    selected.update(name + suffix for name in DATABASES for suffix in ('', '-wal', '-shm'))
    originals, observations, errors = {}, {}, []
    for name in sorted(selected):
        record, raw = observe_file(native / name, read_regular)
        observations[name] = record
        if raw is not None:
            originals[name] = encoded(raw)
        if record['state'] == 'capture_error':
            errors.append({'path': name, **record})
    require(sum(row['bytes'] for row in originals.values()) <= MAX_TOTAL, 'Capture total exceeds bound.')
    errors.extend(row for row in scan['scan_findings'] if row['state'] == 'capture_error')
    if scan['root']['state'] == 'capture_error':
        errors.append(scan['root'])
    snapshots, databases = {}, {}
    destination = home / '.codex'
    require(not destination.exists() and not destination.is_symlink(), 'Disposable native home already exists.')
    destination.mkdir(parents=True)
    with tempfile.TemporaryDirectory(dir=scratch, prefix='history-source-copy-') as temporary:
        copied = Path(temporary)
        for name, item in originals.items():
            target = (destination if name.startswith('sessions/') else copied) / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(base64.b64decode(item['content_b64'], validate=True))
        for name in DATABASES:
            main = observations[name]
            if main['state'] != 'readable':
                databases[name] = {'state': main['state']}
                continue
            sidecars = [observations[name + suffix] for suffix in ('-wal', '-shm')]
            if any(row['state'] not in {'readable', 'missing'} for row in sidecars):
                databases[name] = {'state': 'unreadable_or_unsafe_sidecar'}
                continue
            if main['bytes'] == 0:
                databases[name] = {'state': 'empty_file'}
                continue
            try:
                details = snapshot_database(copied / name, destination / name, session)
                databases[name] = {'state': 'readable', 'metadata': details}
                snapshots[name] = encoded((destination / name).read_bytes())
            except (sqlite3.DatabaseError, RuntimeError) as exc:
                invalid = (isinstance(exc, RuntimeError) and str(exc) == 'Snapshot SQLite integrity check failed.')
                invalid = invalid or getattr(exc, 'sqlite_errorcode', None) in {sqlite3.SQLITE_CORRUPT, sqlite3.SQLITE_NOTADB}
                databases[name] = {'state': 'invalid_database', 'error_type': type(exc).__name__,
                                   'reason': str(exc)}
                if not invalid:
                    databases[name]['state'] = 'sqlite_read_error'
                    errors.append({'path': name, 'operation': 'snapshot', 'reason': str(exc)})
            except OSError as exc:
                databases[name] = {'state': 'capture_error', 'errno': exc.errno}
                errors.append({'path': name, 'operation': 'snapshot', 'errno': exc.errno})
    copied_states = {row['state'] for row in databases.values()}
    can_read = (scan['inventory_complete'] and not errors
        and copied_states.issubset({'readable', 'missing'})
        and any(row['state'] == 'readable' for row in observations.values())
        and all(observations[name]['state'] == 'readable' for name in scan['session_paths']))
    if rpc_reads is not None and can_read:
        reads = rpc_reads(Path(binary), home, workspace)
    else:
        reads = {'requests': [], 'errors': [], 'forced_stop': False, 'process_exit_code': None,
                 'not_attempted': True, 'reason': 'No reader supplied or original stores cannot be copied faithfully.'}
    # Include status and identity changes as well as bytes; inaccessible never means absent.
    after_scan = discover(native, session)
    unchanged = scan == after_scan
    for name, before in observations.items():
        after, _ = observe_file(native / name, read_regular)
        if after != before:
            unchanged = False
    if not unchanged:
        errors.append({'operation': 'source_verification', 'reason': 'Original store changed during capture.'})
    inventory = {'kind': 'trace_inventory', 'observed_ns': time.time_ns(),
        'paths': ['.codex/' + name for name in scan['session_paths']]}
    if not scan['inventory_complete']:
        inventory = None
    return {'schema': 'native-history-challenge-capture-v1', 'session_id': session,
        'uid': os.getuid(), 'gid': os.getgid(), 'started_ns': started_ns,
        'finished_ns': time.time_ns(), 'started_monotonic_ns': started_monotonic_ns,
        'finished_monotonic_ns': time.monotonic_ns(), 'scan': scan, 'path_observations': observations,
        'original_files': originals, 'database_snapshots': snapshots, 'database_findings': databases,
        'local_read_rpc': reads, 'trace_inventory': inventory, 'original_files_unchanged': unchanged,
        'capture_errors': errors, 'credentials_copied': False, 'model_turns_submitted_by_reader': 0,
        'scope': 'Captured original file states and bytes; SQLite and API reads use disposable copies. '
                 'A missing, inaccessible, empty or invalid store is kept distinct. No forensic erasure claim.'}
