"""Compare two native permission profiles offline without modifying old evidence."""
import argparse
from datetime import datetime, timezone
import hashlib
import io
import json
from pathlib import Path
import subprocess
import sys
import time
import uuid
import zipfile

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from research.native import inspect_environment as environment
from research.native import native_boundary_fixture as fixture
from research.native import run_native_store_scope as previous

BASE = '97c6be81af3ee16c57cf38928760d9220120859e'
OUTPUT = Path('runs/native/native-boundary-01')
PRIOR_ARCHIVE = Path('runs/native/exports/native-store-scope-review.zip')
PRIOR_SHA = '5649442bfb5064097f5ba2f8f58fbb49597505a4451d57dd63a5e1bc226754be'
FILES = ('research/native/native_boundary_fixture.py', 'research/native/run_native_boundary.py',
         'research/native/native-boundary-protocol.md', 'research/analysis/native-store-scope-findings.md',
         'research/results/native-store-scope-01-reviewed-summary.json', 'tests/test_native_boundary.py')
LABEL = 'cse227.native.environment'


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def safe(path):
    return not any(p.is_symlink() for p in (path, *path.parents))


def git(*args):
    return subprocess.check_output(['git', *args], cwd=ROOT, text=True).strip()


def checked(argv, timeout=30):
    result = subprocess.run(argv, text=True, capture_output=True, timeout=timeout)
    require(result.returncode == 0, 'Command failed: ' + argv[0] + '\n' + result.stderr[-2500:])
    return result.stdout


def save(path, value):
    require(safe(path), 'A report path is a symbolic link.')
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('x', encoding='utf-8') as stream:
        json.dump(value, stream, indent=2)
        stream.write('\n')


def verify_prior(raw):
    require(sha(raw) == PRIOR_SHA, 'The original store inspection differs and was retained.')
    with zipfile.ZipFile(io.BytesIO(raw)) as package:
        names = package.namelist()
        require(len(names) == len(set(names)) and package.testzip() is None, 'Invalid original archive.')
        manifest = json.loads(package.read('review-manifest.json'))
        require(set(names) == set(manifest['files']) | {'review-manifest.json'}, 'Original archive membership differs.')
        for name, expected in manifest['files'].items():
            data = package.read(name)
            require(sha(data) == expected['sha256'] and len(data) == expected['bytes'], 'Original file hash differs: ' + name)
        packet = json.loads(package.read('diagnostics.json'))
        require(packet['source_commit'] == BASE and packet['inspection_complete'] is True
                and packet['container_removed'] is True and packet['original_evidence_and_source_unchanged'] is True
                and not packet['errors'] and not packet['cleanup_errors'], 'Previous checkpoint was incomplete.')
        require(previous.assess(packet['fixture']) == packet['assessment'] and packet['assessment']['complete'],
                'Recomputed original assessment differs.')
        environment.validate_container(json.loads(package.read('container-before.json')), packet['container_token'])
        for name, digest in packet['source_sha256'].items():
            require(safe(ROOT / name) and sha((ROOT / name).read_bytes()) == digest
                    and sha(package.read('source/' + name)) == digest, 'Original inspection source changed: ' + name)
    return {'archive_sha256': PRIOR_SHA, 'source_commit': BASE,
            'inspection_complete': True, 'native_defense_tested': False}


def prior_inputs():
    require(safe(ROOT / PRIOR_ARCHIVE), 'Prior archive path is a symbolic link.')
    return verify_prior((ROOT / PRIOR_ARCHIVE).read_bytes())


def source_snapshot():
    require(Path.cwd().resolve() == ROOT, 'Run from the project directory.')
    require(git('branch', '--show-current') == 'native-history-defense', 'Unexpected branch.')
    subprocess.run(['git', 'merge-base', '--is-ancestor', BASE, 'HEAD'], cwd=ROOT, check=True)
    require(not git('status', '--porcelain', '--untracked-files=no'), 'Tracked changes exist and were retained.')
    head = git('rev-parse', 'HEAD')
    names = git('ls-files', '-z').split('\0')
    selected = {n for n in names if n and (n.startswith('research/native/') or n.startswith('trace_lab/')
                or n.startswith('host_lab/') or n.startswith('tests/test_native_')
                or n in {'Dockerfile', 'pyproject.toml', *FILES})}
    require(set(FILES).issubset(selected), 'New boundary source must be committed first.')
    require(not git('ls-files', '--others', '--exclude-standard', '--', 'research/native', 'trace_lab', 'host_lab'),
            'Untracked experiment source exists and was retained.')
    source = {}
    for name in sorted(selected):
        path = ROOT / name
        require(safe(path) and path.is_file(), 'Missing or symbolic-link source: ' + name)
        data = path.read_bytes()
        require(data == subprocess.check_output(['git', 'show', head + ':' + name], cwd=ROOT),
                'Runtime source differs from the frozen commit: ' + name)
        source[name] = data
    return head, source


def create_args(name, token, profile, source):
    require(profile in fixture.PROFILES, 'Unknown permission profile.')
    args = environment.create_command(name, token)
    require(args[-2:] == ['-', '--inside'], 'Base container command changed.')
    args.insert(2, '--security-opt=seccomp=unconfined')
    bootstrap = ('import hashlib,json,os,sys; from pathlib import Path; '
                 'v=json.load(sys.stdin); s=v["source"].encode(); '
                 'assert set(v)=={"source"} and hashlib.sha256(s).hexdigest()=="' + sha(source) + '"; '
                 'p=Path("/tmp/native-boundary-fixture.py"); p.open("xb").write(s); p.chmod(0o500); '
                 'os.execv(sys.executable,[sys.executable,"-I",str(p),sys.argv[1]])')
    return args[:-2] + ['-c', bootstrap, profile]


def validate_container(info, token):
    environment.validate_container(info, token)
    host, config = info['HostConfig'], info['Config']
    options = {v.replace(':', '=', 1) for v in host.get('SecurityOpt', [])}
    require(options in ({'no-new-privileges', 'seccomp=unconfined'},
                        {'no-new-privileges=true', 'seccomp=unconfined'}), 'Unexpected security options.')
    require(not host.get('PidMode') and not host.get('IpcMode') == 'host'
            and not config.get('Volumes') and host.get('Memory') == 536870912
            and host.get('PidsLimit') == 64 and host.get('NanoCpus') == 1000000000,
            'Unexpected resource or namespace settings.')
    require(set(host.get('Tmpfs', {})) == {'/home/agent', '/workspace', '/tmp'}, 'Unexpected writable locations.')
    return {'image': info['Image'], 'user': config['User'], 'apparmor_profile': info.get('AppArmorProfile'),
            'network': host['NetworkMode'], 'readonly_root': host['ReadonlyRootfs'],
            'cap_drop': host['CapDrop'], 'security_options': sorted(options),
            'memory': host['Memory'], 'pids': host['PidsLimit'], 'cpus': host['NanoCpus'],
            'tmpfs': host['Tmpfs']}


def assess_condition(value, expected_profile):
    errors = []
    if value.get('profile') != expected_profile or value.get('binary_sha256') != fixture.BINARY_SHA:
        errors.append('Native binary or profile differs.')
    if value.get('uid') != 1000 or value.get('gid') != 1000 or not fixture.unprivileged(value.get('credentials', {})):
        errors.append('Controller credentials differ.')
    for key in ('version', 'sandbox_help'):
        row = value.get(key, {})
        if row.get('exit_code') != 0 or row.get('timed_out') or row.get('output_truncated'):
            errors.append(key + ': incomplete CLI control.')
    if value.get('version', {}).get('stdout', '').strip() != 'codex-cli 0.154.0':
        errors.append('Unexpected CLI version.')
    if '--permission-profile' not in value.get('sandbox_help', {}).get('stdout', ''):
        errors.append('Native help omitted permission-profile.')
    rows = value.get('cases', [])
    if [r.get('operation') for r in rows] != list(fixture.OPERATIONS):
        errors.append('Missing, duplicate, or reordered cases.')
    findings = []
    for row in rows:
        finding = fixture.classify(row)
        if finding != row.get('finding'):
            errors.append('Saved classification differs: ' + str(row.get('operation')))
        if row.get('profile') != expected_profile:
            errors.append('Case profile differs.')
        findings.append({'operation': row.get('operation'), 'finding': finding})
    return {'controls_complete': not errors and all(r['finding'] != 'unresolved' for r in findings),
            'errors': errors, 'findings': findings}


def assess(packet):
    rows = packet.get('conditions', [])
    control = next((r for r in rows if r.get('profile') == 'full_access'), {})
    protected = next((r for r in rows if r.get('profile') == 'workspace'), {})
    complete = (len(rows) == 2 and {r.get('profile') for r in rows} == set(fixture.PROFILES)
                and all(r.get('assessment', {}).get('controls_complete') for r in rows)
                and all([f.get('operation') for f in r.get('assessment', {}).get('findings', [])] == list(fixture.OPERATIONS) for r in rows)
                and control.get('outer_settings') == protected.get('outer_settings')
                and not packet.get('errors') and not packet.get('cleanup_errors')
                and packet.get('containers_removed') is True and packet.get('source_and_prior_unchanged') is True)
    positive = complete and all(r['finding'] == 'mutation_observed' for r in control['assessment']['findings'])
    boundary = positive and all(r['finding'] == 'permission_denial_observed' for r in protected['assessment']['findings'])
    return {'collection_complete': bool(complete), 'full_access_positive_controls_passed': bool(positive),
            'workspace_boundary_controls_passed': bool(boundary), 'ready_for_native_functionality_pilot': bool(boundary),
            'native_live_writer_tested': False, 'model_coding_or_resume_tested': False,
            'scope': 'Deterministic native sandbox CLI commands on disposable path and SQLite canaries. No native model turn.'}


def attach(name, folder, source):
    with (folder / 'container.stdout').open('xb') as out, (folder / 'container.stderr').open('xb') as err:
        process = subprocess.Popen(['docker', 'start', '--attach', '--interactive', name],
                                   stdin=subprocess.PIPE, stdout=out, stderr=err)
        try:
            process.stdin.write(json.dumps({'source': source.decode()}).encode())
            process.stdin.close()
            start = time.monotonic()
            next_notice = start + 30
            while process.poll() is None:
                if time.monotonic() - start > 300:
                    raise RuntimeError('Native boundary container exceeded its 300-second limit.')
                if time.monotonic() > next_notice:
                    print('Boundary controls still running:', round(time.monotonic() - start), 'seconds.', flush=True)
                    next_notice += 30
                if (folder / 'container.stdout').stat().st_size > 8 * 1024**2 or (folder / 'container.stderr').stat().st_size > 2 * 1024**2:
                    raise RuntimeError('Control output exceeded its limit.')
                time.sleep(0.2)
            return process.returncode
        finally:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)


def collect():
    commit, source = source_snapshot()
    prior = prior_inputs()
    out = ROOT / OUTPUT
    require(not out.exists(), 'An earlier boundary run exists and was retained. Do not rerun or replace it.')
    image = json.loads(checked(['docker', 'image', 'inspect', environment.IMAGE]))[0]
    require(image['Id'] == environment.IMAGE and image['Os'] == 'linux' and image['Architecture'] == 'amd64'
            and not image['Config'].get('Volumes'), 'Pinned image is unavailable or differs.')
    token = uuid.uuid4().hex
    packet = {'schema': 'native-boundary-v1', 'created_at': datetime.now(timezone.utc).isoformat(),
              'source_commit': commit, 'source_sha256': {n: sha(b) for n, b in source.items()},
              'prior_inspection': prior, 'image_id': environment.IMAGE, 'run_token': token,
              'conditions': [], 'errors': [], 'cleanup_errors': [], 'model_calls': 0,
              'credentials_mounted': False, 'host_folders_mounted': False, 'network': 'none'}
    save(out / 'started.json', packet)
    for n, b in source.items():
        p = out / 'source' / n
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(b)
    fixture_source = source['research/native/native_boundary_fixture.py']
    try:
        for profile in fixture.PROFILES:
            name = 'cse227-native-boundary-' + token[:12] + '-' + profile.replace('_', '-')
            folder = out / profile
            folder.mkdir()
            print('Starting offline native boundary condition:', profile, flush=True)
            checked(create_args(name, token, profile, fixture_source))
            before = json.loads(checked(['docker', 'inspect', name]))[0]
            settings = validate_container(before, token)
            save(folder / 'container-before.json', before)
            code = attach(name, folder, fixture_source)
            after = json.loads(checked(['docker', 'inspect', name]))[0]
            save(folder / 'container-after.json', after)
            require(code == 0 and after['State']['Status'] == 'exited' and after['State']['ExitCode'] == 0
                    and not after['State']['OOMKilled'], 'Native fixture did not finish normally. Partial evidence retained.')
            value = json.loads((folder / 'container.stdout').read_text())
            assessment = assess_condition(value, profile)
            packet['conditions'].append({'profile': profile, 'container': name, 'outer_settings': settings,
                                         'fixture': value, 'assessment': assessment, 'transport_exit_code': code})
            print('  Complete controls:', assessment['controls_complete'], flush=True)
            for row in assessment['findings']:
                print(' ', row['operation'] + ':', row['finding'], flush=True)
            checked(['docker', 'rm', '--volumes', name])
    except (Exception, KeyboardInterrupt) as exc:
        packet['errors'].append(type(exc).__name__ + ': ' + str(exc))
    finally:
        try:
            owned = checked(['docker', 'ps', '--all', '--quiet', '--filter', f'label={LABEL}={token}']).split()
            for identifier in owned:
                checked(['docker', 'rm', '--force', '--volumes', identifier])
            require(not checked(['docker', 'ps', '--all', '--quiet', '--filter', f'label={LABEL}={token}']).strip(),
                    'A boundary container remains.')
            packet['containers_removed'] = True
        except Exception as exc:
            packet['containers_removed'] = False
            packet['cleanup_errors'].append(str(exc))
        try:
            end_commit, end_source = source_snapshot()
            require(end_commit == commit and end_source == source and prior_inputs() == prior,
                    'Source or prior evidence changed during controls.')
            packet['source_and_prior_unchanged'] = True
        except Exception as exc:
            packet['source_and_prior_unchanged'] = False
            packet['errors'].append(str(exc))
    packet['assessment'] = assess(packet)
    save(out / 'diagnostics.json', packet)
    return packet


def export(packet, destination, backups):
    folder = ROOT / OUTPUT
    files = {p.relative_to(folder).as_posix(): p.read_bytes() for p in folder.rglob('*')
             if p.is_file() and not p.is_symlink()}
    manifest = {'schema': 'native-boundary-export-v1', 'source_commit': packet['source_commit'],
                'files': {n: {'sha256': sha(b), 'bytes': len(b)} for n, b in sorted(files.items())}}
    files['review-manifest.json'] = (json.dumps(manifest, indent=2) + '\n').encode()
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, 'w', zipfile.ZIP_DEFLATED) as package:
        for name, data in sorted(files.items()):
            package.writestr(name, data)
    raw = buffer.getvalue()
    with zipfile.ZipFile(io.BytesIO(raw)) as package:
        require(package.testzip() is None and all(package.read(n) == b for n, b in files.items()), 'Export verification failed.')
    targets = [ROOT / 'runs/native/exports' / destination.name, backups / destination.name, destination]
    for path in targets:
        require(safe(path) and (not path.exists() or path.read_bytes() == raw), 'A different export exists and was retained.')
    for path in targets:
        path.parent.mkdir(parents=True, exist_ok=True)
        if not path.exists():
            with path.open('xb') as stream:
                stream.write(raw)
        require(sha(path.read_bytes()) == sha(raw), 'Export copy verification failed.')
    print('NATIVE BOUNDARY EVIDENCE EXPORTED AND BACKED UP')
    print(json.dumps(packet['assessment'], indent=2))
    print('Containers removed:', packet['containers_removed'])
    print('Original evidence and source unchanged:', packet['source_and_prior_unchanged'])
    print('Upload:', destination)
    print('Backup:', backups / destination.name)
    print('SHA256:', sha(raw))
    print('Model calls: 0. Live native defense evaluation: NOT YET RUN. GitHub uploads: 0.')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--export', required=True, type=Path)
    parser.add_argument('--backup-dir', required=True, type=Path)
    args = parser.parse_args()
    for path in (args.export, args.backup_dir / args.export.name, ROOT / 'runs/native/exports' / args.export.name):
        require(safe(path) and not path.exists(), 'A prior export destination exists and was retained. Do not rerun.')
    require(args.export.parent.is_dir() and args.backup_dir.is_dir(), 'The export or backup directory is missing.')
    packet = collect()
    export(packet, args.export, args.backup_dir)
    return 0 if packet['assessment']['ready_for_native_functionality_pilot'] else 1


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (OSError, RuntimeError, ValueError, KeyError, zipfile.BadZipFile, subprocess.SubprocessError) as exc:
        print('STOP:', exc, file=sys.stderr)
        raise SystemExit(1)
