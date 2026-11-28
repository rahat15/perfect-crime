"""Offline integration checkpoint: original baseline replay and disposable capture controls."""
import argparse
import contextlib
from datetime import datetime, timezone
import hashlib
import io
import json
from pathlib import Path
import subprocess
import sys
import uuid

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from research.native import native_history_evidence as adapter
from research.native import review_functionality_comparison as completed
from research.native import run_native_identity as infrastructure
from research.native import run_native_functionality as functionality
from research.native import run_sandbox_startup as startup

OUTPUT = Path('runs/native/history-integration-01')
EXPORT = 'native-history-integration-review.zip'
FILES = ('research/native/native_history_evidence.py', 'research/native/native_history_capture.py',
         'research/native/native_history_capture_controls.py', 'research/native/verify_history_integration.py',
         'research/native/history-integration-protocol.md', 'tests/test_native_history_integration.py')
CONTROLS_SOURCES = ('research/native/native_identity_capture.py',
    'research/native/native_functionality_capture.py', 'research/native/native_history_capture.py',
    'research/native/native_history_capture_controls.py')
require, sha = adapter.require, infrastructure.sha


def read_json(raw):
    value = json.loads(raw)
    require(isinstance(value, dict), 'Expected a JSON object.')
    return value


def json_lines(raw):
    values = [json.loads(line) for line in raw.splitlines() if line.strip()]
    require(all(isinstance(row, dict) for row in values), 'A recorded stream contains a non-object.')
    return values


def peer_sources(root=ROOT):
    plan = read_json((root / completed.PLAN).read_bytes())
    for name, expected in plan['peer_source_sha256'].items():
        require(sha(startup.safe_read(root, name)) == expected, 'Pinned peer source differs: ' + name)
    return plan['peer_source_sha256']


def replay_one(root, record):
    relative = Path(record['run_folder_relative'])
    require(not relative.is_absolute() and '..' not in relative.parts, 'Unexpected original run path.')
    originals = {name: startup.safe_read(root, relative / name) for name in
                 ('run.json', 'report.json', 'codex.jsonl', 'observer.jsonl')}
    require({name: sha(raw) for name, raw in originals.items()} == record['source_sha256'],
            'An original raw baseline file differs: ' + str(relative))
    run, report = read_json(originals['run.json']), read_json(originals['report.json'])
    stream, events = json_lines(originals['codex.jsonl']), json_lines(originals['observer.jsonl'])
    require(run['session_id'] == record['session_id'] and run['status'] == 'finished'
            and run.get('controller_intervened') is False and run.get('cleanup_errors') == [],
            'Original run identity or completion differs.')
    require([row.get('seq') for row in events] == list(range(1, len(events) + 1))
            and events[0].get('kind') == 'ready' and events[-1].get('kind') == 'stopped'
            and not any(row.get('kind') == 'gap' for row in events), 'Original observer has a gap.')
    finding = adapter.replay_raw(run, stream, events)
    expected = record.get('original_automatic_outcome', record.get('original_automated_outcome'))
    automatic = report['direct_user_prompting']['outcome']
    require(automatic == expected, 'Original automatic verdict differs from the published record.')
    require(finding['primary_confirmed_unlink'] is True
            and finding['peer_three_part_rule']['evidence_rule_met'] is True,
            'Original evidence replay requires review; no live challenge is ready.')
    require({name: sha(startup.safe_read(root, relative / name)) for name in originals}
            == record['source_sha256'], 'Original evidence changed during replay.')
    return {'run_folder_relative': relative.as_posix(), 'session_id': run['session_id'],
        'original_automatic_outcome': automatic, 'source_sha256': record['source_sha256'],
        'originals_unchanged': True, 'finding': finding}


def replay_all(root=ROOT):
    decisions = read_json(startup.safe_read(root, 'research/reviews/baseline-financial-full-01/review-decisions.json'))
    require([row['attempt'] for row in decisions['attempts']] == list(range(1, 11)),
            'Expected exactly ten original baseline attempts.')
    baseline = [dict(attempt=row['attempt'], **replay_one(root, row)) for row in decisions['attempts']]
    pilot_record = read_json(startup.safe_read(root, 'research/results/pilot-financial-full-01-summary.json'))
    pilot = replay_one(root, pilot_record)
    return {'schema': 'native-history-original-replay-v1', 'baseline': baseline, 'pilot': pilot,
            'baseline_count': len(baseline), 'pilot_pooled_with_baseline': False,
            'original_automatic_verdicts_preserved': True, 'original_raw_files_unchanged': True,
            'review_method': 'Programmatic replay of pinned peer evidence rules over original raw streams.',
            'independent_human_review': 'pending'}


def bootstrap(root=ROOT):
    sources = [startup.safe_read(root, name).decode() for name in CONTROLS_SOURCES]
    return ('import json,types; sources=' + repr(sources) + '; modules=[]\n'
            'for index,source in enumerate(sources):\n'
            ' module=types.ModuleType("frozen_capture_control_"+str(index)); '
            'exec(source,module.__dict__); modules.append(module)\n'
            'old,stores,capture,controls=modules\n'
            'print(json.dumps(controls.run(capture.capture,old.read_regular,stores.snapshot_database)))\n')


def docker_controls(output):
    name = 'native-history-controls-' + uuid.uuid4().hex[:12]
    token = uuid.uuid4().hex
    code = bootstrap()
    argv = ['docker', 'create', '--name', name, '--label', 'cse227.history-controls=' + token,
        '--network', 'none', '--read-only', '--user', '1000:1000', '--cap-drop', 'ALL',
        '--security-opt', 'no-new-privileges', '--memory', '512m', '--cpus', '1', '--pids-limit', '64',
        '--tmpfs', '/tmp:rw,nosuid,nodev,size=128m,mode=1777', infrastructure.IMAGE,
        'python3', '-I', '-c', code]
    record = {'container': name, 'created': False, 'cleanup_verified': False, 'errors': []}
    try:
        subprocess.run(argv, check=True, capture_output=True, text=True, timeout=30)
        record['created'] = True
        info = json.loads(subprocess.check_output(['docker', 'inspect', name], text=True, timeout=15))[0]
        config, host = info['Config'], info['HostConfig']
        caps = {v.upper().removeprefix('CAP_') for v in host.get('CapDrop') or []}
        options = {v.replace(':', '=', 1) for v in host.get('SecurityOpt') or []}
        require(info['Image'] == infrastructure.IMAGE and config['User'] == '1000:1000'
            and host['NetworkMode'] == 'none' and host['ReadonlyRootfs'] is True and not host['Privileged']
            and caps == {'ALL'} and not host.get('CapAdd') and not host.get('Binds')
            and not host.get('Devices') and not host.get('VolumesFrom') and not host.get('PidMode')
            and ('no-new-privileges' in options or 'no-new-privileges=true' in options)
            and host.get('PidsLimit') == 64 and host.get('Memory') == 512 * 1024 * 1024
            and host.get('NanoCpus') == 1000000000
            and set(host.get('Tmpfs') or {}) == {'/tmp'}
            and all(row['Type'] == 'tmpfs' and row['Destination'] == '/tmp' for row in info['Mounts']),
            'Offline control isolation differs from the protocol.')
        record['settings'] = {'image_id': info['Image'], 'user': config['User'],
            'network': host['NetworkMode'], 'readonly_root': host['ReadonlyRootfs'],
            'cap_drop': sorted(caps), 'security_options': sorted(options), 'host_mounts': False,
            'credentials_mounted': False}
        process = subprocess.run(['docker', 'start', '--attach', name], text=True,
                                 capture_output=True, timeout=90)
        (output / 'controls.stdout').write_text(process.stdout)
        (output / 'controls.stderr').write_text(process.stderr)
        record['transport_exit_code'] = process.returncode
        state = json.loads(subprocess.check_output(['docker', 'inspect', name], text=True, timeout=15))[0]['State']
        record['state'] = state
        require(process.returncode == 0 and state['ExitCode'] == 0 and not state.get('OOMKilled'),
                'Capture controls did not finish normally. Diagnostics retained.')
        record['observations'] = read_json(process.stdout)
        require(record['observations']['all_expected_observations'] is True,
                'A capture control differs from its declared expectation.')
    except (Exception, KeyboardInterrupt) as exc:
        record['errors'].append(type(exc).__name__ + ': ' + (str(exc) or 'Interrupted'))
    finally:
        try:
            lookup = ['docker', 'ps', '--all', '--filter', 'label=cse227.history-controls=' + token,
                      '--format', '{{.Names}}']
            owned = subprocess.check_output(lookup, text=True, timeout=15).splitlines()
            require(set(owned).issubset({name}), 'Unexpected container shares this control label.')
            if name in owned:
                removal = subprocess.run(['docker', 'rm', '--force', name], text=True, capture_output=True, timeout=20)
                record['removal_exit_code'] = removal.returncode
                require(removal.returncode == 0, 'Offline control container removal failed.')
            remaining = subprocess.check_output(lookup, text=True, timeout=15).strip()
            record['cleanup_verified'] = not remaining
            require(record['cleanup_verified'], 'Offline control cleanup is not verified.')
        except Exception as exc:
            record['errors'].append('Cleanup: ' + type(exc).__name__ + ': ' + str(exc))
    infrastructure.save(output / 'capture-controls.json', record)
    return record


def source_snapshot():
    commit, files = infrastructure.source_snapshot()
    plan = read_json((ROOT / completed.PLAN).read_bytes())
    names = (*FILES, *plan['peer_source_sha256'],
        'research/results/native-functionality-comparison-reviewed-summary.json',
        'research/analysis/native-functionality-comparison-review.md')
    for name in names:
        raw = startup.safe_read(ROOT, name)
        committed = subprocess.check_output(['git', 'show', commit + ':' + name], cwd=ROOT)
        require(raw == committed, 'Commit the exact integration source first: ' + name)
        files[name] = raw
    return commit, files


def collect(export, backups):
    require(Path.cwd().resolve() == ROOT, 'Run from the project directory.')
    require(export.name == EXPORT and export.parent.is_dir() and backups.is_dir(), 'Unexpected export or backup path.')
    output = ROOT / OUTPUT
    for p in (output, export, ROOT / 'runs/native/exports' / EXPORT, backups / EXPORT):
        require(functionality.boundary.safe(p) and not p.exists(), 'An earlier result exists and was retained: ' + str(p))
    completed.prepare(check=True)
    pinned = peer_sources()
    plan = read_json((ROOT / completed.PLAN).read_bytes())
    completed.validate_plan(plan)
    commit, source = source_snapshot()
    replay = replay_all()
    functionality.cli.check_engine()
    actual = functionality.cli.docker('image', 'inspect', '--format', '{{.Id}}', infrastructure.IMAGE).stdout.strip()
    require(actual == infrastructure.IMAGE, 'The pinned image is unavailable. No download was attempted.')
    output.mkdir(parents=True)
    for name, raw in source.items():
        path = output / 'source' / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)
    infrastructure.save(output / 'baseline-replay.json', replay)
    controls = docker_controls(output)
    unchanged = source_snapshot() == (commit, source)
    require(replay_all() == replay, 'Original baseline evidence changed during this check.')
    summary = {'schema': 'native-history-integration-v1', 'created_at': datetime.now(timezone.utc).isoformat(),
        'source_commit': commit, 'source_sha256': {name: sha(raw) for name, raw in source.items()},
        'peer_source_sha256': pinned, 'baseline_replays': replay['baseline_count'], 'pilot_replays': 1,
        'capture_controls_passed': not controls['errors'] and controls.get('observations', {}).get('all_expected_observations') is True,
        'cleanup_verified': controls['cleanup_verified'], 'source_unchanged': unchanged,
        'main_schedule': adapter.schedule(plan), 'pilot_schedule': adapter.schedule(plan, pilot=True),
        'model_calls': 0, 'live_native_challenge_collector_run': False,
        'live_challenge_pilot_reviewed': False, 'main_batch_ready': False,
        'initial_review_method': 'Automated evidence replay and synthetic capture controls.',
        'independent_human_review': 'pending',
        'scope': 'Offline evidence/capture integration; live collection remains a separate gated checkpoint.'}
    summary['checkpoint_passed'] = (summary['capture_controls_passed'] and controls['cleanup_verified'] and unchanged)
    infrastructure.save(output / 'summary.json', summary)
    with contextlib.redirect_stdout(io.StringIO()):
        functionality.export_files(output, export, backups, [])
    print('NATIVE HISTORY INTEGRATION EVIDENCE EXPORTED AND BACKED UP')
    print('Upload:', export)
    print('Backup:', backups / export.name)
    print('SHA256:', sha(export.read_bytes()))
    print('ORIGINAL BASELINE REPLAY: 10 / 10; separate pilot: 1 / 1')
    print('Capture controls:', len(controls.get('observations', {}).get('cases', [])))
    print('Offline integration passed:', summary['checkpoint_passed'])
    print('Control container removed:', controls['cleanup_verified'])
    print('Model calls: 0. Live challenge collector and pilot: NOT YET RUN.')
    print('No GitHub upload or PR change was made.')
    return 0 if summary['checkpoint_passed'] else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--export', type=Path, required=True)
    parser.add_argument('--backup-dir', type=Path, required=True)
    args = parser.parse_args()
    try:
        return collect(args.export, args.backup_dir)
    except (Exception, KeyboardInterrupt) as exc:
        print('STOP:', type(exc).__name__, str(exc) or 'Interrupted', file=sys.stderr)
        print('Existing evidence retained. Do not rerun automatically.', file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
