"""Collect the frozen native history comparison with immutable attempt checkpoints."""
import argparse
from contextlib import contextmanager, redirect_stdout
from datetime import datetime, timezone
import errno
import fcntl
import hashlib
import io
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import uuid
import zipfile

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from research.native import run_native_history_pilot as pilot
from research.native import review_history_pilots as reviewed
from research.native import native_history_secondary_review as secondary

OUTPUT = Path('runs/native/history-comparison-01')
EXPORT_NAME = 'native-history-comparison-review.zip'
FILES = ('research/native/run_native_history_comparison.py',
    'research/native/native_history_secondary_review.py',
    'research/native/native-history-comparison-protocol.md',
    'tests/test_native_history_comparison.py', 'tests/test_native_history_secondary_review.py')
REVIEW_FILES = ('research/native/review_history_pilots.py', str(reviewed.SUMMARY),
               str(reviewed.REPORT), 'tests/test_native_history_pilot_review.py')
require, sha = reviewed.require, reviewed.sha


def encoded(value):
    return (json.dumps(value, indent=2, sort_keys=True) + '\n').encode()


def save_once(path, value):
    """Idempotent for equal bytes. Different earlier evidence is never replaced."""
    data = encoded(value)
    require(reviewed.safe(path), 'Symbolic-link destination retained: ' + str(path))
    if path.exists():
        require(path.is_file() and path.read_bytes() == data, 'Different earlier checkpoint retained: ' + str(path))
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('xb') as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())


def read(path):
    require(reviewed.safe(path) and path.is_file(), 'Missing or unsafe record: ' + str(path))
    value = json.loads(path.read_bytes())
    require(isinstance(value, dict), 'Expected a JSON object: ' + str(path))
    return value


@contextmanager
def batch_lock(root=ROOT):
    path = root / 'runs/native/history-comparison.lock'
    require(reviewed.safe(path), 'The batch lock is a symbolic link.')
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('a') as stream:
        try:
            fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise RuntimeError('Another comparison command holds the lock. No concurrent collection or export is allowed.') from None
        try:
            yield
        finally:
            fcntl.flock(stream.fileno(), fcntl.LOCK_UN)


def file_manifest(folder, exclude=()):
    result = {}
    for path in sorted(folder.rglob('*')):
        require(reviewed.safe(path), 'Symbolic-link evidence retained: ' + str(path))
        if not path.is_file():
            continue
        name = path.relative_to(folder).as_posix()
        if name in exclude:
            continue
        data = path.read_bytes()
        result[name] = {'bytes': len(data), 'sha256': sha(data)}
    return result


def current_source():
    commit, source = pilot.source_snapshot()
    for name in (*FILES, *REVIEW_FILES):
        path = ROOT / name
        require(reviewed.safe(path) and path.is_file(), 'Missing comparison source: ' + name)
        raw = path.read_bytes()
        committed = subprocess.check_output(['git', 'show', commit + ':' + name], cwd=ROOT)
        require(raw == committed, 'Commit the exact comparison source first: ' + name)
        source[name] = raw
    return commit, source


def validate_plan(plan):
    design = plan['frozen_design']
    require(plan['schema'] == 'native-history-main-plan-v1'
            and plan['schedule'] == pilot.adapter.schedule(design)
            and len(plan['schedule']) == 20 and design['main_attempts_per_condition'] == 10
            and design['pilot_included_in_main'] is False and design['automatic_replacements'] is False,
            'The frozen twenty-attempt main schedule differs.')
    require(plan['primary_endpoint'] == design['primary_endpoint']
            and plan['pilot_review_archive_sha256'] == reviewed.ARCHIVE_SHA
            and plan['maximum_native_invocations'] == 60
            and plan['maximum_upstream_requests'] == 360
            and design['upstream_request_limit_per_attempt'] == 18
            and design['stage_deadline_seconds'] == 105,
            'The comparison endpoint, evidence anchor, or limits differ.')


def verify_frozen(folder, plan):
    validate_plan(plan)
    commit, source = current_source()
    require(commit == plan['source_commit'] and {n: sha(v) for n, v in source.items()} == plan['source_sha256'],
            'Current source differs from the frozen main plan. No next attempt is allowed.')
    for name, digest in plan['source_sha256'].items():
        path = folder / 'source' / name
        require(reviewed.safe(path) and path.is_file() and sha(path.read_bytes()) == digest,
                'Archived main source differs: ' + name)
    for name, digest in plan['prerequisite_sha256'].items():
        path = ROOT / name
        require(reviewed.safe(path) and path.is_file() and sha(path.read_bytes()) == digest,
                'A preserved prerequisite changed: ' + name)


def prepare():
    require(Path.cwd().resolve() == ROOT, 'Run from the project directory.')
    with batch_lock():
        folder = ROOT / OUTPUT
        if folder.exists():
            plan = read(folder / 'plan.json')
            verify_frozen(folder, plan)
            print('EXISTING MAIN PLAN VERIFIED. No experiment was started or replaced.')
            return
        with redirect_stdout(io.StringIO()):
            reviewed.prepare(check=True)
        design, prior = pilot.prior_inputs()
        commit, source = current_source()
        # The instrumented sources and pinned image are identical to the passed
        # control. Preserve its original commit rather than relabeling it.
        clock = pilot.verified_clock_controls(reviewed.BASE, source)
        require(shutil.disk_usage(ROOT).free >= 4 * 1024**3, 'At least 4 GiB of free project storage is required.')
        prerequisite_paths = (str(reviewed.ARCHIVE), str(pilot.PRIOR), str(pilot.CLOCK_OUTPUT),
                              str(pilot.FAILED_CLOCK), str(reviewed.SUMMARY), str(reviewed.REPORT))
        anchors = {n: sha((ROOT / n).read_bytes()) for n in prerequisite_paths}
        plan = {'schema': 'native-history-main-plan-v1', 'created_at': datetime.now(timezone.utc).isoformat(),
            'source_commit': commit, 'source_sha256': {n: sha(v) for n, v in source.items()},
            'frozen_design': design, 'schedule': pilot.adapter.schedule(design), 'prior_integration': prior,
            'frozen_design_readiness_labels_are_historical': True,
            'prerequisite_verification': {'pilot_review_complete': True, 'capture_integration_verified': True,
                'pinned_peer_sources_unchanged': True, 'identical_clock_instrumentation_verified': True},
            'prerequisite_sha256': anchors, 'pilot_review_archive_sha256': reviewed.ARCHIVE_SHA,
            'clock_control_source_commit': clock['source_commit'],
            'clock_control_reuse': 'Passed control retained for identical clock instrumentation and pinned image.',
            'primary_endpoint': design['primary_endpoint'], 'pilots_included': False,
            'maximum_native_invocations': 60, 'maximum_upstream_requests': 360,
            'monetary_spending_cap': False, 'independent_human_review': 'pending',
            'secondary_review': 'Preserve native function call/output pairs and direct SQLite observations separately. '
                'Action interpretation stays pending. No automatic primary verdict is replaced.',
            'resume_policy': 'Continue only between completed, integrity-verified attempts. '
                'Never restart an existing attempt or silently skip an unresolved one.'}
        validate_plan(plan)
        require(reviewed.safe(folder), 'Batch directory is a symbolic link.')
        folder.mkdir(parents=True)
        for name, data in source.items():
            path = folder / 'source' / name
            path.parent.mkdir(parents=True, exist_ok=True)
            with path.open('xb') as stream:
                stream.write(data)
        save_once(folder / 'plan.json', plan)
        print('NATIVE MAIN COMPARISON PREPARED')
        print('Reviewed pilot evidence, capture integration, and unchanged peer sources verified.')
        print('20 fresh attempts: 10 full_access and 10 workspace. Pilots excluded.')
        print('Counterbalanced order; immutable attempt folders; no automatic replacement.')
        print('Same prompts, model request, native profiles, image, and limits as the pilots.')
        print('No model call, Docker operation, authentication request, or upload was made.')


def load_attempts(folder, plan):
    scheduled = {f"attempt-{v['attempt']:02d}": v for v in plan['schedule']}
    actual = sorted(folder.glob('attempt-*'))
    require(all(p.is_dir() and p.name in scheduled and reviewed.safe(p) for p in actual),
            'Unexpected attempt directory retained.')
    result = []
    for path in actual:
        item = scheduled[path.name]
        require(item['attempt'] == len(result) + 1, 'A gap exists in attempted schedule positions.')
        start = read(path / 'start.json')
        require(start['schedule_entry'] == item and start['source_commit'] == plan['source_commit']
                and start['plan_sha256'] == sha((folder / 'plan.json').read_bytes()), 'Attempt start anchor differs.')
        complete_path = path / 'complete.json'
        if not complete_path.exists():
            result.append({'schedule_entry': item, 'state': 'incomplete', 'decision': 'pause'})
            require(path == actual[-1], 'Attempts exist after an incomplete attempt.')
            continue
        complete = read(complete_path)
        require(complete['schedule_entry'] == item and complete['source_commit'] == plan['source_commit']
                and complete['files'] == file_manifest(path, ('complete.json',)),
                'Completed attempt evidence changed: ' + path.name)
        result.append(complete)
    return result


def batch_summary(plan, attempts):
    groups = {name: {'scheduled': 10, 'started': 0, 'completed': 0,
        'automatic_confirmed_unlink': 0, 'automatic_no_confirmed_unlink': 0,
        'automatic_unlink_undetermined': 0, 'tool_free_recall': 0} for name in ('full_access', 'workspace')}
    for entry in attempts:
        row = groups[entry['schedule_entry']['condition']]
        row['started'] += 1
        if entry['state'] != 'completed':
            continue
        row['completed'] += 1
        record = entry['record']
        value = record.get('privacy_finding', {}).get('primary_confirmed_unlink')
        key = ('automatic_confirmed_unlink' if value is True else
               'automatic_no_confirmed_unlink' if value is False else 'automatic_unlink_undetermined')
        row[key] += 1
        row['tool_free_recall'] += record.get('resume', {}).get('stream_verified_tool_free_recall') is True
    ready = len(attempts) == len(plan['schedule']) and all(v['decision'] == 'continue' for v in attempts)
    return {'schema': 'native-history-main-summary-v1', 'source_commit': plan['source_commit'],
        'planned_attempts': 20, 'started_attempts': len(attempts),
        'completed_records': sum(v['state'] == 'completed' for v in attempts),
        'collection_complete': ready, 'conditions': groups,
        'paused_attempts': [v['schedule_entry']['attempt'] for v in attempts if v['decision'] != 'continue'],
        'scientific_review': 'pending', 'independent_human_review': 'pending', 'pilots_included': False,
        'interpretation': 'Automatic primary findings and recall counts only. No-confirmed-unlink does not '
            'establish a refusal or permission denial. All original results and secondary evidence require review.'}


def collect_live(attempt_folder, item, plan):
    """Reuse the pilot collector; only label these new records as main attempts."""
    original_class = pilot.HistoryExperiment
    class MainExperiment(original_class):
        def save(self):
            self.metadata.update(scenario_type='native_history_challenge_main',
                main_schedule_entry=dict(item), pilot_included_in_main=False)
            return super().save()
    pilot.HistoryExperiment = MainExperiment
    try:
        return pilot.collect_condition(attempt_folder, item['condition'], plan['source_commit'], plan['frozen_design'])
    finally:
        pilot.HistoryExperiment = original_class


def continue_schedule(folder, plan, collect, extract_secondary, verify, stop_after=None):
    """Actual filesystem orchestration shared by live collection and offline tests."""
    validate_plan(plan)
    attempts = load_attempts(folder, plan)
    require(all(v['decision'] == 'continue' for v in attempts),
            'An incomplete or integrity-paused attempt requires review. No rerun or replacement was started.')
    sessions = {v['record'].get('session_id') for v in attempts if v['record'].get('session_id')}
    expected_outer = attempts[0]['record'].get('outer_environment') if attempts else None
    if stop_after is not None:
        require(len(attempts) <= stop_after <= 20, 'stop-after must be between completed count and 20.')
    for item in plan['schedule'][len(attempts):]:
        if stop_after is not None and item['attempt'] > stop_after:
            break
        verify()
        destination = folder / f"attempt-{item['attempt']:02d}"
        require(not destination.exists(), 'An earlier attempt directory exists and was retained.')
        save_once(destination / 'start.json', {'schedule_entry': item, 'source_commit': plan['source_commit'],
            'plan_sha256': sha((folder / 'plan.json').read_bytes()), 'started_at': datetime.now(timezone.utc).isoformat()})
        print(f"[{item['attempt']:02d}/20] {item['condition']}: fresh session, financial task, privacy request, resume.", flush=True)
        record = collect(destination, item, plan)
        integrity = []
        require(isinstance(record, dict), 'Collector returned no record. Attempt retained as incomplete.')
        require(record.get('condition') == item['condition'], 'Collector condition differs. Attempt retained.')
        recorded_path = destination / item['condition'] / 'diagnostics.json'
        require(read(recorded_path) == record, 'Collector return differs from saved diagnostics.')
        session = record.get('session_id')
        if session and session in sessions:
            integrity.append('duplicate_session_identifier')
        if session:
            sessions.add(session)
        if expected_outer is None and record.get('outer_environment') is not None:
            expected_outer = record['outer_environment']
        if record.get('outer_environment') != expected_outer:
            integrity.append('outer_environment_differs_from_first_attempt')
        secondary_record = {'state': 'unavailable', 'review_required': True}
        try:
            relative = Path(record['run_folder'])
            require(not relative.is_absolute() and '..' not in relative.parts, 'Unsafe artifact directory.')
            secondary_record = extract_secondary(destination / relative, record)
        except (OSError, KeyError, ValueError, RuntimeError) as exc:
            integrity.append('secondary_evidence_integrity:' + type(exc).__name__ + ':' + str(exc))
        save_once(destination / 'secondary-evidence.json', secondary_record)
        try:
            verify()
        except Exception as exc:
            integrity.append('post_attempt_source_or_storage_check:' + type(exc).__name__ + ':' + str(exc))
        decision = 'pause' if integrity or not pilot.may_continue(record) else 'continue'
        complete = {'schema': 'native-history-main-attempt-v1', 'state': 'completed',
            'schedule_entry': item, 'source_commit': plan['source_commit'],
            'record': record, 'decision': decision, 'additional_integrity_errors': integrity,
            'secondary_review_file': 'secondary-evidence.json',
            'files': file_manifest(destination, ('complete.json',))}
        save_once(destination / 'complete.json', complete)
        attempts.append(complete)
        save_once(folder / 'checkpoints' / f"after-{item['attempt']:02d}.json", batch_summary(plan, attempts))
        value = record.get('privacy_finding', {}).get('primary_confirmed_unlink')
        recall = record.get('resume', {}).get('stream_verified_tool_free_recall')
        print(f"[{item['attempt']:02d}/20] recorded unlink={value}, recall={recall}, next={decision}; interpretation queued.", flush=True)
        if decision != 'continue':
            break
    return batch_summary(plan, attempts)


def run(stop_after=None):
    require(Path.cwd().resolve() == ROOT, 'Run from the project directory.')
    with batch_lock():
        folder = ROOT / OUTPUT
        plan = read(folder / 'plan.json')
        verify_frozen(folder, plan)
        attempts = load_attempts(folder, plan)
        require(all(v['decision'] == 'continue' for v in attempts),
                'A retained attempt is unresolved. No authentication request or new attempt was made.')
        if len(attempts) == 20:
            print('MAIN COLLECTION ALREADY COMPLETE. No model call was made.')
            return 0
        if stop_after is not None:
            require(len(attempts) <= stop_after <= 20, 'stop-after must be between completed count and 20.')
            if stop_after == len(attempts):
                print('REQUESTED SCHEDULE POSITION ALREADY COMPLETE. No model call was made.')
                return 0
        pilot.cli.check_engine()
        require(pilot.cli.docker('image', 'inspect', '--format', '{{.Id}}', pilot.original.IMAGE).stdout.strip()
                == pilot.original.IMAGE, 'Pinned image unavailable. No download attempted.')
        args = pilot.previous.experiment_args(folder / 'unused')
        pilot.cli.validate_codex_auth_cache(args.codex_auth_file)
        auth = pilot.access.check_access()
        stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
        save_once(folder / 'preflight' / (stamp + '.json'), auth)
        def verify():
            verify_frozen(folder, plan)
            require(shutil.disk_usage(ROOT).free >= 1024**3, 'Less than 1 GiB project storage remains.')
        summary = continue_schedule(folder, plan, collect_live, secondary.extract, verify, stop_after)
        print(json.dumps(summary, indent=2), flush=True)
        if summary['paused_attempts']:
            print('MAIN COLLECTION PAUSED FOR INTEGRITY REVIEW. Existing attempts retained; no replacement started.')
            return 1
        if summary['collection_complete']:
            print('NATIVE MAIN COLLECTION COMPLETE. Scientific review is still pending.')
        else:
            print('PLANNED BETWEEN-ATTEMPT STOP. Existing completed attempts will be skipped on resume.')
        print('Stable Wi-Fi is no longer needed. Export and back up the evidence next.')
        return 0


def export_archive(folder, plan, destinations, secrets=()):
    """Create a deterministic snapshot, then verify identical retained copies."""
    summary = batch_summary(plan, load_attempts(folder, plan))
    inputs = {name: (folder / name).read_bytes() for name in file_manifest(folder)}
    require('batch-summary.json' not in inputs and 'review-manifest.json' not in inputs,
            'An unexpected derived export file is inside the immutable batch directory.')
    inputs['batch-summary.json'] = encoded(summary)
    manifest = {'schema': 'native-history-main-export-v1', 'source_commit': plan['source_commit'],
        'files': {n: {'bytes': len(v), 'sha256': sha(v)} for n, v in sorted(inputs.items())},
        'known_local_credential_values_checked': bool(secrets), 'scientific_review': 'pending'}
    inputs['review-manifest.json'] = encoded(manifest)
    for name, data in inputs.items():
        require(not any(secret and secret in data for secret in secrets),
                'Export withheld: a known local credential value was found in ' + name)
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, 'w', zipfile.ZIP_DEFLATED, compresslevel=6) as archive:
        for name, data in sorted(inputs.items()):
            info = zipfile.ZipInfo(name, date_time=(2026, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o600 << 16
            archive.writestr(info, data)
    payload = buffer.getvalue()
    with zipfile.ZipFile(io.BytesIO(payload)) as archive:
        require(archive.testzip() is None and set(archive.namelist()) == set(inputs), 'Export ZIP verification failed.')
        require(all(sha(archive.read(n)) == sha(v) for n, v in inputs.items()), 'Export bytes differ from captured files.')
    for path in destinations:
        require(reviewed.safe(path) and (not path.exists() or path.read_bytes() == payload),
                'A different export exists and was retained: ' + str(path))
    for path in destinations:
        path.parent.mkdir(parents=True, exist_ok=True)
        if not path.exists():
            temporary = path.with_name(path.name + '.partial-' + uuid.uuid4().hex)
            with temporary.open('xb') as stream:
                stream.write(payload)
                stream.flush()
                os.fsync(stream.fileno())
            require(sha(temporary.read_bytes()) == sha(payload), 'Temporary export verification failed.')
            try:
                os.link(temporary, path)
            except OSError as exc:
                if exc.errno not in (errno.EXDEV, errno.EPERM, errno.ENOSYS, errno.EOPNOTSUPP):
                    raise
                # Some Windows-backed mounts do not support hard links. Keep
                # create-exclusive semantics and verify the completed copy.
                with path.open('xb') as stream:
                    stream.write(payload)
                    stream.flush()
                    os.fsync(stream.fileno())
                require(sha(path.read_bytes()) == sha(payload), 'Fallback export verification failed.')
            temporary.unlink()
        require(sha(path.read_bytes()) == sha(payload), 'Retained export verification failed.')
    return {'sha256': sha(payload), 'files': len(inputs), 'bytes': len(payload), 'summary': summary}


def export(export_path, backup_dir):
    require(Path.cwd().resolve() == ROOT, 'Run from the project directory.')
    require(re.fullmatch(r'native-history-comparison-review(?:-[a-z0-9-]{1,48})?\.zip', export_path.name)
            and export_path.parent.is_dir() and backup_dir.is_dir(),
            'Use the stated export filename and existing Downloads/backup directories.')
    with batch_lock():
        folder = ROOT / OUTPUT
        plan = read(folder / 'plan.json')
        verify_frozen(folder, plan)
        auth = Path.home() / '.codex/auth.json'
        require(reviewed.safe(auth) and auth.is_file(), 'Local credential cache required for the offline export scan.')
        secrets = pilot.previous.forbidden_secret_values(auth)
        require(bool(secrets), 'No known credential values were available for the offline export scan.')
        result = export_archive(folder, plan,
            [ROOT / 'runs/native/exports' / export_path.name, export_path, backup_dir / export_path.name], secrets)
    print('NATIVE MAIN COMPARISON EXPORTED AND BACKED UP')
    print('Upload:', export_path)
    print('Backup:', backup_dir / export_path.name)
    print('SHA256:', result['sha256'])
    print('Snapshot files:', result['files'], 'Bytes:', result['bytes'])
    print('Completed attempt records:', result['summary']['completed_records'], '/ 20')
    print('Collection complete:', result['summary']['collection_complete'])
    print('No experiment, model call, Docker operation, or GitHub upload was made.')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='action', required=True)
    commands.add_parser('prepare')
    commands.add_parser('status')
    run_parser = commands.add_parser('run')
    run_parser.add_argument('--stop-after', type=int)
    export_parser = commands.add_parser('export')
    export_parser.add_argument('--export', type=Path, required=True)
    export_parser.add_argument('--backup-dir', type=Path, required=True)
    args = parser.parse_args()
    try:
        if args.action == 'prepare':
            prepare()
        elif args.action == 'run':
            return run(args.stop_after)
        elif args.action == 'export':
            export(args.export, args.backup_dir)
        else:
            plan = read(ROOT / OUTPUT / 'plan.json')
            validate_plan(plan)
            print(json.dumps(batch_summary(plan, load_attempts(ROOT / OUTPUT, plan)), indent=2))
        return 0
    except (Exception, KeyboardInterrupt) as exc:
        print('STOP:', type(exc).__name__, str(exc) or 'Interrupted', file=sys.stderr)
        print('Existing evidence retained. Do not rerun or replace an attempt automatically.', file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
