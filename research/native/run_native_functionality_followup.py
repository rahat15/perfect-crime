"""An explicitly separate functionality attempt after an authentication-blocked attempt."""
import argparse
import io
import json
from pathlib import Path
import subprocess
import sys
import zipfile

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from research.native import run_native_functionality as original
from research.native import native_subscription_access as access

BASE = '51bd3acd4e0e411581291e92de7dc405c6738c20'
PRIOR = Path('runs/native/exports/native-functionality-review.zip')
PRIOR_SHA = 'cbda77afed4bbbbb38bbc119b24723ebe1b17fc2d070ef11cfaa86e8d702e490'
OUTPUT = Path('runs/native/native-functionality-02')
FILES = ('research/native/native_subscription_access.py',
         'research/native/run_native_functionality_followup.py',
         'research/native/native-functionality-followup-protocol.md',
         'tests/test_native_functionality_followup.py')
require, sha = original.require, original.sha


def prior_inputs():
    raw = (ROOT / PRIOR).read_bytes()
    require(sha(raw) == PRIOR_SHA, 'Original functionality attempt differs and was retained.')
    with zipfile.ZipFile(io.BytesIO(raw)) as package:
        names = package.namelist()
        manifest = json.loads(package.read('review-manifest.json'))
        require(len(names) == len(set(names)) and set(names) == set(manifest['files']) | {'review-manifest.json'}
                and package.testzip() is None, 'Original functionality archive is invalid.')
        for name, item in manifest['files'].items():
            data = package.read(name)
            require(sha(data) == item['sha256'] and len(data) == item['bytes'], 'Original evidence hash differs: ' + name)
        record = json.loads(package.read('diagnostics.json'))
        run = json.loads(package.read(record['run_folder'] + '/run.json'))
        stream = [json.loads(line) for line in package.read(record['run_folder'] + '/codex.jsonl').splitlines()]
        stderr = package.read(record['run_folder'] + '/codex.stderr').decode()
        require(record['source_commit'] == BASE and record['cleanup_verified'] is True
                and record['source_and_prior_unchanged'] is True and not record['cleanup_errors']
                and record['filesystem_observation']['complete'] is True
                and record['collection_complete'] is False and record['checkpoint_ready'] is False,
                'Original attempt state differs from the reviewed infrastructure failure.')
        require(len(run['stages']) == 1 and run['stages'][0]['name'] == 'coding'
                and run['stages'][0]['exit_code'] == 1 and run['controller_intervened'] is False
                and '401 Unauthorized: Upstream subscription authentication failed' in stderr
                and any(row.get('type') == 'turn.failed' and 'https://auth.openai.com/oauth/token'
                        in row.get('error', {}).get('message', '') for row in stream)
                and not any(row.get('type') == 'turn.completed' for row in stream),
                'Original authentication failure evidence differs.')
        for name, digest in record['source_sha256'].items():
            require(original.boundary.safe(ROOT / name) and sha((ROOT / name).read_bytes()) == digest,
                    'Frozen functionality source changed: ' + name)
    return {'archive_sha256': PRIOR_SHA, 'source_commit': BASE,
            'classification': 'authentication_blocked_before_coding',
            'coding_completed': False, 'resume_started': False,
            'security_success_or_failure_established': False,
            'initial_review_method': 'Archive integrity checks and assistant review of retained runtime logs.',
            'independent_human_review': 'pending',
            'limitation': 'The original runner retained host logs but did not capture native store contents '
                          'before cleanup on this early failure. Deleted disposable volumes cannot be recovered.'}


class FollowupExperiment(original.ProtectedExperiment):
    context = None

    def __init__(self, args):
        super().__init__(args)
        require(isinstance(self.context, dict), 'Follow-up context is missing.')
        original.save(self.directory.parent.parent / 'followup-context.json', self.context)

    def close(self):
        try:
            if self.metadata.get('status') == 'failed':
                stream, errors = original.read_jsonl(self.directory / 'codex.jsonl')
                session = original.session_id_from_stream('codex', stream)
                if session and not errors:
                    settings_path = self.directory / 'agent-settings.json'
                    settings = json.loads(settings_path.read_text()) if settings_path.is_file() else {}
                    original.previous.capture(self, session, 'after-failure', settings.get('pid_namespace'))
                    capture = original.capture_stores(self, session, 'after-failure')
                    self.metadata['failure_native_capture'] = {
                        'captured': True, 'original_files_unchanged': capture['original_files_unchanged'],
                        'capture_errors': capture.get('capture_errors', [])}
                else:
                    self.metadata['failure_native_capture'] = {
                        'captured': False, 'reason': 'No usable recorded session ID or stream.'}
                self.save()
        except Exception as exc:
            self.metadata['failure_native_capture'] = {'captured': False,
                'error_type': type(exc).__name__, 'reason': str(exc)}
            self.save()
        finally:
            super().close()


def collect(export, backup_dir):
    require(Path.cwd().resolve() == ROOT, 'Run from the project directory.')
    require(not (ROOT / OUTPUT).exists(), 'A follow-up attempt already exists and was retained. Do not rerun it.')
    require(export.name == 'native-functionality-followup-review.zip', 'Use the separate follow-up export filename.')
    prior = prior_inputs()
    original.prior_inputs()
    commit, sources = original.source_snapshot()
    subprocess.run(['git', 'merge-base', '--is-ancestor', BASE, 'HEAD'], cwd=ROOT, check=True)
    require(set(FILES).issubset(sources), 'Follow-up source must be committed first.')
    print('Checking online subscription metadata access before any experimental invocation.', flush=True)
    auth_check = access.check_access()
    FollowupExperiment.context = {'schema': 'native-functionality-followup-v1', 'source_commit': commit,
        'original_attempt': prior, 'authentication_preflight': auth_check,
        'changed_experimental_parameters': [],
        'changes': ['Fresh native home and session recorded as a separate attempt.',
                    'Online, metadata-only authentication gate before collection.',
                    'Best-effort native-store capture before cleanup after an invocation failure.'],
        'original_attempt_retained': True, 'automatic_replacement': False}
    old_output, old_class = original.OUTPUT, original.ProtectedExperiment
    try:
        original.OUTPUT = OUTPUT
        original.ProtectedExperiment = FollowupExperiment
        return original.collect(export, backup_dir)
    finally:
        original.OUTPUT, original.ProtectedExperiment = old_output, old_class
        FollowupExperiment.context = None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--export', type=Path, required=True)
    parser.add_argument('--backup-dir', type=Path, required=True)
    args = parser.parse_args()
    try:
        return collect(args.export, args.backup_dir)
    except (Exception, KeyboardInterrupt) as exc:
        print('STOP:', str(exc) or 'Interrupted', file=sys.stderr)
        print('Existing evidence retained. Do not rerun automatically.', file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
