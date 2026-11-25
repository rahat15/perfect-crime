"""Check subscription metadata access without inference, token refresh, or credential output."""
import argparse
import base64
from datetime import datetime, timezone
import hashlib
import http.client
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import time
import uuid

IMAGE = 'sha256:eddc3b1939fb346372fe8e6aa2806f1bb03696867704f3e70143e12492115aa5'
BINARY = '/usr/local/lib/node_modules/@openai/codex/node_modules/@openai/codex-linux-x64/vendor/x86_64-unknown-linux-musl/bin/codex'
BINARY_SHA = '3188814c35471432d4123203e0eb38e5bddc60226e3d7ddf0e59e649ea140022'
HOST = 'chatgpt.com'
ENDPOINT = '/backend-api/codex/models?client_version=0.154.0'
LABEL = 'cse227.native.auth-access'
ROOT = Path(__file__).resolve().parents[2] if '__file__' in globals() else None


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def safe(path):
    return not any(p.is_symlink() for p in (path, *path.parents))


def command(argv, timeout=30, check=True):
    try:
        result = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        raise RuntimeError('Local command timed out: ' + argv[0]) from None
    require(not check or result.returncode == 0, 'Local command failed: ' + argv[0] + '\n' + result.stderr[-1500:])
    return result


def prepare_login():
    require(Path.cwd().resolve() == ROOT, 'Run from the project directory.')
    require(os.environ.get('CODEX_HOME') in (None, str(Path.home() / '.codex')),
            'Unexpected CODEX_HOME override. It was retained; do not log in yet.')
    require(command(['docker', 'image', 'inspect', '--format', '{{.Id}}', IMAGE]).stdout.strip() == IMAGE,
            'Pinned image unavailable; no download was attempted.')
    target = ROOT / 'runs/native/tools/codex-login-0.154.0'
    require(safe(target), 'The login executable path contains a symbolic link.')
    target.parent.mkdir(parents=True, exist_ok=True)
    if not target.exists():
        name = 'native-login-copy-' + uuid.uuid4().hex[:12]
        temporary = target.with_name(target.name + '.partial')
        require(not temporary.exists() and safe(temporary), 'An earlier partial copy was retained.')
        try:
            command(['docker', 'create', '--name', name, '--network', 'none', '--read-only',
                     '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges', IMAGE, 'true'])
            command(['docker', 'cp', name + ':' + BINARY, str(temporary)])
            require(digest(temporary) == BINARY_SHA, 'Copied native binary hash differs.')
            temporary.chmod(0o500)
            temporary.rename(target)
        finally:
            command(['docker', 'rm', '--force', name], check=False)
            remaining = command(['docker', 'ps', '-aq', '--filter', 'name=^/' + name + '$']).stdout.strip()
            require(not remaining, 'Temporary image-copy container cleanup failed.')
    require(target.is_file() and digest(target) == BINARY_SHA, 'Existing login executable differs.')
    result = command([str(target), '--version'])
    require(result.stdout.strip() == 'codex-cli 0.154.0', 'Native login CLI version differs.')
    print('PINNED LOGIN EXECUTABLE READY')
    print('Path:', target)
    print('Version:', result.stdout.strip())
    print('No login, inference request, image download, or experiment was performed.')


def token_expiry_claim(token):
    try:
        parts = token.split('.')
        payload = json.loads(base64.urlsafe_b64decode(parts[1] + '=' * (-len(parts[1]) % 4)))
        expires = payload.get('exp')
        if type(expires) in (int, float):
            return datetime.fromtimestamp(expires, timezone.utc).isoformat(), expires <= time.time()
    except (IndexError, ValueError, TypeError, OverflowError):
        pass
    return None, None


def check_inside(path=Path('/run/research-auth.json'), connection_factory=http.client.HTTPSConnection):
    report = {'schema': 'native-subscription-access-v1', 'created_at': datetime.now(timezone.utc).isoformat(),
              'request_method': 'GET', 'host': HOST, 'path': ENDPOINT, 'http_status': None,
              'metadata_access_verified': False, 'model_inference_requested': False,
              'token_refresh_requested': False, 'credential_values_recorded': False,
              'credential_cache_modified': False, 'errors': []}
    connection = None
    try:
        info = path.lstat()
        require(stat.S_ISREG(info.st_mode) and not path.is_symlink() and not info.st_mode & 0o077,
                'Private regular credential file required.')
        auth = json.loads(path.read_text())
        tokens = auth.get('tokens', {})
        require(auth.get('auth_mode') == 'chatgpt'
                and all(isinstance(tokens.get(k), str) and tokens[k]
                        for k in ('access_token', 'refresh_token', 'id_token', 'account_id')),
                'Expected a complete ChatGPT login cache.')
        expires, reached = token_expiry_claim(tokens['access_token'])
        report.update(access_token_expiry_claim_utc=expires, expiry_claim_reached=reached,
                      expiry_claim_cryptographically_verified=False, cache_format_valid=True)
        connection = connection_factory(HOST, timeout=20)
        connection.request('GET', ENDPOINT, headers={
            'Authorization': 'Bearer ' + tokens['access_token'], 'chatgpt-account-id': tokens['account_id'],
            'Accept': 'application/json', 'Accept-Encoding': 'identity',
            'originator': 'codex_cli_rs', 'User-Agent': 'codex_cli_rs/0.154.0'})
        response = connection.getresponse()
        report['http_status'] = response.status
        raw = response.read(4 * 1024 * 1024 + 1)
        require(len(raw) <= 4 * 1024 * 1024, 'Metadata response exceeded the bound.')
        if response.status == 200:
            value = json.loads(raw)
            report['metadata_access_verified'] = isinstance(value, dict) and 'error' not in value
            if not report['metadata_access_verified']:
                report['errors'].append('unexpected_metadata_response')
        else:
            report['errors'].append('metadata_endpoint_not_successful')
    except Exception as exc:
        # Do not retain exception messages, headers, body, token claims other than exp, or account identifiers.
        report['errors'].append(type(exc).__name__)
    finally:
        if connection is not None:
            connection.close()
    return report


def check_access():
    require(Path.cwd().resolve() == ROOT, 'Run from the project directory.')
    auth = Path.home() / '.codex/auth.json'
    require(safe(auth) and auth.is_file(), 'The local login cache is missing or is a symbolic link.')
    name = 'native-auth-access-' + uuid.uuid4().hex[:12]
    command(['docker', 'image', 'inspect', IMAGE])
    source = Path(__file__).read_text()
    argv = ['docker', 'run', '--rm', '--name', name, '--label', LABEL + '=metadata-only',
            '--pull', 'never', '--network', 'bridge', '--read-only', '--user', '1000:1000',
            '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges', '--pids-limit', '32',
            '--memory', '128m', '--cpus', '1', '--mount',
            'type=bind,source=' + str(auth) + ',target=/run/research-auth.json,readonly',
            IMAGE, 'python3', '-I', '-c', source, '--inside']
    result, cleanup_ok = None, False
    try:
        result = command(argv, timeout=45, check=False)
    finally:
        command(['docker', 'rm', '--force', name], check=False)
        cleanup_ok = not command(['docker', 'ps', '-aq', '--filter', 'name=^/' + name + '$']).stdout.strip()
    require(cleanup_ok, 'Authentication check container cleanup could not be verified.')
    require(result is not None and result.returncode == 0, 'Authentication check did not produce a valid report.')
    report = json.loads(result.stdout)
    require(report.get('schema') == 'native-subscription-access-v1', 'Unexpected authentication check output.')
    report['container_removed'] = cleanup_ok
    report['image_id'] = IMAGE
    folder = ROOT / 'runs/native/auth-access'
    require(safe(folder), 'Authentication report path contains a symbolic link.')
    folder.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
    path = folder / (stamp + '.json')
    with path.open('x') as stream:
        json.dump(report, stream, indent=2)
        stream.write('\n')
    print('Subscription metadata HTTP status:', report['http_status'])
    print('Online metadata access verified:', report['metadata_access_verified'])
    print('Authentication-check container removed:', report['container_removed'])
    print('Model inference requested: False. Credential values recorded: False.')
    print('Report:', path)
    require(report['metadata_access_verified'] is True and not report['errors'],
            'Subscription access is not verified. No experimental invocation was started.')
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--inside', action='store_true')
    group.add_argument('--prepare-login', action='store_true')
    group.add_argument('--check', action='store_true')
    args = parser.parse_args()
    if args.inside:
        print(json.dumps(check_inside()))
    elif args.prepare_login:
        prepare_login()
    else:
        check_access()


if __name__ == '__main__':
    try:
        main()
    except (Exception, KeyboardInterrupt) as exc:
        print('STOP:', str(exc) or 'Interrupted', file=sys.stderr)
        raise SystemExit(1)
