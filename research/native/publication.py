"""Build and verify public evidence copies without changing original experiments."""
import argparse
from collections import Counter
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import re
import stat
import sys
import zipfile

ROOT = Path(__file__).resolve().parents[2]
MANIFEST = Path('research/manifests/native-history-publication.json')
EVIDENCE = Path('research/evidence/native-history')
ARCHIVES = {
    'native-observer-calibration-review.zip': '744ebbdbd9841c6de102ae32b1dc39286ed5272c9fcbccb8541e52eebdab4c23',
    'native-sandbox-startup-review.zip': '03ee443d68514c4d7b0ca685604ef3592afae400886e53f11642ebadb5ae1e65',
    'native-identity-review.zip': '939cbcab7e28684ba4cc8f2c5f93602ad48b6d906beaa41948effac8955504b7',
    'native-store-scope-review.zip': '5649442bfb5064097f5ba2f8f58fbb49597505a4451d57dd63a5e1bc226754be',
    'native-boundary-review.zip': 'c13c95daff44a8d38657656e49f5a29d69c49880411ef383a6912ce10858d198',
    'native-functionality-review.zip': 'cbda77afed4bbbbb38bbc119b24723ebe1b17fc2d070ef11cfaa86e8d702e490',
    'native-functionality-followup-review.zip': '09258ea9bd769674f4bec83d4b9d541c4e294febb201a631b52df297ee88fef5',
    'native-functionality-comparison-review.zip': '48af3d8810100b64f8bc04d834b367ec00b48479b05dbab0dd9bdcd30c895a95',
    'native-history-integration-review.zip': '9a67fe8ce81a835cc42a41ccace291cb646d68e2987dd983bd00fe90fccd70e1',
    'native-history-pilot-recovered-review.zip': '145cc4c5a430b8234cdbafc8a34750bdd1230f90bebd656ad94dfd044651d271',
    'native-history-comparison-review-01.zip': '5537e0a5d3c360061fcd389d0a7f72e571d1ff8bad66a13d0aec731db7f663a7',
}
PRIVATE_FIELDS = {'account_id', 'email', 'access_token', 'refresh_token', 'id_token', 'api_key'}
SECRET = re.compile(rb'(?:sk-(?:proj-)?[A-Za-z0-9_-]{24,}|gh[pousr]_[A-Za-z0-9_]{20,}|eyJ[A-Za-z0-9_-]{15,}\.[A-Za-z0-9_-]{15,}\.[A-Za-z0-9_-]{15,}|-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----)')
# Fixed parser fixtures and offline dummy keys in the archived upstream source.
# This exception is path- and value-bound; known credential matching still applies.
SYNTHETIC_KEYS = {
    'source/host_lab/trace_canary_loop.py': {
        'ff30da380e0704a9075ea950542e7bcbd23e3ad514b8c95aefb2557f3e6d94ed',
        '177ec6576064bb1899c4d2d7f27e9dac50956fc1f11e1e942519d29ce915302a',
        '35d3fa8013fb3381989ba96ff48ef834e1c9484512bbf26326c27d9c075f6575',
        '6e812d6a1572b33de54d8131630667eefc5b48aaf43f8fbf934cc1408b8e5662'},
    'source/trace_lab/cli.py': {
        '5a4e4aa20f2e1a99cde52efb3b035d8e526b2745b4f7ccf2dc00519f0c01419a',
        '5b970cb5f822090ae0702d105eb97387efaaf7fe5aa45098792a9afa787f492b'},
}


def require(ok, message):
    if not ok:
        raise ValueError(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def encoded(value):
    return (json.dumps(value, indent=2, sort_keys=True) + '\n').encode()


def safe(path):
    return not any(p.is_symlink() for p in (path, *path.parents))


def member(name, mode=0):
    p = PurePosixPath(name)
    require(bool(name) and not p.is_absolute() and '..' not in p.parts
            and '\\' not in name and not name.endswith('/') and not stat.S_ISLNK(mode),
            'Unsafe archive member.')


def inventory(z):
    infos = z.infolist()
    names = [v.filename for v in infos]
    require(len(names) == len(set(names)) and len(names) <= 10000, 'Duplicate or excessive ZIP members.')
    require(sum(v.file_size for v in infos) <= 1024**3, 'Archive exceeds the size limit.')
    for v in infos:
        member(v.filename, v.external_attr >> 16)
        require(not v.flag_bits & 1, 'Encrypted ZIP member is unsupported.')
    require(z.testzip() is None, 'ZIP CRC validation failed.')
    return set(names)


def scrub_usage(data):
    """Replace only native token-count account-limit values, preserving other bytes."""
    result = []
    changes = []
    for number, raw in enumerate(data.splitlines(keepends=True), 1):
        try:
            row = json.loads(raw)
        except (ValueError, UnicodeDecodeError):
            result.append(raw)
            continue
        payload = row.get('payload') if isinstance(row, dict) else None
        if not isinstance(payload, dict) or 'rate_limits' not in payload:
            result.append(raw)
            continue
        require(row.get('type') == 'event_msg' and payload.get('type') == 'token_count',
                'Unrecognized rate-limit record; original retained.')
        if payload['rate_limits'] is None:
            result.append(raw)
            continue
        require(isinstance(payload['rate_limits'], dict), 'Unexpected rate-limit value.')
        text = raw.decode('utf-8')
        matches = list(re.finditer(r'"rate_limits"\s*:\s*', text))
        require(len(matches) == 1, 'Ambiguous rate-limit key; original retained.')
        start = matches[0].end()
        value, length = json.JSONDecoder().raw_decode(text[start:])
        require(value == payload['rate_limits'], 'Rate-limit span differs from parsed value.')
        changed = (text[:start] + 'null' + text[start + length:]).encode('utf-8')
        expected = json.loads(raw)
        expected['payload']['rate_limits'] = None
        require(json.loads(changed) == expected, 'Non-account transcript content changed.')
        result.append(changed)
        changes.append({'line': number, 'json_path': 'payload.rate_limits',
                        'original_line_sha256': sha(raw), 'public_line_sha256': sha(changed)})
    return b''.join(result), changes


def credential_scan(name, data, known=()):
    require(Path(name).name not in {'auth.json', '.env', 'credentials.json'},
            'Credential-file name found; publication withheld.')
    require(not any(secret in data for secret in known),
            'Known credential value found; publication withheld without printing it.')
    scanned = data
    if name.endswith('.jsonl'):
        parsed = []
        for line in data.splitlines():
            try:
                row = json.loads(line)
            except (ValueError, UnicodeDecodeError):
                parsed.append(line)
                continue
            if isinstance(row, dict) and row.get('type') == 'response_item':
                payload = row.get('payload')
                if isinstance(payload, dict) and payload.get('type') == 'reasoning':
                    # Opaque native reasoning blobs can accidentally match key-shaped regexes.
                    # Known local credential values are still checked against original bytes above.
                    payload.pop('encrypted_content', None)
            def walk(value):
                if isinstance(value, dict):
                    for key, val in value.items():
                        require(key not in PRIVATE_FIELDS or val in (None, '', False),
                                'Unexpected private account field; publication withheld.')
                        if key == 'rate_limits':
                            require(val is None, 'Account usage limits were not redacted.')
                        walk(val)
                elif isinstance(value, list):
                    for val in value:
                        walk(val)
            walk(row)
            parsed.append(json.dumps(row).encode())
        scanned = b'\n'.join(parsed)
    require(all(sha(match.group()) in SYNTHETIC_KEYS.get(name, set())
                for match in SECRET.finditer(scanned)),
            'Possible credential outside opaque reasoning; publication withheld.')


def put(z, name, data):
    info = zipfile.ZipInfo(name, (1980, 1, 1, 0, 0, 0))
    info.compress_type = zipfile.ZIP_DEFLATED
    info.external_attr = 0o100644 << 16
    z.writestr(info, data)


def build_archive(source, destination, expected, known=()):
    require(safe(source) and source.is_file() and sha(source.read_bytes()) == expected,
            'Original archive is absent or changed: ' + source.name)
    output = io.BytesIO()
    with zipfile.ZipFile(source) as original, zipfile.ZipFile(output, 'w') as public:
        names = inventory(original)
        raw_manifest = original.read('review-manifest.json')
        original_manifest = json.loads(raw_manifest)
        files = original_manifest['files']
        require(names == set(files) | {'review-manifest.json'}, 'Original manifest membership differs.')
        changed = {}
        for name in sorted(names):
            data = original.read(name)
            if name != 'review-manifest.json':
                item = files[name]
                require(len(data) == item['bytes'] and sha(data) == item['sha256'],
                        'Original member hash differs: ' + name)
            derived, edits = scrub_usage(data) if name.endswith('.jsonl') else (data, [])
            credential_scan(name, derived, known)
            if edits:
                changed[name] = {'original_sha256': sha(data), 'original_bytes': len(data),
                    'public_sha256': sha(derived), 'public_bytes': len(derived), 'changes': edits}
            put(public, name, derived)
        declaration = {'schema': 'native-public-evidence-v1', 'original_archive_name': source.name,
            'original_archive_sha256': expected, 'original_manifest_sha256': sha(raw_manifest),
            'original_manifest_retained_unchanged': True, 'omitted_members': [],
            'changed_files': changed,
            'redaction': 'Only payload.rate_limits in native event_msg/token_count JSONL records is set to null. All other member bytes are unchanged.',
            'verification_limit': 'Public hashes verify supplied copies. Redacted original bytes cannot be rehashed from the public copies. The operator verified the transform against the original archives, which remain private and unchanged.'}
        put(public, 'publication-manifest.json', encoded(declaration))
    payload = output.getvalue()
    require(safe(destination) and (not destination.exists() or destination.read_bytes() == payload),
            'Different public archive already exists; retained.')
    destination.parent.mkdir(parents=True, exist_ok=True)
    if not destination.exists():
        with destination.open('xb') as stream:
            stream.write(payload)
    require(sha(source.read_bytes()) == expected, 'Original archive changed during publication preparation.')
    details = verify_archive(destination, expected)
    return {'sha256': sha(payload), 'bytes': len(payload), 'original_archive_name': source.name,
            'original_archive_sha256': expected, **details}


def verify_archive(path, expected_original):
    require(safe(path) and path.is_file(), 'Public archive is missing or unsafe.')
    with zipfile.ZipFile(path) as z:
        names = inventory(z)
        manifest_raw = z.read('review-manifest.json')
        original = json.loads(manifest_raw)['files']
        declaration = json.loads(z.read('publication-manifest.json'))
        require(declaration['schema'] == 'native-public-evidence-v1'
                and declaration['original_archive_sha256'] == expected_original
                and declaration['original_manifest_sha256'] == sha(manifest_raw)
                and declaration['original_manifest_retained_unchanged'] is True
                and declaration['omitted_members'] == [], 'Publication declaration differs.')
        require(names == set(original) | {'review-manifest.json', 'publication-manifest.json'},
                'Public archive membership differs.')
        changed = declaration['changed_files']
        require(set(changed) <= set(original), 'Unlisted redaction target.')
        events = 0
        for name, item in original.items():
            data = z.read(name)
            credential_scan(name, data)
            if name in changed:
                entry = changed[name]
                require(name.endswith('.jsonl') and entry['original_sha256'] == item['sha256']
                        and entry['original_bytes'] == item['bytes'], 'Redaction provenance differs.')
                require(sha(data) == entry['public_sha256'] and len(data) == entry['public_bytes'],
                        'Redacted file hash differs.')
                lines = data.splitlines(keepends=True)
                numbers = [v['line'] for v in entry['changes']]
                require(numbers and len(numbers) == len(set(numbers)), 'Redaction line list is empty or repeated.')
                for edit in entry['changes']:
                    require(edit['json_path'] == 'payload.rate_limits' and 1 <= edit['line'] <= len(lines),
                            'Unexpected redaction field or line.')
                    line = lines[edit['line'] - 1]
                    row = json.loads(line)
                    require(sha(line) == edit['public_line_sha256'] and row['type'] == 'event_msg'
                            and row['payload']['type'] == 'token_count' and row['payload']['rate_limits'] is None,
                            'Declared account-limit redaction differs.')
                events += len(numbers)
            else:
                require(sha(data) == item['sha256'] and len(data) == item['bytes'],
                        'Unchanged original member differs: ' + name)
    return {'original_manifest_entries': len(original), 'redacted_files': len(changed),
            'redacted_usage_events': events, 'unchanged_original_members': len(original) - len(changed)}


def verify(root=ROOT):
    packet = json.loads((root / MANIFEST).read_text())
    require(packet['schema'] == 'native-history-publication-v1'
            and packet['independent_human_review'] == 'pending', 'Unexpected publication status.')
    for name, digest in packet['file_sha256'].items():
        member(name)
        path = root / name
        require(safe(path) and path.is_file() and sha(path.read_bytes()) == digest,
                'Published file differs: ' + name)
    for name, digest in packet['frozen_main_source_sha256'].items():
        member(name)
        path = root / name
        require(safe(path) and path.is_file() and sha(path.read_bytes()) == digest,
                'Frozen collection source differs: ' + name)
    totals = Counter()
    require(len(packet['archives']) == len(ARCHIVES), 'Archive set is incomplete.')
    require(set(packet['archives']) <= set(packet['file_sha256']),
            'An archive is not covered by the publication file hashes.')
    originals = set()
    for name, entry in packet['archives'].items():
        member(name)
        require(name.startswith(EVIDENCE.as_posix() + '/') and (root / name).stat().st_size == entry['bytes'],
                'Archive location or recorded size differs.')
        original = entry['original_archive_name']
        require(original in ARCHIVES and entry['original_archive_sha256'] == ARCHIVES[original],
                'Unexpected original archive.')
        originals.add(original)
        details = verify_archive(root / name, ARCHIVES[original])
        require(all(entry[key] == value for key, value in details.items()), 'Archive counts differ.')
        totals.update(details)
    require(originals == set(ARCHIVES), 'Duplicate or missing original archive.')
    return {'archives': len(originals), **dict(totals),
            'frozen_main_sources': len(packet['frozen_main_source_sha256']),
            'independent_human_review': 'pending'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.parse_args()
    try:
        result = verify()
        print(json.dumps(result, indent=2))
        print('NATIVE PUBLICATION FILE CHECKS PASSED')
        print('These checks verify public-copy consistency, not independent scientific review.')
        print('No experiment, model call, Docker operation, upload, or original-file change was made.')
    except (OSError, ValueError, KeyError, zipfile.BadZipFile) as exc:
        print('STOP:', type(exc).__name__, str(exc), file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
