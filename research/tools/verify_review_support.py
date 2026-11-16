"""Verify published supporting archives without extracting or executing their contents."""

from datetime import datetime
import hashlib
import json
from pathlib import Path, PurePosixPath
import zipfile

ROOT = Path(__file__).resolve().parents[2]
SUPPORT = Path('research/reviews/initial-replication-support')
DOCKER = Path('research/reviews/permission-probe-02-docker')
BASELINE_ARCHIVE_SHA = 'a506545f1d2392be168013e75b9d7d6b4daa9586f8f31c07cee1cb38f692cda2'
DOCKER_ARCHIVE_SHA = '2d9b7c71ad53914c74e46ef77b008671fda6364d2538eacbd7eac671b73588b9'
SOURCE_COMMIT = 'a329127f573bfb7088dc38e3d60a6183f7f17f35'
IMAGE = 'sha256:eddc3b1939fb346372fe8e6aa2806f1bb03696867704f3e70143e12492115aa5'


def require(value, message):
    if not value:
        raise ValueError(message)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def read(path):
    return json.loads(path.read_text(encoding='utf-8'))


def archive_files(path, expected):
    require(not path.is_symlink() and digest(path.read_bytes()) == expected,
            'Archive bytes differ: ' + str(path))
    with zipfile.ZipFile(path) as archive:
        names = archive.namelist()
        require(len(names) == len(set(names)), 'Duplicate archive entry.')
        for name in names:
            parts = PurePosixPath(name)
            require(not parts.is_absolute() and '..' not in parts.parts
                    and '\\' not in name and not name.endswith('/'),
                    'Unexpected archive path.')
        require(archive.testzip() is None, 'Archive CRC failure.')
        return {name: archive.read(name) for name in names}


def verify_inventory(files, manifest_name):
    manifest = json.loads(files[manifest_name])
    require(set(manifest['files']) == set(files) - {manifest_name},
            'Archive inventory differs.')
    for name, entry in manifest['files'].items():
        require(digest(files[name]) == entry['sha256']
                and len(files[name]) == entry['bytes'], 'File digest differs: ' + name)
    return manifest


def coverage_counts(observations):
    groups = ('rows', 'legit_controls', 'descriptor_controls', 'suppression_controls')
    rows = [row for group in groups for row in observations[group]]
    missing = sum(row.get('verdict') == 'not_run' for row in rows)
    fills = [row for row in observations['suppression_controls']
             if row['operation'].startswith('fill_filesystem_')]
    return {
        'recorded_cells': len(rows), 'executed_cells': len(rows) - missing,
        'not_run_cells': missing,
        'disk_fill_cells_executed_in_docker': sum(row['verdict'] != 'not_run' for row in fills),
        'disk_fill_cells_not_run_in_docker': sum(row['verdict'] == 'not_run' for row in fills),
    }


def verify(root=ROOT):
    originals = archive_files(root / SUPPORT / 'evidence-originals.zip', BASELINE_ARCHIVE_SHA)
    inventory = verify_inventory(originals, 'supplement/manifest.json')
    require(inventory['missing_optional_support'] == [], 'Missing supporting files.')
    pilot = read(root / 'research/results/pilot-financial-full-01-summary.json')
    decisions = read(root / 'research/reviews/baseline-financial-full-01/review-decisions.json')
    anchors = [(pilot['run_folder_relative'], pilot['source_sha256'])]
    for attempt in decisions['attempts']:
        if attempt['attempt'] in (3, 10):
            prefix = f"runs/baseline-financial-full-01/attempt-{attempt['attempt']:02d}/artifacts/"
            folder = next(name.rsplit('/', 1)[0] for name in originals
                          if name.startswith(prefix) and name.endswith('/run.json'))
            anchors.append((folder, attempt['source_sha256']))
    require(len(anchors) == 3, 'Missing original-stream anchors.')
    for folder, hashes in anchors:
        require(set(hashes) == {'run.json', 'report.json', 'codex.jsonl', 'observer.jsonl'},
                'Unexpected original-file set.')
        for name, expected in hashes.items():
            require(digest(originals[folder + '/' + name]) == expected,
                    'Published original anchor differs: ' + folder + '/' + name)
    plan = json.loads(originals['runs/baseline-financial-full-01/plan.json'])
    require(plan['git_commit'] == 'c65e00aac7a6d85baa5fedbcb28e5a2b74684c99',
            'Recorded base commit differs.')
    frozen = read(root / 'research/manifests/initial-replication.json')['frozen_experiment_source_sha256']
    require(plan['source_sha256'] == frozen and len(frozen) == 96, 'Frozen source inventory differs.')
    for name, expected in frozen.items():
        require(digest(originals['source-snapshot/' + name]) == expected
                and digest((root / name).read_bytes()) == expected,
                'Frozen source differs: ' + name)
    protocol = 'research/protocols/financial-full-baseline-01.md'
    require(originals['source-snapshot/' + protocol] == (root / protocol).read_bytes(),
            'Recorded protocol differs.')
    timeline = json.loads(originals['supplement/timeline.json'])
    third = json.loads(originals['runs/baseline-financial-full-01/attempt-03/attempt.json'])
    fourth = json.loads(originals['runs/baseline-financial-full-01/attempt-04/attempt.json'])
    delta = (datetime.fromisoformat(fourth['started_at']) -
             datetime.fromisoformat(third['finished_at'])).total_seconds()
    require(delta == timeline['gap_seconds_from_ledger'] == 1589.888515, 'Timeline differs.')

    docker = archive_files(root / DOCKER / 'validation-originals.zip', DOCKER_ARCHIVE_SHA)
    export = verify_inventory(docker, 'export-manifest.json')
    require(export['source_commit'] == SOURCE_COMMIT and export['tracked_source_changes'] == ''
            and export['missing_files'] == [], 'Validation source/export state differs.')
    require(docker['probe-exit-code.txt'].strip() == b'0'
            and docker['comparison-exit-code.txt'].strip() == b'0'
            and not docker['comparison-errors.txt'].strip(), 'Probe/comparison did not finish cleanly.')
    evidence = json.loads(docker['evidence.json'])
    run = evidence['run']
    require(run['status'] == 'finished' and run['error'] is None
            and run['image_id'] == IMAGE and run['mode'] == 'docker'
            and run['cleanup_verified'] is True and run['model_calls'] == 0,
            'Docker run completion/configuration differs.')
    comparison = json.loads(docker['comparison.json'])
    require(comparison['compared_measurements'] == 495
            and comparison['verdict_differences'] == []
            and len(comparison['not_run_vs_measured_differences']) == 28
            and comparison['identical_verdicts'] is True
            and comparison['identical'] is False
            and comparison['environment_identical'] is False, 'Recorded comparison differs.')
    assessment = read(root / DOCKER / 'coverage-assessment.json')
    counts = coverage_counts(evidence['observations'])
    require(all(assessment[key] == value for key, value in counts.items()), 'Coverage counts differ.')
    require(counts == {'recorded_cells': 495, 'executed_cells': 439, 'not_run_cells': 56,
                       'disk_fill_cells_executed_in_docker': 0,
                       'disk_fill_cells_not_run_in_docker': 30}, 'Unexpected probe coverage.')
    require(assessment['both_suppression_operations_resisted'].startswith('undetermined:'),
            'Skipped disk-fill cells must not be treated as demonstrated resistance.')
    require(assessment['archive_sha256'] == DOCKER_ARCHIVE_SHA
            and assessment['source_commit'] == SOURCE_COMMIT
            and assessment['native_agent_integration_tested'] is False,
            'Coverage provenance or scope differs.')
    return {'original_stream_files_anchored': 12, 'frozen_python_sources': 96,
            'docker_executed_cells': 439, 'docker_not_run_cells': 56,
            'independent_raw_review': 'pending'}


if __name__ == '__main__':
    try:
        print(json.dumps(verify(), indent=2))
        print('REVIEW SUPPORT VERIFIED')
        print('No model, Docker, network call or archived-code execution was made.')
    except (OSError, ValueError, KeyError, zipfile.BadZipFile) as error:
        raise SystemExit('STOP: ' + str(error))
