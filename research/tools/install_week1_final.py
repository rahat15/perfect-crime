"""Install the final documentation revision with backups and exact-file checks."""

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import zipfile

FILES = (
    "research/tools/finalize_week1.py",
    "research/tools/pause_checkpoint.py",
    "research/tools/build_pilot_review.py",
    "research/tools/install_week1_final.py",
    "tests/test_week1_handoff.py",
    "tests/test_week1_documentation_update.py",
    "research/README.md",
    "research/reviews/pilot-financial-full-01/README.md",
    "research/reviews/permission-probe-01/evidence.json",
    "research/reviews/permission-probe-01/README.md",
)
RETIRED = (
    "research/reviews/pilot-financial-full-01/review-template.md",
    "research/handoffs/review-template.md",
)
MANIFEST = "research/handoffs/week1-manifest.json"
PRIOR = {'research/tools/finalize_week1.py': ['b096316ba296222905ca62f3997ed2d9a2d6ed76969c427a71b8efa42365d5c2'], 'research/tools/pause_checkpoint.py': ['389b4cd346fede95347bf3d15a7fe8a94284ada6cadfe22338e81e77d87c0d9d', '93d4ef73617fce0fe38e6c1c9d1acbca53480d634c149c4772e6978019c4783b', '2d814d2e759b654c7868cbf96f6c56fc20edb8e9636ef3a1b6915081e9369e61'], 'tests/test_week1_handoff.py': ['cad5855ab15143808d31d97f4dafe84232936e1263bd36489930eebc0687f72c'], 'research/README.md': ['625072f0d90826610d3db30b9f361f8a11177474933f613d3613829a662c988f'], 'research/tools/build_pilot_review.py': ['3b7d21c35f28ee505d3c0ae375041a0716de65a1f0444957d343e8a95f8df0b9'], 'research/reviews/pilot-financial-full-01/README.md': ['fc52476435a1333301c0b988352f13a4abee21be16542e3f3e9195f3ae456ee1'], 'research/handoffs/review-template.md': ['fdcfa5feed1c1f3f9c3bdfdf6713a62b9c5e478eb865dd82719ed737d7522274'], 'research/reviews/pilot-financial-full-01/review-template.md': ['4f3615c04d8df9bc9f8acad1a700c232561a5cfa8759977d4e5bc949587307b9'], 'research/reviews/permission-probe-01/README.md': ['2eed7bef33cb00160f516ca838be48daf82a14caff62f6740c2e8a99889bb4e7']}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest(content):
    return hashlib.sha256(content).hexdigest()


def install(root, archive, expected_hash):
    require(root.resolve() == Path.cwd().resolve(), "Run from the project root.")
    require(subprocess.check_output(["git", "branch", "--show-current"], text=True).strip()
            == "reproduce-financial", "Expected reproduce-financial branch.")
    require(archive.is_file() and digest(archive.read_bytes()) == expected_hash,
            "The downloaded ZIP is missing or differs from the expected file.")
    with zipfile.ZipFile(archive) as package:
        names = package.namelist()
        require(len(names) == len(FILES) and set(names) == set(FILES), "Unexpected ZIP file inventory.")
        require(package.testzip() is None, "The ZIP is damaged.")
        contents = {name: package.read(name) for name in names}
    # Experiment code and original evidence are not migration destinations.
    plan = json.loads((root / "runs/baseline-financial-full-01/plan.json").read_text())
    require(all((root / name).is_file() and digest((root / name).read_bytes()) == value
                for name, value in plan["source_sha256"].items()), "Frozen experiment source changed.")
    require(not set(contents).intersection(plan["source_sha256"]), "Installation would change frozen source.")
    for name, content in contents.items():
        path = root / name
        require(not path.is_symlink(), "A destination is a symbolic link: " + name)
        if path.exists():
            require(path.is_file() and digest(path.read_bytes()) in
                    set(PRIOR.get(name, [])) | {digest(content)},
                    "An existing file has unrecognized edits; it was retained: " + name)
    for name in RETIRED:
        path = root / name
        require(not path.is_symlink(), "A retired path is a symbolic link: " + name)
        require(not path.exists() or (path.is_file() and digest(path.read_bytes()) in PRIOR[name]),
                "A coordination template contains unrecognized changes; it was retained: " + name)
    manifest = root / MANIFEST
    retire_manifest = False
    if manifest.exists():
        require(manifest.is_file() and not manifest.is_symlink(), "Unexpected manifest path.")
        value = json.loads(manifest.read_text())
        require(value.get("schema") in {"initial-replication-handoff-v1", "initial-replication-handoff-v2"},
                "Unknown existing handoff manifest; it was retained.")
        require(bool(value.get("public_file_sha256")), "Existing manifest has no file hashes.")
        for name, expected in value["public_file_sha256"].items():
            path = Path(name)
            require(not path.is_absolute() and ".." not in path.parts, "Unsafe manifest path.")
            require((root / path).is_file() and digest((root / path).read_bytes()) == expected,
                    "An existing manifest file changed; it was retained: " + name)
        retire_manifest = value["schema"] == "initial-replication-handoff-v1"
    tag = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    backup = root / "runs/setup" / ("before-week1-final-" + tag)
    backup.mkdir(parents=True)
    affected = list(contents) + list(RETIRED) + ([MANIFEST] if retire_manifest else [])
    original_hashes = {}
    for name in affected:
        path = root / name
        if path.is_file():
            destination = backup / name
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(path, destination)
            original_hashes[name] = digest(path.read_bytes())
            require(digest(destination.read_bytes()) == original_hashes[name], "Pre-update backup failed.")
    (backup / "original-sha256.json").write_text(json.dumps(original_hashes, indent=2) + "\n")
    for name, content in contents.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
    for name in RETIRED + ((MANIFEST,) if retire_manifest else ()):
        path = root / name
        if path.exists():
            path.unlink()
    require(all(digest((root / name).read_bytes()) == value
                for name, value in plan["source_sha256"].items()), "Frozen source changed during installation.")
    print("FINAL WEEK 1 KIT INSTALLED")
    print("Previous files backed up to:", backup)
    print("Coordination templates removed locally; research evidence retained.")
    print("No experiment, model call or GitHub upload was made.")
    return backup


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", type=Path, required=True)
    parser.add_argument("--sha256", required=True)
    args = parser.parse_args()
    install(Path.cwd(), args.archive, args.sha256)


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, KeyError, TypeError, zipfile.BadZipFile, subprocess.CalledProcessError) as error:
        raise SystemExit("STOP: " + str(error))
