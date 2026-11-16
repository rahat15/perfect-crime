"""Verify and archive local native-observation code and evidence without publishing it."""
import argparse
from datetime import datetime, timezone
import hashlib
import io
import json
from pathlib import Path
import re
import subprocess
import sys
import tarfile
import zipfile

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from research.native.inspect_environment import validate_repository, require

NATIVE_TESTS = tuple(Path("tests") / name for name in (
    "test_native_environment_inventory.py", "test_native_observer_calibration.py",
    "test_native_observer_collection.py", "test_native_checkpoint.py"))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--label", required=True)
    parser.add_argument("--backup-dir", type=Path, required=True)
    parser.add_argument("--export", type=Path)
    args = parser.parse_args()
    require(re.fullmatch(r"[a-z0-9-]{1,48}", args.label), "Invalid checkpoint label.")
    validate_repository()
    require(not args.backup_dir.resolve().is_relative_to(ROOT.resolve()),
            "Choose a backup directory outside the project.")
    files = {ROOT / "research/tools/pause_checkpoint.py",
             ROOT / "research/manifests/initial-replication.json"}
    files.update(ROOT / name for name in NATIVE_TESTS)
    for directory in (ROOT / "research/native", ROOT / "runs/native"):
        for path in directory.rglob("*"):
            if "__pycache__" in path.parts or path.suffix == ".pyc":
                continue
            require(not path.is_symlink(), "Unexpected symbolic link; retained: " + str(path))
            if path.is_file():
                files.add(path)
    require(all(path.is_file() and not path.is_symlink() for path in files),
            "A checkpoint input is missing or is a symbolic link.")
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    state_file = ROOT / "runs/native/checkpoints" / (stamp + ".json")
    state_file.parent.mkdir(parents=True, exist_ok=True)
    state = {"label": args.label, "created_at": datetime.now(timezone.utc).isoformat(),
             "branch": subprocess.check_output(["git", "branch", "--show-current"], text=True).strip(),
             "head": subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip(),
             "scope": "Native-observation code and evidence; earlier replication archives retained.",
             "github_upload": False}
    with state_file.open("x", encoding="utf-8") as stream:
        json.dump(state, stream, indent=2)
        stream.write("\n")
    files.add(state_file)
    expected = {path.relative_to(ROOT).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
                for path in sorted(files)}
    args.backup_dir.mkdir(parents=True, exist_ok=True)
    archive = args.backup_dir / ("native-" + args.label + "-" + stamp + ".tar.gz")
    with tarfile.open(archive, "x:gz") as package:
        for path in sorted(files):
            package.add(path, arcname=path.relative_to(ROOT).as_posix(), recursive=False)
    with tarfile.open(archive, "r:gz") as package:
        actual = {}
        for member in package.getmembers():
            require(member.isfile() and member.name not in actual, "Unexpected backup entry.")
            stream = package.extractfile(member)
            require(stream is not None, "Unreadable backup entry.")
            actual[member.name] = hashlib.sha256(stream.read()).hexdigest()
        require(actual == expected, "Backup verification failed; retain the archive and send the output.")
    print("NATIVE OBSERVATION BACKUP VERIFIED")
    print("Files:", len(expected))
    print("Backup:", archive)
    print("Earlier backups retained. No GitHub upload or model call was made.")
    if args.export:
        export_files = {}
        for directory in (ROOT / "research/native", ROOT / "runs/native/observer-calibration-01"):
            for path in sorted(directory.rglob("*")):
                if path.is_file() and "__pycache__" not in path.parts and path.suffix != ".pyc":
                    require(not path.is_symlink(), "Unexpected symbolic link in review files.")
                    export_files[path.relative_to(ROOT).as_posix()] = path.read_bytes()
        for path in sorted(ROOT / name for name in NATIVE_TESTS):
            require(not path.is_symlink(), "Unexpected symbolic link in review tests.")
            export_files[path.relative_to(ROOT).as_posix()] = path.read_bytes()
        for name in ("runs/native/environment-inventory-01/environment.json",
                     "runs/native/setup/observer-tool-tests.log",
                     "runs/native/setup/observer-calibration-01.log",
                     "runs/native/setup/observer-calibration-exit-code.txt"):
            path = ROOT / name
            if path.is_file():
                require(not path.is_symlink(), "Unexpected symbolic link in review logs.")
                export_files[name] = path.read_bytes()
        manifest = {"schema": "native-observer-review-export-v1", "branch": state["branch"],
                    "head": state["head"], "model_calls": 0, "github_upload": False,
                    "files": {name: {"sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data)}
                              for name, data in sorted(export_files.items())}}
        export_files["review-manifest.json"] = (json.dumps(manifest, indent=2) + "\n").encode()
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as package:
            for name, data in sorted(export_files.items()):
                entry = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
                entry.compress_type = zipfile.ZIP_DEFLATED
                package.writestr(entry, data)
        payload = buffer.getvalue()
        with zipfile.ZipFile(io.BytesIO(payload)) as package:
            require(package.testzip() is None and all(package.read(name) == data
                                                     for name, data in export_files.items()),
                    "Review export verification failed.")
        local_export = ROOT / "runs/native/exports" / args.export.name
        destinations = (args.export, local_export, args.backup_dir / args.export.name)
        for destination in destinations:
            require(not destination.is_symlink() and (
                not destination.exists() or destination.read_bytes() == payload),
                "A different review ZIP exists; it was retained: " + str(destination))
        require(args.export.parent.is_dir(), "The export directory does not exist.")
        for destination in destinations:
            destination.parent.mkdir(parents=True, exist_ok=True)
            if not destination.exists():
                with destination.open("xb") as stream:
                    stream.write(payload)
        print("NATIVE OBSERVER REVIEW EXPORT VERIFIED")
        print("Upload this ZIP here:", args.export)
        print("Local copy:", local_export)
        print("Backup copy:", args.backup_dir / args.export.name)
        print("SHA256:", hashlib.sha256(payload).hexdigest())


if __name__ == "__main__":
    try:
        main()
    except (RuntimeError, OSError, ValueError, subprocess.SubprocessError) as error:
        print("STOP:", error, file=sys.stderr)
        raise SystemExit(1)
