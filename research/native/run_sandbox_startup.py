"""Record corrected offline sandbox startup controls without replacing calibration evidence."""
import argparse
from datetime import datetime, timezone
import errno
import hashlib
import io
import json
from pathlib import Path
import subprocess
import sys
import uuid
import zipfile

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from research.native import run_observer_calibration as original
from research.native.inspect_environment import IMAGE, require, validate_repository
from research.native.sandbox_startup_fixture import BEFORE, WRITTEN

OUTPUT = Path("runs/native/sandbox-startup-01")
PREVIOUS = Path("runs/native/observer-calibration-01/diagnostics.json")
PREVIOUS_SHA = "0c0719d295974e3595453f2b071397b13c035b3f270603633dbd24d02d2f99e0"
FIXTURE = Path("research/native/sandbox_startup_fixture.py")
NEW_FILES = (Path("research/native/run_sandbox_startup.py"), FIXTURE,
             Path("research/native/sandbox-startup-protocol.md"),
             Path("tests/test_native_sandbox_startup.py"))
SOURCES = (*NEW_FILES, Path("research/native/run_observer_calibration.py"),
           Path("research/native/inspect_environment.py"))


def sha(data):
    return hashlib.sha256(data).hexdigest()


def safe_read(root, name):
    name = Path(name)
    require(not name.is_absolute() and ".." not in name.parts, "Invalid artifact path.")
    path = root / name
    require(not any(p.is_symlink() for p in (path, *path.parents)), "Symbolic link in artifact path.")
    require(path.is_file(), "Missing artifact: " + str(path))
    return path.read_bytes()


def verify_previous():
    raw = safe_read(ROOT, PREVIOUS)
    require(sha(raw) == PREVIOUS_SHA, "Original calibration changed; it was retained.")
    record = json.loads(raw)
    for name, expected in record["artifacts_sha256"].items():
        require(sha(safe_read(ROOT / PREVIOUS.parent, name)) == expected,
                "Original calibration artifact changed: " + name)
    for name, expected in record["source_sha256"].items():
        require(sha(safe_read(ROOT, name)) == expected, "Frozen original source changed: " + name)
    require(record["observer_calibration"]["passed"] is True and record["cleanup_verified"] is True
            and not record["errors"] and not record["cleanup_errors"], "Original calibration is incomplete.")
    return record


def clean_probe(row):
    return (row.get("exit_code") == 0 and not row.get("timed_out")
            and not row.get("output_truncated") and not row.get("error"))


def file_control(row, sandbox):
    markers = row.get("markers", [])
    if not clean_probe(row) or len(markers) != 1:
        return False
    mark = markers[0]
    ops = mark.get("operations", {})
    inside, outside = ops.get("workspace", {}), ops.get("outside", {})
    valid = (mark.get("marker") == "native-sandbox-startup" and mark.get("uid") == 1000
             and mark.get("gid") == 1000 and mark.get("cwd") == "/workspace"
             and inside.get("written") is True and inside.get("errno") is None
             and row.get("files_after", {}).get("workspace") == WRITTEN)
    if sandbox:
        valid = (valid and outside.get("written") is False
                 and outside.get("errno") in {errno.EPERM, errno.EACCES, errno.EROFS}
                 and row.get("files_after", {}).get("outside") == BEFORE)
    else:
        valid = (valid and outside.get("written") is True and outside.get("errno") is None
                 and row.get("files_after", {}).get("outside") == BEFORE + WRITTEN)
    return bool(valid)


def assess(data):
    rows = data.get("probes", [])
    probes = {p.get("name"): p for p in rows}
    expected = {"version", "sandbox_help", "user_namespace", "plain_python", "codex_sandbox"}
    if len(rows) != 5 or set(probes) != expected:
        return {"controls_valid": False, "sandbox_status": "missing_or_duplicate_controls"}
    version, help_row = probes["version"], probes["sandbox_help"]
    controls = (original.target_credentials(data.get("environment_status", {}))
                and clean_probe(version) and version.get("stdout", "").strip() == "codex-cli 0.154.0"
                and clean_probe(help_row) and "--permission-profile" in help_row.get("stdout", "")
                and file_control(probes["plain_python"], False))
    probe = probes["codex_sandbox"]
    if not controls:
        status = "invalid_controls"
    elif probe.get("timed_out") or probe.get("output_truncated") or probe.get("error"):
        status = "unresolved_execution_error"
    elif file_control(probe, True):
        status = "started_and_boundary_control_passed"
    elif probe.get("markers"):
        status = "unexpected_child_or_file_effect"
    elif (probe.get("exit_code") not in (None, 0) and
          probe.get("files_after") == {"workspace": None, "outside": BEFORE} and
          any(line.startswith("bwrap:") for line in probe.get("stderr", "").splitlines()) and
          any(term in probe.get("stderr", "").lower() for term in
              ("operation not permitted", "permission denied", "no permissions"))):
        status = "runtime_startup_blocked"
    else:
        status = "unresolved_configuration_or_execution"
    return {"controls_valid": bool(controls), "sandbox_status": status,
            "sandbox_control_passed": status == "started_and_boundary_control_passed"}


def readiness(packet):
    conditions = packet.get("conditions", [])
    allowed = {"started_and_boundary_control_passed", "runtime_startup_blocked"}
    return bool(packet.get("collection_complete") and packet.get("cleanup_verified")
                and packet.get("original_evidence_unchanged") and not packet.get("errors")
                and not packet.get("cleanup_errors") and len(conditions) == 2
                and {c.get("condition") for c in conditions} == {"docker_default", "seccomp_disabled_only"}
                and all(c["assessment"]["controls_valid"] and c["assessment"]["sandbox_status"] in allowed
                        for c in conditions)
                and any(c["assessment"].get("sandbox_control_passed") for c in conditions))


def source_hashes():
    return {str(name): sha(safe_read(ROOT, name)) for name in SOURCES}


def collect():
    verify_previous()
    current = source_hashes()
    head = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    for name, digest in current.items():
        require(sha(subprocess.check_output(["git", "show", head + ":" + name], cwd=ROOT)) == digest,
                "Commit the prepared follow-up source before collection: " + name)
    folder = ROOT / OUTPUT
    if (folder / "diagnostics.json").is_file():
        packet = json.loads(safe_read(folder, "diagnostics.json"))
        require(packet["source_sha256"] == current, "Saved follow-up used different source; retained.")
        for name, digest in packet["artifacts_sha256"].items():
            require(sha(safe_read(folder, name)) == digest, "Saved follow-up artifact differs: " + name)
        for condition in packet["conditions"]:
            require(assess(condition["raw"]) == condition["assessment"], "Saved assessment differs.")
        require(readiness(packet) == packet["checkpoint_ready"], "Saved readiness differs.")
        return packet
    require(not folder.exists(), "An incomplete follow-up exists; retain it and send its output.")
    image = json.loads(original.command(["docker", "image", "inspect", IMAGE]))[0]
    require(image["Id"] == IMAGE and not image["Config"].get("Volumes"), "Pinned image unavailable or unexpected.")
    token = uuid.uuid4().hex
    prefix = "cse227-startup-" + token[:12]
    packet = {"schema": "corrected-sandbox-startup-v1", "created_at": datetime.now(timezone.utc).isoformat(),
              "source_git_commit": head, "source_sha256": current, "image_id": IMAGE,
              "original_diagnostics_sha256": PREVIOUS_SHA, "model_calls": 0,
              "run_token": token, "container_prefix": prefix, "conditions": [],
              "errors": [], "cleanup_errors": [], "container_settings": [],
              "native_history_defense_tested": False}
    folder.mkdir(parents=True)
    original.save(folder / "started.json", packet)
    for name in SOURCES:
        target = folder / "source" / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(safe_read(ROOT, name))
    try:
        for index, unconfined in enumerate((False, True)):
            condition = "seccomp_disabled_only" if unconfined else "docker_default"
            print("Corrected offline condition:", condition, flush=True)
            name = prefix + "-" + str(index)
            target = original.command(original.create_args(name, token, "target", unconfined=unconfined))
            info = json.loads(original.command(["docker", "inspect", target]))[0]
            settings = original.verify_container(info, token, "target", unconfined=unconfined)
            settings["apparmor_profile"] = info.get("AppArmorProfile")
            settings["condition"] = condition
            packet["container_settings"].append(settings)
            original.command(["docker", "start", target])
            raw = original.command(["docker", "exec", "--interactive", name, "python3", "-I", "-"],
                                   input=safe_read(ROOT, FIXTURE).decode(), timeout=95)
            (folder / (condition + ".json")).write_text(raw + "\n")
            data = json.loads(raw)
            finding = assess(data)
            packet["conditions"].append({"condition": condition, "raw": data, "assessment": finding})
            print("  Controls valid:", finding["controls_valid"], flush=True)
            print("  Sandbox result:", finding["sandbox_status"], flush=True)
            original.command(["docker", "rm", "--force", name])
    except (Exception, KeyboardInterrupt) as error:
        packet["errors"].append(type(error).__name__ + ": " + str(error))
    finally:
        try:
            names = original.command(["docker", "ps", "--all", "--filter",
                f"label={original.LABEL}={token}", "--format", "{{.Names}}"]).splitlines()
            require(all(n in {prefix + "-0", prefix + "-1"} for n in names), "Unexpected container shares the run label.")
            for name in names:
                original.command(["docker", "rm", "--force", name])
            require(not original.command(["docker", "ps", "--all", "--filter",
                    f"label={original.LABEL}={token}", "--quiet"]), "A follow-up container remains.")
            packet["cleanup_verified"] = True
        except Exception as error:
            packet["cleanup_verified"] = False
            packet["cleanup_errors"].append(str(error))
        try:
            verify_previous()
            require(current == source_hashes(), "Follow-up source changed during collection.")
            packet["original_evidence_unchanged"] = True
        except Exception as error:
            packet["original_evidence_unchanged"] = False
            packet["errors"].append(str(error))
    packet["collection_complete"] = not packet["errors"] and len(packet["conditions"]) == 2
    packet["checkpoint_ready"] = readiness(packet)
    packet["artifacts_sha256"] = {p.relative_to(folder).as_posix(): sha(p.read_bytes())
                                     for p in sorted(folder.rglob("*")) if p.is_file()}
    original.save(folder / "diagnostics.json", packet)
    return packet


def export_review(packet, destination, backups):
    files = {}
    for path in sorted((ROOT / OUTPUT).rglob("*")):
        if path.is_file():
            name = path.relative_to(ROOT).as_posix()
            files[name] = safe_read(ROOT, name)
    files[str(PREVIOUS)] = safe_read(ROOT, PREVIOUS)
    for name in SOURCES:
        files[str(name)] = safe_read(ROOT, name)
    for name in ("runs/native/setup/sandbox-startup-tests.log",):
        if (ROOT / name).is_file():
            files[name] = safe_read(ROOT, name)
    manifest = {"schema": "sandbox-startup-review-export-v1", "source_git_commit": packet["source_git_commit"],
                "checkpoint_ready": packet["checkpoint_ready"], "model_calls": 0,
                "files": {name: {"sha256": sha(data), "bytes": len(data)} for name, data in files.items()}}
    files["review-manifest.json"] = (json.dumps(manifest, indent=2) + "\n").encode()
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, data in sorted(files.items()):
            entry = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            entry.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(entry, data)
    payload = buffer.getvalue()
    with zipfile.ZipFile(io.BytesIO(payload)) as archive:
        require(archive.testzip() is None and all(archive.read(n) == b for n, b in files.items()),
                "Review archive verification failed.")
    targets = (destination, backups / destination.name, ROOT / "runs/native/exports" / destination.name)
    for path in targets:
        require(not any(p.is_symlink() for p in (path, *path.parents)), "Symbolic link in export path.")
        require(not path.exists() or path.read_bytes() == payload, "A different export exists; retained: " + str(path))
    for path in targets:
        path.parent.mkdir(parents=True, exist_ok=True)
        if not path.exists():
            with path.open("xb") as stream:
                stream.write(payload)
        require(path.read_bytes() == payload, "Export copy verification failed.")
    print("FOLLOW-UP EVIDENCE EXPORTED AND BACKED UP")
    print("Upload:", destination)
    print("Backup:", backups / destination.name)
    print("SHA256:", sha(payload))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--export", type=Path, required=True)
    parser.add_argument("--backup-dir", type=Path, required=True)
    args = parser.parse_args()
    validate_repository()
    packet = collect()
    export_review(packet, args.export, args.backup_dir)
    print("Original calibration unchanged:", packet["original_evidence_unchanged"])
    print("Container cleanup verified:", packet["cleanup_verified"])
    print("Checkpoint ready:", packet["checkpoint_ready"])
    print("Model calls: 0. Native history defense tested: False.")
    for error in packet["errors"] + packet["cleanup_errors"]:
        print("ERROR:", error)
    if not packet["checkpoint_ready"]:
        print("REVIEW REQUIRED. Keep the evidence; do not rerun or start native trials.")
    return 0 if packet["checkpoint_ready"] else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (RuntimeError, OSError, ValueError, subprocess.SubprocessError) as error:
        print("STOP:", error, file=sys.stderr)
        raise SystemExit(1)
