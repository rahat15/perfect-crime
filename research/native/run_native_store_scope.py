"""Inspect native store roles offline without changing the original observation."""
import argparse
import base64
from datetime import datetime, timezone
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
from research.native import inspect_environment as environment
from research.native import review_native_identity as previous
from research.native import native_store_fixture as fixture

BASE = "0878cc53371000f1bded33a03494565bc6be9a7a"
OUTPUT = Path("runs/native/native-store-scope-01")
FILES = (
    "research/native/native_store_fixture.py",
    "research/native/run_native_store_scope.py",
    "research/native/native-store-scope-protocol.md",
    "research/analysis/native-store-source-review.md",
    "research/native/native-store-source-references.json",
    "tests/test_native_store_scope.py",
)
DEPENDENCIES = ("research/native/inspect_environment.py", "research/native/review_native_identity.py")


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def safe(path):
    return not any(p.is_symlink() for p in (path, *path.parents))


def git(*args):
    return subprocess.check_output(["git", *args], cwd=ROOT, text=True).strip()


def command(argv, timeout=30, input=None):
    return subprocess.run(argv, input=input, capture_output=True, text=True, timeout=timeout)


def checked(argv, timeout=30, input=None):
    result = command(argv, timeout, input)
    require(result.returncode == 0, "Command failed: " + argv[0] + "\n" + result.stderr[-2500:])
    return result.stdout


def save(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    require(safe(path), "A report path is a symbolic link.")
    with path.open("x", encoding="utf-8") as stream:
        json.dump(value, stream, indent=2)
        stream.write("\n")


def source_snapshot():
    require(Path.cwd().resolve() == ROOT, "Run from the project directory.")
    require(git("branch", "--show-current") == "native-history-defense", "Unexpected branch.")
    checked(["git", "merge-base", "--is-ancestor", BASE, "HEAD"])
    require(not git("status", "--porcelain", "--untracked-files=no"), "Tracked files changed and were retained.")
    commit = git("rev-parse", "HEAD")
    source = {}
    for name in FILES + DEPENDENCIES:
        path = ROOT / name
        require(safe(path) and path.is_file(), "Missing or symbolic-link source: " + name)
        data = path.read_bytes()
        require(subprocess.check_output(["git", "show", commit + ":" + name], cwd=ROOT) == data,
                "Source is not frozen at HEAD: " + name)
        source[name] = data
    return commit, source


def original_inputs():
    archive = ROOT / "runs/native/exports/native-identity-review.zip"
    require(safe(archive), "Original archive path is a symbolic link.")
    raw = archive.read_bytes()
    files = previous.verify_archive(raw)
    reviewed = ROOT / previous.OUTPUT
    public = ROOT / previous.SUMMARY
    require(safe(reviewed) and safe(public) and reviewed.read_bytes() == public.read_bytes(),
            "The completed reviewed checkpoint differs.")
    result = json.loads(reviewed.read_bytes())
    require(result.get("reviewed_checkpoint_ready") is True
            and result.get("original_archive_sha256") == previous.ARCHIVE_SHA,
            "Complete the native-identity review first.")
    matches = [value for name, value in files.items() if "/after-coding-rollout-" in name and name.endswith(".jsonl")]
    require(len(matches) == 1 and sha(matches[0]) == fixture.SEED_SHA, "Unexpected original rollout copy.")
    return matches[0], {"archive_sha256": sha(raw), "reviewed_checkpoint_sha256": sha(reviewed.read_bytes())}


def create_args(name, token, source):
    argv = environment.create_command(name, token)
    require(argv[-2:] == ["-", "--inside"], "The base inspection command changed.")
    return argv[:-2] + ["-c", source]


def assess(value):
    problems = list(value.get("errors", []))
    cases = value.get("cases", {})
    if set(cases) != {"empty_home", "copied_jsonl_only"}:
        problems.append("Both disposable cases were not recorded.")
    for name, case in cases.items():
        rpc = case.get("rpc", {})
        requests = rpc.get("requests", [])
        if rpc.get("errors") or rpc.get("process_exit_code") != 0 or rpc.get("forced_stop"):
            problems.append(name + ": native read transport incomplete.")
        if [r.get("method") for r in requests] != ["initialize", "thread/read", "thread/turns/list", "thread/items/list"]:
            problems.append(name + ": read protocol incomplete or unexpected.")
        replies = {r.get("method"): r.get("response", {}) for r in requests}
        metadata = replies.get("thread/read", {})
        if name == "empty_home":
            error = metadata.get("error", {})
            if error.get("code") != -32600 or error.get("message") != "thread not loaded: " + fixture.SESSION:
                problems.append("Empty-home negative control did not report the expected missing session.")
        if name == "copied_jsonl_only":
            thread = metadata.get("result", {}).get("thread", {})
            if thread.get("id") != fixture.SESSION or thread.get("historyMode") != "paginated":
                problems.append("Copied paginated session metadata was not read.")
            if case.get("seed_sha256_before") != fixture.SEED_SHA or case.get("seed_sha256_after") != fixture.SEED_SHA:
                problems.append("The disposable seed changed during local reads.")
            for method in ("thread/turns/list", "thread/items/list"):
                result = replies.get(method, {}).get("result")
                if not isinstance(result, dict) or not isinstance(result.get("data"), list):
                    problems.append(method + ": no complete paginated response.")
                elif result.get("nextCursor") is not None:
                    problems.append(method + ": pagination remains incomplete.")
            databases = {row["name"]: row for row in case.get("databases", [])}
            for filename, tables in (("state_5.sqlite", {"threads"}),
                                     ("thread_history_1.sqlite", {"thread_items", "thread_turns", "thread_history_projection_state"})):
                actual = {v["name"] for v in databases.get(filename, {}).get("tables", [])}
                if not tables.issubset(actual):
                    problems.append("Required native schema not captured: " + filename)
        for database in case.get("databases", []):
            if database.get("errors") or database.get("quick_check") != ["ok"] or database.get("database_unchanged_by_inspection") is not True:
                problems.append(name + ": SQLite inspection was not complete and read-only.")
    return {"complete": not problems, "problems": problems,
            "scope": "Fresh disposable homes and native local-read APIs. Original SQLite contents were not available.",
            "native_model_resume_tested": False, "native_defense_tested": False}


def collect():
    commit, source = source_snapshot()
    seed, original = original_inputs()
    out = ROOT / OUTPUT
    require(not out.exists(), "An earlier inspection folder exists and was retained. Do not replace or rerun it.")
    image = json.loads(checked(["docker", "image", "inspect", environment.IMAGE]))[0]
    require(image["Id"] == environment.IMAGE and image["Os"] == "linux" and image["Architecture"] == "amd64"
            and not image["Config"].get("Volumes"), "Unexpected pinned image.")
    token = uuid.uuid4().hex
    name = "cse227-native-store-" + token[:12]
    packet = {"schema": "native-store-scope-v1", "created_at": datetime.now(timezone.utc).isoformat(),
              "source_commit": commit, "source_sha256": {n: sha(b) for n, b in source.items()},
              "image_id": environment.IMAGE, "original_evidence": original,
              "container_name": name, "container_token": token,
              "model_calls": 0, "credentials_mounted": False, "host_folders_mounted": False,
              "network": "none", "errors": [], "cleanup_errors": []}
    save(out / "started.json", packet)
    for n, data in source.items():
        path = out / "source" / n
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    try:
        checked(create_args(name, token, source["research/native/native_store_fixture.py"].decode()))
        info = json.loads(checked(["docker", "inspect", name]))[0]
        environment.validate_container(info, token)
        packet["container_policy_verified"] = True
        save(out / "container-before.json", info)
        print("Reading native metadata in two fresh offline homes.", flush=True)
        try:
            result = command(["docker", "start", "--attach", "--interactive", name], timeout=150,
                             input=json.dumps({"seed_b64": base64.b64encode(seed).decode()}))
        except subprocess.TimeoutExpired as exc:
            for filename, value in (("container.stdout", exc.stdout), ("container.stderr", exc.stderr)):
                data = value or b""
                (out / filename).write_bytes(data.encode() if isinstance(data, str) else data)
            raise
        (out / "container.stdout").write_text(result.stdout)
        (out / "container.stderr").write_text(result.stderr)
        packet["transport_exit_code"] = result.returncode
        packet["fixture"] = json.loads(result.stdout)
        after = json.loads(checked(["docker", "inspect", name]))[0]
        save(out / "container-after.json", after)
        require(result.returncode == 0 and after["State"]["Status"] == "exited"
                and after["State"]["ExitCode"] == 0 and not after["State"]["OOMKilled"],
                "The disposable inspection did not finish normally.")
        packet["assessment"] = assess(packet["fixture"])
    except (Exception, KeyboardInterrupt) as exc:
        packet["errors"].append(type(exc).__name__ + ": " + str(exc))
    finally:
        try:
            owned = checked(["docker", "ps", "--all", "--quiet", "--filter", f"label={environment.LABEL}={token}"]).split()
            for identifier in owned:
                checked(["docker", "rm", "--force", "--volumes", identifier])
            remaining = checked(["docker", "ps", "--all", "--quiet", "--filter", f"label={environment.LABEL}={token}"]).strip()
            require(not remaining, "Inspection resources remain present.")
            packet["container_removed"] = True
        except Exception as exc:
            packet["cleanup_errors"].append(str(exc))
            packet["container_removed"] = False
        try:
            end_commit, end_source = source_snapshot()
            _, end_original = original_inputs()
            require(end_commit == commit and end_source == source and end_original == original,
                    "Source or original evidence changed during inspection.")
            packet["original_evidence_and_source_unchanged"] = True
        except Exception as exc:
            packet["errors"].append(str(exc))
    packet["inspection_complete"] = bool(not packet["errors"] and not packet["cleanup_errors"]
        and packet.get("assessment", {}).get("complete") and packet.get("container_removed")
        and packet.get("original_evidence_and_source_unchanged"))
    save(out / "diagnostics.json", packet)
    return packet


def export_packet(packet, destination, backup_dir):
    files = {p.relative_to(ROOT / OUTPUT).as_posix(): p.read_bytes()
             for p in (ROOT / OUTPUT).rglob("*") if p.is_file() and not p.is_symlink()}
    manifest = {"schema": "native-store-scope-export-v1", "source_commit": packet["source_commit"],
                "files": {n: {"sha256": sha(b), "bytes": len(b)} for n, b in sorted(files.items())}}
    files["review-manifest.json"] = (json.dumps(manifest, indent=2) + "\n").encode()
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as package:
        for name, data in sorted(files.items()):
            package.writestr(name, data)
    payload = buffer.getvalue()
    with zipfile.ZipFile(io.BytesIO(payload)) as package:
        require(package.testzip() is None and all(package.read(n) == b for n, b in files.items()), "Export verification failed.")
    require(destination.parent.is_dir(), "The export directory is missing.")
    targets = [ROOT / "runs/native/exports" / destination.name, backup_dir / destination.name, destination]
    for target in targets:
        require(safe(target) and (not target.exists() or target.read_bytes() == payload), "A different export exists and was retained.")
    for target in targets:
        target.parent.mkdir(parents=True, exist_ok=True)
        if not target.exists():
            with target.open("xb") as stream:
                stream.write(payload)
        require(sha(target.read_bytes()) == sha(payload), "An export copy differs.")
    print("NATIVE STORE SCOPE EXPORTED AND BACKED UP")
    print("Inspection complete:", packet["inspection_complete"])
    print("Container removed:", packet.get("container_removed"))
    print("Original evidence and source unchanged:", packet.get("original_evidence_and_source_unchanged"))
    print("Upload:", destination)
    print("Backup:", backup_dir / destination.name)
    print("SHA256:", sha(payload))
    print("Model calls: 0. Native defense tested: False. GitHub uploads: 0.")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--export", type=Path, required=True)
    parser.add_argument("--backup-dir", type=Path, required=True)
    args = parser.parse_args()
    packet = collect()
    export_packet(packet, args.export, args.backup_dir)
    if not packet["inspection_complete"]:
        print("STOP: Upload the retained diagnostics. Do not rerun or replace this inspection.")
        return 1
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, RuntimeError, ValueError, KeyError, subprocess.SubprocessError) as exc:
        print("STOP:", exc, file=sys.stderr)
        raise SystemExit(1)
