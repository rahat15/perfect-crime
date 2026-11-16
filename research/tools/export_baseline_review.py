"""Export selected existing baseline evidence; never run or regrade a trial."""

import hashlib
import json
from pathlib import Path
import re
import subprocess


BATCH = Path("runs/baseline-financial-full-01")
RAW_NAMES = ("run.json", "report.json", "observer.jsonl", "codex.jsonl")
RUN_FIELDS = (
    "session_id", "client", "status", "exit_code", "error", "codex_version",
    "requested_model", "codex_auth", "permissions_profile", "image_id",
    "initial_task_completed", "controller_intervened", "cleanup_errors",
    "started_at", "finished_at", "elapsed_seconds", "privacy_stream_start",
)
SECRET_FIELDS = {
    "access_token", "refresh_token", "id_token", "api_key", "authorization",
    "password", "secret", "cookie", "set-cookie",
}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def read(path):
    return json.loads(path.read_text(encoding="utf-8"))


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def json_lines(path):
    records = []
    with path.open(encoding="utf-8") as source:
        for number, line in enumerate(source, 1):
            if line.strip():
                try:
                    record = json.loads(line)
                except ValueError:
                    raise ValueError(f"Invalid JSON in {path.name}, line {number}.") from None
                require(isinstance(record, dict), f"Non-object record in {path.name}.")
                records.append(record)
    return records


def source_hashes(root):
    paths = {root / "research/tools/run_baseline.py"}
    for directory in ("host_lab", "trace_lab"):
        paths.update((root / directory).rglob("*.py"))
    return {path.relative_to(root).as_posix(): sha(path) for path in sorted(paths)}


def clean_text(value):
    value = re.sub(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]+", "Bearer [REDACTED]", value)
    value = re.sub(r"\bsk-[A-Za-z0-9_-]{12,}", "[REDACTED_API_KEY]", value)
    value = re.sub(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+", "[REDACTED_JWT]", value)
    value = re.sub(r"(https?://)[^\s/@:]+:[^\s/@]+@", r"\1[REDACTED]@", value)
    value = re.sub(
        r"(?im)^.*\b\w*(?:TOKEN|PASSWORD|SECRET|API_KEY)\w*\s*=.*$",
        "[REDACTED_CREDENTIAL_ASSIGNMENT_LINE]", value,
    )
    if len(value) > 16000:
        value = value[:8000] + "\n[Middle omitted for size]\n" + value[-8000:]
    return value


def redact(value):
    if isinstance(value, dict):
        return {
            key: "[REDACTED]" if str(key).lower() in SECRET_FIELDS else redact(item)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [redact(item) for item in value]
    return clean_text(value) if isinstance(value, str) else value


def privacy_records(stream, offset):
    result = []
    for number, event in enumerate(stream[offset:], offset + 1):
        if event.get("type") == "item.completed":
            item = event.get("item", {})
            kind = item.get("type")
            record = {"record_number_one_based": number, "type": kind, "id": item.get("id")}
            if kind == "command_execution":
                command = item.get("command", "")
                output = item.get("aggregated_output", "")
                if re.search(r"(?i)auth\.json|\.credentials|\bprintenv\b|\benv\b|(?:^|[/\s])\.env(?:\W|$)", command):
                    output = "[Output omitted: command references credentials or environment variables.]"
                elif "SKILL.md" in command:
                    output = "[Bundled skill text omitted; command retained.]"
                record.update(status=item.get("status"), exit_code=item.get("exit_code"),
                              command=command, output=output,
                              command_sha256=hashlib.sha256(command.encode()).hexdigest())
            elif kind in {"agent_message", "error"}:
                record.update(text=item.get("text"), message=item.get("message"))
            elif kind == "file_change":
                record.update(status=item.get("status"), changes=[
                    {"path": change.get("path"), "kind": change.get("kind")}
                    for change in item.get("changes", []) if isinstance(change, dict)
                ])
            else:
                continue
            result.append(record)
        elif event.get("type") in {"error", "turn.failed", "turn.completed"}:
            result.append({"record_number_one_based": number, "type": event.get("type"),
                           "error": event.get("error"), "message": event.get("message")})
    return result


def extract_attempt(root, number):
    attempt = root / BATCH / f"attempt-{number:02d}"
    ledger_path = attempt / "attempt.json"
    ledger_digest = sha(ledger_path)
    ledger = read(ledger_path)
    require(ledger.get("attempt") == number and ledger.get("state") == "finished",
            f"Attempt {number} is not recorded as finished.")
    folders = list((attempt / "artifacts").glob("*/run.json"))
    require(len(folders) == 1, f"Attempt {number} has missing or ambiguous artifacts.")
    folder = folders[0].parent
    require(folder.resolve().is_relative_to(attempt.resolve()), "Artifact path leaves its attempt folder.")
    require(ledger.get("run_folder") == folder.relative_to(attempt).as_posix(),
            f"Attempt {number} artifact path differs from the ledger.")
    hashes = {name: sha(folder / name) for name in RAW_NAMES}
    require(hashes == ledger.get("source_sha256"), f"Attempt {number} evidence hashes changed.")
    run, report = read(folder / "run.json"), read(folder / "report.json")
    stream, observer = json_lines(folder / "codex.jsonl"), json_lines(folder / "observer.jsonl")
    offset, session = run.get("privacy_stream_start"), run.get("session_id")
    require(type(offset) is int and 0 < offset < len(stream), f"Attempt {number} has an invalid privacy boundary.")
    require(isinstance(session, str) and session, f"Attempt {number} has no session ID.")
    events = [
        {key: event.get(key) for key in ("seq", "observed_ns", "kind", "root", "path", "events", "directory")}
        for event in observer if event.get("kind") == "fs" and session in str(event.get("path", ""))
    ]
    inventories = [event for event in observer if event.get("kind") == "trace_inventory"]
    last_inventory = inventories[-1] if inventories else {}
    result = {
        "attempt": number,
        "run_folder_relative": folder.relative_to(root).as_posix(),
        "raw_evidence_matches_attempt_record": True,
        "original_assessment": {key: ledger.get(key) for key in (
            "state", "process_exit_code", "outcome", "success", "flags",
            "no_attempt_containers_running_verified",
        )},
        "run": {key: run.get(key) for key in RUN_FIELDS},
        "stages": [{key: stage.get(key) for key in ("name", "started_ns", "finished_ns", "exit_code", "signal")}
                   for stage in run.get("stages", [])],
        "observation_status": report.get("observation_status"),
        "report_errors": report.get("errors"),
        "grading_details": {key: value for key, value in report.get("direct_user_prompting", {}).items()
                            if key != "interpretation"},
        "privacy_turn_records": privacy_records(stream, offset),
        "session_filesystem_events": events,
        "final_inventory": {key: last_inventory.get(key) for key in ("seq", "observed_ns", "kind", "paths")},
        "source_sha256": hashes,
        "manual_review": None,
    }
    review_path = attempt / "manual-review.json"
    if review_path.is_file():
        review = read(review_path)
        require(review.get("source_sha256") == hashes, f"Attempt {number} manual review refers to different evidence.")
        result["manual_review"] = review
    require(hashes == {name: sha(folder / name) for name in RAW_NAMES} and ledger_digest == sha(ledger_path),
            f"Attempt {number} changed while being read.")
    return result


def build_packet(root):
    batch = root / BATCH
    plan = read(batch / "plan.json")
    require(plan.get("planned_attempts") == 10, "The saved plan does not specify ten attempts.")
    require(sorted(path.name for path in batch.glob("attempt-*"))
            == [f"attempt-{number:02d}" for number in range(1, 11)],
            "Expected exactly ten retained attempt folders.")
    sources = source_hashes(root)
    require(sources == plan.get("source_sha256"), "Experiment source differs from the frozen batch.")
    rows = [extract_attempt(root, number) for number in range(1, 11)]
    sessions = [row["run"]["session_id"] for row in rows]
    require(len(set(sessions)) == 10 and plan.get("pilot_session_id") not in sessions,
            "A session ID was reused between attempts or from the pilot.")
    require(source_hashes(root) == sources, "Experiment source changed during export.")
    return redact({
        "purpose": "Review existing baseline evidence; no new experiment or automatic reclassification.",
        "scope": "Local session JSONL deletion only; not complete erasure of all records.",
        "attempts_exported": len(rows),
        "pilot_included": False,
        "experiment_source_matches_frozen_plan": True,
        "distinct_native_sessions_verified": True,
        "independent_review_status": "pending; review at completed handoff",
        "export_notes": [
            "Selected evidence only; original raw files remain on the experiment computer.",
            "Credential/environment-command outputs and bundled skill text are omitted.",
            "Known credential patterns are redacted; long strings explicitly mark omissions.",
            "Original automated outcomes and existing manual review notes remain separate.",
        ],
        "plan": {key: plan.get(key) for key in (
            "created_at", "model", "codex_version", "authentication", "permissions", "task_profile",
            "max_requests_per_attempt", "external_timeout_seconds", "image_id", "git_commit",
        )},
        "attempts": rows,
    })


def main():
    root = Path(__file__).resolve().parents[2]
    require(Path.cwd().resolve() == root, "Run from the perfect-crime-repro project folder.")
    branch = subprocess.check_output(["git", "branch", "--show-current"], text=True).strip()
    require(branch == "reproduce-financial", "Expected reproduce-financial branch.")
    packet = build_packet(root)
    payload = json.dumps(packet, indent=2, ensure_ascii=True).encode() + b"\n"
    destinations = [root / "runs/setup/baseline-review-diagnostics.json",
                    Path("/mnt/c/Users/ihaxQ/Downloads/baseline-review-diagnostics.json")]
    for path in destinations:
        require(path.parent.is_dir(), f"Output directory is missing: {path.parent}")
        require(not path.exists() or path.read_bytes() == payload,
                f"A different export already exists: {path}. It was not overwritten.")
    for path in destinations:
        if not path.exists():
            with path.open("xb") as output:
                output.write(payload)
    print("BASELINE DIAGNOSTICS READY")
    print("Attempts exported: 10; pilot excluded.")
    print("Evidence hashes and frozen experiment source verified.")
    print("No model calls, Docker operations, uploads, or verdict changes were made.")
    print("Upload this file: C:\\Users\\ihaxQ\\Downloads\\baseline-review-diagnostics.json")
    print("Local copy:", destinations[0])


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, KeyError, TypeError, subprocess.CalledProcessError) as error:
        raise SystemExit("STOP: " + str(error))
