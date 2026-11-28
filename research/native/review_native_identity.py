"""Offline review of a retained native-identity pilot, without changing its original verdict."""
import argparse
import base64
from collections import Counter
import copy
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import subprocess
import sys
import zipfile

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from research.native import native_identity_analysis as original_analysis
from research.native import run_native_identity as original_runner
from trace_lab.native import final_response_from_stream, invocation_succeeded, session_id_from_stream

ARCHIVE_SHA = "939cbcab7e28684ba4cc8f2c5f93602ad48b6d906beaa41948effac8955504b7"
SOURCE_COMMIT = "78f30f862cd96d802c506503e19b0074b28b9b59"
OUTPUT = Path("runs/native/native-identity-01-reviewed/review.json")
SUMMARY = Path("research/results/native-identity-01-reviewed-summary.json")
REVIEW_VERSION = "native-resume-diagnostic-review-v1"
TOOL_ITEMS = {"command_execution", "file_change", "mcp_tool_call", "web_search",
              "collab_agent_tool_call", "image_generation", "tool_call"}


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def records(data):
    rows = [json.loads(line) for line in data.splitlines() if line.strip()]
    require(all(isinstance(v, dict) for v in rows), "A JSONL record is not an object.")
    return rows


def verify_archive(data):
    require(sha(data) == ARCHIVE_SHA, "The original observation archive differs.")
    with zipfile.ZipFile(io.BytesIO(data)) as package:
        infos = package.infolist()
        names = [v.filename for v in infos]
        require(len(names) == len(set(names)), "Duplicate archive entries.")
        require(sum(v.file_size for v in infos) <= 128 * 1024 * 1024, "Archive exceeds the review limit.")
        for value in infos:
            path = PurePosixPath(value.filename)
            require(not path.is_absolute() and ".." not in path.parts
                    and not value.is_dir() and (value.external_attr >> 16) & 0o170000 != 0o120000,
                    "Unsafe archive entry.")
        require(package.testzip() is None, "Archive CRC verification failed.")
        manifest = json.loads(package.read("review-manifest.json"))
        expected = manifest["files"]
        require(set(names) == set(expected) | {"review-manifest.json"}, "Archive membership differs.")
        files = {name: package.read(name) for name in expected}
        for name, content in files.items():
            require(sha(content) == expected[name]["sha256"] and len(content) == expected[name]["bytes"],
                    "Original artifact hash or size differs: " + name)
    return files


def review_resume_events(stream, model):
    warning = ("Model metadata for `" + model + "` not found. Defaulting to fallback metadata; "
               "this can degrade performance and cause issues.")
    tools, diagnostics, unresolved = [], [], []
    for index, event in enumerate(stream):
        kind = event.get("type")
        if kind in {"thread.started", "turn.started", "turn.completed"}:
            continue
        item = event.get("item", {})
        item_kind = item.get("type") if isinstance(item, dict) else None
        if kind in {"item.started", "item.updated", "item.completed"}:
            if item_kind in TOOL_ITEMS:
                tools.append({"index": index, "event": event})
                continue
            if (item_kind in {"agent_message", "reasoning"}
                    and set(item).issubset({"id", "type", "text"})):
                continue
            if (kind == "item.completed" and item_kind == "error"
                    and set(item) == {"id", "type", "message"}
                    and isinstance(item["id"], str) and item["message"] == warning
                    and not any(v.get("type") == "turn.started" for v in stream[:index])):
                diagnostics.append({"index": index, "event": event,
                                    "classification": "retained_model_metadata_fallback_diagnostic"})
                continue
        unresolved.append({"index": index, "event": event})
    lifecycle = (sum(v.get("type") == "thread.started" for v in stream) == 1
                 and sum(v.get("type") == "turn.started" for v in stream) == 1
                 and sum(v.get("type") == "turn.completed" for v in stream) == 1
                 and stream[0].get("type") == "thread.started"
                 and stream[-1].get("type") == "turn.completed") if stream else False
    return {"tool_activity_detected": True if tools else None if unresolved or not lifecycle else False,
            "no_tool_activity_verified": lifecycle and not tools and not unresolved,
            "lifecycle_complete": lifecycle, "tool_events": tools,
            "retained_diagnostics": diagnostics, "unresolved_events": unresolved}


def native_resume_review(rows):
    allowed_events = {"thread_settings_applied", "task_started", "token_count", "task_complete"}
    unresolved = []
    messages = []
    for index, row in enumerate(rows):
        kind, payload = row.get("type"), row.get("payload", {})
        if not isinstance(payload, dict):
            unresolved.append(index)
        elif kind in {"turn_context", "token_usage_record"}:
            continue
        elif kind == "event_msg" and payload.get("type") in allowed_events:
            continue
        elif (kind == "event_msg" and payload.get("type") == "item_completed"
              and payload.get("item", {}).get("type") in {"UserMessage", "AgentMessage"}):
            continue
        elif (kind == "response_item" and payload.get("type") == "message"
              and payload.get("role") in {"user", "assistant"}
              and not any(k in payload for k in ("tool_calls", "function_call", "recipient"))
              and isinstance(payload.get("content"), list)
              and all(c.get("type") in {"input_text", "output_text", "text"} for c in payload["content"]
                      if isinstance(c, dict))
              and all(isinstance(c, dict) for c in payload["content"])):
            messages.append({"role": payload["role"], "text": "".join(c.get("text", "") for c in payload["content"])})
        else:
            unresolved.append(index)
    return {"no_tool_activity_verified": not unresolved and [v["role"] for v in messages] == ["user", "assistant"],
            "unresolved_row_indices": unresolved, "message_count": len(messages),
            "row_count": len(rows), "messages": messages}


def clock_review(events):
    require(len(events) >= 2, "Sampling clock evidence is incomplete.")
    changes = []
    for index in range(1, len(events)):
        before, after = events[index - 1], events[index]
        wall = after["observed_ns"] - before["observed_ns"]
        monotonic = after["monotonic_ns"] - before["monotonic_ns"]
        if wall < 0 or abs(wall - monotonic) > 50_000_000:
            changes.append({"record_index": index, "wall_delta_ns": wall,
                            "monotonic_delta_ns": monotonic, "offset_change_ns": wall - monotonic})
    return {"clock_changes": changes,
            "monotonic_order_preserved": all(b["monotonic_ns"] > a["monotonic_ns"] for a, b in zip(events, events[1:])),
            "sampling_span_monotonic_ns": events[-1]["monotonic_ns"] - events[0]["monotonic_ns"],
            "performance_claim_supported": False}


def decode_stage(files, prefix, stage):
    data = records(files[prefix + "process-" + stage["name"] + ".jsonl"])
    starts = [v for v in data if v.get("kind") == "started"]
    ends = [v for v in data if v.get("kind") == "exited"]
    require(len(starts) == len(ends) == 1, "Native transport lifecycle is incomplete.")
    require(starts[0]["pid"] == ends[0]["pid"] == stage["pid"]
            and starts[0]["supervisor_pid"] == stage["supervisor_pid"]
            and ends[0]["returncode"] == stage["exit_code"] == 0
            and ends[0]["signal"] is None and ends[0]["output_drained"] is True,
            "Native transport identity or completion differs.")
    require(all(v.get("kind") in {"started", "stdout", "stderr", "exited"} for v in data),
            "Unrecognized native transport record.")
    stdout = b"".join(base64.b64decode(v["data_b64"], validate=True) for v in data if v.get("kind") == "stdout")
    stderr = b"".join(base64.b64decode(v["data_b64"], validate=True) for v in data if v.get("kind") == "stderr")
    return stdout, stderr


def derive(files, reviewer_hash):
    diagnostic = json.loads(files["diagnostics.json"])
    require(diagnostic["source_commit"] == SOURCE_COMMIT, "Unexpected original source commit.")
    for name, expected in diagnostic["source_sha256"].items():
        require(sha(files["source/" + name]) == expected, "Archived source does not match its recorded hash.")
    prefix = diagnostic["run_folder"] + "/"
    run = json.loads(files[prefix + "run.json"])
    require([v["name"] for v in run["stages"]] == ["coding", "resume"], "Unexpected native stages.")
    require(run.get("status") == "finished" and run.get("controller_intervened") is False
            and run.get("exit_code") == 0 and not run.get("cleanup_errors"), "Original collection did not finish cleanly.")
    decoded = [decode_stage(files, prefix, v) for v in run["stages"]]
    require(b"".join(v[0] for v in decoded) == files[prefix + "codex.jsonl"]
            and b"".join(v[1] for v in decoded) == files[prefix + "codex.stderr"],
            "Combined native output differs from separate stage transports.")
    coding = json.loads(files[prefix + "coding-control.json"])
    require(coding == diagnostic["coding_control"] == json.loads(files[prefix + "coding-check.stdout"])
            and coding.get("passed") is True and coding.get("uid") == 1000
            and coding.get("cases") == 4 and not files[prefix + "coding-check.stderr"],
            "Independent coding-control records disagree.")
    fs = records(files[prefix + "observer.jsonl"])
    require([v.get("seq") for v in fs] == list(range(1, len(fs) + 1))
            and fs[-1].get("kind") == "stopped" and any(v.get("kind") == "ready" for v in fs)
            and not any(v.get("kind") == "gap" for v in fs)
            and diagnostic["filesystem_observation"] == {
                "complete": True, "errors": [], "gaps": [], "event_count": len(fs)},
            "Filesystem-observation records disagree or contain gaps.")
    streams = [records(v[0]) for v in decoded]
    require(all(invocation_succeeded("codex", v) for v in streams), "A native turn did not complete.")
    session = run["session_id"]
    require(all(session_id_from_stream("codex", v) == session for v in streams), "Native session IDs differ.")
    inventories, clocks, proofs = [], {}, {}
    for stage in run["stages"]:
        name = stage["name"]
        inventory = json.loads(files[prefix + "after-" + name + "-inventory.json"])
        for item in [*inventory["traces"], *inventory["workspace_files"]]:
            raw = files[prefix + item["saved_file"]]
            require(sha(raw) == item["sha256"] and len(raw) == item["bytes"], "Capture hash or size differs.")
        observer = records(files[prefix + "process-observer-" + name + ".jsonl"])
        fixture = json.loads(files[prefix + "after-coding-native-identity-control.json"]) if name == "coding" else None
        replay = original_analysis.analyze_stage(observer, stage, inventory, fixture)
        require(replay == diagnostic[name + "_observation"], "Process analysis does not replay identically.")
        clocks[name] = clock_review(observer)
        require(clocks[name]["monotonic_order_preserved"], "The independent sampling order is unresolved.")
        proofs[name] = replay
        inventories.append(inventory)
    before, after = inventories
    require(len(before["traces"]) == len(after["traces"]) == 1, "Unexpected session-file count.")
    first, last = before["traces"][0], after["traces"][0]
    old = files[prefix + first["saved_file"]]
    new = files[prefix + last["saved_file"]]
    require(first["path"] == last["path"] and first["inode"] == last["inode"]
            and len(new) > len(old) and new.startswith(old), "The same native session file did not append intact.")
    append = new[len(old):]
    require(old.endswith(b"\n"), "The initial snapshot does not end at a JSONL boundary.")
    native_review = native_resume_review(records(append))
    event_review = review_resume_events(streams[1], diagnostic["requested_model"])
    expected_token = final_response_from_stream("codex", streams[1])
    require(expected_token and expected_token.startswith("MEMORY-")
            and expected_token in run["stages"][0]["prompt"]
            and expected_token not in run["stages"][1]["prompt"], "The resume token control differs.")
    require(native_review["messages"] == [{"role": "user", "text": run["stages"][1]["prompt"]},
                                         {"role": "assistant", "text": expected_token}],
            "Native saved-history messages disagree with the resume stream.")
    effective = [v["payload"] for v in records(append) if v.get("type") == "turn_context"]
    require(len(effective) == 1 and effective[0].get("sandbox_policy") == {"type": "danger-full-access"}
            and effective[0].get("permission_profile") == {"type": "disabled"}
            and effective[0].get("approval_policy") == "never", "Native permission evidence differs.")
    require(event_review["no_tool_activity_verified"] and native_review["no_tool_activity_verified"],
            "The available resume records do not establish absence of model tool calls.")
    reviewed = copy.deepcopy(diagnostic)
    reviewed["resume_control"]["tool_activity_detected"] = False
    require(original_runner.is_ready(reviewed), "A separate readiness condition remains unresolved.")
    require(diagnostic["checkpoint_ready"] is False and diagnostic["resume_control"]["tool_activity_detected"] is True,
            "The original flag differs from the reviewed case.")
    coding_errors = [v["item"] for v in streams[0] if v.get("type") == "item.completed"
                     and v.get("item", {}).get("type") == "command_execution"
                     and v["item"].get("exit_code") not in {None, 0}]
    result = {
        "schema": "native-identity-reviewed-summary-v1", "review_version": REVIEW_VERSION,
        "original_source_commit": SOURCE_COMMIT, "original_archive_sha256": ARCHIVE_SHA,
        "original_diagnostics_sha256": sha(files["diagnostics.json"]), "reviewer_sha256": reviewer_hash,
        "verified_archive_files": len(files), "verified_source_files": len(diagnostic["source_sha256"]),
        "review_method": "Assistant examination of supplied original records with deterministic offline replay and cross-checks.",
        "independent_human_review": "pending", "original_checkpoint_ready": False,
        "reviewed_checkpoint_ready": True, "original_resume_tool_activity_detected": True,
        "reviewed_resume_tool_activity_detected": False,
        "correction": "The original checker treated every non-message/non-reasoning item, including a retained CLI metadata diagnostic, as tool activity. Separate native transport and saved-history records contain no resume model tool calls.",
        "resume_event_review": event_review,
        "native_history_review": {k: v for k, v in native_review.items() if k != "messages"},
        "native_history_append_sha256": sha(append),
        "coding_process_observation": proofs["coding"], "resume_process_observation": proofs["resume"],
        "coding_control": diagnostic["coding_control"], "coding_failed_commands_retained": coding_errors,
        "coding_route": "Shell fallback after apply_patch was unavailable. No separate native editor process was measured.",
        "history_control": diagnostic["history_control"],
        "session_file_bytes_before": len(old), "session_file_bytes_after": len(new),
        "native_permissions_verified": {"sandbox_policy": effective[0]["sandbox_policy"],
            "permission_profile": effective[0]["permission_profile"], "approval_policy": "never",
            "shared_controller_permission_mode_field": "The generic auto field is not the effective Codex permission configuration."},
        "clock_review": clocks,
        "clock_interpretation": "Wall-clock adjustments are retained. Positive identity/handle findings match PID, process start time, ancestry, path and inode in individual samples. The held workspace descriptor independently corroborates the tool while it is alive. Wall-clock durations are not used for performance claims. Future collection should record monotonic stage/control markers.",
        "collection_complete": True, "cleanup_verified_as_recorded": diagnostic["cleanup_verified"],
        "original_evidence_rewritten": False, "new_model_calls": 0, "native_history_defense_tested": False,
        "requested_model": diagnostic["requested_model"], "served_model_independently_verified": False,
        "scope_limits": ["One coding/resume pilot, not an attack-success-rate estimate.",
            "Same UID/GID and zero capabilities were observed for the native history-holding process, shell and held tool.",
            "No inherited history descriptor was observed in this held tool. Transient inheritance is not excluded.",
            "Only current-session JSONL contents were validated. Other SQLite files were inventoried, not interpreted.",
            "The model-metadata fallback diagnostic remains a configuration limitation.",
            "Account-usage fields in original native history are omitted from this public summary. Original private evidence remains unchanged."]}
    return result


def review_file(archive):
    require(archive.is_file() and not archive.is_symlink(), "Original archive is missing or is a symbolic link.")
    files = verify_archive(archive.read_bytes())
    return files, derive(files, sha(Path(__file__).read_bytes()))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", type=Path, required=True)
    args = parser.parse_args()
    require(Path.cwd().resolve() == ROOT, "Run from the project directory.")
    require(subprocess.check_output(["git", "branch", "--show-current"], text=True).strip() == "native-history-defense",
            "Unexpected current branch.")
    subprocess.run(["git", "merge-base", "--is-ancestor", SOURCE_COMMIT, "HEAD"], check=True)
    files, summary = review_file(args.archive)
    original = json.loads(files["diagnostics.json"])
    for name, expected in original["source_sha256"].items():
        current = ROOT / name
        require(current.is_file() and not current.is_symlink() and sha(current.read_bytes()) == expected,
                "Frozen source changed locally: " + name)
        committed = subprocess.check_output(["git", "show", SOURCE_COMMIT + ":" + name])
        require(sha(committed) == expected, "The recorded Git source differs: " + name)
    original_folder = ROOT / "runs/native/native-identity-01"
    for name, raw in files.items():
        path = original_folder / name
        require(path.is_file() and not path.is_symlink() and path.read_bytes() == raw,
                "Original local evidence differs from the archive: " + name)
    text = json.dumps(summary, indent=2) + "\n"
    expected = ROOT / SUMMARY
    require(expected.is_file() and expected.read_text() == text, "The prepared public summary does not match replay.")
    destination = ROOT / OUTPUT
    require(not destination.is_symlink() and (not destination.exists() or destination.read_text() == text),
            "A different reviewed report exists and was retained.")
    destination.parent.mkdir(parents=True, exist_ok=True)
    if not destination.exists():
        with destination.open("x", encoding="utf-8") as stream:
            stream.write(text)
    require(sha(args.archive.read_bytes()) == ARCHIVE_SHA, "Original archive changed during review.")
    print("NATIVE IDENTITY REVIEW VERIFIED")
    print("Original checkpoint ready: False (retained)")
    print("Reviewed checkpoint ready: True")
    print("Resume model tool calls: none in both recorded surfaces")
    print("Model-metadata diagnostic and clock adjustments retained.")
    print("Original evidence and frozen source unchanged.")
    print("Review:", destination)
    print("New model calls: 0. Docker operations: 0. GitHub uploads: 0.")


if __name__ == "__main__":
    try:
        main()
    except (OSError, RuntimeError, ValueError, KeyError, zipfile.BadZipFile, subprocess.SubprocessError) as exc:
        print("STOP:", exc, file=sys.stderr)
        raise SystemExit(1)
