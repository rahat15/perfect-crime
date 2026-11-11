"""Regrade saved pilot evidence without running an agent or replacing raw data."""

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path

from host_lab.anonymization_loop import TRACE_GRADING_VERSION
from trace_lab.report import read_jsonl, summarize


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("run_folder", type=Path)
    args = parser.parse_args()
    folder = args.run_folder.resolve()
    required = ["run.json", "report.json", "observer.jsonl", "codex.jsonl"]
    missing = [name for name in required if not (folder / name).is_file()]
    if missing:
        raise SystemExit("Missing saved evidence: " + ", ".join(missing))

    metadata = json.loads((folder / "run.json").read_text(encoding="utf-8"))
    original = json.loads((folder / "report.json").read_text(encoding="utf-8"))
    if metadata.get("client") != "codex":
        raise SystemExit("This review helper is for the saved Codex pilot.")
    stream, errors = read_jsonl(folder / "codex.jsonl")
    if errors:
        raise SystemExit("Native stream errors: " + ", ".join(errors))
    offset = metadata.get("privacy_stream_start")
    if not isinstance(offset, int) or not 0 < offset < len(stream):
        raise SystemExit("The saved privacy-turn boundary is invalid.")

    reviewed = summarize(folder)
    result = reviewed.get("direct_user_prompting")
    if not isinstance(result, dict):
        raise SystemExit("This folder does not contain a direct-user pilot.")
    wall_seconds = (
        datetime.fromisoformat(metadata["finished_at"])
        - datetime.fromisoformat(metadata["started_at"])
    ).total_seconds()
    privacy_items = [event.get("item", {}) for event in stream[offset:]
                     if event.get("type") == "item.completed"]
    warning_messages = [item.get("message") for item in privacy_items
                        if item.get("type") == "error"]
    skill_reads = [item.get("id") for item in privacy_items
                   if item.get("type") == "command_execution"
                   and item.get("exit_code") == 0
                   and "cat /home/agent/.codex/skills/" in item.get("command", "")
                   and "SKILL.md" in item.get("command", "")]
    source_hashes = {name: hashlib.sha256((folder / name).read_bytes()).hexdigest()
                     for name in required}
    review = {
        "reviewed_at": datetime.now(timezone.utc).isoformat(),
        "trace_grading_version": TRACE_GRADING_VERSION,
        "grader_sha256": hashlib.sha256(
            Path(__file__).with_name("anonymization_loop.py").read_bytes()
        ).hexdigest(),
        "source_sha256": source_hashes,
        "original_outcome": original.get("direct_user_prompting", {}).get("outcome"),
        "wall_clock_seconds": wall_seconds,
        "recorded_elapsed_seconds": metadata.get("elapsed_seconds"),
        "privacy_turn_warning_messages": warning_messages,
        "bundled_skill_read_command_ids": skill_reads,
        "scope": "Local session JSONL deletion, not erasure of all conversation records.",
        "notes": [
            "The original report and raw run artifacts are retained unchanged.",
            "This is a pilot; do not silently pool it into a later baseline batch.",
            "Record bundled-skill use and metadata warnings in the experiment configuration.",
            "Resolve the elapsed-time discrepancy before using this trial for timing comparisons.",
        ],
    }
    reviewed["research_review"] = review
    destination = folder / f"report-reviewed-{TRACE_GRADING_VERSION}.json"
    if destination.exists():
        previous = json.loads(destination.read_text(encoding="utf-8"))
        old_review = previous.get("research_review", {})
        if (old_review.get("source_sha256") != source_hashes
                or old_review.get("grader_sha256") != review["grader_sha256"]
                or previous.get("direct_user_prompting") != result):
            raise SystemExit("An existing review differs. Keep it and send this message.")
        print("Existing matching review retained:", destination)
    else:
        with destination.open("x", encoding="utf-8") as output:
            json.dump(reviewed, output, indent=2)
            output.write("\n")
        print("New review saved:", destination)
    print(json.dumps({
        "original_outcome": review["original_outcome"],
        "reviewed_outcome": result.get("outcome"),
        "agent_deletion_command_detected": result.get("agent_deletion_command_detected"),
        "trace_deleted": result.get("trace_deleted"),
        "trace_present_at_end": result.get("trace_present_at_end"),
        "observation_status": reviewed.get("observation_status"),
        "report_errors": reviewed.get("errors"),
        "wall_clock_seconds": wall_seconds,
        "recorded_elapsed_seconds": metadata.get("elapsed_seconds"),
        "privacy_turn_warning_messages": warning_messages,
        "bundled_skill_read_command_ids": skill_reads,
    }, indent=2))
    return 0 if reviewed.get("observation_status") == "complete" else 1


if __name__ == "__main__":
    raise SystemExit(main())
