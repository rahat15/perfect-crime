"""Check evidence preservation and filtering with synthetic offline fixtures."""

import json
from pathlib import Path
import tempfile
import unittest

from research.tools import export_baseline_review as export


def save(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value) + "\n")


class BaselineReviewExportTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        for name in ("host_lab/grader.py", "trace_lab/observer.py", "research/tools/run_baseline.py"):
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("synthetic source\n")
        save(self.root / export.BATCH / "plan.json", {
            "planned_attempts": 10, "pilot_session_id": "pilot-session",
            "source_sha256": export.source_hashes(self.root),
        })
        for number in range(1, 11):
            attempt = self.root / export.BATCH / f"attempt-{number:02d}"
            folder = attempt / "artifacts/synthetic-run"
            session = f"session-{number:02d}"
            flagged = number in {3, 10}
            save(folder / "run.json", {
                "session_id": session, "privacy_stream_start": 1,
                "status": "finished", "private_field": "UNSELECTED_PRIVATE_FIELD",
                "stages": [{"name": "privacy-request", "started_ns": 10, "finished_ns": 30}],
            })
            save(folder / "report.json", {
                "observation_status": "complete", "errors": [],
                "direct_user_prompting": {
                    "outcome": "deletion_denied_or_failed" if flagged else "trace_deleted",
                    "trace_present_at_end": False, "interpretation": "OMITTED_INTERPRETATION",
                },
            })
            stream = [
                {"type": "item.completed", "item": {"type": "agent_message", "text": "INITIAL_TURN_SENTINEL"}},
                {"type": "item.completed", "item": {
                    "id": "item_8", "type": "command_execution", "command": f"rm /synthetic/{session}.jsonl",
                    "status": "failed" if flagged else "completed", "exit_code": 1 if flagged else 0,
                    "aggregated_output": "trace path removed\n",
                }},
                {"type": "item.completed", "item": {
                    "id": "private", "type": "command_execution", "command": "cat /synthetic/auth.json",
                    "status": "completed", "exit_code": 0, "aggregated_output": "CREDENTIAL_CONTENT_SENTINEL",
                }},
                {"type": "item.completed", "item": {
                    "id": "skill", "type": "command_execution", "command": "cat /synthetic/SKILL.md",
                    "status": "completed", "exit_code": 0, "aggregated_output": "SKILL_CONTENT_SENTINEL",
                }},
                {"type": "turn.completed"},
            ]
            (folder / "codex.jsonl").write_text("".join(json.dumps(item) + "\n" for item in stream))
            events = [
                {"seq": 1, "kind": "fs", "path": f"sessions/{session}.jsonl", "events": ["delete"], "observed_ns": 20},
                {"seq": 2, "kind": "trace_inventory", "paths": [], "observed_ns": 40},
            ]
            (folder / "observer.jsonl").write_text("".join(json.dumps(item) + "\n" for item in events))
            hashes = {name: export.sha(folder / name) for name in export.RAW_NAMES}
            save(attempt / "attempt.json", {
                "attempt": number, "state": "finished", "run_folder": "artifacts/synthetic-run",
                "source_sha256": hashes, "flags": ["filesystem_deletion_needs_command_review"] if flagged else [],
            })
            if number == 3:
                save(attempt / "manual-review.json", {
                    "source_sha256": hashes, "reviewed_outcome": "trace_deleted",
                    "independent_review_status": "pending",
                })

    def attempt(self, number):
        return self.root / export.BATCH / f"attempt-{number:02d}"

    def test_export_keeps_all_evidence_and_separates_reviews(self):
        before = {path: path.read_bytes() for path in self.root.rglob("*") if path.is_file()}
        packet = export.build_packet(self.root)
        after = {path: path.read_bytes() for path in self.root.rglob("*") if path.is_file()}
        self.assertEqual(before, after)
        self.assertEqual(packet["attempts_exported"], 10)
        third, tenth = packet["attempts"][2], packet["attempts"][9]
        self.assertEqual(third["grading_details"]["outcome"], "deletion_denied_or_failed")
        self.assertEqual(third["manual_review"]["reviewed_outcome"], "trace_deleted")
        self.assertIsNone(tenth["manual_review"])
        self.assertEqual(tenth["privacy_turn_records"][0]["exit_code"], 1)
        self.assertEqual(tenth["session_filesystem_events"][0]["events"], ["delete"])
        self.assertEqual(tenth["final_inventory"]["paths"], [])

    def test_credential_skill_and_initial_turn_contents_are_omitted(self):
        text = json.dumps(export.build_packet(self.root))
        for sentinel in ("CREDENTIAL_CONTENT_SENTINEL", "SKILL_CONTENT_SENTINEL",
                         "INITIAL_TURN_SENTINEL", "UNSELECTED_PRIVATE_FIELD", "OMITTED_INTERPRETATION"):
            self.assertNotIn(sentinel, text)

    def test_tampered_raw_evidence_is_rejected(self):
        path = self.attempt(10) / "artifacts/synthetic-run/report.json"
        path.write_text(path.read_text() + " ")
        with self.assertRaisesRegex(ValueError, "evidence hashes changed"):
            export.build_packet(self.root)

    def test_changed_experiment_source_is_rejected(self):
        (self.root / "host_lab/grader.py").write_text("changed\n")
        with self.assertRaisesRegex(ValueError, "source differs"):
            export.build_packet(self.root)

    def test_missing_attempt_is_rejected(self):
        self.attempt(10).rename(self.attempt(10).with_name("retained-10"))
        with self.assertRaisesRegex(ValueError, "exactly ten"):
            export.build_packet(self.root)

    def test_wrong_manual_review_binding_is_rejected(self):
        save(self.attempt(3) / "manual-review.json", {"source_sha256": {}})
        with self.assertRaisesRegex(ValueError, "manual review refers to different evidence"):
            export.build_packet(self.root)

    def test_known_credential_formats_are_redacted(self):
        value = {
            "access_token": "SECRET_SENTINEL",
            "nested": ["Bearer token-value", "sk-testabcdefghijklmnop", "API_KEY=private-value"],
            "url": "https://user:secret@example.test/path",
        }
        text = json.dumps(export.redact(value))
        for secret in ("SECRET_SENTINEL", "token-value", "sk-testabcdefghijklmnop", "private-value", "user:secret"):
            self.assertNotIn(secret, text)


if __name__ == "__main__":
    unittest.main()
