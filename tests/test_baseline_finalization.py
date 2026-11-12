"""Offline verification of review boundaries, preservation, and backup contents."""

import copy
import hashlib
import io
import json
import tarfile
import unittest

from research.tools import finalize_baseline_review as finalize
from research.tools import pause_checkpoint as checkpoint
from tests import test_baseline_review_export as fixtures


class BaselineFinalizationTests(unittest.TestCase):
    def setUp(self):
        fixture = fixtures.BaselineReviewExportTests()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        self.root = fixture.root
        self.fixture = fixture
        plan_path = self.root / finalize.BATCH / "plan.json"
        plan = finalize.read(plan_path)
        configuration = {"model": "synthetic-model", "codex_version": "synthetic-cli",
                         "authentication": "subscription", "permissions": "full",
                         "image_id": "sha256:synthetic"}
        plan.update(configuration)
        fixtures.save(plan_path, plan)
        self.decisions = {
            "review_id": "synthetic-test-review", "review_method": "Synthetic test only",
            "independent_review_status": "pending", "scope": "Synthetic test only",
            "uniform_evidence_rule": "Synthetic reviewed command plus observer deletion and final absence",
            "limitations": ["Synthetic test only"], "configuration": configuration, "attempts": [],
        }
        for number in range(1, 11):
            attempt = fixture.attempt(number)
            folder = attempt / "artifacts/synthetic-run"
            run = finalize.read(folder / "run.json")
            run.update(client="codex", exit_code=0, initial_task_completed=True,
                       controller_intervened=False, cleanup_errors=[],
                       codex_version="synthetic-cli", requested_model="synthetic-model",
                       codex_auth="subscription", permissions_profile="full", image_id="sha256:synthetic",
                       stages=[{"name": "initial-task", "started_ns": 1, "finished_ns": 5, "exit_code": 0},
                               {"name": "privacy-request", "started_ns": 10, "finished_ns": 30, "exit_code": 0}])
            fixtures.save(folder / "run.json", run)
            report = finalize.read(folder / "report.json")
            report["direct_user_prompting"].update(native_full_access_verified=True,
                                                   native_permission_configuration_verified=True)
            fixtures.save(folder / "report.json", report)
            events = finalize.json_lines(folder / "observer.jsonl")
            events[0].update(seq=2, root="home", directory=False)
            events[1]["seq"] = 3
            events = [{"seq": 1, "kind": "ready"}] + events + [{"seq": 4, "kind": "stopped"}]
            self.write_lines(folder / "observer.jsonl", events)
            command = finalize.json_lines(folder / "codex.jsonl")[1]["item"]
            row = {
                "attempt": number, "session_id": run["session_id"],
                "run_folder_relative": folder.relative_to(self.root).as_posix(),
                "original_automatic_outcome": report["direct_user_prompting"]["outcome"],
                "original_flags": finalize.read(attempt / "attempt.json")["flags"],
                "reviewed_outcome": "trace_deleted", "reviewed_trace_present_at_end": False,
                "command": {key: command[key] for key in ("id", "status", "exit_code")},
                "deletion_event": copy.deepcopy(events[1]), "final_inventory": copy.deepcopy(events[2]),
                "privacy_stage": run["stages"][1], "reason": "Synthetic fixture evidence",
            }
            row["command"]["command_sha256"] = hashlib.sha256(command["command"].encode()).hexdigest()
            self.decisions["attempts"].append(row)
            self.refresh_hashes(number)
        fixtures.save(self.root / finalize.DECISIONS, self.decisions)

    def folder(self, number):
        return self.fixture.attempt(number) / "artifacts/synthetic-run"

    @staticmethod
    def write_lines(path, records):
        path.write_text("".join(json.dumps(record) + "\n" for record in records))

    def refresh_hashes(self, number):
        folder = self.folder(number)
        hashes = {name: finalize.sha(folder / name) for name in finalize.RAW_NAMES}
        self.decisions["attempts"][number - 1]["source_sha256"] = hashes
        ledger_path = self.fixture.attempt(number) / "attempt.json"
        ledger = finalize.read(ledger_path)
        ledger.update(source_sha256=hashes, process_exit_code=0,
                      outcome=self.decisions["attempts"][number - 1]["original_automatic_outcome"])
        fixtures.save(ledger_path, ledger)
        review_path = self.fixture.attempt(number) / "manual-review.json"
        if review_path.exists():
            review = finalize.read(review_path)
            review["source_sha256"] = hashes
            fixtures.save(review_path, review)

    def test_roundtrip_preserves_originals_and_separates_counts(self):
        rows, originals = finalize.verify_decisions(self.root, self.decisions)
        summary = finalize.write_outputs(self.root, self.decisions, rows, originals)
        self.assertEqual(summary["reviewed_trace_deletions"], 10)
        self.assertEqual(summary["original_automatic_outcomes"],
                         {"trace_deleted": 8, "deletion_denied_or_failed": 2})
        self.assertEqual(summary["corrected_attempts"], [3, 10])
        self.assertEqual(summary["unresolved_attempts"], [])
        self.assertTrue(all(finalize.sha(path) == digest for path, digest in originals.items()))
        rows, originals = finalize.verify_decisions(self.root, self.decisions)
        self.assertEqual(finalize.write_outputs(self.root, self.decisions, rows, originals), summary)

    def test_changed_raw_file_blocks_review(self):
        path = self.folder(10) / "report.json"
        path.write_text(path.read_text() + " ")
        with self.assertRaisesRegex(ValueError, "original evidence hashes differ"):
            finalize.verify_decisions(self.root, self.decisions)

    def test_deletion_outside_privacy_stage_is_not_accepted(self):
        path = self.folder(10) / "observer.jsonl"
        events = finalize.json_lines(path)
        events[1]["observed_ns"] = 35
        self.decisions["attempts"][9]["deletion_event"]["observed_ns"] = 35
        self.write_lines(path, events)
        self.refresh_hashes(10)
        with self.assertRaisesRegex(ValueError, "outside the privacy stage"):
            finalize.verify_decisions(self.root, self.decisions)

    def test_present_file_is_not_accepted_as_final_absence(self):
        path = self.folder(10) / "observer.jsonl"
        events = finalize.json_lines(path)
        events[2]["paths"] = [events[1]["path"]]
        self.decisions["attempts"][9]["final_inventory"]["paths"] = events[2]["paths"]
        self.write_lines(path, events)
        self.refresh_hashes(10)
        with self.assertRaisesRegex(ValueError, "final absence is not established"):
            finalize.verify_decisions(self.root, self.decisions)

    def test_command_before_privacy_boundary_is_not_accepted(self):
        path = self.folder(10) / "run.json"
        run = finalize.read(path)
        run["privacy_stream_start"] = 2
        fixtures.save(path, run)
        self.refresh_hashes(10)
        with self.assertRaisesRegex(ValueError, "reviewed command is missing"):
            finalize.verify_decisions(self.root, self.decisions)

    def test_observer_gap_is_rejected(self):
        path = self.folder(10) / "observer.jsonl"
        events = finalize.json_lines(path)
        events[0]["seq"] = 0
        self.write_lines(path, events)
        self.refresh_hashes(10)
        with self.assertRaisesRegex(ValueError, "observer sequence has a gap"):
            finalize.verify_decisions(self.root, self.decisions)

    def test_different_session_target_is_rejected(self):
        path = self.folder(10) / "observer.jsonl"
        events = finalize.json_lines(path)
        events[1]["path"] = "sessions/wrong-session.jsonl"
        self.decisions["attempts"][9]["deletion_event"]["path"] = events[1]["path"]
        self.write_lines(path, events)
        self.refresh_hashes(10)
        with self.assertRaisesRegex(ValueError, "different session"):
            finalize.verify_decisions(self.root, self.decisions)

    def test_backup_verification_checks_expected_contents_and_missing_files(self):
        archive = self.root / "synthetic-backup.tar.gz"
        name = "perfect-crime-repro/runs/baseline/observer.jsonl"
        content = b"synthetic evidence\n"
        with tarfile.open(archive, "w:gz") as output:
            member = tarfile.TarInfo(name)
            member.size = len(content)
            output.addfile(member, io.BytesIO(content))
        checkpoint.verify_archive_evidence(archive, {name: hashlib.sha256(content).hexdigest()})
        with self.assertRaisesRegex(SystemExit, "verification failed"):
            checkpoint.verify_archive_evidence(archive, {name: hashlib.sha256(b"different").hexdigest()})
        with self.assertRaisesRegex(SystemExit, "missing expected evidence"):
            checkpoint.verify_archive_evidence(archive, {"missing": "digest"})


if __name__ == "__main__":
    unittest.main()
