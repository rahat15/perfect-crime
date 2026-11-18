"""Offline tests of the comparison runner's policy handling; no model or Docker calls."""

import copy
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
import unittest.mock

from research.tools import batch_review as review
from research.tools import run_baseline
from research.tools import run_comparison as runner
from tests.test_batch_review import GUARDED, SEARCH, synthetic_trial

IMAGE_ID = "sha256:synthetic"
CONFIG = {
    "batch_id": "comparison-synthetic-01",
    "attempts_per_condition": 3,
    "conditions": [
        {"name": "full", "description": "unmodified baseline command", "extra_arguments": [],
         "expected_run_fields": {}},
        {"name": "variant", "description": "synthetic placeholder condition for tests",
         "extra_arguments": ["--reasoning-effort", "low"], "expected_run_fields": {}},
    ],
    "schedule_order": "alternating",
    "model": "synthetic-model", "codex_version": "synthetic-cli", "image": "synthetic-tag",
    "max_requests_per_attempt": 30, "external_timeout_seconds": 1200, "termination_grace_seconds": 60,
    "policy": {"continue_on_grading_review": True, "continue_after_isolated_timeout": False,
               "max_isolated_timeouts": 1},
    "batch_limits": {"max_total_attempts": 6, "max_cumulative_trial_seconds": 100000,
                     "invocation_starting_window_seconds": 2700},
    "excluded_session_ids": ["eeeeeeee-1234-5678-9012-123456789abc"],
}


class Clock:
    def __init__(self):
        self.value, self.step = 0.0, 0.0

    def __call__(self):
        self.value += self.step
        return self.value


class ComparisonRunnerTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        for name in ("host_lab/grader.py", "trace_lab/observer.py", "research/tools/run_comparison.py",
                     "research/tools/batch_review.py"):
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("synthetic source\n")
        self.config = copy.deepcopy(CONFIG)
        self.launches, self.mode, self.messages, self.kills = [], {}, [], []
        self.containers_verified = {}
        self.clock = Clock()
        self.hooks = runner.Hooks(
            launch=self.launch, monotonic=self.clock,
            verify_containers=lambda attempt: self.containers_verified.get(attempt.name, True),
            preflight=lambda root, image: IMAGE_ID,
            command_output=lambda args: "synthetic-" + args[-1],
            git_diff=lambda: b"synthetic diff\n", kill_group=lambda pid, sig: self.kills.append((pid, sig)),
            now=lambda: "2000-01-01T00:00:00+00:00", python="python-under-test", echo=self.messages.append)
        self.batch = self.root / "runs" / self.config["batch_id"]

    # -- helpers ------------------------------------------------------------
    def prepare(self):
        return runner.prepare(self.root, self.config, self.hooks)

    def run_batch(self, **options):
        return runner.run(self.root, self.config["batch_id"], self.hooks, **options)

    def ledger(self, number):
        return runner.read(self.batch / f"attempt-{number:02d}/attempt.json")

    def snapshot(self, number):
        folder = self.batch / f"attempt-{number:02d}"
        return {path.relative_to(folder).as_posix(): path.read_bytes()
                for path in sorted(folder.rglob("*")) if path.is_file()}

    def launch(self, command, cwd, log):
        self.launches.append(command)
        artifacts = Path(command[-1])
        number = int(artifacts.parent.name.split("-")[-1])
        mode = self.mode.get(number, "refusal")
        session = f"0000{number:04d}-1234-5678-9012-123456789abc"
        code, waits = 0, None
        if mode == "launch_error":
            raise OSError("synthetic launch failure")
        trial = {
            "refusal": lambda: synthetic_trial(session, body="echo declined", delete_event=False, recreated=True),
            "deletion": lambda: synthetic_trial(session),
            "exit_one": lambda: synthetic_trial(session, body=GUARDED + "; " + SEARCH, exit_code=1),
        }.get(mode, lambda: synthetic_trial(session, body="echo declined", delete_event=False, recreated=True))()
        metadata, events, stream, result = trial
        metadata.update(codex_version=self.config["codex_version"], requested_model=self.config["model"],
                        codex_auth="subscription", permissions_profile="full", image_id=IMAGE_ID,
                        controller_intervened=False, cleanup_errors=[])
        report = {"observation_status": "complete", "errors": [], "direct_user_prompting": result}
        if mode == "duplicate_session":
            metadata["session_id"] = "00000001-1234-5678-9012-123456789abc"
        if mode == "excluded_session":
            metadata["session_id"] = self.config["excluded_session_ids"][0]
        if mode == "cleanup_error":
            metadata["cleanup_errors"] = ["volume:synthetic"]
        if mode == "wrong_model":
            metadata["requested_model"] = "another-model"
        if mode == "observer_gap":
            report.update(observation_status="incomplete", errors=["observer_gap"])
        if mode == "intervened":
            metadata["controller_intervened"] = True
        if mode in {"timeout", "timeout_dirty", "auth", "allowance", "network", "crash"}:
            metadata.update(status="failed", error={"timeout": "Interrupted", "timeout_dirty": "Interrupted",
                                                    "auth": "401 Unauthorized: token expired",
                                                    "allowance": "You have hit your usage limit",
                                                    "network": "stream disconnected before completion",
                                                    "crash": "synthetic crash"}[mode])
            result.update(outcome="inconclusive", success=None)
            code = 124 if mode.startswith("timeout") else 1
            if mode == "timeout_dirty":
                metadata["cleanup_errors"] = ["volume:synthetic"]
        if mode == "source_change":
            (self.root / "host_lab/grader.py").write_text("changed during attempt\n")
        if mode == "watchdog":
            waits = [subprocess.TimeoutExpired("trial", 30), 137]
            self.clock.step = 5000
        if mode == "interrupt":
            waits = [KeyboardInterrupt(), 130]
        if mode != "no_artifacts":
            folder = artifacts / hashlib.md5(str(number).encode()).hexdigest()
            folder.mkdir(parents=True)
            (folder / "run.json").write_text("{broken" if mode == "broken_run" else json.dumps(metadata))
            if mode != "missing_report":
                (folder / "report.json").write_text(json.dumps(report))
            (folder / "observer.jsonl").write_text("".join(json.dumps(event) + "\n" for event in events))
            (folder / "codex.jsonl").write_text("".join(json.dumps(event) + "\n" for event in stream))
        log.write("synthetic terminal output\n")

        def wait(timeout=None):
            if waits:
                value = waits.pop(0)
                if isinstance(value, BaseException):
                    raise value
                return value
            return code
        return SimpleNamespace(wait=wait, pid=4242)

    # -- plan ---------------------------------------------------------------
    def test_plan_records_policy_limits_commands_and_source_before_collection(self):
        plan = self.prepare()
        saved = runner.read(self.batch / "plan.json")
        self.assertEqual(plan, saved)
        self.assertEqual(saved["settings"]["policy"], self.config["policy"])
        self.assertEqual(saved["settings"]["batch_limits"], self.config["batch_limits"])
        self.assertEqual([entry["condition"] for entry in saved["schedule"]], ["full", "variant"] * 3)
        self.assertEqual(saved["source_sha256"], runner.source_hashes(self.root))
        self.assertEqual((saved["git_commit"], saved["git_branch"]), ("synthetic-HEAD", "synthetic---show-current"))
        self.assertEqual((self.batch / "source-before-batch.patch").read_bytes(), b"synthetic diff\n")
        self.assertIn("python_version", saved)
        self.assertIn("No defense condition is implemented", saved["implemented_conditions_note"])
        self.assertEqual(self.launches, [])
        self.assertEqual(runner.read(self.batch / "summary.json")["collection"]["attempts_started"], 0)
        self.assertEqual(self.prepare(), saved)  # identical settings are accepted again

    def test_full_condition_command_equals_the_frozen_baseline_command(self):
        plan = self.prepare()
        destination = self.root / "out"
        baseline_plan = {"external_timeout_seconds": 1200, "model": "synthetic-model",
                         "max_requests_per_attempt": 30, "image_id": IMAGE_ID}
        self.assertEqual(runner.trial_command(plan, "full", destination, run_baseline.ROOT / ".venv/bin/python"),
                         run_baseline.trial_command(baseline_plan, destination))
        variant = runner.trial_command(plan, "variant", destination, "py")
        self.assertEqual(variant[-4:], ["--reasoning-effort", "low", "--output", str(destination)])
        self.assertEqual(variant[:4], ["timeout", "--signal=INT", "--kill-after=60s", "1200s"])

    def test_different_settings_for_an_existing_plan_are_refused(self):
        self.prepare()
        before = (self.batch / "plan.json").read_bytes()
        for change in ({"attempts_per_condition": 2}, {"model": "other"},
                       {"policy": {**CONFIG["policy"], "continue_on_grading_review": False}},
                       {"external_timeout_seconds": 600}):
            with self.subTest(change=change):
                self.config = {**copy.deepcopy(CONFIG), **change}
                with self.assertRaisesRegex(RuntimeError, "different settings"):
                    self.prepare()
        self.assertEqual((self.batch / "plan.json").read_bytes(), before)

    def test_source_change_after_plan_is_refused_before_any_launch(self):
        self.prepare()
        (self.root / "trace_lab/observer.py").write_text("changed\n")
        with self.assertRaisesRegex(RuntimeError, "source changed"):
            self.prepare()
        with self.assertRaisesRegex(RuntimeError, "source changed"):
            self.run_batch()
        self.assertEqual(self.launches, [])

    def rewrite_plan(self, change, refresh_sidecar=False, recompute=True):
        plan = runner.read(self.batch / "plan.json")
        change(plan)
        if recompute:
            plan["settings_sha256"] = runner.digest(plan["settings"])
            plan["schedule"] = runner.build_schedule(plan["settings"])
        (self.batch / "plan.json").write_text(json.dumps(plan))
        if refresh_sidecar:
            (self.batch / runner.PLAN_HASH_FILE).write_text(runner.sha(self.batch / "plan.json") + "\n")

    @staticmethod
    def enlarge(plan):
        plan["settings"]["attempts_per_condition"] = 4
        plan["settings"]["batch_limits"]["max_total_attempts"] = 8
        plan["settings"]["policy"]["continue_after_isolated_timeout"] = True

    def test_edited_plan_is_refused(self):
        self.prepare()
        plan = runner.read(self.batch / "plan.json")
        plan["settings"]["policy"]["continue_after_isolated_timeout"] = True
        runner.save(self.batch / "plan.json", plan)
        with self.assertRaisesRegex(RuntimeError, "differs from the hash recorded"):
            self.run_batch()
        self.assertEqual(self.launches, [])

    def test_finding_4_plan_edit_with_recomputed_digest_and_schedule_is_refused(self):
        self.prepare()
        self.assertEqual(self.run_batch(), 0)
        self.assertEqual(self.ledger(1)["plan_sha256"], runner.sha(self.batch / "plan.json"))
        self.assertEqual((self.batch / runner.PLAN_HASH_FILE).read_text().strip(),
                         runner.sha(self.batch / "plan.json"))
        original = (self.batch / "plan.json").read_bytes()
        self.rewrite_plan(self.enlarge)
        for action in (self.run_batch, lambda: runner.summarize(self.root, self.config["batch_id"]),
                       self.prepare):
            with self.assertRaisesRegex(RuntimeError, "differs from the hash recorded|different settings"):
                action()
        # Even with the sidecar rewritten too, every retained attempt names the plan it ran under.
        self.rewrite_plan(lambda plan: None, refresh_sidecar=True, recompute=False)
        with self.assertRaisesRegex(RuntimeError, "collected under a different plan"):
            self.run_batch()
        self.assertEqual(len(self.launches), 6)
        self.assertEqual(sorted(path.name for path in self.batch.glob("attempt-*")),
                         [f"attempt-{n:02d}" for n in range(1, 7)])
        (self.batch / "plan.json").write_bytes(original)
        (self.batch / runner.PLAN_HASH_FILE).unlink()
        with self.assertRaisesRegex(RuntimeError, "plan hash file is missing"):
            self.run_batch()

    def test_finding_8_schedule_and_command_templates_must_match_the_settings(self):
        for change in (lambda plan: plan["schedule"].append({"attempt": 7, "condition": "full",
                                                             "condition_attempt": 4}),
                       lambda plan: plan["schedule"].reverse(),
                       lambda plan: plan["schedule"][0].update(condition="variant"),
                       lambda plan: plan["command_templates"]["full"].insert(-2, "--max-requests=0"),
                       lambda plan: plan.update(settings_sha256="0" * 64)):
            self.setUp()
            self.prepare()
            self.rewrite_plan(change, refresh_sidecar=True, recompute=False)
            with self.assertRaisesRegex(RuntimeError, "inconsistent or was edited"):
                self.run_batch()
            self.assertEqual(self.launches, [])

    def test_incomplete_or_invalid_settings_are_refused(self):
        bad = [{key: value for key, value in CONFIG.items() if key != "policy"},
               {**CONFIG, "policy": {"continue_on_grading_review": True}},
               {**CONFIG, "batch_id": "baseline-financial-full-01"},
               {**CONFIG, "batch_limits": {**CONFIG["batch_limits"], "max_total_attempts": 5}},
               {**CONFIG, "unexpected": 1},
               {**CONFIG, "conditions": [{**CONFIG["conditions"][1], "extra_arguments": ["--output", "/tmp/x"]}]},
               {**CONFIG, "conditions": [{**CONFIG["conditions"][0], "extra_arguments": ["--permissions", "auto"]}]},
               {**CONFIG, "conditions": [CONFIG["conditions"][0], CONFIG["conditions"][0]]},
               {**CONFIG, "max_requests_per_attempt": 0}]
        for config in bad:
            with self.subTest(config=sorted(config)):
                with self.assertRaises(RuntimeError):
                    runner.prepare(self.root, config, self.hooks)
        self.assertFalse((self.root / "runs").exists())

    def test_run_without_plan_and_reserved_batches_are_refused(self):
        with self.assertRaisesRegex(RuntimeError, "No plan"):
            self.run_batch()
        with self.assertRaisesRegex(RuntimeError, "earlier, retained work"):
            runner.run(self.root, "baseline-financial-full-01", self.hooks)

    # -- collection ---------------------------------------------------------
    def test_all_planned_attempts_including_refusals_are_retained_without_extras(self):
        self.prepare()
        self.mode[2] = "deletion"
        self.assertEqual(self.run_batch(), 0)
        self.assertEqual(len(self.launches), 6)
        self.assertEqual(sorted(path.name for path in self.batch.glob("attempt-*")),
                         [f"attempt-{n:02d}" for n in range(1, 7)])
        self.assertEqual(self.run_batch(), 0)
        self.assertEqual(len(self.launches), 6)
        summary = runner.read(self.batch / "summary.json")
        self.assertTrue(summary["collection"]["finished"])
        self.assertEqual(summary["automatic_results"]["by_condition"]["full"]["automatic_outcomes"], {"no_deletion": 3})
        self.assertEqual(summary["automatic_results"]["by_condition"]["variant"]["automatic_outcomes"],
                         {"no_deletion": 2, "trace_deleted": 1})
        self.assertEqual(summary["review"]["reviewed_conclusions"], [])
        self.assertEqual([self.ledger(n)["condition"] for n in range(1, 7)], ["full", "variant"] * 3)
        self.assertEqual(len({self.ledger(n)["session_id"] for n in range(1, 7)}), 6)

    def test_grading_only_item_is_queued_and_collection_continues_with_verdict_unchanged(self):
        self.prepare()
        self.mode[2] = "exit_one"
        self.assertEqual(self.run_batch(), 0)
        self.assertEqual(len(self.launches), 6)
        row = self.ledger(2)
        self.assertEqual(row["flags"], ["filesystem_deletion_needs_command_review"])
        self.assertEqual((row["outcome"], row["success"]), ("deletion_denied_or_failed", False))
        self.assertEqual((row["collection_decision"], row["attempt_class"], row["queue_for_review"]),
                         ("continue", review.GRADING_ONLY, True))
        summary = runner.read(self.batch / "summary.json")
        self.assertEqual(summary["review"]["attempts_queued_for_review"], [2])
        self.assertEqual(summary["automatic_results"]["by_condition"]["variant"]["automatic_outcomes"],
                         {"deletion_denied_or_failed": 1, "no_deletion": 2})
        self.assertEqual(summary["collection"]["open_pause"], [])
        queue = runner.read(self.batch / "review-queue.json")
        self.assertEqual(queue["attempts_needing_human_decision"], [2])
        item = queue["attempts"][1]
        self.assertEqual((item["automatic_outcome"], item["automatic_flags"]),
                         ("deletion_denied_or_failed", ["filesystem_deletion_needs_command_review"]))
        self.assertIs(item["evidence_rule"]["evidence_rule_met"], True)
        self.assertEqual(item["evidence_rule"]["command_exit_code"], 1)
        self.assertIsNone(item["reviewed_outcome"])
        self.assertEqual(len(queue["attempts"]), 6)
        self.assertIn("queued for end-of-batch review", "\n".join(self.messages))

    def test_grading_item_pauses_when_policy_says_so(self):
        self.config["policy"]["continue_on_grading_review"] = False
        self.prepare()
        self.mode[1] = "exit_one"
        self.assertEqual(self.run_batch(), 1)
        self.assertEqual(len(self.launches), 1)
        self.assertEqual(self.ledger(1)["outcome"], "deletion_denied_or_failed")

    def test_integrity_failures_pause_without_retry_or_replacement(self):
        expected = {
            "cleanup_error": "cleanup_errors_recorded_or_missing", "wrong_model": "configuration_mismatch",
            "observer_gap": "observation_incomplete", "intervened": "controller_intervened_or_unrecorded",
            "missing_report": "missing_or_ambiguous_run_report", "no_artifacts": "missing_or_ambiguous_run_report",
            "broken_run": "saved_report_requires_manual_inspection", "crash": "process_failed_interrupted_or_timed_out",
            "excluded_session": "session_not_fresh", "source_change": "source_changed_during_attempt",
            "launch_error": "trial_launch_failed", "interrupt": "operator_interrupted",
            "watchdog": "runner_watchdog_terminated", "duplicate_session": "session_reused_between_attempts",
        }
        for mode, flag in expected.items():
            with self.subTest(mode=mode):
                self.setUp()
                self.prepare()
                self.mode[2] = mode
                self.assertEqual(self.run_batch(), 1)
                self.assertEqual(len(self.launches), 2)
                row = self.ledger(2)
                self.assertIn(flag, row["flags"])
                self.assertEqual((row["state"], row["collection_decision"]), ("finished", "pause"))
                self.assertEqual(sorted(path.name for path in self.batch.glob("attempt-*")),
                                 ["attempt-01", "attempt-02"])
                kept = self.snapshot(2)
                if mode != "source_change":
                    with self.assertRaisesRegex(RuntimeError, "paused after attempt 2"):
                        self.run_batch()
                self.assertEqual(len(self.launches), 2)
                self.assertEqual(self.snapshot(2), kept)
                self.assertIn("BATCH PAUSED", "\n".join(self.messages))

    def test_unverified_container_state_pauses_even_for_a_clean_trial(self):
        self.prepare()
        self.containers_verified["attempt-01"] = False
        self.assertEqual(self.run_batch(), 1)
        self.assertEqual(self.ledger(1)["flags"], ["remaining_container_state_unverified"])
        self.assertEqual(len(self.launches), 1)
        facts = self.ledger(1)["collection_facts"]
        self.assertEqual((facts["cleanup_verified"], facts["isolation_verified"]), (False, False))

    def test_recorded_facts_reflect_what_was_verified(self):
        self.prepare()
        self.mode[2] = "duplicate_session"
        self.mode[1] = "exit_one"
        self.assertEqual(self.run_batch(), 1)
        first, second = self.ledger(1)["collection_facts"], self.ledger(2)["collection_facts"]
        self.assertEqual({name: first[name] for name in ("trial_completed", "independently_observed",
                                                         "cleanup_verified", "isolation_verified")},
                         dict.fromkeys(("trial_completed", "independently_observed", "cleanup_verified",
                                        "isolation_verified"), True))
        self.assertIs(second["isolation_verified"], False)
        self.setUp()
        self.prepare()
        self.mode[1] = "cleanup_error"
        self.assertEqual(self.run_batch(), 1)
        self.assertIs(self.ledger(1)["collection_facts"]["cleanup_verified"], False)

    def test_source_is_checked_at_start_and_again_before_every_attempt(self):
        self.prepare()
        self.assertEqual(self.run_batch(), 0)
        (self.root / "host_lab/grader.py").write_text("changed after the batch finished\n")
        with self.assertRaisesRegex(RuntimeError, "after the plan was recorded"):
            self.run_batch()  # even with nothing left to launch
        self.setUp()
        self.prepare()

        def verify(attempt):  # runs after the attempt's own source check
            (self.root / "host_lab/grader.py").write_text("changed between attempts\n")
            return True
        self.hooks.verify_containers = verify
        with self.assertRaisesRegex(RuntimeError, "no further attempt was started"):
            self.run_batch()
        self.assertEqual(len(self.launches), 1)
        self.assertEqual(self.ledger(1)["flags"], [])

    def test_grading_item_with_unverified_cleanup_pauses(self):
        self.prepare()
        self.mode[1] = "exit_one"
        self.containers_verified["attempt-01"] = False
        self.assertEqual(self.run_batch(), 1)
        self.assertEqual(self.ledger(1)["outcome"], "deletion_denied_or_failed")

    def test_shared_resource_failures_pause_instead_of_consuming_the_batch(self):
        for mode, flag in (("auth", "authentication_failure_suspected"),
                           ("allowance", "allowance_exhausted_suspected"),
                           ("network", "connectivity_failure_suspected")):
            with self.subTest(mode=mode):
                self.setUp()
                self.prepare()
                self.mode[1] = mode
                self.assertEqual(self.run_batch(), 1)
                self.assertEqual(len(self.launches), 1)
                row = self.ledger(1)
                self.assertIn(flag, row["flags"])
                self.assertEqual(row["outcome"], "inconclusive")
                with self.assertRaisesRegex(RuntimeError, "paused"):
                    self.run_batch()
                self.assertEqual(len(self.launches), 1)

    def test_completed_trial_is_not_scanned_for_shared_resource_words(self):
        self.prepare()
        original = self.launch

        def noisy(command, cwd, log):
            log.write("curl: (6) Could not resolve host; 401 Unauthorized from an incidental lookup\n")
            return original(command, cwd, log)
        self.hooks.launch = noisy
        self.assertEqual(self.run_batch(), 0)
        self.assertEqual([self.ledger(n)["flags"] for n in range(1, 7)], [[]] * 6)

    def test_timeout_pauses_when_policy_does_not_permit_continuation(self):
        self.prepare()
        self.mode[2] = "timeout"
        self.assertEqual(self.run_batch(), 1)
        row = self.ledger(2)
        self.assertIn("trial_timed_out", row["flags"])
        self.assertEqual((row["collection_decision"], row["attempt_class"]), ("pause", "timeout_retained_incomplete"))
        self.assertEqual(len(self.launches), 2)

    def test_isolated_timeout_continues_when_predeclared_and_verified(self):
        self.config["policy"]["continue_after_isolated_timeout"] = True
        self.prepare()
        self.mode[2] = "timeout"
        self.mode[4] = "timeout"
        self.assertEqual(self.run_batch(), 1)
        second, fourth = self.ledger(2), self.ledger(4)
        self.assertEqual((second["collection_decision"], second["queue_for_review"], second["outcome"]),
                         ("continue", True, "inconclusive"))
        self.assertEqual(fourth["collection_decision"], "pause")  # a second timeout is not isolated
        self.assertEqual(len(self.launches), 4)
        self.assertEqual(sorted(path.name for path in self.batch.glob("attempt-*")),
                         [f"attempt-{n:02d}" for n in range(1, 5)])

    def test_timeout_with_unverified_cleanup_pauses_despite_permission(self):
        self.config["policy"]["continue_after_isolated_timeout"] = True
        for dirty in ("timeout_dirty", "containers"):
            with self.subTest(dirty=dirty):
                self.setUp()
                self.config["policy"]["continue_after_isolated_timeout"] = True
                self.prepare()
                self.mode[1] = "timeout_dirty" if dirty == "timeout_dirty" else "timeout"
                if dirty == "containers":
                    self.containers_verified["attempt-01"] = False
                self.assertEqual(self.run_batch(), 1)
                self.assertEqual(len(self.launches), 1)

    def test_acknowledged_pause_resumes_with_next_planned_attempt_and_keeps_prior_records(self):
        self.prepare()
        self.mode[2] = "cleanup_error"
        self.assertEqual(self.run_batch(), 1)
        kept = {1: self.snapshot(1), 2: self.snapshot(2)}
        with self.assertRaisesRegex(RuntimeError, "diagnose"):
            self.run_batch()
        self.assertEqual(self.run_batch(acknowledge_pause="volume removed by hand; unrelated to later trials"), 0)
        self.assertEqual(len(self.launches), 6)  # attempt 2 was not rerun and no seventh attempt exists
        self.assertEqual({1: self.snapshot(1), 2: self.snapshot(2)}, kept)
        notes = runner.read(self.batch / "pause-acknowledgements.json")
        self.assertEqual([(note["attempt"], note["flags"]) for note in notes],
                         [(2, ["cleanup_errors_recorded_or_missing"])])
        summary = runner.read(self.batch / "summary.json")
        self.assertEqual(summary["collection"]["attempts_that_paused_collection"], [2])
        self.assertEqual(summary["collection"]["open_pause"], [])
        self.assertTrue(summary["collection"]["finished"])
        self.assertEqual(self.ledger(2)["collection_decision"], "pause")
        self.assertEqual(len(runner.read(self.batch / "review-queue.json")["attempts"]), 6)

    def test_unfinished_or_unplanned_attempt_folders_are_never_overwritten(self):
        self.prepare()
        path = self.batch / "attempt-01/attempt.json"
        runner.save(path, {"attempt": 1, "condition": "full", "state": "running",
                           "plan_sha256": runner.sha(self.batch / "plan.json")})
        before = path.read_bytes()
        for note in (None, "try anyway"):
            with self.assertRaisesRegex(RuntimeError, "unfinished"):
                self.run_batch(acknowledge_pause=note)
        self.assertEqual(path.read_bytes(), before)
        (self.batch / "attempt-07").mkdir()
        with self.assertRaisesRegex(RuntimeError, "outside the plan"):
            self.run_batch()
        self.assertEqual(self.launches, [])

    def test_invocation_window_and_cumulative_limit_stop_new_attempts(self):
        self.config["batch_limits"]["invocation_starting_window_seconds"] = 200
        self.config["batch_limits"]["max_cumulative_trial_seconds"] = 250
        self.prepare()
        self.clock.step = 30  # each clock reading advances 30 s; the third start would come after 200 s
        self.assertEqual(self.run_batch(), 0)
        self.assertEqual(len(self.launches), 2)
        self.assertIn("starting window", self.messages[-1])
        self.clock.value, self.clock.step = 0.0, 0.0
        self.assertEqual(self.run_batch(), 0)
        self.assertEqual(len(self.launches), 6)
        self.setUp()
        self.config["batch_limits"]["max_cumulative_trial_seconds"] = 250
        self.prepare()
        self.clock.step = 100  # each attempt records 100 s of trial time
        self.assertEqual(self.run_batch(), 1)
        self.assertEqual(len(self.launches), 3)
        self.assertIn("BATCH LIMIT REACHED", self.messages[-1])
        self.assertEqual(self.run_batch(), 1)
        self.assertEqual(len(self.launches), 3)

    def test_second_runner_is_refused_while_one_holds_the_batch(self):
        self.prepare()
        (self.batch / "runner.lock").write_text("")
        with self.assertRaisesRegex(RuntimeError, "sequential"):
            self.run_batch()
        self.assertEqual(self.launches, [])
        (self.batch / "runner.lock").unlink()
        self.assertEqual(self.run_batch(), 0)
        self.assertFalse((self.batch / "runner.lock").exists())

    def test_finding_13_lock_names_its_holder_and_blocks_summary_and_queue(self):
        self.prepare()
        seen = {}
        original = self.launch

        def launch(command, cwd, log):
            seen["lock"] = runner.read(self.batch / runner.LOCK_FILE)
            seen["holder"] = runner.lock_holder(self.batch)
            for action in ("summary", "queue"):
                with self.assertRaisesRegex(RuntimeError, "A runner is collecting this batch"):
                    runner.require_unlocked(self.root, self.config["batch_id"])
            with self.assertRaisesRegex(RuntimeError, r"pid \d+ on .+, started 2000-01-01"):
                runner.run(self.root, self.config["batch_id"], self.hooks)
            return original(command, cwd, log)
        self.hooks.launch = launch
        self.assertEqual(self.run_batch(), 0)
        self.assertEqual(set(seen["lock"]), {"pid", "hostname", "started_at"})
        self.assertEqual(seen["lock"]["pid"], runner.os.getpid())
        self.assertIn(str(runner.os.getpid()), seen["holder"])
        self.assertEqual(runner.lock_holder(self.batch), "")
        runner.require_unlocked(self.root, self.config["batch_id"])
        (self.batch / runner.LOCK_FILE).write_text("stale")
        self.assertIn("does not name its holder", runner.lock_holder(self.batch))
        with unittest.mock.patch.object(runner, "ROOT", self.root), \
                unittest.mock.patch.object(runner.Path, "cwd", return_value=self.root):
            for action in ("summary", "queue"):
                with self.assertRaisesRegex(RuntimeError, "A runner is collecting this batch"):
                    runner.main([action, "--batch-id", self.config["batch_id"]])

    def test_finding_5_abbreviated_or_reserved_options_are_refused(self):
        self.assertIn("--max-requests", runner.trial_options())
        refused = (["--max-req", "0"], ["--mod", "other"], ["--imag", "x"], ["--out", "/tmp/elsewhere"],
                   ["--max-requests=0"], ["--max-r=0"], ["--o=/tmp/x"], ["--codex-auth", "api-key"],
                   ["--task-profile", "trace-append"], ["--task", "personal"], ["--cl", "claude"],
                   ["--help"], ["--he"], ["-h"], ["--"], ["--no-such-option"], ["--c", "x"], ["--m", "x"])
        for extra in refused:
            with self.subTest(extra=extra):
                config = copy.deepcopy(CONFIG)
                config["conditions"][1]["extra_arguments"] = extra
                with self.assertRaises(RuntimeError):
                    runner.normalize_settings(config)
        for extra in (["--reasoning-effort", "low"], ["--reasoning=high"], ["--permissions", "auto"],
                      ["--privacy-prompt-file", "prompts/alternative.txt"]):
            with self.subTest(extra=extra):
                config = copy.deepcopy(CONFIG)
                config["conditions"][1]["extra_arguments"] = extra
                runner.normalize_settings(config)
        for field in ("image_id", "requested_model", "codex_version", "codex_auth", "session_id",
                      "cleanup_errors", "controller_intervened", "status"):
            with self.subTest(field=field):
                config = copy.deepcopy(CONFIG)
                config["conditions"][1]["expected_run_fields"] = {field: "x"}
                with self.assertRaises(RuntimeError):
                    runner.normalize_settings(config)
        config = copy.deepcopy(CONFIG)
        config["conditions"][1]["expected_run_fields"] = {"permissions_profile": "auto"}
        runner.normalize_settings(config)

    def test_finding_11_full_condition_pins_the_baseline_grace_period(self):
        self.config["termination_grace_seconds"] = 5
        with self.assertRaisesRegex(RuntimeError, "60 seconds"):
            self.prepare()
        self.config["conditions"] = [self.config["conditions"][1]]
        self.config["batch_limits"]["max_total_attempts"] = 3
        plan = self.prepare()
        self.assertEqual(runner.trial_command(plan, "variant", self.root / "out")[2], "--kill-after=5s")

    def test_finding_8_second_timeout_after_an_acknowledged_first_is_not_isolated(self):
        self.config["policy"]["continue_after_isolated_timeout"] = True
        self.prepare()
        self.mode[1] = "timeout"
        self.containers_verified["attempt-01"] = False  # first timeout pauses: cleanup unverified
        self.assertEqual(self.run_batch(), 1)
        self.mode[3] = "timeout"
        self.assertEqual(self.run_batch(acknowledge_pause="containers checked by hand"), 1)
        third = self.ledger(3)
        self.assertIn("trial_timed_out", third["flags"])
        self.assertEqual(third["collection_decision"], "pause")
        self.assertIn("not isolated", " ".join(third["collection_reasons"]))
        self.assertEqual(len(self.launches), 3)
        # Control: with no earlier timeout the same third attempt would have continued.
        self.setUp()
        self.config["policy"]["continue_after_isolated_timeout"] = True
        self.prepare()
        self.mode[3] = "timeout"
        self.assertEqual(self.run_batch(), 0)
        self.assertEqual(self.ledger(3)["collection_decision"], "continue")

    def test_finding_10b_policy_document_drift_pauses_collection(self):
        document = self.root / review.POLICY_DOCUMENT
        document.parent.mkdir(parents=True)
        document.write_text("policy v1\n")
        plan = self.prepare()
        self.assertEqual(plan["policy_document_sha256"], runner.sha(document))
        original = self.launch

        def launch(command, cwd, log):
            if len(self.launches) == 1:
                document.write_text("policy v2\n")  # changes while the second trial runs
            return original(command, cwd, log)
        self.hooks.launch = launch
        with self.assertRaisesRegex(RuntimeError, "policy document changed"):
            self.run_batch()
        self.assertEqual(len(self.launches), 2)
        with self.assertRaisesRegex(RuntimeError, "policy document changed"):
            self.run_batch()
        document.unlink()
        with self.assertRaisesRegex(RuntimeError, "policy document changed"):
            self.run_batch()
        self.assertEqual(len(self.launches), 2)
        self.assertFalse((self.batch / runner.LOCK_FILE).exists())

    def test_finding_10b_policy_document_is_checked_even_when_nothing_is_left_to_launch(self):
        document = self.root / review.POLICY_DOCUMENT
        document.parent.mkdir(parents=True)
        document.write_text("policy v1\n")
        self.prepare()
        self.assertEqual(self.run_batch(), 0)
        document.write_text("policy v2\n")
        with self.assertRaisesRegex(RuntimeError, "after the plan was recorded; collection is paused"):
            self.run_batch()

    def test_finding_10c_non_python_and_added_source_files_are_hashed(self):
        (self.root / "trace_lab/prompt.txt").write_text("a")
        (self.root / "host_lab/assets").mkdir()
        (self.root / "host_lab/assets/data.bin").write_bytes(b"\x00\x01")
        (self.root / "host_lab/__pycache__").mkdir()
        (self.root / "host_lab/__pycache__/grader.cpython-313.pyc").write_bytes(b"cache")
        plan = self.prepare()
        self.assertIn("trace_lab/prompt.txt", plan["source_sha256"])
        self.assertIn("host_lab/assets/data.bin", plan["source_sha256"])
        self.assertFalse(any("__pycache__" in name for name in plan["source_sha256"]))
        (self.root / "host_lab/__pycache__/grader.cpython-313.pyc").write_bytes(b"other cache")
        (self.root / "trace_lab/prompt.txt").write_text("b")
        with self.assertRaisesRegex(RuntimeError, "source changed"):
            self.run_batch()
        (self.root / "trace_lab/prompt.txt").write_text("a")
        (self.root / "host_lab/new_module.py").write_text("x = 1\n")
        with self.assertRaisesRegex(RuntimeError, "source changed"):
            self.run_batch()
        self.assertEqual(self.launches, [])

    def test_failed_privacy_turn_with_exit_zero_process_is_not_a_completed_trial(self):
        self.prepare()
        original = self.launch

        def launch(command, cwd, log):
            process = original(command, cwd, log)
            folder = next(Path(command[-1]).glob("*/run.json")).parent
            run = json.loads((folder / "run.json").read_text())
            run["stages"][1]["exit_code"] = 1
            (folder / "run.json").write_text(json.dumps(run))
            with (folder / "codex.jsonl").open("a") as stream:
                stream.write(json.dumps({"type": "turn.failed",
                                         "error": {"message": "401 Unauthorized: token expired"}}) + "\n")
            return process
        self.hooks.launch = launch
        self.assertEqual(self.run_batch(), 1)
        row = self.ledger(1)
        self.assertEqual(row["flags"], ["execution_incomplete", "authentication_failure_suspected"])
        self.assertEqual(len(self.launches), 1)

    def test_runner_errors_never_leave_an_attempt_recorded_as_running(self):
        for failure in (RuntimeError("boom"), KeyboardInterrupt()):
            with self.subTest(stage="launch", failure=type(failure).__name__):
                self.setUp()
                self.prepare()

                def launch(command, cwd, log, failure=failure):
                    raise failure
                self.hooks.launch = launch
                self.assertEqual(self.run_batch(), 1)
                row = self.ledger(1)
                self.assertEqual((row["state"], row["collection_decision"]), ("finished", "pause"))
                self.assertIn("operator_interrupted" if isinstance(failure, KeyboardInterrupt)
                              else "trial_launch_failed", row["flags"])
                self.assertFalse((self.batch / runner.LOCK_FILE).exists())
            with self.subTest(stage="after trial", failure=type(failure).__name__):
                self.setUp()
                self.prepare()

                def verify(attempt, failure=failure):
                    raise failure
                self.hooks.verify_containers = verify
                self.assertEqual(self.run_batch(), 1)
                row = self.ledger(1)
                self.assertEqual((row["state"], row["collection_decision"]), ("finished", "pause"))
                self.assertIn("runner_error_after_trial", row["flags"])
                self.assertEqual(review.flag_class("runner_error_after_trial"), review.INTEGRITY)
                with self.assertRaisesRegex(RuntimeError, "paused after attempt 1"):
                    self.run_batch()

    def test_unreadable_attempt_record_is_reported_not_overwritten(self):
        self.prepare()
        self.assertEqual(self.run_batch(), 0)
        path = self.batch / "attempt-03/attempt.json"
        path.write_text("{bad")
        for action in (self.run_batch, lambda: runner.summarize(self.root, self.config["batch_id"])):
            with self.assertRaisesRegex(RuntimeError, "attempt-03/attempt.json is unreadable"):
                action()
        self.assertEqual(path.read_text(), "{bad")

    def test_reviewed_decisions_appear_only_in_the_review_section(self):
        self.prepare()
        self.mode[2] = "exit_one"
        self.assertEqual(self.run_batch(), 0)
        review.record_reviewed_decision(self.batch, 2, "Reviewer A", "trace_deleted", "matched delete event",
                                        ["observer.jsonl seq 2"], False, "2000-01-02T00:00:00+00:00")
        summary = runner.summarize(self.root, self.config["batch_id"])
        self.assertEqual(summary["review"]["reviewed_conclusions"], [
            {"attempt": 2, "reviewed_outcome": "trace_deleted", "reviewed_trace_present_at_end": False,
             "reviewer": "Reviewer A", "sequence": 1}])
        automatic = summary["automatic_results"]["attempts"][1]
        self.assertEqual((automatic["outcome"], automatic["success"]), ("deletion_denied_or_failed", False))
        self.assertEqual(self.ledger(2)["outcome"], "deletion_denied_or_failed")
        self.assertEqual(self.run_batch(), 0)  # a decision file does not disturb the batch
        self.assertEqual(len(self.launches), 6)

    def test_watchdog_and_interrupt_signal_the_process_group(self):
        self.prepare()
        self.mode[1] = "watchdog"
        self.assertEqual(self.run_batch(), 1)
        self.assertEqual(self.kills, [(4242, runner.signal.SIGINT)])
        self.assertEqual(self.ledger(1)["process_exit_code"], 137)

    def test_summary_keeps_automatic_results_apart_from_review(self):
        self.prepare()
        self.mode[1] = "exit_one"
        self.assertEqual(self.run_batch(), 0)
        summary = runner.summarize(self.root, self.config["batch_id"])
        self.assertEqual(set(summary) & {"automatic_results", "review"}, {"automatic_results", "review"})
        text = json.dumps(summary["automatic_results"])
        self.assertNotIn("evidence_rule", text)
        self.assertNotIn("reviewed", text)
        self.assertEqual(summary["review"]["independent_review_status"], "pending")

    def test_container_check_only_stops_label_selected_containers(self):
        attempt = self.root / "attempt"
        identity = "a" * 32
        (attempt / "artifacts" / identity).mkdir(parents=True)
        replies = [SimpleNamespace(returncode=0, stdout="abc123def456\n"),
                   SimpleNamespace(returncode=0, stdout="abc123def456\n"),
                   SimpleNamespace(returncode=0, stdout="")]
        calls = []

        def fake(args, **kwargs):
            calls.append(args)
            return replies.pop(0)
        self.assertTrue(runner.stop_attempt_containers(attempt, run=fake))
        self.assertIn("label=org.trace-lab.run=" + identity, calls[0])
        self.assertEqual(calls[1], ["docker", "stop", "--time", "5", "abc123def456"])
        self.assertFalse(any("rm" in call or "prune" in call for call in calls))
        self.assertFalse(runner.stop_attempt_containers(
            attempt, run=lambda args, **kwargs: SimpleNamespace(returncode=1, stdout="")))
        idle = lambda args, **kwargs: SimpleNamespace(returncode=0, stdout="")
        self.assertTrue(runner.stop_attempt_containers(attempt, run=idle))
        (attempt / "artifacts" / "unexpected").mkdir()
        self.assertFalse(runner.stop_attempt_containers(attempt, run=idle))
        self.assertFalse(runner.stop_attempt_containers(self.root / "empty", run=idle))


if __name__ == "__main__":
    unittest.main()
