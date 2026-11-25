"""Regression checks for startup classification, retained evidence and cleanup."""
import copy
from contextlib import redirect_stdout
import errno
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import zipfile

from research.native import run_sandbox_startup as runner
from research.native import sandbox_startup_fixture as fixture
from tests.test_native_observer_calibration import credentials
from tests import test_native_observer_collection as original_tests


def file_row(name, sandbox):
    return {"name": name, "exit_code": 0, "timed_out": False, "stdout": "", "stderr": "",
            "output_truncated": False,
            "markers": [{"marker": "native-sandbox-startup", "uid": 1000, "gid": 1000,
                         "cwd": "/workspace", "operations": {
                             "workspace": {"written": True, "errno": None},
                             "outside": {"written": not sandbox, "errno": errno.EROFS if sandbox else None}}}],
            "files_after": {"workspace": fixture.WRITTEN,
                            "outside": fixture.BEFORE if sandbox else fixture.BEFORE + fixture.WRITTEN}}


def data(blocked=False, malformed=False):
    probe = file_row("codex_sandbox", True)
    if blocked or malformed:
        probe.update(exit_code=2 if malformed else 1, markers=[],
                     stderr="error: required --permission-profile <NAME>" if malformed
                     else "bwrap: Creating new namespace failed: Operation not permitted\n",
                     files_after={"workspace": None, "outside": fixture.BEFORE})
    return {"environment_status": credentials(), "probes": [
        {"name": "version", "exit_code": 0, "stdout": "codex-cli 0.154.0\n"},
        {"name": "sandbox_help", "exit_code": 0, "stdout": "--permission-profile <NAME>"},
        {"name": "user_namespace", "exit_code": 1 if blocked else 0},
        file_row("plain_python", False), probe]}


def packet(rows):
    return {"collection_complete": True, "cleanup_verified": True, "original_evidence_unchanged": True,
            "errors": [], "cleanup_errors": [], "conditions": [
                {"condition": name, "raw": item, "assessment": runner.assess(item)}
                for name, item in zip(("docker_default", "seccomp_disabled_only"), rows)]}


class StartupClassificationTests(unittest.TestCase):
    def test_explicit_profile_without_conflicting_legacy_override(self):
        command = fixture.sandbox_command("/usr/bin/python3")
        self.assertEqual(command[command.index("--permission-profile") + 1], ":workspace")
        self.assertNotIn("-c", command[:command.index("--")])
        self.assertNotIn("linux", command)

    def test_expected_boundary_and_marker_pass(self):
        self.assertTrue(runner.assess(data())["sandbox_control_passed"])

    def test_original_missing_argument_error_cannot_pass(self):
        self.assertEqual(runner.assess(data(malformed=True))["sandbox_status"],
                         "unresolved_configuration_or_execution")
        self.assertFalse(runner.readiness(packet([data(malformed=True), data(malformed=True)])))

    def test_runtime_denial_is_not_success(self):
        found = runner.assess(data(blocked=True))
        self.assertEqual(found["sandbox_status"], "runtime_startup_blocked")
        self.assertFalse(found["sandbox_control_passed"])
        self.assertFalse(runner.readiness(packet([data(blocked=True), data(blocked=True)])))

    def test_known_default_denial_and_working_comparison_can_finish(self):
        self.assertTrue(runner.readiness(packet([data(blocked=True), data()])))

    def test_printed_success_requires_parent_file_observation(self):
        d = data()
        d["probes"][-1]["files_after"]["workspace"] = None
        self.assertFalse(runner.assess(d)["sandbox_control_passed"])

    def test_outside_write_disqualifies_sandbox_success(self):
        d = data()
        d["probes"][-1] = file_row("codex_sandbox", False)
        self.assertEqual(runner.assess(d)["sandbox_status"], "unexpected_child_or_file_effect")

    def test_missing_file_error_is_not_permission_denial(self):
        d = data()
        d["probes"][-1]["markers"][0]["operations"]["outside"]["errno"] = errno.ENOENT
        self.assertFalse(runner.assess(d)["sandbox_control_passed"])

    def test_outside_file_must_remain_unchanged(self):
        d = data()
        d["probes"][-1]["files_after"]["outside"] += "unexpected"
        self.assertFalse(runner.assess(d)["sandbox_control_passed"])

    def test_ordinary_uid_must_have_access_to_both_canaries(self):
        d = data()
        d["probes"][-2] = file_row("plain_python", True)
        self.assertFalse(runner.assess(d)["controls_valid"])

    def test_child_uid_gid_and_cwd_must_match(self):
        for key, value in (("uid", 0), ("gid", 0), ("cwd", "/")):
            with self.subTest(key=key):
                d = data()
                d["probes"][-1]["markers"][0][key] = value
                self.assertFalse(runner.assess(d)["sandbox_control_passed"])

    def test_timeout_truncation_and_duplicate_markers_are_not_success(self):
        for key in ("timed_out", "output_truncated"):
            d = data()
            d["probes"][-1][key] = True
            self.assertFalse(runner.assess(d)["sandbox_control_passed"])
        d = data()
        d["probes"][-1]["markers"] *= 2
        self.assertFalse(runner.assess(d)["sandbox_control_passed"])

    def test_missing_duplicate_and_wrong_version_controls_fail(self):
        for transform in (lambda d: d["probes"].pop(), lambda d: d["probes"].append(d["probes"][0]),
                          lambda d: d["probes"][0].update(stdout="codex-cli other")):
            d = data()
            transform(d)
            self.assertFalse(runner.assess(d)["controls_valid"])

    def test_cleanup_integrity_and_controller_failures_prevent_readiness(self):
        for key, value in (("cleanup_verified", False), ("original_evidence_unchanged", False),
                           ("collection_complete", False), ("errors", ["failed"]),
                           ("cleanup_errors", ["failed"])):
            p = packet([data(), data()])
            p[key] = value
            self.assertFalse(runner.readiness(p))


class StartupCollectionTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        for name in runner.SOURCES:
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes((runner.ROOT / name).read_bytes())
        previous = self.root / runner.PREVIOUS
        previous.parent.mkdir(parents=True)
        previous.write_text('{"retained":true}')
        self.containers = {}
        self.calls = []
        self.malformed = False
        self.controller_failure = False
        self.force_cleanup_failure = False

    def command(self, argv, **kwargs):
        if argv[:2] == ["docker", "exec"]:
            self.calls.append(argv)
            if self.controller_failure:
                raise RuntimeError("synthetic controller failure")
            name = argv[argv.index("--interactive") + 1]
            return json.dumps(data(blocked=name.endswith("-0"), malformed=self.malformed))
        if argv[:2] == ["docker", "rm"] and self.force_cleanup_failure:
            raise RuntimeError("synthetic cleanup failure")
        return original_tests.ObserverCollectionTests.command(self, argv, **kwargs)

    def git(self, argv, **kwargs):
        if argv[1:3] == ["rev-parse", "HEAD"]:
            return "f" * 40
        return (self.root / argv[2].split(":", 1)[1]).read_bytes()

    def collect(self):
        with patch.object(runner, "ROOT", self.root), \
             patch.object(runner, "verify_previous", return_value={}), \
             patch.object(runner.subprocess, "check_output", side_effect=self.git), \
             patch.object(runner.original, "command", side_effect=self.command), \
             redirect_stdout(io.StringIO()):
            return runner.collect()

    def test_success_keeps_both_raw_conditions_and_original(self):
        p = self.collect()
        self.assertTrue(p["checkpoint_ready"])
        self.assertEqual(len(p["conditions"]), 2)
        self.assertEqual(self.containers, {})
        self.assertEqual((self.root / runner.PREVIOUS).read_text(), '{"retained":true}')

    def test_probe_errors_do_not_skip_second_condition_or_pass(self):
        self.malformed = True
        p = self.collect()
        self.assertTrue(p["collection_complete"])
        self.assertFalse(p["checkpoint_ready"])
        self.assertEqual(len(p["conditions"]), 2)
        self.assertTrue(p["cleanup_verified"])

    def test_controller_failure_keeps_partial_packet_and_cleans_up(self):
        self.controller_failure = True
        p = self.collect()
        self.assertFalse(p["checkpoint_ready"])
        self.assertTrue(p["errors"])
        self.assertTrue(p["cleanup_verified"])
        self.assertEqual(self.containers, {})

    def test_cleanup_failure_cannot_pass(self):
        self.force_cleanup_failure = True
        p = self.collect()
        self.assertFalse(p["checkpoint_ready"])
        self.assertFalse(p["cleanup_verified"])
        self.assertTrue(p["cleanup_errors"])

    def test_second_call_reuses_hash_verified_evidence_without_docker(self):
        first = self.collect()
        count = len(self.calls)
        self.assertEqual(self.collect(), first)
        self.assertEqual(len(self.calls), count)

    def test_changed_saved_artifact_is_retained_and_rejected(self):
        self.collect()
        path = self.root / runner.OUTPUT / "docker_default.json"
        path.write_text("changed")
        with self.assertRaisesRegex(RuntimeError, "artifact differs"):
            self.collect()
        self.assertEqual(path.read_text(), "changed")

    def test_export_copies_are_identical_and_collision_is_retained(self):
        p = self.collect()
        destination = self.root / "downloads/review.zip"
        backups = self.root / "backups"
        with patch.object(runner, "ROOT", self.root), redirect_stdout(io.StringIO()):
            runner.export_review(p, destination, backups)
            self.assertEqual(destination.read_bytes(), (backups / "review.zip").read_bytes())
            with zipfile.ZipFile(destination) as z:
                self.assertIsNone(z.testzip())
                self.assertTrue(json.loads(z.read("review-manifest.json"))["checkpoint_ready"])
            destination.write_bytes(b"different export")
            with self.assertRaisesRegex(RuntimeError, "different export"):
                runner.export_review(p, destination, backups)
            self.assertEqual(destination.read_bytes(), b"different export")


if __name__ == "__main__":
    unittest.main()
