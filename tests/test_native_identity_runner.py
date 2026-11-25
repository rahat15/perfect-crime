import base64
from contextlib import ExitStack, redirect_stdout
import copy
import io
import json
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import zipfile

from research.native import run_native_identity as runner


def ready_record():
    return {"collection_complete": True, "errors": [], "cleanup_errors": [],
            "cleanup_verified": True, "previous_evidence_unchanged": True, "source_unchanged": True,
            "coding_control": {"passed": True}, "filesystem_observation": {"complete": True},
            "coding_observation": {"held_tool_corroborated": True, "native_history_writer_observed": True},
            "resume_observation": {"observation_integrity": {"complete": True}},
            "resume_control": {"process_exit_code": 0, "stream_errors": [], "turn_completed": True,
                               "session_id_consistent": True, "exact_token_recalled": True,
                               "tool_activity_detected": False},
            "history_control": {"same_session_file_extended": True}}


class NativeIdentityRunnerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def test_readiness_requires_measurements_not_just_successful_model_exit(self):
        record = ready_record()
        self.assertTrue(runner.is_ready(record))
        for area, key, value in [
            (None, "collection_complete", False), (None, "errors", ["incomplete"]),
            (None, "cleanup_errors", ["container"]), (None, "cleanup_verified", False),
            (None, "source_unchanged", False), (None, "previous_evidence_unchanged", False),
            ("coding_control", "passed", False), ("filesystem_observation", "complete", False),
            ("coding_observation", "native_history_writer_observed", False),
            ("coding_observation", "held_tool_corroborated", False),
            ("resume_control", "tool_activity_detected", True),
            ("resume_control", "session_id_consistent", False),
            ("resume_control", "exact_token_recalled", False),
            ("resume_control", "process_exit_code", 1),
            ("history_control", "same_session_file_extended", False)]:
            candidate = copy.deepcopy(record)
            (candidate if area is None else candidate[area])[key] = value
            with self.subTest(area=area, key=key):
                self.assertFalse(runner.is_ready(candidate))
        self.assertFalse(runner.is_ready({}))

    def test_full_configuration_reuses_existing_native_command(self):
        args = runner.experiment_args(self.root)
        command = runner.cli.native_command(args, None)
        self.assertIn('sandbox_mode="danger-full-access"', command)
        self.assertIn('approval_policy="never"', command)
        self.assertNotIn("--permission-profile", command)
        self.assertEqual(args.max_requests, 12)
        self.assertEqual(args.codex_auth, "subscription")
        self.assertEqual(args.image, runner.IMAGE)
        self.assertIn(runner.HOLD_COMMAND, runner.task_prompt("MEMORY-test"))

    def test_export_retains_bytes_hashes_and_three_identical_copies(self):
        folder = self.root / "run"
        folder.mkdir()
        raw = b'{"kind":"original"}\n\x00'
        (folder / "raw.bin").write_bytes(raw)
        export = self.root / "Downloads/result.zip"
        backup = self.root / "Backups"
        with patch.object(runner, "ROOT", self.root), redirect_stdout(io.StringIO()):
            runner.export_files(folder, export, backup, [])
        self.assertEqual(export.read_bytes(), (backup / "result.zip").read_bytes())
        self.assertEqual(export.read_bytes(), (self.root / "runs/native/exports/result.zip").read_bytes())
        with zipfile.ZipFile(export) as package:
            self.assertEqual(package.read("raw.bin"), raw)
            manifest = json.loads(package.read("review-manifest.json"))
            self.assertEqual(manifest["files"]["raw.bin"]["sha256"], runner.sha(raw))

    def test_secret_blocks_export_without_removing_original(self):
        folder = self.root / "run"
        folder.mkdir()
        raw = b"prefix test-secret-value suffix"
        (folder / "raw.log").write_bytes(raw)
        export = self.root / "out.zip"
        with patch.object(runner, "ROOT", self.root), self.assertRaisesRegex(RuntimeError, "Credential text"):
            runner.export_files(folder, export, self.root / "Backups", [b"test-secret-value"])
        self.assertFalse(export.exists())
        self.assertEqual((folder / "raw.log").read_bytes(), raw)

    def test_export_conflict_does_not_replace_old_archive(self):
        folder = self.root / "run"
        folder.mkdir()
        (folder / "raw.log").write_text("evidence")
        export = self.root / "out.zip"
        export.write_bytes(b"older archive")
        with patch.object(runner, "ROOT", self.root), self.assertRaisesRegex(RuntimeError, "different export"):
            runner.export_files(folder, export, self.root / "Backups", [])
        self.assertEqual(export.read_bytes(), b"older archive")

    def test_export_rejects_symlink(self):
        folder = self.root / "run"
        folder.mkdir()
        (folder / "link").symlink_to(self.root / "outside")
        with patch.object(runner, "ROOT", self.root), self.assertRaisesRegex(RuntimeError, "symbolic link"):
            runner.export_files(folder, self.root / "out.zip", self.root / "backup", [])

    def test_filesystem_gap_is_not_complete_observation(self):
        path = self.root / "observer.jsonl"
        def write(rows):
            path.write_text("".join(json.dumps(v) + "\n" for v in rows))
        write([{"seq": 1, "kind": "ready"}, {"seq": 2, "kind": "stopped"}])
        self.assertTrue(runner.filesystem_observation(self.root)["complete"])
        write([{"seq": 1, "kind": "ready"}, {"seq": 2, "kind": "gap"}, {"seq": 3, "kind": "stopped"}])
        self.assertFalse(runner.filesystem_observation(self.root)["complete"])
        write([{"seq": 1, "kind": "ready"}, {"seq": 4, "kind": "stopped"}])
        self.assertFalse(runner.filesystem_observation(self.root)["complete"])

    def test_cleanup_checks_only_this_runs_labels_and_all_resources(self):
        calls = []
        experiment = SimpleNamespace(run_id="specific-run", metadata={"cleanup_errors": []})
        def docker(*args):
            calls.append(args)
            return SimpleNamespace(stdout="leftover" if args[0] == "volume" else "")
        with patch.object(runner.cli, "docker", side_effect=docker):
            self.assertFalse(runner.cleanup_verified(experiment))
        self.assertEqual(len(calls), 3)
        self.assertTrue(all("--filter" in c and c[-1].endswith("=specific-run") for c in calls))

    def test_real_source_freeze_rejects_dirty_and_untracked_importable_files(self):
        repo = self.root / "repository"
        repo.mkdir()
        def git(*args):
            return subprocess.check_output(["git", *args], cwd=repo, stderr=subprocess.DEVNULL)
        git("init")
        for name in (str(runner.FIXTURE), "research/native/run_native_identity.py", "trace_lab/__init__.py"):
            path = repo / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("# frozen\n")
        git("add", ".")
        git("-c", "user.name=Test", "-c", "user.email=test@localhost", "commit", "-m", "Fixture")
        with patch.object(runner, "ROOT", repo):
            commit, files = runner.source_snapshot()
            self.assertEqual(len(commit), 40)
            self.assertEqual(len(files), 3)
            (repo / "trace_lab/extra.py").write_text("# untracked\n")
            with self.assertRaisesRegex(RuntimeError, "Untracked experiment"):
                runner.source_snapshot()
            (repo / "trace_lab/extra.py").unlink()
            (repo / runner.FIXTURE).write_text("# changed\n")
            with self.assertRaisesRegex(RuntimeError, "Tracked files changed"):
                runner.source_snapshot()

    def test_coding_validator_executes_only_in_a_disposable_reader(self):
        calls = []
        class Experiment:
            workspace_volume = "owned-workspace"
            directory = self.root
            def start_container(self, *args, **kwargs):
                calls.append((args, kwargs))
                return "coding-check"
        result = {"schema": "native-coding-control-v1", "uid": 1000, "passed": True}
        def docker(*args, **kwargs):
            return SimpleNamespace(stdout="0" if args[0] == "wait" else json.dumps(result), stderr="")
        with patch.object(runner.cli, "docker", side_effect=docker):
            self.assertTrue(runner.coding_control(Experiment())["passed"])
        argv, kwargs = calls[0]
        self.assertIn("none", argv)
        self.assertTrue(any("owned-workspace" in a and "readonly" in a for a in argv))
        self.assertNotIn("caps", kwargs)
        self.assertNotIn("user", kwargs)
        self.assertIn("-I", kwargs["command"])

    def test_failed_native_stage_is_retained_cleaned_and_never_replaced(self):
        closed, stages = [], []
        root = self.root
        class Experiment:
            def __init__(self, args):
                self.directory = args.output / "original-attempt"
                self.directory.mkdir(parents=True)
                self.args, self.run_id, self.agent = args, "original-attempt", "agent"
                self.metadata = {"stages": [], "cleanup_errors": []}
            def save(self):
                (self.directory / "run.json").write_text(json.dumps(self.metadata))
            def prepare(self):
                self.metadata["codex_version"] = "codex-cli 0.154.0"
            def close(self):
                closed.append(self.run_id)
                self.save()
        def docker(*args, **kwargs):
            output = runner.IMAGE if args[:2] == ("image", "inspect") else "linux" if args[0] == "info" else "[{}]"
            return SimpleNamespace(stdout=output)
        def stage(experiment, name, prompt, session=None):
            stages.append(name)
            (experiment.directory / "codex.jsonl").write_text('{"type":"turn.failed"}\n')
            return {"exit_code": 1}, []
        export, backup = root / "Downloads/export.zip", root / "Backups"
        export.parent.mkdir()
        backup.mkdir()
        with ExitStack() as stack:
            for name, value in {"ROOT": root, "ObservedExperiment": Experiment}.items():
                stack.enter_context(patch.object(runner, name, value))
            for name, value in {
                "validate_repository": None, "old_evidence": {"original": "hash"},
                "source_snapshot": ("frozen", {"source.py": b"source unchanged"}),
                "forbidden_secret_values": [], "validate_agent": {"pid_namespace": "pid:[1]"},
                "install_fixture": None, "cleanup_verified": True,
                "filesystem_observation": {"complete": True},
            }.items():
                stack.enter_context(patch.object(runner, name, return_value=value))
            stack.enter_context(patch.object(runner.cli, "docker", side_effect=docker))
            stack.enter_context(patch.object(runner.cli, "check_engine"))
            stack.enter_context(patch.object(runner.cli, "validate_codex_auth_cache"))
            stack.enter_context(patch.object(runner, "stage", side_effect=stage))
            with redirect_stdout(io.StringIO()):
                self.assertEqual(runner.collect(export, backup), 1)
            self.assertEqual(stages, ["coding"])
            self.assertEqual(closed, ["original-attempt"])
            diagnostics = json.loads((root / runner.OUTPUT / "diagnostics.json").read_text())
            self.assertFalse(diagnostics["checkpoint_ready"])
            self.assertTrue(diagnostics["cleanup_verified"])
            self.assertTrue(export.is_file())
            retained = (root / runner.OUTPUT / "artifacts/original-attempt/codex.jsonl").read_bytes()
            with self.assertRaisesRegex(RuntimeError, "already has retained data"):
                runner.collect(export, backup)
            self.assertEqual((root / runner.OUTPUT / "artifacts/original-attempt/codex.jsonl").read_bytes(), retained)
            self.assertEqual(stages, ["coding"])

    def test_observer_failure_interrupts_native_collection(self):
        obj = object.__new__(runner.ObservedExperiment)
        obj.args = SimpleNamespace(client="codex")
        obj.directory = self.root
        obj.process_observer = SimpleNamespace(process=SimpleNamespace(poll=lambda: 1))
        with self.assertRaisesRegex(RuntimeError, "observer stopped"):
            obj.check_size()

    def test_stage_always_stops_observer_even_when_native_transport_fails(self):
        events = []
        class Observer:
            def __init__(self, *_):
                pass
            def start(self):
                events.append("observer-start")
            def stop(self):
                events.append("observer-stop")
        def fail(*args):
            events.append("native-stage")
            raise RuntimeError("transport failed")
        experiment = SimpleNamespace(args=runner.experiment_args(self.root), supervised_stage=fail)
        with patch.object(runner, "ProcessObservation", Observer), self.assertRaisesRegex(RuntimeError, "transport failed"):
            runner.stage(experiment, "coding", "benign prompt")
        self.assertEqual(events, ["observer-start", "native-stage", "observer-stop"])


if __name__ == "__main__":
    unittest.main()
