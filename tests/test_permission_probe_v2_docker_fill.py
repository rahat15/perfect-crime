"""Tests for the probe-02 docker runner that supplies the fill filesystems (mocked docker, local live run)."""

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from research.tools import run_permission_probe_v2 as runner
from research.tools import run_permission_probe_v2_docker_fill as fill

ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / fill.OUTPUT
TOOL = Path(fill.__file__)
IMAGE = "sha256:eddc3b1939fb346372fe8e6aa2806f1bb03696867704f3e70143e12492115aa5"


class CommandTests(unittest.TestCase):
    def test_command_is_the_committed_one_plus_two_fill_tmpfs_and_the_fixture_arguments(self):
        committed = runner.container_command(IMAGE, "n", "i")
        command = fill.container_command(IMAGE, "n", "i")
        mounts = [command[index + 1] for index, value in enumerate(command) if value == "--tmpfs"]
        self.assertEqual(mounts, ["/probe:" + runner.TMPFS_OPTIONS,
                                  "/probe-fill-records:" + runner.FILL_TMPFS_OPTIONS,
                                  "/probe-fill-workspace:" + runner.FILL_TMPFS_OPTIONS])
        self.assertEqual(command[-6:], ["-I", "-", "--fill-records-root", "/probe-fill-records",
                                        "--fill-workspace-root", "/probe-fill-workspace"])
        stripped = [item for item in command[:-4] if item not in mounts[1:]]
        stripped = [item for index, item in enumerate(stripped)
                    if not (item == "--tmpfs" and stripped[index + 1] != mounts[0])]
        self.assertEqual(stripped, committed, "nothing else differs from the committed docker command")
        for flag in ("--pull=never", "--read-only"):
            self.assertIn(flag, command)
        self.assertEqual(command[command.index("--network") + 1], "none")
        self.assertEqual(command[command.index("--cap-drop") + 1], "ALL")
        self.assertEqual({command[i + 1] for i, v in enumerate(command) if v == "--cap-add"},
                         set(runner.CAPABILITIES))
        for flag in ("--privileged", "--mount", "--volume", "-v", "SYS_ADMIN"):
            self.assertNotIn(flag, command)

    def test_every_tmpfs_option_is_documented_and_equals_the_committed_local_fill_options(self):
        self.assertEqual(set(runner.FILL_TMPFS_OPTIONS.split(",")), set(fill.TMPFS_OPTION_REASONS))
        self.assertEqual(fill.EXPECTED_TMPFS["/probe-fill-records"], runner.FILL_TMPFS_OPTIONS)
        self.assertEqual(fill.EXPECTED_TMPFS["/probe"], runner.TMPFS_OPTIONS)

    @staticmethod
    def inspection():
        return {"network_mode": "none", "readonly_rootfs": True, "binds": None, "mounts": [],
                "user": "0:0", "entrypoint": ["python3"], "command": ["-I", "-"] + fill.FIXTURE_ARGUMENTS,
                "privileged": False, "tmpfs": dict(fill.EXPECTED_TMPFS), "cap_drop": ["ALL"],
                "cap_add": ["CAP_" + name for name in runner.CAPABILITIES],
                "security_options": ["no-new-privileges"]}

    def test_inspection_accepts_exactly_the_expected_mounts_and_rejects_anything_else(self):
        fill.validate_inspection(self.inspection())
        ok = self.inspection()
        ok["mounts"] = [{"Type": "tmpfs", "Destination": "/probe-fill-records"}]
        fill.validate_inspection(ok)
        changes = {
            "tmpfs mounts": lambda r: r["tmpfs"].update({"/tmp": "rw"}),
            "tmpfs mounts ": lambda r: r["tmpfs"].pop("/probe-fill-workspace"),
            "options": lambda r: r["tmpfs"].update({"/probe-fill-records": "rw,size=4g"}),
            "setup command": lambda r: r.update(command=["-I", "-"]),
            "Unexpected mount": lambda r: r.update(mounts=[{"Type": "bind", "Source": "/home",
                                                            "Destination": "/probe"}]),
            "Unexpected mount ": lambda r: r.update(mounts=[{"Type": "tmpfs", "Destination": "/elsewhere"}]),
            "host bind": lambda r: r.update(binds=["/home:/x"]),
            "capabilities": lambda r: r["cap_add"].append("CAP_SYS_ADMIN"),
            "network": lambda r: r.update(network_mode="bridge"),
            "privileged": lambda r: r.update(privileged=True),
            "no-new-privileges": lambda r: r.update(security_options=[]),
        }
        for message, change in changes.items():
            record = self.inspection()
            change(record)
            with self.subTest(message), self.assertRaisesRegex(ValueError, message.strip()):
                fill.validate_inspection(record)

    def raw(self, extra_capability=None):
        record = self.inspection()
        capabilities = record["cap_add"] + ([extra_capability] if extra_capability else [])
        return [{"Image": IMAGE, "Mounts": [],
                 "Config": {"Image": IMAGE, "User": "0:0", "Entrypoint": ["python3"], "Cmd": record["command"]},
                 "HostConfig": {"NetworkMode": "none", "ReadonlyRootfs": True, "CapAdd": capabilities,
                                "CapDrop": ["ALL"], "Privileged": False, "SecurityOpt": ["no-new-privileges"],
                                "Tmpfs": record["tmpfs"], "Binds": None}}]

    def fake(self, calls, raw):
        def command(args, **kwargs):
            calls.append(args)
            if args[:2] == ["docker", "info"]:
                return "linux"
            if args[:3] == ["docker", "image", "inspect"]:
                return IMAGE
            if args[:2] == ["docker", "inspect"]:
                return json.dumps(raw)
            if args[:2] == ["docker", "ps"]:
                return "" if any(call[:2] == ["docker", "rm"] for call in calls) else \
                    next(call for call in calls if call[:2] == ["docker", "create"])[4]
            return ""
        return command

    def test_docker_flow_feeds_the_committed_fixture_and_removes_the_container(self):
        calls = []
        done = subprocess.CompletedProcess([], 0, stdout=b'{"protocol": "x"}', stderr=b"")
        with patch.object(runner, "command", side_effect=self.fake(calls, self.raw())), \
                patch.object(fill.subprocess, "run", return_value=done) as start:
            observations, run, settings, failure = fill.run_docker(IMAGE)
        self.assertIsNone(failure)
        self.assertEqual(observations, {"protocol": "x"})
        self.assertEqual(start.call_args.kwargs["input"], (ROOT / runner.FIXTURE).read_bytes())
        self.assertEqual(start.call_args.args[0][:4], ["docker", "start", "--attach", "--interactive"])
        create = next(call for call in calls if call[:2] == ["docker", "create"])
        self.assertEqual(create, fill.container_command(IMAGE, run["container_name"], run["container_identifier"]))
        self.assertIn(["docker", "rm", "--force", run["container_name"]], calls)
        self.assertTrue(run["cleanup_verified"])
        self.assertEqual(set(settings["tmpfs"]), set(fill.EXPECTED_TMPFS))

    def test_docker_flow_never_starts_a_container_with_unexpected_settings_and_still_cleans_up(self):
        calls = []
        with patch.object(runner, "command", side_effect=self.fake(calls, self.raw("CAP_SYS_ADMIN"))), \
                patch.object(fill.subprocess, "run") as start:
            observations, run, _, failure = fill.run_docker(IMAGE)
        start.assert_not_called()
        self.assertIsNone(observations)
        self.assertIn("capabilities", failure)
        self.assertTrue(run["cleanup_verified"])

    def test_image_must_be_the_exact_local_id(self):
        with patch.object(runner, "command", side_effect=["linux", "sha256:other"]):
            with self.assertRaisesRegex(ValueError, "nothing was pulled"):
                fill.run_docker(IMAGE)

    def test_existing_outputs_are_never_overwritten(self):
        with tempfile.TemporaryDirectory() as directory:
            evidence = Path(directory) / "e.json"
            evidence.write_text("kept")
            result = subprocess.run([sys.executable, str(TOOL), "--mode", "docker", "--evidence", str(evidence),
                                     "--summary", str(Path(directory) / "s.json")], capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("never overwritten", result.stderr + result.stdout)
            self.assertEqual(evidence.read_text(), "kept")


@unittest.skipUnless((OUTPUT / "local-premounted-record.json").is_file(), "no local-premounted record")
class RecordTests(unittest.TestCase):
    def test_record_compare_file_and_readme_agree(self):
        record = json.loads((OUTPUT / "local-premounted-record.json").read_text())
        stored = json.loads((OUTPUT / "compare-local-premounted.json").read_text())
        mine = record["compare_with_committed_probe_02_evidence"]
        for key in ("recorded_cells", "executed_in_both", "not_run_in_both", "not_run_vs_measured",
                    "verdict_difference_count", "same_coverage"):
            self.assertEqual(stored[key], mine[key], key)
        self.assertEqual((stored["recorded_cells"], stored["executed_in_both"], stored["not_run_in_both"],
                          stored["not_run_vs_measured"], stored["verdict_difference_count"]), (495, 467, 28, 0, 0))
        self.assertTrue(stored["same_coverage_and_identical_verdicts"])
        self.assertEqual(stored["coverage"]["b"]["total"]["not_run_by_kind"][runner.NOT_EXECUTED], 0)
        self.assertEqual(mine["committed_evidence_sha256"], runner.sha(ROOT / fill.COMMITTED_EVIDENCE))
        self.assertEqual(record["fixture_sha256"], runner.sha(ROOT / runner.FIXTURE))
        self.assertEqual(record["runner_sha256"], runner.sha(Path(runner.__file__)))
        self.assertEqual(record["docker_fill_runner_sha256"], runner.sha(TOOL))
        self.assertFalse(record["docker_mode"]["executed"])
        self.assertNotIn("SYS_ADMIN", record["environment"]["setup_process_effective_capabilities"])
        text = (OUTPUT / "README.md").read_text()
        for phrase in ("has NOT been executed", record["evidence_sha256"], "--mode docker", "sha256:eddc3b19",
                       "467", "28 disk-fill cells", "--fill-records-root /probe-fill-records",
                       "not a Docker result"):
            self.assertIn(phrase, text)
        self.assertFalse((OUTPUT / "evidence.json").exists())


class LiveTests(unittest.TestCase):
    @unittest.skipUnless(os.geteuid() == 0, "local-premounted needs root to mount tmpfs and drop UIDs")
    def test_local_premounted_executes_the_fill_cells_and_matches_the_committed_evidence(self):
        stray = sorted(name for name in os.listdir(tempfile.gettempdir()) if name.startswith("cse227-probe"))
        with tempfile.TemporaryDirectory() as directory:
            evidence, summary = Path(directory) / "e.json", Path(directory) / "s.json"
            result = subprocess.run([sys.executable, str(TOOL), "--mode", "local-premounted", "--evidence",
                                     str(evidence), "--summary", str(summary)], capture_output=True, text=True,
                                    timeout=300, cwd=str(ROOT))
            if result.returncode != 0 and "private mount namespace" in result.stdout + result.stderr:
                self.skipTest("cannot mount here")
            self.assertEqual(result.returncode, 0, result.stdout[-600:] + result.stderr[-600:])
            self.assertIn("Disk-fill cells: 30 recorded, 28 executed, 2 not run", result.stdout)
            self.assertIn("0 COULD NOT BE EXECUTED", result.stdout)
            measured = json.loads(evidence.read_text())
            command = measured["environment_settings"]["fixture_command"]
            self.assertIn("--fill-records-root", command)
            self.assertEqual(measured["observations"]["environment"]["setup_process"]["status"]["NoNewPrivs"], "1")
            compared = runner.compare(json.loads((ROOT / fill.COMMITTED_EVIDENCE).read_text()), measured)
            self.assertEqual((compared["executed_in_both"], compared["not_run_in_both"],
                              compared["not_run_vs_measured"], compared["verdict_difference_count"]),
                             (467, 28, 0, 0))
            self.assertTrue(compared["same_coverage"])
        self.assertEqual(sorted(name for name in os.listdir(tempfile.gettempdir())
                                if name.startswith("cse227-probe")), stray)
        self.assertNotIn("cse227-probe", Path("/proc/self/mountinfo").read_text())


if __name__ == "__main__":
    unittest.main()
