"""End-to-end tests of the Docker-mode control against a FAKE docker executable.

No Docker daemon exists where these run. They exercise the orchestration (volume,
keeper, initialiser, condition container, inspect validation, steps through
``docker exec``, sidecar snapshots, derivation, comparison with the executed local
control, cleanup) and its error paths. They say nothing about real Docker.
"""

import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import test_account_separation_fake_docker as fake  # noqa: E402
from research.native.account_separation import container  # noqa: E402

MODULE = "research.native.account_separation.run_account_separation_control"


def run_control(env, output, *extra, repeat="2", timeout=120):
    return subprocess.run([sys.executable, "-m", MODULE, "--mode", "docker", "--image", "derived:test",
                           "--repeat", repeat, "--output", str(output), *extra],
                          cwd=str(ROOT), env=env, capture_output=True, text=True, timeout=timeout)


@unittest.skipUnless(fake.EVIDENCE.is_file(), "executed local control evidence is required")
class DockerControlAgainstFake(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.directory = Path(self.temporary.name)
        self.output = self.directory / "docker-control.json"

    def tearDown(self):
        self.temporary.cleanup()

    def assert_clean(self, env):
        left = fake.state(env)
        self.assertEqual(left["containers"], {})
        self.assertEqual(left["volumes"], {})

    def test_full_flow_two_repeats_matches_local_and_cleans_up(self):
        env = fake.install(self.directory)
        proc = run_control(env, self.output)
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        result = json.loads(self.output.read_text())
        self.assertEqual(result["status"], "executed")
        self.assertEqual(result["image_id"], "sha256:" + "d" * 64)
        self.assertEqual(len(result["runs"]), 2)
        self.assertTrue(result["all_statements_hold"])
        self.assertTrue(result["reproducible_identical_verdicts"])
        comparison = result["comparison_with_local_control"]
        self.assertTrue(comparison["verdicts_match"])
        self.assertTrue(comparison["coverage_match"])
        self.assertTrue(result["cleanup"]["verified"])
        self.assert_clean(env)
        run = result["runs"][0]
        self.assertEqual(run["main_read_only"]["scenario"]["image_id"], result["image_id"])
        self.assertEqual(run["main_read_only"]["coverage"]["not_run"], [])
        # Every scenario: 2 volumes, keeper, initialiser, validated condition container.
        calls = fake.calls(env)
        self.assertEqual(sum(c[:2] == ["volume", "create"] for c in calls), 2 * 5 * 2)
        mains = [c for c in calls if c[0] == "run" and c[c.index("--name") + 1].endswith("-main")]
        self.assertEqual(len(mains), 10)
        for argv in mains:
            self.assertEqual(argv[argv.index("--user") + 1], "0:0")
            self.assertEqual(sorted(argv[i + 1] for i, a in enumerate(argv) if a == "--cap-add"),
                             ["SETGID", "SETPCAP", "SETUID"])
            self.assertIn("no-new-privileges", argv)
            self.assertIn("--read-only", argv)
        settings = run["negative_controls"]["N1"]["scenario"]["settings"]
        self.assertEqual(settings["tool_shell"], "/bin/bash.real")
        self.assertTrue(settings["condition_container"]["inspect_validated"])
        n2 = run["negative_controls"]["N2"]["scenario"]["settings"]
        self.assertEqual(n2["records_root_owner"], 1002)
        n3 = run["negative_controls"]["N3"]["scenario"]["settings"]
        self.assertEqual(n3["records_home"], "/workspace/records")
        self.assertIn("8m", n3["volumes"].values())
        # Steps go through `docker exec` without --user, as the live harness does.
        steps = [c for c in calls if c[0] == "exec"]
        self.assertTrue(steps and all("--user" not in c for c in steps))
        # Snapshots come from read-only sidecars.
        sidecars = [c for c in calls if c[0] == "run" and "-snap-" in c[c.index("--name") + 1]]
        self.assertTrue(sidecars and all(m.endswith(",readonly") for c in sidecars
                                         for i, m in enumerate(c) if c[i - 1] == "--mount"))

    def test_refuses_to_overwrite_existing_output(self):
        env = fake.install(self.directory)
        self.output.write_text("earlier evidence\n")
        proc = run_control(env, self.output)
        self.assertEqual(proc.returncode, 4)
        self.assertEqual(self.output.read_text(), "earlier evidence\n")
        self.assertEqual(fake.calls(env), [])

    def test_inspect_mismatch_stops_scenario_and_cleans_up(self):
        env = fake.install(self.directory, fault="inspect_extra_cap")
        proc = run_control(env, self.output, repeat="1")
        self.assertNotEqual(proc.returncode, 0)
        result = json.loads(self.output.read_text())
        self.assertFalse(result["all_statements_hold"])
        self.assertTrue(any("docker inspect differs" in e and "cap-add" in e for e in result["errors"]))
        self.assertEqual(result["runs"][0]["four_statements_read_only"]["a"], "undetermined")
        self.assertEqual(sum(c[0] == "exec" for c in fake.calls(env)), 0)
        self.assert_clean(env)

    def test_initialiser_nonzero_exit_is_reported(self):
        env = fake.install(self.directory, fault="init_exit")
        proc = run_control(env, self.output, repeat="1")
        self.assertNotEqual(proc.returncode, 0)
        result = json.loads(self.output.read_text())
        self.assertTrue(any("layout initialiser exited with status 3" in e for e in result["errors"]))
        self.assert_clean(env)

    def test_step_nonzero_exit_is_reported(self):
        env = fake.install(self.directory, fault="step_exit")
        proc = run_control(env, self.output, repeat="1")
        self.assertNotEqual(proc.returncode, 0)
        result = json.loads(self.output.read_text())
        self.assertTrue(any("step init exited with status 7" in e for e in result["errors"]))
        self.assert_clean(env)

    def test_missing_step_result_is_undetermined_not_a_pass(self):
        env = fake.install(self.directory, fault="step_missing")
        proc = run_control(env, self.output, repeat="1")
        self.assertNotEqual(proc.returncode, 0)
        result = json.loads(self.output.read_text())
        self.assertTrue(any("returned no JSON result" in e for e in result["errors"]))
        run = result["runs"][0]
        self.assertEqual(run["four_statements_read_only"]["a"], "undetermined")
        self.assertEqual(len(run["main_read_only"]["coverage"]["not_run"]), 48)
        self.assertEqual(run["main_read_only"]["coverage"]["executed"], 0)
        self.assert_clean(env)

    def test_step_timeout_is_reported_and_cleaned_up(self):
        env = fake.install(self.directory, fault="slow_step")
        proc = run_control(env, self.output, "--step-timeout", "1", repeat="1", timeout=180)
        self.assertNotEqual(proc.returncode, 0)
        result = json.loads(self.output.read_text())
        self.assertTrue(any("timed out" in e for e in result["errors"]))
        self.assert_clean(env)

    def test_cleanup_failure_is_not_reported_as_verified(self):
        env = fake.install(self.directory, fault="volume_rm_fail")
        proc = run_control(env, self.output, repeat="1")
        self.assertNotEqual(proc.returncode, 0)
        result = json.loads(self.output.read_text())
        self.assertFalse(result["cleanup"]["verified"])
        self.assertTrue(result["cleanup"]["remaining"]["volumes"])

    def test_single_repeat_never_counts_as_a_passed_control(self):
        env = fake.install(self.directory)
        proc = run_control(env, self.output, repeat="1")
        self.assertEqual(proc.returncode, 2)
        self.assertTrue(json.loads(self.output.read_text())["all_statements_hold"])

    def test_sigterm_cleans_up_labelled_resources(self):
        env = fake.install(self.directory, fault="slow_step")
        proc = subprocess.Popen([sys.executable, "-m", MODULE, "--mode", "docker", "--image",
                                 "derived:test", "--repeat", "1", "--output", str(self.output)],
                                cwd=str(ROOT), env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline and not any(c[0] == "exec" for c in fake.calls(env)):
            time.sleep(0.1)
        self.assertTrue(fake.state(env)["containers"], "the scenario never started")
        proc.send_signal(signal.SIGTERM)
        proc.communicate(timeout=60)
        self.assertNotEqual(proc.returncode, 0)
        result = json.loads(self.output.read_text())
        self.assertEqual(result["status"], "interrupted")
        self.assertTrue(result["cleanup"]["verified"])
        self.assert_clean(env)

    def test_missing_image_is_a_failure_without_any_container(self):
        env = fake.install(self.directory)
        proc = subprocess.run([sys.executable, "-m", MODULE, "--mode", "docker", "--image", "absent:tag",
                               "--output", str(self.output)], cwd=str(ROOT), env=env,
                              capture_output=True, text=True, timeout=60)
        self.assertNotEqual(proc.returncode, 0)
        self.assertEqual(json.loads(self.output.read_text())["status"], "failed")
        self.assertFalse(any(c[0] == "run" for c in fake.calls(env)))


class DockerModeWithoutDocker(unittest.TestCase):
    def test_not_executed_without_docker_or_image(self):
        from research.native.account_separation import run_account_separation_control as control
        self.assertEqual(control.docker_mode(None, 2)["status"], "not_executed")
        with tempfile.TemporaryDirectory() as empty:
            env = dict(os.environ, PATH=empty)
            proc = subprocess.run([sys.executable, "-m", MODULE, "--mode", "docker", "--image", "x"],
                                  cwd=str(ROOT), env=dict(env, PYTHONPATH=str(ROOT)),
                                  capture_output=True, text=True)
        self.assertEqual(proc.returncode, 5)
        self.assertIn("not_executed", proc.stdout)


class InspectValidation(unittest.TestCase):
    def info(self, **changes):
        argv = container.docker_run_argv("c", "img", "k=v", "rec", "work", control=True)
        value = {"Image": "sha256:x", "Config": {"User": "0:0", "Labels": {"k": "v"}},
                 "HostConfig": {"CapAdd": ["CAP_SETUID", "SETGID", "SETPCAP"], "CapDrop": ["ALL"],
                                "SecurityOpt": ["no-new-privileges"], "ReadonlyRootfs": True,
                                "Privileged": False, "Tmpfs": {"/tmp": "rw", "/out": "rw",
                                "/home/tool": "rw,uid=1002,gid=1002"}},
                 "Mounts": [{"Type": "volume", "Name": "rec", "Destination": "/home/agent", "RW": True},
                            {"Type": "volume", "Name": "work", "Destination": "/workspace", "RW": True}]}
        self.assertIn("--read-only", argv)
        value["HostConfig"].update(changes)
        return value

    def check(self, info):
        return container.validate_inspect(info, "sha256:x", "k=v", "rec", "work", control=True)

    def test_accepts_the_condition(self):
        self.assertEqual(self.check(self.info()), (True, []))

    def test_rejections(self):
        for change in ({"CapAdd": ["SETUID", "SETGID"]}, {"CapAdd": ["SETUID", "SETGID", "SETPCAP", "KILL"]},
                       {"SecurityOpt": []}, {"ReadonlyRootfs": False}, {"Privileged": True},
                       {"Binds": ["/:/host"]}, {"PidMode": "host"},
                       {"Tmpfs": {"/tmp": "rw", "/out": "rw", "/home/tool": "rw,uid=1000,gid=1000"}}):
            self.assertFalse(self.check(self.info(**change))[0], change)
        shared = self.info()
        shared["Mounts"][1]["Name"] = "rec"
        self.assertFalse(container.validate_inspect(shared, control=True)[0])
        wrong_user = self.info()
        wrong_user["Config"]["User"] = "1000:1000"
        self.assertFalse(self.check(wrong_user)[0])


if __name__ == "__main__":
    unittest.main()
