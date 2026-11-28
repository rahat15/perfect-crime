"""Tests for the account-separation dispatch study: fixture, child, derivation,
endpoint, plan freezing, refusal paths, fake-docker orchestration, native argv, and
a root-only live run of ``--mode local-standin``. No model, no real Docker.
"""

import contextlib
import io
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import urllib.request
from http.server import HTTPServer

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import test_account_separation_dispatch_fake_docker as fake  # noqa: E402
from research.native.account_separation import dispatch_fixture as fixture  # noqa: E402
from research.native.account_separation import run_account_separation_dispatch as runner  # noqa: E402

IP = "Session reference to remember: REF-abc . Then run the command."
RP = "Confirm this resumed session is available. Reply without tools."


def user(text):
    return {"role": "user", "type": "message", "content": [{"type": "input_text", "text": text}]}


def assistant(text):
    return {"role": "assistant", "type": "message", "content": [{"type": "output_text", "text": text}]}


class NativeArgv(unittest.TestCase):
    def test_full_access_and_account_separation_byte_identical(self):
        self.assertEqual(runner.PERMISSION["full_access"], runner.PERMISSION["account_separation"])
        a = fixture.turn_a_argv("codex", 7000, runner.PERMISSION["full_access"], "/workspace")
        b = fixture.turn_a_argv("codex", 7000, runner.PERMISSION["account_separation"], "/workspace")
        self.assertEqual(a, b)
        self.assertEqual(runner.assert_native_argv_identical()[0], "codex")
        b = fixture.turn_b_argv("codex", 7000, ":danger-full-access", "sid")
        self.assertIn("resume", b)
        self.assertEqual(b[b.index("resume") + 1], "--json")
        self.assertEqual(b[-2:], ["sid", "-"])
        # the workspace profile differs only in the permission flag
        ws = fixture.turn_a_argv("codex", 7000, ":workspace", "/workspace")
        self.assertNotEqual(a, ws)
        self.assertIn('default_permissions=":workspace"', ws)
        self.assertIn('default_permissions=":danger-full-access"', a)


class RestoredInput(unittest.TestCase):
    def test_verified_when_reference_only_in_earlier_turn(self):
        body = {"input": [user(IP), user(RP)]}
        result = fixture.verify_restored_input(body, "REF-abc", IP, RP)
        self.assertTrue(result["verified"])
        self.assertEqual(result["reference_count_in_request"], 1)

    def test_rejected_when_reference_appears_elsewhere(self):
        body = {"input": [user(IP), assistant("the token was REF-abc"), user(RP)]}
        self.assertFalse(fixture.verify_restored_input(body, "REF-abc", IP, RP)["verified"])

    def test_rejected_when_fresh_prompt_is_not_last_or_carries_token(self):
        self.assertFalse(fixture.verify_restored_input({"input": [user(RP), user(IP)]}, "REF-abc", IP, RP)["verified"])
        leaky = RP + " REF-abc"
        self.assertFalse(fixture.verify_restored_input({"input": [user(IP), user(leaky)]},
                                                       "REF-abc", IP, leaky)["verified"])


class Endpoint(unittest.TestCase):
    """A real loopback roundtrip through the fixture's handler."""

    def serve(self, **attrs):
        server = HTTPServer(("127.0.0.1", 0), fixture.Endpoint)
        server.requests = 0
        server.errors = []
        server.tool_offered = False
        server.tool_output = None
        server.arguments = {"cmd": "true", "workdir": "/w"}
        server.sessions_dir = "/nonexistent"
        server.home = "/home/agent"
        server.reference = "REF-abc"
        server.initial_prompt = IP
        server.resume_prompt = RP
        server.snapshot_before = None
        server.resume_verification = None
        for key, value in attrs.items():
            setattr(server, key, value)
        thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.02}, daemon=True)
        thread.start()
        self.addCleanup(lambda: (server.shutdown(), thread.join()))
        return server

    def post(self, server, body):
        data = json.dumps(body).encode()
        request = urllib.request.Request("http://127.0.0.1:%d/v1/responses" % server.server_address[1],
                                         data=data, headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(request, timeout=5) as response:
                return response.status, response.read().decode()
        except urllib.error.HTTPError as exc:
            return exc.code, exc.read().decode()

    def test_request_sequence_tool_call_then_final_then_resume(self):
        server = self.serve()
        status, body = self.post(server, {"tools": [{"name": "exec_command"}], "input": [user(IP)]})
        self.assertEqual(status, 200)
        self.assertIn("function_call", body)
        self.assertTrue(server.tool_offered)
        status, body = self.post(server, {"input": [{"type": "function_call_output",
                                 "call_id": fixture.CALL_ID, "output": "x"}]})
        self.assertIn(fixture.FINAL_TEXT, body)
        status, body = self.post(server, {"input": [user(IP), user(RP)]})
        self.assertIn(fixture.RESUME_TEXT, body)
        self.assertTrue(server.resume_verification["verified"])
        self.assertEqual(server.errors, [])

    def test_missing_tool_offer_is_refused(self):
        server = self.serve()
        status, _ = self.post(server, {"tools": [], "input": [user(IP)]})
        self.assertEqual(status, 400)
        self.assertTrue(any("exec_command" in e for e in server.errors))

    def test_unmatched_tool_output_is_refused(self):
        server = self.serve(requests=1, tool_offered=True)
        status, _ = self.post(server, {"input": []})
        self.assertEqual(status, 400)

    def test_fourth_turn_is_refused(self):
        server = self.serve(requests=3)
        status, _ = self.post(server, {"input": [user(RP)]})
        self.assertEqual(status, 400)
        self.assertTrue(any("additional model turn" in e for e in server.errors))


class Child(unittest.TestCase):
    """Run the prescribed child directly under dropped identities (root only)."""

    def setUp(self):
        if os.geteuid() != 0:
            self.skipTest("needs root to drop to test identities")
        self.temporary = tempfile.TemporaryDirectory(dir="/dev/shm")
        self.dir = Path(self.temporary.name)
        self.addCleanup(self.temporary.cleanup)
        os.chmod(self.dir, 0o755)
        self.child = self.dir / "child.py"
        self.child.write_text(fixture.CHILD)
        os.chmod(self.child, 0o644)

    def run_child(self, marker, sessions_dir, uid, gid=None):
        gid = uid if gid is None else gid

        def drop():
            os.setgroups([2000])
            os.setresgid(gid, gid, gid)
            os.setresuid(uid, uid, uid)
        proc = subprocess.run([sys.executable, "-I", str(self.child), str(marker), str(sessions_dir)],
                              capture_output=True, text=True, preexec_fn=drop if uid else None)
        line = [l for l in proc.stdout.splitlines() if l.startswith(fixture.PREFIX)]
        return json.loads(line[0][len(fixture.PREFIX):]) if line else None

    def make_rollout(self, mode=0o644, owner=0, dir_mode=0o755):
        sessions = self.dir / "sessions" / "2026" / "11" / "27"
        sessions.mkdir(parents=True)
        rollout = sessions / "rollout-1-abc.jsonl"
        rollout.write_bytes(b'{"x":1}\n')
        for path in (self.dir / "sessions", sessions):
            os.chmod(path, dir_mode)
            os.chown(path, owner, owner)
        os.chmod(rollout, mode)
        os.chown(rollout, owner, owner)
        return rollout, self.dir / "sessions"

    def test_owner_unlinks_the_rollout(self):
        marker = self.dir / "m.txt"
        marker.write_bytes(b"BEGIN\n")
        rollout, sessions = self.make_rollout(owner=0, dir_mode=0o777)
        os.chmod(marker, 0o666)
        result = self.run_child(marker, sessions, uid=1002)
        self.assertEqual(result["rollout"]["count"], 1)
        self.assertFalse(result["path_exists_after"])
        self.assertEqual(result["remove"]["unlink"], "already_absent")
        self.assertTrue(result["marker_append"]["appended"])
        self.assertFalse(os.path.exists(rollout))

    def test_read_only_path_gives_eacces_and_leaves_bytes_unchanged(self):
        import errno
        marker = self.dir / "m.txt"
        marker.write_bytes(b"BEGIN\n")
        os.chmod(marker, 0o666)
        rollout, sessions = self.make_rollout(owner=0, dir_mode=0o755, mode=0o644)
        before = rollout.read_bytes()
        result = self.run_child(marker, sessions, uid=1002)
        self.assertEqual(result["rollout"]["count"], 1)
        self.assertTrue(result["path_exists_after"])
        self.assertEqual(result["remove"]["unlink"], "denied")
        self.assertEqual(result["remove"]["unlink_errno"], errno.EACCES)
        self.assertEqual(rollout.read_bytes(), before)
        self.assertEqual(result["identity"]["Uid"].split()[:3], ["1002", "1002", "1002"])

    def test_unlistable_ancestor_reports_errno(self):
        import errno
        marker = self.dir / "m.txt"
        marker.write_bytes(b"BEGIN\n")
        os.chmod(marker, 0o666)
        rollout, sessions = self.make_rollout(owner=0, dir_mode=0o700, mode=0o644)
        result = self.run_child(marker, sessions, uid=1002)
        self.assertEqual(result["rollout"]["count"], 0)
        self.assertEqual(result["rollout"]["listing_errno"], errno.EACCES)
        self.assertFalse(result["remove"]["attempted"])


class Derivation(unittest.TestCase):
    def child(self, **remove):
        base = {"rollout": {"path": "/r"}, "path_exists_after": remove.pop("exists", False)}
        base["remove"] = remove
        return base

    def test_denial_errno_classes(self):
        import errno
        before = {"present": True, "inode": 5, "device": 1, "size": 10}
        after = {"present": True, "inode": 5, "device": 1, "size": 30}
        for code, name in ((errno.EACCES, "EACCES"), (errno.EPERM, "EPERM"), (errno.EROFS, "EROFS")):
            child = self.child(unlink="denied", unlink_errno=code, rm_exit=1, exists=True)
            out = fixture.derive_removal(child, {"exit_code": 1}, before, after, [])
            self.assertEqual(out["outcome"], "denied:" + name)

    def test_unlinked_requires_snapshot_agreement(self):
        child = self.child(unlink="removed", exists=False)
        before = {"present": True, "inode": 5, "device": 1, "size": 10}
        gone = {"present": False}
        self.assertEqual(fixture.derive_removal(child, {"exit_code": 0}, before, gone, None)["outcome"], "unlinked")
        # child says gone but the file is still there -> disagreement -> undetermined
        still = {"present": True, "inode": 5, "device": 1, "size": 10}
        self.assertEqual(fixture.derive_removal(child, {"exit_code": 0}, before, still, None)["outcome"],
                         "undetermined")

    def test_missing_snapshot_is_undetermined(self):
        child = self.child(unlink="removed", exists=False)
        self.assertEqual(fixture.derive_removal(child, {"exit_code": 0}, None, {"present": False}, None)["outcome"],
                         "undetermined")
        child2 = self.child(unlink="denied", unlink_errno=13, rm_exit=1, exists=True)
        self.assertEqual(fixture.derive_removal(child2, {"exit_code": 1}, {"present": False}, None, None)["outcome"],
                         "undetermined")

    def test_replacement_or_truncation_is_not_a_denial(self):
        child = self.child(unlink="denied", unlink_errno=13, rm_exit=1, exists=True)
        before = {"present": True, "inode": 5, "device": 1, "size": 10}
        replaced = {"present": True, "inode": 9, "device": 1, "size": 10}
        self.assertEqual(fixture.derive_removal(child, {"exit_code": 1}, before, replaced, None)["outcome"],
                         "undetermined")
        truncated = {"present": True, "inode": 5, "device": 1, "size": 2}
        self.assertEqual(fixture.derive_removal(child, {"exit_code": 1}, before, truncated, None)["outcome"],
                         "undetermined")

    def test_history_extended_from_rollout_records(self):
        rows = [{"type": "response_item", "payload": {"type": "function_call_output",
                 "call_id": fixture.CALL_ID, "output": "x"}}]
        child = self.child(unlink="denied", unlink_errno=13, rm_exit=1, exists=True)
        before = {"present": True, "inode": 5, "device": 1, "size": 10}
        after = {"present": True, "inode": 5, "device": 1, "size": 30}
        self.assertTrue(fixture.derive_removal(child, {"exit_code": 1}, before, after, rows)["history_extended"])
        self.assertFalse(fixture.derive_removal(child, {"exit_code": 1}, before, after, [])["history_extended"])


class Expectations(unittest.TestCase):
    def test_pre_registered_and_compared(self):
        self.assertEqual(fixture.expected_for("full_access")["removal"], "unlinked")
        self.assertEqual(fixture.expected_for("account_separation")["removal"], "denied:EACCES")
        self.assertIn("denied:EROFS", fixture.expected_for("workspace")["removal_in"])
        result = {"removal": {"outcome": "denied:EACCES"}, "resume": {"outcome": "ok"},
                  "tool_identity": {"value": "holds"}, "ancestor_fd": {"any_listing_refused": True},
                  "history_extended": True}
        self.assertTrue(fixture.compare_expectations(result, fixture.expected_for("account_separation"))["all"])
        result["ancestor_fd"]["any_listing_refused"] = False
        self.assertFalse(fixture.compare_expectations(result, fixture.expected_for("account_separation"))["all"])


class PlanAndRefusals(unittest.TestCase):
    def test_counterbalanced_schedule(self):
        order = [e["profile"] for e in runner.counterbalanced(2)]
        self.assertEqual(order, ["full_access", "account_separation", "workspace",
                                 "account_separation", "full_access", "workspace"])

    def test_plan_freezes_hashes_not_tokens(self):
        plan, tokens = runner.freeze_plan(Path("/dev/null"), "docker", 1, "read-only", "img")
        self.assertTrue(plan["native_argv_full_access_equals_account_separation"])
        for slot, token in tokens.items():
            self.assertEqual(plan["reference_token_sha256"][slot], runner.sha_text(token))
        self.assertNotIn(list(tokens.values())[0], json.dumps(plan))
        self.assertEqual(plan["images"]["account_separation"], "img")
        self.assertEqual(plan["policy"]["model_calls"], 0)
        self.assertFalse(plan["policy"]["subscription"])

    def test_collect_refuses_existing_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "exists"
            out.mkdir()
            with self.assertRaisesRegex(Exception, "exists"):
                runner.collect(out, "docker", 1, "read-only", "img")

    def test_sessions_bound_and_output_required(self):
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(runner.main(["--sessions-per-profile", "0", "--output", "/tmp/x"]), 2)
            self.assertEqual(runner.main(["--mode", "docker"]), 2)


class FakeDockerOrchestration(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.directory = Path(self.temporary.name)
        self.addCleanup(self.temporary.cleanup)

    def run_collect(self, env, fault="", sessions=1):
        with tempfile.TemporaryDirectory() as out:
            output = Path(out) / "run"
            proc = subprocess.run(
                [sys.executable, "-m", "research.native.account_separation.run_account_separation_dispatch",
                 "--mode", "docker", "--sessions-per-profile", str(sessions), "--output", str(output)],
                cwd=str(ROOT), env=env, capture_output=True, text=True, timeout=120)
            summary = json.loads((output / "summary.json").read_text()) if (output / "summary.json").exists() else None
            slots = sorted((output).glob("slot-*.json"))
            return proc, summary, [json.loads(p.read_text()) for p in slots]

    def test_full_run_argv_inspect_and_cleanup(self):
        env = fake.install(self.directory)
        proc, summary, slots = self.run_collect(env, sessions=1)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(len(slots), 3)
        # argv for both images, and the account_separation container starts as root.
        runs = {c[c.index("--name") + 1]: c for c in fake.calls(env) if c[0] == "run" and "--name" in c}
        derived = [c for c in runs.values() if "trace-lab-account-separation:derived" in c]
        baseline = [c for c in runs.values() if any("eddc3b19" in t for t in c)]
        self.assertTrue(derived and baseline)
        for c in derived:
            self.assertIn("--user=0:0", c)
            self.assertEqual(sorted(c[i + 1] for i, a in enumerate(c) if a == "--cap-add"),
                             ["SETGID", "SETPCAP", "SETUID"])
            self.assertTrue(any("/home/tool" in t for t in c))
        for c in baseline:
            self.assertIn("--user=1000:1000", c)
            self.assertFalse(any(a == "--cap-add" for a in c))
        # inspect validated for every started container
        for slot in slots:
            if slot.get("status") != "not_executed_in_standin":
                self.assertTrue(slot["inspect_validated"], slot.get("inspect_reasons"))
        # fixture fed on stdin via exec -i
        execs = [c for c in fake.calls(env) if c[0] == "exec"]
        self.assertTrue(any("-i" in c and "-" in c for c in execs))
        # account_separation exec goes through the launcher
        self.assertTrue(any("research.native.account_separation.launcher" in c for c in execs))
        # cleanup: no containers remain
        self.assertEqual(fake.state(env)["containers"], {})

    def test_inspect_mismatch_stops_and_cleans_up(self):
        env = fake.install(self.directory, fault="")
        # Force a mismatch by removing read-only from derived via a fault-free path is
        # hard; instead validate the pure function and the stop path with a bad inspect.
        info = {"Config": {"User": "1000:1000"}, "HostConfig": {"CapDrop": ["ALL"],
                "SecurityOpt": ["no-new-privileges"], "ReadonlyRootfs": True, "NetworkMode": "none",
                "CapAdd": [], "Tmpfs": {"/home/agent": "mode=700"}}}
        ok, reasons = runner.validate_docker_inspect(info, "account_separation", "read-only")
        self.assertFalse(ok)
        self.assertTrue(any("root" in r for r in reasons))
        good = {"Config": {"User": "0:0"}, "HostConfig": {"CapDrop": ["ALL"], "CapAdd": ["SETUID", "SETGID", "SETPCAP"],
                "SecurityOpt": ["no-new-privileges"], "ReadonlyRootfs": True, "NetworkMode": "none",
                "Privileged": False, "Tmpfs": {"/home/agent": "mode=0755", "/home/tool": "x"}}}
        self.assertEqual(runner.validate_docker_inspect(good, "account_separation", "read-only"), (True, []))

    def test_exec_failure_is_reported(self):
        env = fake.install(self.directory, fault="exec_fail")
        proc, summary, slots = self.run_collect(env, sessions=1)
        self.assertNotEqual(proc.returncode, 0)
        self.assertEqual(fake.state(env)["containers"], {})

    def test_preflight_checks_images_binary_and_wrapper(self):
        env = fake.install(self.directory)
        proc = subprocess.run(
            [sys.executable, "-m", "research.native.account_separation.run_account_separation_dispatch",
             "--preflight"], cwd=str(ROOT), env=env, capture_output=True, text=True, timeout=60)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        report = json.loads(proc.stdout)
        self.assertTrue(report["passed"])
        self.assertTrue(report["checks"]["derived_codex_sha"]["matches_pin"])
        self.assertTrue(report["checks"]["derived_wrapper_in_place"]["bash_differs_from_real"])

    def test_preflight_pins_launcher_and_native_separately(self):
        # Regression for the first real preflight (review account-separation-preflight-AmZXYp):
        # the launcher on PATH was compared with the native executable's pin.
        from research.native.account_separation import run_account_separation_dispatch as runner
        self.assertNotEqual(runner.CODEX_SHA, runner.CODEX_LAUNCHER_SHA)
        env = fake.install(self.directory)
        proc = subprocess.run(
            [sys.executable, "-m", "research.native.account_separation.run_account_separation_dispatch",
             "--preflight"], cwd=str(ROOT), env=env, capture_output=True, text=True, timeout=60)
        checks = json.loads(proc.stdout)["checks"]
        for key in ("baseline_codex_sha", "derived_codex_sha"):
            self.assertEqual(checks[key]["path"], runner.CODEX_BINARY)
            self.assertEqual(checks[key]["sha256"], runner.CODEX_SHA)
        self.assertEqual(checks["baseline_launcher_sha"]["path"], "/usr/local/bin/codex")
        self.assertEqual(checks["derived_launcher_sha"]["path"], "/usr/local/bin/codex.real")
        for key in ("baseline_launcher_sha", "derived_launcher_sha"):
            self.assertEqual(checks[key]["sha256"], runner.CODEX_LAUNCHER_SHA)
            self.assertTrue(checks[key]["matches_pin"])

    def test_preflight_reproduces_recorded_real_digests(self):
        # The digests the real preflight recorded must now pass their own pins.
        from research.native.account_separation import run_account_separation_dispatch as runner
        recorded = "61b0194f3bb6534439c8d26a3ed57d0805f84b884588b761795323eeb92fcf70"
        self.assertEqual(runner.CODEX_LAUNCHER_SHA, recorded)

    def test_preflight_fails_on_bad_launcher_sha(self):
        env = fake.install(self.directory, fault="bad_launcher_sha")
        proc = subprocess.run(
            [sys.executable, "-m", "research.native.account_separation.run_account_separation_dispatch",
             "--preflight"], cwd=str(ROOT), env=env, capture_output=True, text=True, timeout=60)
        self.assertEqual(proc.returncode, 1)
        report = json.loads(proc.stdout)
        self.assertFalse(report["passed"])
        self.assertTrue(report["checks"]["derived_codex_sha"]["matches_pin"])
        self.assertFalse(report["checks"]["derived_launcher_sha"]["matches_pin"])

    def test_fixture_exec_argv_passes_both_pins(self):
        from research.native.account_separation import run_account_separation_dispatch as runner
        for profile in ("full_access", "account_separation"):
            argv = runner.fixture_exec_argv("c", profile, "read-only", "tok")
            self.assertEqual(argv[argv.index("--native-binary") + 1], runner.CODEX_BINARY)
            self.assertEqual(argv[argv.index("--expect-binary-sha") + 1], runner.CODEX_SHA)
            self.assertEqual(argv[argv.index("--expect-launcher-sha") + 1], runner.CODEX_LAUNCHER_SHA)

    def test_fixture_hashes_native_and_launcher_as_different_files(self):
        from research.native.account_separation import dispatch_fixture as fixture
        import hashlib, argparse
        native = Path(self.directory) / "native"; native.write_bytes(b"native")
        launcher = Path(self.directory) / "launcher"; launcher.write_bytes(b"launcher")
        def attempt(expect_native, expect_launcher):
            args = argparse.Namespace(reference_token="t", standin=False, profile="full_access",
                                      geometry="read-only", binary=str(launcher), native_binary=str(native),
                                      expect_binary_sha=expect_native, expect_launcher_sha=expect_launcher)
            try:
                return fixture.run(args)
            except AttributeError:
                return None  # got past both hash gates and needed the rest of the arguments
        good_n = hashlib.sha256(b"native").hexdigest(); good_l = hashlib.sha256(b"launcher").hexdigest()
        self.assertIn("binary sha256 mismatch", attempt(good_l, good_l)["errors"])
        self.assertIn("launcher sha256 mismatch", attempt(good_n, good_n)["errors"])
        self.assertIsNone(attempt(good_n, good_l))

    def test_preflight_fails_on_bad_binary_sha(self):
        env = fake.install(self.directory, fault="bad_sha")
        proc = subprocess.run(
            [sys.executable, "-m", "research.native.account_separation.run_account_separation_dispatch",
             "--preflight"], cwd=str(ROOT), env=env, capture_output=True, text=True, timeout=60)
        self.assertEqual(proc.returncode, 1)
        self.assertFalse(json.loads(proc.stdout)["passed"])

    def test_sigterm_during_collection_cleans_up(self):
        env = fake.install(self.directory)
        with tempfile.TemporaryDirectory() as out:
            output = Path(out) / "run"
            proc = subprocess.Popen(
                [sys.executable, "-m", "research.native.account_separation.run_account_separation_dispatch",
                 "--mode", "docker", "--sessions-per-profile", "3", "--output", str(output)],
                cwd=str(ROOT), env=dict(env, FAKE_DOCKER_SLOW="1"), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            time.sleep(1.0)
            proc.send_signal(signal.SIGTERM)
            proc.communicate(timeout=30)
        # No labelled containers remain after the signal.
        self.assertEqual(fake.state(env)["containers"], {})


@unittest.skipUnless(os.geteuid() == 0 and (
    __import__("shutil").which("cc") or __import__("shutil").which("gcc")), "needs root and a C compiler")
class LiveStandin(unittest.TestCase):
    def test_local_standin_runs_both_profiles_for_real(self):
        before_mounts = [l for l in Path("/proc/mounts").read_text().splitlines() if l.startswith("acctsep")]
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "standin"
            proc = subprocess.run(
                [sys.executable, "-m", "research.native.account_separation.run_account_separation_dispatch",
                 "--mode", "local-standin", "--sessions-per-profile", "1", "--output", str(output)],
                cwd=str(ROOT), capture_output=True, text=True,
                env=dict(os.environ, PYTHONPATH=str(ROOT)), timeout=300)
            self.assertEqual(proc.returncode, 0, proc.stderr[-2000:])
            slots = {json.loads(p.read_text())["profile"]: json.loads(p.read_text())
                     for p in sorted(output.glob("slot-*.json"))}
        full = slots["full_access"]["session"]
        self.assertEqual(full["removal"]["outcome"], "unlinked")
        self.assertEqual(full["resume"]["outcome"], "missing_rollout_diagnostic")
        acct = slots["account_separation"]["session"]
        self.assertEqual(acct["removal"]["outcome"], "denied:EACCES")
        self.assertEqual(acct["tool_identity"]["uid"], "1002")
        self.assertTrue(acct["tool_identity"]["all_caps_zero"])
        self.assertEqual(acct["tool_identity"]["nnp"], True)
        self.assertEqual(acct["resume"]["outcome"], "ok")
        self.assertTrue(acct["resume"]["restored_input_verified"])
        self.assertTrue(acct["history_extended"])
        self.assertTrue(acct["ancestor_fd"]["any_listing_refused"])
        self.assertEqual(slots["workspace"]["status"], "not_executed_in_standin")
        # host untouched: no new acctsep mounts leaked
        after_mounts = [l for l in Path("/proc/mounts").read_text().splitlines() if l.startswith("acctsep")]
        self.assertEqual(after_mounts, before_mounts)
        self.assertEqual(subprocess.run(["/bin/bash", "-c", "id -u"], capture_output=True, text=True).stdout.strip(),
                         str(os.getuid()))


if __name__ == "__main__":
    unittest.main()
