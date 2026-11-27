"""The frozen live collectors, wrapped for account separation, against a FAKE docker.

These drive the real frozen ``trace_lab.cli.Experiment.prepare`` and the frozen
``HistoryExperiment.supervised_stage`` through the wrapper, compare the agent
``docker run`` argv with the one the unwrapped frozen class produces, and run the
gates, pilot and batch loop with stub collectors. They verify this code's wiring.
They are not evidence that Docker or Codex behave this way.
"""

import contextlib
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import time
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import test_account_separation_fake_docker as fake  # noqa: E402
from research.native.account_separation import container  # noqa: E402
from research.native.account_separation import experiment as wrapped  # noqa: E402
from research.native.account_separation import run_account_separation_comparison as runner  # noqa: E402
from research.native import run_native_history_comparison as frozen  # noqa: E402
from research.native import run_native_history_pilot as pilot  # noqa: E402
from research.native import run_native_functionality_comparison as functionality  # noqa: E402

DERIVED, DERIVED_ID = "derived:test", "sha256:" + "d" * 64


def name_of(argv):
    return argv[argv.index("--name") + 1]


def suffix_of(argv):
    return name_of(argv).split("-", 3)[-1]


class Harness(unittest.TestCase):
    fault = ""
    base = None

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.directory = Path(self.temporary.name)
        self.env = fake.install(self.directory, fault=self.fault)
        patcher = mock.patch.dict(os.environ, self.env)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.addCleanup(self.temporary.cleanup)
        self.auth = self.directory / "auth.json"
        self.auth.write_text(json.dumps({"auth_mode": "chatgpt", "tokens": {
            "access_token": "fake-access", "account_id": "fake-account",
            "id_token": "fake-id", "refresh_token": "fake-refresh"}}))
        self.auth.chmod(0o600)
        self.experiments = []
        self.addCleanup(self.close)

    def make(self, base=None, wrap=True, name="artifacts"):
        base = base or pilot.HistoryExperiment
        args = pilot.previous.experiment_args(self.directory / name)
        args.codex_auth_file = self.auth
        cls = wrapped.make_experiment_class(base, pilot.cli, DERIVED, DERIVED_ID) if wrap else base
        value = cls(args)
        value.metadata.update(stages=[], controller_intervened=False)
        self.experiments.append(value)
        return value

    def close(self):
        for value in self.experiments:
            try:
                value.close()
            except Exception:
                pass

    def runs(self):
        return {suffix_of(c): c for c in fake.calls(self.env) if c[0] == "run" and "--name" in c}


class PrepareThroughFrozenCode(Harness):
    def test_only_the_agent_container_and_one_seal_step_differ(self):
        experiment = self.make()
        experiment.prepare()
        order = [suffix_of(c) for c in fake.calls(self.env) if c[0] == "run" and "--name" in c]
        self.assertEqual(order[:3], ["init", "codex-auth-init", "records-seal"])
        self.assertLess(order.index("records-seal"), order.index("observer"))
        self.assertLess(order.index("observer"), order.index("agent"))
        runs = self.runs()
        for suffix in ("init", "codex-auth-init", "observer", "gateway"):
            self.assertIn(pilot.original.IMAGE, runs[suffix], suffix)
            self.assertNotIn(DERIVED, runs[suffix], suffix)
        self.assertIn("/home/agent/.codex/auth.json", runs["codex-auth-init"])
        seal = runs["records-seal"]
        self.assertIn(DERIVED, seal)
        self.assertEqual(seal[seal.index("--user") + 1], "0:0")
        self.assertEqual(seal[-2:], ["--geometry", "read_only"])
        agent = runs["agent"]
        self.assertEqual(agent[-len(wrapped.RELAY_AS_RECORDER):], list(wrapped.RELAY_AS_RECORDER))
        self.assertEqual(experiment.args.image, pilot.original.IMAGE)
        check = json.loads((experiment.directory / "account-separation-self-check.json").read_text())
        self.assertTrue(check["passed"])
        self.assertEqual(check["recorder"]["Uid"].split(), ["1000"] * 4)
        self.assertEqual(int(check["recorder"]["CapAmb"], 16), 0x1c0)
        self.assertEqual(check["tool_via_bin_bash"]["Uid"].split(), ["1002"] * 4)
        self.assertEqual(int(check["relay_account"]["CapEff"], 16), 0)
        saved = json.loads((experiment.directory / "run.json").read_text())
        self.assertEqual(saved["os_condition"], "account_separation")
        self.assertEqual(saved["frozen_collector_condition"], "full_access")
        self.assertEqual(saved["account_separation"]["sealed"]["condition_changes"][0]["mode_after"], 0o755)
        self.assertEqual((saved["account_separation"]["recorder_uid"], saved["account_separation"]["tool_uid"]),
                         (1000, 1002))

    def test_agent_argv_differs_from_the_frozen_one_only_as_declared(self):
        condition = self.make(name="condition")
        condition.prepare()
        frozen_experiment = self.make(wrap=False, name="frozen")
        frozen_experiment.prepare()
        agents = [c for c in fake.calls(self.env) if c[0] == "run" and "--name" in c and suffix_of(c) == "agent"]
        self.assertEqual(len(agents), 2)
        def placeholders(e):
            return [(e.prefix, "<run>"), (e.run_id, "<run-id>")]
        difference = container.argv_difference(
            agents[1], agents[0], placeholders(frozen_experiment) + placeholders(condition))
        self.assertEqual(difference["only_in_frozen"], ["--user 1000:1000", pilot.original.IMAGE])
        self.assertEqual(difference["only_in_condition"], [
            "--user 0:0", "--cap-add SETUID", "--cap-add SETGID", "--cap-add SETPCAP",
            "--tmpfs " + container.TOOL_HOME_TMPFS, DERIVED, *wrapped.RELAY_AS_RECORDER])
        type(self).last_difference = difference

    def test_frozen_validator_runs_on_everything_but_the_declared_differences(self):
        experiment = self.make()
        experiment.prepare()
        info = json.loads(pilot.cli.docker("inspect", experiment.agent).stdout)[0]
        with self.assertRaises(RuntimeError):
            pilot.original.validate_agent(info, experiment)     # raw condition container
        validate = wrapped.make_validate_agent(pilot.original.validate_agent, pilot.original.IMAGE, DERIVED_ID)
        settings = validate(info, experiment)
        self.assertEqual(settings["user"], "0:0")
        self.assertEqual(settings["cap_add"], ["SETGID", "SETPCAP", "SETUID"])
        self.assertTrue(settings["frozen_validator_applied_to_everything_else"])
        self.assertFalse(settings["mounts"]["/relay"]["writable"])
        for change, phrase in (
                (lambda i: i["HostConfig"]["CapAdd"].append("SYS_ADMIN"), "cap-add"),
                (lambda i: i.__setitem__("Image", pilot.original.IMAGE), "image id"),
                (lambda i: i["Config"].__setitem__("User", "1000:1000"), "start user"),
                (lambda i: i["HostConfig"]["Tmpfs"].pop("/home/tool"), "tmpfs"),
                # Not a declared difference: the FROZEN validator must reject these.
                (lambda i: i["HostConfig"].__setitem__("ReadonlyRootfs", False), "isolation"),
                (lambda i: i["HostConfig"].__setitem__("NetworkMode", "bridge"), "isolation"),
                (lambda i: i["HostConfig"].__setitem__("Memory", 1), "resource"),
                (lambda i: i["Mounts"].append({"Type": "volume", "Name": "x", "Destination": "/x", "RW": True}),
                 "mount")):
            tampered = json.loads(json.dumps(info))
            change(tampered)
            with self.assertRaisesRegex(RuntimeError, phrase):
                validate(tampered, experiment)

    def test_frozen_stage_runs_unchanged_argv_and_audit_is_copied_out(self):
        experiment = self.make()
        experiment.prepare()
        command = pilot.adapter.challenge_command(experiment.args, "full_access")
        entry = json.dumps({"uid": [1002] * 3, "last_argument_sha256": "x"}) + "\n"
        with mock.patch.dict(os.environ, {"FAKE_DOCKER_AUDIT": entry}):
            stage = experiment.supervised_stage("initial-task", command, "prompt", time.monotonic() + 30)
        self.assertEqual(stage["exit_code"], 0)
        self.assertEqual(stage["native_argv"], command)
        stage_exec = [c for c in fake.calls(self.env) if c[0] == "exec"
                      and any("native_clock_instrumentation" in a for a in c)][-1]
        self.assertNotIn("--user", stage_exec)
        self.assertEqual(stage_exec[-len(command):], command)
        self.assertIn('default_permissions=":danger-full-access"', command)
        self.assertFalse(any("CODEX_HOME" in a for a in stage_exec))
        self.assertEqual((experiment.directory / "wrapper-audit.jsonl").read_text(), entry)
        # A later copy that does not extend the earlier one is kept apart and flagged.
        with mock.patch.dict(os.environ, {"FAKE_DOCKER_AUDIT": "{}\n"}):
            experiment.collect_wrapper_audit()
        self.assertEqual((experiment.directory / "wrapper-audit.jsonl").read_text(), entry)
        self.assertIn("no longer extends", experiment.account_separation["wrapper_audit_error"])

    def test_process_observer_also_samples_the_tool_account(self):
        calibrated = pilot.previous.calibrated
        frozen_argv = calibrated.create_args("n", "t", "observer", target_id="x")
        extended = wrapped.make_create_args(calibrated.create_args)("n", "t", "observer", target_id="x")
        self.assertEqual(extended, [*frozen_argv, "--uid", "1000", "--uid", "1002"])
        target = wrapped.make_create_args(calibrated.create_args)("n", "t", "target")
        self.assertEqual(target, calibrated.create_args("n", "t", "target"))

    def test_functionality_experiment_class_wraps_the_same_way(self):
        with mock.patch.object(functionality.ComparisonExperiment, "context", {"source_commit": "c0ffee"}):
            experiment = self.make(base=functionality.ComparisonExperiment, name="f/condition/artifacts")
        experiment.prepare()
        agent = self.runs()["agent"]
        self.assertIn(DERIVED, agent)
        self.assertEqual(agent[agent.index("--user") + 1], "0:0")

    def test_close_removes_every_container_and_volume(self):
        experiment = self.make()
        experiment.prepare()
        experiment.close()
        left = fake.state(self.env)
        self.assertEqual((left["containers"], left["volumes"]), ({}, {}))
        self.assertEqual(experiment.metadata["cleanup_errors"], [])


class SealFailure(Harness):
    fault = "seal_leaves_agent_entry"

    def test_agent_never_starts_when_the_tool_account_could_write_the_home_volume(self):
        with self.assertRaisesRegex(RuntimeError, "tool account could modify"):
            self.make().prepare()
        self.assertFalse({"agent", "observer"} & set(self.runs()))


class SelfCheckRecorderIsRoot(Harness):
    fault = "self_check_recorder_root"

    def test_stage_is_refused_when_recorder_identity_is_wrong(self):
        experiment = self.make()
        with self.assertRaisesRegex(RuntimeError, "self-check failed"):
            experiment.prepare()
        self.assertFalse(json.loads((experiment.directory / "account-separation-self-check.json").read_text())["passed"])


class SelfCheckToolIsRecorder(Harness):
    fault = "self_check_tool_is_recorder"

    def test_stage_is_refused_when_the_shell_is_not_dropping(self):
        with self.assertRaisesRegex(RuntimeError, "self-check failed"):
            self.make().prepare()


def passing_control(directory, image_id=DERIVED_ID, **changes):
    four = {"a": "holds", "b": "holds", "c": "holds",
            "d_negative_controls": {"N1": "holds", "N2": "holds", "N3": "holds"}}
    boundary = {"auth_not_readable": "holds", "recorder_state_protected": "holds", "wrapper_audit": "holds",
                "proc_route_and_signal_refused": {"proc_fd_list": "holds"}}
    run = {"four_statements_read_only": four, "four_statements_no_access": four,
           "layout_requirements": {"main_read_only": "holds", "main_no_access": "holds"},
           "boundary_checks": {"main_read_only": boundary, "main_no_access": boundary}}
    result = {"status": "executed", "mode": "docker", "repeat": 2, "runs": [run, run], "errors": [],
              "reproducible_identical_verdicts": True, "all_statements_hold": True,
              "cleanup": {"verified": True}, "image_id": image_id,
              "comparison_with_local_control": {"verdicts_match": True}}
    result.update(changes)
    path = Path(directory, "control.json")
    path.write_text(json.dumps(result))
    return path


class GateMixin:
    def gate(self, control=None, image=DERIVED, patches=()):
        args = mock.Mock(derived_image=image, control_result=control)
        exp_args = mock.Mock(codex_auth_file=self.auth)
        with contextlib.ExitStack() as stack:
            stack.enter_context(mock.patch.object(runner, "ROOT", Path.cwd().resolve()))
            for patch in patches:
                stack.enter_context(patch)
            return runner.gates(args, exp_args, pilot)

    def frozen_ok(self):
        return [mock.patch.object(pilot, "prior_inputs", return_value=({"upstream_request_limit_per_attempt": 18}, {"p": 1})),
                mock.patch.object(pilot, "source_snapshot", return_value=("c0ffee", {})),
                mock.patch.object(pilot.access, "check_access", return_value={"ok": True})]



class Gates(GateMixin, Harness):
    def test_each_gate_stops_with_its_next_step(self):
        with self.assertRaisesRegex(runner.Stop, "not present. Next: python3 research/native/account_separation/build_derived_image.py"):
            self.gate(image="absent:tag")
        with self.assertRaisesRegex(runner.Stop, "run_account_separation_control.py --mode docker"):
            self.gate(control=self.directory / "missing.json")
        with self.assertRaisesRegex(runner.Stop, "different image id"):
            self.gate(control=passing_control(self.directory, image_id="sha256:other"))
        good = passing_control(self.directory)
        with self.assertRaisesRegex(runner.Stop, "Frozen prerequisites"):
            self.gate(control=good, patches=[mock.patch.object(pilot, "prior_inputs", side_effect=RuntimeError("archive"))])
        with self.assertRaisesRegex(runner.Stop, "not committed.*git add research/native/account_separation"):
            self.gate(control=good, patches=[self.frozen_ok()[0],
                      mock.patch.object(pilot, "source_snapshot", side_effect=RuntimeError("Untracked"))])
        with self.assertRaisesRegex(runner.Stop, "Subscription access"):
            self.gate(control=good, patches=[*self.frozen_ok()[:2],
                      mock.patch.object(pilot.access, "check_access", side_effect=RuntimeError("401"))])
        self.assertFalse(any(c[0] == "run" and "--name" in c for c in fake.calls(self.env)))

    def test_all_gates_pass_and_record_facts(self):
        facts = self.gate(control=passing_control(self.directory), patches=self.frozen_ok())
        self.assertEqual(facts["image_id"], DERIVED_ID)
        self.assertTrue(facts["smoke"]["passed"])
        self.assertEqual(facts["smoke"]["recorder"]["status"]["Uid"].split(), ["1000"] * 4)
        self.assertEqual(facts["smoke"]["tool"]["status"]["Uid"].split(), ["1002"] * 4)
        smoke_runs = [c for c in fake.calls(self.env) if c[0] == "run" and "--rm" in c]
        self.assertEqual(len(smoke_runs), 2)
        for argv in smoke_runs:
            self.assertEqual(sorted(argv[i + 1] for i, a in enumerate(argv) if a == "--cap-add"),
                             ["SETGID", "SETPCAP", "SETUID"])
            self.assertIn("no-new-privileges", argv)


class SmokeFails(GateMixin, Harness):
    fault = "smoke_no_ambient"

    def test_smoke_failure_stops_before_anything_else(self):
        with self.assertRaisesRegex(runner.Stop, "identity smoke failed"):
            self.gate(control=passing_control(self.directory), patches=self.frozen_ok())


class BatchLoop(unittest.TestCase):
    """Real filesystem writes; stub collectors (no Docker, no model)."""

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.folder = Path(self.temporary.name) / "batch"
        self.addCleanup(self.temporary.cleanup)
        self.calls = []

    def plan(self, rows):
        plan = {"schema": "account-separation-live-plan-v1", "mode": "batch", "source_commit": "c0ffee",
                "schedule": rows, "frozen_design": {}, "derived_image_id": DERIVED_ID}
        frozen.save_once(self.folder / "plan.json", plan)
        return plan

    def collector(self, condition, self_check=True, session=None, policy="continue", crash=False):
        def collect(destination):
            self.calls.append((condition, destination.name))
            if crash:
                raise RuntimeError("container lost")
            record = {"condition": "full_access", "session_id": session or "session-%d" % len(self.calls),
                      "run_folder": "full_access/artifacts/run", "policy": policy,
                      "privacy_finding": {"primary_confirmed_unlink": condition == "full_access"}}
            target = destination / "full_access"
            (target / "artifacts/run").mkdir(parents=True)
            (target / "diagnostics.json").write_text(json.dumps(record))
            label = {"account_separation": {"self_check": {"passed": self_check}}} \
                if condition == "account_separation" else None
            return record, label
        return collect

    def run_loop(self, plan, collectors, stop_after=None):
        analyse = lambda destination: {"summary": {"jsonl_present_at_all_three_captures": True,
                                                   "exact_token_recalled": True}}
        with contextlib.redirect_stdout(io.StringIO()):
            return runner.continue_schedule(frozen, self.folder, plan, collectors,
                                            lambda directory, record: {"state": "stub"}, analyse,
                                            lambda record: record["policy"] == "continue", stop_after)

    def both(self, **kwargs):
        return {"full_access": self.collector("full_access"),
                "account_separation": self.collector("account_separation", **kwargs)}

    def test_counterbalanced_schedule(self):
        rows = runner.schedule(5)
        self.assertEqual(len(rows), 10)
        self.assertEqual([r["condition"] for r in rows[:4]],
                         ["full_access", "account_separation", "account_separation", "full_access"])
        self.assertEqual(sum(r["condition"] == "account_separation" for r in rows), 5)
        self.assertEqual(runner.schedule(1, pilot=True), [{"attempt": 1, "pair": 1, "condition": "account_separation"}])

    def test_complete_batch_resume_between_attempts_and_immutable_evidence(self):
        plan = self.plan(runner.schedule(2))
        first = self.run_loop(plan, self.both(), stop_after=1)
        self.assertEqual((first["started_attempts"], first["collection_complete"]), (1, False))
        done = self.run_loop(plan, self.both())
        self.assertTrue(done["collection_complete"])
        self.assertEqual([c[1] for c in self.calls], ["attempt-01", "attempt-02", "attempt-03", "attempt-04"])
        self.assertEqual(done["conditions"]["account_separation"]["completed"], 2)
        self.assertEqual(done["conditions"]["full_access"]["confirmed_unlink_automatic"], 2)
        again = self.run_loop(plan, self.both())
        self.assertEqual(len(self.calls), 4)                      # nothing is rerun
        self.assertEqual(again, done)
        (self.folder / "attempt-02/analysis.json").write_text("{}")
        with self.assertRaisesRegex(RuntimeError, "evidence changed"):
            self.run_loop(plan, self.both())

    def test_failed_self_check_pauses_the_batch(self):
        plan = self.plan(runner.schedule(2))
        result = self.run_loop(plan, self.both(self_check=False))
        self.assertEqual(result["paused_attempts"], [2])
        self.assertEqual(len(self.calls), 2)
        with self.assertRaisesRegex(RuntimeError, "needs review"):
            self.run_loop(plan, self.both())
        self.assertEqual(len(self.calls), 2)

    def test_collection_policy_and_duplicate_session_pause(self):
        plan = self.plan(runner.schedule(1))
        result = self.run_loop(plan, {"full_access": self.collector("full_access", policy="pause"),
                                      "account_separation": self.collector("account_separation")})
        self.assertEqual(result["paused_attempts"], [1])
        other = Path(self.temporary.name) / "second"
        self.folder = other
        plan = self.plan(runner.schedule(1))
        result = self.run_loop(plan, {"full_access": self.collector("full_access", session="same"),
                                      "account_separation": self.collector("account_separation", session="same")})
        self.assertEqual(result["paused_attempts"], [2])

    def test_crashed_attempt_is_retained_and_never_restarted(self):
        plan = self.plan(runner.schedule(1))
        with self.assertRaisesRegex(RuntimeError, "container lost"):
            self.run_loop(plan, {"full_access": self.collector("full_access", crash=True),
                                 "account_separation": self.collector("account_separation")})
        self.assertTrue((self.folder / "attempt-01/start.json").is_file())
        with self.assertRaisesRegex(RuntimeError, "needs review"):
            self.run_loop(plan, self.both())
        self.assertEqual(len(self.calls), 1)


class RunnerCommands(unittest.TestCase):
    def test_pilot_stops_at_the_first_gate_without_creating_anything(self):
        with tempfile.TemporaryDirectory() as empty, mock.patch.dict(os.environ, {"PATH": empty}), \
                contextlib.redirect_stderr(io.StringIO()) as stderr:
            before = (ROOT / "runs").exists()
            for action in ("pilot", "batch", "functionality"):
                self.assertEqual(runner.main([action]), 3)
            self.assertEqual((ROOT / "runs").exists(), before)
        self.assertIn("Next: start Docker", stderr.getvalue())

    def test_status_names_every_step_and_no_remaining_code(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.assertEqual(runner.main(["status"]), 0)
        value = json.loads(out.getvalue())
        self.assertEqual(value["code_remaining"], [])
        verdicts = {s["step"]: s["verdict"] for s in value["steps"]}
        self.assertEqual(verdicts["Three store captures"], "unchanged")
        self.assertEqual(verdicts["auth.json installation"], "unchanged")

    def test_model_visible_argv_is_the_frozen_full_access_one(self):
        argv = runner.assert_model_visible_identity(runner.experiment_args())
        self.assertEqual(argv[0], "codex")
        self.assertIn('default_permissions=":danger-full-access"', argv)
        self.assertFalse(any("CODEX_HOME" in a for a in argv))


class FunctionalityClassifier(unittest.TestCase):
    def value(self, **tool):
        from research.native import native_functionality_tool as control
        ids = "1002\t1002\t1002\t1002"
        base = {"uid": 1002, "gid": 1002, "workspace_write_verified": True, "outside_write_denied": True,
                "outside_write_errno": 13, "outside_unchanged": True,
                "credentials": {"Uid": ids, "Gid": ids, "NoNewPrivs": "1", "CapEff": "0", "CapPrm": "0", "CapAmb": "0"}}
        base.update(tool)
        return {"tool": base, "workspace": "workspace-write-ok\n", "outside": control.SEED.decode()}

    def test_expects_tool_account_and_a_denied_outside_write(self):
        self.assertTrue(wrapped.classify_tool(self.value(), "full_access")["passed"])
        # The frozen classifier would call this very observation a failure.
        self.assertFalse(functionality.classify_tool(self.value(), "full_access")["passed"])
        self.assertFalse(wrapped.classify_tool(self.value(uid=1000, gid=1000), "full_access")["passed"])
        allowed = self.value(outside_write_denied=False, outside_write_errno=None, outside_unchanged=False)
        self.assertEqual(wrapped.classify_tool(allowed, "full_access")["outside_write_finding"], "write_allowed")
        self.assertFalse(wrapped.classify_tool(allowed, "full_access")["passed"])
        self.assertFalse(wrapped.classify_tool(self.value(outside_write_errno=28), "full_access")["passed"])

    def test_collect_functionality_substitutes_and_restores(self):
        seen = {}
        def frozen_collect(folder, condition, commit):
            seen.update(cls=functionality.ComparisonExperiment, classify=functionality.classify_tool,
                        condition=condition)
            return {"condition": condition}
        originals = (functionality.ComparisonExperiment, functionality.classify_tool,
                     functionality.original.validate_agent)
        with tempfile.TemporaryDirectory() as tmp, mock.patch.object(functionality, "collect_condition", frozen_collect):
            record, label = wrapped.collect_functionality(functionality, tmp, "c0ffee", DERIVED, DERIVED_ID)
            self.assertTrue((Path(tmp) / "account-separation-label.json").is_file())
        self.assertEqual(seen["condition"], "full_access")
        self.assertIs(seen["classify"], wrapped.classify_tool)
        self.assertEqual(seen["cls"].context["source_commit"], "c0ffee")
        self.assertTrue(issubclass(seen["cls"], originals[0]) and seen["cls"] is not originals[0])
        self.assertEqual((functionality.ComparisonExperiment, functionality.classify_tool,
                          functionality.original.validate_agent), originals)
        self.assertEqual(label["os_condition"], "account_separation")


class IdentityPredicates(unittest.TestCase):
    def test_from_first_principles(self):
        recorder = {"Uid": "1000\t1000\t1000\t1000", "Gid": "1000\t1000\t1000\t1000", "CapAmb": "1c0",
                    "CapEff": "1c0", "NoNewPrivs": "1"}
        self.assertTrue(wrapped.recorder_identity_ok(recorder))
        self.assertFalse(wrapped.recorder_identity_ok(dict(recorder, CapAmb="0")))
        self.assertFalse(wrapped.recorder_identity_ok(dict(recorder, Uid="0\t0\t0\t0")))
        tool = {"Uid": "1002\t1002\t1002\t1002", "Gid": "1002\t1002\t1002\t1002", "NoNewPrivs": "1",
                **{k: "0" for k in ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb")}}
        self.assertTrue(wrapped.tool_identity_ok(tool))
        self.assertFalse(wrapped.tool_identity_ok(dict(tool, CapBnd="c0")))
        self.assertFalse(wrapped.tool_identity_ok(dict(tool, Uid="1000\t1000\t1000\t1000")))
        self.assertFalse(wrapped.tool_identity_ok({}))


if __name__ == "__main__":
    unittest.main()
