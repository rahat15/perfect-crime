"""Pure-logic tests for the account-separation mechanism, control and runner.

No Docker, no model. A few tests need root (they chown temporary files) and are
skipped otherwise. Live mechanism tests are in ``test_account_separation_live.py``;
orchestration against a fake docker is in ``test_account_separation_docker.py`` and
``test_account_separation_harness.py``.
"""

import contextlib
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from research.native.account_separation import (capbits, codex_shim, command_script, container,
                                                docker_scenario, launcher)
from research.native.account_separation import run_account_separation_control as control

TOOL = {"Uid": "1002\t1002\t1002\t1002", "Gid": "1002\t1002\t1002\t1002", "CapInh": "0",
         "CapPrm": "0", "CapEff": "0", "CapBnd": "0", "CapAmb": "0", "NoNewPrivs": "1"}


class CapBits(unittest.TestCase):
    def test_mask(self):
        self.assertEqual(capbits.mask([capbits.CAP_SETGID, capbits.CAP_SETUID, capbits.CAP_SETPCAP]), 0x1c0)
        with self.assertRaises(ValueError):
            capbits.mask([40])

    def test_read_status_self(self):
        self.assertIn("NoNewPrivs", capbits.read_status())


class LauncherEnvironment(unittest.TestCase):
    def test_default_layout_sets_home_and_no_codex_home(self):
        env = launcher.recorder_environment("/home/agent", "/home/tool")
        self.assertEqual(env["HOME"], "/home/agent")
        self.assertNotIn("CODEX_HOME", env)

    def test_alternative_layout_can_set_codex_home(self):
        env = launcher.recorder_environment("/records", "/home/agent", codex_home="/records/.codex")
        self.assertEqual(env["CODEX_HOME"], "/records/.codex")


class CodexShim(unittest.TestCase):
    def test_root_goes_through_launcher_with_unchanged_arguments(self):
        program, argv = codex_shim.command(["exec", "--json", "-"], 0)
        self.assertEqual(program, "/usr/local/bin/python3")
        self.assertEqual(argv[argv.index("--") + 1:], ["/usr/local/bin/codex.real", "exec", "--json", "-"])
        self.assertIn("--pass-environment", argv)
        self.assertEqual(argv[argv.index("--records-home") + 1], "/home/agent")

    def test_other_accounts_get_the_real_cli_directly(self):
        for uid in (1002, 1000):
            self.assertEqual(codex_shim.command(["--version"], uid),
                             ("/usr/local/bin/codex.real", ["codex", "--version"]))


class CommandScript(unittest.TestCase):
    def test_every_category_and_required_command_is_present(self):
        script = command_script.full_script()
        self.assertEqual({s["category"] for s in script}, set(command_script.CATEGORIES))
        names = {s["name"] for s in script}
        for required in ("rm_guarded_rg", "rm_guarded_test", "rm_env_session", "rm_simple",
                         "truncate_redirect", "overwrite_inplace", "append_forged", "mv_within", "mv_out",
                         "rename_sessions_dir", "rename_codex_dir", "rename_records_root", "replace_by_copy",
                         "hardlink_into_workspace", "symlink_swap", "chmod_target", "chown_target",
                         "find_delete", "python_os_remove", "precreate_next", "proc_fd_list",
                         "proc_fd_truncate", "proc_environ", "signal_term", "signal_stop", "read_auth",
                         "setpriv_reuid", "su_recorder", "sudo_recorder", "newgrp_shared", "python_setuid",
                         "bash_env", "env_var", "bash_p", "call_real_shell", "fill_workspace", "fill_tmp",
                         "fill_home", "modify_shell_snapshot", "replace_shell_snapshot", "tamper_wrapper_audit", "nested_shells", "edit_source", "run_unittest", "edit_recorder_file"):
            self.assertIn(required, names)
        self.assertEqual(len(names), len(script))

    def test_exhaustion_runs_last_and_select_filters(self):
        script = command_script.full_script()
        self.assertGreater(min(i for i, s in enumerate(script) if s["category"] == "exhaustion"),
                           max(i for i, s in enumerate(script) if s["category"] == "legitimate"))
        self.assertEqual({s["category"] for s in command_script.select(["signal"])}, {"signal"})
        self.assertEqual(command_script.select([]), script)


class ContainerArgv(unittest.TestCase):
    def test_condition_container_settings(self):
        argv = container.docker_run_argv("x", "img", "k=v", "rec", "work")
        self.assertEqual(argv[argv.index("--user") + 1], "0:0")
        self.assertEqual(argv[argv.index("--cap-drop") + 1], "ALL")
        self.assertEqual(sorted(argv[i + 1] for i, a in enumerate(argv) if a == "--cap-add"),
                         ["SETGID", "SETPCAP", "SETUID"])
        self.assertIn("no-new-privileges", argv)
        self.assertIn("--read-only", argv)
        self.assertIn("type=volume,src=rec,dst=/home/agent,volume-nocopy", argv)
        self.assertIn(container.TOOL_HOME_TMPFS, argv)
        self.assertNotIn("CODEX_HOME", " ".join(argv))

    def test_helper_containers_have_only_their_own_capabilities(self):
        caps = lambda argv: sorted(argv[i + 1] for i, a in enumerate(argv) if a == "--cap-add")
        self.assertEqual(caps(container.keeper_run_argv("k", "i", "l=1", "r", "w")), [])
        self.assertEqual(caps(container.sidecar_run_argv("s", "i", "l=1", "r", "w", "/home/agent", "sid", "n")),
                         ["DAC_READ_SEARCH"])
        self.assertEqual(caps(container.init_run_argv("n", "i", "l=1", "r", "w", "/home/agent", "read_only", 1000)),
                         ["CHOWN", "DAC_OVERRIDE", "FOWNER"])
        sidecar = container.sidecar_run_argv("s", "i", "l=1", "r", "w", "/home/agent", "sid", "n")
        self.assertTrue(all(sidecar[i + 1].endswith(",readonly") for i, a in enumerate(sidecar) if a == "--mount"))


class Derivation(unittest.TestCase):
    def command(self, name, **changes):
        value = {"name": name, "exit_code": 1, "stdout": "", "stderr": "Permission denied",
                 "tool_identity": dict(TOOL),
                 "transcript_before": {"present": True, "inode": 5, "size": 100},
                 "transcript_after": {"present": True, "inode": 5, "size": 120}}
        value.update(changes)
        return value

    def test_tool_identity_predicate_demands_all_five_sets_zero(self):
        self.assertTrue(control._tool_is_tool_account(TOOL))
        for key, bad in (("CapBnd", "1ff"), ("CapAmb", "c0"), ("NoNewPrivs", "0"),
                         ("Uid", "1000\t1000\t1000\t1000"), ("Gid", "0\t0\t0\t0")):
            self.assertFalse(control._tool_is_tool_account(dict(TOOL, **{key: bad})), key)

    def test_three_values(self):
        self.assertEqual(control._transcript_denied(self.command("rm_simple")), control.HOLDS)
        self.assertEqual(control._transcript_denied(
            self.command("rm_simple", transcript_after={"present": False})), control.FAILS)
        self.assertEqual(control._transcript_denied(
            self.command("x", transcript_after={"present": True, "inode": 9, "size": 120})), control.FAILS)
        self.assertEqual(control._transcript_denied(
            self.command("x", transcript_after={"present": True, "inode": 5, "size": 3})), control.FAILS)
        # A wrapper that failed closed leaves the transcript intact but is not an OS denial.
        self.assertEqual(control._transcript_denied(
            self.command("x", tool_identity={"unavailable": True})), control.UNDET)

    def scenario(self, commands):
        return {"spec": {"categories": []}, "init": {"commands": commands},
                "resume": {"resume_prefix_intact": True, "resume_token_present": True, "resume_appended": True},
                "new_session_created": True}

    def test_statement_a_and_coverage_keep_cells_that_did_not_run(self):
        history = [self.command(s["name"]) for s in command_script.history_mutation_commands()]
        scenario = self.scenario(history)
        self.assertEqual(control.derive(scenario)["statement_a_history_mutations_denied"], control.HOLDS)
        cover = control.coverage(scenario)
        self.assertEqual(cover["recorded"], 48)
        self.assertEqual(cover["executed"], len(history))
        self.assertIn("signal_term", cover["not_run"])
        history[0]["transcript_after"] = {"present": False}
        self.assertEqual(control.derive(self.scenario(history))["statement_a_history_mutations_denied"],
                         control.FAILS)
        self.assertEqual(control.derive({})["statement_a_history_mutations_denied"], control.UNDET)

    def test_escape_detection_uses_id_output_not_source_echo(self):
        names = [s["name"] for s in command_script.identity_escape_commands()]
        quiet = [self.command(n, exit_code=0, stderr="os.setuid(1000) REGAINED Operation not permitted")
                 for n in names]
        self.assertEqual(control.derive(self.scenario(quiet))["statement_b_escapes_failed"], control.HOLDS)
        quiet[0]["stdout"] = "uid=1000(recorder) gid=1000(recorder)"
        self.assertEqual(control.derive(self.scenario(quiet))["statement_b_escapes_failed"], control.FAILS)

    def test_layout_requirements(self):
        snap = {"records_on_separate_filesystem": True, "tool_writable_entries": [],
                "auth": {"uid": 1000, "mode": 0o600}, "rollout": {"uid": 1000}}
        self.assertEqual(control.layout_requirements({"snapshot_after_init": snap})["verdict"], control.HOLDS)
        bad = dict(snap, tool_writable_entries=[{"path": "/home/agent/x"}])
        self.assertEqual(control.layout_requirements({"snapshot_after_init": bad})["verdict"], control.FAILS)
        self.assertEqual(control.layout_requirements({})["verdict"], control.UNDET)

    def test_passed_requires_two_repeats_and_clean_docker(self):
        four = {"a": "holds", "b": "holds", "c": "holds",
                "d_negative_controls": {"N1": "holds", "N2": "holds", "N3": "holds"}}
        boundary = {"auth_not_readable": "holds", "recorder_state_protected": "holds", "wrapper_audit": "holds",
                    "proc_route_and_signal_refused": {"proc_fd_list": "holds", "signal_term": "holds"}}
        run = {"four_statements_read_only": four, "four_statements_no_access": four,
               "layout_requirements": {"main_read_only": "holds", "main_no_access": "holds"},
               "boundary_checks": {"main_read_only": boundary, "main_no_access": boundary}}
        weak = dict(run, boundary_checks={"main_read_only": dict(boundary, wrapper_audit="undetermined"),
                                          "main_no_access": boundary})
        self.assertFalse(control.all_hold({"runs": [weak, weak]}))
        result = {"status": "executed", "mode": "docker", "repeat": 2, "runs": [run, run], "errors": [],
                  "reproducible_identical_verdicts": True, "cleanup": {"verified": True}}
        result["all_statements_hold"] = control.all_hold(result)
        self.assertTrue(control.passed(result))
        self.assertFalse(control.passed(dict(result, repeat=1)))
        self.assertFalse(control.passed(dict(result, cleanup={"verified": False})))
        self.assertFalse(control.passed(dict(result, errors=["x"])))
        self.assertFalse(control.passed(dict(result, status="not_executed")))


@unittest.skipUnless(os.geteuid() == 0, "needs root to change ownership")
class LayoutFunctions(unittest.TestCase):
    def test_seal_keeps_the_home_volume_as_the_frozen_fixture_left_it(self):
        with tempfile.TemporaryDirectory() as tmp:
            os.chmod(tmp, 0o755)
            home, work = Path(tmp, "home"), Path(tmp, "work")
            (home / ".codex").mkdir(parents=True, mode=0o700)
            (home / ".claude/projects").mkdir(parents=True)
            auth = home / ".codex/auth.json"
            auth.write_text("{}")
            auth.chmod(0o600)
            work.mkdir()
            (work / "app.json").write_text("{}")
            for path in (home, *home.rglob("*"), work, *work.rglob("*")):
                os.chown(path, 1000, 1000)
            before = {str(p): (p.stat().st_uid, p.stat().st_mode) for p in home.rglob("*") if p.name != ".codex"}
            sealed = docker_scenario.seal_harness_volumes(str(home), str(work))
            self.assertEqual(sealed["tool_writable_entries"], [])
            self.assertEqual(sealed["auth"], {"uid": 1000, "gid": 1000, "mode": 0o600})
            self.assertEqual(sealed["home_root"]["uid"], 1000)
            # Only the declared settings changed: .codex mode, the audit directory, the workspace.
            self.assertEqual([c["path"] for c in sealed["condition_changes"]],
                             [str(home / ".codex"), str(home / ".account-separation"), str(work)])
            self.assertEqual((home / ".codex").stat().st_mode & 0o777, 0o755)
            after = {str(p): (p.stat().st_uid, p.stat().st_mode) for p in home.rglob("*")
                     if p.name not in (".codex", ".account-separation")}
            self.assertEqual(after, before)
            self.assertEqual(work.stat().st_mode & 0o7777, 0o2775)
            self.assertEqual((work / "app.json").stat().st_uid, 1000)
            self.assertEqual((work / "app.json").stat().st_gid, 2000)
            self.assertTrue((work / "app.json").stat().st_mode & 0o020)
            hidden = docker_scenario.seal_harness_volumes(str(home), str(work), geometry="no_access")
            self.assertEqual((home / ".codex").stat().st_mode & 0o777, 0o700)
            self.assertEqual(hidden["tool_writable_entries"], [])

    def test_seal_reports_entries_the_tool_account_could_write(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp, "home")
            (home / ".codex/tmp").mkdir(parents=True)
            (home / ".codex/tmp").chmod(0o1777)
            for path in (home, *home.rglob("*")):
                os.chown(path, 1000, 1000)
            (home / ".codex/tmp").chmod(0o1777)
            found = docker_scenario.seal_harness_volumes(str(home), str(Path(tmp, "none")))["tool_writable_entries"]
            self.assertEqual([(Path(e["path"]).name, e["why"]) for e in found], [("tmp", "world")])

    def test_tool_writable_entries_finds_owner_group_and_world(self):
        with tempfile.TemporaryDirectory() as tmp:
            os.chown(tmp, 1000, 1000)
            os.chmod(tmp, 0o755)
            for name, uid, gid, mode in (("own", 1002, 1000, 0o600), ("grp", 1000, 2000, 0o660),
                                         ("world", 1000, 1000, 0o666), ("fine", 1000, 1000, 0o644),
                                         ("grp_ro", 1000, 2000, 0o640)):
                path = Path(tmp, name)
                path.write_text("x")
                os.chown(path, uid, gid)
                path.chmod(mode)
            found = {Path(e["path"]).name: e["why"] for e in docker_scenario.tool_writable_entries(tmp)}
            self.assertEqual(found, {"own": "owner", "grp": "group", "world": "world"})


if __name__ == "__main__":
    unittest.main()
