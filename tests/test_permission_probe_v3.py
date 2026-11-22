"""Tests for permission probe 03: coded expectations, reuse of the probe-02 primitives, three-valued
derivation, mocked docker flow, committed-evidence consistency, and root-only live checks."""

import copy
import errno
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

from research.tools import permission_probe_v3_fixture as fixture
from research.tools import run_permission_probe_v3 as runner

v2, base = fixture.v2, runner.base
ROOT = Path(__file__).resolve().parents[1]
EVIDENCE = ROOT / runner.EVIDENCE
SUMMARY = ROOT / runner.SUMMARY
REVIEW = EVIDENCE.parent
README = REVIEW / "README.md"
DESIGN = ROOT / "research/analysis/permission-probe-03-design.md"
TOOL = Path(runner.__file__)
IMAGE = "sha256:eddc3b1939fb346372fe8e6aa2806f1bb03696867704f3e70143e12492115aa5"
INTEGRATED = ["I1_readonly", "I2_no_access", "I3_readonly_append_only", "I4_no_access_append_only"]
FULL = INTEGRATED + ["N1_same_filesystem", "N2_agent_owned_parent"]


class ExpectationDataTests(unittest.TestCase):
    def test_layouts_and_their_registration_in_the_probe_02_table(self):
        self.assertEqual(list(fixture.LAYOUTS), FULL + ["N3_inherited_descriptor_no_flag"])
        self.assertEqual(list(fixture.INTEGRATED), INTEGRATED)
        committed_cases, committed_child = dict(v2.CASES), v2.CHILD
        for name, item in fixture.LAYOUTS.items():
            spec = item["spec"]
            self.assertNotIn(name, v2.CASES, "importing probe 03 leaves the probe-02 layout table alone")
            with fixture.registered():
                self.assertIs(v2.CASES[name], spec)
                self.assertEqual(v2.identity_for(name, "recorder"), (1001, 1001, []))
                self.assertEqual(v2.identity_for(name, "agent"), (1000, 1000, []))
                self.assertIs(v2.CHILD, fixture.CHILD)
            self.assertEqual(spec["recorder_account"], "separate")
            self.assertEqual(spec["directory"][:2], (v2.RECORDER_UID, v2.RECORDER_GID))
        self.assertEqual(v2.CASES, committed_cases)
        self.assertEqual(list(v2.CASES), list(committed_cases))
        self.assertIs(v2.CHILD, committed_child)
        self.assertEqual((fixture.AGENT, fixture.RECORDER), ((1000, 1000, []), (1001, 1001, [])))
        for name, item in fixture.LAYOUTS.items():
            if item["kind"] == "integrated":
                self.assertEqual(item["placement"], "separate")
                self.assertEqual(item["spec"]["parent"], (0, 0, 0o755), "ancestors are not agent-owned")
        self.assertEqual(fixture.LAYOUTS["N1_same_filesystem"]["placement"], "shared")
        self.assertEqual(fixture.LAYOUTS["N2_agent_owned_parent"]["spec"]["parent"][0], v2.AGENT_UID)
        self.assertEqual({name for name, item in fixture.LAYOUTS.items() if item["sealer"]},
                         {"I3_readonly_append_only", "I4_no_access_append_only"})

    def test_every_ordinary_and_window_cell_has_a_rule_with_a_reason(self):
        for name in FULL:
            self.assertEqual(list(fixture.ORDINARY_CODES[name]), list(v2.OPERATIONS))
            self.assertEqual(list(fixture.WINDOW_CODES[name]), list(fixture.WINDOW_OPERATIONS))
            for operation in v2.OPERATIONS:
                for sysctl in (0, 1):
                    verdict, reason = fixture.expected_ordinary(name, operation, sysctl)
                    self.assertIn(verdict, (v2.D, v2.E, v2.N, fixture.BOUNDARY))
                    self.assertGreater(len(reason), 20)
                with fixture.registered():
                    skip = v2.not_applicable_reason(name, operation)
                self.assertEqual(fixture.ORDINARY_CODES[name][operation] == "N", skip is not None,
                                 (name, operation))
            for operation in fixture.WINDOW_OPERATIONS:
                self.assertIn(fixture.expected_window(name, operation)[0], (v2.D, fixture.BOUNDARY))
        self.assertEqual(fixture.expected_ordinary("N1_same_filesystem", "hardlink_create", 1)[0], v2.D)
        self.assertEqual(fixture.expected_ordinary("N1_same_filesystem", "hardlink_create", 0)[0], v2.E)
        self.assertEqual(fixture.expected_ordinary("I1_readonly", "hardlink_create", 0)[0], fixture.BOUNDARY)
        self.assertEqual(fixture.expected_ordinary("N2_agent_owned_parent", "symlink_swap_dir", 1)[0], v2.E)

    def test_boundary_is_expected_only_across_filesystems_and_never_in_the_no_access_layouts(self):
        for name in FULL:
            codes = set(fixture.ORDINARY_CODES[name].values()) | set(fixture.WINDOW_CODES[name].values())
            separate_and_searchable = (fixture.LAYOUTS[name]["placement"] == "separate"
                                       and fixture.LAYOUTS[name]["spec"]["directory"][2] == 0o755)
            self.assertEqual("X" in codes, separate_and_searchable, name)

    def test_design_document_tables_equal_the_coded_rules(self):
        text = DESIGN.read_text()
        ordinary = text[text.index("Ordinary operations (the sixteen"):text.index("New-session window (the agent")]
        window = text[text.index("New-session window (the agent"):text.index("`N3` runs the descriptor")]
        for section, codes in ((ordinary, fixture.ORDINARY_CODES), (window, fixture.WINDOW_CODES)):
            seen = {}
            for line in section.splitlines():
                match = re.match(r"\| `(\w+)` \|", line)
                if match:
                    seen[match.group(1)] = re.findall(r"\((\w)\)", line)
            self.assertEqual(seen, {name: list(row.values()) for name, row in codes.items()})
        for phrase in ("cannot be independently verified", "blocked_by_filesystem_boundary"):
            self.assertIn(phrase, text)

    def test_suppression_legit_descriptor_and_negative_control_expectations(self):
        for name in FULL:
            self.assertEqual(list(fixture.SUPPRESSION_EXPECTED[name]), list(fixture.SUPPRESSION_OPERATIONS))
            for operation, (verdict, reason) in fixture.SUPPRESSION_EXPECTED[name].items():
                self.assertIn(verdict, (v2.S, v2.NOSUP))
                self.assertGreater(len(reason), 20)
            for control in fixture.LEGIT_CONTROLS:
                value, reason = fixture.expected_legit(name, control)
                self.assertIn(value, (True, False, None, "readable", "denied"))
        for name in INTEGRATED:
            self.assertTrue(all(verdict == v2.NOSUP for verdict, _ in fixture.SUPPRESSION_EXPECTED[name].values()))
        self.assertEqual(fixture.expected_legit("I2_no_access", "agent_read_transcript")[0], "denied")
        self.assertIsNone(fixture.expected_legit("I1_readonly", "sealer_seals_new_session_then_recorder_appends")[0])
        self.assertFalse(fixture.expected_legit("N1_same_filesystem",
                                                "recorder_appends_200_after_agent_filled_workspace")[0])
        for name in fixture.LAYOUTS:
            for control in v2.DESCRIPTOR_CONTROLS:
                verdict, outcome, reason = fixture.expected_descriptor(name, control)
                self.assertEqual(outcome is None, verdict == v2.N)
        self.assertEqual(fixture.expected_descriptor("N3_inherited_descriptor_no_flag", "fd_append_ftruncate")[0],
                         v2.E)
        self.assertEqual(fixture.expected_descriptor("I3_readonly_append_only", "fd_append_ftruncate")[:2],
                         (v2.D, "no_change"))
        self.assertEqual(fixture.expected_descriptor("I4_no_access_append_only", "dirfd_listdir")[1],
                         "names_listed_via_dirfd_only")
        names = {"ordinary": v2.OPERATIONS, "descriptors": v2.DESCRIPTOR_CONTROLS,
                 "suppression": fixture.SUPPRESSION_OPERATIONS}
        for layout, cells in fixture.NEGATIVE_CONTROL_SIGNALS.items():
            self.assertEqual(fixture.LAYOUTS[layout]["kind"], "negative_control")
            for group, name, designed in cells:
                self.assertIn(name, names[group])
                self.assertIn(designed, (v2.E, v2.S))


class ReuseTests(unittest.TestCase):
    def test_child_script_is_probe_02s_with_one_appended_operation(self):
        self.assertEqual(fixture.CHILD.count("elif operation == 'exhaust_inodes'"), 1)
        self.assertNotIn("exhaust_inodes", v2.CHILD)
        self.assertEqual(fixture.CHILD.replace(fixture._EXTRA, ""), v2.CHILD)

    def test_appended_child_operation_runs_and_reports_like_the_others(self):
        with tempfile.TemporaryDirectory() as directory:
            request = {"operation": "exhaust_inodes", "roots": [directory], "base": directory, "parent": directory,
                       "records": directory, "target": os.path.join(directory, "t"), "workspace": directory,
                       "payloads": {}, "inode_sinks": [directory, os.path.join(directory, "absent")], "inode_cap": 5}
            done = subprocess.run([sys.executable, "-I", "-c", fixture.CHILD, json.dumps(request)],
                                  capture_output=True, text=True, timeout=30)
            self.assertEqual(done.returncode, 0, done.stderr)
            result = json.loads(done.stdout)
            self.assertEqual(result["inode_sinks"][0]["created"], 5)
            self.assertEqual(result["inode_sinks"][1]["errno"], errno.ENOENT)
            self.assertFalse(result["operation_succeeded"], "the cap was reached without ENOSPC")
            self.assertIn("uid", result["identity"])
            self.assertEqual(len(os.listdir(directory)), 5)

    def test_workspace_placement_wrapper_supplies_the_root_and_restores_the_original(self):
        calls, original = [], v2.setup_fixture
        with patch.object(v2, "setup_fixture", side_effect=lambda *a, **k: calls.append((a, k))) as inner:
            with fixture.workspace_on("/ws"):
                self.assertIsNot(v2.setup_fixture, inner)
                v2.setup_fixture("/records", "name", "case")
                v2.setup_fixture("/records", "name", "case", workspace_root="/explicit")
            self.assertIs(v2.setup_fixture, inner)
            with fixture.workspace_on(None):
                v2.setup_fixture("/records", "name", "case")
        self.assertEqual([call[0][3] for call in calls], ["/ws", "/explicit", None])
        self.assertIs(v2.setup_fixture, original)

    @staticmethod
    def row(verdict=v2.UNEXPECTED, error=errno.EXDEV, unchanged=True, uid=1000, cap="0" * 16):
        status = {"CapPrm": "0" * 16, "CapEff": cap, "CapAmb": "0" * 16, "NoNewPrivs": "1"}
        return {"case": "I1_readonly", "verdict": verdict, "protected_state_unchanged": unchanged,
                "child": {"errno": error, "failed_step": "rename", "fixture_base_reachable": True,
                          "operation_succeeded": False,
                          "identity": {"uid": [uid] * 3, "gid": [uid] * 3, "groups": [], "status": status,
                                       "inherited_probe_fds": []}}}

    def test_boundary_needs_exdev_an_unchanged_state_and_a_valid_child(self):
        self.assertEqual(fixture.apply_boundary(self.row())["verdict"], fixture.BOUNDARY)
        self.assertEqual(fixture.apply_boundary(self.row())["probe_02_classification"], v2.UNEXPECTED)
        for changed in (self.row(error=errno.ENOSPC), self.row(unchanged=False), self.row(uid=0),
                        self.row(cap="0000000000000002"), self.row(verdict=v2.D, error=errno.EACCES)):
            before = changed["verdict"]
            self.assertEqual(fixture.apply_boundary(changed)["verdict"], before)

    def test_bounded_root_check(self):
        with tempfile.TemporaryDirectory() as directory:
            problem = fixture.bounded_root_problem({"path": directory, "filesystem": {"mount_point": "/"}})
            self.assertIn("not the root of a dedicated filesystem", problem)

    def test_bundle_carries_both_fixtures_and_runs_from_stdin(self):
        payload = runner.bundle()
        compile(payload, "bundle", "exec")
        self.assertIn(b"permission_probe_v2_fixture", payload)
        done = subprocess.run([sys.executable, "-I", "-", "--help"], input=payload, capture_output=True, timeout=60,
                              cwd="/")
        self.assertEqual(done.returncode, 0, done.stderr.decode()[-400:])
        self.assertIn(b"--records-root", done.stdout)
        self.assertIn(b"--shared-root", done.stdout)


class DockerTests(unittest.TestCase):
    def test_command_keeps_the_committed_hardening_and_supplies_three_filesystems(self):
        committed = base.container_command(IMAGE, "n", "i")
        command = runner.container_command(IMAGE, "n", "i")
        mounts = [command[index + 1] for index, value in enumerate(command) if value == "--tmpfs"]
        self.assertEqual(mounts, [path + ":" + runner.TMPFS_OPTIONS for path in runner.CONTAINER_ROOTS.values()])
        self.assertIn("nr_inodes=1024", runner.TMPFS_OPTIONS)
        self.assertIn("size=8m", runner.TMPFS_OPTIONS)
        self.assertEqual(command[-8:], ["-I", "-", "--records-root", "/probe-records", "--workspace-root",
                                        "/probe-workspace", "--shared-root", "/probe-shared"])
        self.assertEqual(command[command.index("--label") + 1], runner.LABEL + "=i")
        for flag in ("--pull=never", "--read-only", "--interactive"):
            self.assertIn(flag, command)
        for flag, value in (("--network", "none"), ("--cap-drop", "ALL"), ("--user", "0:0"),
                            ("--security-opt", "no-new-privileges"), ("--pids-limit", "64"),
                            ("--memory", "256m"), ("--cpus", "1"), ("--entrypoint", "python3")):
            self.assertEqual(command[command.index(flag) + 1], value)
            self.assertEqual(committed[committed.index(flag) + 1], value)
        self.assertEqual({command[i + 1] for i, v in enumerate(command) if v == "--cap-add"}, set(base.CAPABILITIES))
        for flag in ("--privileged", "--mount", "--volume", "-v", "SYS_ADMIN"):
            self.assertNotIn(flag, command)
        self.assertNotIn("/probe:" + base.TMPFS_OPTIONS, command)

    @staticmethod
    def inspection():
        return {"network_mode": "none", "readonly_rootfs": True, "binds": None, "mounts": [], "user": "0:0",
                "entrypoint": ["python3"], "privileged": False, "cap_drop": ["ALL"],
                "command": ["-I", "-"] + runner.fixture_arguments(runner.CONTAINER_ROOTS),
                "tmpfs": {path: runner.TMPFS_OPTIONS for path in runner.CONTAINER_ROOTS.values()},
                "cap_add": ["CAP_" + name for name in base.CAPABILITIES], "security_options": ["no-new-privileges"]}

    def test_inspection_validation(self):
        runner.validate_inspection(self.inspection())
        changes = {
            "tmpfs mounts": lambda r: r["tmpfs"].update({"/probe": "rw"}),
            "tmpfs mounts ": lambda r: r["tmpfs"].pop("/probe-shared"),
            "options": lambda r: r["tmpfs"].update({"/probe-records": "rw,size=8m"}),
            "setup command": lambda r: r["command"].append("--layouts"),
            "Unexpected mount": lambda r: r.update(mounts=[{"Type": "bind", "Destination": "/probe-records"}]),
            "host bind": lambda r: r.update(binds=["/home:/x"]),
            "capabilities": lambda r: r["cap_add"].append("CAP_SYS_ADMIN"),
            "network": lambda r: r.update(network_mode="host"),
            "no-new-privileges": lambda r: r.update(security_options=[]),
        }
        for message, change in changes.items():
            record = self.inspection()
            change(record)
            with self.subTest(message), self.assertRaisesRegex(ValueError, message.strip()):
                runner.validate_inspection(record)

    def raw(self, extra=None):
        record = self.inspection()
        return [{"Image": IMAGE, "Mounts": [],
                 "Config": {"Image": IMAGE, "User": "0:0", "Entrypoint": ["python3"], "Cmd": record["command"]},
                 "HostConfig": {"NetworkMode": "none", "ReadonlyRootfs": True,
                                "CapAdd": record["cap_add"] + ([extra] if extra else []), "CapDrop": ["ALL"],
                                "Privileged": False, "SecurityOpt": ["no-new-privileges"],
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

    def test_docker_flow_feeds_the_bundle_and_removes_only_its_own_container(self):
        calls = []
        done = subprocess.CompletedProcess([], 0, stdout=b'{"protocol": "x"}', stderr=b"")
        with patch.object(base, "command", side_effect=self.fake(calls, self.raw())), \
                patch.object(runner.subprocess, "run", return_value=done) as start:
            observations, run, settings, failure = runner.run_docker(IMAGE)
        self.assertIsNone(failure)
        self.assertEqual(observations, {"protocol": "x"})
        self.assertEqual(start.call_args.kwargs["input"], runner.bundle())
        self.assertIn(["docker", "rm", "--force", run["container_name"]], calls)
        query = next(call for call in calls if call[:2] == ["docker", "ps"])
        self.assertIn("label=%s=%s" % (runner.LABEL, run["container_identifier"]), query)
        self.assertTrue(run["cleanup_verified"])

    def test_docker_flow_refuses_unexpected_settings_before_starting(self):
        calls = []
        with patch.object(base, "command", side_effect=self.fake(calls, self.raw("CAP_SYS_ADMIN"))), \
                patch.object(runner.subprocess, "run") as start:
            observations, run, _, failure = runner.run_docker(IMAGE)
        start.assert_not_called()
        self.assertIsNone(observations)
        self.assertIn("capabilities", failure)
        self.assertTrue(run["cleanup_verified"])
        with patch.object(base, "command", return_value="someone-else"):
            with self.assertRaisesRegex(ValueError, "Unexpected container"):
                runner.remove_own_container("mine", "id")


@unittest.skipUnless(EVIDENCE.is_file() and SUMMARY.is_file() and README.is_file(), "probe 03 not recorded")
class CommittedEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.evidence = json.loads(EVIDENCE.read_text())
        cls.o = cls.evidence["observations"]
        cls.summary = json.loads(SUMMARY.read_text())
        cls.rows = {(r["case"], r["operation"]): r for r in cls.o["rows"]}
        cls.fd = {(r["case"], r["control"]): r for r in cls.o["descriptor_controls"]}
        cls.sup = {(r["case"], r["operation"]): r for r in cls.o["suppression_controls"]}
        cls.legit = {(r["case"], r["control"]): r for r in cls.o["legit_controls"]}

    def test_summary_and_readme_derive_from_the_evidence(self):
        expected = runner.summarize(self.evidence)
        expected["evidence_sha256"] = base.sha(EVIDENCE)
        self.assertEqual(self.summary, json.loads(json.dumps(expected)))
        text = README.read_text()
        for name, table in runner.render_tables(self.evidence).items():
            with self.subTest(name):
                self.assertIn("<!-- BEGIN %s -->\n%s\n<!-- END %s -->" % (name, table, name), text)
        for phrase in (base.sha(EVIDENCE), runner.LEGEND, "Docker mode has not been executed",
                       "not native Codex", "synthetic proxies", "cannot be independently verified",
                       "sha256:eddc3b19", "--mode docker"):
            self.assertIn(phrase, text)
        for word in ("secure", "solves"):
            self.assertNotIn(word, text.lower().replace("insecure", ""))

    def test_evidence_was_produced_by_the_checked_in_code(self):
        run = self.evidence["run"]
        self.assertEqual(run["fixture_sha256"], base.sha(ROOT / runner.V3_FIXTURE))
        self.assertEqual(run["probe_02_fixture_sha256"], base.sha(ROOT / runner.V2_FIXTURE))
        self.assertEqual(run["runner_sha256"], base.sha(TOOL))
        self.assertEqual((run["status"], run["cleanup_verified"], run["model_calls"], run["mode"]),
                         ("finished", True, 0, "local"))
        self.assertEqual(self.o["protocol"], fixture.PROTOCOL)

    def test_every_expected_cell_is_recorded_once_with_the_coded_expectation(self):
        hardlinks = self.o["environment"]["sysctl_fs"]["protected_hardlinks"]
        wanted = {(name, op) for name in FULL for op in v2.OPERATIONS} | {
            (name, fixture.WINDOW_PREFIX + op) for name in FULL for op in fixture.WINDOW_OPERATIONS}
        self.assertEqual(set(self.rows), wanted)
        self.assertEqual(len(self.o["rows"]), len(wanted))
        for (name, operation), row in self.rows.items():
            if operation.startswith(fixture.WINDOW_PREFIX):
                expected = fixture.expected_window(name, operation[len(fixture.WINDOW_PREFIX):])[0]
            else:
                expected = fixture.expected_ordinary(name, operation, hardlinks)[0]
            self.assertEqual(row["expected"], expected, (name, operation))
            self.assertTrue(row["expectation_basis"])
        self.assertEqual(set(self.sup), {(n, op) for n in FULL for op in fixture.SUPPRESSION_OPERATIONS})
        self.assertEqual(set(self.fd), {(n, c) for n in fixture.LAYOUTS for c in v2.DESCRIPTOR_CONTROLS})
        self.assertEqual(set(self.legit), {(n, c) for n in FULL for c in fixture.LEGIT_CONTROLS})
        coverage = self.summary["coverage"]["total"]
        self.assertEqual((coverage["recorded"], coverage["executed"], coverage["not_run"]),
                         (len(self.o["rows"]) + len(self.fd) + len(self.sup) + len(self.legit), 261, 12))
        self.assertEqual(coverage["not_run_by_kind"][base.NOT_EXECUTED], 0)
        self.assertEqual(self.summary["expectation_mismatch_count"], 0)

    def test_geometry_separate_filesystems_and_protected_ancestors(self):
        roots = {item["label"]: item for item in self.o["environment"]["probe_roots"]}
        self.assertTrue(self.o["environment"]["filesystems_distinct"])
        for name in INTEGRATED:
            layout = self.o["layouts"][name]
            self.assertEqual(layout["records_root"], roots["records"]["path"])
            self.assertEqual(layout["workspace_root"], roots["workspace"]["path"])
            row = self.rows[name, "rewrite"]
            chain = row["ancestors"]
            start = [item["path"] for item in chain].index(roots["records"]["path"])
            inside = chain[start:]
            self.assertEqual(len(inside), 4, "mount root, cell, parent, records directory")
            for item in inside:
                self.assertIn(item["uid"], (0, v2.RECORDER_UID), item)
                self.assertNotEqual(item["uid"], v2.AGENT_UID)
                self.assertEqual(int(item["mode"], 8) & 0o022, 0, "not group- or world-writable")
            self.assertTrue(row["after"]["workspace_listing"]["is_directory"])
            self.assertTrue(row["fixture"]["base"].startswith(roots["records"]["path"]))
        self.assertEqual(self.o["layouts"]["N1_same_filesystem"]["records_root"], roots["shared"]["path"])
        self.assertEqual(self.o["layouts"]["N1_same_filesystem"]["workspace_root"], roots["shared"]["path"])

    def test_every_child_was_the_intended_unprivileged_identity(self):
        for row in self.o["rows"]:
            if base.not_run_kind(row) is None:
                self.assertTrue(v2.identity_valid(row["child"], (1000, 1000, [])), (row["case"], row["operation"]))
                if "recorder_create_child" in row:
                    self.assertTrue(v2.identity_valid(row["recorder_create_child"], (1001, 1001, [])))
        for row in self.o["suppression_controls"] + [r for r in self.o["legit_controls"] if "stages" in r]:
            for stage in row.get("stages", []):
                self.assertTrue(stage["identity_valid"], (row["case"], stage["stage"]))
                self.assertEqual(stage["child"]["identity"]["uid"][0],
                                 1000 if stage["acting_role"] == "agent" else 1001)
        setup = self.o["environment"]["setup_process"]
        self.assertEqual(sorted(setup["effective_capability_names"]), sorted(base.CAPABILITIES))

    # ----- first-principles checks on security-critical cells -----

    def test_cross_filesystem_operations_are_exdev_with_the_transcript_untouched(self):
        for name in ("I1_readonly", "I3_readonly_append_only"):
            for operation in ("replace", "rename_out_of_dir", "symlink_swap_file", "hardlink_create"):
                row = self.rows[name, operation]
                self.assertEqual(row["verdict"], fixture.BOUNDARY)
                self.assertEqual(row["child"]["errno"], errno.EXDEV)
                self.assertEqual(row["after"]["target"], row["before"]["target"])
                self.assertEqual(row["after"]["target"]["sha256"], v2.digest(v2.BASE))
                self.assertEqual(row["after"]["original_inode_paths"], ["home/records/" + v2.TARGET_NAME])
        for operation in ("replace", "rename_out_of_dir", "symlink_swap_file", "hardlink_create"):
            row = self.rows["I2_no_access", operation]
            self.assertEqual((row["verdict"], row["child"]["errno"]), (v2.D, errno.EACCES))
            same_fs = self.rows["N1_same_filesystem", operation]
            self.assertEqual(same_fs["verdict"], v2.D)
        self.assertEqual(self.rows["N1_same_filesystem", "hardlink_create"]["child"]["errno"], errno.EPERM)

    def test_negative_control_n2_parent_swap(self):
        swap = self.rows["N2_agent_owned_parent", "symlink_swap_dir"]
        self.assertEqual(swap["verdict"], v2.E)
        self.assertEqual(swap["after"]["records_dir"]["type"], "symlink")
        self.assertEqual(swap["after"]["target_resolved"]["sha256"], v2.digest(v2.ATTACKER))
        self.assertEqual(swap["after"]["original_inode_paths"], ["home/records-moved/" + v2.TARGET_NAME])
        self.assertEqual(self.rows["N2_agent_owned_parent", "rename_parent_dir"]["verdict"], v2.E)
        for name in INTEGRATED:
            for operation in ("rename_parent_dir", "symlink_swap_dir"):
                self.assertEqual((self.rows[name, operation]["verdict"],
                                  self.rows[name, operation]["child"]["errno"]), (v2.D, errno.EACCES))

    def test_fill_and_inode_suppression_only_where_the_agent_reaches_the_records_filesystem(self):
        fill, inode = "fill_workspace_filesystem_then_recorder_append", "exhaust_inodes_then_recorder_new_session"
        direct = "fill_records_filesystem_directly_then_recorder_append"
        for name in INTEGRATED:
            row = self.sup[name, fill]
            self.assertEqual(row["verdict"], v2.NOSUP)
            self.assertTrue(row["records_and_workspace_on_separate_filesystems"])
            self.assertEqual(row["recorder_complete_records"], v2.APPEND_MANY_COUNT)
            results = {sink["path"].split("/")[-2]: sink["result"] for sink in row["agent_fill_sinks"]}
            self.assertEqual(results, {"workspace": "ENOSPC", "home": "EACCES", "records": "EACCES"})
            self.assertEqual(row["capacity_after_fill"]["workspace_filesystem"]["free_bytes"], 0)
            self.assertGreater(row["capacity_after_fill"]["records_filesystem"]["free_bytes"], 0)
            self.assertEqual(row["after"]["target"]["sha256"],
                             v2.digest(v2.BASE + v2.TRUSTED * v2.APPEND_MANY_COUNT))
            self.assertEqual(self.sup[name, direct]["agent_writable_sinks_on_records_filesystem"], [])
            self.assertEqual(len(self.sup[name, direct]["sinks_tried"]), 4)
            node = self.sup[name, inode]
            self.assertEqual((node["verdict"], node["recorder_new_session_result"]), (v2.NOSUP, "ok"))
            self.assertEqual(node["inode_sinks"][0]["result"], "ENOSPC")
            self.assertEqual(node["capacity_after_agent"]["workspace_filesystem"]["free_inodes"], 0)
            self.assertTrue(all(sink["files_created"] == 0 for sink in node["inode_sinks"][1:]))
        same = self.sup["N1_same_filesystem", fill]
        self.assertEqual(same["verdict"], v2.S)
        self.assertLess(same["recorder_complete_records"], v2.APPEND_MANY_COUNT)
        node = self.sup["N1_same_filesystem", inode]
        self.assertEqual((node["verdict"], node["recorder_new_session_result"]), (v2.S, "ENOSPC"))
        self.assertEqual(node["recorder_new_session_file"]["exists"], False)
        self.assertEqual(node["recorder_append_to_existing_transcript_result"], "ok")
        parent = self.sup["N2_agent_owned_parent", direct]
        self.assertEqual(parent["verdict"], v2.S)
        self.assertEqual(len(parent["agent_writable_sinks_on_records_filesystem"]), 1)

    def test_new_session_window_and_sealer(self):
        for name in INTEGRATED:
            for operation in fixture.WINDOW_OPERATIONS:
                row = self.rows[name, fixture.WINDOW_PREFIX + operation]
                self.assertIn(row["verdict"], (v2.D, fixture.BOUNDARY))
                unsealed = row["unsealed_file"]
                self.assertEqual((unsealed["uid"], unsealed["mode"]), (v2.RECORDER_UID, "0o644"))
                self.assertFalse(unsealed["inode_flags"]["append_only"], "the file is not flagged in the window")
                self.assertEqual(row["after"]["target"], row["before"]["target"])
                self.assertEqual("seal" in row, fixture.LAYOUTS[name]["sealer"])
                if "seal" in row:
                    self.assertTrue(row["seal"]["sealed_file"]["inode_flags"]["append_only"])
                    self.assertTrue(row["seal"]["recorder_append_after_seal_passed"])
                    self.assertEqual(row["seal"]["final_file"]["sha256"], v2.digest(v2.BASE + v2.TRUSTED))
        proxy = self.legit["I3_readonly_append_only", "sealer_seals_new_session_then_recorder_appends"]
        self.assertTrue(proxy["passed"])
        self.assertEqual(proxy["recorder_truncate_after_seal_result"], "EPERM")
        self.assertEqual(self.legit["I1_readonly", "sealer_seals_new_session_then_recorder_appends"]["outcome"],
                         v2.N)

    def test_inherited_descriptor_contrast(self):
        plain, flagged = "N3_inherited_descriptor_no_flag", "I3_readonly_append_only"
        self.assertEqual(self.fd[plain, "fd_append_ftruncate"]["after"]["target"]["size"], 0)
        self.assertEqual(self.fd[plain, "fd_append_clear_flag_then_pwrite"]["outcome"], "earlier_bytes_modified")
        for control in ("fd_append_ftruncate", "fd_append_clear_flag_then_pwrite"):
            row = self.fd[flagged, control]
            self.assertEqual((row["verdict"], row["child"]["errno"]), (v2.D, errno.EPERM))
            self.assertEqual(row["after"]["target"]["sha256"], v2.digest(v2.BASE))
        self.assertEqual(self.fd[flagged, "fd_append_write"]["outcome"], "appended_marker")
        self.assertEqual(base.not_run_kind(self.fd[flagged, "fd_wronly_ftruncate"]), base.PRECONDITION_REFUSED)
        self.assertEqual(self.fd["I2_no_access", "dirfd_listdir"]["outcome"], "names_listed_via_dirfd_only")
        contrast = self.summary["inherited_descriptor_contrast_without_and_with_append_only"]
        self.assertEqual(contrast["fd_append_ftruncate"], {plain: v2.E, flagged: v2.D})

    def test_statement_is_derived_and_three_valued(self):
        assessment = runner.assess(self.o)
        for name in INTEGRATED:
            entry = assessment[name]
            self.assertEqual({key: entry[key]["status"] for key in entry if key != "all_three"},
                             {"a_all_tampering_denied_or_blocked": base.HOLDS,
                              "b_all_suppression_operations_resisted": base.HOLDS,
                              "c_all_layout_discriminating_proxies_pass": base.HOLDS})
            self.assertEqual(entry["all_three"], base.HOLDS)
        self.assertEqual(assessment["I1_readonly"]["a_all_tampering_denied_or_blocked"]["satisfied_by"],
                         {v2.D: 16, fixture.BOUNDARY: 5})
        self.assertEqual(assessment["I2_no_access"]["a_all_tampering_denied_or_blocked"]["satisfied_by"], {v2.D: 21})
        self.assertEqual(assessment["N2_agent_owned_parent"]["all_three"], base.FAILS)
        self.assertEqual(assessment["N1_same_filesystem"]["b_all_suppression_operations_resisted"]["status"],
                         base.FAILS)
        controls = runner.negative_controls(self.o)
        self.assertEqual({name: entry["failure_detected"] for name, entry in controls.items()},
                         {"N1_same_filesystem": True, "N2_agent_owned_parent": True,
                          "N3_inherited_descriptor_no_flag": True})
        self.assertEqual(len(self.summary["statement"]), 7)

    def test_not_run_and_bad_cells_change_the_statement_as_the_rule_says(self):
        changed = copy.deepcopy(self.o)
        for row in changed["suppression_controls"]:
            if row["case"] == "I1_readonly" and row["operation"].startswith("fill_"):
                row.update(verdict=v2.N, matches_expectation=None, not_run_reason="/x is not size-limited")
            if row["case"] == "I2_no_access" and row["operation"].startswith("exhaust_"):
                row["verdict"] = v2.S
        for row in changed["rows"]:
            if row["case"] == "I3_readonly_append_only" and row["operation"] == "delete":
                row["verdict"] = v2.UNEXPECTED
            if row["case"] == "I4_no_access_append_only" and row["operation"] == "new_session_window:rewrite":
                row["verdict"] = v2.E
        for row in changed["legit_controls"]:
            if row["case"] == "I4_no_access_append_only" and row["control"] == "recorder_new_transcript":
                row.update(outcome=v2.N, not_run_reason="fixture setup failed")
                row.pop("passed")
        for row in changed["descriptor_controls"]:
            if row["case"] == "N3_inherited_descriptor_no_flag" and row["control"] == "fd_append_ftruncate":
                row["verdict"] = v2.D
        result = runner.assess(changed)
        fills = result["I1_readonly"]["b_all_suppression_operations_resisted"]
        self.assertEqual(fills["status"], base.UNDETERMINED)
        self.assertEqual(len(fills["missing"]), 2)
        self.assertEqual(result["I2_no_access"]["b_all_suppression_operations_resisted"]["status"], base.FAILS)
        self.assertEqual(result["I3_readonly_append_only"]["a_all_tampering_denied_or_blocked"]["status"],
                         base.UNDETERMINED)
        self.assertEqual(result["I4_no_access_append_only"]["a_all_tampering_denied_or_blocked"]["failing"],
                         ["op/I4_no_access_append_only/new_session_window:rewrite"])
        self.assertEqual(result["I4_no_access_append_only"]["c_all_layout_discriminating_proxies_pass"]["status"],
                         base.UNDETERMINED)
        self.assertFalse(runner.negative_controls(changed)["N3_inherited_descriptor_no_flag"]["failure_detected"])
        text = "\n".join(runner.statement(changed))
        self.assertIn("UNDETERMINED", text)
        self.assertIn("NOT detected", text)

    def test_supplementary_records_match_the_compare_files(self):
        record = json.loads((REVIEW / "supplementary-runs.json").read_text())
        self.assertEqual(record["committed_evidence_sha256"], base.sha(EVIDENCE))
        for key, name in (("second_tmpfs_run", "compare-second-run.json"), ("ext4_loop_run", "compare-ext4-loop.json")):
            stored = json.loads((REVIEW / name).read_text())
            for field in ("recorded_cells", "executed_in_both", "not_run_in_both", "not_run_vs_measured",
                          "verdict_difference_count", "same_coverage"):
                self.assertEqual(record[key][field], stored[field], (key, field))
            self.assertEqual((stored["executed_in_both"], stored["not_run_in_both"], stored["not_run_vs_measured"],
                              stored["verdict_difference_count"], stored["same_coverage"]), (261, 12, 0, 0, True))
            self.assertEqual(stored["coverage"]["a"], self.summary["coverage"])
        self.assertEqual({item["fstype"] for item in record["ext4_loop_run"]["filesystems"]}, {"ext4"})
        self.assertTrue(record["ext4_loop_run"]["filesystems_distinct"])
        self.assertFalse(record["docker_mode"]["executed"])


class LiveTests(unittest.TestCase):
    def leftovers(self):
        return sorted(name for name in os.listdir(tempfile.gettempdir()) if name.startswith("cse227-probe"))

    @unittest.skipUnless(os.geteuid() == 0, "probe 03 needs root to mount filesystems and drop UIDs")
    def test_local_run_shows_one_cell_of_every_layout_and_cleans_up(self):
        stray = self.leftovers()
        sysctls = [Path("/proc/sys/fs", name).read_text() for name in
                   ("protected_regular", "protected_hardlinks", "protected_symlinks")]
        with tempfile.TemporaryDirectory() as directory:
            evidence, summary = Path(directory) / "e.json", Path(directory) / "s.json"
            done = subprocess.run([sys.executable, str(TOOL), "--mode", "local", "--evidence", str(evidence),
                                   "--summary", str(summary)], capture_output=True, text=True, timeout=300,
                                  cwd=str(ROOT))
            if done.returncode != 0 and "private mount namespace" in done.stdout + done.stderr:
                self.skipTest("cannot mount here")
            self.assertEqual(done.returncode, 0, done.stdout[-700:] + done.stderr[-700:])
            measured = json.loads(evidence.read_text())
            o = measured["observations"]
            self.assertTrue(o["all_evaluated_observations_match_expectation"])
            rows = {(r["case"], r["operation"]): r["verdict"] for r in o["rows"]}
            fd = {(r["case"], r["control"]): r["verdict"] for r in o["descriptor_controls"]}
            sup = {(r["case"], r["operation"]): r["verdict"] for r in o["suppression_controls"]}
            self.assertEqual(rows["I1_readonly", "replace"], fixture.BOUNDARY)
            self.assertEqual(rows["I2_no_access", "rewrite"], v2.D)
            self.assertEqual(rows["I3_readonly_append_only", "new_session_window:append_marker"], v2.D)
            self.assertEqual(fd["I4_no_access_append_only", "fd_append_ftruncate"], v2.D)
            self.assertEqual(sup["I1_readonly", "exhaust_inodes_then_recorder_new_session"], v2.NOSUP)
            self.assertEqual(sup["N1_same_filesystem", "fill_workspace_filesystem_then_recorder_append"], v2.S)
            self.assertEqual(sup["N1_same_filesystem", "exhaust_inodes_then_recorder_new_session"], v2.S)
            self.assertEqual(rows["N2_agent_owned_parent", "rename_parent_dir"], v2.E)
            self.assertEqual(rows["N2_agent_owned_parent", "symlink_swap_dir"], v2.E)
            self.assertEqual(fd["N3_inherited_descriptor_no_flag", "fd_append_ftruncate"], v2.E)
            controls = runner.negative_controls(o)
            self.assertTrue(all(entry["failure_detected"] for entry in controls.values()))
            for name in INTEGRATED:
                self.assertEqual(runner.assess(o)[name]["all_three"], base.HOLDS)
            compared = base.compare(json.loads(EVIDENCE.read_text()), measured) if EVIDENCE.is_file() else None
            if compared:
                self.assertEqual((compared["verdict_difference_count"], compared["same_coverage"]), (0, True))
            setup = o["environment"]["setup_process"]
            self.assertNotIn("SYS_ADMIN", setup["effective_capability_names"])
        self.assertEqual(self.leftovers(), stray)
        self.assertNotIn("cse227-probe", Path("/proc/self/mountinfo").read_text())
        self.assertEqual([Path("/proc/sys/fs", name).read_text() for name in
                          ("protected_regular", "protected_hardlinks", "protected_symlinks")], sysctls)

    @unittest.skipUnless(os.geteuid() == 0, "probe 03 needs root to mount filesystems and drop UIDs")
    def test_sigterm_during_a_local_run_leaves_no_mount_directory_or_output(self):
        stray = self.leftovers()
        with tempfile.TemporaryDirectory() as directory:
            evidence = Path(directory) / "e.json"
            process = subprocess.Popen([sys.executable, str(TOOL), "--mode", "local", "--evidence", str(evidence),
                                        "--summary", str(Path(directory) / "s.json")], stdout=subprocess.PIPE,
                                       stderr=subprocess.PIPE, text=True, cwd=str(ROOT))
            started = False
            for _ in range(200):
                if process.poll() is not None or self.leftovers() != stray:
                    started = self.leftovers() != stray
                    break
                time.sleep(0.05)
            if not started:
                process.kill()
                process.communicate()
                self.skipTest("the run never created its mount directory")
            time.sleep(1.0)
            process.send_signal(signal.SIGTERM)
            out, err = process.communicate(timeout=120)
            self.assertNotEqual(process.returncode, 0)
            self.assertIn("received signal", out + err)
            self.assertFalse(evidence.exists())
        time.sleep(0.5)
        self.assertEqual(self.leftovers(), stray)
        self.assertNotIn("cse227-probe", Path("/proc/self/mountinfo").read_text())


if __name__ == "__main__":
    unittest.main()
