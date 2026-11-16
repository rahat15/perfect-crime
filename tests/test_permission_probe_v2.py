"""Tests for permission probe 02: pure logic, mocked docker flow, committed-evidence consistency,
first-principles assertions, and root-only live smoke / ACL / SIGTERM checks."""

import copy
import errno
import json
import os
from pathlib import Path
import re
import signal
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

from research.tools import permission_probe_v2_fixture as fixture
from research.tools import run_permission_probe_v2 as runner

ROOT = Path(__file__).resolve().parents[1]
EVIDENCE = ROOT / runner.EVIDENCE
SUMMARY = ROOT / runner.SUMMARY
README = EVIDENCE.with_name("README.md")
DESIGN = ROOT / "research/analysis/permission-probe-02-design.md"
AGENT = (fixture.AGENT_UID, fixture.AGENT_GID, [])
T = fixture.TARGET_NAME


def child(uid=1000, groups=(), succeeded=True, error=None, descriptors=0, **status):
    values = {"CapInh": "0" * 16, "CapPrm": "0" * 16, "CapEff": "0" * 16, "CapBnd": "000001ffffffffff",
              "CapAmb": "0" * 16, "NoNewPrivs": "1"}
    values.update(status)
    return {"identity": {"uid": [uid] * 3, "gid": [uid] * 3, "groups": list(groups), "status": values,
                         "inherited_probe_fds": [{"fd": 4 + index, "target": "/probe/x"}
                                                 for index in range(descriptors)]},
            "operation_succeeded": succeeded, "errno": error, "error": None, "failed_step": "step",
            "fixture_base_reachable": True}


def target(data=fixture.BASE, inode=10, uid=1001, gid=1001, links=1, kind="file", flags=(False, False)):
    return {"exists": True, "type": kind, "uid": uid, "gid": gid, "mode": "0o644", "inode": inode,
            "link_count": links, "size": len(data), "sha256": fixture.digest(data),
            "inode_flags": {"raw": 0, "append_only": flags[0], "immutable": flags[1]}, "acl_access_hex": None}


def state(snapshot=None, names=("home/records/" + T,), entries=None, resolved=None, records=None):
    snapshot = target() if snapshot is None else snapshot
    return {"target": snapshot,
            "target_resolved": resolved or {"resolves": snapshot.get("exists", False),
                                            "sha256": snapshot.get("sha256")},
            "records_dir": records or {"exists": True, "type": "directory", "inode": 5},
            "records_listing": {"is_directory": True,
                                "entries": entries or {T: {"type": "file", "inode": 10, "uid": 1001, "size": 38}}},
            "parent_listing": {"is_directory": True, "entries": {"records": {"type": "directory", "inode": 5}}},
            "workspace_listing": {"is_directory": True, "entries": {}},
            "original_inode_paths": list(names)}


class ExpectationMatrixTests(unittest.TestCase):
    def test_every_case_and_operation_has_one_expectation(self):
        self.assertEqual(set(fixture.EXPECTED_CODES), set(fixture.CASES))
        for case, codes in fixture.EXPECTED_CODES.items():
            self.assertEqual(list(codes), list(fixture.OPERATIONS), case)
            self.assertLessEqual(set(codes.values()), set("EDNH"), case)
            for operation in fixture.OPERATIONS:
                for sysctl in (0, 1):
                    self.assertIn(fixture.expected_verdict(case, operation, sysctl), (fixture.E, fixture.D, fixture.N))

    def test_not_applicable_cells_match_the_coded_N(self):
        for case in fixture.CASES:
            for operation in fixture.OPERATIONS:
                with self.subTest(case=case, operation=operation):
                    self.assertEqual(fixture.not_applicable_reason(case, operation) is not None,
                                     fixture.EXPECTED_CODES[case][operation] == "N")

    def test_hardlink_expectation_follows_the_sysctl(self):
        self.assertEqual(fixture.expected_verdict("recorder_owned_agent_readonly", "hardlink_create", 1), fixture.D)
        self.assertEqual(fixture.expected_verdict("recorder_owned_agent_readonly", "hardlink_create", 0), fixture.E)
        self.assertEqual(fixture.expected_verdict("recorder_owned_no_agent_access", "hardlink_create", 0), fixture.D)

    def test_design_table_equals_the_coded_ordinary_expectations(self):
        text = DESIGN.read_text()
        section = text[text.index("## 5."):text.index("### Justification")]
        seen = {}
        for line in section.splitlines():
            cells = [cell.strip().replace("\\|", "|") for cell in re.split(r"(?<!\\)\|", line)[1:-1]]
            if cells and cells[0] in fixture.CASES:
                seen[cells[0]] = [{"E": "E", "D": "D", "n/a": "N", "D|E": "H"}[cell] for cell in cells[1:]]
        self.assertEqual(seen, {case: list(codes.values()) for case, codes in fixture.EXPECTED_CODES.items()})

    def test_suppression_expectations_complete_and_partitioned(self):
        self.assertEqual(set(fixture.EXPECTED_SUPPRESSION_CODES), set(fixture.CASES))
        for case in fixture.CASES:
            self.assertEqual(list(fixture.EXPECTED_SUPPRESSION_CODES[case]), list(fixture.SUPPRESSION_OPERATIONS))
            for operation in fixture.SUPPRESSION_OPERATIONS:
                expected = fixture.expected_suppression(case, operation)
                self.assertIn(expected["verdict"], (fixture.S, fixture.NOSUP, fixture.N))
                self.assertEqual(fixture.suppression_not_applicable_reason(case, operation) is not None,
                                 expected["verdict"] == fixture.N)
        # the shared-filesystem fill is expected to suppress in every non-immutable layout
        for case in fixture.CASES:
            code = fixture.EXPECTED_SUPPRESSION_CODES[case]["fill_filesystem_then_recorder_append"]
            self.assertEqual(code, "N" if "immutable" in fixture.CASES[case]["file_flags"] else "S", case)

    def test_precreate_details_expectation_depends_on_the_account(self):
        shared = fixture.expected_suppression("agent_owned_writable", "precreate_next_session_name")
        self.assertEqual(shared["recorder_open_without_excl"], "appended_to_agent_created_file")
        separate = fixture.expected_suppression("recorder_owned_agent_readonly", "precreate_next_session_name")
        self.assertEqual(separate["verdict"], fixture.NOSUP)
        self.assertEqual(separate["agent_rewrite_resulting_file"], "denied")

    def test_tampering_and_side_effect_operations_partition(self):
        self.assertEqual(set(fixture.SIDE_EFFECT_OPERATIONS), {"hardlink_create", "create_sibling"})
        self.assertEqual(set(fixture.TAMPERING_OPERATIONS) | set(fixture.SIDE_EFFECT_OPERATIONS),
                         set(fixture.OPERATIONS))

    def test_descriptor_expectations_cover_every_cell_including_dirfd_listdir(self):
        self.assertIn("dirfd_listdir", fixture.DESCRIPTOR_CONTROLS)
        for case in fixture.CASES:
            for control in fixture.DESCRIPTOR_CONTROLS:
                verdict, outcome = fixture.expected_descriptor(case, control, 1)
                self.assertIn(verdict, (fixture.E, fixture.D, fixture.N, fixture.X))
                self.assertEqual(outcome is None, verdict == fixture.N)
        self.assertEqual(fixture.expected_descriptor("recorder_owned_no_agent_access", "dirfd_listdir", 1),
                         (fixture.E, "names_listed_via_dirfd_only"))
        self.assertEqual(fixture.expected_descriptor("agent_owned_writable", "dirfd_listdir", 1),
                         (fixture.E, "names_listed_via_path_and_dirfd"))
        self.assertEqual(fixture.expected_descriptor("append_only_recorder_owned", "fd_append_ftruncate", 1),
                         (fixture.D, "no_change"))
        self.assertEqual(fixture.expected_descriptor("immutable_recorder_owned", "fd_append_write", 1)[0], fixture.N)

    def test_recorder_is_a_separate_unprivileged_account_unless_shared(self):
        for case, layout in fixture.CASES.items():
            uid, gid, groups = fixture.identity_for(case, "recorder")
            self.assertNotEqual(uid, 0)
            if layout["recorder_account"] == "shared_with_agent":
                self.assertEqual((uid, gid), (fixture.AGENT_UID, fixture.AGENT_GID))
            else:
                self.assertEqual((uid, gid, groups), (fixture.RECORDER_UID, fixture.RECORDER_GID, []))
        self.assertEqual({case for case, layout in fixture.CASES.items()
                          if layout["recorder_account"] == "shared_with_agent"},
                         {"agent_owned_writable", "append_only_same_account",
                          "append_only_file_and_dir_same_account"})

    def test_legit_discriminating_classification(self):
        for control in ("agent_workspace_edit_and_test", "recorder_read_back", "agent_read_transcript"):
            self.assertFalse(fixture.legit_discriminating("recorder_owned_agent_readonly", control)[0])
        for control in ("recorder_append", "recorder_new_transcript"):
            self.assertTrue(fixture.legit_discriminating("recorder_owned_agent_readonly", control)[0])
            self.assertFalse(fixture.legit_discriminating("agent_owned_writable", control)[0])


class IdentityTests(unittest.TestCase):
    def test_valid_children(self):
        self.assertTrue(fixture.identity_valid(child(), AGENT))
        self.assertTrue(fixture.identity_valid(child(1001), (1001, 1001, [])))
        self.assertTrue(fixture.identity_valid(child(groups=[2000]), (1000, 1000, [2000])))
        self.assertTrue(fixture.identity_valid(child(descriptors=1), AGENT, descriptors_expected=1))

    def test_privileged_or_wrong_children_rejected(self):
        for name, mutate in {"effective cap": lambda r: r["identity"]["status"].__setitem__("CapEff", "2"),
                             "permitted cap": lambda r: r["identity"]["status"].__setitem__("CapPrm", "1"),
                             "ambient cap": lambda r: r["identity"]["status"].__setitem__("CapAmb", "1"),
                             "nnp off": lambda r: r["identity"]["status"].__setitem__("NoNewPrivs", "0"),
                             "wrong uid": lambda r: r["identity"].__setitem__("uid", [1001, 1001, 1001]),
                             "root": lambda r: r["identity"].__setitem__("uid", [0, 0, 0]),
                             "stray fd": lambda r: r["identity"].__setitem__("inherited_probe_fds",
                                                                             [{"fd": 4, "target": "/x"}])}.items():
            result = child()
            mutate(result)
            with self.subTest(name):
                self.assertFalse(fixture.identity_valid(result, AGENT))
        self.assertFalse(fixture.identity_valid(child(0), (0, 0, [])), "UID 0 is never acceptable")
        self.assertFalse(fixture.identity_valid(child(), AGENT, descriptors_expected=1))
        self.assertFalse(fixture.helper_valid({"uid": [1001] * 3, "gid": [1001] * 3, "groups": [],
                                               "status": {"CapEff": "1", "CapPrm": "0", "CapAmb": "0",
                                                          "NoNewPrivs": "1"}}, (1001, 1001, [])))


class ClassificationTests(unittest.TestCase):
    def test_verdicts(self):
        denied = child(succeeded=False, error=errno.EACCES)
        self.assertEqual(fixture.classify(True, child(), True, False)[0], fixture.E)
        self.assertEqual(fixture.classify(True, denied, False, True)[0], fixture.D)
        self.assertEqual(fixture.classify(True, child(succeeded=False, error=errno.EPERM), False, True)[0], fixture.D)
        self.assertEqual(fixture.classify(True, child(), False, False)[0], fixture.X)
        for result, effect, unchanged in ((denied, False, False), (denied, True, False), (child(), False, True),
                                          (child(succeeded=False, error=errno.ENOSPC), False, True)):
            self.assertEqual(fixture.classify(True, result, effect, unchanged)[0], fixture.UNEXPECTED)
        self.assertEqual(fixture.classify(False, denied, False, True)[0], fixture.UNEXPECTED)

    def test_unreachable_fixture_base_is_not_a_denial(self):
        result = child(succeeded=False, error=errno.EACCES)
        result["fixture_base_reachable"] = False
        self.assertEqual(fixture.classify(True, result, False, True)[0], fixture.UNEXPECTED)

    def test_denial_fields_record_step_and_class(self):
        self.assertEqual(fixture.denial_fields(fixture.D, child(succeeded=False, error=errno.EACCES))["denial_class"],
                         fixture.DENIAL_CLASSES["EACCES"])
        self.assertEqual(fixture.denial_fields(fixture.D, child(succeeded=False, error=errno.EPERM))["denial_errno"],
                         "EPERM")
        self.assertIsNone(fixture.denial_fields(fixture.E, child())["denial_class"])

    def test_content_name_and_side_effects(self):
        before = state()
        for operation, data in (("rewrite", fixture.EDIT), ("truncate", b""),
                                ("overwrite_in_place", fixture.PATCHED),
                                ("append_marker", fixture.BASE + fixture.APPEND)):
            self.assertTrue(fixture.effect_observed(operation, before, state(target(data))))
            self.assertFalse(fixture.effect_observed(operation, before, state(target(data, inode=11))))
        gone = {"exists": False, "errno": errno.ENOENT}
        self.assertTrue(fixture.effect_observed("delete", before, state(gone, names=())))
        self.assertFalse(fixture.effect_observed("delete", before, state(gone, names=("workspace/moved.jsonl",))))
        self.assertTrue(fixture.effect_observed("rename_out_of_dir", before,
                                                state(gone, names=("workspace/moved.jsonl",))))
        self.assertTrue(fixture.effect_observed("replace", before,
                                                state(target(fixture.EDIT, inode=11, uid=1000), names=())))
        linked = state(target(links=2), names=("home/records/" + T, "workspace/hardlink.jsonl"))
        self.assertTrue(fixture.effect_observed("hardlink_create", before, linked))
        self.assertFalse(fixture.effect_observed("rewrite", before, linked))

    def test_descriptor_and_listdir_outcomes(self):
        before = state()
        self.assertEqual(fixture.descriptor_outcome(before, state(target(fixture.BASE + fixture.PATCH))),
                         "appended_only")
        self.assertEqual(fixture.descriptor_outcome(before, state(target(b""))), "truncated")
        self.assertEqual(fixture.descriptor_outcome(before, before), "no_change")
        listed = child()
        listed["dirfd_names"] = [T]
        listed["path_listdir"] = {"ok": True, "names": [T]}
        self.assertEqual(fixture.listdir_outcome(listed, "no_change"), "names_listed_via_path_and_dirfd")
        denied_path = child()
        denied_path["dirfd_names"] = [T]
        denied_path["path_listdir"] = {"ok": False, "errno": errno.EACCES}
        self.assertEqual(fixture.listdir_outcome(denied_path, "no_change"), "names_listed_via_dirfd_only")


class SnapshotAndFeatureTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)

    def test_snapshot_does_not_follow_a_symlink(self):
        real, link = self.root / "real.jsonl", self.root / "link.jsonl"
        real.write_bytes(fixture.ATTACKER)
        link.symlink_to(real)
        record = fixture.snapshot(link)
        self.assertEqual((record["type"], record["symlink_target"]), ("symlink", str(real)))
        self.assertNotIn("sha256", record)
        self.assertEqual(fixture.resolved_snapshot(link)["sha256"], fixture.digest(fixture.ATTACKER))

    def test_acl_blob_and_mode_with_mask(self):
        blob = fixture.acl_blob(7, 1000, 5)
        self.assertEqual(blob[:4], b"\x02\x00\x00\x00")
        self.assertEqual(len(blob), 4 + 5 * 8)
        self.assertEqual(fixture.expected_mode((1001, 1001, 0o700), (1000, 5)), 0o750)

    def test_required_features_and_root_choice(self):
        yes, no = {"supported": True}, {"supported": False, "error": "EOPNOTSUPP: Operation not supported"}
        tmpfs = {"path": "/probe", "filesystem": {"fstype": "tmpfs"},
                 "features": {"append_only_flag": no, "immutable_flag": no, "posix_acl": no}}
        ext4 = {"path": "/alt", "filesystem": {"fstype": "ext4"},
                "features": {"append_only_flag": yes, "immutable_flag": yes, "posix_acl": no}}
        self.assertIs(fixture.choose_root("recorder_owned_agent_readonly", [tmpfs, ext4])[0], tmpfs)
        self.assertIs(fixture.choose_root("immutable_recorder_owned", [tmpfs, ext4])[0], ext4)
        chosen, reason = fixture.choose_root("acl_agent_read_only", [tmpfs, ext4])
        self.assertIsNone(chosen)
        self.assertIn("posix_acl unavailable: EOPNOTSUPP", reason)

    def test_fill_root_problem_rejects_a_non_dedicated_or_large_root(self):
        self.assertIn("not a dedicated tmpfs", fixture.fill_root_problem(
            {"path": "/x", "filesystem": {"fstype": "ext4", "mount_point": "/"}}))


class DockerCommandTests(unittest.TestCase):
    def test_container_command_mirrors_probe_01_plus_two_documented_capabilities(self):
        command = runner.container_command("sha256:synthetic", "probe-name", "synthetic-id")
        added = {command[index + 1] for index, value in enumerate(command) if value == "--cap-add"}
        self.assertEqual(added, {"CHOWN", "DAC_OVERRIDE", "SETUID", "SETGID", "FOWNER", "LINUX_IMMUTABLE"})
        self.assertEqual(set(runner.EXTRA_CAPABILITIES), {"FOWNER", "LINUX_IMMUTABLE"})
        self.assertTrue(all(len(reason) > 20 for reason in runner.CAPABILITIES.values()))
        self.assertEqual(command[command.index("--cap-drop") + 1], "ALL")
        self.assertEqual(command[command.index("--network") + 1], "none")
        self.assertEqual(command[command.index("--security-opt") + 1], "no-new-privileges")
        for flag in ("--privileged", "--mount", "--volume", "-v", "SYS_ADMIN"):
            self.assertNotIn(flag, command)
        self.assertEqual(command[-4:], ["python3", "sha256:synthetic", "-I", "-"])

    @staticmethod
    def inspection():
        return {"network_mode": "none", "readonly_rootfs": True, "binds": None, "mounts": [],
                "user": "0:0", "entrypoint": ["python3"], "command": ["-I", "-"], "privileged": False,
                "tmpfs": {"/probe": "rw"}, "cap_drop": ["ALL"],
                "cap_add": ["CAP_CHOWN", "CAP_DAC_OVERRIDE", "CAP_SETUID", "CAP_SETGID", "CAP_FOWNER",
                            "CAP_LINUX_IMMUTABLE"], "security_options": ["no-new-privileges"]}

    def test_inspection_validation(self):
        runner.validate_inspection(self.inspection())
        for message, change in {"capabilities": lambda r: r["cap_add"].append("CAP_SYS_ADMIN"),
                                "capabilities ": lambda r: r["cap_add"].remove("CAP_FOWNER"),
                                "host bind": lambda r: r.update(mounts=[{"Type": "bind", "Source": "/home"}]),
                                "privileged": lambda r: r.update(privileged=True),
                                "no-new-privileges": lambda r: r.update(security_options=[])}.items():
            record = self.inspection()
            change(record)
            with self.subTest(message), self.assertRaisesRegex(ValueError, message.strip()):
                runner.validate_inspection(record)

    def test_cleanup_only_removes_own_container(self):
        with patch.object(runner, "command", return_value="other-container"):
            with self.assertRaisesRegex(ValueError, "Unexpected container"):
                runner.remove_own_container("expected", "id")
        with patch.object(runner, "command", side_effect=["expected", "", ""]) as call:
            runner.remove_own_container("expected", "id")
            self.assertEqual(call.call_args_list[1].args[0], ["docker", "rm", "--force", "expected"])

    def raw_inspection(self):
        record = self.inspection()
        return [{"Image": "sha256:img", "Mounts": [],
                 "Config": {"Image": "sha256:img", "User": "0:0", "Entrypoint": ["python3"], "Cmd": ["-I", "-"]},
                 "HostConfig": {"NetworkMode": "none", "ReadonlyRootfs": True, "CapAdd": record["cap_add"],
                                "CapDrop": ["ALL"], "Privileged": False, "SecurityOpt": ["no-new-privileges"],
                                "Tmpfs": {"/probe": "rw"}, "Binds": None}}]

    def test_docker_flow_feeds_fixture_on_stdin_and_removes_container(self):
        calls = []

        def fake(args, **kwargs):
            calls.append(args)
            if args[:2] == ["docker", "info"]:
                return "linux"
            if args[:3] == ["docker", "image", "inspect"]:
                return "sha256:img"
            if args[:2] == ["docker", "inspect"]:
                return json.dumps(self.raw_inspection())
            if args[:2] == ["docker", "ps"]:
                return "" if any(c[:2] == ["docker", "rm"] for c in calls) else \
                    next(c for c in calls if c[:2] == ["docker", "create"])[4]
            return ""

        completed = subprocess.CompletedProcess([], 0, stdout=b'{"protocol": "x"}', stderr=b"progress")
        with patch.object(runner, "command", side_effect=fake), \
                patch.object(runner.subprocess, "run", return_value=completed) as start:
            observations, run, settings, failure = runner.run_docker("sha256:img")
        self.assertIsNone(failure)
        self.assertEqual(observations, {"protocol": "x"})
        self.assertEqual(start.call_args.kwargs["input"], (ROOT / runner.FIXTURE).read_bytes())
        self.assertTrue(run["cleanup_verified"])
        self.assertIn(["docker", "rm", "--force", run["container_name"]], calls)

    def test_docker_flow_refuses_bad_settings_and_still_cleans_up(self):
        raw = self.raw_inspection()
        raw[0]["HostConfig"]["CapAdd"].append("CAP_SYS_ADMIN")

        def fake(args, **kwargs):
            if args[:2] == ["docker", "info"]:
                return "linux"
            if args[:3] == ["docker", "image", "inspect"]:
                return "sha256:img"
            if args[:2] == ["docker", "inspect"]:
                return json.dumps(raw)
            return ""

        with patch.object(runner, "command", side_effect=fake), patch.object(runner.subprocess, "run") as start:
            observations, run, _, failure = runner.run_docker("sha256:img")
        start.assert_not_called()
        self.assertIsNone(observations)
        self.assertIn("capabilities", failure)
        self.assertTrue(run["cleanup_verified"])

    def test_default_image_is_probe_01_baseline(self):
        self.assertTrue(runner.default_image().startswith("sha256:eddc3b19"))

    def test_fixture_command_includes_fill_roots(self):
        command = runner.fixture_command("/mnt/x", "/tmp/alt", "/tmp/fr", "/tmp/fw")
        self.assertEqual(command[-6:], ["--alt-root", "/tmp/alt", "--fill-records-root", "/tmp/fr",
                                        "--fill-workspace-root", "/tmp/fw"])
        self.assertEqual(runner.fixture_command("/mnt/x", None)[-2:], ["--root", "/mnt/x"])


def synthetic_evidence():
    layout = {"filesystem": "tmpfs", "recorder_account": "separate"}
    shared = {"filesystem": "tmpfs", "recorder_account": "shared_with_agent"}

    def row(case, operation, verdict, expected=None, matches=True):
        return {"case": case, "operation": operation, "verdict": verdict, "expected": expected or verdict,
                "matches_expectation": matches, "counts_as_tampering": operation != "create_sibling",
                "child": {"errno": None}, "not_run_reason": "x"}

    def legit(case, control, outcome, judged=True, discriminating=True, matches=True):
        item = {"case": case, "control": control, "judged": judged, "outcome": outcome,
                "layout_discriminating": discriminating, "matches_expectation": matches, "child": {"errno": None}}
        if judged:
            item.update(passed=outcome == "passed", expected_pass=True)
        else:
            item.update(observed="readable", expected_observation="readable")
        return item

    def descr(case, verdict, outcome):
        return {"case": case, "control": "fd_append_write", "verdict": verdict, "outcome": outcome,
                "expected": verdict, "expected_outcome": outcome, "matches_expectation": True, "child": {"errno": None}}

    def supp(case, operation, verdict, matches=True):
        return {"case": case, "operation": operation, "verdict": verdict, "expected": verdict,
                "matches_expectation": matches, "verdict_reason": "x", "not_run_reason": "x"}

    observations = {
        "protocol": fixture.PROTOCOL, "scope": "synthetic", "layouts": {"open": layout, "closed": shared},
        "operation_definitions": {"rewrite": {}, "delete": {}, "create_sibling": {}},
        "legit_control_definitions": {"recorder_append": {}, "agent_read_transcript": {}},
        "descriptor_control_definitions": {"fd_append_write": {}},
        "suppression_control_definitions": {"precreate_next_session_name": {},
                                            "fill_filesystem_then_recorder_append": {}},
        "rows": [row("open", "rewrite", fixture.E), row("open", "delete", fixture.E, fixture.D, False),
                 row("open", "create_sibling", fixture.N),
                 row("closed", "rewrite", fixture.D), row("closed", "delete", fixture.D),
                 row("closed", "create_sibling", fixture.E)],
        "legit_controls": [legit("open", "recorder_append", "permission_denied", matches=False),
                           legit("open", "agent_read_transcript", "passed", judged=False, discriminating=False),
                           legit("closed", "recorder_append", "passed", discriminating=False),
                           legit("closed", "agent_read_transcript", "passed", judged=False, discriminating=False)],
        "descriptor_controls": [descr("open", fixture.E, "appended_marker"), descr("closed", fixture.X, "appended_only")],
        "suppression_controls": [supp("open", "precreate_next_session_name", fixture.NOSUP),
                                 supp("open", "fill_filesystem_then_recorder_append", fixture.NOSUP),
                                 supp("closed", "precreate_next_session_name", fixture.S),
                                 supp("closed", "fill_filesystem_then_recorder_append", fixture.S)],
        "all_evaluated_observations_match_expectation": False,
        "environment": {"kernel_release": "k", "python_version": "p",
                        "sysctl_fs": {"protected_hardlinks": 1, "protected_regular": 0},
                        "setup_process": {"effective_capability_names": ["CHOWN"]}, "probe_roots": []}}
    run = {"mode": "local", "image_id": None, "fixture_sha256": "f", "runner_sha256": "r",
           "started_at": "s", "finished_at": "e", "cleanup_verified": True}
    return {"run": run, "environment_settings": {}, "observations": observations}


class SummaryTests(unittest.TestCase):
    def test_counts_mismatches_discriminating_and_protecting_lists(self):
        summary = runner.summarize(synthetic_evidence())
        self.assertEqual(summary["ordinary_verdict_counts"], {fixture.E: 3, fixture.N: 1, fixture.D: 2})
        self.assertEqual(summary["layout_discriminating_proxy_count"], 1)
        self.assertEqual(summary["layout_discriminating_proxy_outcome_counts"], {"permission_denied": 1})
        self.assertEqual(summary["harness_sanity_check_count"], 1)
        self.assertEqual(summary["suppression_verdict_counts"], {fixture.NOSUP: 2, fixture.S: 2})
        self.assertEqual(summary["expectation_mismatch_count"], 2)
        self.assertEqual({(m["kind"], m["case"], m["name"]) for m in summary["expectation_mismatches"]},
                         {("operation", "open", "delete"), ("legit_control", "open", "recorder_append")})
        self.assertEqual(summary["layouts_denying_all_measured_tampering_and_passing_all_judged_proxies"], ["closed"])
        self.assertEqual(summary["layouts_also_resisting_both_suppression_operations"], [])

    def test_a_layout_suppressed_is_not_in_the_strict_list(self):
        evidence = synthetic_evidence()
        # make "open" deny tampering + pass proxies, but it is suppressed -> excluded from strict list
        self.assertNotIn("open", runner.protecting_and_suppression_resistant_layouts(evidence["observations"]))

    def test_tables_mark_outcomes_and_strict_list(self):
        tables = runner.render_tables(synthetic_evidence())
        self.assertIn("| `open` | E | E! | n/a |", tables["matrix"])
        self.assertIn("| `closed` | S | S |", tables["suppression"])
        self.assertIn("recorder_append", tables["legit_discriminating"])
        self.assertEqual(tables["protecting_strict"], "- (none)")
        self.assertIn("Suppression-of-future-records controls: 4.", tables["totals"])

    def test_compare_splits_environment_notrun_and_verdicts(self):
        first, second = synthetic_evidence(), synthetic_evidence()
        second["observations"]["rows"][0]["before"] = {"target": {"inode": 999}}
        result = runner.compare(first, second)
        self.assertTrue(result["identical_verdicts"])
        self.assertTrue(result["environment_identical"])
        second["observations"]["rows"][3]["verdict"] = fixture.E
        second["observations"]["suppression_controls"][0]["verdict"] = fixture.N
        second["observations"]["environment"]["kernel_release"] = "other"
        result = runner.compare(first, second)
        self.assertIn("op/closed/rewrite", result["verdict_differences"])
        self.assertIn("suppress/open/precreate_next_session_name", result["not_run_vs_measured_differences"])
        self.assertFalse(result["environment"]["kernel_release"]["same"])
        self.assertFalse(result["identical_verdicts"])


@unittest.skipUnless(EVIDENCE.is_file() and SUMMARY.is_file() and README.is_file(),
                     "probe 02 evidence has not been recorded in this checkout")
class CommittedEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.evidence = json.loads(EVIDENCE.read_text())
        cls.observations = cls.evidence["observations"]
        cls.summary = json.loads(SUMMARY.read_text())
        cls.hardlinks = cls.observations["environment"]["sysctl_fs"]["protected_hardlinks"]
        cls.rows = {(r["case"], r["operation"]): r for r in cls.observations["rows"]}
        cls.descr = {(r["case"], r["control"]): r for r in cls.observations["descriptor_controls"]}
        cls.supp = {(r["case"], r["operation"]): r for r in cls.observations["suppression_controls"]}

    def test_summary_file_derives_from_evidence(self):
        expected = runner.summarize(self.evidence)
        expected["evidence_sha256"] = runner.sha(EVIDENCE)
        self.assertEqual(self.summary, json.loads(json.dumps(expected)))

    def test_readme_tables_and_totals_derive_from_evidence(self):
        text = README.read_text()
        for name, table in runner.render_tables(self.evidence).items():
            with self.subTest(name):
                self.assertIn("<!-- BEGIN %s -->\n%s\n<!-- END %s -->" % (name, table, name), text)
        self.assertIn(runner.sha(EVIDENCE), text)
        self.assertIn(runner.LEGEND, text)

    def test_evidence_produced_by_the_checked_in_fixture_and_runner(self):
        run = self.evidence["run"]
        self.assertEqual(run["fixture_sha256"], runner.sha(ROOT / runner.FIXTURE))
        self.assertEqual(run["runner_sha256"], runner.sha(Path(runner.__file__)))
        self.assertEqual((run["status"], run["cleanup_verified"], run["model_calls"]), ("finished", True, 0))

    def test_every_cell_present_once_with_coded_expectation(self):
        self.assertEqual(set(self.rows), {(c, o) for c in fixture.CASES for o in fixture.OPERATIONS})
        for (case, operation), row in self.rows.items():
            with self.subTest(case=case, operation=operation):
                self.assertEqual(row["expected"], fixture.expected_verdict(case, operation, self.hardlinks))
                if row["verdict"] != fixture.N:
                    self.assertEqual(row["matches_expectation"], row["verdict"] == row["expected"])
        self.assertEqual(set(self.supp), {(c, o) for c in fixture.CASES for o in fixture.SUPPRESSION_OPERATIONS})
        self.assertEqual({(r["case"], r["control"]) for r in self.observations["legit_controls"]},
                         {(c, o) for c in fixture.CASES for o in fixture.LEGIT_CONTROLS})
        self.assertEqual(set(self.descr), {(c, o) for c in fixture.CASES for o in fixture.DESCRIPTOR_CONTROLS})

    def test_recorded_verdicts_recompute_from_snapshots(self):
        for row in self.observations["rows"]:
            if row["verdict"] == fixture.N:
                continue
            with self.subTest(case=row["case"], operation=row["operation"]):
                identity = fixture.identity_for(row["case"], "agent")
                effect = bool(fixture.effect_observed(row["operation"], row["before"], row["after"]))
                unchanged = fixture.protected_state_unchanged(row["before"], row["after"])
                verdict = fixture.classify(fixture.identity_valid(row["child"], identity), row["child"],
                                           effect, unchanged)[0]
                self.assertEqual(verdict, row["verdict"])
                self.assertEqual(row["ancestors"][0]["path"], "/")

    def test_ancestors_present_on_legit_and_descriptor_rows(self):
        for row in self.observations["legit_controls"] + self.observations["descriptor_controls"]:
            if row.get("outcome") == fixture.N or (row["verdict"] == fixture.N if "verdict" in row else False):
                if "ancestors" not in row:
                    continue
            self.assertEqual(row["ancestors"][0]["path"], "/", row.get("control"))

    def test_every_acting_child_was_the_intended_identity(self):
        for row in self.observations["legit_controls"]:
            if row["outcome"] == fixture.N:
                continue
            role = fixture.LEGIT_CONTROLS[row["control"]][0]
            self.assertTrue(fixture.identity_valid(row["child"], fixture.identity_for(row["case"], role)))
        separate = [r for r in self.observations["legit_controls"] if r["outcome"] != fixture.N
                    and r["acting_role"] == "recorder" and fixture.CASES[r["case"]]["recorder_account"] == "separate"]
        self.assertTrue(all(r["child"]["identity"]["uid"] == [fixture.RECORDER_UID] * 3 for r in separate))
        for row in self.observations["suppression_controls"]:
            for stage in row.get("stages", []):
                self.assertTrue(stage["identity_valid"], (row["case"], row["operation"], stage["stage"]))

    # ----- first-principles assertions (written here, not via the fixture's own classify) -----

    def unchanged_file(self, row, uid=fixture.RECORDER_UID):
        before, after = row["before"]["target"], row["after"]["target"]
        self.assertEqual(before["sha256"], fixture.digest(fixture.BASE))
        self.assertEqual(after["sha256"], before["sha256"])
        self.assertEqual(after["inode"], before["inode"])
        self.assertEqual((after["uid"], after["type"]), (uid, "file"))

    def test_sticky_directory_denies_name_changes_with_eperm(self):
        for operation in ("delete", "rename_within_dir", "replace"):
            row = self.rows["sticky_1777_dir_recorder_file", operation]
            self.assertEqual(row["verdict"], fixture.D)
            self.assertEqual(row["child"]["errno"], errno.EPERM)
            self.assertEqual(row["denial_class"], fixture.DENIAL_CLASSES["EPERM"])
            self.unchanged_file(row)

    def test_agent_owned_parent_allows_directory_rename_and_symlink_swap(self):
        rename = self.rows["recorder_dir_in_agent_owned_parent", "rename_parent_dir"]
        self.assertEqual(rename["verdict"], fixture.E)
        self.assertEqual(rename["after"]["original_inode_paths"], ["home/records-moved/" + T])
        swap = self.rows["recorder_dir_in_agent_owned_parent", "symlink_swap_dir"]
        self.assertEqual(swap["verdict"], fixture.E)
        self.assertEqual(swap["after"]["records_dir"]["type"], "symlink")
        self.assertEqual(swap["after"]["target_resolved"]["sha256"], fixture.digest(fixture.ATTACKER))
        self.assertEqual(swap["after"]["original_inode_paths"], ["home/records-moved/" + T])

    def test_append_only_same_account_allows_append_but_denies_overwrite_delete_rename(self):
        base = "append_only_same_account"
        appended = self.rows[base, "append_marker"]
        self.assertEqual(appended["verdict"], fixture.E)
        self.assertEqual(appended["after"]["target"]["sha256"], fixture.digest(fixture.BASE + fixture.APPEND))
        self.assertTrue(appended["before"]["target"]["inode_flags"]["append_only"])
        for operation in ("truncate", "delete", "rename_within_dir", "overwrite_in_place"):
            row = self.rows[base, operation]
            self.assertEqual(row["verdict"], fixture.D, operation)
            self.assertEqual(row["child"]["errno"], errno.EPERM, operation)

    def test_acl_layouts_enforce_the_named_user_entry(self):
        read_only = self.rows["acl_agent_read_only", "rewrite"]
        self.assertEqual(read_only["verdict"], fixture.D)
        self.assertEqual(read_only["child"]["errno"], errno.EACCES)
        write_dir = self.rows["acl_agent_dir_write_file_read", "delete"]
        self.assertEqual(write_dir["verdict"], fixture.E)
        self.assertEqual(write_dir["after"]["target"]["exists"], False)
        self.assertEqual(self.rows["acl_agent_dir_write_file_read", "rewrite"]["verdict"], fixture.D)

    def test_inherited_append_descriptor_forges_and_truncates_without_the_flag(self):
        append = self.descr["recorder_owned_no_agent_access", "fd_append_write"]
        self.assertEqual((append["verdict"], append["outcome"]), (fixture.E, "appended_marker"))
        self.assertEqual(append["after"]["target"]["sha256"], fixture.digest(fixture.BASE + fixture.APPEND))
        pwrite = self.descr["recorder_owned_no_agent_access", "fd_append_pwrite_overwrite"]
        self.assertEqual((pwrite["verdict"], pwrite["outcome"]), (fixture.X, "appended_only"))
        truncate = self.descr["recorder_owned_no_agent_access", "fd_append_ftruncate"]
        self.assertEqual((truncate["verdict"], truncate["outcome"]), (fixture.E, "truncated"))
        self.assertEqual(truncate["after"]["target"]["size"], 0)
        cleared = self.descr["recorder_owned_no_agent_access", "fd_append_clear_flag_then_pwrite"]
        self.assertEqual((cleared["verdict"], cleared["outcome"]), (fixture.E, "earlier_bytes_modified"))

    def test_append_only_inode_blocks_both_descriptor_overwrite_routes(self):
        for control in ("fd_append_ftruncate", "fd_append_clear_flag_then_pwrite"):
            row = self.descr["append_only_recorder_owned", control]
            self.assertEqual(row["verdict"], fixture.D, control)
            self.assertEqual(row["child"]["errno"], errno.EPERM, control)
            self.assertEqual(row["after"]["target"]["sha256"], fixture.digest(fixture.BASE))
        self.assertEqual(self.descr["append_only_recorder_owned", "fd_append_write"]["outcome"], "appended_marker")

    def test_inherited_dirfd_leaks_listing_even_without_path_access(self):
        row = self.descr["recorder_owned_no_agent_access", "dirfd_listdir"]
        self.assertEqual((row["verdict"], row["outcome"]), (fixture.E, "names_listed_via_dirfd_only"))
        self.assertIn(T, row["child"]["dirfd_names"])
        self.assertFalse(row["child"]["path_listdir"]["ok"])
        self.assertEqual(self.descr["recorder_owned_no_agent_access", "dirfd_unlinkat"]["verdict"], fixture.D)

    def test_precreate_suppression_in_sticky_and_resistance_when_dir_is_recorder_owned(self):
        sticky = self.supp["sticky_1777_dir_recorder_file", "precreate_next_session_name"]
        self.assertEqual(sticky["verdict"], fixture.S)
        self.assertEqual(sticky["agent_precreate"], "created")
        self.assertEqual(sticky["recorder_exclusive_create"], "EEXIST")
        self.assertEqual(sticky["agent_rewrite_resulting_file"], "effect")
        resisted = self.supp["recorder_owned_agent_readonly", "precreate_next_session_name"]
        self.assertEqual(resisted["verdict"], fixture.NOSUP)
        self.assertEqual(resisted["agent_precreate"], "denied")

    def test_disk_fill_suppresses_every_shared_filesystem_layout(self):
        for case in fixture.CASES:
            if "immutable" in fixture.CASES[case]["file_flags"]:
                continue
            row = self.supp[case, "fill_filesystem_then_recorder_append"]
            self.assertEqual(row["verdict"], fixture.S, case)
            self.assertTrue(row["recorder_exhausted"])
            self.assertLess(row["recorder_complete_records"], fixture.APPEND_MANY_COUNT)
        self.assertEqual(self.summary["layouts_also_resisting_both_suppression_operations"], [])

    def test_readme_states_scope_and_what_was_not_executed(self):
        text = README.read_text()
        self.assertEqual(self.evidence["run"]["mode"], "local")
        for phrase in ("--mode local", "--mode docker", "not native Codex", "synthetic proxies",
                       "sha256:eddc3b19", "protected_hardlinks", "protected_regular", "empty"):
            self.assertIn(phrase, text)


class LiveSmokeTests(unittest.TestCase):
    @unittest.skipUnless(os.geteuid() == 0, "live probe needs root to mount tmpfs and drop UIDs")
    def test_local_mode_runs_matches_expectations_and_cleans_up(self):
        observations, run, settings, failure = runner.run_local()
        if failure and any(t in failure for t in ("mount", "unshare", "capset", "Operation not permitted")) \
                and observations is None:
            self.skipTest("this environment cannot mount a private tmpfs: " + failure[:160])
        self.assertIsNone(failure)
        self.assertTrue(run["cleanup_verified"])
        for path in (settings["probe_root"], settings["fill_records_root"], settings["fill_workspace_root"],
                     settings["alternate_root"]):
            if path:
                self.assertFalse(os.path.exists(path), path)
                self.assertNotIn(path, Path("/proc/self/mountinfo").read_text())
        self.assertTrue(observations["all_evaluated_observations_match_expectation"])
        cells = {(r["case"], r["operation"]): r for r in observations["rows"]}
        self.assertEqual(cells["sticky_1777_dir_recorder_file", "delete"]["verdict"], fixture.D)   # sticky
        self.assertEqual(cells["recorder_dir_in_agent_owned_parent", "symlink_swap_dir"]["verdict"],
                         fixture.E)                                                                 # parent-swap
        self.assertEqual(cells["append_only_same_account", "append_marker"]["verdict"], fixture.E)  # +a
        self.assertEqual(cells["acl_agent_read_only", "rewrite"]["verdict"], fixture.D)             # ACL
        descr = {(r["case"], r["control"]): r for r in observations["descriptor_controls"]}
        self.assertEqual(descr["recorder_owned_no_agent_access", "fd_append_write"]["verdict"],
                         fixture.E)                                                                 # inherited fd
        supp = {(r["case"], r["operation"]): r for r in observations["suppression_controls"]}
        self.assertEqual(supp["sticky_1777_dir_recorder_file", "precreate_next_session_name"]["verdict"],
                         fixture.S)                                                                 # precreate
        self.assertEqual(supp["agent_owned_writable", "fill_filesystem_then_recorder_append"]["verdict"],
                         fixture.S)                                                                 # fill

    @unittest.skipUnless(os.geteuid() == 0, "ACL enforcement check needs root to drop to several UIDs")
    def test_acl_is_actually_enforced_for_uid_1000_1001_1002(self):
        with tempfile.TemporaryDirectory(dir="/tmp") as directory:
            path = os.path.join(directory, "acl.jsonl")
            with open(path, "wb") as handle:
                handle.write(fixture.BASE)
            os.chmod(path, 0o600)
            try:
                os.setxattr(path, fixture.ACL_XATTR, fixture.acl_blob(6, fixture.AGENT_UID, 4))
            except OSError as error:
                self.skipTest("filesystem does not support the ACL xattr: " + str(error))
            os.chown(path, fixture.RECORDER_UID, fixture.RECORDER_GID)
            os.chmod(directory, 0o755)

            def can_read(uid):
                pid = os.fork()
                if pid == 0:
                    try:
                        os.setgroups([])
                        os.setresgid(uid, uid, uid)
                        os.setresuid(uid, uid, uid)
                        os.close(os.open(path, os.O_RDONLY))
                        os._exit(0)
                    except OSError:
                        os._exit(1)
                return os.waitpid(pid, 0)[1] == 0

            def can_write(uid):
                pid = os.fork()
                if pid == 0:
                    try:
                        os.setgroups([])
                        os.setresgid(uid, uid, uid)
                        os.setresuid(uid, uid, uid)
                        os.close(os.open(path, os.O_WRONLY))
                        os._exit(0)
                    except OSError:
                        os._exit(1)
                return os.waitpid(pid, 0)[1] == 0

            self.assertTrue(can_read(fixture.AGENT_UID), "ACL grants agent read")
            self.assertFalse(can_write(fixture.AGENT_UID), "ACL grants agent read, not write")
            self.assertTrue(can_write(fixture.RECORDER_UID), "owner can write")
            self.assertFalse(can_read(1002), "an unnamed uid has no access")

    @unittest.skipUnless(os.geteuid() == 0, "SIGTERM leak check needs root to run the local probe")
    def test_sigterm_to_a_running_local_probe_leaves_nothing(self):
        before = set(p for p in os.listdir(tempfile.gettempdir()) if p.startswith("cse227-probe-v2"))
        process = subprocess.Popen([sys.executable, "-I", str(ROOT / runner.FIXTURE.parent / "run_permission_probe_v2.py"),
                                    "--mode", "local", "--evidence", "/tmp/sigterm-e.json",
                                    "--summary", "/tmp/sigterm-s.json", "--overwrite"],
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, cwd=str(ROOT))
        time.sleep(3)
        process.send_signal(signal.SIGTERM)
        try:
            process.wait(timeout=60)
        except subprocess.TimeoutExpired:
            process.kill()
            self.fail("runner did not exit after SIGTERM")
        time.sleep(1)
        leftovers = set(p for p in os.listdir(tempfile.gettempdir()) if p.startswith("cse227-probe-v2")) - before
        mounts = [line for line in Path("/proc/self/mountinfo").read_text().splitlines() if "cse227-probe-v2" in line]
        for name in ("/tmp/sigterm-e.json", "/tmp/sigterm-s.json"):
            if os.path.exists(name):
                os.unlink(name)
        self.assertEqual(leftovers, set(), "SIGTERM left probe directories behind")
        self.assertEqual(mounts, [], "SIGTERM left probe mounts behind")


if __name__ == "__main__":
    unittest.main()
