import copy
import json
import os
from pathlib import Path
import tempfile
import unittest

from research.native import process_observer as observer
from research.native import run_observer_calibration as runner
from research.native.inspect_environment import HELP_COMMANDS


def credentials():
    return {"Uid": "1000 1000 1000 1000", "Gid": "1000 1000 1000 1000",
            "CapEff": "0000000000000000", "CapPrm": "0000000000000000",
            "CapAmb": "0000000000000000", "NoNewPrivs": "1"}


def controlled_evidence():
    fixture = {"uid": 1000, "parent_pid": 7, "parent_start_ticks": 123,
               "pid_namespace": "pid:[42]", "cases": []}
    events = [{"kind": "observer_started", "namespace_pid": "pid:[42]",
               "status": {"Uid": "0 0 0 0", "CapEff": "0000000000080004", "NoNewPrivs": "1"}}]
    for number, case in enumerate(("no_inheritance", "read_only", "inherited_writer")):
        path = "/workspace/" + case
        child = {"pid": 10 + number, "ppid": 7, "uid": 1000, "start_ticks": 200 + number,
                 "handle": None if number == 0 else 4}
        fixture["cases"].append({"case": case, "path": path, "parent_fd": 3,
                                 "child": child, "contents_match_control": True,
                                 "child_exit_code": 0})
        parent = {"pid": 7, "start_ticks": 123, "status": credentials(),
                  "fds": [{"fd": 3, "target": path, "access": "write_only", "append": True}],
                  "fd_errors": [], "fd_table_truncated": False}
        child_process = {"pid": child["pid"], "ppid": 7, "start_ticks": child["start_ticks"],
                         "status": credentials(), "fd_errors": [], "fd_table_truncated": False,
                         "fds": [] if number == 0 else [
                             {"fd": 4, "target": path,
                              "access": "read_only" if number == 1 else "write_only",
                              "append": number == 2}]}
        for _ in range(3):
            events.append({"kind": "process_sample", "processes": copy.deepcopy([parent, child_process]),
                           "process_table_truncated": False, "errors": []})
    events.append({"kind": "observer_finished", "reason": "controller_stop", "samples": 9})
    return fixture, events


class ObserverCalibrationTests(unittest.TestCase):
    def test_real_open_handles_have_distinct_access_modes(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "control.txt"
            path.write_text("control")
            read_fd = os.open(path, os.O_RDONLY)
            write_fd = os.open(path, os.O_WRONLY | os.O_APPEND)
            try:
                sample = observer.snapshot(os.getpid())
                table = {f["fd"]: f for f in sample["fds"]}
                self.assertEqual(table[read_fd]["access"], "read_only")
                self.assertFalse(table[read_fd]["append"])
                self.assertEqual(table[write_fd]["access"], "write_only")
                self.assertTrue(table[write_fd]["append"])
                self.assertEqual(table[write_fd]["target"], str(path))
            finally:
                os.close(read_fd)
                os.close(write_fd)

    def test_path_handle_is_not_misclassified_as_readable(self):
        self.assertEqual(observer.fd_mode(oct(os.O_PATH))["access"], "path_only")

    def test_stat_parser_tolerates_spaces_and_parentheses(self):
        rest = ["S", "37"] + ["0"] * 17 + ["987"]
        self.assertEqual(observer.stat_fields("12 (a name) (x)) " + " ".join(rest)),
                         {"ppid": 37, "start_ticks": 987})

    def test_status_parser_does_not_capture_arbitrary_fields(self):
        result = observer.status_fields("Uid:\t1000 1000 1000 1000\nArbitrary:\tprivate\n")
        self.assertEqual(set(result), {"Uid"})

    def test_controls_pass_only_with_complete_matching_evidence(self):
        fixture, events = controlled_evidence()
        self.assertTrue(runner.grade_observer(fixture, events)["passed"])

    def test_reused_pid_cannot_supply_control_evidence(self):
        fixture, events = controlled_evidence()
        fixture["cases"][2]["child"]["start_ticks"] += 1000
        self.assertFalse(runner.grade_observer(fixture, events)["passed"])

    def test_failed_child_and_changed_contents_are_retained_as_failure(self):
        for field, value in (("child_exit_code", 1), ("contents_match_control", False)):
            with self.subTest(field=field):
                fixture, events = controlled_evidence()
                fixture["cases"][1][field] = value
                self.assertFalse(runner.grade_observer(fixture, events)["passed"])

    def test_missing_finish_or_wrong_namespace_cannot_pass(self):
        fixture, events = controlled_evidence()
        self.assertFalse(runner.grade_observer(fixture, events[:-1])["passed"])
        events[0]["namespace_pid"] = "pid:[other]"
        self.assertFalse(runner.grade_observer(fixture, events)["passed"])

    def test_privileged_target_is_not_the_unprivileged_control(self):
        fixture, events = controlled_evidence()
        for sample in events:
            for process in sample.get("processes", []):
                process["status"]["CapEff"] = "0000000000000001"
        self.assertFalse(runner.grade_observer(fixture, events)["passed"])

    def test_no_handle_claim_requires_readable_fd_table(self):
        fixture, events = controlled_evidence()
        for sample in events:
            for process in sample.get("processes", []):
                if process["pid"] == 10:
                    process["fd_table_error"] = 13
        self.assertFalse(runner.grade_observer(fixture, events)["passed"])

    def test_ablation_changes_only_one_container_option(self):
        default = runner.create_args("name", "token", "target")
        changed = runner.create_args("name", "token", "target", unconfined=True)
        changed.remove("--security-opt=seccomp=unconfined")
        self.assertEqual(default, changed)
        self.assertNotIn("--mount", changed)
        self.assertIn("--user=1000:1000", changed)
        self.assertIn("--network=none", changed)

    def test_observer_privileges_are_not_granted_to_target(self):
        target = runner.create_args("target", "token", "target")
        monitor = runner.create_args("observer", "token", "observer", target_id="owned-id")
        self.assertNotIn("--cap-add=SYS_PTRACE", target)
        self.assertIn("--cap-add=SYS_PTRACE", monitor)
        self.assertIn("--pid=container:owned-id", monitor)
        self.assertNotIn("--pid=host", monitor)

    def test_invalid_container_settings_rejected_before_start(self):
        info = {"Image": runner.IMAGE, "Config": {"User": "1000:1000", "Labels": {runner.LABEL: "token"}},
                "HostConfig": {"CapDrop": ["ALL"], "CapAdd": [], "NetworkMode": "none",
                               "ReadonlyRootfs": True, "Privileged": False,
                               "SecurityOpt": ["no-new-privileges"], "PidMode": "",
                               "PidsLimit": 64, "Memory": 512 * 1024 * 1024, "NanoCpus": 1_000_000_000,
                               "Tmpfs": {"/tmp": "", "/home/agent": "", "/workspace": ""}},
                "Mounts": []}
        runner.verify_container(info, "token", "target")
        for key, value in (("NetworkMode", "host"), ("Privileged", True),
                           ("Binds", ["/home:/host"]), ("PidMode", "host"),
                           ("CapAdd", ["SYS_ADMIN"])):
            changed = copy.deepcopy(info)
            changed["HostConfig"][key] = value
            with self.subTest(key=key), self.assertRaises(RuntimeError):
                runner.verify_container(changed, "token", "target")
        with self.assertRaises(RuntimeError):
            runner.verify_container(info, "token", "target", unconfined=True)

    def test_failed_sandbox_start_is_data_not_failed_basic_control(self):
        condition = {"condition": "docker_default", "environment_status": credentials(), "probes": [
            {"name": "version", "exit_code": 0, "stdout": "codex-cli 0.154.0\n"},
            {"name": "plain_python", "exit_code": 0, "child_started": True},
            {"name": "codex_sandbox", "exit_code": 1, "child_started": False}]}
        second = copy.deepcopy(condition)
        second["condition"] = "seccomp_disabled_only"
        self.assertTrue(runner.environment_controls([condition, second]))
        condition["probes"][0]["stdout"] = "different version"
        self.assertFalse(runner.environment_controls([condition, second]))

    def test_duplicate_case_cannot_replace_missing_control(self):
        fixture, events = controlled_evidence()
        fixture["cases"][2] = copy.deepcopy(fixture["cases"][0])
        self.assertFalse(runner.grade_observer(fixture, events)["passed"])

    def test_missing_samples_are_not_a_complete_stream(self):
        fixture, events = controlled_evidence()
        events[-1]["samples"] += 1
        self.assertFalse(runner.grade_observer(fixture, events)["passed"])

    def test_wrong_parent_does_not_establish_inheritance(self):
        fixture, events = controlled_evidence()
        fixture["cases"][2]["child"]["ppid"] = 999
        self.assertFalse(runner.grade_observer(fixture, events)["passed"])

    def test_corrected_inventory_has_no_obsolete_linux_subcommand(self):
        self.assertNotIn(["codex", "sandbox", "linux", "--help"], [argv for _, argv in HELP_COMMANDS])
        self.assertIn(["codex", "sandbox", "--help"], [argv for _, argv in HELP_COMMANDS])


if __name__ == "__main__":
    unittest.main()
