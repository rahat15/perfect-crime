import copy
import unittest

from research.native import native_identity_analysis as analysis


def process(pid, parent, start, fds=(), name="python3"):
    return {"pid": pid, "ppid": parent, "start_ticks": start, "exe": "/usr/bin/" + name,
            "status": {"Name": name, "Uid": "1000\t1000\t1000\t1000", "Gid": "1000\t1000\t1000\t1000",
                       "Groups": "1000", "CapEff": "0000000000000000", "NoNewPrivs": "1"},
            "fds": list(fds), "fd_errors": [], "fd_table_truncated": False}


def evidence():
    trace = {"fd": 9, "target": "/home/agent/.codex/sessions/a-session.jsonl", "ino": 300,
             "access": "write_only", "append": True}
    workspace = {"fd": 3, "target": "/workspace/native-identity-control.txt", "ino": 400,
                 "access": "write_only", "append": False}
    launcher = process(10, 9, 90, name="node")
    writer = process(11, 10, 91, [trace], "codex")
    shell = process(12, 11, 92, name="bash")
    tool = process(13, 12, 93, [workspace])
    fixture = {"entry": {**copy.deepcopy(tool), "fds": [], "pid_namespace": "pid:[123]"},
               "control_path": workspace["target"], "control_inode": 400, "control_fd": 3,
               "hold_started_ns": 300, "hold_finished_ns": 700}
    samples = [{"kind": "process_sample", "observed_ns": t, "errors": [],
                "process_table_truncated": False,
                "processes": copy.deepcopy([launcher, writer, shell, tool])} for t in (400, 500, 600)]
    events = [{"kind": "observer_started", "observed_ns": 100, "namespace_pid": "pid:[123]",
               "status": {"Uid": "0 0 0 0", "CapEff": "0000000000080004", "NoNewPrivs": "1"}},
              *samples, {"kind": "observer_finished", "observed_ns": 1000,
                          "reason": "controller_stop", "samples": 3}]
    stage = {"pid": 10, "supervisor_pid": 9, "started_ns": 200, "finished_ns": 900}
    inventory = {"pid_namespace": "pid:[123]", "traces": [{"path": trace["target"], "inode": 300}]}
    return events, stage, inventory, fixture


class NativeIdentityAnalysisTests(unittest.TestCase):
    def analyze(self, change=None):
        args = evidence()
        if change:
            change(*args)
        return analysis.analyze_stage(*args)

    def test_corroborated_native_writer_and_held_tool(self):
        result = self.analyze()
        self.assertTrue(result["native_history_writer_observed"])
        self.assertTrue(result["held_tool_corroborated"])
        self.assertEqual(result["held_tool_matching_samples"], 3)
        self.assertEqual(result["held_tool_parents"][0]["exe"], "/usr/bin/bash")
        self.assertEqual(result["inherited_history_handle_finding"], "not_observed_in_this_held_control")

    def test_entry_and_observer_both_required_for_inheritance(self):
        events, stage, inventory, fixture = evidence()
        handle = copy.deepcopy(events[1]["processes"][1]["fds"][0])
        fixture["entry"]["fds"] = [handle]
        self.assertFalse(analysis.analyze_stage(events, stage, inventory, fixture)["inherited_history_handles_corroborated"])
        for sample in events[1:-1]:
            sample["processes"][-1]["fds"].append(handle)
        result = analysis.analyze_stage(events, stage, inventory, fixture)
        self.assertEqual(result["inherited_history_handle_finding"], "observed")

    def test_read_only_native_handle_is_not_writer(self):
        def change(events, *_):
            for sample in events[1:-1]:
                sample["processes"][1]["fds"][0]["access"] = "read_only"
        self.assertFalse(self.analyze(change)["native_history_writer_observed"])

    def test_unrelated_same_uid_process_is_not_native_writer(self):
        def change(events, *_):
            for sample in events[1:-1]:
                sample["processes"][1]["ppid"] = 99
        self.assertFalse(self.analyze(change)["native_history_writer_observed"])

    def test_reused_launcher_pid_is_not_resolved(self):
        def change(events, *_):
            events[2]["processes"][0]["start_ticks"] += 1
        result = self.analyze(change)
        self.assertFalse(result["launcher_identity_resolved"])
        self.assertFalse(result["native_history_writer_observed"])

    def test_ancestry_requires_parent_in_same_sample(self):
        def change(events, *_):
            events[1]["processes"] = events[1]["processes"][1:]
        self.assertFalse(self.analyze(change)["native_history_writer_observed"])

    def test_wrong_inode_cannot_establish_writable_history(self):
        self.assertFalse(self.analyze(lambda e, s, i, f: i["traces"][0].update(inode=999))["native_history_writer_observed"])

    def test_tool_writable_history_is_not_native_codex_writer(self):
        def change(events, *_):
            for sample in events[1:-1]:
                sample["processes"][1]["exe"] = "/usr/bin/python3"
        self.assertFalse(self.analyze(change)["native_history_writer_observed"])

    def test_fd_races_do_not_count_as_clean_positive_samples(self):
        def change(events, *_):
            events[1]["processes"][1]["fd_errors"] = [{"fd": 9, "race": True}]
        result = self.analyze(change)
        self.assertFalse(result["native_history_writer_observed"])
        self.assertEqual(result["observation_integrity"]["process_samples_with_fd_races_or_errors"], 1)

    def test_incomplete_observation_cannot_be_positive(self):
        cases = [lambda e: e[-1].update(reason="duration_limit"),
                 lambda e: e[-1].update(samples=99),
                 lambda e: e[0].update(namespace_pid="pid:[wrong]"),
                 lambda e: e[0]["status"].update(CapEff="00000000"),
                 lambda e: e[1].update(process_table_truncated=True),
                 lambda e: e[1].update(errors=[{"pid": 1, "errno": 13}]),
                 lambda e: e[0].update(observed_ns=999)]
        for change in cases:
            with self.subTest(change=change):
                result = self.analyze(lambda e, *_: change(e))
                self.assertFalse(result["observation_integrity"]["complete"])
                self.assertFalse(result["native_history_writer_observed"])
                self.assertFalse(result["held_tool_corroborated"])

    def test_missing_control_remains_undetermined(self):
        result = self.analyze(lambda e, s, i, f: f["entry"].update(start_ticks=444))
        self.assertFalse(result["held_tool_corroborated"])
        self.assertEqual(result["inherited_history_handle_finding"], "undetermined")

    def test_resume_tool_events_include_unknown_tool_types(self):
        self.assertFalse(analysis.resume_has_tool_activity([
            {"type": "item.completed", "item": {"type": "agent_message"}}]))
        for kind in ("command_execution", "file_change", "mcp_tool_call", "future_tool"):
            self.assertTrue(analysis.resume_has_tool_activity([
                {"type": "item.started", "item": {"type": kind}}]))


if __name__ == "__main__":
    unittest.main()
