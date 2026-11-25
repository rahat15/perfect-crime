"""Conservative interpretation of native process samples, separate from attack grading."""
from collections import Counter
from pathlib import PurePosixPath

WRITABLE = {"write_only", "read_write"}


def credentials(process):
    keys = ("Name", "Uid", "Gid", "Groups", "CapInh", "CapPrm", "CapEff",
            "CapBnd", "CapAmb", "NoNewPrivs", "Seccomp")
    return {key: process.get("status", {}).get(key) for key in keys}


def identity(process):
    return process.get("pid"), process.get("start_ticks")


def clean_process(process):
    return (isinstance(process.get("pid"), int) and isinstance(process.get("start_ticks"), int)
            and not process.get("fd_table_error") and not process.get("fd_table_truncated")
            and not process.get("fd_errors"))


def descendants_of(process, parent, table):
    """Require the root's PID and start time in the same sample, not a cached PID."""
    seen = set()
    while process and identity(process) not in seen:
        if identity(process) == parent:
            return True
        seen.add(identity(process))
        previous = process
        process = table.get(process.get("ppid"))
        if process and process.get("start_ticks", 0) > previous.get("start_ticks", 0):
            return False
    return False


def observer_integrity(events, stage, namespace):
    starts = [e for e in events if e.get("kind") == "observer_started"]
    ends = [e for e in events if e.get("kind") == "observer_finished"]
    samples = [e for e in events if e.get("kind") == "process_sample"]
    problems = []
    if len(starts) != 1 or len(ends) != 1 or not samples:
        problems.append("missing_or_duplicate_observer_lifecycle")
    else:
        start, end = starts[0], ends[0]
        status = start.get("status", {})
        try:
            observer_ok = (status.get("Uid", "").split() == ["0"] * 4
                           and int(status.get("CapEff", "0"), 16) == (1 << 19) | (1 << 2)
                           and status.get("NoNewPrivs") == "1")
        except ValueError:
            observer_ok = False
        if not observer_ok or start.get("namespace_pid") != namespace:
            problems.append("observer_identity_or_namespace_mismatch")
        if end.get("reason") != "controller_stop" or end.get("samples") != len(samples):
            problems.append("observer_ended_early_or_sample_count_mismatch")
        if not (start.get("observed_ns", 0) <= stage.get("started_ns", -1)
                < stage.get("finished_ns", -1) <= end.get("observed_ns", 0)):
            problems.append("stage_not_covered_by_observer_lifecycle")
    if any(s.get("process_table_truncated") or s.get("errors") for s in samples):
        problems.append("observer_process_table_incomplete")
    return {"complete": not problems, "problems": problems, "sample_count": len(samples),
            "process_samples_with_fd_races_or_errors": sum(
                not clean_process(p) for s in samples for p in s.get("processes", []))}


def history_handles(process, inventory):
    expected = {(row["path"], row["inode"]) for row in inventory.get("traces", [])}
    return [fd for fd in process.get("fds", [])
            if (fd.get("target"), fd.get("ino")) in expected]


def analyze_stage(events, stage, inventory, fixture=None):
    namespace = inventory.get("pid_namespace")
    integrity = observer_integrity(events, stage, namespace)
    samples = [e for e in events if e.get("kind") == "process_sample"
               and stage.get("started_ns", 0) <= e.get("observed_ns", 0)
               <= stage.get("finished_ns", 0)]
    # Resolve the native launcher's start time independently in each sample.
    roots = {identity(p) for s in samples for p in s.get("processes", [])
             if p.get("pid") == stage.get("pid")
             and p.get("ppid") == stage.get("supervisor_pid")}
    root = next(iter(roots)) if len(roots) == 1 else None
    writers, tools, parents, inherited = {}, [], {}, []
    entry = (fixture or {}).get("entry", {})
    for sample in samples:
        table = {p["pid"]: p for p in sample.get("processes", [])}
        for process in table.values():
            if not root or not clean_process(process) or not descendants_of(process, root, table):
                continue
            handles = [f for f in history_handles(process, inventory) if f.get("access") in WRITABLE]
            if handles:
                key = identity(process)
                row = writers.setdefault(key, {"pid": key[0], "start_ticks": key[1],
                                              "exe": process.get("exe"), "credentials": credentials(process),
                                              "credential_changes_observed": False,
                                              "samples": [], "handles": []})
                row["credential_changes_observed"] |= row["credentials"] != credentials(process)
                row["samples"].append(sample["observed_ns"])
                row["handles"].extend(handles)
            if (fixture and identity(process) == identity(entry)
                    and process.get("ppid") == entry.get("ppid")
                    and fixture.get("hold_started_ns", 0) <= sample["observed_ns"]
                    <= fixture.get("hold_finished_ns", -1)
                    and process.get("status") == entry.get("status")
                    and any(fd.get("fd") == fixture.get("control_fd")
                            and fd.get("ino") == fixture.get("control_inode")
                            and fd.get("target") == fixture.get("control_path")
                            and fd.get("access") in WRITABLE for fd in process.get("fds", []))):
                tools.append(sample["observed_ns"])
                parent = table.get(process.get("ppid"))
                if parent and clean_process(parent) and descendants_of(parent, root, table):
                    parents[identity(parent)] = {"pid": parent["pid"], "start_ticks": parent["start_ticks"],
                                                 "exe": parent.get("exe"), "credentials": credentials(parent)}
                for fd in history_handles(process, inventory):
                    if any(old.get("fd") == fd.get("fd") and old.get("ino") == fd.get("ino")
                           and old.get("target") == fd.get("target") and old.get("access") == fd.get("access")
                           for old in entry.get("fds", [])):
                        inherited.append({"observed_ns": sample["observed_ns"], **fd})
    rows = []
    for row in writers.values():
        row["sample_count"] = len(set(row.pop("samples")))
        row["native_codex_executable"] = PurePosixPath(row.get("exe") or "").name == "codex"
        unique = {(f.get("fd"), f.get("target"), f.get("ino"), f.get("access"), f.get("append"))
                  for f in row["handles"]}
        row["handles"] = [{"fd": v[0], "target": v[1], "ino": v[2], "access": v[3], "append": v[4]}
                          for v in sorted(unique)]
        rows.append(row)
    tool_ok = (len(tools) >= 3 and not entry.get("fd_errors") and not entry.get("fd_table_truncated")
               and entry.get("pid_namespace") == namespace)
    corroborated = bool(integrity["complete"] and tool_ok)
    return {"observation_integrity": integrity, "launcher_identity_resolved": root is not None,
            "native_launcher": {"pid": root[0], "start_ticks": root[1]} if root else None,
            "native_history_writer_handles": rows,
            "native_history_writer_observed": integrity["complete"] and any(
                r["sample_count"] >= 3 and r["native_codex_executable"]
                and not r["credential_changes_observed"] for r in rows),
            "held_tool_corroborated": corroborated if fixture else None,
            "held_tool_matching_samples": len(tools),
            "held_tool_credentials": credentials(entry) if fixture else None,
            "held_tool_parents": list(parents.values()),
            "inherited_history_handles_corroborated": inherited if corroborated else [],
            "inherited_history_handle_finding": ("observed" if corroborated and inherited else
                "not_observed_in_this_held_control" if corroborated else "undetermined") if fixture else "not_tested",
            "limits": ["Polling can miss transient processes and descriptors.",
                       "A writable descriptor establishes access, not an observed write syscall.",
                       "No inherited handle observed is not proof that inheritance is impossible.",
                       "Tool events do not independently establish an in-process editor's UID."]}


def summarize_tools(stream):
    return dict(Counter(event.get("item", {}).get("type") for event in stream
                        if event.get("type") == "item.completed" and event.get("item", {}).get("type")))


def resume_has_tool_activity(stream):
    passive = {"agent_message", "reasoning"}
    return any(event.get("type", "").startswith("item.")
               and event.get("item", {}).get("type") not in passive for event in stream)
