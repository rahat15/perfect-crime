"""Bounded /proc metadata sampling; no process memory, argv or environment capture."""
import argparse
import errno
import json
import os
from pathlib import Path
import signal
import time

STATUS_KEYS = {"Name", "Uid", "Gid", "Groups", "CapInh", "CapPrm", "CapEff",
               "CapBnd", "CapAmb", "NoNewPrivs", "Seccomp"}


def status_fields(text):
    return {key: value.strip() for line in text.splitlines()
            for key, separator, value in [line.partition(":")]
            if separator and key in STATUS_KEYS}


def stat_fields(text):
    # comm can contain spaces and parentheses; fields after its final ')' are fixed.
    rest = text[text.rfind(")") + 2:].split()
    return {"ppid": int(rest[1]), "start_ticks": int(rest[19])}


def fd_mode(flags):
    value = int(flags, 8)
    access = ("path_only" if value & getattr(os, "O_PATH", 0) else
              {os.O_RDONLY: "read_only", os.O_WRONLY: "write_only",
               os.O_RDWR: "read_write"}.get(value & os.O_ACCMODE, "unknown"))
    return {"flags_octal": flags, "access": access, "append": bool(value & os.O_APPEND)}


def snapshot(pid, proc=Path("/proc")):
    directory = proc / str(pid)
    before = stat_fields((directory / "stat").read_text())
    status = status_fields((directory / "status").read_text())
    result = {"pid": int(pid), **before, "status": status, "fds": [], "fd_errors": []}
    try:
        result["exe"] = os.readlink(directory / "exe")
    except OSError as exc:
        result["exe_error"] = exc.errno
    try:
        entries = sorted((directory / "fd").iterdir(), key=lambda p: int(p.name))
        result["fd_table_truncated"] = len(entries) > 256
        for entry in entries[:256]:
            try:
                target = os.readlink(entry)
                info = (directory / "fdinfo" / entry.name).read_text()
                values = dict(line.split(":", 1) for line in info.splitlines() if ":" in line)
                target_after = os.readlink(entry)
                if target_after != target:
                    result["fd_errors"].append({"fd": int(entry.name), "race": True})
                    continue
                result["fds"].append({"fd": int(entry.name), "target": target,
                                      **fd_mode(values["flags"].strip()),
                                      **{key: int(values[key].strip())
                                         for key in ("mnt_id", "ino", "pos") if key in values}})
            except (OSError, KeyError, ValueError) as exc:
                result["fd_errors"].append({"fd": int(entry.name),
                                            "error": type(exc).__name__,
                                            "errno": getattr(exc, "errno", None)})
    except OSError as exc:
        result["fd_table_error"] = exc.errno
    after = stat_fields((directory / "stat").read_text())
    if before["start_ticks"] != after["start_ticks"]:
        raise ProcessLookupError("PID reused during sample")
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--uid", type=int, action="append",
                        help="Effective UID to include; repeat for multiple accounts. Default: 1000.")
    parser.add_argument("--duration", type=float, default=60)
    parser.add_argument("--interval", type=float, default=0.1)
    args = parser.parse_args()
    selected_uids = set(args.uid or [1000])
    if not (1 <= args.duration <= 120 and 0.05 <= args.interval <= 1):
        parser.error("Sampling duration or interval is outside the bounded protocol")
    stopped = False

    def stop(signum, frame):
        nonlocal stopped
        stopped = True

    for signum in (signal.SIGTERM, signal.SIGINT):
        signal.signal(signum, stop)

    def emit(kind, **fields):
        print(json.dumps({"kind": kind, "observed_ns": time.time_ns(),
                          "monotonic_ns": time.monotonic_ns(), **fields}), flush=True)

    emit("observer_started", observer_pid=os.getpid(),
         status=status_fields(Path("/proc/self/status").read_text()),
         namespace_pid=os.readlink("/proc/self/ns/pid"),
         selected_effective_uids=sorted(selected_uids),
         interval_seconds=args.interval,
         limits="Polling can miss short-lived processes/handles. An observed writable handle "
                "is not proof of a write. No argv, environ or memory is read.")
    deadline = time.monotonic() + args.duration
    samples = 0
    while not stopped and time.monotonic() < deadline:
        processes, errors = [], []
        pids = sorted((p for p in Path("/proc").iterdir() if p.name.isdecimal()),
                      key=lambda p: int(p.name))
        for directory in pids[:128]:
            try:
                status = status_fields((directory / "status").read_text())
                if int(status["Uid"].split()[1]) not in selected_uids:
                    continue
                processes.append(snapshot(int(directory.name)))
            except OSError as exc:
                if exc.errno not in (errno.ENOENT, errno.ESRCH) and not isinstance(exc, ProcessLookupError):
                    errors.append({"pid": int(directory.name), "errno": exc.errno})
            except (ValueError, KeyError, IndexError) as exc:
                errors.append({"pid": int(directory.name), "error": type(exc).__name__})
        emit("process_sample", processes=processes, errors=errors,
             process_table_truncated=len(pids) > 128)
        samples += 1
        time.sleep(args.interval)
    emit("observer_finished", samples=samples,
         reason="controller_stop" if stopped else "duration_limit")


if __name__ == "__main__":
    main()
