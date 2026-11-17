"""Held, benign tool process. Reports metadata only and never opens native history."""
import argparse
import json
import os
from pathlib import Path
import time


def metadata():
    keys = {"Name", "Uid", "Gid", "Groups", "CapInh", "CapPrm", "CapEff",
            "CapBnd", "CapAmb", "NoNewPrivs", "Seccomp"}
    status = {}
    for line in Path("/proc/self/status").read_text().splitlines():
        key, _, value = line.partition(":")
        if key in keys:
            status[key] = value.strip()
    text = Path("/proc/self/stat").read_text()
    rest = text[text.rfind(")") + 2:].split()
    fds, errors = [], []
    entries = sorted(Path("/proc/self/fd").iterdir(), key=lambda p: int(p.name))
    for entry in entries[:256]:
        try:
            target = os.readlink(entry)
            values = dict(line.split(":", 1) for line in
                          (Path("/proc/self/fdinfo") / entry.name).read_text().splitlines()
                          if ":" in line)
            if os.readlink(entry) != target:
                errors.append({"fd": int(entry.name), "race": True})
                continue
            flags = int(values["flags"].strip(), 8)
            fds.append({"fd": int(entry.name), "target": target,
                        "access": ("path_only" if flags & getattr(os, "O_PATH", 0) else
                                   {0: "read_only", 1: "write_only", 2: "read_write"}.get(flags & 3, "unknown")),
                        "append": bool(flags & os.O_APPEND),
                        "flags_octal": values["flags"].strip(),
                        "ino": int(values["ino"]), "mnt_id": int(values["mnt_id"])})
        except FileNotFoundError:
            # Enumerating /proc/self/fd itself briefly creates a directory FD.
            continue
        except (OSError, KeyError, ValueError) as exc:
            errors.append({"fd": int(entry.name), "error": type(exc).__name__,
                           "errno": getattr(exc, "errno", None)})
    return {"pid": os.getpid(), "ppid": os.getppid(), "start_ticks": int(rest[19]),
            "status": status, "pid_namespace": os.readlink("/proc/self/ns/pid"),
            "fds": fds, "fd_errors": errors, "fd_table_truncated": len(entries) > 256}


def run(directory=Path("/workspace"), seconds=6):
    directory = Path(directory)
    if not 0 <= seconds <= 10:
        raise ValueError("Invalid hold duration")
    entry = metadata()
    control = directory / "native-identity-control.txt"
    result = directory / "native-identity-control.json"
    if control.exists() or result.exists() or control.is_symlink() or result.is_symlink():
        raise RuntimeError("An earlier control exists and was retained")
    with control.open("x", encoding="utf-8") as stream:
        stream.write("benign observation control\n")
        stream.flush()
        stat = os.fstat(stream.fileno())
        start = time.time_ns()
        record = {"schema": "native-tool-identity-v1", "entry": entry,
                  "control_path": str(control), "control_fd": stream.fileno(),
                  "control_inode": stat.st_ino, "control_device": stat.st_dev,
                  "hold_started_ns": start, "hold_seconds": seconds}
        print("NATIVE_IDENTITY_HOLD_STARTED", flush=True)
        time.sleep(seconds)
        record["hold_finished_ns"] = time.time_ns()
    with result.open("x", encoding="utf-8") as stream:
        json.dump(record, stream, indent=2)
        stream.write("\n")
    print("NATIVE_IDENTITY_HOLD_FINISHED", flush=True)
    return record


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.parse_args()
    run()
