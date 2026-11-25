"""Synthetic long-lived descriptor controls; this is not a model or native recorder."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

CHILD = r'''
import json, os, sys, time
from pathlib import Path
case, name, inherited = sys.argv[1:]
handle = None
if case == "read_only":
    handle = os.open(name, os.O_RDONLY)
elif case == "inherited_writer":
    handle = int(inherited)
    os.write(handle, b"child-append\n")
raw = Path("/proc/self/stat").read_text()
start = int(raw[raw.rfind(")") + 2:].split()[19])
print(json.dumps({"pid": os.getpid(), "ppid": os.getppid(), "start_ticks": start, "case": case,
                  "handle": handle, "uid": os.getuid()}), flush=True)
time.sleep(3)
if handle is not None:
    os.close(handle)
'''


def run_fixture(root):
    root.mkdir(parents=True, exist_ok=False)
    raw = Path("/proc/self/stat").read_text()
    start = int(raw[raw.rfind(")") + 2:].split()[19])
    result = {"schema": "descriptor-observer-controls-v1", "parent_pid": os.getpid(),
              "parent_start_ticks": start, "uid": os.getuid(),
              "pid_namespace": os.readlink("/proc/self/ns/pid"), "cases": []}
    for case in ("no_inheritance", "read_only", "inherited_writer"):
        path = root / (case + ".jsonl")
        path.write_bytes(b"fixture-start\n")
        handle = os.open(path, os.O_WRONLY | os.O_APPEND)
        try:
            child = subprocess.run(
                [sys.executable, "-I", "-c", CHILD, case, str(path), str(handle)],
                stdin=subprocess.DEVNULL, capture_output=True, text=True,
                pass_fds=(handle,) if case == "inherited_writer" else (),
                timeout=8, check=False,
            )
            if child.returncode != 0:
                raise RuntimeError("Calibration child failed: " + child.stderr[-2000:])
            record = json.loads(child.stdout)
            actual = path.read_bytes()
            expected = b"fixture-start\n" + (b"child-append\n" if case == "inherited_writer" else b"")
            result["cases"].append({"case": case, "path": str(path), "parent_fd": handle,
                                    "child": record, "child_exit_code": child.returncode,
                                    "contents_match_control": actual == expected,
                                    "final_sha256": hashlib.sha256(actual).hexdigest()})
        finally:
            os.close(handle)
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path("/workspace/observer-controls"))
    args = parser.parse_args()
    print(json.dumps(run_fixture(args.root)))
