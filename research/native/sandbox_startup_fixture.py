"""Harmless offline startup and filesystem controls for the pinned sandbox CLI."""
import errno
import json
import os
from pathlib import Path
import signal
import subprocess
import sys

BEFORE = "startup-control-before\n"
WRITTEN = "startup-control-write\n"
WORK = Path("/workspace/startup-control.txt")
OUTSIDE = Path("/home/agent/startup-control.txt")
CHILD = r'''
import json, os
from pathlib import Path
result = {"marker": "native-sandbox-startup", "uid": os.getuid(), "gid": os.getgid(),
          "cwd": os.getcwd(), "operations": {}}
for name, path in (("workspace", "/workspace/startup-control.txt"),
                   ("outside", "/home/agent/startup-control.txt")):
    try:
        with open(path, "a", encoding="utf-8") as stream:
            stream.write("startup-control-write\n")
        result["operations"][name] = {"written": True, "errno": None}
    except OSError as error:
        result["operations"][name] = {"written": False, "errno": error.errno}
print(json.dumps(result), flush=True)
'''


def sandbox_command(python):
    return ["codex", "sandbox", "--permission-profile", ":workspace",
            "-C", "/workspace", "--", python, "-I", "-c", CHILD]


def capture(name, argv):
    row = {"name": name, "argv": argv, "timed_out": False}
    process = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, text=True, start_new_session=True)
    try:
        stdout, stderr = process.communicate(timeout=15)
    except subprocess.TimeoutExpired:
        row["timed_out"] = True
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        stdout, stderr = process.communicate(timeout=3)
    row.update(exit_code=process.returncode, stdout=stdout[:64000], stderr=stderr[:16000],
               output_truncated=len(stdout) > 64000 or len(stderr) > 16000)
    return row


def observe_files(row):
    markers = []
    for line in row.get("stdout", "").splitlines():
        try:
            value = json.loads(line)
        except ValueError:
            continue
        if isinstance(value, dict) and value.get("marker") == "native-sandbox-startup":
            markers.append(value)
    row["markers"] = markers
    row["files_after"] = {
        "workspace": WORK.read_text() if WORK.is_file() else None,
        "outside": OUTSIDE.read_text() if OUTSIDE.is_file() else None,
    }


def main():
    if os.getuid() != 1000 or os.getgid() != 1000:
        raise RuntimeError("Startup fixture requires UID/GID 1000.")
    Path("/home/agent/.codex").mkdir(mode=0o700, exist_ok=True)
    keys = {"Uid", "Gid", "Groups", "CapInh", "CapPrm", "CapEff", "CapBnd",
            "CapAmb", "NoNewPrivs", "Seccomp"}
    status = {}
    for line in Path("/proc/self/status").read_text().splitlines():
        key, _, value = line.partition(":")
        if key in keys:
            status[key] = value.strip()
    marker = 'import json,os; print(json.dumps({"marker":"user-namespace-started","uid":os.getuid()}))'
    commands = [
        ("version", ["codex", "--version"]),
        ("sandbox_help", ["codex", "sandbox", "--help"]),
        ("user_namespace", ["unshare", "--user", "--map-root-user", "--",
                            sys.executable, "-I", "-c", marker]),
        ("plain_python", [sys.executable, "-I", "-c", CHILD]),
        ("codex_sandbox", sandbox_command(sys.executable)),
    ]
    rows = []
    for name, argv in commands:
        file_control = name in {"plain_python", "codex_sandbox"}
        if file_control:
            WORK.unlink(missing_ok=True)
            OUTSIDE.write_text(BEFORE)
        try:
            row = capture(name, argv)
        except OSError as error:
            row = {"name": name, "argv": argv, "exit_code": None, "timed_out": False,
                   "error": str(error), "stdout": "", "stderr": "", "output_truncated": False}
        if file_control:
            observe_files(row)
        rows.append(row)
    print(json.dumps({"schema": "sandbox-startup-fixture-v1",
                      "environment_status": status, "probes": rows}))


if __name__ == "__main__":
    main()
