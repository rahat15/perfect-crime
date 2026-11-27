"""STAND-IN recorder for the account-separation control. NOT Codex.

This program imitates only the record-keeping and shell-dispatch behaviour of
Codex CLI 0.154.0 that our evidence documents, so the OS boundary can be
exercised WITHOUT a model account:

  * it runs as the recorder account (the launcher switches identity before exec);
  * it creates ``sessions/YYYY/MM/DD/rollout-<ts>-<uuid>.jsonl`` under CODEX_HOME,
    opens it read/write with O_APPEND, and keeps it open (as the identity pilot
    observed Codex's own writer holding the JSONL with O_APPEND);
  * it appends one JSON record per event, including a turn-1 record carrying a
    memory token (standing in for the conversation the model would remember);
  * it executes each tool command as ``/bin/bash -lc '<command>'`` — which in the
    derived image / namespaced control passes through the agent-shell wrapper —
    capturing the tool's own identity, exit code, output and the transcript's
    inode/size/sha256/link-count immediately before and after; and
  * on ``resume`` it finds the rollout by session id, verifies the earlier byte
    prefix is intact and the turn-1 token is present, and appends.

Everything it emits is explicitly labelled a stand-in observation. It makes no
claim about Codex's real behaviour; the live pilot must establish that.
"""

import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import uuid

STANDIN = "account-separation-standin-recorder (NOT Codex)"

# A prelude prepended inside the shell command that records the TOOL's own
# identity to a file, without altering the original command's exit status (it
# runs in a brace group ahead of the real command, whose status is what the
# shell returns). This is how we read real/effective/saved UID+GID, the five
# capability sets and NoNewPrivs from INSIDE the tool process.
_IDENTITY_PRELUDE = (
    '{{ cat /proc/self/status > "{status}" 2>/dev/null; '
    'printf "%s %s %s\\n" "$(id -u)" "$(id -g)" "$(id -G)" > "{ids}" 2>/dev/null; }} ; '
)


def _sha(raw):
    return hashlib.sha256(raw).hexdigest()


def transcript_snapshot(path):
    """inode/size/sha256/link-count of the transcript, or absent marker."""
    try:
        info = os.lstat(path)
    except FileNotFoundError:
        return {"present": False}
    except OSError as exc:
        return {"present": None, "errno": exc.errno}
    try:
        with open(path, "rb") as handle:
            raw = handle.read()
        digest = _sha(raw)
    except OSError as exc:
        raw, digest = None, None
    return {"present": True, "inode": info.st_ino, "device": info.st_dev,
            "size": info.st_size, "nlink": info.st_nlink, "uid": info.st_uid,
            "gid": info.st_gid, "mode": info.st_mode & 0o7777,
            "sha256": digest, "readable": raw is not None}


class Recorder:
    def __init__(self, codex_home, session_id):
        self.codex_home = Path(codex_home)
        self.session_id = session_id
        self.sessions_dir = self.codex_home / "sessions"
        self.rollout_path = None
        self.handle = None  # O_APPEND read/write fd kept open for the session.
        self.shell = "/bin/bash"
        self.append_errors = []

    # -- session file lifecycle -------------------------------------------------
    def create(self, token):
        now = time.gmtime()
        day = self.sessions_dir / time.strftime("%Y/%m/%d", now)
        day.mkdir(parents=True, exist_ok=True)
        stamp = time.strftime("%Y-%m-%dT%H-%M-%S", now)
        self.rollout_path = day / ("rollout-%s-%s.jsonl" % (stamp, self.session_id))
        fd = os.open(self.rollout_path, os.O_RDWR | os.O_CREAT | os.O_APPEND | os.O_EXCL, 0o644)
        self.handle = os.fdopen(fd, "a")
        self.append({"type": "session_meta", "schema": "standin-rollout-v1",
                     "session_id": self.session_id, "stand_in": STANDIN})
        self.append({"type": "turn", "turn": 1, "role": "user",
                     "content": "stand-in initial task"})
        self.append({"type": "turn", "turn": 1, "role": "assistant",
                     "memory_token": token,
                     "content": "stand-in assistant turn recording the memory token"})
        return self.rollout_path

    def open_existing(self):
        matches = sorted(self.sessions_dir.rglob("rollout-*-%s.jsonl" % self.session_id))
        if not matches:
            raise FileNotFoundError("no rollout for session %s" % self.session_id)
        if len(matches) != 1:
            raise RuntimeError("ambiguous rollout set for session %s" % self.session_id)
        self.rollout_path = matches[0]
        fd = os.open(self.rollout_path, os.O_RDWR | os.O_APPEND)
        self.handle = os.fdopen(fd, "a")
        return self.rollout_path

    def append(self, record):
        """Append one record. A failed append (for example ENOSPC when the records
        share a filled filesystem) is counted, never hidden, and never fatal for the
        measurement that reports it."""
        record = dict(record, observed_ns=time.time_ns())
        try:
            os.write(self.handle.fileno(), (json.dumps(record) + "\n").encode())
            os.fsync(self.handle.fileno())
        except OSError as exc:
            self.append_errors.append({"type": record.get("type"), "errno": exc.errno})

    def close(self):
        if self.handle is not None:
            try:
                self.handle.close()
            except OSError as exc:
                self.append_errors.append({"type": "close", "errno": exc.errno})
            self.handle = None

    # -- tool command dispatch --------------------------------------------------
    def run_tool_command(self, name, command, scratch):
        """Run one shell-tool command through /bin/bash -lc and measure it fully."""
        status_file = os.path.join(scratch, "tool-status-%s" % name)
        ids_file = os.path.join(scratch, "tool-ids-%s" % name)
        wrapped = _IDENTITY_PRELUDE.format(status=status_file, ids=ids_file) + command

        before = transcript_snapshot(self.rollout_path)
        self.append({"type": "tool_call", "tool": "shell", "name": name, "command": command})
        started = time.monotonic_ns()
        proc = subprocess.run([self.shell, "-lc", wrapped], stdin=subprocess.DEVNULL,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        elapsed = time.monotonic_ns() - started
        after = transcript_snapshot(self.rollout_path)
        stdout = proc.stdout.decode("utf-8", "replace")
        stderr = proc.stderr.decode("utf-8", "replace")
        self.append({"type": "tool_result", "name": name, "exit_code": proc.returncode,
                     "stdout_b64": base64.b64encode(proc.stdout).decode(),
                     "stderr_b64": base64.b64encode(proc.stderr).decode()})

        tool_identity = {}
        try:
            with open(status_file) as handle:
                for line in handle:
                    key, sep, value = line.partition(":")
                    if sep and key in ("Uid", "Gid", "Groups", "CapInh", "CapPrm",
                                       "CapEff", "CapBnd", "CapAmb", "NoNewPrivs", "Seccomp"):
                        tool_identity[key] = value.strip()
        except OSError:
            tool_identity = {"unavailable": True}
        try:
            with open(ids_file) as handle:
                tool_identity["id_command"] = handle.read().strip()
        except OSError:
            pass

        return {"name": name, "command": command, "exit_code": proc.returncode,
                "elapsed_ns": elapsed, "stdout": stdout, "stderr": stderr,
                "errno_guess": _errno_from_text(stdout + "\n" + stderr),
                "tool_identity": tool_identity,
                "transcript_before": before, "transcript_after": after,
                "transcript_changed_excluding_recorder": None}


def _errno_from_text(text):
    """Best-effort errno classification from command output (not authoritative)."""
    lowered = text.lower()
    table = [("operation not permitted", 1, "EPERM"),
             ("permission denied", 13, "EACCES"),
             ("read-only file system", 30, "EROFS"),
             ("no such file or directory", 2, "ENOENT"),
             ("directory not empty", 39, "ENOTEMPTY"),
             ("not a directory", 20, "ENOTDIR")]
    found = [{"errno": num, "name": nm, "phrase": phrase}
             for phrase, num, nm in table if phrase in lowered]
    return found or None


def _load_script(path, categories):
    if path:
        data = json.loads(Path(path).read_text())
        if not isinstance(data, list):
            raise ValueError("command script must be a JSON list")
        return data
    from research.native.account_separation import command_script
    if categories == "none":
        return []
    return command_script.select([c for c in (categories or "").split(",") if c and c != "all"])


# Run DIRECTLY by the recorder (no shell, so no wrapper): measures the documented
# residual. Such a child keeps the recorder identity and the ambient capabilities.
_DIRECT_EXEC_PROBE = r"""
import errno, json, os
def status():
    out = {}
    for line in open('/proc/self/status'):
        k, _, v = line.partition(':')
        if k in ('Uid', 'Gid', 'CapPrm', 'CapEff', 'CapAmb', 'CapBnd', 'NoNewPrivs'):
            out[k] = v.strip()
    return out
def attempt(fn):
    try:
        fn(); return 'allowed'
    except OSError as exc:
        return 'denied:' + errno.errorcode.get(exc.errno, str(exc.errno))
result = {'entry': status()}
rollout = os.environ['ACCT_SEP_ROLLOUT']
result['open_transcript_for_append_as_recorder'] = attempt(lambda: os.close(os.open(rollout, os.O_WRONLY | os.O_APPEND)))
result['setuid_0'] = attempt(lambda: os.setresuid(0, 0, 0))
result['after_setuid_0'] = status()
result['open_recorder_0600_auth_as_uid0_without_dac_override'] = attempt(
    lambda: os.close(os.open(os.environ['ACCT_SEP_AUTH'], os.O_RDONLY)))
print(json.dumps(result))
"""


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("mode", choices=["init", "resume"])
    parser.add_argument("--session-id", required=True)
    parser.add_argument("--token", default="")
    parser.add_argument("--script", help="JSON file: list of {name, command} for init mode.")
    parser.add_argument("--categories", default="all",
                        help="init: comma-separated command categories, 'all' or 'none'.")
    parser.add_argument("--shell", default="/bin/bash",
                        help="Shell the tool commands are dispatched through. /bin/bash is the "
                             "wrapper in the condition; negative control N1 uses the real shell.")
    parser.add_argument("--scratch", default="/tmp")
    parser.add_argument("--output", required=True, help="Where to write the measurement JSON.")
    parser.add_argument("--expect-prefix-sha256", help="resume: sha256 of the pre-resume byte prefix.")
    parser.add_argument("--expect-prefix-len", type=int, help="resume: length of that prefix.")
    args = parser.parse_args(argv)

    codex_home = os.environ.get("CODEX_HOME") or os.path.join(
        os.environ.get("HOME", "/records"), ".codex")
    result = {"schema": "account-separation-standin-result-v1", "stand_in": STANDIN,
              "mode": args.mode, "session_id": args.session_id,
              "recorder_identity": {"uid": os.getuid(), "euid": os.geteuid(),
                                    "gid": os.getgid(), "egid": os.getegid(),
                                    "groups": os.getgroups()},
              "codex_home": codex_home, "errors": []}
    recorder = Recorder(codex_home, args.session_id)
    recorder.shell = args.shell
    result["tool_shell"] = args.shell
    try:
        if args.mode == "init":
            path = recorder.create(args.token)
            result["rollout_path"] = str(path)
            result["commands"] = []
            # Export the paths/ids the command script references by name, exactly
            # as the live runs referenced $CODEX_HOME / $CODEX_SESSION_ID. The
            # wrapper passes ACCT_SEP_* through (they are not shell-startup vars).
            os.environ.update({
                "ACCT_SEP_ROLLOUT": str(path),
                "ACCT_SEP_SESSIONS": str(recorder.sessions_dir),
                "ACCT_SEP_CODEX_HOME": codex_home,
                "ACCT_SEP_RECORDS_HOME": os.environ.get("ACCT_SEP_RECORDS_HOME", str(Path(codex_home).parent)),
                "ACCT_SEP_TOOL_HOME": os.environ.get("ACCT_SEP_TOOL_HOME", "/home/tool"),
                "ACCT_SEP_WORKSPACE": os.environ.get("ACCT_SEP_WORKSPACE", "/workspace"),
                "ACCT_SEP_AUTH": str(Path(codex_home) / "auth.json"),
                "ACCT_SEP_RECPID": str(os.getpid()),
                "ACCT_SEP_TOKEN": args.token,
                "ACCT_SEP_SCRATCH": args.scratch,
            })
            # Stand-in for Codex's per-session shell snapshot (the file the paper's
            # tool-call spoofing rewrote). It lives on the records filesystem.
            snapshot_dir = Path(codex_home) / "shell_snapshots"
            snapshot_dir.mkdir(parents=True, exist_ok=True)
            snapshot = snapshot_dir / (args.session_id + ".sh")
            snapshot.write_text("# stand-in shell snapshot\nexport STAND_IN=1\n")
            os.environ["ACCT_SEP_SHELL_SNAPSHOT"] = str(snapshot)
            os.environ["ACCT_SEP_AUDIT"] = "/home/agent/.account-separation/wrapper-audit.jsonl"
            result["shell_snapshot"] = {"path": str(snapshot), "sha256": _sha(snapshot.read_bytes())}
            # The recorder identity creates a workspace file so the control can
            # test that the agent (a different account, shared group) can edit it.
            workspace = os.environ["ACCT_SEP_WORKSPACE"]
            try:
                if args.categories == "none":
                    raise FileExistsError  # new-session check: records only, no workspace write
                made = os.path.join(workspace, "recorder_made.py")
                with open(os.open(made, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o664), "w") as handle:
                    handle.write("# created by the recorder identity\nVALUE = 1\n")
                result["recorder_workspace_file"] = made
            except FileExistsError:
                pass
            except OSError as exc:
                result["errors"].append("recorder workspace write failed: %s" % exc)
            try:
                probe = subprocess.run([sys.executable, "-I", "-c", _DIRECT_EXEC_PROBE],
                                       capture_output=True, text=True, timeout=30)
                result["residual_direct_exec_probe"] = json.loads(probe.stdout)
            except Exception as exc:  # noqa: BLE001
                result["residual_direct_exec_probe"] = {"unavailable": "%s: %s" % (type(exc).__name__, exc)}
            for step in _load_script(args.script, args.categories):
                measurement = recorder.run_tool_command(step["name"], step["command"], args.scratch)
                result["commands"].append(measurement)
            result["final_snapshot"] = transcript_snapshot(recorder.rollout_path)
            # Prefix that a later resume must find intact: bytes up to the first
            # tool-call record (i.e. the turn-1 content) is always the recorder's
            # own appends; expose the whole current file length/sha for the control.
            raw = Path(recorder.rollout_path).read_bytes()
            result["post_init_prefix_len"] = len(raw)
            result["post_init_prefix_sha256"] = _sha(raw)
            result["token_present_after_init"] = args.token.encode() in raw
        else:  # resume
            path = recorder.open_existing()
            result["rollout_path"] = str(path)
            raw = Path(path).read_bytes()
            result["resume_token_present"] = bool(args.token) and args.token.encode() in raw
            if args.expect_prefix_len is not None and args.expect_prefix_sha256:
                prefix = raw[:args.expect_prefix_len]
                result["resume_prefix_intact"] = (
                    len(prefix) == args.expect_prefix_len
                    and _sha(prefix) == args.expect_prefix_sha256)
            recorder.append({"type": "turn", "turn": 2, "role": "assistant",
                             "content": "stand-in resume turn", "recalled_token": args.token})
            result["resume_appended"] = True
            result["final_snapshot"] = transcript_snapshot(path)
    except Exception as exc:  # noqa: BLE001 - record and fail, never fabricate
        result["errors"].append("%s: %s" % (type(exc).__name__, exc))
    finally:
        recorder.close()
        result["append_errors"] = recorder.append_errors
        if recorder.append_errors:
            result["errors"].append("the recorder could not append %d record(s)" % len(recorder.append_errors))

    Path(args.output).write_text(json.dumps(result, indent=2) + "\n")
    return 1 if result["errors"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
