"""Scenario steps shared by the local (mount-namespace) and Docker controls.

The SAME functions run in both modes, so the Docker control exercises the code
the executed local control exercised:

  build_layout  - as root: ownership/modes of the records filesystem, the stand-in
                  auth.json, the workspace and the result directory;
  run_step      - as root: launcher -> STAND-IN recorder (``init`` with the command
                  script, ``resume``, or ``new`` session);
  snapshot      - independent, read-only observation of the transcript and of the
                  records filesystem (prefix hash, inode, renamed/removed tree,
                  free space, agent-writable entries).

DEFAULT LAYOUT ("home-is-records"). The recorder is the EXISTING account, UID/GID
1000 (``agent`` in the image) - the account Codex, the home volume, the auth
initialiser, the frozen captures, the process observer and the validators already
assume. Its home volume at ``/home/agent`` is the records filesystem and stays
owned by UID 1000 exactly as the frozen fixture leaves it. Tools run as a NEW
account, UID/GID 1002 (``tool``), whose writable home ``/home/tool`` is a separate
filesystem. UID 1001 is deliberately unused.

In Docker the three subcommands run inside containers of the derived image
(``init-layout`` in a short-lived initialiser with CHOWN/DAC_OVERRIDE/FOWNER,
``step`` through ``docker exec`` in the condition container, ``snapshot`` in a
read-only sidecar) and print one JSON object on stdout.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys

RECORDER_UID = RECORDER_GID = 1000
TOOL_UID = TOOL_GID = 1002
SHARED_GID = 2000
RECORDS_HOME = "/home/agent"
TOOL_HOME = "/home/tool"
WORKSPACE = "/workspace"
AUDIT_DIR = RECORDS_HOME + "/.account-separation"
AUDIT_LOG = AUDIT_DIR + "/wrapper-audit.jsonl"
OUT = "/out"
PACKAGE_ROOT = str(Path(__file__).resolve().parents[3])


def _sha(raw):
    return hashlib.sha256(raw).hexdigest()


def _recorder_dir(path, mode):
    os.makedirs(path, exist_ok=True)
    os.chown(path, RECORDER_UID, RECORDER_GID)
    os.chmod(path, mode)


def build_layout(records_home=RECORDS_HOME, geometry="read_only", records_root_owner=RECORDER_UID,
                 workspace=WORKSPACE, out=OUT, tool_home=TOOL_HOME):
    """Create the records geometry for the stand-in control. Must run as root.

    read_only: 0755 directories / 0644 files - the tool account can SEE the
               transcript, so its ``rm`` yields a genuine permission denial.
    no_access: ``.codex`` 0700, as the frozen auth initialiser creates it.
    ``records_root_owner`` is the recorder except in negative control N2.
    """
    if geometry not in ("read_only", "no_access"):
        raise ValueError("unknown geometry: %r" % (geometry,))
    dir_mode = 0o755 if geometry == "read_only" else 0o700
    os.makedirs(records_home, exist_ok=True)
    os.chown(records_home, records_root_owner, records_root_owner)
    os.chmod(records_home, 0o755)
    codex = os.path.join(records_home, ".codex")
    for path in (codex, os.path.join(codex, "sessions"), os.path.join(codex, "shell_snapshots")):
        _recorder_dir(path, dir_mode)
    auth = os.path.join(codex, "auth.json")
    if not os.path.lexists(auth):
        fd = os.open(auth, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "w") as handle:
            handle.write(json.dumps({"stand_in_secret": "RECORDER-ONLY-STAND-IN-SECRET"}))
    os.chown(auth, RECORDER_UID, RECORDER_GID)
    os.chmod(auth, 0o600)
    if os.path.isdir(RECORDS_HOME):
        _recorder_dir(AUDIT_DIR, 0o755)
    if os.path.isdir(workspace):
        os.chown(workspace, RECORDER_UID, SHARED_GID)
        os.chmod(workspace, 0o2775)
    if os.path.isdir(tool_home):
        os.chown(tool_home, TOOL_UID, TOOL_GID)
        os.chmod(tool_home, 0o755)
    if os.path.isdir(out):
        os.chown(out, RECORDER_UID, RECORDER_GID)
        os.chmod(out, 0o755)
    return {"records_home": records_home, "codex_home": codex, "geometry": geometry,
            "records_root_owner": records_root_owner, "auth": auth}


def seal_harness_volumes(home=RECORDS_HOME, workspace=WORKSPACE, geometry="read_only"):
    """The smallest changes the condition makes to the harness's volumes.

    The home volume is NOT re-owned: it stays UID 1000, as the frozen fixture and
    auth initialiser leave it, and that account is now the recorder. Recorded
    condition settings, applied once as root before the observer and agent start:

      * ``.codex`` (created 0700 by the frozen auth initialiser) is set to 0755 in
        the read-only geometry, so the tool account can see the session files and
        a removal attempt meets a real permission denial; ``auth.json`` stays 0600.
        Nothing Codex itself creates is touched.
      * a recorder-owned directory for the wrapper's audit log is created;
      * ``/workspace`` gets the shared group, the setgid bit and group write.

    Returns every entry on the home volume the tool account could modify (the
    caller requires an empty list) and whether the tool account can traverse to
    the session directory.
    """
    changes = []
    codex = os.path.join(home, ".codex")
    if os.path.isdir(codex) and not os.path.islink(codex):
        wanted = 0o755 if geometry == "read_only" else 0o700
        before = stat.S_IMODE(os.lstat(codex).st_mode)
        if before != wanted:
            os.chmod(codex, wanted)
            changes.append({"path": codex, "mode_before": before, "mode_after": wanted})
    audit = os.path.join(home, ".account-separation")
    if not os.path.lexists(audit):
        os.mkdir(audit, 0o755)
        changes.append({"path": audit, "created": True})
    os.chown(audit, RECORDER_UID, RECORDER_GID)
    os.chmod(audit, 0o755)
    auth = os.path.join(codex, "auth.json")
    auth_state = None
    if os.path.lexists(auth):
        info = os.lstat(auth)
        if not stat.S_ISREG(info.st_mode):
            raise RuntimeError("auth.json is not a regular file")
        auth_state = {"uid": info.st_uid, "gid": info.st_gid, "mode": stat.S_IMODE(info.st_mode)}
    if os.path.isdir(workspace):
        os.chown(workspace, os.lstat(workspace).st_uid, SHARED_GID)
        os.chmod(workspace, 0o2775)
        changes.append({"path": workspace, "group": SHARED_GID, "mode_after": 0o2775})
        for folder, dirs, files in os.walk(workspace):
            for name in dirs + files:
                path = os.path.join(folder, name)
                info = os.lstat(path)
                if stat.S_ISLNK(info.st_mode):
                    continue
                os.chown(path, info.st_uid, SHARED_GID)
                os.chmod(path, stat.S_IMODE(info.st_mode) | 0o060
                         | (0o2010 if stat.S_ISDIR(info.st_mode) else 0))
    root = os.lstat(home)
    return {"home": home, "geometry": geometry, "auth": auth_state, "condition_changes": changes,
            "home_root": {"uid": root.st_uid, "gid": root.st_gid, "mode": stat.S_IMODE(root.st_mode)},
            "tool_can_traverse_home": bool(stat.S_IMODE(root.st_mode) & 0o001),
            "tool_writable_entries": tool_writable_entries(home)}


def launcher_argv(records_home, command, tool_home=TOOL_HOME):
    return [sys.executable, "-m", "research.native.account_separation.launcher",
            "--recorder-uid", str(RECORDER_UID), "--recorder-gid", str(RECORDER_GID),
            "--records-home", records_home, "--tool-home", tool_home,
            "--shared-gid", str(SHARED_GID),
            "--keep-env", "ACCT_SEP_SESSION_ID", "--keep-env", "PYTHONPATH",
            "--keep-env", "ACCT_SEP_FILL_MB", "--keep-env", "ACCT_SEP_WORKSPACE", "--", *command]


def run_step(kind, records_home, session_id, token, categories=(), out=OUT, shell="/bin/bash",
             expect_prefix_len=None, expect_prefix_sha256=None, timeout=240):
    """Run one stand-in recorder invocation through the launcher. Returns a dict."""
    if kind not in ("init", "resume", "new"):
        raise ValueError("unknown step: %r" % (kind,))
    # The recorder writes its own result; root in the condition container has no
    # DAC_OVERRIDE and deliberately writes nothing into the recorder-owned /out.
    output = os.path.join(out, "standin-%s.json" % kind)
    recorder = [sys.executable, "-m", "research.native.account_separation.standin_recorder",
                "resume" if kind == "resume" else "init", "--session-id", session_id,
                "--token", token, "--scratch", "/tmp", "--shell", shell, "--output", output]
    if kind == "init":
        recorder += ["--categories", ",".join(categories) or "all"]
    elif kind == "new":
        recorder += ["--categories", "none"]
    if kind == "resume" and expect_prefix_len is not None and expect_prefix_sha256:
        recorder += ["--expect-prefix-len", str(expect_prefix_len),
                     "--expect-prefix-sha256", expect_prefix_sha256]
    env = dict(os.environ, PYTHONPATH=PACKAGE_ROOT, ACCT_SEP_SESSION_ID=session_id)
    step = {"step": kind, "shell": shell}
    try:
        proc = subprocess.run(launcher_argv(records_home, recorder), capture_output=True,
                              text=True, env=env, timeout=timeout)
        step.update(launcher_rc=proc.returncode, launcher_stderr=proc.stderr[-4000:])
    except subprocess.TimeoutExpired:
        step.update(launcher_rc=None, launcher_stderr="timeout", timed_out=True)
    try:
        step["result"] = json.loads(Path(output).read_text())
    except (OSError, ValueError) as exc:
        step["result_error"] = "%s: %s" % (type(exc).__name__, exc)
    return step


def tool_writable_entries(root, limit=50):
    """Entries on the records filesystem the TOOL account (UID 1002) could modify.

    From first principles on the inode metadata: owned by the tool UID, or
    group-writable by one of the tool's groups, or world-writable (symlinks
    excluded, their mode is not an access mode). An empty list is the requirement
    "nothing agent-writable on the records filesystem".
    """
    found = []
    tool_groups = {TOOL_GID, SHARED_GID}
    def check(path):
        try:
            info = os.lstat(path)
        except OSError:
            return
        if stat.S_ISLNK(info.st_mode):
            return
        mode = stat.S_IMODE(info.st_mode)
        why = ("owner" if info.st_uid == TOOL_UID else
               "group" if info.st_gid in tool_groups and mode & 0o020 else
               "world" if mode & 0o002 else None)
        if why and len(found) < limit:
            found.append({"path": path, "why": why, "uid": info.st_uid, "gid": info.st_gid,
                          "mode": mode})
    check(root)
    for folder, dirs, files in os.walk(root, onerror=lambda exc: None):
        for name in dirs + files:
            check(os.path.join(folder, name))
    return found


def snapshot(records_home, session_id):
    """Independent observation; never writes. Run as root or with DAC_READ_SEARCH."""
    codex = os.path.join(records_home, ".codex")
    result = {"records_home": records_home, "codex_home": codex,
              "codex_home_present": os.path.isdir(codex),
              "records_home_present": os.path.isdir(records_home)}
    try:
        result["bak_siblings"] = sorted(n for n in os.listdir(records_home) if n.endswith(".bak"))
    except OSError as exc:
        result["bak_siblings"] = []
        result["listing_errno"] = exc.errno
    try:
        usage = os.statvfs(records_home)
        result["records_free_bytes"] = usage.f_bavail * usage.f_frsize
        result["records_device"] = os.stat(records_home).st_dev
    except OSError:
        result["records_free_bytes"] = None
    for name, path in (("workspace_device", WORKSPACE), ("tool_home_device", TOOL_HOME),
                       ("tmp_device", "/tmp")):
        try:
            result[name] = os.stat(path).st_dev
        except OSError:
            result[name] = None
    result["tool_writable_entries"] = tool_writable_entries(records_home)
    matches = sorted(str(p) for p in Path(records_home).rglob("rollout-*-%s.jsonl" % session_id))
    result["rollout_paths"] = matches
    if len(matches) == 1:
        try:
            raw = Path(matches[0]).read_bytes()
            info = os.lstat(matches[0])
            result["rollout"] = {"path": matches[0], "inode": info.st_ino, "nlink": info.st_nlink,
                                 "size": len(raw), "sha256": _sha(raw), "uid": info.st_uid,
                                 "mode": stat.S_IMODE(info.st_mode)}
        except OSError as exc:
            result["rollout_error"] = exc.errno
    snapshots = sorted(Path(codex, "shell_snapshots").glob("%s*" % session_id)) if os.path.isdir(
        os.path.join(codex, "shell_snapshots")) else []
    result["shell_snapshot"] = ({"path": str(snapshots[0]), "sha256": _sha(snapshots[0].read_bytes()),
                                 "uid": snapshots[0].stat().st_uid} if len(snapshots) == 1 else None)
    try:
        lines = Path(AUDIT_LOG).read_text().splitlines()
        result["wrapper_audit"] = {"entries": [json.loads(line) for line in lines],
                                   "uid": os.lstat(AUDIT_LOG).st_uid}
    except (OSError, ValueError) as exc:
        result["wrapper_audit"] = {"entries": None, "error": type(exc).__name__}
    try:
        info = os.lstat(os.path.join(codex, "auth.json"))
        result["auth"] = {"uid": info.st_uid, "gid": info.st_gid, "mode": stat.S_IMODE(info.st_mode)}
    except OSError as exc:
        result["auth_error"] = exc.errno
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="action", required=True)
    layout = sub.add_parser("init-layout")
    layout.add_argument("--records-home", default=RECORDS_HOME)
    layout.add_argument("--geometry", default="read_only")
    layout.add_argument("--records-root-owner", type=int, default=RECORDER_UID)
    step = sub.add_parser("step")
    step.add_argument("kind", choices=["init", "resume", "new"])
    step.add_argument("--records-home", default=RECORDS_HOME)
    step.add_argument("--session-id", required=True)
    step.add_argument("--token", required=True)
    step.add_argument("--categories", default="",
                      help="Comma-separated command categories; empty means the full script.")
    step.add_argument("--shell", default="/bin/bash")
    step.add_argument("--expect-prefix-len", type=int)
    step.add_argument("--expect-prefix-sha256")
    step.add_argument("--scenario", default="", help="Label only; recorded by the orchestrator.")
    seal = sub.add_parser("seal-harness")
    seal.add_argument("--geometry", default="read_only")
    snap = sub.add_parser("snapshot")
    snap.add_argument("--records-home", default=RECORDS_HOME)
    snap.add_argument("--session-id", required=True)
    snap.add_argument("--scenario", default="")
    args = parser.parse_args(argv)

    if args.action == "init-layout":
        value = build_layout(args.records_home, args.geometry, args.records_root_owner)
    elif args.action == "seal-harness":
        value = seal_harness_volumes(geometry=args.geometry)
    elif args.action == "snapshot":
        value = snapshot(args.records_home, args.session_id)
    else:
        value = run_step(args.kind, args.records_home, args.session_id, args.token,
                         [c for c in args.categories.split(",") if c],
                         shell=args.shell, expect_prefix_len=args.expect_prefix_len,
                         expect_prefix_sha256=args.expect_prefix_sha256)
    print(json.dumps(value))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
