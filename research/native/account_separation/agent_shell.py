"""agent-shell wrapper: force every shell-tool command to run as the tool account.

This module is the POLICY half of the shell replacement. In the derived image a
tiny compiled stub is installed as ``/bin/bash`` and ``/bin/sh`` (the real shells
are moved aside to ``/bin/bash.real`` / ``/bin/sh.real``). However Codex spawns
its shell tool, the kernel runs the stub, which re-execs the Python interpreter
with hardened flags and hands control here:

    /usr/local/bin/python3 -I -S -E <this file> <real-shell> <argv0> <argv...>

``-I`` (isolated) makes the interpreter ignore all ``PYTHON*`` environment
variables and omit the script directory and the current directory from
``sys.path``; ``-S`` skips ``site``; ``-E`` is redundant with ``-I`` but explicit.
Together they ensure the interpreter cannot be subverted into importing attacker
code via argv or environment before this policy runs. The only import below is an
absolute-path import of the mechanism's own ``capbits`` module.

What the wrapper does, in order, failing CLOSED (refusing to exec the command) if
any step fails:

  1. Switch real, effective and saved GID and UID to the tool account (1002).
  2. Clear supplementary groups, keeping at most ONE shared workspace group so
     files the recorder's in-process editor creates under /workspace stay
     group-writable to the tool account and vice versa. That group grants NO access to
     the records filesystem (verified by the control).
  3. Clear the permitted, effective, inheritable and ambient capability sets, and
     drop the bounding set best-effort (emptying the bounding set needs
     CAP_SETPCAP, which the mechanism deliberately does not grant; under
     no_new_privs a non-empty bounding set is inert once the other four sets are
     empty).
  4. Set no_new_privs.
  5. Close every inherited descriptor above stderr, so no recorder transcript
     handle reaches the command (defeats the /proc/self/fd inheritance route).
  6. Sanitise the environment: HOME=/home/tool, a fixed PATH, and remove
     BASH_ENV / ENV / shell-function exports that could run code at shell start.
  7. Exec the REAL shell with the ORIGINAL argv.

A process that is already fully the tool account (a shell started by a tool, for
example by ``make`` or an npm script) is passed straight to the real shell with
its environment and descriptors untouched: nothing is left to drop, and nested
shells must keep working for ordinary coding tasks.

Why the listed bypasses do not work:
  * ``BASH_ENV`` / ``ENV`` would make the real shell source a file at startup, but
    that file runs AFTER the drop, as the tool account, with no capabilities, so it
    cannot touch the records. It is scrubbed anyway.
  * ``bash -p`` (privileged mode) is meaningless here: euid==ruid==1002 and
    egid==rgid==1002, so bash does not treat the shell as privileged, and even if
    it did there are no capabilities to retain.
  * Calling ``/bin/bash.real`` directly gains nothing: the caller is ALREADY the
    agent (that is the whole point), so reaching the real shell is reaching it as
    1002 with no capabilities.
  * A process Codex execs WITHOUT a shell never reaches this wrapper and keeps the
    recorder identity and ambient CAP_SETUID/SETGID. That residual is the known,
    reported limitation, not a wrapper bypass.
"""

import os
import sys

# The stub invokes us as ``python3 -I -S -E``, which (correctly) strips PYTHONPATH
# and the script directory from sys.path so no planted module can shadow our
# imports. Our only non-stdlib import is the mechanism's own ``capbits``, at a
# fixed absolute path under the image-controlled package root; add that root
# explicitly. This path is never tool-writable (image content / the worktree),
# so it cannot be used to inject code.
_PKG_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.realpath(__file__)))))
if _PKG_ROOT not in sys.path:
    sys.path.insert(0, _PKG_ROOT)

from research.native.account_separation import capbits

TOOL_UID = 1002
TOOL_GID = 1002
SHARED_WORKSPACE_GID = 2000  # Shared group for cross-account /workspace collaboration.
TOOL_HOME = "/home/tool"  # The tool account's own home; /home/agent is the records filesystem.
# Identity marker. When this recorder-owned directory exists, every privileged
# entry appends one line AFTER the drop, describing the identity the command is
# about to run with. The tool account cannot modify the log.
AUDIT_DIR = "/home/agent/.account-separation"
AUDIT_LOG = AUDIT_DIR + "/wrapper-audit.jsonl"
TOOL_PATH = "/usr/local/bin:/usr/local/sbin:/usr/sbin:/usr/bin:/sbin:/bin"
# Environment names that can cause a shell to execute code at startup.
_DANGEROUS_ENV = ("BASH_ENV", "ENV", "SHELLOPTS", "BASHOPTS", "PROMPT_COMMAND",
                  "LD_PRELOAD", "LD_LIBRARY_PATH", "LD_AUDIT", "IFS")


def _fail_closed(message):
    sys.stderr.write("agent-shell: refusing to run command: %s\n" % message)
    # 126: command found but not executable/permission problem, conventional for
    # "the shell could not run the command".
    os._exit(126)


def _close_inherited_descriptors():
    try:
        keep = {0, 1, 2}
        for name in os.listdir("/proc/self/fd"):
            fd = int(name)
            if fd not in keep:
                try:
                    os.close(fd)
                except OSError:
                    pass
        return
    except OSError:
        pass
    try:
        os.closerange(3, 1 << 16)
    except Exception:
        pass


def drop_to_tool(uid=TOOL_UID, gid=TOOL_GID, shared_gid=SHARED_WORKSPACE_GID):
    """Steps 1-4. Raises on any failure so the caller can fail closed."""
    # Drop the bounding set first, while we may still hold CAP_SETPCAP ambiently in
    # some deployments; best-effort because the mechanism normally omits SETPCAP.
    capbits.drop_bounding_set(best_effort=True)
    # Supplementary groups: keep only the shared workspace group if present.
    groups = [shared_gid] if shared_gid is not None else []
    os.setgroups(groups)
    os.setresgid(gid, gid, gid)
    os.setresuid(uid, uid, uid)
    # Now unprivileged: clear all four capability sets.
    capbits.ambient_clear_all()
    capbits.capset(0, 0, 0)
    capbits.set_no_new_privs()


def verify_dropped(uid=TOOL_UID, gid=TOOL_GID):
    """Independent, from-first-principles check that the drop fully took effect."""
    if os.getresuid() != (uid, uid, uid) or os.getresgid() != (gid, gid, gid):
        _fail_closed("UID/GID did not switch to the tool account")
    status = capbits.read_status()
    for field in ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"):
        if int(status.get(field, "ffffffffffffffff"), 16) != 0:
            _fail_closed("capability set %s is not empty (%s)" % (field, status.get(field)))
    if status.get("NoNewPrivs") != "1":
        _fail_closed("no_new_privs is not set")


def already_tool(uid=TOOL_UID, gid=TOOL_GID):
    """True only for a process that is ALREADY fully the tool account: all three UIDs and
    GIDs, all five capability sets empty and no_new_privs set. Anything else takes
    the drop path, which fails closed if it cannot complete."""
    if os.getresuid() != (uid, uid, uid) or os.getresgid() != (gid, gid, gid):
        return False
    try:
        status = capbits.read_status()
        return (all(int(status[field], 16) == 0
                    for field in ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"))
                and status.get("NoNewPrivs") == "1")
    except (OSError, KeyError, ValueError):
        return False


def open_audit():
    """Open the audit log while still the recorder. A missing directory means the
    marker is not configured; a present directory that cannot be written is a
    failure, and the command is refused."""
    if not os.path.isdir(AUDIT_DIR):
        return None
    try:
        return os.open(AUDIT_LOG, os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o644)
    except OSError as exc:
        _fail_closed("audit log cannot be opened: %s" % exc)


def write_audit(descriptor, real_shell, arguments):
    if descriptor is None:
        return
    import hashlib
    import json
    import time
    status = capbits.read_status()
    line = json.dumps({
        "schema": "agent-shell-audit-v1", "pid": os.getpid(), "ppid": os.getppid(),
        "uid": list(os.getresuid()), "gid": list(os.getresgid()), "groups": os.getgroups(),
        "caps": {k: status.get(k) for k in ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb")},
        "no_new_privs": status.get("NoNewPrivs"), "real_shell": real_shell,
        "argv_sha256": hashlib.sha256("\0".join(arguments).encode("utf-8", "surrogateescape")).hexdigest(),
        "last_argument_sha256": hashlib.sha256(
            (arguments[-1] if arguments else "").encode("utf-8", "surrogateescape")).hexdigest(),
        "monotonic_ns": time.monotonic_ns(), "time_ns": time.time_ns()}) + "\n"
    try:
        os.write(descriptor, line.encode())
        os.close(descriptor)
    except OSError as exc:
        _fail_closed("audit log cannot be written: %s" % exc)


def sanitized_environment():
    env = dict(os.environ)
    for name in _DANGEROUS_ENV:
        env.pop(name, None)
    # Drop exported shell functions (names like BASH_FUNC_x%%).
    for name in list(env):
        if name.startswith("BASH_FUNC_"):
            env.pop(name, None)
    env["HOME"] = TOOL_HOME
    env["PATH"] = TOOL_PATH
    env.setdefault("LANG", "C.UTF-8")
    return env


def main(argv=None):
    argv = list(sys.argv if argv is None else argv)
    if len(argv) < 3:
        _fail_closed("stub did not pass <real-shell> <argv0> ...")
    real_shell = argv[1]
    original_argv0 = argv[2]
    rest = argv[3:]

    if not os.path.isabs(real_shell) or not os.path.exists(real_shell):
        _fail_closed("real shell %r is not an absolute existing path" % (real_shell,))

    if already_tool():
        # A shell started BY a tool (make, npm scripts, subprocess with
        # shell=True, `bash script.sh`). There is no privilege left to drop, and
        # the call must be transparent: same environment, same descriptors.
        try:
            os.execve(real_shell, [original_argv0] + rest, os.environ)
        except OSError as exc:
            _fail_closed("exec of real shell failed: %s" % exc)

    audit = open_audit()
    try:
        drop_to_tool()
    except OSError as exc:
        _fail_closed("privilege drop failed: %s" % exc)
    verify_dropped()
    write_audit(audit, real_shell, rest)
    _close_inherited_descriptors()
    os.umask(0o002)  # Group-collaborative workspace files; records are owned, not umask-gated.
    env = sanitized_environment()

    exec_argv = [original_argv0] + rest
    try:
        os.execve(real_shell, exec_argv, env)
    except OSError as exc:
        _fail_closed("exec of real shell failed: %s" % exc)


if __name__ == "__main__":
    main()
