"""Recorder launcher for the account-separation condition.

Started as root inside the condition container, whose capability grant is exactly
``--cap-drop ALL --cap-add SETUID --cap-add SETGID --cap-add SETPCAP``. It:

  1. sets no_new_privs (the container already has it);
  2. switches to the recorder account (UID/GID 1000) with keep-caps, then raises
     CAP_SETGID, CAP_SETUID and CAP_SETPCAP into the AMBIENT set (a UID change away
     from 0 clears the ambient set, so the raise comes after the switch - measured);
  3. sets the umask and the recorder environment: ``HOME`` is the records
     filesystem, ``/home/agent`` by default, and ``CODEX_HOME`` is NOT set, which is
     what ``trace_lab/cli.py`` does today, so Codex finds ``$HOME/.codex`` unchanged;
  4. closes every inherited descriptor above stderr; and
  5. execs the real command (Codex through ``codex_shim.py`` in the live condition;
     the stand-in recorder in the control).

Why these capabilities:
  * CAP_SETUID and CAP_SETGID are required. Under no_new_privs a set-user-ID bit or
    a file capability has no effect, so the agent-shell wrapper can change account
    only with capabilities it inherits; ambient capabilities are the one set that
    survives execve of an ordinary program under no_new_privs (measured here, not
    yet inside Docker).
  * CAP_SETPCAP is granted so the wrapper can empty the bounding set and leave a
    tool with all five capability sets at zero. Under no_new_privs a non-empty
    bounding set would be inert once the other four are empty, so this is defence
    in depth.

Measured residual, stated plainly: the recorder process itself, and anything it
starts WITHOUT a shell, is the recorder account and owns the records - it can
change them, exactly as Codex's in-process file editor can. Such a process also
holds CAP_SETUID and can become UID 0; without CAP_DAC_OVERRIDE that gives it root's
OWNERSHIP rights (root-owned files and directories), not a general bypass: opening
the recorder's 0600 file as UID 0 was refused with EACCES in the control. The
wrapper removes every capability, so none of this is reachable from a command that
goes through ``/bin/bash`` or ``/bin/sh``.
"""

import argparse
import os
import sys

from research.native.account_separation import capbits


def _die(message):
    sys.stderr.write("launcher: refusing to start: %s\n" % message)
    raise SystemExit(111)


def close_inherited_descriptors():
    """Close every descriptor above 2 so no transcript handle reaches the child."""
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
        soft, _ = __import__("resource").getrlimit(__import__("resource").RLIMIT_NOFILE)
        os.closerange(3, soft if soft != -1 and soft < 1 << 20 else 1 << 16)
    except Exception:
        os.closerange(3, 1 << 16)


def switch_to_recorder(uid, gid, shared_gid=2000,
                       caps=(capbits.CAP_SETGID, capbits.CAP_SETUID, capbits.CAP_SETPCAP)):
    """Perform steps 1-3. Raises OSError/SystemExit on any failure (fail closed).

    The recorder joins the shared workspace group so files it creates under
    /workspace are group-accessible to the agent and vice versa; that group has
    no access to the records filesystem (verified by the control).
    """
    capbits.set_no_new_privs()
    if capbits.get_no_new_privs() != 1:
        _die("no_new_privs was not set")
    wanted = capbits.mask(caps)
    # The caps are in our permitted set already (granted by the container). Put
    # them in the inheritable set too, then keep them across the UID switch.
    capbits.capset(wanted, wanted, wanted)
    capbits.set_keepcaps(True)
    groups = [gid] if shared_gid is None else [gid, shared_gid]
    os.setgroups(groups)
    os.setresgid(gid, gid, gid)
    os.setresuid(uid, uid, uid)
    # After the UID change the permitted set is preserved by keep-caps; re-assert
    # effective+inheritable, then raise the ambient set so they survive execve.
    capbits.capset(wanted, wanted, wanted)
    for number in caps:
        capbits.ambient_raise(number)
    # Verify the ambient set actually took (ambient raise is silently ineffective
    # if a cap is missing from permitted or inheritable).
    status = capbits.read_status()
    if int(status.get("CapAmb", "0"), 16) != wanted:
        _die("ambient capabilities did not take (CapAmb=%s)" % status.get("CapAmb"))
    if (os.getuid(), os.geteuid(), os.getgid(), os.getegid()) != (uid, uid, gid, gid):
        _die("recorder identity not fully applied")


def drop_all_to(uid, gid, shared_gid=2000):
    """Become ``uid`` with every capability set empty (bounding set included)."""
    capbits.set_no_new_privs()
    capbits.drop_bounding_set(best_effort=True)
    capbits.set_keepcaps(False)
    os.setgroups([gid] if shared_gid is None else [gid, shared_gid])
    os.setresgid(gid, gid, gid)
    os.setresuid(uid, uid, uid)
    capbits.ambient_clear_all()
    capbits.capset(0, 0, 0)
    status = capbits.read_status()
    if (os.getresuid() != (uid, uid, uid) or any(
            int(status[k], 16) for k in ("CapInh", "CapPrm", "CapEff", "CapAmb"))):
        _die("full drop to the recorder account did not take")


def recorder_environment(records_home, tool_home, extra=None, codex_home=None):
    """Build the recorder environment.

    Default layout: HOME is the records filesystem (mounted at ``/home/agent``, the
    path the existing harness uses) and CODEX_HOME is NOT set, exactly like
    ``trace_lab/cli.py``, which never sets CODEX_HOME and lets Codex find
    ``$HOME/.codex``. So Codex needs no relocation at all. ``codex_home`` is only
    for the alternative layout that moves the store elsewhere; that relies on
    Codex honouring CODEX_HOME, which is unverified for the live harness.
    """
    env = {
        "HOME": records_home,
        "PATH": "/usr/local/bin:/usr/local/sbin:/usr/sbin:/usr/bin:/sbin:/bin",
        "LANG": "C.UTF-8",
        "TMPDIR": "/tmp",
        "PYTHONDONTWRITEBYTECODE": "1",
        # Used only by the stand-in control.
        "ACCT_SEP_TOOL_HOME": tool_home,
        "ACCT_SEP_RECORDS_HOME": records_home,
        "ACCT_SEP_WORKSPACE": os.environ.get("ACCT_SEP_WORKSPACE", "/workspace"),
    }
    if codex_home:
        env["CODEX_HOME"] = codex_home
    if extra:
        env.update(extra)
    return env


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--recorder-uid", type=int, default=1000)
    parser.add_argument("--recorder-gid", type=int, default=1000)
    parser.add_argument("--records-home", default="/home/agent",
                        help="Recorder HOME: the records filesystem (holds .codex).")
    parser.add_argument("--tool-home", default="/home/tool")
    parser.add_argument("--codex-home", default=None,
                        help="Set CODEX_HOME explicitly (alternative layout only).")
    parser.add_argument("--no-capabilities", action="store_true",
                        help="Become the recorder account with NO capabilities (used for the relay, "
                             "which must run as UID 1000 but needs nothing else).")
    parser.add_argument("--pass-environment", action="store_true",
                        help="Keep the caller's environment (minus HOME) instead of the minimal "
                             "one; used by the codex shim so the gateway settings reach Codex.")
    parser.add_argument("--shared-gid", type=int, default=2000,
                        help="Shared workspace group the recorder also joins; -1 to omit.")
    parser.add_argument("--umask", default="002",
                        help="Octal umask for the recorder. Records are protected by directory "
                             "ownership, not umask; 002 lets workspace files be group-collaborative.")
    parser.add_argument("--keep-env", action="append", default=[],
                        help="Name of an environment variable to pass through unchanged.")
    parser.add_argument("command", nargs=argparse.REMAINDER,
                        help="The real command to exec, after '--'.")
    args = parser.parse_args(argv)

    command = args.command
    if command and command[0] == "--":
        command = command[1:]
    if not command:
        _die("no command supplied to exec")

    if os.geteuid() != 0:
        _die("must start as root (euid 0) inside the container")

    passthrough = {name: os.environ[name] for name in args.keep_env if name in os.environ}

    shared_gid = None if args.shared_gid < 0 else args.shared_gid
    try:
        if args.no_capabilities:
            drop_all_to(args.recorder_uid, args.recorder_gid, shared_gid)
        else:
            switch_to_recorder(args.recorder_uid, args.recorder_gid, shared_gid)
    except OSError as exc:
        _die("identity/capability transition failed: %s" % exc)

    os.umask(int(args.umask, 8))
    close_inherited_descriptors()
    env = recorder_environment(args.records_home, args.tool_home, passthrough, args.codex_home)
    if args.pass_environment:
        merged = dict(os.environ)
        merged.pop("CODEX_HOME", None)
        merged.update(env)
        if "PATH" in os.environ:
            merged["PATH"] = os.environ["PATH"]
        env = merged

    try:
        os.execvpe(command[0], command, env)
    except OSError as exc:
        _die("exec of recorder command failed: %s" % exc)


if __name__ == "__main__":
    main()
