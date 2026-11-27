#!/usr/local/bin/python3 -IS
"""Installed as ``/usr/local/bin/codex`` in the derived image (real CLI: codex.real).

The frozen harness starts Codex with ``docker exec <agent> ... codex ...`` and no
``--user``; in the condition container that is root. This shim keeps the recorded
native argv byte-identical while making the process that actually runs Codex the
recorder account (UID 1000): as root it execs the launcher, which hands on the ambient
capabilities, switches to the recorder and execs the real CLI with the caller's
environment (gateway settings) and ``HOME=/home/agent``. Any other caller - the
recorder itself or a tool - gets the real CLI directly, unchanged.

It is a Python script, not a shell script, because every shell in the image is the
agent-shell wrapper. Not executed in the research sandbox (no Codex binary).
"""
import os
import sys

REAL = "/usr/local/bin/codex.real"
PYTHON = "/usr/local/bin/python3"
PACKAGE_ROOT = "/opt/trace-lab"


def command(argv, euid):
    if euid != 0:
        return REAL, ["codex", *argv]
    return PYTHON, [PYTHON, "-m", "research.native.account_separation.launcher",
                    "--pass-environment", "--records-home", "/home/agent",
                    "--tool-home", "/home/tool", "--", REAL, *argv]


if __name__ == "__main__":
    program, arguments = command(sys.argv[1:], os.geteuid())
    environment = dict(os.environ)
    if os.geteuid() == 0:
        environment["PYTHONPATH"] = PACKAGE_ROOT
    os.execve(program, arguments, environment)
