"""A fake ``docker`` executable for the dispatch orchestration tests. NOT Docker.

It records every argv, keeps containers in a JSON state file, builds
``docker inspect`` output from the ``docker run`` argv it was given, and answers
the fixture-feeding ``docker exec`` with a canned session JSON. Faults are injected
with FAKE_DOCKER_FAULT. It proves nothing about Docker; it exercises orchestration.
"""

import json
import os
from pathlib import Path
import stat
import sys

ROOT = Path(__file__).resolve().parents[1]

FAKE = r'''#!__PYTHON__ -I
import json, os, sys, time

STATE = os.environ["FAKE_DOCKER_STATE"]
LOG = os.environ["FAKE_DOCKER_LOG"]
FAULT = set(filter(None, os.environ.get("FAKE_DOCKER_FAULT", "").split(",")))
IMAGE_IDS = {"sha256:eddc3b1939fb346372fe8e6aa2806f1bb03696867704f3e70143e12492115aa5":
             "sha256:eddc3b1939fb346372fe8e6aa2806f1bb03696867704f3e70143e12492115aa5",
             "trace-lab-account-separation:derived": "sha256:" + "d" * 64}
PIN = "3188814c35471432d4123203e0eb38e5bddc60226e3d7ddf0e59e649ea140022"
# As in the real images, the launcher on PATH and the native executable are different
# files with different digests.  The first real preflight failed because this helper
# used to answer the native pin for the launcher path.
LAUNCHER_PIN = "61b0194f3bb6534439c8d26a3ed57d0805f84b884588b761795323eeb92fcf70"
NATIVE = "/usr/local/lib/node_modules/@openai/codex/node_modules/@openai/codex-linux-x64/vendor/x86_64-unknown-linux-musl/bin/codex"
ARITY = {"--name", "--label", "--user", "--cap-add", "--cap-drop", "--security-opt", "--network",
         "--mount", "--tmpfs", "--pids-limit", "--memory", "--cpus", "--env", "--workdir",
         "--entrypoint", "--format", "--filter"}


def load():
    try:
        return json.load(open(STATE))
    except (OSError, ValueError):
        return {"containers": {}}


def save(state):
    json.dump(state, open(STATE, "w"))


def parse(args):
    opts, rest, i = {}, [], 0
    while i < len(args):
        a = args[i]
        if a.startswith("--") and "=" in a and a.split("=")[0] in ARITY:
            k, v = a.split("=", 1)
            opts.setdefault(k, []).append(v)
        elif a in ARITY:
            opts.setdefault(a, []).append(args[i + 1]); i += 1
        elif a.startswith("-") and a != "-" and not rest and a not in ("--rm", "--init", "--read-only", "--detach", "--interactive"):
            opts.setdefault(a, []).append(True)
        elif a in ("--rm", "--init", "--read-only", "--detach"):
            opts.setdefault(a, []).append(True)
        elif a == "-i" or a == "--interactive":
            opts.setdefault("-i", []).append(True)
        else:
            rest = args[i:]; break
        i += 1
    return opts, rest


def canned_session(profile):
    standin = profile == "account_separation"
    if profile == "full_access":
        removal, resume, uid, match = "unlinked", "missing_rollout_diagnostic", "0", True
    else:
        removal, resume, uid, match = "denied:EACCES", "ok", "1002", True
    return {"schema": "account-separation-dispatch-session-v1", "profile": profile,
            "interpretable": "fixture_uninterpretable" not in FAULT,
            "removal": {"outcome": removal}, "resume": {"outcome": resume},
            "tool_identity": {"value": "holds", "uid": uid},
            "ancestor_fd": {"any_listing_refused": profile == "account_separation"},
            "history_extended": True, "positive_control_marker_append": True,
            "matches_expectations": {"all": match}}


def inspect(name, entry):
    opts = entry["opts"]
    tmpfs = {}
    for value in opts.get("--tmpfs", []):
        dest = value.split(":", 1)[0]
        tmpfs[dest] = value.split(":", 1)[1] if ":" in value else ""
    user = (opts.get("--user", ["1000:1000"]) or ["1000:1000"])[0]
    caps = list(opts.get("--cap-add", []))
    return {"Id": "id-" + name, "Image": entry["image"],
            "Config": {"User": user, "Cmd": entry["cmd"],
                       "Labels": dict(v.split("=", 1) for v in opts.get("--label", []))},
            "HostConfig": {"CapAdd": caps, "CapDrop": opts.get("--cap-drop", []),
                           "SecurityOpt": opts.get("--security-opt", []),
                           "ReadonlyRootfs": "--read-only" in opts, "Privileged": False,
                           "NetworkMode": (opts.get("--network", ["default"]) or ["default"])[0],
                           "Tmpfs": tmpfs, "Binds": None, "Devices": [], "VolumesFrom": None, "PidMode": ""}}


def main():
    args = sys.argv[1:]
    open(LOG, "a").write(json.dumps(args) + "\n")
    cmd = args[0]
    if cmd == "image":
        _, names = parse(args[1:])
        target = names[1] if len(names) > 1 else names[0]
        if target not in IMAGE_IDS and "image_absent" in FAULT:
            sys.stderr.write("No such image\n"); return 1
        print(IMAGE_IDS.get(target, target)); return 0
    if cmd == "run":
        opts, tail = parse(args[1:])
        if "--rm" in opts:
            # preflight sha / wrapper probes
            if opts.get("--entrypoint", [None])[0] == "sha256sum":
                path = tail[-1]
                if "bad_sha" in FAULT:
                    print("0000 " + path)
                elif "bad_launcher_sha" in FAULT and path in ("/usr/local/bin/codex", "/usr/local/bin/codex.real"):
                    print("1111 " + path)
                elif path == NATIVE:
                    print(PIN + "  " + path)
                elif path in ("/usr/local/bin/codex", "/usr/local/bin/codex.real"):
                    print(LAUNCHER_PIN + "  " + path)
                elif path == "/bin/bash":
                    print("aaaa  /bin/bash")
                else:
                    print("bbbb  " + path)
                return 0
            return 0
        name = opts["--name"][0]
        state = load()
        state["containers"][name] = {"opts": opts, "image": tail[0], "cmd": tail[1:]}
        save(state)
        print("id-" + name); return 0
    if cmd == "inspect":
        state = load()
        name = args[-1]
        if name not in state["containers"]:
            sys.stderr.write("No such object\n"); return 1
        print(json.dumps([inspect(name, state["containers"][name])])); return 0
    if cmd == "exec":
        opts, tail = parse(args[1:])
        # tail: <name> <command...>
        name = tail[0]
        inner = tail[1:]
        if "init-layout" in inner:
            return 0
        if "exec_fail" in FAULT:
            sys.stderr.write("exec failed\n"); return 7
        # the fixture feed: determine profile from the args after the trailing '-'
        profile = None
        for value in ("full_access", "workspace", "account_separation"):
            if value in inner:
                profile = value; break
        sys.stdin.read()
        print(json.dumps(canned_session(profile or "full_access"))); return 0
    if cmd == "ps":
        opts, _ = parse(args[1:])
        state = load()
        print("\n".join(state["containers"])); return 0
    if cmd == "rm":
        opts, names = parse(args[1:])
        state = load()
        for n in names:
            state["containers"].pop(n, None)
        save(state); return 0
    if cmd == "version":
        print("fake"); return 0
    sys.stderr.write("unsupported %s\n" % cmd); return 64


sys.exit(main())
'''


def install(directory, fault=""):
    directory = Path(directory)
    binary = directory / "bin"
    binary.mkdir(parents=True, exist_ok=True)
    script = binary / "docker"
    script.write_text(FAKE.replace("__PYTHON__", sys.executable))
    script.chmod(script.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    env = dict(os.environ, PATH=str(binary) + os.pathsep + os.environ.get("PATH", ""),
               FAKE_DOCKER_STATE=str(directory / "state.json"),
               FAKE_DOCKER_LOG=str(directory / "argv.jsonl"), FAKE_DOCKER_FAULT=fault,
               PYTHONPATH=str(ROOT))
    return env


def calls(env):
    path = Path(env["FAKE_DOCKER_LOG"])
    return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []


def state(env):
    try:
        return json.loads(Path(env["FAKE_DOCKER_STATE"]).read_text())
    except (OSError, ValueError):
        return {"containers": {}}
