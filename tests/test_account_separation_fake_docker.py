"""A fake ``docker`` executable for the account-separation orchestration tests.

There is no Docker daemon where these tests run, so the orchestration code is
driven against this stand-in placed first on PATH. It is NOT evidence about
Docker: it records every argv, keeps containers and volumes in a JSON state file,
builds ``docker inspect`` output from the ``docker run`` argv it was given, and
answers the in-container steps with the measurements of the executed LOCAL control
(``executed-local-control.json``). Faults are injected with FAKE_DOCKER_FAULT.

``install(directory)`` writes the executable and returns the environment to use.
"""

import json
import os
from pathlib import Path
import stat
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
EVIDENCE = ROOT / "research/native/account_separation/executed-local-control.json"

FAKE = r'''#!__PYTHON__ -I
import fcntl, json, os, sys, time

STATE, LOG = os.environ["FAKE_DOCKER_STATE"], os.environ["FAKE_DOCKER_LOG"]
FAULT = set(filter(None, os.environ.get("FAKE_DOCKER_FAULT", "").split(",")))
CANNED = os.environ.get("FAKE_DOCKER_CANNED")
IMAGE_IDS = {"derived:test": "sha256:" + "d" * 64}
ARITY1 = {"--uid", "--duration", "--interval", "--name", "--label", "--user", "--cap-add", "--cap-drop", "--security-opt", "--network",
          "--mount", "--tmpfs", "--pids-limit", "--memory", "--cpus", "--env", "--workdir",
          "--entrypoint", "--hostname", "--time", "--format", "--filter", "--driver", "--opt"}


class Locked:
    def __enter__(self):
        self.handle = open(STATE + ".lock", "w")
        fcntl.flock(self.handle, fcntl.LOCK_EX)
        try:
            self.state = json.load(open(STATE))
        except (OSError, ValueError):
            self.state = {"containers": {}, "volumes": {}}
        return self.state
    def __exit__(self, *exc):
        json.dump(self.state, open(STATE, "w"))
        self.handle.close()


def parse(args):
    options, rest, index = {}, [], 0
    while index < len(args):
        item = args[index]
        if item.startswith("--") and "=" in item and item.split("=")[0] in ARITY1:
            key, value = item.split("=", 1)
            options.setdefault(key, []).append(value)
        elif item in ARITY1:
            options.setdefault(item, []).append(args[index + 1])
            index += 1
        elif item.startswith("-") and not rest:
            options.setdefault(item, []).append(True)
        else:
            rest = args[index:]
            break
        index += 1
    return options, rest


def canned(scenario):
    data = json.load(open(CANNED))
    for run in data["runs"][:1]:
        for value in (run["main_read_only"], run["main_no_access"], *run["negative_controls"].values()):
            if value["scenario"].get("scenario") == scenario:
                return value["scenario"]
    raise SystemExit("fake docker: no canned scenario " + scenario)


def arg(command, name, default=None):
    return command[command.index(name) + 1] if name in command else default


def module_output(command, counters):
    """Answer a docker_scenario invocation from the executed local measurements."""
    action = command[command.index("research.native.account_separation.docker_scenario") + 1]
    if action == "seal-harness":
        entries = [{"path": "/home/agent/shared", "why": "world"}] if "seal_leaves_agent_entry" in FAULT else []
        return json.dumps({"home": "/home/agent", "geometry": arg(command, "--geometry"),
                           "auth": {"uid": 1000, "gid": 1000, "mode": 0o600},
                           "condition_changes": [{"path": "/home/agent/.codex", "mode_before": 0o700, "mode_after": 0o755}],
                           "home_root": {"uid": 1000, "gid": 1000, "mode": 0o755},
                           "tool_can_traverse_home": True, "tool_writable_entries": entries})
    if action == "init-layout":
        return json.dumps({"records_home": arg(command, "--records-home"), "geometry": arg(command, "--geometry"),
                           "records_root_owner": int(arg(command, "--records-root-owner"))})
    scenario = canned(arg(command, "--scenario"))
    if action == "snapshot":
        key = "snap:" + arg(command, "--scenario")
        counters[key] = counters.get(key, 0) + 1
        return json.dumps(scenario["snapshot_after_init" if counters[key] == 1 else "snapshot_after_resume"])
    kind = command[command.index("step") + 1]
    if kind == "init":
        step = {"step": "init", "launcher_rc": scenario.get("launcher_rc"), "launcher_stderr": ""}
        if "init" in scenario:
            step["result"] = scenario["init"]
        else:
            step["result_error"] = scenario.get("init_result_error", "missing")
    elif kind == "resume":
        step = {"step": "resume", "launcher_rc": scenario.get("resume_launcher_rc")}
        if "resume" in scenario:
            step["result"] = scenario["resume"]
        else:
            step["result_error"] = scenario.get("resume_error", "missing")
    else:
        created = scenario.get("new_session_created")
        step = {"step": "new", "launcher_rc": scenario.get("new_session_rc"),
                "result": {"rollout_path": "/home/agent/.codex/sessions/x.jsonl", "errors": []}
                if created else {"errors": ["OSError: [Errno 28] No space left on device"]}}
    return json.dumps(step)


def status_text(command):
    """/proc/self/status as the launcher (recorder), the relay account or a tool would print it."""
    tool = "/bin/bash" in command or "/bin/sh" in command
    plain = "--no-capabilities" in command
    uid = "1002" if tool else "1000"
    if not tool and "self_check_recorder_root" in FAULT:
        uid = "0"
    if tool and "self_check_tool_is_recorder" in FAULT:
        uid = "1000"
    caps = "0000000000000000" if tool or plain else "00000000000001c0"
    if not tool and not plain and "smoke_no_ambient" in FAULT:
        caps = "0000000000000000"
    return ("Uid:\t%s\nGid:\t%s\nGroups:\t2000\nCapInh:\t%s\nCapPrm:\t%s\nCapEff:\t%s\n"
            "CapBnd:\t%s\nCapAmb:\t%s\nNoNewPrivs:\t1" % (
                "\t".join([uid] * 4), "\t".join([uid] * 4), caps, caps, caps, caps, caps))


def inspect(name, entry):
    options = entry["options"]
    mounts = []
    for value in options.get("--mount", []):
        fields = dict(part.split("=", 1) if "=" in part else (part, True) for part in value.split(","))
        mounts.append({"Type": fields["type"], "Name": fields.get("src"), "Destination": fields["dst"],
                       "RW": "readonly" not in fields})
    tmpfs = dict(value.split(":", 1) if ":" in value else (value, "") for value in options.get("--tmpfs", []))
    caps = list(options.get("--cap-add", []))
    if "inspect_extra_cap" in FAULT and name.endswith("-main"):
        caps.append("DAC_OVERRIDE")
    number = lambda key, scale: int(float(options[key][0].rstrip("gm")) * scale(options[key][0])) if key in options else 0
    memory = number("--memory", lambda v: 1024 ** 3 if v.endswith("g") else 1024 ** 2)
    return {"Id": "id-" + name, "Name": "/" + name, "Image": IMAGE_IDS.get(entry["image"], entry["image"]),
            "Config": {"User": options.get("--user", [""])[0], "Cmd": entry["command"],
                       "Env": options.get("--env", []),
                       "Labels": dict(v.split("=", 1) for v in options.get("--label", []))},
            "HostConfig": {"CapAdd": caps, "CapDrop": options.get("--cap-drop", []),
                           "SecurityOpt": options.get("--security-opt", []),
                           "ReadonlyRootfs": "--read-only" in options, "Privileged": False,
                           "NetworkMode": options.get("--network", ["default"])[0],
                           "Binds": None, "Devices": [], "VolumesFrom": None, "PidMode": "",
                           "Tmpfs": tmpfs, "Memory": memory, "PidsLimit": int(options.get("--pids-limit", ["0"])[0]),
                           "NanoCpus": int(float(options.get("--cpus", ["0"])[0]) * 1e9)},
            "Mounts": mounts, "State": {"ExitCode": 0, "OOMKilled": False}, "AppArmorProfile": ""}


def matching(items, filters):
    label = next((f.split("=", 1)[1] for f in filters if f.startswith("label=")), None)
    return [name for name, value in items.items() if label is None or label in value["labels"]]


def main():
    args = sys.argv[1:]
    with open(LOG, "a") as log:
        log.write(json.dumps(args) + "\n")
    command, rest = args[0], args[1:]
    if command == "version":
        print("27.0.0-fake"); return 0
    if command == "image":
        options, names = parse(rest[1:])
        if names[0] not in IMAGE_IDS and not names[0].startswith("sha256:"):
            sys.stderr.write("No such image: %s\n" % names[0]); return 1
        fmt = options.get("--format", [""])[0]
        print("null" if "Labels" in fmt else IMAGE_IDS.get(names[0], names[0])); return 0
    if command == "volume":
        sub, tail = rest[0], rest[1:]
        options, names = parse(tail)
        with Locked() as state:
            if sub == "create":
                state["volumes"][names[0]] = {"labels": options.get("--label", [])}
                print(names[0])
            elif sub == "ls":
                print("\n".join(matching(state["volumes"], options.get("--filter", []))))
            elif sub == "rm":
                if "volume_rm_fail" in FAULT:
                    sys.stderr.write("volume is in use\n"); return 1
                state["volumes"].pop(names[0], None)
        return 0
    if command in ("run", "create"):
        options, tail = parse(rest)
        if "--rm" in options:
            if "research.native.account_separation.launcher" in tail:
                print(status_text(tail))
            return 0
        name = options["--name"][0]
        with Locked() as state:
            state["containers"][name] = {"options": options, "image": tail[0], "command": tail[1:],
                                         "labels": options.get("--label", []), "counters": {}}
        print("id-" + name); return 0
    if command == "inspect":
        with Locked() as state:
            if rest[-1] not in state["containers"]:
                sys.stderr.write("No such object\n"); return 1
            print(json.dumps([inspect(rest[-1], state["containers"][rest[-1]])]))
        return 0
    if command == "wait":
        print("3" if "init_exit" in FAULT and rest[-1].endswith("-init") else "0"); return 0
    if command == "logs":
        options, names = parse(rest)
        name = names[0]
        with Locked() as state:
            entry = state["containers"].get(name)
            keeper = next((v for k, v in state["containers"].items() if k.endswith("-keeper")), entry)
            text = ""
            if entry and "research.native.account_separation.docker_scenario" in entry["command"]:
                text = module_output(entry["command"], keeper["counters"])
        if "--follow" in options:
            banner = {"observer": json.dumps({"kind": "ready", "seq": 1}), "gateway": "gateway ready",
                      "agent": "relay ready"}.get(name.rsplit("-", 1)[-1], "")
            print(banner, flush=True)
            while True:
                with Locked() as state:
                    if name not in state["containers"]:
                        return 0
                time.sleep(0.05)
        print(text); return 0
    if command == "exec":
        options, tail = parse(rest)
        name, inner = tail[0], tail[1:]
        if "slow_step" in FAULT:
            time.sleep(30)
        if "research.native.account_separation.docker_scenario" in inner:
            if "step_exit" in FAULT:
                sys.stderr.write("OCI runtime exec failed\n"); return 7
            if "step_missing" in FAULT:
                return 0
            with Locked() as state:
                print(module_output(inner, state["containers"][name]["counters"]))
            return 0
        if inner[-1:] == ["--version"]:
            print("codex-cli 0.154.0"); return 0
        if any("native_clock_instrumentation" in item for item in inner):
            import base64
            sys.stdin.buffer.read()
            line = json.dumps({"type": "thread.started", "thread_id": "fake-session-0001"}) + "\n"
            for row in ({"kind": "started", "pid": 41, "supervisor_pid": 40},
                        {"kind": "stdout", "data_b64": base64.b64encode(line.encode()).decode()},
                        {"kind": "exited", "pid": 41, "returncode": 0, "signal": None,
                         "output_drained": True}):
                print(json.dumps(dict(row, observed_ns=time.time_ns(), monotonic_ns=time.monotonic_ns())))
            return 0
        if "research.native.account_separation.launcher" in inner:
            if inner[-3:-1] == ["-I", "-c"] and "wrapper-audit" in inner[-1]:
                pass
            print(status_text(inner)); return 0
        if "wrapper-audit" in inner[-1]:
            print(os.environ.get("FAKE_DOCKER_AUDIT", ""), end=""); return 0
        if "shutil.which" in inner[-1]:
            print("/usr/local/bin/codex"); return 0
        if "os.path.exists" in inner[-1]:
            print("True"); return 0
        if "readlink" in inner[-1]:
            print("pid:[4026531836]"); return 0
        reply = os.environ.get("FAKE_DOCKER_EXEC_REPLY")
        if reply:
            print(reply)
        return 0
    if command == "ps":
        options, _ = parse(rest)
        with Locked() as state:
            print("\n".join(matching(state["containers"], options.get("--filter", []))))
        return 0
    if command in ("rm", "stop", "kill"):
        options, names = parse(rest)
        if command == "rm":
            with Locked() as state:
                for name in names:
                    state["containers"].pop(name, None)
        return 0
    sys.stderr.write("fake docker: unsupported command %s\n" % command)
    return 64


sys.exit(main())
'''


def install(directory, fault=""):
    """Write the fake into ``directory`` and return an environment that uses it."""
    directory = Path(directory)
    binary = directory / "bin"
    binary.mkdir(parents=True, exist_ok=True)
    script = binary / "docker"
    script.write_text(FAKE.replace("__PYTHON__", sys.executable))
    script.chmod(script.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    env = dict(os.environ, PATH=str(binary) + os.pathsep + os.environ.get("PATH", ""),
               FAKE_DOCKER_STATE=str(directory / "state.json"),
               FAKE_DOCKER_LOG=str(directory / "argv.jsonl"),
               FAKE_DOCKER_CANNED=str(EVIDENCE), FAKE_DOCKER_FAULT=fault, PYTHONPATH=str(ROOT))
    return env


def calls(env):
    path = Path(env["FAKE_DOCKER_LOG"])
    return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []


def state(env):
    try:
        return json.loads(Path(env["FAKE_DOCKER_STATE"]).read_text())
    except (OSError, ValueError):
        return {"containers": {}, "volumes": {}}


class FakeDockerSelfTest(unittest.TestCase):
    def test_fake_is_labelled_as_a_stand_in(self):
        self.assertIn("NOT evidence about", __doc__)
