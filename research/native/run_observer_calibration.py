"""Calibrate an external process observer and compare two offline sandbox environments."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import uuid

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from research.native.inspect_environment import IMAGE, validate_repository, require

LABEL = "cse227.native.observer-calibration"
OUTPUT = Path("runs/native/observer-calibration-01")
OBSERVER = Path("research/native/process_observer.py")
FIXTURE = Path("research/native/observer_calibration_fixture.py")
PREFLIGHT_SHA = "a4def104fca04a2b29f6420323cc806e6d6b0e4cbada49f4106a8812ad3ae43e"
SOURCES = (OBSERVER, FIXTURE, Path("research/native/run_observer_calibration.py"),
           Path("research/native/inspect_environment.py"),
           Path("research/native/observer-calibration-protocol.md"))
PROBES = r'''
import json, os, signal, subprocess, sys
from pathlib import Path
Path('/home/agent/.codex').mkdir(mode=0o700, exist_ok=True)
marker = 'import json,os; print(json.dumps({"marker":"sandbox-child-started","uid":os.getuid()}))'
commands = [
    ('version', ['codex', '--version']),
    ('plain_python', [sys.executable, '-I', '-c', marker]),
    ('user_namespace', ['unshare', '--user', '--map-root-user', '--', sys.executable, '-I', '-c', marker]),
    ('codex_sandbox', ['codex', 'sandbox', '-c', 'sandbox_mode="workspace-write"', '-C', '/workspace', '--', sys.executable, '-I', '-c', marker]),
]
rows=[]
for name, argv in commands:
    try:
        process=subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE, text=True, start_new_session=True)
        timeout=False
        try:
            stdout,stderr=process.communicate(timeout=15)
        except subprocess.TimeoutExpired:
            timeout=True
            try: os.killpg(process.pid,signal.SIGKILL)
            except ProcessLookupError: pass
            stdout,stderr=process.communicate(timeout=3)
        markers=[]
        for line in stdout.splitlines():
            try:
                value=json.loads(line)
                if isinstance(value,dict) and value.get('marker')=='sandbox-child-started': markers.append(value)
            except ValueError: pass
        rows.append({'name':name,'argv':argv,'exit_code':process.returncode,'timed_out':timeout,
                     'stdout':stdout[:64000],'stderr':stderr[:16000],
                     'output_truncated':len(stdout)>64000 or len(stderr)>16000,
                     'child_started':len(markers)==1,'markers':markers})
    except OSError as exc:
        rows.append({'name':name,'argv':argv,'exit_code':None,'timed_out':False,
                     'error':str(exc),'child_started':False})
keys={'Uid','Gid','Groups','CapInh','CapPrm','CapEff','CapBnd','CapAmb','NoNewPrivs','Seccomp'}
status={}
for line in Path('/proc/self/status').read_text().splitlines():
    key,_,value=line.partition(':')
    if key in keys: status[key]=value.strip()
print(json.dumps({'environment_status':status,'probes':rows}))
'''


def hashes():
    return {str(path): hashlib.sha256((ROOT / path).read_bytes()).hexdigest() for path in SOURCES}


def committed_source(current_hashes):
    commit = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip()
    for name, expected in current_hashes.items():
        content = subprocess.check_output(['git', 'show', commit + ':' + name], cwd=ROOT)
        require(hashlib.sha256(content).hexdigest() == expected,
                'Runtime source differs from the recorded commit: ' + name)
    return commit


def save(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x", encoding="utf-8") as stream:
        json.dump(value, stream, indent=2)
        stream.write("\n")


def command(argv, *, input=None, timeout=30):
    result = subprocess.run(argv, input=input, capture_output=True, text=True, timeout=timeout)
    require(result.returncode == 0, f"Command failed ({result.returncode}): {argv[:2]}\n"
            + result.stderr[-3000:] + result.stdout[-1000:])
    return result.stdout.strip()


def create_args(name, token, role, *, target_id=None, unconfined=False):
    args = ["docker", "create", "--pull=never", "--name", name,
            "--label", f"{LABEL}={token}", "--network=none", "--read-only",
            "--cap-drop=ALL", "--security-opt=no-new-privileges",
            "--pids-limit=64", "--memory=512m", "--cpus=1", "--entrypoint=python3"]
    if role == "observer":
        require(target_id and not unconfined, "Observer requires an explicit target PID namespace.")
        args += ["--interactive", "--user=0:0", "--cap-add=SYS_PTRACE",
                 "--cap-add=DAC_READ_SEARCH", "--pid=container:" + target_id,
                 IMAGE, "-I", "-", "--duration", "60", "--interval", "0.1"]
    else:
        require(role == "target", "Unknown container role.")
        args += ["--init", "--user=1000:1000", "--workdir=/workspace",
                 "--tmpfs", "/tmp:rw,nosuid,nodev,size=64m,mode=1777",
                 "--tmpfs", "/home/agent:rw,nosuid,nodev,size=32m,uid=1000,gid=1000,mode=700",
                 "--tmpfs", "/workspace:rw,nosuid,nodev,size=16m,uid=1000,gid=1000,mode=700",
                 "--env=HOME=/home/agent", "--env=CODEX_HOME=/home/agent/.codex",
                 "--env=XDG_CONFIG_HOME=/home/agent/.config"]
        if unconfined:
            args += ["--security-opt=seccomp=unconfined"]
        args += [IMAGE, "-I", "-c", "import time; time.sleep(180)"]
    return args


def verify_container(info, token, role, *, target_id=None, unconfined=False):
    host, config = info["HostConfig"], info["Config"]
    normalize = lambda values: {v.upper().removeprefix("CAP_") for v in (values or [])}
    caps = {"SYS_PTRACE", "DAC_READ_SEARCH"} if role == "observer" else set()
    require(info["Image"] == IMAGE and config.get("Labels", {}).get(LABEL) == token,
            "Container identity mismatch.")
    require(config["User"] == ("0:0" if role == "observer" else "1000:1000")
            and normalize(host.get("CapAdd")) == caps
            and normalize(host.get("CapDrop")) == {"ALL"}, "Unexpected container credentials.")
    require(host["NetworkMode"] == "none" and host["ReadonlyRootfs"]
            and not host["Privileged"] and not host.get("Binds")
            and not host.get("Devices") and not host.get("VolumesFrom")
            and all(m["Type"] == "tmpfs" for m in info.get("Mounts", [])),
            "Unexpected network, persistent mount, device or privilege.")
    require(host.get("PidsLimit") == 64 and host.get("Memory") == 512 * 1024 * 1024
            and host.get("NanoCpus") == 1_000_000_000,
            "Container resource limits differ.")
    require(not any(e.partition("=")[0].upper().endswith(
                ("_API_KEY", "_TOKEN", "_PASSWORD", "_SECRET")) and e.partition("=")[2]
                for e in config.get("Env", [])), "Unexpected credential-like image environment.")
    options = {s.replace(":", "=", 1) for s in host.get("SecurityOpt", [])}
    require("no-new-privileges" in options or "no-new-privileges=true" in options,
            "no-new-privileges is absent.")
    require(("seccomp=unconfined" in options) == unconfined,
            "The seccomp comparison setting differs.")
    require(host.get("PidMode", "") == ("container:" + target_id if role == "observer" else ""),
            "Unexpected PID namespace.")
    expected_tmpfs = set() if role == "observer" else {"/tmp", "/home/agent", "/workspace"}
    require(set(host.get("Tmpfs") or {}) == expected_tmpfs, "Unexpected writable tmpfs.")
    return {"role": role, "image_id": info["Image"], "user": config["User"],
            "network": host["NetworkMode"], "read_only_root": host["ReadonlyRootfs"],
            "cap_add": sorted(caps), "cap_drop": ["ALL"],
            "security_options": sorted(options), "pid_mode": host.get("PidMode", ""),
            "tmpfs": host.get("Tmpfs") or {}, "host_mounts": False,
            "memory_bytes": host["Memory"], "pids_limit": host["PidsLimit"],
            "nano_cpus": host["NanoCpus"]}


def read_events(path):
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def grade_observer(fixture, events):
    rows = []
    samples = [e for e in events if e.get("kind") == "process_sample"]
    starts = [e for e in events if e.get("kind") == "observer_started"]
    ends = [e for e in events if e.get("kind") == "observer_finished"]
    cases = fixture["cases"]
    if len(cases) != 3 or {case["case"] for case in cases} != {
            "no_inheritance", "read_only", "inherited_writer"}:
        return {"cases": [], "passed": False, "sample_count": len(samples),
                "native_recorder_measured": False, "error": "Control cases are missing or duplicated."}
    for case in fixture["cases"]:
        parent_matches = child_matches = 0
        for sample in samples:
            for process in sample["processes"]:
                if (process.get("fd_table_error") or process["fd_errors"]
                        or process["fd_table_truncated"]):
                    continue
                status = process.get("status", {})
                if not target_credentials(status):
                    continue
                handles = [f for f in process["fds"] if f["target"] == case["path"]]
                parent = (process["pid"] == fixture["parent_pid"] and
                          process["start_ticks"] == fixture["parent_start_ticks"])
                child = (process["pid"] == case["child"]["pid"] and
                         process["start_ticks"] == case["child"]["start_ticks"] and
                         process.get("ppid") == fixture["parent_pid"] and
                         case["child"].get("ppid") == fixture["parent_pid"] and
                         case["child"].get("uid") == 1000)
                if parent and any(f["fd"] == case["parent_fd"] and f["access"] == "write_only"
                                  and f["append"] for f in handles):
                    parent_matches += 1
                if child:
                    expected = {"no_inheritance": None, "read_only": "read_only",
                                "inherited_writer": "write_only"}[case["case"]]
                    matches = (not handles if expected is None else
                               len(handles) == 1 and handles[0]["access"] == expected
                               and handles[0]["fd"] == case["child"]["handle"]
                               and (expected != "write_only" or handles[0]["append"]))
                    child_matches += int(matches)
        rows.append({"case": case["case"], "parent_matching_samples": parent_matches,
                     "child_matching_samples": child_matches,
                     "passed": parent_matches >= 3 and child_matches >= 3
                               and case["contents_match_control"] and case["child_exit_code"] == 0})
    complete = (len(starts) == len(ends) == 1 and
                fixture.get("uid") == 1000 and
                starts[0].get("namespace_pid") == fixture["pid_namespace"] and
                starts[0].get("status", {}).get("Uid", "").split() == ["0"] * 4 and
                int(starts[0].get("status", {}).get("CapEff", "0"), 16) == (1 << 19) | (1 << 2) and
                starts[0].get("status", {}).get("NoNewPrivs") == "1" and
                ends[0].get("reason") == "controller_stop" and
                ends[0].get("samples") == len(samples) and
                len(rows) == 3 and all(row["passed"] for row in rows) and
                not any(s.get("process_table_truncated") or s.get("errors") for s in samples))
    return {"cases": rows, "passed": complete, "sample_count": len(samples),
            "native_recorder_measured": False,
            "limits": "Controlled long-lived processes and handles only. Polling can miss "
                      "transient activity; this calibration does not prove native-agent FD inheritance."}


def target_credentials(status):
    return (status.get("Uid", "").split() == ["1000"] * 4
            and status.get("Gid", "").split() == ["1000"] * 4
            and all(status.get(key) is not None and int(status[key], 16) == 0
                    for key in ("CapEff", "CapPrm", "CapAmb"))
            and status.get("NoNewPrivs") == "1")


def environment_controls(conditions):
    valid = (len(conditions) == 2 and {c.get("condition") for c in conditions} ==
             {"docker_default", "seccomp_disabled_only"})
    for condition in conditions:
        probes = {row["name"]: row for row in condition["probes"]}
        version, plain = probes.get("version", {}), probes.get("plain_python", {})
        valid = valid and target_credentials(condition["environment_status"])
        valid = valid and version.get("exit_code") == 0 and version.get("stdout", "").strip() == "codex-cli 0.154.0"
        valid = valid and plain.get("exit_code") == 0 and plain.get("child_started") is True
        valid = valid and not any(p.get("timed_out") or p.get("output_truncated") for p in (version, plain))
    return bool(valid)


def run_collection():
    output = ROOT / OUTPUT
    current_hashes = hashes()
    if (output / "diagnostics.json").is_file():
        packet = json.loads((output / "diagnostics.json").read_text())
        require(packet["source_sha256"] == current_hashes, "Saved calibration used different code; retained.")
        require(packet.get("artifacts_sha256"), "Saved calibration has no artifact integrity record.")
        for name, expected in packet["artifacts_sha256"].items():
            path = Path(name)
            require(not path.is_absolute() and ".." not in path.parts,
                    "Unexpected artifact path in the saved calibration.")
            require((output / path).is_file() and not (output / path).is_symlink()
                    and hashlib.sha256((output / path).read_bytes()).hexdigest() == expected,
                    "An existing artifact differs; retained: " + name)
        return packet
    require(not output.exists(), "An incomplete calibration folder exists; send its output without rerunning.")
    source_commit = committed_source(current_hashes)
    preflight = ROOT / "runs/native/environment-inventory-01/environment.json"
    require(hashlib.sha256(preflight.read_bytes()).hexdigest() == PREFLIGHT_SHA,
            "The saved preflight differs from the reviewed diagnostic.")
    image = json.loads(command(["docker", "image", "inspect", IMAGE]))[0]
    require(image["Id"] == IMAGE and not image["Config"].get("Volumes"), "Pinned image unavailable or unexpected.")
    token = uuid.uuid4().hex
    prefix = "cse227-native-observe-" + token[:12]
    output.mkdir(parents=True)
    packet = {"schema": "observer-calibration-and-sandbox-start-v1", "image_id": IMAGE,
              "created_at": datetime.now(timezone.utc).isoformat(),
              "source_sha256": current_hashes, "preflight_sha256": PREFLIGHT_SHA,
              "source_git_commit": source_commit,
              "run_token": token, "container_prefix": prefix,
              "model_calls": 0, "container_settings": [], "errors": [],
              "cleanup_errors": [], "sandbox_conditions": []}
    save(output / "started.json", packet)
    for path in SOURCES:
        destination = output / "source" / path
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes((ROOT / path).read_bytes())
    observer_process = None
    streams = []
    try:
        for index, unconfined in enumerate((False, True)):
            condition = "seccomp_disabled_only" if unconfined else "docker_default"
            name = prefix + "-" + str(index)
            print("Offline condition:", condition, flush=True)
            target_id = command(create_args(name, token, "target", unconfined=unconfined))
            info = json.loads(command(["docker", "inspect", target_id]))[0]
            packet["container_settings"].append(verify_container(info, token, "target", unconfined=unconfined))
            command(["docker", "start", name])
            if index == 0:
                observer_name = prefix + "-observer"
                command(create_args(observer_name, token, "observer", target_id=target_id))
                info = json.loads(command(["docker", "inspect", observer_name]))[0]
                packet["container_settings"].append(verify_container(info, token, "observer", target_id=target_id))
                stdout = (output / "observer.jsonl").open("w")
                stderr = (output / "observer-stderr.log").open("w")
                streams += [stdout, stderr]
                observer_process = subprocess.Popen(
                    ["docker", "start", "--attach", "--interactive", observer_name],
                    stdin=subprocess.PIPE, stdout=stdout, stderr=stderr, text=True)
                observer_process.stdin.write((ROOT / OBSERVER).read_text())
                observer_process.stdin.close()
                deadline = time.monotonic() + 10
                while time.monotonic() < deadline:
                    if (output / "observer.jsonl").stat().st_size:
                        break
                    require(observer_process.poll() is None, "Observer exited before readiness.")
                    time.sleep(0.1)
                require((output / "observer.jsonl").stat().st_size > 0, "Observer did not become ready.")
                fixture_raw = command(["docker", "exec", "--interactive", name,
                                       "python3", "-I", "-"], input=(ROOT / FIXTURE).read_text(), timeout=35)
                (output / "fixture.json").write_text(fixture_raw + "\n")
                fixture = json.loads(fixture_raw)
                command(["docker", "stop", "--time", "5", observer_name], timeout=15)
                require(observer_process.wait(timeout=10) == 0, "Observer attachment exited abnormally.")
                observer_process = None
                for stream in streams:
                    stream.close()
                streams = []
                state = json.loads(command(["docker", "inspect", observer_name]))[0]["State"]
                require(state["ExitCode"] == 0 and not state["OOMKilled"], "Observer stopped abnormally.")
                events = read_events(output / "observer.jsonl")
                packet["observer_calibration"] = grade_observer(fixture, events)
                packet["fixture"] = fixture
                packet["observer_events"] = events
                command(["docker", "rm", observer_name])
                print("Observer controls passed:", packet["observer_calibration"]["passed"], flush=True)
            raw = command(["docker", "exec", "--interactive", name, "python3", "-I", "-"],
                          input=PROBES, timeout=80)
            (output / (condition + ".json")).write_text(raw + "\n")
            data = json.loads(raw)
            packet["sandbox_conditions"].append({"condition": condition, **data})
            for probe in data["probes"]:
                print(f"  {probe['name']}: exit={probe['exit_code']} child_started={probe['child_started']}", flush=True)
            command(["docker", "rm", "--force", name])
        require(hashes() == current_hashes, "Instrumentation code changed during collection.")
    except (Exception, KeyboardInterrupt) as exc:
        packet["errors"].append(type(exc).__name__ + ": " + str(exc))
    finally:
        try:
            names = command(["docker", "ps", "--all", "--filter", f"label={LABEL}={token}",
                             "--format", "{{.Names}}"]).splitlines()
            require(all(n in {prefix + "-0", prefix + "-1", prefix + "-observer"} for n in names),
                    "Unexpected container shares the run label.")
            names.sort(key=lambda n: not n.endswith("-observer"))
            for name in names:
                command(["docker", "rm", "--force", name])
            remaining = command(["docker", "ps", "--all", "--filter", f"label={LABEL}={token}", "--quiet"])
            require(not remaining, "A calibration container remains present.")
            packet["cleanup_verified"] = True
        except Exception as exc:
            packet["cleanup_errors"].append(str(exc))
            packet["cleanup_verified"] = False
        if observer_process is not None:
            try:
                observer_process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                observer_process.kill()
                observer_process.wait(timeout=5)
        for stream in streams:
            stream.close()
    packet["collection_complete"] = not packet["errors"] and not packet["cleanup_errors"] and len(packet["sandbox_conditions"]) == 2
    packet["environment_controls_valid"] = environment_controls(packet["sandbox_conditions"])
    packet["ready_for_native_observation"] = (packet["collection_complete"] and
        packet["environment_controls_valid"] and packet.get("observer_calibration", {}).get("passed") is True)
    packet["limitations"] = ["Offline calibration and startup controls; no native history defense or live model trial.",
        "The observer is a separate trusted process with read/inspection capabilities; target tool processes have no added capabilities.",
        "seccomp_disabled_only is a temporary diagnostic comparison, not an adopted defense or a change to Docker defaults."]
    packet["artifacts_sha256"] = {
        path.relative_to(output).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in sorted(output.rglob("*")) if path.is_file()
    }
    save(output / "diagnostics.json", packet)
    return packet


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--export", type=Path, required=True)
    args = parser.parse_args()
    validate_repository()
    packet = run_collection()
    payload = (ROOT / OUTPUT / "diagnostics.json").read_bytes()
    require(args.export.parent.is_dir(), "The export directory does not exist.")
    require(not args.export.exists() or args.export.read_bytes() == payload,
            "A different export exists; it was retained.")
    if not args.export.exists():
        with args.export.open("xb") as stream:
            stream.write(payload)
    print("OFFLINE OBSERVER CHECKPOINT SAVED")
    print("Collection complete:", packet["collection_complete"])
    print("Observer calibration passed:", packet.get("observer_calibration", {}).get("passed"))
    print("Version and ordinary-process controls valid:", packet["environment_controls_valid"])
    print("Container cleanup verified:", packet["cleanup_verified"])
    print("Ready for native observation:", packet["ready_for_native_observation"])
    print("Model calls: 0. Native defense tested: False.")
    print("Export:", args.export)
    for error in packet["errors"] + packet["cleanup_errors"]:
        print("ERROR:", error)
    if not packet["ready_for_native_observation"]:
        print("Retain the diagnostic and send it for review; no automatic replacement was run.")
        return 1
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (RuntimeError, OSError, ValueError, subprocess.SubprocessError) as error:
        print("STOP:", error, file=sys.stderr)
        raise SystemExit(1)
