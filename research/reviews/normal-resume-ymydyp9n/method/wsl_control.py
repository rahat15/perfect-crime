"""Collect ordinary Codex resume controls in the two images verified by Step 5.
Each trial uses a fixed text-only local responder and a fresh Docker container.
No audit-loss trial is executed.
"""
import argparse
from datetime import datetime, timezone
from hashlib import sha256
import json
from pathlib import Path
import subprocess
import sys
import tempfile
from zipfile import ZipFile, ZIP_DEFLATED

BASE = "sha256:eddc3b1939fb346372fe8e6aa2806f1bb03696867704f3e70143e12492115aa5"
DERIVED = "sha256:8bf2e168ec95b21d0aa1072748baec1106f94ddd9fd5f06a1425312ee4a0e998"
NATIVE_SHA = "3188814c35471432d4123203e0eb38e5bddc60226e3d7ddf0e59e649ea140022"
PROFILES = ("full_access", "account_separation", "workspace", "account_separation", "full_access", "workspace")
SCHEMA = "cse227-normal-resume-control-v1"

# The only explicit shell invocation in this control returns the shell user's UID.
# It precedes the CLI run and is separate from the text-only provider.
INSIDE = r"""
import hashlib, json, os, pathlib, subprocess, sys
profile, expected_hash = sys.argv[1:3]
source = sys.stdin.read()
record = {"bootstrap_ok": False, "profile": profile, "recorder_uid": os.geteuid()}
try:
    binary = pathlib.Path('/usr/local/lib/node_modules/@openai/codex/node_modules/@openai/codex-linux-x64/vendor/x86_64-unknown-linux-musl/bin/codex')
    h = hashlib.sha256()
    with binary.open('rb') as file:
        for part in iter(lambda: file.read(1024 * 1024), b''):
            h.update(part)
    record["native_sha256"] = h.hexdigest()
    if record["native_sha256"] != expected_hash:
        raise ValueError("installed executable differs from the Step 5 pin")
    shell = subprocess.run(['/bin/bash', '-c', 'exec /usr/bin/id -u'], stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=15)
    if shell.returncode:
        raise ValueError("fixed shell identity probe failed: " + shell.stderr.strip()[-800:])
    record["identity_probe_uid"] = int(shell.stdout.strip())
    expected_uid = 1002 if profile == "account_separation" else 1000
    if record["recorder_uid"] != 1000 or record["identity_probe_uid"] != expected_uid:
        raise ValueError("recorder or shell-probe UID differs from the declared condition")
    record["bootstrap_ok"] = True
    proc = subprocess.run([sys.executable, '-I', '-c', source, *sys.argv[3:]],
                          stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=220)
    record["control_exit_code"] = proc.returncode
    record["control"] = json.loads(proc.stdout)
    if not isinstance(record["control"], dict):
        raise ValueError("control did not return a JSON object")
except (OSError, ValueError, subprocess.TimeoutExpired) as err:
    record["setup_or_capture_error"] = type(err).__name__
    if not isinstance(err, subprocess.TimeoutExpired):
        record["detail"] = str(err)[:900]
print(json.dumps(record))
"""


def source_bytes():
    path = Path(__file__).with_name("normal_resume.py")
    if path.is_file():
        return path.read_bytes()
    with ZipFile(sys.argv[0]) as kit:
        return kit.read("normal_resume.py")


def docker_args(profile):
    sep = profile == "account_separation"
    image = DERIVED if sep else BASE
    argv = ["docker", "run", "--rm", "-i", "--pull=never", "--init", "--network=none",
            "--read-only", "--workdir=/workspace", "--security-opt=no-new-privileges",
            "--cap-drop=ALL", "--pids-limit=128", "--memory=1g", "--cpus=2",
            "--env=HOME=/home/agent", "--tmpfs=/tmp:rw,nosuid,nodev,size=128m,mode=1777"]
    if sep:
        argv += ["--user=0:0", "--cap-add=SETUID", "--cap-add=SETGID", "--cap-add=SETPCAP",
                 "--env=PYTHONPATH=/opt/trace-lab",
                 "--tmpfs=/home/agent:rw,nosuid,nodev,size=128m,uid=1000,gid=1000,mode=0755",
                 "--tmpfs=/home/tool:rw,exec,nosuid,nodev,size=128m,uid=1002,gid=1002,mode=0755",
                 "--tmpfs=/workspace:rw,nosuid,nodev,size=64m,uid=1000,gid=2000,mode=2775"]
    else:
        argv += ["--user=1000:1000", "--tmpfs=/home/agent:rw,nosuid,nodev,size=128m,uid=1000,gid=1000,mode=0700",
                 "--tmpfs=/workspace:rw,nosuid,nodev,size=64m,uid=1000,gid=1000,mode=0755"]
    argv += ["--entrypoint=/usr/local/bin/python3", image]
    if sep:
        argv += ["-m", "research.native.account_separation.launcher", "--", "/usr/local/bin/python3"]
    permission = ":workspace" if profile == "workspace" else ":danger-full-access"
    return argv + ["-I", "-c", INSIDE, profile, NATIVE_SHA, "--codex", "/usr/local/bin/codex",
                   "--permission-profile", permission, "--profile", profile, "--container-layout"]


def docker_info(*args):
    p = subprocess.run(["docker", *args], stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=30)
    if p.returncode:
        raise ValueError((p.stderr.strip() or "Docker returned an error")[-1000:])
    return p.stdout.strip()


def write_json(path, value):
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")
    tmp.replace(path)


def collect(output_parent):
    source = source_bytes()
    output = Path(tempfile.mkdtemp(prefix="CSE227-normal-resume-", dir=output_parent))
    print(f"Evidence directory: {output}", flush=True)
    plan = {"schema": SCHEMA, "created_utc": datetime.now(timezone.utc).isoformat(),
            "question": "Does ordinary real-Codex resume restore the earlier user phrase, while a fresh session omits it?",
            "scope": "Recorder-side normal resume plus a separate shell UID probe. No active audit-loss sessions.",
            "responder": "Deterministic text-only loopback responder, without inference.",
            "normal_resume_py_sha256": sha256(source).hexdigest(), "native_sha256": NATIVE_SHA,
            "images": {"full_access": BASE, "workspace": BASE, "account_separation": DERIVED},
            "schedule": [{"slot": i, "profile": p} for i, p in enumerate(PROFILES, 1)]}
    write_json(output / "plan.json", plan)
    summary = {"schema": SCHEMA, "planned_controls": len(PROFILES), "attempted_controls": 0,
               "captured_controls": 0, "all_three_phases_evaluable": 0,
               "passing_controls": 0, "original_step6_sessions": 0, "stop_reason": None}
    try:
        summary["docker_server"] = docker_info("version", "--format", "{{.Server.Version}}")
        for expected in (BASE, DERIVED):
            actual = docker_info("image", "inspect", "--format", "{{.Id}}", expected)
            if actual != expected:
                raise ValueError(f"local image ID differs from preflight: {expected}")
        for slot, profile in enumerate(PROFILES, 1):
            print(f"Control {slot}/6 ({profile})", flush=True)
            started = datetime.now(timezone.utc).isoformat()
            rec = {"slot": slot, "profile": profile, "started_utc": started}
            slot_path = output / f"control-{slot:02}.json"
            summary["attempted_controls"] += 1
            write_json(slot_path, rec)
            try:
                p = subprocess.run(docker_args(profile), input=source, capture_output=True, timeout=290)
                rec["docker_exit"] = p.returncode
                if p.returncode:
                    raise ValueError(p.stderr.decode(errors="replace")[-1000:] or f"Docker exit {p.returncode}")
                payload = json.loads(p.stdout)
                if not isinstance(payload, dict) or payload.get("profile") != profile:
                    raise ValueError("unexpected bootstrap record")
                rec.update(payload)
                if not rec.get("setup_or_capture_error") and rec.get("bootstrap_ok"):
                    control = rec.get("control")
                    if not isinstance(control, dict) or control.get("schema") != "normal-text-resume-control-v1":
                        raise ValueError("unexpected measurement schema")
                    summary["captured_controls"] += 1
                    phases = control.get("phases", {})
                    evaluable = all(isinstance(phases.get(name), dict)
                                    and type(phases[name].get("meets_control_criteria")) is bool
                                    and isinstance(phases[name].get("provider_requests"), list)
                                    and len(phases[name]["provider_requests"]) == 1
                                    for name in ("seed", "resume", "fresh"))
                    rec["all_three_phases_evaluable"] = evaluable
                    passed = (evaluable and rec.get("control_exit_code") == 0 and control.get("status") == "pass"
                              and all(phases[key]["meets_control_criteria"] for key in ("seed", "resume", "fresh")))
                    rec["all_checks_passed"] = passed
                    summary["all_three_phases_evaluable"] += int(evaluable)
                    summary["passing_controls"] += int(passed)
            except subprocess.TimeoutExpired:
                rec["setup_or_capture_error"] = "Docker timed out before returning a complete record"
            except (OSError, ValueError, UnicodeError) as err:
                rec["setup_or_capture_error"] = str(err)
            rec["ended_utc"] = datetime.now(timezone.utc).isoformat()
            write_json(slot_path, rec)
            write_json(output / "summary.json", summary)
    except KeyboardInterrupt:
        summary["stop_reason"] = "Interrupted by operator"
    except subprocess.TimeoutExpired:
        summary["stop_reason"] = "Docker timed out; completed control records retained"
    except (OSError, ValueError) as err:
        summary["stop_reason"] = str(err)
    finally:
        summary["ended_utc"] = datetime.now(timezone.utc).isoformat()
        write_json(output / "summary.json", summary)
        rows = ["# Ordinary Codex resume controls", "",
                f"Started {plan['created_utc']}. Finished {summary['ended_utc']}.", "",
                f"Attempted {summary['attempted_controls']}/6, captured {summary['captured_controls']}/6, "
                f"all three phases evaluable {summary['all_three_phases_evaluable']}/6, passed {summary['passing_controls']}/6.",
                "", "| Trial | Profile | Recorder UID | Shell probe UID | Ordinary resume control |",
                "| --- | --- | --- | --- | --- |"]
        for i, profile in enumerate(PROFILES, 1):
            f = output / f"control-{i:02}.json"
            r = json.loads(f.read_text()) if f.is_file() else {}
            if "control_exit_code" in r and not r.get("setup_or_capture_error"):
                status = "passed" if r.get("all_checks_passed") else "did not pass"
            else:
                status = "capture or setup incomplete" if r else "no retained record"
            rows.append(f"| {i} | {profile} | {r.get('recorder_uid', '—')} | {r.get('identity_probe_uid', '—')} | {status} |")
        if summary["stop_reason"]:
            rows.extend(["", "Stopping reason: " + summary["stop_reason"]])
        rows.extend(["", "A direct shell UID check preceded each native CLI trial. "
                     "The local responder emitted text only. These trials measured ordinary session continuity. "
                     "They contribute zero sessions to the original active-record-loss comparison.", ""])
        (output / "summary.md").write_text("\n".join(rows), encoding="utf-8")
        # mkdtemp supplies a fresh directory; create its sibling archive exclusively.
        archive = output.with_name(output.name + ".zip")
        with ZipFile(archive, "x", compression=ZIP_DEFLATED) as z:
            for f in sorted(output.iterdir()):
                z.write(f, f.name)
        print(json.dumps(summary, indent=2))
        print(f"Evidence ZIP: {archive}", flush=True)
    return int(summary["passing_controls"] != len(PROFILES))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-parent", required=True, type=Path, help="Existing directory in which a fresh run directory and ZIP will be created")
    args = parser.parse_args()
    return collect(args.output_parent)


if __name__ == "__main__":
    sys.exit(main())
