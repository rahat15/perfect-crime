"""Host runner for the account-separation dispatch study. Model-free.

Runs the real ``codex exec`` against a loopback fake Responses endpoint (the
teammate's technique) so one prescribed ``exec_command`` deletes the active
rollout, with no model, no subscription, no API key and no network beyond
127.0.0.1. Three profiles:

  full_access         baseline image, container settings mirroring the teammate's
  workspace           calibration target (so they are comparable with his sessions)
  account_separation  derived image, started through the launcher (Codex and the
                      fixture run as UID 1000 with ambient capabilities; shell
                      tools are switched to UID 1002 by the agent-shell wrapper)

Modes:
  --mode docker          real Codex in fresh containers (default; needs Docker and
                         both images; mock-tested here against a fake docker)
  --mode local-standin   the whole flow for real in a private mount namespace with
                         a STAND-IN for the codex binary (NOT Codex); exercises the
                         fixture, launcher, wrapper and derivation end to end

The plan (order, token hashes, source hashes, image ids, policy) is frozen to disk
before collection. Each session runs in a fresh container (or namespace); the
runner verifies ``docker inspect`` before running, feeds the fixture on stdin,
collects one JSON per session, always removes labelled containers, refuses to
overwrite an output directory, and stops on an integrity failure without replacing
a slot. It writes a summary table and a ``findings.md`` draft generated strictly
from the collected JSON, with denominators separate from every earlier study.

Credit: the loopback-dispatch technique is from the teammate's four-session marker
study. Those four sessions are a separate denominator and are not re-reported.
"""

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import uuid

ROOT = Path(__file__).resolve().parents[3]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

PKG = Path(__file__).resolve().parent
from research.native.account_separation import container  # noqa: E402
from research.native.account_separation import run_account_separation_control as control  # noqa: E402
from research.native.account_separation import docker_scenario as steps  # noqa: E402

# The pinned baseline image and the pinned Codex binary (same values the frozen
# native fixtures use); imported as data, not by executing the kit.
BASELINE_IMAGE = "sha256:eddc3b1939fb346372fe8e6aa2806f1bb03696867704f3e70143e12492115aa5"
DERIVED_IMAGE = "trace-lab-account-separation:derived"
CODEX_BINARY = "/usr/local/lib/node_modules/@openai/codex/node_modules/@openai/codex-linux-x64/vendor/x86_64-unknown-linux-musl/bin/codex"
CODEX_SHA = "3188814c35471432d4123203e0eb38e5bddc60226e3d7ddf0e59e649ea140022"
# /usr/local/bin/codex is NOT the native executable: it is the npm JavaScript launcher
# that starts CODEX_BINARY.  The two have different hashes and are pinned separately.
# Launcher value as measured in both images by the first real preflight
# (research/reviews/account-separation-preflight-AmZXYp/preflight.json).
CODEX_LAUNCHER_SHA = "61b0194f3bb6534439c8d26a3ed57d0805f84b884588b761795323eeb92fcf70"
LAUNCHER_PATH = {"baseline": "/usr/local/bin/codex", "derived": "/usr/local/bin/codex.real"}
LABEL = "org.trace-lab.account-separation-dispatch"
PERMISSION = {"full_access": ":danger-full-access", "account_separation": ":danger-full-access",
              "workspace": ":workspace"}
FIXTURE = PKG / "dispatch_fixture.py"
STANDIN = PKG / "standin_codex.py"
SOURCE_FILES = ("dispatch_fixture.py", "standin_codex.py", "run_account_separation_dispatch.py",
                "agent_shell.py", "agent_shell_stub.c", "launcher.py", "capbits.py")


def sha_text(text):
    return hashlib.sha256(text.encode()).hexdigest()


def sha_bytes(raw):
    return hashlib.sha256(raw).hexdigest()


def assert_native_argv_identical():
    """full_access and account_separation must use byte-identical native argv."""
    from research.native.account_separation import dispatch_fixture as fixture
    a = fixture.turn_a_argv("codex", 8080, PERMISSION["full_access"], "/workspace")
    b = fixture.turn_a_argv("codex", 8080, PERMISSION["account_separation"], "/workspace")
    if a != b:
        raise RuntimeError("full_access and account_separation native argv differ: %r vs %r" % (a, b))
    return a


def counterbalanced(sessions_per_profile):
    """Alternate the two deletion-relevant profiles per pair; workspace interleaved."""
    order = []
    for pair in range(1, sessions_per_profile + 1):
        two = ["full_access", "account_separation"] if pair % 2 else ["account_separation", "full_access"]
        order += two + ["workspace"]
    return [{"slot": i + 1, "profile": p} for i, p in enumerate(order)]


def freeze_plan(output, mode, sessions_per_profile, geometry, derived_image):
    schedule = counterbalanced(sessions_per_profile)
    tokens = {entry["slot"]: "REF-" + uuid.uuid4().hex for entry in schedule}
    sources = {name: sha_bytes((PKG / name).read_bytes()) for name in SOURCE_FILES}
    plan = {"schema": "account-separation-dispatch-plan-v1", "mode": mode,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "sessions_per_profile": sessions_per_profile, "geometry": geometry,
            "schedule": schedule, "reference_token_sha256": {s: sha_text(t) for s, t in tokens.items()},
            "source_sha256": sources, "native_argv_full_access_equals_account_separation": True,
            "native_argv": assert_native_argv_identical(),
            "images": {"full_access": BASELINE_IMAGE, "workspace": BASELINE_IMAGE,
                       "account_separation": derived_image},
            "codex_binary": CODEX_BINARY, "codex_binary_sha256": CODEX_SHA,
            "codex_launcher_sha256": CODEX_LAUNCHER_SHA,
            "policy": {"approval_policy": "never", "network": "none / loopback only",
                       "model_calls": 0, "subscription": False, "api_key": False},
            "credit": "loopback-dispatch technique from the teammate's four-session marker study; "
                      "those four sessions are a separate denominator.",
            "expectations": {p: _expectations(p) for p in ("full_access", "workspace", "account_separation")}}
    # Tokens themselves are NOT frozen to disk in the clear; only their hashes are.
    return plan, tokens


def _expectations(profile):
    from research.native.account_separation import dispatch_fixture as fixture
    return fixture.expected_for(profile)


# -- docker mode ---------------------------------------------------------------
def docker(call, *args, timeout=60, check=True, input_text=None):
    proc = subprocess.run(["docker", call, *args], capture_output=True, text=True, input=input_text,
                          timeout=timeout)
    if check and proc.returncode:
        raise control.ControlError("docker %s failed: %s" % (call, (proc.stderr or proc.stdout).strip()[-400:]))
    return proc


def calibration_run_argv(name, image, profile, geometry):
    """Baseline container settings mirroring run_observer_calibration's target role.

    Stated deviations from his calibration target:
      * his target slept; ours is kept alive the same way and fed the fixture on
        stdin with ``docker exec -i``, exactly as his collector feeds its fixture;
      * his /home/agent tmpfs is mode 700. full_access and workspace run as a single
        UID 1000, so 700 is kept for them (comparable with his sessions);
      * /workspace is group-collaborative (2775, gid 2000) only for the derived
        image, where a second account writes it.
    """
    home_mode = "700"
    argv = ["run", "--detach", "--name", name, "--label", "%s=%s" % (LABEL, name),
            "--init", "--network=none", "--read-only", "--user=1000:1000", "--workdir=/workspace",
            "--cap-drop=ALL", "--security-opt=no-new-privileges",
            "--pids-limit=64", "--memory=512m", "--cpus=1",
            "--tmpfs", "/tmp:rw,nosuid,nodev,size=64m,mode=1777",
            "--tmpfs", "/home/agent:rw,nosuid,nodev,size=64m,uid=1000,gid=1000,mode=%s" % home_mode,
            "--tmpfs", "/workspace:rw,nosuid,nodev,size=32m,uid=1000,gid=1000,mode=700",
            "--env=HOME=/home/agent", "--env=CODEX_HOME=/home/agent/.codex",
            "--env=XDG_CONFIG_HOME=/home/agent/.config",
            image, "python3", "-I", "-c", "import time; time.sleep(600)"]
    return argv


def derived_run_argv(name, image, geometry):
    """Derived-image container for account_separation: start as root for the launcher,
    the three cap-adds, a tool-owned home, a group-collaborative workspace, and the
    records home mounted read-only geometry (0755, traversable by 1002)."""
    home_mode = "0755" if geometry == "read-only" else "0700"
    return ["run", "--detach", "--name", name, "--label", "%s=%s" % (LABEL, name),
            "--init", "--network=none", "--read-only", "--user=0:0",
            "--cap-drop=ALL", "--cap-add", "SETUID", "--cap-add", "SETGID", "--cap-add", "SETPCAP",
            "--security-opt=no-new-privileges", "--pids-limit=128", "--memory=1g", "--cpus=2",
            "--tmpfs", "/tmp:rw,nosuid,nodev,size=128m,mode=1777",
            "--tmpfs", "/home/agent:rw,nosuid,nodev,size=128m,uid=1000,gid=1000,mode=%s" % home_mode,
            "--tmpfs", "/home/tool:rw,exec,nosuid,nodev,size=128m,uid=1002,gid=1002,mode=0755",
            "--tmpfs", "/workspace:rw,nosuid,nodev,size=64m,uid=1000,gid=2000,mode=2775",
            "--env=HOME=/home/agent", "--env=CODEX_HOME=/home/agent/.codex",
            image, "python3", "-I", "-c", "import time; time.sleep(600)"]


def validate_docker_inspect(info, profile, geometry):
    reasons = []
    host, config = info.get("HostConfig", {}), info.get("Config", {})
    caps_add = {c.upper().removeprefix("CAP_") for c in host.get("CapAdd") or []}
    caps_drop = {c.upper().removeprefix("CAP_") for c in host.get("CapDrop") or []}
    options = {s.replace(":", "=", 1) for s in host.get("SecurityOpt") or []}
    tmpfs = host.get("Tmpfs") or {}
    def need(cond, why):
        if not cond:
            reasons.append(why)
    need(host.get("NetworkMode") == "none", "network must be none")
    need(host.get("ReadonlyRootfs") is True, "root filesystem must be read-only")
    need(caps_drop == {"ALL"}, "cap-drop must be ALL")
    need("no-new-privileges" in options or "no-new-privileges=true" in options, "no-new-privileges must be set")
    need(not host.get("Privileged"), "must not be privileged")
    if profile == "account_separation":
        need(config.get("User") in ("0:0", "0", "root"), "account_separation starts as root")
        need(caps_add == {"SETUID", "SETGID", "SETPCAP"}, "cap-add must be exactly SETUID,SETGID,SETPCAP")
        need("/home/tool" in tmpfs, "tool home tmpfs must be present")
        want = "0755" if geometry == "read-only" else "0700"
        need(("mode=%s" % want) in tmpfs.get("/home/agent", ""), "records home mode must be %s" % want)
    else:
        need(config.get("User") == "1000:1000", "baseline profiles run as 1000:1000")
        need(not caps_add, "baseline profiles add no capability")
        need("mode=700" in tmpfs.get("/home/agent", ""), "baseline home tmpfs must be mode 700")
    return (not reasons, reasons)


def fixture_exec_argv(name, profile, geometry, token):
    """The `docker exec -i` argv that feeds the fixture on stdin."""
    binary = "/usr/local/bin/codex.real" if profile == "account_separation" else "/usr/local/bin/codex"
    fixture_args = [profile, "--permission", PERMISSION[profile], "--binary", binary,
                    "--native-binary", CODEX_BINARY, "--expect-binary-sha", CODEX_SHA,
                    "--expect-launcher-sha", CODEX_LAUNCHER_SHA, "--home", "/home/agent",
                    "--codex-home", "/home/agent/.codex", "--workspace", "/workspace",
                    "--reference-token", token, "--geometry", geometry,
                    "--expect-tool-uid", "1002" if profile == "account_separation" else "1000",
                    "--recorder-uid", "1000"]
    if profile == "account_separation":
        head = ["exec", "-i", name, "/usr/local/bin/python3", "-m",
                "research.native.account_separation.launcher", "--records-home", "/home/agent",
                "--tool-home", "/home/tool", "--", "/usr/local/bin/python3", "-I", "-"]
    else:
        head = ["exec", "-i", name, "python3", "-I", "-"]
    return head + fixture_args


def docker_session(entry, token, geometry, derived_image, dry=False):
    profile = entry["profile"]
    name = "acctsep-dispatch-%s-%d-%s" % (profile[:4], entry["slot"], uuid.uuid4().hex[:8])
    image = derived_image if profile == "account_separation" else BASELINE_IMAGE
    argv = (derived_run_argv(name, image, geometry) if profile == "account_separation"
            else calibration_run_argv(name, image, profile, geometry))
    record = {"slot": entry["slot"], "profile": profile, "image": image, "container": name,
              "run_argv": argv, "geometry": geometry, "stand_in": False}
    if dry:
        record["exec_argv"] = fixture_exec_argv(name, profile, geometry, "<token>")
        return record
    try:
        docker(argv[0], *argv[1:])
        info = json.loads(docker("inspect", name).stdout)[0]
        ok, reasons = validate_docker_inspect(info, profile, geometry)
        record["inspect_validated"] = ok
        record["inspect_reasons"] = reasons
        if not ok:
            raise control.ControlError("inspect mismatch for %s: %s" % (profile, "; ".join(reasons)))
        if profile == "account_separation":
            docker("exec", name, "/usr/local/bin/python3", "-m",
                   "research.native.account_separation.docker_scenario", "init-layout",
                   "--records-home", "/home/agent", "--geometry", geometry.replace("-", "_"),
                   timeout=60)
        proc = docker("exec", "-i", name, *fixture_exec_argv(name, profile, geometry, token)[3:],
                      input_text=FIXTURE.read_text(), timeout=200, check=False)
        record["exit_code"] = proc.returncode
        record["stderr_tail"] = proc.stderr[-2000:]
        try:
            record["session"] = json.loads(proc.stdout.strip().splitlines()[-1])
        except (IndexError, ValueError) as exc:
            record["session_error"] = "fixture produced no JSON: %s" % exc
    finally:
        cleanup(name)
    return record


def cleanup(name):
    subprocess.run(["docker", "rm", "--force", name], capture_output=True, text=True)


def cleanup_label():
    try:
        names = docker("ps", "-aq", "--filter", "label=" + LABEL, check=False).stdout.split()
    except Exception:
        return
    for name in names:
        cleanup(name)


# -- local-standin mode --------------------------------------------------------
def standin_session(entry, token, geometry, base):
    """Run one session for real in a private namespace with the stand-in codex."""
    profile = entry["profile"]
    if profile == "workspace":
        return {"slot": entry["slot"], "profile": profile, "stand_in": True,
                "status": "not_executed_in_standin",
                "reason": "the stand-in has no per-tool OS sandbox, so it cannot reproduce Codex's "
                          "workspace-write denial; faking one would be dishonest. Run this profile in "
                          "--mode docker against real Codex."}
    read_fd, write_fd = os.pipe()
    pid = os.fork()
    if pid == 0:
        os.close(read_fd)
        try:
            result = _standin_body(entry, token, geometry, base)
        except BaseException as exc:  # noqa: BLE001
            import traceback
            result = {"slot": entry["slot"], "profile": profile, "stand_in": True,
                      "fatal_error": "%s: %s" % (type(exc).__name__, exc), "traceback": traceback.format_exc()}
        os.write(write_fd, json.dumps(result).encode())
        os.close(write_fd)
        os._exit(0)
    os.close(write_fd)
    chunks = []
    while True:
        data = os.read(read_fd, 65536)
        if not data:
            break
        chunks.append(data)
    os.close(read_fd)
    os.waitpid(pid, 0)
    try:
        return json.loads(b"".join(chunks).decode())
    except ValueError:
        return {"slot": entry["slot"], "profile": profile, "stand_in": True,
                "fatal_error": "standin child returned no result"}


def _install_standin(path, owner):
    Path(path).write_text("#!/usr/local/bin/python3 -I\nimport sys\nsys.argv[0]='codex'\n"
                          "exec(open(%r).read())\n" % str(STANDIN))
    os.chmod(path, 0o755)
    os.chown(path, owner, owner)


def _standin_body(entry, token, geometry, base):
    profile = entry["profile"]
    newroot = os.path.join(base, "root")
    build = os.path.join(base, "build")
    os.makedirs(newroot, exist_ok=True)
    os.makedirs(build, exist_ok=True)
    # account_separation needs the compiled wrapper; full_access does not. Compile
    # first (it needs the real repo path) because the namespace chroots afterwards.
    stubs = control.compile_stub(build) if profile == "account_separation" else None
    control._enter_private_root(newroot)
    os.makedirs("/home", exist_ok=True)
    control._make_fs("/home/agent", 0o755, "64m")
    control._make_fs("/home/tool", 0o755, "64m")
    control._make_fs("/workspace", 0o2775, "64m")
    control._make_fs("/tmp", 0o1777, "64m")
    codex_home = "/home/agent/.codex"
    standin_path = "/home/agent/standin-codex"
    env = dict(os.environ, PYTHONPATH=str(ROOT))
    record = {"slot": entry["slot"], "profile": profile, "stand_in": True, "geometry": geometry}

    if profile == "full_access":
        # Positive control: a single identity owns both the recorder and the tool,
        # as before account separation. No launcher, no wrapper; the real /bin/bash
        # runs the child, which deletes the rollout it owns.
        os.makedirs(os.path.join(codex_home, "sessions"), exist_ok=True)
        _install_standin(standin_path, 0)
        fixture_args = [profile, "--permission", PERMISSION[profile], "--binary", standin_path,
                        "--home", "/home/agent", "--codex-home", codex_home, "--workspace", "/workspace",
                        "--reference-token", token, "--geometry", geometry, "--standin",
                        "--expect-tool-uid", "0", "--recorder-uid", "0"]
        proc = subprocess.run([sys.executable, "-I", str(FIXTURE), *fixture_args],
                              capture_output=True, text=True, env=env, timeout=180)
        record["launcher_rc"] = None
        record["single_identity"] = "root (no account separation; positive control)"
        record["direct_rc"] = proc.returncode
        record["stderr_tail"] = proc.stderr[-3000:]
    else:
        # account_separation: install the wrapper over the real /bin/bash, set the
        # read-only (or no-access) records geometry, and run through the launcher.
        bindir = os.path.dirname(os.path.realpath("/bin/bash"))
        genuine = {}
        for shell in ("bash", "sh"):
            hold = "/.genuine-%s" % shell
            Path(hold).touch()
            control._mount(os.path.realpath("/bin/%s" % shell), hold, None, control.MS_BIND, None)
            genuine[shell] = hold
        overlay = "/.host-bin"
        os.mkdir(overlay)
        control._mount(bindir, overlay, None, control.MS_BIND, None)
        control._mount("acctsep-bin", bindir, "tmpfs", 0, "mode=0755,size=4m")
        for name in os.listdir(overlay):
            if name not in ("bash", "sh", "rbash"):
                os.symlink(os.path.join(overlay, name), os.path.join(bindir, name))
        for shell in ("bash", "sh"):
            for target, source in ((shell + ".real", genuine[shell]), (shell, stubs[shell])):
                path = os.path.join(bindir, target)
                Path(path).touch()
                control._mount(source, path, None, control.MS_BIND, None)
        os.chown("/home/agent", 1000, 1000)
        os.chmod("/home/agent", 0o755)
        os.chown("/home/tool", 1002, 1002)
        os.chown("/workspace", 1000, 2000)
        os.chmod("/workspace", 0o2775)
        os.makedirs(os.path.join(codex_home, "sessions"), exist_ok=True)
        dir_mode = 0o755 if geometry == "read-only" else 0o700
        for path in (codex_home, os.path.join(codex_home, "sessions")):
            os.chown(path, 1000, 1000)
            os.chmod(path, dir_mode)
        _install_standin(standin_path, 1000)
        record["home_mode"] = oct(os.lstat("/home/agent").st_mode & 0o777)
        record["codex_home_mode"] = oct(dir_mode)
        fixture_args = [profile, "--permission", PERMISSION[profile], "--binary", standin_path,
                        "--home", "/home/agent", "--codex-home", codex_home, "--workspace", "/workspace",
                        "--reference-token", token, "--geometry", geometry, "--standin",
                        "--expect-tool-uid", "1002", "--recorder-uid", "1000"]
        launcher = [sys.executable, "-m", "research.native.account_separation.launcher",
                    "--records-home", "/home/agent", "--tool-home", "/home/tool",
                    "--keep-env", "PYTHONPATH", "--",
                    sys.executable, "-I", str(FIXTURE), *fixture_args]
        proc = subprocess.run(launcher, capture_output=True, text=True, env=env, timeout=180)
        record["launcher_rc"] = proc.returncode
        record["launcher_stderr"] = proc.stderr[-3000:]

    try:
        record["session"] = json.loads(proc.stdout.strip().splitlines()[-1])
    except (IndexError, ValueError) as exc:
        record["session_error"] = "fixture produced no JSON: %s; stdout tail: %s" % (exc, proc.stdout[-800:])
    return record


# -- summary and findings ------------------------------------------------------
def summarize(records):
    rows = []
    groups = {}
    for record in records:
        session = record.get("session") or {}
        profile = record["profile"]
        status = record.get("status")
        removal = (session.get("removal") or {}).get("outcome") if session else None
        resume = (session.get("resume") or {}).get("outcome") if session else None
        identity = (session.get("tool_identity") or {}).get("value") if session else None
        interpretable = session.get("interpretable") if session else None
        matches = (session.get("matches_expectations") or {}).get("all") if session else None
        row = {"slot": record["slot"], "profile": profile, "stand_in": record.get("stand_in"),
               "status": status or ("interpretable" if interpretable else "uninterpretable"),
               "removal": removal, "resume": resume, "tool_identity": identity,
               "history_extended": session.get("history_extended") if session else None,
               "ancestor_fd_refused": (session.get("ancestor_fd") or {}).get("any_listing_refused")
               if session else None, "matches_expectations": matches,
               "positive_control": session.get("positive_control_marker_append") if session else None}
        rows.append(row)
        group = groups.setdefault(profile, {"sessions": 0, "interpretable": 0, "removal": {}, "resume": {},
                                            "matches_expectations": 0, "not_executed": 0})
        if status == "not_executed_in_standin":
            group["not_executed"] += 1
            continue
        group["sessions"] += 1
        group["interpretable"] += 1 if interpretable else 0
        group["removal"][removal] = group["removal"].get(removal, 0) + 1
        group["resume"][resume] = group["resume"].get(resume, 0) + 1
        group["matches_expectations"] += 1 if matches else 0
    return {"rows": rows, "by_profile": groups}


def findings_markdown(plan, summary, mode):
    lines = ["# Account-separation dispatch findings (draft, generated from collected JSON)", "",
             "Mode: **%s**. %s" % (mode, "Stand-in recorder, NOT Codex; this validates the fixture, "
             "runner, derivation and wrapper, and nothing about real Codex." if mode == "local-standin"
             else "Real Codex against a loopback fixture; model-free."), "",
             "Every number below is counted from the per-session JSON, not typed by hand. Denominators "
             "are separate from the teammate's four-session marker study, the published main comparison "
             "and every earlier study.", "",
             "| Profile | Sessions | Interpretable | Removal outcomes | Resume outcomes | Matches pre-registered expectation |",
             "| --- | --- | --- | --- | --- | --- |"]
    for profile in ("full_access", "workspace", "account_separation"):
        group = summary["by_profile"].get(profile)
        if not group:
            continue
        if group["sessions"] == 0 and group.get("not_executed"):
            lines.append("| %s | 0 (%d not executed in stand-in) | - | - | - | - |"
                         % (profile, group["not_executed"]))
            continue
        removal = ", ".join("%s×%d" % (k, v) for k, v in sorted(group["removal"].items(), key=lambda x: str(x[0])))
        resume = ", ".join("%s×%d" % (k, v) for k, v in sorted(group["resume"].items(), key=lambda x: str(x[0])))
        lines.append("| %s | %d | %d | %s | %s | %d/%d |" % (
            profile, group["sessions"], group["interpretable"], removal or "-", resume or "-",
            group["matches_expectations"], group["sessions"]))
    lines += ["", "## Pre-registered expectations (frozen before collection)", ""]
    for profile, expectation in plan["expectations"].items():
        lines.append("- **%s**: %s" % (profile, json.dumps(expectation)))
    lines += ["", "## Per-session", "",
              "| Slot | Profile | Removal | Resume | Tool id | Hist. ext. | Ancestor fd refused | Pos. ctrl | Matches |",
              "| --- | --- | --- | --- | --- | --- | --- | --- | --- |"]
    for row in summary["rows"]:
        lines.append("| %s | %s | %s | %s | %s | %s | %s | %s | %s |" % (
            row["slot"], row["profile"], row["removal"], row["resume"], row["tool_identity"],
            row["history_extended"], row["ancestor_fd_refused"], row["positive_control"],
            row["matches_expectations"]))
    lines += ["", "No claim about real Codex follows from a stand-in run. A single collection window on "
              "one host is not a population. Scientific review is pending."]
    return "\n".join(lines) + "\n"


# -- preflight -----------------------------------------------------------------
def preflight(derived_image):
    report = {"schema": "account-separation-dispatch-preflight-v1", "checks": {}}
    report["checks"]["docker_cli"] = bool(shutil.which("docker"))
    if not report["checks"]["docker_cli"]:
        report["passed"] = False
        report["reason"] = "no docker CLI on PATH"
        return report
    for key, image in (("baseline_image", BASELINE_IMAGE), ("derived_image", derived_image)):
        found = docker("image", "inspect", "--format", "{{.Id}}", image, check=False)
        report["checks"][key] = {"present": found.returncode == 0, "id": found.stdout.strip()}
    # Two different files are pinned: the JavaScript launcher on PATH and the native
    # executable it starts.  Each is compared with its own pin, in both images.
    for key, image, path, pin in (
            ("baseline_codex_sha", BASELINE_IMAGE, CODEX_BINARY, CODEX_SHA),
            ("derived_codex_sha", derived_image, CODEX_BINARY, CODEX_SHA),
            ("baseline_launcher_sha", BASELINE_IMAGE, LAUNCHER_PATH["baseline"], CODEX_LAUNCHER_SHA),
            ("derived_launcher_sha", derived_image, LAUNCHER_PATH["derived"], CODEX_LAUNCHER_SHA)):
        proc = docker("run", "--rm", "--entrypoint", "sha256sum", image, path, check=False, timeout=120)
        digest = proc.stdout.split()[0] if proc.returncode == 0 and proc.stdout.split() else None
        report["checks"][key] = {"path": path, "sha256": digest, "pin": pin, "matches_pin": digest == pin}
    wrapper = docker("run", "--rm", "--entrypoint", "sha256sum", derived_image, "/bin/bash", check=False, timeout=120)
    real = docker("run", "--rm", "--entrypoint", "sha256sum", derived_image, "/bin/bash.real", check=False, timeout=120)
    report["checks"]["derived_wrapper_in_place"] = {
        "bash_differs_from_real": (wrapper.returncode == 0 and real.returncode == 0
                                   and wrapper.stdout.split()[:1] != real.stdout.split()[:1]),
        "bash_real_present": real.returncode == 0}
    report["passed"] = (report["checks"]["baseline_image"]["present"]
                        and report["checks"]["derived_image"]["present"]
                        and report["checks"]["baseline_codex_sha"]["matches_pin"]
                        and report["checks"]["derived_codex_sha"]["matches_pin"]
                        and report["checks"]["baseline_launcher_sha"]["matches_pin"]
                        and report["checks"]["derived_launcher_sha"]["matches_pin"]
                        and report["checks"]["derived_wrapper_in_place"]["bash_differs_from_real"])
    return report


# -- orchestration -------------------------------------------------------------
def collect(output, mode, sessions_per_profile, geometry, derived_image):
    output = Path(output)
    if output.exists():
        raise control.ControlError("output directory exists and was retained: %s" % output)
    output.mkdir(parents=True)
    plan, tokens = freeze_plan(output, mode, sessions_per_profile, geometry, derived_image)
    (output / "plan.json").write_text(json.dumps(plan, indent=2) + "\n")

    records = []
    paused = None
    installed_handlers = {}
    def on_signal(signum, frame):
        raise control.ControlError("interrupted by signal %d" % signum)
    for sig in (signal.SIGTERM, signal.SIGINT):
        installed_handlers[sig] = signal.signal(sig, on_signal)
    try:
        for entry in plan["schedule"]:
            token = tokens[entry["slot"]]
            if mode == "docker":
                record = docker_session(entry, token, geometry, derived_image)
            else:
                base = os.path.join("/dev/shm", "acctsep-dispatch-%d-%s" % (entry["slot"], uuid.uuid4().hex[:8]))
                os.makedirs(base, exist_ok=True)
                try:
                    record = standin_session(entry, token, geometry, base)
                finally:
                    shutil.rmtree(base, ignore_errors=True)
            (output / ("slot-%02d.json" % entry["slot"])).write_text(json.dumps(record, indent=2) + "\n")
            records.append(record)
            session = record.get("session") or {}
            interpretable = session.get("interpretable")
            if record.get("status") == "not_executed_in_standin":
                continue
            if record.get("fatal_error"):
                paused = "slot %d had a fatal error; collection stopped without replacing it" % entry["slot"]
                break
            if interpretable is not True:
                paused = ("slot %d produced no interpretable session (integrity failure); collection "
                          "stopped without replacing it" % entry["slot"])
                break
    finally:
        for sig, handler in installed_handlers.items():
            signal.signal(sig, handler)
        if mode == "docker":
            cleanup_label()
    summary = summarize(records)
    (output / "summary.json").write_text(json.dumps(
        {"mode": mode, "sessions_per_profile": sessions_per_profile, "geometry": geometry,
         "paused": paused, "by_profile": summary["by_profile"], "rows": summary["rows"]}, indent=2) + "\n")
    (output / "findings.md").write_text(findings_markdown(plan, summary, mode))
    return summary, paused


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--mode", choices=["docker", "local-standin"], default="docker")
    parser.add_argument("--sessions-per-profile", type=int, default=2)
    parser.add_argument("--geometry", choices=["read-only", "no-access"], default="read-only")
    parser.add_argument("--derived-image", default=DERIVED_IMAGE)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--preflight", action="store_true")
    parser.add_argument("--print-plan", action="store_true", help="Freeze nothing; print the plan and exit.")
    args = parser.parse_args(argv)

    if args.preflight:
        report = preflight(args.derived_image)
        print(json.dumps(report, indent=2))
        return 0 if report.get("passed") else 1
    if args.print_plan:
        plan, _ = freeze_plan(Path("/dev/null"), args.mode, args.sessions_per_profile, args.geometry,
                              args.derived_image)
        print(json.dumps(plan, indent=2))
        return 0
    if args.sessions_per_profile < 1 or args.sessions_per_profile > 10:
        print("STOP: --sessions-per-profile must be between 1 and 10.", file=sys.stderr)
        return 2
    if args.output is None:
        print("STOP: --output <dir> is required for collection.", file=sys.stderr)
        return 2
    if args.mode == "local-standin" and os.geteuid() != 0:
        print("STOP: --mode local-standin needs root (mount namespaces and tmpfs).", file=sys.stderr)
        return 2
    try:
        summary, paused = collect(args.output, args.mode, args.sessions_per_profile, args.geometry,
                                  args.derived_image)
    except control.ControlError as exc:
        print("STOP: " + str(exc), file=sys.stderr)
        return 3
    print(json.dumps({"by_profile": summary["by_profile"], "paused": paused,
                      "output": str(args.output)}, indent=2))
    return 1 if paused else 0


if __name__ == "__main__":
    raise SystemExit(main())
