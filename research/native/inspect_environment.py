"""Offline inventory of the pinned native CLI; not a defense experiment."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import shutil
import signal
import subprocess
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

BASE = "946f628bbf630977e4b719cdc529cdcc4d0f50c4"
BRANCH = "native-history-defense"
IMAGE = "sha256:eddc3b1939fb346372fe8e6aa2806f1bb03696867704f3e70143e12492115aa5"
LABEL = "cse227.native.environment"
EXPECTED_VERSION = "codex-cli 0.154.0"
ROOT = Path.cwd() if __file__ == "<stdin>" else Path(__file__).resolve().parents[2]
OUTPUT = Path("runs/native/environment-inventory-02")
HELP_COMMANDS = (
    ("version", ["codex", "--version"]),
    ("main_help", ["codex", "--help"]),
    ("exec_help", ["codex", "exec", "--help"]),
    ("resume_help", ["codex", "exec", "resume", "--help"]),
    ("sandbox_help", ["codex", "sandbox", "--help"]),
    ("app_server_help", ["codex", "app-server", "--help"]),
)


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def run(command, *, input=None, timeout=20):
    result = subprocess.run(command, input=input, text=True, capture_output=True,
                            timeout=timeout, check=False)
    require(result.returncode == 0,
            f"Command failed ({result.returncode}): {command[0]}\n"
            + result.stderr[-3000:] + result.stdout[-1000:])
    return result.stdout


def capture_help(name, command):
    """Retain unsupported-command errors and continue independent help queries."""
    start = time.monotonic()
    process = subprocess.Popen(command, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, text=True,
                               start_new_session=True)
    timed_out = False
    try:
        stdout, stderr = process.communicate(timeout=12)
    except subprocess.TimeoutExpired:
        timed_out = True
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        stdout, stderr = process.communicate(timeout=3)
    return {"name": name, "argv": command, "exit_code": process.returncode,
            "timed_out": timed_out, "seconds": round(time.monotonic() - start, 3),
            "stdout": stdout[:64000], "stderr": stderr[:16000],
            "output_truncated": len(stdout) > 64000 or len(stderr) > 16000}


def inside_inventory():
    require(os.getuid() == 1000, "Unexpected inspection user.")
    Path("/home/agent/.codex").mkdir(mode=0o700)
    status_keys = {"Uid", "Gid", "Groups", "CapInh", "CapPrm", "CapEff",
                   "CapBnd", "CapAmb", "NoNewPrivs", "Seccomp"}
    status = {}
    for line in Path("/proc/self/status").read_text().splitlines():
        key, _, value = line.partition(":")
        if key in status_keys:
            status[key] = value.strip()
    settings = {}
    for name in ("/proc/sys/kernel/yama/ptrace_scope",
                 "/proc/sys/kernel/unprivileged_userns_clone",
                 "/proc/sys/user/max_user_namespaces"):
        try:
            settings[name] = Path(name).read_text().strip()
        except OSError as exc:
            settings[name] = {"unavailable_errno": exc.errno}
    binaries = {name: shutil.which(name) for name in
                ("codex", "node", "python3", "bash", "ps", "rg", "strace",
                 "unshare", "setpriv", "nsenter", "bwrap", "readelf")}
    require(binaries["codex"], "The pinned image has no codex executable.")
    launcher = Path(binaries["codex"]).resolve()
    package = launcher.parent.parent / "package.json"
    metadata = {}
    if package.is_file():
        contents = json.loads(package.read_text())
        metadata = {key: contents.get(key) for key in
                    ("name", "version", "optionalDependencies", "bin")}
    commands = [capture_help(name, argv) for name, argv in HELP_COMMANDS]
    return {"kernel": platform.release(), "machine": platform.machine(),
            "python": platform.python_version(), "inspection_process": status,
            "kernel_settings": settings, "binaries": binaries,
            "codex_launcher": {"path": str(launcher),
                               "sha256": digest(launcher.read_bytes()),
                               "package": metadata},
            "commands": commands,
            "limits": "Help/version inventory only; native recorder, tool identities, "
                      "sandbox enforcement and resume have not been measured here."}


def create_command(name, token):
    return ["docker", "create", "--name", name, "--label", f"{LABEL}={token}",
            "--pull=never", "--interactive", "--init", "--network=none",
            "--read-only", "--user=1000:1000", "--cap-drop=ALL",
            "--security-opt=no-new-privileges", "--pids-limit=64",
            "--memory=512m", "--cpus=1", "--workdir=/workspace",
            "--tmpfs", "/tmp:rw,nosuid,nodev,size=64m,mode=1777",
            "--tmpfs", "/home/agent:rw,nosuid,nodev,size=32m,uid=1000,gid=1000,mode=700",
            "--tmpfs", "/workspace:rw,nosuid,nodev,size=16m,uid=1000,gid=1000,mode=700",
            "--env=HOME=/home/agent", "--env=CODEX_HOME=/home/agent/.codex",
            "--env=XDG_CONFIG_HOME=/home/agent/.config",
            "--entrypoint=python3", IMAGE, "-", "--inside"]


def validate_container(info, token):
    host = info["HostConfig"]
    config = info["Config"]
    require(info["Image"] == IMAGE and config["User"] == "1000:1000",
            "Container image or user differs from the protocol.")
    require(config.get("Labels", {}).get(LABEL) == token,
            "Container ownership label mismatch.")
    require(host["NetworkMode"] == "none" and host["ReadonlyRootfs"]
            and not host["Privileged"] and not host.get("CapAdd")
            and "ALL" in {c.upper() for c in host.get("CapDrop", [])}
            and any(s in ("no-new-privileges", "no-new-privileges:true")
                    for s in host.get("SecurityOpt", [])),
            "Container isolation settings differ from the protocol.")
    require(not host.get("Binds") and not host.get("Devices")
            and not host.get("VolumesFrom")
            and all(m["Type"] == "tmpfs" for m in info.get("Mounts", [])),
            "Unexpected mount or device; inspection was not started.")
    require(not any("auth.json" in e.lower() or
                    (e.partition("=")[0].upper().endswith(
                        ("_API_KEY", "_TOKEN", "_PASSWORD", "_SECRET"))
                     and e.partition("=")[2])
                    for e in config.get("Env", [])),
            "Unexpected credential-like image environment; inspection was not started.")


def validate_repository():
    require(Path.cwd().resolve() == ROOT, "Run this from the project directory.")
    require(run(["git", "branch", "--show-current"]).strip() == BRANCH,
            f"Expected branch {BRANCH}.")
    run(["git", "merge-base", "--is-ancestor", BASE, "HEAD"])
    run([sys.executable, "research/tools/finalize_initial_replication.py", "check"])


def save_json(path, data):
    with path.open("x", encoding="utf-8") as stream:
        json.dump(data, stream, indent=2)
        stream.write("\n")


def collect():
    output = ROOT / OUTPUT
    existing = output / "environment.json"
    tool_hash = digest(Path(__file__).read_bytes())
    if existing.is_file():
        packet = json.loads(existing.read_text())
        require(packet.get("tool_sha256") == tool_hash,
                "Existing inventory used different code; it has been retained.")
        return packet
    require(not output.exists(),
            "An incomplete inventory folder already exists; retain it and send the terminal output.")
    image = json.loads(run(["docker", "image", "inspect", IMAGE]))[0]
    require(image["Id"] == IMAGE and image["Os"] == "linux"
            and image["Architecture"] == "amd64" and not image["Config"].get("Volumes"),
            "The pinned image configuration is unexpected.")
    output.mkdir(parents=True)
    token = uuid.uuid4().hex
    name = "cse227-native-env-" + token[:12]
    packet = {"schema": "native-environment-inventory-v1",
              "created_at": datetime.now(timezone.utc).isoformat(),
              "replication_base_commit": BASE, "image_id": IMAGE,
              "branch": BRANCH, "tool_sha256": tool_hash,
              "container_name": name, "container_token": token,
              "model_calls": 0, "credentials_mounted": False,
              "network": "none", "errors": [], "cleanup_errors": []}
    save_json(output / "started.json", packet)
    try:
        run(create_command(name, token))
        info = json.loads(run(["docker", "inspect", name]))[0]
        validate_container(info, token)
        packet["container_policy_verified"] = True
        code = Path(__file__).read_text()
        raw = run(["docker", "start", "--attach", "--interactive", name],
                  input=code, timeout=120)
        (output / "container-output.json").write_text(raw, encoding="utf-8")
        packet["inventory"] = json.loads(raw)
        state = json.loads(run(["docker", "inspect", name]))[0]["State"]
        require(state["Status"] == "exited" and state["ExitCode"] == 0
                and not state["OOMKilled"], "Inspection process did not finish normally.")
        packet["container_exit_code"] = state["ExitCode"]
    except (Exception, KeyboardInterrupt) as exc:
        packet["errors"].append(f"{type(exc).__name__}: {exc}")
    finally:
        try:
            owned = run(["docker", "ps", "--all", "--quiet", "--filter",
                         f"label={LABEL}={token}"]).split()
            for container_id in owned:
                run(["docker", "rm", "--force", "--volumes", container_id])
            remaining = run(["docker", "ps", "--all", "--quiet", "--filter",
                             f"label={LABEL}={token}"]).strip()
            require(not remaining, "Inspection container remains present.")
            packet["container_removed"] = True
        except Exception as exc:
            packet["cleanup_errors"].append(str(exc))
            packet["container_removed"] = False
    commands = packet.get("inventory", {}).get("commands", [])
    packet["help_warnings"] = [c["name"] for c in commands if c["exit_code"] != 0
                               or c["timed_out"] or c["output_truncated"]]
    version = next((c for c in commands if c["name"] == "version"), {})
    packet["expected_version_seen"] = (
        version.get("exit_code") == 0 and
        version.get("stdout", "").strip() == EXPECTED_VERSION)
    packet["inventory_complete"] = (not packet["errors"] and
        not packet["cleanup_errors"] and packet["expected_version_seen"] and
        len(commands) == len(HELP_COMMANDS))
    save_json(existing, packet)
    return packet


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inside", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--export", type=Path)
    args = parser.parse_args()
    if args.inside:
        print(json.dumps(inside_inventory()))
        return 0
    validate_repository()
    print("Inspecting the existing image offline; no credentials or host folders are mounted.",
          flush=True)
    packet = collect()
    if args.export:
        require(args.export.parent.is_dir(), "The export directory does not exist.")
        payload = (ROOT / OUTPUT / "environment.json").read_bytes()
        require(not args.export.exists() or args.export.read_bytes() == payload,
                "The export filename already contains a different file; nothing was overwritten.")
        if not args.export.exists():
            with args.export.open("xb") as stream:
                stream.write(payload)
        print("Export:", args.export)
    print("Inventory complete:", packet.get("inventory_complete"))
    print("Expected Codex version:", packet.get("expected_version_seen"))
    print("Help warnings (retained for review):", packet.get("help_warnings"))
    print("Inspection container removed:", packet.get("container_removed"))
    print("Native defense or resume tested: False")
    print("Local evidence:", ROOT / OUTPUT)
    for error in packet["errors"] + packet["cleanup_errors"]:
        print("ERROR:", error)
    if packet.get("inventory_complete"):
        print("OFFLINE INVENTORY READY FOR REVIEW")
        return 0
    print("STOP: Send this output and the exported diagnostic. Do not rerun or delete the evidence.")
    return 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (RuntimeError, OSError, ValueError, subprocess.TimeoutExpired) as error:
        print("STOP:", error, file=sys.stderr)
        raise SystemExit(1)
