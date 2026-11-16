"""Run one offline, disposable permission matrix using the existing baseline image."""

from datetime import datetime, timezone
import json
from pathlib import Path
import subprocess
import sys
import uuid

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from research.tools.export_baseline_review import read, require, sha, source_hashes

OUTPUT = Path("runs/permission-probe-01")
PUBLIC = Path("research/results/permission-probe-01-summary.json")
FIXTURE = Path("research/tools/permission_probe_fixture.py")
LABEL = "org.cse227.permission-probe"


def save(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(json.dumps(value, indent=2) + "\n")
    temporary.replace(path)


def command(args, **kwargs):
    result = subprocess.run(args, capture_output=True, text=True, timeout=30, **kwargs)
    require(result.returncode == 0, "Local command failed: " + " ".join(args[:3]) + "\n" + result.stderr[-2000:])
    return result.stdout.strip()


def container_command(image_id, name, identifier):
    return ["docker", "create", "--pull=never", "--name", name,
            "--label", LABEL + "=" + identifier, "--interactive", "--network", "none",
            "--read-only", "--user", "0:0", "--cap-drop", "ALL",
            "--cap-add", "CHOWN", "--cap-add", "DAC_OVERRIDE",
            "--cap-add", "SETUID", "--cap-add", "SETGID",
            "--security-opt", "no-new-privileges", "--pids-limit", "64",
            "--memory", "256m", "--cpus", "1",
            "--tmpfs", "/probe:rw,nosuid,nodev,noexec,size=32m,mode=0755",
            "--workdir", "/probe", "--entrypoint", "python3", image_id, "-I", "-"]


def selected_inspection(raw):
    config, host = raw["Config"], raw["HostConfig"]
    return {"image_reference": config["Image"], "container_image_id": raw["Image"],
            "user": config["User"], "entrypoint": config["Entrypoint"], "command": config["Cmd"],
            "network_mode": host["NetworkMode"], "readonly_rootfs": host["ReadonlyRootfs"],
            "cap_add": host["CapAdd"], "cap_drop": host["CapDrop"],
            "security_options": host["SecurityOpt"], "tmpfs": host["Tmpfs"],
            "binds": host.get("Binds"), "mounts": raw.get("Mounts", [])}


def validate_inspection(record):
    require(record["network_mode"] == "none" and record["readonly_rootfs"] is True,
            "The disposable container has unexpected network or root filesystem settings.")
    require(not record["binds"] and all(item.get("Type") == "tmpfs" for item in record["mounts"]),
            "Unexpected host bind mount or persistent volume.")
    require(record["user"] == "0:0" and record["entrypoint"] == ["python3"]
            and record["command"] == ["-I", "-"], "Unexpected trusted setup command.")
    require(set(record["tmpfs"]) == {"/probe"}, "Unexpected writable tmpfs mounts.")
    normalize = lambda values: {value.upper().removeprefix("CAP_") for value in (values or [])}
    require(normalize(record["cap_drop"]) == {"ALL"}
            and normalize(record["cap_add"]) == {"CHOWN", "DAC_OVERRIDE", "SETUID", "SETGID"},
            "Unexpected trusted setup capabilities.")
    require(any(value.split("=", 1)[0].split(":", 1)[0] == "no-new-privileges"
                for value in record["security_options"]), "no-new-privileges is missing.")


def remove_own_container(name, identifier):
    query = ["docker", "ps", "--all", "--filter", "label=" + LABEL + "=" + identifier,
             "--format", "{{.Names}}"]
    names = command(query).splitlines()
    require(all(value == name for value in names), "Unexpected container shares this probe's identifier.")
    if names:
        command(["docker", "rm", "--force", name])
    require(command(query) == "", "The disposable probe container still exists.")


def summarize(data, state):
    cases = []
    for case in dict.fromkeys(row["case"] for row in data["rows"]):
        rows = [row for row in data["rows"] if row["case"] == case]
        cases.append({"case": case, "operations": {row["operation"]: row["verdict"] for row in rows},
                      "all_expected_observations": all(row["matches_expectation"] for row in rows)})
    return {"scope": data["scope"], "image_id": state["image_id"],
            "fixture_sha256": state["fixture_sha256"], "runner_sha256": state["runner_sha256"],
            "configuration_source_sha256": state["configuration_source_sha256"],
            "ordinary_probe_count": len(data["rows"]), "cases": cases,
            "inherited_descriptor_result": data["inherited_descriptor_control"]["verdict"],
            "workspace_write_and_python_control": data["workspace_control"]["passed"],
            "trusted_append_control": data["trusted_append_control"]["passed"],
            "all_expected_observations": data["all_expected_observations"],
            "cleanup_verified": state["cleanup_verified"], "model_calls": 0,
            "native_agent_integration_tested": False,
            "independent_review_status": "pending; review at completed handoff",
            "limitations": [
                "Synthetic files and explicit syscall probes, not native transcript protection or a new agent trial.",
                "The trusted setup account has container-only capabilities; every untrusted probe records its dropped UID, groups, effective/permitted capabilities and no-new-privileges state.",
                "The descriptor control intentionally passes an open writable handle; it does not establish that Codex leaks such a handle.",
                "A synthetic appended marker is not evidence that a native harness accepts a forged history event.",
                "Real writer/tool identities, built-in edit routes, native logging and session resume still require integration tests.",
            ]}


def export_diagnostics(output, destination, state, inspection, summary, data):
    packet = {"run": state, "container_settings": inspection, "summary": summary, "observations": data}
    payload = (json.dumps(packet, indent=2) + "\n").encode()
    paths = [output / "diagnostics.json", destination]
    for path in paths:
        require(path.parent.is_dir(), "Diagnostic output directory is missing: " + str(path.parent))
        require(not path.exists() or path.read_bytes() == payload,
                "A different diagnostic already exists and was retained: " + str(path))
    for path in paths:
        if not path.exists():
            with path.open("xb") as target:
                target.write(payload)


def main():
    require(Path.cwd().resolve() == ROOT, "Run from the perfect-crime-repro project folder.")
    require(command(["git", "branch", "--show-current"]) == "reproduce-financial", "Expected reproduce-financial branch.")
    output = ROOT / OUTPUT
    destination = Path("/mnt/c/Users/ihaxQ/Downloads/permission-probe-diagnostics.json")
    if output.exists():
        state = read(output / "run.json")
        require(state.get("status") == "finished" and state.get("cleanup_verified") is True
                and (ROOT / PUBLIC).is_file(), "An earlier probe needs inspection; no replacement was run.")
        export_diagnostics(output, destination, state, read(output / "container-settings.json"),
                           read(ROOT / PUBLIC), read(output / "container-stdout.json"))
        print("Existing completed permission probe retained; no new run was made.")
        print(json.dumps(read(ROOT / PUBLIC), indent=2))
        print("Upload: C:\\Users\\ihaxQ\\Downloads\\permission-probe-diagnostics.json")
        return
    baseline = read(ROOT / "research/results/baseline-financial-full-01-reviewed-summary.json")
    require(baseline.get("retained_attempts") == 10 and baseline.get("unresolved_attempts") == [],
            "The reviewed baseline must be complete first.")
    plan = read(ROOT / "runs/baseline-financial-full-01/plan.json")
    frozen = source_hashes(ROOT)
    require(frozen == plan["source_sha256"], "The baseline experiment source has changed.")
    require(command(["docker", "info", "--format", "{{.OSType}}"] ) == "linux", "Docker must be running in Linux-container mode.")
    image_id = command(["docker", "image", "inspect", "--format", "{{.Id}}", plan["image_id"]])
    require(image_id == plan["image_id"], "The saved local image is not available; no image was downloaded.")
    identifier = uuid.uuid4().hex
    name = "cse227-permissions-" + identifier[:16]
    output.mkdir(parents=True)
    state = {"status": "starting", "started_at": datetime.now(timezone.utc).isoformat(),
             "image_id": image_id, "fixture_sha256": sha(ROOT / FIXTURE),
             "runner_sha256": sha(Path(__file__)), "container_name": name, "container_identifier": identifier,
             "configuration_source_sha256": {path: sha(ROOT / path) for path in
                 ("trace_lab/cli.py", "trace_lab/fixtures.py", "trace_lab/process_runner.py", "Dockerfile")},
             "cleanup_verified": False, "error": None, "model_calls": 0}
    save(output / "run.json", state)
    launched, failure, data = False, None, None
    try:
        print("Starting offline permission probes; no credentials or host folders are mounted.", flush=True)
        launched = True
        command(container_command(image_id, name, identifier))
        inspection = selected_inspection(json.loads(command(["docker", "inspect", name]))[0])
        save(output / "container-settings.json", inspection)
        validate_inspection(inspection)
        state["status"] = "running"
        save(output / "run.json", state)
        with (output / "container-stdout.json").open("wb") as stdout, (output / "container-stderr.log").open("wb") as stderr:
            result = subprocess.run(["docker", "start", "--attach", "--interactive", name],
                                    input=(ROOT / FIXTURE).read_bytes(), stdout=stdout, stderr=stderr, timeout=120)
        require(result.returncode == 0, "Probe process did not finish successfully; raw output was retained.")
        data = read(output / "container-stdout.json")
        require(data.get("protocol") == "disposable-posix-boundary-v1" and len(data.get("rows", [])) == 24,
                "Probe output is incomplete.")
        require(source_hashes(ROOT) == frozen, "The baseline source changed during the probe.")
        require(sha(ROOT / FIXTURE) == state["fixture_sha256"] and sha(Path(__file__)) == state["runner_sha256"],
                "A probe helper changed during execution.")
        state["status"] = "finished"
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError, KeyboardInterrupt) as error:
        failure = type(error).__name__ + ": " + str(error)
        state.update(status="incomplete", error=failure)
    finally:
        try:
            if launched:
                remove_own_container(name, identifier)
            state["cleanup_verified"] = True
        except (OSError, ValueError, subprocess.SubprocessError) as error:
            state["cleanup_error"] = str(error)
            state["status"] = "incomplete"
            failure = failure or "Probe container cleanup could not be verified."
        state["finished_at"] = datetime.now(timezone.utc).isoformat()
        save(output / "run.json", state)
    if failure:
        print("STOP:", failure)
        print("Artifacts retained:", output)
        print("Cleanup verified:", state["cleanup_verified"])
        raise SystemExit(1)
    summary = summarize(data, state)
    require(not (ROOT / PUBLIC).exists(), "A public probe summary already exists; it was not overwritten.")
    save(ROOT / PUBLIC, summary)
    save(output / "summary.json", summary)
    export_diagnostics(output, destination, state, inspection, summary, data)
    print("PERMISSION PROBE SAVED")
    print("Ordinary probes: 24; inherited-descriptor control: 1; legitimate-operation controls: 2.")
    print("All expected observations:", data["all_expected_observations"])
    print("Probe container removed:", state["cleanup_verified"])
    print("No model calls or baseline-result changes were made.")
    print("Upload: C:\\Users\\ihaxQ\\Downloads\\permission-probe-diagnostics.json")
    print("Local artifacts:", output)
    if not data["all_expected_observations"]:
        print("Some observations differ from expectations. Retain them for review; do not repeat the probe.")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
        raise SystemExit("STOP: " + str(error))
