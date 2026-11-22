"""Run permission probe 02 with its disk-fill controls executable inside a container.

The committed probe-02 fixture already accepts --fill-records-root and --fill-workspace-root, but the
committed docker mode never supplies them (an unprivileged container cannot mount filesystems), so in the
baseline-image run both fill operations were not_run for all 15 layouts (28 cells that could not be executed).
This runner changes nothing in the measurement code. It imports the committed runner and fixture and:

  --mode docker            builds the committed docker command and adds two size-limited tmpfs mounts that the
                           container RUNTIME provides (docker create --tmpfs), then passes their paths to the
                           fixture. NOT EXECUTABLE on a machine without a Docker daemon.
  --mode local-premounted  proves the fixture-side path: this process mounts the three tmpfs first, as a
                           container runtime would, then starts the committed fixture with the committed
                           capability restriction and the fill-root arguments. The fixture process itself
                           performs no mount (it has no CAP_SYS_ADMIN).

Evidence, summary, coverage and comparison all come from the committed runner's corrected code.
No model call, credential, network access or host bind mount is used. Standard library only.
"""

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import platform
import signal
import subprocess
import sys
import uuid

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from research.tools import permission_probe_v2_fixture as fixture  # noqa: E402
from research.tools import run_permission_probe_v2 as runner  # noqa: E402
from research.tools import run_permission_probe_v2_variants as variants  # noqa: E402

OUTPUT = Path("research/reviews/permission-probe-02-docker-fill")
COMMITTED_EVIDENCE = Path("research/reviews/permission-probe-02/evidence.json")
FILL_RECORDS, FILL_WORKSPACE = "/probe-fill-records", "/probe-fill-workspace"
# Every tmpfs option, and why. The fill mounts use exactly the committed local mode's fill options
# (runner.FILL_TMPFS_OPTIONS), so the ENOSPC point is the same as in the committed local evidence.
TMPFS_OPTION_REASONS = {
    "rw": "the fixture must create files there",
    "nosuid": "no set-user-ID program can gain privilege from the probe filesystems",
    "nodev": "no device nodes",
    "noexec": "nothing on the probe filesystems is executed (the workspace test is read by the interpreter)",
    "size=4m": "small fixed size so the agent's fill reaches ENOSPC quickly and cannot exhaust host memory; "
               "the fixture refuses a fill root larger than 8 MiB",
    "mode=0755": "root-owned mount root that the agent and recorder can traverse but not write",
}
EXPECTED_TMPFS = {"/probe": runner.TMPFS_OPTIONS, FILL_RECORDS: runner.FILL_TMPFS_OPTIONS,
                  FILL_WORKSPACE: runner.FILL_TMPFS_OPTIONS}
FIXTURE_ARGUMENTS = ["--fill-records-root", FILL_RECORDS, "--fill-workspace-root", FILL_WORKSPACE]
require = runner.require


def now():
    return datetime.now(timezone.utc).isoformat()


def container_command(image_id, name, identifier):
    """The committed docker command plus two runtime-provided fill tmpfs mounts and the fixture arguments."""
    command = runner.container_command(image_id, name, identifier)
    require(command[-2:] == ["-I", "-"] and command.count("--tmpfs") == 1, "Unexpected committed docker command.")
    position = command.index("--tmpfs") + 2
    extra = [item for path in (FILL_RECORDS, FILL_WORKSPACE)
             for item in ("--tmpfs", path + ":" + runner.FILL_TMPFS_OPTIONS)]
    return command[:position] + extra + command[position:] + FIXTURE_ARGUMENTS


def validate_inspection(record):
    """The committed validation for everything it covers, plus the exact tmpfs set and fixture arguments."""
    require(set(record["tmpfs"]) == set(EXPECTED_TMPFS),
            "Unexpected writable tmpfs mounts: %s" % sorted(record["tmpfs"]))
    for path, options in EXPECTED_TMPFS.items():
        require(set(record["tmpfs"][path].split(",")) == set(options.split(",")),
                "Unexpected options on %s: %s" % (path, record["tmpfs"][path]))
    require(record["command"] == ["-I", "-"] + FIXTURE_ARGUMENTS, "Unexpected trusted setup command.")
    require(all(item.get("Type") == "tmpfs" and item.get("Destination") in EXPECTED_TMPFS
                for item in record["mounts"]), "Unexpected mount in the container.")
    reduced = dict(record, tmpfs={"/probe": record["tmpfs"]["/probe"]}, command=["-I", "-"])
    runner.validate_inspection(reduced)  # network none, read-only rootfs, user, capabilities, no binds, ...


def run_docker(image):
    """Returns (observations or None, run metadata, settings, error or None). Mirrors runner.run_docker."""
    require(runner.command(["docker", "info", "--format", "{{.OSType}}"]) == "linux",
            "Docker must be running in Linux-container mode.")
    image_id = runner.command(["docker", "image", "inspect", "--format", "{{.Id}}", image])
    require(image_id == image, "The baseline image is not available locally by this id; nothing was pulled.")
    identifier = uuid.uuid4().hex
    name = "cse227-permissions-v2-fill-" + identifier[:16]
    run = {"mode": "docker-fill", "image_id": image_id, "container_name": name,
           "container_identifier": identifier, "capabilities_added": runner.CAPABILITIES,
           "tmpfs_mounts": EXPECTED_TMPFS, "cleanup_verified": False}
    settings, observations, failure, launched = None, None, None, False
    try:
        launched = True
        runner.command(container_command(image_id, name, identifier))
        settings = runner.selected_inspection(json.loads(runner.command(["docker", "inspect", name]))[0])
        validate_inspection(settings)
        result = subprocess.run(["docker", "start", "--attach", "--interactive", name],
                                input=(ROOT / runner.FIXTURE).read_bytes(), capture_output=True, timeout=900)
        run["fixture_exit_code"] = result.returncode
        run["fixture_stderr_tail"] = result.stderr.decode(errors="replace")[-2000:]
        require(result.returncode == 0, "Probe process failed: " + result.stdout.decode(errors="replace")[-500:])
        observations = json.loads(result.stdout)
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
        failure = type(error).__name__ + ": " + str(error)
    finally:
        try:
            if launched:
                runner.remove_own_container(name, identifier)
            run["cleanup_verified"] = True
        except (OSError, ValueError, subprocess.SubprocessError) as error:
            run["cleanup_error"] = str(error)
            failure = failure or "Probe container cleanup could not be verified."
    return observations, run, settings, failure


def run_local_premounted(parent=None):
    """Mount the three tmpfs here (as a runtime would), then run the committed fixture without mount rights."""
    require(os.geteuid() == 0, "local-premounted must run as root (it mounts tmpfs and drops to other UIDs).")
    run = {"mode": "local-premounted", "image_id": None, "cleanup_verified": False}
    settings, observations, failure, mounts = {}, None, None, None
    try:
        variants.enter_private_mount_namespace()
        mounts = variants.Mounts(parent)
        roots = mounts.build({"root": "tmpfs", "alternate_root": False, "fill": "tmpfs"})
        settings = {"roots": {key: roots[key] for key in ("root", "fill_records", "fill_workspace")},
                    "mounts_made_by_this_runner_before_the_fixture_started": variants.mount_lines(mounts.base),
                    "tmpfs_options": {"root": runner.TMPFS_OPTIONS, "fill": runner.FILL_TMPFS_OPTIONS},
                    "setup_capabilities_restricted_to": sorted(runner.CAPABILITIES),
                    "fixture_can_mount": "no: CAP_SYS_ADMIN is dropped from its bounding, permitted and "
                                         "effective sets before it starts"}
        command, code, out, err = variants.run_fixture(roots)
        settings["fixture_command"] = command
        run["fixture_exit_code"] = code
        run["fixture_stderr_tail"] = err.decode(errors="replace")[-1500:]
        require(code == 0, "Probe process failed: " + out.decode(errors="replace")[-500:]
                + err.decode(errors="replace")[-800:])
        observations = json.loads(out)
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
        failure = type(error).__name__ + ": " + str(error)
    finally:
        cleaned = mounts.cleanup() if mounts else True
        run["cleanup_verified"] = bool(cleaned)
        if not cleaned:
            failure = failure or "Mount cleanup could not be verified."
    return observations, run, settings, failure


def execute(arguments):
    started = now()
    hashes = {"fixture_sha256": runner.sha(ROOT / runner.FIXTURE), "runner_sha256": runner.sha(Path(runner.__file__)),
              "docker_fill_runner_sha256": runner.sha(Path(__file__))}
    for path in (arguments.evidence, arguments.summary):
        require(Path(path).parent.is_dir(), "Output directory is missing: " + str(Path(path).parent))
        require(not Path(path).exists(), "Output already exists and was retained (never overwritten): " + str(path))
    if arguments.mode == "docker":
        observations, run, settings, failure = run_docker(arguments.image or runner.default_image())
    else:
        observations, run, settings, failure = run_local_premounted(arguments.scratch_parent)
    run.update(hashes, started_at=started, finished_at=now(), error=failure, model_calls=0,
               environment_note=arguments.environment_note, command=[Path(sys.argv[0]).name] + sys.argv[1:],
               host={"kernel_release": platform.release(), "python_version": platform.python_version()},
               status="finished" if failure is None else "incomplete")
    if failure is not None:
        print("STOP:", failure)
        print("Cleanup verified:", run["cleanup_verified"])
        raise SystemExit(1)
    require(observations.get("protocol") == fixture.PROTOCOL
            and len(observations["suppression_controls"]) == len(fixture.CASES) * len(fixture.SUPPRESSION_OPERATIONS),
            "Probe output is incomplete.")
    evidence = {"run": run, "environment_settings": settings, "observations": observations}
    runner.save(arguments.evidence, json.dumps(evidence, indent=2) + "\n", False)
    summary = runner.summarize(evidence)
    summary["evidence_sha256"] = runner.sha(arguments.evidence)
    runner.save(arguments.summary, json.dumps(summary, indent=2) + "\n", False)
    print("PERMISSION PROBE 02 WITH FILL FILESYSTEMS SAVED (%s mode)" % arguments.mode)
    fills = [row for row in observations["suppression_controls"] if row["operation"].startswith("fill_")]
    print("Disk-fill cells: %d recorded, %d executed, %d not run" % (
        len(fills), sum(runner.not_run_kind(row) is None for row in fills),
        sum(runner.not_run_kind(row) is not None for row in fills)))
    runner.print_coverage_and_assessment(summary)
    print("Expectation mismatches:", summary["expectation_mismatch_count"])
    print("Cleanup verified:", run["cleanup_verified"])
    print("Evidence:", arguments.evidence, "sha256", summary["evidence_sha256"])
    print("Summary:", arguments.summary)
    print("Compare with the committed local evidence:\n  python3 research/tools/run_permission_probe_v2.py "
          "--compare %s %s" % (COMMITTED_EVIDENCE, arguments.evidence))
    print("No model calls were made. Observations are kept as measured, never adjusted.")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--mode", choices=("docker", "local-premounted"), required=True)
    parser.add_argument("--image", help="baseline image id for docker mode (default: probe 01's image id)")
    parser.add_argument("--evidence", required=True, help="new evidence file; an existing file is never overwritten")
    parser.add_argument("--summary", required=True, help="new summary file; an existing file is never overwritten")
    parser.add_argument("--scratch-parent", default=None, help="local-premounted: directory for the mount points")
    parser.add_argument("--environment-note", default=None, help="free text about where this ran; stored verbatim")
    arguments = parser.parse_args(argv)
    for number in (signal.SIGTERM, signal.SIGINT):
        signal.signal(number, variants._raise_interrupted)
    execute(arguments)


if __name__ == "__main__":
    try:
        main()
    except variants.Interrupted as error:
        raise SystemExit("STOP: " + str(error))
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
        raise SystemExit("STOP: " + str(error))
