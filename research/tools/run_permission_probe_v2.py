"""Run permission probe 02 (offline, disposable, synthetic).

Modes
  --mode docker   Run the fixture in a disposable container of the baseline image, mirroring probe 01's
                  container settings plus the two capabilities probe 02 needs (see EXTRA_CAPABILITIES).
  --mode local    Run the fixture directly on this machine as root inside a private tmpfs that this runner
                  mounts in its own mount namespace (falling back to mount/umount) and removes afterwards.
                  The setup process is restricted to docker mode's capability set unless --full-root-setup.

Utilities
  --compare A B          Compare the verdicts of two evidence files (reproducibility check).
  --render-tables FILE   Print the Markdown tables derived from an evidence file.

No model call, credential, network access or host bind mount is used. Standard library only.
"""

import argparse
from collections import Counter
import ctypes
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import signal
import struct
import subprocess
import sys
import tempfile
import uuid

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from research.tools import permission_probe_v2_fixture as fixture  # noqa: E402

FIXTURE = Path("research/tools/permission_probe_v2_fixture.py")
EVIDENCE = Path("research/reviews/permission-probe-02/evidence.json")
SUMMARY = Path("research/results/permission-probe-02-summary.json")
PROBE_01_SUMMARY = Path("research/results/permission-probe-01-summary.json")
LABEL = "org.cse227.permission-probe-v2"
TMPFS_OPTIONS = "rw,nosuid,nodev,noexec,size=64m,mode=0755"

# Capabilities of the trusted setup process in docker mode. The first four are probe 01's set.
BASE_CAPABILITIES = {
    "CHOWN": "assign fixture files and directories to the agent and recorder accounts",
    "DAC_OVERRIDE": "build fixtures inside directories owned by other accounts and read 0600 files for snapshots",
    "SETUID": "drop each child process to the unprivileged agent or recorder UID",
    "SETGID": "drop each child process to the unprivileged GID and set its supplementary groups",
}
EXTRA_CAPABILITIES = {
    "LINUX_IMMUTABLE": "the kernel requires it to set or clear the append-only (+a) and immutable (+i) "
                       "inode flags used by the flag layouts",
    "FOWNER": "FS_IOC_SETFLAGS requires owning the inode or CAP_FOWNER; the flag must be set after chown "
              "(chown is refused on a flagged inode), when UID 0 no longer owns the file; also lets the "
              "setup process empty sticky directories owned by other accounts during cleanup",
}
CAPABILITIES = {**BASE_CAPABILITIES, **EXTRA_CAPABILITIES}

PR_CAPBSET_DROP, PR_SET_NO_NEW_PRIVS, PR_SET_PDEATHSIG = 24, 38, 1
CLONE_NEWNS, MS_NOSUID, MS_NODEV, MS_NOEXEC, MS_REC, MS_PRIVATE = 0x20000, 2, 4, 8, 0x4000, 1 << 18
SHORT = {fixture.E: "E", fixture.D: "D", fixture.X: "X", fixture.UNEXPECTED: "ERR"}
LEGEND = ("E = effect observed, D = permission denial observed, X = different effect observed, "
          "S = suppression observed, R = suppression resisted, n/a = not run (not applicable to the layout), "
          "NR = not run (feature unavailable), no-fd = not run (the recorder identity itself could not open that "
          "descriptor), E(both)/E(dirfd-only) = names listed via both the path and the directory descriptor / "
          "only the descriptor, ERR = unexpected error; a trailing `!` marks a cell that differs from its coded "
          "expectation.")


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def read(path):
    return json.loads(Path(path).read_text())


def now():
    return datetime.now(timezone.utc).isoformat()


def command(args, **kwargs):
    result = subprocess.run(args, capture_output=True, text=True, timeout=60, **kwargs)
    require(result.returncode == 0, "Local command failed: " + " ".join(args[:3]) + "\n" + result.stderr[-2000:])
    return result.stdout.strip()


# ---------------------------------------------------------------- derived views (pure functions)

def _cell(row):
    if row["verdict"] == fixture.N:
        code = "NR" if row["matches_expectation"] is None else "n/a"
    else:
        code = SHORT[row["verdict"]]
    return code + ("!" if row["matches_expectation"] is False else "")


def _legit_cell(row):
    if row["outcome"] == fixture.N:
        return "NR"
    if row["judged"]:
        text = "pass" if row["passed"] else "denied" if row["outcome"] == "permission_denied" else "ERR"
    else:
        text = row["observed"] if row["observed"] != fixture.UNEXPECTED else "ERR"
    return text + ("!" if row["matches_expectation"] is False else "")


def _descriptor_cell(row):
    code = _cell(row)
    if row["verdict"] == fixture.N and row.get("descriptor", {}).get("obtained") is False:
        code = code.replace("n/a", "no-fd")
    if row["verdict"] == fixture.X:
        code = code.replace("X", "X(" + str(row.get("outcome")) + ")")
    if row["control"] == "dirfd_listdir" and row["verdict"] == fixture.E:
        code = "E(dirfd-only)" if row.get("outcome") == "names_listed_via_dirfd_only" else "E(both)"
    return code


def _suppression_cell(row):
    if row["verdict"] == fixture.N:
        code = "NR" if row["matches_expectation"] is None else "n/a"
    else:
        code = {fixture.S: "S", fixture.NOSUP: "R", fixture.UNEXPECTED: "ERR"}.get(row["verdict"], "ERR")
    return code + ("!" if row["matches_expectation"] is False else "")


def _denies_tampering_and_keeps_proxies(observations, case):
    tampering = [row for row in observations["rows"] if row["case"] == case
                 and row.get("counts_as_tampering", row["operation"] in fixture.TAMPERING_OPERATIONS)
                 and row["verdict"] != fixture.N]
    judged = [row for row in observations["legit_controls"] if row["case"] == case and row["judged"]]
    return (tampering and all(row["verdict"] == fixture.D for row in tampering)
            and judged and all(row.get("passed") is True for row in judged))


def _resists_suppression(observations, case):
    suppression = [row for row in observations.get("suppression_controls", []) if row["case"] == case
                   and row["verdict"] != fixture.N]
    return bool(suppression) and all(row["verdict"] == fixture.NOSUP for row in suppression)


def protecting_layouts(observations):
    """Layouts whose measured tampering operations were all denied and whose judged proxies all passed."""
    return [case for case in observations["layouts"]
            if _denies_tampering_and_keeps_proxies(observations, case)]


def protecting_and_suppression_resistant_layouts(observations):
    """Also resist both measured suppression-of-future-records operations."""
    return [case for case in observations["layouts"]
            if _denies_tampering_and_keeps_proxies(observations, case)
            and _resists_suppression(observations, case)]


def discriminating_legit_rows(observations):
    return [row for row in observations["legit_controls"]
            if row["outcome"] != fixture.N and row.get("layout_discriminating") is True]


def summarize(evidence):
    observations, run = evidence["observations"], evidence["run"]
    rows, legit, descriptors = (observations[key] for key in ("rows", "legit_controls", "descriptor_controls"))
    suppression = observations.get("suppression_controls", [])
    discriminating = discriminating_legit_rows(observations)
    cases = []
    for case in observations["layouts"]:
        mine = [row for row in rows if row["case"] == case]
        cases.append({
            "case": case, "filesystem": observations["layouts"][case]["filesystem"],
            "recorder_account": observations["layouts"][case]["recorder_account"],
            "operations": {row["operation"]: row["verdict"] for row in mine},
            "verdict_counts": dict(Counter(row["verdict"] for row in mine)),
            "legit_controls": {row["control"]: (row["outcome"] if row["judged"] or row["outcome"] == fixture.N
                                                else row["observed"])
                               for row in legit if row["case"] == case},
            "suppression_controls": {row["operation"]: row["verdict"]
                                     for row in suppression if row["case"] == case},
            "inherited_descriptor_controls": {
                row["control"]: {"verdict": row["verdict"], "outcome": row.get("outcome")}
                for row in descriptors if row["case"] == case}})
    mismatches = ([{"kind": "operation", "case": row["case"], "name": row["operation"],
                    "expected": row["expected"], "measured": row["verdict"]}
                   for row in rows if row["matches_expectation"] is False]
                  + [{"kind": "legit_control", "case": row["case"], "name": row["control"],
                      "expected": row.get("expected_pass", row.get("expected_observation")),
                      "measured": row.get("outcome") if row["judged"] else row.get("observed")}
                     for row in legit if row["matches_expectation"] is False]
                  + [{"kind": "descriptor_control", "case": row["case"], "name": row["control"],
                      "expected": [row["expected"], row["expected_outcome"]],
                      "measured": [row["verdict"], row.get("outcome")]}
                     for row in descriptors if row["matches_expectation"] is False]
                  + [{"kind": "suppression_control", "case": row["case"], "name": row["operation"],
                      "expected": row["expected"], "measured": row["verdict"]}
                     for row in suppression if row["matches_expectation"] is False])
    not_run = Counter()
    for kind, group, key in (("operation", rows, "verdict"), ("legit_control", legit, "outcome"),
                             ("descriptor_control", descriptors, "verdict"),
                             ("suppression_control", suppression, "verdict")):
        for row in group:
            if row[key] == fixture.N:
                not_run[(kind, row["not_run_reason"])] += 1
    protecting = protecting_layouts(observations)
    protecting_strict = protecting_and_suppression_resistant_layouts(observations)
    environment = observations["environment"]
    return {
        "protocol": observations["protocol"], "scope": observations["scope"], "mode": run["mode"],
        "executed_in_baseline_image": run["mode"] == "docker", "image_id": run.get("image_id"),
        "environment_note": run.get("environment_note"),
        "fixture_sha256": run["fixture_sha256"], "runner_sha256": run["runner_sha256"],
        "started_at": run["started_at"], "finished_at": run["finished_at"],
        "environment": {"kernel_release": environment["kernel_release"],
                        "python_version": environment["python_version"],
                        "sysctl_fs": environment["sysctl_fs"],
                        "setup_process_effective_capabilities":
                            environment["setup_process"]["effective_capability_names"],
                        "probe_roots": [{"label": item["label"], "fstype": item["filesystem"].get("fstype"),
                                         "features": {name: value["supported"]
                                                      for name, value in item["features"].items()}}
                                        for item in environment["probe_roots"]]},
        "layout_count": len(observations["layouts"]), "operation_count": len(observations["operation_definitions"]),
        "ordinary_cell_count": len(rows), "ordinary_verdict_counts": dict(Counter(row["verdict"] for row in rows)),
        "legit_control_count": len(legit),
        "judged_legit_outcome_counts": dict(Counter(row["outcome"] for row in legit if row["judged"])),
        "layout_discriminating_proxy_count": len(discriminating),
        "layout_discriminating_proxy_outcome_counts": dict(Counter(row["outcome"] for row in discriminating)),
        "harness_sanity_check_count": sum(1 for row in legit if row["judged"]
                                          and row.get("layout_discriminating") is False),
        "agent_read_transcript_counts": dict(Counter(row.get("observed", row["outcome"])
                                                     for row in legit if not row["judged"])),
        "descriptor_control_count": len(descriptors),
        "descriptor_verdict_counts": dict(Counter(row["verdict"] for row in descriptors)),
        "suppression_control_count": len(suppression),
        "suppression_verdict_counts": dict(Counter(row["verdict"] for row in suppression)),
        "cases": cases,
        "layouts_denying_all_measured_tampering_and_passing_all_judged_proxies": protecting,
        "layouts_also_resisting_both_suppression_operations": protecting_strict,
        "side_effect_operations_in_those_layouts": {
            case: {row["operation"]: row["verdict"] for row in rows
                   if row["case"] == case and row["operation"] in fixture.SIDE_EFFECT_OPERATIONS}
            for case in protecting},
        "expectation_mismatch_count": len(mismatches), "expectation_mismatches": mismatches,
        "not_run": [{"kind": kind, "count": count, "reason": reason}
                    for (kind, reason), count in sorted(not_run.items())],
        "all_evaluated_observations_match_expectation":
            observations["all_evaluated_observations_match_expectation"],
        "cleanup_verified": run["cleanup_verified"], "model_calls": 0, "native_agent_integration_tested": False,
        "limitations": [
            "Synthetic files and explicit syscall probes; not native transcript protection and not an agent trial.",
            "Legitimate-operation controls are synthetic proxies, not native Codex logging or resume tests.",
            "The current wrapper runs the native recorder and agent tools under one UID; the separate-recorder "
            "layouts describe a configuration that does not exist in the wrapper yet.",
            "In-process built-in edit tools run with the recorder's own authority and are not modelled.",
            "Inherited-descriptor controls pass a descriptor deliberately; whether a real harness leaks one "
            "to tool processes is unknown.",
            "Results depend on kernel, filesystem and sysctls (fs.protected_hardlinks, fs.protected_regular); "
            "local-mode results are not image-matched and must be re-measured with --mode docker in the "
            "baseline image.",
            "Disk-exhaustion suppression depends on the filesystem layout and per-filesystem quotas; the probe "
            "fills small dedicated tmpfs mounts, so its ENOSPC timing is not the production filesystem's.",
            "The precreate control was measured with fs.protected_regular=0; with protected_regular=1 or 2 the "
            "recorder's O_CREAT|O_APPEND open onto an agent-owned file in a sticky world-writable directory can "
            "itself be refused, which this run did not exercise.",
        ]}


def render_tables(evidence):
    """Markdown tables derived only from the evidence; embedded verbatim in the review README."""
    observations = evidence["observations"]
    cases = list(observations["layouts"])

    def table(header, group, key, names, cell):
        lines = ["| Layout | " + " | ".join(header) + " |", "| --- |" + " --- |" * len(header)]
        for case in cases:
            found = {row[key]: row for row in group if row["case"] == case}
            lines.append("| `%s` | %s |" % (case, " | ".join(cell(found[name]) for name in names)))
        return "\n".join(lines)

    operations = list(observations["operation_definitions"])
    legit = list(observations["legit_control_definitions"])
    descriptors = list(observations["descriptor_control_definitions"])
    suppression_ops = list(observations.get("suppression_control_definitions", {}))
    is_discriminating = {row["control"] for row in observations["legit_controls"]
                         if row.get("layout_discriminating") is True}
    discriminating = [name for name in legit if name in is_discriminating]
    sanity = [name for name in legit if name not in is_discriminating]
    totals = Counter(row["verdict"] for row in observations["rows"])
    summary = summarize(evidence)
    lines = ["Ordinary cells: %d. " % len(observations["rows"])
             + "; ".join("%s: %d" % (name, totals[name]) for name in sorted(totals)) + ".",
             "Layout-discriminating proxy controls: %d. " % summary["layout_discriminating_proxy_count"]
             + "; ".join("%s: %d" % item for item in
                         sorted(summary["layout_discriminating_proxy_outcome_counts"].items())) + ".",
             "Harness sanity checks (same in every layout): %d." % summary["harness_sanity_check_count"],
             "Inherited-descriptor controls: %d. " % len(observations["descriptor_controls"])
             + "; ".join("%s: %d" % item for item in sorted(summary["descriptor_verdict_counts"].items())) + ".",
             "Suppression-of-future-records controls: %d. " % summary["suppression_control_count"]
             + "; ".join("%s: %d" % item for item in sorted(summary["suppression_verdict_counts"].items())) + ".",
             "Expectation mismatches: %d." % summary["expectation_mismatch_count"]]
    return {
        "matrix": table(operations, observations["rows"], "operation", operations, _cell),
        "legit_discriminating": table(discriminating, observations["legit_controls"], "control",
                                      discriminating, _legit_cell),
        "legit_sanity": table(sanity, observations["legit_controls"], "control", sanity, _legit_cell),
        "descriptors": table(descriptors, observations["descriptor_controls"], "control", descriptors,
                             _descriptor_cell),
        "suppression": table(suppression_ops, observations["suppression_controls"], "operation",
                             suppression_ops, _suppression_cell),
        "totals": "\n".join("- " + line for line in lines),
        "protecting": "\n".join("- `%s`" % case for case in
                                summary["layouts_denying_all_measured_tampering_and_passing_all_judged_proxies"])
                      or "- (none)",
        "protecting_strict": "\n".join("- `%s`" % case for case in
                                       summary["layouts_also_resisting_both_suppression_operations"])
                             or "- (none)"}


def verdict_signature(evidence):
    """Everything that must be identical between two runs (inode numbers and times excluded)."""
    observations = evidence["observations"]
    signature = {}
    for row in observations["rows"]:
        signature["op/%s/%s" % (row["case"], row["operation"])] = [
            row["verdict"], (row.get("child") or {}).get("errno")]
    for row in observations["legit_controls"]:
        signature["legit/%s/%s" % (row["case"], row["control"])] = [
            row["outcome"], row.get("observed"), (row.get("child") or {}).get("errno")]
    for row in observations["descriptor_controls"]:
        signature["fd/%s/%s" % (row["case"], row["control"])] = [
            row["verdict"], row.get("outcome"), (row.get("child") or {}).get("errno")]
    for row in observations.get("suppression_controls", []):
        signature["suppress/%s/%s" % (row["case"], row["operation"])] = [row["verdict"], row.get("verdict_reason")
                                                                         if row["verdict"] == fixture.S else None]
    return signature


def _env_facts(evidence):
    env = evidence["observations"]["environment"]
    return {"kernel_release": env["kernel_release"], "python_version": env["python_version"],
            "sysctl_fs": env["sysctl_fs"],
            "setup_effective_capabilities": sorted(env["setup_process"]["effective_capability_names"]),
            "probe_root_filesystems": sorted({item["filesystem"].get("fstype") for item in env["probe_roots"]}),
            "mode": evidence["run"]["mode"]}


def compare(first, second):
    one, two = verdict_signature(first), verdict_signature(second)
    keys = set(one) | set(two)
    changed = sorted(key for key in keys if one.get(key) != two.get(key))
    # Split a bare not_run<->measured change from a real verdict change, so they are reported apart.
    not_run_vs_measured = [key for key in changed
                           if fixture.N in (one.get(key, [None])[0], two.get(key, [None])[0])]
    verdict_differences = [key for key in changed if key not in not_run_vs_measured]
    first_env, second_env = _env_facts(first), _env_facts(second)
    env_fields = sorted(set(first_env) | set(second_env))
    environment = {field: {"a": first_env.get(field), "b": second_env.get(field),
                           "same": first_env.get(field) == second_env.get(field)} for field in env_fields}
    return {"compared_measurements": len(keys), "environment": environment,
            "environment_identical": all(item["same"] for item in environment.values()),
            "verdict_differences": verdict_differences,
            "not_run_vs_measured_differences": not_run_vs_measured,
            "identical": not changed,
            "identical_verdicts": not verdict_differences}


# ---------------------------------------------------------------- docker mode

def container_command(image_id, name, identifier):
    capabilities = [item for capability in CAPABILITIES for item in ("--cap-add", capability)]
    return (["docker", "create", "--pull=never", "--name", name,
             "--label", LABEL + "=" + identifier, "--interactive", "--network", "none",
             "--read-only", "--user", "0:0", "--cap-drop", "ALL"] + capabilities
            + ["--security-opt", "no-new-privileges", "--pids-limit", "64",
               "--memory", "256m", "--cpus", "1", "--tmpfs", "/probe:" + TMPFS_OPTIONS,
               "--workdir", "/probe", "--entrypoint", "python3", image_id, "-I", "-"])


def selected_inspection(raw):
    config, host = raw["Config"], raw["HostConfig"]
    return {"image_reference": config["Image"], "container_image_id": raw["Image"],
            "user": config["User"], "entrypoint": config["Entrypoint"], "command": config["Cmd"],
            "network_mode": host["NetworkMode"], "readonly_rootfs": host["ReadonlyRootfs"],
            "cap_add": host["CapAdd"], "cap_drop": host["CapDrop"], "privileged": host.get("Privileged"),
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
    require(not record.get("privileged"), "The container must not be privileged.")
    normalize = lambda values: {value.upper().removeprefix("CAP_") for value in (values or [])}
    require(normalize(record["cap_drop"]) == {"ALL"} and normalize(record["cap_add"]) == set(CAPABILITIES),
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


def default_image():
    return read(ROOT / PROBE_01_SUMMARY)["image_id"]


def run_docker(image):
    """Returns (observations or None, run metadata, settings, error or None)."""
    require(command(["docker", "info", "--format", "{{.OSType}}"]) == "linux",
            "Docker must be running in Linux-container mode.")
    image_id = command(["docker", "image", "inspect", "--format", "{{.Id}}", image])
    require(image_id == image, "The baseline image is not available locally by this id; nothing was pulled.")
    identifier = uuid.uuid4().hex
    name = "cse227-permissions-v2-" + identifier[:16]
    run = {"mode": "docker", "image_id": image_id, "container_name": name, "container_identifier": identifier,
           "capabilities_added": CAPABILITIES, "cleanup_verified": False}
    settings, observations, failure, launched = None, None, None, False
    try:
        launched = True
        command(container_command(image_id, name, identifier))
        settings = selected_inspection(json.loads(command(["docker", "inspect", name]))[0])
        validate_inspection(settings)
        result = subprocess.run(["docker", "start", "--attach", "--interactive", name],
                                input=(ROOT / FIXTURE).read_bytes(), capture_output=True, timeout=900)
        run["fixture_exit_code"] = result.returncode
        run["fixture_stderr_tail"] = result.stderr.decode(errors="replace")[-2000:]
        require(result.returncode == 0, "Probe process failed: " + result.stdout.decode(errors="replace")[-500:])
        observations = json.loads(result.stdout)
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
        failure = type(error).__name__ + ": " + str(error)
    finally:
        try:
            if launched:
                remove_own_container(name, identifier)
            run["cleanup_verified"] = True
        except (OSError, ValueError, subprocess.SubprocessError) as error:
            run["cleanup_error"] = str(error)
            failure = failure or "Probe container cleanup could not be verified."
    return observations, run, settings, failure


# ---------------------------------------------------------------- local mode

FILL_TMPFS_OPTIONS = "rw,nosuid,nodev,noexec,size=4m,mode=0755"


def setup_preexec(tmpfs_mounts, restrict):
    """preexec_fn for the fixture process in local mode.

    tmpfs_mounts: list of (mount_point, options) to mount inside a fresh private mount namespace, so the
    mounts are visible only to the fixture process tree and vanish when it exits (leak-safe on crash).
    restrict: reduce the setup process to exactly docker mode's capability set (bounding, permitted and
    effective) and set no-new-privileges, so local setup cannot rely on privileges the container lacks.
    """
    libc = ctypes.CDLL(None, use_errno=True)
    libc.mount.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_ulong, ctypes.c_char_p]
    libc.capset.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
    keep = {fixture.CAPABILITY_NAMES.index(name) for name in CAPABILITIES}
    mask = sum(1 << bit for bit in keep)
    header = struct.pack("Ii", 0x20080522, 0)  # _LINUX_CAPABILITY_VERSION_3, this process
    data = struct.pack("IIIIII", mask & 0xFFFFFFFF, mask & 0xFFFFFFFF, 0, mask >> 32, mask >> 32, 0)

    def check(result, what):
        if result != 0:
            raise OSError(ctypes.get_errno(), what + " failed: " + os.strerror(ctypes.get_errno()))

    def enter():
        libc.prctl(PR_SET_PDEATHSIG, 9, 0, 0, 0)  # die if the runner dies before we drop privileges
        if tmpfs_mounts:
            check(libc.unshare(CLONE_NEWNS), "unshare(CLONE_NEWNS)")
            check(libc.mount(b"none", b"/", None, MS_REC | MS_PRIVATE, None), "mount(MS_PRIVATE)")
            for mount_point, options in tmpfs_mounts:
                data_option = "size=%s,mode=0755" % dict(part.split("=", 1) for part in options.split(",")
                                                         if "=" in part)["size"]
                check(libc.mount(b"tmpfs", os.fsencode(mount_point), b"tmpfs",
                                 MS_NOSUID | MS_NODEV | MS_NOEXEC, data_option.encode()), "mount(tmpfs)")
        if restrict:
            for bit in range(len(fixture.CAPABILITY_NAMES)):
                if bit not in keep:
                    check(libc.prctl(PR_CAPBSET_DROP, bit, 0, 0, 0), "prctl(PR_CAPBSET_DROP)")
            check(libc.capset(header, data), "capset")
            check(libc.prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0), "prctl(PR_SET_NO_NEW_PRIVS)")
    return enter


def mounted(path):
    path = os.path.realpath(path)
    for line in Path("/proc/self/mountinfo").read_text().splitlines():
        if line.split()[4] == path:
            return True
    return False


def fixture_command(mount_point, alt_root, fill_records=None, fill_workspace=None):
    args = [sys.executable, "-I", str(ROOT / FIXTURE), "--root", mount_point]
    if alt_root:
        args += ["--alt-root", alt_root]
    if fill_records:
        args += ["--fill-records-root", fill_records]
    if fill_workspace:
        args += ["--fill-workspace-root", fill_workspace]
    return args


class _Terminated(Exception):
    """Raised by the SIGTERM handler so cleanup runs rather than the process dying mid-run."""


def run_local(alt_parent=None, scratch_parent=None, restrict=True):
    """Returns (observations or None, run metadata, settings, error or None).

    Default: a private 64m tmpfs for the general layouts, two small dedicated tmpfs for the fill controls,
    and an alternate ext4 scratch root for flag/ACL layouts if the primary tmpfs lacks those features. All
    mount points are created under tempfile.gettempdir() (never /, which may be read-only).
    scratch_parent: use a fresh directory on scratch_parent's existing filesystem for the general layouts
    instead of a tmpfs (cross-filesystem comparison); the fill controls then have no dedicated tmpfs.
    """
    require(os.geteuid() == 0, "Local mode must run as root (it mounts tmpfs filesystems and drops UIDs).")
    temp = tempfile.gettempdir()
    use_tmpfs = scratch_parent is None
    created, tmpfs_mounts, fallback_mounted = [], [], []

    def scratch(prefix, parent):
        path = tempfile.mkdtemp(prefix=prefix, dir=parent)
        os.chmod(path, 0o755)
        created.append(path)
        return path

    mount_point = scratch("cse227-probe-v2-", temp if use_tmpfs else scratch_parent)
    fill_records = fill_workspace = alt_root = None
    if use_tmpfs:
        tmpfs_mounts.append((mount_point, TMPFS_OPTIONS))
        fill_records = scratch("cse227-probe-v2-fillrec-", temp)
        fill_workspace = scratch("cse227-probe-v2-fillws-", temp)
        tmpfs_mounts += [(fill_records, FILL_TMPFS_OPTIONS), (fill_workspace, FILL_TMPFS_OPTIONS)]
        if alt_parent:
            alt_root = scratch("cse227-probe-v2-alt-", alt_parent)
    command_line = fixture_command(mount_point, alt_root, fill_records, fill_workspace)
    run = {"mode": "local", "image_id": None, "cleanup_verified": False}
    settings = {"probe_root": mount_point, "probe_root_kind": "private tmpfs" if use_tmpfs else "scratch directory",
                "tmpfs_options": TMPFS_OPTIONS if use_tmpfs else None, "alternate_root": alt_root,
                "fill_records_root": fill_records, "fill_workspace_root": fill_workspace,
                "fill_tmpfs_options": FILL_TMPFS_OPTIONS if use_tmpfs else None, "mount_strategy": None,
                "setup_capabilities_restricted_to": sorted(CAPABILITIES) if restrict else None,
                "fixture_command": command_line}
    observations, failure, live = None, None, []
    previous = signal.getsignal(signal.SIGTERM)
    signal.signal(signal.SIGTERM, lambda *_: (_ for _ in ()).throw(_Terminated("received SIGTERM")))

    def run_fixture(preexec):
        process = subprocess.Popen(command_line, preexec_fn=preexec, stdin=subprocess.DEVNULL,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd="/")
        live.append(process)
        out, err = process.communicate(timeout=900)
        live.remove(process)
        return process.returncode, out, err

    try:
        try:
            code, out, err = run_fixture(setup_preexec(tmpfs_mounts, restrict))
            settings["mount_strategy"] = ("private mount namespace (unshare + tmpfs) around the fixture process"
                                          if use_tmpfs else "none (existing filesystem)")
        except subprocess.TimeoutExpired:
            raise
        except subprocess.SubprocessError as error:
            require(use_tmpfs, "Setup of the local fixture process failed: " + str(error))
            settings["private_namespace_error"] = str(error)
            for point, options in tmpfs_mounts:
                command(["mount", "-t", "tmpfs", "-o", options, "tmpfs", point])
                fallback_mounted.append(point)
            settings["mount_strategy"] = "mount -t tmpfs in the caller's namespace, unmounted afterwards"
            code, out, err = run_fixture(setup_preexec([], restrict))
        run["fixture_exit_code"] = code
        run["fixture_stderr_tail"] = err.decode(errors="replace")[-2000:]
        require(code == 0, "Probe process failed: " + out.decode(errors="replace")[-500:]
                + err.decode(errors="replace")[-1500:])
        observations = json.loads(out)
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError, _Terminated) as error:
        failure = type(error).__name__ + ": " + str(error)
    finally:
        signal.signal(signal.SIGTERM, previous)
        for process in live:  # kill a fixture still running (e.g. after SIGTERM) so it cannot write behind us
            process.kill()
            try:
                process.wait(timeout=10)
            except subprocess.SubprocessError:
                pass
        try:
            for point in fallback_mounted:
                if mounted(point):
                    command(["umount", point])
            for path in created:
                if os.path.isdir(path) and not mounted(path):
                    fixture.clear_flags_recursive(path)
                    shutil.rmtree(path)
            require(not any(mounted(path) for path in created) and not any(os.path.exists(path) for path in created),
                    "Probe directories or mounts remain.")
            run["cleanup_verified"] = True
        except (OSError, ValueError, subprocess.SubprocessError) as error:
            run["cleanup_error"] = str(error)
            failure = failure or "Local probe cleanup could not be verified."
    return observations, run, settings, failure


# ---------------------------------------------------------------- entry point

def save(path, text, overwrite):
    path = Path(path)
    require(path.parent.is_dir(), "Output directory is missing: " + str(path.parent))
    require(overwrite or not path.exists(), "Output already exists and was retained (use --overwrite): " + str(path))
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(text)
    temporary.replace(path)


def execute(arguments):
    started = now()
    hashes = {"fixture_sha256": sha(ROOT / FIXTURE), "runner_sha256": sha(Path(__file__))}
    for path in (arguments.evidence, arguments.summary):
        require(Path(path).parent.is_dir(), "Output directory is missing: " + str(Path(path).parent))
        require(arguments.overwrite or not Path(path).exists(),
                "Output already exists and was retained (use --overwrite): " + str(path))
    if arguments.mode == "docker":
        observations, run, settings, failure = run_docker(arguments.image or default_image())
    else:
        observations, run, settings, failure = run_local(
            None if arguments.no_alt_root else arguments.alt_parent,
            scratch_parent=arguments.local_scratch_parent, restrict=not arguments.full_root_setup)
    require(sha(ROOT / FIXTURE) == hashes["fixture_sha256"], "The fixture changed during the run.")
    run.update(hashes, started_at=started, finished_at=now(), error=failure, model_calls=0,
               environment_note=arguments.environment_note,
               command=[Path(sys.argv[0]).name] + sys.argv[1:],
               host={"kernel_release": platform.release(), "python_version": platform.python_version(),
                     "machine": platform.machine()},
               status="finished" if failure is None else "incomplete")
    if failure is not None:
        print("STOP:", failure)
        print("Cleanup verified:", run["cleanup_verified"])
        raise SystemExit(1)
    require(observations.get("protocol") == fixture.PROTOCOL
            and len(observations["rows"]) == len(fixture.CASES) * len(fixture.OPERATIONS)
            and len(observations["legit_controls"]) == len(fixture.CASES) * len(fixture.LEGIT_CONTROLS)
            and len(observations["descriptor_controls"]) == len(fixture.CASES) * len(fixture.DESCRIPTOR_CONTROLS)
            and len(observations["suppression_controls"]) == len(fixture.CASES) * len(fixture.SUPPRESSION_OPERATIONS),
            "Probe output is incomplete.")
    evidence = {"run": run, "environment_settings": settings, "observations": observations}
    save(arguments.evidence, json.dumps(evidence, indent=2) + "\n", arguments.overwrite)
    summary = summarize(evidence)
    summary["evidence_sha256"] = sha(arguments.evidence)
    save(arguments.summary, json.dumps(summary, indent=2) + "\n", arguments.overwrite)
    print("PERMISSION PROBE 02 SAVED (%s mode)" % arguments.mode)
    print("Ordinary cells:", summary["ordinary_cell_count"], summary["ordinary_verdict_counts"])
    print("Layout-discriminating proxy controls:", summary["layout_discriminating_proxy_count"],
          summary["layout_discriminating_proxy_outcome_counts"],
          "(+%d harness sanity checks)" % summary["harness_sanity_check_count"])
    print("Inherited-descriptor controls:", summary["descriptor_control_count"], summary["descriptor_verdict_counts"])
    print("Suppression-of-future-records controls:", summary["suppression_control_count"],
          summary["suppression_verdict_counts"])
    print("Layouts denying tampering + keeping proxies:",
          summary["layouts_denying_all_measured_tampering_and_passing_all_judged_proxies"])
    print("  of those, also resisting both suppression operations:",
          summary["layouts_also_resisting_both_suppression_operations"])
    print("Expectation mismatches:", summary["expectation_mismatch_count"])
    flag_not_run = [item for item in summary["not_run"]
                    if "inode flag" in item["reason"] and "not applicable" not in item["reason"]]
    if arguments.mode == "docker" and flag_not_run:
        print("NOTE: this kernel's filesystem lacked inode-flag support, so the four flag layouts are not_run:")
        for item in flag_not_run:
            print("  -", item["count"], item["kind"], "cells:", item["reason"])
    print("Cleanup verified:", run["cleanup_verified"])
    print("Evidence:", arguments.evidence)
    print("Summary:", arguments.summary)
    print("No model calls were made. Mismatching observations are retained for review, never adjusted.")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--mode", choices=("docker", "local"))
    parser.add_argument("--image", help="baseline image id for docker mode (default: probe 01's image id)")
    parser.add_argument("--evidence", default=str(ROOT / EVIDENCE))
    parser.add_argument("--summary", default=str(ROOT / SUMMARY))
    parser.add_argument("--overwrite", action="store_true", help="replace existing evidence/summary outputs")
    parser.add_argument("--alt-parent", default="/tmp",
                        help="local mode: directory on a non-tmpfs filesystem for the alternate scratch root")
    parser.add_argument("--no-alt-root", action="store_true", help="local mode: do not create an alternate root")
    parser.add_argument("--local-scratch-parent", default=None,
                        help="local mode: do not mount a tmpfs; use a fresh scratch directory under this "
                             "directory on its existing filesystem (cross-filesystem comparison)")
    parser.add_argument("--full-root-setup", action="store_true",
                        help="local mode: keep root's full capability set for the setup process instead of "
                             "restricting it to docker mode's set")
    parser.add_argument("--environment-note", default=None,
                        help="operator's free-text description of where this ran; stored verbatim")
    parser.add_argument("--compare", nargs=2, metavar=("EVIDENCE_A", "EVIDENCE_B"))
    parser.add_argument("--render-tables", metavar="EVIDENCE")
    arguments = parser.parse_args(argv)
    if arguments.compare:
        result = compare(read(arguments.compare[0]), read(arguments.compare[1]))
        print(json.dumps(result, indent=2))
        raise SystemExit(0 if result["identical_verdicts"] else 1)
    if arguments.render_tables:
        for name, text in render_tables(read(arguments.render_tables)).items():
            print("<!-- %s -->\n%s\n" % (name, text))
        return
    require(arguments.mode is not None, "Choose --mode docker or --mode local.")
    execute(arguments)


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
        raise SystemExit("STOP: " + str(error))
