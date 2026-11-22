"""Run permission probe 03: the integrated layout as one fixture (offline, disposable, synthetic).

Modes
  --mode local    Real run on this machine as root. This process enters a private mount namespace, mounts three
                  small dedicated filesystems (records, workspace, shared negative control), then starts the
                  fixture with the committed probe-02 capability restriction (no CAP_SYS_ADMIN, no-new-privs).
                  --filesystem tmpfs (default) or ext4-loop (two genuinely separate ext4 filesystems on loop
                  devices, plus a third for the negative control).
  --mode docker   The same payload in a disposable container of the baseline image; the three filesystems are
                  supplied by the container runtime (docker create --tmpfs). Mock-tested only on machines
                  without a Docker daemon.

Utilities
  --compare A B          The committed probe-02 runner's compare (coverage first, verdicts among cells executed
                         in both). Exit status 0 same coverage and verdicts, 1 a verdict differs, 3 coverage only.
  --render-tables FILE   Print the Markdown tables derived from an evidence file.

The fixture runs from a stdin bundle that carries the committed probe-02 fixture and the probe-03 fixture, so
the container needs no host bind mount. No model call, credential or network access. Standard library only.
"""

import argparse
from collections import Counter
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
from research.tools import permission_probe_v3_fixture as fixture  # noqa: E402
from research.tools import run_permission_probe_v2 as base  # noqa: E402
from research.tools import run_permission_probe_v2_variants as variants  # noqa: E402

v2 = fixture.v2
V2_FIXTURE = Path("research/tools/permission_probe_v2_fixture.py")
V3_FIXTURE = Path("research/tools/permission_probe_v3_fixture.py")
EVIDENCE = Path("research/reviews/permission-probe-03/evidence.json")
SUMMARY = Path("research/results/permission-probe-03-summary.json")
LABEL = "org.cse227.permission-probe-v3"
# rw/nosuid/nodev/noexec/mode as in probe 02. size=8m: small, so a fill reaches ENOSPC quickly and stays far
# below the container memory limit. nr_inodes=1024: bounds the inode-exhaustion control.
TMPFS_OPTIONS = "rw,nosuid,nodev,noexec,size=8m,nr_inodes=1024,mode=0755"
CONTAINER_ROOTS = {"records": "/probe-records", "workspace": "/probe-workspace", "shared": "/probe-shared"}
HOLDS, FAILS, UNDETERMINED = base.HOLDS, base.FAILS, base.UNDETERMINED
SHORT = {v2.E: "E", v2.D: "D", fixture.BOUNDARY: "B", v2.X: "X", v2.S: "S", v2.NOSUP: "R", v2.UNEXPECTED: "ERR"}
LEGEND = ("D = permission denial observed, B = blocked by the filesystem boundary (EXDEV, not a permission "
          "decision), E = effect observed, X = different effect observed, S = suppression observed, "
          "R = suppression resisted, n/a = not applicable to the layout, no-fd = the layout refused the recorder "
          "the descriptor, NR = could not be executed in this environment, ERR = unexpected error; a trailing "
          "`!` marks a cell that differs from its coded expectation.")
require, sha, read = base.require, base.sha, base.read


def now():
    return datetime.now(timezone.utc).isoformat()


def bundle():
    """One Python program for stdin: registers the committed probe-02 fixture as a module, then runs probe 03."""
    parts = ["import sys, types",
             "_module = types.ModuleType('permission_probe_v2_fixture')",
             "exec(compile(%r, 'permission_probe_v2_fixture.py', 'exec'), _module.__dict__)"
             % (ROOT / V2_FIXTURE).read_text(),
             "sys.modules['permission_probe_v2_fixture'] = _module",
             "exec(compile(%r, 'permission_probe_v3_fixture.py', 'exec'), {'__name__': '__main__'})"
             % (ROOT / V3_FIXTURE).read_text()]
    return ("\n".join(parts) + "\n").encode()


def fixture_arguments(roots):
    return ["--records-root", roots["records"], "--workspace-root", roots["workspace"],
            "--shared-root", roots["shared"]]


# ---------------------------------------------------------------- derived views (pure functions)

def _tamper_judge(row):
    return {v2.D: True, fixture.BOUNDARY: True, v2.E: False, v2.X: False}.get(row["verdict"])


def _proxy_judge(row):
    if row.get("passed") is True:
        return True
    return False if row["outcome"] in ("permission_denied", "starved_enospc") else None


def _suppression_judge(row):
    return {v2.NOSUP: True, v2.S: False}.get(row["verdict"])


def assess(observations):
    """Per layout: (a) tampering, (b) suppression, (c) layout-discriminating proxies, three-valued."""
    result = {}
    for layout in observations["layouts"]:
        tampering = [("op/%s/%s" % (layout, row["operation"]), row) for row in observations["rows"]
                     if row["case"] == layout and row["counts_as_tampering"]]
        suppression = [("suppress/%s/%s" % (layout, row["operation"]), row)
                       for row in observations["suppression_controls"] if row["case"] == layout]
        proxies = [("legit/%s/%s" % (layout, row["control"]), row) for row in observations["legit_controls"]
                   if row["case"] == layout and row["judged"] and row["layout_discriminating"]]
        entry = {"a_all_tampering_denied_or_blocked": base._requirement(tampering, _tamper_judge),
                 "b_all_suppression_operations_resisted": base._requirement(suppression, _suppression_judge),
                 "c_all_layout_discriminating_proxies_pass": base._requirement(proxies, _proxy_judge)}
        entry["a_all_tampering_denied_or_blocked"]["satisfied_by"] = dict(Counter(
            row["verdict"] for _, row in tampering if _tamper_judge(row) is True))
        entry["all_three"] = base.combine(entry, list(entry))["status"]
        result[layout] = entry
    return result


def negative_controls(observations):
    """Did each negative control show the failure it was built to show?"""
    groups = {"ordinary": ("rows", "operation"), "descriptors": ("descriptor_controls", "control"),
              "suppression": ("suppression_controls", "operation")}
    result = {}
    for layout, cells in observations["negative_control_signals"].items():
        if layout not in observations["layouts"]:
            continue
        checks = []
        for group, name, designed in cells:
            key, field = groups[group]
            found = [row for row in observations[key] if row["case"] == layout and row[field] == name]
            measured = found[0]["verdict"] if found else None
            checks.append({"cell": "%s/%s" % (group, name), "designed_to_show": designed, "measured": measured,
                           "shown": measured == designed})
        result[layout] = {"breaks": observations["layouts"][layout].get("breaks"), "signals": checks,
                          "failure_detected": all(check["shown"] for check in checks),
                          "undetermined": any(check["measured"] in (None, v2.N, v2.UNEXPECTED) for check in checks)}
    return result


def descriptor_effects(observations, layout):
    """Inherited-descriptor controls of a layout: which were executed and which had an effect on the transcript
    or revealed its directory listing. Not part of requirements (a)-(c); reported beside them."""
    rows = [row for row in observations["descriptor_controls"] if row["case"] == layout]
    executed = [row for row in rows if base.not_run_kind(row) is None]
    return {"executed": len(executed), "recorded": len(rows),
            "effect": [row["control"] for row in executed if row["verdict"] in (v2.E, v2.X)],
            "denied": [row["control"] for row in executed if row["verdict"] == v2.D],
            "not_run": [row["control"] for row in rows if base.not_run_kind(row) is not None]}


def descriptor_contrast(observations, plain="N3_inherited_descriptor_no_flag", flagged="I3_readonly_append_only"):
    """The same inherited descriptor without and with the append-only inode flag."""
    found = {(row["case"], row["control"]): row for row in observations["descriptor_controls"]}
    return {control: {plain: (found.get((plain, control)) or {}).get("verdict"),
                      flagged: (found.get((flagged, control)) or {}).get("verdict")}
            for control in observations["descriptor_control_definitions"]}


def statement(observations):
    """The code-derived final statement, one line per integrated layout and per negative control."""
    lines, assessment = [], assess(observations)
    names = {"a_all_tampering_denied_or_blocked": "(a) tampering",
             "b_all_suppression_operations_resisted": "(b) suppression",
             "c_all_layout_discriminating_proxies_pass": "(c) layout-discriminating proxies"}
    for layout, entry in assessment.items():
        if observations["layouts"][layout]["kind"] != "integrated":
            continue
        parts = []
        for key, title in names.items():
            part = entry[key]
            text = "%s %s: %d cells good" % (title, part["status"].upper(), len(part["satisfied"]))
            if key.startswith("a_") and part["satisfied_by"]:
                text += " (%s)" % ", ".join("%d %s" % (count, verdict) for verdict, count
                                            in sorted(part["satisfied_by"].items()))
            if part["failing"]:
                text += "; failing: " + ", ".join(cell.split("/", 2)[2] for cell in part["failing"])
            if part["missing"]:
                text += "; undetermined: " + ", ".join(item["cell"].split("/", 2)[2] for item in part["missing"])
            if part["not_applicable"]:
                text += "; %d not applicable" % len(part["not_applicable"])
            parts.append(text)
        passed_on = descriptor_effects(observations, layout)
        parts.append("Separately, with a descriptor deliberately passed to the agent: effect in %d of %d executed "
                     "controls (%s)" % (len(passed_on["effect"]), passed_on["executed"],
                                        ", ".join(passed_on["effect"]) or "none"))
        lines.append("`%s`: " % layout + ". ".join(parts) + ".")
    for layout, entry in negative_controls(observations).items():
        shown = ", ".join("%s = %s" % (check["cell"].split("/", 1)[1], check["measured"])
                          for check in entry["signals"])
        lines.append("`%s` (breaks: %s): designed failure %s (%s)." % (
            layout, entry["breaks"], "DETECTED" if entry["failure_detected"] else
            "UNDETERMINED" if entry["undetermined"] else "NOT detected", shown))
    return lines


def summarize(evidence):
    observations, run = evidence["observations"], evidence["run"]
    groups = (("operation", "rows"), ("legit_control", "legit_controls"),
              ("descriptor_control", "descriptor_controls"), ("suppression_control", "suppression_controls"))
    mismatches, not_run = [], Counter()
    for kind, key in groups:
        for row in observations[key]:
            name = row.get("operation", row.get("control"))
            if row["matches_expectation"] is False:
                mismatches.append({"kind": kind, "layout": row["case"], "name": name,
                                   "expected": row.get("expected", row.get("expected_pass",
                                                                           row.get("expected_observation"))),
                                   "measured": base.row_verdict(row)})
            if base.not_run_kind(row) is not None:
                not_run[(kind, base.not_run_kind(row), row.get("not_run_reason"))] += 1
    environment = observations["environment"]
    sections = Counter()
    for row in observations["rows"]:
        sections[(row.get("section"), row["verdict"])] += 1
    return {
        "protocol": observations["protocol"], "scope": observations["scope"], "mode": run["mode"],
        "filesystem_kind": run.get("filesystem_kind"), "executed_in_baseline_image": run["mode"] == "docker",
        "image_id": run.get("image_id"), "environment_note": run.get("environment_note"),
        "probe_02_fixture_sha256": run["probe_02_fixture_sha256"], "fixture_sha256": run["fixture_sha256"],
        "runner_sha256": run["runner_sha256"], "started_at": run["started_at"], "finished_at": run["finished_at"],
        "environment": {"kernel_release": environment["kernel_release"],
                        "python_version": environment["python_version"], "sysctl_fs": environment["sysctl_fs"],
                        "setup_process_effective_capabilities":
                            environment["setup_process"]["effective_capability_names"],
                        "filesystems_distinct": environment["filesystems_distinct"],
                        "probe_roots": [{"label": item["label"], "fstype": item["filesystem"].get("fstype"),
                                         "capacity": item["capacity"],
                                         "features": {name: value["supported"]
                                                      for name, value in item["features"].items()}}
                                        for item in environment["probe_roots"]]},
        "coverage": base.coverage(observations),
        "ordinary_and_window_verdict_counts": {"%s/%s" % key: count for key, count in sorted(sections.items())},
        "legit_outcome_counts": dict(Counter(row["outcome"] for row in observations["legit_controls"])),
        "descriptor_verdict_counts": dict(Counter(row["verdict"] for row in observations["descriptor_controls"])),
        "suppression_verdict_counts": dict(Counter(row["verdict"] for row in observations["suppression_controls"])),
        "assessment_rule": base.ASSESSMENT_RULE,
        "assessment": assess(observations), "negative_controls": negative_controls(observations),
        "inherited_descriptor_effects": {layout: descriptor_effects(observations, layout)
                                         for layout in observations["layouts"]},
        "inherited_descriptor_contrast_without_and_with_append_only": descriptor_contrast(observations),
        "statement": statement(observations),
        "expectation_mismatch_count": len(mismatches), "expectation_mismatches": mismatches,
        "not_run": [{"kind": kind, "why": why, "count": count, "reason": reason}
                    for (kind, why, reason), count in sorted(not_run.items(), key=lambda item: str(item[0]))],
        "all_evaluated_observations_match_expectation":
            observations["all_evaluated_observations_match_expectation"],
        "cleanup_verified": run["cleanup_verified"], "model_calls": 0, "native_agent_integration_tested": False,
        "limitations": [
            "Synthetic files and explicit syscalls; not native transcript protection and not an agent trial.",
            "Legitimate-operation controls are synthetic proxies, not native Codex logging or resume.",
            "The current wrapper runs recorder and tools under one UID; these layouts do not exist in it yet.",
            "The sealer is modelled by the trusted setup process; nothing here shows who would run it natively "
            "or how long the unsealed window would be.",
            "A cell blocked by the filesystem boundary (EXDEV) did not test the permission behind it.",
            "Inherited-descriptor controls pass a descriptor on purpose.",
            "Small dedicated filesystems: ENOSPC timing and inode counts are the probe's, not production's.",
            "A result from one environment is not a result for another; cells not executed are undetermined.",
        ]}


def _code(row):
    kind = base.not_run_kind(row)
    if kind is not None:
        code = {base.NOT_APPLICABLE: "n/a", base.PRECONDITION_REFUSED: "no-fd", base.NOT_EXECUTED: "NR"}[kind]
    elif "verdict" in row:
        code = SHORT[row["verdict"]]
        if row["verdict"] == v2.X:
            code = "X(%s)" % row.get("outcome")
        if row.get("control") == "dirfd_listdir" and row["verdict"] == v2.E:
            code = "E(dirfd-only)" if row.get("outcome") == "names_listed_via_dirfd_only" else "E(both)"
    elif row["judged"]:
        code = {"passed": "pass", "permission_denied": "denied", "starved_enospc": "starved"}.get(row["outcome"], "ERR")
    else:
        code = row["observed"] if row["observed"] != v2.UNEXPECTED else "ERR"
    return code + ("!" if row["matches_expectation"] is False else "")


def render_tables(evidence):
    """Markdown tables derived only from the evidence; embedded verbatim in the review README."""
    observations = evidence["observations"]
    summary = summarize(evidence)

    def table(rows, field, names, strip=""):
        layouts = [layout for layout in observations["layouts"] if any(row["case"] == layout for row in rows)]
        lines = ["| Layout | " + " | ".join(name[len(strip):] for name in names) + " |",
                 "| --- |" + " --- |" * len(names)]
        for layout in layouts:
            found = {row[field]: row for row in rows if row["case"] == layout}
            lines.append("| `%s` | %s |" % (layout, " | ".join(_code(found[name]) if name in found else "-"
                                                              for name in names)))
        return "\n".join(lines)

    ordinary = [row for row in observations["rows"] if row.get("section") == fixture.ORDINARY]
    window = [row for row in observations["rows"] if row.get("section") == fixture.WINDOW]
    seals = ["| Layout | window operations where the file was intact, sealed, and the recorder then appended |",
             "| --- | --- |"]
    for layout in observations["layouts"]:
        mine = [row for row in window if row["case"] == layout and "seal" in row]
        if mine:
            seals.append("| `%s` | %d of %d |" % (layout, sum(
                row["seal"].get("recorder_append_after_seal_passed") is True for row in mine), len(mine)))
    coverage = summary["coverage"]["total"]
    totals = ["Recorded %d, executed %d, not run %d (%d not applicable to the layout, %d recorder precondition "
              "refused by the layout, %d could not be executed in this environment)." % (
                  coverage["recorded"], coverage["executed"], coverage["not_run"],
                  coverage["not_run_by_kind"][base.NOT_APPLICABLE],
                  coverage["not_run_by_kind"][base.PRECONDITION_REFUSED],
                  coverage["not_run_by_kind"][base.NOT_EXECUTED]),
              "Ordinary and new-session-window cells: " + "; ".join(
                  "%s: %d" % item for item in summary["ordinary_and_window_verdict_counts"].items()) + ".",
              "Inherited-descriptor cells: " + "; ".join(
                  "%s: %d" % item for item in sorted(summary["descriptor_verdict_counts"].items())) + ".",
              "Suppression cells: " + "; ".join(
                  "%s: %d" % item for item in sorted(summary["suppression_verdict_counts"].items())) + ".",
              "Legitimate-proxy rows: " + "; ".join(
                  "%s: %d" % item for item in sorted(summary["legit_outcome_counts"].items())) + ".",
              "Expectation mismatches: %d." % summary["expectation_mismatch_count"]]
    return {
        "ordinary": table(ordinary, "operation", list(observations["operation_definitions"])),
        "window": table(window, "operation", [fixture.WINDOW_PREFIX + name
                                               for name in observations["window_operations"]],
                        fixture.WINDOW_PREFIX),
        "seal": "\n".join(seals),
        "suppression": table(observations["suppression_controls"], "operation",
                             list(observations["suppression_control_definitions"])),
        "descriptors": table(observations["descriptor_controls"], "control",
                             list(observations["descriptor_control_definitions"])),
        "legit": table(observations["legit_controls"], "control", list(observations["legit_control_definitions"])),
        "coverage": base.render_coverage(summary["coverage"]),
        "totals": "\n".join("- " + line for line in totals),
        "statement": "\n".join("- " + line for line in summary["statement"])}


# ---------------------------------------------------------------- docker mode

def container_command(image_id, name, identifier):
    """The committed probe-02 docker command with its hardening flags, three runtime tmpfs and the arguments."""
    command = base.container_command(image_id, name, identifier)
    require(command[-2:] == ["-I", "-"] and command.count("--tmpfs") == 1 and command.count("--workdir") == 1
            and command.count("--label") == 1, "Unexpected committed docker command.")
    position = command.index("--tmpfs")
    mounts = [item for path in CONTAINER_ROOTS.values() for item in ("--tmpfs", path + ":" + TMPFS_OPTIONS)]
    command = command[:position] + mounts + command[position + 2:]
    command[command.index("--workdir") + 1] = CONTAINER_ROOTS["workspace"]
    command[command.index("--label") + 1] = LABEL + "=" + identifier
    return command + fixture_arguments(CONTAINER_ROOTS)


def validate_inspection(record):
    paths = set(CONTAINER_ROOTS.values())
    require(set(record["tmpfs"]) == paths, "Unexpected writable tmpfs mounts: %s" % sorted(record["tmpfs"]))
    for path in paths:
        require(set(record["tmpfs"][path].split(",")) == set(TMPFS_OPTIONS.split(",")),
                "Unexpected options on %s: %s" % (path, record["tmpfs"][path]))
    require(record["command"] == ["-I", "-"] + fixture_arguments(CONTAINER_ROOTS),
            "Unexpected trusted setup command.")
    require(all(item.get("Type") == "tmpfs" and item.get("Destination") in paths for item in record["mounts"]),
            "Unexpected mount in the container.")
    base.validate_inspection(dict(record, tmpfs={"/probe": "checked above"}, command=["-I", "-"]))


def remove_own_container(name, identifier):
    query = ["docker", "ps", "--all", "--filter", "label=" + LABEL + "=" + identifier, "--format", "{{.Names}}"]
    names = base.command(query).splitlines()
    require(all(value == name for value in names), "Unexpected container shares this probe's identifier.")
    if names:
        base.command(["docker", "rm", "--force", name])
    require(base.command(query) == "", "The disposable probe container still exists.")


def run_docker(image):
    """Returns (observations or None, run metadata, settings, error or None)."""
    require(base.command(["docker", "info", "--format", "{{.OSType}}"]) == "linux",
            "Docker must be running in Linux-container mode.")
    image_id = base.command(["docker", "image", "inspect", "--format", "{{.Id}}", image])
    require(image_id == image, "The baseline image is not available locally by this id; nothing was pulled.")
    identifier = uuid.uuid4().hex
    name = "cse227-permissions-v3-" + identifier[:16]
    run = {"mode": "docker", "filesystem_kind": "tmpfs", "image_id": image_id, "container_name": name,
           "container_identifier": identifier, "capabilities_added": base.CAPABILITIES, "cleanup_verified": False}
    settings, observations, failure, launched = None, None, None, False
    try:
        launched = True
        base.command(container_command(image_id, name, identifier))
        settings = base.selected_inspection(json.loads(base.command(["docker", "inspect", name]))[0])
        validate_inspection(settings)
        result = subprocess.run(["docker", "start", "--attach", "--interactive", name], input=bundle(),
                                capture_output=True, timeout=900)
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

def build_roots(mounts, kind):
    """Three dedicated filesystems under the mounts base. Returns {label: path}."""
    roots = {}
    for label in CONTAINER_ROOTS:
        if kind == "tmpfs":
            roots[label] = mounts.tmpfs(label, TMPFS_OPTIONS)
            continue
        image = os.path.join(mounts.base, label + ".ext4")
        with open(image, "wb") as handle:
            handle.truncate(16 * 1024 * 1024)
        variants.run_tool(["mkfs.ext4", "-q", "-F", "-m", "0", "-N", "1024", "-O", "^has_journal", image])
        roots[label] = mounts.mount(["-o", "loop,nosuid,nodev,noexec", image], mounts.directory(label))
        lost = os.path.join(roots[label], "lost+found")
        if os.path.isdir(lost):
            os.rmdir(lost)
        os.chmod(roots[label], 0o755)
    return roots


def run_local(kind="tmpfs", parent=None, layouts=None):
    """Returns (observations or None, run metadata, settings, error or None)."""
    require(os.geteuid() == 0, "Local mode must run as root (it mounts filesystems and drops to other UIDs).")
    run = {"mode": "local", "filesystem_kind": kind, "image_id": None, "cleanup_verified": False}
    settings, observations, failure, mounts, process = {}, None, None, None, None
    try:
        variants.enter_private_mount_namespace()
        mounts = variants.Mounts(parent)
        roots = build_roots(mounts, kind)
        command = [sys.executable, "-I", "-"] + fixture_arguments(roots) + (
            ["--layouts", ",".join(layouts)] if layouts else [])
        settings = {"roots": roots, "filesystem_kind": kind,
                    "tmpfs_options": TMPFS_OPTIONS if kind == "tmpfs" else None,
                    "mounts_made_by_this_runner_before_the_fixture_started": variants.mount_lines(mounts.base),
                    "setup_capabilities_restricted_to": sorted(base.CAPABILITIES),
                    "fixture_command": command, "fixture_program": "stdin bundle of the probe-02 and probe-03 fixtures"}
        process = subprocess.Popen(command, preexec_fn=base.setup_preexec([], True), stdin=subprocess.PIPE,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd="/")
        out, err = process.communicate(bundle(), timeout=900)
        run["fixture_exit_code"] = process.returncode
        run["fixture_stderr_tail"] = err.decode(errors="replace")[-1500:]
        require(process.returncode == 0, "Probe process failed: " + out.decode(errors="replace")[-600:]
                + err.decode(errors="replace")[-900:])
        observations = json.loads(out)
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
        failure = type(error).__name__ + ": " + str(error)
    finally:
        if process is not None and process.poll() is None:
            process.kill()
            process.wait()
        cleaned = mounts.cleanup() if mounts else True
        run["cleanup_verified"] = bool(cleaned)
        if not cleaned:
            failure = failure or "Mount cleanup could not be verified."
    return observations, run, settings, failure


# ---------------------------------------------------------------- entry point

def print_result(summary, out=None):
    def show(*parts):
        print(*parts, file=out or sys.stdout)

    total = summary["coverage"]["total"]
    show("Coverage: recorded %d, executed %d, not run %d (%d not applicable to the layout, %d recorder "
         "precondition refused by the layout, %d COULD NOT BE EXECUTED in this environment)" % (
             total["recorded"], total["executed"], total["not_run"], total["not_run_by_kind"][base.NOT_APPLICABLE],
             total["not_run_by_kind"][base.PRECONDITION_REFUSED], total["not_run_by_kind"][base.NOT_EXECUTED]))
    for item in summary["not_run"]:
        if item["why"] == base.NOT_EXECUTED:
            show("  NOT EXECUTED HERE: %d %s cells: %s" % (item["count"], item["kind"], item["reason"]))
    show("Statement derived from the evidence (holds / fails / undetermined, never anything stronger):")
    for line in summary["statement"]:
        show("  " + line)
    show("Expectation mismatches:", summary["expectation_mismatch_count"])
    for item in summary["expectation_mismatches"]:
        show("  MISMATCH %(kind)s %(layout)s %(name)s: expected %(expected)s, measured %(measured)s" % item)


def execute(arguments):
    started = now()
    hashes = {"probe_02_fixture_sha256": sha(ROOT / V2_FIXTURE), "fixture_sha256": sha(ROOT / V3_FIXTURE),
              "runner_sha256": sha(Path(__file__)), "probe_02_runner_sha256": sha(Path(base.__file__))}
    for path in (arguments.evidence, arguments.summary):
        require(Path(path).parent.is_dir(), "Output directory is missing: " + str(Path(path).parent))
        require(arguments.overwrite or not Path(path).exists(),
                "Output already exists and was retained (use --overwrite): " + str(path))
    if arguments.mode == "docker":
        observations, run, settings, failure = run_docker(arguments.image or base.default_image())
    else:
        observations, run, settings, failure = run_local(
            arguments.filesystem, arguments.scratch_parent,
            arguments.layouts.split(",") if arguments.layouts else None)
    run.update(hashes, started_at=started, finished_at=now(), error=failure, model_calls=0,
               environment_note=arguments.environment_note, command=[Path(sys.argv[0]).name] + sys.argv[1:],
               host={"kernel_release": platform.release(), "python_version": platform.python_version()},
               status="finished" if failure is None else "incomplete")
    if failure is not None:
        print("STOP:", failure)
        print("Cleanup verified:", run["cleanup_verified"])
        raise SystemExit(1)
    require(observations.get("protocol") == fixture.PROTOCOL, "Probe output is incomplete.")
    evidence = {"run": run, "environment_settings": settings, "observations": observations}
    base.save(arguments.evidence, json.dumps(evidence, indent=1) + "\n", arguments.overwrite)
    summary = summarize(evidence)
    summary["evidence_sha256"] = sha(arguments.evidence)
    base.save(arguments.summary, json.dumps(summary, indent=2) + "\n", arguments.overwrite)
    print("PERMISSION PROBE 03 SAVED (%s mode, %s)" % (arguments.mode, run["filesystem_kind"]))
    print_result(summary)
    print("Cleanup verified:", run["cleanup_verified"])
    print("Evidence:", arguments.evidence, "sha256", summary["evidence_sha256"])
    print("Summary:", arguments.summary)
    print("No model calls were made. Observations are kept as measured, never adjusted.")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--mode", choices=("docker", "local"))
    parser.add_argument("--filesystem", choices=("tmpfs", "ext4-loop"), default="tmpfs",
                        help="local mode: kind of the three dedicated filesystems")
    parser.add_argument("--image", help="baseline image id for docker mode (default: probe 01's image id)")
    parser.add_argument("--evidence", default=str(ROOT / EVIDENCE))
    parser.add_argument("--summary", default=str(ROOT / SUMMARY))
    parser.add_argument("--overwrite", action="store_true", help="replace existing evidence/summary outputs")
    parser.add_argument("--layouts", default=None, help="local mode: comma-separated layout names (partial run)")
    parser.add_argument("--scratch-parent", default=None, help="local mode: directory for the mount points")
    parser.add_argument("--environment-note", default=None, help="free text about where this ran; stored verbatim")
    parser.add_argument("--compare", nargs=2, metavar=("EVIDENCE_A", "EVIDENCE_B"))
    parser.add_argument("--render-tables", metavar="EVIDENCE")
    arguments = parser.parse_args(argv)
    if arguments.compare:
        result = base.compare(read(arguments.compare[0]), read(arguments.compare[1]))
        print(json.dumps(result, indent=2))
        print("Executed in both: %d | not run in both: %d | not run vs measured: %d | verdict differences among "
              "cells executed in both: %d | same coverage: %s" % (
                  result["executed_in_both"], result["not_run_in_both"], result["not_run_vs_measured"],
                  result["verdict_difference_count"], result["same_coverage"]), file=sys.stderr)
        raise SystemExit(1 if result["verdict_difference_count"] else 0 if result["same_coverage"] else 3)
    if arguments.render_tables:
        for name, text in render_tables(read(arguments.render_tables)).items():
            print("<!-- %s -->\n%s\n" % (name, text))
        return
    require(arguments.mode is not None, "Choose --mode docker or --mode local.")
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
