"""Run permission probe 02 (offline, disposable, synthetic).

Modes
  --mode docker   Run the fixture in a disposable container of the baseline image, mirroring probe 01's
                  container settings plus the two capabilities probe 02 needs (see EXTRA_CAPABILITIES).
  --mode local    Run the fixture directly on this machine as root inside a private tmpfs that this runner
                  mounts in its own mount namespace (falling back to mount/umount) and removes afterwards.
                  The setup process is restricted to docker mode's capability set unless --full-root-setup.

Utilities
  --compare A B          Compare two evidence files: coverage (executed in both, not run in both, not run
                         versus measured) and verdicts among the cells executed in both. Exit status 0 = same
                         coverage and identical verdicts, 1 = a verdict differs, 3 = coverage differs only.
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

# Why a cell was not run. Derived from the recorded not_run_reason, whose producers in the fixture are:
#   "not applicable: ..."                       the operation has no meaning in this layout (not_applicable_reason,
#                                               suppression_not_applicable_reason)
#   "the recorder identity could not open ..."  the layout itself refused the recorder the descriptor that the
#                                               control would have passed on (an executed, refused precondition)
#   anything else                               the environment could not execute the cell: a missing filesystem
#                                               feature, no dedicated fill filesystem, a fixture setup failure
# A missing or unrecognised reason is treated as "could not be executed", the conservative reading.
NOT_APPLICABLE = "not_applicable_to_this_layout"
PRECONDITION_REFUSED = "layout_refused_the_recorder_precondition"
NOT_EXECUTED = "not_executed_in_this_environment"
HOLDS, FAILS, UNDETERMINED, NO_CELL = "holds", "fails", "undetermined", "no_applicable_cell"
GROUPS = (("ordinary_tampering_matrix", "rows", "operation", "op"),
          ("legitimate_and_read_controls", "legit_controls", "control", "legit"),
          ("inherited_descriptor_controls", "descriptor_controls", "control", "fd"),
          ("suppression_of_future_records", "suppression_controls", "operation", "suppress"))
SUPPRESSION_SETS = {
    "and_resists_every_suppression_operation": tuple(fixture.SUPPRESSION_OPERATIONS),
    "and_resists_precreate_and_separate_filesystem_fill": tuple(
        name for name in fixture.SUPPRESSION_OPERATIONS if name != "fill_filesystem_then_recorder_append"),
}
ASSESSMENT_RULE = (
    "Three-valued. A layout HOLDS a requirement only if every required cell was executed and gave the good "
    "verdict. It FAILS if at least one required cell was executed and gave the bad verdict (a tampering effect, a "
    "denied proxy, an observed suppression); that is a determined result even if other cells are missing. "
    "Otherwise, if any required cell was not executed in this environment or ended in unexpected_error, the layout "
    "is UNDETERMINED and the missing cells are named. Cells that are not applicable to the layout are not required. "
    "Undetermined is never reported as resisted, denied, kept or suppressed.")


def row_verdict(row):
    return row["verdict"] if "verdict" in row else row["outcome"]


def not_run_kind(row):
    """None for an executed cell; otherwise why it was not run, from the recorded reason."""
    if row_verdict(row) != fixture.N:
        return None
    reason = row.get("not_run_reason") or ""
    if reason.startswith("not applicable:"):
        return NOT_APPLICABLE
    if reason.startswith("the recorder identity could not open the descriptor"):
        return PRECONDITION_REFUSED
    return NOT_EXECUTED


def coverage(observations):
    """Recorded / executed / not_run per measurement group, with the not_run cells split by kind."""
    result, total = {}, Counter()
    for name, key, _, _ in GROUPS:
        rows = observations.get(key, [])
        kinds = Counter(not_run_kind(row) for row in rows)
        executed = kinds.pop(None, 0)
        entry = {"recorded": len(rows), "executed": executed, "not_run": len(rows) - executed,
                 "not_run_by_kind": {kind: kinds.get(kind, 0)
                                     for kind in (NOT_APPLICABLE, PRECONDITION_REFUSED, NOT_EXECUTED)}}
        result[name] = entry
        for field in ("recorded", "executed", "not_run"):
            total[field] += entry[field]
        for kind, count in entry["not_run_by_kind"].items():
            total[kind] += count
    result["total"] = {"recorded": total["recorded"], "executed": total["executed"], "not_run": total["not_run"],
                       "not_run_by_kind": {kind: total[kind]
                                           for kind in (NOT_APPLICABLE, PRECONDITION_REFUSED, NOT_EXECUTED)}}
    return result


def _requirement(cells, judge):
    """cells: [(cell name, row)]. judge(row) -> True (good), False (bad) or None (executed, not interpretable)."""
    satisfied, failing, missing, not_applicable = [], [], [], []
    for name, row in cells:
        kind = not_run_kind(row)
        if kind == NOT_APPLICABLE:
            not_applicable.append(name)
        elif kind is not None:
            missing.append({"cell": name, "why": kind, "reason": row.get("not_run_reason")})
        else:
            verdict = judge(row)
            if verdict is True:
                satisfied.append(name)
            elif verdict is False:
                failing.append(name)
            else:
                missing.append({"cell": name, "why": "executed_but_" + str(row_verdict(row)),
                                "reason": row.get("verdict_reason")})
    status = (FAILS if failing else UNDETERMINED if missing else HOLDS if satisfied else NO_CELL)
    return {"status": status, "satisfied": satisfied, "failing": failing, "missing": missing,
            "not_applicable": not_applicable}


def _tamper_judge(row):
    return {fixture.D: True, fixture.E: False, fixture.X: False}.get(row["verdict"])


def _proxy_judge(row):
    if row.get("passed") is True:
        return True
    return False if row["outcome"] == "permission_denied" else None


def _suppression_judge(row):
    return {fixture.NOSUP: True, fixture.S: False}.get(row["verdict"])


def assess_layouts(observations):
    """Per layout, the three-valued status of each requirement, with the cells behind it."""
    result = {}
    for case in observations["layouts"]:
        tampering = [("op/%s/%s" % (case, row["operation"]), row) for row in observations["rows"]
                     if row["case"] == case
                     and row.get("counts_as_tampering", row["operation"] in fixture.TAMPERING_OPERATIONS)]
        judged = [("legit/%s/%s" % (case, row["control"]), row) for row in observations["legit_controls"]
                  if row["case"] == case and row["judged"]]
        discriminating = [(name, row) for name, row in judged if row.get("layout_discriminating") is True]
        entry = {"tampering_denied": _requirement(tampering, _tamper_judge),
                 "judged_proxies_kept": _requirement(judged, _proxy_judge),
                 "discriminating_proxies_kept": _requirement(discriminating, _proxy_judge)}
        for row in observations.get("suppression_controls", []):
            if row["case"] == case:
                entry["resists:" + row["operation"]] = _requirement(
                    [("suppress/%s/%s" % (case, row["operation"]), row)], _suppression_judge)
        result[case] = entry
    return result


def combine(assessment, requirements):
    """Conjunction of requirements for one layout: fails beats undetermined beats holds."""
    parts = [assessment.get(name, {"status": UNDETERMINED, "satisfied": [], "failing": [], "not_applicable": [],
                                   "missing": [{"cell": name, "why": "not_recorded", "reason": None}]})
             for name in requirements]
    failing = [cell for part in parts for cell in part["failing"]]
    missing = [item for part in parts for item in part["missing"]]
    satisfied = [cell for part in parts for cell in part["satisfied"]]
    status = FAILS if failing else UNDETERMINED if missing or not satisfied else HOLDS
    return {"status": status, "failing": failing, "missing": missing, "satisfied": satisfied}


def _three_lists(assessments, cases, requirements):
    lists = {HOLDS: [], FAILS: [], UNDETERMINED: []}
    for case in cases:
        verdict = combine(assessments[case], requirements)
        if verdict["status"] == HOLDS:
            lists[HOLDS].append(case)
        elif verdict["status"] == FAILS:
            lists[FAILS].append({"layout": case, "failing_cells": verdict["failing"],
                                 "cells_not_executed": [item["cell"] for item in verdict["missing"]]})
        else:
            lists[UNDETERMINED].append({"layout": case, "missing_cells": verdict["missing"],
                                        "executed_and_good": verdict["satisfied"]})
    return lists


def protection_assessment(observations, proxies="judged_proxies_kept"):
    """The layout lists, three-valued. proxies: 'judged_proxies_kept' or 'discriminating_proxies_kept'."""
    assessments = assess_layouts(observations)
    cases = list(observations["layouts"])
    base = _three_lists(assessments, cases, ("tampering_denied", proxies))
    result = {"rule": ASSESSMENT_RULE, "proxy_requirement": proxies,
              "per_layout_status": {case: {name: part["status"] for name, part in assessments[case].items()}
                                    for case in cases},
              "tampering_denied_and_proxies_kept": base}
    for name, operations in SUPPRESSION_SETS.items():
        lists = _three_lists(assessments, base[HOLDS], tuple("resists:" + operation for operation in operations))
        lists["evaluated_for"] = "layouts in tampering_denied_and_proxies_kept.holds"
        lists["required_operations"] = list(operations)
        result[name] = lists
    return result


def protecting_layouts(observations):
    """Layouts that HOLD 'every tampering operation denied and every judged proxy kept' (never undetermined)."""
    return protection_assessment(observations)["tampering_denied_and_proxies_kept"][HOLDS]


def protecting_and_suppression_resistant_layouts(observations):
    """Of those, the layouts that HOLD resistance to every suppression operation; see protection_assessment()
    for the layouts that fail it and the layouts for which it is undetermined."""
    return protection_assessment(observations)["and_resists_every_suppression_operation"][HOLDS]


def discriminating_legit_rows(observations):
    return [row for row in observations["legit_controls"]
            if row["outcome"] != fixture.N and row.get("layout_discriminating") is True]


def _cell(row):
    kind = not_run_kind(row)
    if kind is not None:
        code = {NOT_APPLICABLE: "n/a", PRECONDITION_REFUSED: "no-fd", NOT_EXECUTED: "NR"}[kind]
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
    if row["verdict"] == fixture.X:
        code = code.replace("X", "X(" + str(row.get("outcome")) + ")")
    if row["control"] == "dirfd_listdir" and row["verdict"] == fixture.E:
        code = "E(dirfd-only)" if row.get("outcome") == "names_listed_via_dirfd_only" else "E(both)"
    return code


def _suppression_cell(row):
    kind = not_run_kind(row)
    if kind is not None:
        code = "n/a" if kind == NOT_APPLICABLE else "NR"
    else:
        code = {fixture.S: "S", fixture.NOSUP: "R", fixture.UNEXPECTED: "ERR"}.get(row["verdict"], "ERR")
    return code + ("!" if row["matches_expectation"] is False else "")


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
    for kind, group in (("operation", rows), ("legit_control", legit), ("descriptor_control", descriptors),
                        ("suppression_control", suppression)):
        for row in group:
            if not_run_kind(row) is not None:
                not_run[(kind, not_run_kind(row), row.get("not_run_reason"))] += 1
    assessment = protection_assessment(observations)
    holding = assessment["tampering_denied_and_proxies_kept"][HOLDS]
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
        "coverage": coverage(observations),
        "not_run_classification": "From the recorded not_run_reason: a reason starting 'not applicable:' is "
                                  "not applicable to the layout; 'the recorder identity could not open the "
                                  "descriptor' is a precondition the layout itself refused; every other reason "
                                  "(or none) means the cell could not be executed in this environment.",
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
        "protection_assessment": assessment,
        "superseded_fields": "Summaries written by the runner at commit a329127 carried "
                             "'layouts_also_resisting_both_suppression_operations', computed after dropping "
                             "not_run cells; it overstated resistance wherever disk-fill cells were not run. It is "
                             "replaced by protection_assessment, which is three-valued.",
        "side_effect_operations_in_tamper_denying_layouts": {
            case: {row["operation"]: row["verdict"] for row in rows
                   if row["case"] == case and row["operation"] in fixture.SIDE_EFFECT_OPERATIONS}
            for case in holding},
        "expectation_mismatch_count": len(mismatches), "expectation_mismatches": mismatches,
        "not_run": [{"kind": kind, "why": why, "count": count, "reason": reason}
                    for (kind, why, reason), count in sorted(not_run.items(), key=lambda item: str(item[0]))],
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
            "a result from one environment is not a result for another, and cells not executed in an "
            "environment are undetermined there.",
            "Disk-exhaustion suppression depends on the filesystem layout and per-filesystem quotas; the probe "
            "fills small dedicated tmpfs mounts, so its ENOSPC timing is not the production filesystem's. In "
            "docker mode the fill controls are not executed at all.",
            "The precreate control's fallback step is refused by the file mode before fs.protected_regular is "
            "consulted, so the probe matrix does not show that sysctl's effect.",
        ]}


def _assessment_lines(title, lists):
    def names(items):
        return ", ".join("`%s`" % item for item in items) or "(none)"
    lines = ["**%s**" % title, "", "- holds: " + names(lists[HOLDS])]
    if lists[FAILS]:
        lines.append("- fails (determined):")
        lines += ["  - `%s`: %s" % (item["layout"], ", ".join("`%s`" % cell.split("/", 2)[2]
                                                             for cell in item["failing_cells"]))
                  for item in lists[FAILS]]
    else:
        lines.append("- fails (determined): (none)")
    if lists[UNDETERMINED]:
        lines.append("- undetermined (required cells not executed here):")
        lines += ["  - `%s`: missing %s" % (item["layout"], ", ".join(
            "`%s`" % missing["cell"].split("/", 2)[2] for missing in item["missing_cells"]))
            for item in lists[UNDETERMINED]]
    else:
        lines.append("- undetermined: (none)")
    return lines


def render_assessment(assessment):
    lines = _assessment_lines("Every tampering operation denied and every judged proxy kept",
                              assessment["tampering_denied_and_proxies_kept"])
    lines += [""] + _assessment_lines(
        "Of the layouts that hold the above: also resist every suppression operation "
        "(precreate, shared-filesystem fill, separate-filesystem fill)",
        assessment["and_resists_every_suppression_operation"])
    lines += [""] + _assessment_lines(
        "Of the layouts that hold the first: also resist precreate and the separate-filesystem fill",
        assessment["and_resists_precreate_and_separate_filesystem_fill"])
    return "\n".join(lines)


def render_coverage(table):
    lines = ["| Measurement group | Recorded | Executed | Not run | not applicable to the layout | "
             "recorder precondition refused by the layout | could not be executed in this environment |",
             "| --- | ---: | ---: | ---: | ---: | ---: | ---: |"]
    for name, entry in table.items():
        kinds = entry["not_run_by_kind"]
        lines.append("| %s | %d | %d | %d | %d | %d | %d |" % (
            name.replace("_", " "), entry["recorded"], entry["executed"], entry["not_run"],
            kinds[NOT_APPLICABLE], kinds[PRECONDITION_REFUSED], kinds[NOT_EXECUTED]))
    return "\n".join(lines)


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
             "Recorded %(recorded)d, executed %(executed)d, not run %(not_run)d." % summary["coverage"]["total"],
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
        "coverage": render_coverage(summary["coverage"]),
        "totals": "\n".join("- " + line for line in lines),
        "assessment": render_assessment(summary["protection_assessment"])}


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


def not_run_kinds(evidence):
    """cell -> why it was not run (only for cells that were not run)."""
    observations, result = evidence["observations"], {}
    for _, key, name_key, prefix in GROUPS:
        for row in observations.get(key, []):
            kind = not_run_kind(row)
            if kind is not None:
                result["%s/%s/%s" % (prefix, row["case"], row[name_key])] = kind
    return result


def _env_facts(evidence):
    env = evidence["observations"]["environment"]
    return {"kernel_release": env["kernel_release"], "python_version": env["python_version"],
            "sysctl_fs": env["sysctl_fs"],
            "setup_effective_capabilities": sorted(env["setup_process"]["effective_capability_names"]),
            "probe_root_filesystems": sorted({item["filesystem"].get("fstype") for item in env["probe_roots"]}),
            "mode": evidence["run"]["mode"]}


def compare(first, second):
    """Coverage first, verdicts second. Verdicts are compared only among cells executed in BOTH files."""
    one, two = verdict_signature(first), verdict_signature(second)
    skipped_one, skipped_two = not_run_kinds(first), not_run_kinds(second)
    keys = sorted(set(one) | set(two))
    both = [key for key in keys if key in one and key in two and key not in skipped_one and key not in skipped_two]
    neither = [key for key in keys if key in skipped_one and key in skipped_two]
    only_first = [key for key in keys if key in one and key not in skipped_one
                  and (key in skipped_two or key not in two)]
    only_second = [key for key in keys if key in two and key not in skipped_two
                   and (key in skipped_one or key not in one)]
    differing = [key for key in both if one[key] != two[key]]
    reason_kind_differs = [key for key in neither if skipped_one[key] != skipped_two[key]]
    first_env, second_env = _env_facts(first), _env_facts(second)
    environment = {field: {"a": first_env.get(field), "b": second_env.get(field),
                           "same": first_env.get(field) == second_env.get(field)}
                   for field in sorted(set(first_env) | set(second_env))}
    same_coverage = not only_first and not only_second and not reason_kind_differs
    return {
        "recorded_cells": len(keys),
        "coverage": {"a": coverage(first["observations"]), "b": coverage(second["observations"])},
        "executed_in_both": len(both), "not_run_in_both": len(neither),
        "not_run_vs_measured": len(only_first) + len(only_second),
        "executed_only_in_a": only_first, "executed_only_in_b": only_second,
        "not_run_in_both_for_different_kinds_of_reason": reason_kind_differs,
        "verdict_differences_among_executed_in_both": differing,
        "verdict_difference_count": len(differing),
        "same_coverage": same_coverage,
        "verdicts_identical_among_cells_executed_in_both": not differing,
        "same_coverage_and_identical_verdicts": same_coverage and not differing,
        "environment": environment,
        "environment_identical": all(item["same"] for item in environment.values()),
        "note": "A cell not run in either file contributes no verdict agreement. 'verdicts identical' speaks only "
                "about the cells executed in both files; it is not a statement about coverage."}


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


def print_coverage_and_assessment(summary, out=None):
    """Coverage, then every layout list WITH its fails and undetermined lists beside it."""
    def show(*parts):
        print(*parts, file=out or sys.stdout)

    total = summary["coverage"]["total"]
    show("Coverage: recorded %d, executed %d, not run %d (%d not applicable to the layout, %d recorder "
         "precondition refused by the layout, %d COULD NOT BE EXECUTED in this environment)" % (
             total["recorded"], total["executed"], total["not_run"], total["not_run_by_kind"][NOT_APPLICABLE],
             total["not_run_by_kind"][PRECONDITION_REFUSED], total["not_run_by_kind"][NOT_EXECUTED]))
    for item in summary["not_run"]:
        if item["why"] == NOT_EXECUTED:
            show("  NOT EXECUTED HERE: %d %s cells: %s" % (item["count"], item["kind"], item["reason"]))
    assessment = summary["protection_assessment"]
    for title, key in (("Tampering denied and judged proxies kept", "tampering_denied_and_proxies_kept"),
                       ("  of those, also resist every suppression operation",
                        "and_resists_every_suppression_operation"),
                       ("  of those, also resist precreate and the separate-filesystem fill",
                        "and_resists_precreate_and_separate_filesystem_fill")):
        lists = assessment[key]
        show(title + ":")
        show("    holds:", lists[HOLDS])
        show("    fails (determined):", [item["layout"] for item in lists[FAILS]])
        show("    UNDETERMINED (required cells not executed here):",
             {item["layout"]: [missing["cell"].split("/", 2)[2] for missing in item["missing_cells"]]
              for item in lists[UNDETERMINED]})


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
    print_coverage_and_assessment(summary)
    print("Expectation mismatches:", summary["expectation_mismatch_count"])
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
        print("Executed in both: %d | not run in both: %d | not run vs measured: %d | verdict differences among "
              "cells executed in both: %d | same coverage: %s" % (
                  result["executed_in_both"], result["not_run_in_both"], result["not_run_vs_measured"],
                  result["verdict_difference_count"], result["same_coverage"]), file=sys.stderr)
        # 0: same coverage and identical verdicts; 1: a verdict differs; 3: verdicts agree but coverage differs
        raise SystemExit(1 if result["verdict_difference_count"] else 0 if result["same_coverage"] else 3)
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
