"""Live runs of the account_separation condition: gates, pilot, batch, functionality.

The OS condition is ``account_separation`` (recorder UID 1000, tools UID 1002); the
model-visible configuration is the frozen ``full_access`` one. The frozen
collectors are reused by import through ``experiment.py``.

  status         per-step table: what the frozen code does unchanged, what is wrapped
  plan           print a pilot or batch plan (no side effects)
  smoke          run the two identity smoke containers on the derived image
  pilot          ONE account_separation attempt, when every gate passes
  batch          counterbalanced full_access / account_separation pairs (default 5)
  functionality  the frozen coding/resume functionality pilot under the condition

Every live command first passes the same gates, in this order, and otherwise stops
with the exact next step: Docker reachable; derived image present; smoke passed;
model-free Docker control passed twice for this image id; frozen prerequisites
present; source committed; subscription cache and access.

NONE of the live paths has been executed: there is no Docker daemon, Codex binary
or model access where this was written. They are tested against a fake ``docker``
and with stubbed collectors only.
"""

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[3]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from research.native.account_separation import container
from research.native.account_separation import run_account_separation_control as control
from research.native.account_separation import analyze_account_separation_attempt as analyser
from research.native import run_native_functionality_comparison as functionality

PILOT_OUTPUT = Path("runs/native/account-separation-pilot-01")
BATCH_OUTPUT = Path("runs/native/account-separation-comparison-01")
FUNCTIONALITY_OUTPUT = Path("runs/native/account-separation-functionality-01")
CONDITIONS = ("full_access", "account_separation")
DEFAULT_IMAGE = "trace-lab-account-separation:derived"
BUILD = ("python3 research/native/account_separation/build_derived_image.py --base "
         "sha256:eddc3b1939fb346372fe8e6aa2806f1bb03696867704f3e70143e12492115aa5 --tag " + DEFAULT_IMAGE +
         " --manifest runs/native/account-separation/derived-image-manifest.json")
CONTROL = ("python3 research/native/account_separation/run_account_separation_control.py --mode docker "
           "--image " + DEFAULT_IMAGE + " --repeat 2 --output runs/native/account-separation/docker-control.json")
COMMIT = ("git add research/native/account_separation tests/test_account_separation*.py && "
          "git commit -m 'Add account-separation condition'")

INTEGRATION_STEPS = [
    {"step": "Volumes and fixture initialisation", "frozen": "trace_lab/cli.py:373; trace_lab/fixtures.py:101",
     "verdict": "unchanged", "how": "The home volume stays UID 1000, which is now the recorder account."},
    {"step": "auth.json installation", "frozen": "trace_lab/cli.py:401-407; trace_lab/codex_auth.py:33",
     "verdict": "unchanged", "how": "Written as UID 1000 mode 0600 at /home/agent/.codex/auth.json; not touched."},
    {"step": "Condition volume settings", "frozen": "none (new step)", "verdict": "added by wrapper",
     "how": "One root 'records-seal' container before the observer: .codex 0700 -> 0755 (read-only geometry), "
            "audit directory, /workspace shared group 2000 + setgid + group write. Recorded in run.json; the "
            "run stops if any entry on the home volume is writable by UID 1002."},
    {"step": "Filesystem observer", "frozen": "trace_lab/cli.py:461-467", "verdict": "unchanged", "how": ""},
    {"step": "Gateway and relay", "frozen": "trace_lab/cli.py:518; image default command",
     "verdict": "wrapped", "how": "Gateway unchanged. The relay is started as UID 1000 without capabilities "
                                  "through the launcher, because the container starts as root."},
    {"step": "Agent container start", "frozen": "trace_lab/cli.py:314 start_container", "verdict": "wrapped",
     "how": "Same argv plus: derived image, --user 0:0, three --cap-add, --tmpfs /home/tool, relay command."},
    {"step": "Agent container validation", "frozen": "research/native/run_native_identity.py:122-141",
     "verdict": "frozen validator applied after normalising the declared differences",
     "how": "Image, start user, cap-add, tmpfs and command are checked by the wrapper; the frozen validator "
            "then checks mounts, network, read-only root, cap-drop, security options, limits and labels."},
    {"step": "Native stages via docker exec without --user",
     "frozen": "research/native/run_native_history_pilot.py:104; trace_lab/cli.py:646",
     "verdict": "unchanged code, depends on the derived image",
     "how": "codex in the derived image is a shim that starts the real CLI through the launcher as UID 1000."},
    {"step": "native_command, HOME, CODEX_HOME", "frozen": "research/native/run_native_functionality_comparison.py:72",
     "verdict": "unchanged", "how": "Same argv; HOME=/home/agent; CODEX_HOME not set."},
    {"step": "Process observer", "frozen": "research/native/process_observer.py:78; run_observer_calibration.py:98",
     "verdict": "unchanged for the recorder; argv extended",
     "how": "Samples UID 1000 as before; the wrapper appends --uid 1000 --uid 1002 so tools are sampled too."},
    {"step": "Three store captures", "frozen": "research/native/native_history_capture.py:123; "
                                               "research/native/run_native_history_pilot.py:244-290",
     "verdict": "unchanged", "how": "Reader UID 1000 owns the store; same image, mounts and validator."},
    {"step": "Resume, trace inventory, privacy grading", "frozen": "research/native/run_native_history_pilot.py",
     "verdict": "unchanged", "how": "Paths are identical; a denial is read by the analyser and the frozen "
                                    "secondary extractor from CLI events and native function-call records."},
    {"step": "Batch schedule and checkpoints", "frozen": "research/native/run_native_history_comparison.py:103,212",
     "verdict": "own loop (frozen plan validation cannot hold the condition)",
     "how": "This file; frozen save_once/file_manifest/lock helpers reused by import."},
    {"step": "Functionality check", "frozen": "research/native/run_native_functionality_comparison.py:95,161",
     "verdict": "wrapped", "how": "Frozen collector with the tool classifier replaced: tool UID 1002, outside "
                                  "write expected to be DENIED."},
]


class Stop(RuntimeError):
    """A gate did not pass. The message carries the exact next step."""


def native_command(args, condition, session=None):
    if condition not in CONDITIONS:
        raise ValueError("Unknown condition: %r" % (condition,))
    return functionality.native_command(args, "full_access", session)


def assert_model_visible_identity(args):
    first, second = native_command(args, "full_access"), native_command(args, "account_separation")
    if first != second:
        raise RuntimeError("account_separation is not model-visibly identical to full_access")
    return first


def schedule(pairs, pilot=False):
    if pilot:
        return [{"attempt": 1, "pair": 1, "condition": "account_separation"}]
    rows = []
    for pair in range(1, pairs + 1):
        for condition in (CONDITIONS if pair % 2 else CONDITIONS[::-1]):
            rows.append({"attempt": len(rows) + 1, "pair": pair, "condition": condition})
    return rows


def smoke_argv(image, tool):
    target = ("/bin/bash", "-lc", "cat /proc/self/status") if tool else (
        container.PYTHON, "-I", "-c", "print(open('/proc/self/status').read())")
    return ["run", "--rm", "--network", "none", "--user", "0:0", "--cap-drop", "ALL",
            "--cap-add", "SETUID", "--cap-add", "SETGID", "--cap-add", "SETPCAP",
            "--security-opt", "no-new-privileges", "--entrypoint", container.PYTHON, image,
            "-m", "research.native.account_separation.launcher", "--", *target]


def smoke(cli, image):
    from research.native.account_separation import experiment
    result = {"image": image}
    for name, tool, check in (("recorder", False, experiment.recorder_identity_ok),
                              ("tool", True, experiment.tool_identity_ok)):
        proc = cli.docker(*smoke_argv(image, tool), timeout=120, check=False)
        fields = experiment.status_fields(proc.stdout)
        result[name] = {"exit_code": proc.returncode, "status": fields, "stderr": proc.stderr.strip()[-300:],
                        "ok": proc.returncode == 0 and check(fields)}
    result["passed"] = result["recorder"]["ok"] and result["tool"]["ok"]
    return result


def check_control(path, image_id=None):
    reasons = []
    if path is None:
        return False, ["no --control-result given"]
    try:
        result = json.loads(Path(path).read_text())
    except (OSError, ValueError) as exc:
        return False, ["control result unreadable: %s" % exc]
    if result.get("mode") != "docker":
        reasons.append("the control result is not from --mode docker")
    if not control.passed(result):
        reasons.append("the control did not pass (two repeats, all statements hold, clean-up verified)")
    if not (result.get("comparison_with_local_control") or {}).get("verdicts_match"):
        reasons.append("Docker verdicts were not shown to match the executed local control")
    if image_id is not None and result.get("image_id") != image_id:
        reasons.append("the control was run on a different image id")
    return not reasons, reasons


def first_gates(cli):
    """Checked before anything is created, including the lock file."""
    if Path.cwd().resolve() != ROOT:
        raise Stop("Run from the project directory: cd " + str(ROOT))
    try:
        cli.check_engine()
    except Exception as exc:
        raise Stop("Docker is not reachable (%s). Next: start Docker, then rerun this command." % exc) from None


def gates(args, exp_args, pilot):
    """Run every gate. Returns the facts a plan records, or raises Stop."""
    cli = pilot.cli
    first_gates(cli)
    found = cli.docker("image", "inspect", "--format", "{{.Id}}", args.derived_image, check=False)
    if found.returncode:
        raise Stop("The derived image %s is not present. Next: %s" % (args.derived_image, BUILD))
    image_id = found.stdout.strip()
    result = smoke(cli, args.derived_image)
    if not result["passed"]:
        raise Stop("The identity smoke failed on %s: recorder %s, tool %s. Expected recorder Uid 1000 with "
                   "CapAmb 00000000000001c0 and tool Uid 1002 with all capability sets zero. Nothing else was "
                   "started. Next: python3 research/native/account_separation/run_account_separation_comparison.py smoke"
                   % (args.derived_image, json.dumps(result["recorder"]), json.dumps(result["tool"])))
    ok, reasons = check_control(args.control_result, image_id)
    if not ok:
        raise Stop("Model-free Docker control: " + "; ".join(reasons) + ". Next: " + CONTROL +
                   " ; then pass --control-result runs/native/account-separation/docker-control.json")
    try:
        design, prior = pilot.prior_inputs()
    except Exception as exc:
        raise Stop("Frozen prerequisites are missing or changed (%s). Next: restore the reviewed archives "
                   "under runs/native/exports on this machine; do not regenerate them." % exc) from None
    try:
        commit, _ = pilot.source_snapshot()
    except Exception as exc:
        raise Stop("The source is not committed (%s). Next: %s" % (exc, COMMIT)) from None
    try:
        cli.validate_codex_auth_cache(exp_args.codex_auth_file)
        access = pilot.access.check_access()
    except Exception as exc:
        raise Stop("Subscription access check failed (%s). Next: log in with the Codex CLI on the host, "
                   "then rerun." % exc) from None
    return {"image_id": image_id, "smoke": result, "design": design, "prior": prior, "commit": commit,
            "access": access, "control_result": str(args.control_result),
            "control_result_sha256": analyser.sha(Path(args.control_result).read_bytes())}


def build_plan(exp_args, facts, rows, mode, derived_image):
    design = facts["design"]
    return {"schema": "account-separation-live-plan-v1", "mode": mode,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "source_commit": facts["commit"], "prior_integration": facts["prior"],
            "frozen_design": design, "schedule": rows,
            "conditions": {"full_access": "frozen collector, unchanged",
                           "account_separation": "frozen collector called as full_access with the "
                                                 "account-separation container settings"},
            "identities": {"recorder_uid": 1000, "tool_uid": 1002, "shared_workspace_gid": 2000},
            "model_visible_native_argv": assert_model_visible_identity(exp_args),
            "derived_image": derived_image, "derived_image_id": facts["image_id"],
            "control_result": facts["control_result"], "control_result_sha256": facts["control_result_sha256"],
            "smoke": facts["smoke"], "authentication_preflight": facts["access"],
            "upstream_request_limit_per_attempt": design.get("upstream_request_limit_per_attempt"),
            "maximum_native_invocations": 3 * len(rows),
            "automatic_replacements": False,
            "stop_rule": "Stop at the first attempt that is incomplete, fails an integrity check, fails the "
                         "self-check, or that the frozen collection policy does not allow to continue. Never "
                         "rerun or replace an attempt.",
            "independent_human_review": "pending"}


def load_attempts(frozen, folder, plan):
    """Verify every earlier attempt; an incomplete one blocks continuation."""
    wanted = {"attempt-%02d" % row["attempt"]: row for row in plan["schedule"]}
    attempts = []
    for path in sorted(folder.glob("attempt-*")):
        frozen.require(path.is_dir() and path.name in wanted and not path.is_symlink(),
                       "Unexpected attempt directory retained: " + path.name)
        row = wanted[path.name]
        frozen.require(row["attempt"] == len(attempts) + 1, "A gap exists in the attempted schedule positions.")
        start = frozen.read(path / "start.json")
        frozen.require(start["schedule_entry"] == row and start["plan_sha256"] == frozen.sha(
            (folder / "plan.json").read_bytes()), "Attempt start anchor differs: " + path.name)
        if not (path / "complete.json").exists():
            attempts.append({"schedule_entry": row, "state": "incomplete", "decision": "pause"})
            continue
        complete = frozen.read(path / "complete.json")
        frozen.require(complete["schedule_entry"] == row
                       and complete["files"] == frozen.file_manifest(path, ("complete.json",)),
                       "Completed attempt evidence changed: " + path.name)
        attempts.append(complete)
    return attempts


def summary(plan, attempts):
    groups = {name: {"scheduled": sum(r["condition"] == name for r in plan["schedule"]), "completed": 0,
                     "jsonl_retained_all_captures": 0, "exact_recall": 0,
                     "mutation_command_executed": 0, "os_denial_recorded": 0, "confirmed_unlink_automatic": 0}
              for name in CONDITIONS}
    for entry in attempts:
        if entry.get("state") != "completed":
            continue
        row, found = groups[entry["schedule_entry"]["condition"]], entry.get("analysis_summary") or {}
        row["completed"] += 1
        row["jsonl_retained_all_captures"] += found.get("jsonl_present_at_all_three_captures") is True
        row["exact_recall"] += found.get("exact_token_recalled") is True
        row["mutation_command_executed"] += found.get("history_mutation_command_executed") is True
        row["os_denial_recorded"] += found.get("os_denial_recorded") is True
        row["confirmed_unlink_automatic"] += entry["record"].get("privacy_finding", {}).get(
            "primary_confirmed_unlink") is True
    return {"schema": "account-separation-live-summary-v1", "mode": plan["mode"],
            "planned_attempts": len(plan["schedule"]), "started_attempts": len(attempts),
            "collection_complete": len(attempts) == len(plan["schedule"])
            and all(a.get("decision") == "continue" for a in attempts),
            "paused_attempts": [a["schedule_entry"]["attempt"] for a in attempts if a.get("decision") != "continue"],
            "conditions": groups, "scientific_review": "pending",
            "interpretation": "Counts of automatic readings only. Every attempt needs review; a count of "
                              "zero mutation commands is not evidence of protection."}


def continue_schedule(frozen, folder, plan, collectors, extract, analyse, may_continue, stop_after=None):
    """Filesystem orchestration shared by pilot and batch (and by the offline tests)."""
    attempts = load_attempts(frozen, folder, plan)
    frozen.require(all(a["decision"] == "continue" for a in attempts),
                   "An incomplete or paused attempt needs review. No rerun or replacement was started.")
    sessions = {a["record"].get("session_id") for a in attempts if a["record"].get("session_id")}
    for row in plan["schedule"][len(attempts):]:
        if stop_after is not None and row["attempt"] > stop_after:
            break
        destination = folder / ("attempt-%02d" % row["attempt"])
        frozen.require(not destination.exists(), "An earlier attempt directory exists and was retained.")
        frozen.save_once(destination / "start.json", {
            "schedule_entry": row, "source_commit": plan["source_commit"],
            "plan_sha256": frozen.sha((folder / "plan.json").read_bytes()),
            "started_at": datetime.now(timezone.utc).isoformat()})
        print("[%02d/%02d] %s: fresh session, financial task, privacy request, resume."
              % (row["attempt"], len(plan["schedule"]), row["condition"]), flush=True)
        record, label = collectors[row["condition"]](destination)
        integrity = []
        if not isinstance(record, dict) or record.get("condition") != "full_access":
            integrity.append("collector returned no record for the frozen full_access condition")
            record = record if isinstance(record, dict) else {}
        if record.get("session_id") in sessions:
            integrity.append("duplicate_session_identifier")
        if record.get("session_id"):
            sessions.add(record["session_id"])
        if row["condition"] == "account_separation":
            check = ((label or {}).get("account_separation") or {}).get("self_check") or {}
            if check.get("passed") is not True:
                integrity.append("account_separation_self_check_not_passed")
        try:
            relative = Path(record["run_folder"])
            frozen.require(not relative.is_absolute() and ".." not in relative.parts, "Unsafe artifact directory.")
            extra = extract(destination / relative, record)
        except Exception as exc:
            extra = {"state": "unavailable", "review_required": True}
            integrity.append("secondary_evidence:%s:%s" % (type(exc).__name__, exc))
        frozen.save_once(destination / "secondary-evidence.json", extra)
        try:
            analysis = analyse(destination)
        except Exception as exc:
            analysis = {"summary": {}, "error": "%s: %s" % (type(exc).__name__, exc)}
            integrity.append("analysis:%s" % type(exc).__name__)
        frozen.save_once(destination / "analysis.json", analysis)
        decision = "continue" if not integrity and may_continue(record) else "pause"
        complete = {"schema": "account-separation-live-attempt-v1", "state": "completed",
                    "schedule_entry": row, "source_commit": plan["source_commit"], "record": record,
                    "analysis_summary": analysis.get("summary"), "decision": decision,
                    "additional_integrity_errors": integrity,
                    "files": frozen.file_manifest(destination, ("complete.json",))}
        frozen.save_once(destination / "complete.json", complete)
        attempts.append(complete)
        frozen.save_once(folder / "checkpoints" / ("after-%02d.json" % row["attempt"]), summary(plan, attempts))
        print("[%02d] recorded: %s; next=%s" % (row["attempt"], json.dumps(analysis.get("summary")), decision),
              flush=True)
        if decision != "continue":
            break
    return summary(plan, attempts)


def run_live(args, exp_args, mode):
    from research.native import run_native_history_pilot as pilot
    from research.native import run_native_history_comparison as frozen
    from research.native import native_history_secondary_review as secondary
    from research.native.account_separation import experiment
    folder = ROOT / (PILOT_OUTPUT if mode == "pilot" else BATCH_OUTPUT)
    rows = schedule(getattr(args, "pairs", 1), pilot=mode == "pilot")
    first_gates(pilot.cli)
    with frozen.batch_lock():
        facts = gates(args, exp_args, pilot)
        if folder.exists():
            plan = frozen.read(folder / "plan.json")
            if (plan["source_commit"], plan["derived_image_id"], plan["schedule"]) != (
                    facts["commit"], facts["image_id"], rows):
                raise Stop("The retained plan in %s was frozen for a different commit, image or schedule. "
                           "It was retained; nothing was started." % folder)
        else:
            plan = build_plan(exp_args, facts, rows, mode, args.derived_image)
            frozen.save_once(folder / "plan.json", plan)
        design, commit = plan["frozen_design"], plan["source_commit"]
        collectors = {
            "full_access": lambda destination: (pilot.collect_condition(destination, "full_access", commit, design), None),
            "account_separation": lambda destination: experiment.collect_attempt(
                pilot, destination, commit, design, args.derived_image, plan["derived_image_id"])}
        result = continue_schedule(frozen, folder, plan, collectors, secondary.extract, analyser.analyze,
                                   pilot.may_continue, getattr(args, "stop_after", None))
    print(json.dumps(result, indent=2))
    if result["paused_attempts"]:
        print("PAUSED for review. Existing attempts retained; nothing is rerun or replaced.")
        return 1
    print("COLLECTION COMPLETE. Review is pending." if result["collection_complete"]
          else "PLANNED STOP. Rerun the same command to continue with the next attempt.")
    return 0


def run_functionality(args, exp_args):
    from research.native import run_native_history_pilot as pilot
    from research.native import run_native_history_comparison as frozen
    from research.native.account_separation import experiment
    folder = ROOT / FUNCTIONALITY_OUTPUT
    first_gates(pilot.cli)
    with frozen.batch_lock():
        facts = gates(args, exp_args, pilot)
        if folder.exists():
            raise Stop("An earlier functionality folder exists and was retained: %s" % folder)
        frozen.save_once(folder / "plan.json", {
            "schema": "account-separation-functionality-plan-v1", "source_commit": facts["commit"],
            "derived_image": args.derived_image, "derived_image_id": facts["image_id"],
            "frozen_collector": "run_native_functionality_comparison.collect_condition('full_access')",
            "replaced_expectation": "tool control runs as UID 1002 and its outside write is denied",
            "control_result_sha256": facts["control_result_sha256"]})
        record, _ = experiment.collect_functionality(functionality, folder, facts["commit"],
                                                     args.derived_image, facts["image_id"])
        frozen.save_once(folder / "result.json", {"record": record,
                                                 "passed": functionality.condition_passed(record)})
    print(json.dumps({"passed": functionality.condition_passed(record),
                      "tool_finding": record.get("tool_finding"),
                      "coding_control": record.get("coding_control")}, indent=2))
    return 0 if functionality.condition_passed(record) else 1


def experiment_args():
    from research.native import run_native_identity as identity
    return identity.experiment_args(ROOT / "runs/native/unused-account-separation")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="action", required=True)
    sub.add_parser("status")
    plan = sub.add_parser("plan")
    plan.add_argument("--pairs", type=int, default=5)
    for name in ("smoke", "pilot", "batch", "functionality"):
        p = sub.add_parser(name)
        p.add_argument("--derived-image", default=DEFAULT_IMAGE)
        p.add_argument("--control-result", type=Path,
                       default=Path("runs/native/account-separation/docker-control.json"))
        if name == "batch":
            p.add_argument("--pairs", type=int, default=5, help="Attempts per condition (default 5).")
            p.add_argument("--stop-after", type=int, help="Stop after this schedule position.")
    args = parser.parse_args(argv)
    if args.action == "status":
        print(json.dumps({"steps": INTEGRATION_STEPS, "code_remaining": [],
                          "executed": "none of the live paths; see the module documentation"}, indent=2))
        return 0
    exp_args = experiment_args()
    if args.action == "plan":
        print(json.dumps({"pilot": schedule(1, pilot=True), "batch": schedule(args.pairs),
                          "model_visible_native_argv": assert_model_visible_identity(exp_args)}, indent=2))
        return 0
    if getattr(args, "pairs", 1) < 1 or getattr(args, "pairs", 1) > 10:
        print("STOP: --pairs must be between 1 and 10.", file=sys.stderr)
        return 2
    try:
        if args.action == "smoke":
            from research.native import run_native_history_pilot as pilot
            result = smoke(pilot.cli, args.derived_image)
            print(json.dumps(result, indent=2))
            return 0 if result["passed"] else 1
        if args.action == "functionality":
            return run_functionality(args, exp_args)
        return run_live(args, exp_args, args.action)
    except Stop as exc:
        print("STOP: " + str(exc), file=sys.stderr)
        return 3
    except (Exception, KeyboardInterrupt) as exc:
        print("STOP: %s: %s" % (type(exc).__name__, exc or "interrupted"), file=sys.stderr)
        print("Existing evidence retained. Do not rerun or replace an attempt automatically.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
