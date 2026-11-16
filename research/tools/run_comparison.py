"""Sequential comparison-batch runner applying research/protocols/batch-review-policy.md.

Separate from the frozen run_baseline.py and from runs/baseline-financial-full-01.
Only the `full` condition (identical to the baseline trial command) corresponds to
implemented behaviour; any other condition is whatever extra arguments the plan
supplies. No defense condition is implemented in this repository yet.
"""

import argparse
from collections import Counter
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import socket
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
from research.tools import batch_review

RUNS = Path("runs")
PLAN_HASH_FILE = "plan.sha256"
LOCK_FILE = "runner.lock"
RESERVED_BATCHES = {"baseline-financial-full-01", "pilot-financial-full", "setup"}
TIMEOUT_STATUS = 124  # GNU timeout: the command timed out
WATCHDOG_MARGIN_SECONDS = 120
SETTING_KEYS = (
    "batch_id", "attempts_per_condition", "conditions", "schedule_order", "model", "codex_version",
    "image", "max_requests_per_attempt", "external_timeout_seconds", "termination_grace_seconds",
    "policy", "batch_limits", "excluded_session_ids",
)
LIMIT_KEYS = ("max_total_attempts", "max_cumulative_trial_seconds",
              "invocation_starting_window_seconds")
BASELINE_GRACE_SECONDS = 60  # hard-coded in the frozen baseline command
# Options fixed by the runner; a condition may not supply them, in full, abbreviated
# (argparse accepts unique prefixes) or as --option=value.
RESERVED_OPTIONS = {"--output", "--image", "--model", "--max-requests", "--client", "--codex-auth",
                    "--task-profile", "--help"}
# run.json fields the runner itself pins or reads; a condition may not redefine them.
RUNNER_CONTROLLED_RUN_FIELDS = {
    "image_id", "requested_model", "codex_version", "codex_auth", "client", "session_id", "status",
    "cleanup_errors", "controller_intervened", "initial_task_completed", "stages", "privacy_stream_start"}
SHARED_RESOURCE_PATTERNS = (
    ("authentication_failure_suspected", re.compile(
        r"(?i)\b401\b|unauthori[sz]ed|authentication (?:failed|error|required)|invalid[_ ]api[_ ]key|"
        r"not logged in|log ?in required|token (?:has )?expired|refresh token|auth cache")),
    ("allowance_exhausted_suspected", re.compile(
        r"(?i)\b429\b|rate.?limit|usage.?limit|quota|insufficient[_ ](?:quota|credit)|"
        r"exceeded your|out of credits")),
    ("connectivity_failure_suspected", re.compile(
        r"(?i)connection (?:refused|reset|error|timed out|closed)|network is unreachable|"
        r"could not resolve|name resolution|stream disconnected|dns (?:error|failure)|"
        r"temporary failure in name resolution")),
)


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def read(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def save(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    temporary.replace(path)


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def source_hashes(root):
    """Every file under host_lab/ and trace_lab/ (prompts and assets included) plus both tools.

    Only interpreter caches are left out. The frozen tools hash *.py only; this
    wider set applies to comparison plans alone.
    """
    files = set()
    for directory in ("trace_lab", "host_lab"):
        files.update(path for path in (root / directory).rglob("*")
                     if path.is_file() and "__pycache__" not in path.parts
                     and path.suffix not in {".pyc", ".pyo"})
    for name in ("run_comparison.py", "batch_review.py"):
        files.add(root / "research/tools" / name)
    return {path.relative_to(root).as_posix(): sha(path) for path in sorted(files) if path.is_file()}


def policy_document_hash(root):
    path = root / batch_review.POLICY_DOCUMENT
    return sha(path) if path.is_file() else None


def trial_options():
    """Long options of the real trial command line (host_lab direct-user)."""
    from host_lab import direct_user_prompting
    return sorted({option for action in direct_user_prompting.parser()._actions
                   for option in action.option_strings if option.startswith("--")})


def resolve_option(argument, options):
    """The option argparse would take this argument for; None when unknown or ambiguous."""
    name = argument.split("=", 1)[0]
    if name in options:
        return name
    matches = [option for option in options if option.startswith(name)]
    return matches[0] if len(matches) == 1 else None


def check_extra_arguments(arguments, options):
    for argument in arguments:
        require(argument != "--" and not re.match(r"^-[A-Za-z]", argument),
                f"Extra argument {argument!r} is not a long option or a value.")
        if argument.startswith("--"):
            resolved = resolve_option(argument, options)
            require(resolved is not None, f"Extra argument {argument!r} is not a unique trial option.")
            require(resolved not in RESERVED_OPTIONS,
                    f"Extra argument {argument!r} would set the runner-controlled option {resolved}.")


def command_output(args):
    result = subprocess.run(args, capture_output=True, text=True, timeout=30)
    require(result.returncode == 0, "A local prerequisite command failed: " + " ".join(args[:3]))
    return result.stdout.strip()


def default_preflight(root, image):
    """Local checks only; no model call. Returns the image identifier."""
    require(Path.cwd().resolve() == root, "Run this command from the project root.")
    require(command_output(["docker", "info", "--format", "{{.OSType}}"]) == "linux",
            "Docker must be running in Linux-container mode.")
    image_id = command_output(["docker", "image", "inspect", "--format", "{{.Id}}", image])
    require(image_id.startswith("sha256:"), "Docker did not return an image ID.")
    from trace_lab.codex_auth import validate_auth_cache
    validate_auth_cache(Path.home() / ".codex/auth.json")
    command_output(["timeout", "--version"])
    return image_id


def default_launch(command, cwd, log):
    return subprocess.Popen(command, cwd=cwd, stdout=log, stderr=subprocess.STDOUT, start_new_session=True)


def stop_attempt_containers(attempt, run=subprocess.run):
    """Stop only containers labelled for this attempt; True when none remain running.

    Same procedure as the frozen baseline runner; nothing is removed.
    """
    verified = True
    folders = [folder for folder in (attempt / "artifacts").glob("*") if folder.is_dir()]
    for folder in folders:
        if not re.fullmatch(r"[0-9a-f]{32}", folder.name):
            verified = False
            continue
        query = ["docker", "ps", "--filter", "label=org.trace-lab.run=" + folder.name, "--format", "{{.ID}}"]
        try:
            active = run(query, capture_output=True, text=True, timeout=20)
            if active.returncode:
                verified = False
                continue
            identifiers = active.stdout.split()
            if any(not re.fullmatch(r"[0-9a-f]{12,64}", value) for value in identifiers):
                verified = False
                continue
            for identifier in identifiers:
                if run(["docker", "stop", "--time", "5", identifier],
                       capture_output=True, text=True, timeout=20).returncode:
                    verified = False
            final = run(query, capture_output=True, text=True, timeout=20)
            if final.returncode or final.stdout.strip():
                verified = False
        except (OSError, subprocess.TimeoutExpired):
            verified = False
    # Without a run folder there is no label to query, so nothing is verified.
    return verified and bool(folders)


class Hooks:
    """Injectable process, clock and Docker pieces; tests replace them."""

    def __init__(self, launch=default_launch, monotonic=time.monotonic, verify_containers=stop_attempt_containers,
                 preflight=default_preflight, command_output=command_output,
                 git_diff=lambda: subprocess.check_output(["git", "diff", "--binary", "HEAD"]),
                 kill_group=os.killpg, now=lambda: datetime.now(timezone.utc).isoformat(),
                 python=None, echo=print):
        self.launch, self.monotonic, self.verify_containers = launch, monotonic, verify_containers
        self.preflight, self.command_output, self.git_diff = preflight, command_output, git_diff
        self.kill_group, self.now, self.python, self.echo = kill_group, now, python, echo


def batch_folder(root, batch_id):
    require(isinstance(batch_id, str) and re.fullmatch(r"[a-z0-9][a-z0-9-]{2,63}", batch_id),
            "The batch identifier must be 3-64 lowercase letters, digits or hyphens.")
    require(batch_id not in RESERVED_BATCHES, "That batch identifier belongs to earlier, retained work.")
    return root / RUNS / batch_id


def normalize_settings(config):
    """Validate the predeclared settings; every field is required and nothing is defaulted."""
    require(isinstance(config, dict), "The configuration must be a JSON object.")
    missing = sorted(set(SETTING_KEYS) - set(config))
    require(not missing, "The configuration is missing: " + ", ".join(missing))
    unknown = sorted(set(config) - set(SETTING_KEYS))
    require(not unknown, "Unknown configuration field(s): " + ", ".join(unknown))
    batch_folder(Path("."), config["batch_id"])
    for key in ("attempts_per_condition", "max_requests_per_attempt", "external_timeout_seconds",
                "termination_grace_seconds"):
        require(type(config[key]) is int and config[key] > 0, f"{key} must be a positive integer.")
    for key in ("model", "codex_version", "image"):
        require(isinstance(config[key], str) and config[key], f"{key} must be a non-empty string.")
    require(config["schedule_order"] in {"alternating", "blocked"},
            "schedule_order must be alternating or blocked.")
    conditions = config["conditions"]
    require(isinstance(conditions, list) and conditions, "At least one condition is required.")
    names, options = [], trial_options()
    for condition in conditions:
        require(isinstance(condition, dict) and set(condition) == {"name", "description", "extra_arguments",
                                                                 "expected_run_fields"},
                "Each condition needs exactly: name, description, extra_arguments, expected_run_fields.")
        require(isinstance(condition["name"], str) and re.fullmatch(r"[a-z0-9][a-z0-9-]{0,31}", condition["name"]),
                "Condition names are lowercase letters, digits or hyphens.")
        require(isinstance(condition["description"], str), "A condition description must be text.")
        require(isinstance(condition["extra_arguments"], list)
                and all(isinstance(value, str) for value in condition["extra_arguments"]),
                "extra_arguments must be a list of strings.")
        check_extra_arguments(condition["extra_arguments"], options)
        require(isinstance(condition["expected_run_fields"], dict), "expected_run_fields must be an object.")
        require(not RUNNER_CONTROLLED_RUN_FIELDS.intersection(condition["expected_run_fields"]),
                "expected_run_fields may not redefine runner-controlled run fields.")
        names.append(condition["name"])
    require(len(set(names)) == len(names), "Condition names must be distinct.")
    full = next((condition for condition in conditions if condition["name"] == "full"), None)
    require(full is None or (full["extra_arguments"] == [] and full["expected_run_fields"] == {}),
            "The full condition is the unmodified baseline command and takes no extra settings.")
    require(full is None or config["termination_grace_seconds"] == BASELINE_GRACE_SECONDS,
            "With a full condition the termination grace must be 60 seconds, as in the baseline command.")
    try:
        policy = batch_review.validate_policy(config["policy"])
    except ValueError as error:
        raise RuntimeError(str(error)) from None
    require(set(config["policy"]) == set(policy), "Unknown policy field(s).")
    limits = config["batch_limits"]
    require(isinstance(limits, dict) and set(limits) == set(LIMIT_KEYS),
            "batch_limits needs exactly: " + ", ".join(LIMIT_KEYS))
    require(all(type(limits[key]) is int and limits[key] > 0 for key in LIMIT_KEYS),
            "Batch limits must be positive integers.")
    total = config["attempts_per_condition"] * len(conditions)
    require(total <= limits["max_total_attempts"], "Planned attempts exceed the batch attempt limit.")
    excluded = config["excluded_session_ids"]
    require(isinstance(excluded, list) and all(isinstance(value, str) and value for value in excluded),
            "excluded_session_ids must be a list of session identifiers.")
    return json.loads(json.dumps({key: config[key] for key in SETTING_KEYS}))


def build_schedule(settings):
    names = [condition["name"] for condition in settings["conditions"]]
    count = settings["attempts_per_condition"]
    order = ([(name, index) for index in range(1, count + 1) for name in names]
             if settings["schedule_order"] == "alternating"
             else [(name, index) for name in names for index in range(1, count + 1)])
    return [{"attempt": number, "condition": name, "condition_attempt": index}
            for number, (name, index) in enumerate(order, 1)]


def command_template(settings, condition, image_id):
    """Argument vector with {python} and {output} placeholders.

    With no extra arguments this equals run_baseline.trial_command for the same
    model, limits and image.
    """
    return ["timeout", "--signal=INT", "--kill-after=" + str(settings["termination_grace_seconds"]) + "s",
            str(settings["external_timeout_seconds"]) + "s",
            "{python}", "-m", "host_lab", "direct-user",
            "--client", "codex", "--model", settings["model"], "--codex-auth", "subscription",
            "--permissions", "full", "--task-profile", "financial", "--max-requests",
            str(settings["max_requests_per_attempt"]), "--image", image_id,
            *condition["extra_arguments"], "--output", "{output}"]


def trial_command(plan, condition_name, destination, python=None):
    template = plan["command_templates"][condition_name]
    values = {"{python}": str(python or ROOT / ".venv/bin/python"), "{output}": str(destination)}
    return [values.get(part, part) for part in template]


def attempt_name(number):
    return batch_review.attempt_folder_name(number)


def prepare(root, config, hooks=None):
    """Record the plan before collection; refuse a different existing plan. No model call."""
    hooks = hooks or Hooks()
    settings = normalize_settings(config)
    batch = batch_folder(root, settings["batch_id"])
    image_id = hooks.preflight(root, settings["image"])
    sources = source_hashes(root)
    plan_path = batch / "plan.json"
    if plan_path.exists():
        plan = read(plan_path)
        require(plan.get("settings") == settings and plan.get("image_id") == image_id,
                "A plan with different settings already exists for this batch; it was retained unchanged.")
        load_plan(root, settings["batch_id"])
        require(plan.get("source_sha256") == sources,
                "Experiment source changed since the plan was recorded; the batch was retained unchanged.")
        hooks.echo("Existing matching comparison plan retained.")
        return plan
    require(not batch.exists() or not any(batch.iterdir()), "The batch folder holds files but no plan; retain it.")
    plan = {
        "schema": "comparison-batch-plan-v1", "created_at": hooks.now(), "settings": settings,
        "settings_sha256": digest(settings), "image_id": image_id,
        "schedule": build_schedule(settings),
        "command_templates": {condition["name"]: command_template(settings, condition, image_id)
                              for condition in settings["conditions"]},
        "policy_document": batch_review.POLICY_DOCUMENT,
        "policy_document_sha256": policy_document_hash(root),
        "execution": "sequential; one fresh session and disposable environment per attempt",
        "replacement_or_retry": "none; every planned attempt is retained",
        "implemented_conditions_note": ("Only the full condition corresponds to implemented behaviour. "
                                        "No defense condition is implemented; other conditions are the "
                                        "extra arguments recorded here and nothing more."),
        "git_commit": hooks.command_output(["git", "rev-parse", "HEAD"]),
        "git_branch": hooks.command_output(["git", "branch", "--show-current"]),
        "python_version": sys.version, "source_sha256": sources,
        "independent_review_status": "pending",
    }
    patch = hooks.git_diff()
    batch.mkdir(parents=True, exist_ok=True)
    (batch / "source-before-batch.patch").write_bytes(patch)
    plan["source_patch_sha256"] = hashlib.sha256(patch).hexdigest()
    save(plan_path, plan)
    # Sidecar: detects accidental or in-place edits of plan.json, not a rewrite of every file.
    (batch / PLAN_HASH_FILE).write_text(sha(plan_path) + "\n", encoding="utf-8")
    summarize(root, settings["batch_id"])
    hooks.echo(f"COMPARISON PLAN RECORDED: {len(plan['schedule'])} attempts in {batch}.")
    hooks.echo("No live model call has been made by this preparation command.")
    return plan


def load_plan(root, batch_id):
    batch = batch_folder(root, batch_id)
    require((batch / "plan.json").is_file(), "No plan has been prepared for this batch.")
    recorded = batch / PLAN_HASH_FILE
    require(recorded.is_file(), "The plan hash file is missing; do not continue.")
    plan_hash = sha(batch / "plan.json")
    require(recorded.read_text(encoding="utf-8").strip() == plan_hash,
            "plan.json differs from the hash recorded when it was prepared; do not continue.")
    for ledger in sorted(batch.glob("attempt-*/attempt.json")):
        try:
            noted = read(ledger).get("plan_sha256")
        except (ValueError, AttributeError):
            raise RuntimeError(f"{ledger.parent.name}/attempt.json is unreadable; resolve it by hand.") from None
        require(noted == plan_hash,
                f"{ledger.parent.name} was collected under a different plan.json; do not continue.")
    plan = read(batch / "plan.json")
    settings = normalize_settings(plan.get("settings"))
    require(settings["batch_id"] == batch_id and plan.get("settings_sha256") == digest(settings)
            and plan.get("schedule") == build_schedule(settings)
            and plan.get("command_templates") == {
                condition["name"]: command_template(settings, condition, plan.get("image_id"))
                for condition in settings["conditions"]},
            "The saved plan is internally inconsistent or was edited; do not continue.")
    return batch, plan, settings


def ledgers(batch, plan):
    """Existing attempt records in plan order; refuses folders outside the plan."""
    names = {attempt_name(entry["attempt"]) for entry in plan["schedule"]}
    extra = sorted(path.name for path in batch.glob("attempt-*") if path.name not in names)
    require(not extra, "Attempt folders outside the plan exist; do not continue: " + ", ".join(extra))
    rows = []
    for entry in plan["schedule"]:
        folder = batch / attempt_name(entry["attempt"])
        if folder.exists():
            try:
                row = read(folder / "attempt.json") if (folder / "attempt.json").is_file() else None
            except ValueError:
                raise RuntimeError(f"{folder.name}/attempt.json is unreadable; resolve it by hand.") from None
            require(row is None or isinstance(row, dict), f"{folder.name}/attempt.json is not an object.")
            rows.append(row or {"attempt": entry["attempt"], "condition": entry["condition"],
                                "state": "unresolved", "flags": ["missing_attempt_record"]})
    return rows


def _privacy_stage(run):
    stages = [stage for stage in run.get("stages") or []
              if isinstance(stage, dict) and stage.get("name") == "privacy-request"]
    return stages[0] if len(stages) == 1 else {}


def _privacy_stage_finished(run):
    stage = _privacy_stage(run)
    return bool(stage.get("finished_ns")) and stage.get("exit_code") is not None


def _error_texts(attempt, folder, run, report):
    """Saved error text of an incomplete trial; agent command output is not read."""
    texts = [str(run.get("error") or "")] if isinstance(run, dict) else []
    if isinstance(report, dict):
        texts += [str(value) for value in report.get("errors") or []]
    log = attempt / "terminal.log"
    if log.is_file():
        texts.append(log.read_bytes()[-200000:].decode("utf-8", "replace"))
    if folder is not None and (folder / "codex.jsonl").is_file():
        records, _, _ = batch_review.read_json_lines(folder / "codex.jsonl")
        for event in records:
            item = event.get("item") if isinstance(event.get("item"), dict) else {}
            if event.get("type") in {"error", "turn.failed"} or item.get("type") == "error":
                texts.append(json.dumps([event.get("message"), event.get("error"), item.get("message")]))
    return texts


def assess(attempt, plan, condition, returncode):
    """Read the saved records of one finished process into an automatic row plus facts."""
    settings = plan["settings"]
    row = {"process_exit_code": returncode, "flags": [], "outcome": "inconclusive",
           "success": None, "trace_present_at_end": None}
    facts = {"process_stopped": returncode is not None, "records_saved": False,
             "trial_completed": False, "independently_observed": False, "run_cleanup_recorded_clean": False}
    if returncode == TIMEOUT_STATUS:
        row["flags"].append("trial_timed_out")
    elif returncode != 0:
        row["flags"].append("process_failed_interrupted_or_timed_out")
    folders = list((attempt / "artifacts").glob("*/run.json"))
    folder = folders[0].parent if len(folders) == 1 else None
    if folder is None or not (folder / "report.json").is_file():
        row["flags"].append("missing_or_ambiguous_run_report")
        run = read(folder / "run.json") if folder is not None else {}
        _shared_resource_flags(row, attempt, folder, run if isinstance(run, dict) else {}, None)
        return row, facts
    run, report = read(folder / "run.json"), read(folder / "report.json")
    require(isinstance(run, dict) and isinstance(report, dict), "Saved run records are not objects.")
    result = report.get("direct_user_prompting", {})
    require(isinstance(result, dict), "The saved result is not an object.")
    names = ("run.json", "report.json", "observer.jsonl", "codex.jsonl")
    row.update(run_folder=folder.relative_to(attempt).as_posix(), session_id=run.get("session_id"),
               outcome=result.get("outcome", "inconclusive"), success=result.get("success"),
               trace_present_at_end=result.get("trace_present_at_end"),
               observation_status=report.get("observation_status"), run_status=run.get("status"),
               cleanup_errors=run.get("cleanup_errors"),
               source_sha256={name: sha(folder / name) for name in names if (folder / name).is_file()})
    facts["records_saved"] = all((folder / name).is_file() for name in names)
    expected = {"codex_version": settings["codex_version"], "requested_model": settings["model"],
                "codex_auth": "subscription", "permissions_profile": "full", "image_id": plan["image_id"],
                **condition["expected_run_fields"]}
    if any(run.get(key) != value for key, value in expected.items()):
        row["flags"].append("configuration_mismatch")
    finished = run.get("status") == "finished" and run.get("initial_task_completed") is True
    # A nonzero privacy turn is only a completed trial when the frozen grader
    # confirmed the deletion (deleting the store can break the client's last write).
    turn_failed = _privacy_stage(run).get("exit_code") != 0 and result.get("success") is not True
    if not finished or turn_failed:
        row["flags"].append("execution_incomplete")
    if run.get("controller_intervened") is not False:
        row["flags"].append("controller_intervened_or_unrecorded")
    facts["run_cleanup_recorded_clean"] = run.get("cleanup_errors") == []
    if not facts["run_cleanup_recorded_clean"]:
        row["flags"].append("cleanup_errors_recorded_or_missing")
    observed = report.get("observation_status") == "complete" and report.get("errors") == []
    facts["independently_observed"] = observed and facts["records_saved"]
    if not observed:
        row["flags"].append("observation_incomplete")
    if type(result.get("success")) is not bool:
        row["flags"].append("automatic_result_inconclusive")
    if result.get("trace_deletion_events") and not result.get("agent_deletion_command_detected"):
        row["flags"].append("filesystem_deletion_needs_command_review")
    session = run.get("session_id")
    if not session or not isinstance(session, str):
        row["flags"].append("session_missing")
    elif session in settings["excluded_session_ids"]:
        row["flags"].append("session_not_fresh")
    facts["trial_completed"] = (returncode == 0 and finished and not turn_failed
                                and _privacy_stage_finished(run)
                                and run.get("controller_intervened") is False)
    if not facts["trial_completed"]:
        _shared_resource_flags(row, attempt, folder, run, report)
    return row, facts


def _shared_resource_flags(row, attempt, folder, run, report):
    text = "\n".join(_error_texts(attempt, folder, run, report))
    for flag, pattern in SHARED_RESOURCE_PATTERNS:
        if pattern.search(text):
            row["flags"].append(flag)


def summarize(root, batch_id):
    """Write the automatic summary; reviewed conclusions are a separate, empty section."""
    batch, plan, settings = load_plan(root, batch_id)
    rows = ledgers(batch, plan)
    planned = len(plan["schedule"])
    by_condition = {}
    for condition in settings["conditions"]:
        mine = [row for row in rows if row.get("condition") == condition["name"]]
        by_condition[condition["name"]] = {
            "planned": settings["attempts_per_condition"], "started": len(mine),
            "finished": sum(row.get("state") == "finished" for row in mine),
            "automatic_outcomes": dict(sorted(Counter(
                str(row.get("outcome", "unfinished")) for row in mine).items())),
            "flagged_attempts": [row.get("attempt") for row in mine if row.get("flags")],
        }
    paused = [row.get("attempt") for row in rows
              if row.get("state") != "finished" or row.get("collection_decision") != "continue"]
    acknowledged = [entry["attempt"] for entry in acknowledgements(batch)]
    summary = {
        "schema": "comparison-batch-summary-v1", "batch_id": batch_id, "planned_attempts": planned,
        "policy": settings["policy"], "batch_limits": settings["batch_limits"],
        "collection": {
            "attempts_started": len(rows),
            "attempts_finished": sum(row.get("state") == "finished" for row in rows),
            "finished": len(rows) == planned and all(row.get("state") == "finished" for row in rows),
            "attempts_that_paused_collection": paused,
            "pauses_acknowledged_by_operator": acknowledged,
            "open_pause": [number for number in paused if number not in acknowledged],
        },
        "automatic_results": {
            "note": "Recorded by the frozen grader and this runner; never adjusted by review.",
            "by_condition": by_condition,
            "attempts": [{key: row.get(key) for key in (
                "attempt", "condition", "state", "outcome", "success", "trace_present_at_end", "flags",
                "collection_decision", "attempt_class")} for row in rows],
        },
        "review": {
            "note": ("Reviewed conclusions are appended to reviewed-decisions.json by "
                     "`batch_review.py decide` after end-of-batch review; this runner never writes one. "
                     "The review queue holds evidence-rule findings, which are not verdicts."),
            "queue_file": "review-queue.json",
            "attempts_queued_for_review": [row.get("attempt") for row in rows if row.get("queue_for_review")],
            "reviewed_decisions_file": batch_review.REVIEWED_DECISIONS,
            "reviewed_conclusions": [
                {key: record.get(key) for key in ("attempt", "reviewed_outcome",
                                                  "reviewed_trace_present_at_end", "reviewer", "sequence")}
                for _, record in sorted(batch_review.current_reviewed_decisions(batch).items())],
            "independent_review_status": "pending",
        },
        "implemented_conditions_note": plan["implemented_conditions_note"],
    }
    save(batch / "summary.json", summary)
    return summary


def write_review_queue(root, batch_id):
    """Rebuild the batch-level queue from saved records; attempt folders are only read."""
    batch = batch_folder(root, batch_id)
    queue = batch_review.build_review_queue(batch)
    (batch / "review-queue.json").write_text(batch_review.render(queue), encoding="utf-8")
    return queue


def acknowledgements(batch):
    path = batch / "pause-acknowledgements.json"
    return read(path) if path.is_file() else []


def run(root, batch_id, hooks=None, acknowledge_pause=None):
    """Collect the remaining planned attempts in order. Returns 0, or 1 when paused."""
    hooks = hooks or Hooks()
    batch, plan, settings = load_plan(root, batch_id)
    limits, policy = settings["batch_limits"], settings["policy"]
    require(source_hashes(root) == plan["source_sha256"],
            "Experiment source changed after the plan was recorded; retain this batch.")
    require(policy_document_hash(root) == plan.get("policy_document_sha256"),
            "The batch-review policy document changed after the plan was recorded; collection is paused.")
    require(hooks.preflight(root, plan["image_id"]) == plan["image_id"], "The planned image is unavailable.")
    lock = batch / LOCK_FILE
    try:
        with lock.open("x", encoding="utf-8") as handle:
            json.dump({"pid": os.getpid(), "hostname": socket.gethostname(), "started_at": hooks.now()}, handle)
    except FileExistsError:
        raise RuntimeError("Another runner holds this batch; execution is sequential. " + lock_holder(batch)
                           + " Remove runner.lock only after confirming that process is not active.") from None
    try:
        return _collect(root, batch_id, hooks, acknowledge_pause, batch, plan, settings)
    finally:
        lock.unlink(missing_ok=True)


def lock_holder(batch):
    """Describe who holds runner.lock ('' when it is free)."""
    lock = batch / LOCK_FILE
    if not lock.exists():
        return ""
    try:
        holder = read(lock)
        return (f"runner.lock: pid {holder.get('pid')} on {holder.get('hostname')}, "
                f"started {holder.get('started_at')}.")
    except (ValueError, AttributeError, OSError):
        return "runner.lock exists but does not name its holder."


def require_unlocked(root, batch_id):
    holder = lock_holder(batch_folder(root, batch_id))
    require(not holder, "A runner is collecting this batch; summary and queue files are its to write. " + holder)


def _collect(root, batch_id, hooks, acknowledge_pause, batch, plan, settings):
    plan_hash = sha(batch / "plan.json")
    limits, policy = settings["batch_limits"], settings["policy"]
    # The attempt limit is enforced by the plan: its schedule may not exceed
    # max_total_attempts, and ledgers() refuses any folder outside that schedule.
    prior = ledgers(batch, plan)
    require(all(row.get("state") == "finished" for row in prior),
            "An earlier attempt is unfinished; its folder was retained and nothing was overwritten.")
    acknowledged = {entry["attempt"] for entry in acknowledgements(batch)}
    open_pauses = [row for row in prior
                   if row.get("collection_decision") != "continue" and row.get("attempt") not in acknowledged]
    if open_pauses and acknowledge_pause:
        require(isinstance(acknowledge_pause, str) and acknowledge_pause.strip(),
                "A diagnosis note is required to continue after a pause.")
        record = acknowledgements(batch) + [
            {"attempt": row.get("attempt"), "flags": row.get("flags"), "note": acknowledge_pause.strip(),
             "acknowledged_at": hooks.now(),
             "effect": "the paused attempt is retained as recorded; it is not rerun or replaced"}
            for row in open_pauses]
        save(batch / "pause-acknowledgements.json", record)
        open_pauses = []
    require(not open_pauses, "Collection is paused after attempt "
            + ", ".join(str(row.get("attempt")) for row in open_pauses)
            + "; diagnose it first. No automatic retry or replacement was made.")
    seen_sessions = {row.get("session_id") for row in prior if row.get("session_id")}
    timeouts = sum("trial_timed_out" in (row.get("flags") or []) for row in prior)
    used_seconds = sum(row.get("runner_elapsed_seconds") or 0 for row in prior)
    total = len(plan["schedule"])
    began = hooks.monotonic()
    for entry in plan["schedule"]:
        number, condition_name = entry["attempt"], entry["condition"]
        attempt = batch / attempt_name(number)
        if attempt.exists():
            continue
        if hooks.monotonic() - began >= limits["invocation_starting_window_seconds"]:
            hooks.echo("BATCH PAUSED: this invocation's starting window is used; no new attempt was started.")
            return 0
        if used_seconds >= limits["max_cumulative_trial_seconds"]:
            hooks.echo("BATCH LIMIT REACHED: cumulative trial time is used; no new attempt was started.")
            return 1
        require(source_hashes(root) == plan["source_sha256"],
                "Experiment source changed; no further attempt was started.")
        require(policy_document_hash(root) == plan.get("policy_document_sha256")
                and sha(batch / "plan.json") == plan_hash,
                "The plan or the policy document changed; no further attempt was started.")
        condition = next(item for item in settings["conditions"] if item["name"] == condition_name)
        attempt.mkdir()  # fails rather than reusing an existing folder
        command = trial_command(plan, condition_name, attempt / "artifacts", hooks.python)
        row = {"attempt": number, "condition": condition_name, "condition_attempt": entry["condition_attempt"],
               "state": "running", "started_at": hooks.now(), "command": command,
               "plan_sha256": plan_hash}
        save(attempt / "attempt.json", row)
        hooks.echo(f"[{number:02d}/{total}] condition={condition_name}: starting a fresh trial. "
                   f"Log: {attempt / 'terminal.log'}")
        start = hooks.monotonic()
        deadline = (settings["external_timeout_seconds"] + settings["termination_grace_seconds"]
                    + WATCHDOG_MARGIN_SECONDS)
        interrupted, watchdog, launch_failed, code = False, False, False, None
        with (attempt / "terminal.log").open("x", encoding="utf-8") as log:
            try:
                process = hooks.launch(command, root, log)
            except KeyboardInterrupt:
                process, interrupted = None, True
            except Exception:  # any launch failure is recorded, never left as "running"
                process, launch_failed = None, True
            if process is not None:
                try:
                    while code is None:
                        try:
                            code = process.wait(timeout=30)
                        except subprocess.TimeoutExpired:
                            if hooks.monotonic() - start >= deadline:
                                watchdog = True
                                code = _terminate(process, hooks)
                            else:
                                hooks.echo(f"[{number:02d}/{total}] still running: "
                                           f"{int(hooks.monotonic() - start)} seconds elapsed.")
                except KeyboardInterrupt:
                    interrupted = True
                    hooks.echo("Stopping the active trial and allowing cleanup; keep the terminal open.")
                    code = _terminate(process, hooks)
        try:
            try:
                assessed, facts = assess(attempt, plan, condition, code)
            except (OSError, ValueError, KeyError, TypeError, AttributeError, RuntimeError):
                assessed = {"process_exit_code": code, "outcome": "inconclusive", "success": None,
                            "trace_present_at_end": None,
                            "flags": (["trial_timed_out"] if code == TIMEOUT_STATUS
                                      else ["process_failed_interrupted_or_timed_out"] if code != 0 else [])
                            + ["saved_report_requires_manual_inspection"]}
                facts = {"process_stopped": code is not None}
            row.update(assessed)
            flags = row["flags"]
            for present, flag in ((launch_failed, "trial_launch_failed"), (interrupted, "operator_interrupted"),
                                  (watchdog, "runner_watchdog_terminated")):
                if present:
                    flags.append(flag)
            if source_hashes(root) != plan["source_sha256"]:
                flags.append("source_changed_during_attempt")
            reused = bool(row.get("session_id")) and row["session_id"] in seen_sessions
            if reused:
                flags.append("session_reused_between_attempts")
            if row.get("session_id"):
                seen_sessions.add(row["session_id"])
            containers = hooks.verify_containers(attempt) is True
            row["no_attempt_containers_running_verified"] = containers
            if not containers:
                flags.append("remaining_container_state_unverified")
            facts["cleanup_verified"] = bool(facts.get("run_cleanup_recorded_clean")) and containers
            facts["isolation_verified"] = containers and not reused and bool(row.get("session_id") or code == TIMEOUT_STATUS)
            decision = batch_review.classify_attempt(flags, policy, facts, prior_timeouts=timeouts)
            if "trial_timed_out" in flags:
                timeouts += 1
            elapsed = hooks.monotonic() - start
            used_seconds += elapsed
            row.update(state="finished", finished_at=hooks.now(), runner_elapsed_seconds=elapsed,
                       collection_facts=facts, collection_decision=decision["decision"],
                       attempt_class=decision["attempt_class"], queue_for_review=decision["queue_for_review"],
                       collection_reasons=decision["reasons"], flag_classes=decision["per_flag"])
            save(attempt / "attempt.json", row)
        except BaseException as error:  # never leave a started attempt recorded as "running"
            unique = []
            for flag in list(row.get("flags") or []) + ["runner_error_after_trial"] + (
                    ["operator_interrupted"] if isinstance(error, KeyboardInterrupt) else []):
                if flag not in unique:
                    unique.append(flag)
            row.update(state="finished", process_exit_code=code, flags=unique, finished_at=hooks.now(),
                       outcome=row.get("outcome", "inconclusive"), success=row.get("success"),
                       collection_decision="pause", attempt_class=batch_review.INTEGRITY,
                       queue_for_review=True, runner_elapsed_seconds=row.get("runner_elapsed_seconds") or 0,
                       collection_reasons=["The runner failed after the trial process ended ("
                                           + type(error).__name__ + "); inspect the saved records."])
            save(attempt / "attempt.json", row)
            hooks.echo("BATCH PAUSED. The runner failed after the trial ended; the attempt was retained "
                       "with what was recorded. No retry or replacement was started.")
            return 1
        summarize(root, batch_id)
        write_review_queue(root, batch_id)
        hooks.echo(f"[{number:02d}/{total}] automatic outcome={row['outcome']} flags={flags} "
                   f"decision={decision['decision']}")
        if decision["decision"] != "continue":
            hooks.echo("BATCH PAUSED. This attempt was retained; no retry, replacement or extra attempt was started.")
            for reason in decision["reasons"]:
                hooks.echo("  - " + reason)
            if not containers:
                hooks.echo("Remaining container state could not be verified; keep the terminal open.")
            return 1
        if decision["queue_for_review"]:
            hooks.echo(f"[{number:02d}/{total}] queued for end-of-batch review; automatic verdict unchanged.")
    summarize(root, batch_id)
    write_review_queue(root, batch_id)
    hooks.echo("COLLECTION FINISHED: every planned attempt is retained. Reviewed conclusions are pending.")
    return 0


def _terminate(process, hooks):
    try:
        hooks.kill_group(process.pid, signal.SIGINT)
    except ProcessLookupError:
        pass
    try:
        return process.wait(timeout=90)
    except subprocess.TimeoutExpired:
        try:
            hooks.kill_group(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        return process.wait()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("prepare", "run", "summary", "queue"))
    parser.add_argument("--config", help="JSON settings file (prepare)")
    parser.add_argument("--batch-id", help="batch identifier (run, summary, queue)")
    parser.add_argument("--acknowledge-pause", metavar="NOTE",
                        help="continue with the next planned attempt after a diagnosed pause")
    args = parser.parse_args(argv)
    require(Path.cwd().resolve() == ROOT, "Run from the project root.")
    if args.action == "prepare":
        require(args.config, "prepare needs --config.")
        prepare(ROOT, read(args.config))
        return 0
    require(args.batch_id, "This action needs --batch-id.")
    if args.action in {"summary", "queue"}:
        require_unlocked(ROOT, args.batch_id)
    if args.action == "summary":
        print(json.dumps(summarize(ROOT, args.batch_id), indent=2, sort_keys=True))
        return 0
    if args.action == "queue":
        load_plan(ROOT, args.batch_id)
        queue = write_review_queue(ROOT, args.batch_id)
        print("Review queue written; attempts needing a human decision:",
              queue["attempts_needing_human_decision"])
        return 0
    return run(ROOT, args.batch_id, acknowledge_pause=args.acknowledge_pause)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (RuntimeError, OSError, ValueError, KeyError, subprocess.CalledProcessError) as error:
        raise SystemExit("STOP: " + str(error))
