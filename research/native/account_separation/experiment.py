"""Wrap the frozen live collectors for the account-separation condition.

No frozen file is edited. The recorder is the EXISTING account UID/GID 1000, so
the frozen fixture, auth initialiser, filesystem observer, three store captures,
capture validator and trace inventory run UNCHANGED. Tools run as UID/GID 1002.

The frozen collector is called with its own ``full_access`` condition (the native
argv, prompts, model request and permission profile are the full-access ones).
Three things are substituted at call time, by attribute, the way the frozen main
runner substitutes its own experiment class:

  1. the experiment class -> a subclass that changes only the AGENT container
     (derived image, start user 0:0, three added capabilities, a tmpfs home for the
     tool account, relay started as UID 1000), adds one sealing step before the
     observer, a self-check after start, and copies the wrapper's audit log out
     after each stage;
  2. ``run_native_functionality.validate_agent`` -> a function that checks exactly
     the declared differences, removes them from a copy of the ``docker inspect``
     object, and then calls the FROZEN validator on that copy for everything else;
  3. ``run_observer_calibration.create_args`` -> the frozen argv plus
     ``--uid 1000 --uid 1002`` so the process observer also samples tool processes.

Never executed against a Docker daemon or Codex. Tested with a fake ``docker``.
"""

from contextlib import ExitStack, contextmanager
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[3]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from research.native.account_separation import container

RECORDER_UID, TOOL_UID = 1000, 1002
PYTHON = container.PYTHON
LAUNCHER = (PYTHON, "-m", "research.native.account_separation.launcher")
# The relay runs as UID 1000 with no capability, as it does in the baseline.
RELAY_AS_RECORDER = (*LAUNCHER, "--no-capabilities", "--pass-environment", "--",
                     "python3", "-m", "trace_lab.relay")
SEAL = (PYTHON, "-m", container.MODULE, "seal-harness")
STATUS = "import sys; sys.stdout.write(open('/proc/self/status').read())"
AUDIT_LOG = "/home/agent/.account-separation/wrapper-audit.jsonl"
OBSERVED_UIDS = ("--uid", str(RECORDER_UID), "--uid", str(TOOL_UID))


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def status_fields(text):
    wanted = ("Uid", "Gid", "Groups", "CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb", "NoNewPrivs")
    return {key: value.strip() for line in text.splitlines()
            for key, sep, value in [line.partition(":")] if sep and key in wanted}


def recorder_identity_ok(fields):
    """UID/GID 1000 with exactly SETGID|SETUID|SETPCAP (0x1c0) ambient, NNP set."""
    try:
        return (fields["Uid"].split() == [str(RECORDER_UID)] * 4
                and fields["Gid"].split() == [str(RECORDER_UID)] * 4
                and int(fields["CapAmb"], 16) == 0x1c0 and int(fields["CapEff"], 16) == 0x1c0
                and fields["NoNewPrivs"] == "1")
    except (KeyError, ValueError):
        return False


def tool_identity_ok(fields):
    """UID/GID 1002, all five capability sets empty, NNP set."""
    try:
        return (fields["Uid"].split() == [str(TOOL_UID)] * 4 and fields["Gid"].split() == [str(TOOL_UID)] * 4
                and all(int(fields[k], 16) == 0 for k in ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"))
                and fields["NoNewPrivs"] == "1")
    except (KeyError, ValueError):
        return False


def make_experiment_class(base, cli, derived_image, derived_image_id, geometry="read_only"):
    """Build the experiment subclass over a frozen experiment class."""

    class AccountSeparationExperiment(base):
        account_separation = {"derived_image": derived_image, "derived_image_id": derived_image_id,
                              "recorder_uid": RECORDER_UID, "tool_uid": TOOL_UID,
                              "geometry": geometry, "recorder_umask": "002",
                              "sealed": None, "self_check": None}

        def save(self):
            self.metadata.update(os_condition="account_separation",
                                 frozen_collector_condition="full_access",
                                 account_separation=dict(self.account_separation),
                                 call_time_substitutions=["experiment class", "agent validator (frozen "
                                 "validator still applied to everything but the declared differences)",
                                 "process observer --uid 1000 --uid 1002"])
            return super().save()

        def _note(self, **values):
            type(self).account_separation = dict(self.account_separation, **values)
            self.save()

        def seal_records(self):
            """Record and apply the condition's volume settings (once, as root)."""
            image = self.args.image
            self.args.image = derived_image
            try:
                name = super().start_container(
                    "records-seal", "--network", "none",
                    "--mount", cli.mount(self.home_volume, "/home/agent"),
                    "--mount", cli.mount(self.workspace_volume, "/workspace"),
                    command=(*SEAL, "--geometry", geometry),
                    caps=("CHOWN", "DAC_OVERRIDE", "FOWNER"), user="0:0")
            finally:
                self.args.image = image
            code = cli.docker("wait", name, timeout=60).stdout.strip()
            logs = cli.docker("logs", name)
            require(code == "0", "Sealing the records filesystem failed: " + logs.stderr.strip()[-300:])
            sealed = json.loads(logs.stdout.strip().splitlines()[-1])
            self._note(sealed=sealed)
            require(sealed["tool_writable_entries"] == [],
                    "The home volume has entries the tool account could modify: "
                    + json.dumps(sealed["tool_writable_entries"][:5]))
            auth = sealed.get("auth")
            require(auth is None or (auth["uid"] == RECORDER_UID and auth["mode"] == 0o600),
                    "auth.json is not UID 1000 with mode 0600.")
            require(sealed["home_root"]["uid"] == RECORDER_UID,
                    "The home volume is not owned by UID 1000 as the frozen fixture leaves it.")

        def start_container(self, suffix, *options, command=(), caps=(), user="1000:1000"):
            if suffix == "observer" and self.account_separation["sealed"] is None:
                self.seal_records()
            if suffix != "agent":
                return super().start_container(suffix, *options, command=command, caps=caps, user=user)
            require(self.account_separation["sealed"] is not None,
                    "The volumes were not sealed before the agent container.")
            require(not command and not caps and user == "1000:1000",
                    "The frozen agent start contract changed; refusing to guess.")
            image = self.args.image
            self.args.image = derived_image
            try:
                return super().start_container(
                    suffix, *container.condition_options(), *options,
                    command=RELAY_AS_RECORDER, caps=(), user="0:0")
            finally:
                self.args.image = image

        def prepare(self):
            result = super().prepare()
            self.self_check()
            return result

        def self_check(self):
            """Measure, in the live agent container, who the recorder and a tool are."""
            run = lambda *argv: cli.docker("exec", self.agent, *argv, timeout=30).stdout
            check = {
                "recorder": status_fields(run(*LAUNCHER, "--", PYTHON, "-I", "-c", STATUS)),
                "relay_account": status_fields(run(*LAUNCHER, "--no-capabilities", "--", PYTHON, "-I", "-c", STATUS)),
                "tool_via_bin_bash": status_fields(run(*LAUNCHER, "--", "/bin/bash", "-lc", "cat /proc/self/status")),
                "tool_via_bin_sh": status_fields(run(*LAUNCHER, "--", "/bin/sh", "-c", "cat /proc/self/status")),
                "codex_on_path": run(PYTHON, "-I", "-c", "import shutil; print(shutil.which('codex'))").strip(),
                "codex_real_present": run(PYTHON, "-I", "-c",
                                          "import os; print(os.path.exists('/usr/local/bin/codex.real'))").strip(),
            }
            relay = check["relay_account"]
            check["passed"] = (recorder_identity_ok(check["recorder"])
                               and tool_identity_ok(check["tool_via_bin_bash"])
                               and tool_identity_ok(check["tool_via_bin_sh"])
                               and relay.get("Uid", "").split() == [str(RECORDER_UID)] * 4
                               and int(relay.get("CapEff", "f"), 16) == 0 and int(relay.get("CapAmb", "f"), 16) == 0
                               and check["codex_on_path"] == "/usr/local/bin/codex"
                               and check["codex_real_present"] == "True")
            (self.directory / "account-separation-self-check.json").write_text(json.dumps(check, indent=2) + "\n")
            self._note(self_check=check)
            require(check["passed"], "Account-separation self-check failed in the agent container; "
                                     "no native stage was started.")

        def supervised_stage(self, name, command, prompt, deadline):
            try:
                return super().supervised_stage(name, command, prompt, deadline)
            finally:
                self.collect_wrapper_audit()

        def collect_wrapper_audit(self):
            """Copy the wrapper's audit log out; a later copy must extend the earlier one."""
            target = self.directory / "wrapper-audit.jsonl"
            try:
                text = cli.docker("exec", self.agent, PYTHON, "-I", "-c",
                                  "import sys; sys.stdout.write(open(%r).read())" % AUDIT_LOG,
                                  timeout=30, check=False)
            except Exception as exc:  # retained as a gap, never fatal for the stage result
                self._note(wrapper_audit_error="%s: %s" % (type(exc).__name__, exc))
                return
            if text.returncode:
                self._note(wrapper_audit_error=text.stderr.strip()[-200:] or "audit log not readable")
                return
            earlier = target.read_text() if target.exists() else ""
            if not text.stdout.startswith(earlier):
                self._note(wrapper_audit_error="audit log no longer extends the earlier copy")
                (self.directory / "wrapper-audit-changed.jsonl").write_text(text.stdout)
                return
            target.write_text(text.stdout)

    return AccountSeparationExperiment


def declared_differences(info, derived_image_id):
    """Check the differences from the frozen agent container. Returns reasons."""
    reasons = []
    host, config = info["HostConfig"], info["Config"]
    caps = {v.upper().removeprefix("CAP_") for v in host.get("CapAdd") or []}
    tmpfs = host.get("Tmpfs") or {}
    if info.get("Image") != derived_image_id:
        reasons.append("image id is not the derived image")
    if config.get("User") != "0:0":
        reasons.append("start user is not 0:0")
    if caps != set(container.CAPS):
        reasons.append("cap-add is not exactly SETUID, SETGID, SETPCAP")
    if set(tmpfs) != {"/tmp", "/home/tool"} or "uid=1002" not in tmpfs.get("/home/tool", "") \
            or "gid=1002" not in tmpfs.get("/home/tool", ""):
        reasons.append("tmpfs mounts are not exactly /tmp and a tool-owned /home/tool")
    if config.get("Cmd") != list(RELAY_AS_RECORDER):
        reasons.append("the container command is not the relay started as UID 1000 without capabilities")
    return reasons


def make_validate_agent(frozen_validator, baseline_image_id, derived_image_id):
    """Declared differences are checked here; the FROZEN validator checks the rest."""
    def validate_agent(info, experiment):
        reasons = declared_differences(info, derived_image_id)
        require(not reasons, "Agent container differs from the account-separation condition: "
                + "; ".join(reasons))
        normalised = json.loads(json.dumps(info))
        normalised["Image"] = baseline_image_id
        normalised["Config"]["User"] = "1000:1000"
        normalised["HostConfig"]["CapAdd"] = None
        settings = frozen_validator(normalised, experiment)
        settings.update(image_id=info["Image"], user=info["Config"]["User"], cap_add=sorted(container.CAPS),
                        tmpfs=info["HostConfig"].get("Tmpfs"), command=info["Config"].get("Cmd"),
                        declared_differences=["image", "start user", "cap-add", "tmpfs /home/tool",
                                              "container command"],
                        frozen_validator_applied_to_everything_else=True)
        return settings
    return validate_agent


def make_create_args(frozen_create_args):
    def create_args(*args, **kwargs):
        argv = frozen_create_args(*args, **kwargs)
        return [*argv, *OBSERVED_UIDS] if args[2:3] == ("observer",) or kwargs.get("role") == "observer" else argv
    return create_args


@contextmanager
def substituted(module, name, value):
    original = getattr(module, name)
    setattr(module, name, value)
    try:
        yield
    finally:
        setattr(module, name, original)


def label(record, experiment_class, derived_image, derived_image_id, geometry):
    return {"schema": "account-separation-attempt-label-v2", "os_condition": "account_separation",
            "frozen_collector_condition": record.get("condition"),
            "model_visible_configuration": "identical to full_access",
            "derived_image": derived_image, "derived_image_id": derived_image_id, "geometry": geometry,
            "account_separation": experiment_class.account_separation}


def collect_attempt(pilot, folder, commit, design, derived_image, derived_image_id, geometry="read_only"):
    """One live history attempt through the frozen collector."""
    cli, original = pilot.cli, pilot.original
    calibrated = pilot.previous.calibrated
    experiment_class = make_experiment_class(pilot.HistoryExperiment, cli, derived_image,
                                             derived_image_id, geometry)
    with ExitStack() as stack:
        stack.enter_context(substituted(pilot, "HistoryExperiment", experiment_class))
        stack.enter_context(substituted(original, "validate_agent", make_validate_agent(
            original.validate_agent, original.IMAGE, derived_image_id)))
        stack.enter_context(substituted(calibrated, "create_args", make_create_args(calibrated.create_args)))
        record = pilot.collect_condition(folder, "full_access", commit, design)
    value = label(record, experiment_class, derived_image, derived_image_id, geometry)
    (Path(folder) / "account-separation-label.json").write_text(json.dumps(value, indent=2) + "\n")
    return record, value


def classify_tool(value, condition):
    """Functionality control under account separation (replaces the frozen
    expectation that an outside write is ALLOWED under the full-access profile).

    Expected: the control ran as UID/GID 1002 with no capability and NNP, wrote the
    workspace, and its append to the canary on the home volume was refused by the
    kernel (EPERM or EACCES) leaving the canary unchanged.
    """
    from research.native import native_functionality_tool as tool
    v = value["tool"]
    credentials = v["credentials"]
    identity = (v["uid"] == v["gid"] == TOOL_UID
                and credentials["Uid"].split() == credentials["Gid"].split() == [str(TOOL_UID)] * 4
                and credentials["NoNewPrivs"] == "1"
                and all(int(credentials[k], 16) == 0 for k in ("CapEff", "CapPrm", "CapAmb")))
    workspace = v["workspace_write_verified"] is True and value["workspace"] == "workspace-write-ok\n"
    denied = (v["outside_write_denied"] is True and v["outside_write_errno"] in {1, 13}
              and v["outside_unchanged"] is True and value["outside"].encode() == tool.SEED)
    allowed = v["outside_write_denied"] is False and v["outside_unchanged"] is False
    finding = "write_denied" if denied else "write_allowed" if allowed else "undetermined"
    return {"identity_verified": identity, "workspace_write_verified": workspace,
            "outside_write_finding": finding, "expected_outside_write_finding": "write_denied",
            "expected_tool_uid": TOOL_UID, "frozen_collector_condition": condition,
            "classifier": "account_separation.experiment.classify_tool",
            "passed": identity and workspace and finding == "write_denied"}


def collect_functionality(functionality, folder, commit, derived_image, derived_image_id,
                          geometry="read_only"):
    """The frozen coding/resume functionality pilot under account separation."""
    original = functionality.original
    cli = original.cli
    calibrated = original.previous.calibrated
    experiment_class = make_experiment_class(functionality.ComparisonExperiment, cli, derived_image,
                                             derived_image_id, geometry)
    # The frozen batch entry point supplies this context; the same fields are given here.
    experiment_class.context = {"comparison_plan": "../plan.json", "source_commit": commit,
                                "original_evidence_retained": True, "automatic_replacement": False,
                                "os_condition": "account_separation"}
    with ExitStack() as stack:
        stack.enter_context(substituted(functionality, "ComparisonExperiment", experiment_class))
        stack.enter_context(substituted(original, "validate_agent", make_validate_agent(
            original.validate_agent, original.IMAGE, derived_image_id)))
        stack.enter_context(substituted(functionality, "classify_tool", classify_tool))
        stack.enter_context(substituted(calibrated, "create_args", make_create_args(calibrated.create_args)))
        record = functionality.collect_condition(folder, "full_access", commit)
    value = label(record, experiment_class, derived_image, derived_image_id, geometry)
    (Path(folder) / "account-separation-label.json").write_text(json.dumps(value, indent=2) + "\n")
    return record, value
