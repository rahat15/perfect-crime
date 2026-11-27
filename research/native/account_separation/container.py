"""Container settings for the account-separation condition, and their validation.

The recorder is the image's existing account, UID/GID 1000. Tools run as UID/GID
1002. The condition's AGENT container is the frozen one
(``trace_lab.cli.Experiment.start_container`` plus the frozen per-container seccomp
setting) with exactly these differences:

  * ``--user 0:0`` instead of ``1000:1000`` (the launcher hands capabilities to the
    recorder account; ``docker exec`` without ``--user`` then starts as root too);
  * ``--cap-add SETUID --cap-add SETGID --cap-add SETPCAP``;
  * ``--tmpfs /home/tool`` owned by 1002, the tool account's home;
  * the derived image instead of the baseline image;
  * an explicit command: the same relay, started as UID 1000 without capabilities.

Mounts, network, read-only root, cap-drop, no-new-privileges, seccomp setting,
limits, labels and environment are unchanged. The home volume at ``/home/agent``
is unchanged too: owned by UID 1000, it is the records filesystem.

Nothing in this module talks to Docker.
"""

LABEL_KEY = "org.trace-lab.account-separation-control"
RECORDER, TOOL = 1000, 1002
CAPS = ("SETUID", "SETGID", "SETPCAP")
TOOL_HOME_TMPFS = "/home/tool:rw,exec,nosuid,nodev,size=256m,mode=0755,uid=1002,gid=1002"
TMP_TMPFS = "/tmp:rw,nosuid,nodev,size=256m,mode=1777"
MODULE = "research.native.account_separation.docker_scenario"
PYTHON = "/usr/local/bin/python3"
SLEEP = (PYTHON, "-I", "-c", "import time; time.sleep(3600)")


def mount(volume, destination, readonly=False):
    # Same form as trace_lab.cli.mount (no automatic population of the volume).
    return "type=volume,src=%s,dst=%s,volume-nocopy" % (volume, destination) + (",readonly" if readonly else "")


def _label(label):
    return ["--label", label] if label else []


def volume_create_argv(name, label, size):
    """A size-bounded, tmpfs-backed local volume (control only)."""
    return ["volume", "create", "--label", label, "--driver", "local", "--opt", "type=tmpfs",
            "--opt", "device=tmpfs", "--opt", "o=size=%s,nosuid,nodev" % size, name]


def _hardened(name, label, user, caps=(), memory="512m", pids="64"):
    argv = ["run", "--detach", "--name", name, *_label(label), "--network", "none", "--init",
            "--read-only", "--user", user, "--cap-drop", "ALL"]
    for cap in caps:
        argv += ["--cap-add", cap]
    return argv + ["--security-opt", "no-new-privileges", "--pids-limit", pids,
                   "--memory", memory, "--cpus", "2"]


def keeper_run_argv(name, image, label, records_volume, workspace_volume):
    """Holds the tmpfs-backed volumes mounted for the lifetime of a scenario."""
    return _hardened(name, label, "65534:65534", memory="64m", pids="16") + [
        "--mount", mount(records_volume, "/home/agent", True),
        "--mount", mount(workspace_volume, "/workspace", True), image, *SLEEP]


def init_run_argv(name, image, label, records_volume, workspace_volume, records_home, geometry,
                  records_root_owner):
    """Short-lived root initialiser, like the harness's own fixture initialiser."""
    return _hardened(name, label, "0:0", caps=("CHOWN", "DAC_OVERRIDE", "FOWNER")) + [
        "--mount", mount(records_volume, "/home/agent"),
        "--mount", mount(workspace_volume, "/workspace"), image,
        PYTHON, "-m", MODULE, "init-layout", "--records-home", records_home,
        "--geometry", geometry, "--records-root-owner", str(records_root_owner)]


def sidecar_run_argv(name, image, label, records_volume, workspace_volume, records_home, session,
                     scenario):
    """Read-only observer of the records filesystem; cannot modify what it reads."""
    return _hardened(name, label, "0:0", caps=("DAC_READ_SEARCH",)) + [
        "--mount", mount(records_volume, "/home/agent", True),
        "--mount", mount(workspace_volume, "/workspace", True), image,
        PYTHON, "-m", MODULE, "snapshot", "--records-home", records_home,
        "--session-id", session, "--scenario", scenario]


def condition_options(control=False):
    """Options that distinguish the condition container from the baseline agent."""
    options = []
    for cap in CAPS:
        options += ["--cap-add", cap]
    options += ["--tmpfs", TOOL_HOME_TMPFS]
    if control:
        # Recorder-owned (UID 1000) result directory for the stand-in (control only).
        options += ["--tmpfs", "/out:rw,nosuid,nodev,size=16m,mode=0755,uid=1000,gid=1000"]
    return options


def docker_run_argv(name, image, label=None, home_volume="acctsep-records",
                    workspace_volume="acctsep-workspace", control=False, command=SLEEP):
    """The ``docker run`` argv of the condition container."""
    return ["run", "--detach", "--name", name, *_label(label), "--network", "none",
            "--init", "--read-only", "--user", "0:0", "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges", "--pids-limit", "128", "--memory", "2g",
            "--cpus", "2", "--tmpfs", TMP_TMPFS, *condition_options(control),
            "--mount", mount(home_volume, "/home/agent"),
            "--mount", mount(workspace_volume, "/workspace"), image, *command]


def _caps(values):
    return {v.upper().removeprefix("CAP_") for v in (values or [])}


def inspect_summary(info):
    host, config = info.get("HostConfig", {}), info.get("Config", {})
    mounts = {m["Destination"]: m for m in info.get("Mounts", [])}
    tmpfs = host.get("Tmpfs") or {}
    volumes = {d: m.get("Name") for d, m in mounts.items() if m.get("Type") == "volume"}
    records = volumes.get("/home/agent")
    return {"image_id": info.get("Image"), "user": config.get("User"),
            "cap_add": sorted(_caps(host.get("CapAdd"))), "cap_drop": sorted(_caps(host.get("CapDrop"))),
            "security_options": sorted(s.replace(":", "=", 1) for s in host.get("SecurityOpt") or []),
            "readonly_root": host.get("ReadonlyRootfs"), "network": host.get("NetworkMode"),
            "volumes": volumes, "tmpfs": tmpfs,
            "records_separate": bool(records) and records != volumes.get("/workspace")
                                and "/home/tool" in tmpfs and "/tmp" in tmpfs}


def validate_inspect(info, image_id=None, label=None, home_volume=None, workspace_volume=None,
                     control=False, extra_volumes=()):
    """Check a ``docker inspect`` object against the condition. Returns (ok, reasons)."""
    reasons = []
    def need(condition, why):
        if not condition:
            reasons.append(why)
    host, config = info.get("HostConfig", {}), info.get("Config", {})
    summary = inspect_summary(info)
    options = set(summary["security_options"])
    need(image_id is None or info.get("Image") == image_id, "image id differs from the derived image")
    if label:
        key, _, value = label.partition("=")
        need((config.get("Labels") or {}).get(key) == value, "run label is missing")
    need(config.get("User") in ("0:0", "0", "root"), "start user must be root (0:0)")
    need(_caps(host.get("CapDrop")) == {"ALL"}, "cap-drop must be exactly ALL")
    need(_caps(host.get("CapAdd")) == set(CAPS), "cap-add must be exactly SETUID, SETGID, SETPCAP")
    need("no-new-privileges" in options or "no-new-privileges=true" in options,
         "no-new-privileges must be set")
    need(host.get("ReadonlyRootfs") is True, "root filesystem must be read-only")
    need(not host.get("Privileged"), "must not be privileged")
    need(not host.get("Binds") and not host.get("Devices") and not host.get("VolumesFrom")
         and not host.get("PidMode"), "no binds, devices, volumes-from or shared PID namespace")
    volumes = summary["volumes"]
    need(set(volumes) == {"/home/agent", "/workspace", *extra_volumes},
         "volume mounts must be exactly /home/agent (records), /workspace" +
         "".join(", " + v for v in extra_volumes))
    need(home_volume is None or volumes.get("/home/agent") == home_volume,
         "/home/agent is not the expected records volume")
    need(workspace_volume is None or volumes.get("/workspace") == workspace_volume,
         "/workspace is not the expected workspace volume")
    need(volumes.get("/home/agent") != volumes.get("/workspace"),
         "records and workspace must be different filesystems")
    for destination in ("/home/agent", "/workspace"):
        entry = next((m for m in info.get("Mounts", []) if m.get("Destination") == destination), {})
        need(entry.get("RW") is True, destination + " must be writable")
    expected_tmpfs = {"/tmp", "/home/tool"} | ({"/out"} if control else set())
    need(set(summary["tmpfs"]) == expected_tmpfs, "tmpfs mounts must be exactly " +
         ", ".join(sorted(expected_tmpfs)))
    work = summary["tmpfs"].get("/home/tool", "")
    need("uid=1002" in work and "gid=1002" in work, "/home/tool must be owned by the tool account (1002)")
    return (not reasons, reasons)


def argv_difference(frozen_argv, condition_argv, placeholders=()):
    """Tokens removed from / added to the frozen agent ``docker run`` argv.

    Run-specific names (container, label and volume names) are replaced by the
    given placeholders first so two different runs can be compared.
    """
    def normal(argv):
        out = []
        for token in argv:
            for value, name in placeholders:
                token = token.replace(value, name)
            out.append(token)
        return out
    def pairs(argv):
        items, index = [], 0
        while index < len(argv):
            token = argv[index]
            if token.startswith("--") and len(token) > 2 and index + 1 < len(argv) \
                    and not argv[index + 1].startswith("-") and token not in ("--init", "--read-only", "--detach"):
                items.append(token + " " + argv[index + 1])
                index += 2
            else:
                items.append(token)
                index += 1
        return items
    a, b = pairs(normal(frozen_argv)), pairs(normal(condition_argv))
    return {"only_in_frozen": [t for t in a if t not in b], "only_in_condition": [t for t in b if t not in a]}
