"""Re-run permission probe 02 under filesystem and sysctl variants (offline, disposable, synthetic).

This wrapper imports the committed fixture and runner UNCHANGED and only changes the environment
around them: which filesystem the probe root is on (tmpfs, overlayfs, a bind mount, plain ext4) and
three hardening sysctls (fs.protected_regular, fs.protected_hardlinks, fs.protected_symlinks).

For each variant it
  1. builds the mounts inside a private mount namespace (they vanish when this process exits),
  2. saves, sets and ALWAYS restores the sysctls (finally + SIGTERM/SIGINT + a marker file),
  3. runs the committed fixture with the committed runner's capability restriction,
  4. writes the evidence in the committed runner's evidence shape,
  5. compares it with the committed evidence using the committed runner's --compare,
  6. checks every difference against the predictions written below as data,
  7. runs a few small "sysctl effect controls" (clearly not part of the probe-02 matrix) that show
     whether each sysctl actually changes behaviour in a sticky directory.

Usage (as root, from the repository root)
  python3 research/tools/run_permission_probe_v2_variants.py --list
  python3 research/tools/run_permission_probe_v2_variants.py --run all
  python3 research/tools/run_permission_probe_v2_variants.py --run protected_hardlinks_0 --keep-evidence all
  python3 research/tools/run_permission_probe_v2_variants.py --restore-stale-marker

No model call, credential or network access is used. Standard library only.
"""

import argparse
import atexit
import ctypes
from datetime import datetime, timezone
import errno
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import signal
import stat
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from research.tools import permission_probe_v2_fixture as fixture  # noqa: E402
from research.tools import run_permission_probe_v2 as runner  # noqa: E402

PROTOCOL = "disposable-posix-boundary-v2-variants-1"
OUTPUT = Path("research/reviews/permission-probe-02-variants")
COMMITTED_EVIDENCE = Path("research/reviews/permission-probe-02/evidence.json")
SUMMARY_NAME = "variants-summary.json"
SYSCTL_DIRECTORY = "/proc/sys/fs"
SYSCTLS = ("protected_regular", "protected_hardlinks", "protected_symlinks")
MARKER_NAME = "cse227-probe-v2-variants-unrestored-sysctl.json"
OP, FD, SUP = "op/%s/%s", "fd/%s/%s", "suppress/%s/%s"

# ---------------------------------------------------------------- variants and predictions (data)
#
# The predictions below are literals, reasoned from kernel documentation (admin-guide/sysctl/fs.rst,
# filesystems/overlayfs.rst, mount(2)) before the variant is run by this file. The files cannot prove
# that ordering; each variant's record stores this file's sha256 next to the evidence sha256.
#
# "predicted_differences": cells whose verdict/outcome/errno signature is predicted to differ from the
# committed evidence, with the predicted verdict. An empty list predicts NO difference at all.

_HARDLINK_WHY = ("fs.protected_hardlinks=0 removes the rule that the caller must own the file or have "
                 "read+write access to it; link(2) then only needs search on the source directory and "
                 "write on the destination directory, which the agent has here")
_HARDLINK_LAYOUTS = (
    "recorder_file_agent_writable_dir", "sticky_1777_dir_recorder_file", "sticky_1770_shared_group_dir",
    "setgid_2770_shared_group_file_0640", "recorder_owned_agent_readonly",
    "recorder_dir_in_agent_owned_parent", "acl_agent_read_only", "acl_agent_dir_write_file_read")

VARIANTS = {
    "wrapper_control_tmpfs": {
        "description": "Control: same configuration as the committed run (64m tmpfs root, ext4 alternate root, "
                       "two 4m fill tmpfs, default sysctls) but driven through this wrapper.",
        "root": "tmpfs", "alternate_root": True, "fill": "tmpfs", "sysctls": {},
        "predicted_differences": [],
        "prediction_basis": "Nothing differs from the committed run; this checks the wrapper itself.",
    },
    "overlayfs_on_tmpfs": {
        "description": "Probe root is an overlayfs mount whose lower, upper and work directories are on a tmpfs.",
        "root": "overlay_tmpfs", "alternate_root": False, "fill": "tmpfs", "sysctls": {},
        "predicted_differences": [],
        "prediction_basis": "Every fixture file is created after the mount, so it lives only in the upper layer; "
                            "overlayfs applies the same VFS permission, sticky and rename checks, forwards inode "
                            "flags (fileattr) and POSIX ACL xattrs to the upper inode, and renames of upper-only "
                            "directories need no redirect. No verdict change and no not_run cell is predicted.",
    },
    "overlayfs_on_ext4": {
        "description": "Probe root is an overlayfs mount whose lower, upper and work directories are on ext4.",
        "root": "overlay_ext4", "alternate_root": False, "fill": "tmpfs", "sysctls": {},
        "predicted_differences": [],
        "prediction_basis": "Same reasoning as overlayfs_on_tmpfs; ext4 as the upper filesystem supports the "
                            "trusted.overlay xattrs, inode flags and POSIX ACLs.",
    },
    "bind_mount_ext4": {
        "description": "Probe root is reached through a bind mount of an ext4 directory (what a Docker bind "
                       "mount or named volume is); the two fill filesystems are bind mounts of small tmpfs.",
        "root": "bind_ext4", "alternate_root": False, "fill": "bind_tmpfs", "sysctls": {},
        "predicted_differences": [],
        "prediction_basis": "A bind mount exposes the same superblock and inodes under another path; permission "
                            "checks are per inode and per mount flags, and this bind adds no mount flags.",
    },
    "ext4_scratch_with_fill": {
        "description": "Probe root is a plain directory on the temp directory's filesystem (ext4 here) AND the two "
                       "dedicated fill tmpfs are supplied (the committed ext4 run had 28 fill cells not_run).",
        "root": "plain", "alternate_root": False, "fill": "tmpfs", "sysctls": {},
        "predicted_differences": [],
        "prediction_basis": "The committed ext4 run already matched every non-fill verdict; the fill controls run "
                            "on their own tmpfs either way, so they should now be measured and equal.",
    },
    "protected_regular_1": {
        "description": "fs.protected_regular=1 (default here 0); otherwise the control configuration.",
        "root": "tmpfs", "alternate_root": True, "fill": "tmpfs", "sysctls": {"protected_regular": 1},
        "predicted_differences": [],
        "prediction_basis": "protected_regular only refuses an O_CREAT open of an EXISTING regular file that the "
                            "opener does not own in a sticky directory whose owner is not the file owner. The only "
                            "probe-02 step of that shape is the recorder's O_CREAT|O_APPEND onto the agent's "
                            "pre-created next-session file in the sticky layouts, and that step is already refused "
                            "with EACCES by the file's 0644 mode, so its recorded outcome and errno cannot change. "
                            "O_CREAT|O_EXCL returns EEXIST before the sysctl is consulted.",
    },
    "protected_regular_2": {
        "description": "fs.protected_regular=2 (also group-writable sticky directories); otherwise the control.",
        "root": "tmpfs", "alternate_root": True, "fill": "tmpfs", "sysctls": {"protected_regular": 2},
        "predicted_differences": [],
        "prediction_basis": "Same as protected_regular_1; level 2 extends the rule to the 1770 group-writable "
                            "sticky layout, where the step is likewise already refused by the 0644 mode.",
    },
    "protected_hardlinks_0": {
        "description": "fs.protected_hardlinks=0 (default here 1); otherwise the control configuration.",
        "root": "tmpfs", "alternate_root": True, "fill": "tmpfs", "sysctls": {"protected_hardlinks": 0},
        "predicted_differences": [{"cell": OP % (layout, "hardlink_create"),
                                   "from": fixture.D, "to": fixture.E, "why": _HARDLINK_WHY}
                                  for layout in _HARDLINK_LAYOUTS],
        "prediction_basis": "Exactly the hard-link cells the committed fixture codes as sysctl-dependent flip from "
                            "denial to effect. The 0700 layout still fails the path lookup (EACCES) and the "
                            "append-only/immutable inodes still refuse link(2) (EPERM), so those stay denied.",
    },
    "protected_symlinks_1": {
        "description": "fs.protected_symlinks=1 (default here 0); otherwise the control configuration.",
        "root": "tmpfs", "alternate_root": True, "fill": "tmpfs", "sysctls": {"protected_symlinks": 1},
        "predicted_differences": [],
        "prediction_basis": "protected_symlinks only restricts FOLLOWING a symlink that sits in a sticky "
                            "world-writable directory. Probe 02 never gets a symlink into a sticky directory (the "
                            "swap is refused there by the sticky rule first); its symlinks are created in "
                            "non-sticky directories, where following is unrestricted.",
    },
}

NOT_RUN_VARIANTS = {
    "bind_mount_separate_records_workspace": (
        "not_run: the committed fixture places the agent workspace next to the records tree under ONE probe root "
        "for every ordinary, legitimate-proxy and descriptor measurement; only the two fill controls accept a "
        "separate workspace filesystem, and those must be dedicated tmpfs mounts of at most 8 MiB "
        "(fixture.fill_root_problem). Putting records and workspace on different bind-mounted filesystems for the "
        "ordinary operations (where rename_out_of_dir, replace, hardlink_create and the symlink swaps would cross a "
        "filesystem boundary) therefore needs a change to the frozen fixture, which was not made. The "
        "separate-filesystem case IS exercised for the fill control in bind_mount_ext4, where the two fill "
        "filesystems are separate bind mounts."),
}

# Small sysctl effect controls (NOT part of the probe-02 matrix). In a sticky directory owned by the recorder,
# the agent first plants an entry named like the next session; the recorder then opens that name.
EFFECT_DIRECTORIES = {
    "sticky_1777": {"mode": 0o1777, "gid": fixture.RECORDER_GID, "agent_groups": []},
    "sticky_1770_shared_group": {"mode": 0o1770, "gid": fixture.SHARED_GID, "agent_groups": [fixture.SHARED_GID]},
}
EFFECT_CONTROLS = {
    "regular_0666_recorder_o_creat_append": {
        "planted": "regular", "recorder_flags": "O_WRONLY|O_CREAT|O_APPEND",
        "what": "agent plants a world-writable regular file; recorder opens it with O_CREAT (no O_EXCL)"},
    "regular_0666_recorder_append_without_o_creat": {
        "planted": "regular", "recorder_flags": "O_WRONLY|O_APPEND",
        "what": "same file, recorder opens it WITHOUT O_CREAT (shows O_CREAT is what the sysctl keys on)"},
    "regular_0666_recorder_o_creat_excl": {
        "planted": "regular", "recorder_flags": "O_WRONLY|O_CREAT|O_EXCL|O_APPEND",
        "what": "same file, recorder insists on creating the name itself"},
    "symlink_recorder_o_creat_append": {
        "planted": "symlink", "recorder_flags": "O_WRONLY|O_CREAT|O_APPEND",
        "what": "agent plants a symlink to a world-writable file in its workspace; recorder opens the name"},
    "symlink_recorder_o_creat_excl": {
        "planted": "symlink", "recorder_flags": "O_WRONLY|O_CREAT|O_EXCL|O_APPEND",
        "what": "same symlink, recorder insists on creating the name itself"},
}
# (control, directory) -> sysctl values under which the recorder's open is predicted to be refused with EACCES.
# Anything not refused is predicted to "append into the agent's file", except the O_EXCL controls: always EEXIST.
EFFECT_REFUSED_WHEN = {
    ("regular_0666_recorder_o_creat_append", "sticky_1777"): {"protected_regular": [1, 2]},
    ("regular_0666_recorder_o_creat_append", "sticky_1770_shared_group"): {"protected_regular": [2]},
    ("symlink_recorder_o_creat_append", "sticky_1777"): {"protected_symlinks": [1]},
}
EFFECT_BASIS = ("fs.rst: protected_regular=1 refuses O_CREAT opens of regular files the opener does not own in "
                "world-writable sticky directories unless the directory owner owns the file; =2 also in "
                "group-writable sticky directories. protected_symlinks=1 refuses following a symlink in a sticky "
                "world-writable directory unless follower and link owner match or the directory owner owns the "
                "link. O_CREAT|O_EXCL fails with EEXIST on any existing name, including a symlink.")


def predicted_effect(control, directory, sysctls):
    if control.endswith("_o_creat_excl"):
        return "refused:EEXIST"
    rule = EFFECT_REFUSED_WHEN.get((control, directory), {})
    if any(sysctls.get(name) in values for name, values in rule.items()):
        return "refused:EACCES"
    return "appended_into_agent_file"


# ---------------------------------------------------------------- small helpers

def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def read(path):
    return json.loads(Path(path).read_text())


def now():
    return datetime.now(timezone.utc).isoformat()


def write_json(path, value):
    path = Path(path)
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(json.dumps(value, indent=2) + "\n")
    temporary.replace(path)


class Interrupted(BaseException):
    """Raised from the SIGTERM/SIGINT handler so every finally block (unmount, sysctl restore) runs."""


def _raise_interrupted(number, _frame):
    raise Interrupted("received signal %d" % number)


# ---------------------------------------------------------------- sysctl guard

class SysctlGuard:
    """Save, set and always restore sysctls; a marker file exists exactly while values may be changed."""

    def __init__(self, directory=SYSCTL_DIRECTORY, marker=None, names=SYSCTLS):
        self.directory, self.names = Path(directory), tuple(names)
        self.marker = Path(marker) if marker else Path(tempfile.gettempdir()) / MARKER_NAME
        self.original, self.active = None, False

    def read(self):
        return {name: int((self.directory / name).read_text().strip()) for name in self.names}

    def _write(self, name, value):
        (self.directory / name).write_text("%d\n" % value)

    def refuse_if_stale(self):
        require(not self.marker.exists(),
                "A previous run left %s, so sysctls may be unrestored. Inspect it, then run this tool with "
                "--restore-stale-marker. Nothing was started." % self.marker)

    def apply(self, values):
        """Returns the values read back after setting. Raises OSError if the kernel refuses a write."""
        unknown = set(values) - set(self.names)
        require(not unknown, "Unknown sysctl: " + ", ".join(sorted(unknown)))
        self.refuse_if_stale()
        self.original = self.read()
        if not values:
            return dict(self.original)
        write_json(self.marker, {"original": self.original, "requested": values, "pid": os.getpid(),
                                 "written_at": now()})
        self.active = True
        for name, value in values.items():
            self._write(name, value)
        current = self.read()
        require(all(current[name] == value for name, value in values.items()),
                "A sysctl did not take the requested value: %r" % current)
        return current

    def restore(self):
        """Idempotent. Returns the values read back; removes the marker only when they equal the originals."""
        if self.original is None:
            return None
        if self.active:
            current = self.read()
            for name, value in self.original.items():
                if current[name] != value:
                    self._write(name, value)
        current = self.read()
        if current == self.original:
            self.active = False
            if self.marker.exists():
                self.marker.unlink()
        return current

    def restore_from_marker(self):
        """Recovery path for a stale marker: write back the recorded originals and verify."""
        saved = read(self.marker)["original"]
        for name, value in saved.items():
            self._write(name, value)
        current = self.read()
        require(all(current[name] == value for name, value in saved.items()),
                "Sysctls still differ from the marker: %r" % current)
        self.marker.unlink()
        return current


# ---------------------------------------------------------------- mounts (inside a private namespace)

_NAMESPACE = {"entered": False}


def enter_private_mount_namespace():
    """Unshare the mount namespace once, so every mount made below disappears when this process exits."""
    if _NAMESPACE["entered"]:
        return
    libc = ctypes.CDLL(None, use_errno=True)
    libc.mount.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_ulong, ctypes.c_char_p]
    if libc.unshare(runner.CLONE_NEWNS) != 0 or \
            libc.mount(b"none", b"/", None, runner.MS_REC | runner.MS_PRIVATE, None) != 0:
        raise OSError(ctypes.get_errno(), "private mount namespace: " + os.strerror(ctypes.get_errno()))
    _NAMESPACE["entered"] = True


def run_tool(args):
    result = subprocess.run(args, capture_output=True, text=True, timeout=60)
    if result.returncode != 0:
        raise OSError(errno.EIO, "%s failed: %s" % (" ".join(args[:3]), result.stderr.strip()[-400:]))
    return result.stdout


def mount_lines(base):
    """The /proc/self/mountinfo lines for everything mounted below base (recorded as the variant's setup)."""
    lines = []
    for line in Path("/proc/self/mountinfo").read_text().splitlines():
        if line.split()[4].startswith(base):
            left, _, right = line.partition(" - ")
            fields, tail = left.split(), right.split()
            lines.append({"mount_point": fields[4], "root": fields[3], "mount_options": fields[5],
                          "fstype": tail[0], "source": tail[1], "super_options": tail[2] if len(tail) > 2 else ""})
    return lines


class Mounts:
    """Builds the roots of one variant under a fresh base directory and removes everything afterwards."""

    def __init__(self, parent=None):
        self.base = tempfile.mkdtemp(prefix="cse227-probe-v2-variant-", dir=parent or tempfile.gettempdir())
        os.chmod(self.base, 0o755)
        self.mounted = []

    def directory(self, name):
        path = os.path.join(self.base, name)
        os.makedirs(path, mode=0o755)
        os.chmod(path, 0o755)
        return path

    def mount(self, args, point):
        run_tool(["mount"] + args + [point])
        self.mounted.append(point)
        return point

    def tmpfs(self, name, options):
        return self.mount(["-t", "tmpfs", "-o", options, "tmpfs"], self.directory(name))

    def build(self, spec):
        """Returns {'root', 'alternate_root', 'fill_records', 'fill_workspace', 'effects'} for a variant spec."""
        kind = spec["root"]
        if kind == "tmpfs":
            root = self.tmpfs("probe", runner.TMPFS_OPTIONS)
        elif kind in ("overlay_tmpfs", "overlay_ext4"):
            backing = (self.tmpfs("overlay-backing", runner.TMPFS_OPTIONS.replace(",noexec", ""))
                       if kind == "overlay_tmpfs" else self.directory("overlay-backing"))
            layers = {}
            for layer in ("lower", "upper", "work"):
                layers[layer] = os.path.join(backing, layer)
                os.mkdir(layers[layer], 0o755)
                os.chmod(layers[layer], 0o755)
            root = self.mount(["-t", "overlay", "-o", "lowerdir=%(lower)s,upperdir=%(upper)s,workdir=%(work)s"
                               % layers, "overlay"], self.directory("probe"))
        elif kind == "bind_ext4":
            root = self.mount(["--bind", self.directory("bind-source")], self.directory("probe"))
        elif kind == "plain":
            root = self.directory("probe")
        else:
            raise ValueError("Unknown root kind: " + kind)
        os.chmod(root, 0o755)
        fill = {}
        for name in ("fill-records", "fill-workspace"):
            if spec["fill"] == "bind_tmpfs":
                source = self.tmpfs(name + "-source", runner.FILL_TMPFS_OPTIONS)
                fill[name] = self.mount(["--bind", source], self.directory(name))
            else:
                fill[name] = self.tmpfs(name, runner.FILL_TMPFS_OPTIONS)
        return {"root": root, "alternate_root": self.directory("alternate") if spec["alternate_root"] else None,
                "fill_records": fill["fill-records"], "fill_workspace": fill["fill-workspace"],
                "effects": self.tmpfs("effects", runner.FILL_TMPFS_OPTIONS)}

    def cleanup(self):
        """Unmount in reverse order, clear inode flags on what remains and delete the base. Returns True if gone."""
        for point in reversed(self.mounted):
            if subprocess.run(["umount", point], capture_output=True).returncode != 0:
                subprocess.run(["umount", "-l", point], capture_output=True)
        self.mounted = []
        if os.path.isdir(self.base):
            fixture.clear_flags_recursive(self.base)
            shutil.rmtree(self.base, ignore_errors=True)
        return not os.path.exists(self.base) and not mount_lines(self.base)


# ---------------------------------------------------------------- sysctl effect controls

def as_identity(identity, action):
    """Run action() in a forked child dropped to identity with the committed fixture's drop code."""
    uid, gid, groups = identity
    reader, writer = os.pipe()
    sys.stdout.flush()
    sys.stderr.flush()
    pid = os.fork()
    if pid == 0:
        code = 1
        try:
            os.close(reader)
            fixture.drop_identity(uid, gid, groups)
            os.umask(0)
            report = {"uid": list(os.getresuid()), "gid": list(os.getresgid()), "groups": sorted(os.getgroups()),
                      "status": fixture.proc_status(), "result": "ok", "errno": None}
            try:
                action()
            except OSError as error:
                report.update(result="refused:" + errno.errorcode.get(error.errno, str(error.errno)),
                              errno=error.errno)
            os.write(writer, json.dumps(report).encode())
            code = 0
        finally:
            os._exit(code)
    os.close(writer)
    data = b""
    while True:
        chunk = os.read(reader, 65536)
        if not chunk:
            break
        data += chunk
    os.close(reader)
    _, status = os.waitpid(pid, 0)
    require(status == 0 and data, "An effect-control child failed.")
    report = json.loads(data)
    report["identity_valid"] = fixture.helper_valid(report, identity)
    return report


def _open_flags(text):
    value = 0
    for name in text.split("|"):
        value |= getattr(os, name)
    return value


def _lstat_record(path):
    try:
        metadata = os.lstat(path)
    except OSError as error:
        return {"exists": False, "errno": error.errno}
    record = {"exists": True, "uid": metadata.st_uid, "gid": metadata.st_gid,
              "mode": oct(stat.S_IMODE(metadata.st_mode)),
              "type": "symlink" if stat.S_ISLNK(metadata.st_mode) else "directory"
              if stat.S_ISDIR(metadata.st_mode) else "file"}
    if record["type"] == "file":
        record["content"] = Path(path).read_bytes().decode("latin-1")
    if record["type"] == "symlink":
        record["symlink_target"] = os.readlink(path)
    return record


def measure_effect_controls(root, sysctls):
    """One fresh directory per (control, directory kind). Returns rows with outcome, prediction and match."""
    rows = []
    agent_record, recorder_record = "agent-planted\n", "recorder-record\n"
    for directory_kind, layout in EFFECT_DIRECTORIES.items():
        for control, definition in EFFECT_CONTROLS.items():
            base = os.path.join(root, directory_kind + "--" + control)
            records, workspace = os.path.join(base, "records"), os.path.join(base, "workspace")
            for path in (base, records, workspace):
                os.mkdir(path, 0o755)
            os.chmod(records, layout["mode"])
            os.chown(records, fixture.RECORDER_UID, layout["gid"])
            os.chown(workspace, fixture.AGENT_UID, fixture.AGENT_GID)
            name, outside = os.path.join(records, "next-session.jsonl"), os.path.join(workspace, "agent-file.jsonl")
            agent = (fixture.AGENT_UID, fixture.AGENT_GID, layout["agent_groups"])
            recorder = (fixture.RECORDER_UID, fixture.RECORDER_GID, [])

            def plant():
                target = name if definition["planted"] == "regular" else outside
                descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o666)
                os.write(descriptor, agent_record.encode())
                os.fchmod(descriptor, 0o666)
                os.close(descriptor)
                if definition["planted"] == "symlink":
                    os.symlink(outside, name)

            def record():
                descriptor = os.open(name, _open_flags(definition["recorder_flags"]), 0o644)
                try:
                    os.write(descriptor, recorder_record.encode())
                finally:
                    os.close(descriptor)

            planted = as_identity(agent, plant)
            before = {"name": _lstat_record(name), "agent_file": _lstat_record(outside)}
            opened = as_identity(recorder, record)
            after = {"name": _lstat_record(name), "agent_file": _lstat_record(outside)}
            holder = after["name"] if definition["planted"] == "regular" else after["agent_file"]
            if not (planted["identity_valid"] and opened["identity_valid"] and planted["result"] == "ok"):
                outcome = "unexpected_error"
            elif opened["result"] == "ok" and holder.get("content") == agent_record + recorder_record \
                    and holder.get("uid") == fixture.AGENT_UID:
                outcome = "appended_into_agent_file"
            elif opened["result"].startswith("refused:") and after == before:
                outcome = opened["result"]
            else:
                outcome = "unexpected_error"
            expected = predicted_effect(control, directory_kind, sysctls)
            rows.append({"control": control, "directory": directory_kind, "what": definition["what"],
                         "recorder_open_flags": definition["recorder_flags"],
                         "directory_metadata": _lstat_record(records), "before_recorder_open": before,
                         "after_recorder_open": after, "agent_child": planted, "recorder_child": opened,
                         "outcome": outcome, "predicted": expected, "matches_prediction": outcome == expected})
    return rows


# ---------------------------------------------------------------- derived views (pure functions)

def layout_lists(observations):
    """The three-valued layout lists and the suppression table, recomputed from one evidence file.

    Uses the runner's protection_assessment: a layout is listed under "holds" only if every required cell
    was executed and good, under "fails" if an executed cell was bad, and otherwise under "undetermined"
    with the missing cells named. List A requires the layout-discriminating proxies; the runner's own list
    (all judged proxies) is included for comparison.
    """
    discriminating = runner.protection_assessment(observations, "discriminating_proxies_kept")
    judged = runner.protection_assessment(observations, "judged_proxies_kept")
    table = {case: {row["operation"]: row["verdict"] for row in observations.get("suppression_controls", [])
                    if row["case"] == case} for case in observations["layouts"]}
    return {
        "rule": runner.ASSESSMENT_RULE,
        "tampering_denied_and_discriminating_proxies_kept": discriminating["tampering_denied_and_proxies_kept"],
        "and_resists_every_suppression_operation": discriminating["and_resists_every_suppression_operation"],
        "and_resists_precreate_and_separate_filesystem_fill":
            discriminating["and_resists_precreate_and_separate_filesystem_fill"],
        "runner_tampering_denied_and_all_judged_proxies_kept": judged["tampering_denied_and_proxies_kept"],
        "suppression_table": table}


def environment_facts(evidence):
    environment = evidence["observations"]["environment"]
    return {"kernel_release": environment["kernel_release"], "python_version": environment["python_version"],
            "sysctl_fs": environment["sysctl_fs"],
            "setup_process_capabilities": environment["setup_process"]["effective_capability_names"],
            "setup_process_no_new_privs": environment["setup_process"]["status"].get("NoNewPrivs"),
            "probe_roots": [{"label": item["label"], "fstype": item["filesystem"].get("fstype"),
                             "mount_options": item["filesystem"].get("mount_options"),
                             "features": {name: value["supported"] for name, value in item["features"].items()}}
                            for item in environment["probe_roots"]],
            "fill_roots": [{"label": item["label"], "fstype": item["filesystem"].get("fstype")}
                           for item in (environment.get("fill_roots") or [])],
            "layout_filesystems": sorted({str(layout["filesystem"])
                                          for layout in evidence["observations"]["layouts"].values()})}


def difference_analysis(committed, variant, predictions):
    """Every signature difference versus the committed evidence, split and checked against the predictions."""
    before, after = runner.verdict_signature(committed), runner.verdict_signature(variant)
    predicted = {item["cell"]: item for item in predictions}
    differences = []
    for cell in sorted(set(before) | set(after)):
        old, new = before.get(cell), after.get(cell)
        if old == new:
            continue
        old_verdict, new_verdict = (old or [None])[0], (new or [None])[0]
        if fixture.N in (old_verdict, new_verdict):
            kind = "not_run_vs_measured"
        elif old_verdict != new_verdict:
            kind = "verdict_changed"
        else:
            kind = "same_verdict_other_detail_changed"
        entry = {"cell": cell, "kind": kind, "committed": old, "variant": new,
                 "predicted": cell in predicted and predicted[cell]["to"] == new_verdict
                 and predicted[cell]["from"] == old_verdict}
        if cell in predicted:
            entry["prediction"] = predicted[cell]
        if not entry["predicted"]:
            entry["flag"] = "UNEXPLAINED: not predicted before the run; kept as measured"
        differences.append(entry)
    seen = {entry["cell"] for entry in differences}
    coverage = runner.compare(committed, variant)
    return {"recorded_cells": coverage["recorded_cells"], "executed_in_both": coverage["executed_in_both"],
            "not_run_in_both": coverage["not_run_in_both"], "same_coverage": coverage["same_coverage"],
            "differences": differences,
            "verdict_changed": [e["cell"] for e in differences if e["kind"] == "verdict_changed"],
            "same_verdict_other_detail_changed": [e["cell"] for e in differences
                                                  if e["kind"] == "same_verdict_other_detail_changed"],
            "not_run_vs_measured": [e["cell"] for e in differences if e["kind"] == "not_run_vs_measured"],
            "predicted_and_observed": [e["cell"] for e in differences if e["predicted"]],
            "unpredicted_observed": [e["cell"] for e in differences if not e["predicted"]],
            "predicted_but_not_observed": sorted(set(predicted) - seen),
            "all_predictions_held": not [e for e in differences if not e["predicted"]]
            and not (set(predicted) - seen)}


def derive(evidence, committed, variant):
    """Everything in a variant's summary entry that is a pure function of its evidence file."""
    observations = evidence["observations"]
    summary = runner.summarize(evidence)
    return {"environment": environment_facts(evidence), "coverage": runner.coverage(observations),
            "counts": {"ordinary": summary["ordinary_verdict_counts"],
                       "layout_discriminating_proxies": summary["layout_discriminating_proxy_outcome_counts"],
                       "inherited_descriptor": summary["descriptor_verdict_counts"],
                       "suppression": summary["suppression_verdict_counts"]},
            "mismatches_with_the_fixture_coded_expectations": summary["expectation_mismatches"],
            "all_evaluated_observations_match_fixture_expectation":
                observations["all_evaluated_observations_match_expectation"],
            "not_run": summary["not_run"], "layout_lists": layout_lists(observations),
            "difference_analysis": difference_analysis(committed, evidence, VARIANTS[variant]
                                                       ["predicted_differences"])}


def reference_record(committed, path):
    return {"evidence": str(path), "evidence_sha256": sha(ROOT / path),
            "fixture_sha256": committed["run"]["fixture_sha256"], "runner_sha256": committed["run"]["runner_sha256"],
            "environment": environment_facts(committed), "layout_lists": layout_lists(committed["observations"])}


# ---------------------------------------------------------------- executing one variant

def run_fixture(roots):
    """Run the committed fixture with the committed runner's capability restriction. Returns (code, out, err)."""
    command = runner.fixture_command(roots["root"], roots["alternate_root"], roots["fill_records"],
                                     roots["fill_workspace"])
    process = subprocess.Popen(command, preexec_fn=runner.setup_preexec([], True), stdin=subprocess.DEVNULL,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd="/")
    try:
        out, err = process.communicate(timeout=900)
    except BaseException:
        process.kill()
        process.wait()
        raise
    return command, process.returncode, out, err


def measure_once(variant, guard, scratch_parent=None):
    """One full probe-02 run under a variant. Returns (evidence or None, effect rows or None, failure or None)."""
    spec = VARIANTS[variant]
    started = now()
    hashes = {"fixture_sha256": sha(ROOT / runner.FIXTURE), "runner_sha256": sha(Path(runner.__file__)),
              "wrapper_sha256": sha(Path(__file__))}
    run = {"mode": "local-variant", "variant": variant, "image_id": None, "cleanup_verified": False,
           "model_calls": 0, **hashes}
    settings = {"variant": variant, "description": spec["description"], "root_kind": spec["root"],
                "fill_kind": spec["fill"], "alternate_root_offered": spec["alternate_root"],
                "setup_capabilities_restricted_to": sorted(runner.CAPABILITIES), "sysctl": {}}
    mounts, observations, effects, failure = None, None, None, None
    try:
        enter_private_mount_namespace()
        mounts = Mounts(scratch_parent)
        roots = mounts.build(spec)
        settings.update(roots=roots, mounts=mount_lines(mounts.base))
        settings["sysctl"]["during"] = guard.apply(spec["sysctls"])
        settings["sysctl"]["original"] = dict(guard.original)
        settings["sysctl"]["requested"] = spec["sysctls"]
        command, code, out, err = run_fixture(roots)
        settings["fixture_command"] = command
        run["fixture_exit_code"] = code
        run["fixture_stderr_tail"] = err.decode(errors="replace")[-1500:]
        require(code == 0, "Probe process failed: " + out.decode(errors="replace")[-500:]
                + err.decode(errors="replace")[-800:])
        observations = json.loads(out)
        effects = measure_effect_controls(roots["effects"], settings["sysctl"]["during"])
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
        failure = type(error).__name__ + ": " + str(error)
    finally:
        try:
            settings["sysctl"]["restored"] = guard.restore()
            restored = guard.original is None or settings["sysctl"]["restored"] == guard.original
        except OSError as error:
            restored, failure = False, failure or "sysctl restore failed: " + str(error)
        cleaned = mounts.cleanup() if mounts else True
        run["cleanup_verified"] = bool(cleaned and restored)
        if not run["cleanup_verified"]:
            failure = failure or "Variant cleanup (mounts or sysctls) could not be verified."
    run.update(started_at=started, finished_at=now(), error=failure, environment_note=spec["description"],
               command=[Path(sys.argv[0]).name] + sys.argv[1:],
               host={"kernel_release": platform.release(), "python_version": platform.python_version()},
               status="finished" if failure is None else "incomplete")
    if failure is not None:
        return None, None, failure
    recorded = observations["environment"]["sysctl_fs"]
    require(all(recorded.get(name) == value for name, value in spec["sysctls"].items()),
            "The fixture did not observe the requested sysctl values: %r" % recorded)
    return {"run": run, "environment_settings": settings, "observations": observations}, effects, None


def committed_compare(first, second):
    """The committed runner's own --compare command line; returns its JSON output."""
    result = subprocess.run([sys.executable, str(Path(runner.__file__)), "--compare", str(first), str(second)],
                            capture_output=True, text=True, timeout=120)
    require(result.returncode in (0, 1, 3) and result.stdout.strip(), "--compare failed: " + result.stderr[-400:])
    return json.loads(result.stdout)


def execute_variant(variant, output, guard, runs=2, keep="differing", scratch_parent=None):
    """Run a variant `runs` times, write its files into output and return its summary entry."""
    spec = VARIANTS[variant]
    committed = read(ROOT / COMMITTED_EVIDENCE)
    entry = {"status": "not_run", "description": spec["description"], "requested_sysctls": spec["sysctls"],
             "predicted_differences": spec["predicted_differences"], "prediction_basis": spec["prediction_basis"],
             "regenerate_command": "python3 research/tools/run_permission_probe_v2_variants.py --run %s "
                                   "--keep-evidence all --output-dir <directory>" % variant}
    evidence_path = output / ("evidence-%s.json" % variant)
    repeat_path = output / (".repeat-%s.json" % variant)
    try:
        evidence, effects, failure = measure_once(variant, guard, scratch_parent)
        if failure:
            entry["not_run_reason"] = failure
            return entry
        write_json(evidence_path, evidence)
        compare_path = output / ("compare-%s.json" % variant)
        comparison = committed_compare(ROOT / COMMITTED_EVIDENCE, evidence_path)
        write_json(compare_path, comparison)
        write_json(output / ("effect-controls-%s.json" % variant),
                   {"variant": variant, "note": "Supplementary sysctl effect controls measured by the wrapper; "
                                                "NOT part of the probe-02 matrix.",
                    "sysctls_during": evidence["environment_settings"]["sysctl"]["during"],
                    "prediction_basis": EFFECT_BASIS, "rows": effects})
        entry.update(status="executed", evidence_sha256=sha(evidence_path),
                     wrapper_sha256=evidence["run"]["wrapper_sha256"],
                     fixture_sha256=evidence["run"]["fixture_sha256"],
                     runner_sha256=evidence["run"]["runner_sha256"],
                     started_at=evidence["run"]["started_at"], finished_at=evidence["run"]["finished_at"],
                     setup={key: evidence["environment_settings"][key]
                            for key in ("root_kind", "fill_kind", "alternate_root_offered", "mounts", "sysctl")},
                     comparison_file=compare_path.name, comparison=comparison,
                     effect_controls_file="effect-controls-%s.json" % variant,
                     effect_controls={"%s/%s" % (row["directory"], row["control"]):
                                      {"outcome": row["outcome"], "predicted": row["predicted"],
                                       "matches_prediction": row["matches_prediction"]} for row in effects},
                     derived=derive(evidence, committed, variant))
        repeats = []
        for _ in range(max(0, runs - 1)):
            again, again_effects, failure = measure_once(variant, guard, scratch_parent)
            if failure:
                repeats.append({"status": "failed", "error": failure})
                continue
            write_json(repeat_path, again)
            result = committed_compare(evidence_path, repeat_path)
            repeats.append({"status": "executed", "recorded_cells": result["recorded_cells"],
                            "executed_in_both": result["executed_in_both"],
                            "not_run_in_both": result["not_run_in_both"],
                            "not_run_vs_measured": result["not_run_vs_measured"],
                            "verdict_differences_among_executed_in_both":
                                result["verdict_differences_among_executed_in_both"],
                            "same_coverage_and_identical_verdicts": result["same_coverage_and_identical_verdicts"],
                            "effect_controls_identical":
                                [row["outcome"] for row in again_effects] == [row["outcome"] for row in effects]})
        entry["reproducibility"] = {"runs": runs, "repeats": repeats,
                                    "all_repeats_identical": None if not repeats else all(
                                        item.get("same_coverage_and_identical_verdicts")
                                        and item.get("effect_controls_identical")
                                        for item in repeats)}
        differs = bool(entry["derived"]["difference_analysis"]["differences"])
        entry["evidence_file"] = evidence_path.name if keep == "all" or differs else None
        entry["evidence_committed_because"] = ("its signature differs from the committed run" if differs else
                                               "--keep-evidence all" if keep == "all" else None)
        return entry
    finally:
        if repeat_path.exists():
            repeat_path.unlink()
        if entry.get("evidence_file") is None and evidence_path.exists():
            evidence_path.unlink()


def update_summary(output, entries, guard):
    path = output / SUMMARY_NAME
    committed = read(ROOT / COMMITTED_EVIDENCE)
    summary = read(path) if path.exists() else {"variants": {}}
    summary["variants"].update(entries)
    summary.update(
        protocol=PROTOCOL,
        scope="Probe 02 re-run unchanged under filesystem and sysctl variants. Synthetic POSIX/Linux mechanism "
              "measurements; no native coding agent, model, native logging or resume. Not the baseline Docker image.",
        prediction_note="Predictions are literals in run_permission_probe_v2_variants.py (sha256 recorded per "
                        "variant). Whether they were written before the runs cannot be verified from these files.",
        committed_reference=reference_record(committed, COMMITTED_EVIDENCE),
        not_run_variants=NOT_RUN_VARIANTS, effect_control_prediction_basis=EFFECT_BASIS,
        variants={name: summary["variants"][name] for name in VARIANTS if name in summary["variants"]},
        sysctls_after_last_run=guard.read(), updated_at=now())
    write_json(path, summary)
    return summary


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--list", action="store_true", help="print the variants and their predictions")
    parser.add_argument("--run", help="comma-separated variant names, or 'all'")
    parser.add_argument("--output-dir", default=str(ROOT / OUTPUT))
    parser.add_argument("--runs", type=int, default=2, help="full runs per variant (the extra ones check repeatability)")
    parser.add_argument("--keep-evidence", choices=("differing", "all"), default="differing",
                        help="keep the ~4 MB evidence file only when it differs from the committed run, or always")
    parser.add_argument("--scratch-parent", default=None, help="directory for the variant's mount points")
    parser.add_argument("--restore-stale-marker", action="store_true",
                        help="restore sysctls from a marker left by an interrupted run, then exit")
    arguments = parser.parse_args(argv)
    guard = SysctlGuard()
    if arguments.restore_stale_marker:
        print("Restored:", guard.restore_from_marker())
        return
    if arguments.list or not arguments.run:
        for name, spec in VARIANTS.items():
            print("%s\n  %s\n  sysctls: %s\n  predicted differences: %d" % (
                name, spec["description"], spec["sysctls"] or "defaults", len(spec["predicted_differences"])))
        for name, reason in NOT_RUN_VARIANTS.items():
            print("%s\n  %s" % (name, reason))
        return
    require(os.geteuid() == 0, "Variants must run as root (mounts, sysctls, dropping to other UIDs).")
    names = list(VARIANTS) if arguments.run == "all" else arguments.run.split(",")
    require(all(name in VARIANTS for name in names), "Unknown variant; use --list.")
    output = Path(arguments.output_dir)
    require(output.is_dir(), "Output directory is missing: " + str(output))
    guard.refuse_if_stale()
    initial = guard.read()
    atexit.register(guard.restore)
    for number in (signal.SIGTERM, signal.SIGINT):
        signal.signal(number, _raise_interrupted)
    try:
        for name in names:
            print("Running variant %s ..." % name, flush=True)
            entry = execute_variant(name, output, guard, arguments.runs, arguments.keep_evidence,
                                    arguments.scratch_parent)
            update_summary(output, {name: entry}, guard)
            if entry["status"] != "executed":
                print("  NOT RUN:", entry["not_run_reason"])
                continue
            analysis = entry["derived"]["difference_analysis"]
            print("  recorded %d; executed in both %d; not run in both %d; verdict changed %d; other detail "
                  "changed %d; not_run-vs-measured %d; unpredicted %d; predicted but not observed %d" % (
                      analysis["recorded_cells"], analysis["executed_in_both"], analysis["not_run_in_both"],
                      len(analysis["verdict_changed"]),
                      len(analysis["same_verdict_other_detail_changed"]), len(analysis["not_run_vs_measured"]),
                      len(analysis["unpredicted_observed"]), len(analysis["predicted_but_not_observed"])))
            lists = entry["derived"]["layout_lists"]
            for key in ("tampering_denied_and_discriminating_proxies_kept",
                        "and_resists_every_suppression_operation",
                        "and_resists_precreate_and_separate_filesystem_fill"):
                print("  %s: holds %d, fails %d, UNDETERMINED %d" % (
                    key, len(lists[key]["holds"]), len(lists[key]["fails"]), len(lists[key]["undetermined"])))
            print("  repeat runs identical:", entry["reproducibility"]["all_repeats_identical"],
                  "| effect controls matching prediction: %d/%d" % (
                      sum(item["matches_prediction"] for item in entry["effect_controls"].values()),
                      len(entry["effect_controls"])))
    finally:
        final = guard.restore() or guard.read()
        print("Sysctls restored and verified:", guard.read(), "| initial:", initial,
              "| equal:", guard.read() == initial, "| marker present:", guard.marker.exists(), flush=True)
        del final
    print("Summary:", output / SUMMARY_NAME)
    print("No model calls were made. Differences are kept as measured, never adjusted.")


if __name__ == "__main__":
    try:
        main()
    except Interrupted as error:
        raise SystemExit("STOP: " + str(error))
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
        raise SystemExit("STOP: " + str(error))
