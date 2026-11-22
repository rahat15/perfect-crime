"""Permission probe 03: the recommended layout measured as ONE integrated fixture (stdlib only).

Probe 02 measured the pieces separately: recorder-owned records, a separate records filesystem, protected
ancestors, the append-only flag. Probe 03 builds them together: the records tree is on its OWN filesystem,
the agent's workspace is on another, every ancestor of the records directory up to the mount root is owned
by root or the recorder, the recorder is UID 1001 and the agent UID 1000, both without capabilities.

Measurement code is the committed probe-02 fixture, imported unchanged (identity drop, child operations,
snapshots, effect definitions, classification, legitimate/descriptor/precreate/fill measurements). What
this file adds, and why it has to differ, is listed in research/analysis/permission-probe-03-design.md.

Expectations: every expected verdict below is a literal with a one-line reason from POSIX/Linux semantics.
The evidence records this file's sha256 (and the probe-02 fixture's), so a reader can check which
expectations a run was compared with. The files cannot prove the expectations were written before any
earlier run.

Synthetic mechanism probe: no native coding agent, model, native logging or native resume is exercised.
"""

import argparse
import contextlib
import errno
import json
import os
from pathlib import Path
import sys
import time

if "__file__" in globals():
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
try:
    from research.tools import permission_probe_v2_fixture as v2
except ImportError:  # inside a container the runner's stdin bundle registers the module under this name
    import permission_probe_v2_fixture as v2

PROTOCOL = "disposable-posix-boundary-v3"
SCOPE = ("Synthetic POSIX/Linux file operations by dropped-privilege child processes against integrated layouts "
         "(records on their own filesystem, protected ancestors, separate recorder account). No native coding "
         "agent, model, native logging or native session resume was run. Legitimate-operation controls are "
         "synthetic proxies.")
A, R = v2.AGENT_UID, v2.RECORDER_UID
E, D, N, X, S, NOSUP, UNEXPECTED = v2.E, v2.D, v2.N, v2.X, v2.S, v2.NOSUP, v2.UNEXPECTED
BOUNDARY = "blocked_by_filesystem_boundary"
INODE_CAP = 8192
BOUNDED_ROOT_MAX_BYTES = 64 * 1024 * 1024
WINDOW_PREFIX = "new_session_window:"
NEW_SESSION_NAME = v2.NEXT_SESSION_NAME

VERDICT_DEFINITIONS = dict(v2.VERDICT_DEFINITIONS, **{
    BOUNDARY: "Child failed with EXDEV (source and destination on different mounts) and the protected state is "
              "identical. Not a permission denial: the filesystem boundary stopped the operation before any "
              "permission was consulted. Probe 02 has no such verdict because its workspace shared the "
              "records filesystem.",
    S: "The agent's action was executed and the recorder's follow-up was starved or refused as defined.",
    NOSUP: "The agent's action was executed (or found nothing it could write) and the recorder's follow-up "
           "completed in full.",
})

# ---------------------------------------------------------------- layouts

_READONLY = ((0, 0, 0o755), (R, R, 0o755), (R, R, 0o644))
_NO_ACCESS = ((0, 0, 0o755), (R, R, 0o700), (R, R, 0o600))
ORDINARY, WINDOW, DESCRIPTORS, SUPPRESSION, LEGIT = "ordinary", "new_session_window", "descriptors", \
    "suppression", "legit"
FULL = (ORDINARY, WINDOW, DESCRIPTORS, SUPPRESSION, LEGIT)
LAYOUTS = {
    "I1_readonly": {
        "kind": "integrated", "placement": "separate", "sealer": False, "sections": FULL,
        "spec": v2._layout("Records dir 0755 and transcript 0644, recorder-owned, on their own filesystem.",
                           *_READONLY)},
    "I2_no_access": {
        "kind": "integrated", "placement": "separate", "sealer": False, "sections": FULL,
        "spec": v2._layout("Records dir 0700 and transcript 0600, recorder-owned, on their own filesystem.",
                           *_NO_ACCESS)},
    "I3_readonly_append_only": {
        "kind": "integrated", "placement": "separate", "sealer": True, "sections": FULL,
        "spec": v2._layout("I1 plus the append-only flag on each transcript; new session files are flagged by "
                           "a separate privileged sealer step.", *_READONLY, file_flags=("append_only",))},
    "I4_no_access_append_only": {
        "kind": "integrated", "placement": "separate", "sealer": True, "sections": FULL,
        "spec": v2._layout("I2 plus the append-only flag on each transcript, with the same sealer.",
                           *_NO_ACCESS, file_flags=("append_only",))},
    "N1_same_filesystem": {
        "kind": "negative_control", "placement": "shared", "sealer": False, "sections": FULL,
        "breaks": "records and the agent's workspace share one filesystem",
        "spec": v2._layout("Negative control: I1, but the workspace is on the records filesystem.", *_READONLY)},
    "N2_agent_owned_parent": {
        "kind": "negative_control", "placement": "separate", "sealer": False, "sections": FULL,
        "breaks": "the parent of the records directory is owned by the agent",
        "spec": v2._layout("Negative control: I1, but the parent of the records directory is agent-owned.",
                           (A, A, 0o755), (R, R, 0o755), (R, R, 0o644))},
    "N3_inherited_descriptor_no_flag": {
        "kind": "negative_control", "placement": "separate", "sealer": False, "sections": (DESCRIPTORS,),
        "breaks": "a writable transcript descriptor reaches the agent and the inode is not append-only",
        "spec": v2._layout("Negative control: I1 with a deliberately inherited writable descriptor "
                           "(descriptor controls only); contrast with I3.", *_READONLY)},
}
INTEGRATED = tuple(name for name, item in LAYOUTS.items() if item["kind"] == "integrated")
AGENT, RECORDER = (A, v2.AGENT_GID, []), (R, v2.RECORDER_GID, [])

# ---------------------------------------------------------------- child operations added to the probe-02 child
#
# The probe-02 child script is reused whole; one operation is appended (probe 02 has no inode-exhaustion
# step). The identity report, step tracking and error handling around it are probe 02's.
_ANCHOR = "    else:\n        raise RuntimeError('Unknown operation')"
_EXTRA = r'''    elif operation == 'exhaust_inodes':
        result['inode_sinks'] = []
        for sink in request['inode_sinks']:
            entry = {'directory': sink, 'created': 0, 'errno': None}
            result['inode_sinks'].append(entry)
            try:
                while entry['created'] < request['inode_cap']:
                    os.close(os.open(os.path.join(sink, 'i-%05d' % entry['created']),
                                     os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644))
                    entry['created'] += 1
            except OSError as error:
                entry['errno'] = error.errno
        step('create empty files until no inode is free')
        if not any(entry['errno'] == 28 for entry in result['inode_sinks']):
            raise RuntimeError('no sink reached ENOSPC')
'''
if v2.CHILD.count(_ANCHOR) != 1:
    raise RuntimeError("The probe-02 child script changed; cannot append the probe-03 operation.")
CHILD = v2.CHILD.replace(_ANCHOR, _EXTRA + _ANCHOR)


@contextlib.contextmanager
def registered():
    """For the duration of a run only: let the probe-02 primitives see the probe-03 layouts and child script.

    The probe-02 functions look layouts up by name in v2.CASES and start children from v2.CHILD. Both are put
    back exactly as they were on exit, so importing this module changes nothing in probe 02.
    """
    cases, child = dict(v2.CASES), v2.CHILD
    v2.CASES.update({name: item["spec"] for name, item in LAYOUTS.items()})
    v2.CHILD = CHILD
    try:
        yield
    finally:
        v2.CHILD = child
        v2.CASES.clear()
        v2.CASES.update(cases)

# ---------------------------------------------------------------- expectations (data, with reasons)

RULES = {
    "M": (D, "the agent is 'other' on a recorder-owned 0644 file: opening it for writing fails with EACCES"),
    "W": (D, "changing a name needs write permission on the records directory; the agent has r-x only: EACCES"),
    "L": (D, "the records directory is 0700 recorder-owned: path lookup fails with EACCES before anything else"),
    "O": (D, "chmod needs ownership and chown needs CAP_CHOWN; the agent has neither: EPERM"),
    "P": (D, "renaming the records directory needs write permission on its root-owned 0755 parent: EACCES"),
    "X": (BOUNDARY, "source and destination are on different mounts: rename(2)/link(2) fail with EXDEV before "
                    "any permission check"),
    "F": (D, "clearing the append-only flag needs CAP_LINUX_IMMUTABLE and ownership: EPERM"),
    "N": (N, "not applicable to this layout"),
    "A": (E, "the parent of the records directory is agent-owned: the agent may rename the directory within it "
             "and put a symlink in its place"),
    "H": (None, "link(2) on one filesystem: with fs.protected_hardlinks=1 the caller must own the file or have "
                "read+write access (EPERM), with 0 it succeeds"),
}
# columns: v2.OPERATIONS order
#   rewrite truncate overwrite append delete replace chmod chown rename_within rename_out rename_parent
#   hardlink symlink_swap_file symlink_swap_dir create_sibling clear_flags
_ORDINARY = {
    "I1_readonly":              "M M M M W X O O W X P X X P W N",
    "I2_no_access":             "L L L L L L L L L L L L L L L N",
    "I3_readonly_append_only":  "M M M M W X O O W X P X X P W F",
    "I4_no_access_append_only": "L L L L L L L L L L L L L L L L",
    "N1_same_filesystem":       "M M M M W W O O W W P H W P W N",
    "N2_agent_owned_parent":    "M M M M W X O O W X A X X A W N",
}
WINDOW_OPERATIONS = ("rewrite", "truncate", "overwrite_in_place", "append_marker", "delete", "replace",
                     "rename_within_dir", "symlink_swap_file")
# The agent acts on a NEW session file the recorder has just created (0644, recorder-owned) and that has not
# been flagged yet. Its protection in that window can only come from the file mode and the directory.
_WINDOW = {
    "I1_readonly":              "M M M M W X W X",
    "I2_no_access":             "L L L L L L L L",
    "I3_readonly_append_only":  "M M M M W X W X",
    "I4_no_access_append_only": "L L L L L L L L",
    "N1_same_filesystem":       "M M M M W W W W",
    "N2_agent_owned_parent":    "M M M M W X W X",
}
ORDINARY_CODES = {name: dict(zip(v2.OPERATIONS, codes.split())) for name, codes in _ORDINARY.items()}
WINDOW_CODES = {name: dict(zip(WINDOW_OPERATIONS, codes.split())) for name, codes in _WINDOW.items()}

SUPPRESSION_OPERATIONS = {
    "precreate_next_session_name":
        "Probe 02's control: the agent tries to create the predictable next session name first; the recorder "
        "then creates it exclusively, opens it without O_EXCL, and the agent tries to rewrite it.",
    "fill_workspace_filesystem_then_recorder_append":
        "Probe 02's fill control: the agent writes fill.bin in its workspace, in the parent of the records "
        "directory and in the records directory until ENOSPC; the recorder then appends %d records. In the "
        "integrated layouts the workspace is on another filesystem than the records."
        % v2.APPEND_MANY_COUNT,
    "fill_records_filesystem_directly_then_recorder_append":
        "The agent tries to create and fill a file in every directory of the records filesystem from the mount "
        "root down to the records directory; the recorder then appends %d records. Finding nothing writable "
        "counts as resisted only if the recorder's appends then complete." % v2.APPEND_MANY_COUNT,
    "exhaust_inodes_then_recorder_new_session":
        "The agent creates empty files in its workspace and in every directory of the records filesystem until "
        "no inode is free; the recorder then creates a new session file (which needs an inode).",
}
# layout -> operation -> (verdict, reason)
_SEPARATE = "the agent can write only on its own workspace filesystem; the records filesystem keeps its space"
SUPPRESSION_EXPECTED = {}
for _name in ("I1_readonly", "I2_no_access", "I3_readonly_append_only", "I4_no_access_append_only"):
    SUPPRESSION_EXPECTED[_name] = {
        "precreate_next_session_name": (NOSUP, "the agent cannot create an entry in the records directory"),
        "fill_workspace_filesystem_then_recorder_append": (NOSUP, _SEPARATE),
        "fill_records_filesystem_directly_then_recorder_append":
            (NOSUP, "no directory on the records filesystem is writable by the agent"),
        "exhaust_inodes_then_recorder_new_session": (NOSUP, "inodes are counted per filesystem; " + _SEPARATE)}
SUPPRESSION_EXPECTED["N1_same_filesystem"] = {
    "precreate_next_session_name": (NOSUP, "the agent cannot create an entry in the records directory"),
    "fill_workspace_filesystem_then_recorder_append":
        (S, "the workspace shares the records filesystem, so filling the workspace leaves the recorder no space"),
    "fill_records_filesystem_directly_then_recorder_append":
        (NOSUP, "this control only tries the directories above the records directory, none of which is "
                "agent-writable; the shared workspace is covered by the other fill control"),
    "exhaust_inodes_then_recorder_new_session":
        (S, "the workspace shares the records filesystem's inode table, so the recorder's create fails ENOSPC")}
SUPPRESSION_EXPECTED["N2_agent_owned_parent"] = {
    "precreate_next_session_name": (NOSUP, "the records directory itself is still recorder-owned 0755"),
    "fill_workspace_filesystem_then_recorder_append":
        (S, "the agent-owned parent is on the records filesystem, so the agent can fill that filesystem"),
    "fill_records_filesystem_directly_then_recorder_append":
        (S, "the agent-owned parent of the records directory is a writable sink on the records filesystem"),
    "exhaust_inodes_then_recorder_new_session":
        (S, "the agent can create files in the agent-owned parent and exhaust the records filesystem's inodes")}

LEGIT_CONTROLS = dict(v2.LEGIT_CONTROLS, **{
    "sealer_seals_new_session_then_recorder_appends": ("recorder", True,
        "Recorder creates a new session file; a privileged sealer sets the append-only flag on it; the recorder "
        "appends a record afterwards. Only in layouts with a sealer."),
    "recorder_appends_200_after_agent_filled_workspace": ("recorder", True,
        "Availability proxy: after the agent has filled every place it can write, the recorder appends %d "
        "records to the existing transcript." % v2.APPEND_MANY_COUNT),
})
# Judged proxies expected to FAIL (everything else is expected to pass).
LEGIT_EXPECTED_FAILURES = {
    ("N1_same_filesystem", "recorder_appends_200_after_agent_filled_workspace"):
        "negative control: the shared filesystem is full",
    ("N2_agent_owned_parent", "recorder_appends_200_after_agent_filled_workspace"):
        "negative control: the agent filled the records filesystem through the agent-owned parent",
}
AGENT_READ_EXPECTED_DENIED = {"I2_no_access", "I4_no_access_append_only"}
DISCRIMINATING = ("recorder_append", "recorder_new_transcript", "sealer_seals_new_session_then_recorder_appends",
                  "recorder_appends_200_after_agent_filled_workspace")

# Cells in which each negative control is designed to show the failure it breaks the layout for.
NEGATIVE_CONTROL_SIGNALS = {
    "N1_same_filesystem": [("suppression", "fill_workspace_filesystem_then_recorder_append", S),
                           ("suppression", "exhaust_inodes_then_recorder_new_session", S)],
    "N2_agent_owned_parent": [("ordinary", "rename_parent_dir", E), ("ordinary", "symlink_swap_dir", E)],
    "N3_inherited_descriptor_no_flag": [("descriptors", "fd_append_ftruncate", E),
                                        ("descriptors", "fd_append_clear_flag_then_pwrite", E),
                                        ("descriptors", "fd_wronly_pwrite_overwrite", E)],
}


def expected_ordinary(layout, operation, protected_hardlinks):
    """(verdict, reason) for an ordinary cell."""
    code = ORDINARY_CODES[layout][operation]
    verdict, reason = RULES[code]
    if code == "H":
        verdict = D if protected_hardlinks == 1 else E
    return verdict, reason


def expected_window(layout, operation):
    return RULES[WINDOW_CODES[layout][operation]]


def expected_descriptor(layout, control):
    """(verdict, outcome, reason) for an inherited-descriptor cell."""
    spec = LAYOUTS[layout]["spec"]
    flagged = "append_only" in spec["file_flags"]
    no_search = spec["directory"][2] == 0o700
    kind = v2.DESCRIPTOR_CONTROLS[control][0]
    if control == "dirfd_listdir":
        return (E, "names_listed_via_dirfd_only" if no_search else "names_listed_via_path_and_dirfd",
                "getdents on an open directory descriptor is not re-checked against path permissions")
    if kind == "directory":
        return D, "no_change", ("a directory descriptor is only a lookup start; unlinkat/renameat still need "
                                "write and search permission on the directory, which the agent lacks")
    if control == "fd_append_write":
        return E, "appended_marker", "an open file description carries its own write authority"
    if control == "fd_append_pwrite_overwrite":
        return X, "appended_only", "on Linux pwrite on an O_APPEND descriptor appends whatever the offset"
    if kind == "file_wronly":
        if flagged:
            return N, None, "the recorder itself cannot open an append-only file O_WRONLY without O_APPEND"
        return E, v2.DESCRIPTOR_CONTROLS[control][1], "a plain O_WRONLY descriptor allows overwrite and truncate"
    if flagged:
        return D, "no_change", ("ftruncate and clearing O_APPEND are refused with EPERM on an append-only inode")
    return E, v2.DESCRIPTOR_CONTROLS[control][1], ("O_APPEND on the descriptor does not stop ftruncate, and "
                                                    "fcntl can clear it, when the inode is not append-only")


def expected_legit(layout, control):
    """(expected value, reason). For judged controls the value is True/False (pass); for the read control
    'readable'/'denied'; None when the control is not applicable to the layout."""
    if control == "agent_read_transcript":
        denied = layout in AGENT_READ_EXPECTED_DENIED
        return ("denied" if denied else "readable"), ("0700/0600 gives the agent no access" if denied else
                                                       "0755/0644 lets 'other' read")
    if control == "sealer_seals_new_session_then_recorder_appends" and not LAYOUTS[layout]["sealer"]:
        return None, "not applicable: this layout has no sealer step"
    if (layout, control) in LEGIT_EXPECTED_FAILURES:
        return False, LEGIT_EXPECTED_FAILURES[(layout, control)]
    return True, "the acting account owns what it writes, or writes only in its own workspace"


def legit_discriminating(layout, control):
    return control in DISCRIMINATING


# ---------------------------------------------------------------- helpers around the probe-02 primitives

@contextlib.contextmanager
def workspace_on(root):
    """Make every probe-02 measurement place the agent workspace on `root` (None = next to the records).

    Probe 02's measure_* functions call setup_fixture without a workspace filesystem. They are reused whole;
    only the workspace location they get is changed here. An explicit workspace_root argument still wins.
    """
    original = v2.setup_fixture

    def placed(records_root, name, case, workspace_root=None):
        return original(records_root, name, case, workspace_root if workspace_root is not None else root)

    v2.setup_fixture = placed
    try:
        yield
    finally:
        v2.setup_fixture = original


def apply_boundary(row):
    """EXDEV with an unchanged protected state and a valid child is the filesystem boundary, not an error."""
    child = row.get("child") or {}
    if (row["verdict"] == UNEXPECTED and child.get("errno") == errno.EXDEV
            and row.get("protected_state_unchanged") is True and child.get("fixture_base_reachable") is True
            and v2.identity_valid(child, AGENT)):
        row["probe_02_classification"] = row["verdict"]
        row["verdict"] = BOUNDARY
        row["verdict_reason"] = "child got EXDEV at step '%s'; protected state identical" % child.get("failed_step")
    return row


def capacity(path):
    values = os.statvfs(path)
    return {"total_bytes": values.f_blocks * values.f_frsize, "free_bytes": values.f_bavail * values.f_frsize,
            "total_inodes": values.f_files, "free_inodes": values.f_ffree}


def bounded_root_problem(root, need_inodes=False):
    """Fill and inode cells only run on a small dedicated filesystem; anything else would be unbounded."""
    filesystem = root["filesystem"]
    if filesystem.get("mount_point") != root["path"]:
        return "%s is not the root of a dedicated filesystem" % root["path"]
    size = capacity(root["path"])
    if not 0 < size["total_bytes"] <= BOUNDED_ROOT_MAX_BYTES:
        return "%s is not size-limited (%d bytes)" % (root["path"], size["total_bytes"])
    if need_inodes and not 0 < size["total_inodes"] <= INODE_CAP:
        return "%s has no bounded inode count (%d inodes)" % (root["path"], size["total_inodes"])
    return None


def records_filesystem_directories(fixture, records_root):
    """Every directory of the records filesystem from the mount root down to the records directory."""
    return [records_root, fixture["base"], fixture["parent"], fixture["records"]]


def _identity(identity):
    return {"uid": identity[0], "gid": identity[1], "groups": identity[2]}


# ---------------------------------------------------------------- measurements that probe 02 does not have

def measure_window(root, all_roots, layout, operation, expected):
    """The agent acts on a new session file between its creation by the recorder and its sealing."""
    spec = LAYOUTS[layout]
    fixture = v2.setup_fixture(root["path"], layout + "--window-" + operation, layout)
    path = os.path.join(fixture["records"], NEW_SESSION_NAME)
    recorder, agent = v2.identity_for(layout, "recorder"), v2.identity_for(layout, "agent")
    payloads = {key: value.decode("latin-1") for key, value in v2.PAYLOADS.items()}
    payloads["NEW_SESSION"] = v2.BASE.decode("latin-1")  # the new file starts with one ordinary record
    created = v2.run_child(recorder, "recorder_create_next_session_excl", fixture, all_roots,
                           extra={"next_session": path, "payloads": payloads})
    unsealed = v2.snapshot(path)
    row = {"case": layout, "operation": WINDOW_PREFIX + operation, "section": WINDOW,
           "effect_category": v2.OPERATIONS[operation][0], "counts_as_tampering": True,
           "fixture": v2._fixture_record(fixture, root), "ancestors": v2.ancestors(fixture["records"]),
           "acting_role": "agent", "intended_identity": _identity(agent), "new_session_path": path,
           "recorder_create_child": created, "unsealed_file": unsealed, "expected": expected,
           "sealer_in_layout": spec["sealer"]}
    ready = (v2.identity_valid(created, recorder) and created.get("operation_succeeded") is True
             and unsealed.get("type") == "file" and unsealed.get("uid") == recorder[0]
             and unsealed.get("sha256") == v2.digest(v2.BASE)
             and (unsealed.get("inode_flags") or {}).get("append_only") is False)
    if not ready:
        row.update(verdict=UNEXPECTED, verdict_reason="the recorder could not create the unsealed new session file",
                   matches_expectation=False)
        return row
    metadata = os.lstat(path)
    new_file = dict(fixture, target=path, device=metadata.st_dev, inode=metadata.st_ino)
    before = v2.state(new_file)
    child = v2.run_child(agent, operation, new_file, all_roots)
    after = v2.state(new_file)
    effect = bool(v2.effect_observed(operation, before, after))
    unchanged = v2.protected_state_unchanged(before, after)
    verdict, reason = v2.classify(v2.identity_valid(child, agent), child, effect, unchanged)
    row.update(before=before, after=after, child=child, defined_effect_present=effect,
               protected_state_unchanged=unchanged, verdict=verdict, verdict_reason=reason)
    apply_boundary(row)
    row.update(v2.denial_fields(row["verdict"], child))
    if spec["sealer"] and unchanged:
        seal = {"performed_by": "setup process (CAP_LINUX_IMMUTABLE, CAP_FOWNER), not the recorder"}
        try:
            v2.change_inode_flags(path, add=v2.FS_APPEND_FL)
            seal["sealed_file"] = v2.snapshot(path)
            follow = v2.run_child(recorder, "recorder_append", new_file, all_roots)
            final = v2.snapshot(path)
            seal.update(recorder_append_child=follow, final_file=final,
                        recorder_append_after_seal_passed=(
                            v2.identity_valid(follow, recorder) and follow.get("operation_succeeded") is True
                            and final.get("sha256") == v2.digest(v2.BASE + v2.TRUSTED)
                            and (final.get("inode_flags") or {}).get("append_only") is True))
        except OSError as error:
            seal["error"] = errno.errorcode.get(error.errno, str(error.errno))
        row["seal"] = seal
    row["matches_expectation"] = row["verdict"] == expected
    return row


def measure_direct_fill(root, all_roots, layout, operation, expected):
    """The agent tries every directory of the records filesystem as a fill sink; then the recorder appends."""
    fixture = v2.setup_fixture(root["path"], layout + "--suppress-direct-fill", layout)
    sinks = [os.path.join(path, "fill.bin") for path in records_filesystem_directories(fixture, root["path"])]
    before, chain = v2.state(fixture), v2.ancestors(fixture["records"])
    size_before = capacity(root["path"])
    agent = v2._stage("agent_fill", "agent", layout, "fill_filesystem", fixture, all_roots,
                      {"fill_sinks": sinks, "fill_chunk": v2.FILL_CHUNK, "fill_sink_cap": v2.FILL_SINK_CAP})
    size_after = capacity(root["path"])
    recorder = v2._stage("recorder_append_many", "recorder", layout, "recorder_append_many", fixture, all_roots,
                         {"append_many_count": v2.APPEND_MANY_COUNT})
    after = v2.state(fixture)
    entries = agent["child"].get("fill", [])
    refused = [entry for entry in entries if entry["stopped"] == "open failed"
               and entry["errno"] in v2.DENIAL_ERRNOS]
    done = recorder["child"]
    if len(entries) == len(sinks) and len(refused) == len(sinks) and agent["identity_valid"]:
        whole = (recorder["result"] == "ok" and done.get("complete_records") == v2.APPEND_MANY_COUNT
                 and not done.get("exhausted") and after["target"].get("inode") == before["target"].get("inode")
                 and after["target"].get("sha256") == v2.digest(v2.BASE + v2.TRUSTED * v2.APPEND_MANY_COUNT))
        verdict, reason = ((NOSUP, "no directory on the records filesystem accepted a file from the agent, and the "
                                   "recorder appended all %d records" % v2.APPEND_MANY_COUNT) if whole else
                           (UNEXPECTED, "no sink was writable but the recorder's appends did not complete"))
        detail = {"recorder_complete_records": done.get("complete_records"),
                  "recorder_exhausted": done.get("exhausted")}
    else:
        verdict, reason, detail = v2.fill_verdict(agent, recorder, before, after)
    row = {"case": layout, "operation": operation, "category": "suppression_of_future_records",
           "fixture": v2._fixture_record(fixture, root), "ancestors": chain,
           "recorder_account": LAYOUTS[layout]["spec"]["recorder_account"],
           "sinks_tried": [{"path": entry["path"], "bytes_written": entry["bytes_written"],
                            "result": errno.errorcode.get(entry["errno"], entry["stopped"])} for entry in entries],
           "agent_writable_sinks_on_records_filesystem": [entry["path"] for entry in entries
                                                          if entry["stopped"] != "open failed"],
           "capacity_before_fill": size_before, "capacity_after_fill": size_after,
           "before": before, "after": after, "stages": [agent, recorder], "verdict": verdict,
           "verdict_reason": reason, "expected": expected, "matches_expectation": verdict == expected}
    row.update(detail)
    return row


def measure_inodes(records_root, workspace_root, all_roots, layout, operation, expected):
    """The agent uses up every inode it can reach; then the recorder needs one for a new session file."""
    separate = workspace_root is not records_root
    fixture = v2.setup_fixture(records_root["path"], layout + "--suppress-inodes", layout,
                               workspace_root=workspace_root["path"] if separate else None)
    sinks = [fixture["workspace"]] + records_filesystem_directories(fixture, records_root["path"])
    before, chain = v2.state(fixture), v2.ancestors(fixture["records"])
    sizes = {"records_filesystem": capacity(records_root["path"]),
             "workspace_filesystem": capacity(workspace_root["path"])}
    agent = v2._stage("agent_exhaust_inodes", "agent", layout, "exhaust_inodes", fixture, all_roots,
                      {"inode_sinks": sinks, "inode_cap": INODE_CAP})
    after_agent = {"records_filesystem": capacity(records_root["path"]),
                   "workspace_filesystem": capacity(workspace_root["path"])}
    create = v2._stage("recorder_new_session", "recorder", layout, "recorder_new_transcript", fixture, all_roots, {})
    created = v2.snapshot(os.path.join(fixture["records"], "new-session.jsonl"))
    append = v2._stage("recorder_append_one_record", "recorder", layout, "recorder_append", fixture, all_roots, {})
    after = v2.state(fixture)
    reached = any(entry["errno"] == errno.ENOSPC for entry in agent["child"].get("inode_sinks", []))
    recorder_uid = v2.identity_for(layout, "recorder")[0]
    if not (agent["identity_valid"] and create["identity_valid"] and reached and agent["result"] == "ok"):
        verdict, reason = UNEXPECTED, "the agent did not exhaust any filesystem's inodes, or an identity was wrong"
    elif (create["result"] == "ok" and created.get("type") == "file" and created.get("uid") == recorder_uid
          and created.get("sha256") == v2.digest(v2.NEW_SESSION)):
        verdict, reason = NOSUP, "the recorder created its new session file after the agent's inode exhaustion"
    elif create["result"] == "ENOSPC" and created.get("exists") is False:
        verdict, reason = S, "the recorder's create failed with ENOSPC: no inode was left on the records filesystem"
    else:
        verdict, reason = UNEXPECTED, "recorder outcome outside the definition: " + str(create["result"])
    return {"case": layout, "operation": operation, "category": "suppression_of_future_records",
            "fixture": v2._fixture_record(fixture, records_root), "ancestors": chain,
            "recorder_account": LAYOUTS[layout]["spec"]["recorder_account"],
            "records_and_workspace_on_separate_filesystems": separate,
            "inode_sinks": [{"directory": entry["directory"], "files_created": entry["created"],
                             "result": errno.errorcode.get(entry["errno"], "cap reached")}
                            for entry in agent["child"].get("inode_sinks", [])],
            "capacity_before": sizes, "capacity_after_agent": after_agent,
            "recorder_new_session_result": create["result"], "recorder_new_session_file": created,
            "recorder_append_to_existing_transcript_result": append["result"],
            "before": before, "after": after, "stages": [agent, create, append], "verdict": verdict,
            "verdict_reason": reason, "expected": expected, "matches_expectation": verdict == expected}


def _legit_row(layout, control, fixture, root, chain, stages, outcome, expected_pass, extra=None):
    row = {"case": layout, "control": control, "acting_role": "recorder", "judged": True,
           "layout_discriminating": True, "discriminating_note": "depends on the layout and its filesystems",
           "recorder_account": LAYOUTS[layout]["spec"]["recorder_account"],
           "intended_identity": _identity(v2.identity_for(layout, "recorder")),
           "fixture": v2._fixture_record(fixture, root), "ancestors": chain, "stages": stages,
           "child": stages[-1]["child"], "identity_valid": all(stage["identity_valid"] for stage in stages),
           "outcome": outcome, "passed": outcome == "passed", "expected_pass": expected_pass,
           "matches_expectation": outcome != UNEXPECTED and (outcome == "passed") == expected_pass}
    row.update(extra or {})
    return row


def measure_sealer_proxy(root, all_roots, layout, control, expected_pass):
    """Recorder creates a new session file, the privileged sealer flags it, the recorder appends."""
    fixture = v2.setup_fixture(root["path"], layout + "--legit-sealer", layout)
    path = os.path.join(fixture["records"], NEW_SESSION_NAME)
    chain = v2.ancestors(fixture["records"])
    create = v2._stage("recorder_creates_new_session", "recorder", layout, "recorder_create_next_session_excl",
                       fixture, all_roots, {"next_session": path})
    created = v2.snapshot(path)
    extra = {"new_session_path": path, "created_file": created,
             "sealed_by": "setup process (CAP_LINUX_IMMUTABLE, CAP_FOWNER), not the recorder"}
    try:
        v2.change_inode_flags(path, add=v2.FS_APPEND_FL)
        extra["sealed_file"] = v2.snapshot(path)
    except OSError as error:
        extra["seal_error"] = errno.errorcode.get(error.errno, str(error.errno))
    metadata = os.lstat(path) if created.get("exists") else None
    target = dict(fixture, target=path) if metadata else fixture
    append = v2._stage("recorder_appends_after_seal", "recorder", layout, "recorder_append", target, all_roots, {})
    truncate = v2._stage("recorder_truncate_after_seal", "recorder", layout, "truncate", target, all_roots, {})
    final = v2.snapshot(path)
    extra.update(final_file=final, recorder_truncate_after_seal_result=truncate["result"])
    sealed = (extra.get("sealed_file", {}).get("inode_flags") or {}).get("append_only") is True
    passed = (create["result"] == "ok" and created.get("uid") == v2.identity_for(layout, "recorder")[0] and sealed
              and append["result"] == "ok" and final.get("sha256") == v2.digest(v2.NEW_SESSION + v2.TRUSTED)
              and truncate["result"] == "EPERM")
    denied = not passed and (create["result"] in ("EACCES", "EPERM") or append["result"] in ("EACCES", "EPERM"))
    outcome = "passed" if passed else "permission_denied" if denied else UNEXPECTED
    extra["child"] = append["child"]
    return _legit_row(layout, control, fixture, root, chain, [create, append, truncate], outcome, expected_pass, extra)


def measure_availability_proxy(records_root, workspace_root, all_roots, layout, control, expected_pass):
    """Probe 02's fill measurement, read as a legitimate-operation proxy for the recorder."""
    row = v2.measure_fill(records_root, workspace_root, all_roots, layout, control,
                          {"verdict": NOSUP if expected_pass else S})
    outcome = {NOSUP: "passed", S: "starved_enospc"}.get(row["verdict"], UNEXPECTED)
    return _legit_row(layout, control, {"base": row["fixture"]["base"]}, records_root, row["ancestors"],
                      row["stages"], outcome, expected_pass,
                      {"fill_measurement": {key: row[key] for key in (
                          "verdict", "verdict_reason", "agent_fill_sinks", "recorder_complete_records",
                          "recorder_torn_bytes", "recorder_exhausted", "recorder_append_errno",
                          "records_and_workspace_on_separate_filesystems", "capacity_before_fill",
                          "capacity_after_fill")}})


# ---------------------------------------------------------------- the run

def _not_run(layout, key, name, reason, expected, whole):
    row = v2._not_run_row(layout, key, name, reason, expected, whole)
    return row


def run_probes(records_root, workspace_root, shared_root, layouts=None, log=sys.stderr):
    with registered():
        return _run_probes(records_root, workspace_root, shared_root, layouts, log)


def _run_probes(records_root, workspace_root, shared_root, layouts, log):
    if os.geteuid() != 0:
        raise RuntimeError("The setup process must be UID 0 inside the disposable environment.")
    os.umask(0o022)
    roots = v2._collect_roots([("records", records_root), ("workspace", workspace_root), ("shared", shared_root)])
    records, workspace, shared = roots
    all_roots = [item["path"] for item in roots]
    for item in roots:
        item["capacity"] = capacity(item["path"])
    environment = v2.environment(roots)
    environment["filesystems_distinct"] = len({os.stat(item["path"]).st_dev for item in roots}) == 3
    hardlinks = environment["sysctl_fs"]["protected_hardlinks"]
    rows, legit, descriptors, suppression, recorded_layouts = [], [], [], [], {}
    started = time.time()

    def clean():
        for item in roots:
            v2.empty_directory(item["path"])

    try:
        for layout in (layouts or list(LAYOUTS)):
            item, spec = LAYOUTS[layout], LAYOUTS[layout]["spec"]
            records_side = shared if item["placement"] == "shared" else records
            workspace_side = shared if item["placement"] == "shared" else workspace
            workspace_path = None if item["placement"] == "shared" else workspace["path"]
            chosen, missing = v2.choose_root(layout, [records_side])
            recorded_layouts[layout] = dict(
                spec, kind=item["kind"], placement=item["placement"], sealer=item["sealer"],
                breaks=item.get("breaks"), sections=list(item["sections"]),
                records_filesystem=records_side["filesystem"], workspace_filesystem=workspace_side["filesystem"],
                records_root=records_side["path"], workspace_root=workspace_side["path"],
                filesystem=records_side["filesystem"].get("fstype"),
                required_features=v2.required_features(layout),
                agent_identity=v2.identity_for(layout, "agent"),
                recorder_identity=v2.identity_for(layout, "recorder"))
            bounded = bounded_root_problem(records_side) or bounded_root_problem(workspace_side)
            bounded_inodes = (bounded_root_problem(records_side, True)
                              or bounded_root_problem(workspace_side, True))
            with workspace_on(workspace_path):
                if ORDINARY in item["sections"]:
                    for operation in v2.OPERATIONS:
                        expected, basis = expected_ordinary(layout, operation, hardlinks)
                        skip = v2.not_applicable_reason(layout, operation)
                        if missing:
                            row = _not_run(layout, "operation", operation, missing, expected, True)
                        elif skip:
                            row = _not_run(layout, "operation", operation, skip, expected, False)
                        else:
                            row = apply_boundary(v2.measure_operation(chosen, all_roots, layout, operation,
                                                                      expected))
                            row["matches_expectation"] = row["verdict"] == expected
                        row.update(section=ORDINARY, expectation_basis=basis,
                                   counts_as_tampering=v2.OPERATIONS[operation][1])
                        rows.append(row)
                        clean()
                if WINDOW in item["sections"]:
                    for operation in WINDOW_OPERATIONS:
                        expected, basis = expected_window(layout, operation)
                        if missing:
                            row = _not_run(layout, "operation", WINDOW_PREFIX + operation, missing, expected, True)
                            row.update(section=WINDOW, counts_as_tampering=True)
                        else:
                            row = measure_window(chosen, all_roots, layout, operation, expected)
                        row["expectation_basis"] = basis
                        rows.append(row)
                        clean()
                if DESCRIPTORS in item["sections"]:
                    for control in v2.DESCRIPTOR_CONTROLS:
                        verdict, outcome, basis = expected_descriptor(layout, control)
                        if missing:
                            row = _not_run(layout, "control", control, missing, verdict, True)
                            row.update(expected_outcome=outcome, outcome=None)
                        else:
                            row = v2.measure_descriptor(chosen, all_roots, layout, control, (verdict, outcome))
                        row["expectation_basis"] = basis
                        descriptors.append(row)
                        clean()
                if SUPPRESSION in item["sections"]:
                    for operation in SUPPRESSION_OPERATIONS:
                        expected, basis = SUPPRESSION_EXPECTED[layout][operation]
                        wanted = {"verdict": expected}
                        problem = missing
                        if operation == "precreate_next_session_name":
                            wanted.update(recorder_open_without_excl="appended_to_recorder_created_file",
                                          agent_rewrite_resulting_file="denied")
                        elif operation == "exhaust_inodes_then_recorder_new_session":
                            problem = problem or bounded_inodes
                        else:
                            problem = problem or bounded
                        if problem:
                            row = v2._suppression_not_run(layout, operation, problem, wanted, True)
                        elif operation == "precreate_next_session_name":
                            row = v2.measure_precreate(chosen, all_roots, layout, wanted)
                        elif operation == "fill_workspace_filesystem_then_recorder_append":
                            row = v2.measure_fill(records_side, workspace_side, all_roots, layout, operation, wanted)
                        elif operation == "fill_records_filesystem_directly_then_recorder_append":
                            row = measure_direct_fill(records_side, all_roots, layout, operation, expected)
                        else:
                            row = measure_inodes(records_side, workspace_side, all_roots, layout, operation,
                                                 expected)
                        row["expectation_basis"] = basis
                        suppression.append(row)
                        clean()
                if LEGIT in item["sections"]:
                    for control, (role, judged, _) in LEGIT_CONTROLS.items():
                        expected, basis = expected_legit(layout, control)
                        base = {"case": layout, "control": control, "judged": judged, "outcome": N,
                                "layout_discriminating": legit_discriminating(layout, control)}
                        if expected is None:
                            row = dict(base, not_run_reason=basis, matches_expectation=True)
                        elif missing:
                            row = dict(base, not_run_reason=missing, matches_expectation=None)
                        elif control == "sealer_seals_new_session_then_recorder_appends":
                            row = measure_sealer_proxy(chosen, all_roots, layout, control, expected)
                        elif control == "recorder_appends_200_after_agent_filled_workspace":
                            row = (dict(base, not_run_reason=bounded, matches_expectation=None) if bounded else
                                   measure_availability_proxy(records_side, workspace_side, all_roots, layout,
                                                              control, expected))
                        else:
                            row = v2.measure_legit(chosen, all_roots, layout, control)
                            row["layout_discriminating"] = legit_discriminating(layout, control)
                            if judged:
                                row.update(expected_pass=expected, matches_expectation=(
                                    row["passed"] == expected and row["outcome"] != UNEXPECTED))
                            else:
                                row.update(expected_observation=expected,
                                           matches_expectation=row["observed"] == expected)
                        row["expectation_basis"] = basis
                        legit.append(row)
                        clean()
            print("Completed layout: " + layout, file=log, flush=True)
    finally:
        emptied = {}
        for item in roots:
            try:
                v2.empty_directory(item["path"])
                emptied[item["path"]] = os.listdir(item["path"]) == []
            except OSError as error:
                emptied[item["path"]] = "cleanup failed: " + str(error)
    evaluated = [row for row in rows + legit + descriptors + suppression if row["matches_expectation"] is not None]
    return {
        "protocol": PROTOCOL, "scope": SCOPE, "environment": environment,
        "accounts": {"agent": [A, v2.AGENT_GID], "recorder": [R, v2.RECORDER_GID]},
        "verdict_definitions": VERDICT_DEFINITIONS,
        "operation_definitions": {name: {"effect_category": value[0], "counts_as_tampering": value[1],
                                         "effect_definition": value[2]} for name, value in v2.OPERATIONS.items()},
        "window_operations": list(WINDOW_OPERATIONS),
        "legit_control_definitions": {name: {"actor": value[0], "judged": value[1], "description": value[2],
                                             "layout_discriminating": name in DISCRIMINATING}
                                      for name, value in LEGIT_CONTROLS.items()},
        "descriptor_control_definitions": {name: {"descriptor": v2.DESCRIPTOR_OPEN_FLAGS[value[0]][0],
                                                  "defined_effect_outcome": value[1]}
                                           for name, value in v2.DESCRIPTOR_CONTROLS.items()},
        "suppression_control_definitions": {name: {"description": text}
                                            for name, text in SUPPRESSION_OPERATIONS.items()},
        "negative_control_signals": {name: [list(cell) for cell in cells]
                                     for name, cells in NEGATIVE_CONTROL_SIGNALS.items()},
        "layouts": recorded_layouts, "rows": rows, "legit_controls": legit,
        "descriptor_controls": descriptors, "suppression_controls": suppression,
        "all_evaluated_observations_match_expectation": all(row["matches_expectation"] for row in evaluated),
        "probe_roots_emptied": emptied, "duration_seconds": round(time.time() - started, 3)}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--records-root", default="/probe-records", help="empty dedicated records filesystem")
    parser.add_argument("--workspace-root", default="/probe-workspace", help="empty dedicated workspace filesystem")
    parser.add_argument("--shared-root", default="/probe-shared",
                        help="empty dedicated filesystem for the same-filesystem negative control")
    parser.add_argument("--layouts", default=None, help="comma-separated layout names (default: all)")
    arguments = parser.parse_args(argv)
    try:
        print(json.dumps(run_probes(arguments.records_root, arguments.workspace_root, arguments.shared_root,
                                    arguments.layouts.split(",") if arguments.layouts else None), indent=2))
    except Exception as error:
        print(json.dumps({"status": "incomplete", "error": type(error).__name__ + ": " + str(error)}))
        raise SystemExit(1)


if __name__ == "__main__":
    main()
