"""Disposable POSIX/Linux permission probes, version 2 (stdlib only, self-contained).

Run as UID 0 inside an isolated environment (a container tmpfs, or a private tmpfs mounted by
``run_permission_probe_v2.py --mode local``). The setup process only builds fixtures and takes
snapshots. Every measured operation runs in a fresh child that was dropped, before exec, to an
unprivileged identity: the agent account (1000) or a separate unprivileged recorder account (1001).

These are synthetic mechanism probes. No native coding agent, model, native logging or native
session resume is exercised. See research/analysis/permission-probe-02-design.md.

Expectations: every expected verdict is a literal in this file (_EXPECTED, _EXPECTED_SUPPRESSION,
LEGIT_EXPECTED_FAILURES, expected_descriptor) reasoned from POSIX/Linux semantics. Each evidence file
records the sha256 of the fixture that produced it, so a reader can confirm the expectations in that
file are the ones the run was measured against. The files cannot prove the expectations were written
before any earlier exploratory run; the pre-registered measurement is the teammate's --mode docker run
in the committed baseline image, done after this code is committed.
"""

import argparse
import errno
import fcntl
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import socket
import stat
import struct
import subprocess
import sys
import time

try:  # ctypes is only needed to set no-new-privileges where the environment has not already.
    import ctypes
    _LIBC = ctypes.CDLL(None, use_errno=True)
except Exception:  # pragma: no cover - depends on the interpreter build
    _LIBC = None

PROTOCOL = "disposable-posix-boundary-v2"
SCOPE = ("Synthetic POSIX/Linux file operations by dropped-privilege child processes. No native "
         "coding agent, model, native logging, native session resume or built-in edit route was run. "
         "Legitimate-operation controls are synthetic proxies.")

AGENT_UID = AGENT_GID = 1000
RECORDER_UID = RECORDER_GID = 1001
SHARED_GID = 2000

BASE = b'{"event":"original-synthetic-record"}\n'
EDIT = b'{"event":"changed-synthetic-record"}\n'
APPEND = b'{"event":"fabricated-test-marker"}\n'
TRUSTED = b'{"event":"trusted-test-marker"}\n'
PATCH = b'{"event":"OVERWRITTEN'
PATCHED = PATCH + BASE[len(PATCH):]
ATTACKER = b'{"event":"attacker-controlled-record"}\n'
SIBLING = b'{"event":"sibling-synthetic-record"}\n'
NEW_SESSION = b'{"event":"new-session-synthetic-record"}\n'

TARGET_NAME = "synthetic-transcript.jsonl"
FS_IOC_GETFLAGS = 0x80086601
FS_IOC_SETFLAGS = 0x40086602
FS_IMMUTABLE_FL = 0x10
FS_APPEND_FL = 0x20
FLAG_BITS = {"append_only": FS_APPEND_FL, "immutable": FS_IMMUTABLE_FL}
ACL_XATTR = "system.posix_acl_access"
PR_SET_NO_NEW_PRIVS = 38
DENIAL_ERRNOS = (errno.EACCES, errno.EPERM)

E, D, N, X = ("effect_observed", "permission_denial_observed", "not_run", "different_effect_observed")
UNEXPECTED = "unexpected_error"
S, NOSUP = "suppression_observed", "no_suppression_observed"
NEXT_SESSION_NAME = "next-session.jsonl"
APPEND_MANY_COUNT = 200
FILL_CHUNK = 4096
FILL_ROOT_MAX_BYTES = 8 * 1024 * 1024
# Per-sink safety cap, larger than a fill filesystem so a reachable sink genuinely reaches ENOSPC
# (never the cap) while still bounding the write if a fill root were somehow not size-limited.
FILL_SINK_CAP = 4 * FILL_ROOT_MAX_BYTES
PR_SET_PDEATHSIG = 1
DENIAL_CLASSES = {
    "EACCES": "discretionary access check refused (mode bits or ACL of the file or a directory)",
    "EPERM": "refused by an ownership, sticky-bit, inode-flag, protected_hardlinks or capability rule",
}

# operation -> (effect category, counted as tampering with the transcript path?, definition of "effect")
OPERATIONS = {
    "rewrite": ("content_modified", True,
                "same inode; content equals the replacement record"),
    "truncate": ("content_modified", True, "same inode; size 0"),
    "overwrite_in_place": ("content_modified", True,
                           "same inode; leading bytes replaced by pwrite at offset 0, length unchanged"),
    "append_marker": ("record_appended", True,
                      "same inode; content equals original record plus fabricated marker"),
    "delete": ("path_removed", True,
               "transcript path absent and no other name in the fixture refers to the original inode"),
    "replace": ("path_replaced", True,
                "transcript path is a regular file with a different inode, owned by the agent, "
                "holding the replacement record"),
    "chmod_then_rewrite": ("content_modified", True,
                           "same inode; content equals the replacement record (after chmod 0666)"),
    "chown_to_agent": ("ownership_changed", True,
                       "transcript owner and group changed to the agent account"),
    "rename_within_dir": ("path_moved_inode_preserved", True,
                          "transcript path absent; records/moved.jsonl is the original inode"),
    "rename_out_of_dir": ("path_moved_inode_preserved", True,
                          "transcript path absent; workspace/moved.jsonl is the original inode"),
    "rename_parent_dir": ("path_moved_inode_preserved", True,
                          "records directory path absent; the original inode is now under home/records-moved"),
    "hardlink_create": ("additional_hard_link_created", False,
                        "workspace/hardlink.jsonl is the original inode; link count +1; transcript content "
                        "unchanged (a second name, not a modification)"),
    "symlink_swap_file": ("path_redirected_by_symlink", True,
                          "lstat of the transcript path is a symlink and reading the path yields "
                          "agent-controlled content"),
    "symlink_swap_dir": ("path_redirected_by_symlink", True,
                         "lstat of the records directory path is a symlink and reading the transcript "
                         "path yields agent-controlled content; original inode under home/records-moved"),
    "create_sibling": ("sibling_file_created", False,
                       "records/sibling.jsonl exists, owned by the agent; transcript unchanged"),
    "clear_inode_flags_then_rewrite": ("content_modified", True,
                                       "append-only/immutable flags cleared and content equals the "
                                       "replacement record"),
}
TAMPERING_OPERATIONS = tuple(name for name, value in OPERATIONS.items() if value[1])
SIDE_EFFECT_OPERATIONS = tuple(name for name, value in OPERATIONS.items() if not value[1])

VERDICT_DEFINITIONS = {
    E: "Child reported success and the independent before/after snapshots show the operation's defined effect.",
    D: "Child failed with EACCES or EPERM and the protected state (transcript snapshot, records directory "
       "metadata and listing, parent listing, locations of the original inode) is identical before and after.",
    X: "Child reported success and state changed, but not in the way the operation's effect is defined; "
       "the concrete outcome is recorded.",
    N: "Not executed: not applicable to the layout, or the environment lacks a required feature (reason recorded).",
    UNEXPECTED: "Anything else: wrong child identity or descriptor state, fixture base unreachable, other errno, "
                "partial change together with a reported error, or reported success without a change.",
}


def _layout(description, parent, directory, target, recorder="separate", agent_groups=(),
            file_flags=(), dir_flags=(), dir_acl=None, file_acl=None):
    return {"description": description, "parent": parent, "directory": directory, "file": target,
            "recorder_account": recorder, "agent_groups": list(agent_groups),
            "file_flags": list(file_flags), "dir_flags": list(dir_flags),
            "dir_acl": dir_acl, "file_acl": file_acl}


_A, _R, _S = AGENT_UID, RECORDER_UID, SHARED_GID
# (uid, gid, mode) for the parent of the records directory, the records directory and the transcript.
CASES = {
    "agent_owned_writable": _layout(
        "Agent-owned file, directory and parent (current same-account wrapper baseline).",
        (_A, _A, 0o755), (_A, _A, 0o755), (_A, _A, 0o600), recorder="shared_with_agent"),
    "recorder_file_agent_writable_dir": _layout(
        "Recorder-owned file in an agent-owned directory.",
        (0, 0, 0o755), (_A, _A, 0o755), (_R, _R, 0o644)),
    "sticky_1777_dir_recorder_file": _layout(
        "Recorder-owned file in a recorder-owned world-writable sticky directory.",
        (0, 0, 0o755), (_R, _R, 0o1777), (_R, _R, 0o644)),
    "sticky_1770_shared_group_dir": _layout(
        "Recorder-owned file in a sticky directory writable by a group shared with the agent.",
        (0, 0, 0o755), (_R, _S, 0o1770), (_R, _S, 0o640), agent_groups=(_S,)),
    "setgid_2770_shared_group_file_0640": _layout(
        "Setgid shared-group directory (no sticky bit); file group-readable only.",
        (0, 0, 0o755), (_R, _S, 0o2770), (_R, _S, 0o640), agent_groups=(_S,)),
    "setgid_2770_shared_group_file_0660": _layout(
        "Setgid shared-group directory (no sticky bit); file group-writable.",
        (0, 0, 0o755), (_R, _S, 0o2770), (_R, _S, 0o660), agent_groups=(_S,)),
    "recorder_owned_agent_readonly": _layout(
        "Recorder-owned file and directory; agent has read/search access only (0755/0644).",
        (0, 0, 0o755), (_R, _R, 0o755), (_R, _R, 0o644)),
    "recorder_owned_no_agent_access": _layout(
        "Recorder-owned file and directory; agent has no access (0700/0600).",
        (0, 0, 0o755), (_R, _R, 0o700), (_R, _R, 0o600)),
    "recorder_dir_in_agent_owned_parent": _layout(
        "Recorder-owned file and directory (0755/0644) whose parent directory is agent-owned.",
        (_A, _A, 0o755), (_R, _R, 0o755), (_R, _R, 0o644)),
    "append_only_same_account": _layout(
        "Agent-owned file with the append-only inode flag; recorder and agent share one account.",
        (_A, _A, 0o755), (_A, _A, 0o755), (_A, _A, 0o644), recorder="shared_with_agent",
        file_flags=("append_only",)),
    "append_only_file_and_dir_same_account": _layout(
        "Agent-owned file and directory both append-only; recorder and agent share one account.",
        (_A, _A, 0o755), (_A, _A, 0o755), (_A, _A, 0o644), recorder="shared_with_agent",
        file_flags=("append_only",), dir_flags=("append_only",)),
    "append_only_recorder_owned": _layout(
        "Recorder-owned file and directory (0755/0644); file append-only.",
        (0, 0, 0o755), (_R, _R, 0o755), (_R, _R, 0o644), file_flags=("append_only",)),
    "immutable_recorder_owned": _layout(
        "Recorder-owned file and directory (0755/0644); file immutable.",
        (0, 0, 0o755), (_R, _R, 0o755), (_R, _R, 0o644), file_flags=("immutable",)),
    "acl_agent_read_only": _layout(
        "Recorder-owned 0700/0600 plus POSIX ACL giving the agent r-x on the directory and r-- on the file.",
        (0, 0, 0o755), (_R, _R, 0o700), (_R, _R, 0o600), dir_acl=(_A, 5), file_acl=(_A, 4)),
    "acl_agent_dir_write_file_read": _layout(
        "Recorder-owned 0700/0600 plus POSIX ACL giving the agent rwx on the directory and r-- on the file.",
        (0, 0, 0o755), (_R, _R, 0o700), (_R, _R, 0o600), dir_acl=(_A, 7), file_acl=(_A, 4)),
}

# Expected verdict per cell, in OPERATIONS order, reasoned from POSIX/Linux semantics (design section 5).
# Fixed here in code; each evidence file records this file's sha256.
# E effect, D denial, N not applicable, H hard link: D when fs.protected_hardlinks=1, E when 0.
_EXPECTED = {
    #                                         RW TR OW AP DL RP CM CO RW RO RP HL SF SD SB CF
    "agent_owned_writable":                  "E  E  E  E  E  E  E  N  E  E  E  E  E  E  E  N",
    "recorder_file_agent_writable_dir":      "D  D  D  D  E  E  D  D  E  E  D  H  E  D  E  N",
    "sticky_1777_dir_recorder_file":         "D  D  D  D  D  D  D  D  D  D  D  H  D  D  E  N",
    "sticky_1770_shared_group_dir":          "D  D  D  D  D  D  D  D  D  D  D  H  D  D  E  N",
    "setgid_2770_shared_group_file_0640":    "D  D  D  D  E  E  D  D  E  E  D  H  E  D  E  N",
    "setgid_2770_shared_group_file_0660":    "E  E  E  E  E  E  D  D  E  E  D  E  E  D  E  N",
    "recorder_owned_agent_readonly":         "D  D  D  D  D  D  D  D  D  D  D  H  D  D  D  N",
    "recorder_owned_no_agent_access":        "D  D  D  D  D  D  D  D  D  D  D  D  D  D  D  N",
    "recorder_dir_in_agent_owned_parent":    "D  D  D  D  D  D  D  D  D  D  E  H  D  E  D  N",
    "append_only_same_account":              "D  D  D  E  D  D  D  N  D  D  E  D  D  E  E  D",
    "append_only_file_and_dir_same_account": "D  D  D  E  D  D  D  N  D  D  D  D  D  D  E  D",
    "append_only_recorder_owned":            "D  D  D  D  D  D  D  D  D  D  D  D  D  D  D  D",
    "immutable_recorder_owned":              "D  D  D  D  D  D  D  D  D  D  D  D  D  D  D  D",
    "acl_agent_read_only":                   "D  D  D  D  D  D  D  D  D  D  D  H  D  D  D  N",
    "acl_agent_dir_write_file_read":         "D  D  D  D  E  E  D  D  E  E  D  H  E  D  E  N",
}
EXPECTED_CODES = {case: dict(zip(OPERATIONS, codes.split())) for case, codes in _EXPECTED.items()}

# Suppression of FUTURE records (availability). Its own category, never folded into tampering with
# existing bytes. Each is an agent action followed by recorder follow-ups run as the recorder identity.
SUPPRESSION_OPERATIONS = {
    "precreate_next_session_name":
        "Agent creates records/next-session.jsonl (a predictable next transcript name) first. The recorder then "
        "tries O_CREAT|O_EXCL on that name, then O_CREAT|O_APPEND without O_EXCL, then the agent tries to rewrite "
        "whatever file holds that name. Suppression = the agent's file holds the name and the recorder's "
        "exclusive create fails with EEXIST.",
    "fill_filesystem_then_recorder_append":
        "Records tree and workspace on ONE small size-limited tmpfs. Agent writes fill.bin in the workspace, the "
        "parent of the records directory and the records directory until ENOSPC. The recorder then appends records "
        "to the existing transcript. Suppression = the recorder hits ENOSPC before all records are written.",
    "fill_filesystem_then_recorder_append_separate_fs":
        "Same, but the records tree and the workspace are on two SEPARATE small tmpfs filesystems; the agent still "
        "tries every sink it can reach.",
}
# S suppression expected, R resisted, N not applicable. Reasoned from semantics: precreate suppresses exactly
# where the agent may create an entry in the records directory; filling one shared filesystem always starves the
# recorder; with separate filesystems it suppresses only where the agent can create a file somewhere on the
# records filesystem (the records directory or an agent-owned ancestor of it). Fixed here in code.
_EXPECTED_SUPPRESSION = {
    #                                         PRE FILL SEP
    "agent_owned_writable":                  "S   S    S",
    "recorder_file_agent_writable_dir":      "S   S    S",
    "sticky_1777_dir_recorder_file":         "S   S    S",
    "sticky_1770_shared_group_dir":          "S   S    S",
    "setgid_2770_shared_group_file_0640":    "S   S    S",
    "setgid_2770_shared_group_file_0660":    "S   S    S",
    "recorder_owned_agent_readonly":         "R   S    R",
    "recorder_owned_no_agent_access":        "R   S    R",
    "recorder_dir_in_agent_owned_parent":    "R   S    S",
    "append_only_same_account":              "S   S    S",
    "append_only_file_and_dir_same_account": "S   S    S",
    "append_only_recorder_owned":            "R   S    R",
    "immutable_recorder_owned":              "R   N    N",
    "acl_agent_read_only":                   "R   S    R",
    "acl_agent_dir_write_file_read":         "S   S    S",
}
EXPECTED_SUPPRESSION_CODES = {case: dict(zip(SUPPRESSION_OPERATIONS, codes.split()))
                              for case, codes in _EXPECTED_SUPPRESSION.items()}


def expected_suppression(case, operation):
    """Coded expectation for one suppression cell: verdict plus the per-stage outcomes for precreate."""
    verdict = {"S": S, "R": NOSUP, "N": N}[EXPECTED_SUPPRESSION_CODES[case][operation]]
    expected = {"verdict": verdict}
    if operation == "precreate_next_session_name" and verdict != N:
        shared = CASES[case]["recorder_account"] == "shared_with_agent"
        if verdict == S:
            expected.update(recorder_open_without_excl="appended_to_agent_created_file" if shared else "denied",
                            agent_rewrite_resulting_file="effect")
        else:
            expected.update(recorder_open_without_excl="appended_to_recorder_created_file",
                            agent_rewrite_resulting_file="denied")
    return expected


def suppression_not_applicable_reason(case, operation):
    if operation != "precreate_next_session_name" and "immutable" in CASES[case]["file_flags"]:
        return ("not applicable: the recorder cannot append to an immutable transcript even on an empty "
                "filesystem, so no fill is needed to stop it")
    return None


def legit_discriminating(case, control):
    """Whether this proxy's outcome can depend on the layout; otherwise it is only a harness sanity check."""
    if control == "agent_workspace_edit_and_test":
        return False, "sanity check: the workspace is agent-owned 0755 in every layout"
    if control == "recorder_read_back":
        return False, "sanity check: the recorder reads a file it owns in every layout"
    if control == "agent_read_transcript":
        return False, "recorded only, not judged"
    if CASES[case]["recorder_account"] == "shared_with_agent":
        return False, "sanity check: recorder and agent are one account in this layout"
    return True, "layout-discriminating: a separate recorder account writes into the records directory"


LEGIT_CONTROLS = {
    "agent_workspace_edit_and_test": ("agent", True,
        "Agent creates a module and a unittest in the workspace, sees it fail, edits the module, sees it pass."),
    "recorder_append": ("recorder", True,
        "Recorder opens the existing transcript O_WRONLY|O_APPEND and writes one record."),
    "recorder_new_transcript": ("recorder", True,
        "Recorder creates a new file in the records directory with O_CREAT|O_EXCL (new-session proxy)."),
    "recorder_read_back": ("recorder", True,
        "Recorder reads the transcript back and the hash matches (resume proxy)."),
    "agent_read_transcript": ("agent", False,
        "Whether the agent account can read the transcript. Recorded, not judged."),
}
JUDGED_LEGIT_CONTROLS = tuple(name for name, value in LEGIT_CONTROLS.items() if value[1])
# Expected failures among the judged controls; every other judged control is expected to pass.
LEGIT_EXPECTED_FAILURES = {
    ("recorder_file_agent_writable_dir", "recorder_new_transcript"),
    ("immutable_recorder_owned", "recorder_append"),
}
AGENT_READ_EXPECTED_DENIED = {"recorder_owned_no_agent_access"}

# control -> (descriptor kind, open flags for the recorder-identity helper, defined effect outcome)
DESCRIPTOR_CONTROLS = {
    "fd_append_write": ("file_append", "appended_marker"),
    "fd_append_pwrite_overwrite": ("file_append", "earlier_bytes_modified"),
    "fd_append_ftruncate": ("file_append", "truncated"),
    "fd_append_clear_flag_then_pwrite": ("file_append", "earlier_bytes_modified"),
    "fd_wronly_pwrite_overwrite": ("file_wronly", "earlier_bytes_modified"),
    "fd_wronly_ftruncate": ("file_wronly", "truncated"),
    "dirfd_unlinkat": ("directory", "path_removed"),
    "dirfd_renameat": ("directory", "path_moved_inode_preserved"),
    "dirfd_listdir": ("directory", "names_listed"),
}
DESCRIPTOR_OPEN_FLAGS = {
    "file_append": ("O_WRONLY|O_APPEND", os.O_WRONLY | os.O_APPEND),
    "file_wronly": ("O_WRONLY", os.O_WRONLY),
    "directory": ("O_RDONLY|O_DIRECTORY", os.O_RDONLY | os.O_DIRECTORY),
}


def expected_verdict(case, operation, protected_hardlinks):
    """Coded expectation for one ordinary cell."""
    code = EXPECTED_CODES[case][operation]
    if code == "H":
        return D if protected_hardlinks == 1 else E
    return {"E": E, "D": D, "N": N}[code]


def not_applicable_reason(case, operation):
    layout = CASES[case]
    if operation == "chown_to_agent" and layout["file"][:2] == (AGENT_UID, AGENT_GID):
        return "not applicable: the transcript is already owned by the agent account, so chown would be a no-op"
    if operation == "clear_inode_flags_then_rewrite" and not layout["file_flags"]:
        return "not applicable: this layout sets no append-only/immutable inode flag"
    return None


def expected_descriptor(case, control, protected_hardlinks):
    """Coded expectation (verdict, outcome) for one inherited-descriptor cell."""
    flags = CASES[case]["file_flags"]
    kind = DESCRIPTOR_CONTROLS[control][0]
    if control == "dirfd_listdir":
        # getdents on an already-open directory descriptor is not re-checked against path permissions.
        return E, ("names_listed_via_dirfd_only" if case == "recorder_owned_no_agent_access"
                   else "names_listed_via_path_and_dirfd")
    if kind == "file_append":
        if "immutable" in flags:
            return N, None
        if control == "fd_append_write":
            return E, "appended_marker"
        if control == "fd_append_pwrite_overwrite":
            return X, "appended_only"
        return (D, "no_change") if "append_only" in flags else (E, DESCRIPTOR_CONTROLS[control][1])
    if kind == "file_wronly":
        return (N, None) if flags else (E, DESCRIPTOR_CONTROLS[control][1])
    verdict = expected_verdict(case, "delete" if control == "dirfd_unlinkat" else "rename_within_dir",
                               protected_hardlinks)
    return verdict, (DESCRIPTOR_CONTROLS[control][1] if verdict == E else "no_change")


def identity_for(case, role):
    """(uid, gid, supplementary groups) of the acting child for a role in a layout."""
    layout = CASES[case]
    if role == "agent" or layout["recorder_account"] == "shared_with_agent":
        return AGENT_UID, AGENT_GID, sorted(layout["agent_groups"])
    return RECORDER_UID, RECORDER_GID, []


CHILD = r'''
import fcntl, hashlib, json, os, struct, subprocess, sys
request = json.loads(sys.argv[1])
os.umask(0o022)
status = {}
with open('/proc/self/status') as handle:
    for line in handle:
        key, _, value = line.partition(':')
        if key in ('CapInh', 'CapPrm', 'CapEff', 'CapBnd', 'CapAmb', 'NoNewPrivs', 'Seccomp'):
            status[key] = value.strip()
inherited = []
for name in sorted(os.listdir('/proc/self/fd'), key=int):
    try:
        target = os.readlink('/proc/self/fd/' + name)
    except OSError:
        continue
    if any(target == root or target.startswith(root + '/') for root in request['roots']):
        inherited.append({'fd': int(name), 'target': target,
                          'open_flags_octal': oct(fcntl.fcntl(int(name), fcntl.F_GETFL))})
identity = {'uid': list(os.getresuid()), 'gid': list(os.getresgid()), 'groups': sorted(os.getgroups()),
            'status': status, 'inherited_probe_fds': inherited}
result = {'identity': identity, 'operation': request['operation'], 'operation_succeeded': False,
          'errno': None, 'error': None, 'failed_step': None, 'completed_steps': [],
          'fixture_base_reachable': None}
try:
    os.stat(request['base'])
    result['fixture_base_reachable'] = True
except OSError as error:
    result['fixture_base_reachable'] = False
    result['fixture_base_errno'] = error.errno
target, records, parent, workspace = (request[key] for key in ('target', 'records', 'parent', 'workspace'))
name = os.path.basename(target)
payload = {key: value.encode('latin-1') for key, value in request['payloads'].items()}
current = [None]

def step(label):
    if current[0] is not None:
        result['completed_steps'].append(current[0])
    current[0] = label

def write_all(descriptor, data):
    while data:
        data = data[os.write(descriptor, data):]

def write_path(path, flags, data, mode=0o644):
    descriptor = os.open(path, flags, mode)
    try:
        if data is not None:
            write_all(descriptor, data)
    finally:
        os.close(descriptor)

def run_tests():
    return subprocess.run([sys.executable, '-I', '-B', '-m', 'unittest', 'discover', '-s', workspace,
                           '-p', 'test_*.py'], cwd=workspace, capture_output=True, text=True, timeout=20)

try:
    operation = request['operation']
    descriptor = request.get('fd')
    rewrite = os.O_WRONLY | os.O_TRUNC
    if operation == 'rewrite':
        step('open(O_WRONLY|O_TRUNC)+write'); write_path(target, rewrite, payload['EDIT'])
    elif operation == 'truncate':
        step('open(O_WRONLY|O_TRUNC)'); write_path(target, rewrite, None)
    elif operation == 'overwrite_in_place':
        step('open(O_WRONLY)'); handle = os.open(target, os.O_WRONLY)
        try:
            step('pwrite(offset 0)'); os.pwrite(handle, payload['PATCH'], 0)
        finally:
            os.close(handle)
    elif operation == 'append_marker':
        step('open(O_WRONLY|O_APPEND)+write'); write_path(target, os.O_WRONLY | os.O_APPEND, payload['APPEND'])
    elif operation == 'delete':
        step('unlink'); os.unlink(target)
    elif operation == 'replace':
        replacement = os.path.join(workspace, 'replacement.jsonl')
        step('create workspace replacement')
        write_path(replacement, os.O_WRONLY | os.O_CREAT | os.O_EXCL, payload['EDIT'])
        step('rename(replacement, transcript)'); os.rename(replacement, target)
    elif operation == 'chmod_then_rewrite':
        step('chmod(0666)'); os.chmod(target, 0o666)
        step('open(O_WRONLY|O_TRUNC)+write'); write_path(target, rewrite, payload['EDIT'])
    elif operation == 'chown_to_agent':
        step('chown(agent uid, agent gid)'); os.chown(target, os.getuid(), os.getgid())
    elif operation == 'rename_within_dir':
        step('rename(transcript, records/moved.jsonl)'); os.rename(target, os.path.join(records, 'moved.jsonl'))
    elif operation == 'rename_out_of_dir':
        step('rename(transcript, workspace/moved.jsonl)'); os.rename(target, os.path.join(workspace, 'moved.jsonl'))
    elif operation == 'rename_parent_dir':
        step('rename(records, home/records-moved)'); os.rename(records, os.path.join(parent, 'records-moved'))
    elif operation == 'hardlink_create':
        step('link(transcript, workspace/hardlink.jsonl)'); os.link(target, os.path.join(workspace, 'hardlink.jsonl'))
    elif operation == 'symlink_swap_file':
        attacker = os.path.join(workspace, 'attacker.jsonl')
        link = os.path.join(workspace, 'swap-link')
        step('create workspace attacker file')
        write_path(attacker, os.O_WRONLY | os.O_CREAT | os.O_EXCL, payload['ATTACKER'])
        step('symlink(attacker, workspace/swap-link)'); os.symlink(attacker, link)
        step('rename(swap-link, transcript)'); os.rename(link, target)
    elif operation == 'symlink_swap_dir':
        attacker = os.path.join(workspace, 'attacker-records')
        step('create workspace attacker directory'); os.mkdir(attacker, 0o755)
        write_path(os.path.join(attacker, name), os.O_WRONLY | os.O_CREAT | os.O_EXCL, payload['ATTACKER'])
        step('rename(records, home/records-moved)'); os.rename(records, os.path.join(parent, 'records-moved'))
        step('symlink(attacker-records, records)'); os.symlink(attacker, records)
    elif operation == 'create_sibling':
        step('open(records/sibling.jsonl, O_CREAT|O_EXCL)+write')
        write_path(os.path.join(records, 'sibling.jsonl'), os.O_WRONLY | os.O_CREAT | os.O_EXCL, payload['SIBLING'])
    elif operation == 'clear_inode_flags_then_rewrite':
        step('open(O_RDONLY)'); handle = os.open(target, os.O_RDONLY)
        try:
            step('ioctl(FS_IOC_GETFLAGS)')
            flags = struct.unpack('i', fcntl.ioctl(handle, 0x80086601, bytes(8))[:4])[0]
            result['inode_flags_seen'] = flags
            step('ioctl(FS_IOC_SETFLAGS) clearing append-only and immutable')
            fcntl.ioctl(handle, 0x40086602, struct.pack('i', flags & ~0x30) + bytes(4))
        finally:
            os.close(handle)
        step('open(O_WRONLY|O_TRUNC)+write'); write_path(target, rewrite, payload['EDIT'])
    elif operation == 'agent_workspace_edit_and_test':
        module = os.path.join(workspace, 'calc.py')
        step('create workspace module and test')
        write_path(module, os.O_WRONLY | os.O_CREAT | os.O_EXCL, b'def add(a, b):\n    return a - b\n')
        write_path(os.path.join(workspace, 'test_calc.py'), os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                   b'import unittest\nimport calc\n\n\nclass CalcTest(unittest.TestCase):\n'
                   b'    def test_add(self):\n        self.assertEqual(calc.add(2, 2), 4)\n')
        step('run failing test'); first = run_tests()
        step('edit workspace module'); write_path(module, rewrite, b'def add(a, b):\n    return a + b\n')
        step('run passing test'); second = run_tests()
        result['test_exit_codes'] = [first.returncode, second.returncode]
        result['second_test_stderr_tail'] = second.stderr[-300:]
        if first.returncode == 0 or second.returncode != 0:
            raise RuntimeError('workspace test did not go from failing to passing')
    elif operation == 'recorder_append':
        step('open(O_WRONLY|O_APPEND)+write'); write_path(target, os.O_WRONLY | os.O_APPEND, payload['TRUSTED'])
    elif operation == 'recorder_new_transcript':
        step('open(records/new-session.jsonl, O_CREAT|O_EXCL|O_APPEND)+write')
        write_path(os.path.join(records, 'new-session.jsonl'),
                   os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_APPEND, payload['NEW_SESSION'])
    elif operation in ('recorder_read_back', 'agent_read_transcript'):
        step('open(O_RDONLY)+read'); handle = os.open(target, os.O_RDONLY)
        try:
            data = b''
            while True:
                chunk = os.read(handle, 65536)
                if not chunk:
                    break
                data += chunk
        finally:
            os.close(handle)
        result['read_size'] = len(data)
        result['read_sha256'] = hashlib.sha256(data).hexdigest()
    elif operation == 'fd_append_write':
        step('write(inherited fd)'); write_all(descriptor, payload['APPEND'])
    elif operation in ('fd_append_pwrite_overwrite', 'fd_wronly_pwrite_overwrite'):
        step('pwrite(inherited fd, offset 0)'); os.pwrite(descriptor, payload['PATCH'], 0)
    elif operation in ('fd_append_ftruncate', 'fd_wronly_ftruncate'):
        step('ftruncate(inherited fd, 0)'); os.ftruncate(descriptor, 0)
    elif operation == 'fd_append_clear_flag_then_pwrite':
        step('fcntl(F_SETFL) clearing O_APPEND')
        fcntl.fcntl(descriptor, fcntl.F_SETFL, fcntl.fcntl(descriptor, fcntl.F_GETFL) & ~os.O_APPEND)
        result['open_flags_after_setfl_octal'] = oct(fcntl.fcntl(descriptor, fcntl.F_GETFL))
        step('pwrite(inherited fd, offset 0)'); os.pwrite(descriptor, payload['PATCH'], 0)
    elif operation == 'dirfd_unlinkat':
        step('unlinkat(inherited dirfd, transcript)'); os.unlink(name, dir_fd=descriptor)
    elif operation == 'dirfd_renameat':
        step('renameat(inherited dirfd, transcript, inherited dirfd, moved.jsonl)')
        os.rename(name, 'moved.jsonl', src_dir_fd=descriptor, dst_dir_fd=descriptor)
    elif operation == 'dirfd_listdir':
        try:
            result['path_listdir'] = {'ok': True, 'names': sorted(os.listdir(records))}
        except OSError as error:
            result['path_listdir'] = {'ok': False, 'errno': error.errno}
        step('listdir(inherited dirfd)'); result['dirfd_names'] = sorted(os.listdir(descriptor))
    elif operation == 'precreate_next_session':
        step('open(records/next-session.jsonl, O_CREAT|O_EXCL)+write')
        write_path(request['next_session'], os.O_WRONLY | os.O_CREAT | os.O_EXCL, payload['ATTACKER'])
    elif operation == 'recorder_create_next_session_excl':
        step('open(records/next-session.jsonl, O_CREAT|O_EXCL|O_APPEND)+write')
        write_path(request['next_session'], os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_APPEND,
                   payload['NEW_SESSION'])
    elif operation == 'recorder_open_next_session_no_excl':
        step('open(records/next-session.jsonl, O_CREAT|O_APPEND)+write')
        write_path(request['next_session'], os.O_WRONLY | os.O_CREAT | os.O_APPEND, payload['NEW_SESSION'])
    elif operation == 'agent_rewrite_next_session':
        step('open(records/next-session.jsonl, O_WRONLY|O_TRUNC)+write')
        write_path(request['next_session'], rewrite, payload['EDIT'])
    elif operation == 'fill_filesystem':
        result['fill'] = []
        block = bytes(request['fill_chunk'])
        for sink in request['fill_sinks']:
            entry = {'path': sink, 'bytes_written': 0, 'errno': None, 'stopped': None}
            result['fill'].append(entry)
            try:
                handle = os.open(sink, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
            except OSError as error:
                entry.update(errno=error.errno, stopped='open failed')
                continue
            try:
                while entry['bytes_written'] < request['fill_sink_cap']:
                    entry['bytes_written'] += os.write(handle, block)
                entry['stopped'] = 'safety cap reached'
            except OSError as error:
                entry.update(errno=error.errno, stopped='write failed')
            finally:
                os.close(handle)
        step('fill sinks until ENOSPC')
        if not any(entry['errno'] == 28 for entry in result['fill']):
            raise RuntimeError('no sink reached ENOSPC')
    elif operation == 'recorder_append_many':
        result.update(complete_records=0, torn_bytes=0, exhausted=False, append_errno=None)
        record = payload['TRUSTED']
        try:
            step('open(O_WRONLY|O_APPEND)'); handle = os.open(target, os.O_WRONLY | os.O_APPEND)
        except OSError:
            raise
        try:
            step('append one record per write(2) call until all written or the filesystem is full')
            for _ in range(request['append_many_count']):
                try:
                    written = os.write(handle, record)
                except OSError as error:
                    result.update(exhausted=True, append_errno=error.errno)
                    break
                if written != len(record):
                    result.update(torn_bytes=written, exhausted=True)
                    break
                result['complete_records'] += 1
        finally:
            os.close(handle)
    else:
        raise RuntimeError('Unknown operation')
    step(None)
    result['operation_succeeded'] = True
except OSError as error:
    result.update(errno=error.errno, error=type(error).__name__ + ': ' + os.strerror(error.errno or 0),
                  failed_step=current[0])
except Exception as error:
    result.update(error=type(error).__name__ + ': ' + str(error), failed_step=current[0])
print(json.dumps(result))
'''

PAYLOADS = {"EDIT": EDIT, "APPEND": APPEND, "TRUSTED": TRUSTED, "PATCH": PATCH, "ATTACKER": ATTACKER,
            "SIBLING": SIBLING, "NEW_SESSION": NEW_SESSION}


def digest(data):
    return hashlib.sha256(data).hexdigest()


# ---------------------------------------------------------------- environment helpers

def proc_status(keys=("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb", "NoNewPrivs", "Seccomp")):
    values = {}
    with open("/proc/self/status") as handle:
        for line in handle:
            key, _, value = line.partition(":")
            if key in keys:
                values[key] = value.strip()
    return values


CAPABILITY_NAMES = (
    "CHOWN DAC_OVERRIDE DAC_READ_SEARCH FOWNER FSETID KILL SETGID SETUID SETPCAP LINUX_IMMUTABLE "
    "NET_BIND_SERVICE NET_BROADCAST NET_ADMIN NET_RAW IPC_LOCK IPC_OWNER SYS_MODULE SYS_RAWIO SYS_CHROOT "
    "SYS_PTRACE SYS_PACCT SYS_ADMIN SYS_BOOT SYS_NICE SYS_RESOURCE SYS_TIME SYS_TTY_CONFIG MKNOD LEASE "
    "AUDIT_WRITE AUDIT_CONTROL SETFCAP MAC_OVERRIDE MAC_ADMIN SYSLOG WAKE_ALARM BLOCK_SUSPEND AUDIT_READ "
    "PERFMON BPF CHECKPOINT_RESTORE").split()


def capability_names(mask_hex):
    mask = int(mask_hex, 16)
    return [CAPABILITY_NAMES[bit] if bit < len(CAPABILITY_NAMES) else "CAP_" + str(bit)
            for bit in range(64) if mask >> bit & 1]


def sysctl(name):
    try:
        return int(Path("/proc/sys/fs", name).read_text().strip())
    except (OSError, ValueError):
        return None


def filesystem_of(path):
    """Mount point, filesystem type and options for a path, from /proc/self/mountinfo."""
    path = os.path.realpath(path)
    best = None
    try:
        lines = Path("/proc/self/mountinfo").read_text().splitlines()
    except OSError as error:
        return {"error": str(error)}
    for line in lines:
        left, _, right = line.partition(" - ")
        fields, tail = left.split(), right.split()
        mount_point = fields[4].replace("\\040", " ")
        if path == mount_point or path.startswith(mount_point.rstrip("/") + "/"):
            if best is None or len(mount_point) >= len(best["mount_point"]):
                best = {"mount_point": mount_point, "fstype": tail[0], "mount_options": fields[5],
                        "super_options": tail[2] if len(tail) > 2 else ""}
    return best or {"error": "no mount found"}


def get_inode_flags(path):
    descriptor = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        return struct.unpack("i", fcntl.ioctl(descriptor, FS_IOC_GETFLAGS, bytes(8))[:4])[0]
    finally:
        os.close(descriptor)


def change_inode_flags(path, add=0, remove=0):
    descriptor = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        flags = struct.unpack("i", fcntl.ioctl(descriptor, FS_IOC_GETFLAGS, bytes(8))[:4])[0]
        fcntl.ioctl(descriptor, FS_IOC_SETFLAGS, struct.pack("i", (flags | add) & ~remove) + bytes(4))
    finally:
        os.close(descriptor)


def acl_blob(user_object, named_uid, named_permissions):
    """Binary system.posix_acl_access value: owner, one named user, empty group/other, mask."""
    entries = [(0x01, user_object, 0xFFFFFFFF), (0x02, named_permissions, named_uid),
               (0x04, 0, 0xFFFFFFFF), (0x10, named_permissions, 0xFFFFFFFF), (0x20, 0, 0xFFFFFFFF)]
    return struct.pack("<I", 2) + b"".join(struct.pack("<HHI", *entry) for entry in entries)


def _error(error):
    return {"supported": False, "errno": error.errno,
            "error": errno.errorcode.get(error.errno, str(error.errno)) + ": " + os.strerror(error.errno or 0)}


def detect_features(root):
    """Try each optional feature on a scratch file in this root; never assume support."""
    scratch = Path(root) / ".feature-probe"
    scratch.write_bytes(b"x")
    features = {}
    for name, bit in FLAG_BITS.items():
        try:
            change_inode_flags(scratch, add=bit)
            features[name + "_flag"] = {"supported": bool(get_inode_flags(scratch) & bit)}
            if not features[name + "_flag"]["supported"]:
                features[name + "_flag"]["error"] = "flag did not read back after FS_IOC_SETFLAGS"
            change_inode_flags(scratch, remove=bit)
        except OSError as error:
            features[name + "_flag"] = _error(error)
    try:
        blob = acl_blob(6, AGENT_UID, 4)
        os.setxattr(scratch, ACL_XATTR, blob)
        features["posix_acl"] = {"supported": os.getxattr(scratch, ACL_XATTR) == blob}
        if not features["posix_acl"]["supported"]:
            features["posix_acl"]["error"] = "ACL xattr did not read back"
    except OSError as error:
        features["posix_acl"] = _error(error)
    try:
        change_inode_flags(scratch, remove=FS_APPEND_FL | FS_IMMUTABLE_FL)
    except OSError:
        pass
    scratch.unlink()
    return features


def required_features(case):
    layout = CASES[case]
    needed = [name + "_flag" for name in layout["file_flags"] + layout["dir_flags"]]
    if layout["dir_acl"] or layout["file_acl"]:
        needed.append("posix_acl")
    return sorted(set(needed))


def choose_root(case, roots):
    """roots: list of {'path', 'features'}. Returns (root or None, reason when None)."""
    needed = required_features(case)
    reasons = []
    for root in roots:
        missing = [name for name in needed if not root["features"][name]["supported"]]
        if not missing:
            return root, None
        reasons.append("%s (%s): %s" % (root["path"], root["filesystem"].get("fstype"), "; ".join(
            name + " unavailable: " + str(root["features"][name].get("error")) for name in missing)))
    return None, "required filesystem feature unavailable on every probe root -- " + " | ".join(reasons)


def clear_flags_recursive(root):
    """Remove append-only/immutable flags below root so the tree can be deleted."""
    for directory, names, files in os.walk(root, topdown=True, followlinks=False):
        for name in [""] + names + files:
            path = os.path.join(directory, name) if name else directory
            try:
                if not stat.S_ISLNK(os.lstat(path).st_mode) and get_inode_flags(path) & (FS_APPEND_FL | FS_IMMUTABLE_FL):
                    change_inode_flags(path, remove=FS_APPEND_FL | FS_IMMUTABLE_FL)
            except OSError:
                pass


def empty_directory(root):
    clear_flags_recursive(root)
    for entry in os.scandir(root):
        if entry.is_dir(follow_symlinks=False):
            shutil.rmtree(entry.path)
        else:
            os.unlink(entry.path)


# ---------------------------------------------------------------- snapshots

def snapshot(path):
    """lstat-based snapshot of one path; never follows a final symlink."""
    path = str(path)
    try:
        metadata = os.lstat(path)
    except OSError as error:
        return {"exists": False, "errno": error.errno}
    kind = ("file" if stat.S_ISREG(metadata.st_mode) else "directory" if stat.S_ISDIR(metadata.st_mode)
            else "symlink" if stat.S_ISLNK(metadata.st_mode) else "other")
    record = {"exists": True, "type": kind, "uid": metadata.st_uid, "gid": metadata.st_gid,
              "mode": oct(stat.S_IMODE(metadata.st_mode)), "inode": metadata.st_ino,
              "link_count": metadata.st_nlink}
    if kind == "symlink":
        record["symlink_target"] = os.readlink(path)
        return record
    if kind == "file":
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
        with os.fdopen(descriptor, "rb") as handle:
            data = handle.read()
        record.update(size=len(data), sha256=digest(data))
    if kind in ("file", "directory"):
        try:
            flags = get_inode_flags(path)
            record["inode_flags"] = {"raw": flags, "append_only": bool(flags & FS_APPEND_FL),
                                     "immutable": bool(flags & FS_IMMUTABLE_FL)}
        except OSError as error:
            record["inode_flags"] = None
            record["inode_flags_errno"] = error.errno
        try:
            record["acl_access_hex"] = os.getxattr(path, ACL_XATTR, follow_symlinks=False).hex()
        except OSError:
            record["acl_access_hex"] = None
    return record


def resolved_snapshot(path):
    """What reading the path yields when symlinks are followed (as a naive reader would)."""
    try:
        metadata = os.stat(path)
        with open(path, "rb") as handle:
            data = handle.read()
    except OSError as error:
        return {"resolves": False, "errno": error.errno}
    return {"resolves": True, "realpath": os.path.realpath(path), "uid": metadata.st_uid,
            "inode": metadata.st_ino, "size": len(data), "sha256": digest(data)}


def listing(path):
    try:
        if not stat.S_ISDIR(os.lstat(path).st_mode):
            return {"is_directory": False}
        entries = {}
        for name in sorted(os.listdir(path)):
            metadata = os.lstat(os.path.join(path, name))
            entries[name] = {"type": ("file" if stat.S_ISREG(metadata.st_mode) else "directory"
                                      if stat.S_ISDIR(metadata.st_mode) else "symlink"
                                      if stat.S_ISLNK(metadata.st_mode) else "other"),
                             "inode": metadata.st_ino, "uid": metadata.st_uid, "size": metadata.st_size}
        return {"is_directory": True, "entries": entries}
    except OSError as error:
        return {"is_directory": False, "errno": error.errno}


def inode_paths(base, device, inode):
    """Every name below base (symlinks not followed) that refers to the given inode."""
    found = []
    for directory, names, files in os.walk(base, followlinks=False):
        for name in names + files:
            path = os.path.join(directory, name)
            try:
                metadata = os.lstat(path)
            except OSError:
                continue
            if metadata.st_ino == inode and metadata.st_dev == device:
                found.append(os.path.relpath(path, base))
    return sorted(found)


def ancestors(path):
    """Metadata of every directory from / down to path."""
    records, current = [], Path(path)
    for item in [current] + list(current.parents):
        metadata = os.lstat(item)
        records.append({"path": str(item), "uid": metadata.st_uid, "gid": metadata.st_gid,
                        "mode": oct(stat.S_IMODE(metadata.st_mode))})
    return records[::-1]


def state(fixture):
    return {"target": snapshot(fixture["target"]), "target_resolved": resolved_snapshot(fixture["target"]),
            "records_dir": snapshot(fixture["records"]), "records_listing": listing(fixture["records"]),
            "parent_listing": listing(fixture["parent"]), "workspace_listing": listing(fixture["workspace"]),
            "original_inode_paths": inode_paths(fixture["base"], fixture["device"], fixture["inode"])}


PROTECTED_STATE_KEYS = ("target", "records_dir", "records_listing", "parent_listing", "original_inode_paths")


def protected_state_unchanged(before, after):
    return all(before[key] == after[key] for key in PROTECTED_STATE_KEYS)


# ---------------------------------------------------------------- fixture setup

def expected_mode(spec, acl):
    """Mode bits as lstat reports them; with an access ACL the group bits show the ACL mask."""
    return (spec[2] & ~0o070) | (acl[1] << 3) if acl else spec[2]


class FixtureSetupError(RuntimeError):
    """The environment refused a step needed to build a layout (the cell is then recorded as not_run)."""


def setup_fixture(root, name, case, workspace_root=None):
    """Build one fresh fixture. chmod/ACL are applied while UID 0 owns the inode, then chown, then flags.

    workspace_root: put the agent workspace on another filesystem (the separate-fs fill variant); default
    is next to the records tree.
    """
    try:
        return _setup_fixture(root, name, case, workspace_root)
    except OSError as error:
        raise FixtureSetupError("fixture setup failed for layout %s: %s: %s" % (
            case, errno.errorcode.get(error.errno, error.errno), os.strerror(error.errno or 0))) from error


def _setup_fixture(root, name, case, workspace_root=None):
    layout = CASES[case]
    base = Path(root) / name
    workspace_base = base if workspace_root is None else Path(workspace_root) / name
    parent, workspace = base / "home", workspace_base / "workspace"
    records = parent / "records"
    target = records / TARGET_NAME
    for directory in dict.fromkeys((base, workspace_base, parent, records, workspace)):
        os.mkdir(directory, 0o755)
        os.chmod(directory, 0o755)
    descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(BASE)
    for path, spec, acl in ((target, layout["file"], layout["file_acl"]),
                            (records, layout["directory"], layout["dir_acl"]),
                            (parent, layout["parent"], None)):
        os.chmod(path, spec[2])
        if acl:
            os.setxattr(path, ACL_XATTR, acl_blob(spec[2] >> 6 & 7, acl[0], acl[1]))
        os.chown(path, spec[0], spec[1])
    os.chown(workspace, AGENT_UID, AGENT_GID)
    for path, flags in ((target, layout["file_flags"]), (records, layout["dir_flags"])):
        for flag in flags:
            change_inode_flags(path, add=FLAG_BITS[flag])
    metadata = os.lstat(target)
    fixture = {"base": str(base), "parent": str(parent), "records": str(records), "target": str(target),
               "workspace": str(workspace), "workspace_base": str(workspace_base),
               "device": metadata.st_dev, "inode": metadata.st_ino}
    verify_fixture(fixture, case)
    return fixture


def verify_fixture(fixture, case):
    """Independent lstat check that the fixture really has the layout under test."""
    layout = CASES[case]
    checks = (("target", layout["file"], layout["file_acl"], layout["file_flags"]),
              ("records", layout["directory"], layout["dir_acl"], layout["dir_flags"]),
              ("parent", layout["parent"], None, []), ("workspace", (AGENT_UID, AGENT_GID, 0o755), None, []),
              ("base", (0, 0, 0o755), None, []))
    for key, spec, acl, flags in checks:
        metadata = os.lstat(fixture[key])
        actual = (metadata.st_uid, metadata.st_gid, stat.S_IMODE(metadata.st_mode))
        wanted = (spec[0], spec[1], expected_mode(spec, acl))
        if actual != wanted:
            raise RuntimeError("Fixture %s for %s is %r, expected %r" % (key, case, actual, wanted))
        if key in ("target", "records"):
            present = {name for name, bit in FLAG_BITS.items() if _flags_or_zero(fixture[key]) & bit}
            if present != set(flags):
                raise RuntimeError("Fixture %s for %s has inode flags %r, expected %r"
                                   % (key, case, sorted(present), sorted(flags)))
            if acl and os.getxattr(fixture[key], ACL_XATTR) != acl_blob(spec[2] >> 6 & 7, acl[0], acl[1]):
                raise RuntimeError("Fixture %s for %s lacks the expected ACL" % (key, case))
    if Path(fixture["target"]).read_bytes() != BASE:
        raise RuntimeError("Fixture transcript content is wrong for " + case)


def _flags_or_zero(path):
    try:
        return get_inode_flags(path)
    except OSError:
        return 0


# ---------------------------------------------------------------- dropped-privilege children

def set_no_new_privs():
    if _LIBC is not None:
        _LIBC.prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)


def drop_identity(uid, gid, groups):
    """Irreversibly become an unprivileged account (called after fork, before exec or helper work)."""
    set_no_new_privs()
    os.setgroups(list(groups))
    os.setresgid(gid, gid, gid)
    os.setresuid(uid, uid, uid)
    if _LIBC is not None:  # the UID change clears any pending death signal, so set it afterwards
        _LIBC.prctl(PR_SET_PDEATHSIG, 9, 0, 0, 0)


def run_child(identity, operation, fixture, roots, descriptor=None, extra=None):
    uid, gid, groups = identity
    request = {"operation": operation, "roots": list(roots),
               "payloads": {key: value.decode("latin-1") for key, value in PAYLOADS.items()}}
    request.update({key: fixture[key] for key in ("base", "parent", "records", "target", "workspace")})
    request.update(extra or {})
    if descriptor is not None:
        request["fd"] = descriptor
    completed = subprocess.run(
        [sys.executable, "-I", "-c", CHILD, json.dumps(request)],
        preexec_fn=lambda: drop_identity(uid, gid, groups), close_fds=True,
        pass_fds=() if descriptor is None else (descriptor,), stdin=subprocess.DEVNULL,
        capture_output=True, text=True, timeout=60, cwd="/",
        env={"PATH": "/usr/local/bin:/usr/bin:/bin", "LC_ALL": "C"})
    if completed.returncode != 0:
        raise RuntimeError("Probe subprocess failed: " + completed.stderr[-2000:])
    return json.loads(completed.stdout)


def open_as(identity, path, flags):
    """Open path in a helper process dropped to `identity` and receive the descriptor over SCM_RIGHTS.

    Returns (descriptor or None, helper report). The open is permission-checked as that identity.
    """
    uid, gid, groups = identity
    ours, theirs = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    sys.stdout.flush()
    sys.stderr.flush()
    pid = os.fork()
    if pid == 0:
        code = 1
        try:
            ours.close()
            drop_identity(uid, gid, groups)
            report = {"uid": list(os.getresuid()), "gid": list(os.getresgid()),
                      "groups": sorted(os.getgroups()), "status": proc_status(), "errno": None, "error": None}
            try:
                descriptor = os.open(path, flags | os.O_CLOEXEC)
            except OSError as error:
                report.update(errno=error.errno, error=type(error).__name__ + ": " + os.strerror(error.errno))
                theirs.sendall(json.dumps(report).encode())
            else:
                socket.send_fds(theirs, [json.dumps(report).encode()], [descriptor])
            code = 0
        finally:
            os._exit(code)
    theirs.close()
    try:
        message, descriptors, _, _ = socket.recv_fds(ours, 65536, 1)
    finally:
        ours.close()
        _, wait_status = os.waitpid(pid, 0)
    if wait_status != 0 or not message:
        for descriptor in descriptors:
            os.close(descriptor)
        raise RuntimeError("Descriptor helper failed")
    return (descriptors[0] if descriptors else None), json.loads(message)


def capabilities_clear(status):
    try:
        return all(int(status[key], 16) == 0 for key in ("CapEff", "CapPrm", "CapAmb"))
    except (KeyError, ValueError, TypeError):
        return False


def identity_valid(result, identity, descriptors_expected=0):
    """The child must be exactly the intended unprivileged account, with no stray probe descriptors."""
    uid, gid, groups = identity
    seen = result.get("identity", {})
    status = seen.get("status", {})
    return (uid != 0 and seen.get("uid") == [uid] * 3 and seen.get("gid") == [gid] * 3
            and seen.get("groups") == sorted(groups) and status.get("NoNewPrivs") == "1"
            and capabilities_clear(status)
            and len(seen.get("inherited_probe_fds", [None])) == descriptors_expected)


def helper_valid(report, identity):
    uid, gid, groups = identity
    status = report.get("status", {})
    return (uid != 0 and report.get("uid") == [uid] * 3 and report.get("gid") == [gid] * 3
            and report.get("groups") == sorted(groups) and status.get("NoNewPrivs") == "1"
            and capabilities_clear(status))


# ---------------------------------------------------------------- classification

def effect_observed(operation, before, after):
    """Does the independent snapshot pair show the operation's defined effect?"""
    old, new = before["target"], after["target"]
    names = after["original_inode_paths"]
    here = "home/records/" + TARGET_NAME
    same_file = bool(new.get("exists")) and new.get("type") == "file" and new.get("inode") == old.get("inode")
    content = new.get("sha256")
    if operation in ("rewrite", "chmod_then_rewrite"):
        return same_file and content == digest(EDIT)
    if operation == "clear_inode_flags_then_rewrite":
        flags = new.get("inode_flags") or {}
        return (same_file and content == digest(EDIT) and flags.get("append_only") is False
                and flags.get("immutable") is False)
    if operation == "truncate":
        return same_file and new.get("size") == 0
    if operation == "overwrite_in_place":
        return same_file and content == digest(PATCHED)
    if operation == "append_marker":
        return same_file and content == digest(BASE + APPEND)
    if operation == "chown_to_agent":
        return (same_file and (new["uid"], new["gid"]) == (AGENT_UID, AGENT_GID)
                and (old["uid"], old["gid"]) != (AGENT_UID, AGENT_GID))
    if operation == "delete":
        return old.get("exists") is True and new.get("exists") is False and names == []
    if operation == "replace":
        return (bool(new.get("exists")) and new.get("type") == "file" and new["inode"] != old["inode"]
                and content == digest(EDIT) and new["uid"] == AGENT_UID)
    if operation == "rename_within_dir":
        return new.get("exists") is False and names == ["home/records/moved.jsonl"]
    if operation == "rename_out_of_dir":
        return new.get("exists") is False and names == ["workspace/moved.jsonl"]
    if operation == "rename_parent_dir":
        return (after["records_dir"].get("exists") is False and new.get("exists") is False
                and names == ["home/records-moved/" + TARGET_NAME])
    if operation == "hardlink_create":
        return (same_file and content == old.get("sha256") and new["link_count"] == old["link_count"] + 1
                and names == sorted([here, "workspace/hardlink.jsonl"]))
    if operation == "symlink_swap_file":
        return new.get("type") == "symlink" and after["target_resolved"].get("sha256") == digest(ATTACKER)
    if operation == "symlink_swap_dir":
        return (after["records_dir"].get("type") == "symlink"
                and after["target_resolved"].get("sha256") == digest(ATTACKER)
                and names == ["home/records-moved/" + TARGET_NAME])
    if operation == "create_sibling":
        sibling = after["records_listing"].get("entries", {}).get("sibling.jsonl")
        return (new == old and names == before["original_inode_paths"] and sibling is not None
                and sibling["type"] == "file" and sibling["uid"] == AGENT_UID and sibling["size"] == len(SIBLING))
    raise ValueError("Unknown operation: " + operation)


def descriptor_outcome(before, after):
    """Name what an inherited-descriptor action did to the transcript."""
    old, new = before["target"], after["target"]
    names = after["original_inode_paths"]
    if protected_state_unchanged(before, after):
        return "no_change"
    if new.get("exists") is False:
        if names == []:
            return "path_removed"
        if names == ["home/records/moved.jsonl"]:
            return "path_moved_inode_preserved"
        return "other_change"
    if new.get("type") != "file" or new.get("inode") != old.get("inode"):
        return "other_change"
    return {digest(BASE + APPEND): "appended_marker", digest(BASE + PATCH): "appended_only",
            digest(PATCHED): "earlier_bytes_modified", digest(b""): "truncated"}.get(new.get("sha256"), "other_change")


def listdir_outcome(child, state_outcome):
    """Outcome of dirfd_listdir: did the inherited descriptor reveal names, and did the path also?"""
    if state_outcome != "no_change":
        return "other_change"
    if child.get("operation_succeeded") is not True or TARGET_NAME not in child.get("dirfd_names", []):
        return "no_change"
    path = child.get("path_listdir", {})
    if path.get("ok") is True and TARGET_NAME in path.get("names", []):
        return "names_listed_via_path_and_dirfd"
    if path.get("ok") is False and path.get("errno") in DENIAL_ERRNOS:
        return "names_listed_via_dirfd_only"
    return "other_change"


def denial_fields(verdict, child):
    """Which step failed and which kernel check refused, so denials can be told apart per row."""
    if verdict != D:
        return {"failed_step": child.get("failed_step"), "denial_errno": None, "denial_class": None}
    name = errno.errorcode.get(child.get("errno"))
    return {"failed_step": child.get("failed_step"), "denial_errno": name,
            "denial_class": DENIAL_CLASSES.get(name)}


def classify(valid, child, effect, unchanged):
    """Return (verdict, reason). A denial needs a permission errno AND unchanged protected state."""
    if not valid:
        return UNEXPECTED, "child identity or inherited-descriptor state is not the intended one"
    if child.get("fixture_base_reachable") is not True:
        return UNEXPECTED, "fixture base was not reachable by the child; the layout under test was not reached"
    succeeded = child.get("operation_succeeded") is True
    if effect:
        if succeeded:
            return E, "defined effect present in the independent snapshot"
        return UNEXPECTED, "defined effect present although the child reported an error"
    if not succeeded and child.get("errno") in DENIAL_ERRNOS and unchanged:
        return D, "child got %s at step '%s'; protected state identical" % (
            errno.errorcode[child["errno"]], child.get("failed_step"))
    if succeeded and not unchanged:
        return X, "child reported success; state changed but not as the effect is defined"
    if succeeded:
        return UNEXPECTED, "child reported success but no change is visible"
    if not unchanged:
        return UNEXPECTED, "child reported an error and the protected state changed (partial effect)"
    return UNEXPECTED, "child failed with a non-permission error: " + str(child.get("error"))


# ---------------------------------------------------------------- measurements

def _fixture_record(fixture, root):
    return {"root": root["path"], "base": fixture["base"], "filesystem": root["filesystem"]}


def _not_run_row(case, key, name, reason, expected, whole_case):
    return {"case": case, key: name, "verdict": N, "not_run_reason": reason, "expected": expected,
            "matches_expectation": None if whole_case else expected == N}


def _suppression_not_run(case, operation, reason, expected, whole_case):
    return {"case": case, "operation": operation, "category": "suppression_of_future_records", "verdict": N,
            "not_run_reason": reason, "expected": expected["verdict"],
            "matches_expectation": None if whole_case else expected["verdict"] == N}


def measure_operation(root, all_roots, case, operation, expected):
    fixture = setup_fixture(root["path"], case + "--" + operation, case)
    identity = identity_for(case, "agent")
    before = state(fixture)
    chain = ancestors(fixture["records"])
    child = run_child(identity, operation, fixture, all_roots)
    after = state(fixture)
    effect = bool(effect_observed(operation, before, after))
    unchanged = protected_state_unchanged(before, after)
    verdict, reason = classify(identity_valid(child, identity), child, effect, unchanged)
    return {"case": case, "operation": operation, "effect_category": OPERATIONS[operation][0],
            "counts_as_tampering": OPERATIONS[operation][1], "fixture": _fixture_record(fixture, root),
            "acting_role": "agent", "intended_identity": {"uid": identity[0], "gid": identity[1],
                                                           "groups": identity[2]},
            "before": before, "after": after, "ancestors": chain, "child": child,
            "defined_effect_present": effect, "protected_state_unchanged": unchanged,
            "verdict": verdict, "verdict_reason": reason, **denial_fields(verdict, child),
            "expected": expected, "matches_expectation": verdict == expected}


def measure_legit(root, all_roots, case, control):
    role, judged, _ = LEGIT_CONTROLS[control]
    fixture = setup_fixture(root["path"], case + "--legit-" + control, case)
    identity = identity_for(case, role)
    before = state(fixture)
    child = run_child(identity, control, fixture, all_roots)
    after = state(fixture)
    valid = identity_valid(child, identity) and child.get("fixture_base_reachable") is True
    succeeded = valid and child.get("operation_succeeded") is True
    new, old = after["target"], before["target"]
    if control == "agent_workspace_edit_and_test":
        entries = after["workspace_listing"].get("entries", {})
        passed = (succeeded and child.get("test_exit_codes", [0, 1])[1] == 0
                  and child["test_exit_codes"][0] != 0 and protected_state_unchanged(before, after)
                  and all(entries.get(name, {}).get("uid") == AGENT_UID for name in ("calc.py", "test_calc.py")))
    elif control == "recorder_append":
        passed = (succeeded and new.get("inode") == old["inode"] and new.get("sha256") == digest(BASE + TRUSTED))
    elif control == "recorder_new_transcript":
        created = snapshot(os.path.join(fixture["records"], "new-session.jsonl"))
        passed = (succeeded and new == old and created.get("type") == "file"
                  and created.get("uid") == identity[0] and created.get("sha256") == digest(NEW_SESSION))
    else:
        passed = (succeeded and child.get("read_sha256") == digest(BASE)
                  and protected_state_unchanged(before, after))
    denied = (valid and child.get("operation_succeeded") is False and child.get("errno") in DENIAL_ERRNOS
              and protected_state_unchanged(before, after))
    outcome = "passed" if passed else "permission_denied" if denied else UNEXPECTED
    discriminating, why = legit_discriminating(case, control)
    row = {"case": case, "control": control, "acting_role": role, "judged": judged,
           "layout_discriminating": discriminating, "discriminating_note": why,
           "recorder_account": CASES[case]["recorder_account"],
           "intended_identity": {"uid": identity[0], "gid": identity[1], "groups": identity[2]},
           "fixture": _fixture_record(fixture, root), "ancestors": ancestors(fixture["records"]),
           "before": before, "after": after, "child": child, "identity_valid": valid, "outcome": outcome}
    if judged:
        expected_pass = (case, control) not in LEGIT_EXPECTED_FAILURES
        row.update(passed=passed, expected_pass=expected_pass, matches_expectation=passed == expected_pass
                   and outcome != UNEXPECTED)
    else:
        observed = {"passed": "readable", "permission_denied": "denied"}.get(outcome, UNEXPECTED)
        expected = "denied" if case in AGENT_READ_EXPECTED_DENIED else "readable"
        row.update(observed=observed, expected_observation=expected, matches_expectation=observed == expected)
    return row


def measure_descriptor(root, all_roots, case, control, expected):
    kind, defined = DESCRIPTOR_CONTROLS[control]
    flag_text, flags = DESCRIPTOR_OPEN_FLAGS[kind]
    fixture = setup_fixture(root["path"], case + "--inherited-" + control, case)
    opener, agent = identity_for(case, "recorder"), identity_for(case, "agent")
    before = state(fixture)
    path = fixture["records"] if kind == "directory" else fixture["target"]
    descriptor, helper = open_as(opener, path, flags)
    row = {"case": case, "control": control, "layout_description": CASES[case]["description"],
           "fixture": _fixture_record(fixture, root), "ancestors": ancestors(fixture["records"]),
           "descriptor": {"kind": kind, "path": path, "open_flags": flag_text,
                          "opened_by_role": "recorder", "recorder_account": CASES[case]["recorder_account"],
                          "opened_by": helper, "obtained": descriptor is not None},
           "defined_effect_outcome": defined, "expected": expected[0], "expected_outcome": expected[1]}
    if descriptor is None:
        ok = helper_valid(helper, opener) and helper.get("errno") in DENIAL_ERRNOS
        row.update(verdict=N if ok else UNEXPECTED, outcome=None,
                   not_run_reason="the recorder identity could not open the descriptor (%s): %s"
                                  % (flag_text, helper.get("error")), before=before, after=state(fixture))
        row["matches_expectation"] = row["verdict"] == expected[0]
        return row
    try:
        child = run_child(agent, control, fixture, all_roots, descriptor)
    finally:
        os.close(descriptor)
    after = state(fixture)
    valid = identity_valid(child, agent, descriptors_expected=1) and helper_valid(helper, opener)
    if control == "dirfd_listdir":
        outcome = listdir_outcome(child, descriptor_outcome(before, after))
        verdict, reason = classify(valid, child, outcome.startswith("names_listed"), outcome == "no_change")
    else:
        outcome = descriptor_outcome(before, after)
        verdict, reason = classify(valid, child, outcome == defined, outcome == "no_change")
    row.update(before=before, after=after, child=child, outcome=outcome, verdict=verdict,
               verdict_reason=reason, **denial_fields(verdict, child),
               matches_expectation=verdict == expected[0] and (expected[1] is None or outcome == expected[1]))
    return row


def _stage(name, role, case, operation, fixture, all_roots, extra):
    identity = identity_for(case, role)
    child = run_child(identity, operation, fixture, all_roots, extra=extra)
    valid = identity_valid(child, identity) and child.get("fixture_base_reachable") is True
    result = ("invalid" if not valid else "ok" if child.get("operation_succeeded") is True
              else errno.errorcode.get(child.get("errno"), "error"))
    return {"stage": name, "acting_role": role,
            "intended_identity": {"uid": identity[0], "gid": identity[1], "groups": identity[2]},
            "child": child, "identity_valid": valid, "result": result}


def precreate_details(stages, recorder_uid):
    """Name what each stage did to records/next-session.jsonl, from the snapshot taken after each stage."""
    results = [stage["result"] for stage in stages]
    files = [stage["next_session_file_after"] for stage in stages]
    denied = DENIAL_ERRNO_NAMES = ("EACCES", "EPERM")
    detail = {}
    if results[0] == "ok" and files[0].get("uid") == AGENT_UID and files[0].get("sha256") == digest(ATTACKER):
        detail["agent_precreate"] = "created"
    elif results[0] in denied and files[0].get("exists") is False:
        detail["agent_precreate"] = "denied"
    else:
        detail["agent_precreate"] = UNEXPECTED
    created = detail["agent_precreate"] == "created"
    if results[1] == "ok" and not created and files[1].get("uid") == recorder_uid \
            and files[1].get("sha256") == digest(NEW_SESSION):
        detail["recorder_exclusive_create"] = "created"
    elif results[1] == "EEXIST" and files[1] == files[0]:
        detail["recorder_exclusive_create"] = "EEXIST"
    elif results[1] in denied and files[1] == files[0]:
        detail["recorder_exclusive_create"] = "denied"
    else:
        detail["recorder_exclusive_create"] = UNEXPECTED
    if results[2] == "ok" and created and files[2].get("inode") == files[0].get("inode") \
            and files[2].get("sha256") == digest(ATTACKER + NEW_SESSION):
        detail["recorder_open_without_excl"] = "appended_to_agent_created_file"
    elif results[2] == "ok" and not created and files[2].get("uid") == recorder_uid \
            and files[2].get("inode") == files[1].get("inode") \
            and files[2].get("sha256") == digest(NEW_SESSION + NEW_SESSION):
        detail["recorder_open_without_excl"] = "appended_to_recorder_created_file"
    elif results[2] in denied and files[2] == files[1]:
        detail["recorder_open_without_excl"] = "denied"
    else:
        detail["recorder_open_without_excl"] = UNEXPECTED
    if results[3] == "ok" and files[3].get("inode") == files[2].get("inode") \
            and files[3].get("sha256") == digest(EDIT):
        detail["agent_rewrite_resulting_file"] = "effect"
    elif results[3] in denied and files[3] == files[2]:
        detail["agent_rewrite_resulting_file"] = "denied"
    else:
        detail["agent_rewrite_resulting_file"] = UNEXPECTED
    detail["resulting_file_owner_uid"] = files[3].get("uid")
    return detail


def precreate_verdict(detail, transcript_unchanged):
    if UNEXPECTED in detail.values() or not transcript_unchanged:
        return UNEXPECTED, "a stage did something other than the named outcomes, or the transcript changed"
    if detail["agent_precreate"] == "created" and detail["recorder_exclusive_create"] == "EEXIST":
        return S, "the agent's file holds the name; the recorder's exclusive create failed with EEXIST"
    if detail["agent_precreate"] == "denied" and detail["recorder_exclusive_create"] == "created":
        return NOSUP, "the agent could not create the name; the recorder created it"
    return UNEXPECTED, "combination of stage outcomes outside the definition"


def measure_precreate(root, all_roots, case, expected):
    operation = "precreate_next_session_name"
    fixture = setup_fixture(root["path"], case + "--suppress-precreate", case)
    path = os.path.join(fixture["records"], NEXT_SESSION_NAME)
    before, stages = state(fixture), []
    for name, role, child_operation in (
            ("agent_precreate", "agent", "precreate_next_session"),
            ("recorder_exclusive_create", "recorder", "recorder_create_next_session_excl"),
            ("recorder_open_without_excl", "recorder", "recorder_open_next_session_no_excl"),
            ("agent_rewrite_resulting_file", "agent", "agent_rewrite_next_session")):
        stage = _stage(name, role, case, child_operation, fixture, all_roots, {"next_session": path})
        stage["next_session_file_after"] = snapshot(path)
        stages.append(stage)
    after = state(fixture)
    detail = precreate_details(stages, identity_for(case, "recorder")[0])
    verdict, reason = precreate_verdict(detail, after["target"] == before["target"])
    row = {"case": case, "operation": operation, "category": "suppression_of_future_records",
           "fixture": _fixture_record(fixture, root), "ancestors": ancestors(fixture["records"]),
           "recorder_account": CASES[case]["recorder_account"], "next_session_path": path,
           "before": before, "after": after, "stages": stages, "verdict": verdict, "verdict_reason": reason,
           "expected": expected["verdict"],
           "expected_details": {key: value for key, value in expected.items() if key != "verdict"}}
    row.update(detail)
    row["matches_expectation"] = (verdict == expected["verdict"]
                                  and all(detail[key] == value for key, value in row["expected_details"].items()))
    return row


def fill_verdict(agent_stage, recorder_stage, before, after):
    """Returns (verdict, reason, detail) for one fill cell, from the stages and the transcript snapshots.

    A full filesystem may reject a write(2) with ENOSPC or return a short (torn) write; both starve the
    recorder and count as suppression.
    """
    agent, recorder = agent_stage["child"], recorder_stage["child"]
    complete, torn = recorder.get("complete_records"), recorder.get("torn_bytes")
    exhausted = recorder.get("exhausted")
    detail = {"agent_fill_sinks": [{"path": entry["path"], "bytes_written": entry["bytes_written"],
                                    "result": errno.errorcode.get(entry["errno"], entry["stopped"])}
                                   for entry in agent.get("fill", [])],
              "recorder_complete_records": complete, "recorder_torn_bytes": torn,
              "recorder_exhausted": exhausted,
              "recorder_append_errno": errno.errorcode.get(recorder.get("append_errno"))}
    old, new = before["target"], after["target"]
    agent_hit_enospc = any(entry["errno"] == errno.ENOSPC for entry in agent.get("fill", []))
    if agent_stage["result"] != "ok" or not agent_hit_enospc or recorder_stage["result"] != "ok" \
            or complete is None:
        return UNEXPECTED, "the agent fill did not reach ENOSPC, or a recorder stage did not run cleanly", detail
    same = new.get("inode") == old.get("inode")
    if not exhausted and complete == APPEND_MANY_COUNT and same \
            and new.get("sha256") == digest(BASE + TRUSTED * APPEND_MANY_COUNT):
        return NOSUP, "the recorder appended all %d records after the agent's fill" % APPEND_MANY_COUNT, detail
    if exhausted and complete < APPEND_MANY_COUNT and same \
            and new.get("sha256") == digest(BASE + TRUSTED * complete + TRUSTED[:torn]):
        return S, "the filesystem starved the recorder after %d of %d records (%d torn bytes)" % (
            complete, APPEND_MANY_COUNT, torn), detail
    return UNEXPECTED, "recorder outcome outside the definition: " + str(recorder.get("error")), detail


def filesystem_capacity(path):
    values = os.statvfs(path)
    return {"total_bytes": values.f_blocks * values.f_frsize, "free_bytes": values.f_bavail * values.f_frsize}


def measure_fill(records_root, workspace_root, all_roots, case, operation, expected):
    separate = workspace_root is not records_root
    tag = case + ("--suppress-fill-separate" if separate else "--suppress-fill-shared")
    capacity_before = {"records_filesystem": filesystem_capacity(records_root["path"]),
                       "workspace_filesystem": filesystem_capacity(workspace_root["path"])}
    fixture = setup_fixture(records_root["path"], tag, case,
                            workspace_root=workspace_root["path"] if separate else None)
    try:
        sinks = [os.path.join(fixture[key], "fill.bin") for key in ("workspace", "parent", "records")]
        before = state(fixture)
        chain = ancestors(fixture["records"])
        agent = _stage("agent_fill", "agent", case, "fill_filesystem", fixture, all_roots,
                       {"fill_sinks": sinks, "fill_chunk": FILL_CHUNK, "fill_sink_cap": FILL_SINK_CAP})
        capacity_after = {"records_filesystem": filesystem_capacity(records_root["path"]),
                          "workspace_filesystem": filesystem_capacity(workspace_root["path"])}
        recorder = _stage("recorder_append_many", "recorder", case, "recorder_append_many", fixture, all_roots,
                          {"append_many_count": APPEND_MANY_COUNT})
        after = state(fixture)
    finally:
        # free the small fill tmpfs immediately so the next fill fixture starts from an empty filesystem
        for tree in dict.fromkeys((fixture["base"], fixture["workspace_base"])):
            clear_flags_recursive(tree)
            shutil.rmtree(tree, ignore_errors=True)
    verdict, reason, detail = fill_verdict(agent, recorder, before, after)
    row = {"case": case, "operation": operation, "category": "suppression_of_future_records",
           "fixture": _fixture_record(fixture, records_root), "ancestors": chain,
           "recorder_account": CASES[case]["recorder_account"],
           "records_and_workspace_on_separate_filesystems": separate,
           "records_filesystem": records_root["filesystem"].get("fstype"),
           "workspace_filesystem": workspace_root["filesystem"].get("fstype"),
           "capacity_before_fill": capacity_before, "capacity_after_fill": capacity_after,
           "before": before, "after": after, "stages": [agent, recorder], "verdict": verdict,
           "verdict_reason": reason, "expected": expected["verdict"], "expected_details": {},
           "matches_expectation": verdict == expected["verdict"]}
    row.update(detail)
    return row


def fill_root_problem(root):
    """A fill root must be a small dedicated tmpfs; otherwise the fill would be unbounded or harmful."""
    if root["filesystem"].get("fstype") != "tmpfs" or root["filesystem"].get("mount_point") != root["path"]:
        return "the fill root %s is not a dedicated tmpfs mount" % root["path"]
    total = filesystem_capacity(root["path"])["total_bytes"]
    if not 0 < total <= FILL_ROOT_MAX_BYTES:
        return "the fill root %s is not size-limited (%d bytes)" % (root["path"], total)
    return None


def environment(roots):
    status = proc_status()
    return {"kernel_release": platform.release(), "kernel_version": platform.version(),
            "machine": platform.machine(), "python_version": platform.python_version(),
            "python_executable": sys.executable,
            "sysctl_fs": {name: sysctl(name) for name in
                          ("protected_hardlinks", "protected_symlinks", "protected_regular", "protected_fifos")},
            "setup_process": {"uid": list(os.getresuid()), "gid": list(os.getresgid()),
                              "groups": sorted(os.getgroups()), "status": status,
                              "effective_capability_names": capability_names(status.get("CapEff", "0"))},
            "no_new_privs_via_prctl_available": _LIBC is not None,
            "probe_roots": roots}


def _collect_roots(specs):
    roots = []
    for label, path in specs:
        if path is None:
            continue
        path = os.path.realpath(path)
        if not os.path.isdir(path) or os.listdir(path):
            raise RuntimeError("Expected an empty probe root directory: " + path)
        roots.append({"label": label, "path": path, "filesystem": filesystem_of(path),
                      "ancestors": ancestors(path), "features": detect_features(path)})
    return roots


def _fill_roots(fill_roots):
    """Validate the two small dedicated tmpfs mounts used by the fill controls (records, workspace)."""
    if not fill_roots:
        return None, "no dedicated size-limited fill filesystem was provided (fill needs a small tmpfs)"
    roots = _collect_roots([("fill_records", fill_roots[0]),
                            ("fill_workspace", fill_roots[1] if len(fill_roots) > 1 else None)])
    for root in roots:
        problem = fill_root_problem(root)
        if problem:
            return None, problem
    return roots, None


def run_probes(root, alt_root=None, fill_roots=None, cases=None, log=sys.stderr):
    if os.geteuid() != 0:
        raise RuntimeError("The setup process must be UID 0 inside the disposable environment.")
    os.umask(0o022)
    roots = _collect_roots([("primary", root), ("alternate", alt_root)])
    fill_info, fill_reason = _fill_roots(fill_roots)
    all_roots = [item["path"] for item in roots] + [item["path"] for item in (fill_info or [])]
    env = environment(roots)
    env["fill_roots"] = fill_info
    env["fill_roots_unavailable_reason"] = fill_reason
    hardlinks = env["sysctl_fs"]["protected_hardlinks"]
    rows, legit, descriptors, suppression, layouts = [], [], [], [], {}
    fill_records = fill_info[0] if fill_info else None
    fill_workspace = fill_info[1] if fill_info and len(fill_info) > 1 else fill_records
    started = time.time()
    try:
        for case in (cases or list(CASES)):
            chosen, reason = choose_root(case, roots)
            layout = dict(CASES[case], required_features=required_features(case),
                          probe_root=chosen["path"] if chosen else None,
                          filesystem=chosen["filesystem"].get("fstype") if chosen else None,
                          agent_identity=identity_for(case, "agent"),
                          recorder_identity=identity_for(case, "recorder"))
            layouts[case] = layout
            for operation in OPERATIONS:
                expected = expected_verdict(case, operation, hardlinks)
                skip = not_applicable_reason(case, operation)
                if chosen is None:
                    rows.append(_not_run_row(case, "operation", operation, reason, expected, True))
                elif skip:
                    rows.append(_not_run_row(case, "operation", operation, skip, expected, False))
                else:
                    try:
                        rows.append(measure_operation(chosen, all_roots, case, operation, expected))
                    except FixtureSetupError as error:
                        rows.append(_not_run_row(case, "operation", operation, str(error), expected, True))
            for control in LEGIT_CONTROLS:
                if chosen is None:
                    legit.append({"case": case, "control": control, "judged": LEGIT_CONTROLS[control][1],
                                  "outcome": N, "not_run_reason": reason, "matches_expectation": None})
                    continue
                try:
                    legit.append(measure_legit(chosen, all_roots, case, control))
                except FixtureSetupError as error:
                    legit.append({"case": case, "control": control, "judged": LEGIT_CONTROLS[control][1],
                                  "outcome": N, "not_run_reason": str(error), "matches_expectation": None})
            for control in DESCRIPTOR_CONTROLS:
                expected = expected_descriptor(case, control, hardlinks)
                try:
                    if chosen is None:
                        raise FixtureSetupError(reason)
                    descriptors.append(measure_descriptor(chosen, all_roots, case, control, expected))
                except FixtureSetupError as error:
                    row = _not_run_row(case, "control", control, str(error), expected[0], True)
                    row.update(expected_outcome=expected[1], outcome=None)
                    descriptors.append(row)
            for operation in SUPPRESSION_OPERATIONS:
                expected = expected_suppression(case, operation)
                skip = suppression_not_applicable_reason(case, operation)
                separate = operation.endswith("_separate_fs")
                try:
                    if operation == "precreate_next_session_name":
                        if chosen is None:
                            raise FixtureSetupError(reason)
                        suppression.append(measure_precreate(chosen, all_roots, case, expected))
                    elif skip:
                        suppression.append(_suppression_not_run(case, operation, skip, expected, False))
                    elif fill_records is None:
                        suppression.append(_suppression_not_run(case, operation, fill_reason, expected, True))
                    else:
                        suppression.append(measure_fill(fill_records,
                                                        fill_workspace if separate else fill_records,
                                                        all_roots, case, operation, expected))
                except FixtureSetupError as error:
                    suppression.append(_suppression_not_run(case, operation, str(error), expected, True))
            print("Completed layout: " + case, file=log, flush=True)
    finally:
        cleaned = {}
        for item in roots + (fill_info or []):
            try:
                empty_directory(item["path"])
                cleaned[item["path"]] = os.listdir(item["path"]) == []
            except OSError as error:
                cleaned[item["path"]] = "cleanup failed: " + str(error)
    evaluated = [row for row in rows + legit + descriptors + suppression
                 if row["matches_expectation"] is not None]
    return {"protocol": PROTOCOL, "scope": SCOPE, "environment": env,
            "accounts": {"agent": [AGENT_UID, AGENT_GID], "recorder": [RECORDER_UID, RECORDER_GID],
                         "shared_group": SHARED_GID},
            "payload_sha256": {"BASE": digest(BASE), "EDIT": digest(EDIT), "BASE+APPEND": digest(BASE + APPEND),
                               "BASE+TRUSTED": digest(BASE + TRUSTED), "PATCHED": digest(PATCHED),
                               "BASE+PATCH": digest(BASE + PATCH), "ATTACKER": digest(ATTACKER),
                               "NEW_SESSION": digest(NEW_SESSION)},
            "verdict_definitions": VERDICT_DEFINITIONS,
            "operation_definitions": {name: {"effect_category": value[0], "counts_as_tampering": value[1],
                                             "effect_definition": value[2]} for name, value in OPERATIONS.items()},
            "legit_control_definitions": {name: {"actor": value[0], "judged": value[1], "description": value[2]}
                                          for name, value in LEGIT_CONTROLS.items()},
            "descriptor_control_definitions": {name: {"descriptor": DESCRIPTOR_OPEN_FLAGS[value[0]][0],
                                                      "defined_effect_outcome": value[1]}
                                               for name, value in DESCRIPTOR_CONTROLS.items()},
            "suppression_control_definitions": {name: {"description": text} for name, text in
                                                SUPPRESSION_OPERATIONS.items()},
            "layouts": layouts, "rows": rows, "legit_controls": legit, "descriptor_controls": descriptors,
            "suppression_controls": suppression,
            "all_evaluated_observations_match_expectation": all(row["matches_expectation"] for row in evaluated),
            "probe_roots_emptied": cleaned, "duration_seconds": round(time.time() - started, 3)}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--root", default="/probe", help="empty private tmpfs directory")
    parser.add_argument("--alt-root", default=None,
                        help="optional empty scratch directory on another filesystem for flag/ACL layouts")
    parser.add_argument("--fill-records-root", default=None,
                        help="empty small dedicated tmpfs mount used as the records filesystem for the fill controls")
    parser.add_argument("--fill-workspace-root", default=None,
                        help="empty small dedicated tmpfs mount used as the separate workspace filesystem")
    arguments = parser.parse_args(argv)
    fill_roots = [path for path in (arguments.fill_records_root, arguments.fill_workspace_root) if path]
    try:
        print(json.dumps(run_probes(arguments.root, arguments.alt_root, fill_roots or None), indent=2))
    except Exception as error:
        print(json.dumps({"status": "incomplete", "error": type(error).__name__ + ": " + str(error)}))
        raise SystemExit(1)


if __name__ == "__main__":
    main()
