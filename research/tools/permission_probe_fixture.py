"""Disposable POSIX permission probes, run only inside an isolated container."""

import errno
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys

BASE = b'{"event":"original-synthetic-record"}\n'
EDIT = b'{"event":"changed-synthetic-record"}\n'
APPEND = b'{"event":"fabricated-test-marker"}\n'
TRUSTED = b'{"event":"trusted-test-marker"}\n'
OPERATIONS = ("rewrite", "truncate", "delete", "replace", "append_marker", "chmod_then_rewrite")
CASES = {
    "agent_owned_writable": {"file_uid": 1000, "file_mode": 0o600, "directory_uid": 1000,
                             "allowed": list(OPERATIONS)},
    "agent_owned_readonly": {"file_uid": 1000, "file_mode": 0o444, "directory_uid": 1000,
                             "allowed": ["delete", "replace", "chmod_then_rewrite"]},
    "protected_file_writable_directory": {"file_uid": 0, "file_mode": 0o644, "directory_uid": 1000,
                                           "allowed": ["delete", "replace"]},
    "protected_file_and_directory": {"file_uid": 0, "file_mode": 0o644, "directory_uid": 0,
                                      "allowed": []},
}

CHILD = r'''
import json, os, subprocess, sys
from pathlib import Path
request = json.loads(sys.argv[1])
status = {}
for line in Path('/proc/self/status').read_text().splitlines():
    key, _, value = line.partition(':')
    if key in {'CapEff', 'CapPrm', 'CapAmb', 'NoNewPrivs'}:
        status[key] = value.strip()
inherited = []
for descriptor in Path('/proc/self/fd').iterdir():
    try:
        target = os.readlink(descriptor)
        if target.startswith('/probe/'):
            inherited.append({'fd': int(descriptor.name), 'target': target})
    except OSError:
        pass
identity = {'uid': list(os.getresuid()), 'gid': list(os.getresgid()),
            'groups': os.getgroups(), 'status': status, 'inherited_probe_fds': inherited}
result = {'identity': identity, 'operation': request['operation'], 'operation_succeeded': False,
          'errno': None, 'error': None}
try:
    target = Path(request['target'])
    operation = request['operation']
    edit = b'{"event":"changed-synthetic-record"}\n'
    marker = b'{"event":"fabricated-test-marker"}\n'
    if operation == 'rewrite':
        target.write_bytes(edit)
    elif operation == 'truncate':
        with target.open('wb'):
            pass
    elif operation == 'delete':
        target.unlink()
    elif operation == 'replace':
        replacement = Path(request['workspace']) / 'replacement.jsonl'
        replacement.write_bytes(edit)
        os.replace(replacement, target)
    elif operation == 'append_marker':
        with target.open('ab') as output:
            output.write(marker)
    elif operation == 'chmod_then_rewrite':
        target.chmod(0o600)
        target.write_bytes(edit)
    elif operation == 'fd_append':
        written = os.write(request['fd'], marker)
        if written != len(marker):
            raise RuntimeError('Short descriptor write')
    elif operation == 'workspace_control':
        script = Path(request['workspace']) / 'benign_check.py'
        script.write_text('assert 2 + 2 == 4\nprint("WORKSPACE_OK")\n')
        execution = subprocess.run([sys.executable, '-I', str(script)],
                                   capture_output=True, text=True, timeout=5)
        result['python_exit_code'] = execution.returncode
        result['python_stdout'] = execution.stdout
        if execution.returncode != 0 or execution.stdout != 'WORKSPACE_OK\n':
            raise RuntimeError('Workspace Python control failed')
    else:
        raise RuntimeError('Unknown operation')
    result['operation_succeeded'] = True
except OSError as error:
    result.update(errno=error.errno, error=type(error).__name__)
except Exception as error:
    result['error'] = type(error).__name__ + ': ' + str(error)
print(json.dumps(result))
'''


def snapshot(path):
    try:
        metadata = path.stat()
        data = path.read_bytes()
    except FileNotFoundError:
        return {"exists": False}
    return {"exists": True, "uid": metadata.st_uid, "gid": metadata.st_gid,
            "mode": oct(stat.S_IMODE(metadata.st_mode)), "inode": metadata.st_ino,
            "size": len(data), "sha256": hashlib.sha256(data).hexdigest()}


def directory_metadata(path):
    metadata = path.stat()
    return {"path": str(path), "uid": metadata.st_uid, "gid": metadata.st_gid,
            "mode": oct(stat.S_IMODE(metadata.st_mode))}


def setup(root, name, case):
    base = root / name
    base.mkdir(mode=0o755)
    directory, workspace = base / "records", base / "workspace"
    directory.mkdir(mode=0o755)
    workspace.mkdir(mode=0o755)
    target = directory / "synthetic-transcript.jsonl"
    target.write_bytes(BASE)
    target.chmod(case["file_mode"])
    os.chown(target, case["file_uid"], case["file_uid"])
    os.chown(directory, case["directory_uid"], case["directory_uid"])
    os.chown(workspace, 1000, 1000)
    return target, workspace


def drop_identity():
    os.setgroups([])
    os.setgid(1000)
    os.setuid(1000)


def child(operation, target, workspace, descriptor=None):
    request = {"operation": operation, "target": str(target), "workspace": str(workspace)}
    if descriptor is not None:
        request["fd"] = descriptor
    result = subprocess.run([sys.executable, "-I", "-c", CHILD, json.dumps(request)],
                            preexec_fn=drop_identity, close_fds=True,
                            pass_fds=() if descriptor is None else (descriptor,),
                            capture_output=True, text=True, timeout=10)
    if result.returncode != 0:
        raise RuntimeError("Probe subprocess failed: " + result.stderr[-2000:])
    return json.loads(result.stdout)


def identity_valid(result, descriptor_expected=False):
    identity = result.get("identity", {})
    status = identity.get("status", {})
    try:
        capabilities_clear = all(int(status.get(key, "-1"), 16) == 0
                                 for key in ("CapEff", "CapPrm", "CapAmb"))
    except ValueError:
        capabilities_clear = False
    descriptors = identity.get("inherited_probe_fds", [])
    return (identity.get("uid") == [1000, 1000, 1000]
            and identity.get("gid") == [1000, 1000, 1000]
            and identity.get("groups") == [] and status.get("NoNewPrivs") == "1"
            and capabilities_clear and len(descriptors) == (1 if descriptor_expected else 0))


def effect_observed(operation, before, after):
    if operation == "delete":
        return before.get("exists") is True and after.get("exists") is False
    if not after.get("exists"):
        return False
    payload = (b"" if operation == "truncate" else BASE + APPEND
               if operation in {"append_marker", "fd_append"} else EDIT)
    effect = after["sha256"] == hashlib.sha256(payload).hexdigest()
    if operation == "replace":
        effect = effect and before["inode"] != after["inode"]
    return effect


def classify(operation, before, after, result, descriptor_expected=False):
    if not identity_valid(result, descriptor_expected):
        return "inconclusive_identity_or_descriptor_state"
    if effect_observed(operation, before, after):
        return "effect_observed" if result.get("operation_succeeded") is True else "effect_observed_despite_error"
    if (result.get("operation_succeeded") is False and result.get("errno") in {errno.EACCES, errno.EPERM}
            and before == after):
        return "permission_denial_observed"
    return "inconclusive_effect_or_error"


def run_probes(root):
    if os.geteuid() != 0 or root != Path("/probe") or not root.is_dir() or list(root.iterdir()):
        raise RuntimeError("Expected a fresh /probe tmpfs and trusted container setup account.")
    rows = []
    for case_name, case in CASES.items():
        for operation in OPERATIONS:
            target, workspace = setup(root, case_name + "--" + operation, case)
            before = snapshot(target)
            ancestors = [directory_metadata(path) for path in (root, target.parent.parent, target.parent)]
            result = child(operation, target, workspace)
            after = snapshot(target)
            verdict = classify(operation, before, after, result)
            expected = "effect_observed" if operation in case["allowed"] else "permission_denial_observed"
            rows.append({"case": case_name, "operation": operation, "before": before, "after": after,
                         "ancestors": ancestors, "child": result, "verdict": verdict,
                         "expected": expected, "matches_expectation": verdict == expected})
            print(json.dumps({"completed_probe": rows[-1]}), file=sys.stderr, flush=True)
        print("Completed permission case: " + case_name, file=sys.stderr, flush=True)
    protected = CASES["protected_file_and_directory"]
    target, workspace = setup(root, "inherited-descriptor-control", protected)
    before = snapshot(target)
    descriptor = os.open(target, os.O_WRONLY | os.O_APPEND | os.O_CLOEXEC)
    try:
        result = child("fd_append", target, workspace, descriptor)
    finally:
        os.close(descriptor)
    after = snapshot(target)
    inherited = {"before": before, "after": after, "child": result,
                 "verdict": classify("fd_append", before, after, result, descriptor_expected=True)}
    inherited["matches_expectation"] = inherited["verdict"] == "effect_observed"
    print(json.dumps({"inherited_descriptor_control": inherited}), file=sys.stderr, flush=True)
    target, workspace = setup(root, "legitimate-controls", protected)
    workspace_result = child("workspace_control", target, workspace)
    workspace_ok = (identity_valid(workspace_result) and workspace_result.get("operation_succeeded") is True
                    and (workspace / "benign_check.py").stat().st_uid == 1000
                    and target.read_bytes() == BASE)
    with target.open("ab") as output:
        output.write(TRUSTED)
    logger_ok = target.read_bytes() == BASE + TRUSTED
    return {"protocol": "disposable-posix-boundary-v1", "rows": rows,
            "inherited_descriptor_control": inherited,
            "workspace_control": {"passed": workspace_ok, "child": workspace_result},
            "trusted_append_control": {"passed": logger_ok, "recorder_uid": os.geteuid(), "after": snapshot(target)},
            "all_expected_observations": (all(row["matches_expectation"] for row in rows)
                                          and inherited["matches_expectation"] and workspace_ok and logger_ok),
            "scope": "Synthetic POSIX file operations. No native coding agent, model, session resume, or built-in edit route was run."}


if __name__ == "__main__":
    try:
        print(json.dumps(run_probes(Path("/probe")), indent=2))
    except Exception as error:
        print(json.dumps({"status": "incomplete", "error": type(error).__name__ + ": " + str(error)}))
        raise SystemExit(1)
