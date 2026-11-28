"""Read-only native-store inventory, run inside a disposable unprivileged reader."""
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys


def read_regular(path, limit):
    path = Path(path)
    if not path.is_absolute() or ".." in path.parts:
        raise ValueError("Capture paths must be absolute without parent traversal")
    directory = os.open(path.anchor, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for component in path.parts[1:-1]:
            next_fd = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory)
            os.close(directory)
            directory = next_fd
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
    finally:
        os.close(directory)
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_size > limit:
            raise RuntimeError("Capture file type or size is outside the protocol")
        data = b""
        while len(data) <= limit:
            block = os.read(fd, min(65536, limit + 1 - len(data)))
            if not block:
                break
            data += block
        after = os.fstat(fd)
        if len(data) > limit or (before.st_ino, before.st_size, before.st_mtime_ns) != (
                after.st_ino, after.st_size, after.st_mtime_ns):
            raise RuntimeError("Capture changed while being read")
        return data, before
    finally:
        os.close(fd)


def capture(session, home=Path("/home/agent"), workspace=Path("/workspace")):
    if not re.fullmatch(r"[A-Za-z0-9-]{16,80}", session):
        raise ValueError("Invalid session identifier")
    root = home / ".codex"
    if root.is_symlink() or not root.is_dir():
        raise RuntimeError("Native directory is missing or is a symbolic link")
    entries, traces, workspace_files = [], [], []
    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root).as_posix()
        # Neither credential contents nor credential hashes are collected.
        if relative == "auth.json":
            continue
        info = path.lstat()
        if len(entries) >= 512:
            raise RuntimeError("Native inventory exceeded its entry limit")
        entries.append({"path": str(path), "mode": oct(stat.S_IMODE(info.st_mode)),
                        "uid": info.st_uid, "gid": info.st_gid, "inode": info.st_ino,
                        "device": info.st_dev, "bytes": info.st_size,
                        "kind": "symlink" if stat.S_ISLNK(info.st_mode) else
                                "directory" if stat.S_ISDIR(info.st_mode) else "file"})
        if relative.startswith("sessions/") and path.name.endswith("-" + session + ".jsonl"):
            data, info = read_regular(path, 8 * 1024 * 1024)
            if len(traces) >= 4:
                raise RuntimeError("Too many files match the current native session")
            traces.append({"path": str(path), "inode": info.st_ino, "device": info.st_dev,
                           "uid": info.st_uid, "gid": info.st_gid, "bytes": len(data),
                           "sha256": hashlib.sha256(data).hexdigest(),
                           "content_b64": base64.b64encode(data).decode("ascii")})
    for name in ("normalize_labels.py", "native-identity-control.json", "native-identity-control.txt"):
        path = workspace / name
        if path.exists() or path.is_symlink():
            data, info = read_regular(path, 1024 * 1024)
            workspace_files.append({"name": name, "sha256": hashlib.sha256(data).hexdigest(),
                                    "bytes": len(data), "content_b64": base64.b64encode(data).decode("ascii")})
    return {"schema": "native-identity-inventory-v1", "session_id": session,
            "entries": entries, "traces": traces, "workspace_files": workspace_files,
            "scope": "Current session JSONL contents and other native-store metadata. "
                     "Other stores, caches and remote records are not validated as history."}


if __name__ == "__main__":
    print(json.dumps(capture(sys.argv[1])))
