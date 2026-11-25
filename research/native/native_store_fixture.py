"""Offline native metadata reads and schema inspection in a disposable home."""
import base64
import hashlib
import json
import os
from pathlib import Path
import selectors
import signal
import sqlite3
import subprocess
import sys
import time

BINARY = "/usr/local/lib/node_modules/@openai/codex/node_modules/@openai/codex-linux-x64/vendor/x86_64-unknown-linux-musl/bin/codex"
BINARY_SHA = "3188814c35471432d4123203e0eb38e5bddc60226e3d7ddf0e59e649ea140022"
VERSION = "codex-cli 0.154.0"
SESSION = "01a1e7be-70d3-7ee3-84cd-e8437a83cdeb"
SEED_SHA = "33560b60d259bc6089be7f81f9951da310b7043e024de075d54f861f25b15f09"
SEED_PATH = Path("sessions/2026/11/17/rollout-2026-11-17T04-23-00-01a1e7be-70d3-7ee3-84cd-e8437a83cdeb.jsonl")
METHODS = {"initialize", "thread/read", "thread/turns/list", "thread/items/list"}
MAX_OUTPUT = 4 * 1024 * 1024


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def digest(path):
    h = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def decode_seed(payload):
    require(set(payload) == {"seed_b64"}, "Unexpected fixture input fields.")
    raw = base64.b64decode(payload["seed_b64"], validate=True)
    require(hashlib.sha256(raw).hexdigest() == SEED_SHA, "The copied rollout differs.")
    meta = json.loads(raw.splitlines()[0])["payload"]
    require(meta["id"] == SESSION and meta["history_mode"] == "paginated", "Unexpected copied session.")
    return raw


def process_env(home):
    return {"PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin"),
            "HOME": str(home), "CODEX_HOME": str(home / ".codex"),
            "XDG_CONFIG_HOME": str(home / ".config"), "TMPDIR": "/tmp",
            "HTTP_PROXY": "http://127.0.0.1:9", "HTTPS_PROXY": "http://127.0.0.1:9",
            "ALL_PROXY": "http://127.0.0.1:9", "NO_PROXY": "localhost,127.0.0.1"}


def validate_read_message(value):
    require(isinstance(value, dict), "Native transport returned a non-object message.")
    require(not ("method" in value and "id" in value), "Unexpected server request; no action authorized.")
    if "method" in value:
        passive = value["method"] == "configWarning" or (
            value["method"] == "remoteControl/status/changed"
            and isinstance(value.get("params"), dict)
            and value["params"].get("status") == "disabled")
        require(passive, "Unexpected notification during local reads.")


def rpc_reads(binary, home, workspace):
    """Only four allowlisted local-read methods. Never submit a turn or resume."""
    requests = [("initialize", {"clientInfo": {"name": "native_store_scope", "version": "1"},
                                "capabilities": {"experimentalApi": True}}),
                ("thread/read", {"threadId": SESSION}),
                ("thread/turns/list", {"threadId": SESSION, "limit": 100, "itemsView": "full"}),
                ("thread/items/list", {"threadId": SESSION, "limit": 100})]
    record = {"requests": [], "messages": [], "errors": [], "forced_stop": False}
    stderr_path = home / "app-server.stderr"
    with stderr_path.open("xb") as error_stream:
        process = subprocess.Popen([str(binary), "app-server", "--listen", "stdio://", "-c", "analytics.enabled=false"],
            cwd=workspace, env=process_env(home), stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=error_stream, start_new_session=True)
        selector = selectors.DefaultSelector()
        selector.register(process.stdout, selectors.EVENT_READ)
        pending = b""
        size = 0
        def send(value):
            process.stdin.write((json.dumps(value) + "\n").encode())
            process.stdin.flush()
        def receive(request_id, deadline):
            nonlocal pending, size
            while time.monotonic() < deadline:
                if b"\n" not in pending:
                    if not selector.select(min(0.2, max(0, deadline - time.monotonic()))):
                        continue
                    part = os.read(process.stdout.fileno(), 65536)
                    require(part, "Native read transport closed before its response.")
                    size += len(part)
                    require(size <= MAX_OUTPUT, "Native read output exceeded its limit.")
                    pending += part
                    continue
                line, pending = pending.split(b"\n", 1)
                if not line.strip():
                    continue
                value = json.loads(line)
                record["messages"].append({"observed_monotonic_ns": time.monotonic_ns(), "message": value})
                validate_read_message(value)
                if value.get("id") == request_id:
                    require(("result" in value) != ("error" in value), "Malformed native read response.")
                    return value
            raise TimeoutError("Native read response timed out.")
        try:
            for number, (method, params) in enumerate(requests, 1):
                require(method in METHODS, "A non-read method was blocked.")
                item = {"id": number, "method": method, "params": params,
                        "sent_monotonic_ns": time.monotonic_ns()}
                record["requests"].append(item)
                send({k: v for k, v in item.items() if k != "sent_monotonic_ns"})
                item["response"] = receive(number, time.monotonic() + 20)
                if method == "initialize":
                    require("result" in item["response"], "Native initialization failed.")
                    send({"method": "initialized", "params": {}})
        except Exception as exc:
            record["errors"].append(type(exc).__name__ + ": " + str(exc))
        finally:
            process.stdin.close()
            deadline = time.monotonic() + 8
            while time.monotonic() < deadline:
                if selector.select(0.1):
                    part = os.read(process.stdout.fileno(), 65536)
                    if not part:
                        break
                    size += len(part)
                    if size > MAX_OUTPUT:
                        record["errors"].append("Native shutdown output exceeded its limit.")
                        break
                    pending += part
                elif process.poll() is not None:
                    break
            try:
                process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                record["forced_stop"] = True
                os.killpg(process.pid, signal.SIGTERM)
                try:
                    process.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    os.killpg(process.pid, signal.SIGKILL)
                    process.wait(timeout=2)
            selector.close()
            process.stdout.close()
            record["process_exit_code"] = process.returncode
    record["stderr"] = stderr_path.read_text(errors="replace")
    record["trailing_stdout"] = pending.decode(errors="replace")
    try:
        for line in pending.splitlines():
            if line.strip():
                validate_read_message(json.loads(line))
    except (ValueError, RuntimeError) as exc:
        record["errors"].append("Unexpected shutdown output: " + str(exc))
    require(len(record["stderr"].encode()) <= MAX_OUTPUT, "Native diagnostics exceeded their limit.")
    return record


def sqlite_inventory(native):
    result = []
    for path in sorted(native.glob("*.sqlite")):
        require(path.is_file() and not path.is_symlink(), "Unexpected SQLite path.")
        before = digest(path)
        row = {"name": path.name, "bytes": path.stat().st_size, "sha256": before,
               "uid": path.stat().st_uid, "gid": path.stat().st_gid, "tables": [], "errors": []}
        connection = None
        try:
            connection = sqlite3.connect(path.resolve().as_uri() + "?mode=ro", uri=True, timeout=2)
            connection.execute("PRAGMA query_only=ON")
            connection.execute("PRAGMA trusted_schema=OFF")
            row["quick_check"] = [v[0] for v in connection.execute("PRAGMA quick_check")]
            for name, sql in connection.execute("SELECT name, sql FROM sqlite_master WHERE type='table' ORDER BY name"):
                quoted = '"' + name.replace('"', '""') + '"'
                columns = [dict(zip(("cid", "name", "type", "notnull", "default", "pk"), v))
                           for v in connection.execute("PRAGMA table_info(" + quoted + ")")]
                table = {"name": name, "sql": sql, "columns": columns,
                         "rows": connection.execute("SELECT count(*) FROM " + quoted).fetchone()[0]}
                if name in {"threads", "thread_turns", "thread_items", "thread_history_projection_state"}:
                    column = "id" if name == "threads" else "thread_id"
                    table["copied_session_rows"] = connection.execute(
                        "SELECT count(*) FROM " + quoted + ' WHERE "' + column + '"=?', (SESSION,)).fetchone()[0]
                    if name == "threads":
                        table["copied_session_history_modes"] = [v[0] for v in connection.execute(
                            "SELECT history_mode FROM threads WHERE id=?", (SESSION,))]
                row["tables"].append(table)
        except sqlite3.Error as exc:
            row["errors"].append(str(exc))
        finally:
            if connection is not None:
                connection.close()
        row["database_unchanged_by_inspection"] = digest(path) == before
        result.append(row)
    return result


def run_case(binary, case_root, workspace, seed):
    case_root.mkdir()
    native = case_root / ".codex"
    native.mkdir(mode=0o700)
    path = native / SEED_PATH
    if seed is not None:
        path.parent.mkdir(parents=True)
        path.write_bytes(seed)
    before = digest(path) if path.exists() else None
    rpc = rpc_reads(binary, case_root, workspace)
    databases = sqlite_inventory(native)
    files = []
    candidates = list(native.iterdir()) + list((native / "sessions").rglob("*"))
    for item in sorted(candidates):
        require(not item.is_symlink(), "Unexpected symbolic link in disposable native storage.")
        if item.is_file() and (item.parent == native or item.is_relative_to(native / "sessions")):
            files.append({"path": str(item.relative_to(native)), "bytes": item.stat().st_size,
                          "sha256": digest(item), "uid": item.stat().st_uid, "gid": item.stat().st_gid})
    return {"seed_present": seed is not None, "seed_sha256_before": before,
            "seed_sha256_after": digest(path) if path.exists() else None,
            "rpc": rpc, "databases": databases, "files": files}


def run_fixture(payload, binary=Path(BINARY), home=Path("/home/agent"), workspace=Path("/workspace"), enforce_uid=True):
    if enforce_uid:
        require(os.getuid() == os.getgid() == 1000, "Unexpected inspection identity.")
    seed = decode_seed(payload)
    require(binary.is_file() and digest(binary) == BINARY_SHA, "Pinned native binary differs from the inspected release.")
    version = subprocess.run([str(binary), "--version"], capture_output=True, text=True, timeout=10,
                             env=process_env(home), cwd=workspace)
    require(version.returncode == 0 and version.stdout.strip() == VERSION, "Unexpected CLI version.")
    record = {"schema": "native-store-fixture-v1", "uid": os.getuid(), "gid": os.getgid(),
              "binary_sha256": BINARY_SHA, "version": version.stdout.strip(), "version_stderr": version.stderr,
              "seed_sha256": SEED_SHA, "session_id": SESSION, "cases": {}, "errors": [],
              "model_turns_submitted": 0, "resume_requests_submitted": 0}
    for name, contents in (("empty_home", None), ("copied_jsonl_only", seed)):
        try:
            record["cases"][name] = run_case(binary, home / name, workspace, contents)
        except Exception as exc:
            record["errors"].append({"case": name, "error": type(exc).__name__ + ": " + str(exc)})
    return record


if __name__ == "__main__":
    try:
        value = json.load(sys.stdin)
        print(json.dumps(run_fixture(value)))
    except Exception as exc:
        print(json.dumps({"schema": "native-store-fixture-v1", "errors": [type(exc).__name__ + ": " + str(exc)]}))
        raise SystemExit(1)
