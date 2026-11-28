"""STAND-IN for the Codex CLI. NOT Codex. For the model-free local-standin control.

It implements only the slice of the ``codex exec`` / ``codex exec resume`` interface
the dispatch fixture depends on, so the fixture, the launcher, the agent-shell
wrapper and the derivation can be exercised end to end WITHOUT the real binary, a
model or the network (it talks only to the fixture's loopback endpoint). It proves
nothing about real Codex; every result that uses it is labelled a stand-in.

Documented behaviour it reproduces:
  * parse ``exec`` / ``exec resume <id>``, ``--json``, ``-m``, ``-C <work>`` and the
    ``-c model_providers.fixture.*`` provider flags; read the prompt from stdin (the
    trailing ``-``);
  * emit ``--json`` event lines: ``thread.started``, ``item.completed`` with a
    ``command_execution`` item (exit_code/status/aggregated_output), a final
    ``agent_message``, and ``turn.completed``;
  * POST to the configured Responses ``base_url`` with ``tools`` including
    ``exec_command``; run the returned ``cmd`` as ``/bin/bash -lc`` (so the agent
    shell wrapper applies); POST back the ``function_call_output``;
  * write a rollout at ``CODEX_HOME/sessions/YYYY/MM/DD/rollout-<ts>-<uuid>.jsonl``
    with ``session_meta``, ``turn_context`` (sandbox policy/approval as the fixture
    reads them), and ``response_item`` user message, ``function_call`` and
    ``function_call_output``;
  * on resume, restore the earlier input from the rollout, or exit non-zero with
    ``no rollout found for thread id <id>`` when it is gone.
"""

import json
import os
from pathlib import Path
import subprocess
import sys
import time
import urllib.request
import uuid

BANNER = "account-separation-standin-codex (NOT Codex)"


def log(event):
    sys.stdout.write(json.dumps(event) + "\n")
    sys.stdout.flush()


def parse(argv):
    """Parse `exec [resume] ...`. The session id, when present, is the lone bare
    positional argument (besides the trailing `-`), wherever it sits."""
    opts = {"config": {}, "resume_id": None, "workdir": None, "model": None, "json": False,
            "resume": False}
    rest = argv[1:] if argv and argv[0] == "exec" else argv
    if rest and rest[0] == "resume":
        opts["resume"] = True
        rest = rest[1:]
    positionals = []
    index = 0
    while index < len(rest):
        token = rest[index]
        if token in ("-c", "-C", "-m") and index + 1 < len(rest):
            value = rest[index + 1]
            if token == "-c":
                key, _, raw = value.partition("=")
                opts["config"][key] = raw.strip('"') if raw[:1] == '"' and raw[-1:] == '"' else raw
            elif token == "-C":
                opts["workdir"] = value
            else:
                opts["model"] = value
            index += 2
            continue
        if token == "--json":
            opts["json"] = True
        elif token == "-":
            pass
        elif not token.startswith("-"):
            positionals.append(token)
        index += 1
    if opts["resume"] and positionals:
        opts["resume_id"] = positionals[0]
    return opts


def sandbox_policy(permission):
    if permission == ":workspace":
        return {"type": "workspace-write", "network_access": False, "writable_roots": []}, "managed"
    return {"type": "danger-full-access"}, "disabled"


class Rollout:
    def __init__(self, codex_home, session_id):
        now = time.gmtime()
        self.dir = Path(codex_home) / "sessions" / time.strftime("%Y/%m/%d", now)
        self.dir.mkdir(parents=True, exist_ok=True)
        stamp = time.strftime("%Y-%m-%dT%H-%M-%S", now)
        self.path = self.dir / ("rollout-%s-%s.jsonl" % (stamp, session_id))
        self.session_id = session_id
        self.handle = None

    def create(self, permission, workdir):
        # Hold the rollout open for the whole turn, as the real recorder does, so a
        # tool that unlinks the directory entry does not stop the recorder writing
        # (the writes land on the now-unlinked inode and the path is gone).
        self.handle = open(os.open(self.path, os.O_RDWR | os.O_CREAT | os.O_APPEND, 0o644), "a")
        policy, profile = sandbox_policy(permission)
        self.append({"type": "session_meta", "payload": {"id": self.session_id, "stand_in": BANNER}})
        self.append({"type": "turn_context", "payload": {
            "sandbox_policy": policy, "approval_policy": "never", "cwd": str(workdir),
            "permission_profile": {"type": profile}}})

    def append(self, record):
        self.handle.write(json.dumps(record) + "\n")
        self.handle.flush()
        os.fsync(self.handle.fileno())

    def user_message(self, text):
        self.append({"type": "response_item", "payload": {
            "type": "message", "role": "user", "content": [{"type": "input_text", "text": text}]}})

    def items(self):
        rows = []
        for line in self.path.read_text().splitlines():
            try:
                rows.append(json.loads(line))
            except ValueError:
                pass
        return rows


def post(base_url, body):
    data = json.dumps(body).encode()
    request = urllib.request.Request(base_url.rstrip("/") + "/responses", data=data,
                                     headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(request, timeout=30) as response:
        raw = response.read().decode()
    item = None
    for block in raw.split("\n\n"):
        for line in block.splitlines():
            if line.startswith("data:"):
                try:
                    payload = json.loads(line[5:].strip())
                except ValueError:
                    continue
                if payload.get("type") == "response.output_item.done":
                    item = payload.get("item")
    if item is None:
        raise RuntimeError("stand-in: endpoint returned no output item")
    return item


def user_turn(text):
    return {"type": "message", "role": "user", "content": [{"type": "input_text", "text": text}]}


def tools():
    return [{"type": "function", "name": "exec_command",
             "description": "Run a shell command", "parameters": {"type": "object"}}]


def run_exec(opts, prompt, codex_home):
    workdir = opts["workdir"] or os.getcwd()
    permission = opts["config"].get("default_permissions", ":danger-full-access")
    base_url = opts["config"].get("model_providers.fixture.base_url")
    if not base_url:
        sys.stderr.write("stand-in: no fixture base_url configured\n")
        return 2
    session_id = str(uuid.uuid4())
    rollout = Rollout(codex_home, session_id)
    rollout.create(permission, workdir)
    rollout.user_message(prompt)
    log({"type": "thread.started", "thread_id": session_id})

    call = post(base_url, {"model": opts["model"], "input": [user_turn(prompt)], "tools": tools()})
    if call.get("type") != "function_call" or call.get("name") != "exec_command":
        sys.stderr.write("stand-in: first turn was not an exec_command call\n")
        return 3
    arguments = json.loads(call["arguments"])
    rollout.append({"type": "response_item", "payload": call})

    proc = subprocess.run(["/bin/bash", "-lc", arguments["cmd"]],
                          cwd=arguments.get("workdir", workdir), stdin=subprocess.DEVNULL,
                          capture_output=True, text=True)
    output = proc.stdout + proc.stderr
    log({"type": "item.completed", "item": {
        "id": "item_cmd", "type": "command_execution", "command": arguments["cmd"],
        "exit_code": proc.returncode, "status": "completed" if proc.returncode == 0 else "failed",
        "aggregated_output": output}})
    output_record = {"type": "function_call_output", "call_id": call["call_id"], "output": output}
    rollout.append({"type": "response_item", "payload": output_record})

    final = post(base_url, {"model": opts["model"],
                            "input": [user_turn(prompt), call, output_record], "tools": tools()})
    text = "".join(part.get("text", "") for part in final.get("content", []) if isinstance(part, dict))
    rollout.append({"type": "response_item", "payload": final})
    log({"type": "item.completed", "item": {"id": "item_msg", "type": "agent_message", "text": text}})
    log({"type": "turn.completed"})
    return 0


def find_rollout(codex_home, session_id):
    matches = [p for p in (Path(codex_home) / "sessions").rglob("rollout-*.jsonl")
               if p.name.endswith("-%s.jsonl" % session_id)]
    return matches[0] if len(matches) == 1 else None


def run_resume(opts, prompt, codex_home):
    session_id = opts["resume_id"]
    base_url = opts["config"].get("model_providers.fixture.base_url")
    path = find_rollout(codex_home, session_id)
    if path is None:
        sys.stderr.write("Error: no rollout found for thread id %s\n" % session_id)
        return 1
    rows = []
    for line in path.read_text().splitlines():
        try:
            rows.append(json.loads(line))
        except ValueError:
            pass
    restored = [r["payload"] for r in rows if r.get("type") == "response_item"
                and isinstance(r.get("payload"), dict)
                and r["payload"].get("type") in ("message", "function_call", "function_call_output")]
    log({"type": "thread.started", "thread_id": session_id})
    final = post(base_url, {"model": opts["model"], "input": restored + [user_turn(prompt)], "tools": tools()})
    text = "".join(part.get("text", "") for part in final.get("content", []) if isinstance(part, dict))
    with path.open("a") as handle:
        handle.write(json.dumps({"type": "response_item", "payload": final}) + "\n")
    log({"type": "item.completed", "item": {"id": "item_resume", "type": "agent_message", "text": text}})
    log({"type": "turn.completed"})
    return 0


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv or argv[0] != "exec":
        sys.stderr.write("stand-in: only `exec` is supported\n")
        return 64
    opts = parse(argv)
    prompt = sys.stdin.read() if sys.stdin and not sys.stdin.closed else ""
    codex_home = os.environ.get("CODEX_HOME") or os.path.join(os.environ.get("HOME", "/tmp"), ".codex")
    try:
        if opts["resume_id"]:
            return run_resume(opts, prompt, codex_home)
        return run_exec(opts, prompt, codex_home)
    except Exception as exc:  # noqa: BLE001
        sys.stderr.write("stand-in error: %s: %s\n" % (type(exc).__name__, exc))
        return 1


if __name__ == "__main__":
    sys.exit(main())
