"""Measure input restoration during normal resume using a fixed, text-only loopback responder."""
import argparse
from datetime import datetime, timezone
import hashlib
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import os
from pathlib import Path
import secrets
import shutil
import subprocess
import tempfile
import threading
import uuid


PROBE = "Please acknowledge this text-only control."
ACK = "Acknowledged."


def sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def user_inputs(payload):
    items = payload.get("input", [])
    if isinstance(items, str):
        return [items]
    texts = []
    for item in items:
        if not isinstance(item, dict) or item.get("role") != "user":
            continue
        content = item.get("content", [])
        if isinstance(content, str):
            texts.append(content)
        elif isinstance(content, list):
            texts.extend(c.get("text", "") for c in content
                         if isinstance(c, dict) and c.get("type") in ("input_text", "text"))
    return texts


class TextOnlyHandler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_POST(self):
        if self.path != "/v1/responses":
            self.send_error(404)
            return
        try:
            size = int(self.headers.get("Content-Length", "0"))
            if not 0 < size <= 4 * 1024 * 1024:
                self.send_error(413)
                return
            body = json.loads(self.rfile.read(size))
            texts = user_inputs(body)
            self.server.observed.append({
                "seed_prompt_in_user_input": self.server.seed_prompt in texts,
                "probe_prompt_in_user_input": PROBE in texts,
                "advertised_tools": len(body.get("tools") or []),
            })
        except (ValueError, TypeError, AttributeError):
            self.send_error(400)
            return
        rid, mid = "resp_" + uuid.uuid4().hex, "msg_" + uuid.uuid4().hex
        message = {"id": mid, "type": "message", "role": "assistant", "status": "completed",
                   "content": [{"type": "output_text", "text": ACK, "annotations": []}]}
        response = {"id": rid, "object": "response", "status": "completed",
                    "model": "gpt-5", "output": [message],
                    "usage": {"input_tokens": 0, "output_tokens": 0, "total_tokens": 0}}
        events = [
            {"type": "response.created", "response": dict(response, status="in_progress", output=[])},
            {"type": "response.output_item.added", "output_index": 0,
             "item": dict(message, status="in_progress", content=[])},
            {"type": "response.output_text.delta", "item_id": mid, "output_index": 0,
             "content_index": 0, "delta": ACK},
            {"type": "response.output_item.done", "output_index": 0, "item": message},
            {"type": "response.completed", "response": response},
        ]
        text = "".join("event: " + e["type"] + "\ndata: " + json.dumps(e) + "\n\n" for e in events)
        raw = text.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)


def run_control(args):
    binary = Path(shutil.which(args.codex) or args.codex).absolute()
    if args.container_layout:
        home, workspace = Path("/home/agent"), Path("/workspace")
        state = home / ".codex"
        if os.getuid() != 1000 or not workspace.is_dir() or not home.is_dir():
            raise ValueError("container layout requires UID 1000 and the expected temporary mounts")
        # Only a fresh private container home is eligible.
        state.mkdir(mode=0o700, exist_ok=False)
    else:
        base = Path(tempfile.mkdtemp(prefix="resume-control-", dir=args.work_dir)).resolve()
        home, state, workspace = (base / name for name in ("home", "state", "workspace"))
        for directory in (home, state, workspace):
            directory.mkdir(mode=0o700)
    sandbox = None if args.permission_profile else args.sandbox or "read-only"
    env = {"HOME": str(home), "CODEX_HOME": str(state), "LANG": "C.UTF-8",
           "PATH": f"{binary.parent}:/usr/local/bin:/usr/bin:/bin", "NO_COLOR": "1",
           "HTTP_PROXY": "http://127.0.0.1:9", "HTTPS_PROXY": "http://127.0.0.1:9",
           "ALL_PROXY": "http://127.0.0.1:9", "NO_PROXY": "127.0.0.1,localhost"}
    version = subprocess.run([str(binary), "--version"], env=env, cwd=workspace,
                             capture_output=True, text=True, timeout=15)
    reference = "REF-" + secrets.token_hex(16)
    seed = "Please acknowledge the control reference " + reference + "."
    report = {"schema": "normal-text-resume-control-v1",
              "started_utc": datetime.now(timezone.utc).isoformat(),
              "profile": args.profile, "requested_sandbox": sandbox,
              "requested_permission_profile": args.permission_profile, "layout": "container" if args.container_layout else "isolated host",
              "codex_invoked_path": str(binary), "entrypoint_file_sha256": sha256(binary),
              "codex_version": version.stdout.strip(), "process_uid": os.getuid(),
              "reference_sha256": hashlib.sha256(reference.encode()).hexdigest(),
              "provider": "local fixed text, no model inference or tool responses",
              "phases": {}, "status": "incomplete"}
    with HTTPServer(("127.0.0.1", 0), TextOnlyHandler) as httpd:
        httpd.seed_prompt, httpd.observed = seed, []
        settings = [f'model_providers.control.base_url="http://127.0.0.1:{httpd.server_port}/v1"',
                    'model_provider="control"', 'model_providers.control.name="Text control"',
                    'model_providers.control.wire_api="responses"', 'model_providers.control.requires_openai_auth=false',
                    'model_providers.control.supports_websockets=false', 'model_providers.control.request_max_retries=0',
                    'model_providers.control.stream_max_retries=0', 'analytics.enabled=false', 'feedback.enabled=false',
                    'web_search="disabled"', 'features.apps=false', 'features.shell_tool=false',
                    'approval_policy="on-request"', 'project_doc_max_bytes=0']
        if args.permission_profile:
            settings.append(f'default_permissions="{args.permission_profile}"')
        argv = [str(binary)]
        for setting in settings:
            argv.extend(["-c", setting])
        argv += ["exec", "--skip-git-repo-check", "--json", "--model", "gpt-5"]
        if sandbox:
            argv.extend(["--sandbox", sandbox])
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
        try:
            seed_thread = None
            for phase in ("seed", "resume", "fresh"):
                if phase == "resume" and not seed_thread:
                    break
                suffix = ["resume", seed_thread, PROBE] if phase == "resume" else [seed if phase == "seed" else PROBE]
                httpd.observed = []
                try:
                    proc = subprocess.run(argv + suffix, env=env, cwd=workspace, stdin=subprocess.DEVNULL,
                                          capture_output=True, text=True, timeout=45)
                except subprocess.TimeoutExpired:
                    report["phases"][phase] = {"timed_out": True, "provider_requests": list(httpd.observed)}
                    break
                kinds, item_types, thread, acknowledged, errors = [], [], None, False, []
                for line in proc.stdout.splitlines():
                    try:
                        event = json.loads(line)
                    except ValueError:
                        continue
                    if not isinstance(event, dict):
                        continue
                    kind = event.get("type")
                    kinds.append(kind)
                    if kind == "thread.started":
                        thread = event.get("thread_id")
                    item = event.get("item") or {}
                    if item:
                        item_types.append(item.get("type"))
                    if item.get("type") == "error":
                        errors.append(str(item.get("message", ""))[:650])
                    if kind == "item.completed" and item.get("type") == "agent_message":
                        acknowledged = item.get("text") == ACK
                    if kind == "error" and isinstance(event.get("message"), str):
                        errors.append(event["message"][:500])
                details = {"exit_code": proc.returncode, "thread_id": thread, "cli_event_types": kinds,
                           "cli_item_types": item_types, "fixed_ack_observed": acknowledged,
                           "provider_requests": list(httpd.observed)}
                if errors or proc.returncode or not httpd.observed:
                    details["diagnostics"] = (errors + proc.stderr.splitlines()[-5:])[-6:]
                report["phases"][phase] = details
                requests = details["provider_requests"]
                valid = (proc.returncode == 0 and acknowledged and isinstance(thread, str) and
                         len(requests) == 1 and all(t in ("error", "agent_message") for t in item_types) and
                         all(msg.startswith("Model metadata for `gpt-5` not found. Defaulting to fallback metadata") for msg in errors) and
                         requests[0]["seed_prompt_in_user_input"] == (phase != "fresh") and
                         requests[0]["probe_prompt_in_user_input"] == (phase != "seed"))
                if phase == "seed":
                    seed_thread = thread
                elif phase == "resume":
                    valid = valid and thread == seed_thread
                else:
                    valid = valid and thread != seed_thread
                details["meets_control_criteria"] = valid
                if not valid:
                    break
        finally:
            httpd.shutdown()
    phases = report["phases"]
    report["status"] = "pass" if len(phases) == 3 and all(p.get("meets_control_criteria") for p in phases.values()) else "incomplete"
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--codex", default="codex")
    permissions = parser.add_mutually_exclusive_group()
    permissions.add_argument("--sandbox", choices=["read-only", "workspace-write", "danger-full-access"])
    permissions.add_argument("--permission-profile", choices=[":workspace", ":danger-full-access"])
    parser.add_argument("--container-layout", action="store_true", help="Use the Docker wrapper's fresh container home and workspace.")
    parser.add_argument("--work-dir", type=Path, help="Parent directory for a fresh private trial directory.")
    parser.add_argument("--profile", default="native-host")
    args = parser.parse_args()
    try:
        evidence = run_control(args)
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        evidence = {"schema": "normal-text-resume-control-v1", "status": "incomplete", "diagnostic": str(exc)}
    print(json.dumps(evidence, indent=2))
    return 0 if evidence["status"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
