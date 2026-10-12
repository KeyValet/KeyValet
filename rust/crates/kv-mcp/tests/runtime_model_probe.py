#!/usr/bin/env python3
"""Drive the real Claude CLI with a local synthetic Messages API, never account credentials.

This probes the CLI's actual MCP/hook lifecycle, not the hosted model or OAuth account.
Outputs and configs live under --output; built-in tools and persistent sessions are disabled.
Add --cases channel to probe idle channels with an open synthetic JSON input stream.
"""
import argparse
import concurrent.futures
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import shutil
import shlex
import signal
import subprocess
import sys
import threading
import time

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--output", type=Path, required=True)
parser.add_argument("--fixture", type=Path, required=True)
parser.add_argument("--cases", nargs="+", default=["progress", "silent", "approval-200", "approval-50"])
args = parser.parse_args()
args.output = args.output.resolve()
args.output.mkdir(parents=True, exist_ok=True)
state = {case: 0 for case in args.cases}
lock = threading.Lock()


class Model(BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"{}")

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers.get("Content-Length", "0"))) or b"{}")
        if "count_tokens" in self.path:
            payload = b'{"input_tokens": 10}'
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
            return
        case = self.path.split("/")[1]
        names = [tool.get("name", "") for tool in body.get("tools", [])]
        first = "arm_channel" if case == "channel" else "credential_http_request" if case.startswith("approval-") else "block_" + case
        find = lambda short: next((name for name in names if name.endswith("__" + short)), None)
        selected, inputs = None, {}
        with lock:
            phase = state[case]
            if find(first):
                if phase == 0:
                    selected = find(first)
                    if case.startswith("approval-"):
                        inputs = {"type": "api_key", "name": "fixture", "purpose": "Synthetic three minute approval test", "method": "POST", "url": "https://example.test/request", "body": {"test": True}}
                elif case.startswith("approval-"):
                    result_blocks = [block for message in body.get("messages", []) if message.get("role") == "user" for block in (message.get("content") if isinstance(message.get("content"), list) else []) if block.get("type") == "tool_result"]
                    last = json.dumps(result_blocks[-1]) if result_blocks else ""
                    if "approval_pending" in last or "still_pending" in last:
                        selected = find("credential_wait_approval")
                        inputs = {"approval_id": "01J00000000000000000000000"}
                elif phase == 2:
                    selected = find("take_result")
                state[case] += 1
            directory = args.output / ("claude-local-" + case)
            with (directory / "model.jsonl").open("a") as log:
                messages = json.dumps(body.get("messages", []))
                log.write(json.dumps({"event": "model_response", "phase": phase, "selected_tool": selected, "available_tools": names, "channel_received": "Synthetic approval arrived" in messages, "original_result_received": "Synthetic original result received." in messages}) + "\n")
        message = {"id": "msg_synthetic", "type": "message", "role": "assistant", "content": [], "model": body.get("model", "synthetic"), "stop_reason": None, "stop_sequence": None, "usage": {"input_tokens": 10, "output_tokens": 1}}
        events = [{"type": "message_start", "message": message}]
        if selected:
            events.extend([
                {"type": "content_block_start", "index": 0, "content_block": {"type": "tool_use", "id": "tool_synthetic_" + str(phase), "name": selected, "input": {}}},
                {"type": "content_block_delta", "index": 0, "delta": {"type": "input_json_delta", "partial_json": json.dumps(inputs)}},
            ])
        else:
            events.extend([
                {"type": "content_block_start", "index": 0, "content_block": {"type": "text", "text": ""}},
                {"type": "content_block_delta", "index": 0, "delta": {"type": "text_delta", "text": "Synthetic probe completed."}},
            ])
        events.extend([
            {"type": "content_block_stop", "index": 0},
            {"type": "message_delta", "delta": {"stop_reason": "tool_use" if selected else "end_turn", "stop_sequence": None}, "usage": {"output_tokens": 20}},
            {"type": "message_stop"},
        ])
        payload = "".join("event: " + event["type"] + "\ndata: " + json.dumps(event) + "\n\n" for event in events).encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)


server = ThreadingHTTPServer(("127.0.0.1", 0), Model)
threading.Thread(target=server.serve_forever, daemon=True).start()


def run(case):
    directory = args.output / ("claude-local-" + case)
    directory.mkdir(exist_ok=True)
    for artifact in ("model.jsonl", "probe.jsonl", "hook.jsonl"):
        (directory / artifact).unlink(missing_ok=True)
    config_dir = directory / "user"
    config_dir.mkdir(exist_ok=True)
    approval = case.startswith("approval-")
    mcp = {"command": str(args.fixture.resolve()), "args": [], "env": {"W5_APPROVE_AFTER_S": "180", "KEYVALET_WAIT_IN_CALL_S": "200", "KEYVALET_RUNTIME_BUDGETS": json.dumps({"claude-code": int(case.split("-")[-1])})}} if approval else {"command": sys.executable, "args": [str(Path(__file__).with_name("runtime_probe.py")), "--log", str(directory / "probe.jsonl")] + (["--channels"] if case == "channel" else [])}
    (directory / "mcp.json").write_text(json.dumps({"mcpServers": {"keyvalet": mcp}}))
    hook = shlex.join([sys.executable, str(Path(__file__).with_name("runtime_hook_probe.py")), "--runtime", "claude", "--log", str(directory / "hook.jsonl")] + ([] if approval else ["--block-once"]))
    (directory / "settings.json").write_text(json.dumps({"hooks": {} if case == "channel" else {"Stop": [{"hooks": [{"type": "command", "command": hook, "timeout": 10}]}]}}))
    env = dict(os.environ)
    for name in ["ANTHROPIC_AUTH_TOKEN", "CLAUDE_CODE_OAUTH_TOKEN", "CLAUDE_CODE_USE_BEDROCK", "CLAUDE_CODE_USE_VERTEX", "CLAUDE_CODE_USE_FOUNDRY"]:
        env.pop(name, None)
    env.update(ANTHROPIC_API_KEY="synthetic-local-only", ANTHROPIC_BASE_URL=f"http://127.0.0.1:{server.server_port}/{case}", CLAUDE_CONFIG_DIR=str(config_dir), ENABLE_TOOL_SEARCH="false", DISABLE_AUTOUPDATER="1", CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC="1")
    command = [shutil.which("claude"), "--setting-sources", "", "--settings", str(directory / "settings.json"), "--strict-mcp-config", "--mcp-config", str(directory / "mcp.json"), "--tools", "", "--allowedTools", "mcp__keyvalet__*", "--no-session-persistence", "--output-format", "stream-json", "--verbose", "-p", "Use only the synthetic KeyValet MCP tools. Run the requested probe once, then receive its result; do not run shell commands or read/write files."]
    if case == "channel":
        command = command[:-1] + ["--input-format", "stream-json", "--dangerously-load-development-channels", "server:keyvalet"]
    started = time.monotonic()
    with (directory / "stdout.log").open("w") as output, (directory / "stderr.log").open("w") as errors:
        process = subprocess.Popen(command, cwd=directory, env=env, stdin=subprocess.PIPE if case == "channel" else subprocess.DEVNULL, stdout=output, stderr=errors, start_new_session=True)
        try:
            if case == "channel":
                process.stdin.write((json.dumps({"type": "user", "message": {"role": "user", "content": "Call arm_channel once, finish this turn and wait for the synthetic channel. On that channel call take_result once."}}) + "\n").encode())
                process.stdin.flush()
                status = "exited"
                while process.poll() is None and time.monotonic() - started < 45:
                    model_log = directory / "model.jsonl"
                    events = [json.loads(line) for line in model_log.read_text().splitlines()] if model_log.exists() else []
                    if any(event["channel_received"] and event["original_result_received"] for event in events):
                        time.sleep(0.5)
                        status = "channel_wake_confirmed"
                        os.killpg(process.pid, signal.SIGTERM)
                        break
                    time.sleep(0.2)
                if process.poll() is None and status != "channel_wake_confirmed":
                    status = "channel_unconfirmed"
                    os.killpg(process.pid, signal.SIGTERM)
                code = process.wait(timeout=10)
                process.stdin.close()
            else:
                code = process.wait(timeout=320)
                status = "exited"
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGTERM)
            code = process.wait(timeout=10)
            status = "supervisor_timeout"
    result = {"runtime": "claude-local-model", "version": "2.1.282", "case": case, "elapsed_s": round(time.monotonic() - started, 3), "exit_code": code, "status": status}
    (directory / "run.json").write_text(json.dumps(result, indent=2))
    print(json.dumps(result), flush=True)


with concurrent.futures.ThreadPoolExecutor(max_workers=len(args.cases)) as executor:
    list(executor.map(run, args.cases))
server.shutdown()
