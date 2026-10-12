#!/usr/bin/env python3
"""Live, logged-in clients around the Rust kv-mcp Server + Appendix C FakeHelper.

The relay records the real wire metadata and exposes two fixed HTTP fixture aliases.
The silent alias suppresses progress on the wire; it does not impersonate a model.
All configurations live in a private temporary directory. No global configuration writes.
"""
import argparse
import concurrent.futures
import json
import os
from pathlib import Path
import shlex
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time


def relay(args):
    begin = time.monotonic()
    mutex = threading.Lock()
    calls = {}
    list_ids = set()

    def record(event, **fields):
        with mutex, Path(args.log).open("a") as log:
            log.write(json.dumps({"event": event, "elapsed_s": round(time.monotonic()-begin, 3), **fields})+"\n")

    env = dict(os.environ)
    env.update({"W5_APPROVE_AFTER_S": str(args.delay), "KEYVALET_WAIT_IN_CALL_S": str(args.budget),
                "KEYVALET_RUNTIME_BUDGETS": json.dumps({name: args.budget for name in
                    ["claude-code", "codex-mcp-client", "rmcp", "Cursor", "gemini-cli", "grok"]}),
                "R2D_HELPER_SOCKET": args.socket, "R2D_HELPER_LOG": args.helper_log, "KEYVALET_LANG": "en"})
    child = subprocess.Popen([args.binary], env=env, stdin=subprocess.PIPE, stdout=subprocess.PIPE)

    def upstream():
        for line in sys.stdin:
            msg = json.loads(line)
            method = msg.get("method")
            if method == "initialize":
                record("initialize", client_info=msg["params"].get("clientInfo"))
            elif method == "tools/list":
                list_ids.add(msg["id"])
            elif method == "tools/call":
                params = msg["params"]
                name = params["name"]
                calls[msg["id"]] = (name, time.monotonic())
                record("tool_started", tool=name, request_id=msg["id"], progress_token=params.get("_meta", {}).get("progressToken"))
                if name in ["r2d_block_progress", "r2d_block_silent"]:
                    params.update({"name": "credential_http_request", "arguments": {
                        "type": "api_key", "name": "fixture", "method": "POST",
                        "url": "https://example.test/request", "body": {"fixture": True},
                        "purpose": "R2-D synthetic four-minute approval experiment"}})
            elif method == "notifications/cancelled":
                record("cancelled", params=msg.get("params"))
            child.stdin.write(json.dumps(msg).encode()+b"\n")
            child.stdin.flush()
        child.stdin.close()

    threading.Thread(target=upstream, daemon=True).start()
    for line in child.stdout:
        msg = json.loads(line)
        if msg.get("id") in list_ids:
            tools = [t for t in msg["result"]["tools"] if t["name"] in ["credential_http_request", "credential_wait_approval"]]
            for kind in ["progress", "silent"]:
                tools.append({"name": "r2d_block_"+kind, "description": "Call once: a synthetic HTTP request waits four minutes for approval"+
                              (" with progress." if kind=="progress" else " without progress."),
                              "inputSchema": {"type": "object", "properties": {}}})
            msg["result"]["tools"] = tools
        if msg.get("method") == "notifications/progress":
            silent = args.kind == "silent"
            record("progress_suppressed" if silent else "progress_sent", params=msg["params"])
            if silent:
                continue
        elif msg.get("method") == "notifications/claude/channel":
            record("channel_sent", params=msg["params"])
        elif msg.get("id") in calls:
            name, started = calls[msg["id"]]
            record("tool_completed", tool=name, request_id=msg["id"], wait_s=round(time.monotonic()-started,3), result=msg.get("result"), error=msg.get("error"))
        sys.stdout.write(json.dumps(msg)+"\n")
        sys.stdout.flush()
    child.wait()


def run_case(args, runtime, kind):
    out = Path(args.output).resolve() / (runtime+"-"+kind)
    out.mkdir(parents=True, exist_ok=True)
    work = Path(tempfile.mkdtemp(prefix="kv-r2d-", dir="/tmp"))
    os.chmod(work, 0o700)
    four = kind in ["progress", "silent", "timeout-small", "timeout-large"]
    delay = 240 if four else 35
    budget = 300 if four else 10
    relay_args = [str(Path(__file__).resolve()), "relay", "--binary", str(Path(args.binary).resolve()), "--kind", kind,
                  "--log", str(out/"wire.jsonl"), "--delay", str(delay), "--budget", str(budget),
                  "--socket", str(work/"h.sock"), "--helper-log", str(out/"helper.json")]
    mcp = {"command": sys.executable, "args": relay_args}
    small = kind == "timeout-small"
    if small: mcp["timeout"] = 5000
    elif kind == "timeout-large": mcp["timeout"] = 900000
    prompt = ("This is an isolated KeyValet runtime experiment with a fake helper and no real credentials. "
              "Use only the KeyValet MCP server; do not use built-in tools, edit files or run commands. ")
    if four:
        tool = "r2d_block_silent" if kind == "silent" else "r2d_block_progress"
        prompt += f"Call {tool} exactly once with empty arguments, wait for its response, then report it and finish. Do not repeat it if it times out."
    else:
        prompt += ('Call credential_http_request once with type=api_key, name=fixture, method=POST, '
                   'url=https://example.test/request, body={"fixture":true}, purpose="R2-D synthetic approval experiment". ')
        if kind == "stop":
            prompt += "After the first response, report its status and finish the turn."
        else:
            prompt += "Complete this task using the next_steps in the tool result, then report the final result."
    hook = " ".join(shlex.quote(s) for s in [str(Path(args.hook_binary).resolve()),
        "codex-stop" if runtime=="codex" else "devin-stop", str(work/"h.sock"), str(out/"hook.jsonl")])
    if runtime == "codex":
        cmd = ["codex", "exec", "--ignore-user-config", "--skip-git-repo-check", "--ephemeral", "--sandbox", "read-only", "--json",
               "-c", "mcp_servers.keyvalet.command="+json.dumps(sys.executable), "-c", "mcp_servers.keyvalet.args="+json.dumps(relay_args),
               "-c", 'mcp_servers.keyvalet.default_tools_approval_mode="approve"',
               "-c", "features.hooks="+("true" if kind=="stop" else "false")]
        if kind in ["timeout-small", "timeout-large"]:
            cmd += ["-c", "mcp_servers.keyvalet.tool_timeout_sec="+("5" if small else "900")]
        if kind=="stop":
            cmd += ["--dangerously-bypass-hook-trust", "-c", 'hooks.Stop=[{hooks=[{type="command",command='+json.dumps(hook)+',timeout=10}]}]']
        cmd.append(prompt)
    elif runtime == "devin":
        user = json.loads((Path.home()/".config/devin/config.json").read_text())
        config = {"version": 1, "devin": {"org_id": user["devin"]["org_id"]}, "mcpServers": {"keyvalet": mcp}}
        if kind=="stop": config["hooks"] = {"Stop":[{"hooks":[{"type":"command","command":hook,"timeout":10}]}]}
        cfg = work/"devin.json"; cfg.write_text(json.dumps(config))
        cmd = ["devin", "--config", str(cfg), "--respect-workspace-trust", "false", "--permission-mode", "dangerous", "-p", prompt]
    else:
        raise ValueError(runtime)
    start=time.monotonic()
    with (out/"stdout.log").open("w") as stdout, (out/"stderr.log").open("w") as stderr:
        proc = subprocess.Popen(cmd, cwd=work, stdin=subprocess.DEVNULL, stdout=stdout, stderr=stderr, start_new_session=True)
        status = "exited"
        try: proc.wait(timeout=420 if four else 180)
        except subprocess.TimeoutExpired:
            status="supervisor_deadline";os.killpg(proc.pid, signal.SIGTERM)
            try:proc.wait(timeout=3)
            except subprocess.TimeoutExpired:os.killpg(proc.pid, signal.SIGKILL);proc.wait()
        # Reap fixture children even if a client forgot to close its stdio transport.
        try:os.killpg(proc.pid, signal.SIGTERM)
        except ProcessLookupError:pass
    result={"runtime":runtime, "kind":kind, "command":cmd, "elapsed_s":round(time.monotonic()-start,3),
            "status":status,"exit":proc.returncode, "private_config_removed":True}
    (out/"run.json").write_text(json.dumps(result,indent=2)+"\n")
    shutil.rmtree(work)
    print(json.dumps({k:v for k,v in result.items() if k!="command"}),flush=True)


if __name__ == "__main__":
    p=argparse.ArgumentParser();sub=p.add_subparsers(dest="mode",required=True)
    r=sub.add_parser("relay")
    for option in ["binary","kind","log","socket","helper-log"]:r.add_argument("--"+option, required=True)
    for option in ["delay","budget"]:r.add_argument("--"+option,type=int,required=True)
    lab=sub.add_parser("run")
    lab.add_argument("--binary",required=True);lab.add_argument("--hook-binary",required=True);lab.add_argument("--output",required=True)
    lab.add_argument("--runtimes",nargs="+",default=["codex","devin"])
    lab.add_argument("--kinds",nargs="+",default=["progress","silent","pending","stop","timeout-small"])
    args=p.parse_args()
    if args.mode=="relay":relay(args)
    else:
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
            futures=[pool.submit(run_case,args,r,k) for r in args.runtimes for k in args.kinds]
            for f in concurrent.futures.as_completed(futures):f.result()
