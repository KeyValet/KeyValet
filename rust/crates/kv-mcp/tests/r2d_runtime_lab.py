#!/usr/bin/env python3
"""Live, logged-in clients around the Rust kv-mcp Server + Appendix C FakeHelper.

The Rust fixture records wire metadata and exposes two fixed HTTP aliases.
The silent alias deliberately sends no progress; it does not impersonate a model.
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
import time


def run_case(args, runtime, kind):
    out = Path(args.output).resolve() / (runtime+"-"+kind)
    out.mkdir(parents=True, exist_ok=True)
    work = Path(tempfile.mkdtemp(prefix="kv-r2d-", dir="/tmp"))
    os.chmod(work, 0o700)
    four = kind in ["progress", "silent", "timeout-small", "timeout-large"]
    delay = 240 if four else 35
    budget = 300 if four else 10
    fixture_env = {"W5_APPROVE_AFTER_S": str(delay), "KEYVALET_WAIT_IN_CALL_S": str(budget),
                   "KEYVALET_RUNTIME_BUDGETS": json.dumps({name: budget for name in
                    ["claude-code", "codex-mcp-client", "rmcp", "Cursor", "gemini-cli", "grok"]}),
                   "R2D_HELPER_SOCKET": str(work/"h.sock"), "R2D_HELPER_LOG": str(out/"helper.json"),
                   "R2D_WIRE_LOG": str(out/"wire.jsonl"), "KEYVALET_LANG": "en"}
    mcp = {"command": str(Path(args.binary).resolve()), "args": [], "env": fixture_env}
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
               "-c", "mcp_servers.keyvalet.command="+json.dumps(mcp["command"]), "-c", "mcp_servers.keyvalet.args=[]",
               "-c", 'mcp_servers.keyvalet.default_tools_approval_mode="approve"',
               "-c", "features.hooks="+("true" if kind=="stop" else "false")]
        for key,value in fixture_env.items():
            cmd += ["-c", "mcp_servers.keyvalet.env."+key+"="+json.dumps(value)]
        if kind in ["timeout-small", "timeout-large"]:
            cmd += ["-c", "mcp_servers.keyvalet.tool_timeout_sec="+("5" if small else "900")]
        if kind=="stop":
            cmd += ["--dangerously-bypass-hook-trust", "-c", 'hooks.Stop=[{hooks=[{type="command",command='+json.dumps(hook)+',timeout=10}]}]']
        cmd.append(prompt)
    elif runtime == "devin":
        user = json.loads((Path.home()/".config/devin/config.json").read_text())
        config = {"version": 1, "devin": {"org_id": user["devin"]["org_id"]}}
        # Current Devin keeps MCP configuration separately from --config. Override
        # the imported real server at project scope with an inert entry and use a
        # unique fixture name, so an accidental name lookup cannot reach the vault.
        (work/".devin").mkdir()
        (work/".devin/mcp_config.json").write_text(json.dumps({"mcpServers": {
            **{name: {"disabled": True} for name in json.loads((Path.home()/".config/devin/mcp_config.json").read_text()).get("mcpServers", {})}, "r2dprobe": mcp}}))
        prompt = prompt.replace("KeyValet MCP server", "r2dprobe MCP server").replace("only the KeyValet", "only r2dprobe")
        prompt = "Use only MCP server r2dprobe, never server keyvalet. "+prompt
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
    lab=sub.add_parser("run")
    lab.add_argument("--binary",required=True);lab.add_argument("--hook-binary",required=True);lab.add_argument("--output",required=True)
    lab.add_argument("--runtimes",nargs="+",default=["codex","devin"])
    lab.add_argument("--kinds",nargs="+",default=["progress","silent","pending","stop","timeout-small"])
    args=p.parse_args()
    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:
        futures=[pool.submit(run_case,args,r,k) for r in args.runtimes for k in args.kinds]
        for f in concurrent.futures.as_completed(futures):f.result()
