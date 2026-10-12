#!/usr/bin/env python3
"""A synthetic stdio MCP server for the four-minute runtime acceptance probes."""

import argparse
import json
import signal
import sys
import threading
import time
from pathlib import Path

parser = argparse.ArgumentParser()
parser.add_argument("--log", required=True)
parser.add_argument("--duration", type=float, default=240)
parser.add_argument("--channels", action="store_true")
args = parser.parse_args()
lock = threading.Lock()
started = time.monotonic()
calls = set()


def log(event, **fields):
    with lock, Path(args.log).open("a") as file:
        file.write(json.dumps({"event": event, "elapsed_s": round(time.monotonic() - started, 3), **fields}) + "\n")


def send(value):
    with lock:
        sys.stdout.write(json.dumps(value) + "\n")
        sys.stdout.flush()


def reply(request_id, value):
    send({"jsonrpc": "2.0", "id": request_id, "result": value})


def tool(request):
    params = request["params"]
    name = params["name"]
    token = params.get("_meta", {}).get("progressToken")
    log("tool_started", tool=name, progress_token=token)
    if name == "arm_channel":
        reply(request["id"], {"content": [{"type": "text", "text": "Channel armed. Finish this turn and remain idle."}], "isError": False})
        time.sleep(20)
        send({"jsonrpc": "2.0", "method": "notifications/claude/channel", "params": {"content": "Synthetic approval arrived. Call take_result once and say CHANNEL_WAKE_CONFIRMED.", "meta": {"approval_id": "01J00000000000000000000000"}}})
        log("channel_sent")
        return
    if name == "take_result":
        reply(request["id"], {"content": [{"type": "text", "text": "Synthetic original result received."}], "isError": False})
        return
    if name in calls:
        reply(request["id"], {"content": [{"type": "text", "text": "This probe was already called. Finish without retrying."}], "isError": False})
        return
    calls.add(name)
    begin = time.monotonic()
    next_progress = 15.0
    while time.monotonic() - begin < args.duration:
        elapsed = time.monotonic() - begin
        if name == "block_progress" and token is not None and elapsed >= next_progress:
            send({"jsonrpc": "2.0", "method": "notifications/progress", "params": {"progressToken": token, "progress": elapsed, "message": f"Waiting for synthetic approval ({int(elapsed)} s elapsed)"}})
            log("progress_sent", wait_s=round(elapsed, 3))
            next_progress += 15
        time.sleep(0.05)
    reply(request["id"], {"content": [{"type": "text", "text": f"PROBE_COMPLETE: {name} waited {args.duration} seconds."}], "isError": False})
    log("tool_completed", tool=name, wait_s=round(time.monotonic() - begin, 3))


def stopped(number, _frame):
    log("signal", signal=number)
    sys.exit(0)


signal.signal(signal.SIGTERM, stopped)
signal.signal(signal.SIGINT, stopped)
log("server_started")
for line in sys.stdin:
    try:
        request = json.loads(line)
        method = request.get("method")
        if method == "initialize":
            log("initialize", client_info=request["params"].get("clientInfo"), protocol=request["params"].get("protocolVersion"))
            capabilities = {"tools": {}}
            if args.channels:
                capabilities["experimental"] = {"claude/channel": {}}
            reply(request["id"], {"protocolVersion": request["params"]["protocolVersion"], "capabilities": capabilities, "serverInfo": {"name": "keyvalet", "version": "w5-probe"}})
        elif method == "tools/list":
            reply(request["id"], {"tools": [{"name": name, "description": description, "inputSchema": {"type": "object", "properties": {}}} for name, description in [("block_progress", "Block for four minutes, with progress every 15 seconds when a token is supplied."), ("block_silent", "Block for four minutes without progress."), ("arm_channel", "Schedule a synthetic approval channel after this turn finishes."), ("take_result", "Receive the synthetic approved result immediately.")]]})
        elif method == "tools/call":
            threading.Thread(target=tool, args=(request,), daemon=True).start()
        elif method == "notifications/cancelled":
            log("cancelled", params=request.get("params"))
        elif "id" in request:
            reply(request["id"], {})
    except (KeyError, ValueError) as error:
        log("invalid_request", error=str(error))
log("stdin_closed")
