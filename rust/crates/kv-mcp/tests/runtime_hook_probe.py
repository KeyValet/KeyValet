#!/usr/bin/env python3
"""Record field names only; no transcript, tool input, or credential values are logged."""

import argparse
import json
import os
import sys
import time
from pathlib import Path

parser = argparse.ArgumentParser()
parser.add_argument("--runtime", required=True)
parser.add_argument("--log", required=True)
parser.add_argument("--block-once", action="store_true")
args = parser.parse_args()
value = json.load(sys.stdin)
event = value.get("hook_event_name", value.get("hookEventName", "unknown"))
record = {"time": time.time(), "runtime": args.runtime, "event": event, "fields": sorted(value), "ppid": os.getppid()}
for name in ["stop_hook_active", "loop_count", "stopHookActive", "loopCount"]:
    if name in value:
        record[name] = value[name]
with Path(args.log).open("a") as file:
    file.write(json.dumps(record) + "\n")
marker = Path(args.log + ".blocked")
if args.block_once and not marker.exists():
    marker.write_text("blocked\n")
    reason = "Synthetic KeyValet Stop probe: call the keyvalet take_result tool once, then finish. Do not call either four-minute probe again."
    if args.runtime == "cursor":
        print(json.dumps({"followup_message": reason}))
    elif args.runtime == "gemini":
        print(json.dumps({"decision": "deny", "reason": reason}))
    else:
        print(json.dumps({"decision": "block", "reason": reason}))
else:
    print("{}")
