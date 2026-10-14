#!/usr/bin/env python3
"""Save only KeyValet notification metadata, without other apps' notification bodies."""
import argparse
import json
import pathlib
import re
import subprocess
import time


def read_notifications(serial):
    dump = subprocess.check_output(
        ["adb", "-s", serial, "shell", "dumpsys", "notification"], text=True
    )
    records = []
    for block in re.split(r"(?=\s+NotificationRecord\()", dump):
        lines = block.splitlines()
        if not lines or not re.search(
            r"^\s*NotificationRecord\([^\n]*pkg=dev\.keyvalet\.mobile(?:\s|\))", block
        ):
            continue
        header = next(line.strip() for line in lines if "NotificationRecord(" in line)
        record = {"record": header}
        for name in ("mCreationTimeMs", "mUpdateTimeMs", "mImportance", "mSound", "mVibration", "mIntercept", "mSuppressedVisualEffects"):
            match = re.search(r"^\s*" + name + r"=([^\n]+)", block, re.MULTILINE)
            if match:
                record[name] = match.group(1).strip()
        channel = re.search(r"^\s*effectiveNotificationChannel=([^\n]+)", block, re.MULTILINE)
        if channel:
            record["channel"] = channel.group(1).strip()
        actions = re.search(r"actions=\{(.*?)\n\s*\}", block, re.DOTALL)
        if actions:
            record["actions"] = actions.group(1).strip()
        records.append(record)
    return {
        "at_unix_ms": time.time_ns() // 1_000_000,
        "package": "dev.keyvalet.mobile",
        "notifications": records,
        "notification_history": [
            line.strip() for line in dump.splitlines()
            if line.strip().startswith("StatusBarNotification(pkg=dev.keyvalet.mobile ")
        ],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=pathlib.Path)
    parser.add_argument("--serial", default="28301FDH200GY5")
    parser.add_argument("--watch-seconds", type=int, default=0)
    args = parser.parse_args()
    if not 0 <= args.watch_seconds <= 120:
        parser.error("watch duration must be between 0 and 120 seconds")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    if not args.watch_seconds:
        evidence = read_notifications(args.serial)
        args.output.write_text(json.dumps(evidence, ensure_ascii=False, indent=2) + "\n")
        print(json.dumps(evidence, ensure_ascii=False))
        return
    samples, previous = [], None
    deadline = time.monotonic() + args.watch_seconds
    print("notification_monitor_ready", flush=True)
    while time.monotonic() < deadline:
        evidence = read_notifications(args.serial)
        signature = json.dumps(evidence["notifications"], sort_keys=True)
        if signature != previous:
            previous = signature
            samples.append(evidence)
            args.output.write_text(json.dumps({"samples": samples}, ensure_ascii=False, indent=2) + "\n")
            print("notification_change at_unix_ms=" + str(evidence["at_unix_ms"]) + " count=" + str(len(evidence["notifications"])), flush=True)
        time.sleep(0.5)


if __name__ == "__main__":
    main()
