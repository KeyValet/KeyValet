#!/usr/bin/env python3
"""Read-only installed-device diagnostics; stdout is a metadata allowlist.

Run as the owner first, or with sudo in the owner's GUI terminal to include
root-only audit tails and authenticated installed-CLI status. Never starts a
pairing, opens a credential session, signs, or requests a native dialog.
"""
import datetime
import hashlib
import json
import os
from pathlib import Path
import plistlib
import re
import subprocess


def command(args, timeout=45):
    started = datetime.datetime.now(datetime.timezone.utc)
    try:
        process = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
        return process, round((datetime.datetime.now(datetime.timezone.utc)-started).total_seconds(), 3)
    except subprocess.TimeoutExpired:
        return None, timeout


report = {"observed_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
          "uid": os.geteuid(), "touch_id_requests": 0, "services": {},
          "signatures": {}, "audit": {}, "cli": {}}
for domain, label in [("system", "helper"), ("gui/501", "agent"), ("gui/501", "relay")]:
    process, elapsed = command(["/bin/launchctl", "print", f"{domain}/dev.keyvalet.{label}"])
    fields = [line.strip() for line in process.stdout.splitlines()
              if re.match(r"\s*(state|program|pid|runs|last exit code|last terminating signal) =", line)] if process else []
    report["services"][label] = {"exit": process.returncode if process else None,
                                 "elapsed_s": elapsed, "fields": fields}
    plist = Path(f"/Library/Launch{'Daemons' if label=='helper' else 'Agents'}/dev.keyvalet.{label}.plist")
    with plist.open("rb") as stream:
        data = plistlib.load(stream)
    report["services"][label]["gui_session"] = data.get("LimitLoadToSessionType")
    report["services"][label]["stderr_path"] = data.get("StandardErrorPath")

for binary, identifier in [("kv-cli", "cli"), ("kv-helper", "helper"),
                           ("kv-touchid", "touchid"), ("kv-relay-client", "relay-client")]:
    path = Path("/usr/local/lib/keyvalet/bin") / binary
    requirement = f'=identifier "dev.keyvalet.{identifier}" and anchor apple generic and certificate leaf[subject.OU] = "PWCRJPY7YC"'
    process, elapsed = command(["/usr/bin/codesign", "--verify", "--strict", "-R", requirement, str(path)])
    report["signatures"][binary] = {"exit": process.returncode if process else None,
                                   "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                                   "elapsed_s": elapsed}

process, elapsed = command(["/usr/bin/log", "show", "--predicate", 'subsystem CONTAINS "keyvalet"',
                           "--last", "2h", "--style", "json"])
try:
    entries = json.loads(process.stdout) if process else []
except ValueError:
    entries = []
events = []
for entry in entries:
    message = entry.get("eventMessage", "")
    # These are launchd lifecycle facts, not arbitrary daemon/request text.
    if re.match(r"(service state:|exited due to|signaled service:|internal event:|Successfully spawned|bootout initiated by:)", message):
        events.append({"timestamp": entry.get("timestamp"), "subsystem": entry.get("subsystem"), "message": message})
report["unified_log"] = {"exit": process.returncode if process else None, "elapsed_s": elapsed,
                         "events_n": len(entries), "lifecycle_events": events}

for path in [Path("/var/db/keyvalet/audit.log"), Path("/var/db/keyvalet/remote/audit.log")]:
    try:
        with path.open("rb") as stream:
            stream.seek(0, 2)
            size = stream.tell()
            stream.seek(max(0, size-1024*1024))
            lines = stream.read().splitlines()
        events = []
        for line in lines:
            try:
                entry = json.loads(line)
            except ValueError:
                continue
            event = {key: entry[key] for key in ["timestamp", "time", "ts", "ok", "remote_op", "op"] if key in entry}
            reason = entry.get("reason")
            if isinstance(reason, str) and re.fullmatch(r"[a-z_:-]{1,128}", reason):
                event["reason"] = reason
            events.append(event)
        report["audit"][str(path)] = {"bytes": size, "events": events[-100:]}
    except OSError as error:
        report["audit"][str(path)] = {"error_kind": type(error).__name__}

if os.geteuid() == 0:
    for name, args in [("status", ["status", "--json"]), ("devices", ["devices", "list", "--json"])]:
        process, elapsed = command(["/usr/local/lib/keyvalet/bin/kv-cli", *args], timeout=150)
        item = {"exit": process.returncode if process else None, "elapsed_s": elapsed}
        try:
            value = json.loads(process.stdout) if process else {}
            if value.get("ok") is False:
                item["error_code"] = value.get("error", {}).get("code")
            else:
                item["ok"] = value.get("ok")
                output = value.get("output", value)
                item["output_kind"] = output.get("command")
                output = output.get("result", {})
                # Whitelist counts and public state only; never persist an opaque CLI object.
                item["state"] = {key: output[key] for key in ["relay", "pending_n", "grants_n", "unattended", "remote_error"] if key in output}
                if name == "status":
                    remote = output.get("remote") or {}
                    item["state"].update({key: remote[key] for key in ["relay", "pending_n", "grants_n", "unattended"] if key in remote})
                    error = output.get("remote_error") or {}
                    item["state"]["remote_error"] = error.get("code")
                if name == "devices":
                    item["devices"] = [{key: device[key] for key in ["device_id", "label", "os", "key_kind", "caps", "revoked"] if key in device}
                                       for device in output.get("devices", [])]
        except (ValueError, TypeError):
            item["error_code"] = "non_json_output"
        report["cli"][name] = item
else:
    report["cli"]["skip"] = "root_required_by_installed_cli"
print(json.dumps(report, ensure_ascii=False, indent=2))
