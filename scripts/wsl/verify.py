#!/usr/bin/env python3
"""Live WSL/Windows validation from a logged-in vault owner's desktop. No credential reads."""

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import platform
import queue
import subprocess
import sys
import threading
import time

sys.dont_write_bytecode = True
from configure import atomic_write


class McpProbe:
    def __init__(self, bridge):
        env = dict(os.environ, KEYVALET_GRANT_MODE="per_use", KEYVALET_SESSION_TTL_MINUTES="5")
        self.process = subprocess.Popen(["sh", str(bridge), "mcp"], stdin=subprocess.PIPE,
                                        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, env=env)
        self.messages = queue.Queue(maxsize=8)
        self.identifier = 0
        self.reader = threading.Thread(target=self._read, daemon=True)
        self.reader.start()

    def _read(self):
        try:
            while True:
                line = self.process.stdout.readline(4 * 1024 * 1024 + 1)
                if not line:
                    self.messages.put(None)
                    return
                if len(line) > 4 * 1024 * 1024:
                    raise ValueError("MCP response exceeded the probe limit.")
                message = json.loads(line)
                if not isinstance(message, dict) or message.get("jsonrpc") != "2.0":
                    raise ValueError("Non-MCP output appeared on stdout.")
                self.messages.put(message)
        except (OSError, ValueError):
            self.messages.put(ValueError("Invalid MCP stdout; check the Windows launcher/worker."))

    def send(self, method, params, notification=False, timeout=30):
        self.identifier += 1
        request = {"jsonrpc": "2.0", "method": method, "params": params}
        if not notification:
            request["id"] = self.identifier
        try:
            self.process.stdin.write((json.dumps(request, ensure_ascii=False) + "\n").encode("utf-8"))
            self.process.stdin.flush()
        except OSError:
            raise ValueError("Windows MCP launcher closed its input; check the owner desktop and service.") from None
        if notification:
            return None
        deadline = time.monotonic() + timeout
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise ValueError(f"MCP request timed out: {method}")
            try:
                reply = self.messages.get(timeout=remaining)
            except queue.Empty:
                raise ValueError(f"MCP request timed out: {method}") from None
            if reply is None:
                raise ValueError(f"Windows MCP launcher exited before replying to {method}.")
            if isinstance(reply, Exception):
                raise reply
            if reply.get("id") != self.identifier:
                if "id" in reply:
                    raise ValueError("Unexpected MCP response ID.")
                continue
            if "error" in reply or "result" not in reply:
                raise ValueError(f"MCP rejected the probe request: {method}")
            return reply["result"]

    def tool(self, name, arguments, timeout=30):
        result = self.send("tools/call", {"name": name, "arguments": arguments}, timeout=timeout)
        if not isinstance(result, dict) or result.get("isError"):
            raise ValueError(f"Tool failed or was cancelled: {name}")
        return result

    def status(self):
        result = self.tool("credential_status", {})
        for content in result.get("content", []):
            if content.get("type") == "text":
                text = content.get("text", "")
                start = text.find("{")
                if start >= 0:
                    return json.loads(text[start:])
        raise ValueError("MCP protection status did not contain its JSON report.")

    def close(self):
        if not self.process.stdin.closed:
            self.process.stdin.close()
        try:
            result = self.process.wait(timeout=15)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.wait(timeout=5)
            raise ValueError("Client EOF did not terminate the Windows launcher.") from None
        finally:
            self.reader.join(timeout=5)
            self.process.stdout.close()
        if result != 0:
            raise ValueError(f"Windows MCP launcher exited unsuccessfully after EOF ({result}).")


def verify(bridge, unlock, report):
    status = subprocess.run(["sh", str(bridge), "cli", "status"], stdout=subprocess.PIPE,
                            stderr=subprocess.DEVNULL, timeout=30)
    if status.returncode:
        raise ValueError("Cannot query authenticated Windows service status; check the Windows installation/account.")
    public = json.loads(status.stdout)
    report["provider"] = public.get("provider")
    report["checks"].append("authenticated Windows public status from WSL")

    # Enable detection for this isolated probe without changing user configuration.
    env = dict(os.environ, KEYVALET_HOOKS="on")
    fixture = {"tool_name": "Bash", "tool_input": {"command": "echo sk-proj-abcdefghijklmnopqrstuvwxyz0123456789"}}
    hook = subprocess.run(["sh", str(bridge), "hook", "codex-tool"], input=json.dumps(fixture).encode(),
                          stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, env=env, timeout=30)
    if hook.returncode != 2 or json.loads(hook.stdout).get("hookSpecificOutput", {}).get("permissionDecision") != "deny":
        raise ValueError("Native Codex hook did not deny the synthetic credential through WSL stdin/stdout.")
    report["checks"].append("native hook stdio and exit-2 deny through Windows interop")

    ttl = subprocess.run(["sh", str(bridge), "mcp"], input=b"", stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE, env=dict(os.environ, KEYVALET_SESSION_TTL_MINUTES="invalid"), timeout=30)
    if ttl.returncode == 0 or ttl.stdout.strip() or b"KEYVALET_SESSION_TTL_MINUTES" not in ttl.stderr:
        raise ValueError("Invalid session expiry was accepted; install a current-main Windows package.")
    report["checks"].append("invalid session TTL fails before MCP launch")

    probe = McpProbe(bridge)
    try:
        initialized = probe.send("initialize", {"protocolVersion": "2025-03-26", "capabilities": {},
                                               "clientInfo": {"name": "keyvalet-wsl-validation", "version": "1"}})
        if not isinstance(initialized.get("protocolVersion"), str):
            raise ValueError("MCP initialize did not negotiate a protocol.")
        probe.send("notifications/initialized", {}, notification=True)
        tools = probe.send("tools/list", {}).get("tools", [])
        names = {tool.get("name") for tool in tools}
        if not {"credential_status", "credential_unlock", "credential_lock", "credential_http_request"}.issubset(names):
            raise ValueError("The protected MCP worker did not expose the required tools.")
        report["tool_count"] = len(tools)
        report["checks"].append("protected Windows MCP worker initializes and lists tools")
        current = probe.status()
        if current.get("state") != "locked":
            raise ValueError("A new MCP connection must start locked.")
        report["checks"].append("MCP public protection status while locked")
        if unlock:
            if public.get("provider") != "windows_hello":
                raise ValueError("Complete Windows Hello vault setup before using --unlock.")
            print("Approve Windows Hello: WSL validation will unlock then immediately lock; no credential reads.", file=sys.stderr)
            probe.tool("credential_unlock", {"purpose": "验证 WSL 桥接：解锁后立即锁定，不读取凭证 / WSL validation: unlock then lock; no credential reads"}, timeout=180)
            if probe.status().get("state") != "unlocked":
                raise ValueError("Hello approval did not unlock this probe session.")
            probe.tool("credential_lock", {})
            if probe.status().get("state") != "locked":
                raise ValueError("Explicit revocation did not relock the probe session.")
            report["hello_tested"] = True
            report["checks"].append("Windows Hello unlock and explicit lock through protected MCP")
    finally:
        probe.close()
    report["checks"].append("client EOF terminates the Windows MCP launcher")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--unlock", action="store_true", help="Open one Windows Hello approval, then lock; no credential reads/writes.")
    parser.add_argument("--result", type=Path, default=Path.home() / ".local/share/keyvalet/wsl/interop-test.json")
    args = parser.parse_args()
    report = {"timestamp_utc": datetime.now(timezone.utc).isoformat(), "architecture": platform.machine(),
              "hello_tested": False, "checks": [], "passed": False, "error": None}
    try:
        verify(Path(__file__).parent / "bridge.sh", args.unlock, report)
        report["passed"] = True
    except (OSError, ValueError, subprocess.TimeoutExpired) as error:
        report["error"] = str(error)
    atomic_write(args.result, json.dumps(report, ensure_ascii=False, indent=2) + "\n")
    if report["passed"]:
        print(f"WSL Windows interop passed ({len(report['checks'])} checks). Report: {args.result}")
        return 0
    print(f"WSL validation failed: {report['error']}. Report: {args.result}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
