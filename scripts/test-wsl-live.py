#!/usr/bin/env python3
"""No-Hello live interop test, inside a disposable WSL distro with Windows KeyValet installed.

This tests native CLI/hooks, TTL refusal and per-user installation. A headless CI account
cannot establish the protected owner desktop, so MCP initialization/Hello use wsl/verify.py.
"""

import json
import os
from pathlib import Path
import subprocess
import sys


def run(args, data=b"", env=None, expected=0):
    result = subprocess.run(args, input=data, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            env=env, timeout=30)
    if result.returncode != expected:
        raise RuntimeError(f"Unexpected exit code {result.returncode} for {args[0]}")
    return result


def main():
    if os.getuid() == 0:
        raise RuntimeError("Run the live WSL test as the disposable standard Linux user.")
    source = Path(run(["wslpath", "-u", r"C:\Program Files\KeyValet\wsl"]).stdout.decode().strip())
    bridge = ["sh", str(source / "bridge.sh")]
    public = json.loads(run(bridge + ["cli", "status"]).stdout)
    if public.get("provider") != "uninitialized":
        raise RuntimeError("This no-Hello disposable test requires the clean test vault.")
    fixture = {"tool_name": "Bash", "tool_input": {"command": "echo sk-proj-abcdefghijklmnopqrstuvwxyz0123456789"}}
    encoded = json.dumps(fixture).encode()
    denied = json.loads(run(bridge + ["hook", "codex-tool"], encoded,
                            dict(os.environ, KEYVALET_HOOKS="on", KEYVALET_LANG="zh"), expected=2).stdout)
    if denied.get("hookSpecificOutput", {}).get("permissionDecision") != "deny":
        raise RuntimeError("Windows Codex hook did not deny the fixture through WSL interop.")
    bypassed = run(bridge + ["hook", "codex-tool"], encoded, dict(os.environ, KEYVALET_HOOKS="off"))
    if bypassed.stdout:
        raise RuntimeError("WSLENV did not forward the explicit hook-off setting.")
    allowed = json.loads(run(bridge + ["hook", "cursor-shell"], json.dumps({"command": "echo 中文测试"}, ensure_ascii=False).encode(),
                             dict(os.environ, KEYVALET_HOOKS="on")).stdout)
    if allowed.get("permission") != "allow":
        raise RuntimeError("Native Cursor hook did not allow the harmless Unicode fixture.")
    invalid = subprocess.run(bridge + ["mcp"], input=b"", stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                             env=dict(os.environ, KEYVALET_SESSION_TTL_MINUTES="invalid"), timeout=30)
    if invalid.returncode == 0 or invalid.stdout.strip() or b"KEYVALET_SESSION_TTL_MINUTES" not in invalid.stderr:
        raise RuntimeError("Native Windows launcher did not reject invalid expiry through WSLENV.")

    home = Path.home()
    if any((home / name).exists() for name in (".claude.json", ".claude", ".codex", ".cursor", ".local/share/keyvalet/wsl")):
        raise RuntimeError("Use a fresh disposable Linux account without existing client configurations.")
    (home / ".claude.json").write_text('{"mcpServers":{"other":{"command":"keep-me"}}}', encoding="utf-8")
    run(["sh", str(source / "install.sh")])
    installed = home / ".local/share/keyvalet/wsl"
    wrapped = json.loads(run([str(installed / "bin/keyvalet"), "status"]).stdout)
    if wrapped.get("provider") != "uninitialized":
        raise RuntimeError("Installed WSL wrapper did not reach authenticated Windows status.")
    for directory in (".claude", ".codex", ".cursor"):
        if not (home / directory).is_dir():
            raise RuntimeError("WSL client configuration was not installed.")
    before = (home / ".codex/config.toml").read_bytes()
    run(["sh", str(source / "install.sh")])
    if (home / ".codex/config.toml").read_bytes() != before:
        raise RuntimeError("Reinstall changed the already-current Codex config.")
    run(["sh", str(installed / "uninstall.sh")])
    restored = json.loads((home / ".claude.json").read_text())
    if restored != {"mcpServers": {"other": {"command": "keep-me"}}} or installed.exists():
        raise RuntimeError("WSL uninstall did not preserve unrelated config and remove its files.")
    print("Live WSL interop passed: authenticated CLI, native hook stdio/deny/Unicode, WSLENV, TTL refusal, client install/reinstall/uninstall. No Hello or desktop MCP tested.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
