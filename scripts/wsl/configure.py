#!/usr/bin/env python3
"""Per-user WSL adapters. No vault access, elevation or installed-service dependencies here."""

import argparse
import json
import os
from pathlib import Path
import shlex
import stat
import sys
import tempfile

CLIENTS = ("claude", "codex", "cursor")
ASSETS = ("bridge.sh", "install.sh", "uninstall.sh", "configure.py", "verify.py")
MARKER = "KeyValet WSL bridge v1\n"
VARIABLES = ["KEYVALET_LANG", "KEYVALET_SESSION_TTL_MINUTES", "KEYVALET_GRANT_MODE", "KEYVALET_HOOKS"]


def read_owned(path):
    """Do not follow a configuration symlink or replace another user's file."""
    try:
        info = path.lstat()
    except FileNotFoundError:
        return None
    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid():
        raise ValueError(f"Expected a regular file owned by you: {path}")
    return path.read_text(encoding="utf-8")


def read_json(path):
    text = read_owned(path)
    try:
        value = json.loads(text) if text is not None else {}
    except ValueError:
        raise ValueError(f"Invalid JSON; configuration left unchanged: {path}") from None
    if not isinstance(value, dict):
        raise ValueError(f"Expected a JSON object: {path}")
    return value, text


def object_at(value, key, path):
    if key not in value:
        value[key] = {}
    if not isinstance(value[key], dict):
        raise ValueError(f"Expected an object for {key}: {path}")
    return value[key]


def hook_command(root, mode):
    return f"{shlex.quote(str(root / 'bin' / 'kv-hook'))} {mode}"


def merge_hooks(value, additions, path, remove=False):
    hooks = object_at(value, "hooks", path)
    for event, addition in additions.items():
        entries = hooks.get(event, [])
        if not isinstance(entries, list):
            raise ValueError(f"Expected a hook array for {event}: {path}")
        command = addition.get("command")
        if command is None:
            command = addition["hooks"][0]["command"]
        kept = []
        for entry in entries:
            if not isinstance(entry, dict):
                raise ValueError(f"Expected a hook object for {event}: {path}")
            if entry.get("command") == command:
                continue
            if "hooks" in entry:
                if not isinstance(entry["hooks"], list):
                    raise ValueError(f"Expected a handler array for {event}: {path}")
                remaining = [h for h in entry["hooks"] if not (isinstance(h, dict) and h.get("command") == command)]
                if not remaining and entry["hooks"]:
                    continue
                entry = dict(entry, hooks=remaining)
            kept.append(entry)
        if not remove:
            kept.append(addition)
        if kept:
            hooks[event] = kept
        else:
            hooks.pop(event, None)


def json_plan(path, root, kind, remove):
    value, original = read_json(path)
    if remove and original is None:
        return None
    if remove and ("mcpServers" if kind == "mcp" else "hooks") not in value:
        return None
    mcp = str(root / "bin" / "kv-mcp")
    if kind == "mcp":
        servers = object_at(value, "mcpServers", path)
        if remove:
            if isinstance(servers.get("keyvalet"), dict) and servers["keyvalet"].get("command") == mcp:
                del servers["keyvalet"]
        else:
            servers["keyvalet"] = {"command": mcp, "args": []}
    elif kind in ("claude", "codex"):
        additions = {
            "PreToolUse": {"matcher": "Bash|apply_patch|mcp__.*" if kind == "codex" else ".*",
                           "hooks": [{"type": "command", "command": hook_command(root, "codex-tool" if kind == "codex" else "tool"), "timeout": 10}]}
        }
        if kind == "claude":
            additions["UserPromptSubmit"] = {"hooks": [{"type": "command", "command": hook_command(root, "prompt"), "timeout": 10}]}
        merge_hooks(value, additions, path, remove)
    else:
        if value.get("version", 1) != 1:
            raise ValueError(f"Unsupported Cursor hooks version: {path}")
        if not remove:
            value["version"] = 1
        merge_hooks(value, {
            "beforeShellExecution": {"command": hook_command(root, "cursor-shell"), "timeout": 10},
            "beforeMCPExecution": {"command": hook_command(root, "cursor-mcp"), "timeout": 10},
            "preToolUse": {"command": hook_command(root, "cursor-tool"), "timeout": 10, "matcher": "Write|Edit|StrReplace|MultiEdit|Delete|Notebook|Create|Patch"},
        }, path, remove)
    rendered = json.dumps(value, ensure_ascii=False, indent=2) + "\n"
    # Reinstall/uninstall without changes must not reformat an unrelated existing file.
    if original is not None and json.loads(original) == value:
        return None
    return path, rendered


def codex_plan(path, root, remove):
    original = read_owned(path)
    if remove and original is None:
        return None
    command = str(root / "bin" / "kv-mcp")
    if original is None:
        return path, "[mcp_servers.keyvalet]\ncommand = " + json.dumps(command, ensure_ascii=False) + "\nenv_vars = " + json.dumps(VARIABLES) + "\n"
    # Preserve comments, quoted table names and unrelated settings with a TOML syntax tree.
    # Ubuntu 22.04's Python 3.10 is supported; this is packaged as python3-tomlkit by apt.
    try:
        import tomlkit
        from tomlkit.exceptions import TOMLKitError
    except ImportError:
        raise ValueError("Existing Codex config needs tomlkit. Install python3-tomlkit (e.g. sudo apt install python3-tomlkit), then rerun; no files were changed.") from None
    try:
        value = tomlkit.parse(original)
    except (ValueError, TOMLKitError):
        raise ValueError(f"Invalid TOML; configuration left unchanged: {path}") from None
    if "mcp_servers" not in value:
        if remove:
            return None
        value["mcp_servers"] = tomlkit.table()
    servers = value["mcp_servers"]
    if not isinstance(servers, dict):
        raise ValueError(f"Expected a table for mcp_servers: {path}")
    existing = servers.get("keyvalet")
    if remove:
        if isinstance(existing, dict) and existing.get("command") == command:
            del servers["keyvalet"]
        else:
            return None
    else:
        replacement = {"command": command, "env_vars": VARIABLES}
        if existing == replacement:
            return None
        servers["keyvalet"] = replacement
    return path, tomlkit.dumps(value)


def plans(home, root, clients, remove=False):
    result = []
    for client in clients:
        if client == "claude":
            result.extend([json_plan(home / ".claude.json", root, "mcp", remove),
                           json_plan(home / ".claude" / "settings.json", root, "claude", remove)])
        elif client == "codex":
            result.extend([codex_plan(home / ".codex" / "config.toml", root, remove),
                           json_plan(home / ".codex" / "hooks.json", root, "codex", remove)])
        else:
            result.extend([json_plan(home / ".cursor" / "mcp.json", root, "mcp", remove),
                           json_plan(home / ".cursor" / "hooks.json", root, "cursor", remove)])
    return [plan for plan in result if plan is not None]


def atomic_write(path, text, mode=0o600):
    path.parent.mkdir(parents=True, exist_ok=True)
    # Check again at the write boundary. os.replace does not follow a final symlink.
    read_owned(path)
    temporary = None
    try:
        fd, temporary = tempfile.mkstemp(prefix=".keyvalet-wsl-", dir=path.parent)
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as stream:
            os.fchmod(stream.fileno(), mode)
            stream.write(text)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if temporary is not None and os.path.exists(temporary):
            os.unlink(temporary)


def apply_plans(changes):
    for path, _ in changes:
        original = read_owned(path)
        backup = path.with_name(path.name + ".bak-keyvalet-wsl")
        previous_backup = read_owned(backup)
        if original is not None and previous_backup is None:
            atomic_write(backup, original)
    for path, rendered in changes:
        atomic_write(path, rendered)


def configure(home, source, clients, remove=False):
    home = home.absolute()
    root = home / ".local" / "share" / "keyvalet" / "wsl"
    if root.is_symlink():
        raise ValueError(f"Bridge directory must not be a symlink: {root}")
    marker = read_owned(root / ".keyvalet-wsl-managed")
    if root.exists() and marker != MARKER:
        raise ValueError(f"Bridge directory is not managed by this installer: {root}")
    # Parse all clients and check every backup before touching any config or installing files.
    changes = plans(home, root, clients, remove)
    for path, _ in changes:
        read_owned(path.with_name(path.name + ".bak-keyvalet-wsl"))
    if not remove:
        # On /mnt/c, Windows-owned protected files need not have this Linux user's uid.
        # They are source files, not per-user configuration destinations.
        assets = {}
        for name in ASSETS:
            path = source / name
            if not stat.S_ISREG(path.lstat().st_mode):
                raise ValueError("The WSL installer assets are incomplete.")
            assets[name] = path.read_text(encoding="utf-8")
        for name, text in assets.items():
            atomic_write(root / name, text)
        for name, mode in (("kv-mcp", "mcp"), ("kv-hook", "hook"), ("keyvalet", "cli")):
            atomic_write(root / "bin" / name, "#!/bin/sh\n# KeyValet WSL bridge\nexec /bin/sh " + shlex.quote(str(root / "bridge.sh")) + " " + mode + ' "$@"\n', 0o700)
        atomic_write(root / ".keyvalet-wsl-managed", MARKER)
    apply_plans(changes)
    if remove and marker == MARKER:
        for name in ASSETS + ("bin/kv-mcp", "bin/kv-hook", "bin/keyvalet"):
            path = root / name
            if read_owned(path) is not None:
                path.unlink()
        try:
            (root / "bin").rmdir()
        except OSError:
            pass  # Keep any files the user added.
        if set(path.name for path in root.iterdir()) == {".keyvalet-wsl-managed"}:
            (root / ".keyvalet-wsl-managed").unlink()
            root.rmdir()
        # Keep the marker when user files remain, so a later reinstall can reuse its
        # directory without treating those files as an unmanaged installation.
    return root, len(changes)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("install", "uninstall"))
    parser.add_argument("--source", type=Path, default=Path(__file__).parent)
    parser.add_argument("--clients", nargs="+", choices=CLIENTS, default=list(CLIENTS))
    args = parser.parse_args()
    if os.getuid() == 0:
        parser.error("Run as your regular Linux user, without sudo.")
    try:
        root, count = configure(Path.home(), args.source, args.clients, args.action == "uninstall")
    except (OSError, ValueError) as error:
        print(f"KeyValet WSL: {error}", file=sys.stderr)
        return 1
    if args.action == "install":
        print(f"Installed WSL bridge; updated {count} client files. Windows vault remains on Windows.")
        print(f"CLI: {shlex.quote(str(root / 'bin' / 'keyvalet'))} status --summary")
        if "codex" in args.clients:
            print("In Codex, run /hooks to review and trust the KeyValet hook; restart clients to load MCP.")
    else:
        print(f"Removed WSL bridge; updated {count} client files. Config backups were retained.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
