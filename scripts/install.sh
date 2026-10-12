#!/bin/sh
# Installs KeyValet. Runs as a regular user; steps that need privileges go through sudo (prompts for a password).
#
# Layout after install (all root:wheel, not writable by a regular user / AI agent):
#   /usr/local/lib/keyvalet/bin/kv-helper   root helper (Touch ID gated): launchd daemon at
#                                           /var/run/keyvalet/helper.sock when signed for our
#                                           team (PWCRJPY7YC), else the sudo -n fallback
#   /usr/local/lib/keyvalet/bin/kv-touchid  Touch ID authentication helper (also the per-user
#                                           LaunchAgent dev.keyvalet.agent in daemon mode)
#   /usr/local/lib/keyvalet/bin/kv-touchid  Touch ID authentication helper (hardened runtime signature)
#   /usr/local/lib/keyvalet/bin/kv-mcp      MCP server (runs unprivileged, one process per AI session)
#   /usr/local/lib/keyvalet/bin/kv-cli      terminal management CLI (runs as root via sudo)
#   /usr/local/lib/keyvalet/bin/kv-hook     secret-detection hook for AI runtimes (Claude Code, Codex), runs unprivileged
#   /usr/local/lib/keyvalet/templates/      bundled credential template catalog
#   /usr/local/bin/keyvalet                 wrapper script that execs kv-cli via sudo
#   /var/db/keyvalet/                       the encrypted credential vault (0700)
#   /var/run/keyvalet/                      daemon + agent Unix sockets (daemon mode)
#   /Library/LaunchDaemons/dev.keyvalet.helper.plist / /Library/LaunchAgents/dev.keyvalet.agent.plist
#   /etc/sudoers.d/keyvalet                 lets only the current user run the helper passwordlessly (it still requires Touch ID once started)
#
# Upgrading from the pre-rename credential-mcp: automatically migrates /var/db/credential-mcp to /var/db/keyvalet and removes the old install.
set -eu

# This mode also provides an installation-free configuration test boundary.
kv_runtime_config() {
  python3 - "$@" <<'KV_RUNTIME_PY'
import argparse
import copy
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import tempfile

parser = argparse.ArgumentParser()
parser.add_argument("action", choices=("install", "remove"))
parser.add_argument("--home", type=Path, default=Path.home())
parser.add_argument("--project", type=Path)
parser.add_argument("--bin", type=Path, default=Path("/usr/local/lib/keyvalet/bin"))
parser.add_argument("--detected", default="")
args = parser.parse_args()
home = args.home.absolute()
project = args.project.absolute() if args.project else None
state_path = home / ".keyvalet/remote-runtime-state.json"
pending = {}

def safe(path):
    for parent in (path, *path.parents):
        if parent.is_symlink():
            raise ValueError("unsafe configuration link")
    if path.exists() and (not path.is_file() or path.stat().st_uid != os.getuid()):
        raise ValueError("unsafe configuration owner or type")

def read(path):
    safe(path)
    if path.exists():
        if path.stat().st_size > 4 * 1024 * 1024:
            raise ValueError("configuration too large")
        return path.read_text(encoding="utf-8")
    return ""

def pairs(items):
    result = {}
    for key, value in items:
        if key in result:
            raise ValueError("duplicate configuration key")
        result[key] = value
    return result

def load_json(path):
    value = json.loads(read(path) or "{}", object_pairs_hook=pairs)
    if not isinstance(value, dict):
        raise ValueError("configuration must be an object")
    return value

def plan_json(path, value):
    text = json.dumps(value, indent=2, ensure_ascii=False) + "\n"
    if text != read(path):
        pending[path] = text

def table(value, key):
    child = value.setdefault(key, {})
    if not isinstance(child, dict):
        raise ValueError("configuration table must be an object")
    return child

def atomic(path, text):
    safe(path)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, name = tempfile.mkstemp(prefix=".keyvalet-config-", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            stream.write(text)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(name, path)
    finally:
        if os.path.exists(name):
            os.unlink(name)

def toml_load(text):
    try:
        import tomllib
        return tomllib.loads(text)
    except ImportError:
        try:
            import tomlkit
            return tomlkit.parse(text).unwrap()
        except ImportError:
            raise ValueError("TOML configuration requires Python 3.11+ or tomlkit") from None

def header_path(header):
    value = toml_load(header + "\n__keyvalet_probe__ = 1\n")
    keys = []
    while isinstance(value, dict) and "__keyvalet_probe__" not in value:
        if len(value) != 1:
            return ()
        key, value = next(iter(value.items()))
        keys.append(key)
    return tuple(keys)

def toml_update(path, remove, entry):
    original = read(path)
    before = toml_load(original)
    lines = original.splitlines(keepends=True)
    if lines and not lines[-1].endswith("\n"):
        lines[-1] += "\n"
    headers = []
    for index, line in enumerate(lines):
        if re.match(r"^\s*\[", line):
            headers.append((index, header_path(line.strip())))
    servers = before.get("mcp_servers", {})
    if not isinstance(servers, dict):
        raise ValueError("invalid MCP TOML table")
    existing = servers.get("keyvalet")
    if existing is not None and not isinstance(existing, dict):
        raise ValueError("invalid KeyValet TOML table")
    section = next((i for i, keys in headers if keys == ("mcp_servers", "keyvalet")), None)
    if existing is not None and section is None:
        # Preserve inline/commented TOML exactly when the existing WSL dependency is present.
        try:
            import tomlkit
        except ImportError:
            raise ValueError("inline KeyValet TOML requires tomlkit; original file retained") from None
        document = tomlkit.parse(original)
        current = document["mcp_servers"]["keyvalet"]
        if remove:
            if entry.get("created"):
                del document["mcp_servers"]["keyvalet"]
            elif current.get("tool_timeout_sec") == 900:
                if entry.get("had_timeout"):
                    current["tool_timeout_sec"] = entry["timeout"]
                else:
                    current.pop("tool_timeout_sec", None)
        else:
            current["tool_timeout_sec"] = 900
        changed = tomlkit.dumps(document)
    elif section is None:
        if remove:
            return
        changed = original.rstrip() + "\n\n[mcp_servers.keyvalet]\ncommand = " + json.dumps(str(args.bin / "kv-mcp")) + "\nargs = []\ntool_timeout_sec = 900\n"
    else:
        end = next((i for i, _ in headers if i > section), len(lines))
        timeout = [i for i in range(section + 1, end) if re.match(r'^\s*(?:tool_timeout_sec|"tool_timeout_sec"|\'tool_timeout_sec\')\s*=', lines[i])]
        if remove and entry.get("created"):
            ranges = [(i, next((j for j, _ in headers if j > i), len(lines))) for i, keys in headers if keys[:2] == ("mcp_servers", "keyvalet")]
            for start, stop in reversed(ranges):
                del lines[start:stop]
        elif not remove or existing.get("tool_timeout_sec") == 900:
            if timeout:
                del lines[timeout[0]]
                end -= 1
            if not remove:
                lines.insert(end, "tool_timeout_sec = 900\n")
            elif entry.get("had_timeout"):
                lines.insert(end, "tool_timeout_sec = " + json.dumps(entry["timeout"]) + "\n")
        changed = "".join(lines)
    after = toml_load(changed)
    expected = copy.deepcopy(before)
    target = expected.setdefault("mcp_servers", {})
    if remove:
        if entry.get("created"):
            target.pop("keyvalet", None)
            if not target and "mcp_servers" not in after:
                expected.pop("mcp_servers", None)
        elif isinstance(target.get("keyvalet"), dict) and target["keyvalet"].get("tool_timeout_sec") == 900:
            if entry.get("had_timeout"):
                target["keyvalet"]["tool_timeout_sec"] = entry["timeout"]
            else:
                target["keyvalet"].pop("tool_timeout_sec", None)
    else:
        current = target.setdefault("keyvalet", {"command": str(args.bin / "kv-mcp"), "args": []})
        current["tool_timeout_sec"] = 900
    if after != expected:
        raise ValueError("TOML update would change unrelated configuration")
    if changed != original:
        pending[path] = changed

def strip_hooks(rows, commands):
    if not isinstance(rows, list):
        raise ValueError("hook event must be an array")
    kept = []
    for row in rows:
        if not isinstance(row, dict):
            raise ValueError("hook row must be an object")
        if row.get("command") in commands:
            continue
        item = copy.deepcopy(row)
        if "hooks" in item:
            nested = item["hooks"]
            if not isinstance(nested, list) or any(not isinstance(h, dict) for h in nested):
                raise ValueError("invalid nested hook array")
            item["hooks"] = [h for h in nested if h.get("command") not in commands]
            if not item["hooks"]:
                continue
        kept.append(item)
    return kept

try:
    state = load_json(state_path)
    records = table(state, "files")
    if args.action == "remove":
        for name, entry in list(records.items()):
            path = Path(name)
            if not path.exists():
                continue
            if entry["format"] == "toml":
                toml_update(path, True, entry)
                continue
            value = load_json(path)
            if entry.get("server") and isinstance(value.get("mcpServers"), dict):
                server = value["mcpServers"].get("keyvalet")
                if isinstance(server, dict):
                    if entry.get("created"):
                        del value["mcpServers"]["keyvalet"]
                    elif server.get("timeout") == 900000:
                        if entry.get("had_timeout"):
                            server["timeout"] = entry["timeout"]
                        else:
                            server.pop("timeout", None)
            if entry.get("event") and isinstance(value.get("hooks"), dict):
                event = entry["event"]
                if event in value["hooks"]:
                    value["hooks"][event] = strip_hooks(value["hooks"][event], entry["commands"])
                    if not value["hooks"][event]:
                        del value["hooks"][event]
            plan_json(path, value)
    else:
        specified = set(filter(None, args.detected.split(",")))
        def detected(name, *paths):
            return name in specified if specified else any(path.exists() for path in paths) or shutil.which(name) is not None
        def server(path, timed=True):
            value = load_json(path)
            servers = table(value, "mcpServers")
            current = servers.get("keyvalet")
            if current is not None and not isinstance(current, dict):
                raise ValueError("KeyValet MCP entry must be an object")
            record = records.setdefault(str(path), {"format":"json", "server":True, "created":current is None, "had_timeout":current is not None and "timeout" in current})
            if current is not None and "timeout" in current and "timeout" not in record:
                record["timeout"] = current["timeout"]
            current = servers.setdefault("keyvalet", {"command":str(args.bin / "kv-mcp"), "args":[]})
            if timed:
                current["timeout"] = 900000
            plan_json(path, value)
        def hook(path, event, mode, cursor=False):
            value = load_json(path)
            hooks = table(value, "hooks")
            command = shlex.quote(str(args.bin / "kv-hook")) + " " + mode
            rows = strip_hooks(hooks.get(event, []), [command])
            action = {"type":"command", "command":command, "timeout":10}
            rows.append({"command":command, "timeout":10} if cursor else {"hooks":[action]})
            hooks[event] = rows
            if cursor:
                value.setdefault("version", 1)
            records[str(path)] = {"format":"json", "event":event, "commands":[command]}
            plan_json(path, value)
        if detected("claude", home / ".claude", home / ".claude.json"):
            server(home / ".claude.json")
            hook(home / ".claude/settings.json", "Stop", "claude-stop")
            if project and (project / ".mcp.json").exists():
                server(project / ".mcp.json")
        for runtime in ("codex", "grok"):
            if detected(runtime, home / ("." + runtime)):
                path = home / ("." + runtime) / "config.toml"
                before = toml_load(read(path))
                current = before.get("mcp_servers", {}).get("keyvalet")
                record = records.setdefault(str(path), {"format":"toml", "created":current is None, "had_timeout":current is not None and "tool_timeout_sec" in current})
                if current is not None and "tool_timeout_sec" in current and "timeout" not in record:
                    record["timeout"] = current["tool_timeout_sec"]
                toml_update(path, False, record)
                if runtime == "codex":
                    hook(home / ".codex/hooks.json", "Stop", "codex-stop")
        if detected("cursor", home / ".cursor"):
            hook(home / ".cursor/hooks.json", "stop", "cursor-stop", True)
        if detected("gemini", home / ".gemini"):
            path = home / ".gemini/settings.json"
            server(path)
            # Merge the staged server entry when the hook shares settings.json.
            value = json.loads(pending.get(path, read(path) or "{}"))
            command = shlex.quote(str(args.bin / "kv-hook")) + " gemini-after-agent"
            hooks = table(value, "hooks")
            hooks["AfterAgent"] = strip_hooks(hooks.get("AfterAgent", []), [command]) + [{"hooks":[{"type":"command", "name":"keyvalet-approval", "command":command, "timeout":10000}]}]
            records[str(path)].update(event="AfterAgent", commands=[command])
            plan_json(path, value)
        if detected("devin", home / ".config/devin", home / ".devin"):
            hook(home / ".config/devin/config.json", "Stop", "devin-stop")
        # Save restoration metadata before changing user files, including interrupted installs.
        atomic(state_path, json.dumps(state, indent=2) + "\n")
    for path, text in pending.items():
        if path.exists():
            backup = Path(str(path) + ".bak-keyvalet-remote")
            if not backup.exists():
                atomic(backup, read(path))
        atomic(path, text)
    if args.action == "remove" and state_path.exists():
        state_path.unlink()
    print("KeyValet runtime configuration " + args.action + ": " + str(len(pending)) + " files")
except (OSError, ValueError, TypeError, KeyError, AttributeError):
    raise SystemExit("Cannot update KeyValet runtime configuration; originals retained where validation failed.") from None
KV_RUNTIME_PY
}

if [ "${1:-}" = --runtime-config ]; then
  shift
  kv_runtime_config "$@"
  exit
fi

KV_PROJECT_DIR=$(pwd)

kv_remote_linux() {
  KV_SOURCE=$(cd "$(dirname "$0")/.." && pwd)
  if [ -x "$KV_SOURCE/bin/kv-relay-client" ] && [ ! -d "$KV_SOURCE/rust" ]; then
    KV_REMOTE_BIN="$KV_SOURCE/bin"
    KV_CLIENT_ASSETS="$KV_SOURCE/service/relay-client"
  else
    case "${CARGO_TARGET_DIR:-target}" in
      /*) KV_REMOTE_BIN="$CARGO_TARGET_DIR/release" ;;
      *) KV_REMOTE_BIN="$KV_SOURCE/rust/${CARGO_TARGET_DIR:-target}/release" ;;
    esac
    KV_CLIENT_ASSETS="$KV_SOURCE/rust/crates/kv-relay-client/service"
  fi
  for binary in kv-server kv-relay-client; do
    [ -x "$KV_REMOTE_BIN/$binary" ] || { echo "Missing remote approval binary: $binary" >&2; return 1; }
  done
  [ -f "$KV_CLIENT_ASSETS/keyvalet-relay.service" ] || { echo "Missing relay-client service template" >&2; return 1; }
  [ -f "$KV_SOURCE/deploy/relay/keyvalet-relay.service" ] || { echo "Missing relay-server service template" >&2; return 1; }
  KV_REMOTE_STAGE=$(mktemp -d)
  cp "$KV_REMOTE_BIN/kv-server" "$KV_REMOTE_BIN/kv-relay-client" "$KV_REMOTE_STAGE/"
  cp "$KV_CLIENT_ASSETS/keyvalet-relay.service" "$KV_REMOTE_STAGE/client.service"
  # Server and client cannot share a StateDirectory owned by different service users.
  sed -e "s@/usr/local/lib/keyvalet/kv-server@/usr/local/lib/keyvalet/bin/kv-server@g" \
      -e "s@/var/lib/keyvalet-relay@/var/lib/keyvalet-relay-server@g" \
      -e "s@StateDirectory=keyvalet-relay\$@StateDirectory=keyvalet-relay-server@" \
      "$KV_SOURCE/deploy/relay/keyvalet-relay.service" > "$KV_REMOTE_STAGE/server.service"
  cp "$KV_SOURCE/deploy/relay/nginx.conf.template" "$KV_REMOTE_STAGE/nginx.conf.template"
  KV_SERVER_RESTART=0
  if systemctl is-active --quiet keyvalet-relay-server.service; then KV_SERVER_RESTART=1; fi
  sudo /bin/sh -eu -c '
    STAGE="$1"; OWNER_UID="$2"; SERVER_WAS_ACTIVE="$3"
    for directory in /etc/keyvalet /etc/systemd/system /etc/ssl/keyvalet-relay /var/lib/keyvalet-relay /var/lib/keyvalet-relay-server /usr/local/lib/keyvalet/bin; do
      [ ! -L "$directory" ] || { echo "Refusing remote installation symlink" >&2; exit 1; }
    done
    for account in keyvalet-relay keyvalet-relay-server; do
      if ! getent passwd "$account" >/dev/null; then
        /usr/sbin/useradd --system --user-group --home-dir "/var/lib/$account" --no-create-home --shell /usr/sbin/nologin "$account"
      fi
      SERVICE_UID=$(id -u "$account")
      [ "$SERVICE_UID" -gt 0 ] && [ "$SERVICE_UID" -lt 1000 ] || { echo "Relay account must be a system user" >&2; exit 1; }
      getent passwd "$account" | grep -Eq ":(/usr/sbin/nologin|/sbin/nologin|/bin/false)$" || { echo "Relay account must have a non-login shell" >&2; exit 1; }
      if [ -d "/var/lib/$account" ]; then
        [ "$(stat -c %u "/var/lib/$account")" = "$SERVICE_UID" ] || { echo "Relay state has an unexpected owner" >&2; exit 1; }
      else
        install -d -o "$account" -g "$account" -m 0700 "/var/lib/$account"
      fi
    done
    systemctl stop keyvalet-relay.service 2>/dev/null || true
    systemctl stop keyvalet-relay-server.service 2>/dev/null || true
    install -o root -g root -m 0755 "$STAGE/kv-relay-client" "$STAGE/kv-server" /usr/local/lib/keyvalet/bin/
    ln -sfn bin/kv-server /usr/local/lib/keyvalet/kv-server
    install -o root -g root -m 0644 "$STAGE/client.service" /etc/systemd/system/keyvalet-relay.service
    if [ -e /etc/systemd/system/keyvalet-relay-server.service ]; then
      [ -f /etc/systemd/system/keyvalet-relay-server.service ] && [ ! -L /etc/systemd/system/keyvalet-relay-server.service ] && [ "$(stat -c %u /etc/systemd/system/keyvalet-relay-server.service)" = 0 ] || { echo "Untrusted relay-server unit" >&2; exit 1; }
    else
      install -o root -g root -m 0644 "$STAGE/server.service" /etc/systemd/system/keyvalet-relay-server.service
    fi
    install -d -o root -g root -m 0700 /etc/ssl/keyvalet-relay
    install -d -o root -g root -m 0755 /usr/local/lib/keyvalet/relay
    install -o root -g root -m 0644 "$STAGE/nginx.conf.template" /usr/local/lib/keyvalet/relay/nginx.conf.template
    if [ -e /etc/keyvalet/relay-client.toml ]; then
      [ -f /etc/keyvalet/relay-client.toml ] && [ ! -L /etc/keyvalet/relay-client.toml ] && [ "$(stat -c %u /etc/keyvalet/relay-client.toml)" = 0 ] || { echo "Untrusted relay-client configuration" >&2; exit 1; }
      chown root:keyvalet-relay /etc/keyvalet/relay-client.toml
      chmod 0640 /etc/keyvalet/relay-client.toml
    fi
    systemctl daemon-reload
    # The helper creates the dedicated socket only after the relay UID exists.
    systemctl restart keyvalet.service
    if [ -f /etc/keyvalet/relay-client.toml ]; then
      [ ! -L /etc/keyvalet/relay-client.toml ] && [ "$(stat -c %u /etc/keyvalet/relay-client.toml)" = 0 ] || { echo "Untrusted relay-client configuration" >&2; exit 1; }
      chown root:keyvalet-relay /etc/keyvalet/relay-client.toml
      chmod 0640 /etc/keyvalet/relay-client.toml
    fi
    systemctl enable keyvalet-relay.service
    # The control worker must run before pairing creates the first authenticated binding.
    systemctl start keyvalet-relay.service
    if [ "$SERVER_WAS_ACTIVE" = 1 ]; then systemctl start keyvalet-relay-server.service; fi
  ' sh "$KV_REMOTE_STAGE" "$(id -u)" "$KV_SERVER_RESTART"
  rm -rf "$KV_REMOTE_STAGE"
  echo "Relay server assets installed. Deploy with: keyvalet relay install --data /var/lib/keyvalet-relay-server --public-url https://relay.example.com"
  echo "Cloudflare: 1. A/AAAA record + orange cloud. 2. Origin CA certificate + Full (strict). 3. Allow Cloudflare IP ranges on 443; keep 8787 private."
}

kv_remove_remote() {
  KV_REMOVE_OS=$(uname -s)
  sudo /bin/sh -eu -c '
    PLATFORM="$1"; OWNER_UID="$2"
    if [ "$PLATFORM" = Linux ]; then
      systemctl disable --now keyvalet-relay.service 2>/dev/null || true
      systemctl disable --now keyvalet-relay-server.service 2>/dev/null || true
      rm -f /etc/systemd/system/keyvalet-relay.service /etc/systemd/system/keyvalet-relay-server.service
      rm -f /etc/keyvalet/relay-client.toml
      if [ -f /etc/nginx/conf.d/keyvalet-relay.conf ] && grep -q "KeyValet\|keyvalet-relay" /etc/nginx/conf.d/keyvalet-relay.conf; then
        rm -f /etc/nginx/conf.d/keyvalet-relay.conf
        if command -v nginx >/dev/null; then nginx -t && systemctl reload nginx; fi
      fi
      systemctl daemon-reload
    else
      /bin/launchctl bootout "gui/$OWNER_UID/dev.keyvalet.relay" 2>/dev/null || true
      rm -f /Library/LaunchAgents/dev.keyvalet.relay.plist
    fi
  ' sh "$KV_REMOVE_OS" "$(id -u)"
  kv_runtime_config remove --home "$HOME" --project "$KV_PROJECT_DIR"
  echo "Relay services and runtime registrations removed; ciphertext queues, certificates and service accounts retained."
}

if [ "${1:-}" = --uninstall ]; then
  shift
  kv_remove_remote
  KV_SOURCE=$(cd "$(dirname "$0")/.." && pwd)
  if [ -f "$KV_SOURCE/scripts/uninstall-legacy.sh" ]; then
    exec /bin/sh "$KV_SOURCE/scripts/uninstall-legacy.sh" "$@"
  fi
  exec /bin/sh "$KV_SOURCE/scripts/uninstall.sh" "$@"
fi

if [ "$(uname -s)" = Linux ]; then
  /bin/sh "$(dirname "$0")/install-linux.sh" "$@"
  kv_remote_linux
  KV_REGISTER=1
  for option in "$@"; do [ "$option" != --no-register ] || KV_REGISTER=0; done
  if [ "$KV_REGISTER" = 1 ] && [ "${KEYVALET_NO_REGISTER:-0}" != 1 ]; then
    kv_runtime_config install --home "$HOME" --project "$KV_PROJECT_DIR"
  fi
  exit
fi

# UI language: KEYVALET_LANG=en|zh takes priority, otherwise fall back to the macOS UI language
KV_LANG=${KEYVALET_LANG:-}
case "$KV_LANG" in zh*) KV_LANG=zh ;; en*) KV_LANG=en ;; *) KV_LANG= ;; esac
if [ -z "$KV_LANG" ]; then
  if /usr/bin/defaults read -g AppleLanguages 2>/dev/null | /usr/bin/sed -n 2p | /usr/bin/grep -q zh; then KV_LANG=zh; else KV_LANG=en; fi
fi
say() { if [ "$KV_LANG" = zh ]; then printf '%s\n' "$1"; else printf '%s\n' "$2"; fi; }

INSTALL_DIR=/usr/local/lib/keyvalet
VAULT_DIR=/var/db/keyvalet
CLI_LINK=/usr/local/bin/keyvalet
SUDOERS_FILE=/etc/sudoers.d/keyvalet
SRC_DIR=$(cd "$(dirname "$0")/.." && pwd)

if [ "$(id -u)" = 0 ]; then
  say "请以普通用户运行（脚本会在需要时调用 sudo）：./scripts/install.sh" "Run as a regular user (the script calls sudo when needed): ./scripts/install.sh" >&2
  exit 1
fi

if [ -x "$SRC_DIR/bin/kv-helper" ] && [ ! -d "$SRC_DIR/rust" ]; then
  # Release package: prebuilt Apple Silicon binaries, no source tree. Only /usr/bin/codesign
  # is needed below (the kv-touchid ad-hoc hardened-runtime signature); no Xcode CLT/cargo.
  say "==> 使用发行包内的预编译二进制（Apple Silicon）" "==> Using the release package's prebuilt binaries (Apple Silicon)"
  PREBUILT=1
  BIN_DIR="$SRC_DIR/bin"
  for b in kv-helper kv-touchid kv-mcp kv-cli kv-hook kv-server kv-relay-client; do
    [ -x "$BIN_DIR/$b" ] || { say "发行包不完整：缺少 $b" "Incomplete release package: missing $b" >&2; exit 1; }
    [ "$(/usr/bin/lipo -archs "$BIN_DIR/$b" 2>/dev/null)" = arm64 ] || { say "$b 不是 arm64 二进制，此发行包只支持 Apple Silicon；请改用源码安装" "$b is not an arm64 binary; this release package supports Apple Silicon only -- install from source instead" >&2; exit 1; }
  done
  # hw.optional.arm64, not uname -m: a Rosetta-translated shell reports x86_64 on Apple Silicon.
  [ "$(/usr/sbin/sysctl -n hw.optional.arm64 2>/dev/null)" = 1 ] || { say "此发行包只支持 Apple Silicon；Intel Mac 请改用源码安装" "This release package supports Apple Silicon only; on Intel Macs please install from source" >&2; exit 1; }
else
  CARGO_BIN=$(command -v cargo || true)
  [ -n "$CARGO_BIN" ] || { say "找不到 cargo，请先安装 Rust 工具链（https://rustup.rs）" "cargo not found; install the Rust toolchain first (https://rustup.rs)" >&2; exit 1; }

  PREBUILT=0
  say "==> 构建（cargo build --release）" "==> Building (cargo build --release)"
  # Use one absolute directory for both Cargo and artifact lookup, including relative overrides.
  case "${CARGO_TARGET_DIR:-target}" in
    /*) KV_BUILD_TARGET_DIR=$CARGO_TARGET_DIR ;;
    *) KV_BUILD_TARGET_DIR="$SRC_DIR/rust/${CARGO_TARGET_DIR:-target}" ;;
  esac
  cd "$SRC_DIR/rust"
  cargo build --release --locked --target-dir "$KV_BUILD_TARGET_DIR"
  BIN_DIR="$KV_BUILD_TARGET_DIR/release"
  for b in kv-helper kv-touchid kv-mcp kv-cli kv-hook kv-server kv-relay-client; do
    [ -x "$BIN_DIR/$b" ] || { say "构建产物缺失：$b" "Build artifact missing: $b" >&2; exit 1; }
  done
fi

STAGE=$(mktemp -d)
trap 'rm -rf "$STAGE"' EXIT
mkdir -p "$STAGE/bin" "$STAGE/templates"
cp "$BIN_DIR/kv-helper" "$BIN_DIR/kv-touchid" "$BIN_DIR/kv-mcp" "$BIN_DIR/kv-cli" "$BIN_DIR/kv-hook" "$BIN_DIR/kv-server" "$BIN_DIR/kv-relay-client" "$STAGE/bin/"
cp -R "$SRC_DIR/templates/." "$STAGE/templates/" 2>/dev/null || true
TEAM_ID=PWCRJPY7YC
team_of() { /usr/bin/codesign -dv --verbose=4 "$1" 2>&1 | /usr/bin/sed -n 's/^TeamIdentifier=\(.*\)/\1/p'; }

# A codesigning identity owned by our team: prefer "Developer ID Application", accept
# "Apple Development" (the developer's machine). Prints the SHA-1 to sign with, nothing if none.
pick_signing_identity() {
  want=$1
  /usr/bin/security find-identity -v -p codesigning 2>/dev/null \
    | /usr/bin/sed -n "s/^ *[0-9]*) \([0-9A-Fa-f]\{40\}\) \"\($want: [^\"]*\)\"/\1|\2/p" \
    | while IFS='|' read -r hash name; do
        ou=$(/usr/bin/security find-certificate -c "$name" -a -p 2>/dev/null \
          | /usr/bin/openssl x509 -noout -subject -nameopt sep_multiline 2>/dev/null \
          | /usr/bin/sed -n 's/^ *OU=\(.*\)/\1/p' | /usr/bin/head -1)
        if [ "$ou" = "$TEAM_ID" ]; then echo "$hash"; break; fi
      done
}
IDENTITY_SHA=$( { pick_signing_identity "Developer ID Application"; pick_signing_identity "Apple Development"; } | /usr/bin/head -1 )

# Hardened runtime everywhere: a real team signature when we have one (required for the launchd
# daemon mode below -- the daemon verifies the agent's Apple-anchored identity before trusting
# its prompts). Without an identity, fall back to the ad-hoc kv-touchid signature as before.
if [ "$PREBUILT" = 1 ] && [ "$(team_of "$BIN_DIR/kv-helper")" = "$TEAM_ID" ] && [ "$(team_of "$BIN_DIR/kv-touchid")" = "$TEAM_ID" ]; then
  say "发行包自带 $TEAM_ID 签名，保持原样" "The release package already carries the $TEAM_ID signature; keeping it"
elif [ -n "$IDENTITY_SHA" ]; then
  say "==> 使用 $TEAM_ID 身份为二进制签名" "==> Signing binaries with the $TEAM_ID identity"
  for b in helper touchid mcp cli hook server relay-client; do
    /usr/bin/codesign --force --options runtime --identifier "dev.keyvalet.$b" -s "$IDENTITY_SHA" "$STAGE/bin/kv-$b" >/dev/null \
      || { say "签名失败：kv-$b" "Signing failed: kv-$b" >&2; exit 1; }
  done
else
  codesign -s - -o runtime -f "$STAGE/bin/kv-touchid" >/dev/null
fi

# Daemon mode requires verifiable code identity on BOTH the daemon (it must not be spoofable)
# and the agent (the daemon verifies it before trusting its prompt answers).
DAEMON_MODE=0
if /usr/bin/codesign --verify --strict "$STAGE/bin/kv-helper" 2>/dev/null \
   && /usr/bin/codesign --verify --strict "$STAGE/bin/kv-touchid" 2>/dev/null \
   && [ "$(team_of "$STAGE/bin/kv-helper")" = "$TEAM_ID" ] \
   && [ "$(team_of "$STAGE/bin/kv-touchid")" = "$TEAM_ID" ]; then
  DAEMON_MODE=1
  say "==> 启用 launchd 守护进程模式（dev.keyvalet.helper + dev.keyvalet.agent）" "==> Enabling launchd daemon mode (dev.keyvalet.helper + dev.keyvalet.agent)"
else
  say "未检测到可用的 $TEAM_ID 签名身份，按 sudo 模式安装（功能相同，每个会话经 sudo 起 helper）" "No usable $TEAM_ID signing identity found; installing in sudo mode (same features -- each session spawns the helper via sudo)"
fi

RELAY_MODE=0
if [ "$DAEMON_MODE" = 1 ] && /usr/bin/codesign --verify --strict "$STAGE/bin/kv-relay-client" 2>/dev/null \
    && [ "$(team_of "$STAGE/bin/kv-relay-client")" = "$TEAM_ID" ] \
    && /usr/bin/codesign -v -R 'identifier "dev.keyvalet.relay-client"' "$STAGE/bin/kv-relay-client" 2>/dev/null; then
  RELAY_MODE=1
  if [ "$PREBUILT" = 1 ]; then
    KV_RELAY_PLIST="$SRC_DIR/service/relay-client/dev.keyvalet.relay.plist"
  else
    KV_RELAY_PLIST="$SRC_DIR/rust/crates/kv-relay-client/service/dev.keyvalet.relay.plist"
  fi
  cp "$KV_RELAY_PLIST" "$STAGE/dev.keyvalet.relay.plist"
fi

USER_NAME=$(id -un)
case "$USER_NAME" in
  *[!A-Za-z0-9_.-]*|"") say "用户名 $USER_NAME 含有不支持的字符" "User name $USER_NAME contains unsupported characters" >&2; exit 1 ;;
esac

if [ "$DAEMON_MODE" = 1 ]; then
  UID_NUM=$(id -u)
  cat > "$STAGE/dev.keyvalet.helper.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>dev.keyvalet.helper</string>
  <key>ProgramArguments</key><array>
    <string>$INSTALL_DIR/bin/kv-helper</string><string>--daemon</string><string>--uid</string><string>$UID_NUM</string>
  </array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
</dict></plist>
EOF
  cat > "$STAGE/dev.keyvalet.agent.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>dev.keyvalet.agent</string>
  <key>ProgramArguments</key><array>
    <string>$INSTALL_DIR/bin/kv-touchid</string><string>--agent</string>
  </array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><dict><key>SuccessfulExit</key><false/></dict>
  <key>LimitLoadToSessionType</key><string>Aqua</string>
  <key>ProcessType</key><string>Interactive</string>
</dict></plist>
EOF
fi

cat > "$STAGE/sudoers" <<SUDOERS
# KeyValet: only $USER_NAME may run the vault helper without a password (arguments must match exactly).
# After starting, the helper requires Touch ID (device owner authentication) before providing any service.
$USER_NAME ALL=(root) NOPASSWD: $INSTALL_DIR/bin/kv-helper
SUDOERS
/usr/sbin/visudo -cqf "$STAGE/sudoers" || { say "生成的 sudoers 规则校验失败" "Validation of the generated sudoers rule failed" >&2; exit 1; }
cat > "$STAGE/keyvalet" <<EOF
#!/bin/sh
# Detect the UI language as the user (root can't read the user's language preference), pass it to the CLI via --lang
KV_LANG=\${KEYVALET_LANG:-}
if [ -z "\$KV_LANG" ]; then
  # The first entry of AppleLanguages (line 2 of the output) is the current UI language
  if /usr/bin/defaults read -g AppleLanguages 2>/dev/null | /usr/bin/sed -n 2p | /usr/bin/grep -q zh; then KV_LANG=zh; else KV_LANG=en; fi
fi
exec /usr/bin/sudo -k -- $INSTALL_DIR/bin/kv-cli --lang "\$KV_LANG" "\$@"
EOF

say "==> 安装到 ${INSTALL_DIR}（需要 sudo）" "==> Installing to ${INSTALL_DIR} (requires sudo)"
sudo -k
if [ -t 0 ]; then
  SUDO="sudo"
else
  # No terminal (e.g. run on the user's behalf by an AI agent): ask for the password with a native macOS dialog
  # Dialog text is chosen by UI language (fixed strings, no single quotes), written into the generated script single-quoted
  ASKPASS_MSG=$(say "安装 KeyValet 需要管理员权限。请输入 macOS 登录密码（sudo）：" "Installing KeyValet requires administrator privileges. Enter your macOS login password (sudo):")
  ASKPASS_TITLE=$(say "KeyValet · 安装" "KeyValet · Install")
  ASKPASS_CANCEL=$(say "取消" "Cancel")
  ASKPASS_OK=$(say "安装" "Install")
  cat > "$STAGE/install-askpass" <<'EOF'
#!/bin/sh
exec /usr/bin/osascript \
  -e 'on run argv' \
  -e 'set r to display dialog (item 1 of argv) with title (item 2 of argv) default answer "" with hidden answer buttons {item 3 of argv, item 4 of argv} default button 2 cancel button 1 with icon caution giving up after 180' \
  -e 'if gave up of r then error number -128' \
  -e 'return text returned of r' \
  -e 'end run' \
EOF
  cat >> "$STAGE/install-askpass" <<EOF
  -- '$ASKPASS_MSG' '$ASKPASS_TITLE' '$ASKPASS_CANCEL' '$ASKPASS_OK' 2>/dev/null
EOF
  chmod 0700 "$STAGE/install-askpass"
  export SUDO_ASKPASS="$STAGE/install-askpass"
  SUDO="sudo -A"
fi
# This whole root script is ONE single-quoted string: never use a single quote (apostrophe)
# anywhere inside it, not even in a comment -- it would end the string early.
$SUDO /bin/sh -eu -c '
  INSTALL_DIR="$1"; VAULT_DIR="$2"; CLI_LINK="$3"; STAGE="$4"; SUDOERS_FILE="$5"; KV_LANG="$6"; DAEMON_MODE="$7"; OWNER_UID="$8"; RELAY_MODE="$9"; OWNER_HOME="${10}"
  say() { if [ "$KV_LANG" = zh ]; then printf "%s\n" "$1"; else printf "%s\n" "$2"; fi; }
  rm -rf "$INSTALL_DIR.new"
  mkdir -p "$INSTALL_DIR.new"
  cp -R "$STAGE/bin" "$STAGE/templates" "$INSTALL_DIR.new/"
  xattr -cr "$INSTALL_DIR.new" 2>/dev/null || true
  chown -R root:wheel "$INSTALL_DIR.new"
  chmod -R u=rwX,go=rX "$INSTALL_DIR.new"
  chmod 0755 "$INSTALL_DIR.new"/bin/*
  # Stop the daemon and the per-user agent before switching binaries; the agent lives in the
  # GUI domain of the installing user.
  /bin/launchctl bootout "system/dev.keyvalet.helper" 2>/dev/null || true
  /bin/launchctl bootout "gui/$OWNER_UID/dev.keyvalet.agent" 2>/dev/null || true
  /bin/launchctl bootout "gui/$OWNER_UID/dev.keyvalet.relay" 2>/dev/null || true
  # Revoke sessions before switching the installed executables and rotating the vault key.
  /usr/bin/pkill -TERM -x kv-helper || [ "$?" -eq 1 ]
  /usr/bin/pkill -TERM -u "$OWNER_UID" -x kv-mcp || [ "$?" -eq 1 ]
  rm -rf "$INSTALL_DIR.old"
  if [ -e "$INSTALL_DIR" ]; then mv "$INSTALL_DIR" "$INSTALL_DIR.old"; fi
  mv "$INSTALL_DIR.new" "$INSTALL_DIR"

  mkdir -p "$(dirname "$CLI_LINK")"
  install -o root -g wheel -m 0755 "$STAGE/keyvalet" "$CLI_LINK"

  # Migrate from credential-mcp (the pre-rename name): move the whole vault (master key, credentials, audit log, settings), then remove the old install
  if [ -d /var/db/credential-mcp ] && [ ! -e "$VAULT_DIR" ]; then
    mv /var/db/credential-mcp "$VAULT_DIR"
    say "已迁移凭证库：/var/db/credential-mcp -> $VAULT_DIR" "Migrated vault: /var/db/credential-mcp -> $VAULT_DIR"
  fi
  rm -rf /usr/local/lib/credential-mcp /usr/local/bin/credential-vault /etc/sudoers.d/credential-mcp

  if [ ! -d "$VAULT_DIR" ]; then mkdir -m 0700 "$VAULT_DIR"; fi
  chown root:wheel "$VAULT_DIR"
  chmod 0700 "$VAULT_DIR"

  install -o root -g wheel -m 0440 "$STAGE/sudoers" "$SUDOERS_FILE"
  /usr/sbin/visudo -cq || { rm -f "$SUDOERS_FILE"; say "sudoers 整体校验失败，已撤销规则" "Overall sudoers validation failed; the rule was removed" >&2; exit 1; }

  # macOS supports only hardware-protected vaults. The CLI directly collects the recovery
  # passphrase from a hidden terminal/native dialog, and never returns it to the installer.
  say "==> 初始化或迁移 Secure Enclave 凭证库" "==> Initializing or migrating the Secure Enclave vault"
  "$INSTALL_DIR/bin/kv-cli" --lang "$KV_LANG" setup-enclave
  "$INSTALL_DIR/bin/kv-cli" --lang "$KV_LANG" status --summary
  rm -rf "$INSTALL_DIR.old"

  if [ "$DAEMON_MODE" = 1 ]; then
    install -o root -g wheel -m 0644 "$STAGE/dev.keyvalet.helper.plist" /Library/LaunchDaemons/dev.keyvalet.helper.plist
    install -o root -g wheel -m 0644 "$STAGE/dev.keyvalet.agent.plist" /Library/LaunchAgents/dev.keyvalet.agent.plist
    /bin/launchctl bootstrap system /Library/LaunchDaemons/dev.keyvalet.helper.plist
    /bin/launchctl bootstrap "gui/$OWNER_UID" /Library/LaunchAgents/dev.keyvalet.agent.plist
    /bin/launchctl print system/dev.keyvalet.helper >/dev/null
    /bin/launchctl print "gui/$OWNER_UID/dev.keyvalet.agent" >/dev/null
    say "launchd 守护进程已启动：dev.keyvalet.helper + dev.keyvalet.agent" "launchd daemon started: dev.keyvalet.helper + dev.keyvalet.agent"
  fi
  if [ "$RELAY_MODE" = 1 ]; then
    install -o root -g wheel -m 0644 "$STAGE/dev.keyvalet.relay.plist" /Library/LaunchAgents/dev.keyvalet.relay.plist
    /bin/launchctl enable "gui/$OWNER_UID/dev.keyvalet.relay"
    /bin/launchctl bootstrap "gui/$OWNER_UID" /Library/LaunchAgents/dev.keyvalet.relay.plist
  else
    rm -f /Library/LaunchAgents/dev.keyvalet.relay.plist
    say "远程 relay 需要签名的 daemon 与 relay-client" "Remote relay requires the signed daemon and relay-client"
  fi
' sh "$INSTALL_DIR" "$VAULT_DIR" "$CLI_LINK" "$STAGE" "$SUDOERS_FILE" "$KV_LANG" "$DAEMON_MODE" "$(id -u)" "$RELAY_MODE" "$HOME"
sudo -k

# Verify the passwordless rule took effect: the helper exits immediately on reading EOF (no Touch ID prompt)
if ! /usr/bin/sudo -n -- "$INSTALL_DIR/bin/kv-helper" </dev/null >/dev/null 2>&1; then
  say "⚠️  免密规则未生效：请确认 /etc/sudoers 包含 #includedir /private/etc/sudoers.d" "⚠️  The passwordless sudo rule is not in effect: make sure /etc/sudoers contains #includedir /private/etc/sudoers.d" >&2
  exit 1
fi

. "$SRC_DIR/scripts/configure-runtimes.sh"
if [ "${KEYVALET_NO_REGISTER:-0}" != 1 ]; then
  kv_runtime_config install --home "$HOME" --project "$KV_PROJECT_DIR"
fi

echo
say "安装完成。" "Installation complete."
echo
say "在 Claude Code 中注册（用户级，所有项目可用）：" "Register it in Claude Code (user scope, available in all projects):"
echo "  claude mcp add keyvalet --scope user -- $INSTALL_DIR/bin/kv-mcp"
say "（如之前注册过旧名字：claude mcp remove credential --scope user）" "(If you registered it under the old name before: claude mcp remove credential --scope user)"
echo
say "在 Devin CLI 中安装插件（含密钥检测 hook 和 /keyvalet:* 命令）：" "Install the plugin in Devin CLI (includes the secret-detection hook and /keyvalet:* commands):"
echo "  devin plugins install KeyValet/KeyValet#devin-plugin"
echo
say "在终端中管理凭证：" "Manage credentials from the terminal:"
echo "  keyvalet help"
