#!/usr/bin/env python3
"""Offline WSL bridge/config tests. No Windows install, service, vault or GUI is needed."""

import importlib.util
import io
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

import tomlkit

sys.dont_write_bytecode = True
SOURCE = Path(__file__).resolve().parent / "wsl"
spec = importlib.util.spec_from_file_location("wsl_configure", SOURCE / "configure.py")
configure = importlib.util.module_from_spec(spec)
spec.loader.exec_module(configure)
sys.modules["configure"] = configure
verify_spec = importlib.util.spec_from_file_location("wsl_verify", SOURCE / "verify.py")
verify = importlib.util.module_from_spec(verify_spec)
verify_spec.loader.exec_module(verify)


class BridgeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="keyvalet-wsl-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.fake = self.root / "Windows 测试 ' Program Files" / "kv-mcp.exe"
        self.fake.parent.mkdir()
        self.fake.write_text(
            "#!" + sys.executable + "\n"
            "import json, os, sys\n"
            "if '--echo' in sys.argv:\n"
            "    sys.stdout.buffer.write(sys.stdin.buffer.read())\n"
            "else:\n"
            "    print(json.dumps({'args': sys.argv[1:], 'env': os.environ.get('WSLENV'), 'cwd': os.getcwd()}))\n"
            "sys.exit(23 if '--fail' in sys.argv else 0)\n", encoding="utf-8")
        self.fake.chmod(0o700)
        path = self.root / "wslpath"
        path.write_text("#!/bin/sh\nprintf '%s\\n' \"$*\" > \"$TEST_TRANSLATION\"\nprintf '%s\\n' \"$TEST_BINARY\"\n", encoding="utf-8")
        path.chmod(0o700)
        self.env = dict(os.environ, WSL_DISTRO_NAME="KeyValet-Test", PATH=str(self.root) + os.pathsep + os.environ["PATH"],
                        TEST_BINARY=str(self.fake), TEST_TRANSLATION=str(self.root / "translation"))

    def run_bridge(self, mode="mcp", args=(), data=b"", env=None):
        return subprocess.run(["sh", str(SOURCE / "bridge.sh"), mode, *args], input=data,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=self.root,
                              env=env or self.env, timeout=5)

    def test_byte_exact_stdio_and_eof(self):
        data = b'{"jsonrpc":"2.0","id":1}\n\x00\r\n' + "中文".encode() + bytes(range(256))
        result = self.run_bridge(args=["--echo"], data=data)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, data)
        self.assertEqual(result.stderr, b"")

    def test_arguments_cwd_and_native_status_are_preserved(self):
        args = ["with spaces", "汉字", "$(touch injected)", "single'quote", "", "back\\slash", "--fail"]
        result = self.run_bridge(args=args)
        self.assertEqual(result.returncode, 23)
        payload = json.loads(result.stdout)
        self.assertEqual(payload["args"], args)
        self.assertTrue(Path(payload["cwd"]).samefile(self.root))
        self.assertFalse((self.root / "injected").exists())
        self.assertEqual((self.root / "translation").read_text().strip(), r"-u C:\Program Files\KeyValet\bin\kv-mcp.exe")

    def test_only_known_targets_and_context_variables(self):
        result = self.run_bridge(mode="hook", args=["codex-tool"], env=dict(self.env, WSLENV="KEEP/p:KEYVALET_LANG/p:KEYVALET_HOOKS/u:OTHER/l:KEYVALET_SESSION_TTL_MINUTES:KEYVALET_GRANT_MODE/l"))
        payload = json.loads(result.stdout)
        self.assertEqual(payload["args"], ["codex-tool"])
        self.assertEqual(payload["env"], "KEYVALET_LANG/w:KEYVALET_SESSION_TTL_MINUTES/w:KEYVALET_GRANT_MODE/w:KEYVALET_HOOKS/w:KEEP/p:OTHER/l")
        self.assertIn("kv-hook.exe", (self.root / "translation").read_text())
        bad = self.run_bridge(mode="custom.exe")
        self.assertNotEqual(bad.returncode, 0)
        self.assertEqual(bad.stdout, b"")

    def test_missing_install_fails_on_stderr(self):
        self.fake.unlink()
        result = self.run_bridge(mode="cli", args=["status"])
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, b"")
        self.assertIn(b"install KeyValet on Windows first", result.stderr)


class ConfigurationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="keyvalet-wsl-config-")
        self.addCleanup(self.temp.cleanup)
        self.home = Path(self.temp.name) / "用户 home ' & $()"
        self.home.mkdir()
        self.root = self.home / ".local" / "share" / "keyvalet" / "wsl"

    def write(self, relative, content):
        path = self.home / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        return path

    def install(self, clients=configure.CLIENTS):
        return configure.configure(self.home, SOURCE, clients)

    def test_install_merges_clients_and_reinstall_keeps_original_backups(self):
        claude_original = '{"mcpServers":{"other":{"command":"other"}},"projects":{"x":{}}}\n'
        claude = self.write(".claude.json", claude_original)
        hooks = self.write(".codex/hooks.json", json.dumps({"description": "keep me", "hooks": {"PreToolUse": [{"matcher": "Bash", "hooks": [{"type": "command", "command": "other-hook"}]}]}}))
        cursor = self.write(".cursor/hooks.json", json.dumps({"version": 1, "hooks": {"beforeShellExecution": [{"command": "other-cursor-hook"}]}}))
        codex_original = '# Keep this comment\nmodel = "user-choice"\n[mcp_servers."other.name"]\ncommand = "other" # Keep this too\n[mcp_servers.keyvalet]\nurl = "https://example.invalid/old"\n'
        codex = self.write(".codex/config.toml", codex_original)
        root, count = self.install()
        self.assertEqual(count, 6)
        configured = json.loads(claude.read_text())
        self.assertEqual(configured["projects"], {"x": {}})
        self.assertEqual(configured["mcpServers"]["other"], {"command": "other"})
        self.assertEqual(configured["mcpServers"]["keyvalet"]["command"], str(root / "bin/kv-mcp"))
        parsed = tomlkit.parse(codex.read_text())
        self.assertEqual(parsed["model"], "user-choice")
        self.assertEqual(parsed["mcp_servers"]["other.name"]["command"], "other")
        self.assertNotIn("url", parsed["mcp_servers"]["keyvalet"])
        self.assertIn("# Keep this comment", codex.read_text())
        self.assertIn("# Keep this too", codex.read_text())
        self.assertEqual(json.loads(hooks.read_text())["hooks"]["PreToolUse"][0]["hooks"][0]["command"], "other-hook")
        self.assertEqual(json.loads(cursor.read_text())["hooks"]["beforeShellExecution"][0]["command"], "other-cursor-hook")
        for path in [claude, codex, hooks, cursor]:
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        snapshot = {p: p.read_bytes() for p in self.home.rglob("*") if p.is_file()}
        _, count = self.install()
        self.assertEqual(count, 0)
        for path, data in snapshot.items():
            self.assertEqual(path.read_bytes(), data)
        self.assertEqual(claude.with_name(claude.name + ".bak-keyvalet-wsl").read_text(), claude_original)
        self.assertEqual(codex.with_name(codex.name + ".bak-keyvalet-wsl").read_text(), codex_original)

    def test_mixed_hook_groups_are_preserved_and_owned_hook_is_not_duplicated(self):
        command = configure.hook_command(self.root, "codex-tool")
        path = self.write(".codex/hooks.json", json.dumps({"hooks": {"PreToolUse": [{"matcher": "custom", "description": "retain", "hooks": [{"type": "command", "command": command}, {"type": "command", "command": "other"}]}]}}))
        self.install(clients=("codex",))
        groups = json.loads(path.read_text())["hooks"]["PreToolUse"]
        self.assertEqual(groups[0]["description"], "retain")
        self.assertEqual(groups[0]["hooks"], [{"type": "command", "command": "other"}])
        self.assertEqual(sum(h["command"] == command for g in groups for h in g["hooks"]), 1)

    def test_invalid_client_prevents_all_config_and_asset_writes(self):
        existing = self.write(".claude.json", '{"keep":"original"}\n')
        self.write(".cursor/hooks.json", '{"hooks":{"beforeShellExecution":"invalid"}}')
        with self.assertRaises(ValueError):
            self.install()
        self.assertEqual(existing.read_text(), '{"keep":"original"}\n')
        self.assertFalse(self.root.exists())
        self.assertFalse(existing.with_name(existing.name + ".bak-keyvalet-wsl").exists())

    def test_malformed_toml_and_json_are_not_overwritten(self):
        for relative, content in [(".codex/config.toml", 'model = "one"\nmodel = "two"\n'), (".claude.json", "{broken}")]:
            with self.subTest(relative=relative):
                path = self.write(relative, content)
                with self.assertRaises(ValueError):
                    self.install()
                self.assertEqual(path.read_text(), content)
                self.assertFalse(self.root.exists())
                path.unlink()

    def test_inline_toml_table_and_selected_clients(self):
        path = self.write(".codex/config.toml", '[mcp_servers]\nkeyvalet = {url = "https://example.invalid"}\nother = {command = "other"}\n')
        self.install(clients=("codex",))
        parsed = tomlkit.parse(path.read_text())
        self.assertEqual(parsed["mcp_servers"]["other"]["command"], "other")
        self.assertEqual(parsed["mcp_servers"]["keyvalet"]["command"], str(self.root / "bin/kv-mcp"))
        self.assertFalse((self.home / ".claude.json").exists())
        self.assertFalse((self.home / ".cursor").exists())

    def test_symlink_config_and_backup_are_rejected_before_writes(self):
        real = self.write("real.json", "{}")
        for relative in (".claude.json", ".claude.json.bak-keyvalet-wsl"):
            with self.subTest(relative=relative):
                target = self.home / relative
                target.symlink_to(real)
                with self.assertRaises(ValueError):
                    self.install()
                self.assertEqual(real.read_text(), "{}")
                self.assertFalse(self.root.exists())
                target.unlink()

    def test_uninstall_preserves_other_settings_user_files_and_backups(self):
        path = self.write(".claude.json", '{"mcpServers":{"other":{"command":"other"}},"keep":true}')
        original = path.read_text()
        self.install()
        custom = self.root / "notes.txt"
        custom.write_text("keep me")
        configure.configure(self.home, SOURCE, configure.CLIENTS, remove=True)
        value = json.loads(path.read_text())
        self.assertEqual(value, {"mcpServers": {"other": {"command": "other"}}, "keep": True})
        self.assertEqual(path.with_name(path.name + ".bak-keyvalet-wsl").read_text(), original)
        self.assertEqual(custom.read_text(), "keep me")
        self.assertFalse((self.root / "bin/kv-mcp").exists())
        self.install()
        self.assertEqual(custom.read_text(), "keep me")

    def test_wrappers_survive_unicode_and_shell_metacharacters(self):
        self.install(clients=("claude",))
        # Replace only the user's bridge copy with a harmless fixture; execute generated
        # launchers to detect accidental command substitution and argument splitting.
        (self.root / "bridge.sh").write_text("#!/bin/sh\nprintf '%s\\n' \"$1\" \"$2\"\n")
        result = subprocess.run([str(self.root / "bin/kv-hook"), "codex-tool"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, b"hook\ncodex-tool\n")
        self.assertFalse((self.home / "injected").exists())
        command = configure.hook_command(self.root, "cursor-shell")
        self.assertEqual(shlex.split(command), [str(self.root / "bin/kv-hook"), "cursor-shell"])


class ValidationProbeTests(unittest.TestCase):
    """Check that the opt-in probe cannot report cancelled Hello or leaked protocol as success."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="keyvalet-wsl-probe-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.log = self.root / "calls.txt"
        fixture = self.root / "fixture.py"
        fixture.write_text('''import json, os, sys
mode = sys.argv[1]
if mode == 'cli':
    print(json.dumps({'provider': 'windows_hello'}))
    sys.exit(0)
if mode == 'hook':
    sys.stdin.read()
    print(json.dumps({'hookSpecificOutput': {'permissionDecision': 'deny'}}))
    sys.exit(2)
if os.environ.get('KEYVALET_SESSION_TTL_MINUTES') == 'invalid':
    print('KEYVALET_SESSION_TTL_MINUTES must be an integer', file=sys.stderr)
    sys.exit(1)
assert os.environ.get('KEYVALET_GRANT_MODE') == 'per_use'
assert os.environ.get('KEYVALET_SESSION_TTL_MINUTES') == '5'
unlocked = False
for line in sys.stdin:
    request = json.loads(line)
    method = request['method']
    if 'id' not in request:
        continue
    result = {}
    if method == 'initialize':
        if os.environ.get('PROBE_BANNER'):
            print('unwanted stdout banner', flush=True)
        result = {'protocolVersion': '2025-03-26'}
    elif method == 'tools/list':
        result = {'tools': [{'name': name} for name in ['credential_status', 'credential_unlock', 'credential_lock', 'credential_http_request']]}
    else:
        name = request['params']['name']
        with open(os.environ['PROBE_LOG'], 'a') as log:
            log.write(name + '\\n')
        if name == 'credential_unlock' and os.environ.get('PROBE_CANCEL'):
            result = {'isError': True, 'content': []}
        else:
            if name == 'credential_unlock':
                unlocked = True
            elif name == 'credential_lock':
                unlocked = False
            result = {'content': [{'type': 'text', 'text': 'Status:\\n' + json.dumps({'state': 'unlocked' if unlocked else 'locked'})}]}
    print(json.dumps({'jsonrpc': '2.0', 'id': request['id'], 'result': result}), flush=True)
with open(os.environ['PROBE_LOG'], 'a') as log:
    log.write('EOF\\n')
''', encoding="utf-8")
        self.bridge = self.root / "bridge.sh"
        self.bridge.write_text("#!/bin/sh\nexec " + shlex.quote(sys.executable) + " " + shlex.quote(str(fixture)) + ' "$@"\n')
        self.report = {"checks": [], "hello_tested": False}

    def test_default_probe_never_unlocks_or_reads_credentials(self):
        with mock.patch.dict(os.environ, {"PROBE_LOG": str(self.log)}):
            verify.verify(self.bridge, False, self.report)
        self.assertFalse(self.report["hello_tested"])
        self.assertEqual(self.log.read_text().splitlines(), ["credential_status", "EOF"])

    def test_cancelled_hello_is_not_recorded_as_verified_and_closes_input(self):
        with mock.patch.dict(os.environ, {"PROBE_LOG": str(self.log), "PROBE_CANCEL": "1"}), mock.patch("sys.stderr", new=io.StringIO()):
            with self.assertRaisesRegex(ValueError, "cancelled: credential_unlock"):
                verify.verify(self.bridge, True, self.report)
        self.assertFalse(self.report["hello_tested"])
        self.assertEqual(self.log.read_text().splitlines(), ["credential_status", "credential_unlock", "EOF"])

    def test_stdout_banner_fails_mcp_validation_and_still_closes_input(self):
        with mock.patch.dict(os.environ, {"PROBE_LOG": str(self.log), "PROBE_BANNER": "1"}):
            with self.assertRaisesRegex(ValueError, "Invalid MCP stdout"):
                verify.verify(self.bridge, False, self.report)
        self.assertFalse(self.report["hello_tested"])
        self.assertEqual(self.log.read_text().splitlines(), ["EOF"])


if __name__ == "__main__":
    unittest.main()
