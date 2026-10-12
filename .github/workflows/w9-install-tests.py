"""Verify the installer against disposable runtime configuration and service templates."""
import json
from pathlib import Path
import re
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
INSTALLER = ROOT / "scripts/install.sh"


class RuntimeConfiguration(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.home = Path(self.temporary.name).resolve() / "owner"
        self.project = Path(self.temporary.name).resolve() / "project"
        self.home.mkdir()
        self.project.mkdir()

    def write(self, relative, value):
        path = self.home / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(value if isinstance(value, str) else json.dumps(value))
        return path

    def run_config(self, action="install", detected="claude,codex,grok,gemini,cursor,devin"):
        return subprocess.run(
            ["sh", str(INSTALLER), "--runtime-config", action, "--home", str(self.home),
             "--project", str(self.project), "--detected", detected],
            capture_output=True, text=True, check=False,
        )

    def test_timeouts_and_stop_modes_preserve_other_servers_and_hooks(self):
        claude = self.write(".claude.json", {"mcpServers":{"other":{"command":"keep"}, "keyvalet":{"command":"custom", "timeout":42, "env":{"LANG":"en"}}}, "custom":True})
        settings = self.write(".claude/settings.json", {"hooks":{"Stop":[{"hooks":[{"type":"command", "command":"user-stop"}]}], "UserPromptSubmit":[{"hooks":[{"command":"user-prompt"}]}]}})
        cursor = self.write(".cursor/hooks.json", {"version":1, "hooks":{"stop":[{"command":"user-cursor"}]}})
        codex = self.write(".codex/config.toml", '# User comment\nmodel = "custom"\n[mcp_servers.other]\ncommand = "keep"\n[mcp_servers."keyvalet"]\ncommand = "custom"\ntool_timeout_sec = 41\n[mcp_servers.keyvalet.env]\nLANG = "zh"\n')
        self.write(".grok/config.toml", '[mcp_servers.other]\ncommand = "keep"\n')
        project = self.project / ".mcp.json"
        project.write_text(json.dumps({"mcpServers":{"other":{"command":"project-keep"}}}))
        result = self.run_config()
        self.assertEqual(result.returncode, 0, result.stderr)
        value = json.loads(claude.read_text())
        self.assertEqual(value["mcpServers"]["keyvalet"], {"command":"custom", "timeout":900000, "env":{"LANG":"en"}})
        self.assertEqual(value["mcpServers"]["other"], {"command":"keep"})
        self.assertEqual(value["custom"], True)
        self.assertIn("user-stop", settings.read_text())
        self.assertIn("user-prompt", settings.read_text())
        self.assertIn("claude-stop", settings.read_text())
        self.assertIn("user-cursor", cursor.read_text())
        self.assertIn("cursor-stop", cursor.read_text())
        self.assertIn('# User comment\nmodel = "custom"', codex.read_text())
        self.assertIn('command = "custom"', codex.read_text())
        self.assertIn('tool_timeout_sec = 900', codex.read_text())
        self.assertIn('LANG = "zh"', codex.read_text())
        self.assertIn("codex-stop", (self.home / ".codex/hooks.json").read_text())
        self.assertIn("devin-stop", (self.home / ".config/devin/config.json").read_text())
        gemini = json.loads((self.home / ".gemini/settings.json").read_text())
        self.assertEqual(gemini["mcpServers"]["keyvalet"]["timeout"], 900000)
        self.assertIn("gemini-after-agent", json.dumps(gemini["hooks"]["AfterAgent"]))
        self.assertEqual(json.loads(project.read_text())["mcpServers"]["other"], {"command":"project-keep"})
        self.assertEqual(self.run_config().returncode, 0)
        hooks = json.loads(settings.read_text())["hooks"]["Stop"]
        self.assertEqual(len(hooks), 2)
        self.assertEqual(self.run_config("remove").returncode, 0)
        self.assertEqual(json.loads(claude.read_text())["mcpServers"]["keyvalet"]["timeout"], 42)
        self.assertIn("tool_timeout_sec = 41", codex.read_text())
        self.assertEqual(json.loads(settings.read_text())["hooks"]["Stop"], [{"hooks":[{"type":"command", "command":"user-stop"}]}])
        self.assertNotIn("keyvalet", json.loads(project.read_text())["mcpServers"])
        self.assertEqual(self.run_config("remove").returncode, 0)

    def test_malformed_json_refuses_all_changes(self):
        original = self.write(".claude.json", {"mcpServers":{"keyvalet":{"command":"keep", "timeout":41}}})
        self.write(".cursor/hooks.json", "{")
        before = original.read_bytes()
        result = self.run_config()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(original.read_bytes(), before)
        self.assertFalse((self.home / ".keyvalet/remote-runtime-state.json").exists())

    def test_duplicate_json_and_wrong_hook_types_are_rejected(self):
        for text in ('{"mcpServers":{},"mcpServers":{}}', '{"hooks":{"Stop":{}}}'):
            path = ".claude.json" if "mcpServers" in text else ".claude/settings.json"
            target = self.write(path, text)
            self.assertNotEqual(self.run_config(detected="claude").returncode, 0)
            self.assertEqual(target.read_text(), text)
            target.unlink()

    def test_configuration_links_are_rejected(self):
        other = self.home / "other.json"
        other.write_text("{}")
        (self.home / ".claude.json").symlink_to(other)
        self.assertNotEqual(self.run_config(detected="claude").returncode, 0)
        self.assertEqual(other.read_text(), "{}")

    def test_uninstall_preserves_a_timeout_changed_after_installation(self):
        path = self.write(".claude.json", {"mcpServers":{"keyvalet":{"command":"custom"}}})
        self.assertEqual(self.run_config(detected="claude").returncode, 0)
        value = json.loads(path.read_text())
        value["mcpServers"]["keyvalet"]["timeout"] = 17
        path.write_text(json.dumps(value))
        self.assertEqual(self.run_config("remove").returncode, 0)
        self.assertEqual(json.loads(path.read_text())["mcpServers"]["keyvalet"]["timeout"], 17)

    def test_toml_without_final_newline_is_preserved_and_valid(self):
        path = self.write(".codex/config.toml", '[mcp_servers.keyvalet]\ncommand = "keep"')
        result = self.run_config(detected="codex")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('command = "keep"\ntool_timeout_sec = 900\n', path.read_text())

    def test_removal_of_the_only_new_server_preserves_global_settings(self):
        codex = self.write(".codex/config.toml", 'model = "owner-custom"\n')
        grok = self.write(".grok/config.toml", "")
        installed = self.run_config(detected="codex,grok")
        self.assertEqual(installed.returncode, 0, installed.stderr)
        removed = self.run_config("remove")
        self.assertEqual(removed.returncode, 0, removed.stderr)
        self.assertIn('model = "owner-custom"', codex.read_text())
        self.assertNotIn("keyvalet", codex.read_text())
        self.assertEqual(grok.read_text().strip(), "")


class InstallerSource(unittest.TestCase):
    def test_shell_syntax_and_root_string_boundaries(self):
        subprocess.run(["sh", "-n", str(INSTALLER)], check=True)
        source = INSTALLER.read_text()
        bodies = re.findall(r"/bin/sh -eu -c '\n(.*?)\n[ \t]*' sh", source, re.S)
        self.assertTrue(bodies)
        for body in bodies:
            self.assertNotIn("'", body)
            self.assertRegex(body, r'\w+="\$1"')
            self.assertNotIn("$HOME", body)


if __name__ == "__main__":
    unittest.main()
