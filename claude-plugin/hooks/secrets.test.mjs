import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { handle } from "./secrets.mjs";

test("legacy plaintext caches do not affect hook decisions", () => {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "keyvalet-hook-test-"));
  const oldHome = process.env.HOME;
  try {
    process.env.HOME = home;
    const run = path.join(home, ".keyvalet", "run");
    fs.mkdirSync(run, { recursive: true, mode: 0o700 });
    const value = "synthetic-unrecognized-credential-012345";
    fs.writeFileSync(path.join(run, "legacy.redact"), value, { mode: 0o600 });
    assert.equal(handle("tool", { tool_name: "Bash", tool_input: { command: `APP_VALUE=${value} app` } }), null);
  } finally {
    if (oldHome === undefined) delete process.env.HOME;
    else process.env.HOME = oldHome;
    fs.rmSync(home, { recursive: true });
  }
});

test("recognized secrets still require confirmation without printing their full value", () => {
  const value = "ghp_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8";
  const result = handle("tool", { tool_name: "Write", tool_input: { content: `KEY=${value}` } });
  assert.equal(result.hookSpecificOutput.permissionDecision, "ask");
  assert.ok(!JSON.stringify(result).includes(value));
});

test("harmless commands continue without a prompt", () => {
  assert.equal(handle("tool", { tool_name: "Bash", tool_input: { command: "cargo fmt --all -- --check" } }), null);
});

test("PowerShell commands require the same confirmation without printing the key", () => {
  // A deterministic format fixture; not a service-issued credential.
  const value = "ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8";
  const result = handle("tool", { tool_name: "PowerShell", tool_input: { command: `$env:API_TOKEN = '${value}'` } });
  assert.equal(result?.hookSpecificOutput.permissionDecision, "ask");
  assert.ok(result.hookSpecificOutput.permissionDecisionReason.includes("shell command"));
  assert.ok(!JSON.stringify(result).includes(value));
  assert.equal(handle("tool", { tool_name: "PowerShell", tool_input: { command: "Get-ChildItem" } }), null);
});

test("the plugin routes both shell tools to the detector", () => {
  const config = JSON.parse(fs.readFileSync(new URL("./hooks.json", import.meta.url), "utf8"));
  for (const tool of ["Bash", "PowerShell"]) {
    assert.ok(config.hooks.PreToolUse.some((row) => new RegExp(`^(?:${row.matcher})$`).test(tool)));
  }
});
