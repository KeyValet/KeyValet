# Runtime support status

What KeyValet's `kv-hook` secret-detection hook actually does in each AI coding runtime, and how
confident we are in that, as of 2026-10. Remote waiting and Stop evidence below is from
[W5's versioned measurements](remote-approval-reports/W5.md); it is separate from secret-detection
hook verification and from installed remote-device acceptance.

## Operating systems

| OS | Status | Verification |
| --- | --- | --- |
| macOS 14+ | Released, Secure Enclave required | Existing native CI and local tests |
| Windows 11 24H2+ | Development preview: SYSTEM service, protected Hello agent, native dialogs, CLI recovery and PowerShell installer/package workflow implemented | Native x64 and ARM64 build, clippy, tests, SYSTEM service, standard-owner status, upgrade/restart/uninstall and PS 5.1/7 checks pass; real Hello, installed GUI process isolation, signed distribution and live client tests pending |
| GNU/Linux + systemd | v0.3.0 release packaging: x64/ARM64 archives, service user, polkit, TPM 2.0, explicit software protection, CLI/MCP/hooks | Native Ubuntu 24.04 x86_64 checks and TPM integration on `ndu`; Ubuntu 22.04 / Debian 12 CI and native ARM64 packaging; ARM64 hardware and desktop fingerprint matrix pending |
| WSL → Windows vault | Current-main development packages include stdio MCP, native hook and public-status bridges; Linux client configurations are merged per user | Actual native x64/ARM64 WSL 1 CLI/hooks/env/config lifecycle passed, plus offline tests and package/ACL checks; owner desktop MCP/Hello, WSL 2 and live clients pending. See [WSL setup and CI records](wsl.md) |

See [Windows support and acceptance checks](windows.md) for the preview's exact scope. The runtime
contracts below do not establish that a Windows installation has been exercised end-to-end.
See [Linux support and acceptance checks](linux.md) for installation and SSH approval.

## Coding runtimes

| Runtime | MCP | Hooks | `kv-hook` mode | Confidence |
| --- | --- | --- | --- | --- |
| Claude Code | Yes (reference implementation) | Yes (`UserPromptSubmit`, `PreToolUse`) | `prompt`, `tool` | High — this is the primary target, exercised directly every session. |
| Codex | Yes — standard stdio server (`codex mcp add` or `config.toml`) | Yes, native — `~/.codex/hooks.json` `PreToolUse` (matcher `Bash\|apply_patch\|mcp__.*`) | `codex-tool` | Medium — contract taken from the official docs (developers.openai.com/codex/hooks, 2026-10-10): deny via `hookSpecificOutput.permissionDecision: "deny"` or exit 2 + stderr — `codex-tool` emits both; `ask` is parsed but unsupported (the hook run is marked failed and the call proceeds), so it is never emitted. `apply_patch` carries the patch text in `tool_input.command`; MCP calls arrive as `mcp__<server>__<tool>` with the arguments object and keyvalet's own server is exempt; matcher values `Edit`/`Write` are aliases for `apply_patch`. Non-managed hooks are skipped until the user trusts them via `/hooks` inside Codex. Not yet watched end-to-end in a live Codex session. |
| Cursor | Yes — plugin `cursor-plugin/mcp.json`, `cursor mcp add`, or `~/.cursor/mcp.json` | Yes, native — plugin `cursor-plugin/hooks/hooks.json` and/or `~/.cursor/hooks.json`: `beforeShellExecution`, `beforeMCPExecution`, `preToolUse` (file-write tools via matcher), `sessionStart` (context pointer) | `cursor-shell`, `cursor-mcp`, `cursor-tool`, `cursor-session` | Medium-high — contract confirmed from cursor.com/docs/hooks: stdout JSON `{permission, user_message, agent_message}`, exit 2 = deny, `ask` accepted but not enforced so it is never emitted. `beforeMCPExecution` carries `mcp_server_name` — keyvalet's own calls (`credential_set` & co. legitimately carry secrets) are exempted on it. `tool_input` is a JSON-encoded string per docs, parsed-or-scanned regardless of actual shape. The full plugin bundle (commands `/keyvalet-*`, `keyvalet` skill, hooks, MCP) installs to `~/.cursor/plugins/local/keyvalet`. Not run against a live Cursor session. Caveats: `beforeMCPExecution` doesn't run in cloud agents (Cursor's own deferral); `beforeSubmitPrompt` exists but is block-only (no context injection), so the prompt-side nudge isn't possible — a pasted key in the message relies on the skill/sessionStart context. |
| Grok Build | Yes, native (`grok mcp add`, namespaced `server__tool`) | Yes, native — only `PreToolUse` can block (`~/.grok/hooks/*.json`) | `grok-tool` | Low-medium — docs.x.ai/build/features/hooks gives the config shape (same `hooks.PreToolUse[].hooks[]` structure as Claude Code's `hooks.json`); independent 2026-10 field reports say Grok reads Claude Code's hook *config* for compatibility but does not parse the nested `hookSpecificOutput.permissionDecision` *output* — an unrecognized decision is silently treated as absent (allow). Grok's actual contract is exit code (0 = allow, 2 = deny), which `grok-tool` uses; it also prints a secondary `{"decision": "deny", "reason": ...}` JSON some docs describe, in case that's read too. Input field casing (`tool_name`/`tool_input` vs `toolName`/`toolInput`) wasn't consistently confirmed across sources, so both are accepted. The matcher is `.*` — every tool incl. MCP calls, so keyvalet's own tools (`keyvalet__credential_set` & co.) are exempted by server/tool name. Not run against a real Grok Build install. |
| Devin CLI | Yes — `.mcp.json` in `devin-plugin/`, `devin mcp add`, or auto-imported from `~/.claude.json` when Claude Code is configured | Yes, native — plugin `hooks.json` (`UserPromptSubmit`, `PreToolUse`); project/user equivalents are `.devin/hooks.v1.json` and the `"hooks"` key in `config.json` | `prompt`, `devin-tool` | Medium — contract from Devin CLI's own docs (stdin `tool_name`/`tool_input`, stdout `{"decision": "approve"\|"block", "reason"}`, `hookSpecificOutput.additionalContext`; exit 2 also blocks). `devin-tool` is exercised against Devin-shaped payloads in unit tests but hasn't been watched end-to-end in a live session. Devin's decision vocabulary has no "ask" (approve/block only), so a flag blocks — same trade-off as Cursor. Devin documents plugin hooks as best-effort/fail-open, i.e. a hook failure just skips the check. Tool names are Devin's own (`exec`, `write`, `edit`, `apply_patch`, `notebook_edit`, `write_to_process`, plus MCP calls in either shape: the `mcp_call_tool` builtin or the namespaced `mcp__<server>__<tool>`); calls on the `keyvalet` server are exempt in both shapes since `credential_set`'s `value` legitimately carries a secret. `exec` scans `env` values too. |

## Remote waiting, progress and Stop hooks

The installer updates only KeyValet's MCP entry: Claude Code user/project JSON and Gemini JSON
use `timeout: 900000`; Codex and Grok TOML use `tool_timeout_sec = 900`. Other servers, custom
KeyValet commands/environment fields and user hooks are preserved. Unix updates are preflighted
and recorded for removal. Ambiguous TOML layouts are refused for manual review; the Unix inline
table path needs `tomlkit`, while Windows currently handles explicit tables only.

Installing a client timeout does not automatically increase the server's wait budget. The
server uses the real `clientInfo.name`, defaults unknown names to 50 s, and caps every call by
the remaining budget. Initial in-call wait defaults to 60 s; later waits allow 5–600 s while
still respecting that client's budget. Explicit timeout cancellation lowers that MCP instance
to 50 s. Progress is emitted every 15 s only when the caller supplied a `progressToken`.

| Runtime / W5 version | Default server budget | Four-minute measurement / progressToken | Stop registration / measured behavior | Channels |
| --- | --- | --- | --- | --- |
| Claude Code CLI 2.1.282 | 180 s | Local synthetic model endpoint: 240 s with/without progress; token present. Hosted login failed before tool use | `Stop` → `claude-stop`; block continues the round, active loop then releases | Interactive runtime reported unavailable; idle wake unverified |
| Claude Desktop | 50 s | Not measured | No new Stop registration | Not measured |
| Codex TUI and `codex exec` 0.162.1 | 60 s; 180 s after explicit timeout confirmation ≥190 s | Both completed 240 s with/without progress; token present. This establishes a lower bound, not an exact default timeout | `Stop` → `codex-stop`; both modes continued after block | Not a V1 channels target |
| Gemini CLI 0.39.1 | 180 s | Login wait only; no initialize/token/tool measurement | `AfterAgent` → `gemini-after-agent`; source schema tested, live hook unmeasured | Not a V1 channels target |
| Cursor IDE | 120 s for an explicit IDE name | IDE not measured | `stop` → `cursor-stop`; source schema tested | Not a V1 channels target |
| `cursor-agent` 2026.10.01-e373342 / ambiguous `Cursor` | 50 s | Cancellation at about 60 s; no token, so progress could not be sent | Same mode; live stop input not observed | Not a V1 channels target |
| Grok Build | 180 s | NotSignedIn before tools; documented 6000 s is not a new measurement | No Stop hook; existing `grok-tool` PreToolUse retained | Not a V1 channels target |
| Devin CLI 3000.11.3 | 50 s; its generic `rmcp` name stays unknown | Completed 240 s with/without progress; token present | `Stop` → `devin-stop`; continued after block. Global installer config location still needs a live check | Not a V1 channels target |

Stop checks use the authenticated process identity. Unexpired pending approvals can block at
most three times; expiry, no pending approval or an active loop releases the round. A returned
`approval_pending` is a waiting state, not denial: continue independent work, then call
`credential_wait_approval(approval_id)`. It returns the original result; do not repeat the
credential-use tool. Restart recovery can instead return `approved_retry_required` with the
same approval ID. CI checks these transitions and single consumption with fake transports;
W5 also measured three-minute approval with the real Claude CLI and a fake helper.

For HTTP, known OpenAI/Anthropic templates carry a 600 s client hint; the default connection
wait is 540 s and unknown hosts get 55 s. On pending timeout the gateway returns HTTP 429,
`Retry-After: 30` and `X-KeyValet-Approval: pending; id=…`. TCP keepalive is used without
application heartbeat bytes. This does not establish external HTTP exactly-once delivery.

Full hosted-client, channels and installed-device acceptance remains in
[OPEN-QUESTIONS](remote-approval-reports/OPEN-QUESTIONS.md).

## Why Cursor, Grok, Devin and Codex don't just reuse Claude Code's hook output

All four runtimes can *load* a hook registered the Claude Code way (`.claude/settings.json` or,
for Grok, apparently similar; Devin imports `.claude/settings*.json` too, and Codex's
`hooks.json` shape is deliberately Claude-Code-like), which might suggest
zero new code is needed. In practice none of them *enforces* Claude Code's decision format when
it does:

- Cursor's schema is a different shape entirely (`permission`/`user_message`/`agent_message`) and
  doesn't enforce `"ask"`.
- Grok reads the config but field reports say it ignores `hookSpecificOutput.permissionDecision`
  specifically, falling back to "no decision understood = allow" -- which would make KeyValet's
  hook silently inert on Grok if it only ever spoke Claude Code's dialect.
- Devin *does* parse `hookSpecificOutput.additionalContext` (its documented context-injection
  channel), but its documented decision vocabulary is only `approve`/`block` — `permissionDecision`
  is a Claude-ism it doesn't read, so `tool` mode's "ask" would silently allow there as well.
- Codex *does* parse `hookSpecificOutput.permissionDecision`, but only honours `"deny"`: `"ask"`
  is parsed yet unsupported — the hook run is marked failed and the tool call proceeds — so
  `tool` mode's "ask" is a silent allow on Codex too. `codex-tool` emits `deny` via the JSON
  *and* exits 2 with the reason on stderr, the other documented deny channel.

So each gets its own `kv-hook` mode speaking its native contract, sharing the same detection core
(`detect`, `tool_reason`, the returned-secret exact-match check) rather than reusing `handle`'s
Claude-Code-shaped output.

## What's still open

- The secret-detection PreToolUse adapters still need live verification on the non-Claude
  runtimes. W5's real Codex/Devin Stop and MCP measurements establish the separate waiting
  lifecycle described above; they do not establish that each secret-detection hook blocked a
  pasted secret in the live runtime.
- Grok's tool-name vocabulary for its own built-in tools (editing, shell) isn't confirmed to match
  Claude Code's (`Write`/`Edit`/`Bash`/...), so `grok-tool` and `cursor-mcp` both use a recursive
  scan of every string field in the tool call's params instead of extracting by known field name --
  broader but not dependent on guessing the right tool name or field name.
- Grok's MCP support is real and namespaces server tools as `server__tool`; KeyValet's own MCP
  server should work there unmodified (no runtime-specific code needed for the MCP side, only for
  the hook side covered above).
