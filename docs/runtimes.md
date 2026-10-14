# Runtime support status

What KeyValet's `kv-hook` secret-detection hook actually does in each AI coding runtime, and how
confident we are in that, as of 2026-10. Remote waiting and Stop evidence below is from
[R2-D's measurements](remote-approval-reports/R2-D-runtimes.md) and the historical
[W5 report](remote-approval-reports/W5.md); it is separate from secret-detection
hook verification and from installed remote-device acceptance.

## Operating systems

| OS | Status | Verification |
| --- | --- | --- |
| macOS 14+ | Released, Secure Enclave required | Existing native CI and local tests |
| Windows 11 24H2+ | Unsigned releases: SYSTEM service, protected Hello agent, native dialogs, CLI recovery and PowerShell installer/package workflow implemented; local and remote features do not require Authenticode | Native x64 and ARM64 build, clippy, tests, SYSTEM service, standard-owner status, upgrade/restart/uninstall and PS 5.1/7 checks pass; physical x64 Hello setup/unlock and remote key fixtures pass; full installed client/remote lifecycle and physical ARM64 acceptance pending |
| GNU/Linux + systemd | v0.3.0 release packaging: x64/ARM64 archives, service user, polkit, TPM 2.0, explicit software protection, CLI/MCP/hooks | Native Ubuntu 24.04 x86_64 checks and TPM integration on `ndu`; Ubuntu 22.04 / Debian 12 CI and native ARM64 packaging; ARM64 hardware and desktop fingerprint matrix pending |
| WSL → Windows vault | Current-main development packages include stdio MCP, native hook and public-status bridges; Linux client configurations are merged per user | Actual native x64/ARM64 WSL 1 CLI/hooks/env/config lifecycle passed, plus offline tests and package/ACL checks; owner desktop MCP/Hello, WSL 2 and live clients pending. See [WSL setup and CI records](wsl.md) |

See [Windows support and acceptance checks](windows.md) for the current scope. The runtime
contracts below do not establish that a Windows installation has been exercised end-to-end.
See [Linux support and acceptance checks](linux.md) for installation and SSH approval.

## Coding runtimes

| Runtime | MCP | Hooks | `kv-hook` mode | Confidence |
| --- | --- | --- | --- | --- |
| Claude Code | Yes (reference implementation) | Yes (`UserPromptSubmit`, `PreToolUse`), shell matcher includes `Bash` and `PowerShell` | `prompt`, `tool` | High for the existing Claude integration. Windows PowerShell command detection and installer/plugin matching have regression coverage; live Windows Claude is pending. |
| Codex | Yes — standard stdio server (`codex mcp add` or `config.toml`) | Yes, native — `~/.codex/hooks.json` `PreToolUse` (matcher `Bash\|apply_patch\|mcp__.*`) | `codex-tool` | Medium — contract taken from the official docs (developers.openai.com/codex/hooks, 2026-10-10): deny via `hookSpecificOutput.permissionDecision: "deny"` or exit 2 + stderr — `codex-tool` emits both; `ask` is parsed but unsupported (the hook run is marked failed and the call proceeds), so it is never emitted. `apply_patch` carries the patch text in `tool_input.command`; MCP calls arrive as `mcp__<server>__<tool>` with the arguments object and keyvalet's own server is exempt; matcher values `Edit`/`Write` are aliases for `apply_patch`. Non-managed hooks are skipped until the user trusts them via `/hooks` inside Codex. Not yet watched end-to-end in a live Codex session. |
| Cursor | Yes — plugin `cursor-plugin/mcp.json`, `cursor mcp add`, or `~/.cursor/mcp.json` | Yes, native — plugin `cursor-plugin/hooks/hooks.json` and/or `~/.cursor/hooks.json`: `beforeShellExecution`, `beforeMCPExecution`, `preToolUse` (file-write tools via matcher), `sessionStart` (context pointer) | `cursor-shell`, `cursor-mcp`, `cursor-tool`, `cursor-session` | Medium-high — contract confirmed from cursor.com/docs/hooks: stdout JSON `{permission, user_message, agent_message}`, exit 2 = deny, `ask` accepted but not enforced so it is never emitted. `beforeMCPExecution` carries `mcp_server_name` — keyvalet's own calls (`credential_set` & co. legitimately carry secrets) are exempted on it. `tool_input` is a JSON-encoded string per docs, parsed-or-scanned regardless of actual shape. The full plugin bundle (commands `/keyvalet-*`, `keyvalet` skill, hooks, MCP) installs to `~/.cursor/plugins/local/keyvalet`. Not run against a live Cursor session. Caveats: `beforeMCPExecution` doesn't run in cloud agents (Cursor's own deferral); `beforeSubmitPrompt` exists but is block-only (no context injection), so the prompt-side nudge isn't possible — a pasted key in the message relies on the skill/sessionStart context. |
| Grok Build | Yes, native (`grok mcp add`, namespaced `server__tool`) | Yes, native — only `PreToolUse` can block (`~/.grok/hooks/*.json`) | `grok-tool` | Low-medium — docs.x.ai/build/features/hooks gives the config shape (same `hooks.PreToolUse[].hooks[]` structure as Claude Code's `hooks.json`); independent 2026-10 field reports say Grok reads Claude Code's hook *config* for compatibility but does not parse the nested `hookSpecificOutput.permissionDecision` *output* — an unrecognized decision is silently treated as absent (allow). Grok's actual contract is exit code (0 = allow, 2 = deny), which `grok-tool` uses; it also prints a secondary `{"decision": "deny", "reason": ...}` JSON some docs describe, in case that's read too. Input field casing (`tool_name`/`tool_input` vs `toolName`/`toolInput`) wasn't consistently confirmed across sources, so both are accepted. The matcher is `.*` — every tool incl. MCP calls, so keyvalet's own tools (`keyvalet__credential_set` & co.) are exempted by server/tool name. Not run against a real Grok Build install. |
| Devin CLI | Yes — `.mcp.json` in `devin-plugin/`, `devin mcp add`, or auto-imported from `~/.claude.json` when Claude Code is configured | Yes, native — plugin `hooks.json` (`UserPromptSubmit`, `PreToolUse`); project/user equivalents are `.devin/hooks.v1.json` and the `"hooks"` key in `config.json` | `prompt`, `devin-tool` | Medium — contract from Devin CLI's own docs (stdin `tool_name`/`tool_input`, stdout `{"decision": "approve"\|"block", "reason"}`, `hookSpecificOutput.additionalContext`; exit 2 also blocks). `devin-tool` is exercised against Devin-shaped payloads in unit tests but hasn't been watched end-to-end in a live session. Devin's decision vocabulary has no "ask" (approve/block only), so a flag blocks — same trade-off as Cursor. Devin documents plugin hooks as best-effort/fail-open, i.e. a hook failure just skips the check. Tool names are Devin's own (`exec`, `write`, `edit`, `apply_patch`, `notebook_edit`, `write_to_process`, plus MCP calls in either shape: the `mcp_call_tool` builtin or the namespaced `mcp__<server>__<tool>`); calls on the `keyvalet` server are exempt in both shapes since `credential_set`'s `value` legitimately carries a secret. `exec` scans `env` values too. |

## Remote waiting, progress and Stop hooks

R2-D measured the installed clients on 2026-10-12–13 with the Rust `kv-mcp` Server and
an Appendix C fake helper. The model was the user's logged-in hosted model. The
four-minute tools use the real credential-request path; the silent fixture deliberately
omits progress notifications while recording the token received from the client.
[Commands, wire traces, hook fields and limitations](remote-approval-reports/R2-D-runtimes.md)
are versioned separately from installed-device or secret-detection acceptance.

The installer writes KeyValet's entry only: Claude Code and Gemini JSON use
`timeout: 900000`; Codex and Grok TOML use `tool_timeout_sec = 900`. R2-D verified Codex's
field: 5 seconds caused a tool timeout at 5 seconds, while 900 seconds allowed the
240-second tool to complete. Claude/Gemini/Grok field effectiveness remains unmeasured.
Preserve other servers, custom commands/environment and user hooks when updating entries.
Devin 3000.3+ uses `.devin/mcp_config.json` / `.devin/mcp_config.local.json` or
`~/.config/devin/mcp_config.json`; `--config` for its main settings alone does not isolate
MCP servers. The [current Devin configuration contract](https://docs.devin.ai/cli/extensibility/mcp/configuration)
describes the dedicated files and migration.

The server selects its budget using the actual `clientInfo`. Exactly
`codex-mcp-client` version `0.162.1` now gets 180 seconds, supported by calls lasting
240 seconds with and without progress. Other Codex names/versions get 50 seconds,
leaving a ten-second margin for an unverified 60-second timeout; an explicitly confirmed
server timeout of at least 190 seconds can permit 180 seconds. Explicit runtime overrides
and smaller confirmed timeout caps still take precedence. Generic `rmcp`, including
Devin's client, remains at 50 seconds. A dedicated Devin server can use a scoped
`KEYVALET_RUNTIME_BUDGETS` override; do not raise every `rmcp` client globally.
Initial waits default to 60 seconds and later waits allow 5–600 seconds, capped by the
remaining runtime budget. Progress stays at 15 seconds and requires a client token.
A timeout notification lowers that MCP instance to 50 seconds without denying its approval.

| Runtime / installed version | Server budget | Four minutes: progress / silent | Real clientInfo / token | Stop evidence | Channels |
| --- | --- | --- | --- | --- | --- |
| Claude Code CLI 2.1.282 | 180 s; hosted verification pending | Not entered: existing provider's HI call had no reply at the 45 s supervisor deadline; Claude OAuth expired before tools | No new tool/token measurement | W5 synthetic-model evidence only; no R2-D live Stop test | Idle wake, busy merge and disabled-channel discard deferred for a usable session |
| Claude Desktop | 50 s | Not installed | Unmeasured | No new registration | Unmeasured |
| Codex exec 0.162.1 | 180 s for this exact client/version; other versions 50 s | 240.015 / 240.006 s; 16 / 0 progress notifications; neither killed | `codex-mcp-client` / `0.162.1`; token in both | Nine fields; actual `block` followed by `credential_wait_approval`; later model stream / round did not finish before the supervisor deadline | Not a V1 channels target |
| Codex TUI 0.162.1 | Same | 240.007 / 240.012 s; 15 / 0 notifications; neither killed | Same; token in both | This round's Stop test was exec; W5 separately measured TUI | Not a V1 channels target |
| Gemini CLI 0.39.1 | 180 s; unverified | Login prompt; no tool measurement | Unmeasured | `AfterAgent` schema has CI; live behavior unmeasured | Not a V1 channels target |
| Cursor IDE | 120 s for an explicit IDE name | Not installed | Unmeasured | `stop` schema has CI | Not a V1 channels target |
| cursor-agent 2026.10.01-e373342 | 50 s | Account usage exhausted before tools; no new measurement | W5's `Cursor` / `1.0.0` and absent token are historical evidence | Live input unmeasured | Not a V1 channels target |
| Grok Build 1.0.50 (cached native binary; not on PATH) | 180 s; unverified | `NotSignedIn` before tools | Unmeasured | No Stop registration | Not a V1 channels target |
| Devin CLI 3000.11.3 | 50 s for generic `rmcp` | 240.006 / 240.007 s; 16 / 0 notifications; neither killed | `rmcp` / `3.1.0`; token in both | Five fields; `block` continued into the wait tool, returned the original result, then active loop released | Not a V1 channels target |

A four-minute completion establishes a lower bound, not an exact timeout or proof that
progress resets an idle timer. Codex and Devin followed `next_steps` both before and after
adding the instruction to call the wait tool before finishing when no independent work
remains. Neither repeated the original request. Stop checks still use the authenticated
process identity and at most three blocks. The live Rust hook fixture measured actual
input field names and accepted output; it does not prove installed helper peer authentication.

MCP outcomes are normal tool results (`isError=false`): pending means wait, denied means
do not bypass approval or ask for a key, expired allows a new request if still needed,
and explicit local cancellation returns `approval_cancelled`. Current helper IPC's
`approval_expired` plus `reason: "cancelled"` is adapted to that cancellation state.
A local prompt timeout remains pending while its retained `approval_id` / `expires_at`
is unexpired. A transport cancellation alone never means local refusal.

HTTP known-host hints remain 600 seconds for OpenAI/Anthropic, giving a 540-second
connection wait; unknown hosts get 55 seconds. Pending returns HTTP 429 with
`Retry-After: 30` and `X-KeyValet-Approval: pending; id=…`. TCP keepalive sends no HTTP
heartbeat. Terminal outcomes have JSON `error.type`:

| Local outcome | HTTP | error.type |
| --- | --- | --- |
| Explicit denial | 403 | `keyvalet_approval_denied` |
| Explicit cancellation | 409 | `keyvalet_approval_cancelled` |
| Approval exp reached without a decision | 410 | `keyvalet_approval_expired` |

Terminal responses set `x-should-retry: false`. Both official Python SDKs respected it
with their default retry count of two. Expiry is a gone approval resource, so 410 avoids
confusing it with a transport timeout or automatically creating a new prompt.

A downstream disconnect during approval keeps the operation in the same live gateway
session. Retry the identical method, URL, headers and body with the same credential token
and `X-KeyValet-Approval-Id: <approval_id>` to claim the retained response once. SDK retries
without the header can also join the identical active binding. Retry-count and approval-ID
headers do not enter the approval binding or reach the upstream. The cache holds at most
16 tickets and 8 MiB per detached response; exp or session revocation clears it. A larger or
interrupted detached response returns `keyvalet_response_unavailable` without executing
again. Original live responses retain streaming behavior. Claims count at response handoff;
this is not external HTTP exactly-once delivery or recovery across gateway/helper restart.

OpenAI Python 3.29.0 and Anthropic Python 1.13.0 succeeded through the actual loopback
gateway in HTTP/1.1 and with `http1=False, http2=True`. The gateway now validates HTTP/2
`:authority` as well as Host. A `*.openai.com` / `*.anthropic.com` credential allows a concrete
subdomain, and rejects the apex and deceptive suffix before helper use. Transparent
CONNECT bindings remain explicit DNS hosts; h2-only clients should use the direct gateway.

Only Codex and Devin's usable hosted accounts were measured this round. Claude's usable
session and a third runtime, channels, unmeasured timeout fields and installed native UI
outcomes remain pending in [R2-D](remote-approval-reports/R2-D-runtimes.md) and
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
