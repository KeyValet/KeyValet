# KeyValet

**Keys in the chip. Approval in your hand.**

Let AI agents use any API, on any machine, without ever holding a secret. KeyValet keeps your API keys and OAuth accounts in a hardware-protected vault that only a system service can read — not the agent — and makes each call for the agent after you say yes.

[Install](#install) · [Website](https://keyvalet.dev/) · [Guide](https://keyvalet.dev/guide/) · [Security](SECURITY.md) · [简体中文](README.zh-CN.md)

Works with Claude Code, Codex, Cursor, Gemini CLI, Grok, Devin — any MCP client or HTTP SDK — on macOS, Linux and Windows 11.

## Why KeyValet

Most "the agent never sees the key" tools run the broker as the agent's own user, with the master key in a file or an environment variable. A prompt-injected agent can read both. KeyValet is built so it can't:

- **The broker isn't the agent.** The vault belongs to a root daemon on macOS, a dedicated system user on Linux, a LocalSystem service on Windows. The agent's process can't read the file or the memory.
- **The key is in the chip.** Secure Enclave on macOS (required), TPM 2.0 on Linux, Windows Hello on Windows. Copying the vault gets you ciphertext.
- **One approval, one call.** Per-use prompts show the real request — method, host, path, the fields that matter — and one touch runs exactly that call, once. Loosening anything always needs your fingerprint.
- **Nothing leaves your machine.** No account, no cloud, no telemetry. The audit log is local and the agent can't read it either.

What it doesn't do: protect you from a compromised root/SYSTEM on the same machine, or verify what an agent *says* it's doing. The complete list is in [SECURITY.md](SECURITY.md).

## How it works

1. **The agent asks** — over MCP or through the local gateway, naming the credential and why.
2. **You approve** — Touch ID, polkit or Hello. Per credential by default; per call if you want, with the real request on screen.
3. **KeyValet makes the call** — the privileged service injects the key, only toward hosts you allowed, and scrubs anything that echoes it back.
4. **The agent gets the answer** — never the key. Session, purpose and result go to the audit log.

## Try it

```sh
curl -fsSL https://keyvalet.dev/install.sh | sh
```

Then just talk to your agent:

> `/keyvalet:add openai` — a native dialog asks **you** for the key; it never passes through the chat.
>
> "Use KeyValet to list my OpenAI models." — one Touch ID, and the agent gets the response, not the key.
>
> "Connect my GitHub account through KeyValet and create a repo called demo." — OAuth, refresh tokens and private keys stay in the vault; the agent only ever holds a short-lived token.

Pasted a key into the chat anyway? The hooks catch it and store it in KeyValet instead of a `.env` file.

Under the hood: ~50 service templates, OAuth 2.0 with automatic refresh, Google service accounts, GitHub Apps, JWT, TOTP, AWS STS, a streaming gateway for SDKs (`OPENAI_BASE_URL=…`), `keyvalet scan` to pull existing secrets out of `.env` files, and approval modes from per-call to "remember for 8 hours".

## Install

| | Requirements | Details |
| --- | --- | --- |
| **macOS** | Apple Silicon, macOS 14+. Signed and notarized. | [Guide](https://keyvalet.dev/guide/#install) |
| **Linux** | systemd, polkit, sudo; `tpm2-tools` for TPM 2.0, or explicit `--software` without a TPM. x64 and ARM64. | [Linux](docs/linux.md) |
| **Windows 11** | 24H2+, Windows Hello. Unsigned x64/ARM64 release packages; signing is optional for local and remote features. | [Windows](docs/windows.md) · [WSL](docs/wsl.md) |

The one-line installer above picks the right package, asks for your password once, and configures the agents it finds (Claude Code, Codex, Cursor, Grok, Devin CLI). Uninstall: `curl -fsSL https://keyvalet.dev/install.sh | sh -s -- --uninstall`. Key protection, recovery and platform limits: [protection matrix](docs/key-protection.md).

## Next: approve from your phone

Today you approve on the machine the agent runs on. Next, agents run on machines nobody is sitting at — a Linux server, a headless Mac mini, an overnight job — and the *approval* comes to whatever is in your hand: a phone app (iOS + Android), or the laptop you're already using.

- The key never moves: it stays in the TPM / Secure Enclave of the machine that runs the agent. Your phone signs an approval bound to one request; the relay carries only ciphertext. The phone app uses the official relay; a self-hosted relay works with laptop approvers.
- You set the boundary — this once, 1 hour, this session, this credential always, this machine always — and can tighten, revoke or lock remotely. Loosening needs Face ID / Touch ID; tightening never does.
- A timeout is never a "no": the agent gets "pending", keeps working, and picks up the result when you approve.

**Status: in development.** The protocol, relay and helper checks are on `main` with software tests; the end-to-end pair → phone approval path and the phone app distribution are not finished. Design: [architecture](docs/remote-approval-architecture-2026-10.zh-CN.md) · [product](docs/remote-approval-product-2026-10.zh-CN.md) · [open items](docs/remote-approval-reports/OPEN-QUESTIONS.md).

## Learn more

[Guide](https://keyvalet.dev/guide/) · [Security model](SECURITY.md) · [Contributing](CONTRIBUTING.md) · [Code of Conduct](CODE_OF_CONDUCT.md) · [Governance](GOVERNANCE.md) · [Trademark](TRADEMARK.md)

Apache-2.0 · by [Simvito Limited](https://github.com/KeyValet)
