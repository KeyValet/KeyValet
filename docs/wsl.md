# WSL clients using the Windows vault

The WSL stdio bridge is available in development packages built from current `main`; it is not
included in the original v0.3.0 tag. Install KeyValet on Windows first, from the Windows account
that will run WSL, and complete Windows Hello setup. Run your WSL clients as a regular Linux user.

The bridge starts the protected installation's native `kv-mcp.exe` through WSL interop. That
launcher authenticates the Windows SYSTEM service, which creates the protected MCP worker.
The Windows vault, Hello prompts, approvals, credential injection and HTTP requests stay in the
Windows implementation. This follows Microsoft's [WSL Windows interoperability](https://learn.microsoft.com/en-us/windows/wsl/filesystems#run-windows-tools-from-linux): Windows programs use the active Windows user and accept pipes and redirected input/output.

## Install in each WSL distribution

Enable Windows executable interop and access to `C:` in the distribution. Python 3 is required;
preserving an existing Codex TOML config also requires `tomlkit`. On Ubuntu/Debian:

```sh
sudo apt install python3 python3-tomlkit
sh "$(wslpath -u 'C:\Program Files\KeyValet\wsl\install.sh')"
```

The installer checks authenticated public Windows service status without opening Hello. It copies
the bridge to `~/.local/share/keyvalet/wsl`, then configures the Linux user's clients:

| Client | MCP configuration | Secret detection hooks |
| --- | --- | --- |
| Claude Code | `~/.claude.json` | `~/.claude/settings.json` |
| Codex CLI / WSL extension | `~/.codex/config.toml` | `~/.codex/hooks.json` |
| Cursor in the WSL environment | `~/.cursor/mcp.json` | `~/.cursor/hooks.json` |

Use `--clients codex` or `--clients claude codex` to select clients. Existing unrelated servers,
settings and hook handlers are preserved; only the `keyvalet` MCP entry is redirected to the Windows
bridge. Original config backups use the suffix `.bak-keyvalet-wsl` and are retained across reinstalls.
All selected configs are parsed before writing; malformed configs or unsafe file links stop the
installation without rewriting them. TOML comments and unrelated tables are preserved with
[TOML Kit](https://tomlkit.readthedocs.io/en/latest/quickstart/).

Restart the clients. In Codex, use `/mcp` to check connectivity and `/hooks` to review and trust
the KeyValet hook. Codex requires review of non-managed hooks before running them; the installer
does not grant that trust. See the official [MCP configuration](https://learn.chatgpt.com/docs/extend/mcp?surface=cli)
and [hook trust flow](https://learn.chatgpt.com/docs/hooks#review-and-trust-hooks).

To install from a source checkout, run `sh scripts/wsl/install.sh` inside WSL after installing
the matching Windows package. Native Windows applications use the Windows installer's separate
client configuration; a Cursor process running on Windows should use that native configuration.

## Using it

```sh
~/.local/share/keyvalet/wsl/bin/keyvalet status --summary
```

The MCP and hook commands preserve stdin, stdout, cwd and exit status. Their launchers print no
stdout banners. `KEYVALET_LANG`, `KEYVALET_SESSION_TTL_MINUTES`, `KEYVALET_GRANT_MODE` and `KEYVALET_HOOKS`
are forwarded through `WSLENV`; Windows validates the session settings. The cwd is the Windows
view of the WSL directory, usually a UNC path for projects in the Linux filesystem. Closing the
MCP input closes the Windows launcher channel and revokes its worker session.

Prefer `credential_http_request`: the helper makes the request and injects the credential on
Windows, so the agent can run in WSL without receiving the credential. Native secret dialogs and
Hello appear on the Windows desktop. An active, unlocked Windows session belonging to the vault
owner is required. Different Linux users in a distribution are not separate Windows identities;
Windows authorization is based on the active Windows account.

Administrative commands such as setup/recovery/rotation require the Windows UAC path; run them
in a Windows terminal as described in [Windows operations](windows.md#operation-and-recovery).
The WSL CLI wrapper supports the native CLI's unelevated public status operation.

Exported secret-file paths are Windows paths. If an approved workflow needs a Linux path, convert
the returned path with `wslpath -u`. Exported gateway environment files are PowerShell scripts;
source them in PowerShell. The authenticated Windows loopback SDK gateway is not a Linux gateway:
this bridge covers stdio/MCP and hooks, and does not add a WSL TCP listener or change peer checks.
Hooks are a detection aid; unknown credential formats can still escape detection.

## Remove this user's WSL configuration

```sh
sh ~/.local/share/keyvalet/wsl/uninstall.sh
```

This removes the installed bridge's MCP entries and hook handlers, preserving unrelated settings,
config backups and any user-added files. A directory containing user files retains its management
marker for a later reinstall. The Windows service and vault are retained. Remove the
WSL bridge before uninstalling Windows KeyValet, or use this copied uninstaller afterwards.

## Verification

Offline tests exercise byte-exact stdio, EOF, exit codes, arguments containing Unicode/spaces/shell
syntax, environment forwarding, multi-client merges, mixed hook groups, TOML comments/quoted/inline
tables, invalid-config refusal, backups, idempotence and removal. They use disposable fixtures and
require no installed KeyValet or Windows desktop:

```sh
python3 scripts/test-wsl.py
```

The manual **Actions → Windows WSL interop → Run workflow** imports a checksum-verified Canonical
Ubuntu image into a disposable WSL 1 distribution on x64 and ARM64. It runs the real native CLI,
hooks, `WSLENV`, invalid-TTL rejection and user adapter install/reinstall/uninstall while the
SYSTEM service is installed, then removes both the service test data and the distribution.
`wsl_interop_tested` in its service report is true only when those checks run. A runner that needs
a reboot to enable WSL fails its setup; this workflow does not silently substitute mock results.
It covers headless interop, not the owner desktop MCP/Hello path or WSL 2's separate SDK networking.

Windows x64 and native ARM64 CI also install the packaged bridge assets, compare their hashes and
reject writable bridge files before stopping a running service during an upgrade. Actual WSL
interop, Hello prompts and live client sessions require a logged-in Windows 11 owner. From WSL:

```sh
python3 ~/.local/share/keyvalet/wsl/verify.py
# Additionally open one real Windows Hello approval, then immediately lock:
python3 ~/.local/share/keyvalet/wsl/verify.py --unlock
```

The desktop probe checks the actual native Windows hook's stdin/stdout and deny exit code, authenticated public
status, invalid-TTL refusal, protected MCP initialization/tool listing, locked protection status and
launcher exit on EOF. `--unlock` adds Hello unlock and explicit lock. It reads no credential values
and uses a five-minute `per_use` session. The private `interop-test.json` report records only check
results, architecture, provider and whether Hello was actually exercised; cancellation is a failure.
The report's absence is not a passing result. This probe still does not replace testing each live
client's hook/trust flow, actual approval behavior or the separate process-isolation/TPM matrix.
Record results in the [Windows validation matrix](windows.md#validation-before-a-public-windows-release);
offline fixtures alone do not demonstrate a live WSL/client/Hello session.
