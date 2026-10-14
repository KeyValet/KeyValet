# Windows support

Windows release packages are unsigned. The service, Hello provider, UI agent, local installer and
remote approval implementation do not require an Authenticode certificate. Native x64 and ARM64
service/build/test validation has passed; the remaining interactive client and hardware checks
are recorded below. Cross-target checks alone do not establish successful Windows hardware behavior.

The target is Windows 11 24H2 or later (build 26100+), with Windows Hello configured for the
installing account. Current paths assume Windows is installed on `C:`. One Windows account owns
each installation. CI executes the service and tests on native x64 and ARM64 Windows runners.
Current-main packages include the [WSL stdio bridge](wsl.md), using the same Windows
vault and authorization. The original v0.3.0 tag predates these follow-up changes.

| Area | Implementation | Verification still needed |
| --- | --- | --- |
| W1: portability and CI | Shared Rust code, Windows paths, native x64 and ARM64 build/clippy/workspace tests | Physical ARM64 Hello and desktop behavior |
| W2: privileged service | SCM LocalSystem service, protected vault ACL, owner SID, local named pipes, service-created agent and MCP workers, authenticated process identities; native no-Hello installation/upgrade/restart tests pass | Installed GUI worker isolation, second-account credential/gateway rejection and interactive lifecycle checks |
| W3: Hello and UI | `kv-agent.exe`, fixed challenge signature + HKDF, shared device binding/recovery/rotation, native WinUI 3 approvals and hidden secret input | Physical x64 create/sign, repeated RS256 signatures, software-executor Strong and independent UserCanceled(3) pass. Installed protected MCP unlock/lock, observed Windows Security cancellation and unlocked-client crash cleanup pass on the earlier package. Presence crashed and has a native-tested lifecycle fix awaiting deployment; current WinUI/public-client lifecycle remains under acceptance |
| W4: installation and packages | UAC installer, login launcher, client config merge, PowerShell exports, unsigned x64/ARM64 release ZIPs; no-Hello fresh install/upgrade/uninstall pass; WSL bridge implemented | Interactive owner/UAC installation, live Claude Code/Codex/Cursor and WSL sessions |
| W5: distribution | Native x64/ARM64 package workflow included in the tagged draft release; published SHA256 checksums; Authenticode optional | Hardware matrix, SmartScreen observation, maintainer publication |

## Windows release identity policy

Windows executables are accepted without an Authenticode signature. The helper authenticates the
actual named-pipe process/token, owner or relay service SID, fixed installed file identity and
privileged ownership/ACLs of the executable and parent directories. Agent and MCP workers must
also match service-created child processes. These checks apply equally to signed and unsigned
packages. `agent_trust` reports `installed` for an accepted Windows agent.

Installation and remote pairing/approval require no unsigned opt-in. The legacy `-AllowUnsigned`
packaging and `-AllowUnsignedAgent` installer switches remain accepted for compatibility and
have no effect. Upgrades remove the old protected development markers. This policy supersedes
the signature requirement recorded in earlier acceptance reports and archived packages.

## Native approval windows

Remote approvals, SAS pairing, standing-grant confirmation and device revocation now use
WinUI 3 controls through Microsoft's `windows-reactor` Rust projection. Each dialog runs in
a short-lived `kv-agent.exe --remote-window` child, separate from the agent's Hello apartment;
the child only returns an unsigned UI choice. Existing scope validation, confirmation-label
matching, hardware authentication and signed decisions remain in the shared Rust flows.
Closing a dialog, Escape and timeout leave the approval pending. The HTTP method and destination,
requester protection, risk and the agent's explicitly labelled description remain visible;
process details and the optional denial editor can be expanded. The layout supports scrolling,
resizing and the system's light/dark theme.

Building the Windows UI requires Rust 1.95 or later (CI uses current stable). The build stages
the pinned Windows App SDK runtime with a separate cache for each architecture. Windows ZIPs
include the runtime, its Microsoft signatures and `bin/native-ui-runtime.json`; installation
checks hashes/signatures and protects runtime files with the same administrator-owned ACLs as
the agent. No separate runtime installation or MSIX registration is required. GUI-only checks
remain ignored in Cargo tests: `cargo test -p kv-agent remote_winui -- --ignored --nocapture`.

## 2026-10-14 unsigned closure

The earlier K4/inbound snapshot passed Mac and native Windows x64 workspace fmt/clippy/build/test. Later WinRT lifecycle and shared-tree release/rejoin changes are undergoing a separate integration run; new Mac compilation is paused below the 15 GiB space threshold. K4 reception requires the signed current executor label for every finite/standing T2 Grant and rejects wildcard/global T2; startup retires old incompatible tickets, and use revalidates authority. Accepted inbound approvals commit to SQLite and the existing vault audit checkpoint before relay ACK. Restart verifies the latest receipt hash, original envelope signature and current sender authority without another hardware ECDH. Cancellation/issuance/expiry and escalation survive restart; desktop wake resumes the pending queue with at most five dialogs. These changes do not claim hardware rollback protection or external HTTP exactly-once.

Seven native executables now include SDK version resources while retaining the Windows manifest. `scripts/prepare-windows-signing.ps1` and the optional signing-input workflow validate fixed PE names, architecture, product/version and unsigned hashes. The SignPath Foundation application was declined for insufficient public visibility. Windows releases proceed unsigned; the signing preparation is optional.

`test-windows-desktop.ps1` runs the installed MCP launcher and real service-owned worker as the unelevated owner. Physical Success, observed Windows Security cancellation, explicit lock, EOF and unlocked-client crash cleanup passed on snapshot 2 (8/7/7 checks). Cancellation requires both API rejection/locked state and an operator receipt; the initial run without an observed Hello prompt is retained as insufficient evidence. No credential values are read. Physical SYSTEM dual-PCP/Quick/HPKE and cleanup also passed. These receipts do not establish real AI model calls or exported-file cleanup.

The ignored presence capture crashed on its second `IsSupportedAsync` call. A fake SDK reproduced factory reuse after WinRT teardown; the fix retains a thread apartment and a service-process MTA across worker replacement. Native targeted regression and Clippy passed; actual lock/unlock retesting awaits SSH recovery. Unknown/unavailable signals still classify as away. See [current receipts and limits](remote-approval-reports/R3-B-unsigned-acceptance.md#8-供电恢复后的真机续验) and [optional signing](windows-signpath-setup.zh-CN.md).

## Remote approval V1 status

Current-main source adds `KeyValetRelay`, a separate virtual service account
`NT SERVICE\KeyValetRelay`, and its dedicated `\\.\pipe\keyvalet-relay` transport. The installer
registers the service before restarting the helper, gives it read access to public
`relay-client.toml` and Modify access only to `C:\ProgramData\KeyValet\Relay`. It does not give
the relay account access to the credential vault. The unpaired service starts automatically and
waits for binding, including with unsigned executables; the installer never invents account/device
IDs. The helper accepts only the actual relay service account at its protected installed path.

On Windows, a denied metadata read does not establish whether the protected configuration
exists. The relay asks the authenticated helper's relay-only `remote.relay.config_presence`
operation about the fixed installed path. Only an authoritative `exists: false` enters the
waiting loop. An existing unreadable configuration, a failed identity check or a malformed
response remains an error. Custom configuration paths cannot borrow this absence proof.
The operation neither reads configuration contents nor accepts a path/account/device argument,
and works before remote identity enrollment. Application event 1001 from `KeyValetRelay` records
`waiting_for_relay_binding`; event 1002 records binding readiness.

The LocalSystem helper grants the fixed relay service SID only query access to its actual process
object (`PROCESS_QUERY_LIMITED_INFORMATION`) and primary token (`TOKEN_QUERY`). This permits the
existing pipe-server token, executable file identity and protected-path checks. These two object DACLs change;
vault/directory/service permissions, default-token descriptors and protected worker descriptors
do not. No memory access, token duplication/impersonation or debug privilege is granted.

| Remote path | Tested source evidence | Native Windows acceptance |
| --- | --- | --- |
| DK: PCP ECDH P-256 + dedicated PCP ECDSA P-256 | K1 optional `dk_sig`, common identity verifier and legacy vectors | Native LocalSystem dual-key creation/reopen, identity signature, raw ECDH, HPKE and cleanup pass on the TPM 2.0 VM |
| Quick: separate PCP ECDSA P-256 / ES256 | Helper selects a dedicated Quick key; approval verifier uses `ak_q.alg` | Native Quick approval of a software executor fixture passes; desktop click acceptance pending |
| Strong Hello RSA-2048 / RS256 | Valid terminal completion notification and bounded status query, followed by GetResults, pinned-key and RS256 validation | Physical x64 AK_s creation, native T2 approval, genuine repeated signing and software-executor HPKE/nonce verification pass. Independent cancellation returns UserCanceled(3) in 2.22 s, with no signature; deletion reopens as NotFound. The combined round retained its cancellation timeout/exit 101. Original VM remains waiting for PIN; production bound relay/client acceptance remains pending |
| Desktop approval / SAS / scope / confirmation | Shared Rust view/flow tests; PairConfirm now uses W0 JCS | TaskDialog DPI and keyboard/timeout pending; installed protected worker startup and local Hello vault flow pass |
| Relay virtual account / private pipe | Authenticated fixed-path absence probe; exact process/token metadata grants; fixed relay SID, file identity and protected-path checks; unsigned releases start automatically | Prior VM waiting/unreadable-config tests used a disposable trusted signer. The current CI harness runs those tests with unsigned packages and no opt-in; bound end-to-end acceptance remains separate |
| Presence | Conservative injectable state machine; WinRT factory lifetime fix has native regression coverage | Physical capture crashed before transitions completed; fixed deployment and real lock/unlock retest pending |

The [2026-10-12 native VM acceptance](windows-native-acceptance-2026-10-12.zh-CN.md) verifies
current-main x64 workspace tests, installation, ordinary-owner IPC, remote service registration,
upgrade, uninstall and restart. The [R2-B acceptance report](remote-approval-reports/R2-B-windows.md)
records K1 dual-key hardware and fixture results. The [2026-10-13 physical Hello report](remote-approval-reports/R2-B-physical-hello-2026-10-13.md)
records native RSA signing/cancellation and the physical worker startup fix, installed Hello setup and vault unlock. Earlier intermittent vault timeouts remain documented.
The [R3-B Windows closure report](remote-approval-reports/R3-B-security-closure.md) records the
unbound relay fix, native negative cases, metadata access boundary and the current T2 fixture result.
The original VM remains waiting for PIN.
The older WSL results below verify the earlier local implementation. PCP is an identity key provider, not a
hardware presence gate. Hardware failure never selects software implicitly; an explicit
software provider reports `key_kind=software`.

| Windows remote key | Stored public key | Algorithm / use | Context |
| --- | --- | --- | --- |
| DK agreement key, PCP TPM P-256 | `dk_pub` (the existing HPKE public key field) | ECDH; RFC 9180 HPKE decapsulation | LocalSystem, no user presence |
| DK identity signing key, distinct PCP TPM P-256 | Optional `dk_sig: {pub, alg: "ES256"}` | ECDSA/SHA-256; 64-byte P1363 signatures for auth, pairing, recovery and envelopes | LocalSystem, no user presence |
| Quick approval key, another PCP TPM P-256 | `ak_q: {pub, alg: "ES256"}` | ECDSA/SHA-256 approval decisions | LocalSystem signing after owner UI authorization |
| Strong approval key, Hello RSA-2048 | `ak_s: {pub, alg: "RS256"}` | PKCS#1 v1.5/SHA-256; 256-byte signatures | Unelevated owner desktop; PIN/biometric prompt |

When `dk_sig` is present, every identity verifier uses it; malformed/null/unsupported `dk_sig`
fails validation. Records that omit it keep the original ES256 verification against `dk_pub`.
HPKE always uses `dk_pub`. The complete record, including `dk_sig` and all unknown nested fields,
participates in JCS signatures and record digests. Approval signatures continue to use their
recorded Quick/Strong key and algorithm.

PCP metadata version 2 pins the separate identity key names and public keys in authenticated
vault metadata. Creation failures clean up newly created keys and return an error; reopening a
missing half also fails. Existing unsuccessful PCP version 1 metadata is rejected rather than
silently converted or replaced with software. Explicit DPAPI software selection remains separate.
`status --json` exposes `remote_identity.pcp_ecdh`, `pcp_ecdsa` and `ready`; `status --summary`
shows each half as present, absent or unknown. This is a read-only inventory of KeyValet's PCP
machine keys, separate from enrollment and physical TPM evidence.

Remote approval does not give a Linux/Windows helper protection against root/SYSTEM. Signed
approvals protect the protocol against unprivileged agents and an untrusted relay; a compromised
SYSTEM helper can still read/use credentials. See [remote boundaries](../SECURITY.md#remote-approval-v1).

Workflow-generated Windows packages include the new binaries and W3 service assets. Public
packages are unsigned and join macOS and Linux artifacts in the tagged draft release.
`scripts/install.ps1 -Uninstall`, run as the original owner, removes the remote service and
managed runtime entries before the base uninstall. Queues/certificates/vault remain by default.
Installer source/parser tests are separate from real Windows lifecycle acceptance.

## Build and install a Windows release

Use a Windows development machine with stable Rust, Visual Studio C++ build tools and the Windows
SDK. Add the ARM64 C++ tools when building that target. Enable Windows Hello first. Build from
the repository root in PowerShell; the tag must match `rust/crates/kv-cli/Cargo.toml`:

```powershell
rustup target add x86_64-pc-windows-msvc
.\scripts\package-windows.ps1 -Tag v0.3.0 -Architecture x64
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\install.ps1 `
    -PackagePath .\dist\keyvalet-v0.3.0-windows-x64.zip
```

Start installation from the intended account's **unelevated** interactive PowerShell. UAC handles
only the system phase. The original user then gets the MCP/hook configuration and Hello setup.
If installation starts elevated, sign out and back in before running setup from an elevated
terminal. The installer does not create a Hello key as SYSTEM or as a different UAC account.
An existing vault owner cannot be silently changed by rerunning the installer as another account.

No signing certificate or development marker is needed. The installer validates package paths,
PE architecture, privileged ownership and existing ACLs before replacing an installation. The
vault and device binding files retain their private ACLs.

For an optional signed local build, add `-SigningCertificateThumbprint <certificate-thumbprint>`.
The signing option verifies the certificate belongs to `Simvito Limited`; runtime feature access
is identical for signed and unsigned packages. **Actions → Windows package → Run workflow**
builds unsigned artifacts. The reusable workflow also runs during the main release workflow and
adds x64/ARM64 ZIPs to the tagged draft release without Windows signing secrets.

The online installer verifies a published ZIP against the release's `SHA256SUMS`; the draft
release must first be published by a maintainer. Each package job emits `SHA256SUMS-windows-x64`
or `SHA256SUMS-windows-arm64`; the release workflow verifies all five platform packages and
assembles a combined checksum file. Until publication, use `-PackagePath` as above.

### Unsigned release distribution

Unsigned release packages include `WINDOWS-RELEASE.txt` and the installer/uninstaller. Local
and remote functionality is available without Authenticode signing. Removing the signature
requirement does not establish new interactive or bound end-to-end acceptance; the full live
AI-client and protected cancellation lifecycle remain recorded separately.

Credential operations require the protected installed path; this is an installer package, not
a portable vault. Downloaded unsigned programs can encounter SmartScreen warnings or be blocked
by application control policy; browser-download behavior has not been tested.
See [Microsoft's signing guidance](https://learn.microsoft.com/en-us/windows/apps/package-and-deploy/code-signing-options)
and the [earlier signing investigation](remote-approval-reports/R3-B-security-closure.md).
Previously distributed preview ZIPs retain their old runtime checks; rebuild or install the new
release package to use this policy.

## Operation and recovery

Run administrative CLI commands in an elevated terminal. UAC can use a separate administrator
account; Hello still runs as the recorded vault owner in the original interactive session:

```powershell
& 'C:\Program Files\KeyValet\bin\kv-cli.exe' setup-hello
& 'C:\Program Files\KeyValet\bin\kv-cli.exe' protection
& 'C:\Program Files\KeyValet\bin\kv-cli.exe' hello-test
& 'C:\Program Files\KeyValet\bin\kv-cli.exe' rotate-recovery
```

`keyvalet.ps1` in the install bin directory provides a UAC wrapper for interactive CLI use. Use
`kv-cli.exe` directly in the elevated terminal when input/output must stay in that terminal.
`keyvalet status --summary` (or `kv-cli.exe status`) is the read-only exception: the owner can
query the authenticated service without UAC or Hello. The installer prints this summary in the
original console after setup, including when `-SkipSetup` leaves the vault uninitialized.
Recovery passphrases go through hidden terminal input or native secret input, never a CLI argument
or the AI chat. `recover-vault` rebinds using the recovery passphrase and a new Hello key;
`recovery-read list` or `recovery-read get <type> <name>` provides emergency read-only recovery.
Rotation refuses to proceed while helper sessions exist. Close or lock all clients first.

`status` / `protection` report `provider: "windows_hello"`, recovery configuration and device binding.
`key_protection` describes the scheme, hardware evidence and Hello authorization; `tpm` reports
the current system device through TBS, without inferring physical vs virtual implementation.
The creation-time Hello attestation and current device detection are separate. A detected system
TPM does not prove that this key uses it. See the [protection matrix and fields](key-protection.md).
`tpm_backed: true` means the OS returned successful key attestation. `null` means unknown, not
proof that the device lacks a TPM; KeyValet does not independently validate attestation
certificates. Windows Hello may use OS-managed software protection when a TPM is absent. KeyValet
currently accepts unknown attestation on its supported Windows 11 24H2+ target, displaying
`hardware: "unknown"` prominently. This is an application policy, not a Windows-version rule that
permits or forbids unknown. Successful recorded attestation displays `hardware: "os_reported"`;
KeyValet does not claim independent verification. `hardware_required` is false for this provider.
KeyValet requires Hello and does not generate a `master.key` fallback. It rejects signatures that do not
verify as RSA-2048 PKCS#1 v1.5/SHA-256, rather than deriving an unstable key from a different format.
The implementation follows the signing flow in Microsoft's
[Windows Hello guidance](https://learn.microsoft.com/en-us/windows/apps/develop/security/windows-hello).

The vault and audit log live in `C:\ProgramData\KeyValet`, with access restricted to SYSTEM and
Administrators. Recovery depends on the recovery passphrase and the encrypted vault. The device
binding files add a separate privileged local secret; a copied `vault.enc` and a Hello signature
alone cannot decrypt a bound vault. Do not expose the binding files to an unprivileged client.
Administrators/SYSTEM remain outside the protection boundary.

`KeyValetAgent` is a login **launcher**. It asks `KeyValetHelper` to start the real UI worker using
the interactive owner's WTS token. The service assigns restricted process/thread descriptors
before that worker starts, retains its process handle and accepts only that child PID. The
worker's executable must also pass owner SID, installed file identity and ancestor ACL
checks. The service stamps a distinct token security attribute for each launch, requiring SeTcbPrivilege.
Conditional ACEs let that worker initialize its own objects while ordinary owner processes and
other workers retain only identity queries. The process starts suspended; its actual token object's
owner and DACL are set before resume. Ordinary processes cannot duplicate/impersonate that token,
change its default DACL, or gain thread-context/VM access; OWNER RIGHTS also protects new threads.
Failure to set the attribute or descriptors rejects launch. Creation-time mitigation attributes disable legacy extension points/global hook DLLs,
dynamic code and non-Microsoft DLL loading, using Microsoft's
[process attribute API](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-updateprocthreadattribute).
This must be tested with
WinRT/Hello on a real Windows desktop; Rust type checks do not establish compatibility of those
restricted descriptors with every OS component. The service restarts a crashed worker or a
worker whose broker connection has expired, so a late Hello response cannot leave a permanently
retired agent in place. Reopen/reauthenticate credential sessions after an agent restart. A worker
enters an unnamed, non-inherited Job Object during process creation. Its kill-on-close policy
also terminates the process tree if the helper crashes; see Microsoft's
[Job Object lifecycle](https://learn.microsoft.com/en-us/windows/win32/procthread/job-objects).
Closing the service terminates the child. An ordinary invocation of `kv-agent.exe` only launches it;
`--serve` started outside the service is rejected by the helper. Privileged confirmations also
require a fresh signature against the pinned Hello key after the purpose dialog; desktop button
automation alone cannot approve them. Workers require an unelevated owner token with UAC enabled.
Hello operations share one 120-second request budget (shorter than the helper's 130-second
deadline); expired WinRT operations are cancelled. A new key is removed if credential retrieval,
public-key validation, metadata creation or initial signing fails. Approval requests with missing
or invalid pinned metadata do not open a dialog or invoke Hello.
These process restrictions are not VBS/PPL isolation or a secure input desktop. The generic
secret-entry dialog uses the ordinary interactive desktop; protection against same-desktop
keyboard/screen monitoring is not established by these tests and needs separate validation.

Before listening, the service grants the recorded owner only process query-limited and token
query rights, allowing clients to verify its kernel PID, SYSTEM SID, installed file identity and ACLs
without administrator/debug privileges. Token duplication, impersonation and adjustment remain
denied to that owner. Windows checks the token DACL separately from the process DACL; see
[access-token object rights](https://learn.microsoft.com/en-us/windows/win32/secauthz/access-rights-for-access-token-objects).
Identity and protected-path checks happen before any client protocol bytes are sent.

MCP clients run `C:\Program Files\KeyValet\bin\kv-mcp.exe` as a stdio launcher. The authenticated
SYSTEM service starts a separate protected `kv-mcp.exe --worker` in the owner's interactive
session, with the same process/thread/token restrictions as the Hello agent. A private random
named pipe accepts only the retained child PID. The service relays the MCP stream; native secret
input and imported private files are handled inside the worker. Only the project directory,
language, session TTL (zero or at most one year) and requested grant mode are forwarded from the launcher; its environment,
executable and claimed session identity cannot select the worker. Raw values deliberately
requested with `credential_get` still reach the MCP client under the normal authorization policy.
Client EOF closes the whole channel, locks the helper session and removes session files. A stuck
worker is terminated, followed by a protected cleanup process; startup also purges dead creators.

The installer merges Claude Code, Codex and Cursor configuration, backs up existing files to
`.bak-keyvalet`, preserves unrelated MCP servers/hooks and sets Cursor hook schema version 1.
JSON updates use atomic replacement. Mixed user/KeyValet hook rows retain their user commands;
invalid hook schemas are refused without replacing the existing configuration. Before extraction,
the installer checks a single version/architecture root, required files, case-insensitive duplicate
names, path traversal, reserved Windows names, ZIP links and expansion limits. Every executable
must have a matching x64/ARM64 PE32+ header in unsigned release packages. Upgrades validate
existing owner-record/binary ACLs and service configuration before stopping the running service.
An existing Codex `mcp_servers.keyvalet` table is kept and must be reviewed if its command is stale.
An upgrade stops existing installed agent/MCP processes. Restart clients after installation,
and trust Codex hooks with `/hooks` before expecting them to
run. Slash-command/plugin distribution for Windows is a separate follow-up; MCP and hooks are
configured directly by this installer.

The desktop acceptance harness runs from a source checkout in the ordinary owner PowerShell.
Use a fresh output directory for each run:

```powershell
.\scripts\test-windows-desktop.ps1 -AllowSystemChanges -Mode Preflight `
  -ResultDirectory "$env:USERPROFILE\KeyValet-Test\mcp-preflight"
```

`PreflightCrash` performs the same locked-state checks and kills only its own test launcher.
Both modes require the protected helper installation and an owner desktop, but no Hello prompt.
For `Success`, `Cancel` and `Crash`, first click **Verify and allow** in the KeyValet purpose
dialog, then approve the new Windows Security prompt for Success/Crash or cancel that security
prompt for Cancel. Merely letting the purpose dialog time out is not observed Hello cancellation.
After the operator confirms cancellation, save `{"windows_security_cancelled":true}` as
`operator-cancel.json` inside that run's result directory; a failure without this receipt is
insufficient evidence. Test preparation is separate from the production request budget.
These modes use metadata queries; they do not read existing credential values.
The harness verifies the observed helper-created worker exits after EOF/crash. Exported-file
cleanup still needs a test that actually creates an export.

Gateway exports are PowerShell `.ps1` files. Use the returned instruction in PowerShell:

```powershell
. 'C:\Users\you\.keyvalet\run\<generated-file>.ps1'; <your-command>
```

Session files have protected owner-only ACLs from creation, pin their private directory handles
and use create-new filenames. Locking deletes the actual created files by handle and blocks late
writes; startup removes files whose creator PID is dead or reused. Explicit plaintext exports
remain readable by the owning account while the session is active. Gateway TCP clients are
checked against that account's SID using the **client source port**, before bearer-token handling.

Close AI clients before uninstalling. Run `scripts/uninstall.ps1` from an elevated terminal. It
removes the service, task and executables; the vault is retained unless `-RemoveVault` is supplied.
It prints the remaining user-config/PATH cleanup steps rather than removing unrelated settings.

## Validation before a public Windows release

Rust unit tests and offline script checks run without an installed KeyValet, elevation, a desktop
session or real Hello.
They include synthetic Hello vault unlock/recovery/rotation, framed agent replies, pipe identity
checks, SID parsing, loopback identity, private export ACL rejection and PID-reuse cleanup. The
launch protocol rejects extra environment/executable/session parameters, and relay tests require
client EOF to terminate an open worker stream. Handshake schemas reject duplicate fields directly
from the original JSON frame. Tests cover byte-wise slow peers, deadlines that include flushing,
short writes, I/O failures and draining buffered output at worker EOF. Agent-channel tests cover
late approvals after timeout/cancellation, concurrent replies arriving out of order, unknown
payload IDs containing JSON-like bytes, and revocation when an agent connection is replaced.
They also require disconnect/cancellation to clear pending requests, reject binary key frames
as authentication or confirmation approvals, and strictly pin decoded Hello response metadata.
Aligned Win32 buffer and SID parsing tests run on every Rust test host, covering initialized
prefixes, arithmetic overflow, unaligned structures, invalid SID pointers and truncated counts.
Portable Hello tests cover deterministic RSA/HKDF,
corrupt/replaced public keys and signatures, incompatible padding, invalid requests, cancellation,
backend failures, shared prompt deadlines, creation cleanup and raw-payload boundaries. Synthetic
Hello vault tests check that cancelled or inconsistent setup/recovery/rotation preserves existing
data, broken binding files are rejected before prompting, copied vaults require binding or explicit
recovery, and valid-looking metadata edits cannot bypass ciphertext authentication. Native
Windows tests use filtered tokens with `AccessCheck` to verify process/thread/token permissions
and create a disposable child to verify Job Object membership and kill-on-close.
The PowerShell test parses installers without running their system actions and exercises config
merging, Unicode, backups, atomic writes, quoting, malformed archives/checksums and PE headers;
CI runs it under PowerShell 7 and Windows PowerShell 5.1.
Environment export rendering is tested without Windows or filesystem access. Scripts use a UTF-8
BOM for [Windows PowerShell 5.1 Unicode compatibility](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_character_encoding)
and escape [PowerShell's smart single quotes](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_quoting_rules).
NUL-containing values and malformed variable names are rejected before creating a file. Windows
CI explicitly runs an opt-in subprocess test with both PowerShell engines: it executes Rust-rendered
scripts containing synthetic Unicode, multiline values and attempted quote injections, checking
that values survive exactly and the injected code does not run. On a development host with
PowerShell installed, run it without installing KeyValet or requesting elevation:

```sh
cd rust
KEYVALET_TEST_POWERSHELL=pwsh cargo test -p kv-mcp windows_script::tests::powershell_executes_export_fixture --locked -- --ignored --exact
```

The Windows CI job separately invokes `scripts/test-windows-service.ps1` on a disposable clean
runner, with explicit system-change authorization. It builds an unsigned release ZIP from the tested
binaries and checks installation, the real SYSTEM service/pipe peer, no-Hello public status from
a newly created standard test account without administrator/debug privileges,
untrusted file ACL rejection before service stop, wrong-owner refusal, upgrade, SCM restart and
uninstall with vault retention/removal. Its JSON report is uploaded as an artifact. This integration
script refuses any existing KeyValet installation/task/service/vault and removes its temporary
local account/profile during cleanup. It does not create a Hello
key. To run it on a **clean disposable** Windows 11 test machine, from an elevated terminal:

```powershell
cd rust
cargo build --workspace --locked
cd ..
.\scripts\test-windows-service.ps1 -AllowSystemChanges
```

Native validation on 2026-10-11 at `6a013c6` passed in
[CI run 38113625136](https://github.com/KeyValet/KeyValet/actions/runs/38113625136): x64 on
Windows build `10.0.26100.0`, ARM64 on `10.0.26200.0` with the explicitly checked
`aarch64-pc-windows-msvc` host. Both reports recorded `passed: true`, `hello_tested: false`,
unsigned development packages and all eight service lifecycle/owner/ACL checks. The complete
workspace and PS 5.1/7 export execution tests also passed on each architecture. Reports are
the `windows-service-test` and `windows-service-test-arm64` artifacts. This is native VM execution,
not a physical TPM/Hello attestation result.

At `1bdc42b`, the [full cross-platform CI](https://github.com/KeyValet/KeyValet/actions/runs/38115685082)
and [actual x64/ARM64 WSL 1 interop run](https://github.com/KeyValet/KeyValet/actions/runs/38115740726)
both passed. The latter adds packaged WSL asset hashes/ACL rejection and actual native CLI/hooks,
Unicode input, environment forwarding, invalid-TTL refusal and Linux client adapter installation,
reinstall and uninstall. Both downloaded JSON reports contain all ten checks, `passed: true`,
`wsl_interop_tested: true`, `hello_tested: false`, and no error. This validates headless interop
using the CI runner's Windows identity; the owner's protected desktop MCP/Hello session is a
separate check. See [WSL verification](wsl.md#verification) for the installed desktop probe.

After its cleanup, install a release package normally as the intended unelevated owner to
exercise the interactive Hello and MCP paths. Hosted CI does not replace Windows 11
desktop/Hello testing.

| Target / path | Automation result | Desktop acceptance |
| --- | --- | --- |
| Windows x64, SYSTEM service, standard owner, PS 5.1/7 | Passed in the linked native run; physical x64 Hello setup/unlock and remote key fixtures pass | Standard-owner UAC and full protected client/WSL lifecycle pending |
| Windows ARM64, same service/CLI/export paths | Passed on native ARM64; no emulation-only claim | Physical ARM64 Hello + protected WinRT/UI pending |
| Claude Code, native Windows and WSL | Config/hook fixtures; WSL relay fixtures | Live setup → approval → proxy call → disconnect pending |
| Codex CLI / WSL extension | Config/hook fixtures including explicit deny; user hook trust documented | Live `/mcp`, `/hooks`, approval and cancellation pending |
| Cursor, native Windows and WSL environment | Native schema/config/hook fixtures | Live shell/MCP/file hooks and approval pending |
| WSL stdio → Windows vault | Native x64/ARM64 WSL 1 CLI/hooks/env/config lifecycle passed; offline byte/EOF/config and package ACL checks pass | Owner desktop MCP, Linux-filesystem cwd in approvals, Windows Hello and WSL 2 session pending |
| Unsigned Windows x64 / ARM64 | Release workflow packages both native architectures without signing secrets | SmartScreen/application-control observations and the interactive matrix remain pending |

On each real target record the Windows build, CPU architecture, Hello method, signing status and
TPM/attestation result, then check:

- New setup, unlock, cancellation/timeout, missing Hello/key and public-key replacement rejection;
  recovery read-only mode, rebind, rotation and stale-session revocation.
- SYSTEM service boot/stop/restart, agent crash/restart and MCP client disconnect/crash; ordinary same-user processes cannot
  obtain VM-read/write, remote-thread, thread-context or DACL-write access to the service child.
  They cannot change its token default DACL or inject through a third-party/global hook DLL.
  WinRT/TaskDialog/Hello still work with those restrictions, in signed and unsigned test packages.
- MCP native secret input/import stays inside the protected worker; project cwd, language and
  grant mode reach it correctly. Stdout remains valid MCP JSON, with no worker handshake leakage;
  EOF and service stop revoke helper sessions and clean exported files even after worker failure.
- A second local account cannot connect to any service pipe or use the gateway. A squatted pipe cannot
  collect any protocol/key data; a wrong-path, untrusted-ACL or externally launched worker is rejected and audited.
- Fresh install (including a standard owner with separate UAC administrator credentials),
  same-owner upgrade, wrong-owner refusal, Unicode paths/configuration, hooks in
  live Claude Code/Codex/Cursor, PowerShell gateway/secret files, lock cleanup and uninstall.
- Unsigned x64 + ARM64 packages and actual SmartScreen/application-control behavior.
  WSL clients use the stdio bridge and the same Windows approvals; test it separately from an
  independent Linux vault and from the Windows-only loopback SDK gateway.

The interactive key test is opt-in, from an unelevated Windows 11 terminal with Hello enabled:

```powershell
cd rust
cargo test -p kv-agent hardware_roundtrip -- --ignored --nocapture
```

The protected SCM-launched worker needs a separate installed end-to-end test; the opt-in key
test alone does not exercise service process isolation. The WSL desktop probe
`python3 ~/.local/share/keyvalet/wsl/verify.py --unlock` exercises that installed worker and an
actual Hello approval without reading credential values. Run it as the logged-in owner after
setup; record its report alongside the physical/desktop matrix. Physical x64 native Hello creation,
repeated RS256 signing, deterministic vault derivation and a software-executor Strong exchange
pass. Current completion waiting returns UserCanceled(3) in the separate owner diagnostic in
2.22 seconds, with no signature; deletion reopens as NotFound. The combined fixture's cancellation
timeout remains a recorded failure. The physical worker startup fix has been installed; setup-hello and a real vault unlock
through the service-created worker pass. Status reports successful OS key attestation,
windows_hello_tpm, device binding and recovery configured; certificate validation is not independent.
Installed protected-worker sign cancellation, a bound public relay and real client Strong
approval remain pending. See the [physical report](remote-approval-reports/R2-B-physical-hello-2026-10-13.md)
and [R3 acceptance](remote-approval-reports/R3-B-security-closure.md).
