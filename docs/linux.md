# Linux support

The local Linux implementation uses a systemd service running as the non-login system user
`keyvalet`, a Unix socket with kernel peer credentials, and polkit for independent user
authorization. The Rust MCP server, CLI, hooks, proxy, streaming gateway and protocol engines
run natively. Linux does not use the macOS passwordless sudo helper path.

## Install

The supported build is GNU/Linux on x86_64 or aarch64, with systemd, polkit and sudo. Ubuntu
22.04 and Debian 12 have CI jobs; Ubuntu 24.04 x86_64 is the current real-machine test target.
ARM64 packaging is defined but has not been tested on ARM64 hardware. Native archives require
the builder's glibc baseline: the archive tested on `ndu` requires glibc 2.39 (Ubuntu 24.04);
the x64 packaging workflow builds on Ubuntu 22.04, while ARM64 builds on Ubuntu 24.04.
Build from source on an older supported distribution. The v0.3.0 release workflow packages
both architectures and verifies them before creating the release. Install a published package:

```sh
curl -fsSL https://keyvalet.dev/install.sh | sh
```

The installer checks the archive's SHA-256 against the checksum attached to the same release.
Alternatively, install a source checkout with stable Rust and a C compiler:

```sh
# Ubuntu / Debian
sudo apt install build-essential pkg-config sudo policykit-1 tpm2-tools
sh scripts/install.sh
```

Run the installer as the regular user who will own the vault. It uses sudo to install trusted
code, create the system account and register the service, then initializes a TPM vault. Keep
the separately entered recovery passphrase offline. Installation displays the protection
summary; `keyvalet status --summary` displays it again without unlocking the vault.

When there is no TPM 2.0, software protection requires an explicit choice:

```sh
curl -fsSL https://keyvalet.dev/install.sh | sh -s -- --software
# Or from a source checkout:
sh scripts/install.sh --software
# After an installation made with --no-setup:
keyvalet setup-software
```

Software setup is refused when a TPM 2.0 is detected. Missing TPM permissions, broken TPM tools,
bad metadata or a failed hardware operation never select software automatically. An existing
software vault remains software on upgrade; use `keyvalet setup-tpm` to migrate it after adding
a working TPM. This rotates the vault key and recovery passphrase.

`--no-setup` installs without initializing a vault; `--no-register` skips AI client configuration.
Re-running the installer preserves the configured provider and vault. The installer registers
Claude Code when available, installs hooks for detected Codex, Cursor and Grok configurations,
and installs the Cursor plugin and a Devin MCP configuration when appropriate. Existing custom
configuration is preserved. Devin's commands and hooks use the repository's Devin plugin.
For another MCP client, configure the stdio command
`/usr/local/lib/keyvalet/bin/kv-mcp`.

## Remote approval V1 (current-main integration)

The repository includes the encrypted relay, relay client, helper verifier and MCP wait/Stop
logic. Software-key integration tests exercise signed approvals through the real relay/helper
and consume each result once. This is development source, not an assertion that the complete
Ubuntu → desktop/phone pairing and approval path has passed installed-device acceptance.
Installed desktop pairing and approval are tracked in the
[R2-A native acceptance report](remote-approval-reports/R2-A-m2-acceptance.md) and
[R3-A closure record](remote-approval-reports/R3-A-m2-closure.md). R3-A reproduced the Mac
owner socket refusing a connection even while launchctl reports the service as running.
A contended synchronous state lock stopped the agent reply pump and filled the accept queue.
The signed Mac repair passes 5/5 installed owner IPC reads (0.0166–0.0325 s). Native
Ubuntu → Mac pairing, including SAS confirmation and the Mac Strong path, completed in
144.165 s; both installed CLIs exited successfully and both device lists contain the peer.
Twenty approval samples and the negative use cases have been measured; revocation,
presence routing and the lid-close window still need installed-device verification.
R3-A also found that runtime session binding still inspected the MCP parent's executable
directly from the unprivileged helper. The broker now proves that same live socket's parent
UID, start time and executable hash for each use. Its native tests cover 14 role/process cases,
including a nondumpable CLI; helper and relay capabilities remain empty. The installed ndu
repair passed native MCP unlock and saved the selected host-restricted proxy credential.
The proof cache retains the original fd and its kernel socket cookie, and duplicates it only
during inspection. Closing the helper connection reaches the client immediately; reusing an fd
for a different socket invalidates the proof. Ten installed status probes left fd/socket counts
unchanged at 17/9 and needed no authentication.
The first Claude attempt then failed provider authentication before calling any tool;
the first installed `keyvalet run` and curl fallback then exited before a password prompt
because its driver registered the terminal agent too late. The corrected driver waits for
pkttyagent's registration notification before execing the installed CLI with the same owner
PID/start time. Registration preflight passed without requesting authentication; GET count
was 0 before the attended retry. The corrected native run then received a Strong gateway
decision and a Quick GET decision; both executed exactly once. The first GET returned HTTP 401
and run exited 0. A normal attended token update then succeeded; the next GET returned
upstream HTTP 403, also with run exit 0. The user chose the original GET for approval
measurements and kept its upstream status separate. Helper request-to-decision times were 5.320 s and 4.797 s, respectively.
The 401 is not API success; the attended refresh used the installed Mac MCP and preserved the same proxy-only
host restriction. The native audit CLI compared two authenticated endpoints: 3 matched
authorization facts, 0 findings and 0 unavailable endpoints. The per_use sampling attempt
then recorded one allowed GET (19.349 s) and one denied GET (no execution); the owner
ended the attended window before 20 samples. Both test processes exited and no approvals
remain waiting. After the owner resumed, 20 identical per_use GETs each executed once: helper request-to-decision p50 3.0905 s (above 3 s), p95 6.0237 s (below 8 s). A deliberate Deny returned approval_denied with no execution. With an initial MCP wait budget of 5 s, continuation executed the same approval once; reclaim returned already_consumed in 0.005954 s, and adding $select=id created a new approval and one execution. No request expiry changed. Total GET executions are 27 (401 once, 403 26 times). ndu currently uses per_use; the two-hour lid test has not started.

The installed remote per_session command took 5.719533 s; the installed MCP read
per_session and tightened it to per_use through the same settings backend. That local
write exposed an audit checkpoint publication bug: SQLite committed its setting_changed
record while the independent vault checkpoint stayed behind. The helper correctly refused
the next delivered Grant. Both settings write paths now use the existing authenticated
audit transaction. A narrowly bound maintenance check verified the full 1943-record chain
and its independent receipts, then published the single observed settings record after a
quiescent root-only backup; no history, nonce, device identity or key was reset. The repaired
ndu helper/CLI are installed, all three services run, and the original signed T1 Grant arrived
once. Ordinary sudo -u keyvalet lacks the systemd TPM group; maintenance used the existing
service UID and its exact supplementary groups, without changing membership or capabilities.
The runtime peer broker still holds only SYS_PTRACE; helper and relay have no capabilities.
See the R3-A report for the one-time recovery evidence; do not reuse its exact hashes on
another state. The attended installed-MCP write now reads the remote per_session setting and tightens
it to per_use; native CLI and remote status agree. The new T1 Grant is installed and
subsequently revoked. The latest per_session / one-hour issuance / revoke-all times are
4.760682 / 6.162329 / 4.992178 seconds (the earlier issuance was 2.777137 seconds,
and the earlier revoke-all was 2.817435 seconds); the latest Strong issuance exceeds 5 seconds.
lock takes 3.300604 seconds. The finite T2 test passed at 21:31Z: both native labels and
real SE Strong issuance took 16.629137 seconds including owner input, the executor
reported unattended=true, and cleanup returned it to per_use with no active Grants. Post-run status has zero pending requests, zero active grants and unattended=false.
The prepared foreground-TTY driver keeps CLI JSON private and requires both real user-entered
labels; it does not substitute confirmations or extend their 120-second deadline. The
21:41:47Z workspace snapshot passed all four checks: 1390 passed / 0 failed / 10 ignored,
with 360 source files unchanged during the run; the earlier 17:04Z 1384-test snapshot
remains in the report. Earlier proxy/mobile failures and the
ownership requests remain in the report; ignored hardware tests are not native passes. Metadata queries now keep their Quick signature
and do not open a dialog per audit page; Strong controls still need the original SE
userPresence signature after an explicit confirmation. The Mac confirmation package was
installed at 15:26Z with 5/5 owner IPC reads. The T2 attempt reached its first label but
received no terminal input and timed out; no T2 Grant was issued. The owner entered aaa
instead of the displayed keyvalet label. Input capture has seven fake-CLI regressions,
and the no-KeyValet native sudo input probe passed at 21:23Z with four input bytes,
one newline and zero KeyValet/Touch ID calls. A first T2 retry returned user_cancelled
after 40.610067 seconds; it was not retried automatically. The next attended retry
completed both labels and real signing, then revoked the test Grant. The old failed
receipts remain intact.

Nightly revocation regression tests also found that an execution device was excluded from
its own DeviceRevoke delivery, and that a received self-removal proof left authority from
other issuers usable. The source now sends the persisted Strong revocation ciphertext to
the target before relay DELETE, invalidates its unused approvals and installed Grants,
and rejects late Grant use and new remote requests using the persistent local tombstone.
Only revocation ciphertext receives this outbound exception; normal messages still need
an active peer. Signature validation, Strong requirements, nonce history and Linux
capabilities are unchanged. Linux release build and six revocation regressions passed;
the new ndu helper was installed at 17:24Z, with the same device/account IDs, vault and
CLI hashes. All three services are active and relay reconnection was confirmed. The Mac
helper package was installed at 21:26Z with all three services running and 5/5 owner
IPC probes. Actual revocation
propagation timing is still unmeasured; an offline
or backpressured target cannot be assumed to have applied a proof merely because the
relay accepted it. A pure execution device has no AK_s and cannot replace it with a polkit
decision or its DK for a relay device deletion. Keep the full old ledger and revoked
identity during re-enrollment; the earlier unused-singleton archive procedure does not
apply after real approvals and Grants have been used. On the configured pure execution
installation, the native `keyvalet devices revoke <Mac-id> --json` preflight returned
`key_unavailable` in 0.226363 seconds including SSH, without starting authentication or
completing a revocation. Use an approver with a real AK_s for relay device deletion; the
reverse execution-only command needs a defined product workflow.

A running service alone does not prove that its IPC listener accepts connections.
The Linux caller proof now uses the separate peer broker described in
[the isolation report](remote-approval-reports/linux-auth-relay-isolation.md).
The non-root helper and relay client retain empty capability sets; only the broker can inspect
another UID's executable, and it verifies the passed socket, process lifetime, UID and installed role.

The current source installer provisions the following separate units:

| Identity / unit | Data / connection |
| --- | --- |
| `keyvalet`, `keyvalet.service` | TPM-protected vault `/var/lib/keyvalet`; no capabilities |
| `root`, `keyvalet-peer.service` | Peer identity only; `CAP_SYS_PTRACE`, `AF_UNIX`, no vault access |
| `keyvalet-relay`, `keyvalet-relay.service` | Ciphertext queue `/var/lib/keyvalet-relay/queue`; helper `/run/keyvalet/relay.sock` |
| `keyvalet-relay-server`, `keyvalet-relay-server.service` | Server SQLite `/var/lib/keyvalet-relay-server`; listens on `127.0.0.1:8787` |

The client config is `/etc/keyvalet/relay-client.toml`, written by root and readable by the relay
account. It needs the real public `device_id` and `account_id` returned by authenticated setup;
the installer never creates placeholder identities. The client runs its helper control transport
before account binding, so authenticated owner setup can register and pair a new device. Remote
status can report unavailable before this setup completes. Server and client state directories
must stay separate.

On an existing TPM installation, back up `/var/lib/keyvalet`, `/etc/keyvalet` and any
`/var/lib/keyvalet-relay*` state before upgrading, then run:

```sh
sh scripts/install.sh
systemctl is-active keyvalet.service keyvalet-peer.service keyvalet-relay.service
keyvalet status --summary
keyvalet relay set-url https://relay.keyvalet.dev
keyvalet pair --new
```

Do not add `--software` to a TPM upgrade. Keep the recovery code in the owner's terminal;
do not put recovery codes, pairing links or session tokens in tickets or logs. Join the pairing
from the approver, compare both six-digit codes, and complete Strong confirmation on that device.
If the terminal closes after joining but before confirmation, `keyvalet pair --resume` on
each device continues the same pending pairing. It shows the original SAS and uses the
original expiration; it does not redeem the link again or extend the pairing lifetime.
An expired or revoked candidate cannot resume.
On 2026-10-13, this exact source installation succeeded on Ubuntu 24.04 / Linux 6.8 with all
three runtime services active. The original encrypted vault remained byte-for-byte identical,
and the installed CLI opened it using TPM protection. That particular vault contained no
credential types; credential-use acceptance needs a configured credential in addition to pairing.
See the R2-A report for backup paths, rollback commands and each measured result.

For a self-hosted relay on the same Ubuntu host, install nginx and use the current source
installer. This preparation sequence requires your real domain and Cloudflare Origin CA files:

```sh
sh scripts/install.sh --no-setup --no-register
sudo install -d -m 0700 /etc/ssl/keyvalet-relay
sudo install -m 0644 /private/path/origin.pem /etc/ssl/keyvalet-relay/origin.pem
sudo install -m 0600 /private/path/origin.key /etc/ssl/keyvalet-relay/origin.key
keyvalet relay install --listen 127.0.0.1:8787 \
  --data /var/lib/keyvalet-relay-server --public-url https://relay.example.com
sudo systemctl daemon-reload
sudo systemctl enable --now keyvalet-relay-server.service
sudo nginx -t
sudo systemctl reload nginx
keyvalet relay status --public-url https://relay.example.com
```

Use Cloudflare A/AAAA records pointing to the origin with the orange cloud enabled; select
Full (strict), and allow inbound 443 only from Cloudflare's published ranges. Keep 8787 private.
The chain is Cloudflare → nginx → loopback kv-server. No Tailscale/Caddy is installed. The
installer supplies templates and certificate-directory permissions; it does not obtain a
certificate or change DNS/firewall rules. Actual edge acceptance is tracked separately in
[the W9 report](remote-approval-reports/W9.md).

W9 has deployed `https://relay.keyvalet.dev` on `simvito` with proxied DNS, a dedicated Origin CA
certificate and a hostname-only Full (strict) rule. HTTPS, authenticated WSS and a W0 software
ES256/HPKE round trip passed. This verifies the public relay transport; it does not resolve the
installed helper/desktop/phone acceptance gaps above.

The intended pairing sequence is `relay set-url`, `pair --new` on the execution host, scanning
or joining on the Mac/phone, comparing the six-digit SAS on both devices, and Strong confirmation
on the approver. Then `approvals`, `approve <id>` / `deny <id>` and remote settings are the CLI
entry points. The R2-A report records the installed-device result for each step; a
successful parser or software test does not establish successful device pairing.
Phone internal distribution also requires the resources in the
[mobile report](remote-approval-reports/W8.md).

Requester protection is displayed as hardware kind or `software_key`; software receives a red
warning in the approval UI. Unknown attestation stays unverified. A remote approval does not
unlock an unopened credential vault by itself. Remote approval does not give a Linux/Windows
helper protection against root/SYSTEM; the existing server trust boundary remains in force.

To remove the new service and runtime registrations from current source, use
`sh scripts/install.sh --uninstall`. Workflow-built packages route their uninstaller through
this mode. Queued ciphertext, certificates and service accounts are retained by default.
Direct older `scripts/uninstall.sh` entry points predate remote cleanup; see the W9 ownership
follow-up in the ledger.

## Desktop and SSH approval

A desktop session needs a running polkit authentication agent. Polkit's PAM configuration
decides whether the login password or a fingerprint is accepted. The three KeyValet actions
use `auth_self`, without a retained authorization: unlock, credential use and sensitive changes
are checked independently by the service. Existing grant modes determine when use approval is
needed; each new connection still requires fresh unlock authorization.

For SSH, run this in a separate terminal belonging to the vault owner:

```sh
keyvalet approve <kv-mcp-pid>
```

This registers `pkttyagent` for that MCP process and its start time. The login password belongs
in the polkit agent's terminal, never in chat or a KeyValet secret-entry dialog. Without an agent,
denied or canceled authentication fails closed. There is no confirmation-code fallback.
Secret entry uses Zenity on a desktop (install `zenity`), or hidden input on `/dev/tty`; it never
consumes MCP's JSON stdin. A detached client without a terminal or desktop cannot collect a
secret interactively; use the terminal CLI to add it first.

OAuth opens a browser with `xdg-open` when available, otherwise prints the authorization URL to
the user's terminal. For a localhost OAuth callback over SSH, forward the callback port or use
a provider's device-code flow. Clipboard tools (`wl-copy` or `xclip`) are optional.

## Protection and recovery

TPM mode creates a P-256 ECDH key using trusted `tpm2-tools` executables and the kernel resource
manager `/dev/tpmrm0`. The child object's `fixedTPM` and `fixedParent` attributes prohibit
migration. Its encrypted public/private blobs and a public peer point are stored in authenticated
vault metadata; the private scalar is never exported. The derived secret crosses an anonymous
pipe and is expanded with HKDF-SHA256. No persistent TPM handle, PCR binding, TPM clearing or
firmware changes are needed.

The TPM enforces device binding, while polkit supplies user authorization. This implementation
does not put a user-presence, PIN or PCR policy into the TPM key. Root, a compromised service,
or someone with the necessary blobs and TPM access can use it without polkit. The derived AES
key and decrypted records enter service memory. A firmware TPM such as Intel PTT can provide
hardware isolation; a device node alone does not prove the host's physical implementation.
See the [protection matrix](key-protection.md) for the distinction between detection and evidence.

Software mode stores a random key outside `vault.enc`, in a digest-named `0600` file in the
service's `0700` directory. Metadata contains only its digest. It depends on service-account
and filesystem isolation, not TPM hardware. Both modes mix a separate local device-binding
secret into the vault key. Linux backup tools do not automatically exclude these files: a full
directory backup includes them. Protect backups and keep the recovery passphrase separately.

```sh
keyvalet tpm-test                   # Hardware round trip; vault unchanged
keyvalet recovery-check             # Verify passphrase without hardware or printing values
keyvalet recovery-read list         # Audited read-only recovery
keyvalet rotate-recovery            # Rotate provider key, vault key and recovery passphrase
keyvalet recover-vault              # Recover and bind a fresh TPM key
keyvalet recover-vault --software   # Explicit recovery on a machine without TPM
```

Recovery uses the encrypted vault and passphrase independently of the original TPM and binding
file. Rotation invalidates the old passphrase for the current vault, while old backups still
accept their old passphrases. Maintenance refuses active helper sessions. Writes from the root
CLI retain service ownership, and superseded software and device-binding keys are removed
after a successful commit.

## Installed boundaries

| Path / identity | Ownership and use |
| --- | --- |
| `/usr/local/lib/keyvalet` | Root-owned binaries and templates, checked before use |
| `/var/lib/keyvalet` | `keyvalet`, `0700`; vault, settings, audit and local key files |
| `/run/keyvalet/helper.sock` | Service socket; only the configured owner's kernel UID receives credential sessions; root receives control queries only |
| `/etc/keyvalet/owner.uid` | Root-owned owner configuration; client-supplied UID/PID is ignored |
| `keyvalet.service` | Non-login service account; no capabilities, no new privileges, restricted filesystem access and core dumps disabled |
| `dev.keyvalet.unlock/use/modify` | Polkit verifies the socket peer's PID, start time and UID |

The AI user's ability to obtain root defeats this boundary. Do not give the AI account
passwordless general-purpose sudo. The MCP process disables core dumps and same-user ptrace;
that does not isolate the entire interactive desktop or a compromised OS.

`sh scripts/uninstall.sh` stops and removes the service and installed code, preserving the vault,
owner configuration and service account. `--purge` asks for explicit confirmation before
deleting the vault and owner configuration; the non-login service account is retained. WSL can
run this independent Linux service when systemd and polkit are available; access to a Windows
vault through a WSL bridge remains a separate pending feature.

## Verification

Routine CI needs no installed KeyValet, root, GUI or TPM: format, strict clippy, locked workspace
build and all workspace tests run as a regular user. Hardware tests are ignored by default.

### Unit-test coverage

From the repository root on Linux:

```sh
rustup component add llvm-tools-preview
sh scripts/test-linux-coverage.sh
```

The script runs locked workspace tests and writes `summary.md`, `coverage.json` and `lcov.info`
to `rust/target/linux-coverage`. Set `KV_COVERAGE_DIR` to change the report directory and
`KV_LLVM_BIN` for an explicitly installed matching LLVM toolset. Python 3 is required.
Ubuntu 22.04 and Debian 12 CI upload these reports as artifacts. Failed tests fail the coverage
step too, and their status is retained in the report. Every reported module must have exactly
100% production line coverage; missing source files or empty counters also fail the step.

The summary measures production lines in Linux key protection, kernel peer identity, daemon
startup and terminal management, plus shared master-key metadata. Unit tests and their fixtures
live in separate module files and do not enter these production-line counts.

The 2026-10-10 expansion covers approval identity and revocation, child
exit/timeout/cancellation, NSS lookup errors, private file ownership and permissions,
software-key cleanup, TPM creation/unlock and file-write failures, workspace cleanup,
metadata corruption and device-binding mismatches. Daemon tests cover startup policy,
lock/socket errors, session limits, root control queries, disconnects and shutdown. CLI tests
cover executable trust, target-process ownership, home lookup and terminal failures.
Private system interfaces let the same production paths run against temporary files,
Unix sockets and controlled child processes. TPM command fixtures exercise metadata and
key derivation without installing binaries, creating service accounts or accessing hardware.
Signal and exec fixtures run in subprocesses so they cannot affect the test runner; their
parent tests invoke them automatically even though the child entry points are marked ignored.

Measured on `ndu` with native Rust 1.99.0, excluding test code:

| Production module | Previous report | Current production lines | Coverage |
| --- | ---: | ---: | ---: |
| Key protection and polkit (`kv-platform/src/linux.rs`) | 65.67% | 557/557 | 100.00% |
| Kernel peer identity (`kv-platform/src/peer_linux.rs`) | 93.55% | 65/65 | 100.00% |
| Daemon startup (`kv-helper/src/daemon_linux.rs`) | 41.07% | 146/146 | 100.00% |
| Terminal management (`kv-cli/src/linux_cli.rs`) | 35.25% | 160/160 | 100.00% |
| Shared master-key metadata (`kv-vault/src/master_key.rs`) | 96.48% | 235/235 | 100.00% |

The final coverage run covers all 1,163 measured production lines and passes 631 workspace tests,
with six hardware, environment or subprocess-fixture entry points ignored by the top-level runner.
The matching format, strict clippy and locked build checks pass; macOS regression passes 583 tests
with four ignored. Native LLVM 23 reports 18 zero-hash profile mismatches in `base64ct`, `rand` and
`tokio`; none belong to these five measured modules. Real polkit/PAM, physical TPM and GUI behavior
need their integration checks in addition to these isolated unit tests. The physical TPM
round-trip and corrupted-key rejection test also passes separately on `ndu`.

The TPM integration test can be run on a TPM 2.0 host as root or a user with device access:

```sh
cargo test -p kv-platform tpm_round_trip -- --ignored
```

Real-machine verification uses synthetic credentials only. See the acceptance record below;
desktop fingerprint approval, ARM64 hardware and live AI client UI remain additional release
matrix checks.

### Acceptance record — 2026-10-10

Host: `ndu`, Ubuntu 24.04.4 / kernel 6.8.0, x86_64, MSI MPG Z790 EDGE WIFI and Core i9-13900K.
Sysfs and TPM commands report TPM 2.0, manufacturer `INTC`, firmware 600.18; the platform and
vendor indicate Intel PTT. BIOS H.10 is dated 2022-11-15. These observations establish a
working TPM interface on this host; they are not certificate-based hardware attestation.

| Check | Result |
| --- | --- |
| Native Rust 1.99 format, strict clippy, locked build and tests | Passed; 461 Linux tests after removing the installation, vault, service account and rules; three environment-dependent tests ignored. macOS regression checks also pass |
| Real TPM test, including a corrupted private blob with a software key present | Passed; no hardware fallback |
| Install / upgrade / uninstall and reinstall, service ownership, systemd sandbox and owner configuration | Passed; default uninstall preserves the synthetic vault and reinstall opens it; no real AI client configuration touched |
| Runtime configuration | Passed in an isolated home: valid JSON, user ownership, idempotence and custom-file preservation |
| Installed native MCP initialize, tool discovery, locked protection probe, unlock, grant, get, lock and EOF | Passed with synthetic credentials and temporary PID-scoped test authorization |
| Independent polkit password authentication | Passed with a temporary Unix account: separate real PAM unlock, use and modify approvals; account removed afterwards |
| Owner's SSH agent and cancellation | Password prompt appears for the non-dumpable MCP process; cancellation refuses access |
| Forged approval/UID, foreign UID, per-use parameter changes and replay | Refused; audit records kernel UID/PID and omits credential values |
| Gateway peer UID, bad token, hostile Host, proxy-only and disconnect | Passed; foreign user disconnected, owner reaches validation, EOF closes the listener |
| Maintenance during active sessions | Refused |
| TPM recovery check/read, rotation, old-passphrase rejection and fresh-key recovery | Passed; files retain service ownership |
| No TPM / broken TPM | Private mount namespaces only: default setup refuses, explicit software setup and service use pass, rotation/recovery pass, broken TPM refuses despite a software key being present |
| Linux x64 archive and checksum | Native archive built and SHA-256 verified; glibc 2.39 baseline |

No real credentials, TPM persistent handles, TPM clearing, BIOS changes or the owner's login
password were used. Temporary polkit rules, users and isolated state were removed. `guang`
currently has passwordless general-purpose sudo, so this host does not demonstrate isolation
from that account obtaining root. Desktop fingerprint, ARM64 hardware, older-distribution CI
runs, signed public distribution and live AI client UI remain unverified.


The last complete authenticated native audit before device revocation has 53 matched
groups and one difference (53/54, 98.148148%; both endpoints available). The missing receiver event is the old
13:00:05Z query_grants directive 01M4TNJG10T64E6D72NQ0VMM7A; the new T2 issuance
and revocation are matched. Preserve this historical failed query and its original
expiry. Do not rewrite audit history or shorten the query window to claim zero differences.
The earlier 37/37 frozen sample remains a separate passing snapshot. See the
[R3-A native evidence](remote-approval-reports/assets/r3a-audit-timeout-native-20261013T232726Z.json).

After Mac revoked ndu, the installed ndu CLI could obtain only its local authenticated
snapshot; its remote audit reports one unavailable peer. Its 53 unmatched local groups
are not a new complete comparison of both endpoints. The noninteractive Mac attempt
could not obtain sudo, so neither attempt proves 100% reconciliation after revocation.
The same since cutoff and limit were retained; no history was filtered or rewritten.
[Post-revocation audit attempt](remote-approval-reports/assets/r3a-post-revocation-native-audit.json).


The original attended OS-transition observation returned Mac away in all 51 installed status
reads. The observer also missed OS notifications; distributed CoreFoundation notifications
need the main-thread run loop, while the old agent blocked that thread on its socket.
The fake-worker regression reproduced the blocked notification dispatch (0 passed / 1 failed).
The owned `kv-touchid/src/remote_agent.rs` now dispatches the main-thread run loop while
the original private transport runs on a worker in the same process. Four focused cases
and the crate's all-target clippy check pass; code identity checks, conservative unknown
presence and real SE Strong signatures are unchanged. The new agent was built, signed
and installed at 23:26Z, with all four strict team/identifier checks passing and owner IPC
5/5 successful. The first native observation returned 149 present and 67 away samples
and recorded four real OS events; unlock to the first authenticated present read took
7.574238 seconds. A complete measured cycle then succeeded: 39 authenticated reads
(19 present / 20 away), lock to away 8.160197 seconds, unlock to present 6.782415 seconds.
These remote readback times include transport and SSH sampling; they do not establish
the local probe's independent latency. Actual desktop-first request delivery remains unverified.
An earlier observer ended before unlock; its early-Enter handling was reproduced with a
fake runner and fixed (3 tests pass). See the
[before](remote-approval-reports/assets/r3a-presence-main-loop-before.log) and
[after](remote-approval-reports/assets/r3a-presence-main-loop-after.log) regression evidence,
the [completed native cycle](remote-approval-reports/assets/r3a-presence-native-verified.json)
and the [observer regression](remote-approval-reports/assets/r3a-presence-early-enter-after.log).

The latest four checks passed at 22:59:38Z (1398 passed / 0 failed / 10 ignored, 69 groups);
514 source/config/schema/fixture files stayed unchanged during checks and before signing.
After the owner explicitly asked us to free space, only rebuildable caches in this round’s
`target-r2a/debug` were removed, releasing 3.972 GB and another 3.030 GB after CI. Installed
programs, signed packages, root-only backups and evidence were preserved. The current
source snapshot still matches all 514 checked files after installation. A real installed
query timed out after 10.181756 seconds, then received a verified successful result for
the original ID at 15.759854 seconds; the executor applied it once. No credential request
or KeyValet Touch ID was used for that regression.
The physical two-hour lid test was cancelled by the owner and replaced by source review.
The review found that an undecided incoming approver request is kept only in memory
after relay acknowledgment, so a helper restart can lose that request. Ordinary sleep
retaining memory is a different boundary. Do not claim this review proves a two-hour
native run. See the [review receipt](remote-approval-reports/assets/r3a-lid-code-review-20261014.json).


A control command returning `directive_result_timeout` has an unconfirmed executor outcome.
Check remote status/grants or audit before deciding whether to issue another command. The
helper now records `directive_wait_timeout` with the original ID, peer, operation and JCS
hash; it preserves the original queue, nonce/expiry and empty `result_ok`. A late authentic
result can still be accepted once. `audit --remote` explains timeout/result facts under
`directive_outcomes` without changing core comparison counts, findings or exit code 3.
The historical query remains a missing receiver record; it was not changed into a success.
See the [current regression/CI evidence](remote-approval-reports/assets/r3a-audit-presence-ci-summary.json).


The owner explicitly authorized six otherwise out-of-scope files for Secure Enclave error
preservation. The Swift bridge classifies only known NSError domain/code pairs and bounded
underlying errors; unknown facts remain a generic failure. The private agent and core adapter
preserve key_operation_cancelled and key_authentication_failed without returning signature
material on failure. The actual userPresence ACL, nonce/expiry, role and verification order
remain unchanged. Three fake FFI/agent regressions and 12 pure NSError cases passed; the
workspace snapshot including Swift passed all four checks (1402 passed / 0 failed / 10 ignored).
The signed helper/CLI/agent package was installed at 00:53Z, with owner IPC 5/5.
The first new GET was stopped before issuance: after agent restart the lock/saver
notification history is unknown and the native dictionary cannot provide those initial
values, so presence remains away. After an installation or agent restart, observe real
screensaver exit and lock/unlock, then require the executor's authenticated status to
show present before measuring desktop-priority delivery. Do not inject notifications
or treat recent keyboard input alone as complete presence. The continuation driver
waits for that genuine hint (7 fake transport/privacy tests passed) and does not reinstall.
The later native continuation verified Mac delivery, Escape and system Touch ID cancellation;
the final segment also completed forward revocation as recorded below.
The 1402-test snapshot belongs to that earlier installed package; the child-hop repair
and shared-tree changes have their own final workspace checks. The pure execution endpoint
still has no AK_s for the reverse Strong revocation command. See the
[authorization](remote-approval-reports/assets/r3a-se-failure-scope-authorization.json),
[checks](remote-approval-reports/assets/r3a-se-closure-final-ci-summary.json) and
[ready package](remote-approval-reports/assets/r3a-se-remaining-ready.json).

The continuation at 01:03Z restored genuine present, then delivered a Mac GET dialog:
Deny returned approval_denied in 5.038746 seconds with zero executions. Escape emitted
remote_ui_rejected/user_cancelled and left the executor request waiting with zero executions.
There were no active paired phones, so this is not evidence of phone silence or a banner.
At 01:05Z, cancelling the actual SE prompt still returned key_operation_failed in 8.531664 seconds.
The missed child boundary was identified: the device-key child collapsed typed errors into
exit 1, and the agent collapsed all nonzero exits again. The owner authorized the additional
agent.rs file and future necessary R3-A cross-file fixes. Three child/runner regressions
now pass after fixing that bridge. At 05:14Z the signed agent was installed, owner IPC
passed 5/5, and the installed product returned key_operation_cancelled for a real system
Touch ID cancellation in 10.485434 seconds, with no new Grant. Final biometric
authentication failure remains software-tested only; a single mismatched fingerprint
while the system prompt remains open is not a final failure result.
[Native cancellation and revocation](remote-approval-reports/assets/r3a-se-revocation-native-verified.json).

The current integrated tree passed all four checks at 01:32:24Z: 1416 passed,
0 failed, 10 ignored, 69 groups; 522 source/Swift/fixture files stayed unchanged.
The new native package rebuilds only the agent and keeps the verified installed
helper/CLI/relay hashes with their original component CI provenance.
[Current checks](remote-approval-reports/assets/r3a-se-child-closure-ci5-summary.json).
All 522 source/Swift/fixture files still matched those checks at 05:33Z.
[Final source verification](remote-approval-reports/assets/r3a-final-source-check-20261014.json).

The final attended revocation used the installed commands: first approve one GET only
after its original process has exited, then issue a one-hour T1 Grant with real Mac
Touch ID, and finally run Mac `keyvalet devices revoke <ndu-device-id>` with another
real Strong confirmation. The revocation command took 9.100511 seconds; from command
start to ndu's invalidation readback took 10.583576 seconds. The unused approval changed
from approved_unused to cancelled with zero executions, and the fresh Grant was revoked
before its expiry. The ndu device itself is now revoked and all used history is retained.
These steps are a completed destructive acceptance case, not a command sequence to repeat
on the current revoked identity. The supported re-enrolment/pairing path that preserves
used history is still open; do not restore an old RemoteStore or nonce state, erase used
history, or substitute the executor's DK or polkit approval for AK_s.
[Complete native receipt](remote-approval-reports/assets/r3a-remaining-native-20261014T051814Z.json).

The owner cancelled the physical two-hour lid test. A source review identified an
approver restart gap; the shared source now persists inbound acceptance before ACK and
checks its authenticated receipt, original signature, live authority and expiry on
recovery. Seven relevant CI regressions passed. This helper change was not included in
the agent-only native installation, and neither code review nor those tests prove a
two-hour hardware backlog run.
[Review follow-up](remote-approval-reports/assets/r3a-lid-review-followup-20261014.json).

At 05:48Z the last complete workspace run passed all four checks: 1416 passed /
0 failed / 10 ignored, 69 groups; 525 source/build-input files, including plist files,
stayed unchanged. A later shared Windows GUI change added windows-reactor and
windows-reactor-setup to kv-agent; neither was present in the lockfile at that time.
R3-A retained that work and did not add dependencies or update Cargo.lock. A subsequent
check used locked/offline protection: fmt passed, while clippy stopped resolving an
uncached windows-reference package; build/test were not run. This is not a claim that
the package is unavailable online. At that point the final CI requirement remained open for the
changed tree; the earlier native installation and revocation receipts remain valid
for their recorded component hashes.
[Last complete checks](remote-approval-reports/assets/r3a-se-child-closure-ci7-summary.json),
[dependency-protected recheck](remote-approval-reports/assets/r3a-se-child-closure-ci8-summary.json).

The shared Windows workflow updated its lockfile at 05:52Z; R3-A did not change
dependency declarations or Cargo.lock. The final guarded run at 06:02:44Z passed
fmt, clippy, build and test: 1416 passed / 0 failed / 10 ignored, 69 groups;
526 source/build-input files stayed unchanged. Clippy additionally used --locked,
and Cargo stayed offline, so this recheck did not introduce dependencies.
The native installation retains its recorded component hashes and CI provenance;
no additional installation or Touch ID was triggered by these shared UI changes.
[Final checks](remote-approval-reports/assets/r3a-se-child-closure-ci9-summary.json),
[source verification](remote-approval-reports/assets/r3a-final-source-check-ci9-20261014.json).
