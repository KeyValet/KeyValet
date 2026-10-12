# Relay client service integration (W9)

These files are templates. W3 does not register, install or start any real service.

- `keyvalet-relay.service`: install under `/etc/systemd/system/`. Create the non-login system
  user and group `keyvalet-relay`; grant read access only to `/etc/keyvalet/relay-client.toml`.
  systemd creates `/var/lib/keyvalet-relay` with mode 0700; the process creates its `queue` child.
  The helper must create `/var/run/keyvalet/relay.sock` for this account and authenticate
  `SO_PEERCRED` plus the root peer broker's executable/UID proof (Linux 6.5+). Install the
  `scripts/linux/keyvalet-peer.service` dependency with the helper. `/var/run` and `/run` refer to the same runtime layout; the client derives its
  endpoint from `kv_platform::paths::RELAY_SOCKET`. Do not grant relay access to the vault.
  Provision the account before starting/restarting the helper so its relay listener is created.
- `dev.keyvalet.relay.plist`: install as a root-owned LaunchAgent and bootstrap into the owner's
  GUI domain. Provision `~/Library/Application Support/KeyValet/relay-client.toml` for that user.
  The queue is the sibling `relay-queue` directory, mode 0700. Sign `kv-relay-client` with team
  `PWCRJPY7YC`, hardened runtime and identifier `dev.keyvalet.relay-client`. The helper needs its
  own relay audit-token requirement; `AGENT_REQUIREMENT` identifies `kv-touchid` and must not be
  reused. Enable this agent only with the signed helper/agent daemon mode and the relay IPC
  subprotocol. The client does not launch a sudo helper.
- `windows-service.ps1`: elevated integration template. The binary's `service install` command
  registers `KeyValetRelay`, depends on `KeyValetHelper`, and runs as
  `NT SERVICE\KeyValetRelay`. Provision its SID and queue ACLs before starting it.
  The helper must host `\\.\pipe\keyvalet-relay` with a DACL granting only this service SID and
  SYSTEM, plus peer token and Authenticode verification. Queue files live in
  `C:\ProgramData\KeyValet\Relay\queue`; the template grants this subtree to the relay account
  and gives it read access to the config file. Preserve the helper vault's separate ACL.
  `service uninstall` stops and marks the service for deletion; it preserves the queue and config.

Copy `relay-client.toml.example` to the platform's configuration location and fill in the IDs
from registration. HTTPS is required for remote relays. Numeric loopback HTTP is supported for
local relay instances and tests. Configuration does not accept private keys or transport-path
overrides. The service starts its authenticated control worker before the binding exists,
so first registration and pairing have a network transport. A URL-only configuration keeps
this mode active; invalid configurations are rejected. Full device/account bindings enable the
envelope connection and spool. Configuration changes restart that connection automatically.

The identity query, relay handshake, durable helper receipts, idempotent relay submissions and
helper-controlled retirement now share the W1–W5 contracts. Before starting production services,
install the verified helper runtime with authenticated vault metadata and the real policy/runner
adapter. Provision the relay account/service SID before restarting the helper; Windows resolves
the virtual service SID when creating its dedicated pipe. See
`docs/remote-approval-reports/W1-W5-integration.md` for acceptance evidence and remaining native
deployment checks.
