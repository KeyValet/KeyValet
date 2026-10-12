# kv-relay-client

An unprivileged transport for helper-owned, encrypted remote approval envelopes. Production
code has no private key or cryptographic provider and never opens ciphertext. The helper owns
identity signing, incoming-envelope validation, authorization and the decision to acknowledge.

See [service integration](service/README.md) for the W9 templates and
[W3 report](../../../docs/remote-approval-reports/W3.md) and
[W1–W5 acceptance report](../../../docs/remote-approval-reports/W1-W5-integration.md) for the
shared identity/receipt contracts, platform paths and production integration prerequisites.

## Verification and coverage

Run the package's fmt, clippy, build and test checks in the workspace's `rust/` directory with an
isolated `CARGO_TARGET_DIR`. Tests use temporary directories, fake IPC and loopback relays,
including the W2 `spawn_test_relay` harness. They do not need an installed helper or service,
root, sudo, a GUI session, a signed binary or device-key hardware.

Install the developer tool `cargo-llvm-cov` and the chosen Rust toolchain's `llvm-tools-preview`
component on the CI runner. Neither is a crate dependency. From the repository root:

```sh
CARGO_TARGET_DIR="$PWD/rust/target-w3" KV_RELAY_TOOLCHAIN=stable \
    sh rust/crates/kv-relay-client/coverage.sh
```

The script runs the entire test suite once, preserves the full production-source coverage data,
then enforces **100% line coverage for every CI-testable source file and 100% function coverage**.
It also writes a full HTML report. Test source files are omitted from both coverage denominators.
No `cfg(coverage)` behavior changes or per-line suppression attributes are used.

Only these native adapters are excluded from the CI gate; they remain in the full report:

| File | Boundary requiring a native process or system fixture |
| --- | --- |
| `src/main.rs` | Process stderr and exit status |
| `src/process.rs` | Tokio runtime creation, OS signals and real installation paths |
| `src/platform/native.rs` | Account database and kernel audit-token/code-signature checks |
| `src/helper/native.rs` | Real authenticated socket/named-pipe connector; explicit fake peer only under `cfg(test)` |
| `src/queue/native.rs` | Unix filesystem ownership and permission enforcement |
| `src/windows.rs` | SCM registration, controls, service account and lifecycle |

Command validation, configuration loading, daemon composition, path derivation, ciphertext FIFO,
HTTP/WS authentication, status, retries, heartbeat and helper-authorized ack all remain included.
macOS coverage cannot measure branches compiled only on Linux or Windows; the report lists those
platform verification gaps separately. Line/function coverage does not assert 100% region or
branch coverage.

Outputs are `coverage-final-full.json`, `coverage-final-ci.json` and
`coverage-html/html/index.html` in `CARGO_TARGET_DIR`. The script exits unsuccessfully if any
included file has an uncovered line or an included function remains unexecuted.
