# Metadata-only push deployment

`kv-server` posts to `http://127.0.0.1:8788/v1/push`; `kv-push` never accepts
approval ciphertext or plaintext. Only the provider token, `approval_id`, `to`
and `delivery.mode` cross this boundary. Configure a shared random bearer through
`KV_PUSH_RELAY_BEARER_FILE`. Both clients forbid redirects; relay disables proxies
and rejects non-loopback dispatcher URLs. No nginx route proxies port 8788.

Install [kv-push.service](../../deploy/relay/kv-push.service) and the relay
[push.conf](../../deploy/relay/push.conf) drop-in. The environment files are
`root:root` mode `0600`; systemd reads them before changing service users.

`/etc/keyvalet-push/push.env` uses these real server paths:

```sh
KV_PUSH_PORT=8788
KV_PUSH_RELAY_BEARER_FILE=/etc/keyvalet-push/relay-bearer
KV_FCM_SERVICE_ACCOUNT_FILE=/etc/keyvalet-push/fcm-service-account.json
```

The user supplies the FCM file, owned `root:keyvalet-push` mode `0640`.
The service directory is `root:keyvalet-push` mode `0750`. The relay credential
file is `root:keyvalet-push` mode `0640`; the relay server service user is also
a member of that group. The bearer is generated on the server and never copied
to the repository or printed.

`/etc/keyvalet-relay/push.env`:

```sh
KEYVALET_PUSH_URL=http://127.0.0.1:8788/v1/push
KV_PUSH_RELAY_BEARER_FILE=/etc/keyvalet-push/relay-bearer
```

When iOS resources are ready, add the actual APNs key file path, Key ID, team
`PWCRJPY7YC`, topic `dev.keyvalet.mobile` and environment via `KV_APNS_KEY_FILE`,
`KV_APNS_KEY_ID`, `KV_APNS_TEAM`, `KV_APNS_TOPIC`, `KV_APNS_SANDBOX`. Do not add
placeholder APNs credentials to a running service. TestFlight uses production;
development-signed apps use the matching sandbox configuration.

The outer signed envelope's `push.mode` is the executor's projection of the
encrypted delivery decision. Relay only knows WebSocket connectivity, not human
presence. Connectivity never changes silent/banner or approval strength. Missing
request hints conservatively use banner; escalation uses banner; cancellation
and Directive/DirectiveResult/Grant/DeviceRevoke updates use silent. The phone
ignores push mode for rendering and uses Rust's verified decrypted plan.

Jobs are transactional with messages and keyed by account/id/recipient/type.
Retries are at 1, 2 and 4 seconds after failures, at most four attempts including
the initial send. Provider 429 honors bounded Retry-After (60–3600 seconds),
while jobs expire within 120 seconds or their envelope deadline. Rotation is
looked up on each attempt. Missing tokens are skipped and counted. Escalation
supersedes queued requests, and resolution/cancellation retires request wakes.
Push failure does not roll back an accepted approval; WS and reconnect fetch
remain usable.

APNs invalid-token responses and FCM `UNREGISTERED` become HTTP 410, the
authenticated synchronous invalid-token callback on the original relay→push
request. Relay deletes only if the device's stored token still equals the one
sent. Permission errors and provider failures do not delete tokens. A separate
public callback endpoint is unnecessary. Logout clears the token immediately;
revocation and expired human sessions are pruned before dispatch and by cleanup.
An already accepted provider push cannot be recalled; signed-out Rust refuses
to decrypt/display it and native code clears approval notifications.

Android's native JobScheduler persists regular sync jobs across reboot and uses
expedited work for high-priority FCM. No Flutter background isolate runs. Tokens
are re-uploaded on login, cold launch and rotation, with offline retry and an
encrypted remote-logout outbox. Hardware keys require first device unlock after
reboot. User force-stop suppresses delivery until the app is opened again; this
is different from system process eviction.
