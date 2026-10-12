# Google and Apple sign-in

The app requires a verified Google or Apple account before opening approvals,
devices, activity or settings. This follows the system-provider / server-session
flow in Simvito, with a separate KeyValet identity and device binding.
The latest product instruction overrides the original anonymous-only W8 onboarding.

Fixed relay: https://relay.keyvalet.dev/. The app does not display the address and has
no address editor or exported address-changing API. Rust rejects other hosts; loopback is confined to CI logic. The relay must deploy the new
account endpoints before enabling client sign-in. Its public account providers
endpoint returned HTTP 200 with google=true and apple=false on 2026-10-12 after
loading the registered KeyValet Google client IDs; health returned HTTP 200.
No production deployment or OAuth project registration is performed by these scripts.

Console steps and the deployed public identifiers are in
[the Chinese setup guide](../../docs/mobile-console-setup.zh-CN.md).

On 2026-10-12, a Pixel 7 running Android 16 passed real Google sign-in,
server-side logout, sign-in again with the same account, and session restoration
after a forced stop and cold launch. This acceptance uses the local Debug APK
and its matching Android OAuth client, configured on the live relay. Play app
signing, Apple sign-in and the full phone approval flow still need acceptance.

## Google setup

Use a KeyValet Google Cloud project and configure its consent screen and test users.
Create a **Web application** OAuth client as the backend ID-token audience.
Create an **Android** client for package dev.keyvalet.mobile, registering the
SHA-1 fingerprints of the actual debug and release signing certificates; production
must include the Google Play app-signing fingerprint. Create an **iOS** client for
bundle dev.keyvalet.mobile. These identifiers must not be copied from Simvito.

Set KEYVALET_GOOGLE_WEB_CLIENT_ID, KEYVALET_GOOGLE_ANDROID_CLIENT_ID and
KEYVALET_GOOGLE_IOS_CLIENT_ID on the relay. The Web and iOS IDs are public SDK
configuration returned by /v1/account/providers; the Android ID is the allowed
presenter (azp). The SDK receives serverClientId explicitly, so this login
does not require google-services.json. FCM still needs its separate Firebase
project configuration.

Copy mobile/ios/Flutter/OAuth.xcconfig.example to OAuth.xcconfig and replace
KEYVALET_GOOGLE_REVERSED_CLIENT_ID with the reversed iOS client identifier.
Both debug and release configurations include it; the resulting URL scheme
returns Google's native iOS flow to the app. It is a public identifier.

## Apple setup

Under team PWCRJPY7YC, enable **Sign in with Apple** for the explicit App ID
dev.keyvalet.mobile. Regenerate development and distribution provisioning
profiles with this capability. Runner has the entitlement in both configurations;
KeyValetNSE does not request it.

Create an Apple **Services ID** associated with that App ID for Android's browser
flow. Register domain relay.keyvalet.dev and the exact return URL
https://relay.keyvalet.dev/v1/account/apple/callback. Complete Apple's domain
verification if requested. Configure KEYVALET_APPLE_APP_ID,
KEYVALET_APPLE_SERVICES_ID on the relay. The callback address is fixed in the app
and relay.
Use the App ID as iOS audience and Services ID as Android audience.

The HTTPS form-post callback validates a live Apple login state before forwarding
URL-encoded fields to the fixed Android SignInWithAppleCallback activity.
It cannot select another package or arbitrary URL. The returned ID token is
verified by the relay before any local session is established. Direct ID-token
verification uses Apple's public JWKS and does not require an Apple private key.

Account deletion, provider unlinking, Apple authorization-code exchange / daily
refresh-token validation and cross-provider account linking are not implemented.
Those lifecycle operations need a separate product/API contract and Apple's
server credentials. The app never merges accounts by matching email addresses.
The first verified identity owns the phone and its cached approvals; signing in
with another identity is rejected, rather than displaying the first owner's history.

## Protocol and storage

| Endpoint | Authorization | Result |
| --- | --- | --- |
| GET /v1/account/providers | Public | Availability and public SDK identifiers |
| POST /v1/account/begin | Public, rate limited | Device record, provider → one-use attempt/state/nonce hash |
| POST /v1/account/finish | Provider ID token + hardware DK proof | Verified user, relay account, opaque 30-day user session |
| GET /v1/account/session | Bearer user session | Verified public profile and expiry |
| POST /v1/account/logout | Bearer user session | Revoke that user session and associated device sessions / WebSocket |
| POST /v1/account/apple/callback | Live Apple state | Fixed Android intent redirect |
| POST /v1/devices/push-token | Device session tied to a live user session | Update APNs / FCM token, bound to that device and OS |

The DK login proof is ES256 over canonical JSON:

    {
      "purpose": "keyvalet-account-login-v1",
      "attempt_id": "<relay attempt>",
      "provider": "google",
      "device_id": "<own device>",
      "identity_token_hash": "<sha256 hex of the exact ID token>",
      "state": "<relay state>"
    }

Apple also requires the ID token's nonce to equal the relay nonce hash and the
SDK state to match. google_sign_in 7.2.0 exposes no nonce parameter; its token
is bound to the fresh one-use attempt by the hardware DK proof instead.
The backend checks RS256 signature, official JWKS kid, issuer, audience,
registered presenter, expiry, issued-at, subject and verified email.
JWT parsing and signature verification never happen in Dart.

x-keyvalet-user-session accompanies the device challenge and verify requests.
The resulting Device token is linked to the live user session in SQLite.
HTTP and WebSocket paths reject it after logout / expiry. Desktop relay clients
continue using DK authentication. Pairing retains both-device SAS confirmation
and rejects a phone from another owner joining a claimed relay account. Ownership
is claimed only after both SAS confirmations commit; scanning a code or signing
in while confirmation is pending cannot claim an executor. A phone has one live
human session; signing in again invalidates older sessions on that phone.

User session credentials remain in the hardware-derived encrypted mobile database
and never appear in the Dart view models, diagnostics or native account-status
response. The relay stores session hashes and verified provider/subject/email/name
metadata; approval payloads remain opaque ciphertext. Offline use can restore a
previously verified, unexpired local session; it cannot create a new one.
Logout deletes local credentials before remote revocation is attempted. An explicit
server refusal is not treated as an offline notification fallback. Pending sign-in
responses cannot resurrect a logged-out session.

## Build and verification

    cd mobile
    flutter pub get
    flutter analyze
    flutter test
    cd ..
    mobile/scripts/codegen.sh
    mobile/scripts/build-native.sh android
    mobile/scripts/build-native.sh ios-sim
    mobile/scripts/build-native.sh ios

Rust tests use software provider keys, software devices, temporary databases and
spawn_test_relay_with_accounts. They do not contact Google, Apple, an installed
KeyValet daemon, Firebase or APNs. Run the owned-package checks with
CARGO_TARGET_DIR=rust/target-w8 from the repository root and
--manifest-path rust/Cargo.toml -p kv-mobile-core -p kv-push -p kv-server.
The full software approval scenario now starts with account login before pairing,
then verifies silent delivery, a real 30-second escalation, Quick / Strong,
a one-hour grant and revoke-all.

Official references: [Google ID-token verification](https://developers.google.com/identity/gsi/web/guides/verify-google-id-token),
[Google OpenID Connect](https://developers.google.com/identity/openid-connect/openid-connect),
[Apple user verification](https://developer.apple.com/documentation/signinwithapple/verifying-a-user),
[Apple sign-in authentication](https://developer.apple.com/documentation/signinwithapple/authenticating-users-with-sign-in-with-apple).
