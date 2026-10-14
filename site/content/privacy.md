+++
title = "Privacy policy"
description = "What stays on your device, what leaves it when you use an API or remote approval, and how to contact KeyValet about your data."
+++

Effective date: 14 October 2026. KeyValet is an Apache-2.0 open-source project maintained by **Simvito Limited**. This policy covers this website, the software, and the official remote-approval relay at `relay.keyvalet.dev`. Remote approval and mobile distribution remain under acceptance; available features depend on your build and the configured providers.

Privacy contact: [support@simvito.com](mailto:support@simvito.com).

## Local credentials and approvals

Your credential vault is stored encrypted on the machine where you install KeyValet. Credential values, recovery passphrases, and device private keys are not uploaded to a KeyValet account or synchronized through the relay. Platform key protection depends on the configured provider; see the [security model](/security/).

KeyValet processes secrets in local memory when you authorize an operation. The operating system handles its own biometric or PIN authentication; KeyValet does not collect fingerprint images, biometric templates, or your Windows Hello PIN. A recovery passphrase entered into KeyValet is processed locally to protect or recover the vault.

Local settings and audit records can contain credential labels, allowed hosts, request metadata, purpose text, timestamps, and outcomes. The application does not intentionally record credential values in audit logs. Avoid putting secrets in labels, purpose text, or support reports. Local files and backups remain under your control, subject to the installation's operating-system permissions.

## API requests and sign-in to other services

When you authorize an API operation, KeyValet sends the request and the required authentication material to the service you configured. That service receives the request data and applies its own privacy policy. OAuth sign-in similarly contacts the selected identity provider. An approved raw credential read or short-lived token request can disclose that material to the requesting client; proxy-only credentials have a different access boundary. See the [guide](/guide/) and [security model](/security/) before selecting an authorization scope.

## Optional remote approval

Local vault use does not require a KeyValet relay account. Enabling remote approval registers devices and establishes network connections for authentication, pairing, delivery, and device-presence hints.

The relay processes account and device identifiers, device labels, operating-system and capability metadata, public keys, optional public attestation information, session/recovery verification hashes, pairing state, routing metadata, and message timestamps and expiry. With account sign-in enabled, it also stores the provider identifier and subject, email address, and display name supplied by that provider. It verifies the sign-in proof; it does not receive your Google or Apple password.

During sign-in and account recovery, the relay processes verification material such as provider identity tokens and remote-account recovery codes. A remote-account recovery code is different from your local vault recovery passphrase; neither should be sent to support.

Approval requests and decisions travel in end-to-end encrypted envelopes. The relay operator can observe routing information, message sizes and timing, and public registration metadata. Encryption does not hide this metadata or ordinary network information such as IP addresses. The relay does not receive vault contents or device private keys.

When enabled on a supported mobile build, notifications use a device push token. KeyValet and the selected push provider process the token and delivery information. Push messages are delivery signals; credential values and approval details are not sent as readable push content. Disabling notifications, logging out, or revoking a device can invalidate the relevant token or authorization; those actions do not erase every historical record.

For a self-hosted relay, the person operating that relay controls its server-side records and retention. Current mobile builds use the official relay; desktop self-hosting is a separate deployment choice.

## Website, downloads, and providers

This website uses Cloudflare Pages. Download links can lead to this site or GitHub Releases. Cloudflare and GitHub process network and request information needed to serve content, protect their services, and record download activity. The site source does not include an advertising tracker or analytics script, and the application does not include a separate product-usage analytics collector. Operational relay messages and server logs are still data processing.

Depending on the features you choose, relevant provider policies include [Cloudflare](https://www.cloudflare.com/privacypolicy/), [GitHub](https://docs.github.com/en/site-policy/privacy-policies/github-general-privacy-statement), [Google, including Firebase delivery](https://policies.google.com/privacy), and [Apple](https://www.apple.com/legal/privacy/). They may process data in countries other than your own. Using an external API is governed by that API provider's policy as well.

## Retention and your choices

Local vaults, settings, audit files, and backups remain until you remove them. Uninstalling software does not necessarily remove retained data or backups. Do not send your vault, recovery material, or credentials to support.

Relay sessions and messages have expiry rules, and expired approvals are rejected. Expiry is not a promise of immediate erasure from every database, log, or backup. Account/device records and security metadata can remain for operation, revocation, and troubleshooting. The current service does not offer an automatic account-deletion interface.

You can keep remote approval disabled, revoke devices and permissions, sign out of the mobile account, or disable notifications. For access, correction, or removal requests concerning official-relay metadata, email [support@simvito.com](mailto:support@simvito.com). We may need to verify your control of the account or device. Never send passwords, PINs, recovery codes, or private keys. For a self-hosted service, contact its operator.

## Changes

Material changes to these data flows will be reflected here with an updated effective date. The [open-source repository](https://github.com/KeyValet/KeyValet) and [Code signing policy](/code-signing/) describe the software and its release process.
