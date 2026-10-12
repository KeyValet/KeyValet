+++
title = "Pricing"
description = "KeyValet is free and open source on macOS, Linux and Windows, and remote approval from your phone will be free on the official relay within a fair-use quota. Team plans — shared credentials, org policy, audit export, CI identity, hosted relay — are planned, not available yet."
+++

<div class="plans wide">
  <div class="plan">
    <h3>Free</h3>
    <p class="price">$0</p>
    <p>Open source (Apache-2.0), forever. Everything the product does today:</p>
    <ul>
      <li>Local vault protected by Secure Enclave (macOS) or TPM 2.0 (Linux), with device binding; Windows Hello in the Windows preview</li>
      <li>The broker runs as a privileged system service the agent can’t read — on all three platforms</li>
      <li>All credential kinds: API keys, OAuth 2.0, Google service accounts, GitHub Apps, JWT, TOTP, AWS STS</li>
      <li>~50 service templates + generic bearer/header/query/basic</li>
      <li>Proxied calls and the loopback SDK gateway</li>
      <li>Approval modes: per-use, per-credential, per-session, remember — Touch ID, polkit or Hello</li>
      <li>Hooks for Claude Code, Codex, Cursor, Grok Build and Devin CLI</li>
      <li><code>keyvalet scan</code> and the local, root-only audit log</li>
    </ul>
    <p>In development, also Free:</p>
    <ul>
      <li>Remote approval: agents on a server or headless Mac, approvals on your phone (iOS + Android) or laptop</li>
      <li>Pairing and remote settings: modes, standing grants, lock, revoke-all</li>
      <li>Official relay (relay.keyvalet.dev) within a fair-use quota: 3 devices, 2,000 remote approvals/month; the phone app always uses it</li>
      <li>Self-hosted relay (nginx + Cloudflare) for laptop approvers, no quota</li>
      <li>Policy engine (risk tiers, policy.yaml)</li>
    </ul>
    <p class="cta-plan"><a class="btn primary" href="/#install">Install on macOS or Linux</a></p>
  </div>
  <div class="plan">
    <span class="badge">Planned — not available yet</span>
    <h3>Team</h3>
    <p class="price">$15 <small>per seat / month · $12 billed annually</small></p>
    <p>Machine identities unlimited (fair use).</p>
    <ul>
      <li>Shared credentials wrapped per member device</li>
      <li>Org policy as code — it can only tighten members’ local policy</li>
      <li>Audit export (JSONL / OTLP)</li>
      <li>CI identity: GitHub OIDC → short-lived capability token; no static secrets in repo settings</li>
      <li>Hosted relay without quotas</li>
      <li>Encrypted cross-device sync</li>
      <li>Member management</li>
    </ul>
    <p>14-day trial, no credit card, when it ships.</p>
    <p class="cta-plan"><a class="btn ghost" href="https://github.com/KeyValet/KeyValet/discussions">Get notified</a></p>
  </div>
  <div class="plan">
    <span class="badge">Planned — not available yet</span>
    <h3>Team + phone approvals</h3>
    <p class="price">$18 <small>per seat / month · $15 billed annually</small></p>
    <p>Everything in Team, plus:</p>
    <ul>
      <li>Shared credentials routed to the owner’s phone for approval</li>
      <li>N-of-M approvals for sensitive credentials</li>
      <li>Hosted relay without quotas for the whole team</li>
      <li>OIDC SSO (Okta, Entra, Google)</li>
      <li>90-day encrypted audit retention</li>
    </ul>
    <p class="cta-plan"><a class="btn ghost" href="https://github.com/KeyValet/KeyValet/discussions">Get notified</a></p>
  </div>
</div>

## FAQ

### Is Free really free?

Yes — no time limit, no watermark, no security downgrade. An upgrade prompt may appear once, at the moment you hit a Team-only need, and never again.

### Do you ever see my secrets?

No. Everything is local: secrets live in a root-only vault on your Mac, protected by Secure Enclave and device binding. Team plans sync only ciphertext wrapped to your devices.

### Why does Team cost money?

Shared keys, CI identity, policy distribution and audit export need a relay — and people to run it.

### Can I self-host the relay?

Yes, for laptop approvers (Mac / Windows): the relay server ships in the Linux and macOS packages and deploys behind nginx + Cloudflare. The phone app connects only to the official relay, so phone approvals use relay.keyvalet.dev. The relay sees ciphertext either way.

### What about Enterprise?

Later: self-hosted, SSO/SCIM, isolated CI execution. Not before 2027.
