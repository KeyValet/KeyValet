# KeyValet Mobile design system

Source: installed `ui-ux-pro-max` skill, queried on 2026-10-12 with
`security approval mobile minimal`, then `mobile security dashboard`, plus
`responsive accessible cards navigation --stack flutter`.

The matched Minimalism / Swiss style and vault palette fit a security control app.
The generator's marketing conversion pattern does not fit this app and is not used.
Page structure follows the product specification and the skill's native app rules.

## Direction

Calm, precise, professional. Navy anchors the product; fog white creates space;
cobalt identifies actions. Green describes a reported connected state, amber
describes offline delivery, and red describes sensitive or destructive operations.
No decorative gradients, emoji, animated ornaments or invented metrics.
The latest product requirement adds Google / Apple sign-in before the control pages.

## Tokens

| Role | Light | Dark |
| --- | --- | --- |
| Canvas | #F4F6FA | #101725 |
| Surface | #FFFFFF | #1A2333 |
| Main text | #172338 | #EEF2FA |
| Secondary text | #5D6B81 | #AEBBD0 |
| Action | #3454D1 | #AABDFF |
| Decorative border | #DFE5EF | #334157 |
| Control border | #7D8AA1 | #7D8FA1 |
| Success text | #147653 | #77D8B0 |
| Warning text | #8A5100 | #FFCE83 |
| Danger text | #B52E3D | #FFACA9 |
| Summary surface | #172338 | #172338 |
| Summary secondary text | #BDCBE1 | #BDCBE1 |

Use native system fonts for Latin and Chinese; no font downloads or new dependencies.
Type scale: 13 / 14 / 16 / 17 / 21 / 26 / 32, strong titles, regular body.
Monospaced system text is reserved for actual HTTP targets and six-digit pairing codes.
Spacing follows 4/8 dp; phone gutters 20 dp; readable content measure 680 dp.
Cards have a 20 dp radius, inputs/buttons 14 dp, minimum action height 48–52 dp.

## Screens

- Sign-in: navy product panel, Google and Apple actions, clear setup / network errors,
  and a privacy note. No guest entry. Signing in never implies approval.

- Pending: clear page title, navy count summary, individually readable requests,
  explicit risk/signing/delivery tags, useful empty state with pairing action.
- Approval detail: largest type for the actual operation; metadata grouped by
  source, credential and request; agent purpose explicitly unverified; scope
  choices from Rust only; signing requirement adjacent to Allow/Deny.
- Devices: reported connection/mode/protection, readable grant count; pairing CTA.
  Device detail keeps revoke-all in its first section, groups grants and sensitive
  controls, retains typed-label confirmation and biometric signing.
- Activity: day headers and compact record cards, reported queued/delivered state.
- Settings: grouped account, notification, display and diagnostic controls.
  The fixed relay address is internal and never displayed in the app.
  Relay editing remains a real Rust intent, diagnostics remain redacted by Rust.
- Pairing: scanner or paste, clear SAS comparison, explicit both-device checkbox.

## Interaction and accessibility

Use native Material controls, vector Material icons, standard back behavior and
four bottom destinations. No special motion; Flutter reduced-motion preferences
disable route transitions. Content text reflows with system scaling; the brand wordmark stays on one line with full accessible text. Cards and controls
have visible tap feedback. Status has labels as well as color. Safe areas protect
system bars; pages scroll rather than clip in landscape and at large text sizes.
Public models and user intents are the only Dart data; security logic stays in Rust.
