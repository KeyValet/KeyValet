+++
title = "Code signing policy"
description = "Current platform signing status, unsigned Windows releases, and the people responsible for approving KeyValet releases."
+++

Updated: 14 October 2026. KeyValet is maintained by **Simvito Limited** and released under Apache-2.0.

## Current status

Windows release packages are **unsigned**. An Authenticode signature is not required for KeyValet installation, local credentials, remote pairing or approval. Windows may still warn about or block downloaded executables under its application control policies.

The SignPath Foundation application was declined because the project did not yet meet its public visibility criteria. SignPath signing is not enabled and is not a prerequisite for Windows releases.

macOS release packages use the Simvito Limited Developer ID and Apple notarization. Linux release archives have published SHA256 checksums. Checksums verify file integrity; they do not replace a trusted publisher signature. The [download page](/download/) labels the status of each platform.

## Release team

The initial project maintainer is **Guang**, GitHub [@hhstuhacker](https://github.com/hhstuhacker). The current project has one maintainer; these roles do not imply three independent people.

| Role | Member | Responsibility |
| --- | --- | --- |
| Authors / committers | Guang (@hhstuhacker) | Maintain the project source and build workflows. |
| Reviewers | Guang (@hhstuhacker) | Review changes from external contributors before inclusion. |
| Release approvers | Guang (@hhstuhacker), for Simvito Limited | Review the source, validation and artifacts, then publish the draft release. |

Release-team membership changes will be reflected here. See the project's [governance](https://github.com/KeyValet/KeyValet/blob/main/GOVERNANCE.md).

## Windows release process

1. Build from the public KeyValet source using the project's automated build workflow and locked dependencies.
2. Build native x64 and ARM64 ZIPs with the fixed program names, product/version metadata and installation scripts.
3. Verify the archive checksums with the macOS and Linux packages and attach them to a draft release.
4. A maintainer reviews validation and publishes the release, labeled unsigned for Windows.

Windows process authentication verifies the actual service/owner SID, fixed installed file identity and privileged ownership/ACLs. Agent and MCP workers also match service-created child processes. Authenticode signatures and the old unsigned-development marker do not determine feature access.

Previously distributed preview packages retain their older runtime signature checks. The new release behavior requires rebuilding or installing the updated package. See [downloads](/download/) and the [Windows support record](https://github.com/KeyValet/KeyValet/blob/main/docs/windows.md) for publication and acceptance.

## Privacy and reporting

Software data flows, optional network services and provider policies are described in our [Privacy policy](/privacy/). Credential values and device private keys are not included in distributed packages or signing submissions.

For questions about this policy, contact [support@simvito.com](mailto:support@simvito.com). For a suspected vulnerability, use the project's [private vulnerability reporting](https://github.com/KeyValet/KeyValet/security/advisories/new) and avoid posting secrets in a public issue.
