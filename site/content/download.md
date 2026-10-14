+++
title = "Download KeyValet"
description = "macOS, Linux and unsigned Windows releases, source code, checksums, and release signing status."
+++

KeyValet is a free, Apache-2.0 open-source credential broker for AI agents and developer tools. It stores credentials locally and lets you control how automated tools use them. Start with the [guide](/guide/), [Privacy policy](/privacy/), and [Code signing policy](/code-signing/).

## macOS and Linux

[Download published releases on GitHub](https://github.com/KeyValet/KeyValet/releases). Select the archive for your operating system and architecture, and check the release's `SHA256SUMS`.

| Platform | Available release | Signing status |
| --- | --- | --- |
| macOS, Apple Silicon | macOS arm64 archive | Simvito Limited Developer ID signature and Apple notarization. |
| Linux, x64 / ARM64 | Native Linux archives | Published SHA256 checksums; these are not Windows Authenticode signatures. |

The installer selects the platform-specific release:

```sh
curl -fsSL https://keyvalet.dev/install.sh | sh
```

## Windows 11

Windows releases use unsigned x64 and ARM64 ZIPs. KeyValet does not require an Authenticode signature for local credentials, remote pairing or approval. Windows application control policies can still affect whether downloaded executables run.

The release workflow now includes Windows packages in the draft release. Once a maintainer publishes it, select `keyvalet-<tag>-windows-x64.zip` or `keyvalet-<tag>-windows-arm64.zip` from [GitHub Releases](https://github.com/KeyValet/KeyValet/releases) and verify its entry in `SHA256SUMS`. Until the updated release is published, [build the package from source](https://github.com/KeyValet/KeyValet/blob/main/docs/windows.md#build-and-install-a-windows-release).

Enable Windows Hello, extract the ZIP, and run the installer from the intended user's normal PowerShell. Replace the placeholder with your ZIP's full path; UAC handles system installation:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\install.ps1 `
  -PackagePath '<full-path-to-the-downloaded-release.zip>'
```

The installer enables the relay service automatically and waits for pairing. No development switch or trust marker is needed. Credential operations use the protected installed directory; this is an installer package, not a portable vault. See the included Windows guide for setup, recovery and uninstall instructions.

Earlier preview ZIPs contain older signature checks. Use a newly built release package for the current behavior. The remaining live client and hardware acceptance is listed in the [Windows support record](https://github.com/KeyValet/KeyValet/blob/main/docs/windows.md).

## Code signing policy

Windows releases proceed without Authenticode signing. The SignPath Foundation application was declined and SignPath signing is not enabled. macOS signing and notarization continue unchanged. See the [Code signing policy](/code-signing/) for each platform's signing and release process.

The source for releases is available in the [repository](https://github.com/KeyValet/KeyValet). Checksums verify integrity; they do not provide a publisher signature.
