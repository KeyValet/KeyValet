+++
title = "下载 KeyValet"
description = "macOS、Linux 与没有代码签名的 Windows 正式包，以及源码、校验值和签名状态。"
+++

KeyValet 是供 AI agent 与开发工具使用的免费 Apache-2.0 开源凭证代理。凭证保存在本机，由你控制自动化工具如何使用。开始前请阅读[指南](/zh-CN/guide/)、[隐私政策](/zh-CN/privacy/)与 [Code signing policy](/zh-CN/code-signing/)。

## macOS 与 Linux

[在 GitHub 下载公开发布包](https://github.com/KeyValet/KeyValet/releases)。选择对应操作系统与架构的归档，并核对该版本的 `SHA256SUMS`。

| 平台 | 可用发布包 | 签名状态 |
| --- | --- | --- |
| macOS，Apple Silicon | macOS arm64 归档 | Simvito Limited Developer ID 签名与 Apple 公证。 |
| Linux，x64 / ARM64 | 原生 Linux 归档 | 提供 SHA256 校验值，不是 Windows Authenticode 签名。 |

安装器会选择对应平台的发布包：

```sh
curl -fsSL https://keyvalet.dev/install.sh | sh
```

## Windows 11

Windows 正式包采用没有代码签名的 x64 与 ARM64 ZIP。本地凭证、远程配对和审批不要求 Authenticode 签名；Windows 的应用控制策略仍可能影响下载程序的运行。

发布流程现已将 Windows 包纳入 draft release。维护者公开发布后，在 [GitHub Releases](https://github.com/KeyValet/KeyValet/releases) 中选择 `keyvalet-<tag>-windows-x64.zip` 或 `keyvalet-<tag>-windows-arm64.zip`，并核对 `SHA256SUMS`。新版本公开发布前，可以[从源码构建](https://github.com/KeyValet/KeyValet/blob/main/docs/windows.md#build-and-install-a-windows-release)。

先配置 Windows Hello，再解压 ZIP。由预期使用者在普通 PowerShell 中运行包内安装器，把占位符换成 ZIP 的完整路径；系统安装由 UAC 提权：

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\install.ps1 `
  -PackagePath '<下载的正式 ZIP 完整路径>'
```

安装器会自动启动 relay 服务并等待配对，不需要开发开关或信任标记。凭证操作使用受保护的安装目录；此包是安装包，不是便携凭证库。设置、恢复与卸载步骤见包内 Windows 指南。

此前的预览 ZIP 仍包含旧签名检查，应使用新构建的正式包。真实客户端与硬件的剩余验收项见 [Windows 支持记录](https://github.com/KeyValet/KeyValet/blob/main/docs/windows.md)。

## Code signing policy

Windows 正式发布不要求代码签名。SignPath Foundation 申请本次未获批，也未启用 SignPath 签名；macOS 继续使用原有签名与公证流程。各平台的签名状态与发布流程见[代码签名政策](/zh-CN/code-signing/)。

发布源码位于[项目仓库](https://github.com/KeyValet/KeyValet)。校验值用于核对完整性，不是发布者签名。
