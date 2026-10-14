+++
title = "Code signing policy · 代码签名政策"
description = "各平台签名状态、没有代码签名的 Windows 正式包，以及 KeyValet 的发布审批负责人。"
+++

更新日期：2026 年 10 月 14 日。KeyValet 由 **Simvito Limited** 维护，以 Apache-2.0 发布。

## 当前状态

Windows 正式包**没有代码签名**。安装、本地凭证、远程配对与审批均不要求 Authenticode 签名。Windows 自身的应用控制策略仍可能对下载的程序提示或阻止运行。

SignPath Foundation 申请因项目公开知名度尚未达到要求而未获批。没有启用 SignPath 签名，Windows 正式发布也不以签名申请获批为前提。

macOS 发布包使用 Simvito Limited Developer ID 签名并经 Apple 公证。Linux 发布归档提供 SHA256 校验值。校验值用于核对文件完整性，不能代替可信发布者签名。[下载页](/zh-CN/download/)分别标明各平台的状态。

## 发布团队

初始项目维护者为 **Guang**，GitHub [@hhstuhacker](https://github.com/hhstuhacker)。当前项目只有一名维护者，下列角色不表示存在三个独立人员。

| 角色 | 成员 | 职责 |
| --- | --- | --- |
| 作者 / 提交者 | Guang（@hhstuhacker） | 维护项目源码与构建工作流。 |
| 审查者 | Guang（@hhstuhacker） | 在纳入项目之前审查外部贡献。 |
| 发布审批者 | Guang（@hhstuhacker），代表 Simvito Limited | 审查源码、验证结果与产物，再公开发布 draft release。 |

发布团队成员变化会更新在本页。项目组织规则见[治理文档](https://github.com/KeyValet/KeyValet/blob/main/GOVERNANCE.md)。

## Windows 发布流程

1. 用项目自动构建工作流，从公开的 KeyValet 源码和锁定依赖构建。
2. 构建原生 x64 与 ARM64 ZIP，核对固定程序名称、产品与版本元数据、安装脚本。
3. 与 macOS、Linux 包一起核对摘要，将所有包和校验值附到 draft release。
4. 维护者审查验证结果并公开发布，Windows 包标明没有代码签名。

Windows 进程认证验证实际服务或 owner SID、固定安装文件身份、特权属主与 ACL；agent 和 MCP worker 还必须匹配服务创建的子进程。代码签名与旧开发标记不再决定功能是否可用。

此前分发的预览包仍保留旧运行时签名检查；新行为需要重新构建或安装更新后的包。发布与验收状态见[下载页](/zh-CN/download/)和 [Windows 支持记录](https://github.com/KeyValet/KeyValet/blob/main/docs/windows.md)。

## 隐私与问题反馈

[隐私政策](/zh-CN/privacy/)说明软件的数据流、可选网络服务与提供方政策。分发包和签名提交不包含凭证值或设备私钥。

签名政策问题请联系 [support@simvito.com](mailto:support@simvito.com)。疑似漏洞请使用项目的[私密漏洞报告](https://github.com/KeyValet/KeyValet/security/advisories/new)，不要在公开 issue 中发布秘密。
