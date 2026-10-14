+++
title = "隐私政策"
description = "哪些数据留在本机，API 调用与远程审批会发送什么，以及如何联系 KeyValet 处理数据请求。"
+++

生效日期：2026 年 10 月 14 日。KeyValet 是由 **Simvito Limited** 维护的 Apache-2.0 开源项目。本政策涵盖官网、软件和 `relay.keyvalet.dev` 官方远程审批 relay。远程审批与手机分发仍在验收中；可用功能取决于构建版本及已配置的服务。

隐私联系邮箱：[support@simvito.com](mailto:support@simvito.com)。

## 本地凭证与审批

凭证库加密保存在安装 KeyValet 的机器上。凭证值、恢复口令和设备私钥不会上传到 KeyValet 账户，也不会通过 relay 同步。平台密钥保护取决于实际配置的 provider，详见[安全模型](/zh-CN/security/)。

你授权操作时，KeyValet 会在本机内存中处理秘密。操作系统负责自己的生物识别或 PIN 认证；KeyValet 不收集指纹图像、生物识别模板或 Windows Hello PIN。输入 KeyValet 的恢复口令在本机用于保护或恢复凭证库。

本地设置与审计记录可能包含凭证标签、允许的域名、请求元数据、目的说明、时间和结果。应用不会主动把凭证值写进审计日志；请勿在标签、目的说明或支持报告中填写秘密。本地文件和备份由你控制，受安装时的操作系统权限约束。

## API 请求与第三方登录

你批准 API 操作后，KeyValet 会把请求及所需的认证材料发送给你配置的服务。该服务接收请求数据，并适用其自己的隐私政策。OAuth 登录会联系你选择的身份提供方。你授权的原始凭证读取或短期 token 请求，可以把相应材料交给请求客户端；仅代理凭证具有不同的访问边界。选择授权范围前，请阅读[指南](/zh-CN/guide/)与[安全模型](/zh-CN/security/)。

## 可选的远程审批

使用本地凭证库不需要 KeyValet relay 账户。启用远程审批会注册设备，并建立用于认证、配对、投递和设备在场提示的网络连接。

relay 处理账户与设备标识、设备标签、操作系统和能力信息、公钥、可选的公开证明、会话与恢复验证哈希、配对状态、路由元数据、消息时间和过期时间。启用账户登录时，还会保存身份提供方标识与 subject，以及提供方返回的邮箱和显示名称。relay 验证登录证明，不接收 Google 或 Apple 密码。

登录和账户恢复过程中，relay 会处理身份提供方的身份 token、远程账户恢复码等验证材料。远程账户恢复码与本地凭证库恢复口令不同；两者都不要发送给支持人员。

审批请求与决定通过端到端加密信封传输。relay 运营者仍能看到路由信息、消息大小与时间，以及公开注册元数据。加密不会隐藏这些元数据或 IP 地址等普通网络信息。relay 不接收凭证库内容或设备私钥。

支持的手机构建启用通知后，会使用设备 push token。KeyValet 与所选推送服务处理 token 和投递信息。推送消息用于提示客户端收取消息，不以可读的推送内容发送凭证值或审批详情。关闭通知、退出登录或吊销设备可以使相关 token 或授权失效，但不会删除所有历史记录。

自托管 relay 的服务端数据与保留策略由部署者管理。当前手机构建使用官方 relay；桌面自托管是另一种部署选择。

## 网站、下载与服务提供方

官网托管于 Cloudflare Pages。下载链接可能指向本站或 GitHub Releases。Cloudflare 与 GitHub 会处理提供内容、保护服务和记录下载活动所需的网络与请求信息。网站源码没有广告追踪或分析脚本，应用没有单独的产品使用分析采集器；relay 的运行消息与服务端日志仍属于数据处理。

根据你选择的功能，相关政策包括 [Cloudflare](https://www.cloudflare.com/privacypolicy/)、[GitHub](https://docs.github.com/en/site-policy/privacy-policies/github-general-privacy-statement)、[Google（含 Firebase 投递）](https://policies.google.com/privacy)与 [Apple](https://www.apple.com/legal/privacy/)。提供方可能在你所在国家或地区以外处理数据。第三方 API 调用还适用对应服务的政策。

## 数据保留与你的选择

本地凭证库、设置、审计文件和备份会保留至你主动移除。卸载软件不一定删除保留的数据或备份。不要把凭证库、恢复材料或凭证发给支持人员。

relay 会话与消息具有过期规则，过期的审批会被拒绝。过期不代表数据库、日志和备份中的每份副本都会立即擦除。账户、设备记录与安全元数据可能为了运行、吊销和排障继续保留。当前服务没有自动删除账户的界面。

你可以保持远程审批关闭、吊销设备与授权、退出手机账户，或关闭通知。涉及官方 relay 元数据的查询、更正或移除请求，请发到 [support@simvito.com](mailto:support@simvito.com)。我们可能需要验证你对账户或设备的控制权；不要发送密码、PIN、恢复码或私钥。自托管服务的数据请求请联系其部署者。

## 更新

数据流发生实质变化时，本页会更新生效日期。[开源仓库](https://github.com/KeyValet/KeyValet)与 [Code signing policy](/zh-CN/code-signing/)说明软件与发布流程。
