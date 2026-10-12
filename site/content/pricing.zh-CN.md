+++
title = "定价"
description = "KeyValet 在 macOS、Linux、Windows 上免费且开源（Apache-2.0），手机远程审批在官方 relay 的合理使用额度内也免费。团队版——共享凭证、组织策略、审计导出、CI 身份、托管 relay——计划中，尚未推出。"
+++

<div class="plans wide">
  <div class="plan">
    <h3>免费版</h3>
    <p class="price">$0</p>
    <p>开源（Apache-2.0），永久免费。包含今天产品的全部功能：</p>
    <ul>
      <li>Secure Enclave（macOS）或 TPM 2.0（Linux）+ 设备绑定保护的本地凭证库；Windows 预览版用 Hello</li>
      <li>代理以 agent 读不到的特权系统服务运行——三个平台都是</li>
      <li>全部凭证种类：API key、OAuth 2.0、Google service account、GitHub App、JWT、TOTP、AWS STS</li>
      <li>约 50 个服务模板 + 通用 bearer/header/query/basic</li>
      <li>代理调用和本地 SDK 网关</li>
      <li>授权模式：逐次、按凭证、按会话、记住一段时间——Touch ID、polkit 或 Hello</li>
      <li>Claude Code、Codex、Cursor、Grok、Devin 的 hook</li>
      <li><code>keyvalet scan</code> 和本地、只有 root 能读的审计日志</li>
    </ul>
    <p>开发中，同样免费：</p>
    <ul>
      <li>远程审批：agent 跑在服务器或无头 Mac 上，在手机（iOS + Android）或笔记本上批</li>
      <li>配对与远程设置：模式、常设放行票、锁定、一键全部收回</li>
      <li>官方 relay（relay.keyvalet.dev）合理使用额度：3 台设备、每月 2,000 次远程审批；手机 App 固定使用它</li>
      <li>自托管 relay（nginx + Cloudflare）给笔记本审批端，无额度限制</li>
      <li>策略引擎（风险分级、policy.yaml）</li>
    </ul>
    <p class="cta-plan"><a class="btn primary" href="/zh-CN/#install">在 macOS 或 Linux 上安装</a></p>
  </div>
  <div class="plan">
    <span class="badge">计划中——尚未推出</span>
    <h3>团队版</h3>
    <p class="price">$15 <small>每席位/月 · 年付 $12</small></p>
    <p>机器身份不限量（合理使用）。</p>
    <ul>
      <li>共享凭证，按成员设备分别封装</li>
      <li>组织策略即代码——只能收紧成员的本地策略</li>
      <li>审计导出（JSONL / OTLP）</li>
      <li>CI 身份：GitHub OIDC → 短期能力令牌，仓库设置里不再有静态秘密</li>
      <li>无配额限制的托管 relay</li>
      <li>加密的跨设备同步</li>
      <li>成员管理</li>
    </ul>
    <p>上线后提供 14 天试用，无需信用卡。</p>
    <p class="cta-plan"><a class="btn ghost" href="https://github.com/KeyValet/KeyValet/discussions">订阅通知</a></p>
  </div>
  <div class="plan">
    <span class="badge">计划中——尚未推出</span>
    <h3>团队版 + 手机批准</h3>
    <p class="price">$18 <small>每席位/月 · 年付 $15</small></p>
    <p>包含团队版全部功能，另加：</p>
    <ul>
      <li>共享凭证的批准路由到负责人手机</li>
      <li>敏感凭证 N-of-M 批准</li>
      <li>全团队无配额限制的托管 relay</li>
      <li>OIDC SSO（Okta、Entra、Google）</li>
      <li>90 天加密审计留存</li>
    </ul>
    <p class="cta-plan"><a class="btn ghost" href="https://github.com/KeyValet/KeyValet/discussions">订阅通知</a></p>
  </div>
</div>

## 常见问题

### 免费版真的免费吗？

真的——没有时间限制，没有水印，没有安全降级。只有当你碰到只有团队版才有的需求时，可能看到一次升级提示，之后不再出现。

### 你们会看到我的秘密吗？

不会。一切都在本地：秘密存在你机器上只有系统服务能读的凭证库，由 Secure Enclave / TPM 和设备绑定保护。远程审批的 relay 和团队版同步的都只是封装到你设备的密文。

### 团队版为什么收费？

共享密钥、CI 身份、策略分发和审计导出需要一台 relay——以及运维它的人。

### relay 可以自托管吗？

可以，给笔记本审批端（Mac / Windows）用：relay 服务端随 Linux 和 macOS 包发布，部署在 nginx + Cloudflare 后面。手机 App 只连官方 relay，所以手机审批走 relay.keyvalet.dev。不管哪种，relay 看到的都是密文。

### 有企业版吗？

以后会有：自托管、SSO/SCIM、隔离的 CI 执行。不会早于 2027。
