# KeyValet

**钥匙在芯片里，批准在你手上。**

让 AI agent 在任何机器上用任何 API，却永远碰不到秘密。KeyValet 把你的 API key 和 OAuth 账号放在一个只有系统服务能读、agent 读不到的硬件保护凭证库里；你点头之后，由它替 agent 发出每一次调用。

[安装](#安装) · [官网](https://keyvalet.dev/zh-CN/) · [使用指南](https://keyvalet.dev/zh-CN/guide/) · [安全模型](SECURITY.md) · [English](README.md)

支持 Claude Code、Codex、Cursor、Gemini CLI、Grok、Devin——任何 MCP 客户端或 HTTP SDK；支持 macOS、Linux 和 Windows 11。

## 为什么是 KeyValet

市面上多数「agent 看不到 key」的工具，代理进程和 agent 跑在同一个系统用户下，主密钥是个文件或环境变量——被注入的 agent 两样都读得到。KeyValet 从结构上堵死这条路：

- **代理不是 agent。** 凭证库归 macOS 的 root 守护进程、Linux 的独立系统用户、Windows 的 LocalSystem 服务所有。agent 的进程读不到文件，也读不到内存。
- **钥匙在芯片里。** macOS 必须有 Secure Enclave，Linux 用 TPM 2.0，Windows 用 Hello。拷走凭证库文件只能拿到密文。
- **一次批准，一次调用。** 逐次弹窗显示真实请求——方法、主机、路径、关键字段——按一次只放这一笔。任何放宽都要你的指纹。
- **什么都不出你的机器。** 没有账号、没有云、没有遥测。审计日志也在本地，agent 同样读不到。

它不做的事：防同一台机器上被攻破的 root / SYSTEM；核验 agent *自称*在干什么。完整清单见 [SECURITY.md](SECURITY.md)。

## 怎么运作

1. **agent 申请**——通过 MCP 或本地网关，说明要用哪个凭证、为了什么。
2. **你批准**——Touch ID、polkit 或 Hello。默认按凭证；想逐次也可以，屏幕上就是真实请求。
3. **KeyValet 代为调用**——特权服务注入 key，只发往你允许的域名，并抹掉响应里回显的秘密。
4. **agent 拿到结果**——拿不到 key。会话、目的、结果进审计日志。

## 试一下

```sh
curl -fsSL https://keyvalet.dev/install.sh | sh
```

然后直接跟 agent 说：

> `/keyvalet:add openai`——原生对话框让**你**输入 key，它不经过对话。
>
> 「用 KeyValet 列出我的 OpenAI 模型。」——一次 Touch ID，agent 拿到响应，拿不到 key。
>
> 「通过 KeyValet 连接我的 GitHub 账号，建一个叫 demo 的仓库。」——OAuth、refresh token、私钥都留在凭证库里，agent 手里只有短期 token。

还是把 key 贴进了对话？hook 会接住它，存进 KeyValet 而不是 `.env`。

底下有什么：约 50 个服务模板、自动刷新的 OAuth 2.0、Google 服务账号、GitHub App、JWT、TOTP、AWS STS、给 SDK 用的流式网关（`OPENAI_BASE_URL=…`）、把 `.env` 里的秘密收进来的 `keyvalet scan`，以及从「逐次」到「记住 8 小时」的授权模式。

## 安装

| | 要求 | 详情 |
| --- | --- | --- |
| **macOS** | Apple Silicon，macOS 14+。已签名并公证。 | [使用指南](https://keyvalet.dev/zh-CN/guide/#安装) |
| **Linux** | systemd、polkit、sudo；TPM 2.0 需要 `tpm2-tools`，无 TPM 须显式加 `--software`。x64 与 ARM64。 | [Linux](docs/linux.md) |
| **Windows 11** | 24H2+、Windows Hello。x64/ARM64 正式包没有代码签名；本地与远程功能不要求签名。 | [Windows](docs/windows.md) · [WSL](docs/wsl.md) |

上面那条命令会选对平台的包，要你输一次密码，并配置好检测到的 agent（Claude Code、Codex、Cursor、Grok、Devin CLI）。卸载：`curl -fsSL https://keyvalet.dev/install.sh | sh -s -- --uninstall`。密钥保护、恢复与各平台边界：[保护矩阵](docs/key-protection.zh-CN.md)。

## 下一步：在手机上批准

今天你在 agent 所在的那台机器上批准。下一步，agent 跑在没人坐在旁边的机器上——Linux 服务器、拔了显示器的 Mac mini、过夜任务——*批准*来到你手边的设备上：手机 App（iOS + Android），或你正在用的笔记本。

- 钥匙不动：留在跑 agent 那台机器的 TPM / Secure Enclave 里。手机签一个绑定到这一次请求的批准；relay 只转发密文。手机 App 走官方 relay，自托管 relay 配笔记本审批端。
- 你定边界——这一次、1 小时、本会话、这个凭证一直允许、这台机器一直允许——也能远程收紧、收回、锁定。放宽要 Face ID / Touch ID，收紧永远不要。
- 超时不等于「否」：agent 得到「待批准」，先干别的，你批了它接着拿结果。

**状态：开发中。** 协议、relay、helper 校验已在 `main` 上并有软件测试；端到端的配对 → 手机批准链路和 App 分发还没完成。设计：[架构](docs/remote-approval-architecture-2026-10.zh-CN.md) · [产品](docs/remote-approval-product-2026-10.zh-CN.md) · [待办](docs/remote-approval-reports/OPEN-QUESTIONS.md)。

## 了解更多

[使用指南](https://keyvalet.dev/zh-CN/guide/) · [安全模型](SECURITY.md) · [参与贡献](CONTRIBUTING.md) · [行为准则](CODE_OF_CONDUCT.md) · [治理](GOVERNANCE.md) · [商标](TRADEMARK.md)

Apache-2.0 · 来自 [Simvito Limited](https://github.com/KeyValet)
