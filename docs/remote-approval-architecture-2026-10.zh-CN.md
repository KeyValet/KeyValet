# 远程审批与多设备配对：架构设计

- 版本：V1 实现与验收回写（2026-10-13）。第一轮 W0–W9、后续接口收口与第二轮 R2-A/B/C/D 的事实合并于本文；原报告保留各自测试快照。
- 范围：执行端代码覆盖 macOS / Linux / Windows，审批端代码覆盖 macOS 原生弹窗、Windows PCP/Hello 与手机 App。Ubuntu × MacBook 使用官方 relay 联调，真实批准/执行与 20 次计时已通过实测，完整 M2 尚未完成；Android Pixel 7 对软件执行端的核心审批已通过，iOS 尚未完成真机验收。云端密钥保护与隔离执行为 V2。
- 怎么读：正文与附录描述当前契约，明确标为「目标」「验收中」「V2／计划中」的内容不代表已通过；§16 是实测验收表，§17 保留实施分工及当前里程碑，§18 汇总已决与仍开放事项。接口核对以当前代码为准；实现违背已决安全要求时，在 §18 与 OPEN-QUESTIONS 留下冲突，不用旧附录覆盖 K1–K4。
- 与现有文档的关系：本文是 [architecture-2026-10.md](architecture-2026-10.md) §7.4（Approver）、§8.1（设备密钥）、§8.3（配对）、§9（路由）、§10.3（relay）的细化与修订。冲突处以本文为准，并在落地时回写总架构文档。产品侧见 [remote-approval-product-2026-10.zh-CN.md](remote-approval-product-2026-10.zh-CN.md)。
- 实施状态：**M0/M1 完成，M2–M5 未完成。** Windows LocalSystem 双 PCP 键、安装／升级／卸载与真机 Hello 分项已有通过记录，签名现为可选，新版无签名整包与完整公网双角色仍待验；Pixel 7 配对、锁屏 Quick、App 指纹 Strong、同 ID 升级与设置三步通过，但重启拉取及远端退出清理未通过。Mac/ndu Strong 配对=1，真实 GET=27（401×1/403×26），n=20 p50=3.0905 s/p95=6.0237 s，冻结 audit=37/37；T2 两轮已通过并撤回；Mac→ndu 正向吊销 10.583576 s、SE 取消保真与 Mac 实际投递已验，反向吊销/保留历史的重新配对、手机通知和原生 biometric failure 仍待验收；ndu 当前已吊销，present 已恢复，完整锁屏周期已测 8.160/6.782 s；两小时合盖由本人取消并改为源码 review，最新 audit 53/54、差异 1。运行时只有 Codex 和 Devin 的托管模型实测完成，Claude/channels 门槛未过。证据见 [R2-A](remote-approval-reports/R2-A-m2-acceptance.md)、[R2-B](remote-approval-reports/R2-B-windows.md)、[R2-C](remote-approval-reports/R2-C-mobile.md)、[R2-D](remote-approval-reports/R2-D-runtimes.md)。

---

## 0. 决策摘要

| # | 决策 | 一句话理由 |
| --- | --- | --- |
| D1 | 凭证留在 Ubuntu 服务器的 vault 里，由服务器上的 helper 注入执行；MacBook 只做审批，不做执行端 | 服务器上的 agent 要 7×24 跑，MacBook 合盖就离线；Secure Enclave 又要求 GUI 会话。总架构 §9 的「Linux 调 Mac 执行」保留为后续可选路由，不是第一版 |
| D2 | 第一天就有 relay，不做 Mac↔Ubuntu 直连 | 直连无法在 MacBook 睡眠时排队；helper 不能开入站端口 |
| D3 | 官方 relay 已部署到 `relay.keyvalet.dev`；自托管只服务桌面审批端 | K2/K3 要求手机登录及固定官方地址；桌面／CLI 仍支持匿名自托管 |
| D4 | MacBook、Windows 与手机 App 共用总架构里的「审批设备」模型：同一套设备密钥、HPKE 信封、Quick/Strong 两档 | 任何一种审批端都只是多一台设备，协议不变 |
| D5 | 每台设备的**身份密钥**与**审批密钥**是不同的密钥对象 | 身份密钥要无人值守签名（relay 认证、信封签名），审批密钥要求用户在场（Touch ID）。总架构 §8.1 已有此要求 |
| D6 | 审批决定签名覆盖除 `sig` 外完整对象的 JCS，包括 digest、nonce、decision、scope 与扩展；执行端重算 digest，一次性 nonce 落库 | 防重放、防「批了 A 执行 B」，未知字段也不能被替换 |
| D7 | Grant 预授权（§7.1、§7.4）已实现，设置票始终 Strong | K4/D03 不因短有效期降低签发或验签要求 |
| D8 | 任何一环拿不到合法批准都 fail closed；没有确认码、没有软件回退 | 与 Linux 现有实现一致 |
| D9 | 服务器 root 不在威胁模型内，与 macOS 一致 | 远程审批不给普通 Linux helper 增加抵御 root 的隔离；文档、状态、弹窗都要如实写 |
| D10 | 审批超时只产生「待批准」，永不映射成「拒绝」；agent 侧用「调用内等待 → 放手 → 续等工具 → Stop hook / channels 唤醒」四层提供等待与续等入口；各运行时实测仍按 §16 验收 | 各家 agent 的工具调用超时从 60 s 到 28 h 不等、推送能力只有 Claude Code 有；把「不」留给用户，把等待交给可阻塞的工具调用（§6.9） |
| D11 | 审批端不只是「批/拒」，还是执行端的**远程控制面**：所有授权边界（这一次 / 1 小时 / 本会话 / 这个凭证一直允许 / 这台机器一直允许 / 全局 T1 / 逐执行端 T2）和设置（模式、锁定、吊销、会话寿命）由签名 ApprovalDecision 衍生内部授权，或由审批密钥签独立 Grant / Directive 对象，经 relay 下发，执行端只认签名不认来源 | 一套对象模型同时覆盖弹窗里的范围选择、预授权令牌和设置页；收紧用 Quick，放宽必须 Strong；以后 iPhone App、Web 控制台、团队策略都是同一条路（§7.4–7.6） |
| D12 | 第一版只实现本地硬件密钥，但密钥保护、执行端、审批者、授权签发者四条线都在 V1 就留出接口与枚举位，云 KMS、Nitro Enclave、Web 设备密钥、服务型审批者只加实现不改协议 | 协议字段一旦上线就难改；接口与保留字段的成本很低（§13） |
| D13 | 执行端第一版就覆盖 macOS / Linux / Windows；审批端第一版覆盖**手机 App（Flutter，iOS + Android）**以及 macOS（Touch ID）与 Windows（Hello）的原生弹窗 + 终端；手机 App 是唯一的图形审批/控制面，桌面不做图形设置页，Web 只随 Team 服务 Lead | 用户与 Team 买家都是混合 OS；无头机器的用户只有手机在手边；Windows Hello 只有 RSA-2048，所以签名算法按密钥记录决定（`ES256` / `RS256`），而不是写死 |
| D14 | V1 按**工作流**并行实施，不按时间串行：先冻结附录里的接口契约与测试向量，再让 relay、relay-client、设备密钥、helper、MCP/hook/proxy、桌面 agent、CLI、手机 App、安装器各自独立推进，最后一个集成工作流收口 | 要让多个 agent 同时干活，唯一可行的协作方式是「契约先行 + crate 级所有权」；谁都不能改别人的 crate，契约变更只能由契约所有者改并同步测试向量（§17） |

---

## 1. 要解决的问题与边界

### 1.1 问题

既有本地审批使用 macOS Touch ID 和 Linux polkit；无人值守执行端需要把审批送到用户手边。V1 的签名／HPKE、等待恢复和远程控制面已接线，实机完成度以 §16 为准。

### 1.2 第一版目标与验收边界

1. Ubuntu 服务器上的 agent（Claude Code / Codex / OpenClaw / Hermes / cron 脚本）发起凭证使用请求时，用户在 MacBook 上收到带完整真实请求的审批弹窗，Touch ID 一下，服务器上的 helper 才注入执行。
2. MacBook 和 Ubuntu 通过一次配对互相认识；之后可以再加第二台 Mac，也可以吊销任一台。
3. 用户可以在 MacBook 上一次性签发「今天 500 次以内对 `api.github.com` 的 GET/POST」这类预授权，服务器上符合范围的调用不再打扰人。
4. MacBook 合盖、离线、relay 不可达时，行为可预期：请求排队或超时，绝不放行。
5. 两端都有审计：服务器记「谁批的、多久批的」，MacBook 记「我批了什么给哪台机器」。
6. 用户没有立刻批时，Claude Code、Codex、Cursor、Gemini、Devin、Grok 以及走 HTTP 的 OpenClaw / Hermes / SDK 上的 agent 都不会把超时当成拒绝，并且在用户随后批准时能在不重新下指令的情况下拿到结果（§6.9）。
7. 审批端的弹窗／CLI／手机设置共用签名 Grant／Directive 控制面；收紧 Quick、放宽和设置票 Strong，T2 需单独确认且不得全局继承（§7.4–§7.6）。
8. 执行端在 macOS / Linux / Windows 上都能跑；审批端是手机 App（iOS + Android）加 macOS / Windows 的原生弹窗 + 终端（§2.3、§3.1、§9.2）。手机 App 在 V1 内：锁屏 Quick / 生物识别 Strong 审批、每台执行端的设置页、放行票与一键收回、无人值守开关、扫码配对、活动摘要、推送与静默/升级投递。
9. 云 KMS、Nitro Enclave、Web 控制台、服务型审批者在协议与接口上已经有位置，第一版不实现（§13）。

### 1.3 第一版不做

- Linux 桌面作为审批端（V2）；桌面图形设置页（不做）；瘦菜单栏/托盘（V2，按需）；Mac 替 Linux 执行凭证操作（总架构 §9 路由，V2）；vault 密文跨设备同步与手机 OAuth 添加凭证（V2）；团队 N-of-M、服务／组织审批者与 Web 控制台（V2）；不同操作的签名批量授权（V2）；官方计费／配额执行及 App Store / Play 公开上架（计划中）。TestFlight／Play 内部测试打包脚本已实现，发行包和上传尚未完成。
- 云端密钥保护与隔离执行的**实现**（只留接口，§13）。
- 不改变 Linux / Windows helper 的隔离边界：远程审批不让它防 root / SYSTEM。

---

## 2. 拓扑与进程

```
┌─ Ubuntu 服务器（vault + 执行端）──────────────────────────────────────────────┐
│  agent 进程（普通用户 u，例如 claude / codex / openclaw / cron）                  │
│     │  kv-mcp · kv-hook · keyvalet run / 网关（用户 u，不持任何秘密）              │
│     │  IPC v4：Unix socket；helper 将已连接 FD 交给 peer broker 验证调用方          │
│     ▼                                                                             │
│  kv-helper（systemd，系统用户 keyvalet，/var/lib/keyvalet 0700，无入站、无长连接）  │
│     vault 密文 · TPM 主密钥 · TPM 身份密钥 DK_srv · devices · nonces · grants      │
│     Approver 选择：polkit（本地）│ remote-device（新）│ capability token │ auto    │
│  keyvalet-peer.service（root，仅 CAP_SYS_PTRACE、AF_UNIX）                       │
│     SO_PEERCRED + SO_PEERPIDFD（Linux 6.5+）；执行文件 inode／UID／角色证明       │
│     无网络、无 vault 路径、无密钥操作；helper/client 的 capability 集合为空      │
│     │  IPC：/run/keyvalet/relay.sock（仅允许 keyvalet-relay 用户）                  │
│     ▼                                                                             │
│  kv-relay-client（systemd，系统用户 keyvalet-relay，唯一出站进程）                 │
│     relay HTTP/WS、control transport、密文队列；签名／HPKE 委托 helper          │
│                                                                                   │
│  kv-server（可选桌面自托管；SQLite；路由密文）                                    │
└──────────────────────────────┬────────────────────────────────────────────────────┘
                               │ TLS：Cloudflare（橙色云代理）→ nginx（Origin CA 证书）→ 127.0.0.1:8787
┌──────────────────────────────▼────────────────────────────────────────────────────┐
│  MacBook（审批端）                                                                 │
│  kv-relay-client（per-user LaunchAgent dev.keyvalet.relay，签名校验）               │
│     │ IPC                                                                         │
│  dev.keyvalet.helper（root daemon）── 审计 · peers · issued_approvals                │
│     │ 经 audit token + code requirement 校验后委托                                  │
│  dev.keyvalet.agent（per-user LaunchAgent）→ kv-touchid                             │
│     SE 身份密钥 DK_mac · SE 审批密钥 AK_mac_quick / AK_mac_strong · 审批对话框        │
└───────────────────────────────────────────────────────────────────────────────────┘
┌─ 手机（审批端，Flutter App）────────────────────────────────────────────────────────┐
│  Flutter UI（Dart，只渲染）── kv-mobile-core（Rust：信封、Grant/Directive、队列、SQLite）│
│  kv_native（Swift / Kotlin）：SE / Keystore 密钥、生物识别门控签名、推送、证明            │
│  iOS NSE / Android FirebaseMessagingService：后台解密与通知渲染（原生 + 同一 Rust 库）   │
│  WS 到 relay（前台）· APNs / FCM 唤醒（后台）                                           │
└───────────────────────────────────────────────────────────────────────────────────┘
```

### 2.1 进程与信任边界

| 进程 | 机器 | 运行身份 | 持有 | 不持有 |
| --- | --- | --- | --- | --- |
| agent 及 `kv-mcp` / `kv-hook` / 网关 | Ubuntu | 普通用户 `u` | IPC 连接；approval_id | 任何秘密、任何私钥、vault 文件读权限 |
| `kv-helper` | Ubuntu | 系统用户 `keyvalet` | vault 密文、TPM 密钥句柄、设备目录、nonce/grant/令牌表、审计链 | 出站网络、长连接 |
| `kv-relay-client` | Ubuntu | 新系统用户 `keyvalet-relay` | relay 会话令牌、对端公钥缓存、待发/待收信封 | 任何私钥、任何审批明文；HPKE 封解均由 helper 完成 |
| `keyvalet-peer.service` | Ubuntu（Linux 6.5+） | root，仅 `CAP_SYS_PTRACE` | Unix socket 的内核 PID/UID、安装执行文件与角色映射 | 不处理 vault、私钥、网络连接、批准或执行操作 |
| `kv-server`（relay） | Ubuntu 或别处 | 容器 / 系统用户 | 设备公钥、账户、密文 blob、时间戳 | 明文、UMK、凭证元数据 |
| `kv-relay-client` | Mac | 当前用户（LaunchAgent） | 同上 | 同上 |
| `dev.keyvalet.helper` | Mac | root | Mac 本地 vault、peers、本机签发记录、审计 | 出站长连接 |
| `dev.keyvalet.agent` + `kv-touchid` | Mac | 当前用户（GUI 会话） | SE 密钥操作、审批对话框 | 任何明文（远程审批不涉及 Mac 本地凭证） |
| 手机 App 主进程（Flutter + `kv-mobile-core` + `kv_native`） | iPhone / Android | App 沙箱 | 设备密钥句柄（SE / Keystore）、peers、待批队列、签发记录（SQLite） | 任何凭证值；Dart 层不持私钥、不验签 |
| iOS NSE / Android 消息服务 | 手机 | 扩展 / 服务进程 | 同一 Rust 库、App Group 里的密文队列与设备密钥加密表示 | 审批密钥的使用权（Quick/Strong 签名只在主 App 内发生） |
| `kv-push` | simvito | 专用无登录系统用户 `keyvalet-push` | 提供商凭据、设备推送 token、目标与投递模式 | 审批内容、密文、设备审批私钥；仅监听 `127.0.0.1:8788` |

**信封的加解密在哪一侧完成是关键细节。** 为了让 `kv-relay-client` 不持私钥，HPKE 解封（需要身份私钥做 ECDH）在 helper 内完成：relay-client 收到信封 → 原样经 IPC 交给 helper → helper 用 TPM/SE 做 ECDH、解封、验签。封装也由 helper 完成。relay-client 负责经过认证的 control transport、重连和持久密文队列，不处理授权策略。helper 已移除 reqwest、rustls、tokio-tungstenite、futures-util 的直接生产依赖；全部 relay HTTP/WS 都在客户端执行。

注册、配对和吊销的 HTTP/临时 WS 也由 relay-client 执行。Linux/macOS 尚未配对时先运行控制 worker，经附录 C 的有界控制队列领取 helper 已构造的请求；helper 自己签 DK challenge 和 Strong 证明，不接收 relay 会话令牌。完整配置绑定出现或改变后，客户端启动或重建长连接。Windows 的受保护配置缺失证明与无绑定 control worker 已接线；临时可信 VM 签名下 Auto/Running 等待绑定和不可读配置拒绝有历史通过记录。当前源码默认无签名发行，relay 自动运行并等待绑定，以 OS 身份、固定安装文件身份与受保护 ACL 认证；旧未签名包 Manual/Stopped 不代表当前策略。新整包及实际绑定公网链路仍需验收，见 [Windows 发行策略](windows.md#windows-release-identity-policy)与 [R3-B 续验](remote-approval-reports/R3-B-unsigned-acceptance.md)。

审批端的已验证入站请求在 relay ACK 前写入 SQLite `inbound_approvals`，与 vault AEAD 审计收据同事务提交。重启核对最新收据哈希、信封身份签名与当前设备权限后恢复；取消／已签发不重新呈现，过期拒绝，升级提示单独保留。恢复不重新做硬件 ECDH，也不提供硬件反回滚或外部 HTTP exactly-once。见 [R3-B 无签名验收](remote-approval-reports/R3-B-unsigned-acceptance.md)。

Linux helper 的跨 UID 调用方检查通过独立 root broker 完成：传递已连接 socket 的 FD，使用 `SO_PEERCRED`、`SO_PEERPIDFD`、受信安装文件 inode 和进程存活检查确定身份，helper 再核对 owner/relay UID。broker 只接受安装的 helper 服务进程，不接受客户端声明的 PID、路径或角色。远程认证要求内核支持 `SO_PEERPIDFD`，不支持时失败关闭；Mac 的 audit token 和 Windows 的管道身份规则保留。实测边界见 [认证与网络隔离报告](remote-approval-reports/linux-auth-relay-isolation.md)。

### 2.2 推荐的服务器账户布局

- agent 以普通用户 `u` 运行，不给 `u` 免密 sudo；`keyvalet` 与 `keyvalet-relay` 是无登录系统用户。
- vault 所有者（`keyvalet` 配置里的 owner）= `u`。现有实现「只有 root 配置的 owner 能拿凭证会话」不变。
- 若用户还想在服务器上本地审批，SSH 登录 `u` 后 `keyvalet approve <pid>` 仍然可用，作为 relay 不可达时的后备。

### 2.3 三平台矩阵

Ubuntu + MacBook 只是第一个 dogfooding 实例。协议里没有「Linux 是执行端、Mac 是审批端」这种假设——每台设备注册时声明能力 `caps ⊆ {execute, approve_quick, approve_strong, sync}`，同一台机器可以同时是执行端和审批端（例如用户的 MacBook 既跑 Claude Code 又批服务器的请求）。

| | macOS | Linux | Windows 11 | iOS / Android（手机 App） |
| --- | --- | --- | --- | --- |
| 执行端（vault + 注入） | V1。`dev.keyvalet.helper`（root）+ `dev.keyvalet.agent`；SE 主密钥（现有） | V1。`keyvalet` 系统用户 + systemd；TPM 2.0 或显式软件（现有） | V1。`KeyValetHelper` 服务（LocalSystem）+ 受保护的 `kv-agent.exe`；Hello 主密钥（现有开发预览）。无人值守（RDP 断开、无登录会话）时与 Linux 服务器同样走远程审批 | 不做 |
| 审批端 | V1。Touch ID；Quick/Strong 两把 SE 键 | V2。桌面 polkit `auth_self` 作在场门，TPM/软件键签名；状态永远标 `presence: polkit`（非硬件在场） | V1。Hello `KeyCredentialManager` RSA-2048 作 Strong 键（每次签名要求在场）；PCP TPM P-256 作 Quick，独立 ECDH／ECDSA 双键组成逻辑身份 DK | **V1**。iOS：SE 三把键（§3.1）；Android：Keystore（StrongBox 优先）三把键，`AK_s` 生物绑定；锁屏 Quick / 生物识别 Strong；唯一的图形设置面 |
| `kv-relay-client` | per-user LaunchAgent `dev.keyvalet.relay`，helper 以 audit token + code requirement 校验 | systemd `keyvalet-relay.service`，专用系统用户；root `keyvalet-peer.service` 用 `SO_PEERPIDFD` 固定进程并核对执行文件，要求 Linux 6.5+ | Windows 服务 `KeyValetRelay`，虚拟服务账户 `NT SERVICE\KeyValetRelay`，经 `\\.\pipe\keyvalet-relay` 连 helper，管道 DACL 只给该 SID + SYSTEM，helper 用 `GetNamedPipeClientProcessId` 校验 | 内置于 `kv-mobile-core`（前台 WS）；后台靠 APNs / FCM 唤醒后拉取 |
| 本地审批后备 | Touch ID 对话框 | SSH `keyvalet approve <pid>` | 登录会话内 Hello；无会话则无后备（只能远程） | 不适用（手机不是执行端） |
| 安装器 | `install.sh` | `install.sh` | `install.ps1` 旧包原生安装／升级／卸载通过；当前无签名发行接线已实现，新整包回归中；Authenticode可选 | Android Debug APK 真机通过核心流程；Play 签名发行和 iOS TestFlight／真机验收待资源；公开上架计划中 |

---

## 3. 密钥与身份

### 3.1 设备密钥

每台设备至少两类密钥对象。HPKE 固定为 `DHKEM(P-256, HKDF-SHA256) + HKDF-SHA256 + AES-128-GCM`（与总架构 §8.1 一致，适配 SE/TPM/PCP 的 ECDH 能力）；**签名算法不写死**，由设备记录里的 `alg` 决定：`ES256`（P-256）或 `RS256`（RSA-2048，Windows Hello 唯一支持的形态）。身份密钥必须是 P-256（HPKE 需要），审批密钥可以是任一种。

| 密钥 | Linux（TPM 2.0） | Linux（显式软件） | macOS（Secure Enclave） | Windows 11 | iOS / Android（手机 App） | 用途 | 用户在场 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 身份密钥 `DK`（P-256） | 新建 TPM ECC 对象，`sign`+`decrypt`，`fixedTPM`/`fixedParent`，与现有 vault 主密钥是**不同对象** | `0600` 文件，状态报 `software_key` | 新建 SE `P256`，`kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`，无生物 ACL | 两把 PCP TPM P-256：ECDH 专用键 `dk_pub` + ECDSA 身份键 `dk_sig`；任一键失败报错，无自动软件回退 | iOS：SE `P256`，`AfterFirstUnlockThisDeviceOnly`；Android：Keystore EC P-256，StrongBox 优先、回退 TEE 并上报 `key_kind` | relay 会话认证；信封签名；HPKE 接收 | 否（无人值守） |
| 审批密钥 Quick `AK_q` | （V2 审批端）TPM P-256，在场 = polkit | — | SE `P256`，`WhenUnlockedThisDeviceOnly`，无生物 ACL | PCP TPM P-256（与 `DK` 不同对象），在场 = 已登录桌面会话里的点击 | iOS：SE `P256`，`WhenUnlockedThisDeviceOnly`，无生物 ACL（锁屏动作 `authenticationRequired` 保证已解锁）；Android：Keystore P-256，`setUnlockedDeviceRequired(true)` | 签 T0/T1 的「点一下允许」 | 屏幕解锁即可 |
| 审批密钥 Strong `AK_s` | （V2）同上，状态标 `presence: polkit` | — | SE `P256`，`userPresence` ACL | Hello `KeyCredentialManager` RSA-2048（`RS256`），每次 `RequestSignAsync` 都要 PIN / 指纹 / 人脸 | iOS：SE `P256`，`.biometryCurrentSet`；Android：Keystore P-256，`setUserAuthenticationRequired(true)` + `setUserAuthenticationParameters(0, AUTH_BIOMETRIC_STRONG)` + `setInvalidatedByBiometricEnrollment(true)`，签名经 `BiometricPrompt.CryptoObject` | 签 T2、unlock、admin、Directive | 每次 Touch ID / Hello / Face ID / 指纹 / polkit |

说明：

- 任何设备的 `DK` 只用于签 **请求** 和认证自己，永远签不出 **批准**。执行端验证批准时只接受已配对审批设备的 `AK_q`/`AK_s`，并按该键记录的 `alg` 验签。
- Mac 身份密钥用 `AfterFirstUnlock` 是为了锁屏时 relay 重连还能完成挑战签名；审批密钥用 `WhenUnlocked`，锁屏期间自然批不了。Windows 等价：`DK`/`AK_q` 由服务里的 PCP 使用，`AK_s` 只能在用户交互会话里由 `kv-agent.exe` 调 Hello。
- TPM / PCP 无用户在场机制：执行端 root / SYSTEM 可以静默用 `DK` 发请求——这只是「能发请求」，不是「能批准」，威胁模型不变。
- Mac 的 SE 操作与现有一样经 `dev.keyvalet.helper → dev.keyvalet.agent → kv-touchid`。W1 spike 的实测范围见下表；生产使用 SE ECDH 的 32 字节共享点，由 W0 的 Rust 实现完成 HKDF/AEAD。
- Linux TPM 侧：`tpm2_create` 带 `sign|decrypt` 的非受限 ECC 密钥，ECDSA 用 `tpm2_sign`，ECDH 用 `tpm2_ecdhzgen`，均通过现有的受信 `tpm2-tools` 路径与 `/dev/tpmrm0`；blob 放进 vault 的 AEAD 认证元数据，与现有主密钥 blob 同样处理。
- Windows 侧：逻辑 DK 由两把独立持久 PCP TPM P-256 对象组成：ECDH 键用于 HPKE，`dk_pub` 是其公钥；ECDSA 键用于所有设备身份签名，公钥以 `dk_sig: {pub, alg: "ES256"}` 发布。已验证的 Windows 11 PCP 不允许同一把 P-256 键兼作 ECDH/ECDSA：设置 `NCRYPT_KEY_USAGE_PROPERTY` 返回 `0x80090029`，generic usage 同样失败；K1 因此采用两个独立硬件对象。PCP 的 ECDH／签名走 `NCryptSecretAgreement`／`NCryptSignHash`；`BCRYPT_KDF_RAW_SECRET` 得到的 32 字节共享点进入既有 RFC 9180 流程。旧设备无 `dk_sig` 时仍用 `dk_pub` 验身份签名；存在但无效的 `dk_sig` 拒绝，不回退。Quick 是另一把 PCP ECDSA 对象；Hello Strong 仍为独立 RS256。双键原生创建／重开／清理及 HPKE、Quick 互操作已经通过；物理 x64 Hello 初始化／解锁、Strong、真正重复签名和独立取消已通过。VM 仍等待 PIN，生产 bound relay／真实客户端闭环待验，见 [R3-B](remote-approval-reports/R3-B-security-closure.md) 与 [无签名修复验收](remote-approval-reports/R3-B-unsigned-acceptance.md)。
- protection/status --summary 单独列出 pcp_ecdh／pcp_ecdsa 的 present、absent 或 unknown；只有双键实际存在才报告 remote_identity.ready。R2-B 在创建及清理前后分别核对两项，不把半套或错误状态标为硬件可用。
- 底层 `DeviceKeyProvider` 位于 `kv-ipc::remote`，core 提供 typed adapter，platform 实现硬件 provider。`public_jwk()` 返回 HPKE 的 `dk_pub`，`identity_sign_jwk()` 默认 `None`，Windows DK 返回 ECDSA 身份公钥；`ecdh()`／`sign()` 各用专用 PCP 句柄。审批仍按 AK 的 alg 选 ES256／RS256。

**硬件事实表（W1 与后续验收，不代表完整产品链路通过）**：

| 项目 | 实测环境与结果 | 尚未验证 |
| --- | --- | --- |
| SE HPKE / 双用途 | Apple Silicon、macOS 26.5.1、Swift 6.2.3 / SDK 26.2；`hpke_recipient=pass`、`raw_ecdh=pass length=32`、`same_key_es256=pass signature_length=64`；DK/Quick 与 W0 HPKE 和签名互操作通过 | 后续独立 Strong userPresence 签名 1 项通过、3.66 s；macOS 14、锁屏 ACL、重复／取消与已安装两端链路仍未验 |
| PCP RAW_SECRET / 双键 | Windows 11 VM、LocalSystem、模拟 TPM 2.0；双 PCP 键创建／持久化重开、身份 ES256、32 字节 raw ECDH、HPKE + Quick 互操作和清理通过。使用显式 split identity 契约，不声称同一 PCP 键双用途 | 物理 TPM、Hello Strong 交互、完整远程审批 |
| macOS 在场初始值 | 实测 console/input/display 可取，screensaver 初值未知；代码保守返回 Away | 完整锁屏/屏保/显示器转换及启动可用性 |

证据与命令：[W1](remote-approval-reports/W1.md)、[后续硬件验收](remote-approval-reports/v1-completion.md)、[R2-B](remote-approval-reports/R2-B-windows.md)。SE 加密表示只绑定设备；PCP 不提供用户在场审批门。硬件失败不自动切换软件键。

### 3.2 密钥材料存放

| 内容 | Linux | macOS | Windows | 手机 |
| --- | --- | --- | --- | --- |
| 自己的 DK | TPM blob 或显式软件文件，保存于 vault AEAD 元数据 | SE opaque representation 与 provider metadata，独立加密 remote metadata | PCP metadata v2 同时 pin ECDH／ECDSA 句柄名与公钥；SYSTEM/Administrators DACL，vault AEAD 认证 | iOS DK 放 App Group，AfterFirstUnlockThisDeviceOnly；Android Keystore 别名 |
| AK_q / AK_s | 远程审批者为 V2 | 各自 SE 表示与 ACL，Strong 为 userPresence | Quick 为第三把 PCP ECDSA；Strong 为 owner Hello RSA-2048／RS256 | iOS 批准键留主 App Keychain，NSE 只读公钥缓存；Android Keystore |
| 对端 DeviceRecord | 加密目录与 SQLite 完整 record_json | 同左，root-only | 同左，受保护 DACL | 硬件派生 AEAD 的 SQLite，App Group／应用私有目录 |
| relay 会话 | 设备 session token 仅在 relay-client | 同左 | 同左 | 人类会话加密保存，设备会话内存；登录到期／退出后拒绝私有操作 |

目录修改由已认证 owner 控制面负责，使用加密 prepare 日志与 SQLite directory_commits 标记恢复一致提交，保留 tombstone。Windows 半套 DK 创建失败会清理已创建的那把；删除尝试两把并使用 `NCryptDeleteKey(handle, 0)`。旧的不成功 PCP v1 metadata 不静默迁移。显式 DPAPI 软件 provider 单独标为 software，不是 PCP 创建失败的回退。跨库一致性不提供硬件反回滚（§11）。

### 3.3 账户模型（K2/K3）

- 桌面／执行端的第一台设备创建**匿名账户**（`account_id` 随机），之后通过配对加入同一账户。设备会话以 DK 证明持有者，Google／Apple 登录不能代替 DK、Quick 或 Strong。
- 手机产品必须先用 Google／Apple 登录，并固定连接 `https://relay.keyvalet.dev/`。DK 对一次性 attempt、state、设备 ID 和精确 ID token 的 SHA-256 签名绑定，relay 用官方 JWKS 验证 ID token；用户以 `provider + subject` 标识，不按邮箱合并。人类会话与设备会话分别保存 token hash，双方 SAS 确认完成后才建立账户归属。桌面自托管保持独立支持，手机不自动迁入自建 relay。具体扩展见 [账户登录契约](../mobile/docs/account-login.md)。
- relay 只认「同账户设备之间」的消息。
- 账户恢复码：首次注册时显示账户 ID 与恢复码，须一起离线保存。全部设备会话丢失时用 `POST /v1/recovery` 和新 DK 签名证明恢复；原子撤销旧注册／会话、取消请求并轮换恢复码。`keyvalet relay recover <account-id>` 从隐藏输入或 stdin 读取旧码，helper 先持久保存新 DK 与加密的新码，再经 relay-client 发送；中断后凭同一 DK 续接。此接口恢复 relay 账户，不恢复 vault、硬件私钥或丢失机器上的离线授权。见 [恢复与审计](remote-recovery-audit.zh-CN.md)。
- Team（阶段 2）在同一模型上加「组织」维度，不在本文范围。

### 3.4 轮换与吊销

- owner 吊销设备生成 AK_s 的 Strong `DeviceDeleteProof`；helper 先撤销本机权威、保存 tombstone 与逐 peer 密文，再投递 DeviceRevoke 及 relay DELETE。relay 注销会话并断开 WS；peer 收到有效证明后废止该设备尚未消费的批准与 Grant。网络失败保留待办，状态显示 `device_revocations_pending`，需要新 relay challenge 时由 owner 重试。已安装两端「一分钟内失效」尚未测；离线设备不能保证即时清除。
- 若已启用 V2 的 vault 同步，吊销后还要按总架构 §8.2 旋转 UMK；第一版不同步，所以不涉及。
- 轮换身份密钥 = 吊销旧设备 + 重新配对，不做原地轮换。
- 全部设备会话丢失时，`POST /v1/recovery` 不需要旧 Device 会话，要求离线保存的账户 ID／恢复码和新 DK 身份签名（按 `dk_sig` 选择）。新码在发送前保存；同事务比较旧 hash、撤销旧设备与设备／人类会话、清 push token、取消审批／配对、删旧消息、注册新设备并轮换码。失败原子保留旧状态，并发恢复仅一个成功。它只恢复 relay 账户，不恢复 vault、旧私钥或丢失设备上的离线 Grant；手机仍须 Google／Apple 登录。

---

## 4. 配对协议

配对在不信任 relay 的前提下建立双方公钥与能力的信任。HTTP 返回只是候选记录，SAS 与已签名 E2E 确认都完成后才写入目录。

```text
执行端 owner                      relay                     审批端 owner
pair --new                                                   pair <kv-pair://…> / 手机扫码
helper 创建／重开 DK                                         helper／手机原生读取 DK、AK_q、AK_s
首次匿名注册 → account_id、一次性恢复码                       手机先 Google／Apple 登录
生成 raw token 16 字节，冻结最多 600 s 的 exp
POST pair/start {token_hash, initiator: DeviceRecord, exp}
显示 URI 与 Unicode QR                                       helper 解析 URI，POST pair/complete
                                                             {token, joiner: DeviceRecord}
                         候选记录、pairing_id、account_id、expires_at
两端 DK 身份签名与 HPKE 交换 PairAccept；各自计算 SAS
终端核对六位码 y/N                                           核对 SAS，AK_s 签 PairConfirm 的 JCS
双方交换原始 PairConfirm 信封，核对 pairing_id／完整记录／期限
本端 owner 确认 + 对端有效确认 → 原子提交信任目录
POST pair/finish {pairing_id, confirm}，双方 finish 后 relay 标 finished
```

- token 为一次性随机 128 bit，URI 使用 base32；relay 仅存 hash 与重放墓碑。期限从首次创建计算，Strong 提示或重试不延长它。URI／二维码与恢复码不写日志；恢复码只向 owner 显示，并提示连同账户 ID 离线保存。
- 初次注册先保存加密身份，注册失败重用原密钥。已注册单例加入须以自己的 DK 会话证明同一设备，且不能已有信任／墓碑／审批／授权状态；迁移有加密恢复日志。安装器不编造 account/device ID。
- PairConfirm 的最小签名载荷是 **JCS `{sas}`**，不是六位 ASCII 数字。现代 owner／手机确认还包含 `device: DeviceRecord`、`exclude_global`；签名覆盖整个确认对象去掉顶层 `sig` 后的 JCS，包含未知字段。缩成 `{sas}` 验证现代确认会丢失密钥／能力／排除标志的绑定，必须拒绝。Strong 一方使用 AK_s 及其 alg；纯执行端以 owner 终端确认并发送 DK 认证的空 AK 签名确认。双方都无 AK_s 时拒绝。
- 旧 SAS 输入为 `ASCII("keyvalet-pair-v1") || raw_token_16 || sorted_JCS(DK_1, DK_2) || JCS(approver.ak_q.pub 或 null) || JCS(approver.ak_s.pub)`。任一记录有 `dk_sig` 时使用 `keyvalet-pair-v1-split-identity` 新域，双方身份改为 JCS `{dk_pub, dk_sig}`，缺失 dk_sig 在该输入中编码 null；按 JCS 字节排序并保留嵌套扩展。SHA256 按无符号大端整数转十进制、至少左补到六位，取前六位。加入方有 AK_s 时选加入方，否则选发起方。旧记录和向量的字节保持。
- 两个审批端也交换 AK_s 签名的完整本端 DeviceRecord，核对全部身份／审批键、算法、能力与扩展，不能仅凭单组 AK 的 SAS 信任对端。全部 DK 身份验证采用 §3.1 的 dk_sig 规则，HPKE 仍用 dk_pub。
- 配对信封 id 为 pairing_id；收到旧轮确认返回 wrong_pairing，不能清空新一轮。移动端与 helper 重发同一签名／密文，不重签不同字段、不延长期限。finish 的同成员／同 SAS 有效重试幂等，伪签名或换 SAS 仍拒绝。
- 新执行端展示将生效的未过期全局 T1 Grant 数量。任一端选择排除即签入 `exclude_global: true`，双方保存排除状态，阻止旧票补发及未来全局票投递；逐设备票不受影响。全局 T2 不属于该继承机制。
- 不一致、过期或验证失败不能建立信任。真实模块的双端确认与重试已通过；ndu × Mac 安装后的 Strong 配对仍未完成，Pixel 7 × 软件 fixture 配对已通过，不能相互代替（§16）。

---

## 5. 信封与密码学

所有经 relay 的消息都是同一种信封：

```json
{
  "v": 1,
  "type": "approval_request | approval_escalate | approval_decision | approval_cancel | grant | directive | directive_result | presence_hint | device_revoke | pair_*",
  "id": "01J…",                 // ULID，消息 id；approval_* 系列与 approval_id 相同
  "account": "acct_…",
  "from": "dev_…",
  "to": "dev_…",
  "created_at": 1760200000,
  "exp": 1760200300,
  "enc": "<HPKE 封装密钥 base64>",
  "ct": "<HPKE 密文 base64>",
  "sig": "<ES256(from 的身份签名键, AAD || decoded_ct)>"
}
```

- AAD 为信封去掉 enc、ct、sig 后完整头对象的 JCS，包括未知扩展及已签名 push.mode；基础字段为 v/type/id/account/from/to/created_at/exp。签名覆盖 AAD 拼接解码后的 ct，不能用字段字符串串接代替。
- `sig` 由发送方**身份密钥** `DK` 签（身份密钥恒为 P-256，所以信封签名恒为 ES256），覆盖头部和密文。relay 与接收端均调用 `verify_identity_signature(DeviceRecord, …)`：合法 dk_sig 存在时只用其 pub，缺失时用 dk_pub；坏 dk_sig 失败，不回退、不跳过。relay 还检查 from/to 同账户。信封**内部**的对象（ApprovalDecision、Grant、Directive）另有自己的签名，按签名密钥记录的 `alg` 验证（§3.1）。
- 一次 HPKE 一个信封，不复用上下文；明文最大 64 KiB（审批请求的 body 摘要已截断，足够）。
- 接收端用自己的时钟检查 `exp`；若 `created_at` 与本地时钟偏差 > 60 s，仍处理但在 UI 和审计里标注「发送方时钟偏差」。relay 的时间戳不用于安全判断。
- 多审批设备：发送方对每个 approver 各封一个信封（fan-out 在 helper 内完成，密文不同、`id` 相同）。

---

## 6. 审批流程

### 6.1 三类审批

| 类别 | 触发 | 最低档位 | 产生什么 |
| --- | --- | --- | --- |
| `unlock` | 服务器 helper 为某个客户端进程开凭证会话（Linux 现有「每个新连接需要独立解锁授权」） | Strong | 一个会话，寿命 `session.unlock_ttl`（默认 12 h，上限 24 h；到期后下一次请求再触发 unlock） |
| `use` | 某条凭证的某次具体使用，按风险档 T0–T3 与授权模式 | T0：auto / 预授权；T1：Quick 或预授权；T2：Strong；普通 Grant 不覆盖，只有显式设置签发的 T2 Grant 才可覆盖（§7.6；所有 T2 须逐执行端签入当前标签）；T3：直接拒绝 | 一次性批准（`per_use`）或 grant（其他模式，见 §6.6） |
| `admin` | 新增/删除凭证、放宽授权模式、增删设备、签发能力令牌、修改策略 | Strong | 一次性批准 |

`unlock` 是无人值守场景里最容易被忽略的一环：没有它，服务器上的 helper 根本开不了会话。它把「这台机器上的用户 `u` 的进程 X 想开始使用 vault」告诉用户，批一次管 12 小时。

### 6.2 请求规范化与 digest

沿用总架构 §7.2，并加入远程字段：

```
canonical = JCS({
  v: 1, kind: "unlock" | "use" | "admin",
  requester: device_id,                       // 新增：哪台机器
  credential, action.kind, method, host(lowercase), path(normalized), query_keys(sorted),
  body_sha256, headers_digest, agent: { runtime, repo_or_cwd, uid, pid, exe_sha256 },
  purpose, nonce, exp
})
digest = SHA-256(canonical)
```

`action` 的实际形状是 `{kind, ...扩展}`，credential 和无 HTTP 绑定字段使用显式 null；agent 为实际执行绑定，不能从展示用 ApprovalRequest 重建。host 仅 ASCII、小写；query_keys 按 UTF-16 顺序排序且保留重复；path 解码 unreserved 后移除点段，保留重复斜杠／保留字符分隔符，不做 Unicode 归一化。重复 JSON key、无效 Unicode、非有限数与超出 ±(2^53−1) 的整数拒绝。

DeviceRecord 的完整 JCS 保留可选字段缺失与 null 的区别。dk_sig 缺失不序列化；合法值及嵌套未知字段进入所有覆盖记录的签名、摘要和 authority 比较。显式 null 虽可无损解析，但注册／身份验证拒绝；不能删除未知字段或无效 dk_sig 后再用旧 DK 验签。K1 没有改变 RFC 9180 suite、原 ECDH 字节或旧向量。

### 6.3 `ApprovalRequest`（信封明文）

以下为协议展示形状；风险来自执行端策略，UI 不决定级别。当前生产适配器保守地把 GET／HEAD／TOTP 作为 T1，其余 use 为 T2、管理 T3 拒绝，不能用示例中的 POST/T1 组合推断所有实际 POST 都可 Quick。

审批端要渲染、但不需要任何秘密：

```json
{
  "approval_id": "01J…",
  "kind": "use",
  "digest": "…",
  "nonce": "…",
  "exp": 1760200300,
  "requester": { "device_id": "dev_…", "label": "srv", "os": "linux", "protection": "tpm2 | software_key" },
  "agent": { "runtime": "claude-code", "cwd": "/home/u/proj", "user": "u", "pid": 48213 },
  "credential": { "ref": "github/default", "kind": "oauth2", "display": "GitHub (guang)", "proxy_only": true },
  "operation": {
    "summary": "POST repos/guang/demo/issues · title=\"Fix…\" · 1.2 KB",   // 模板 summarize 规则产出
    "method": "POST", "host": "api.github.com", "path": "/repos/guang/demo/issues",
    "query_keys": [], "body_bytes": 1228
  },
  "purpose": "创建 issue 记录测试失败",                                    // agent 自述，UI 必须标注为自述
  "tier": "T1",
  "min_level": "quick",                                                   // 执行端策略算出的最低档
  "scope_options": ["per_use", "per_credential", "per_session", "remember:1h", "remember:8h", "remember:24h",
                    "standing:credential", "standing:device"],       // 执行端按策略给出；T2 请求只给 per_use
  "requested_scope": "per_credential",
  "merged_count": 1                                                       // 30 s 内合并的同凭证请求数
}
```

不进入请求的：任何头部明文、body 原文、凭证值、vault 路径。`summary` 由模板的 `summarize` 规则在执行端生成，没有规则就显示 method/host/path/大小。

### 6.4 `ApprovalDecision`（信封明文）

```json
{
  "approval_id": "01J…",
  "digest": "…",
  "nonce": "…",
  "decision": "allow | deny",
  "level": "quick | strong",
  "scope": { "mode": "per_credential", "until": 1760243200 },
  "approver": "dev_mac…",
  "issued_at": 1760200012,
  "sig": "<ES256(AK_q 或 AK_s, JCS(上面除 sig 外全部字段))>"
}
```

`level=strong` 必须由 `AK_s` 签；`quick` 由 `AK_q` 签。执行端据 `level` 选对应公钥验签，签错键即拒绝。

### 6.5 执行端验证清单（顺序固定，任一失败即拒绝并审计原因）

1. 信封：`to` 是自己、`from` 是已配对且未吊销的审批设备、`exp` 未过、`sig` 用该记录的身份键（dk_sig 存在时只用它，否则 dk_pub）验证通过、HPKE 解封成功。
2. `approval_id` 在 `pending_approvals` 中且状态为 `waiting`。
3. `digest` 与 pending 记录一致；`nonce` 一致。
4. `level` ≥ 该请求的 `min_level`；T2 必须 `strong`。
5. 用 `level` 对应的审批公钥验 `sig`。
6. `nonce` 表 `INSERT OR FAIL`（防同一批准被用两次）。
7. `decision=allow` → 按 `scope` 产生 grant（§6.6）→ 执行；`deny` → 向 agent 返回结构化拒绝，关闭 pending。
8. 两端审计。

### 6.6 授权范围与 grant（沿用总架构 §7.6）

远程批准的 scope.mode 映射到现有授权模式，per_use 不产生 Grant；其他选项产生最多 T1 的 helper 内部授权，保留原 ApprovalDecision 的签名与完整请求证明，authority 为 approval_decision，不伪造新的 AK Grant 签名，不能拿它跨设备安装。普通票不覆盖 T2；显式设置签发的 T2 票受 §7.6 约束。审批端只能选 scope_options 提供的范围，不能放大。

### 6.7 时序

**正常路径（MacBook 在线）**

```
agent ─credential_http_request─▶ kv-mcp ─IPC─▶ helper
  helper：Identity → Policy（T1，需 Quick）→ 无 grant/令牌覆盖 → 选 Approver
  Approver 选择：无本机 polkit agent → 有在线 approver → remote-device
  helper：生成 nonce、digest、ApprovalRequest；写 pending(waiting)；对每个 approver 封信封 → relay-client
relay-client ─WS─▶ relay：POST /v1/approvals（密文、to、exp）
relay ─WS 推送─▶ Mac relay-client ─IPC─▶ Mac helper：验签、解封 → agent/kv-touchid：弹对话框
用户：看请求 → 「允许（本会话）」→ Quick：直接签；Strong：Touch ID 后签
Mac helper：封 ApprovalDecision → relay-client → relay：POST /v1/approvals/{id}/reply
relay ─WS─▶ Ubuntu relay-client ─IPC─▶ helper：§6.5 清单 → 执行注入 → 响应脱敏 → kv-mcp → agent
helper：审计 {approval_id, approver, level, latency_ms}
```

**MacBook 离线 / 睡眠**

- relay 把请求留在队列（TTL = 请求 `exp`）。Mac 醒来后 relay-client 重连，拉取全部待处理，按时间顺序弹窗；已过期的直接丢弃并提示「有 N 条已过期」。
- agent 那一侧的等待、放手、续等与唤醒见 §6.9——那是本设计里和各家 agent 运行时耦合最深的部分，单独成节。
- `exp` 默认 10 分钟；策略可按 `class: batch` 把特定凭证/主机的请求 `exp` 延长到最多 24 h（例如夜间批处理）。

**超时与放弃**

- `exp` 过后 helper 把 pending 标为 `expired`，并向 relay 发 `approval_cancel`，Mac 端已弹出的对话框自动关闭；agent 若再问，得到 `approval_expired`。
- 用户在 Mac 上点「拒绝」→ agent 立即收到 `approval_denied`，附用户可选填的一句原因。`denied` 是唯一表示「用户说了不」的状态；超时永远不映射成 `denied`（§6.9.1）。

**并发合并**

- 当前只合并同一 session／完整执行绑定相同的重试；method、URL、headers、body、凭证或进程绑定改变即成为独立审批。不同操作的一次批量批准需要新的签名批承诺，K4/D06 已划入 V2，不能用 merged_count 的 UI 字段宣称已授权多种操作。

### 6.8 Approver 选择顺序（修订总架构 §7.4）

```
if 策略判定 auto（T0 且规则允许）                          → auto（审计 auto）
elif 有效 Grant 覆盖（普通票 ≤T1；显式 T2 票受 §7.6 约束） → capability（审计 jti）
elif 本机有可用的本地审批通道（Mac Touch ID / Linux polkit agent 已为该客户端注册）
     且 config.approval.prefer != "remote"                 → 本地
elif 有已配对 approver（在线优先；离线也发，排队）           → remote-device
     · fan-out 到全部 approver；按 §6.10 的在场判定决定每个 approver 是横幅还是静默，静默 30 s 未决升级为横幅
else                                                        → no_approver（不冒充用户拒绝，不做 TTY 确认码）
```

Strong 只接受 Mac Touch ID（本地）或 remote `AK_s`；Linux 本地 polkit 对 `use` 的 T2 视为 Strong（现有行为），对 `unlock`/`admin` 同样。

### 6.9 agent 侧的等待、放手、续等与唤醒

这一节回答：审批没在一分钟内来，agent 的那次调用怎么办；审批后来到了，正在跑的 session 怎么知道。设计目标是**在每一种运行时上都有一条能走通的路**，而不是依赖某一家的私有能力。

#### 6.9.1 状态语义：超时不是「否」

| 状态 | 含义 | 终态？ | agent 该做什么 |
| --- | --- | --- | --- |
| `approval_pending` | 请求已送出，用户还没决定，`exp` 未到 | 否 | 继续别的工作；有空就 `credential_wait_approval`；或等唤醒 |
| `approval_denied` | 用户点了拒绝 | 是 | 不要重试、不要绕路（例如让用户直接粘 key）；把原因告诉用户 |
| `approval_expired` | `exp` 已过且没有决定 | 是（对这次请求） | 仍需要结果时可新建审批；非必要不自动重发 |
| `approval_cancelled` | 明确本地取消，此次请求已结束且未获授权 | 是 | 先确认是否需要新请求；不当作拒绝，不索要 key |
| `no_approver` | 没有任何可用审批通道 | 是 | 告诉用户配置设备或 SSH 本地审批 |

超时只产生 `approval_pending`。把超时当成「否」会让模型把它理解成权限问题去绕，这正是我们要避免的行为。这些状态作为**正常工具结果**（`isError: false`，`status` 字段）返回，不作为协议错误——协议错误会让一些运行时直接把工具标红并终止思考。

#### 6.9.2 四层机制

```
调用内等待（按运行时预算，期间每 15 s 发一次 progress）
   │ 预算内批了 → 直接返回真实结果，模型无感
   ▼ 预算用尽
返回 approval_pending{approval_id, expires_at, wait_tool, next_steps}
   │
   ├─ 续等：模型调用 credential_wait_approval(approval_id, max_wait_s)
   │        批了 → 直接返回原请求的执行结果（不是「去重试」）
   ├─ 唤醒：Claude Code channels（有则用）；其他运行时无推送
   └─ 兜底：kv-hook Stop 模式——session 想结束但仍有未到期 pending 时，
            阻止一次并指示它调用续等工具（每个 approval 最多阻止 3 次）
HTTP 路径（网关 / 透明代理 / keyvalet run）：挂连接到按目标主机估算的客户端超时之前
```

**第一层：调用内等待。** 预算取 `min(policy.wait_in_call_s, runtime_budget − 10 s)`，默认 `wait_in_call_s = 60`。runtime_budget 根据实际 clientInfo.name/version 查表（§6.9.3），叠加显式 override 与已确认的 KEYVALET_TOOL_TIMEOUT_SEC 上限。安装器配置不会自动出现在 initialize，不能仅凭写入配置就提高未测客户端预算。等待期间，如果客户端在请求 `_meta` 里给了 `progressToken`，每 15 s 发一次 `notifications/progress`（`message: "waiting for approval on MacBook (42 s)"`），本轮没有证明它重置任何运行时计时器；无 token 时不伪造进度，仍受绝对预算约束。helper 侧 `pending_approvals` 把完整请求（参数与 body，仅内存、上限 1 MiB、到 `exp` 清除）留着，预算内批准就地执行并返回真实结果。

**第二层：放手。** 预算用尽返回：

```json
{ "status": "approval_pending", "approval_id": "01J…", "expires_at": 1760200900,
  "approver": { "label": "MacBook", "online": false },
  "wait_tool": "credential_wait_approval",
  "next_steps": "你可以先做不需要这条凭证的事。需要结果时调用 credential_wait_approval(approval_id)，批准后它直接返回本次请求的结果。不要重复发起同一请求，不要向用户索要密钥。" }
```

`next_steps` 是写给模型的 UI，与现有工具描述同一口径。

**第三层：续等工具。** `credential_wait_approval(approval_id, max_wait_s?)`：长轮询 pending 状态，`max_wait_s` 同样被运行时预算封顶，期间发 progress。正常结果为 ok（原结果、只领取一次）、approval_denied、approval_cancelled、approval_expired 或 still_pending；已领取返回 already_consumed。helper 重启导致内存里的请求丢失时，返回 `approved_retry_required`，此时模型用相同参数 + `approval_id` 重发原调用，helper 比对除 `nonce/exp` 外的全部规范化字段（含 `body_sha256`）一致才执行。

**第四层 a：唤醒（Claude Code channels）。** `kv-mcp` 声明 `capabilities.experimental["claude/channel"]`；批准到达时发 `notifications/claude/channel`，`content` 为「approval 01J… for GitHub POST repos/… granted; call credential_wait_approval("01J…") to get the result」，`meta.approval_id`。服务端能力声明和发送已有 CI；空闲唤醒、busy 合并及未启用时丢弃三项在 R2-D 均未测，是待验收的客户端行为。约束：research preview；自定义服务器要 `claude --dangerously-load-development-channels server:keyvalet` 或组织 allowlist；官方契约描述未启用时静默丢弃，R2-D 尚无有效交互会话复验——所以它只是加速器，任何正确性都不建立在它之上。安装器不替用户加这个标志，只在文档里给出。

**第四层 b：Stop hook 兜底。** `kv-hook` 新增 `stop` 模式（Claude Code `Stop`、Devin `Stop`、Codex `Stop`、Cursor `stop`、Gemini `AfterAgent`）。流程：hook 从 stdin 拿到 `session_id`，用自己的父进程 pid（= agent 进程）向 helper 查「这个 agent pid 有没有未到期、未被领取的 pending」；有，且该 approval 被此 hook 阻止的次数 < 3，且 `stop_hook_active`/`loop_count` 未触顶，则返回「别停，去 `credential_wait_approval(01J…)`」（Claude/Devin/Codex：`{"decision":"block","reason":…}`；Cursor：`{"followup_message":…}`；Gemini：`{"decision":"deny","reason":…}`）；否则放行。阻止次数计在 pending 记录上，`exp` 过后一律放行。这一层的代价是每次阻止多一轮模型调用，等待本身在工具调用里阻塞、不耗 token。

**HTTP 路径。** 网关与透明代理没有「返回 pending 再续等」的余地——SDK 等的是 HTTP 响应。做法：挂连接到 `min(policy.http_wait_s, host_hint − 60 s)`，`host_hint` 来自模板（OpenAI / Anthropic SDK 默认 600 s → 挂 540 s；未知主机默认 55 s）；期间每 20 s 发送一个 TCP keepalive，不发应用层字节（HTTP/1.1 不能在状态行前发心跳；`102 Processing` 兼容性差，不用）。超出后返回 `429` + `Retry-After: 30` + JSON `{error: {type: "keyvalet_approval_pending", approval_id}}` + 响应头 `X-KeyValet-Approval: pending; id=01J…`。OpenAI/Anthropic SDK 对 429 会按 `Retry-After` 自动重试（默认最多 2 次），默认重试次数有限，不能承诺任意等待都能续上；同一活 session 的恢复边界见下文。`keyvalet run` 包裹的子进程走同一代理，但 wrapper 额外在子进程的 stderr 打一行「KeyValet: waiting for approval on MacBook」。

本地结果细化：拒绝为 `approval_denied`，明确取消为 `approval_cancelled`；旧 IPC `approval_expired + reason=cancelled` 做明确兼容适配，不猜英文错误。对话框等待超时而 exp 未到仍为 pending；到期才为 expired。HTTP 拒绝／取消／到期分别 403／409／410，并带 `x-should-retry: false`；等待预算用尽仍为 429＋Retry-After。

连接断开后，独立任务继续等同一许可。批准后只执行原始二进制 body；仅相同活会话的 route token、epoch、凭证、method、URL、过滤后 headers、body 可领取保留响应。`X-KeyValet-Approval-Id` 及 SDK retry-count 不进入上游或 digest；不带 ID 的同一活绑定重试也可合并。每条请求 ≤1 MiB，最多 16 个 ticket，detached response ≤8 MiB；超限／中断返回 response_unavailable，不再次执行。响应在 exp／gateway revoke／shutdown 清除；gateway 重启或原始流交付后断流不保证恢复，单次许可不等于外部 HTTP exactly-once。实测见 R2-D。

#### 6.9.3 运行时预算与能力表（2026-10-13 回填 R2-D，须随版本复核）

| 运行时 | 工具调用超时（默认） | progress 续命 | 安装器写入 | 唤醒 | Stop 兜底 | 调用内预算 |
| --- | --- | --- | --- | --- | --- | --- |
| Claude Code CLI（stdio） | 文档约 28 h / 空闲 30 min；W5 合成本地模型两组 240 s 是历史证据。R2-D 托管 OAuth 过期、日常第三方 provider 未回复，未进入工具 | W5 有 token／标准进度；真实托管续命语义未测 | `.mcp.json` / `~/.claude.json` KeyValet `timeout: 900000` | 声明／发送有 CI；idle 唤醒、busy 合并、无 flag 静默丢弃均未测；须交互会话 | W5 block 后续调工具，active 防循环 | 180 s |
| Claude Code Desktop | 历史 60 s bug；本轮未安装、未测 | 未测 | 写入与实际效果分开，未复验 | 未测 | 未测 | 50 s |
| Codex | R2-D 托管 exec 240.015 / 240.006 s、TUI 240.007 / 240.012 s；是实测下界，不是精确上界 | 四组均有 token；有进度组完成，不推断续命语义 | `tool_timeout_sec` 生效：5 s 配置在 5 s 超时，900 s 允许 240 s 完成 | 无 | exec 捕获九字段并在 block 后续等；最终结果受模型 stream 错误／监督结束影响 | `codex-mcp-client / 0.162.1` 默认 180 s；未测 name/version 50 s；显式确认硬限 ≥190 s 可用 180 s，更小确认／override 优先 |
| Gemini CLI | 600 s 为契约／源码值；R2-D 登录中止，未进入工具 | progressReporter 未实测 | 每服务器 `timeout: 900000` | 无 | `AfterAgent` 输入／行为未实测 | 180 s |
| Cursor IDE | 文档描述空闲型超时；本轮未安装、未测 | 续命未测 | 无已确认额外字段 | 无 V1 channels | stop followup schema 有 CI，live 未测 | 明确 IDE 标识 120 s |
| Cursor CLI / ACP | W5 2026.10.01 两组约 60 s cancellation；R2-D usage limit，未进入工具，不计为工具时限 | W5 未提供 token，未推断续命 | 无接口 | 无 | stop 有 CI，实际输入仍未测 | 50 s |
| Grok Build | 文档 6000 s；R2-D native 1.0.50 仍 NotSignedIn，未进入工具 | 未测 | `tool_timeout_sec = 900` 的实际效果未测 | 无 | 未确认，不注册未验证变体 | 180 s |
| Devin CLI | R2-D 托管模型、有效隔离两组 240.006 / 240.007 s，精确上界未测 | token=1，标准通知 16 / 0 | 未确认额外字段 | 无 | R2-D 五字段；block 后 wait 得原结果、active 放行 | 默认 50 s；实际 clientInfo 通用 `rmcp / 3.1.0`，不全局提额 |
| OpenClaw / Hermes / SDK（HTTP） | Python OpenAI 3.29.0 / Anthropic 1.13.0 实测 read timeout=600、max_retries=2；实际 gateway HTTP/1.1、h2-only、wildcard 边界与终态已验证 | 不适用 | 不适用 | 不适用 | 不适用 | 挂连接 55–540 s |
| 未知 MCP 客户端 | 上限未测，使用保守预算 | 有 token 才发，不推断续命 | — | — | — | 50 s |

未测 clientInfo.name/version 按保守预算处理；实测 profile、显式 override 和较小确认上限的优先级以代码为准。四分钟完成只证明 ≥240 s，不证明精确上界或 progress 续命；R2-D 的实验显式用 300 s 预算，不是产品默认。

W5 的联网 Claude OAuth、Gemini 浏览器登录、Grok NotSignedIn 均在工具前失败，不计为工具超时；Claude Desktop 和 Cursor IDE 未测。原始版本、字段名与三分钟批准结果见 [W5 报告](remote-approval-reports/W5.md)。安装器写入只针对 KeyValet 条目，不代表客户端必然接受该字段，也不自动替代 MCP 端保守预算。

R2-D 的真实托管、超时配置与登录限制见 [运行时报告](remote-approval-reports/R2-D-runtimes.md)。Codex exec 与 TUI 是同一运行时的两种模式，不计作两家来满足 §16 的「Claude + 另外两家」。channels 三项仍须可用的已登录交互会话；不以 `-p` 或软件通知测试代替。

#### 6.9.4 session 与 approval 的关联

- 一个 `kv-mcp` 连接 = 一个 agent session。`kv-mcp` 在 `initialize` 记录 `clientInfo`，并把自己的父进程 pid 作为 `agent.pid` 写进每个 ApprovalRequest（§6.3 已有）。
- hook 进程的父进程也是同一个 agent 进程，所以 Stop hook 用 `getppid()` 就能找到属于自己 session 的 pending，无需运行时之间不兼容的 `session_id`。
- 同一 agent 进程多个并发 pending：Stop hook 的提示列出全部 `approval_id`；`credential_wait_approval` 一次等一个。
- session 已经不在（进程退出）：pending 照常到 `exp`；批准后 helper 记 `approved_unused`。把它接到 `claude -p --resume` / `codex exec resume` 之类的无头续跑不在 V1 内，只在 Mac 端提供 `keyvalet approvals --on-approve <cmd>` 让用户自己接。

#### 6.9.5 默认值

```toml
[approval]
wait_in_call_s = 60        # 调用内等待上限（再被运行时预算封顶）
wait_tool_max_s = 600      # credential_wait_approval 单次上限（同样被封顶）
default_exp_s = 600        # 请求有效期
http_wait_s = 540          # HTTP 路径挂连接上限（再被 host_hint 封顶）
stop_hook_max_blocks = 3   # 每个 approval 最多被 Stop hook 阻止几次
progress_interval_s = 15
```

### 6.10 在场判定与投递升级：怎么知道「人在不在电脑前」

目的只有一个：**人在桌前时先弹桌面框、手机别响；人不在时手机马上响。** 判错的代价不对称——误判「在」会让请求在没人看的屏幕上干等，误判「不在」只是手机多响一次。所以规则是：拿不准就当不在。

#### 6.10.1 三个状态与信号来源

每台**带 GUI 的设备**（执行端或审批端都可能）由本机的用户态 agent（`dev.keyvalet.agent` / `kv-agent.exe` / Linux 桌面 agent）持续计算一个粗粒度状态：

```
present  = 有本用户的图形会话 ∧ 会话处于前台/活动 ∧ 屏幕未锁、屏保未启动
           ∧ 距最近一次键鼠输入 < idle_threshold（默认 120 s）
           ∧ （有物理显示器 ∨ 远程桌面会话活跃）
           ∧ 本机审批通道可用（Touch ID / Hello / polkit agent）
idle     = 上面全部成立，但距最近输入 ≥ idle_threshold
away     = 其余一切：无图形会话、锁屏、屏保、显示器休眠、RDP 断开、快速用户切换到别人、信号拿不到
```

| 信号 | macOS | Windows | Linux |
| --- | --- | --- | --- |
| 本用户的图形会话存在且在前台 | `SCDynamicStoreCopyConsoleUser` 的 console user == vault owner；`dev.keyvalet.agent` 在该会话内运行 | `WTSGetActiveConsoleSessionId` / `WTSEnumerateSessions`：owner 的会话 `WTSActive`；RDP 会话 `WTSActive` 也算 | `org.freedesktop.login1`：owner 的会话 `Type ∈ {x11, wayland}` 且 `Active=yes`、`State=active` |
| 屏幕锁定 / 屏保 | `CGSessionCopyCurrentDictionary()[CGSSessionScreenIsLocked]`；分布式通知 `com.apple.screenIsLocked` / `screenIsUnlocked` / `com.apple.screensaver.didstart` | `WTSRegisterSessionNotification` 收 `WTS_SESSION_LOCK` / `UNLOCK`；`WTS_SESSION_REMOTE_CONTROL` | logind 的 `LockedHint`（GNOME/KDE 设置；拿不到当 `unknown`→away）；`org.freedesktop.ScreenSaver.GetActive` 作补充 |
| 最近输入 | `CGEventSourceSecondsSinceLastEventType(kCGEventSourceStateCombinedSessionState, kCGAnyInputEventType)` | 会话内 agent 调 `GetLastInputInfo`（服务进程不能直接调） | logind `IdleHint` / `IdleSinceHint`；X11 用 XScreenSaver 扩展，Wayland 依赖合成器的 idle-notify 协议，缺失则 `unknown` |
| 显示器 | `CGGetActiveDisplayList` 数量 > 0 且 `CGDisplayIsAsleep == false`；无头 Mac mini 接假 HDMI 头会显示 1 个，交给 idle 判 | `EnumDisplayDevices` 有活动显示器 ∨ RDP 会话 | DRM 连接器状态（`/sys/class/drm/*/status == connected`）∨ 远程桌面会话 |
| 本机审批通道 | `kv-touchid` 可达 | `kv-agent.exe` 在该会话且 Hello 可用 | 该会话注册了 polkit agent |

实现为 `kv-platform::PresenceProbe` trait（`fn state(&self) -> PresenceState { Present | Idle | Away, since, signals }`），每个平台一个实现；任何信号取不到 → 该项按最保守值处理。agent 在状态变化时（去抖 5 s）经 IPC 告诉本机 helper，helper 缓存；没有 agent 的机器（无头服务器、Windows 服务无登录会话）恒为 `away`。

#### 6.10.2 实际投递路由

人在场判定由执行端完成，桌面通过签名、加密的 PresenceHint 更新执行端缓存；状态变化经五秒去抖立即发送，未变化每 60 秒刷新。缺失信号为 away，WS 在线不等于人在场。Linux 精确可配置 idle 来源与 macOS 启动屏保初值仍需补验。

| 本机／桌面状态或消息 | 执行端签名的 push.mode | relay 调度（手机 WS 在线／离线均相同） |
| --- | --- | --- |
| 本机或桌面 approver present | silent | Silent |
| idle／away／unknown | banner | Banner |
| notify always-phone | banner | Banner |
| 旧审批没有 hint | 无 | 保守 Banner |
| 30 秒仍未决的 approval_escalate | banner | 同 approval_id 的 Banner |
| cancel、Grant、Directive/Result、DeviceRevoke | silent 或无 | Silent 控制更新 |

PresenceHint 正文是 E2E 密文；relay 只读取已签名 Envelope 扩展 push.mode。该扩展只给提供商选择唤醒方式，不参与最低审批级别或授权判断。手机解密后的 Rust 请求决定正文、强度和可用动作。本地「我不在电脑前」只把 verified silent 提示成 banner，不发送伪造在场信息。

kv-server 在信封提交事务中登记 push_jobs；kv-push 为独立 systemd 服务 keyvalet-push.service，专用无登录用户，仅监听 127.0.0.1:8788。relay 通过 bearer 调私有 POST /v1/push，nginx 不代理该入口，公网返回 404。内部请求仅为 `{device_push_token, approval_id, to, delivery:{mode}}`，拒绝正文、密文及未知字段。FCM 为 data-only 三字段元数据；APNs 仅通用唤醒，NSE 验证／解密后填实际通知内容。

#### 6.10.3 投递升级、重试与 token 生命周期

执行端在静默请求 30 秒仍未决时发送同 ID 的签名 approval_escalate，决定收到后退休旧唤醒并发送签名取消；relay 不解密或自行提升审批强度。push job 初次发送加三次重试，退避 1/2/4 s，每次 lease 读取最新 token；HTTP 28 s、lease 30 s，job 最迟于 120 s 或信封 exp 结束。429 Retry-After 有界且超过 job 生命周期就放弃唤醒；推送失败不回滚审批，前台 WS／上线拉取继续可用。

手机登录后、冷启动和 SDK token 轮换都登记当前 token，上传摘要绑定人类会话。退出先清本地登录／通知，远端清理请求保留加密 outbox；在线退出、会话到期／吊销／最后人类会话删除清 relay token 与 job。APNs 410／FCM UNREGISTERED 比较发送时旧 token 后删除，不能删并发轮换的新 token；权限／配置错误保留 token。迟到上传响应不能复活已退出会话。

Android 后台由 FCM → JobScheduler → Rust 先拉 HTTPS 待批，20 s 预算后返回已验证缓存并要求重试，不启动 Dart isolate。Silent／Banner 使用独立渠道，同 tag/id 的升级取消旧渠道再投递；相同计划去重。Quick 仅对 per_use Quick 开放允许／拒绝，动作要求系统解锁，FGS 用 AK_q 签；Strong 通知仅打开主 App，由实际 BiometricPrompt CryptoObject 使用 AK_s。

iOS NSE 已实现 App Group／原生 Rust 解密与 passive/timeSensitive 通知，Quick 要求 authenticationRequired，Strong 进 App；只有编译／模拟器证据，SE、锁屏／APNs、Apple 登录未验。Pixel 7 真实核心流程通过；升级请求到横幅约 35 s、静默到升级 28.620 s，≤30 s 端到端目标未过。重启后新审批拉取及退出后的 relay 删除未通过，手机 relay HTTPS 访问仍需恢复；一小时离线尚未测。详见 R2-C，不能用 FCM 202 代替这些验收。

#### 6.10.4 用户可覆盖

| 设置 | 作用 | 存放 |
| --- | --- | --- |
| `keyvalet remote <device> notify prefer-local \| always-phone \| both` | 该执行端的默认投递策略；`always-phone` 让手机永远横幅 | 执行端 `settings`，Directive |
| `presence.idle_threshold_s`（默认 120） | 多久没碰键鼠算「不在」 | 本机配置 |
| `presence.escalate_after_s`（默认 30） | 静默多久升级横幅 | 执行端配置 |
| 手机 App「我不在电脑前」开关 | 手机侧强制把 silent 当 banner 处理，不发任何东西给执行端 | 手机本地 |
| 勿扰时段 | 手机侧按系统 Focus；执行端侧 `class: batch` 让请求等更久而不是半夜响 | 各自本地 |

#### 6.10.5 策略场景（完整 OS 转换仍待实机验收）

| 场景 | 判定 | 结果 |
| --- | --- | --- |
| 坐在 MacBook 前跑 Claude Code（本机即执行端） | 本机 present | Touch ID 框；手机静默，30 s 没批才响 |
| 坐在 MacBook 前 SSH 到服务器跑 agent | 执行端 away；MacBook 审批端 present | MacBook 弹远程审批框；手机静默，30 s 后响 |
| 合盖出门，服务器夜里有请求 | 执行端 away；MacBook away | 手机立即横幅 |
| 无头 Mac mini + 假 HDMI 头 + 自动登录 | 有会话、未锁，但 idle 数小时 → idle | 手机立即横幅；Mac mini 屏幕上也留着框 |
| 盯着一个 3 分钟的构建没碰键盘 | idle | 手机横幅 + 本机框同时在；先批哪个都行 |
| Windows 台式机 RDP 已断开 | `WTSDisconnected` → away | 手机横幅 |
| 快速用户切换到家人账号 | console user ≠ owner → away | 手机横幅；家人屏幕上不弹 |
| Linux 桌面，DE 不报 `LockedHint` | unknown → away | 手机横幅 + 本机 polkit 框 |

#### 6.10.6 隐私与安全边界

- 在场状态是元数据。它只以 E2E 形式发给同账户设备，relay 不知道明文状态，但可持久保存该密文消息；签名头的 push.mode 是可见投递元数据。粒度只有三档，不含应用名、窗口标题或输入内容。
- 在场状态**只影响投递方式，不影响授权**：present 不会让任何审批变成自动，away 不会降低任何档位。被注入的 agent 伪造不了它（由 agent 进程之外的用户态 KeyValet agent 计算，经 helper 下发）。
- macOS 的 `CGEventSource` 空闲时间不需要辅助功能权限；`CGSessionCopyCurrentDictionary` 不需要特殊权限。Windows `GetLastInputInfo` 必须在会话内进程调用，这正是 `kv-agent.exe` 所在的位置。Linux 的 Wayland 空闲信号因合成器而异，拿不到就按 away——这是三平台里最不可靠的一项，V1 接受。

---

## 7. 授权对象、预授权与远程设置

§7.1–7.3 是总架构 §7.5 能力令牌的落地（从审批端签发、在执行端验证与计费）；§7.4 把它与弹窗范围、常设允许统一成一个 Grant 对象；§7.5–7.6 是审批端作为远程控制面的设计与安全栏。

### 7.1 签发（Mac）

```sh
keyvalet grant --to srv \
  --credential github/default \
  --hosts api.github.com --methods GET,POST --paths '/repos/guang/**' \
  --budget 500/24h --until 2026-10-18T00:00+08:00 \
  --agent 'claude-code:/home/u/proj'          # 可选，限制 agent 身份
```

- Touch ID 一次，用 `AK_s` 签一张 §7.4 形状的 Grant（`level=credential` + 收窄 + `budget` + `exp`；语义对应总架构 §7.5 的 `authorization_details`）。
- 令牌经 relay 以 `grant` 信封送到服务器；服务器 helper 验签（必须 `AK_s`，`alg` 按设备记录）、检查 `aud` 是自己或 `*`、写入 `grants` 表（§7.4）。
- 令牌本身不含秘密，泄露也只说明「某范围被允许」；`keyvalet grant` 命令行签出的范围永远 ≤ T1，T2 只能走 §7.6 的设置页路径。

### 7.2 使用（Ubuntu）

- Policy 阶段匹配 `credential × host × method × path × agent`，命中则 debit 预算（`calls`、可选 `bytes`），执行，审计 `jti`。预算用完 → 回到正常审批。
- owner grant revoke 通过已签名 revoke_grant Directive 逐执行端撤销，并保存已认证回执／revocation_pending；没有 token_revoke 协议类型。remote grant revoke/revoke-all 为 Quick，owner 本地路径仍要求相应认证。
- `keyvalet grant list` 两端都能看：剩余预算、到期时间、最近使用。

### 7.3 默认与 V2 推荐

普通票最多 T1；host/method/path/agent 与预算可收窄，未查询到的剩余预算显示未知。根据多次批准自动推荐「24 小时只读」尚未实现，属于 V2，不作为当前弹窗选项或验收通过项。

### 7.4 统一的授权对象：Grant

弹窗里选的范围（§6.6）、上面的能力令牌（§7.1）、以及用户要的「这个凭证一直允许」「这台机器一直允许」「全局不用再管」，共用同一范围／预算／吊销模型。独立签发的 Grant 由 AK 签名；弹窗决定衍生的内部授权保存原 ApprovalDecision 证明，不伪造可传输的 Grant 签名（§6.6）。独立 Grant 形状如下：

```json
{
  "kind": "grant",
  "jti": "01J…",
  "iss": "dev_mac…",                       // 签发设备
  "iss_alg": "ES256",                      // 由设备记录决定，Windows Hello 为 RS256
  "aud": "dev_srv… | *",                   // 目标执行端；* = 账户内全部执行端
  "scope": {
    "level": "credential | device | global",
    "credential": "github/default",        // level=credential 时必填
    "hosts": ["api.github.com"],           // 可选收窄，缺省 = 凭证模板的 allowed_hosts
    "methods": ["GET","POST"],             // 可选收窄
    "paths": ["/repos/guang/**"],          // 可选收窄
    "agent": "claude-code:/home/u/proj",   // 可选收窄
    "max_tier": "T1"                       // T0 | T1 | T2（T2 只有 §7.6 的红色模式才允许）
  },
  "budget": { "calls": 500, "per": "24h" },  // 可选
  "nbf": 1760200000,
  "exp": 1760203600,                       // null = 常设（standing），直到吊销
  "origin": "approval:01J… | settings | recommendation",
  "sig": "…"                               // 覆盖除 sig 外全部字段的 JCS
}
```

映射关系：

| 用户看到的选项 | 生成的 Grant | 档位 |
| --- | --- | --- |
| 这一次 | 不生成（一次性批准） | 按请求 |
| 这个凭据本会话 / 本会话全部 | `level=credential` / `device`，`exp = 会话结束`（执行端把会话 id 记在 `origin`） | Quick |
| 记住 1 小时 / 8 小时 / 24 小时 | `level=credential`，`exp = now + N h` | Quick |
| 这个凭证一直允许 | `level=credential`，`exp = null`，`max_tier = T1` | **Strong** |
| 这台机器一直允许 | `level=device`，`exp = null`，`max_tier = T1` | **Strong** |
| 全局一直允许（所有机器） | `aud = *`，`level=global`，`exp = null`，`max_tier = T1` | **Strong** |
| 设置签发的短期票，包括 1 小时票 | origin=settings，明确到期及范围 | **Strong**（K4/D03） |
| 无人值守模式（含敏感操作） | 逐执行端 max_tier=T2；不允许全局 T2 | **Strong + 两个一次性准备令牌 + 两轮精确标签确认**（桌面 helper/CLI，§7.6） |
| 预授权能力令牌（`keyvalet grant …`） | `level=credential` + 收窄 + `budget` + `exp` | Strong |

执行端的覆盖判定沿用总架构 §7.6：`同凭证（或 level 更宽）∧ tier ≤ max_tier ∧ host/method/path/agent 命中 ∧ 预算未超 ∧ 未过期 ∧ 未吊销 → 跳过审批，审计 jti`。多张 Grant 同时命中取**最窄的 max_tier 不放大、预算各自扣减**。T2 请求只有 `max_tier = T2` 的 Grant 能覆盖，且每次仍重算 digest 并审计 `unattended_t2`。

执行端保存 grants/object_json/authority_json；审批端持久保存 issued_grants 和完整 issued_grant_objects，列表区分 installed／issued／approval_decision 来源。预算／uses_n／last_used_at 是经过签名 QueryGrants 回执获得的逐执行端快照，带 fetched_at；未查到显示 not_fetched，不假报零使用量。

审批端撤销持久保存意图和目标列表，逐执行端发送签名 Directive；仅对应设备的已认证回执确认完成。离线、取消或未获回执时保留 revocation_pending；重试继续未完成目标，过期 Directive 需 owner 重签，不在后台绕过硬件授权。全局 T1 向未来经 SAS 信任、未排除的执行端补发；已撤销或待撤销的票不补发。Grant 列表按 jti 游标、每页 1–100（默认 50）和 48 KiB 分页，CLI 自动取完，手机以 QueryGrants 续页；列表元数据不能当新票安装。

### 7.5 远程设置：Directive（控制面）

审批端对执行端的一切设置变更，都是一个签名的 **Directive**，经 relay 的 `directive` 信封下发，执行端执行后以 `directive_result` 回报。执行端只认签名与范围，不认「从哪台设备的哪个界面来」，当前 CLI／手机共用该控制面；菜单栏、Web 和团队审批者为 V2。未知 service/org issuer 或 quorum 不能授权。CLI 的 * 展开为当前执行端的独立 Directive，V1 不提供单个全局 Directive 的广播回执对象。

```json
{
  "kind": "directive",
  "id": "01J…",
  "iss": "dev_mac…", "iss_alg": "ES256",
  "aud": "dev_srv…",
  "op": "set_mode | revoke_grant | revoke_all_grants | lock | set_unlock_ttl | set_class | set_device_label |
         revoke_device | query_status | query_pending | query_grants | query_audit | cancel_approval | notify",
  "args": { … },
  "nonce": "…", "exp": 1760200300,
  "sig": "…"
}
```

档位规则（与 README「放宽永远要指纹」一致）：

| 方向 | 例子 | 最低档 |
| --- | --- | --- |
| 收紧 | `lock`、`revoke_grant`、`revoke_all_grants`、`cancel_approval`、`set_mode` 变严、`set_unlock_ttl` 变短 | Quick（甚至锁屏通知上的一个按钮） |
| 查询 | `query_*` | Quick；结果经信封回传，只含元数据与摘要，不含凭证值 |
| 放宽／目录变更 | set_mode 变松、set_unlock_ttl 变长、新建或扩大 class、set_device_label、设置签发 Grant（短期也包括） | Strong |
| 危险 | `revoke_device`、`max_tier = T2` 的 Grant | Strong + §7.6 二次确认 |

执行端对每条 Directive：验签（按 `iss` 的 `AK_q`/`AK_s`，`alg` 来自设备记录）→ 档位够 → `nonce` 一次性 → `exp` 未过 → 执行 → 审计 `directive_applied{op, iss}` → 回 `directive_result{id, ok, state_summary}`。失败也回报，附原因。

set_mode 取值为 per_use／per_credential／per_session／remember:<h>。本地 /keyvalet:mode 经特权 remote_settings 与远程 SetMode 共用 helper 设置后端和 CAS；过时本地提案拒绝覆盖远程更新，成功变更均审计。该操作不向 MCP／relay-client 开放新的设置能力。notify 只影响投递，仍为 Quick，不改变审批最低级别。

### 7.6 审批边界的安全栏

K4 已决定以下边界，不因 UI 或联调需要降低档位：

1. 普通 Grant 最多 T1，T2 弹窗只允许 per_use。所有设置／预授权签发均为 Strong，包括有限期 1 小时票；弹窗衍生的有限 T1 会话／remember 范围可按原请求使用 Quick。
2. 显式 T2 只能从设置意图签发。桌面 helper 先用 AK_s 完成独立准备签名，再返回最多 120 s 的一次性令牌；只保存 hash，绑定 caller UID/PID/role、完整意图和当前 DeviceRecord，准备不产生 Grant。R3-A 按用户确认将桌面 helper 的有限与常设 T2 均改为两个不同令牌、两次精确标签确认；两轮共用原期限，最终失败也消费令牌。CLI 要求 2→1，拒绝旧的一轮准备、令牌重复或截止时间变化；手机实现由 R3-C 单独核对，不从桌面结果推断。UI 布尔同意不能代替签名。
3. 有限期与常设 T2 的签名 Grant 都必须包含 confirm=当前执行端标签（K4/D04）。共享接收验证、安装与使用前重验均执行该条件；missing/null/empty/wrong-label／签后篡改拒绝。启动升级把旧的缺当前标签 T2 票标失效并审计，防止重装；有效 T1／T2 保留。见 [R3-B 无签名验收 §2](remote-approval-reports/R3-B-unsigned-acceptance.md#2-安全修复)。
4. 全局 T2 拒绝（K4/D05）。CLI 通配符 unattended 只对当前执行端逐个确认、逐张签发，不覆盖未来设备；发行端与共享接收验证器均拒绝 global 或 aud=* 的 T2。有限／常设负向向量与 Mac／Windows 原生 CI 已通过。
5. 全局 T1 可覆盖未来经 SAS 信任的执行端；配对展示数量并允许签名排除，待撤销／已撤销票不能补发。scope_options、caps、模板主机和策略限制不能被放大。
6. T2 模式在状态／审批标题中显示无人值守，并对每次覆盖单独审计 unattended_t2。CLI unattended 必须指定 --until；手机／原生签发逻辑提供常设两次确认，不把它写成 CLI 已支持 --standing。
7. 远程 revoke_grant／revoke_all_grants 为 Quick，执行端回执才表示生效；本机 owner grant revoke 的控制路径仍走 owner 认证。立即锁定／收紧不能授权新操作，离线目标保留 revocation_pending。

不同操作批量授权、服务／组织 issuer、quorum 与 attestation 验证为 V2。验收通过只指相应对象与平台，不能由软件覆盖率或单次 FCM 唤起推导整个安全栏已通过。

---

## 8. relay 服务

### 8.1 技术选型

Rust axum + tokio、单二进制 kv-server，relay feature 默认开启。当前自托管与官方实例均用 SQLite WAL、单实例进程内连接队列；Postgres／LISTEN-NOTIFY／多实例扩展为 V2。TLS 链路为 Cloudflare 橙色云 → nginx Origin CA → 127.0.0.1:8787；服务不监听公网。

### 8.2 API

附录 B 按 http.rs 当前路由列出完整方法、认证、请求和响应，不把匿名设备会话当人类登录。

- 桌面注册为 POST /v1/devices，返回匿名账户及一次性恢复码；手机使用 /v1/account/begin → finish，以 provider ID token 和 DK 身份签名绑定登录。已登录手机再经双方 SAS 加入执行端账户。
- POST /v1/auth/challenge → verify：随机 32 字节、60 s、单次 challenge；身份验签使用 dk_sig（存在）或 dk_pub（缺失），换取 24 h Device 会话及 account_id。手机另带 x-keyvalet-user-session，退出／到期／吊销后 HTTP/WS 拒绝旧 Device token。
- 配对 start／complete／finish 与恢复 /v1/recovery 的语义见 §3.4、§4；恢复不要求旧 Device 会话，不给手机免登录。
- /v1/approvals 提交逐接收方信封，reply 首个有效外层回复使 relay resolved；relay 不知道 allow/deny，真正执行仍依赖 helper 的 AK／digest／nonce 验证。cancel 保留原签名信封。
- /v1/messages 与 ack 传递非审批密文及 typed 回执；/v1/presence 是 kv-relay-v1 WS，不是人类在场证明。手机 push-token 更新／删除要求本人有效设备会话，手机还须活跃人类会话。
- /v1/health 为公开诊断；/metrics 在当前 router 要求 Device 会话，未实现单独的 socket-loopback 检查。部署监听 loopback 不等于经 nginx 的访问也被限制到 loopback；该边界需落实，见 OPEN-QUESTIONS S03。

### 8.3 数据模型（SQLite）

当前 server schema v3 的 14 张表及键／外键见附录 D。完整 DeviceRecord（含 dk_sig 与未知字段）在 devices.record 中保存，dk_pub 索引仍是 HPKE 公钥；不凭拆开的 SQL 列重建签名记录。accounts 只保存 recovery_hash，设备／人类会话各保存 token_hash；login_users 以 provider/subject 唯一，不按 email 合并。

pairings 保存固定原始期限、双方确认状态和 SAS hash；used_pair_tokens 是 hash-only 重放墓碑。approvals 的 waiting/resolved/cancelled/expired 为路由状态；messages 以 `(account_id,id,to_device,type)` 标识完整原始信封，按 type ack 防止同 ID request/escalate/cancel 相互提前确认。完全相同重试幂等，不同密文冲突，ack 不重置。

push_jobs 与 messages 外键及提交同事务，唤醒失败不撤销已接受信封。已 ack 消息七天后清理；审批相关记录到 exp 后七天清理；未 ack 的普通消息持久保留，过期后不投递。每设备每分钟 60 次 approvals／600 条 messages，账户待处理最多 500，单信封 80 KiB、HTTP/WS 输入 1 MiB。plan 当前默认 self_hosted，尚无计费／套餐配额执行。

### 8.4 relay 看得到 / 看不到

| 看得到 | 看不到 |
| --- | --- |
| 账户内有哪些设备、公钥、在线状态、上次心跳 | 任何凭证值、UMK、CEK |
| 谁向谁发了多少条、什么时候、多大、`type` | 请求里的凭证名、主机、路径、agent、purpose、决策内容（全部在 `ct` 内） |
| 配对发生过、设备被吊销过 | 哪条 `approval_id` 批了还是拒了（`resolved` 不区分） |
| 手机 push token、已签名的静默／横幅投递提示；托管登录的 provider/subject/email/name | 设备私钥与审批正文 |

推送提示位于 Envelope 外层扩展 `push: {mode: silent|banner}`，纳入 AAD 与 DK 签名；helper 根据原始请求生成，relay 不解析 `ct`。旧请求缺提示时只做保守唤醒，手机仍依据解密并验签后的 delivery 决定呈现。升级必须 banner，取消和控制面更新 silent。relay 与 `kv-push` 仅用 loopback HTTP 和受限 bearer 传递 `{device_push_token, approval_id, to, delivery}`；不传信封、摘要或凭证信息。持久队列最多并发 8 个投递，初次加 3 次重试，限流遵循 Retry-After，任务 120 s 到期；失败不改变审批权限。失效 token 采用匹配旧值的删除，防止擦除新 token；退出、人类会话过期和吊销清除 token。

HTTP 认证／登录／恢复参数依赖 TLS。Cloudflare 终止 TLS，能接触这些临时凭据；端到端保密承诺覆盖审批与授权信封，不把账户认证参数称为端到端密文。

relay 被攻破的后果：丢消息、延迟、拒绝服务、观察元数据；不能伪造请求或批准（签名），不能重放（nonce + `exp`），不能解密。

### 8.5 部署

当前官方 relay 位于 simvito：**Cloudflare 橙色云 → nginx（Origin CA）→ kv-server 127.0.0.1:8787**；kv-push 是专用服务，127.0.0.1:8788，仅内部 bearer 调用。不用 Tailscale，不用 Caddy，不需要更改现有其他站点或 zone 全局 TLS 设置。

自托管 relay **只服务桌面审批端／CLI**，仍可匿名注册及恢复。手机产品固定官方 relay.keyvalet.dev，不能连接自建地址；App 无地址展示、编辑入口或导出的地址修改 API。不是安装自建 push 或同邮箱登录就能绕过该限制。

```sh
# CLI renders deployment assets; administrator activation is a separate step.
keyvalet relay install --listen 127.0.0.1:8787 --data /var/lib/keyvalet-relay-server --public-url https://relay.example.com
keyvalet relay set-url https://relay.example.com
keyvalet relay status --public-url https://relay.example.com
```

relay install 写出 unit／nginx 模板，不能代替创建专用用户、安装二进制、配置 Origin CA、启动 systemd 和 nginx。server 使用 keyvalet-relay-server.service 与 /var/lib/keyvalet-relay-server；执行端客户端使用 keyvalet-relay.service 与 /var/lib/keyvalet-relay，二者权限／目录不混用。参考实际 [nginx 模板](../deploy/relay/nginx.conf.template)、[push 私有入口](../deploy/relay/push-private.nginx.conf) 与 W9/R2-C 部署记录。

nginx 的源站限制检查实际 TCP 来源的 Cloudflare IP allowlist，避免共享 real-ip 改写或伪造 CF 头绕过。kv-server 仅对 socket peer 恰为 127.0.0.1 的请求采纳单个合法 CF-Connecting-IP；其他来源／重复或无效头回退到 socket IP。应用心跳 30 s、nginx 超时 90 s、server 无入站活动 100 s 断开，是已测试的应用／部署值，不将 100 s 写成 Cloudflare 平台承诺。

已实测公网 health 200、普通认证 WSS／HPKE／typed ack，直连 origin 加伪造 CF 头 403、公网 push 404、内部未认证 push 401、认证 FCM 202。R2-A 2026-10-13 的现行 server SHA256 为 1eced902770d81e9933c204c8830ca7d2c7565e3fc0105e93aeeb44c45f9eab0，保留 account.env、systemd 与 nginx 配置；Google 已配置，Apple 未配置。Origin CA 私钥留在服务器，不读／不导出。单项传输通过不代表硬件审批延迟通过。

托管计费、Free 3 台／每月 2,000 次等套餐额度仍是计划；当前官方实例没有这些配额执行。桌面同机自托管的可用性与执行端耦合，手机只走官方实例。

---

## 9. 客户端

### 9.1 `kv-relay-client`

- 新 crate `rust/crates/kv-relay-client`，同一二进制在三平台运行。
- Linux：systemd 单元 `keyvalet-relay.service`，`User=keyvalet-relay`，`ProtectSystem=strict`、`PrivateTmp`、`NoNewPrivileges`、`RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6`，无 `CAP_*`。配置文件 `/etc/keyvalet/relay-client.toml`（relay_url、device_id、account_id）。与 helper 通信走 `/var/run/keyvalet/relay.sock`，helper 经 root peer broker 的 SO_PEERCRED／SO_PEERPIDFD 与执行文件证明只接受真实专用 relay UID／角色，不能仅凭 UID 或自报路径。
- macOS：per-user LaunchAgent `dev.keyvalet.relay`，由 `dev.keyvalet.helper` 以 audit token + code requirement 校验（与 `dev.keyvalet.agent` 同机制），IPC 走 helper 的 socket 新增 `relay` 子协议。
- Windows：服务 `KeyValetRelay`，以虚拟服务账户 `NT SERVICE\KeyValetRelay` 运行（不是 LocalSystem），经 `\\.\pipe\keyvalet-relay` 连 `KeyValetHelper`；管道 DACL 只给该 SID 与 SYSTEM。helper 从 `GetNamedPipeClientProcessId` 获取真实 PID，核对进程令牌 SID、固定安装文件身份及受保护 owner／DACL；MCP 另核对服务创建的子进程与持有的进程句柄。Authenticode 是可选发行诊断，不能以模型提交的 PID／角色替代 OS 认证。配置在 `C:\ProgramData\KeyValet\relay-client.toml`；新无签名整包验收与历史收据分列于 [R3-B 续验](remote-approval-reports/R3-B-unsigned-acceptance.md)。
- 行为：指数退避重连（1 s → 60 s）；本地磁盘队列（待发信封，密文），防 relay 短暂不可达时丢请求；收到信封立即转交 helper，由 helper 决定是否 ack（验签失败也 ack，避免毒消息反复投递，但审计）。
- 不做任何策略判断，不存任何明文，不持任何私钥。

### 9.2 审批端 UI（macOS / Windows）

- **V1 桌面弹窗**：macOS 在 `kv-touchid` 内使用 SwiftUI/AppKit 专用审批窗口；Windows 由 `kv-agent.exe` 的短生命周期 UI 子进程使用 WinUI 3 原生控件。标题带来源：「srv 上的 claude-code 请求使用 GitHub (guang)」。正文按 §6.3 渲染：真实操作（summary）、主机/方法/路径、agent 自述 purpose（标注「agent 自述」）、风险档、执行端保护状态（`tpm2` / `software_key`，后者红色提示）、时钟偏差提示。按钮：允许（+ 范围下拉，选项来自 `scope_options`，§7.4 映射）/ 拒绝；Strong 时点允许触发 Touch ID / Hello；选到「一直允许」时按钮文案变为「一直允许（Touch ID）」。
- **V1 设置（终端）**：`keyvalet remote <device>` 子命令组（§9.3）覆盖 §7.5 全部 Directive；没有图形设置页也能完成所有远程设置。
- **V1 手机 App 是唯一的图形审批/控制面**（Flutter/Rust/native，见 §9.2.1；Android Debug 核心真机流程通过，iOS／TestFlight／Play 签名分发待验）：锁屏 Quick / 生物识别 Strong 审批、每台执行端一页设置（当前模式、常设 Grant 列表含剩余预算/到期/来源、无人值守红色状态与 `unattended_t2` 计数、`unlock_ttl`、batch 类、锁定、`revoke_all_grants` 大按钮）、扫码配对与吊销、最近活动摘要、推送（APNs 经 `kv-push`，Android 经 FCM data message）。桌面**不做**图形设置页——产品决策见产品文档 §6.2。
- **V2**：瘦菜单栏/托盘项（状态点、待批数、打开待批、一键全部收回；仅当 dogfooding 证明桌前需要）；Linux 桌面审批端；手机上走 OAuth 添加凭证。
- Web 控制台随 Team（总架构阶段 2），服务 Lead 角色；不做个人审批端（`webauthn` 位保留，§13.1）。
- 本机优先与手机静默/升级的判定见 §6.10；审批端睡眠：醒来后由 relay-client 拉取积压，一次最多排队弹 5 个，其余在列表里。

#### 9.2.1 手机 App 技术选型：Flutter + Rust 核心 + 原生薄层

决定：用 **Flutter** 做 UI，一套代码覆盖 iOS 与 Android；协议、密码学、状态机全部在 Rust（crate `kv-mobile-core`），经 `flutter_rust_bridge` 暴露给 Dart。这取代总架构 §3.1 里「iPhone App（Swift + UniFFI）」的写法，落地时回写。

Dart 侧**不碰任何私钥、不做任何验签、不解析任何信封**——它只渲染 Rust 给的结构体、把用户的点击交回 Rust。下面这些必须是原生代码（一个平台插件 `kv_native`，Swift / Kotlin 各一份）：

| 必须原生 | iOS | Android | 为什么 Flutter 插件不够 |
| --- | --- | --- | --- |
| 硬件密钥与生物绑定签名（`DK`、`AK_q`、`AK_s`） | `SecureEnclave.P256`；`AK_s` 带 `.biometryCurrentSet`，`AK_q` 带 `WhenUnlockedThisDeviceOnly`，`DK` 带 `AfterFirstUnlockThisDeviceOnly` | `KeyGenParameterSpec`：`setIsStrongBoxBacked(true)` 优先、回退 TEE 并上报；`AK_s` 用 `setUserAuthenticationRequired(true)` + `setUserAuthenticationParameters(0, AUTH_BIOMETRIC_STRONG)`，签名经 `BiometricPrompt.authenticate(CryptoObject(Signature))` | **生物识别必须门控密钥操作本身**。`local_auth` 一类插件只返回布尔值，被攻破的 App 进程可以跳过它直接签名；只有密钥级绑定才是 Strong |
| 推送与后台解密 | Notification Service Extension（Swift，独立 target，不能跑 Flutter 引擎）链接同一个 Rust 静态库（手写 C JSON ABI），从 App Group 共享容器读设备密钥的加密表示与密文队列，解密后改通知正文、`interruptionLevel`、`threadIdentifier`；锁屏动作 `UNNotificationAction(options: .authenticationRequired)` → 主 App 后台唤起 → Rust 用 `AK_q` 签 Quick 决定 | `FirebaseMessagingService`（Kotlin）收 data message → Rust 解密 → 按 `delivery.mode` 选通知渠道；动作按钮 → 前台服务签 Quick | iOS NSE 与 Android 消息服务都在 Flutter 引擎之外运行；后台路径全走原生 + Rust，不依赖 Dart 后台 isolate |
| 设备证明 | App Attest 原生适配器 | Play Integrity 原生适配器 | relay challenge／验证未接入，attestation 仍 unverified；K4/D09 为 V2 |
| 扫码 | Flutter 插件（`mobile_scanner`）即可 | 同左 | 不涉及安全 |

Rust 核心因此有两套绑定：Dart（`flutter_rust_bridge`，主 App）与 Swift／Kotlin（手写 C JSON ABI，NSE／后台）。状态（待批队列、peers、设备记录、本机签发记录）放 Rust 侧 SQLite，iOS 在 App Group 容器、Android 在应用私有目录；NSE 与主 App 对同一个 SQLite 用 WAL + 文件锁。

已知代价与对策：双绑定的维护成本（用同一份 Rust 公开类型，CI 同时生成两套并编译）；iOS NSE 的时间／内存预算（仅编译，真实解密性能尚未测）；Flutter 在 iOS 的后台执行不可靠（所以后台一律原生）；Flutter 包体与启动时间（可接受）。V2 的瘦菜单栏/托盘不复用 Flutter desktop，用各平台原生轻量实现，避免为一个状态点引入第二个 Flutter 工程。

**App 的页面清单（V1）**：登录后四页：① 待批（列表 + 详情，详情即 §6.3 的全部字段；详情页底部是范围选择与允许/拒绝）；② 设备（已配对执行端列表 → 每台一页：状态、模式、常设 Grant、无人值守开关、锁定、`revoke-all`、吊销、最近活动；加设备 = 扫码）；③ 活动（本机签发的批准/票/指令，按天分组，摘要级）；④ 设置（已验证账户／退出、通知偏好、「我不在电脑前」、语言／显示、无密钥诊断；不展示 relay 地址）。手机首次进入为 Google／Apple 登录页，设置页包含退出；固定官方 relay，无地址编辑入口。该后续产品要求与匿名桌面账户分开，见 §3.3 和手机账户契约。

**目录与构建**：`mobile/`（Flutter 工程，`pubspec.yaml`）、`mobile/ios/`（含 `KeyValetNSE` target）、`mobile/android/`、`rust/crates/kv-mobile-core/`（`crate-type = ["staticlib", "cdylib", "rlib"]`，`flutter_rust_bridge` 代码生成输出到 `mobile/lib/src/rust/`，同一生成器输出 C header 到 NSE／iOS 插件／Android JNI）。构建验收包含 aarch64-apple-ios、aarch64-apple-ios-sim、aarch64-linux-android；flutter analyze 与40项测试通过。它不等于已在普通macOS Rust CI执行NSE／真实硬件。

### 9.3 CLI

现有入口为 relay install/status/set-url/recover、pair --new/URI、devices list/revoke/rename、approvals/approve/deny、grant、remote、audit --remote 和 status --summary。完整实际 --help 语法见附录 E；不以规划中的 flag 补齐命令。

CLI 提交 owner intent，不持私钥或指定 issuer/nonce/alg。目标优先精确 device_id，再匹配唯一 active label；* 对 Directive 展开当前 execute 设备，对 T1 全局 Grant 保留未来设备语义。unattended 必须 --until，有限 T2 逐设备两轮标签确认；常设 T2 是 helper／手机签发逻辑，并非现有 CLI flag。pair 会显示双方 SAS、恢复码和全局授权排除选择；JSON 也不是二次确认旁路。

Linux 正整数 approve <pid> 仍保留本地 polkit 后备；远程 approval_id 用相应选项消歧。approvals --watch --on-approve 仅对本次观察到的明确 Allow 触发一次用户命令，参数不插进 shell 源码，历史重现不会重复执行。

### 9.4 MCP 与 agent 可见行为

- `credential_http_request` 等使用类工具：新增可选参数 `approval_id`（§6.9.2 `approved_retry_required` 时使用）；新增结构化结果状态 `approval_pending`、`approval_denied`、`approval_cancelled`、`approval_expired`、`no_approver`（§6.9.1，正常结果而非协议错误），文案是写给模型看的，明确告诉它该等待还是该放弃。
- 新工具 `credential_wait_approval(approval_id, max_wait_s?)`（§6.9.2 第三层）。工具描述里写清：批准后直接返回原请求结果；不要重复发起原请求。
- kv-mcp 在 initialize 读取实际 clientInfo.name/version 选运行时预算（§6.9.3），它不是调用方认证或授权来源；对带 `progressToken` 的请求按 `progress_interval_s` 发 `notifications/progress`；声明 `experimental["claude/channel"]` 能力并在批准时发 `notifications/claude/channel`（§6.9.2 第四层 a）。
- `credential_status`：增加 `remote_approval: { relay: connected|offline, approvers: [{label, online}], pending: [{approval_id, summary, expires_at}], grants: n, unattended: bool, runtime_budget_s: n }`。
- hooks：`kv-hook` 新增 `stop` 模式及各运行时变体（§6.9.2 第四层 b）；安装器为 Claude Code / Devin / Codex / Cursor / Gemini 注册对应 Stop 类事件。现有 PreToolUse / UserPromptSubmit 模式不变。
- 安装器只更新 KeyValet 自己的配置项。Codex 的 timeout=5/900 字段效果已实测，Claude/Gemini/Grok 尚未测；Devin 3000.3+ 的专用 mcp_config 路径及短超时同步 env 仍需维护者核对（OPEN-QUESTIONS T10），不能把配置写入当作生效证明。
- 明确本地取消映射 approval_cancelled；兼容旧 IPC approval_expired + reason=cancelled。对话框 timeout 在请求 exp 前仍为 pending。所有 A.8 状态为 isError=false；channels 只通知、不领取结果，三个 live 场景待测。
- HTTP 403/409/410 三终态均带 x-should-retry:false；429 才表示仍待批。同一活 gateway session 可按原绑定领取有限响应，缓存最多 16 tickets、每条响应 8 MiB，不能跨重启恢复或承诺外部 HTTP exactly-once（§6.9.2）。

### 9.5 配置（执行端 `/etc/keyvalet/helper.toml` 新段）

```toml
[approval]
prefer = "auto"            # auto | local | remote
wait_in_call_s = 60        # 调用内等待上限（再被运行时预算封顶，§6.9）
wait_tool_max_s = 600      # credential_wait_approval 单次上限
default_exp_s = 600        # 请求有效期
http_wait_s = 540          # HTTP 路径挂连接上限（再被模板 host_hint 封顶）
stop_hook_max_blocks = 3   # 每个 approval 最多被 Stop hook 阻止几次
progress_interval_s = 15
unlock_ttl_s = 43200       # 远程 unlock 的会话寿命

[[approval.class]]         # 可选：延长特定请求的有效期（夜间批处理）
name = "batch"
match = { credential = "openai/*", host = "api.openai.com" }
exp_s = 86400
```

---

## 10. 执行端与审批端的本地数据

桌面两种角色共用 helper 的 remote SQLite，而非另建 peers 表；完整 DDL 见附录 D。devices.record_json 保存完整公钥目录，镜像进 vault AEAD 元数据；dk_sig 不需要单独 SQL 列，不能省略它后重建签名对象。pending 保留规范化与公开请求快照，完整请求 body／结果仅在 Zeroizing 内存、上限 1 MiB，取消／到期／领取后清理。批准后的执行绑定与凭证版本、进程身份再次核对。

授权分 installed grants、issued 对象、逐执行端 usage 和 revocation targets；approval_history 提供持久 decision_seq，owner 可看最近 200 条，MCP 不可读取 owner 历史。remote_outbox 与摘要绑定 receipts 提供 spooled／accepted／inspect 交付恢复；remote_audit 为独立链表，vault 检查点另存（§11）。SQLite 目录／文件权限由真实 runner 检查，普通 CI 使用临时 fixture。

手机使用硬件 DK ECDH 派生的 AEAD 存储键加密 SQLite 业务记录，WAL／文件锁保护主 App 与原生后台并发；iOS App Group、Android 私有目录。索引与时序元数据不加密，正文／人类 session 不进入 Dart，短 UI 历史轮转不能截断持久审计／发件箱。手机库内链头不等于库外反回滚锚点。

---

## 11. 审计

执行端记录审批来源、digest、级别、nonce 消费、Grant 使用／预算／unattended_t2、Directive 应用／拒绝和设置变更；审批端记录签发决定、票、指令、配对与吊销。日志不包含凭证值、完整 body、密文、私钥、恢复码、配对 token 或 session token。relay 只记录静态事件／数量，不能提供两端明文审批对账。

`keyvalet audit --remote [--device <id或label>] [--since 24h或RFC3339] [--limit 1..200] [--json]` 读取 owner 本机链并用签名 QueryAudit 自动分页查询 peers。按 approval_id、Grant jti、Directive id 与两端设备关系比较完整签名对象 JCS 摘要、digest、级别及动作；缺失／差异／离线／吊销／历史不完整区分报告。首个页面冻结 through 序号／hash；每端上限 100,000 条，跨设备不承诺共同事务快照。全部完整且无差异才退出 0；缺口退出 3，不能把空集合视为实机 100% 验收。

桌面提交顺序为：同步独立审计收据与 vault AEAD 准备检查点 → SQLite 提交 → 发布已提交检查点。启动／查询核对全链、链头和留存收据；中断可完成／丢弃准备状态，单独回滚 SQLite、删除已提交尾部或留存收据会拒绝。失败事务的独立收据不成为授权。

边界：SQLite、加密 metadata 和日志一起回到一致旧备份仍可通过；最终检查点发布前的恢复窗口无法区分旧状态与未提交事务。手机链头在同一加密库内，只查篡改／缺行，缺少库外锚点；旧版 UI 曾删除的历史无法补回，标 history_complete=false。**没有硬件单调计数器或外部见证的反回滚保证**。软件匹配／差异／中断测试已通过，Mac/ndu 真实请求对账尚未测，见 [恢复与审计](remote-recovery-audit.zh-CN.md) 与 R2-A。

---

## 12. 威胁模型

| 攻击者 | 能做什么 | 不能做什么 | 依赖的机制 |
| --- | --- | --- | --- |
| Ubuntu 上被注入的 agent（用户 `u`） | 发起任意请求、编造 purpose、刷请求 | 读 vault、读 helper 内存、签批准、伪装成审批设备、让批准覆盖到不同的请求 | 文件权限 + 系统用户隔离；批准签名只认 `AK_*`；digest 绑定；限流与合并；UI 标注 purpose 为自述 |
| relay 运营者 / 被攻破的 relay / Cloudflare 边缘（TLS 在边缘终止） | 丢、延迟、重放旧信封、看元数据、拒绝服务 | 解密、伪造、让旧批准再次生效、把批准改派给别的请求 | HPKE + ES256；nonce 一次性；`exp`；`to`/`digest` 在 AAD/签名覆盖范围内 |
| 配对时的中间人 | 替换公钥 | 让两端 6 位 SAS 一致 | SAS 混入 token 与全部公钥；一次性 token |
| 偷到的 MacBook（已锁屏） | — | 批 Strong（Touch ID）；批 Quick（需解锁）；重连 relay 后拿到的只有密文 | SE ACL；`WhenUnlocked` |
| 偷到的 MacBook（已解锁、在手） | 批 Quick 级请求、看待处理内容、收紧设置、吊销 Grant | 批 T2 / unlock / admin；签常设或 T2 Grant；放宽任何设置 | SE userPresence 的系统认证（Touch ID／系统密码）；不等同于 biometryCurrentSet；放宽一律 Strong（§7.5） |
| 被注入的 agent 试图「自己给自己放权」 | 发起请求、在 purpose 里写「请选一直允许」 | 生成 Grant 或 Directive（没有审批密钥）；让弹窗出现执行端没给的范围选项 | Grant/Directive 只认审批密钥签名；`scope_options` 由执行端给出（§7.6 第 3 条） |
| 用户自己开了含 T2 的无人值守 | 被注入的 agent 可做任何该 Grant 范围内的敏感操作 | — | **这是用户明示接受的风险**：红色状态、显式到期／常设确认、`unattended_t2` 逐条审计、`revoke_all_grants` 一键收回（§7.6） |
| Ubuntu root / 被攻破的 helper 或 root peer broker | 一切（与现状相同） | — | **不在威胁模型内**，文档与状态如实声明 |
| Mac 上同用户的恶意进程 | 伪造一个看起来像 KeyValet 的对话框骗用户按 Touch ID | 拿到 `AK_*` 私钥；让真实 helper 发出批准（需要经签名校验的 agent） | 现有缓解：留意非自己触发的弹窗、看审计；V2 菜单栏 App 的一致视觉锚点；V1 的手机 App 本身就是独立于桌面的第二确认面 |
| 普通用户冒充 relay／CLI 或利用 PID 重用 | 连接本地 socket、提交伪路径／PID | 取得其他角色或签名／批准权限 | root peer broker 校验已连接 FD、SO_PEERPIDFD、安装 inode、存活和 UID；broker 仅 AF_UNIX／CAP_SYS_PTRACE，无 vault 路径 |
| 网络窃听 | 看到 TLS 流量 | 看审批内容 | TLS + 端到端加密双层；登录／恢复参数只由 TLS 保护 |

明确不承诺：防服务器 root；防 Mac root；防物理访问 TPM 芯片；relay 的可用性；Quick 级批准在 Mac 已解锁且在手时的防护。

---

## 13. 扩展口子：云端密钥保护、隔离执行与更多审批者

执行与审批在设备本地完成，官方 relay/push 已上线。协议字段与 trait 一旦上线就难改，所以下面四条线在 V1 就把接口、枚举位和保留字段放好，**只放接口，不做实现**。原则：relay 永远不需要知道这些；执行端与审批端通过「设备记录里的声明」互相知道对方是什么。

### 13.1 四个 trait

| trait | 第一版实现 | 保留的实现位 | 对协议的影响 |
| --- | --- | --- | --- |
| `DeviceKeyProvider`（身份键与审批键） | `secure_enclave`、`tpm2`、`pcp_tpm`、`windows_hello`、`software` | `nitro_enclave_ephemeral`（启动时生成、公钥进证明文档）、`kms_asymmetric`（KMS Sign / ECDH，云执行端的身份）、`webcrypto`（Web 控制台的不可导出 P-256）、`yubikey_piv` | 设备记录的 key_kind 描述字段；`alg` 已支持 ES256/RS256，云 KMS 的 ECC_NIST_P256 也是 ES256 |
| `MasterKeyProvider`（vault 主密钥，现有） | SE、TPM、Hello、软件 | `kms_envelope`（UMK 由 KMS 包裹，BYO-KMS 或托管）、`enclave_sealed` | `umk_wraps[*].alg` 枚举加 `kms-envelope`、`enclave-attested-hpke`；vault v2 格式本来就是「每设备一份包裹」 |
| `Executor`（谁来注入与执行，总架构 §9.1） | 本机 helper（三平台） | `nitro_enclave`（SealedJob HPKE 到 enclave 临时键，KMS Recipient 解 CEK）、`remote_helper`（V2 的 Mac 代 Linux 执行）、`cloud_worker`（远程 MCP 端点背后的执行池） | ApprovalRequest 的 `requester.protection` 由字符串改为对象 `{kind, attestation?}`；`caps` 加 `execute_isolated` |
| `Approver`（谁来批，总架构 §7.4） | `touchid`、`hello`、`polkit`、`remote-device`、`auto`、`capability` | `team`（N-of-M，路由到凭证所有者）、`policy_service`（组织策略服务自动批、带服务签名）、`webauthn`（浏览器 passkey 作审批键） | ApprovalDecision 加 `approver_kind: device \| service`，`quorum?: {m, n, sigs[]}`；执行端验签时按 `approver_kind` 选信任锚 |

### 13.2 协议里现在就放的保留字段

```
device record:      { …, key_kind, dk_pub, dk_sig?, ak_q, ak_s, attestation: null或对象, caps[] }
ApprovalRequest:    { …, requester: { device_id, label, os, protection: { kind, attestation? } } }
ApprovalDecision:   { …, approver_kind: "device", quorum?: … }
Grant / Directive:  { …, iss_kind: "device" | "service" | "org" }      // 第一版只有 device
Envelope:           { v: 1, … }                                         // v 升级规则：收到更高 v 的信封 ack 但不处理，审计 unsupported_version
```

执行端对 `attestation` 的态度：第一版**只记录不验证**，`status` 里显示 `attestation: unverified`。K4/D09 将证明 challenge／验证列为 V2；原生 App Attest／Play Integrity API 适配器不能代表已验证硬件。未知描述值可以保留，service/org issuer、非 null quorum 和未知授权枚举均失败关闭。

### 13.3 每条云端路线各自要补什么（现在不做）

| 路线 | 已经有的 | 要补的 | 协议改动 |
| --- | --- | --- | --- |
| BYO-KMS / 托管 KMS 包裹 UMK（总架构 §11.4） | vault v2 `umk_wraps`；`MasterKeyProvider` | `kms_envelope` 实现；KMS 策略治理文档；轮换流程 | 无（新 `alg` 值） |
| Nitro Enclave 执行端（总架构 §11） | `Executor` trait；relay 对 caps 透明；§9 路由 | enclave 镜像、NSM 证明、KMS Recipient、`vsock-proxy`；审批端验证 PCR | 无（`protection.kind = nitro_enclave` + `attestation`） |
| Web 控制台作审批设备 | 设备记录、HPKE、Grant/Directive 都是 JSON | WebCrypto 键、浏览器端 HPKE、Quick-only（无在场门） | 无（`key_kind = webcrypto`，`caps` 不含 `approve_strong`） |
| 团队 N-of-M | `Approver` trait；fan-out 已存在 | 组织目录、法定人数策略、合并签名 | ApprovalDecision 用上 `quorum` |
| 远程 MCP 端点（总架构 §10.4） | 全部对象都是设备无关的签名 JSON | Hydra、资源服务器、`cloud_worker` 执行端 | 无 |

### 13.4 明确不留的口子

- 不设计「relay 代为解密以便云端处理」的任何路径——端到端是不可谈判的。
- 不在第一版引入插件式 `Approver` 的动态加载；trait 在代码里，实现随版本发布。
- 不为未来可能的 Ed25519 / X25519 提前做双栈；SE/TPM/PCP 都是 P-256，等真有需求再加 `alg` 值。

---

## 14. 失败模式与降级

| 情况 | 行为 |
| --- | --- |
| relay 不可达 | 请求进 relay-client 本地密文队列并立即把 `approval_pending` 返回给 agent（不等完调用内预算）；`status` 报 `relay: offline`；用户可 SSH 上服务器用 `keyvalet approve <pid>` 走 polkit 后备 |
| 全部审批设备离线 | 请求排队到 `exp`；agent 收到 `approval_pending`（`approver.online = false`）；过期后 `approval_expired` |
| 运行时在我们的预算之前杀掉工具调用（预算表过时、Desktop 60 s bug、未知客户端） | pending 不受影响，继续等到 `exp`；模型随后用 `credential_wait_approval` 或 Stop hook 兜底拿到结果；`kv-mcp` 审计 `client_timeout_observed` 并把该 `clientInfo` 的预算降到 50 s 直到重启 |
| 批准到达时 session 已退出 | pending 标 `approved_unused`；Mac 端 `approvals --on-approve` 可挂用户自己的续跑命令；V1 不自动续跑 |
| Stop hook 阻止达到上限仍无决定 | 放行，session 正常结束；pending 留到 `exp`；审计 `stop_hook_exhausted` |
| helper 重启丢失内存中的完整请求 | `credential_wait_approval` 返回 `approved_retry_required`；模型带 `approval_id` 重发原调用，字段一致才执行一次 |
| 时钟漂移 > 60 s | 处理但 UI/审计标注；> `exp` 窗口则一律视为过期（宁可误拒） |
| TPM 故障 | 与现有一致：报错，不降级到软件；relay 会话无法续签 → `status` 报 `identity_key: unavailable` |
| 审批设备全部丢失 | 可用 owner 本地审批；relay recover 以恢复码与新 DK 恢复账户并原子撤销旧注册，不能恢复 vault 或擦掉旧离线 Grant（§3.4） |
| 同一请求收到两个批准 | 第二个在 waiting 状态检查处拒绝；若仍 waiting 但 nonce 已消费则原子 INSERT 拒绝，不能跳过验证顺序 |
| Mac 醒来时积压过多 | 过期的丢弃并汇总提示；未过期的按序弹，每个 wake batch 最多展示 5 个，完成一个不补位 |
| 批准到了但 agent 已放弃 | pending 标 `approved_unused`，`exp` 后作废；审计可见 |

---

## 15. 代码落点

| crate | 变更 |
| --- | --- |
| `kv-platform` | kv-ipc 的 DeviceKeyProvider／PresenceProbe trait 的平台实现：TPM（创建/签名/ECDH）、SE 身份与审批密钥（经 `kv-touchid` 桥，三种 ACL）、Windows PCP（`NCryptSecretAgreement`/`NCryptSignHash`，服务上下文持久化）、Hello RS256 审批键、软件键；`presence_kind()` 上报；`PresenceProbe` trait 与三平台实现（§6.10.1：会话 / 锁屏 / 空闲 / 显示器 / 审批通道五个信号） |
| `kv-vault` | 元数据 v1.x：`identity_key_blob`、`devices`（含 `alg`、`key_kind`、`attestation`）；`umk_wraps[*].alg` 枚举预留 `kms-envelope` / `enclave-attested-hpke`（只读写，不实现） |
| `kv-core` | 规范化与 digest 加 `kind/requester/agent`；`ApprovalRequest`/`ApprovalDecision`/`Grant`/`Directive` 类型与 JCS 编码；签名验证按 `alg` 分派 ES256/RS256；HPKE 使用现有 P-256/HKDF/AES-GCM 组合，hpke 仅为独立 dev 向量参考；§13.2 保留字段的序列化（未知字段保留、未知 `v` 拒绝） |
| `kv-helper` | `Approver` 实现 `RemoteDevice`（三平台）；pending/grants/directives/settings/nonce 表；§6.5 验证器；§6.8 选择器；fan-out；relay 子协议 IPC；内存中的完整请求保留与就地执行、`approval_id` 恢复、`agent_pid` 查询、Stop hook 计数（§6.9）；Grant 覆盖判定（§7.4）；Directive 执行器与档位规则（§7.5）；无人值守状态与 `unattended_t2` 审计（§7.6）；本地 `/keyvalet:mode` 与远程 `set_mode` 共用 `settings` |
| `kv-ipc` | 29 个实际 remote op 与五角色白名单（附录 C），owner intent、恢复意图和 typed control；默认 identity_sign_jwk |
| `kv-relay-client`（新） | WS 客户端、重连、磁盘队列、systemd / LaunchAgent / Windows 服务集成；转发 `presence_hint` 与 `approval_escalate` |
| `kv-mobile-core`（新，W8） | 手机 App 的 Rust 核心：信封、Grant/Directive、待批队列、SQLite 状态；两套绑定（`flutter_rust_bridge` 给 Dart、手写 C JSON ABI 给 NSE／Android 原生后台）；`kv_native` 插件接口定义（§9.2.1） |
| `kv-server`（新） | §8 全部，feature `relay` |
| `kv-agent` / `kv-touchid` | macOS：远程审批对话框（范围下拉含常设选项）、SAS 确认、Strong 签名、Grant/Directive 签发流程、在场状态计算与去抖上报；Windows `kv-agent.exe`：WinUI 3 原生窗口 + Hello RS256 签名 + 会话内 `GetLastInputInfo` / WTS 通知 |
| `kv-cli` | `relay / pair / devices / approvals [--on-approve] / grant … revoke-all / remote <device> …`（§9.3） |
| `kv-mcp` | `clientInfo` → 运行时预算表；`notifications/progress`；`credential_wait_approval`；`approval_id` 参数；四种结果状态；`claude/channel` 能力与通知；`credential_status` 字段；现有 60/180/200 s 常量改为由预算决定（§6.9） |
| `kv-hook` | 新 `stop` 模式及 Claude / Devin / Codex / Cursor / Gemini 变体：`getppid()` 查 pending、按上限阻止、各运行时输出 schema（§6.9.2 第四层 b） |
| `kv-proxy` | 网关与透明代理的挂连接等待、TCP keepalive、`429 + Retry-After` 与 `X-KeyValet-Approval` 头；`keyvalet run` 的 stderr 提示（§6.9.2 HTTP 路径） |
| `kv-protocols` | 模板新增 `client_timeout_hint_s`（OpenAI / Anthropic 等 SDK 默认超时），供 `kv-proxy` 决定挂连接上限 |
| `scripts/install.sh` / `install.ps1` | Linux：创建专用 helper／relay 用户，root peer broker 与三个单元；Mac：安装 `dev.keyvalet.relay`；Windows：注册 `KeyValetRelay` 服务与管道 DACL；三平台都为各运行时写入 KeyValet 自己的工具超时与 Stop 类 hook 注册（§6.9.3）。`install.sh` 遵守 AGENTS.md 的单引号与位置参数约束 |

---

## 16. 测试与验收

**CI 可跑（不依赖本机安装、TPM、SE、Touch ID）**，按 AGENTS.md 用 `env!("CARGO_MANIFEST_DIR")` 加载仓库文件，软件 P-256 密钥实现 `DeviceKeyProvider`，进程内 SQLite relay：

1. 配对：正常完成；SAS 不一致 → 双方丢弃；token 过期/复用 → 拒绝。
2. 信封：头部任一字段篡改 → 解封失败；`sig` 用错设备 → 拒绝；`to` 不是自己 → 拒绝。
3. 决策：重放同一决策 → nonce 冲突拒绝；digest 不一致 → 拒绝；`exp` 过 → 拒绝；T2 用 `AK_q` 签 → 拒绝；已吊销设备签 → 拒绝。
4. 范围：scope 超出 scope_options 拒绝；普通票不覆盖 T2，显式 T2 票另受 K4 安全栏及未关闭验证缺口约束。
5. 排队：approver 离线 → 消息持久化 → 重连后送达；超时 → `approval_pending` → 带 `approval_id` 重试成功且只执行一次；参数变了 → 当新请求。
6. 能力令牌：验签、`aud`、预算扣减到 0 回落到审批、吊销后拒绝。
7. 相同完整绑定的重试可合并；不同操作各自审批，跨操作签名批承诺为 V2，不能把旧的不同操作合并目标记为通过。
8. relay：限流、同账户校验、`resolved` 后其他设备收到 cancel、7 天清理。
9. 明文零泄露：用含唯一标记的凭证名/主机跑完整流程，断言 relay 数据库与 relay 日志中 grep 不到标记。
10. 等待与恢复（§6.9，用进程内假 MCP 客户端驱动 `kv-mcp`）：预算内批准 → 原调用直接返回结果且发过 progress；预算用尽 → `approval_pending` 为正常结果；`credential_wait_approval` 批准后返回原请求结果且 pending 关闭、第二次调用得到 `already_consumed`；拒绝 → `approval_denied`；`exp` 过 → `approval_expired`；helper 重启后 → `approved_retry_required` → 带 `approval_id` 重发只执行一次；不同 `clientInfo.name` 得到表中对应预算；未知客户端 50 s。
11. Stop hook：有未到期 pending → 各运行时输出 schema 正确（Claude/Devin/Codex block、Cursor followup、Gemini deny）；阻止计数到 3 → 放行；`exp` 过 → 放行；无 pending → 放行且输出为空对象。
12. HTTP 路径：模板带 `client_timeout_hint_s` 时挂连接上限正确；超出后 `429` + `Retry-After` + `X-KeyValet-Approval`；挂连接期间批准 → 正常响应；`keyvalet run` 子进程 stderr 出现等待提示。
13. Grant（§7.4）：弹窗各范围选项生成的 Grant 字段正确；常设 Grant 覆盖 T1、不覆盖 T2；`max_tier = T2` Grant 覆盖 T2 且审计 `unattended_t2`；多张 Grant 命中时 `max_tier` 不放大、预算各扣；`aud = *` 对新配对设备生效；吊销后立即不覆盖；RS256 签发的 Grant 在执行端用设备记录的 `alg` 验签通过、用错 `alg` 失败。
14. Directive（§7.5）：收紧用 `AK_q` 通过、放宽用 `AK_q` 拒绝、放宽用 `AK_s` 通过；`nonce` 重放拒绝；`exp` 过拒绝；`query_*` 回包不含任何凭证值；本地 `/keyvalet:mode` 与远程 `set_mode` 写同一份 `settings` 且都审计；`revoke_all_grants` 后 `grants` 全部 `revoked_at` 非空。
15. 安全栏（§7.6）：`scope_options` 外的范围被拒；T2 请求的 `scope_options` 只有 `per_use`；`unattended` 签发缺二次确认时 CLI 拒绝；无人值守状态在 `status` 与弹窗标题中可见。
16. 保留字段（§13.2）：带未知 `attestation.kind`、未知 key_kind 的设备记录能存能读、状态显示 `unverified`；`v: 2` 信封被 ack 不处理并审计 `unsupported_version`；带未知顶层字段的 Grant/Directive 验签仍按 JCS 全字段通过（不丢字段）。
17. 在场与投递（§6.10，用假 `PresenceProbe` 驱动）：五个信号任一缺失 → `away`；`present` → 本机为主、远程 `delivery.mode = silent`；`idle`/`away` → 远程 `banner`；静默 30 s 未决 → 发 `approval_escalate` 且同一 `approval_id`；桌面 presence_hint 变化去抖 5 s 后立即发，未变化每 60 s 刷新；`notify always-phone` 覆盖判定；在场状态不改变任何档位（present 下 T2 仍 Strong）。

**`#[ignore]`（实机）**：TPM 身份密钥往返；SE 三种 ACL 创建与 HPKE 解封；Touch ID Strong 签名；锁屏下 `AfterFirstUnlock` 身份签名可用而 `WhenUnlocked` 审批签名不可用；Windows PCP 在 LocalSystem 下的 P-256 ECDH/ECDSA 与原始共享点导出；Hello RS256 签名每次都弹在场；Windows 服务账户 `NT SERVICE\KeyValetRelay` 的管道 DACL 校验；三平台 `PresenceProbe` 的真实信号：锁屏 / 解锁 / 屏保 / 拔显示器 / RDP 断开 / 快速用户切换各一次，状态在 5 s 内变化。

**运行时实测清单（W5，结果回填 §6.9.3）**：每个运行时各跑一次「阻塞 4 分钟的工具 + 每 15 s progress」与「阻塞 4 分钟、不发 progress」，记录是否被杀、何时被杀、`progressToken` 是否存在；Stop 类 hook 的输入字段与阻止后的行为；Claude Code channels 在 `--dangerously-load-development-channels server:keyvalet` 下能否唤醒空闲 session。对象：Claude Code CLI 与 Desktop、Codex TUI 与 `codex exec`、Gemini CLI、Cursor IDE 与 `cursor-agent`、Grok Build、Devin CLI。

**R3-A 收尾实测（2026-10-14，未全部达标）**：Ubuntu×Mac 的已安装 Strong 配对完成 1 次（144.164769 s），真实 GET 批准/执行 27 次（401×1、403×26；HTTP 200=0）；20 次同质 Quick 样本 p50=3.0905 s、p95=6.0237 s。原生 MCP 与远程设置共用后端，有限 T2 两轮标签和真实 Strong 签发/撤回已完成。Mac 实际 GET/Deny 为 5.038746 s、执行 0，Esc 不签决定并按原 exp 自然到期；完整锁屏周期 39 次读取，锁屏→away=8.160197 s、解锁→present=6.782415 s。手机活跃数 0，手机静默/横幅未验。

05:14Z 新 agent 已签名安装，owner IPC 5/5；helper/CLI/relay 保留原组件哈希和 CI 来源。系统 Touch ID 取消现已在完整 installed path 返回 key_operation_cancelled / 10.485434 s，新 Grant=0；此前 8.531664 s 通用失败及其修前回归保留。Mac→ndu 真实吊销完成 1 次：命令 9.100511 s、从命令开始到待用批准及 Grant 失效读回 10.583576 s，执行 0。最新一小时 Strong Grant 签发 6.162329 s，超过 5 s。ndu 现已吊销，历史保留；纯执行端没有 AK_s，反向吊销及保留历史的重新加入未闭环。真实最终 biometric failure 仍未测，不能沿用软件分类用例充作硬件证据。

最后完整双端 audit 为 53/54=98.148148%，历史缺接收记录 1 条保留；吊销后原生查询只有 ndu 单端快照、对端 unavailable=1，不能称新的完整对账通过。当前四项 CI 于 06:02Z 全绿：1416 passed / 0 failed / 10 ignored、69 组，526 份源码/构建输入未变；共享依赖由对应工作流对齐后，R3-A 在 locked/offline 保护下重验，未新增依赖或修改锁文件。本人取消两小时物理合盖测试；源码 review 的入站持久化缺口已有共享源码修复和 7 项 CI，当前 Mac helper 尚未部署该项，无两小时实机通过声明。[实机收尾](remote-approval-reports/assets/r3a-se-revocation-native-verified.json)、[当前 CI](remote-approval-reports/assets/r3a-se-child-closure-ci9-summary.json)、[最终源码核对](remote-approval-reports/assets/r3a-final-source-check-ci9-20261014.json)、[R3-A 报告](remote-approval-reports/R3-A-m2-closure.md)。

| §16／R3-A 项目 | 当前结果 | 数字与证据 |
| --- | --- | --- |
| pair → 首次远程批准 <10 分钟 | 真批准已执行；耗时未达标，API 401 | pair=1 / 144.164769 s；首次 allow=7873.538466 s；GET=27；[实机 audit](remote-approval-reports/assets/r3a-first-run-ndu-audit.json) |
| p50 <3 s／p95 <8 s，≥20 次 | 20 次已测；p50 超阈值、p95 达标 | n=20；p50=3.0905 s／p95=6.0237 s；20/20 各执行 1 次；[R3-A §3](remote-approval-reports/R3-A-m2-closure.md) |
| 拒绝／续等／重放／改参数 | 通过；重放指同批准再次领取 | deny=3 / execution=0；wait=1、reclaim=1／0.005954 s、query-change=1；[原 Deny/续等](remote-approval-reports/R3-A-m2-closure.md#3-验收表)、[新 Mac Deny/Esc](remote-approval-reports/assets/r3a-delivery-escape-native-verified.json) |
| 双向吊销 ≤60 s | 正向达标；反向缺 AK_s 被拒 | 正向完成=1，命令=9.100511 s、失效读回=10.583576 s；待用批准 cancelled／执行 0、Grant revoked；反向完成=0／key_unavailable／0.226363 s 含 SSH；[实机收尾](remote-approval-reports/assets/r3a-se-revocation-native-verified.json)、[反向预检](remote-approval-reports/assets/r3a-executor-revocation-ndu-preflight-native.json) |
| 两端 audit 100%，差异 0 | 最后完整双端未达标；吊销后完整快照不可用 | 吊销前 53/54=98.148148%，findings=1、端点=2；吊销后端点=1／unavailable=1，单端 findings=53 不算新双端差异；[完整对账](remote-approval-reports/assets/r3a-audit-timeout-native-20261013T232726Z.json)、[吊销后尝试](remote-approval-reports/assets/r3a-post-revocation-native-audit.json) |
| 合盖 2 小时，不重复、正确 expired | 本人取消实测，源码 review 已完成 | 计时 0 s／请求 0；原缺口 1 项、共享源码持久化回归 7/7，当前 Mac helper 未部署；[原 review](remote-approval-reports/assets/r3a-lid-code-review-20261014.json)、[复核](remote-approval-reports/assets/r3a-lid-review-followup-20261014.json) |
| 切模式／1 小时票／全部收回各 <5 s | 最新一小时 Strong 签发超阈值；模式/收回达标 | per_session=4.760682 s；最新 allow=6.162329 s（此前 2.777137 s）；revoke-all=4.992178 s；lock=3.300604 s；T2 两轮=16.629137 s，已撤回；[最新签发](remote-approval-reports/assets/r3a-remaining-native-20261014T051814Z.json)、[其他控制面](remote-approval-reports/assets/r3a-controls-213127.json) |
| 本机优先／锁屏 away | Mac 实际投递/锁屏转换已验；手机未验 | Mac GET/Deny=1／5.038746 s、执行 0；手机=0；完整周期 present=19／away=20，锁屏→away=8.160197 s、解锁→present=6.782415 s；[真实周期](remote-approval-reports/assets/r3a-presence-native-verified.json)、[实际投递](remote-approval-reports/assets/r3a-delivery-escape-native-verified.json) |
| SE 取消／biometric failure producer | 系统取消实机通过；认证失败仅软件验证 | key_operation_cancelled=1／10.485434 s，新 Grant=0；真实 biometric failure=0；[实机收尾](remote-approval-reports/assets/r3a-se-revocation-native-verified.json) |
| R3-A 最终四项 CI | 当前整合源码全绿 | 06:02Z 1416 passed／0 failed／10 ignored、69 组，526 份源码/构建输入未变；locked/offline 保护，未改依赖/锁文件；[当前四项](remote-approval-reports/assets/r3a-se-child-closure-ci9-summary.json)、[源码核对](remote-approval-reports/assets/r3a-final-source-check-ci9-20261014.json) |

下表保留第二轮的历史快照；本轮的最新数字以上表及 R3-A 报告为准。

**第二轮实机验收（2026-10-13）**：通过只限表中范围；未测与未通过都不计入 M5。各报告测试快照不同，计数不是同一源码的跨平台比较。

| 项目 | 目标／范围 | 结果 | 数字与证据 |
| --- | --- | --- | --- |
| pair 到首次远程 use | <10 分钟，Ubuntu × Mac | 未通过 | 首轮 209.526 s 停止、use n=0；[R2-A §4](remote-approval-reports/R2-A-m2-acceptance.md)、[记录](remote-approval-reports/assets/r2a-pair-attempt-1.json) |
| Mac 审批 p50／p95 | <3 s／<8 s、≥20 次 | 未测 | n=0；[R2-A §4](remote-approval-reports/R2-A-m2-acceptance.md) |
| 拒绝／超时续等／单次消费／改参数 | 真实凭证请求各一次 | 未测 | 实际 use n=0；R2-A §4；[R2-A记录](remote-approval-reports/R2-A-m2-acceptance.md) |
| 双向设备吊销 | 1 分钟内失效 | 未测 | 待真实配对及批准／Grant；R2-A §4；[R2-A记录](remote-approval-reports/R2-A-m2-acceptance.md) |
| 双端 audit | approval_id 100% 对账 | 未测 | 审批数 0，不能以空集计通过；R2-A §4；[R2-A记录](remote-approval-reports/R2-A-m2-acceptance.md) |
| Mac 合盖积压 | 实际 2 小时、不重复、正确 expired | 未测 | 尚未开始计时；R2-A §4；[R2-A记录](remote-approval-reports/R2-A-m2-acceptance.md) |
| Mac 控制面 | 切模式／1 小时票／全部收回各 <5 s | 未测 | 各 n=0；R2-A §4；[R2-A记录](remote-approval-reports/R2-A-m2-acceptance.md) |
| 本机优先与锁屏 away | 实际 GUI／锁屏转换 | 未测 | Mac/ndu 配对未完成；R2-A §4、R2-C 真机表；[R2-A记录](remote-approval-reports/R2-A-m2-acceptance.md) |
| notify always-phone Directive | 指令落地 | 未测 | 桌面端 n=0；手机本地 away 是另一条路径；R2-A §4；[R2-A记录](remote-approval-reports/R2-A-m2-acceptance.md) |
| ndu TPM 安装与原 vault | 三服务、权限、TPM 解锁与数据保留 | 通过 | helper/client 无 caps、broker 仅 SYS_PTRACE；原 vault hash 不变，凭证列表 0；[R2-A §3](remote-approval-reports/R2-A-m2-acceptance.md) |
| Mac 签名 daemon 安装 | helper／agent／relay | 通过 | team PWCRJPY7YC，三服务 running；三把 SE 公钥不同，完整 Strong 配对未过；R2-A §3、§5；[R2-A记录](remote-approval-reports/R2-A-m2-acceptance.md) |
| Windows PCP 双 DK | LocalSystem 创建／重开／签名／ECDH／清理 | 通过 | ES256 64 B、raw ECDH 32 B，错误 dk_pub 验 dk_sig 签名失败；[R2-B 原生结果](remote-approval-reports/R2-B-windows.md)、[SYSTEM](remote-approval-reports/assets/r2b-system-native.json) |
| Windows Quick × 软件执行端 | HPKE 往返，按 AK alg 验签 | 通过 | 62.5863 ms，单次、不含 UI／公网；[证据](remote-approval-reports/assets/r2b-native-keys.json) |
| Windows 安装／升级／卸载 | owner／跨账户／ACL／服务 | 通过 | 11 项；[证据](remote-approval-reports/assets/r2b-windows-service-test.json)；unsigned x64／模拟 TPM |
| Windows Hello Strong | 创建／批准／取消／重复／跨端 RS256 | 真机分项通过；完整生产闭环待验 | IsSupported=true，RSA-2048/RS256；独立取消 UserCanceled(3)/2.2217 s，重复签名与软件执行端 HPKE/nonce通过；联合 fixture 的取消超时保留，VM 无 PIN。见 [R3-B](remote-approval-reports/R3-B-security-closure.md) |
| Pixel 7 核心手机审批 | 软件 fixture 配对、锁屏 Quick、App 指纹 Strong | 通过 | 配对约 9 s；Quick 37 s、Strong 14 s（含用户操作），执行各 1、二次 Replay；[R2-C 真机表](remote-approval-reports/R2-C-mobile.md)、[事件](remote-approval-reports/assets/r2c-physical-events.json) |
| Pixel 7 静默到同 ID 升级 | 30 s 定时／声音；端到端 ≤30 s 分开 | 定时与同 ID 通过；端到端未通过 | 静默到横幅 28.620 s，请求到横幅约 35 s；[采样](remote-approval-reports/assets/r2c-audio-upgrade-trace.json) |
| Pixel 7 设置三步 | 切模式／1 小时票／全部收回 | 功能通过；各 <5 s 未通过 | 约 5 s／≤16 s／<1 s，含指纹／用户输入，单次样本；R2-C 真机表；[R2-C记录](remote-approval-reports/R2-C-mobile.md) |
| 跳过生物识别签 AK_s | Android／iOS 分别拒绝 | Android 通过；iOS 未测 | Pixel 7 2/2、0 skipped、1.242 s；[XML](remote-approval-reports/assets/r2c-android-signing-gate.xml) |
| 系统结束 Android 后台进程 | FCM → 原生/Rust 审批唤起 | 通过 | PID 16454→空→16720，约 7 s；[证据](remote-approval-reports/assets/r2c-approval-process-kill.json) |
| Android 重启恢复与远端退出 | 新审批拉取／relay token 与会话删除 | 未通过 | boot 37→38、同 token／唤起通过，新请求持续 retry；本地退出约 1.1 s，远端 token/会话仍在；R2-C 真机表；[R2-C记录](remote-approval-reports/R2-C-mobile.md) |
| 手机离线积压 | 实际 1 小时 | 未测 | 用户延后窗口；R2-C 真机表；[R2-C记录](remote-approval-reports/R2-C-mobile.md) |
| iOS／发行渠道 | SE、APNs、Apple、TestFlight／Play 包 | 未测 | iOS/iOS-sim 编译通过；未生成 IPA／签名 AAB 或上传；R2-C Play 与 iOS；[R2-C记录](remote-approval-reports/R2-C-mobile.md) |
| 运行时托管模型 | Claude + 另外两家，四分钟与续等 | 门槛未通过 | Codex exec 240.015/240.006 s、TUI 240.007/240.012 s；Devin 240.006/240.007 s。仅两家，Claude 未进工具；[R2-D §B](remote-approval-reports/R2-D-runtimes.md) |
| Claude channels | idle／busy／无 flag | 未测 | 三项均待可用交互会话；R2-D §B；[R2-D记录](remote-approval-reports/R2-D-runtimes.md) |
| HTTP SDK 与连接回收 | 两 SDK、h1/h2、wildcard、终态、低 fd | 通过（loopback／假 helper） | 26 SDK 记录；fd=256 两 bounded 测试 20/20 轮、40 结果；R2-D §A/§D/最终验证；[R2-D记录](remote-approval-reports/R2-D-runtimes.md) |
| 一周／两周 dogfooding | 覆盖 >80%、人工审批可解释 | 未测 | 尚未开始，不由 CI 推算；R2-A §7；[R2-A记录](remote-approval-reports/R2-A-m2-acceptance.md) |
| 工作区四条 CI | 各报告的冻结源码快照 | 通过 | R2-A Mac 1333/0/10；R2-B Mac 1323/0/10、Windows 1079/0/25；R2-C 四项 exit 0；R2-D Mac 1331/0/10。ignored 硬件项另列，不当通过；[四份R2汇总](remote-approval-reports/R2-E-docs.md) |

---


## 17. V1 实施计划：按工作流并行

### 17.1 原则

1. **契约先行。** 附录 A–F 是冻结的接口；W0 先把它们落成 Rust 类型 + JSON Schema + 测试向量，其他工作流只依赖这些，不依赖彼此的实现。
2. **crate 级所有权。** 每个工作流只改自己名下的 crate / 目录；要改别人的东西，只能在报告里提出，由 W0（契约所有者）或 W9（集成）落地。
3. **接口先 stub 后实现。** 依赖方先对契约编程并用假实现（in-memory relay、软件密钥、假 MCP 客户端）跑通测试，等被依赖方交付再切换。
4. **同一工作树、各自的 target 目录。** 所有工作流都在 `main` 工作树上直接改文件，不建分支、不提交；各自 `CARGO_TARGET_DIR=rust/target-<ws>` 避免构建锁互等；只对自己的 crate 跑 `cargo fmt -p` / `clippy -p` / `test -p`，全工作区检查留给 W9。
5. **每个工作流的「完成」= 自己 crate 的 CI 命令全绿 + 契约测试向量全过 + 报告写到 `docs/remote-approval-reports/W<n>.md`（改动文件、未决问题、对契约的变更请求）。** 截图与录屏放 `docs/remote-approval-reports/assets/`。
6. **不操作 git。** 所有工作流都不 commit、不建分支、不 stash、不 checkout；只允许只读的 `git status / diff / log`。由用户在集成后统一处理版本控制。

### 17.2 工作流

| 编号 | 工作流 | 拥有的 crate / 目录 | 依赖 | 产出 |
| --- | --- | --- | --- | --- |
| **W0** | 契约与测试向量 | `rust/crates/kv-core`（新增 `remote` 模块）、`rust/crates/kv-core/testdata/remote/`、`rust/crates/kv-ipc`（新增消息）、`docs/remote-approval-*.md` 附录 | 无 | 附录 A–F 的 Rust 类型、JCS 规范化、digest、HPKE 信封、ES256/RS256 分派、JSON Schema、测试向量；软件 `DeviceKeyProvider` 测试实现；`kv-ipc` 新消息 |
| **W1** | 平台密钥与在场 | `rust/crates/kv-platform`、`rust/crates/kv-touchid`（SE 新键）、`rust/crates/kv-agent`（Windows PCP / Hello、Linux 在场探针） | W0 的 trait 定义 | `DeviceKeyProvider` 三平台实现（TPM、SE、PCP+Hello、软件）；`PresenceProbe` 三平台实现；spike 结论回填 §3.1 |
| **W2** | relay 服务 | `rust/crates/kv-server`（新）、`deploy/relay/`（新：systemd 单元、nginx 配置模板、Dockerfile） | W0 | 附录 B 的全部 API；SQLite；presence；限流（从 `CF-Connecting-IP` 取客户端 IP，仅信任本地 nginx）；§8.5 的 nginx + Cloudflare 橙色云部署资产；进程内测试 harness 供他人复用 |
| **W3** | relay 客户端 | `rust/crates/kv-relay-client`（新，含 `service/` 下的 systemd / LaunchAgent / Windows 服务模板） | W0、W2 的 API（先对 harness） | 三平台守护进程；重连；磁盘密文队列；与 helper 的 relay 子协议；服务模板交 W9 接入安装器 |
| **W4** | 执行端 helper | `rust/crates/kv-helper` | W0、W1 的 trait（先用软件实现） | `RemoteDevice` Approver；pending / grants / directives / settings / nonces；§6.5 验证；Grant 覆盖；Directive 执行；§6.9 等待与就地执行；§6.10 投递决策与升级定时器；审计事件 |
| **W5** | agent 侧：MCP / hook / proxy | `rust/crates/kv-mcp`、`rust/crates/kv-hook`、`rust/crates/kv-proxy`、`rust/crates/kv-protocols`（只加 `client_timeout_hint_s`） | W0 的 IPC 消息；W4 的行为（先对假 helper） | 运行时预算表；progress；`credential_wait_approval`；四种结果状态；channel 能力；Stop hook 五种变体；HTTP 挂连接与 429；运行时实测回填 §6.9.3 |
| **W6** | 桌面审批端 | `rust/crates/kv-agent`（对话框部分）、`rust/crates/kv-touchid`（对话框部分） | W0、W1 | macOS / Windows 远程审批对话框（范围选项、Strong 流程）、SAS 确认框、Grant/Directive 签发流程、在场状态上报 |
| **W7** | CLI | `rust/crates/kv-cli` | W0 的 IPC 消息 | `relay / pair / devices / approvals / grant / remote` 全部子命令；人类可读 + `--json` 输出 |
| **W8** | 手机 App | `mobile/`、`rust/crates/kv-mobile-core`（新）、`rust/crates/kv-push`（新） | W0、W2 的 API | Flutter 工程（iOS + Android）；`kv-mobile-core` 双绑定；`kv_native`（Swift / Kotlin）；iOS NSE；Android 消息服务；`kv-push`；TestFlight / 内部测试轨道打包脚本 |
| **W9** | 安装器、文档与集成 | `scripts/install.sh`、`scripts/install.ps1`、`docs/linux.md`、`docs/windows.md`、`docs/runtimes.md`、`SECURITY.md`、`site/content/guide*.md`、`.github/workflows/*` | 其余全部 | 三平台安装器变更（`keyvalet relay install` 调用 W2 的部署资产写 nginx 配置并提示 Cloudflare 步骤、relay-client 服务、运行时超时、Stop hook 注册）；文档更新；全工作区 `fmt / clippy / build / test`；§16 实机验收并记录到 review 文档 |

### 17.3 依赖与里程碑

| 里程碑 | 当前状态 | 依据与剩余条件 |
| --- | --- | --- |
| M0 契约／向量 | 完成，K1 扩展已交付 | W0 与 R2-B 新旧向量、schema；K4 接收验证、负向向量与旧票失效处理已完成，Mac／Windows CI 通过 |
| M1 relay harness／模块集成 | 完成 | W2、W1–W5、owner integration、v1-completion；软件密钥／假 OS 不能代替硬件 |
| M2 Ubuntu × MacBook 一次远程 use | 完整验收未完成 | R3-A Strong 配对=1、真实 GET=27 / HTTP 401×1、403×26；n=20 p50/p95 已测；双向吊销/合盖/在场待测，控制前三项通过，T2 标签待补 |
| M3 iPhone 加入及审批／投递 | 未完成 | iOS 仅编译／模拟器；签名资源／APNs／Apple 登录／真机待验；Android 通过不能关闭 iPhone 里程碑 |
| M4 Windows 双角色 + Android | 部分完成 | PCP 双键与安装、x64 Hello 分项和 x64／ARM64 无界面 CI 通过；正式 Windows 公网双角色、protected 客户端及物理 ARM64 待验；Android 重启恢复／远端退出未过 |
| M5 所有 §16 项目与一周使用 | 未完成 | 多份四项 CI 通过；延迟、真实双端 audit／吊销、两小时合盖、channels 与发行矩阵仍缺 |

第一轮 W0–W9 分工保留为历史，第二轮分工与 K1–K4 见 [R2 prompts](remote-approval-agent-prompts-r2-2026-10.zh-CN.md)。不同报告的通过只对应记录的源码与平台，不把较早二进制或覆盖率作为当前所有路径的验收。

### 17.4 V2 及以后（不在本轮）

Linux 桌面审批端；瘦菜单栏/托盘；vault 密文同步与手机 OAuth 添加凭证；总架构 §9 的 Mac 代 Linux 执行；第一个云端实现（BYO-KMS 包裹 UMK 或 Nitro 执行端）接到 §13 的接口上；不同操作批承诺、产品多审批方／quorum、服务／组织信任根、attestation 验证；公开上架与托管计费／配额执行（计划中）。官方 relay 已上线。

---

## 18. 已决事项与仍开放问题

已决与已实现的处置如下；“已决”不自动表示对应验收通过。

| 项目 | 已决处置 | 实现／证据 |
| --- | --- | --- |
| K1 / D13 Windows | DK 分 PCP ECDH 与 ECDSA；可选 dk_sig，坏值拒绝 | R2-B／R3-B；原生双键、真机 Hello 分项通过；VM 无 PIN，生产链路待验 |
| K2 / D11 账户 | 桌面匿名 + 恢复码，手机 Google／Apple + DK 证明；双方 SAS 后归属用户 | W8 账户补充、R2-C；Google Debug 实测通过，Apple 未测 |
| K3 relay | 手机固定 relay.keyvalet.dev；自托管只服务桌面 | W8、R2-C、R2-A 线上部署 |
| K4 / OPEN D01/D02 | owner intent、匿名初始化与 Strong 一次性准备令牌按实际 B/C 契约回写 | owner integration；源码／软件回归通过，Mac 真实配对仍未过 |
| K4 / OPEN D03 | 短期设置 Grant 保持 Strong | R2-C 1 小时票实际 Strong；产品 Quick 文案已纠正 |
| K4 / OPEN D04/D05 | 有限 T2 签名必须含标签；全局 T2 拒绝 | 发行与接收／使用前重验均已约束；负向向量、旧票失效处理和两平台 CI 通过，见 R3-B 无签名验收 |
| K4 / OPEN D06/D07/D09 | 跨操作 batch、多审批方／quorum、attestation 验证为 V2 | 相同绑定重试与基础 fan-out、双 Strong 设备记录交换已有软件回归；不等于 V2 权威已支持 |
| K4 / OPEN D08 | /v1/recovery 关闭旧恢复接口缺口 | v1-completion、恢复审计文档；真实全设备丢失恢复验收分开 |
| K4 / OPEN D10 | Linux 6.5+ root peer broker；helper/client 无 capabilities | isolation 8 个原生 UID 用例、R2-A 已安装三服务 |
| 运行时 T08 | typed 拒绝／取消／到期、活 gateway session 的有限响应恢复 | R2-D 软件与 SDK 通过；跨重启及外部 exactly-once 不承诺 |
| 默认等待／Stop | 初始 60 s、续等 5–600 s、progress 15 s、最多三次 Stop | W5/R2-D；实际 runtime profile／override 仍封顶 |

| 仍开放 | 当前状态／下一步 | 追踪 |
| --- | --- | --- |
| metrics 边界 | metrics 只有 Device 认证、无 socket-loopback 条件；运维访问边界及公网负向验收仍待落实。S01/S02 接收规则已修复，不再与此合并为未实现 | OPEN S03；R3-B 无签名验收 |
| Ubuntu × Mac 真机链路 | Strong 配对=1、GET=27；n=20 p50/p95 已测，旧 audit 37/37；控制前三项通过，T2 标签／双向吊销／控制后 audit／两小时合盖待测 | R3-A、E03/E04/E08/T01/T02 |
| Windows 生产／桌面范围 | 旧包的真机 Hello、PCP及protected MCP解锁／取消／Crash通过；当前签名可选，新WinUI／无签名发行包、绑定公网、锁屏崩溃修复复验／物理ARM64仍待验 | R3-B 无签名验收 §8–10、Windows发行策略、E02 |
| Android 稳定性／预算 | 恢复 relay HTTPS 后复验重启与远端退出；横幅单次约 35 s、1 小时票 ≤16 s 未满足预算；一小时离线待窗口 | R2-C、E05/E08/T03 |
| iOS／商店发行／Apple 登录 | profiles/App Group/APNs/ASC/Apple provider/Play keystore 与实际发行指纹、IPA/AAB 尚缺 | R2-C、E06/E09 |
| 运行时与配置 | Claude 有效会话、第三家、channels 三项、IDE／未测 Stop／timeout；Devin 专用 MCP 配置与短 timeout env 核对 | R2-D、E07/T10 |
| 硬件反回滚与历史 | 一致旧备份、手机库内锚点、旧历史缺口仍是边界 | T04 |
| presence／原生覆盖率 | 初始屏保、Linux 精确 idle／polkit、OS 转换、native/Swift 覆盖率待验 | T05/T06 |
| 账户生命周期 | 删除／解绑、跨 provider 显式链接、Apple code/refresh 生命周期未实现 | E09，计划中 |

完整逐项处置与需要决定的冲突见 [OPEN-QUESTIONS](remote-approval-reports/OPEN-QUESTIONS.md)。旧架构 §18 的 TPM／域名选址已由真机与部署事实替代，不能再当未决前置条件。

---

## 附录 A. 对象契约（JSON 形状）

约定：所有对象的 `sig` 覆盖「除 `sig` 外全部字段」的 JCS（RFC 8785）编码；时间戳为 Unix 秒（整数）；id 为 ULID 字符串；二进制字段为 base64url 无填充；未知字段**必须保留并参与签名验证**（不得丢弃），未知枚举值按各字段说明处理。JSON Schema 落在 `rust/crates/kv-core/schemas/remote/*.schema.json`，测试向量落在 `rust/crates/kv-core/testdata/remote/`。

### A.1 Envelope

```json
{ "v": 1, "type": "<见下>", "id": "ULID", "account": "acct_…", "from": "dev_…", "to": "dev_…",
  "created_at": 0, "exp": 0, "enc": "b64url", "ct": "b64url", "sig": "b64url" }
```

- `type ∈ { approval_request, approval_escalate, approval_decision, approval_cancel, grant, directive, directive_result, presence_hint, device_revoke, pair_offer, pair_accept, pair_confirm }`。
- AAD = JCS 编码的 `{v, type, id, account, from, to, created_at, exp}` 及全部未知头扩展（不含 `enc/ct/sig`）；`sig` = ES256（发送方 DK 身份签名公钥：合法 `dk_sig.pub` 或无此字段时的 `dk_pub`）覆盖 `AAD_bytes ‖ ct_bytes`。
- 可选签名头 `push: {mode: "silent" | "banner"}` 只携带投递模式。helper 为手机接收方在 seal 前加入该字段，纳入 AAD 与外层签名；relay 仅验证提示和外层，不解析 `ct`。具体投递规则见 §8.4。
- HPKE：`DHKEM(P-256, HKDF-SHA256)`、`HKDF-SHA256`、`AES-128-GCM`，mode base，`info = "keyvalet/envelope/v1"`。
- 接收端：`v > 1` → ack 不处理，审计 `unsupported_version`；`exp < now` → 丢弃，审计 `expired_envelope`。

### A.2 ApprovalRequest（信封明文，`type = approval_request`）

```json
{ "approval_id": "ULID", "kind": "unlock | use | admin", "digest": "hex-sha256", "nonce": "b64url-16B", "exp": 0,
  "requester": { "device_id": "dev_…", "label": "srv", "os": "linux | macos | windows",
                 "protection": { "kind": "tpm2 | secure_enclave | windows_hello | software_key | <未知→显示 unknown>", "attestation": null } },
  "agent": { "runtime": "claude-code | codex | cursor | gemini-cli | devin | grok | http | unknown", "cwd": "…", "user": "u", "pid": 0 },
  "credential": { "ref": "type/name", "kind": "static | oauth2 | …", "display": "…", "proxy_only": true },
  "operation": { "summary": "…", "method": "GET", "host": "…", "path": "/…", "query_keys": [], "body_bytes": 0 },
  "purpose": "…", "tier": "T0 | T1 | T2", "min_level": "quick | strong",
  "scope_options": ["per_use", "per_credential", "per_session", "remember:1h", "remember:8h", "remember:24h", "standing:credential", "standing:device"],
  "requested_scope": "per_credential", "merged_count": 1,
  "delivery": { "mode": "banner | silent", "escalate_after_s": 30 } }
```

`unlock` 时 `credential`/`operation` 为 `null`，`agent` 必填；`admin` 时 `operation.summary` 为操作名（如 `admin.add_device`）。`digest` 的 canonical 见 §6.2。

### A.3 ApprovalDecision（`type = approval_decision`）

```json
{ "approval_id": "ULID", "digest": "hex", "nonce": "b64url", "decision": "allow | deny",
  "level": "quick | strong", "scope": { "mode": "per_use | per_credential | per_session | remember | standing", "level": "credential | device", "until": 0 },
  "approver": "dev_…", "approver_kind": "device", "quorum": null, "issued_at": 0, "reason": "…(deny 时可选)", "sig": "b64url" }
```

`sig` 由 `level` 对应的审批键签，`alg` 取自设备记录。scope.mode=standing 时执行端保存 exp=null 的内部授权及原决定证明；它不是可跨设备转发的独立 AK 签名 Grant。reason/quorum 的缺失与 null 保留，V1 非 null quorum 和非 device approver 拒绝。

### A.4 Grant（`type = grant`）

见 §7.4。K4 规范：global 要求 aud=* 且 max_tier≤T1；所有 T2（有限／常设）必须 settings 来源、Strong AK 签名、confirm=当前执行端标签，不能使用全局 audience。budget.per 为 1h/24h/7d。共享 verify_grant 已对全部 T2 强制当前标签并拒绝 wildcard/global；Grant schema／样例／新负向向量同步，见 §7.6 和 R3-B 无签名验收。其他既有向量保持逐字节一致；原 finite 正例已加入签名标签。

### A.5 Directive / DirectiveResult（`type = directive | directive_result`）

见 §7.5 的 JSON；`args` 按 `op`：`set_mode{mode}`、`revoke_grant{jti}`、`revoke_all_grants{}`、`lock{}`、`set_unlock_ttl{seconds}`、`set_class{name, match, exp_s}`、`set_device_label{label}`、`revoke_device{device_id}`、`notify{policy: prefer-local|always-phone|both}`、`query_status{}`、`query_pending{}`、query_grants{after?,limit=50（1–100）}、query_audit{since,limit（1–200）,after?,through?}、`cancel_approval{approval_id}`。
`DirectiveResult = { "id": "<directive id>", "ok": true, "error": null, "state": { … 按 op 的返回 … } }`，`query_audit` 返回条目只含 §11 的元数据字段，不含任何凭证值或请求体。

### A.6 PresenceHint（`type = presence_hint`）

```json
{ "device_id": "dev_…", "state": "present | idle | away", "since": 0, "sent_at": 0 }
```

### A.7 Pairing 与 DeviceRecord

- PairOffer 为 `{token_hash, initiator: DeviceRecord, ...扩展}`；HTTP PairStart 另带 exp，外层身份认证和签名按 K1，不能信任 relay 裸 pair_accept 提示。
- PairAccept 为 `{token, joiner: DeviceRecord, global_grants?: 数量, ...扩展}`；授权数量只在 E2E 密文中。
- PairConfirm 基础为 `{sas, sig, ...扩展}`，最小签名载荷 JCS `{sas}`。现代确认携带 `{sas, device: 本端DeviceRecord, exclude_global, sig}`，签整个对象除顶层 sig；AK_s 按其 alg，纯执行端为空 AK 签名但仍有外层 DK 身份签名。双方真实确认前不得提交信任。

```text
DeviceRecord = {
  device_id, label, os, key_kind,
  dk_pub: JWK(P-256),
  dk_sig?: {pub: JWK(P-256), alg: "ES256", ...扩展},
  ak_q: {pub: JWK, alg: "ES256"或"RS256", ...扩展}或null,
  ak_s: {pub: JWK, alg: "ES256"或"RS256", ...扩展}或null,
  caps, attestation: null或对象, ...扩展
}
```

dk_pub 是既有 wire 字段，承担 HPKE ECDH；不能改名为新对象 dk。dk_sig 缺失则保持原 dk_pub 的 ES256 身份验签与 ECDH。存在时全部设备身份签名仅用 dk_sig.pub 验，算法必须 ES256、公钥必须 P-256；null、RSA、其他曲线／算法、私钥字段、无效点均拒绝，不回退或跳过。dk_sig 本身及嵌套未知字段参与完整记录 JCS、签名、摘要和 authority 比较；缺失保持缺失。审批签名仍使用 AK 与其 alg。

SAS 的完整旧域／split identity 新域、排序、token16、AK 角色选择与十进制转换见 §4；旧向量不改。label 可经已认证 SetDeviceLabel 更新，其余身份／审批公钥、算法、caps、平台和扩展权威字段不原地替换。现代确认绑定完整记录与 exclude_global，K1 不降低未知字段规则。

### A.8 agent 可见的工具结果（MCP）

```json
{ "status": "ok | approval_pending | approval_denied | approval_cancelled | approval_expired | no_approver | approved_retry_required | still_pending | already_consumed",
  "approval_id": "ULID", "expires_at": 0, "approver": { "label": "…", "online": true }, "wait_tool": "credential_wait_approval",
  "next_steps": "…", "result": { … 仅 status=ok 时 … } }
```

### A.9 DeviceRevoke（`type = device_revoke`）

`{ device_id, proof: { action: "revoke_device", account, by, device_id, challenge }, sig }`。proof 与 relay 删除使用同一个 DeviceDeleteProof；sig 是已信任发送者 AK_s 对 proof 的 JCS 签名。接收方核对目标、账户、发送者、32 字节 challenge 和 Strong 能力，然后写入设备 tombstone、撤销该设备签发的 Grant 并取消其尚未消费的决定。只有外层 DK 签名不能授权吊销。

吊销只收紧固定账户中固定设备 ID 的权限，设备 ID 不复用。为送达离线设备，吊销信封 `exp = 9007199254740991`，由原有持久 outbox 重发，relay 仍在 ack 后 7 天清理。接收方不要求旧 challenge 保持新鲜；relay DELETE 仍要求自己的新鲜一次性 challenge。relay 只验外层签名和路由，不能读取此正文。

---

## 附录 B. relay API 契约

下表逐项对应 kv-server/src/http.rs 的 25 个方法／路径组合（含 metrics）。D 表示 Authorization: Device <session_token>；U 表示 Bearer 人类会话。手机 challenge/verify 另带 x-keyvalet-user-session，设备会话绑定活跃人类会话。公开入口仍有其自身证明／限流／配对限制，不能把“无 D”理解为跳过验证。

| 方法 | 路径 | 认证／请求 | 响应 |
| --- | --- | --- | --- |
| POST | `/v1/devices` | 桌面匿名；DeviceRecord 的字段平铺，另有 push_token? | {account_id,device_id,recovery_code?}；首个注册显示一次 |
| POST | `/v1/devices/push-token` | D；手机须关联活跃人类会话；{push_token:{platform:apns或fcm,token}} | {ok:true}；仅本人且 OS 对应 |
| DELETE | `/v1/devices/push-token` | D；手机须活跃人类会话，无体 | {ok:true}；清本人 token/job |
| DELETE | `/v1/devices/{id}` | D、同账户；{by:device或recovery,recovery_code?}；device 分支须下述 Strong headers | {ok:true}；撤销注册／会话／WS |
| POST | `/v1/auth/challenge` | {device_id}；手机另附人类会话 | {challenge:无填充b64url32B,exp}；60 s |
| POST | `/v1/auth/verify` | {device_id,challenge,sig}；身份键签原始32B，不是 JCS | {session_token,exp,account_id}；24 h |
| POST | `/v1/recovery` | 无旧 D；{account_id,recovery_code,new_recovery_code,device,nonce,sig} | {ok,account_id,device_id,recovery_code}；§3.4 |
| GET | `/v1/account/providers` | 公开，无体 | {google,apple,google_web_client_id,google_ios_client_id,apple_app_id,apple_services_id,apple_callback_url} |
| POST | `/v1/account/begin` | 公开限流；{provider:google或apple,device:DeviceRecord} | {attempt_id,nonce_hash,state,expires_at}；600 s 一次性 attempt |
| POST | `/v1/account/finish` | {attempt_id,identity_token,state,signature,display_name?}；ID token + DK 证明 | {session_token,expires_at,account_id,user:{id,provider,email,display_name}}；30天 U |
| GET | `/v1/account/session` | U，无体 | {user:{id,provider,email,display_name},expires_at} |
| POST | `/v1/account/logout` | U，无体 | {ok:true}；清该会话与设备会话、token/job、WS |
| POST | `/v1/account/apple/callback` | application/x-www-form-urlencoded；{state,id_token?,code?,user?,error?}，须有效 Apple state | 固定 Android intent redirect；无任意包名／URL 选择 |
| GET | `/v1/presence` | D，WS 子协议 kv-relay-v1；30 s ping | t=envelope／ack／pong；裸 pair_accept／approval_cancel 仅提示 |
| POST | `/v1/pair/start` | D；{token_hash,initiator:DeviceRecord,exp} | {pairing_id} |
| POST | `/v1/pair/complete` | 新加入方无 D；已有单例须本人 D；{token,joiner:DeviceRecord} | {pairing_id,initiator,account_id,expires_at} |
| POST | `/v1/pair/finish` | D；{pairing_id,confirm:PairConfirm} | {ok:true}；双方 finish 后完成，同确认可重试 |
| POST | `/v1/approvals` | D；{id,exp,envelopes:[Envelope]} | {accepted:n}；每个 to 一份 |
| GET | `/v1/approvals?state=waiting` | D | {envelopes:[Envelope]}；仅发给本人 |
| POST | `/v1/approvals/{id}/reply` | D；{envelope}，仅原收件方 | {ok:true}；首个外层有效回复 resolved |
| POST | `/v1/approvals/{id}/cancel` | D；原 requester，{envelope?:Envelope} | {ok:true}；原签名取消原样投递 |
| POST | `/v1/messages` | D；{envelopes:[Envelope]} | {accepted:n}；持久化至 ack |
| POST | `/v1/messages/ack` | D；{ids:[],type?:string} | {ok:true}；本人对应消息，客户端总带 type |
| GET | `/v1/health` | 公开 | {ok:true,version} |
| GET | `/metrics` | 当前 D，聚合数值；缺少原文所述独立 loopback 限制 | Prometheus 文本；S03 待处置 |

身份证明统一采用 verify_identity_signature(DeviceRecord,…)，dk_sig 合法存在时只用它，否则 dk_pub。登录 DK proof 为 JCS `{purpose:"keyvalet-account-login-v1",attempt_id,provider,device_id,identity_token_hash,state}`；identity_token_hash 为精确 ID token SHA256 hex。Apple 另核 nonce/state；provider+subject 唯一、邮箱不隐式合并。待 SAS 不抢占账户归属，另一用户不能加入已归属账户。

恢复 DK proof 为 JCS `{action:"recover_account",account_id,device,nonce,new_recovery_code_hash}`，两码／nonce 都为32随机字节无填充 base64url，新码 hash 为字符串 SHA256 hex。新码先保存，失去旧会话也能恢复；响应不缓存，失败不修改旧权威。

设备 DELETE 的 device 分支还要求 x-kv-challenge 与 x-kv-strong-signature：AK_s 对 JCS `{action:"revoke_device",account,by,device_id,challenge}` 签名，challenge 单次消费并与删除原子提交。恢复码分支仍需该路由的 D；无旧会话的全账户恢复使用 /v1/recovery。

所有 JSON 错误使用 `{error:{code,message}}`，不回传数据库／provider 原始正文。普通路由映射：unauthorized 401、forbidden 403、not_found 404、rate_limited 429（Retry-After:60）、payload_too_large 413、bad_envelope 400、expired 410、conflict 409。账户流程额外有 provider_not_configured／provider_unavailable 503、invalid_identity 401、account_conflict 409、login_rejected（按原失败 400/401/403/429）；extractor／路由错误仍可返回普通错误。账户与 recovery 都 Cache-Control:no-store。完整 provider 配置见 [账户契约](../mobile/docs/account-login.md)。

限额：设备每分钟 approvals 60／messages 600、账户待处理500、信封80 KiB、HTTP/WS输入1 MiB。恢复码／ID token／会话 token 不进入日志，表内 session_token 字段只说明形状，不是证据记录许可。

传输重试必须幂等：相同账户、`id`、`to`、`type` 的同一完整签名信封重发成功，保留原 `acked_at`，不再重复推送；密文、签名或签名覆盖字段不同则返回 `conflict`。`/v1/approvals` 允许同一 requester 在原 `exp` 下向不同接收方分批提交，新增片段只在 `waiting` 时接收；已经存储的相同片段和相同回复在 `resolved` 后仍可重试。限额不重复计算已存储的片段。

同一个 `approval_id` 下的 request、escalate、cancel 是独立密文。ack 带 `type` 才能逐条确认，避免原 request 的 ack 与新 cancel 投递交错时提前确认 cancel。省略 type 的旧请求保留按 ID 批量确认的兼容行为；HTTP 与 WS ack 均支持 type 选择器，新 W2/W3 应一起部署。

relay 推送的裸 `approval_cancel`、`pair_accept` 控制帧只是无签名元数据提示。helper 状态变化必须依据签名信封；客户端忽略裸提示并继续传输。首个回复使 relay 状态成为 `resolved` 后，requester 仍可发送 helper 签名的取消信封以清除其他接收方的缓存，不改变已决状态。审批到期后同样可投递短时有效的签名取消信封；其有效期由 helper 单独给出，只授权清理该 requester 的原审批缓存，不延长审批的执行权限。空体 `{}` 的旧取消接口只操作未过期的等待审批，重复取消幂等。

---

## 附录 C. IPC 消息（kv-ipc）

IPC v4 remote 命名空间：请求 `{op:"remote.…",params:{…},...extra}`，响应 `{ok:true,result:{…}}` 或 `{ok:false,error:{code,message}}`。多请求连接使用关联 id；冷连接默认无推送，notifications=true 可订阅。底层 Op／五角色白名单来自 kv-ipc/src/remote.rs，core/ipc.rs 只提供 typed alias，不另定义权限。

| op | 允许调用方 → helper | params | result |
| --- | --- | --- | --- |
| `remote.relay.identity` | relay-client | {} | {dk_pub,device_id,account_id}；仅公开绑定 |
| `remote.relay.inbound` | relay-client | {envelope} | {ack:true}；审计永久拒绝后也可 ack，暂时故障不 ack |
| `remote.relay.outbound.poll` | relay-client | {max_wait_ms} | {envelopes:[]} |
| `remote.relay.outbound.ack` | relay-client | {envelopes:[],stage:spooled或accepted或inspect} | {retired_count} |
| `remote.relay.control.poll` | relay-client | {max_wait_ms} | {request:RelayControlJob或null}；冷启动可用 |
| `remote.relay.control.complete` | relay-client | {id,result:{kind,value}} | {ok:true}；必须对应原命令 |
| `remote.relay.control.sign` | relay-client | {id,payload_b64} | {sig_b64}；固定该请求首个32B challenge |
| `remote.relay.status` | relay-client | {connected,last_error,since} | {}；不把任意 last_error 写审计 |
| `remote.sign_identity` | relay-client | {payload_b64} | {sig_b64}；仅原始32B challenge |
| `remote.presence.update` | agent | PresenceHint | {}；真实本端 device_id／时序核对 |
| `remote.pending.list` | CLI owner、MCP | {agent_pid?} | {pending:[]}；owner 另有 recent/decision_seq，MCP 无 owner 历史 |
| `remote.pending.for_agent` | hook | {agent_pid} | {pending:[{approval_id,expires_at,stop_hook_blocks}]} |
| `remote.pending.stop_block` | hook | {approval_id} | {allowed,blocks_left}；原子最多三次 |
| `remote.wait` | MCP | {approval_id,max_wait_ms,...预算提示} | A.8，调用方归属检查；只领取一次 |
| `remote.client_timeout_observed` | MCP | {}，控制提示不作权威 | {}；审计，不拒绝／取消／消费 |
| `remote.decide` | CLI owner、agent | DecideIntent（C.1） | {sent:true} |
| `remote.grant.issue` | CLI owner、agent | GrantIntent（C.1）；兼容 Unsigned Grant | {grant}或GrantConfirmation |
| `remote.grant.list` | CLI owner | {after?,limit?:50} | {grants,next_cursor}；1–100分页 |
| `remote.grant.revoke` | CLI owner | {jti} | {}；逐目标回执，离线 revocation_pending |
| `remote.directive.issue` | CLI owner、agent | DirectiveIntent（C.1）；兼容 Unsigned Directive | {result:DirectiveResult}；等待回执，超时10 s |
| `remote.pair.start` | CLI owner、agent | owner {relay_url}；兼容 PairOffer | PairSasResult 及 C.1 扩展 |
| `remote.pair.complete` | CLI owner、agent | PairJoinIntent {uri}；兼容 PairAccept | PairSasResult 及公开 binding |
| `remote.pair.confirm` | CLI owner、agent | {sas,confirmed,exclude_global?:false}；兼容 PairConfirm | {}；最终状态读 status.pairing |
| `remote.account.recover` | CLI owner | {account_id,recovery_code,relay_url,software?:false} | {binding:RelayBinding,recovery_code}；owner 一次性显示 |
| `remote.devices.list` | CLI owner | {} | {devices:[DeviceRecord]} |
| `remote.devices.revoke` | CLI owner | {device_id} | {}；Strong 删除证明／墓碑／持久重试 |
| `remote.devices.rename` | CLI owner | {device_id,label} | {}；SetDeviceLabel 及已认证回执 |
| `remote.status` | CLI owner、MCP | {} | {relay,approvers,pending_n,grants_n,unattended,runtime_budget_s,approval,...} |
| `remote.audit.list` | CLI owner | QueryAuditArgs（A.5） | 本机固定链头审计页；不能授予权限 |

这是 R2 冻结快照的 29-op 列表：relay-client 9、hook 2、MCP 4、CLI owner 15、agent 7，重叠操作按该行明确授权。R3 的重新加入扩展需按现行 kv-ipc 单独核对，不能把本表当作新增操作的授权。owner／agent 不能冒充 relay/hook/MCP-only 的 op；MCP 不能签决定、Grant、Directive 或恢复账户。身份由真实 OS transport 决定：Linux peer broker、Mac audit token/code requirement、Windows pipe PID/token SID／固定文件身份／受保护 ACL；不使用模型提交的 PID／角色。

`remote.approval.resolved` 是 helper → 已认证 MCP 的非消费通知，`{op,params:{approval_id,status}}`，不是第三十个可调用 op；无请求正文／结果。Windows 保留 worker 进程句柄，在 ready 前把经 OS 验证 worker PID 绑定 launcher 实际父 PID。

RelayControlJob 为 `{id,relay_url,device_id:字符串或null,command:{op,params?}}`。命令仅 authenticate／register／recover_account／pair_start／pair_complete／pair_finish／messages／ack／challenge／pending／delete_device；pending 使用临时 WS，不接受任意 HTTP 路径。result kind 必须匹配，失败只返回固定代码；HTTP session token 始终在 relay-client。队列最多8、deadline45 s、poll≤30 s；完成／取消后的 ID 不能签名或回执。control.sign pin 首个32B challenge，同一值可重试、换值拒绝，签名结果按完整 DeviceRecord 的 K1 身份规则核对。

outbox 回执绑定完整信封规范 JSON 摘要。poll 丢响应仍返回原信封；客户端先落盘再回 spooled，helper 保存回执后停止 poll 重送；relay 明确接受后回 accepted，再删客户端磁盘前缀。inspect 只有 helper 判断已接受／过期／不再等待的连续队首可退休；遇第一条仍有效即停止。spooled／accepted 的 retired_count 恒为0，迟到回执不会恢复已完成状态。

入站验证／处理与持久审计完成后才 ack；已审计永久拒绝可 ack 防毒队列，存储／审计／provider 暂时失败不能 ack。presence.update 只传粗粒度 hint；helper 签名／加密后经同一 outbox 发送，原始 signals 留本机。

---

### C.1 Owner intent 实现扩展（2026-10-12）

第 2、3 项对接在现有 op 名称和调用方白名单内增加以下参数投影。类型定义共用 `kv-ipc`／`kv-core`，CLI 不提供签名、发行者、对象 ID 或 nonce；这些由 helper 填充。原有 Unsigned 对象兼容路径保留；旧 T2 请求仅附标签会返回 `secondary_confirmation_required`。

| op | 当前 owner 参数／结果扩展 |
| --- | --- |
| `remote.decide` | `{ approval_id, decision, scope, scope_option?, reason?, level? }`；helper 按原始请求、范围和风险选择最低级别，`level` 只能提高级别。remember 时间在实际授权后重新锚定。 |
| `remote.grant.issue` | `GrantIntent = { source: settings \| preauthorization, kind: grant, aud, scope, budget?, nbf, exp, origin: settings, confirm?, confirmation_token? }`；普通签发返回 `{ grant }`。T2 首次返回 `GrantConfirmation = { confirmation_token, expires_at, device_id, label, confirmations_left }`，精确标签确认后才签发。 |
| `remote.directive.issue` | `{ kind: directive, aud, op, args }`；helper 生成签名对象，并等待对应执行端的已认证回执。 |
| `remote.pair.start` / `complete` / `confirm` | owner 分别提交 `{ relay_url }`、`{ uri }`、`{ sas, confirmed, exclude_global?: false }`。开始／加入及配对状态可扩展 `global_grants` 数量、`uri`、`expires_at`、公开 `binding`、一次性 `recovery_code`、`pair_error`。最终完成状态从 `remote.status.pairing` 读取。 |
| `remote.pending.list` | owner 结果额外包含最近 200 条 `recent`，每条有持久递增 `decision_seq`；MCP 的结果不包含 owner 历史。 |
| `remote.grant.list` | 对象 Extra 承载 issued／installed 台账、使用快照和获取时间、各执行端使用量及 `revocation_pending`。审批决定衍生的内部 Grant 保留 `approval_decision` 权威来源，不伪造 Grant 签名。 |

T2 准备令牌最长 120 秒，只保存哈希，绑定调用方 UID／PID／角色、完整意图和当前设备记录，失败的最终尝试也消费令牌。R3-A 桌面 helper 的有限与常设 T2 都令 `confirmations_left` 从 2 开始，第一次精确标签确认交换新令牌和 1，第二次才签发；两轮共享原截止时间。缺省 1 的旧回应仍可被类型解码，但新 CLI 不用于 T2 授权，须成套升级 helper/CLI；手机实现独立验收。准备证明使用与 Grant 不同的签名域，不产生可执行 Grant。

首次注册先保存加密设备身份，再调用 relay，断网重试复用原密钥。已有身份加入仅允许尚无信任关系和授权／审批状态的单设备，并通过受认证迁移日志保持账户、目录和 SQLite 一致。公开绑定只包含 relay URL、设备 ID 和账户 ID；恢复码不保存到该配置。配对 API 的 `expires_at` 和认证结果的 `account_id` 已纳入附录 B 响应字段表。

本地设置使用现有特权控制通道的 `remote_settings`，与远程 Directive 共用 helper 设置后端及 CAS，不扩大 MCP／relay-client 的 op 白名单。桌面确认经已有已认证私有 agent 通道进行；UI 同意不能替代实际 AK 签名。代码／schema、真实模块测试及实机验收边界详见 [第 2、3 项报告](remote-approval-reports/owner-integration-23.md)。

恢复扩展：`remote.account.recover` 只允许 CLI owner，在冷启动时也可调用；不允许 relay-client、MCP、hook 或 agent 发起。结果包含公开 binding 和新的一次性恢复码；没有私钥或 HTTP session token。typed control 的 `recover_account` 仅传固定恢复对象、返回 `recovered`，不得接受任意 URL 路径。helper 将新码和目标绑定先存 vault AEAD 的准备状态，失败重试保留原 DK；已提交而响应丢失时先认证新 DK 并恢复同一新码。

### C.2 管理一致性与分页扩展（2026-10-12）

- `remote.devices.revoke` 在配置 relay 时生成 Strong 删除证明、持久保存 peer 吊销信封并首先撤销本地权威，再投递密文及删除 relay 注册。网络或限流失败保留待重试状态，`remote.status.device_revocations_pending` 显示未完成 relay 删除的数量。离线 peer 由原有 outbox 继续投递；需要新 relay challenge 时由 owner 重试，不在后台绕过 Strong。
- `remote.devices.rename` 针对已连接的远程执行端发送 SetDeviceLabel，并等待已认证回执。执行端设置、SQLite DeviceRecord 和加密目录同时更新，owner 缓存新标签；T2 标签确认使用该记录。只有 label 可变，密钥／能力变更必须重新建立权威。relay 的配对注册校验同样区分 label 与不可变身份。
- SQLite 与加密目录通过加密 prepare 日志、SQLite `directory_commits` 标记和提交后发布保持同一提交决定。重开时提交标记存在则完成发布，否则丢弃准备日志。审计或 SQLite 回滚不会发布新目录；这不提供 T04 的硬件反回滚；独立审计检查点的已实现范围和边界见 §11。
- `remote.grant.list` 和 QueryGrants Directive 的 args 均为 `{ after?: jti, limit?: 50 }`。limit 为 1–100，after 最长 256 字节且无控制字符；按 jti 排序，返回 `{ grants: […], next_cursor: jti | null }`。单页元数据正文不超过 48 KiB；超大对象返回显式 `object_omitted: true` 的有限摘要，不附带伪造签名。列表是元数据，不能作为新的授权对象安装。
- CLI 自动获取后续页再渲染完整列表，重复游标报协议错误。移动端用 Quick 签发有游标绑定的后续 QueryGrants，并合并各页；既有信封重放保护防止重复续页。分页期间授权变更可能影响快照，列表不承诺跨页事务快照。

## 附录 D. 当前 SQLite DDL

下面逐字收录两个 schema.sql（2026-10-14）；不把概念表当实际迁移。helper 的完整 record_json／object_json／authority_json 保留签名字段与扩展，dk_sig 无独立列也不会丢失。server v3 保存完整 record BLOB、人类身份／会话与持久 push_jobs；push 生命周期 trigger 由运行时初始化，见 R2-C。

### D.1 helper（执行端／审批端共用）

```sql
-- Appendix D columns remain stable; lossless signed objects use explicit extension columns.
PRAGMA foreign_keys = ON;
PRAGMA journal_mode = WAL;
PRAGMA synchronous = FULL;
CREATE TABLE IF NOT EXISTS devices (
  id TEXT PRIMARY KEY, account_id TEXT NOT NULL, label TEXT NOT NULL, os TEXT NOT NULL, key_kind TEXT NOT NULL,
  dk_pub TEXT NOT NULL, akq_pub TEXT, akq_alg TEXT, aks_pub TEXT, aks_alg TEXT,
  caps TEXT NOT NULL, attestation BLOB, trust TEXT NOT NULL, added_at INTEGER NOT NULL, revoked_at INTEGER,
  record_json TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS directory_commits (id TEXT PRIMARY KEY);
CREATE TABLE IF NOT EXISTS device_revocations (device_id TEXT PRIMARY KEY,body_json TEXT NOT NULL,relay_done INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS device_revocation_targets (device_id TEXT NOT NULL,peer TEXT NOT NULL,envelope_json TEXT NOT NULL,
  PRIMARY KEY(device_id,peer));
CREATE TABLE IF NOT EXISTS pending_approvals (
  id TEXT PRIMARY KEY, kind TEXT NOT NULL, digest TEXT NOT NULL, nonce TEXT NOT NULL, canonical_json TEXT NOT NULL,
  exp INTEGER NOT NULL, state TEXT NOT NULL, created_at INTEGER NOT NULL, resolved_at INTEGER,
  approver TEXT, level TEXT, scope_json TEXT, agent_pid INTEGER, agent_runtime TEXT,
  stop_hook_blocks INTEGER NOT NULL DEFAULT 0, claimed_at INTEGER, escalated_at INTEGER,
  request_json TEXT NOT NULL, decision_json TEXT, session_id TEXT NOT NULL, epoch INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS nonces (nonce TEXT PRIMARY KEY, digest TEXT NOT NULL, used_at INTEGER NOT NULL, exp INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS grants (
  jti TEXT PRIMARY KEY, iss TEXT NOT NULL, iss_alg TEXT NOT NULL, aud TEXT NOT NULL, level TEXT NOT NULL, credential TEXT,
  hosts_json TEXT, methods_json TEXT, paths_json TEXT, agent TEXT, max_tier TEXT NOT NULL,
  budget_json TEXT, budget_left_json TEXT, nbf INTEGER, exp INTEGER, origin TEXT NOT NULL, sig TEXT NOT NULL,
  installed_at INTEGER NOT NULL, revoked_at INTEGER, object_json TEXT NOT NULL, authority_json TEXT NOT NULL,
  session_id TEXT);
CREATE TABLE IF NOT EXISTS directives (id TEXT PRIMARY KEY, iss TEXT NOT NULL, op TEXT NOT NULL, args_json TEXT NOT NULL,
  applied_at INTEGER NOT NULL, ok INTEGER NOT NULL, error TEXT);
CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value_json TEXT NOT NULL, set_by TEXT NOT NULL, set_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS revoked_jti (jti TEXT PRIMARY KEY, revoked_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS issued_approvals (approval_id TEXT PRIMARY KEY, peer TEXT NOT NULL, kind TEXT NOT NULL, digest TEXT NOT NULL,
  decision TEXT NOT NULL, level TEXT NOT NULL, scope_json TEXT, issued_at INTEGER NOT NULL, summary_text TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS approval_history (seq INTEGER PRIMARY KEY AUTOINCREMENT,
  approval_id TEXT NOT NULL UNIQUE REFERENCES issued_approvals(approval_id));
CREATE TABLE IF NOT EXISTS issued_grants (jti TEXT PRIMARY KEY, peer TEXT NOT NULL, level TEXT NOT NULL, credential TEXT, max_tier TEXT NOT NULL,
  exp INTEGER, origin TEXT NOT NULL, issued_at INTEGER NOT NULL, revoked_at INTEGER);
CREATE TABLE IF NOT EXISTS issued_directives (id TEXT PRIMARY KEY, peer TEXT NOT NULL, op TEXT NOT NULL, issued_at INTEGER NOT NULL,
  result_ok INTEGER, result_summary TEXT);
CREATE TABLE IF NOT EXISTS issued_grant_objects (jti TEXT PRIMARY KEY REFERENCES issued_grants(jti), object_json TEXT NOT NULL,
  issued_at INTEGER NOT NULL, revoked_at INTEGER);
CREATE TABLE IF NOT EXISTS issued_grant_usage (jti TEXT NOT NULL REFERENCES issued_grants(jti), peer TEXT NOT NULL,
  usage_json TEXT NOT NULL, fetched_at INTEGER NOT NULL, PRIMARY KEY(jti,peer));
CREATE TABLE IF NOT EXISTS issued_grant_revocations (jti TEXT PRIMARY KEY REFERENCES issued_grants(jti),
  requested_at INTEGER NOT NULL, confirmed_at INTEGER);
CREATE TABLE IF NOT EXISTS issued_grant_revocation_targets (jti TEXT NOT NULL REFERENCES issued_grant_revocations(jti),
  peer TEXT NOT NULL, confirmed_at INTEGER, PRIMARY KEY(jti,peer));
CREATE TABLE IF NOT EXISTS issued_directive_objects (id TEXT PRIMARY KEY REFERENCES issued_directives(id), object_json TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS grant_use_stats (jti TEXT PRIMARY KEY REFERENCES grants(jti), uses_n INTEGER NOT NULL, last_used_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS peer_state_cache (peer TEXT PRIMARY KEY, mode TEXT, unattended INTEGER, grants_count INTEGER, pending_count INTEGER,
  presence TEXT, last_seen INTEGER, fetched_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS remote_outbox (
  seq INTEGER PRIMARY KEY AUTOINCREMENT, envelope_json TEXT NOT NULL, exp INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS remote_outbox_receipts (
  envelope_hash TEXT PRIMARY KEY, stage TEXT NOT NULL, exp INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS remote_audit (
  seq INTEGER PRIMARY KEY AUTOINCREMENT, entry_json TEXT NOT NULL, prev_hash TEXT NOT NULL, entry_hash TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS inbound_approvals (
  id TEXT PRIMARY KEY, peer TEXT NOT NULL, object_json TEXT NOT NULL, state TEXT NOT NULL,
  exp INTEGER NOT NULL, receipt_seq INTEGER NOT NULL REFERENCES remote_audit(seq));
CREATE INDEX IF NOT EXISTS pending_agent ON pending_approvals(agent_pid, state, exp);
CREATE INDEX IF NOT EXISTS grants_issuer ON grants(iss, revoked_at);
CREATE INDEX IF NOT EXISTS inbound_exp ON inbound_approvals(state, exp);
```

pending_approvals 状态为 waiting／approved／approved_unused／executed／denied／expired／cancelled；devices 信任来源含 verified_sas／recovery／revoked。完整请求／执行结果只在内存，不写 request_json 的公开快照。实际授权同时受 vault 加密目录与审计检查点约束，不把 SQLite 私有权限当硬件反回滚。

审批端的 `inbound_approvals` 状态为 waiting／issued／cancelled／expired；object_json 保留原签名信封和审批对象，receipt_seq 引用包含该对象哈希与状态的最新审计收据。入站签名、HPKE、角色验证和事务／vault 检查点提交成功后才 ACK；重启先验证检查点、目录与最新收据，再重验当前执行端的身份签名和权限，恢复尚未到期的 waiting。取消、签发和过期状态不恢复为 waiting；签发与 outbox／ledger 同事务提交。恢复过程不再次调用硬件 ECDH，不能恢复旧版本已 ACK 后完全丢失的对象，也不提供全备份硬件反回滚或外部 HTTP exactly-once。

### D.2 relay-server（schema v3）

```sql
PRAGMA foreign_keys = ON;
PRAGMA secure_delete = ON;

CREATE TABLE IF NOT EXISTS accounts (
    id TEXT PRIMARY KEY,
    created_at INTEGER NOT NULL,
    recovery_hash TEXT NOT NULL,
    plan TEXT NOT NULL DEFAULT 'self_hosted'
);
CREATE TABLE IF NOT EXISTS devices (
    id TEXT PRIMARY KEY,
    account_id TEXT NOT NULL REFERENCES accounts(id),
    dk_pub TEXT NOT NULL UNIQUE,
    akq_pub TEXT, akq_alg TEXT, aks_pub TEXT, aks_alg TEXT,
    key_kind TEXT NOT NULL, attestation BLOB, os TEXT NOT NULL,
    caps TEXT NOT NULL, label TEXT NOT NULL,
    created_at INTEGER NOT NULL, revoked_at INTEGER, last_seen INTEGER,
    record BLOB NOT NULL, push_token BLOB
);
CREATE INDEX IF NOT EXISTS devices_account ON devices(account_id);
CREATE TABLE IF NOT EXISTS sessions (
    token_hash TEXT PRIMARY KEY,
    device_id TEXT NOT NULL REFERENCES devices(id),
    exp INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS sessions_device ON sessions(device_id);
CREATE TABLE IF NOT EXISTS pairings (
    pairing_id TEXT PRIMARY KEY, token_hash TEXT UNIQUE,
    account_id TEXT NOT NULL REFERENCES accounts(id),
    initiator_device TEXT NOT NULL REFERENCES devices(id),
    initiator_pubs BLOB NOT NULL, joiner_pubs BLOB,
    joiner_device TEXT REFERENCES devices(id),
    state TEXT NOT NULL CHECK(state IN ('offered', 'accepted', 'finished', 'expired')),
    exp INTEGER NOT NULL, initiator_finished INTEGER NOT NULL DEFAULT 0,
    joiner_finished INTEGER NOT NULL DEFAULT 0, sas_hash TEXT
);
CREATE INDEX IF NOT EXISTS pairings_joiner ON pairings(joiner_device, state);
CREATE TABLE IF NOT EXISTS used_pair_tokens (
    token_hash TEXT PRIMARY KEY, exp INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS approvals (
    id TEXT NOT NULL, account_id TEXT NOT NULL REFERENCES accounts(id),
    requester TEXT NOT NULL REFERENCES devices(id),
    state TEXT NOT NULL CHECK(state IN ('waiting', 'resolved', 'cancelled', 'expired')),
    exp INTEGER NOT NULL, resolved_by TEXT REFERENCES devices(id), resolved_at INTEGER,
    PRIMARY KEY(account_id, id)
);
CREATE TABLE IF NOT EXISTS messages (
    id TEXT NOT NULL, account_id TEXT NOT NULL REFERENCES accounts(id),
    from_device TEXT NOT NULL REFERENCES devices(id),
    to_device TEXT NOT NULL REFERENCES devices(id), type TEXT NOT NULL,
    envelope BLOB NOT NULL, created_at INTEGER NOT NULL, exp INTEGER NOT NULL,
    delivered_at INTEGER, acked_at INTEGER,
    PRIMARY KEY(account_id, id, to_device, type)
);
CREATE INDEX IF NOT EXISTS messages_inbox ON messages(to_device, acked_at, exp);
CREATE INDEX IF NOT EXISTS approvals_waiting ON approvals(account_id, state, exp);

CREATE TABLE IF NOT EXISTS push_jobs (
    account_id TEXT NOT NULL, id TEXT NOT NULL, to_device TEXT NOT NULL,
    type TEXT NOT NULL, mode TEXT NOT NULL CHECK(mode IN ('silent','banner')),
    attempts INTEGER NOT NULL DEFAULT 0, next_attempt INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    PRIMARY KEY(account_id,id,to_device,type),
    FOREIGN KEY(account_id,id,to_device,type)
        REFERENCES messages(account_id,id,to_device,type) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS push_jobs_due ON push_jobs(next_attempt,expires_at);

CREATE TABLE IF NOT EXISTS login_users (
    id TEXT PRIMARY KEY, provider TEXT NOT NULL, subject TEXT NOT NULL,
    email TEXT NOT NULL, display_name TEXT NOT NULL, created_at INTEGER NOT NULL,
    UNIQUE(provider,subject)
);
CREATE TABLE IF NOT EXISTS device_users (
    device_id TEXT PRIMARY KEY REFERENCES devices(id),
    user_id TEXT NOT NULL REFERENCES login_users(id)
);
CREATE TABLE IF NOT EXISTS account_owners (
    account_id TEXT PRIMARY KEY REFERENCES accounts(id) ON DELETE CASCADE,
    user_id TEXT NOT NULL REFERENCES login_users(id)
);
CREATE TABLE IF NOT EXISTS login_attempts (
    id TEXT PRIMARY KEY, provider TEXT NOT NULL, nonce_hash TEXT NOT NULL,
    state TEXT NOT NULL UNIQUE, device BLOB NOT NULL, exp INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS account_sessions (
    token_hash TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES login_users(id),
    device_id TEXT NOT NULL REFERENCES devices(id), exp INTEGER NOT NULL,
    created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS device_session_users (
    token_hash TEXT PRIMARY KEY REFERENCES sessions(token_hash) ON DELETE CASCADE,
    account_session TEXT NOT NULL REFERENCES account_sessions(token_hash) ON DELETE CASCADE
);

PRAGMA user_version = 3;
```

server 启动另启用 WAL；账户／会话／token 清理与迁移按生产初始化代码执行。表结构与字段类型来自源码，未知 DeviceRecord 字段在 record／record_json 中保留，旧设备记录无需补 dk_sig 列。

---

## 附录 E. 当前 CLI 与 MCP 面

以下为仓库构建的 kv-cli remote --help；另以 relay／pair／devices／approvals／grant／audit --remote／status --help 核对各 family。所有远程 family 接受 --json，pair/watch 输出 JSON Lines；恢复码只从隐藏输入或 stdin 读取，不能进 argv／证据。

```text
relay install|status|set-url|recover
pair --new | pair <kv-pair://...>
devices list|revoke <id>|rename <id> <label>
approvals [--watch] [--on-approve <cmd>] | approve <id> [--scope ...] | deny <id> [--reason ...]
grant ...|list|revoke <jti>|revoke-all
remote <device|label|*> mode <per_use|per_credential|per_session|remember:Nh>
remote <device|label|*> allow <--credential type/name|--all> [--hosts ...] [--methods ...] [--paths ...] [--agent ...] [--until duration|RFC3339|--standing]
remote <device|label|*> unattended --include-sensitive --until <duration|RFC3339>
remote <device|label|*> lock
remote <device|label|*> unlock-ttl <hours|duration>
remote <device|label|*> class <name> [--credential pattern] [--host pattern] --exp <duration>
remote <device|label|*> label <label>
remote <device|label|*> notify <prefer-local|always-phone|both>
remote <device|label|*> status|pending|grants
remote <device|label|*> audit [--since duration|RFC3339] [--limit 1..200]
remote <device|label|*> grant revoke <jti> | revoke-all
status [--summary]
```

family 的补充语法：

```text
relay install [--listen 127.0.0.1:8787] [--data /var/lib/keyvalet-relay-server] --public-url https://relay.example.com [--root /staging]
relay status [--public-url URL]
relay recover <account-id> [--public-url URL] [--software] [--json]
approve <id> [--scope per_use|per_credential|per_session|remember:1h|remember:8h|remember:24h|standing:credential|standing:device]
deny <id> [--reason <text>]
grant --to <device|label|*> --credential type/name [--hosts host,...] [--methods GET,POST] [--paths /path,...] [--budget calls/1h|24h|7d] --until <duration|RFC3339> [--agent identity]
grant list | grant revoke <jti> | grant revoke-all
audit --remote [--device <device|label>] [--since duration|RFC3339] [--limit 1..200] [--json]
```

remote audit 的 help／parser 与 QueryAudit/helper 均接受 limit 1..200；201 及以上在 CLI 拒绝，T12 已有边界回归。CLI unattended 无 --standing，也没有非交互 --yes 跳过标签；不把手机常设 T2 的实现写成 CLI flag。

| 退出码 | 当前含义 |
| --- | --- |
| 0 | 成功，包括 watch 正常中断；audit 无差异且查询完整 |
| 2 | 参数错误、未知／歧义标签 |
| 3 | 验证／授权拒绝、协议响应错误或本地失败；audit 差异／缺口 |
| 4 | 超时或过期，包括 pairing／Directive 回执等待 |
| 5 | relay/helper/control transport 不可达／未就绪；status --summary 可仅展示本地公开状态与 remote_error |
| 6 | Strong 或终端确认取消、缺少二次确认 |

MCP 工具 credential_wait_approval：

```json
{"name":"credential_wait_approval","inputSchema":{"type":"object","required":["approval_id"],"properties":{"approval_id":{"type":"string"},"max_wait_s":{"type":"integer","minimum":5,"maximum":600}}}}
```

批准后返回原请求结果，不能重发原调用；approved_retry_required 才允许同参数／同 ID 恢复。使用类工具新增可选 approval_id，credential_status.remote_approval 见 §9.4，content[0].text 的 JSON 状态见 A.8，isError=false。模型文案说明 pending 继续等、denied 不绕路、expired 按需新建、cancelled 先确认新意图，不索要 key。SDK HTTP 与跨 session 边界见 §6.9.2。

---

## 附录 F. 代码布局、依赖与测试向量

kv-server（bin、relay feature 默认开）、kv-relay-client（bin/library control transport）、kv-mobile-core（staticlib/cdylib/rlib）、kv-push（bin）已加入 workspace 并实现，不再是空骨架。底层 provider／presence trait 在 kv-ipc，core typed adapter 无平台循环；mobile 用关闭默认桌面依赖的 core remote feature。

生产 HPKE 使用现有 p256/hkdf/aes-gcm 组合，让 ECDH 委托硬件 provider；hpke 0.12 为 dev-only 独立参考实现。JCS 为 serde_jcs，HTTP/WS 为 axum/tokio-tungstenite，SQLite 为 rusqlite。CLI QR 使用已批准 qrcode=0.14.1、关闭 image 默认 feature。依赖选择／发布时间与各工作流归属见 W0–W9、v1-completion，R2-B/C/D 没有新增运行依赖。

向量在 rust/crates/kv-core/testdata/remote。当前 32 个 JSON 清单如下，全部带 expect；测试从 CARGO_MANIFEST_DIR 加载，不依赖本机安装、Python 或外网。generate.py 用独立 Python cryptography 生成自定义向量；RFC 9180 P-256 base suite16/1/1 与 hpke 参考同时验证。

```text
approval_request_digest.json
decision_replayed.json
decision_valid.json
decision_validation_cases.json
decision_wrong_key.json
device_record_with_dk_sig_envelope.json
device_record_with_dk_sig_legacy.json
device_record_with_dk_sig_pair_sas.json
device_record_with_dk_sig_tampered.json
device_record_with_dk_sig_valid.json
device_record_with_dk_sig_wrong_dk.json
directive_loosen_quick_rejected.json
directive_tighten_quick_ok.json
envelope_rejections.json
envelope_roundtrip.json
envelope_tampering.json
grant_standing_t1.json
grant_t2_requires_settings.json
grant_validation_cases.json
ipc_contracts.json
jcs.json
jcs_numbers.json
owner_intent_contracts.json
pair_sas.json
path_normalization.json
provider_adapter.json
relay_contract_extensions.json
rfc9180_p256_base.json
rs256_decision.json
schema_rejections.json
schema_samples.json
test_keys.json
```

| K1 新向量 | expect 覆盖 |
| --- | --- |
| device_record_with_dk_sig_valid.json | 完整记录 JCS／SHA256／签名／未知字段 roundtrip |
| device_record_with_dk_sig_wrong_dk.json | dk_sig 验成功，同签名用 dk_pub 必失败 |
| device_record_with_dk_sig_tampered.json | 篡改 dk_sig 嵌套扩展使完整记录签名失败 |
| device_record_with_dk_sig_legacy.json | 缺失字段仍缺失，旧 dk_pub 身份签名成功 |
| device_record_with_dk_sig_envelope.json | split 签名与旧 HPKE 接收键互操作；错误 DK 拒绝 |
| device_record_with_dk_sig_pair_sas.json | 新域 SAS，换 signing key／扩展改变 SAS；旧域不变 |

R2-B 对其动手前24个旧向量逐字节核对保持；schema_samples 有意更新、ipc_contracts 有并行扩展，不能将所有32个文件称为原始未改。K4/D04/D05 的接收拒绝条件与负向向量已在 R3-B 无签名修复中完成；Grant 相关 schema／样例有意同步，其他向量逐字节保持。

日志与审批／模型文案使用 kv-i18n 中英文本；调试日志也不允许凭证值、完整 body、ct、私钥、恢复码、配对／会话令牌。证据只保存脱敏事件、数字和公开结果。
