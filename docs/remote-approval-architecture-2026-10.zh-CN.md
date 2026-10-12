# 远程审批与多设备配对：架构设计

- 版本：第二版（2026-10-11，评审后）。第一版写于同日，评审时把手机 App 纳入第一版、把实施计划改成可并行的工作流，并补齐附录里的接口契约。
- 范围：把审批动作从「agent 所在的机器」搬到「用户手边的设备」，让多台机器互相认识，并把审批端做成执行端的远程控制面（授权边界与设置）。**第一版（V1）**：执行端覆盖 macOS / Linux / Windows；审批端覆盖 **手机 App（Flutter，iOS + Android）**、macOS（Touch ID）与 Windows（Hello）的原生弹窗 + 终端。首个 dogfooding 实例是 **Ubuntu 服务器（vault + 执行端）+ MacBook / iPhone（审批端）+ 自托管 relay**。云端密钥保护与隔离执行只留接口。
- 怎么读：§0–§13 是设计；§14–§16 是失败模式、代码落点、测试；§17 是**按工作流拆分的 V1 实施计划**（给多个并行 agent 用，配套 prompt 见 [remote-approval-agent-prompts-2026-10.zh-CN.md](remote-approval-agent-prompts-2026-10.zh-CN.md)）；附录 A–F 是各工作流之间的**接口契约**（JSON 形状、relay API、IPC 消息、DDL、CLI/MCP 面、crate 布局）。契约与正文冲突时以附录为准。
- 与现有文档的关系：本文是 [architecture-2026-10.md](architecture-2026-10.md) §7.4（Approver）、§8.1（设备密钥）、§8.3（配对）、§9（路由）、§10.3（relay）的细化与修订。冲突处以本文为准，并在落地时回写总架构文档。产品侧见 [remote-approval-product-2026-10.zh-CN.md](remote-approval-product-2026-10.zh-CN.md)。
- 现状：**以下全部尚未实现**。Linux 现有实现见 [linux.md](linux.md)（systemd 服务、polkit、TPM 2.0、SSH `keyvalet approve <pid>`）；macOS 现有实现见 README 与 SECURITY.md。

---

## 0. 决策摘要

| # | 决策 | 一句话理由 |
| --- | --- | --- |
| D1 | 凭证留在 Ubuntu 服务器的 vault 里，由服务器上的 helper 注入执行；MacBook 只做审批，不做执行端 | 服务器上的 agent 要 7×24 跑，MacBook 合盖就离线；Secure Enclave 又要求 GUI 会话。总架构 §9 的「Linux 调 Mac 执行」保留为后续可选路由，不是第一版 |
| D2 | 第一天就有 relay，不做 Mac↔Ubuntu 直连 | 直连无法在 MacBook 睡眠时排队；helper 不能开入站端口 |
| D3 | relay 先自托管（可以就装在这台 Ubuntu 上），官方 relay 之后 | 用户已有服务器；relay 只见密文，和 vault 同机不扩大泄露面，只耦合可用性 |
| D4 | MacBook、Windows 与手机 App 共用总架构里的「审批设备」模型：同一套设备密钥、HPKE 信封、Quick/Strong 两档 | 任何一种审批端都只是多一台设备，协议不变 |
| D5 | 每台设备的**身份密钥**与**审批密钥**是不同的密钥对象 | 身份密钥要无人值守签名（relay 认证、信封签名），审批密钥要求用户在场（Touch ID）。总架构 §8.1 已有此要求 |
| D6 | 审批决定签名覆盖 `digest ‖ nonce ‖ decision ‖ scope`，执行端重算 digest；一次性 nonce 落库 | 防重放、防「批了 A 执行 B」。沿用总架构 §7.2–7.3 |
| D7 | 预授权能力令牌（§7.5）是第一版必备，不是可选 | 无人值守机器上「每次都弹」等于逼用户开全放行；没有预授权就没有产品 |
| D8 | 任何一环拿不到合法批准都 fail closed；没有确认码、没有软件回退 | 与 Linux 现有实现一致 |
| D9 | 服务器 root 不在威胁模型内，与 macOS 一致 | 远程审批不给普通 Linux helper 增加抵御 root 的隔离；文档、状态、弹窗都要如实写 |
| D10 | 审批超时只产生「待批准」，永不映射成「拒绝」；agent 侧用「调用内等待 → 放手 → 续等工具 → Stop hook / channels 唤醒」四层保证每个运行时都有路走 | 各家 agent 的工具调用超时从 60 s 到 28 h 不等、推送能力只有 Claude Code 有；把「不」留给用户，把等待交给可阻塞的工具调用（§6.9） |
| D11 | 审批端不只是「批/拒」，还是执行端的**远程控制面**：所有授权边界（这一次 / 1 小时 / 本会话 / 这个凭证一直允许 / 这台机器一直允许 / 全局无人值守）和设置（模式、锁定、吊销、会话寿命）都是审批端用审批密钥**签名的 Grant / Directive 对象**，经 relay 下发，执行端只认签名不认来源 | 一套对象模型同时覆盖弹窗里的范围选择、预授权令牌和设置页；收紧用 Quick，放宽必须 Strong；以后 iPhone App、Web 控制台、团队策略都是同一条路（§7.4–7.6） |
| D12 | 第一版只实现本地硬件密钥，但密钥保护、执行端、审批者、授权签发者四条线都在 V1 就留出接口与枚举位，云 KMS、Nitro Enclave、Web 设备密钥、服务型审批者只加实现不改协议 | 协议字段一旦上线就难改；接口与保留字段的成本很低（§13） |
| D13 | 执行端第一版就覆盖 macOS / Linux / Windows；审批端第一版覆盖**手机 App（Flutter，iOS + Android）**以及 macOS（Touch ID）与 Windows（Hello）的原生弹窗 + 终端；手机 App 是唯一的图形审批/控制面，桌面不做图形设置页，Web 只随 Team 服务 Lead | 用户与 Team 买家都是混合 OS；无头机器的用户只有手机在手边；Windows Hello 只有 RSA-2048，所以签名算法按密钥记录决定（`ES256` / `RS256`），而不是写死 |
| D14 | V1 按**工作流**并行实施，不按时间串行：先冻结附录里的接口契约与测试向量，再让 relay、relay-client、设备密钥、helper、MCP/hook/proxy、桌面 agent、CLI、手机 App、安装器各自独立推进，最后一个集成工作流收口 | 要让多个 agent 同时干活，唯一可行的协作方式是「契约先行 + crate 级所有权」；谁都不能改别人的 crate，契约变更只能由契约所有者改并同步测试向量（§17） |

---

## 1. 要解决的问题与边界

### 1.1 问题

KeyValet 现在的审批发生在 agent 所在机器上：macOS 弹 Touch ID，Linux 走 polkit（桌面 agent 或 SSH 上的 `pkttyagent`）。当 agent 跑在无人值守的机器上——Ubuntu 服务器、拔了显示器的 Mac mini、CI runner——没有人在旁边按，结果只有两个：agent 卡死，或者用户被迫把一切设成自动放行。

### 1.2 第一版要做到

1. Ubuntu 服务器上的 agent（Claude Code / Codex / OpenClaw / Hermes / cron 脚本）发起凭证使用请求时，用户在 MacBook 上收到带完整真实请求的审批弹窗，Touch ID 一下，服务器上的 helper 才注入执行。
2. MacBook 和 Ubuntu 通过一次配对互相认识；之后可以再加第二台 Mac，也可以吊销任一台。
3. 用户可以在 MacBook 上一次性签发「今天 500 次以内对 `api.github.com` 的 GET/POST」这类预授权，服务器上符合范围的调用不再打扰人。
4. MacBook 合盖、离线、relay 不可达时，行为可预期：请求排队或超时，绝不放行。
5. 两端都有审计：服务器记「谁批的、多久批的」，MacBook 记「我批了什么给哪台机器」。
6. 用户没有立刻批时，Claude Code、Codex、Cursor、Gemini、Devin、Grok 以及走 HTTP 的 OpenClaw / Hermes / SDK 上的 agent 都不会把超时当成拒绝，并且在用户随后批准时能在不重新下指令的情况下拿到结果（§6.9）。
7. 审批端连上之后就是执行端的遥控器：在弹窗里选「这一次 / 1 小时 / 本会话 / 这个凭证一直允许 / 这台机器一直允许 / 全局无人值守」，在设置页改模式、锁定、吊销、看审计；收紧立刻生效，放宽必须 Touch ID / Hello（§7.4–7.6）。
8. 执行端在 macOS / Linux / Windows 上都能跑；审批端是手机 App（iOS + Android）加 macOS / Windows 的原生弹窗 + 终端（§2.3、§3.1、§9.2）。手机 App 在 V1 内：锁屏 Quick / 生物识别 Strong 审批、每台执行端的设置页、放行票与一键收回、无人值守开关、扫码配对、活动摘要、推送与静默/升级投递。
9. 云 KMS、Nitro Enclave、Web 控制台、服务型审批者在协议与接口上已经有位置，第一版不实现（§13）。

### 1.3 第一版不做

- Linux 桌面作为审批端（V2）；桌面图形设置页（不做）；瘦菜单栏/托盘（V2，按需）；Mac 作为 Linux 的执行端（§9 路由，V2）；vault 密文跨设备同步与「在手机上走 OAuth 添加凭证」（V2，V1 在执行端终端添加凭证）；团队 N-of-M 审批与 Web 控制台（随 Team）；官方托管 relay 的计费与配额执行（接口保留）；App Store / Play 公开上架（V1 走 TestFlight 与内部测试轨道）。
- 云端密钥保护与隔离执行的**实现**（只留接口，§13）。
- 不改变 Linux / Windows helper 的隔离边界：远程审批不让它防 root / SYSTEM。

---

## 2. 拓扑与进程

```
┌─ Ubuntu 服务器（vault + 执行端）──────────────────────────────────────────────┐
│  agent 进程（普通用户 u，例如 claude / codex / openclaw / cron）                  │
│     │  kv-mcp · kv-hook · keyvalet run / 网关（用户 u，不持任何秘密）              │
│     │  IPC v4：Unix socket，SO_PEERCRED                                           │
│     ▼                                                                             │
│  kv-helper（systemd，系统用户 keyvalet，/var/lib/keyvalet 0700，无入站、无长连接）  │
│     vault 密文 · TPM 主密钥 · TPM 身份密钥 DK_srv · devices · nonces · grants      │
│     Approver 选择：polkit（本地）│ remote-device（新）│ capability token │ auto    │
│     │  IPC：/var/run/keyvalet/relay.sock（仅允许 keyvalet-relay 用户）              │
│     ▼                                                                             │
│  kv-relay-client（systemd，系统用户 keyvalet-relay，唯一出站进程）                 │
│     WS 长连接到 relay · HPKE 封装/解封 · 请签名时经 IPC 请 helper 用 DK_srv 签       │
│                                                                                   │
│  kv-server --features relay（可选同机部署；SQLite；只见密文）                       │
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
| `kv-relay-client` | Ubuntu | 新系统用户 `keyvalet-relay` | relay 会话令牌、对端公钥缓存、待发/待收信封 | 任何私钥、任何秘密明文（信封内容对它是密文：它只做 HPKE 封装，解封在 helper 内） |
| `keyvalet-peer.service` | Ubuntu（Linux 6.5+） | root，仅 `CAP_SYS_PTRACE` | Unix socket 的内核 PID/UID、安装执行文件与角色映射 | 不处理 vault、私钥、网络连接、批准或执行操作 |
| `kv-server`（relay） | Ubuntu 或别处 | 容器 / 系统用户 | 设备公钥、账户、密文 blob、时间戳 | 明文、UMK、凭证元数据 |
| `kv-relay-client` | Mac | 当前用户（LaunchAgent） | 同上 | 同上 |
| `dev.keyvalet.helper` | Mac | root | Mac 本地 vault、peers、本机签发记录、审计 | 出站长连接 |
| `dev.keyvalet.agent` + `kv-touchid` | Mac | 当前用户（GUI 会话） | SE 密钥操作、审批对话框 | 任何明文（远程审批不涉及 Mac 本地凭证） |
| 手机 App 主进程（Flutter + `kv-mobile-core` + `kv_native`） | iPhone / Android | App 沙箱 | 设备密钥句柄（SE / Keystore）、peers、待批队列、签发记录（SQLite） | 任何凭证值；Dart 层不持私钥、不验签 |
| iOS NSE / Android 消息服务 | 手机 | 扩展 / 服务进程 | 同一 Rust 库、App Group 里的密文队列与设备密钥加密表示 | 审批密钥的使用权（Quick/Strong 签名只在主 App 内发生） |
| `kv-push` | 云（美国） | 容器 | APNs 密钥、FCM 服务账号、设备推送令牌 | 审批内容（只转发 `approval_id` 与 `delivery.mode`） |

**信封的加解密在哪一侧完成是关键细节。** 为了让 `kv-relay-client` 不持私钥，HPKE 解封（需要身份私钥做 ECDH）在 helper 内完成：relay-client 收到信封 → 原样经 IPC 交给 helper → helper 用 TPM/SE 做 ECDH、解封、验签。封装方向只需要对方公钥，relay-client 可以自己做，但为统一审计路径，第一版也交给 helper。relay-client 退化为「带重连的管道 + 本地队列」。

注册、配对和吊销的 HTTP/临时 WS 也由 relay-client 执行。尚未配对时服务先运行控制 worker，经附录 C 的有界控制队列领取 helper 已构造的请求；helper 自己签 DK challenge 和 Strong 证明，不接收 relay 会话令牌。完整配置绑定出现或改变后，客户端启动或重建长连接。

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
| 审批端 | V1。Touch ID；Quick/Strong 两把 SE 键 | V2。桌面 polkit `auth_self` 作在场门，TPM/软件键签名；状态永远标 `presence: polkit`（非硬件在场） | V1。Hello `KeyCredentialManager` RSA-2048 作 Strong 键（每次签名要求在场）；PCP TPM P-256 作 Quick 与身份键 | **V1**。iOS：SE 三把键（§3.1）；Android：Keystore（StrongBox 优先）三把键，`AK_s` 生物绑定；锁屏 Quick / 生物识别 Strong；唯一的图形设置面 |
| `kv-relay-client` | per-user LaunchAgent `dev.keyvalet.relay`，helper 以 audit token + code requirement 校验 | systemd `keyvalet-relay.service`，专用系统用户，`SO_PEERCRED` 校验 | Windows 服务 `KeyValetRelay`，虚拟服务账户 `NT SERVICE\KeyValetRelay`，经 `\\.\pipe\keyvalet-relay` 连 helper，管道 DACL 只给该 SID + SYSTEM，helper 用 `GetNamedPipeClientProcessId` 校验 | 内置于 `kv-mobile-core`（前台 WS）；后台靠 APNs / FCM 唤醒后拉取 |
| 本地审批后备 | Touch ID 对话框 | SSH `keyvalet approve <pid>` | 登录会话内 Hello；无会话则无后备（只能远程） | 不适用（手机不是执行端） |
| 安装器 | `install.sh` | `install.sh` | `install.ps1` + winget；依赖 Authenticode 签名就绪（见总架构 §8.1.1） | TestFlight / Play 内部测试轨道（V1）；公开上架 V2 |

---

## 3. 密钥与身份

### 3.1 设备密钥

每台设备至少两类密钥对象。HPKE 固定为 `DHKEM(P-256, HKDF-SHA256) + HKDF-SHA256 + AES-128-GCM`（与总架构 §8.1 一致，适配 SE/TPM/PCP 的 ECDH 能力）；**签名算法不写死**，由设备记录里的 `alg` 决定：`ES256`（P-256）或 `RS256`（RSA-2048，Windows Hello 唯一支持的形态）。身份密钥必须是 P-256（HPKE 需要），审批密钥可以是任一种。

| 密钥 | Linux（TPM 2.0） | Linux（显式软件） | macOS（Secure Enclave） | Windows 11 | iOS / Android（手机 App） | 用途 | 用户在场 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 身份密钥 `DK`（P-256） | 新建 TPM ECC 对象，`sign`+`decrypt`，`fixedTPM`/`fixedParent`，与现有 vault 主密钥是**不同对象** | `0600` 文件，状态报 `software_key` | 新建 SE `P256`，`kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`，无生物 ACL | NCrypt Platform Crypto Provider（TPM）P-256，ECDH + ECDSA；无 TPM 则 DPAPI 保护的软件键，状态报 `software_key` | iOS：SE `P256`，`AfterFirstUnlockThisDeviceOnly`；Android：Keystore EC P-256，StrongBox 优先、回退 TEE 并上报 `key_kind` | relay 会话认证；信封签名；HPKE 接收 | 否（无人值守） |
| 审批密钥 Quick `AK_q` | （V2 审批端）TPM P-256，在场 = polkit | — | SE `P256`，`WhenUnlockedThisDeviceOnly`，无生物 ACL | PCP TPM P-256（与 `DK` 不同对象），在场 = 已登录桌面会话里的点击 | iOS：SE `P256`，`WhenUnlockedThisDeviceOnly`，无生物 ACL（锁屏动作 `authenticationRequired` 保证已解锁）；Android：Keystore P-256，`setUnlockedDeviceRequired(true)` | 签 T0/T1 的「点一下允许」 | 屏幕解锁即可 |
| 审批密钥 Strong `AK_s` | （V2）同上，状态标 `presence: polkit` | — | SE `P256`，`userPresence` ACL | Hello `KeyCredentialManager` RSA-2048（`RS256`），每次 `RequestSignAsync` 都要 PIN / 指纹 / 人脸 | iOS：SE `P256`，`.biometryCurrentSet`；Android：Keystore P-256，`setUserAuthenticationRequired(true)` + `setUserAuthenticationParameters(0, AUTH_BIOMETRIC_STRONG)` + `setInvalidatedByBiometricEnrollment(true)`，签名经 `BiometricPrompt.CryptoObject` | 签 T2、unlock、admin、Directive | 每次 Touch ID / Hello / Face ID / 指纹 / polkit |

说明：

- 任何设备的 `DK` 只用于签 **请求** 和认证自己，永远签不出 **批准**。执行端验证批准时只接受已配对审批设备的 `AK_q`/`AK_s`，并按该键记录的 `alg` 验签。
- Mac 身份密钥用 `AfterFirstUnlock` 是为了锁屏时 relay 重连还能完成挑战签名；审批密钥用 `WhenUnlocked`，锁屏期间自然批不了。Windows 等价：`DK`/`AK_q` 由服务里的 PCP 使用，`AK_s` 只能在用户交互会话里由 `kv-agent.exe` 调 Hello。
- TPM / PCP 无用户在场机制：执行端 root / SYSTEM 可以静默用 `DK` 发请求——这只是「能发请求」，不是「能批准」，威胁模型不变。
- Mac 的 SE 操作与现有一样经 `dev.keyvalet.helper → dev.keyvalet.agent → kv-touchid`。W1 spike 的实测范围见下表；生产使用 SE ECDH 的 32 字节共享点，由 W0 的 Rust 实现完成 HKDF/AEAD。
- Linux TPM 侧：`tpm2_create` 带 `sign|decrypt` 的非受限 ECC 密钥，ECDSA 用 `tpm2_sign`，ECDH 用 `tpm2_ecdhzgen`，均通过现有的受信 `tpm2-tools` 路径与 `/dev/tpmrm0`；blob 放进 vault 的 AEAD 认证元数据，与现有主密钥 blob 同样处理。
- Windows 侧：PCP 的 P-256 ECDH/ECDSA 走 `NCryptSecretAgreement` / `NCryptSignHash`；Hello 走现有 `KeyCredentialManager` 路径（总架构 §8.1.1 已验证 PKCS#1 v1.5/SHA-256）。**W1 spike**：PCP 密钥在 LocalSystem 服务上下文下的创建与持久化、以及 HPKE 解封所需的原始共享点能否从 `NCryptDeriveKey` 以 `BCRYPT_KDF_RAW_SECRET` 取出。
- `DeviceKeyProvider` trait（§13.1）把以上全部收口：`sign(alg)`, `ecdh()`, `public_jwk()`, `presence_kind()`。

**W1 事实表（2026-10-12 回填，不代表三平台硬件验收完成）**：

| 项目 | 实测环境与结果 | 尚未验证 |
| --- | --- | --- |
| SE HPKE / 双用途 | Apple Silicon、macOS 26.5.1、Swift 6.2.3 / SDK 26.2；`hpke_recipient=pass`、`raw_ecdh=pass length=32`、`same_key_es256=pass signature_length=64`；DK/Quick 与 W0 HPKE 和签名互操作通过 | macOS 14、锁屏后的 ACL、Strong 交互与取消 |
| PCP RAW_SECRET / 双用途 | Windows 目标交叉编译通过；原生 LocalSystem + TPM 2.0 spike 尚未执行 | 创建/持久化、ECDH+ES256 双用途、RAW_SECRET 导出与字节序 |
| macOS 在场初始值 | 实测 console/input/display 可取，screensaver 初值未知；代码保守返回 Away | 完整锁屏/屏保/显示器转换及启动可用性 |

证据与命令：[W1 报告](remote-approval-reports/W1.md)。SE 加密表示只绑定设备；PCP 不提供用户在场审批门。硬件失败不自动切换软件键。

### 3.2 密钥材料存放

| 内容 | Linux | macOS | Windows | 手机 |
| --- | --- | --- | --- | --- |
| 自己的 `DK` 私钥 | TPM blob（或 0600 软件文件）→ vault 元数据 | SE 加密表示 → root-only 文件（与主密钥同机制） | PCP 持久化句柄名（或 DPAPI 软件键）→ `C:\ProgramData\KeyValet`（SYSTEM + Administrators DACL） | iOS：SE 加密表示放 App Group 容器（NSE 也要用）；Android：Keystore 别名 |
| 自己的 `AK_q` / `AK_s` | （V2）同上 | 同上 | `AK_q` 同上；`AK_s` 是 Hello 凭据，归属用户账户，由 `kv-agent.exe` 使用 | iOS：Keychain（`ThisDeviceOnly`，不进 iCloud）；Android：Keystore 别名；只有主 App 能用 |
| 对端设备记录（公钥、`alg`、能力、标签、信任来源） | vault 元数据 `devices`（AEAD 认证） | `/var/db/keyvalet/peers.json`（root-only，AEAD 认证） | 同目录 `peers.json`（同 DACL，AEAD 认证） | Rust 侧 SQLite（App Group / 应用私有目录），AEAD 认证 |
| relay 会话令牌 | relay-client 内存 | 同上 | 同上 | `kv-mobile-core` 内存；后台由推送唤醒后重新挑战 |

修改 `devices` / `peers` 属于 **admin** 类操作，需要 Strong 审批（见 §7.1）。

### 3.3 账户模型（沿用总架构 §10.2 Free 档）

- 第一台向某个 relay 注册的设备创建一个**匿名账户**（`account_id` 随机），之后的设备通过配对加入同一账户。无邮箱、无密码。手机 App 也是普通设备：首次扫码即注册 + 配对，不需要先「登录」。
- relay 只认「同账户设备之间」的消息。
- 账户恢复码：注册时生成一次，用于所有设备丢失时在 relay 上吊销/重建。自托管 relay 的管理员也可以直接在服务器上操作。
- Team（阶段 2）在同一模型上加「组织」维度，不在本文范围。

### 3.4 轮换与吊销

- 吊销设备：任一仍受信的审批设备（Strong）或服务器本地 polkit 发起；两端删除记录、relay 删除注册并断开其 presence；该设备签过的尚未使用的批准与能力令牌全部失效（按 `device_id` 过滤）。
- 若已启用 V2 的 vault 同步，吊销后还要按总架构 §8.2 旋转 UMK；第一版不同步，所以不涉及。
- 轮换身份密钥 = 吊销旧设备 + 重新配对，不做原地轮换。

---

## 4. 配对协议

目标：在**不信任 relay** 的前提下，让两台设备拿到对方真实公钥，并且用户亲眼确认过。

```
Ubuntu（服务器，终端经 SSH）                     relay                         MacBook
keyvalet pair --new
  helper 生成 token（128 bit，一次性，10 分钟）
  若尚无账户：POST /v1/devices 注册 DK_srv → account_id
  POST /v1/pair/start {token_hash, DK_srv_pub, meta(hostname, os, caps=[execute])}
  终端打印：
    kv-pair://relay.example.net/<base32(token)>
    （以及同内容二维码，给以后的 iPhone 用）
                                                                keyvalet pair kv-pair://…
                                                                  relay-client 解析 relay_url + token
                                                                  helper 生成/读取 DK_mac, AK_q, AK_s
                                                                  POST /v1/pair/complete
                                                                    {token, DK_mac_pub, AK_q_pub, AK_s_pub,
                                                                     meta(hostname, os, caps=[approve_quick, approve_strong])}
  ◀── relay 把对方公钥集合转发给双方（WS）──▶
  两端各自计算
    sas = SHA-256("keyvalet-pair-v1" ‖ token ‖ sort(DK_srv_pub, DK_mac_pub) ‖ AK_q_pub ‖ AK_s_pub)
    取前 6 位十进制
  终端显示 6 位数，等待 y/N                                       对话框显示 6 位数 + Touch ID「确认配对」（用 AK_s 签 sas）
  用户核对两边一致后在服务器按 y
  helper 校验 Mac 发来的 sas 签名（AK_s）→ 写入 devices
                                                                  helper 写入 peers（Ubuntu 的 DK_srv_pub, caps）
  POST /v1/pair/finish {token}（两端各一次；relay 把 pairing 标记完成并删除 token）
```

细节与边界：

- token 只用一次、10 分钟过期；relay 只存 `token_hash`，`start` 后任何一方未在 10 分钟内 `complete` 就作废。
- SAS 绑定 token、双方 DK 和审批端 AK。优先采用加入方的 AK；加入方是纯执行端时采用发起审批端的 AK，保持既有执行端发起的测试向量不变。两端都是审批端时，确认对象还必须携带本端完整 DeviceRecord 并由本端 AK_s 签名，接收方核对全部密钥与能力；不能只凭 SAS 信任另一组 AK。6 位数对「只能尝试一次」的在线攻击足够；不做更长的码。
- Mac 侧用 `AK_s` 对 sas 签名并发给服务器，服务器据此确认「这把 Strong 审批键确实在用户按过 Touch ID 的设备上」；服务器侧没有用户在场机制，所以服务器端的确认是终端里的 `y`——这条终端必须是 vault owner 的 SSH 会话（与现有 `keyvalet approve` 同要求）。
- 第二台审批设备（另一台 Mac、以后的 iPhone）重复同一流程；也允许由**已配对的审批设备**代替服务器终端做 `--new`（它用 `AK_s` 签发 token），这样以后加 iPhone 不必再 SSH。
- 配对信息写入后，服务器把 Mac 标为 `approver`，默认策略：T0/T1 可由 Quick 批，T2/unlock/admin 必须 Strong。
- 失败处理：6 位数不一致 → 两端都丢弃，审计 `pair_sas_mismatch`；超时 → 丢弃；relay 返回未知 token → 提示重新 `--new`。
- `/pair/complete` 只取得路由和候选公钥，不能建立信任。加入方发送 DK 签名、HPKE 加密的 PairAccept，双方发送 PairConfirm；本端 owner 确认、对端确认验签和原始期限均满足后才提交目录。配对信封的 `id` 为 relay 的 `pairing_id`；后台轮询绑定这一轮 ID，旧配对消息不能使新配对失败。移动端持久保存原始信封供断网重试，不延长期限。
- 加入新执行端前显示账户内将生效的未过期全局授权数量，并提供排除此设备的选择。任一端选择排除，就把 `exclude_global: true` 放入签名确认对象；双方提交排除状态，阻止已有授权补发及未来全局授权投递，逐设备授权仍可使用。

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
  "sig": "<ES256(from.DK, header_bytes ‖ ct)>"
}
```

- AAD = `v ‖ type ‖ id ‖ account ‖ from ‖ to ‖ created_at ‖ exp` 的 JCS（RFC 8785）编码；篡改头部即解封失败。
- `sig` 由发送方**身份密钥** `DK` 签（身份密钥恒为 P-256，所以信封签名恒为 ES256），覆盖头部和密文。relay 验 `sig` 并检查 `from`/`to` 同账户，否则拒收；接收端再次验签（不信任 relay 的验证）。信封**内部**的对象（ApprovalDecision、Grant、Directive）另有自己的签名，按签名密钥记录的 `alg` 验证（§3.1）。
- 一次 HPKE 一个信封，不复用上下文；明文最大 64 KiB（审批请求的 body 摘要已截断，足够）。
- 接收端用自己的时钟检查 `exp`；若 `created_at` 与本地时钟偏差 > 60 s，仍处理但在 UI 和审计里标注「发送方时钟偏差」。relay 的时间戳不用于安全判断。
- 多审批设备：发送方对每个 approver 各封一个信封（fan-out 在 helper 内完成，密文不同、`id` 相同）。

---

## 6. 审批流程

### 6.1 三类审批

| 类别 | 触发 | 最低档位 | 产生什么 |
| --- | --- | --- | --- |
| `unlock` | 服务器 helper 为某个客户端进程开凭证会话（Linux 现有「每个新连接需要独立解锁授权」） | Strong | 一个会话，寿命 `session.unlock_ttl`（默认 12 h，上限 24 h；到期后下一次请求再触发 unlock） |
| `use` | 某条凭证的某次具体使用，按风险档 T0–T3 与授权模式 | T0：auto / 预授权；T1：Quick 或预授权；T2：Strong，且不被任何 grant/令牌覆盖；T3：直接拒绝 | 一次性批准（`per_use`）或 grant（其他模式，见 §6.6） |
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

`unlock` 与 `admin` 的 `credential/method/...` 字段按类别填空或填操作名（如 `admin.add_device`）。

### 6.3 `ApprovalRequest`（信封明文）

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

1. 信封：`to` 是自己、`from` 是已配对且未吊销的审批设备、`exp` 未过、`sig` 用该设备 `DK` 验证通过、HPKE 解封成功。
2. `approval_id` 在 `pending_approvals` 中且状态为 `waiting`。
3. `digest` 与 pending 记录一致；`nonce` 一致。
4. `level` ≥ 该请求的 `min_level`；T2 必须 `strong`。
5. 用 `level` 对应的审批公钥验 `sig`。
6. `nonce` 表 `INSERT OR FAIL`（防同一批准被用两次）。
7. `decision=allow` → 按 `scope` 产生 grant（§6.6）→ 执行；`deny` → 向 agent 返回结构化拒绝，关闭 pending。
8. 两端审计。

### 6.6 授权范围与 grant（沿用总架构 §7.6）

远程批准的 `scope.mode` 映射到现有四种模式，`per_use` 不产生 grant；其余产生 `grant = {credential, max_tier: T1, allowed_hosts, methods, budget, until, mode, approver, approval_id}`。T2 永远不被 grant 覆盖。审批端只能从执行端给出的 `scope_options` 里选，不能放大。

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

- 同凭证 30 s 内的多条 T0/T1 请求合并为一个 ApprovalRequest（`merged_count`），批准后产生 `until=now+30s` 的临时 grant，与总架构 §7.6 一致；T2 从不合并。

### 6.8 Approver 选择顺序（修订总架构 §7.4）

```
if 策略判定 auto（T0 且规则允许）                          → auto（审计 auto）
elif 有效能力令牌覆盖且 tier ≤ T1                            → capability（审计 jti）
elif 本机有可用的本地审批通道（Mac Touch ID / Linux polkit agent 已为该客户端注册）
     且 config.approval.prefer != "remote"                 → 本地
elif 有已配对 approver（在线优先；离线也发，排队）           → remote-device
     · fan-out 到全部 approver；按 §6.10 的在场判定决定每个 approver 是横幅还是静默，静默 30 s 未决升级为横幅
else                                                        → deny，原因 "no_approver"（不做 TTY 确认码）
```

Strong 只接受 Mac Touch ID（本地）或 remote `AK_s`；Linux 本地 polkit 对 `use` 的 T2 视为 Strong（现有行为），对 `unlock`/`admin` 同样。

### 6.9 agent 侧的等待、放手、续等与唤醒

这一节回答：审批没在一分钟内来，agent 的那次调用怎么办；审批后来到了，正在跑的 session 怎么知道。设计目标是**在每一种运行时上都有一条能走通的路**，而不是依赖某一家的私有能力。

#### 6.9.1 状态语义：超时不是「否」

| 状态 | 含义 | 终态？ | agent 该做什么 |
| --- | --- | --- | --- |
| `approval_pending` | 请求已送出，用户还没决定，`exp` 未到 | 否 | 继续别的工作；有空就 `credential_wait_approval`；或等唤醒 |
| `approval_denied` | 用户点了拒绝 | 是 | 不要重试、不要绕路（例如让用户直接粘 key）；把原因告诉用户 |
| `approval_expired` | `exp` 已过且没有决定 | 是（对这次请求） | 再发一次会产生新弹窗；若非必要不要自动重发 |
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

**第一层：调用内等待。** 预算取 `min(policy.wait_in_call_s, runtime_budget − 10 s)`，默认 `wait_in_call_s = 60`。`runtime_budget` 由 `kv-mcp` 在 `initialize` 时根据 `clientInfo.name` 查表（§6.9.3），再叠加安装器为该运行时写入的每服务器超时。等待期间，如果客户端在请求 `_meta` 里给了 `progressToken`，每 15 s 发一次 `notifications/progress`（`message: "waiting for approval on MacBook (42 s)"`），这会重置 Claude Code 的空闲计时器与 Cursor IDE 的进度型超时；没给 token 就只能靠绝对预算。helper 侧 `pending_approvals` 把完整请求（参数与 body，仅内存、上限 1 MiB、到 `exp` 清除）留着，预算内批准就地执行并返回真实结果。

**第二层：放手。** 预算用尽返回：

```json
{ "status": "approval_pending", "approval_id": "01J…", "expires_at": 1760200900,
  "approver": { "label": "MacBook", "online": false },
  "wait_tool": "credential_wait_approval",
  "next_steps": "你可以先做不需要这条凭证的事。需要结果时调用 credential_wait_approval(approval_id)，批准后它直接返回本次请求的结果。不要重复发起同一请求，不要向用户索要密钥。" }
```

`next_steps` 是写给模型的 UI，与现有工具描述同一口径。

**第三层：续等工具。** `credential_wait_approval(approval_id, max_wait_s?)`：长轮询 pending 状态，`max_wait_s` 同样被运行时预算封顶，期间发 progress。结果三选一：`approved` + 原请求的执行结果（helper 从内存里取出完整请求执行，一次性，关闭 pending）；`denied`；`still_pending`（再等或放弃由模型决定）。helper 重启导致内存里的请求丢失时，返回 `approved_retry_required`，此时模型用相同参数 + `approval_id` 重发原调用，helper 比对除 `nonce/exp` 外的全部规范化字段（含 `body_sha256`）一致才执行。

**第四层 a：唤醒（Claude Code channels）。** `kv-mcp` 声明 `capabilities.experimental["claude/channel"]`；批准到达时发 `notifications/claude/channel`，`content` 为「approval 01J… for GitHub POST repos/… granted; call credential_wait_approval("01J…") to get the result」，`meta.approval_id`。空闲 session 会被唤醒，忙碌时下一轮合并送达。约束：research preview；自定义服务器要 `claude --dangerously-load-development-channels server:keyvalet` 或组织 allowlist；未启用时 Claude Code **静默丢弃**且不报错——所以它只是加速器，任何正确性都不建立在它之上。安装器不替用户加这个标志，只在文档里给出。

**第四层 b：Stop hook 兜底。** `kv-hook` 新增 `stop` 模式（Claude Code `Stop`、Devin `Stop`、Codex `Stop`、Cursor `stop`、Gemini `AfterAgent`）。流程：hook 从 stdin 拿到 `session_id`，用自己的父进程 pid（= agent 进程）向 helper 查「这个 agent pid 有没有未到期、未被领取的 pending」；有，且该 approval 被此 hook 阻止的次数 < 3，且 `stop_hook_active`/`loop_count` 未触顶，则返回「别停，去 `credential_wait_approval(01J…)`」（Claude/Devin/Codex：`{"decision":"block","reason":…}`；Cursor：`{"followup_message":…}`；Gemini：`{"decision":"deny","reason":…}`）；否则放行。阻止次数计在 pending 记录上，`exp` 过后一律放行。这一层的代价是每次阻止多一轮模型调用，等待本身在工具调用里阻塞、不耗 token。

**HTTP 路径。** 网关与透明代理没有「返回 pending 再续等」的余地——SDK 等的是 HTTP 响应。做法：挂连接到 `min(policy.http_wait_s, host_hint − 60 s)`，`host_hint` 来自模板（OpenAI / Anthropic SDK 默认 600 s → 挂 540 s；未知主机默认 55 s）；期间每 20 s 发送一个 TCP keepalive，不发应用层字节（HTTP/1.1 不能在状态行前发心跳；`102 Processing` 兼容性差，不用）。超出后返回 `429` + `Retry-After: 30` + JSON `{error: {type: "keyvalet_approval_pending", approval_id}}` + 响应头 `X-KeyValet-Approval: pending; id=01J…`。OpenAI/Anthropic SDK 对 429 会按 `Retry-After` 自动重试（默认最多 2 次），足够覆盖「用户正在掏手机」的几十秒；更长的等待靠挂连接本身。`keyvalet run` 包裹的子进程走同一代理，但 wrapper 额外在子进程的 stderr 打一行「KeyValet: waiting for approval on MacBook」。

#### 6.9.3 运行时预算与能力表（2026-10-12 回填 W5，须随版本复核）

| 运行时 | 工具调用超时（默认） | progress 续命 | 安装器写入 | 唤醒 | Stop 兜底 | 调用内预算 |
| --- | --- | --- | --- | --- | --- | --- |
| Claude Code CLI（stdio） | 文档约 28 h / 空闲 30 min；2.1.282 在合成本地模型接口下两组均完成 240 s，不证明上界 | 实测有 token、15 次标准进度；空闲上界未测 | `.mcp.json` / `~/.claude.json` KeyValet `timeout: 900000` | channels 声明/发送有 CI；交互式运行时提示不可用，空闲唤醒未通过 | 实测 `Stop` block 后续调工具，active 防循环 | 180 s |
| Claude Code Desktop | 60 s 硬超时（已知 bug，忽略 `MCP_TOOL_TIMEOUT`） | 否 | 同上（不生效） | 同上 | 同上 | 50 s |
| Codex | 0.162.1 TUI/exec 两组均完成 240 s；精确默认上限未证实，旧版按 60 s 保守处理 | 两组均提供 token；有进度完成，不证明续命语义 | `[mcp_servers.keyvalet] tool_timeout_sec = 900` | 无 | TUI 与 exec 均实测触发 `Stop`，block 后继续，active 防循环 | 默认 60 s；显式确认硬超时后 180 s |
| Gemini CLI | 600 s | 代码有 progressReporter，未实测 | 每服务器 `timeout: 900000` | 无 | `AfterAgent` deny=重试 | 180 s |
| Cursor IDE | 空闲型，进度重置 | 能 | 无接口 | 无 | `stop` followup | 120 s |
| Cursor CLI / ACP | 2026.10.01 两组约 60 s cancellation；clientInfo 为 `Cursor` | 未提供 progressToken，未实际发送进度，不能推断续命是否有效 | 无接口 | 无 | stop 解析有 CI；未观察到真实输入 | 50 s |
| Grok Build | 文档 6000 s；1.0.50 因未登录未进入工具，未实测 | 未确认 | `[mcp_servers.keyvalet] tool_timeout_sec = 900` | 无 | Stop 未确认，不注册未验证的变体 | 180 s |
| Devin CLI | 3000.11.3 两组均完成 240 s，精确上限未知 | 实测有 token、15 次标准进度 | 未确认额外超时字段 | 无 | 实测 `Stop` block 后继续，active 防循环 | 默认 50 s；实际 clientInfo 为通用 `rmcp`，不能全局提额 |
| OpenClaw / Hermes / SDK（HTTP） | 客户端决定：OpenAI/Anthropic SDK 600 s，curl/requests 无限 | 不适用 | 不适用 | 不适用（它们有自己的 cron/heartbeat） | 不适用 | 挂连接 55–540 s |
| 未知 MCP 客户端 | 按 MCP TS SDK 默认 60 s 假设 | 否 | — | — | — | 50 s |

`clientInfo.name` 查不到的客户端一律按最后一行处理。表中「未确认」项是 W5 的实测清单（§16）。

W5 的联网 Claude OAuth、Gemini 浏览器登录、Grok NotSignedIn 均在工具前失败，不计为工具超时；Claude Desktop 和 Cursor IDE 未测。原始版本、字段名与三分钟批准结果见 [W5 报告](remote-approval-reports/W5.md)。安装器写入只针对 KeyValet 条目，不代表客户端必然接受该字段，也不自动替代 MCP 端保守预算。

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

#### 6.10.2 用在两处

**（a）执行端选本机还是远程（§6.8 的「本机优先」分支）**

```
执行端本机 present            → 本机弹窗为主；远程 approver 收「静默」投递
执行端本机 idle 或 away       → 远程 approver 收「横幅」投递；若本机有图形会话仍同时弹本机框（人回来就能看到）
```

**（b）多个审批端之间谁先响**

桌面审批端（MacBook、Windows 笔记本）把自己的状态作为 E2E 的 `presence_hint {state, since}` 发给同账户的执行端（变化时发送，最多每 60 s 一次；relay 只转发不存，relay 自己只知道「连着」）。执行端 fan-out 时为每个 approver 决定投递方式，写在**密文内**的 `delivery: { mode: banner | silent, escalate_after_s }`：

```
有任一桌面审批端 present      → 该桌面端 banner；手机 silent，escalate_after_s = 30
没有桌面审批端 present        → 手机 banner；idle 的桌面端也 banner
```

#### 6.10.3 投递升级（executor 驱动）

静默投递不是不投，是「进列表、不响、不亮屏」。升级由执行端的定时器驱动，不依赖手机端能否在后台计时：

```
t0          发 approval_request（手机：delivery.mode = silent）
t0 + 30 s   仍 waiting → 发 approval_escalate{approval_id}（手机：横幅 + 声音；同一条，不重复显示）
t0 + exp    过期 → approval_cancel
```

iOS 侧：NSE 解密后按 `delivery.mode` 设置 `interruptionLevel`（silent → `.passive`，banner → `.timeSensitive`）与声音；`approval_escalate` 用同一 `threadIdentifier` 更新已投递的通知。Android 侧：FCM data message → 原生服务解密 → 按模式选通知渠道（静默渠道 / 高优先级渠道）。两端都把 `delivery` 当提示，不当安全判断——内容仍然必须完整显示。

#### 6.10.4 用户可覆盖

| 设置 | 作用 | 存放 |
| --- | --- | --- |
| `keyvalet remote <device> notify prefer-local \| always-phone \| both` | 该执行端的默认投递策略；`always-phone` 让手机永远横幅 | 执行端 `settings`，Directive |
| `presence.idle_threshold_s`（默认 120） | 多久没碰键鼠算「不在」 | 本机配置 |
| `presence.escalate_after_s`（默认 30） | 静默多久升级横幅 | 执行端配置 |
| 手机 App「我不在电脑前」开关 | 手机侧强制把 silent 当 banner 处理，不发任何东西给执行端 | 手机本地 |
| 勿扰时段 | 手机侧按系统 Focus；执行端侧 `class: batch` 让请求等更久而不是半夜响 | 各自本地 |

#### 6.10.5 典型场景核对

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

- 在场状态是元数据。它只以 E2E 形式发给同账户设备，relay 不存；粒度只有三档，不含应用名、窗口标题或输入内容。
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
- 吊销：Mac 上 `keyvalet grant revoke <jti>`（Strong）→ `device_revoke`/`token_revoke` 信封 → 服务器 `revoked_jti`；服务器本地 polkit 也可吊销。
- `keyvalet grant list` 两端都能看：剩余预算、到期时间、最近使用。

### 7.3 推荐默认

安装后不自动签发任何令牌。首次远程审批时，Mac 对话框提供「以后 24 小时内自动放行此凭证对此主机的只读请求」快捷项（只对 T0/T1、只对 `GET/HEAD`），接受即签发一张等价令牌——这是总架构 §6.4「从历史推荐规则」的远程版。

### 7.4 统一的授权对象：Grant

弹窗里选的范围（§6.6）、上面的能力令牌（§7.1）、以及用户要的「这个凭证一直允许」「这台机器一直允许」「全局不用再管」，本质是同一种东西：**一张由审批密钥签名、描述「在什么范围内不必再问」的票**。第一版就把它们统一成一个对象，免得三套存储、三套吊销、三套 UI：

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
| 无人值守模式（含敏感操作） | 上面任一 + `max_tier = T2` | **Strong + 二次确认**（§7.6） |
| 预授权能力令牌（`keyvalet grant …`） | `level=credential` + 收窄 + `budget` + `exp` | Strong |

执行端的覆盖判定沿用总架构 §7.6：`同凭证（或 level 更宽）∧ tier ≤ max_tier ∧ host/method/path/agent 命中 ∧ 预算未超 ∧ 未过期 ∧ 未吊销 → 跳过审批，审计 jti`。多张 Grant 同时命中取**最窄的 max_tier 不放大、预算各自扣减**。T2 请求只有 `max_tier = T2` 的 Grant 能覆盖，且每次仍重算 digest 并审计 `unattended_t2`。

存储：执行端 `grants` 表（替代原 `grants` + `capability_tokens` 两张表），审批端 `issued_grants`。吊销：`directive{op: revoke_grant, jti}`（§7.5），或执行端本地 polkit / Touch ID。

### 7.5 远程设置：Directive（控制面）

审批端对执行端的一切设置变更，都是一个签名的 **Directive**，经 relay 的 `directive` 信封下发，执行端执行后以 `directive_result` 回报。执行端只认签名与范围，不认「从哪台设备的哪个界面来」，所以 iPhone App、菜单栏 App、CLI、以后的 Web 控制台和团队策略下发走同一条路。

```json
{
  "kind": "directive",
  "id": "01J…",
  "iss": "dev_mac…", "iss_alg": "ES256",
  "aud": "dev_srv… | *",
  "op": "set_mode | revoke_grant | revoke_all_grants | lock | set_unlock_ttl | set_class | set_device_label |
         revoke_device | query_status | query_pending | query_grants | query_audit | cancel_approval",
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
| 放宽 | `set_mode` 变松、`set_unlock_ttl` 变长、`set_class` 延长 `exp`、签发常设 Grant | Strong |
| 危险 | `revoke_device`、`max_tier = T2` 的 Grant | Strong + §7.6 二次确认 |

执行端对每条 Directive：验签（按 `iss` 的 `AK_q`/`AK_s`，`alg` 来自设备记录）→ 档位够 → `nonce` 一次性 → `exp` 未过 → 执行 → 审计 `directive_applied{op, iss}` → 回 `directive_result{id, ok, state_summary}`。失败也回报，附原因。

`set_mode` 的取值就是现有四种授权模式（`per_use` / `per_credential` / `per_session` / `remember:<h>`），作用于执行端上该用户的会话；本地 `/keyvalet:mode` 与远程 `set_mode` 写同一份状态，最后写入者生效，两边都审计。

### 7.6 审批边界的安全栏

用户要的「以后再也不需要管」是合理需求，但它正是提示注入最想要的开关。第一版的栏：

1. **常设 Grant 的 `max_tier` 默认 T1**：只读与普通写入可以永远不问；删除、支付、IAM、发布、吊销这类 T2 默认仍然每次 Strong。这是现有产品决策（product-2026-10 J4「T2 永远弹窗」）的延续。
2. **T2 纳入无人值守必须显式、分开、带红色状态**：`max_tier = T2` 的 Grant 只能从设置页签发，不出现在弹窗快捷项里；签发时 Strong 之后再输入执行端标签作二次确认；两端 `status` 与弹窗标题常驻红色「无人值守（含敏感操作）」；默认带 `exp`（建议 7 天），用户可改为常设但要再确认一次；每次被它覆盖的 T2 调用都单独审计 `unattended_t2` 并可在审批端设置页看到计数。
3. **范围永远只能收窄不能放大**：弹窗里的选项由执行端在 `scope_options` 里给出，审批端选不出执行端没给的；设置页签发的 Grant 不能超过设备记录里的 `caps`。
4. **全局（`aud = *`）Grant 对后加入的执行端也生效**，所以配对新设备时要提示「账户内有 N 张全局 Grant 将对此设备生效」，并允许一键排除。
5. **任何 Grant 的吊销是 Quick**，而且 `revoke_all_grants` 永远在审批端的第一屏。

这一节的第 2 条是对既有「T2 永远弹窗」决策的放宽，需要用户拍板（§18）。

---

## 8. relay 服务

### 8.1 技术选型

沿用总架构 §10.1：Rust（axum + tokio），单二进制 `kv-server`，feature `relay`。自托管用 SQLite（WAL），官方实例用 Postgres；presence 与队列用进程内 broadcast（单实例）或 Postgres LISTEN/NOTIFY（多实例）。TLS 由 **Cloudflare 橙色云代理 + 本机 nginx** 提供（§8.5），`kv-server` 只监听 `127.0.0.1`。

### 8.2 API

| 方法 | 路径 | 调用方 | 作用 |
| --- | --- | --- | --- |
| POST | `/v1/devices` | 任一设备 | 注册：`{DK_pub, AK_q: {pub, alg}?, AK_s: {pub, alg}?, key_kind, attestation?, os, caps, label}`；首个设备创建匿名账户并返回恢复码。relay 只存不验 `attestation`（§13.2） |
| POST | `/v1/auth/challenge` → `/v1/auth/verify` | 设备 | 用 `DK` 签 32 字节挑战换会话令牌（24 h，可续） |
| GET | `WS /v1/presence` | 设备 | 长连接；30 s 心跳；服务端推送 `approval_request / approval_decision / approval_cancel / grant / directive / directive_result / device_revoke / pair_*` |
| POST | `/v1/pair/start` / `complete` / `finish` | 两端 | §4 |
| POST | `/v1/approvals` | 请求方 | `{id, to[], exp, envelopes[]}`；每个 `to` 一个信封 |
| POST | `/v1/approvals/{id}/reply` | 审批方 | 决策信封；首个有效回复后状态 `resolved`，其余设备收到 `approval_cancel` |
| POST | `/v1/approvals/{id}/cancel` | 请求方 | 过期/取消 |
| GET | `/v1/approvals?state=waiting` | 审批方 | 重连后拉取积压 |
| POST | `/v1/messages` | 任一 | 非审批类信封（令牌、吊销），同样按 `to` 投递并持久化到送达 |
| DELETE | `/v1/devices/{id}` | 同账户 Strong 设备 / 恢复码 / 管理员 | 吊销 |
| GET | `/v1/health`, `/metrics` | 运维 | — |

### 8.3 数据模型（SQLite）

```sql
accounts(id, created_at, recovery_hash, plan)
devices(id, account_id, dk_pub, akq_pub, akq_alg, aks_pub, aks_alg, key_kind, attestation BLOB, os, caps, label, created_at, revoked_at, last_seen)
sessions(token_hash, device_id, exp)
pairings(token_hash, account_id, initiator_device, initiator_pubs, joiner_pubs, state, exp)
messages(id, account_id, from_device, to_device, type, envelope BLOB, created_at, exp, delivered_at, acked_at)
approvals(id, account_id, requester, state, exp, resolved_by, resolved_at)      -- 状态机：waiting → resolved | cancelled | expired
```

- `messages.envelope` 就是 §5 的整个 JSON（含密文）；relay 从不解析 `ct`。
- 送达并 ack 后 7 天内删除（给审计对账留窗口）；`approvals` 过期后 7 天删除。
- 容量限制：每设备每分钟 ≤ 60 条请求、≤ 600 条消息；每账户待处理 ≤ 500；单信封 ≤ 80 KiB。

### 8.4 relay 看得到 / 看不到

| 看得到 | 看不到 |
| --- | --- |
| 账户内有哪些设备、公钥、在线状态、上次心跳 | 任何凭证值、UMK、CEK |
| 谁向谁发了多少条、什么时候、多大、`type` | 请求里的凭证名、主机、路径、agent、purpose、决策内容（全部在 `ct` 内） |
| 配对发生过、设备被吊销过 | 哪条 `approval_id` 批了还是拒了（`resolved` 不区分） |

relay 被攻破的后果：丢消息、延迟、拒绝服务、观察元数据；不能伪造请求或批准（签名），不能重放（nonce + `exp`），不能解密。

### 8.5 部署

**同机部署（第一版）**：在这台 Ubuntu 上，链路固定为 **Cloudflare 橙色云（代理 DNS）→ nginx（443，Cloudflare Origin CA 证书）→ `kv-server` 监听 `127.0.0.1:8787`**。不用 Tailscale，不用 Caddy。

```sh
# 1. kv-server：二进制 + systemd，只听本地
keyvalet relay install --listen 127.0.0.1:8787 --data /var/lib/keyvalet-relay --public-url https://relay.example.com
# 2. nginx：安装器写出 /etc/nginx/conf.d/keyvalet-relay.conf（下方模板），证书放 /etc/ssl/keyvalet-relay/{origin.pem,origin.key}
# 3. Cloudflare：A/AAAA 记录 relay.example.com 指向服务器公网 IP，开启橙色云；SSL/TLS 模式 Full (strict)；可选开启 Authenticated Origin Pulls
# 4. 防火墙：443 只放行 Cloudflare 的 IP 段（https://www.cloudflare.com/ips/），8787 不对外
```

```nginx
# /etc/nginx/conf.d/keyvalet-relay.conf（安装器模板）
server {
    listen 443 ssl http2;
    server_name relay.example.com;
    ssl_certificate     /etc/ssl/keyvalet-relay/origin.pem;   # Cloudflare Origin CA，15 年有效，只被 Cloudflare 信任
    ssl_certificate_key /etc/ssl/keyvalet-relay/origin.key;
    # 可选：Authenticated Origin Pulls，拒绝不经 Cloudflare 的直连
    # ssl_client_certificate /etc/ssl/keyvalet-relay/cloudflare-origin-pull-ca.pem;
    # ssl_verify_client on;
    client_max_body_size 1m;                     # 单信封 ≤ 80 KiB，留余量
    location / {
        proxy_pass http://127.0.0.1:8787;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;  # WebSocket /v1/presence
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header CF-Connecting-IP $http_cf_connecting_ip;
        proxy_read_timeout 90s;                  # 客户端 30 s 心跳；Cloudflare 自身 WS 空闲上限 100 s
        proxy_send_timeout 90s;
    }
}
```

Cloudflare 橙色云的几个事实与对策：

- WebSocket 在所有套餐都支持；空闲连接 100 s 无流量会被边缘断开，所以客户端心跳 30 s、nginx `proxy_read_timeout` 90 s。
- TLS 在 Cloudflare 边缘终止：Cloudflare 能看到 HTTP 层——但信封内容本来就是端到端密文，Cloudflare 看到的与 relay 自己看到的一样只是元数据（§8.4）；威胁模型里把 Cloudflare 视为与 relay 运营者同级的中间人（§12）。
- `kv-server` 从 `CF-Connecting-IP` 取客户端 IP 做限流，且只在请求来自 nginx（本地）时信任该头。
- 免费套餐够用：请求体上限 100 MB、无 WS 连接数硬限；若日后官方 relay 走 Cloudflare 则另评估 Spectrum / Tunnel。
- 同机的代价是可用性耦合：服务器重启时 relay 也不在，但那时也没有请求要批。安全上不扩大泄露面（vault 已在这台机器上）。
- 官方 relay（后续）：同一二进制，Postgres，美国托管，Free 配额 3 台设备 / 每月 2,000 次远程审批 / 待审批保留 7 天（见总架构 §10.3 与 strategy 文档）；配额执行代码在第一版就留接口（`plan` 字段），不实现计费。

---

## 9. 客户端

### 9.1 `kv-relay-client`

- 新 crate `rust/crates/kv-relay-client`，同一二进制在三平台运行。
- Linux：systemd 单元 `keyvalet-relay.service`，`User=keyvalet-relay`，`ProtectSystem=strict`、`PrivateTmp`、`NoNewPrivileges`、`RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6`，无 `CAP_*`。配置文件 `/etc/keyvalet/relay-client.toml`（relay_url、device_id、account_id）。与 helper 通信走 `/var/run/keyvalet/relay.sock`，helper 用 `SO_PEERCRED` 只接受 uid=`keyvalet-relay`。
- macOS：per-user LaunchAgent `dev.keyvalet.relay`，由 `dev.keyvalet.helper` 以 audit token + code requirement 校验（与 `dev.keyvalet.agent` 同机制），IPC 走 helper 的 socket 新增 `relay` 子协议。
- Windows：服务 `KeyValetRelay`，以虚拟服务账户 `NT SERVICE\KeyValetRelay` 运行（不是 LocalSystem），经 `\\.\pipe\keyvalet-relay` 连 `KeyValetHelper`；管道 DACL 只给该 SID 与 SYSTEM，helper 用 `GetNamedPipeClientProcessId` → 进程令牌校验 SID 与 Authenticode 发布者；配置在 `C:\ProgramData\KeyValet\relay-client.toml`。
- 行为：指数退避重连（1 s → 60 s）；本地磁盘队列（待发信封，密文），防 relay 短暂不可达时丢请求；收到信封立即转交 helper，由 helper 决定是否 ack（验签失败也 ack，避免毒消息反复投递，但审计）。
- 不做任何策略判断，不存任何明文，不持任何私钥。

### 9.2 审批端 UI（macOS / Windows）

- **V1 桌面弹窗**：macOS 复用现有 `kv-touchid` 原生对话框；Windows 复用 `kv-agent.exe` 的 TaskDialog。标题带来源：「srv 上的 claude-code 请求使用 GitHub (guang)」。正文按 §6.3 渲染：真实操作（summary）、主机/方法/路径、agent 自述 purpose（标注「agent 自述」）、风险档、执行端保护状态（`tpm2` / `software_key`，后者红色提示）、时钟偏差提示。按钮：允许（+ 范围下拉，选项来自 `scope_options`，§7.4 映射）/ 拒绝；Strong 时点允许触发 Touch ID / Hello；选到「一直允许」时按钮文案变为「一直允许（Touch ID）」。
- **V1 设置（终端）**：`keyvalet remote <device>` 子命令组（§9.3）覆盖 §7.5 全部 Directive；没有图形设置页也能完成所有远程设置。
- **V1 手机 App 是唯一的图形审批/控制面**（一套 Flutter 代码出 iOS 与 Android，见 §9.2.1；iOS 走 TestFlight、Android 走内部测试轨道，不等公开上架）：锁屏 Quick / 生物识别 Strong 审批、每台执行端一页设置（当前模式、常设 Grant 列表含剩余预算/到期/来源、无人值守红色状态与 `unattended_t2` 计数、`unlock_ttl`、batch 类、锁定、`revoke_all_grants` 大按钮）、扫码配对与吊销、最近活动摘要、推送（APNs 经 `kv-push`，Android 经 FCM data message）。桌面**不做**图形设置页——产品决策见产品文档 §6.2。
- **V2**：瘦菜单栏/托盘项（状态点、待批数、打开待批、一键全部收回；仅当 dogfooding 证明桌前需要）；Linux 桌面审批端；手机上走 OAuth 添加凭证。
- Web 控制台随 Team（总架构阶段 2），服务 Lead 角色；不做个人审批端（`webauthn` 位保留，§13.1）。
- 本机优先与手机静默/升级的判定见 §6.10；审批端睡眠：醒来后由 relay-client 拉取积压，一次最多排队弹 5 个，其余在列表里。

#### 9.2.1 手机 App 技术选型：Flutter + Rust 核心 + 原生薄层

决定：用 **Flutter** 做 UI，一套代码覆盖 iOS 与 Android；协议、密码学、状态机全部在 Rust（crate `kv-mobile-core`），经 `flutter_rust_bridge` 暴露给 Dart。这取代总架构 §3.1 里「iPhone App（Swift + UniFFI）」的写法，落地时回写。

Dart 侧**不碰任何私钥、不做任何验签、不解析任何信封**——它只渲染 Rust 给的结构体、把用户的点击交回 Rust。下面这些必须是原生代码（一个平台插件 `kv_native`，Swift / Kotlin 各一份）：

| 必须原生 | iOS | Android | 为什么 Flutter 插件不够 |
| --- | --- | --- | --- |
| 硬件密钥与生物绑定签名（`DK`、`AK_q`、`AK_s`） | `SecureEnclave.P256`；`AK_s` 带 `.biometryCurrentSet`，`AK_q` 带 `WhenUnlockedThisDeviceOnly`，`DK` 带 `AfterFirstUnlockThisDeviceOnly` | `KeyGenParameterSpec`：`setIsStrongBoxBacked(true)` 优先、回退 TEE 并上报；`AK_s` 用 `setUserAuthenticationRequired(true)` + `setUserAuthenticationParameters(0, AUTH_BIOMETRIC_STRONG)`，签名经 `BiometricPrompt.authenticate(CryptoObject(Signature))` | **生物识别必须门控密钥操作本身**。`local_auth` 一类插件只返回布尔值，被攻破的 App 进程可以跳过它直接签名；只有密钥级绑定才是 Strong |
| 推送与后台解密 | Notification Service Extension（Swift，独立 target，不能跑 Flutter 引擎）链接同一个 Rust 静态库（UniFFI / C ABI），从 App Group 共享容器读设备密钥的加密表示与密文队列，解密后改通知正文、`interruptionLevel`、`threadIdentifier`；锁屏动作 `UNNotificationAction(options: .authenticationRequired)` → 主 App 后台唤起 → Rust 用 `AK_q` 签 Quick 决定 | `FirebaseMessagingService`（Kotlin）收 data message → Rust 解密 → 按 `delivery.mode` 选通知渠道；动作按钮 → 前台服务签 Quick | iOS NSE 与 Android 消息服务都在 Flutter 引擎之外运行；后台路径全走原生 + Rust，不依赖 Dart 后台 isolate |
| 设备证明 | App Attest | Play Integrity | 平台 API |
| 扫码 | Flutter 插件（`mobile_scanner`）即可 | 同左 | 不涉及安全 |

Rust 核心因此有两套绑定：Dart（`flutter_rust_bridge`，主 App）与 Swift（UniFFI 或手写 C ABI，NSE）。状态（待批队列、peers、设备记录、本机签发记录）放 Rust 侧 SQLite，iOS 在 App Group 容器、Android 在应用私有目录；NSE 与主 App 对同一个 SQLite 用 WAL + 文件锁。

已知代价与对策：双绑定的维护成本（用同一份 Rust 公开类型，CI 同时生成两套并编译）；iOS NSE 的 30 s / 内存上限（解密一条信封远低于此）；Flutter 在 iOS 的后台执行不可靠（所以后台一律原生）；Flutter 包体与启动时间（可接受）。V2 的瘦菜单栏/托盘不复用 Flutter desktop，用各平台原生轻量实现，避免为一个状态点引入第二个 Flutter 工程。

**App 的页面清单（V1）**：① 待批（列表 + 详情，详情即 §6.3 的全部字段；详情页底部是范围选择与允许/拒绝）；② 设备（已配对执行端列表 → 每台一页：状态、模式、常设 Grant、无人值守开关、锁定、`revoke-all`、吊销、最近活动；加设备 = 扫码）；③ 活动（本机签发的批准/票/指令，按天分组，摘要级）；④ 设置（relay 地址、通知偏好、「我不在电脑前」、关于/诊断、导出诊断包不含任何密钥）。没有登录页、没有账号页。

**目录与构建**：`mobile/`（Flutter 工程，`pubspec.yaml`）、`mobile/ios/`（含 `KeyValetNSE` target）、`mobile/android/`、`rust/crates/kv-mobile-core/`（`crate-type = ["staticlib", "cdylib", "rlib"]`，`flutter_rust_bridge` 代码生成输出到 `mobile/lib/src/rust/`，UniFFI 输出到 `mobile/ios/KeyValetNSE/Generated/`）。CI：`cargo build -p kv-mobile-core --target aarch64-apple-ios` 与 `--target aarch64-linux-android`，`flutter analyze`，`flutter test`。

### 9.3 CLI

| 命令 | 端 | 作用 |
| --- | --- | --- |
| `keyvalet relay install / status / set-url` | 两端 | 部署或指向 relay |
| `keyvalet pair --new` / `keyvalet pair <kv-pair://…>` | 两端 | §4 |
| `keyvalet devices list / revoke <id> / rename` | 两端 | 设备目录 |
| `keyvalet approvals [--watch]` | 审批端 | 待处理与最近决策；`approve <id> [--scope …]` / `deny <id>` 供终端用户使用（Strong 仍走 Touch ID / Hello） |
| `keyvalet grant … / list / revoke <jti> / revoke-all` | 审批端签发；两端查看 | §7.1、§7.4 |
| `keyvalet remote <device> mode <per_use\|per_credential\|per_session\|remember:Nh>` | 审批端 | Directive `set_mode`；放宽 Strong、收紧 Quick |
| `keyvalet remote <device> allow --credential X [--hosts …] [--until …\|--standing]` | 审批端 | 签发 §7.4 Grant（`--standing` 为常设，Strong） |
| `keyvalet remote <device> unattended --include-sensitive --until 7d` | 审批端 | `max_tier = T2` Grant，Strong + 二次输入设备标签（§7.6） |
| `keyvalet remote <device> lock / unlock-ttl <h> / class … / label …` | 审批端 | 其余 Directive |
| `keyvalet remote <device> status / pending / grants / audit [--since …]` | 审批端 | `query_*` Directive，结果本地渲染 |
| `keyvalet approve <pid>` | Linux 执行端 | 现有 SSH polkit 后备路径，不变 |
| `keyvalet status --summary` | 两端 | 增加：relay 连接状态、已配对设备数、待处理数、有效 Grant 数、是否处于无人值守（红） |

### 9.4 MCP 与 agent 可见行为

- `credential_http_request` 等使用类工具：新增可选参数 `approval_id`（§6.9.2 `approved_retry_required` 时使用）；新增结构化结果状态 `approval_pending`、`approval_denied`、`approval_expired`、`no_approver`（§6.9.1，正常结果而非协议错误），文案是写给模型看的，明确告诉它该等待还是该放弃。
- 新工具 `credential_wait_approval(approval_id, max_wait_s?)`（§6.9.2 第三层）。工具描述里写清：批准后直接返回原请求结果；不要重复发起原请求。
- `kv-mcp` 在 `initialize` 读取 `clientInfo.name` 选运行时预算（§6.9.3）；对带 `progressToken` 的请求按 `progress_interval_s` 发 `notifications/progress`；声明 `experimental["claude/channel"]` 能力并在批准时发 `notifications/claude/channel`（§6.9.2 第四层 a）。
- `credential_status`：增加 `remote_approval: { relay: connected|offline, approvers: [{label, online}], pending: [{approval_id, summary, expires_at}], grants: n, unattended: bool, runtime_budget_s: n }`。
- hooks：`kv-hook` 新增 `stop` 模式及各运行时变体（§6.9.2 第四层 b）；安装器为 Claude Code / Devin / Codex / Cursor / Gemini 注册对应 Stop 类事件。现有 PreToolUse / UserPromptSubmit 模式不变。
- 安装器为每个运行时写入 KeyValet 服务器自己的工具超时（§6.9.3「安装器写入」列），只改 KeyValet 这一项，不动用户其他服务器的配置。

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

执行端（Ubuntu helper，SQLite 于 `/var/lib/keyvalet/state.db`，与 vault 分开；敏感字段无）：

```sql
devices(id, account_id, dk_pub, akq_pub, akq_alg, aks_pub, aks_alg, key_kind, attestation_json, caps, label, trust, added_at, revoked_at)
                                                         -- 亦镜像到 vault AEAD 元数据；attestation 第一版只存不验（§13.2）
pending_approvals(id, kind, digest, nonce, canonical_json, exp, state, created_at, resolved_at, approver, level, scope_json,
                  agent_pid, agent_runtime, stop_hook_blocks, claimed_at)   -- 完整请求体只在 helper 内存（§6.9.2），不落盘
nonces(nonce, digest, used_at, exp)                      -- 现有；Directive 的 nonce 也进这张表
grants(jti, iss, iss_alg, aud, level, credential, hosts_json, methods_json, paths_json, agent, max_tier,
       budget_json, budget_left_json, nbf, exp, origin, sig, revoked_at)   -- §7.4，统一了弹窗范围 / 能力令牌 / 常设允许
directives(id, iss, op, args_json, applied_at, ok, error)                 -- §7.5 审计用副本
settings(key, value_json, set_by, set_at)                                 -- mode / unlock_ttl / class 等，本地与远程写同一份
revoked_jti(jti, revoked_at)
```

审批端（macOS root-only / Windows SYSTEM+Administrators）：

```sql
peers(id, account_id, dk_pub, caps, key_kind, label, trust, added_at, revoked_at)
issued_approvals(approval_id, peer, kind, digest, decision, level, scope_json, issued_at, summary_text)
issued_grants(jti, peer, level, credential, max_tier, exp, origin, issued_at, revoked_at)
issued_directives(id, peer, op, issued_at, result_ok, result_summary)
peer_state_cache(peer, mode, unattended, grants_count, pending_count, last_seen, fetched_at)   -- query_* 结果缓存，供设置页秒开
```

---

## 11. 审计

- 执行端每条 `use` 审计新增：`approver_device`, `approval_level`, `approval_latency_ms`, `approval_path` (`local | remote | grant:<jti> | auto`), `unattended_t2`（被 T2 Grant 覆盖时为 true）, `relay_clock_skew_s`。
- 执行端新增事件：`grant_installed / revoked / exhausted`, `directive_applied / rejected{op, iss, reason}`, `setting_changed{key, by: local|remote:<device>}`。
- 审批端新增事件：`remote_approval_issued / denied / expired_unseen`, `grant_issued / revoked`, `directive_issued{op, aud, result}`, `unattended_enabled / disabled`, `device_paired / revoked`, `pair_sas_mismatch`。
- 两端都进现有哈希链；`keyvalet audit --remote` 可按 `approval_id` 把两端记录对上。
- relay 自己的日志只有元数据，默认 7 天。

---

## 12. 威胁模型

| 攻击者 | 能做什么 | 不能做什么 | 依赖的机制 |
| --- | --- | --- | --- |
| Ubuntu 上被注入的 agent（用户 `u`） | 发起任意请求、编造 purpose、刷请求 | 读 vault、读 helper 内存、签批准、伪装成审批设备、让批准覆盖到不同的请求 | 文件权限 + 系统用户隔离；批准签名只认 `AK_*`；digest 绑定；限流与合并；UI 标注 purpose 为自述 |
| relay 运营者 / 被攻破的 relay / Cloudflare 边缘（TLS 在边缘终止） | 丢、延迟、重放旧信封、看元数据、拒绝服务 | 解密、伪造、让旧批准再次生效、把批准改派给别的请求 | HPKE + ES256；nonce 一次性；`exp`；`to`/`digest` 在 AAD/签名覆盖范围内 |
| 配对时的中间人 | 替换公钥 | 让两端 6 位 SAS 一致 | SAS 混入 token 与全部公钥；一次性 token |
| 偷到的 MacBook（已锁屏） | — | 批 Strong（Touch ID）；批 Quick（需解锁）；重连 relay 后拿到的只有密文 | SE ACL；`WhenUnlocked` |
| 偷到的 MacBook（已解锁、在手） | 批 Quick 级请求、看待处理内容、收紧设置、吊销 Grant | 批 T2 / unlock / admin；签常设或 T2 Grant；放宽任何设置 | `userPresence` 只认机主生物特征；放宽一律 Strong（§7.5） |
| 被注入的 agent 试图「自己给自己放权」 | 发起请求、在 purpose 里写「请选一直允许」 | 生成 Grant 或 Directive（没有审批密钥）；让弹窗出现执行端没给的范围选项 | Grant/Directive 只认审批密钥签名；`scope_options` 由执行端给出（§7.6 第 3 条） |
| 用户自己开了含 T2 的无人值守 | 被注入的 agent 可做任何该 Grant 范围内的敏感操作 | — | **这是用户明示接受的风险**：红色常驻状态、默认 7 天到期、`unattended_t2` 逐条审计、`revoke_all_grants` 一键收回（§7.6） |
| Ubuntu root / 被攻破的 helper | 一切（与现状相同） | — | **不在威胁模型内**，文档与状态如实声明 |
| Mac 上同用户的恶意进程 | 伪造一个看起来像 KeyValet 的对话框骗用户按 Touch ID | 拿到 `AK_*` 私钥；让真实 helper 发出批准（需要经签名校验的 agent） | 现有缓解：留意非自己触发的弹窗、看审计；V2 菜单栏 App 的一致视觉锚点；V1 的手机 App 本身就是独立于桌面的第二确认面 |
| 网络窃听 | 看到 TLS 流量 | 看内容 | TLS + 端到端加密双层 |

明确不承诺：防服务器 root；防 Mac root；防物理访问 TPM 芯片；relay 的可用性；Quick 级批准在 Mac 已解锁且在手时的防护。

---

## 13. 扩展口子：云端密钥保护、隔离执行与更多审批者

第一版全部跑在用户自己的机器上。但协议字段与 trait 一旦上线就难改，所以下面四条线在 V1 就把接口、枚举位和保留字段放好，**只放接口，不做实现**。原则：relay 永远不需要知道这些；执行端与审批端通过「设备记录里的声明」互相知道对方是什么。

### 13.1 四个 trait

| trait | 第一版实现 | 保留的实现位 | 对协议的影响 |
| --- | --- | --- | --- |
| `DeviceKeyProvider`（身份键与审批键） | `secure_enclave`、`tpm2`、`pcp_tpm`、`windows_hello`、`software` | `nitro_enclave_ephemeral`（启动时生成、公钥进证明文档）、`kms_asymmetric`（KMS Sign / ECDH，云执行端的身份）、`webcrypto`（Web 控制台的不可导出 P-256）、`yubikey_piv` | 设备记录的 `key.kind` 枚举；`alg` 已支持 ES256/RS256，云 KMS 的 ECC_NIST_P256 也是 ES256 |
| `MasterKeyProvider`（vault 主密钥，现有） | SE、TPM、Hello、软件 | `kms_envelope`（UMK 由 KMS 包裹，BYO-KMS 或托管）、`enclave_sealed` | `umk_wraps[*].alg` 枚举加 `kms-envelope`、`enclave-attested-hpke`；vault v2 格式本来就是「每设备一份包裹」 |
| `Executor`（谁来注入与执行，总架构 §9.1） | 本机 helper（三平台） | `nitro_enclave`（SealedJob HPKE 到 enclave 临时键，KMS Recipient 解 CEK）、`remote_helper`（V2 的 Mac 代 Linux 执行）、`cloud_worker`（远程 MCP 端点背后的执行池） | ApprovalRequest 的 `requester.protection` 由字符串改为对象 `{kind, attestation?}`；`caps` 加 `execute_isolated` |
| `Approver`（谁来批，总架构 §7.4） | `touchid`、`hello`、`polkit`、`remote-device`、`auto`、`capability` | `team`（N-of-M，路由到凭证所有者）、`policy_service`（组织策略服务自动批、带服务签名）、`webauthn`（浏览器 passkey 作审批键） | ApprovalDecision 加 `approver_kind: device \| service`，`quorum?: {m, n, sigs[]}`；执行端验签时按 `approver_kind` 选信任锚 |

### 13.2 协议里现在就放的保留字段

```
device record:      { …, key: { kind, alg }, attestation?: { kind: app_attest | nitro_nsm | tpm_quote | none, doc }, caps[] }
ApprovalRequest:    { …, requester: { device_id, label, os, protection: { kind, attestation? } } }
ApprovalDecision:   { …, approver_kind: "device", quorum?: … }
Grant / Directive:  { …, iss_kind: "device" | "service" | "org" }      // 第一版只有 device
Envelope:           { v: 1, … }                                         // v 升级规则：收到更高 v 的信封 ack 但不处理，审计 unsupported_version
```

执行端对 `attestation` 的态度：第一版**只记录不验证**，`status` 里显示 `attestation: unverified`。验证逻辑随第一个云执行端一起来。

### 13.3 每条云端路线各自要补什么（现在不做）

| 路线 | 已经有的 | 要补的 | 协议改动 |
| --- | --- | --- | --- |
| BYO-KMS / 托管 KMS 包裹 UMK（总架构 §11.4） | vault v2 `umk_wraps`；`MasterKeyProvider` | `kms_envelope` 实现；KMS 策略治理文档；轮换流程 | 无（新 `alg` 值） |
| Nitro Enclave 执行端（总架构 §11） | `Executor` trait；relay 对 caps 透明；§9 路由 | enclave 镜像、NSM 证明、KMS Recipient、`vsock-proxy`；审批端验证 PCR | 无（`protection.kind = nitro_enclave` + `attestation`） |
| Web 控制台作审批设备 | 设备记录、HPKE、Grant/Directive 都是 JSON | WebCrypto 键、浏览器端 HPKE、Quick-only（无在场门） | 无（`key.kind = webcrypto`，`caps` 不含 `approve_strong`） |
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
| 审批设备全部丢失 | 服务器本地 polkit 仍可操作一切；用恢复码在 relay 吊销旧设备；重新配对 |
| 同一请求收到两个批准 | 第二个在 nonce 表 `INSERT OR FAIL` 处失败，审计 `duplicate_decision` |
| Mac 醒来时积压过多 | 过期的丢弃并汇总提示；未过期的按序弹，最多 5 个同时 |
| 批准到了但 agent 已放弃 | pending 标 `approved_unused`，`exp` 后作废；审计可见 |

---

## 15. 代码落点

| crate | 变更 |
| --- | --- |
| `kv-platform` | `DeviceKeyProvider` trait（§13.1）及实现：TPM（创建/签名/ECDH）、SE 身份与审批密钥（经 `kv-touchid` 桥，三种 ACL）、Windows PCP（`NCryptSecretAgreement`/`NCryptSignHash`，服务上下文持久化）、Hello RS256 审批键、软件键；`presence_kind()` 上报；`PresenceProbe` trait 与三平台实现（§6.10.1：会话 / 锁屏 / 空闲 / 显示器 / 审批通道五个信号） |
| `kv-vault` | 元数据 v1.x：`identity_key_blob`、`devices`（含 `alg`、`key_kind`、`attestation`）；`umk_wraps[*].alg` 枚举预留 `kms-envelope` / `enclave-attested-hpke`（只读写，不实现） |
| `kv-core` | 规范化与 digest 加 `kind/requester/agent`；`ApprovalRequest`/`ApprovalDecision`/`Grant`/`Directive` 类型与 JCS 编码；签名验证按 `alg` 分派 ES256/RS256；HPKE 信封（`hpke` crate 或自组合，需审查依赖发布时间 ≥ 7 天）；§13.2 保留字段的序列化（未知字段保留、未知 `v` 拒绝） |
| `kv-helper` | `Approver` 实现 `RemoteDevice`（三平台）；pending/grants/directives/settings/nonce 表；§6.5 验证器；§6.8 选择器；fan-out；relay 子协议 IPC；内存中的完整请求保留与就地执行、`approval_id` 恢复、`agent_pid` 查询、Stop hook 计数（§6.9）；Grant 覆盖判定（§7.4）；Directive 执行器与档位规则（§7.5）；无人值守状态与 `unattended_t2` 审计（§7.6）；本地 `/keyvalet:mode` 与远程 `set_mode` 共用 `settings` |
| `kv-ipc` | 新消息：`RelayInbound/Outbound`、`SignWithIdentity`、`PendingList`、`Decide`、`WaitApproval`、`PendingForAgent(pid)`、`IssueGrant`、`IssueDirective`、`DirectiveResult`、`PeerStateQuery` |
| `kv-relay-client`（新） | WS 客户端、重连、磁盘队列、systemd / LaunchAgent / Windows 服务集成；转发 `presence_hint` 与 `approval_escalate` |
| `kv-mobile-core`（新，W8） | 手机 App 的 Rust 核心：信封、Grant/Directive、待批队列、SQLite 状态；两套绑定（`flutter_rust_bridge` 给 Dart、UniFFI/C ABI 给 iOS NSE）；`kv_native` 插件接口定义（§9.2.1） |
| `kv-server`（新） | §8 全部，feature `relay` |
| `kv-agent` / `kv-touchid` | macOS：远程审批对话框（范围下拉含常设选项）、SAS 确认、Strong 签名、Grant/Directive 签发流程、在场状态计算与去抖上报；Windows `kv-agent.exe`：同样的 TaskDialog 版本 + Hello RS256 签名 + 会话内 `GetLastInputInfo` / WTS 通知 |
| `kv-cli` | `relay / pair / devices / approvals [--on-approve] / grant … revoke-all / remote <device> …`（§9.3） |
| `kv-mcp` | `clientInfo` → 运行时预算表；`notifications/progress`；`credential_wait_approval`；`approval_id` 参数；四种结果状态；`claude/channel` 能力与通知；`credential_status` 字段；现有 60/180/200 s 常量改为由预算决定（§6.9） |
| `kv-hook` | 新 `stop` 模式及 Claude / Devin / Codex / Cursor / Gemini 变体：`getppid()` 查 pending、按上限阻止、各运行时输出 schema（§6.9.2 第四层 b） |
| `kv-proxy` | 网关与透明代理的挂连接等待、TCP keepalive、`429 + Retry-After` 与 `X-KeyValet-Approval` 头；`keyvalet run` 的 stderr 提示（§6.9.2 HTTP 路径） |
| `kv-protocols` | 模板新增 `client_timeout_hint_s`（OpenAI / Anthropic 等 SDK 默认超时），供 `kv-proxy` 决定挂连接上限 |
| `scripts/install.sh` / `install.ps1` | Linux：创建 `keyvalet-relay` 用户与单元；Mac：安装 `dev.keyvalet.relay`；Windows：注册 `KeyValetRelay` 服务与管道 DACL；三平台都为各运行时写入 KeyValet 自己的工具超时与 Stop 类 hook 注册（§6.9.3）。`install.sh` 遵守 AGENTS.md 的单引号与位置参数约束 |

---

## 16. 测试与验收

**CI 可跑（不依赖本机安装、TPM、SE、Touch ID）**，按 AGENTS.md 用 `env!("CARGO_MANIFEST_DIR")` 加载仓库文件，软件 P-256 密钥实现 `DeviceKeyProvider`，进程内 SQLite relay：

1. 配对：正常完成；SAS 不一致 → 双方丢弃；token 过期/复用 → 拒绝。
2. 信封：头部任一字段篡改 → 解封失败；`sig` 用错设备 → 拒绝；`to` 不是自己 → 拒绝。
3. 决策：重放同一决策 → nonce 冲突拒绝；digest 不一致 → 拒绝；`exp` 过 → 拒绝；T2 用 `AK_q` 签 → 拒绝；已吊销设备签 → 拒绝。
4. 范围：`scope` 超出 `scope_options` → 拒绝；grant 覆盖判定与 T2 不覆盖。
5. 排队：approver 离线 → 消息持久化 → 重连后送达；超时 → `approval_pending` → 带 `approval_id` 重试成功且只执行一次；参数变了 → 当新请求。
6. 能力令牌：验签、`aud`、预算扣减到 0 回落到审批、吊销后拒绝。
7. 合并：30 s 内同凭证 3 条 T1 → 1 个请求 → 临时 grant；T2 不合并。
8. relay：限流、同账户校验、`resolved` 后其他设备收到 cancel、7 天清理。
9. 明文零泄露：用含唯一标记的凭证名/主机跑完整流程，断言 relay 数据库与 relay 日志中 grep 不到标记。
10. 等待与恢复（§6.9，用进程内假 MCP 客户端驱动 `kv-mcp`）：预算内批准 → 原调用直接返回结果且发过 progress；预算用尽 → `approval_pending` 为正常结果；`credential_wait_approval` 批准后返回原请求结果且 pending 关闭、第二次调用得到 `already_consumed`；拒绝 → `approval_denied`；`exp` 过 → `approval_expired`；helper 重启后 → `approved_retry_required` → 带 `approval_id` 重发只执行一次；不同 `clientInfo.name` 得到表中对应预算；未知客户端 50 s。
11. Stop hook：有未到期 pending → 各运行时输出 schema 正确（Claude/Devin/Codex block、Cursor followup、Gemini deny）；阻止计数到 3 → 放行；`exp` 过 → 放行；无 pending → 放行且输出为空对象。
12. HTTP 路径：模板带 `client_timeout_hint_s` 时挂连接上限正确；超出后 `429` + `Retry-After` + `X-KeyValet-Approval`；挂连接期间批准 → 正常响应；`keyvalet run` 子进程 stderr 出现等待提示。
13. Grant（§7.4）：弹窗各范围选项生成的 Grant 字段正确；常设 Grant 覆盖 T1、不覆盖 T2；`max_tier = T2` Grant 覆盖 T2 且审计 `unattended_t2`；多张 Grant 命中时 `max_tier` 不放大、预算各扣；`aud = *` 对新配对设备生效；吊销后立即不覆盖；RS256 签发的 Grant 在执行端用设备记录的 `alg` 验签通过、用错 `alg` 失败。
14. Directive（§7.5）：收紧用 `AK_q` 通过、放宽用 `AK_q` 拒绝、放宽用 `AK_s` 通过；`nonce` 重放拒绝；`exp` 过拒绝；`query_*` 回包不含任何凭证值；本地 `/keyvalet:mode` 与远程 `set_mode` 写同一份 `settings` 且都审计；`revoke_all_grants` 后 `grants` 全部 `revoked_at` 非空。
15. 安全栏（§7.6）：`scope_options` 外的范围被拒；T2 请求的 `scope_options` 只有 `per_use`；`unattended` 签发缺二次确认时 CLI 拒绝；无人值守状态在 `status` 与弹窗标题中可见。
16. 保留字段（§13.2）：带未知 `attestation.kind`、未知 `key.kind` 的设备记录能存能读、状态显示 `unverified`；`v: 2` 信封被 ack 不处理并审计 `unsupported_version`；带未知顶层字段的 Grant/Directive 验签仍按 JCS 全字段通过（不丢字段）。
17. 在场与投递（§6.10，用假 `PresenceProbe` 驱动）：五个信号任一缺失 → `away`；`present` → 本机为主、远程 `delivery.mode = silent`；`idle`/`away` → 远程 `banner`；静默 30 s 未决 → 发 `approval_escalate` 且同一 `approval_id`；桌面审批端 `presence_hint` 变化去抖 5 s、最多 60 s 一次；`notify always-phone` 覆盖判定；在场状态不改变任何档位（present 下 T2 仍 Strong）。

**`#[ignore]`（实机）**：TPM 身份密钥往返；SE 三种 ACL 创建与 HPKE 解封；Touch ID Strong 签名；锁屏下 `AfterFirstUnlock` 身份签名可用而 `WhenUnlocked` 审批签名不可用；Windows PCP 在 LocalSystem 下的 P-256 ECDH/ECDSA 与原始共享点导出；Hello RS256 签名每次都弹在场；Windows 服务账户 `NT SERVICE\KeyValetRelay` 的管道 DACL 校验；三平台 `PresenceProbe` 的真实信号：锁屏 / 解锁 / 屏保 / 拔显示器 / RDP 断开 / 快速用户切换各一次，状态在 5 s 内变化。

**运行时实测清单（W5，结果回填 §6.9.3）**：每个运行时各跑一次「阻塞 4 分钟的工具 + 每 15 s progress」与「阻塞 4 分钟、不发 progress」，记录是否被杀、何时被杀、`progressToken` 是否存在；Stop 类 hook 的输入字段与阻止后的行为；Claude Code channels 在 `--dangerously-load-development-channels server:keyvalet` 下能否唤醒空闲 session。对象：Claude Code CLI 与 Desktop、Codex TUI 与 `codex exec`、Gemini CLI、Cursor IDE 与 `cursor-agent`、Grok Build、Devin CLI。

**实机验收（Ubuntu + MacBook）**，结果记入 review 文档：

| 指标 | 目标 |
| --- | --- |
| 从 `pair --new` 到首次远程批准成功 | < 10 分钟 |
| 审批端到端延迟（Mac 在线，经 Cloudflare + nginx）p50 / p95 | < 3 s / < 8 s |
| 一周 dogfooding 中被预授权/grant 覆盖的调用占比 | > 80 % |
| 一周内人工审批次数 | 可数、可解释（每一次都值得看） |
| MacBook 合盖 2 小时后醒来：积压送达且无重复执行 | 通过 |
| 吊销 Mac 后其旧批准与令牌 1 分钟内失效 | 通过 |
| `keyvalet audit --remote` 两端记录按 `approval_id` 全部对上 | 100 % |
| 从 MacBook 远程把 srv 切到 `per_use`、再签一张 1 小时 Grant、再 `revoke_all_grants`：三步各自在 5 s 内在 srv 生效且两端审计一致 | 通过 |
| Windows 执行端（M4）：同一套 CI 测试 + 实机 Hello 审批端批 Linux 请求 | 通过 |
| iPhone 与 Android（M3/M4）：锁屏 Quick、生物识别 Strong、静默→30 s 升级、设置页三步（切模式 / 签票 / 全部收回）各通过一次 | 通过 |
| 被篡改的 UI 层跳过生物识别后用 `AK_s` 签名 → 失败（iOS 与 Android 各一次） | 通过 |

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

```
M0  W0 交付契约 + 测试向量（其他工作流在此之前只读文档、搭骨架、写对契约的测试）
M1  W2 relay harness 可用；W1 软件实现可用  ──▶ W3 / W4 / W5 / W6 / W7 / W8 开始对真实依赖联调
M2  Linux 执行端（W4+W5+W3）× macOS 桌面审批端（W6+W7）端到端：Ubuntu + MacBook 上完成一次远程 use 审批
M3  手机 App（W8）加入同一账户：iPhone 批 Ubuntu 的请求；静默/升级投递正确
M4  Windows 执行端 + Windows 审批端（W1+W4+W6）接入；Android 接入
M5  W9 集成：安装器、文档、全工作区 CI、§16 实机验收表全部通过  ──▶ 一周 dogfooding
```

每个工作流在报告里必须写明自己处在哪个里程碑、还缺谁的什么。

### 17.4 V2 及以后（不在本轮）

Linux 桌面审批端；瘦菜单栏/托盘；vault 密文同步与手机 OAuth 添加凭证；总架构 §9 的 Mac 代 Linux 执行；第一个云端实现（BYO-KMS 包裹 UMK 或 Nitro 执行端）接到 §13 的接口上；App Store / Play 公开上架；官方 relay 与配额执行。

---

## 18. 需要用户决定的开放问题

1. 这台 Ubuntu 有没有 TPM 2.0（`ls /dev/tpmrm0`；`keyvalet status --summary`）？没有就按 §3.1 软件模式走，审批弹窗会一直标「software_key」。
2. relay 放这台 Ubuntu 上，还是单独一台小 VPS？用哪个域名接 Cloudflare 橙色云（§8.5 需要一个代理 DNS 记录与 Origin CA 证书）。
3. 服务器上跑哪些 agent（Claude Code / Codex / OpenClaw / Hermes / 自己的脚本）？决定 M2 先验证哪条接入路径（MCP、网关、`keyvalet run`）。
4. agent 是否已经以独立普通用户运行？若目前以 root 或 sudo 用户运行，第一步是先分用户。
5. `unlock_ttl` 默认 12 h 是否合适；夜间批处理是否需要 `class: batch` 的 24 h 有效期。
6. 调用内等待默认 60 s 还是 180 s？现设计默认 60 s、按运行时预算上调（§6.9.5）。
7. Stop hook 兜底是否默认开启；上限 3 次是否合适。
8. 是否在文档中推荐用户给 Claude Code 加 `--dangerously-load-development-channels server:keyvalet`。
9. **「以后再也不需要管」是否包含敏感操作（T2）？** 现设计（§7.6）：允许，但单独开、Strong + 二次确认、红色常驻、默认 7 天到期。这是对既有「T2 永远弹窗」决策的放宽。
10. 常设 Grant 的默认范围：「这个凭证一直允许」是否默认收窄到模板的 `allowed_hosts` 与 `GET/HEAD`？
11. 手机 App 的 Apple 开发者账号 / Google Play 开发者账号是否已就绪（TestFlight 与内部测试轨道都需要）；APNs 密钥与 FCM 项目由谁持有。
12. 并行工作流的 agent 数量：建议 W0 先单独跑完（它是所有人的依赖），之后 W1–W8 八个并行，W9 最后；若人手不够，合并顺序建议 W6+W7、W2+W3。

---

## 附录 A. 对象契约（JSON 形状）

约定：所有对象的 `sig` 覆盖「除 `sig` 外全部字段」的 JCS（RFC 8785）编码；时间戳为 Unix 秒（整数）；id 为 ULID 字符串；二进制字段为 base64url 无填充；未知字段**必须保留并参与签名验证**（不得丢弃），未知枚举值按各字段说明处理。JSON Schema 落在 `rust/crates/kv-core/schemas/remote/*.schema.json`，测试向量落在 `rust/crates/kv-core/testdata/remote/`。

### A.1 Envelope

```json
{ "v": 1, "type": "<见下>", "id": "ULID", "account": "acct_…", "from": "dev_…", "to": "dev_…",
  "created_at": 0, "exp": 0, "enc": "b64url", "ct": "b64url", "sig": "b64url" }
```

- `type ∈ { approval_request, approval_escalate, approval_decision, approval_cancel, grant, directive, directive_result, presence_hint, device_revoke, pair_offer, pair_accept, pair_confirm }`。
- AAD = JCS 编码的 `{v, type, id, account, from, to, created_at, exp}`；`sig` = ES256（发送方 `DK`，恒 P-256）覆盖 `AAD_bytes ‖ ct_bytes`。
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

`sig` 由 `level` 对应的审批键签，`alg` 取自设备记录。`scope.mode = standing` 时执行端生成 A.4 的常设 Grant（`exp = null`）。

### A.4 Grant（`type = grant`）

见 §7.4 的 JSON；补充约束：`scope.level = global` 时 `aud` 必须为 `*`；`max_tier = T2` 时 `origin` 必须为 `settings` 且 `exp` 非空或带 `confirm: "<执行端 label>"` 字段；`budget.per ∈ {1h, 24h, 7d}`。

### A.5 Directive / DirectiveResult（`type = directive | directive_result`）

见 §7.5 的 JSON；`args` 按 `op`：`set_mode{mode}`、`revoke_grant{jti}`、`revoke_all_grants{}`、`lock{}`、`set_unlock_ttl{seconds}`、`set_class{name, match, exp_s}`、`set_device_label{label}`、`revoke_device{device_id}`、`notify{policy: prefer-local|always-phone|both}`、`query_status{}`、`query_pending{}`、`query_grants{}`、`query_audit{since, limit≤200}`、`cancel_approval{approval_id}`。
`DirectiveResult = { "id": "<directive id>", "ok": true, "error": null, "state": { … 按 op 的返回 … } }`，`query_audit` 返回条目只含 §11 的元数据字段，不含任何凭证值或请求体。

### A.6 PresenceHint（`type = presence_hint`）

```json
{ "device_id": "dev_…", "state": "present | idle | away", "since": 0, "sent_at": 0 }
```

### A.7 Pairing（`type = pair_offer | pair_accept | pair_confirm`）

- `pair_offer`（发起方经 relay `/v1/pair/start` 后由 relay 转发给加入方）：`{ "token_hash": "hex", "initiator": <DeviceRecord> }`
- `pair_accept`：`{ "token": "b64url", "joiner": <DeviceRecord>, "global_grants"?: 0 }`；授权数量只在加密正文中。
- `pair_confirm`：`{ "sas": "6 位十进制", "device": <本端 DeviceRecord>, "exclude_global": false, "sig": "<AK_s 对整个对象 JCS 的签名（审批端）或空（纯执行端终端确认）>" }`；按附录 A 的通用签名规则移除 sig 后签名。两种确认均须有外层 DK 签名。
- `DeviceRecord = { "device_id", "label", "os", "key_kind", "dk_pub": "jwk", "ak_q": {"pub": "jwk", "alg": "ES256|RS256"} | null, "ak_s": {…} | null, "caps": ["execute","approve_quick","approve_strong"], "attestation": null }`
- `sas = 前 6 位十进制 of SHA-256("keyvalet-pair-v1" ‖ token ‖ sort(dk_pub_a, dk_pub_b) ‖ ak_q_pub ‖ ak_s_pub)`，公钥用 JWK 的 JCS 编码。
- 优先使用加入方 AK；其没有 AK_s 时使用发起方 AK。双方都没有 Strong 键时拒绝配对。DeviceRecord 的 label 是可变显示字段，其余公钥、算法、能力、平台及扩展权威字段保持不变；配对最终标签采用经确认签名认证的记录。

### A.8 agent 可见的工具结果（MCP）

```json
{ "status": "ok | approval_pending | approval_denied | approval_expired | no_approver | approved_retry_required | still_pending | already_consumed",
  "approval_id": "ULID", "expires_at": 0, "approver": { "label": "…", "online": true }, "wait_tool": "credential_wait_approval",
  "next_steps": "…", "result": { … 仅 status=ok 时 … } }
```

### A.9 DeviceRevoke（`type = device_revoke`）

`{ device_id, proof: { action: "revoke_device", account, by, device_id, challenge }, sig }`。proof 与 relay 删除使用同一个 DeviceDeleteProof；sig 是已信任发送者 AK_s 对 proof 的 JCS 签名。接收方核对目标、账户、发送者、32 字节 challenge 和 Strong 能力，然后写入设备 tombstone、撤销该设备签发的 Grant 并取消其尚未消费的决定。只有外层 DK 签名不能授权吊销。

吊销只收紧固定账户中固定设备 ID 的权限，设备 ID 不复用。为送达离线设备，吊销信封 `exp = 9007199254740991`，由原有持久 outbox 重发，relay 仍在 ack 后 7 天清理。接收方不要求旧 challenge 保持新鲜；relay DELETE 仍要求自己的新鲜一次性 challenge。relay 只验外层签名和路由，不能读取此正文。

---

## 附录 B. relay API 契约

认证：除 `/v1/devices`、`/v1/auth/*`、`/v1/pair/complete`、`/v1/health` 外，所有请求带 `Authorization: Device <session_token>`。错误体统一 `{ "error": { "code": "…", "message": "…" } }`，`code ∈ { unauthorized, forbidden, not_found, rate_limited, payload_too_large, bad_envelope, expired, conflict }`。

| 方法 | 路径 | 请求体 | 响应 |
| --- | --- | --- | --- |
| POST | `/v1/devices` | `DeviceRecord` + `push_token?` | `{ account_id, device_id, recovery_code? }`（首台设备才有 recovery_code） |
| POST | `/v1/auth/challenge` | `{ device_id }` | `{ challenge: b64url-32B, exp }` |
| POST | `/v1/auth/verify` | `{ device_id, challenge, sig }` | `{ session_token, exp, account_id }`；account_id 供身份绑定核对 |
| GET | `/v1/presence`（WebSocket） | 子协议 `kv-relay-v1`；客户端每 30 s 发 `{"t":"ping"}` | 服务端推 `{"t":"envelope","envelope":{…}}`、`{"t":"ack","id"}`、`{"t":"pong"}` |
| POST | `/v1/pair/start` | `{ token_hash, initiator: DeviceRecord, exp }` | `{ pairing_id }` |
| POST | `/v1/pair/complete` | `{ token, joiner: DeviceRecord }` | `{ pairing_id, initiator: DeviceRecord, account_id, expires_at }`；expires_at 为原始期限，同时向发起方推 `pair_accept` |
| POST | `/v1/pair/finish` | `{ pairing_id, confirm: pair_confirm }` | `{ ok }`；双方都 finish 后删除 token；同一成员、同一 SAS 的有效确认在原期限内可重试，仍需验签 |
| POST | `/v1/approvals` | `{ id, exp, envelopes: [Envelope] }`（每个 `to` 一个） | `{ accepted: n }` |
| POST | `/v1/approvals/{id}/reply` | `{ envelope: Envelope }` | `{ ok }`；首个有效回复后状态 resolved，向其他设备推 `approval_cancel` |
| POST | `/v1/approvals/{id}/cancel` | `{ envelope?: Envelope }` | `{ ok }`；带信封时传递 requester/helper 签名的 `approval_cancel`，保持密文与签名完整 |
| GET | `/v1/approvals?state=waiting` | — | `{ envelopes: [Envelope] }`（只返回 `to` = 自己的） |
| POST | `/v1/messages` | `{ envelopes: [Envelope] }` | `{ accepted: n }`；非审批类，持久化到 ack |
| POST | `/v1/messages/ack` | `{ ids: [], type?: string }` | `{ ok }`；relay-client 总是带 type，仅确认 helper 刚处理的信封类型 |
| DELETE | `/v1/devices/{id}` | `{ by: "device" \| "recovery", recovery_code? }` | `{ ok }` |
| GET | `/v1/health` | — | `{ ok, version }` |

限流默认：每设备每分钟 60 条 `approvals`、600 条 `messages`；每账户待处理 ≤ 500；单信封 ≤ 80 KiB。保留：送达并 ack 后 7 天删除。

传输重试必须幂等：相同账户、`id`、`to`、`type` 的同一完整签名信封重发成功，保留原 `acked_at`，不再重复推送；密文、签名或签名覆盖字段不同则返回 `conflict`。`/v1/approvals` 允许同一 requester 在原 `exp` 下向不同接收方分批提交，新增片段只在 `waiting` 时接收；已经存储的相同片段和相同回复在 `resolved` 后仍可重试。限额不重复计算已存储的片段。

同一个 `approval_id` 下的 request、escalate、cancel 是独立密文。ack 带 `type` 才能逐条确认，避免原 request 的 ack 与新 cancel 投递交错时提前确认 cancel。省略 type 的旧请求保留按 ID 批量确认的兼容行为；HTTP 与 WS ack 均支持 type 选择器，新 W2/W3 应一起部署。

relay 推送的裸 `approval_cancel`、`pair_accept` 控制帧只是无签名元数据提示。helper 状态变化必须依据签名信封；客户端忽略裸提示并继续传输。首个回复使 relay 状态成为 `resolved` 后，requester 仍可发送 helper 签名的取消信封以清除其他接收方的缓存，不改变已决状态。审批到期后同样可投递短时有效的签名取消信封；其有效期由 helper 单独给出，只授权清理该 requester 的原审批缓存，不延长审批的执行权限。空体 `{}` 的旧取消接口只操作未过期的等待审批，重复取消幂等。

---

## 附录 C. IPC 消息（`kv-ipc`）

在现有 IPC v4 上新增一个 `remote` 命名空间；所有消息都是 `{ "op": "remote.<name>", "params": {…} }` / `{ "ok": true, "result": {…} } | { "ok": false, "error": { "code", "message" } }`。

| op | 调用方 → 被调方 | params | result |
| --- | --- | --- | --- |
| `remote.relay.identity` | relay-client → helper | `{}` | `{ dk_pub, device_id, account_id }`（仅公钥；客户端核对配置绑定） |
| `remote.relay.inbound` | relay-client → helper | `{ envelope }` | `{ ack: true }` |
| `remote.relay.outbound.poll` | relay-client → helper（长轮询） | `{ max_wait_ms }` | `{ envelopes: [] }` |
| `remote.relay.outbound.ack` | relay-client → helper | `{ envelopes: [], stage: "spooled" \| "accepted" \| "inspect" }` | `{ retired_count }` |
| `remote.relay.control.poll` | relay-client → helper（冷启动亦可） | `{ max_wait_ms }` | `{ request: { id, relay_url, device_id: id或null, command: { op, params? } } 或 null }` |
| `remote.relay.control.complete` | relay-client → helper | `{ id, result: { kind, value } }` | `{ ok: true }`；结果类型必须对应原请求 |
| `remote.relay.control.sign` | relay-client → helper | `{ id, payload_b64 }` | `{ sig_b64 }`；仅该请求绑定的 DK challenge |
| `remote.relay.status` | relay-client → helper | `{ connected, last_error, since }` | `{}` |
| `remote.sign_identity` | relay-client → helper | `{ payload_b64 }` | `{ sig_b64 }` |
| `remote.presence.update` | agent → helper | `PresenceHint` | `{}` |
| `remote.pending.list` | cli / mcp → helper | `{ agent_pid? }` | `{ pending: [ApprovalRequest 摘要] }` |
| `remote.pending.for_agent` | hook → helper | `{ agent_pid }` | `{ pending: [{approval_id, expires_at, stop_hook_blocks}] }` |
| `remote.pending.stop_block` | hook → helper | `{ approval_id }` | `{ allowed: bool, blocks_left }` |
| `remote.wait` | mcp → helper（长轮询） | `{ approval_id, max_wait_ms }` | A.8 结果 |
| `remote.client_timeout_observed` | mcp → helper | `{}`（传输提示可忽略） | `{}`；仅审计，不拒绝、不取消、不消费审批 |
| `remote.decide` | agent / cli（审批端）→ helper | `{ approval_id, decision, scope, level }` | `{ sent: true }` |
| `remote.grant.issue` | cli / agent → helper | `Grant`（未签名） | `{ grant }`（已签名并已发送） |
| `remote.grant.list` / `revoke` | cli → helper | `{ after?, limit? }` / `{ jti }` | `{ grants, next_cursor }` / `{}`；分页规则见 C.2 |
| `remote.directive.issue` | cli / agent → helper | `Directive`（未签名） | `{ result: DirectiveResult }`（等待回包，超时 10 s） |
| `remote.pair.start` / `complete` / `confirm` | cli / agent → helper | 见 A.7 | `{ sas }` / `{}` |
| `remote.devices.list` / `revoke` / `rename` | cli → helper | … | … |
| `remote.status` | cli / mcp → helper | `{}` | `{ relay, approvers[], pending_n, grants_n, unattended, runtime_budget_s, approval: { wait_in_call_s, wait_tool_max_s, progress_interval_s } }` |

helper 对每个 op 校验调用方身份：relay-client 仅允许明确列出的 `remote.relay.*` 与 `remote.sign_identity`；hook 仅允许 `remote.pending.for_agent` / `stop_block`；MCP 仅允许 `remote.wait` / `pending.list` / `status` / `client_timeout_observed`；其余只允许 CLI（owner）与审批端 agent。签名身份 challenge 必须是原始 32 字节，不开放任意 DK 签名 oracle。

控制请求与结果的类型定义在 `kv-core::remote::relay_control`。命令只包括身份认证、设备注册、配对 start/complete/finish、密文 messages/ack、challenge、临时 WS 收取和携带 helper Strong 证明的吊销，不接受任意 HTTP 路径。队列最多 8 条、期限 45 s、poll 最多等待 30 s；取消或完成后请求 ID 失效。`control.sign` 使用 helper 自己的身份提供器并验证返回签名；首次 32 字节 challenge 被固定，相同 challenge 可重试，换 challenge 被拒绝。HTTP 会话令牌始终由客户端维护，错误只返回固定代码。

outbox 的交付以完整信封的规范 JSON 摘要绑定持久化回执。poll 响应丢失时继续返回原信封；客户端先持久化密文，再回 `spooled`，helper 记入数据库后停止 poll 重送，直到 `accepted` 才删除 helper outbox。relay 明确接受后，客户端先回 `accepted`，再删除自己的磁盘前缀。客户端每次发送前回 `inspect`：只有 helper 可以把已接受、已过期或对应审批已不再等待的连续前缀标为可删除，返回 `retired_count`；遇到首条仍有效的信封就停止。客户端只按该数量删除，不进行策略判断。`spooled` / `accepted` 返回数量恒为 0；相同回执幂等，迟到的落盘回执不会恢复已完成状态。

入站信封在 helper 完成验证/处理后 ack；已持久审计的永久拒绝（过期、签名错误、未来版本、已处理重放等）也可 ack，避免重放队列被毒化。存储、审计或密钥提供器等暂时失败不 ack。`remote.presence.update` 由 helper 将粗粒度 hint 封装并签名，再经同一 outbox 发送；原始 presence signals 不跨进程传播。

helper 可向已认证 MCP 连接发送 `remote.approval.resolved`，形状为 `{ op, params: { approval_id, status } }`；只通知结果可取，不包含请求正文或执行结果，不消费结果。单次冷连接默认只收响应；需要持久通知的冷连接显式带 `notifications: true`，已建立的凭证连接使用相同推送契约。Windows 由服务保留 worker 进程句柄，并在发送 worker ready 前，将其 PID 绑定到经 OS 验证的 launcher 父 PID；模型提交的 PID 不能覆盖该绑定。

---

### C.1 Owner intent 实现扩展（2026-10-12）

第 2、3 项对接在现有 op 名称和调用方白名单内增加以下参数投影。类型定义共用 `kv-ipc`／`kv-core`，CLI 不提供签名、发行者、对象 ID 或 nonce；这些由 helper 填充。原有未签名对象的 T1 兼容路径保留；旧 T2 请求仅附标签会返回 `secondary_confirmation_required`。

| op | 当前 owner 参数／结果扩展 |
| --- | --- |
| `remote.decide` | `{ approval_id, decision, scope, scope_option?, reason?, level? }`；helper 按原始请求、范围和风险选择最低级别，`level` 只能提高级别。remember 时间在实际授权后重新锚定。 |
| `remote.grant.issue` | `GrantIntent = { source: settings \| preauthorization, kind: grant, aud, scope, budget?, nbf, exp, origin: settings, confirm?, confirmation_token? }`；普通签发返回 `{ grant }`。T2 首次返回 `GrantConfirmation = { confirmation_token, expires_at, device_id, label, confirmations_left }`，精确标签确认后才签发。 |
| `remote.directive.issue` | `{ kind: directive, aud, op, args }`；helper 生成签名对象，并等待对应执行端的已认证回执。 |
| `remote.pair.start` / `complete` / `confirm` | owner 分别提交 `{ relay_url }`、`{ uri }`、`{ sas, confirmed, exclude_global?: false }`。开始／加入及配对状态可扩展 `global_grants` 数量、`uri`、`expires_at`、公开 `binding`、一次性 `recovery_code`、`pair_error`。最终完成状态从 `remote.status.pairing` 读取。 |
| `remote.pending.list` | owner 结果额外包含最近 200 条 `recent`，每条有持久递增 `decision_seq`；MCP 的结果不包含 owner 历史。 |
| `remote.grant.list` | 对象 Extra 承载 issued／installed 台账、使用快照和获取时间、各执行端使用量及 `revocation_pending`。审批决定衍生的内部 Grant 保留 `approval_decision` 权威来源，不伪造 Grant 签名。 |

T2 准备令牌最长 120 秒，只保存哈希，绑定调用方 UID／PID／角色、完整意图和当前设备记录，失败的最终尝试也消费令牌。常设 T2 的 `confirmations_left` 从 2 开始，第一次精确标签确认交换新令牌和 1，第二次才签发；两轮共享原截止时间。有限 T2 返回 1。准备证明使用与 Grant 不同的签名域，不产生可执行 Grant。

首次注册先保存加密设备身份，再调用 relay，断网重试复用原密钥。已有身份加入仅允许尚无信任关系和授权／审批状态的单设备，并通过受认证迁移日志保持账户、目录和 SQLite 一致。公开绑定只包含 relay URL、设备 ID 和账户 ID；恢复码不保存到该配置。配对 API 的 `expires_at` 和认证结果的 `account_id` 已纳入附录 B 响应字段表。

本地设置使用现有特权控制通道的 `remote_settings`，与远程 Directive 共用 helper 设置后端及 CAS，不扩大 MCP／relay-client 的 op 白名单。桌面确认经已有已认证私有 agent 通道进行；UI 同意不能替代实际 AK 签名。代码／schema、真实模块测试及实机验收边界详见 [第 2、3 项报告](remote-approval-reports/owner-integration-23.md)。

### C.2 管理一致性与分页扩展（2026-10-12）

- `remote.devices.revoke` 在配置 relay 时生成 Strong 删除证明、持久保存 peer 吊销信封并首先撤销本地权威，再投递密文及删除 relay 注册。网络或限流失败保留待重试状态，`remote.status.device_revocations_pending` 显示未完成 relay 删除的数量。离线 peer 由原有 outbox 继续投递；需要新 relay challenge 时由 owner 重试，不在后台绕过 Strong。
- `remote.devices.rename` 针对已连接的远程执行端发送 SetDeviceLabel，并等待已认证回执。执行端设置、SQLite DeviceRecord 和加密目录同时更新，owner 缓存新标签；T2 标签确认使用该记录。只有 label 可变，密钥／能力变更必须重新建立权威。relay 的配对注册校验同样区分 label 与不可变身份。
- SQLite 与加密目录通过加密 prepare 日志、SQLite `directory_commits` 标记和提交后发布保持同一提交决定。重开时提交标记存在则完成发布，否则丢弃准备日志。审计或 SQLite 回滚不会发布新目录；这不代替 T04 的硬件反回滚及完整审计锚定。
- `remote.grant.list` 和 QueryGrants Directive 的 args 均为 `{ after?: jti, limit?: 50 }`。limit 为 1–100，after 最长 256 字节且无控制字符；按 jti 排序，返回 `{ grants: […], next_cursor: jti | null }`。单页元数据正文不超过 48 KiB；超大对象返回显式 `object_omitted: true` 的有限摘要，不附带伪造签名。列表是元数据，不能作为新的授权对象安装。
- CLI 自动获取后续页再渲染完整列表，重复游标报协议错误。移动端用 Quick 签发有游标绑定的后续 QueryGrants，并合并各页；既有信封重放保护防止重复续页。分页期间授权变更可能影响快照，列表不承诺跨页事务快照。

## 附录 D. 本地数据 DDL

```sql
-- 执行端与审批端共用的表（同一 state.db；审批端的 vault 可能为空）
CREATE TABLE devices (
  id TEXT PRIMARY KEY, account_id TEXT NOT NULL, label TEXT NOT NULL, os TEXT NOT NULL, key_kind TEXT NOT NULL,
  dk_pub TEXT NOT NULL, akq_pub TEXT, akq_alg TEXT, aks_pub TEXT, aks_alg TEXT,
  caps TEXT NOT NULL, attestation BLOB, trust TEXT NOT NULL, added_at INTEGER NOT NULL, revoked_at INTEGER);
CREATE TABLE pending_approvals (
  id TEXT PRIMARY KEY, kind TEXT NOT NULL, digest TEXT NOT NULL, nonce TEXT NOT NULL, canonical_json TEXT NOT NULL,
  exp INTEGER NOT NULL, state TEXT NOT NULL, created_at INTEGER NOT NULL, resolved_at INTEGER,
  approver TEXT, level TEXT, scope_json TEXT, agent_pid INTEGER, agent_runtime TEXT,
  stop_hook_blocks INTEGER NOT NULL DEFAULT 0, claimed_at INTEGER, escalated_at INTEGER);
CREATE TABLE nonces (nonce TEXT PRIMARY KEY, digest TEXT NOT NULL, used_at INTEGER NOT NULL, exp INTEGER NOT NULL);
CREATE TABLE grants (
  jti TEXT PRIMARY KEY, iss TEXT NOT NULL, iss_alg TEXT NOT NULL, aud TEXT NOT NULL, level TEXT NOT NULL, credential TEXT,
  hosts_json TEXT, methods_json TEXT, paths_json TEXT, agent TEXT, max_tier TEXT NOT NULL,
  budget_json TEXT, budget_left_json TEXT, nbf INTEGER, exp INTEGER, origin TEXT NOT NULL, sig TEXT NOT NULL,
  installed_at INTEGER NOT NULL, revoked_at INTEGER);
CREATE TABLE directives (id TEXT PRIMARY KEY, iss TEXT NOT NULL, op TEXT NOT NULL, args_json TEXT NOT NULL,
  applied_at INTEGER NOT NULL, ok INTEGER NOT NULL, error TEXT);
CREATE TABLE settings (key TEXT PRIMARY KEY, value_json TEXT NOT NULL, set_by TEXT NOT NULL, set_at INTEGER NOT NULL);
CREATE TABLE revoked_jti (jti TEXT PRIMARY KEY, revoked_at INTEGER NOT NULL);
-- 审批端专用
CREATE TABLE issued_approvals (approval_id TEXT PRIMARY KEY, peer TEXT NOT NULL, kind TEXT NOT NULL, digest TEXT NOT NULL,
  decision TEXT NOT NULL, level TEXT NOT NULL, scope_json TEXT, issued_at INTEGER NOT NULL, summary_text TEXT NOT NULL);
CREATE TABLE issued_grants (jti TEXT PRIMARY KEY, peer TEXT NOT NULL, level TEXT NOT NULL, credential TEXT, max_tier TEXT NOT NULL,
  exp INTEGER, origin TEXT NOT NULL, issued_at INTEGER NOT NULL, revoked_at INTEGER);
CREATE TABLE issued_directives (id TEXT PRIMARY KEY, peer TEXT NOT NULL, op TEXT NOT NULL, issued_at INTEGER NOT NULL,
  result_ok INTEGER, result_summary TEXT);
CREATE TABLE peer_state_cache (peer TEXT PRIMARY KEY, mode TEXT, unattended INTEGER, grants_count INTEGER, pending_count INTEGER,
  presence TEXT, last_seen INTEGER, fetched_at INTEGER NOT NULL);
```

状态机：`pending_approvals.state ∈ { waiting, approved, approved_unused, executed, denied, expired, cancelled }`；`devices.trust ∈ { verified_sas, recovery, revoked }`。relay 侧 DDL 见 §8.3。

---

## 附录 E. CLI 与 MCP 面

CLI 约定：所有子命令支持 `--json`；退出码 `0` 成功、`2` 参数错误、`3` 被执行端拒绝（验签/档位）、`4` 超时、`5` relay 不可达、`6` 需要 Strong 但用户取消。完整命令表见 §9.3；`keyvalet remote <device> …` 中 `<device>` 接受设备 id、标签或 `*`。

MCP 新工具 `credential_wait_approval`：

```json
{ "name": "credential_wait_approval",
  "description": "等待一条待批准的 KeyValet 请求。批准后直接返回该请求的执行结果；不要重复发起原请求。",
  "inputSchema": { "type": "object", "required": ["approval_id"],
    "properties": { "approval_id": { "type": "string" }, "max_wait_s": { "type": "integer", "minimum": 5, "maximum": 600 } } } }
```

现有使用类工具（`credential_http_request` 等）新增可选参数 `approval_id`（string）。`credential_status` 的 `remote_approval` 字段见 §9.4。所有新状态都通过 `content[0].text` 的 JSON（A.8）返回，`isError = false`。

---

## 附录 F. 代码布局、依赖与测试向量

新 crate：`rust/crates/kv-server`（bin `kv-server`，features `relay`，默认开）、`rust/crates/kv-relay-client`（bin `kv-relay-client`）、`rust/crates/kv-mobile-core`（lib，`staticlib + cdylib + rlib`）、`rust/crates/kv-push`（bin）。全部加入 `rust/Cargo.toml` 的 workspace members（由 W0 一次性加入，带空骨架，避免并行改同一文件）。

依赖选型（W0 决定并写入 `Cargo.lock`；其他工作流不新增依赖，需要则在报告里申请）：HTTP/WS 用 workspace 已有或 `axum` + `tokio-tungstenite`；SQLite 用 workspace 已有的 `rusqlite`；HPKE 优先 `hpke` crate，若其 P-256 支持或维护状态不满足则在 `kv-core` 内用现有 `p256` + `hkdf` + `aes-gcm` 自组合（RFC 9180 的 DHKEM 与 key schedule 都有测试向量）；JCS 用 `serde_jcs`；JWK 用 `p256::pkcs8` 导出。任何新依赖须已发布 ≥ 7 天，并记录在 W0 报告里。

测试向量（`rust/crates/kv-core/testdata/remote/`，W0 生成，所有工作流消费）：`envelope_roundtrip.json`（软件密钥对、明文、期望密文长度与 AAD）、`approval_request_digest.json`（canonical 与 digest）、`decision_valid.json` / `decision_wrong_key.json` / `decision_replayed.json`、`grant_standing_t1.json` / `grant_t2_requires_settings.json`、`directive_tighten_quick_ok.json` / `directive_loosen_quick_rejected.json`、`pair_sas.json`、`rs256_decision.json`（Windows Hello 形态）。每个向量文件自带 `expect` 字段，各 crate 的测试只断言 `expect`。

日志与 i18n：审批对话框与 MCP 结果文案通过现有 `kv-i18n`（zh-CN / en）；日志里永远不出现凭证值、请求体、`ct`、私钥材料；`RUST_LOG=kv_remote=debug` 打开远程审批调试。
