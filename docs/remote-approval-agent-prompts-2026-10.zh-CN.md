# 远程审批 V1：并行开发的 agent prompt

用法：每个工作流一个代码块，**整块复制**给一个 agent，不需要再补任何上下文。每个 prompt 自带全部规则、阅读清单、所有权边界、验收标准与报告格式。顺序：先单独跑 W0（它是所有人的依赖），W0 报告「契约与测试向量已落地」后再并行启动 W1–W8，最后跑 W9。配套设计见 [remote-approval-architecture-2026-10.zh-CN.md](remote-approval-architecture-2026-10.zh-CN.md)。

---

## W0 契约与测试向量

```text
你是 KeyValet 仓库（/Users/guang/dev/keyvalet）「远程审批 V1」项目的 W0 工作流：契约与测试向量。你是其他八个并行工作流的唯一依赖，你的产出就是它们编程的对象。

【先读，不读完不要动手】
1. AGENTS.md（仓库根目录）：CI 命令、测试不得依赖本机安装、install.sh 单引号约束、签名与发布规则。全部遵守。
2. docs/remote-approval-architecture-2026-10.zh-CN.md 全文，重点：§3.1 密钥与 alg、§5 信封、§6.2 规范化与 digest、§6.3–6.5 请求/决定/验证、§7.4–7.6 Grant / Directive / 安全栏、§13.2 保留字段、§17 工作流、附录 A–F（契约、relay API、IPC、DDL、CLI/MCP、代码布局与依赖）。附录与正文冲突时以附录为准。
3. docs/remote-approval-product-2026-10.zh-CN.md §6.1、§6.2（用户语言与审批边界）。
4. rust/crates/kv-core、rust/crates/kv-ipc、rust/crates/kv-vault 现有代码：模块组织、错误类型、序列化约定、测试风格；你的新代码必须像这个仓库里已有的代码。

【硬性规则】
- 不执行任何改变 git 状态的命令：不 commit、不 branch、不 stash、不 checkout、不 reset、不 rebase、不 push。只允许只读的 git status / git diff / git log。直接在当前 main 工作树上改文件。
- 只改你拥有的路径：rust/crates/kv-core/（新增 remote 模块、schemas/remote/、testdata/remote/）、rust/crates/kv-ipc/（新增 remote 命名空间消息）、rust/Cargo.toml（只为新增 workspace 成员与依赖）、rust/Cargo.lock、以及为新 crate 创建空骨架：rust/crates/kv-server、rust/crates/kv-relay-client、rust/crates/kv-mobile-core、rust/crates/kv-push（每个只含 Cargo.toml + src/lib.rs 或 main.rs 的最小可编译骨架，不写功能）。其他任何文件不碰；需要别处改动的，写进报告的「变更请求」。
- 使用 CARGO_TARGET_DIR=/Users/guang/dev/keyvalet/rust/target-w0，所有 cargo 命令都加 -p 限定到你的 crate；不要对整个工作区跑 fmt/clippy/test（那是 W9 的事）。
- 新依赖必须已发布 ≥ 7 天，优先复用工作区已有依赖；每个新依赖在报告里写出名称、版本、发布日期、选择理由。候选见架构文档附录 F。
- 代码、注释、提交信息风格用英文，与现有 crate 一致；不新增与现有风格不符的注释；不写 README 之类的文档文件。
- 日志与错误信息里永远不出现私钥材料、密文、凭证值。
- 遇到契约里没写清、而你必须做决定的地方：先在报告里列出问题与你的选择，再按你的选择实现，并在代码里加 `// CONTRACT:` 注释指向架构文档的章节号。

【任务】
A. 在 kv-core 新增 remote 模块，落地附录 A 的全部对象为 Rust 类型（serde），字段名、枚举值、可选性与附录完全一致；未知字段必须保留（serde(flatten) 的 extra map 或等价手段）并参与签名验证；未知枚举值按附录各字段说明处理（例如 protection.kind 未知 → Unknown(String)）。
B. JCS（RFC 8785）规范化、§6.2 的 digest、附录 A.1 的 AAD、A.7 的 SAS 计算。
C. HPKE 信封：DHKEM(P-256, HKDF-SHA256) + HKDF-SHA256 + AES-128-GCM，base mode，info = "keyvalet/envelope/v1"；seal/open API 以 trait 形式接受外部提供的 ECDH（为了让 SE/TPM/PCP 的硬件 ECDH 接入），同时提供一个软件 P-256 实现用于测试与 relay-client。按附录 F 决定用 hpke crate 还是自组合；两条路都要通过 RFC 9180 的官方测试向量。
D. 签名：ES256 与 RS256（PKCS#1 v1.5/SHA-256）验签分派，按设备记录里的 alg 选择；签名 API 同样是 trait（硬件签名在别的 crate 实现）。
E. DeviceKeyProvider trait（§3.1、§13.1）：sign(alg, payload)、ecdh(peer_pub)、public_jwk()、presence_kind()、key_kind()；加一个 SoftwareDeviceKey 实现（P-256 与 RSA-2048 两种）供全工作区测试使用。
F. PresenceProbe trait 定义（§6.10.1：返回 Present | Idle | Away + since + 各信号原值），只定义不实现。
G. Approver / Executor 两个 trait 的扩展点字段（§13.1：approver_kind、quorum、requester.protection 对象化）体现在类型里。
H. kv-ipc：按附录 C 新增 remote.* 消息的请求/响应类型与 op 名常量，以及「调用方身份 → 允许的 op 集合」表（只定义，helper 来执行）。
I. JSON Schema：每个对象一个文件，放 rust/crates/kv-core/schemas/remote/；加一个测试断言每个 Rust 类型的样例序列化通过对应 schema。
J. 测试向量：按附录 F 的清单生成到 rust/crates/kv-core/testdata/remote/，每个文件带 expect 字段；用固定的测试密钥对（写在向量文件里，仅供测试）。kv-core 自己的测试必须全部只断言 expect。
K. 在 rust/Cargo.toml 加入四个新 crate 骨架为 workspace 成员，确保 cargo build -p 各自通过。

【验收（全部通过才算完成）】
- CARGO_TARGET_DIR=rust/target-w0 cargo fmt -p kv-core -p kv-ipc -p kv-server -p kv-relay-client -p kv-mobile-core -p kv-push -- --check
- 同上 clippy --all-targets -- -D warnings；build；test —— 均 -p 限定。
- RFC 9180 测试向量、附录 F 列出的全部自制向量、JSON Schema 校验测试全部通过。
- 用 env!("CARGO_MANIFEST_DIR") 加载 testdata，不依赖本机 KeyValet 安装。

【报告（写到 docs/remote-approval-reports/W0.md，不要放别处）】
1. 改动文件清单。2. 新依赖表（名称/版本/发布日期/理由）。3. 契约落地时做的每一个解释性决定与对应章节。4. 测试向量清单与各自覆盖的规则。5. 对架构文档附录的变更请求（如有）。6. 未决问题。
```

---

## W1 平台密钥与在场探针

```text
你是 KeyValet 仓库（/Users/guang/dev/keyvalet）「远程审批 V1」项目的 W1 工作流：三平台设备密钥与在场探针。

【先读，不读完不要动手】
1. AGENTS.md：CI 命令、测试不得依赖本机安装、需要 root/sudo/Touch ID 的测试标 #[ignore] 并写明运行方法、签名团队 PWCRJPY7YC。
2. docs/remote-approval-architecture-2026-10.zh-CN.md：§3.1–3.2（每平台三把键、alg、存放）、§6.10（在场判定的五个信号与三平台 API）、§13.1（DeviceKeyProvider 保留实现位）、附录 A.7（DeviceRecord 形状）。
3. docs/architecture-2026-10.md §8.0–8.1.1（现有 SE / TPM / Hello 实现的事实与边界，尤其「加密表示只绑定设备」「Apple 不支持 daemon 用 SE」「PCP 是身份键不是审批门」）。
4. docs/linux.md、docs/windows.md、docs/key-protection.md：现有平台实现状态。
5. rust/crates/kv-platform、kv-touchid、kv-agent 现有代码；rust/crates/kv-core/src/remote/ 里 W0 已落地的 DeviceKeyProvider、PresenceProbe trait 与 SoftwareDeviceKey（以它们为准，不要自己再定义一套）。

【硬性规则】
- 不执行任何改变 git 状态的命令（不 commit / branch / stash / checkout / reset / rebase / push）；只读 git 命令可用。直接在 main 工作树改文件。
- 只改你拥有的路径：rust/crates/kv-platform/、rust/crates/kv-touchid/（仅新增 SE 身份键与审批键的创建/签名/ECDH 桥接）、rust/crates/kv-agent/（仅 Windows PCP/Hello 密钥与三平台在场探针部分；对话框部分归 W6，不要碰）。其他文件不碰；需要改 kv-core trait 的，写进报告「变更请求」。
- CARGO_TARGET_DIR=/Users/guang/dev/keyvalet/rust/target-w1；所有 cargo 命令 -p 限定；不跑全工作区检查。
- 不新增依赖；确需则在报告申请。
- 硬件失败永远报错，不静默回退软件键；软件键只在显式配置下使用并在 key_kind 上报 software。
- 任何需要真实 TPM / SE / Hello / 图形会话的测试标 #[ignore]，并在测试文档注释里写明在哪台机器怎么跑。
- 代码与注释英文，风格与现有 crate 一致；日志不出现密钥材料。

【任务】
A. DeviceKeyProvider 实现：
   - Linux TPM 2.0：新建 sign+decrypt 的非受限 ECC P-256 对象（fixedTPM/fixedParent），与现有 vault 主密钥是不同对象；ECDSA 经 tpm2_sign、ECDH 经 tpm2_ecdhzgen，走现有受信 tpm2-tools 路径与 /dev/tpmrm0；blob 存入 vault 的 AEAD 认证元数据（接口由 kv-vault 提供，若缺少则写变更请求）。
   - Linux 显式软件：0600 文件，key_kind = software。
   - macOS SE：三把键 DK（AfterFirstUnlockThisDeviceOnly，无生物 ACL）、AK_q（WhenUnlockedThisDeviceOnly，无生物 ACL）、AK_s（userPresence），经 helper → dev.keyvalet.agent → kv-touchid 的现有路径；先做 spike：CryptoKit HPKE.Recipient 是否接受 SecureEnclave.P256.KeyAgreement.PrivateKey 做解封，不行则改为 SE ECDH 取共享点 + Rust 侧 HKDF/AEAD（kv-core 的 trait 设计就是为此）。把 spike 结论写进报告并建议回填架构文档 §3.1。
   - Windows：DK 与 AK_q 用 NCrypt Platform Crypto Provider 的 P-256（NCryptSecretAgreement / NCryptSignHash，LocalSystem 服务上下文下创建与持久化）；AK_s 用现有 Windows Hello KeyCredentialManager RSA-2048，alg = RS256；无 TPM 时 DPAPI 软件键并上报 software。先做 spike：PCP 的原始 ECDH 共享点能否以 BCRYPT_KDF_RAW_SECRET 取出；结论进报告。
B. PresenceProbe 实现（§6.10.1 表）：
   - macOS：SCDynamicStoreCopyConsoleUser 的 console user 与 owner 比较；CGSessionCopyCurrentDictionary 的 CGSSessionScreenIsLocked；分布式通知 com.apple.screenIsLocked / screenIsUnlocked / com.apple.screensaver.didstart；CGEventSourceSecondsSinceLastEventType(kCGEventSourceStateCombinedSessionState, kCGAnyInputEventType)；CGGetActiveDisplayList 与 CGDisplayIsAsleep；kv-touchid 可达性。
   - Windows：WTSGetActiveConsoleSessionId / WTSEnumerateSessions 的会话状态（WTSActive / WTSDisconnected）；WTSRegisterSessionNotification 的 LOCK/UNLOCK；会话内进程的 GetLastInputInfo；EnumDisplayDevices；Hello 可用性。
   - Linux：org.freedesktop.login1 的 Active/State/Type/LockedHint/IdleHint/IdleSinceHint；org.freedesktop.ScreenSaver.GetActive 补充；/sys/class/drm/*/status；polkit agent 注册状态。任何信号取不到 → 该项按最保守值（away）。
   - 去抖 5 s，状态变化时经 IPC 上报 helper（消息名用 kv-ipc 里 W0 定义的 remote.presence.update；若 helper 尚未实现接收，先在 agent 侧留接口与单元测试）。
C. 单元测试用 W0 的 SoftwareDeviceKey 与可注入的假信号源覆盖全部状态机分支；硬件测试 #[ignore]。

【验收】
- CARGO_TARGET_DIR=rust/target-w1 cargo fmt -p kv-platform -p kv-touchid -p kv-agent -- --check；clippy --all-targets -- -D warnings；build；test，均 -p 限定且通过。
- 每个平台的 DeviceKeyProvider 都能用 W0 的测试向量验证自己产生的签名/ECDH 与软件实现一致（软件路径 CI 可跑；硬件路径 #[ignore] 并在本机至少跑一次 macOS 的）。
- PresenceProbe 的五个信号任一缺失 → Away 有测试。

【报告（docs/remote-approval-reports/W1.md）】
改动文件；两个 spike 的实测结论与证据（命令、输出摘要）；每平台 key_kind 与 presence_kind 的上报值；对 kv-core / kv-vault 的变更请求；未决问题；哪些测试需要在哪台机器跑。
```

---

## W2 relay 服务

```text
你是 KeyValet 仓库（/Users/guang/dev/keyvalet）「远程审批 V1」项目的 W2 工作流：relay 服务 kv-server 及其部署资产。

【先读，不读完不要动手】
1. AGENTS.md：CI 命令、测试不得依赖本机安装。
2. docs/remote-approval-architecture-2026-10.zh-CN.md：§5 信封（relay 只验外层签名与同账户）、§8 全部（技术选型、API、数据模型、看得到/看不到、§8.5 nginx + Cloudflare 橙色云部署）、§12 威胁模型里 relay 一行、附录 A.1（Envelope）、附录 B（API 契约，以此为准）。
3. docs/architecture-2026-10.md §10.1–10.3（总架构对 relay 的要求与官方实例的后续形态）。
4. rust/crates/kv-core/src/remote/（W0 落地的 Envelope、DeviceRecord 类型与验签 API；直接复用，不要重新定义）；rust/crates/kv-server 的空骨架（W0 建好）。

【硬性规则】
- 不执行任何改变 git 状态的命令（不 commit / branch / stash / checkout / reset / rebase / push）；只读 git 命令可用。直接在 main 工作树改文件。
- 只改：rust/crates/kv-server/、deploy/relay/（新建：systemd 单元、nginx 配置模板、Dockerfile、README 不要写）。其他文件不碰；需要改 kv-core 的写变更请求。
- CARGO_TARGET_DIR=/Users/guang/dev/keyvalet/rust/target-w2；cargo 命令 -p kv-server；不跑全工作区检查。
- 依赖：优先 workspace 已有；HTTP/WS 允许 axum + tokio-tungstenite（或 axum 自带 ws），SQLite 用 rusqlite；任何新依赖须已发布 ≥ 7 天并写入报告。
- relay 永远不解析 ct，不存明文，日志只有元数据；不要为「方便调试」加任何解密路径。
- 部署链路固定：Cloudflare 橙色云 → nginx（Origin CA 证书）→ kv-server 监听 127.0.0.1:8787。不要引入 Tailscale、Caddy、Let's Encrypt 或自签证书方案。
- 代码与注释英文，风格与现有 crate 一致。

【任务】
A. 实现附录 B 的全部端点与错误体；WebSocket 子协议 kv-relay-v1（ping/pong/envelope/ack）；30 s 心跳容忍、100 s 无流量视为断开（与 Cloudflare 边缘行为一致）。
B. 设备注册与匿名账户（首台设备创建账户并返回一次性恢复码，存 Argon2id 哈希）；challenge/verify 用 kv-core 的 ES256 验签换会话令牌（24 h，可续）。
C. 配对三步（start/complete/finish）：token 只存哈希、10 分钟过期、一次性；向发起方推 pair_accept。
D. approvals：fan-out 存储（每个 to 一条）、首个有效 reply 后标 resolved 并向其余设备推 approval_cancel、cancel、waiting 拉取只返回 to = 自己。
E. messages / ack：非审批类信封持久化到 ack；ack 后 7 天清理；approvals 过期后 7 天清理（后台任务）。
F. 限流（附录 B 默认值）；客户端 IP 取 CF-Connecting-IP，但只在对端是 127.0.0.1（nginx）时信任该头，否则用 socket 地址。
G. SQLite（WAL）数据模型按 §8.3；presence 表进程内维护；plan 字段预留，不实现计费。
H. deploy/relay/：keyvalet-relay.service（Restart=always、专用用户、只听本地）；nginx 模板（照 §8.5 的配置，含 WS 升级头、proxy_read_timeout 90s、client_max_body_size 1m、Origin CA 证书路径、可选 Authenticated Origin Pulls 注释块）；Dockerfile（distroless 或 debian-slim，非 root）；一份 cloudflare-checklist.txt（DNS 橙色云、SSL 模式 Full (strict)、防火墙只放 Cloudflare IP 段）。
I. 进程内测试 harness：pub fn spawn_test_relay() -> (Url, Handle)，用内存 SQLite，供 W3/W4/W8 的测试复用；在 kv-server 内用它写端到端测试：两台软件设备注册 → 配对 → 一条审批 → 回复 → 另一设备收到 cancel → 重放被拒 → 限流触发 → 清理任务。
J. 零明文测试：用含唯一标记的字符串当 ct 以外的测试负载跑完整流程，断言数据库文件与日志中 grep 不到标记以外的任何明文字段（即只允许出现 id/时间戳/公钥）。

【验收】
- CARGO_TARGET_DIR=rust/target-w2 cargo fmt -p kv-server -- --check；clippy --all-targets -- -D warnings；build；test 全过。
- 端点行为与附录 B 表逐行一致（在测试里逐端点断言请求/响应体形状）。
- `kv-server --listen 127.0.0.1:8787 --data /tmp/x` 能启动并通过 /v1/health。

【报告（docs/remote-approval-reports/W2.md）】
改动文件；新依赖表；与附录 B 的任何偏差及理由；harness 的用法示例；nginx/Cloudflare 部署步骤的实测记录（如本机只能验证 nginx 配置语法，写明）；未决问题与变更请求。
```

---

## W3 relay 客户端

```text
你是 KeyValet 仓库（/Users/guang/dev/keyvalet）「远程审批 V1」项目的 W3 工作流：三平台 relay 客户端守护进程 kv-relay-client。

【先读，不读完不要动手】
1. AGENTS.md：CI 命令、测试不得依赖本机安装、signed daemon/agent 模式与 sudo 模式、audit token 校验（kv-platform/src/paths.rs 的 AGENT_REQUIREMENT）。
2. docs/remote-approval-architecture-2026-10.zh-CN.md：§2（进程与信任边界，relay-client 不持私钥、HPKE 封解都在 helper）、§2.3（三平台的进程形态与账户）、§8（relay API）、§9.1（relay-client 行为）、§14（失败模式里 relay 不可达的行为）、附录 B、附录 C（remote.relay.* 与 remote.sign_identity IPC 消息）。
3. rust/crates/kv-ipc（现有 IPC v4 的传输与 W0 新增的 remote.* 消息类型）、rust/crates/kv-platform/src/paths.rs（socket/pipe 路径、标签）、scripts/install.sh 里 LaunchAgent/systemd 的现有写法（只读，不改）；rust/crates/kv-server 的 spawn_test_relay harness（W2，若尚未就绪先用 W0 的类型对一个最小假 relay 编程）。

【硬性规则】
- 不执行任何改变 git 状态的命令（不 commit / branch / stash / checkout / reset / rebase / push）；只读 git 命令可用。直接在 main 工作树改文件。
- 只改 rust/crates/kv-relay-client/。服务定义文件（systemd 单元、LaunchAgent plist、Windows 服务注册）写到 rust/crates/kv-relay-client/service/ 下作为模板，由 W9 接入安装器；不要改 scripts/。
- CARGO_TARGET_DIR=/Users/guang/dev/keyvalet/rust/target-w3；cargo 命令 -p kv-relay-client。
- 不新增依赖（WS 客户端优先 tokio-tungstenite，与 W2 一致）；确需则报告申请。
- 这个进程不持任何私钥、不做任何策略判断、不存任何明文；需要签名就经 IPC 请 helper 用身份键签；收到的信封原样交给 helper，由 helper 决定 ack。
- 代码与注释英文，风格与现有 crate 一致。

【任务】
A. 单二进制，三平台编译：Linux 以系统用户 keyvalet-relay 运行、连 /var/run/keyvalet/relay.sock；macOS 以 per-user LaunchAgent dev.keyvalet.relay 运行、连 helper socket 的 relay 子协议；Windows 以虚拟服务账户 NT SERVICE\KeyValetRelay 的服务运行、连 \\.\pipe\keyvalet-relay。路径与标签常量从 kv-platform 取，缺的写变更请求。
B. 启动：读配置（relay_url、device_id、account_id；Linux /etc/keyvalet/relay-client.toml，macOS ~/Library/Application Support/KeyValet/relay-client.toml，Windows C:\ProgramData\KeyValet\relay-client.toml）→ 经 IPC 向 helper 要身份公钥 → /v1/auth/challenge → 请 helper 签 → /v1/auth/verify → 建 WS。
C. 运行：30 s 心跳；收到 envelope → remote.relay.inbound → 收到 helper 的 ack 再回 relay ack；长轮询 remote.relay.outbound.poll 取待发信封 → POST /v1/approvals 或 /v1/messages；定期 remote.relay.status 上报连接状态。
D. 可靠性：指数退避重连 1 s → 60 s；磁盘密文队列（待发信封，只存密文；Linux /var/lib/keyvalet-relay/queue、其他平台对应目录），relay 不可达时不丢；重连后先拉 GET /v1/approvals?state=waiting 再处理队列。
E. 服务模板：systemd 单元（ProtectSystem=strict、PrivateTmp、NoNewPrivileges、RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6、无 CAP_*）、LaunchAgent plist（KeepAlive）、Windows 服务安装/卸载子命令（sc.exe 参数或 windows-service crate 已在工作区则用之）。
F. 测试：用 W2 的 spawn_test_relay（或最小假 relay）+ 假 helper（实现 remote.relay.* 的 IPC 服务端）覆盖：认证流程、心跳、断线重连、队列持久化与恢复、waiting 拉取、ack 语义、relay 返回 429/5xx 的退避。全部 CI 可跑，不依赖本机安装。

【验收】
- CARGO_TARGET_DIR=rust/target-w3 cargo fmt -p kv-relay-client -- --check；clippy --all-targets -- -D warnings；build（在 macOS 上至少 build 通过 Linux 目标用 cargo check --target x86_64-unknown-linux-gnu 如工具链可用，否则在报告说明）；test 全过。
- 杀掉假 relay 30 s 再拉起，期间发出的信封全部送达且顺序不变。

【报告（docs/remote-approval-reports/W3.md）】
改动文件；服务模板路径与 W9 接入说明；对 kv-platform 路径常量、kv-ipc 消息的变更请求；平台未验证项；未决问题。
```

---

## W4 执行端 helper

```text
你是 KeyValet 仓库（/Users/guang/dev/keyvalet）「远程审批 V1」项目的 W4 工作流：执行端 kv-helper 的远程审批核心。这是协议语义最集中的工作流，正确性优先于一切。

【先读，不读完不要动手】
1. AGENTS.md：CI 命令、测试不得依赖本机安装（用 env!("CARGO_MANIFEST_DIR")、假 runner）、信任检查放真实进程 runner 里。
2. docs/remote-approval-architecture-2026-10.zh-CN.md：§2 进程边界、§3.4 吊销、§4 配对（执行端侧）、§5 信封、§6 全部（三类审批、规范化、请求/决定、§6.5 验证清单顺序、§6.6 grant、§6.7 时序、§6.8 选择顺序、§6.9 等待/放手/续等/唤醒与运行时预算、§6.10 在场与投递升级）、§7.4–7.6（统一 Grant、Directive 档位规则、安全栏）、§10 本地数据、§11 审计、§12 威胁模型、§14 失败模式、附录 A/C/D。
3. docs/architecture-2026-10.md §6（策略与风险档 T0–T3）、§7（审批子系统、grant 范围精确定义 §7.6）、§8.5。
4. rust/crates/kv-helper 现有代码（Pipeline、Approver、grant/模式、审计链、IPC 服务端）；rust/crates/kv-core/src/remote/ 与 rust/crates/kv-ipc 里 W0 落地的类型与消息（直接用，不要重定义）；W0 的 testdata/remote 向量。

【硬性规则】
- 不执行任何改变 git 状态的命令（不 commit / branch / stash / checkout / reset / rebase / push）；只读 git 命令可用。直接在 main 工作树改文件。
- 只改 rust/crates/kv-helper/。需要 kv-core / kv-ipc / kv-vault 改动的写变更请求；需要 kv-platform 的 DeviceKeyProvider / PresenceProbe 实现时先用 W0 的 SoftwareDeviceKey 与假探针，W1 交付后切换（切换点用一个构造函数注入）。
- CARGO_TARGET_DIR=/Users/guang/dev/keyvalet/rust/target-w4；cargo 命令 -p kv-helper。
- 不新增依赖；确需则报告申请。
- 验证顺序必须与 §6.5 完全一致，任一失败即拒绝并审计原因；fail closed，没有确认码、没有软件回退。
- 完整请求体只在内存里保留（上限 1 MiB、到 exp 清除），不落盘；日志不出现凭证值、请求体、密文。
- 代码与注释英文，风格与现有 crate 一致。

【任务】
A. 设备目录与配对执行端侧：devices 表（附录 D）、镜像到 vault AEAD 元数据的接口调用；pair start（生成 token、打印 kv-pair:// 与二维码内容由 CLI 渲染，helper 只给数据）/ 接收 pair_accept / 计算 SAS / 等终端 y 确认 / 验证对方 AK_s 对 sas 的签名 / 写入 devices；吊销设备时使该设备签过的未用批准与 Grant 全部失效。
B. Approver 实现 RemoteDevice 与 §6.8 选择顺序（auto → 能力/Grant 覆盖 → 本地通道 → remote-device → deny no_approver）；fan-out 到全部 approver，每个 approver 的 delivery 由 §6.10.2 规则决定；presence_hint 的接收与缓存；approval_escalate 定时器（默认 30 s）；approval_cancel 在 exp 时发出。
C. 三类审批 unlock / use / admin 的 ApprovalRequest 构造（§6.3，scope_options 由策略与 tier 决定：T2 只给 per_use）、规范化与 digest（§6.2）、nonce 表、pending_approvals 状态机（waiting → approved / approved_unused / executed / denied / expired / cancelled）。
D. ApprovalDecision 验证器（§6.5 顺序）：信封校验 → pending 存在且 waiting → digest/nonce 一致 → level ≥ min_level 且 T2 必须 strong → 用 level 对应公钥按设备记录 alg 验签 → nonce INSERT OR FAIL → 执行或拒绝 → 两端审计。
E. Grant（§7.4）：验签（alg 按设备记录）、aud 为自己或 *、安装到 grants 表；覆盖判定（同凭证或更宽 level ∧ tier ≤ max_tier ∧ host/method/path/agent 命中 ∧ 预算未超 ∧ 未过期 ∧ 未吊销）；多张命中时 max_tier 不放大、预算各扣；T2 只被 max_tier=T2 的 Grant 覆盖且审计 unattended_t2；弹窗 scope 选项到 Grant 的映射表；unlock 会话寿命 unlock_ttl。
F. Directive（§7.5）：验签与档位规则（收紧/查询 Quick 可，放宽 Strong，危险 Strong + 二次确认字段）、nonce 一次性、exp、执行 set_mode / revoke_grant / revoke_all_grants / lock / set_unlock_ttl / set_class / set_device_label / revoke_device / notify / query_* / cancel_approval、回 DirectiveResult；query_audit 只返回元数据；本地 /keyvalet:mode 与远程 set_mode 共用 settings 表，最后写入者生效。
G. 等待与恢复（§6.9）：调用内等待预算 = min(wait_in_call_s, 运行时预算 − 10 s)（运行时预算由 kv-mcp 经 IPC 告知）；预算内批准就地执行；超预算返回 approval_pending（A.8）；remote.wait 长轮询；approved_retry_required（内存请求丢失时）与带 approval_id 的重发比对（除 nonce/exp 外全部规范化字段）；remote.pending.for_agent 与 stop_block 计数（上限 stop_hook_max_blocks）；HTTP 路径所需的「挂连接等待」接口（kv-proxy 调用）。
H. 配置（§9.5 的 [approval] 段与 [[approval.class]]）；settings 表；审计事件（§11 全部新增字段与事件）。
I. IPC 服务端：实现附录 C 全部 remote.* op，并严格按「调用方身份 → 允许的 op 集合」拒绝越权调用。
J. 测试（全部 CI 可跑，用 W0 向量、SoftwareDeviceKey、假探针、假 relay 管道）：架构文档 §16 的测试 1、3、4、5、6、7、10、11（helper 侧）、13、14、15、16、17 全部覆盖；每条验证失败路径都有一个测试断言「被拒 + 审计原因」。

【验收】
- CARGO_TARGET_DIR=rust/target-w4 cargo fmt -p kv-helper -- --check；clippy --all-targets -- -D warnings；build；test 全过。
- W0 的 decision_* / grant_* / directive_* 向量在 helper 验证器上全部得到 expect 的结果。
- 「批了 A 执行 B」「同一批准用两次」「Quick 键签 T2」「放宽用 Quick」「已吊销设备的票」五个攻击用例全部被拒并审计。

【报告（docs/remote-approval-reports/W4.md）】
改动文件；对 kv-core / kv-ipc / kv-vault / kv-platform 的变更请求；状态机与验证顺序的实现位置；与 §6.5 / §7.5 / §6.9 任何偏差及理由；未决问题。
```

---

## W5 agent 侧：MCP、hook、proxy

```text
你是 KeyValet 仓库（/Users/guang/dev/keyvalet）「远程审批 V1」项目的 W5 工作流：agent 可见的一侧——kv-mcp、kv-hook、kv-proxy（以及 kv-protocols 里一个字段）。你的用户是模型，不是人：工具结果与错误文案都是写给模型看的 UI。

【先读，不读完不要动手】
1. AGENTS.md：CI 命令、测试不得依赖本机安装。
2. docs/remote-approval-architecture-2026-10.zh-CN.md：§6.9 全部（状态语义、四层机制、§6.9.3 运行时预算表、§6.9.4 session 关联、§6.9.5 默认值）、§9.4（MCP 与 agent 可见行为）、§14（运行时提前杀掉工具调用等失败模式）、§15 中 kv-mcp / kv-hook / kv-proxy / kv-protocols 行、§16 测试 10–12 与「运行时实测清单」、附录 A.8、附录 C（remote.wait / pending.for_agent / stop_block / status）、附录 E（credential_wait_approval 的 schema）。
3. docs/runtimes.md 与 rust/crates/kv-hook/src/lib.rs 顶部注释（现有各运行时 hook 事件与输出 schema：Claude Code、Cursor、Grok、Devin、Codex）；rust/crates/kv-mcp/src/session.rs（现有 UNLOCK_TIMEOUT 180 s / REQUEST_TIMEOUT 60 s / PROXY_REQUEST_TIMEOUT 200 s 常量与 grant 重试逻辑）；rust/crates/kv-proxy（网关与透明代理的请求生命周期）。
4. 外部事实（已核对，写进 §6.9.3）：Claude Code CLI stdio 工具超时约 28 h、空闲 30 min 可被 notifications/progress 重置、Desktop 有 60 s 硬超时 bug；Codex tool_timeout_sec 旧版 60 s 新版 300 s；Gemini CLI 600 s；Cursor IDE 进度型、Cursor CLI/ACP 60 s 硬限且不可配；Grok 6000 s；Devin 文档未写。Claude Code channels 要 experimental["claude/channel"] 能力 + notifications/claude/channel，未启用时静默丢弃。Stop 类 hook：Claude/Devin/Codex 用 {"decision":"block","reason":…}，Cursor 用 {"followup_message":…}，Gemini AfterAgent 用 {"decision":"deny","reason":…}。

【硬性规则】
- 不执行任何改变 git 状态的命令（不 commit / branch / stash / checkout / reset / rebase / push）；只读 git 命令可用。直接在 main 工作树改文件。
- 只改 rust/crates/kv-mcp/、rust/crates/kv-hook/、rust/crates/kv-proxy/、rust/crates/kv-protocols/（仅新增模板字段 client_timeout_hint_s 与读取代码，不改任何模板的其他内容）。helper 行为由 W4 实现，你用一个假 helper（实现附录 C 的 remote.wait / pending.for_agent / stop_block / status）做测试。
- CARGO_TARGET_DIR=/Users/guang/dev/keyvalet/rust/target-w5；cargo 命令 -p 限定到这四个 crate。
- 不新增依赖；确需则报告申请。
- 超时永远不映射成拒绝；approval_* 状态作为正常工具结果（isError=false）返回，不作为协议错误。
- 代码与注释英文，风格与现有 crate 一致。

【任务】
A. kv-mcp：initialize 时读 clientInfo.name 查 §6.9.3 预算表（表以代码常量 + 可配置覆盖实现，未知客户端 50 s）；对带 progressToken 的请求按 progress_interval_s 发 notifications/progress（message 含已等待秒数）；现有三个超时常量改为由预算与 helper 协商决定；新增工具 credential_wait_approval（附录 E schema，描述文案写清「批准后直接返回原请求结果，不要重复发起」）；使用类工具加可选 approval_id；A.8 的全部状态与 next_steps 文案（中英文经 kv-i18n）；声明 experimental["claude/channel"] 能力并在批准到达时发 notifications/claude/channel（content 与 meta.approval_id）；credential_status 新增 remote_approval 字段；被运行时提前杀掉时审计 client_timeout_observed 并把该 clientInfo 预算降到 50 s 直到重启。
B. kv-hook：新增 stop 模式及五个运行时变体（Claude Code Stop、Devin Stop、Codex Stop、Cursor stop、Gemini AfterAgent）：用 getppid() 作为 agent pid 调 remote.pending.for_agent；有未到期 pending 且 stop_block 允许 → 按各运行时 schema 输出「别停，去 credential_wait_approval(<ids>)」；否则输出空对象放行；尊重 stop_hook_active / loop_count；无 pending 时零输出零副作用。保持现有 PreToolUse / UserPromptSubmit 模式不变。
C. kv-proxy：网关与透明代理在需要审批时挂连接到 min(http_wait_s, host_hint − 60 s)（host_hint 来自模板 client_timeout_hint_s，未知主机 55 s），每 20 s TCP keepalive，不发应用层字节；超出后返回 429 + Retry-After: 30 + JSON {error:{type:"keyvalet_approval_pending", approval_id}} + 头 X-KeyValet-Approval: pending; id=…；挂连接期间批准 → 正常响应；keyvalet run 的子进程 stderr 打一行等待提示。
D. kv-protocols：模板字段 client_timeout_hint_s（可选整数），为 OpenAI、Anthropic 模板填 600，其余不填。
E. 运行时实测（§16「运行时实测清单」）：对本机能装的运行时各跑「阻塞 4 分钟 + 每 15 s progress」与「阻塞 4 分钟不发 progress」两种工具，记录是否被杀、何时、progressToken 是否存在、Stop 类 hook 的实际输入字段；Claude Code 用 --dangerously-load-development-channels server:keyvalet 验证 channels 能否唤醒空闲 session。装不了的运行时写明未测。结论回填到报告，并给出 §6.9.3 表的修订建议（不要直接改架构文档）。
F. 测试（CI 可跑，进程内假 MCP 客户端 + 假 helper）：§16 测试 10、11、12 全部；预算表查表；progress 发送节奏；A.8 每种状态的文案快照测试；各运行时 Stop 输出 schema 快照测试。

【验收】
- CARGO_TARGET_DIR=rust/target-w5 cargo fmt -p kv-mcp -p kv-hook -p kv-proxy -p kv-protocols -- --check；clippy --all-targets -- -D warnings；build；test 全过。
- 用假 helper 让批准在 3 分钟后到达：Claude Code CLI 实机上 credential_http_request 直接返回结果（预算内）；把预算改成 50 s 后得到 approval_pending，再调 credential_wait_approval 拿到结果；Stop hook 在有 pending 时阻止一次、三次后放行。

【报告（docs/remote-approval-reports/W5.md）】
改动文件；运行时实测表（每个运行时：版本、两种阻塞的结果、progressToken、Stop hook 输入字段、channels 结果）与对 §6.9.3 的修订建议；对 kv-ipc / helper 的变更请求；未决问题。
```

---

## W6 桌面审批端（macOS / Windows）

```text
你是 KeyValet 仓库（/Users/guang/dev/keyvalet）「远程审批 V1」项目的 W6 工作流：macOS 与 Windows 上的桌面审批端——对话框、SAS 确认、Grant/Directive 签发流程、在场状态上报的 UI 侧。

【先读，不读完不要动手】
1. AGENTS.md：CI 命令、测试不得依赖本机安装、需要 GUI/Touch ID 的测试 #[ignore]、签名团队 PWCRJPY7YC 与 daemon/agent 模式。
2. docs/remote-approval-architecture-2026-10.zh-CN.md：§3.1（Mac 三把 SE 键、Windows PCP + Hello RS256）、§4（配对的审批端侧：显示 6 位 SAS、用 AK_s 签 sas）、§6.3（对话框必须显示的字段）、§6.4（决定对象）、§6.10（在场状态由桌面 agent 计算并上报）、§7.4（弹窗范围选项到 Grant 的映射、哪些需要 Strong）、§7.5–7.6（Directive 档位、无人值守二次确认）、§9.2（V1 桌面弹窗规格）、附录 A.3 / A.4 / A.5 / A.7、附录 C（remote.decide / grant.issue / directive.issue / pair.* / presence.update）。
3. docs/remote-approval-product-2026-10.zh-CN.md §6（审批界面规范）、§6.1（审批边界用户语言）、J-R2 的对话框示例。
4. rust/crates/kv-touchid（现有 Swift 对话框与 SE 桥）、rust/crates/kv-agent（现有 Windows TaskDialog / Hello 路径）、docs/architecture-2026-10.md §7.1（弹窗统一显示什么）、附录 A（现有弹窗文案）。W1 在同一两个 crate 里负责密钥与探针实现：你只改对话框与流程部分，密钥调用通过 W1 暴露的接口（未就绪先用 W0 的 SoftwareDeviceKey 注入）。

【硬性规则】
- 不执行任何改变 git 状态的命令（不 commit / branch / stash / checkout / reset / rebase / push）；只读 git 命令可用。直接在 main 工作树改文件。
- 只改 rust/crates/kv-touchid/ 与 rust/crates/kv-agent/ 中对话框、流程、文案相关的文件；密钥/探针实现文件归 W1，不碰；若必须共改同一文件，只新增函数不改既有函数，并在报告写明。
- CARGO_TARGET_DIR=/Users/guang/dev/keyvalet/rust/target-w6；cargo 命令 -p kv-touchid -p kv-agent。
- 不新增依赖。
- 对话框绝不显示凭证值、完整请求头、body 原文、哈希、vault 路径；purpose 必须标注「agent 自述」；真实操作是视觉主体。
- 放宽（常设票、无人值守、放松模式）一律 Strong；收紧 Quick。无人值守（max_tier=T2）不出现在弹窗快捷项里，只在终端/设置路径。
- 代码与注释英文；用户可见文案走 kv-i18n（zh-CN / en）。

【任务】
A. 远程审批对话框（macOS 原生对话框 via kv-touchid，Windows TaskDialog via kv-agent.exe）：标题「<执行端标签> 上的 <runtime> 请求使用 <凭证显示名>」；正文按 §6.3 渲染（summary 最大字号；方法/主机/路径/大小；agent 自述；来源设备 + 保护状态，software_key 红色；风险档，T2 红并说明不能预授权；时钟偏差、合并数、积压提示）；范围下拉只列 scope_options 中的项，默认 requested_scope；按钮允许/拒绝；选到 standing:* 时按钮文案变「一直允许（Touch ID / Hello）」并走 Strong；Strong 时 Touch ID / Hello 后用 AK_s 签 A.3 决定，Quick 用 AK_q；拒绝可填一句原因。
B. SAS 确认对话框：显示对方设备记录（标签、OS、key_kind、caps）与 6 位数，确认即 Touch ID / Hello 用 AK_s 签 sas → remote.pair.confirm。
C. Grant / Directive 签发流程（供 CLI 与未来设置页调用）：根据 A.4 / A.5 构造、按档位规则决定是否触发 Strong、二次确认（输入执行端标签）对 max_tier=T2 的 Grant 强制；经 remote.grant.issue / remote.directive.issue 交 helper 发送。
D. 在场状态上报：调用 W1 的 PresenceProbe（未就绪用假探针），去抖 5 s，状态变化经 remote.presence.update 上报本机 helper。
E. 积压处理：唤醒后一次最多排队弹 5 个，其余留待列表（列表在 V1 由 CLI 的 keyvalet approvals 提供，这里只保证不一次弹出超过 5 个）。
F. 测试：对话框视图模型（从 ApprovalRequest 到显示字段）的纯 Rust 单元测试，覆盖每个 kind、每个 tier、software_key、时钟偏差、合并、积压；范围选项 → Grant 字段映射测试；档位判断测试（哪些走 Strong）；GUI/Touch ID/Hello 的实际弹出用 #[ignore] 测试并写明在哪台机器怎么跑。

【验收】
- CARGO_TARGET_DIR=rust/target-w6 cargo fmt -p kv-touchid -p kv-agent -- --check；clippy --all-targets -- -D warnings；build；test 全过。
- 在本机 macOS 上用 W0 的测试向量驱动一次真实对话框（#[ignore] 测试），截图保存到 docs/remote-approval-reports/assets/w6-*.png，并由人工核对产品文档 §6 的「必须显示」清单逐项满足。

【报告（docs/remote-approval-reports/W6.md）】
改动文件；对 W1 接口的依赖点与当前注入方式；截图路径；对 kv-i18n 文案键的新增清单；对附录 A / C 的变更请求；未决问题（含 Windows 是否已能实机验证）。
```

---

## W7 CLI

```text
你是 KeyValet 仓库（/Users/guang/dev/keyvalet）「远程审批 V1」项目的 W7 工作流：kv-cli 的远程审批子命令。

【先读，不读完不要动手】
1. AGENTS.md：CI 命令、测试不得依赖本机安装。
2. docs/remote-approval-architecture-2026-10.zh-CN.md：§4（配对终端流程：打印 kv-pair:// 与二维码、显示 6 位数、等 y）、§7.1（keyvalet grant 参数）、§7.4–7.6（Grant / Directive / 安全栏，尤其 unattended 的二次确认）、§8.5（keyvalet relay install 的职责：写 systemd 单元与 nginx 模板、提示 Cloudflare 步骤——模板文件由 W2 提供在 deploy/relay/，由 W9 接入安装器；你只实现命令行为）、§9.3（全部命令表，以此为准）、§6.10.4（notify 子命令）、附录 C（CLI 允许的 op）、附录 E（退出码、--json、<device> 的解析规则）。
3. docs/remote-approval-product-2026-10.zh-CN.md J-R1、J-R3b（用户视角的命令与预期）。
4. rust/crates/kv-cli 现有代码（子命令组织、输出风格、--json 约定、错误处理）；rust/crates/kv-ipc 里 W0 的 remote.* 消息类型。

【硬性规则】
- 不执行任何改变 git 状态的命令（不 commit / branch / stash / checkout / reset / rebase / push）；只读 git 命令可用。直接在 main 工作树改文件。
- 只改 rust/crates/kv-cli/。helper 行为由 W4 实现，你用假 helper（实现附录 C 的 CLI 可调 op）做测试。
- CARGO_TARGET_DIR=/Users/guang/dev/keyvalet/rust/target-w7；cargo 命令 -p kv-cli。
- 不新增依赖（二维码渲染若工作区没有相应 crate，先只打印 kv-pair:// 文本并在报告申请）。
- CLI 不做任何签名、不碰任何私钥、不自行判断档位：构造好对象交给 helper（remote.grant.issue / remote.directive.issue），由 helper 决定是否触发 Strong；CLI 只负责参数校验、二次确认的交互（输入执行端标签）与结果渲染。
- 代码与注释英文；用户可见文案走 kv-i18n。

【任务】
A. keyvalet relay install / status / set-url：install 接 --listen（默认 127.0.0.1:8787）、--data、--public-url；写 kv-server 的 systemd 单元与 deploy/relay/ 的 nginx 模板到目标路径（路径由参数与平台决定），打印 Cloudflare 橙色云的三步提示（DNS 代理、Full (strict)、防火墙只放 Cloudflare IP）；status 调 /v1/health；set-url 写 relay-client 配置。
B. keyvalet pair --new（执行端或已配对审批端发起）/ keyvalet pair <kv-pair://…>（加入）：打印 kv-pair:// 与二维码；两端显示 6 位 SAS；执行端终端等 y/N；超时与 SAS 不一致的提示。
C. keyvalet devices list / revoke <id> / rename。
D. keyvalet approvals [--watch] / approve <id> [--scope …] / deny <id> [--reason]：审批端终端视图；--watch 持续刷新；Strong 由 helper 触发 Touch ID / Hello。
E. keyvalet grant … / list / revoke <jti> / revoke-all（§7.1 参数全集）。
F. keyvalet remote <device> …：mode / allow（--credential、--hosts、--methods、--paths、--agent、--until | --standing、--all）/ unattended --include-sensitive --until（强制交互输入执行端标签二次确认）/ lock / unlock-ttl / class / label / notify / status / pending / grants / audit --since；<device> 接受 id、标签或 *。
G. keyvalet status --summary 新增远程字段渲染；keyvalet approvals --on-approve <cmd>（批准后执行用户命令，参数只含 approval_id 与摘要）。
H. 全部子命令支持 --json；退出码按附录 E（0/2/3/4/5/6）。
I. 测试：参数解析与校验快照；每个子命令对假 helper 的 IPC 调用序列断言；--json 输出 schema 稳定性快照；退出码；unattended 缺二次确认即拒绝。

【验收】
- CARGO_TARGET_DIR=rust/target-w7 cargo fmt -p kv-cli -- --check；clippy --all-targets -- -D warnings；build；test 全过。
- `keyvalet remote --help` 与 §9.3 表逐行对应；每条命令的 --json 输出都能被 serde 反序列化回对应类型。

【报告（docs/remote-approval-reports/W7.md）】
改动文件；对 kv-ipc 的变更请求；二维码渲染依赖申请（如需）；与 §9.3 的偏差；未决问题。
```

---

## W8 手机 App（Flutter，iOS + Android）

```text
你是 KeyValet 仓库（/Users/guang/dev/keyvalet）「远程审批 V1」项目的 W8 工作流：手机 App——Flutter 工程、Rust 核心 kv-mobile-core、原生薄层 kv_native、iOS 通知扩展、Android 消息服务、推送服务 kv-push。手机 App 是 V1 唯一的图形审批/控制面。

【先读，不读完不要动手】
1. AGENTS.md：CI 命令、测试不得依赖本机安装、签名团队 PWCRJPY7YC。
2. docs/remote-approval-architecture-2026-10.zh-CN.md：§3.1–3.3（手机列：iOS SE 三把键、Android Keystore 三把键、alg、存放、匿名账户）、§4（手机扫码配对）、§5 信封、§6.3–6.4（请求与决定）、§6.10（在场判定对手机的影响：delivery.mode、approval_escalate、「我不在电脑前」开关）、§7.4–7.6（Grant / Directive / 安全栏——手机设置页签发的就是这些对象）、§9.2 与 §9.2.1（页面清单、Flutter + Rust + 原生薄层的分工、必须原生的三件事、目录与构建、双绑定）、附录 A、附录 B（手机直接调 relay API）。
3. docs/remote-approval-product-2026-10.zh-CN.md §6（界面规范）、§6.1（审批边界用户语言）、§6.2（界面规划、在场规则、Flutter 决定）、J-R2、J-R3b、J-R4。
4. rust/crates/kv-core/src/remote/（W0 的类型、HPKE/签名 trait、SoftwareDeviceKey）；rust/crates/kv-mobile-core 与 rust/crates/kv-push 的空骨架（W0 建好）；rust/crates/kv-server 的 spawn_test_relay（W2）。

【硬性规则】
- 不执行任何改变 git 状态的命令（不 commit / branch / stash / checkout / reset / rebase / push）；只读 git 命令可用。直接在 main 工作树改文件。
- 只改：mobile/（新建 Flutter 工程）、rust/crates/kv-mobile-core/、rust/crates/kv-push/。其他文件不碰；需要 kv-core 改动的写变更请求。
- CARGO_TARGET_DIR=/Users/guang/dev/keyvalet/rust/target-w8；cargo 命令 -p kv-mobile-core -p kv-push。
- Dart 层不碰任何私钥、不做任何验签、不解析任何信封：只渲染 Rust 给的结构体、把用户操作交回 Rust。
- 生物识别必须门控密钥操作本身：iOS AK_s 用 SecureEnclave.P256 + .biometryCurrentSet；Android AK_s 用 KeyGenParameterSpec.setUserAuthenticationRequired(true) + setUserAuthenticationParameters(0, AUTH_BIOMETRIC_STRONG) + setInvalidatedByBiometricEnrollment(true)，签名经 BiometricPrompt.authenticate(CryptoObject(Signature))。禁止用 local_auth 一类只返回布尔值的插件作为 Strong 的依据。
- 后台路径全部原生 + Rust：iOS Notification Service Extension（Swift，独立 target，不跑 Flutter）、Android FirebaseMessagingService（Kotlin）；不依赖 Dart 后台 isolate。
- 新依赖（pub.dev 包、Cargo crate）须已发布 ≥ 7 天并写入报告；Flutter 侧优先 flutter_rust_bridge、mobile_scanner，其余按需申请。
- 没有登录页、没有账号页；首次扫码即注册 + 配对。
- 代码与注释英文；用户可见文案中英双语（Flutter 的 l10n）。

【任务】
A. kv-mobile-core（Rust）：设备注册与挑战认证、WS 客户端（前台）、信封封解（经 kv_native 提供的硬件 ECDH/签名 trait 实现）、ApprovalRequest 解析为视图模型、ApprovalDecision / Grant / Directive 构造与签名调用、待批队列与 peers / issued_* 的 SQLite（iOS 放 App Group 容器、Android 放应用私有目录；NSE 与主 App 对同一库用 WAL + 文件锁）、delivery.mode 与 approval_escalate 的通知语义、「我不在电脑前」本地开关；两套绑定：flutter_rust_bridge（给 Dart）与 UniFFI 或手写 C ABI（给 iOS NSE），同一份公开类型。
B. kv_native（Flutter 平台插件，Swift / Kotlin）：三把键的创建/签名/ECDH（iOS：DK AfterFirstUnlockThisDeviceOnly、AK_q WhenUnlockedThisDeviceOnly、AK_s biometryCurrentSet；Android：StrongBox 优先、回退 TEE 并上报 key_kind，AK_q setUnlockedDeviceRequired(true)，AK_s 如上）；App Attest / Play Integrity（自建 relay 可关）；推送令牌获取。
C. iOS NSE（KeyValetNSE target）：收到 APNs（mutable-content）→ 从 App Group 读密文队列/拉取 → 用 Rust 解密 → 设置通知正文（§6.3 字段摘要，不含凭证值）、interruptionLevel（silent → .passive，banner → .timeSensitive）、threadIdentifier（approval_id，approval_escalate 更新同一条）；锁屏动作 UNNotificationAction(options: .authenticationRequired) → 主 App 后台唤起 → Rust 用 AK_q 签 Quick 决定；Strong 必须打开 App 走生物识别。
D. Android：FirebaseMessagingService 收 data message → Rust 解密 → 两个通知渠道（静默 / 高优先级）→ 动作按钮走前台服务签 Quick；Strong 打开 App。
E. Flutter UI（§9.2 页面清单）：待批（列表 + 详情，详情即 §6.3 全部字段，底部范围选择只列 scope_options，允许/拒绝，standing 选项触发生物识别）；设备（已配对执行端 → 每台一页：状态、模式、常设 Grant 列表含剩余预算/到期/来源、无人值守红色开关（含二次输入执行端标签）、锁定、revoke-all 大按钮、吊销、最近活动；加设备 = 扫码）；活动（本机签发记录按天分组）；设置（relay 地址、通知偏好、「我不在电脑前」、诊断导出不含密钥）。
F. kv-push：接收 relay 的 {device_push_token, approval_id, delivery.mode} → APNs（mutable-content:1）与 FCM data message；不接触审批内容。
G. 目录与构建：mobile/（pubspec.yaml、lib/、ios/ 含 KeyValetNSE、android/）；kv-mobile-core crate-type = ["staticlib","cdylib","rlib"]；代码生成输出 mobile/lib/src/rust/ 与 mobile/ios/KeyValetNSE/Generated/；构建脚本（cargo build --target aarch64-apple-ios / aarch64-linux-android、flutter analyze、flutter test）；TestFlight 与 Play 内部测试轨道的打包脚本（签名材料不入库，路径与占位写清）。
H. 测试：Rust 侧用 W0 向量与 SoftwareDeviceKey 覆盖封解、视图模型、Grant/Directive 构造、队列与升级语义；Flutter widget 测试覆盖四个页面的关键状态；原生侧写一个「被篡改的 UI 层直接调用签名、跳过生物识别」的测试，断言 AK_s 签名失败（iOS 与 Android 各一，设备/模拟器限制写明）。

【验收】
- CARGO_TARGET_DIR=rust/target-w8 cargo fmt -p kv-mobile-core -p kv-push -- --check；clippy --all-targets -- -D warnings；build（含 iOS 与 Android 目标，工具链缺失时在报告写明）；test 全过；flutter analyze 与 flutter test 全过。
- 用 W2 的 spawn_test_relay + 一台软件「执行端」模拟器：扫码（或粘贴 kv-pair://）配对 → 收到一条 silent 请求不响 → 30 s 后 escalate 变横幅 → 锁屏 Quick 批准 → 一条 T2 请求只能进 App 用生物识别批 → 设置页签一张 1 小时票 → revoke-all。全程录屏或截图到 docs/remote-approval-reports/assets/w8-*。

【报告（docs/remote-approval-reports/W8.md）】
改动文件与目录结构；pub.dev 与 Cargo 新依赖表（名称/版本/发布日期/理由）；双绑定的生成方式；原生薄层的接口清单；生物识别门控测试的结果与限制；对 kv-core / relay API 的变更请求；未决问题（含开发者账号、APNs 密钥、FCM 项目等需要人提供的东西）。
```

---

## W9 安装器、文档与集成

```text
你是 KeyValet 仓库（/Users/guang/dev/keyvalet）「远程审批 V1」项目的 W9 工作流：安装器、文档与最终集成。你最后启动，前提是 W0–W8 都已把报告写到 docs/remote-approval-reports/。你是唯一允许对整个工作区跑 fmt / clippy / build / test、并跨 crate 修补集成问题的人。

【先读，不读完不要动手】
1. AGENTS.md 全文：CI 四条命令、测试不得依赖本机安装、scripts/install.sh 的根部分是一个单引号 sh -eu -c '...' 字符串（里面绝不能出现单引号，所有变量来自位置参数）、签名团队与 daemon/agent 模式、发布流程。
2. docs/remote-approval-reports/W0.md … W8.md 全部：每个工作流的改动文件、变更请求、未决问题。
3. docs/remote-approval-architecture-2026-10.zh-CN.md：§2.3（三平台矩阵与安装器）、§6.9.3「安装器写入」列（为各运行时写 KeyValet 自己的工具超时与 Stop hook 注册）、§8.5（nginx + Cloudflare 橙色云部署与 keyvalet relay install）、§9.1（relay-client 服务）、§15（代码落点里 install.sh / install.ps1 行）、§16（CI 测试 1–17、#[ignore] 清单、实机验收表）、§17（里程碑 M5 的定义）。
4. docs/remote-approval-product-2026-10.zh-CN.md §7（功能清单与验收标准）、§11（成功指标）。
5. docs/linux.md、docs/windows.md、docs/wsl.md、docs/runtimes.md、SECURITY.md、site/content/guide.md 与 guide.zh-CN.md、README.md（现有文档的事实与口径；你要更新它们）。
6. scripts/install.sh、scripts/install.ps1（若存在）、.github/workflows/*.yml 现有内容。

【硬性规则】
- 不执行任何改变 git 状态的命令（不 commit / branch / stash / checkout / reset / rebase / push）；只读 git 命令可用（git status / diff 用来核对整体改动）。直接在 main 工作树改文件。
- 你拥有：scripts/install.sh、scripts/install.ps1、docs/linux.md、docs/windows.md、docs/wsl.md、docs/runtimes.md、SECURITY.md、site/content/guide*.md、README.md、.github/workflows/*。对其他 crate 的修改只限于「让工作区整体编译与测试通过所必需的集成修补」，每处在报告里列出并说明为什么不能由原工作流完成；不要重写别人的实现。
- CARGO_TARGET_DIR=/Users/guang/dev/keyvalet/rust/target-w9。全工作区检查命令（在 rust/ 下）：cargo fmt --all -- --check；cargo clippy --workspace --all-targets -- -D warnings；cargo build --workspace --locked；cargo test --workspace --locked。
- install.sh 的根部分：绝不在 sh -eu -c '...' 字符串里出现单引号（包括注释）；所有变量来自位置参数；改完后除了 sh -n 还要人工检查这两条，因为 sh -n 查不出来。
- 文档只写已实现并通过测试的行为；未实现的写「计划中」，不用现在时；明确写出「远程审批不让 Linux / Windows helper 获得抵御 root / SYSTEM 的能力」。
- 不修改任何安全策略或 CI 保护配置来让检查通过；过不去就修代码或报告。

【任务】
A. 安装器（三平台）：
   - 创建 relay-client 的运行身份与服务（Linux 系统用户 keyvalet-relay + systemd；macOS LaunchAgent dev.keyvalet.relay；Windows 服务 KeyValetRelay，虚拟服务账户），模板来自 W3 的 rust/crates/kv-relay-client/service/。
   - keyvalet relay install 所需的文件落位：kv-server systemd 单元、deploy/relay/ 的 nginx 模板写到 /etc/nginx/conf.d/keyvalet-relay.conf（存在 nginx 时），证书目录 /etc/ssl/keyvalet-relay/ 占位与权限，安装结束打印 Cloudflare 橙色云三步提示。不引入 Tailscale / Caddy。
   - 为检测到的每个运行时写入 KeyValet 自己的工具超时：Claude Code .mcp.json / ~/.claude.json 的 keyvalet 条目 timeout: 900000；Codex ~/.codex/config.toml [mcp_servers.keyvalet] tool_timeout_sec = 900；Grok ~/.grok/config.toml 同名字段；Gemini settings.json 的 keyvalet 条目 timeout: 900000。只改 KeyValet 自己的条目，保留用户其他配置。
   - 注册 Stop 类 hook：Claude Code Stop、Devin Stop、Codex Stop、Cursor stop、Gemini AfterAgent，命令指向 kv-hook 的对应模式（W5 提供的模式名）。
   - 卸载路径同步清理以上全部。
B. 文档：
   - docs/linux.md：远程审批与配对章节（服务器 + 手机/Mac 的完整步骤、relay 同机部署、nginx/Cloudflare、后备的 SSH 审批不变）、新增的服务与用户、保护状态显示。
   - docs/windows.md：Windows 执行端与审批端（Hello RS256）的状态与验证矩阵。
   - docs/runtimes.md：每个运行时的预算、progress、Stop hook、channels 支持矩阵（以 W5 报告的实测为准）。
   - SECURITY.md：远程审批的保证与不保证（§12 的表翻译成用户语言；relay/Cloudflare 只见密文；放宽永远 Strong；无人值守的边界）。
   - site/content/guide*.md 与 README：安装后的远程审批最小用法；手机 App 内测安装方式。
   - 把 W1/W5 报告里的 spike 与实测结论回填到 docs/remote-approval-architecture-2026-10.zh-CN.md 的 §3.1 与 §6.9.3（只改事实表，不改设计）。
C. 集成：
   - 处理 W0–W8 报告里的全部「变更请求」：能在契约所有权内解决的改 kv-core / kv-ipc 并同步测试向量；需要设计决定的列入报告「待拍板」。
   - 全工作区四条 CI 命令全绿；.github/workflows/test.yml 覆盖新 crate；release.yml 把 kv-server、kv-relay-client 纳入 macOS 与 Linux 包（Windows 维持现有手动流程）。
   - 实机验收（§16 表）：在 Ubuntu 服务器 + MacBook + iPhone/Android 上逐项执行，结果（通过/未通过/未测及原因）写入 docs/review-2026-10.zh-CN.md 的新小节。
D. 把本轮所有工作流的未决问题汇总成一份清单（docs/remote-approval-reports/OPEN-QUESTIONS.md），按「需要用户拍板 / 需要外部资源 / 技术债」分类。

【验收】
- rust/ 下四条 CI 命令全部通过；sh -n scripts/install.sh 通过且人工确认单引号与位置参数规则。
- 新装一台 Ubuntu（或容器）跑 install.sh 后：keyvalet status --summary 显示 relay 字段；keyvalet relay install 产出 nginx 配置并通过 nginx -t（若装了 nginx）。
- 文档中每一个「已支持」的句子都能在仓库里找到对应实现与测试。

【报告（docs/remote-approval-reports/W9.md）】
改动文件；对各 crate 的集成修补清单及理由；CI 四条命令的输出摘要；实机验收表；OPEN-QUESTIONS.md 的链接；未完成项。
```
