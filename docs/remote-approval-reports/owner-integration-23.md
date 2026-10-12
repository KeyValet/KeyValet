# 远程审批 V1：第 2、3 项接口与管理闭环

2026-10-12。对应用户「你去做 2 3」：统一 CLI、桌面展示和真实 helper 的 owner IPC；补齐审批历史、已签发授权、使用快照、撤销传播及本地／远程设置的一致性。直接修改 main 工作树，没有运行改变 git 状态的命令。W9 的安装器、发布流水线及部署资产没有在本轮修改。

## 实现结果

### Owner IPC 和认证边界

- `kv-ipc` 提供 `DecideIntent`、`GrantIntent`、`GrantConfirmation`、`DirectiveIntent`、配对意图及公开 `RelayBinding`；`kv-core` 复用这些类型并绑定实际协议类型。意图不接受调用方指定的 `iss/jti/nonce/alg/sig` 等授权字段。
- CLI 只提交参数、处理终端确认、渲染结果。helper 选择最低审批级别、补齐发行者／ID／nonce／时间，并通过原有 W0 验签接口验证实际签名。旧 `Unsigned` 路径保留兼容性，但单独提供标签的旧 T2 请求被拒绝。
- T2 使用 Strong → 非 Grant 的独立准备证明 → 一次性令牌 → 精确执行端标签 → 签发。准备令牌只在 helper 内保存哈希，绑定调用方 UID、PID、角色、完整意图及当前设备记录，最长 120 秒，失败的最终尝试也消费令牌。常设 T2 要求两个不同令牌和两次标签确认，两轮共享原截止时间。
- CLI 的有限 T2 通配符操作展开为当前执行端的独立确认和独立授权；全局 T2 不向未来设备扩展。桌面仍拒绝全局 T2。T1 设置授权维持 Strong，遵守现有安全边界。
- 原生私有 UI 路径经现有已认证 agent 连接传递审批、配对及全局确认。通用认证使用 `kv-i18n` 操作文案，不直接显示原始 JSON 绑定。UI 批准不能替代随后对 AK 的实际签名与验签。

### 匿名注册和配对

- 首次 owner 配对通过真实 `/v1/devices` 注册，账户 ID 来自 relay。恢复码只在本次响应交给 owner 并提示保存，不写入公开配置或日志。CLI 原子保存 relay URL、设备 ID、账户 ID。
- 网络调用前先保存生成的加密身份元数据。注册断网后可重新打开原身份，并重试同一组密钥；本地 `unregistered:<device_id>` 是未注册状态的内部路由占位符，不发送给 relay。
- 已有单设备身份允许注册或加入账户，但要求没有其他设备、吊销墓碑、授权、审批历史、待办、Directive、nonce、发件箱或正在处理的请求。迁移期间旧 helper 停止处理请求；加密身份／目录和 SQLite 的账户更新通过受认证日志恢复，保留原有 DK、AK 和设备 ID。已有信任关系的身份拒绝迁移。
- 配对使用真实 DK challenge/verify、`Device` 会话头、`kv-relay-v1` WebSocket 和 HPKE 信封。内置临时 WS 只用于配对阶段；relay-client 已连接时让它负责收信。两端均确认 SAS 后才写入信任目录，CLI 等待 helper 返回完成状态。
- 审批设备发起配对时先完成 Strong 的独立证明，SAS 确认继续要求 AK_s 签名。纯执行端保持 owner 终端确认。
- 已注册但配对启动失败时，响应可以同时携带公开绑定、一次性恢复码和 `pair_error`，CLI 先呈现恢复码，再返回对应错误。首次注册失败后也会尝试加载保存的原身份，避免同一进程把它当作新的身份生成。

### 审批和授权管理

- owner 的 `remote.pending.list` 返回待办及最近 200 条签发决定，MCP 不能读取 owner 的决定历史。历史有持久递增 `decision_seq`；watch 只对本次观察到的待办触发 hook，游标防止历史轮转后重复执行。兼容旧 helper 的无游标结果。
- 独立签发 Grant 的完整对象和 issuer 台账持久化；列表包含有效期、撤销状态、预算、使用次数、最近使用时间、每个执行端的快照和获取时间。尚未查询执行端的使用量明确标为 `not_fetched`，不伪造零使用量。
- `remote <device> grants` 的已认证执行端回执更新预算及使用快照。审批决定衍生的内部 Grant 也可通过该快照关联 owner 的 Allow 历史并展示、撤销；它保留 `approval_decision` 权威来源和空 Grant 签名，不转换成可传送的新签名 Grant。
- `grant revoke` 发出逐执行端签名 Directive，只有对应设备的已认证回执才能确认撤销。请求及目标列表持久化；调用取消或执行端离线时保留 `revocation_pending`，重复撤销可继续未完成目标，已经完成的撤销幂等。既有发件箱负责未过期信封的发送。
- 全局 T1 授权覆盖未来通过 SAS 信任的执行端。已经撤销或有 owner 撤销请求的授权不会补发给新设备。同一个本机授权在 installed／issued 两个台账中不会重复计数。
- 本地 CLI 设置和远程 `SetMode` 使用同一个 helper 设置后端及 CAS 写入。过时的本地提案拒绝覆盖远程更新；收紧、放宽和授权变更写入同一审计链。缺少授权后端时默认采用严格模式。
- 已认证使用快照同步执行端本地撤销状态，防止 owner 台账继续显示有效。`status --summary` 可在远程权限拒绝时展示本地公开状态和远程错误；普通 `status` 的权限拒绝保持退出码 3。
- helper 在 agent 注册及身份初始化后提供真实设备 ID；原生 presence 使用该 ID。由 Away 转为 Present 时重置原生每次唤醒的提示队列。

## 主要改动文件

下表列出本轮语义改动；当前工作树还包含 W0–W9 及其他并行工作的文件，不把整个 `git status` 归为本轮成果。

| 范围 | 文件 |
| --- | --- |
| 共享 IPC | `rust/crates/kv-ipc/src/remote.rs`；`rust/crates/kv-core/src/remote/ipc.rs` |
| 共享设置 | `rust/crates/kv-core/src/settings.rs`；`rust/crates/kv-helper/src/remote/settings.rs` |
| helper owner 控制 | `rust/crates/kv-helper/src/remote/{mod.rs,engine.rs,ipc.rs,owner.rs,grants.rs,directives.rs,store.rs,schema.sql}` |
| 注册／配对／运行时 | `rust/crates/kv-helper/src/remote/{bootstrap.rs,startup.rs,pairing.rs,pairing_relay.rs,server.rs,production.rs,platform_keys.rs}` |
| 特权本地设置入口 | `rust/crates/kv-helper/src/{main.rs,daemon_win.rs}` |
| CLI | `rust/crates/kv-cli/src/main.rs`；`src/remote.rs`；`src/remote/{relay.rs,system.rs,output.rs,tests.rs,live_helper_tests.rs}` |
| 桌面端 | `rust/crates/kv-agent/src/remote/{flows.rs,tests.rs}`；`rust/crates/kv-agent/src/remote_agent.rs`；`rust/crates/kv-touchid/src/remote_agent.rs` |
| 私有 agent 通道 | `rust/crates/kv-platform/src/agent.rs` |
| relay 公开响应扩展 | `rust/crates/kv-server/src/{auth.rs,pairing.rs}` |
| 真实模块回归测试 | `rust/crates/kv-helper/src/remote/tests/{owner.rs,owner_workflow.rs}` |
| 依赖边 | `rust/crates/kv-helper/Cargo.toml`；`rust/crates/kv-cli/Cargo.toml`；`rust/Cargo.lock` |
| CI 格式整理 | `rust/crates/kv-mobile-core/src/tests/account.rs`：仅将一处链式调用按 rustfmt 换行；保留并行工作的测试与业务改动 |

W9 在同一工作树完成了配对 transport 的 Device 认证／WS 契约修正、共享 schema／fixture 投影、额外 owner 契约回归和格式整理；参见 [W9 报告](W9.md)。保留其改动。

## 依赖

没有选入新的 registry 包或版本。以下增加的是既有锁定包的直接依赖边；锁文件更新已由用户授权。

| 包 | 锁定版本 | 用途／来源 |
| --- | --- | --- |
| reqwest | 0.12.28 | helper 配对 HTTP；沿用工作区版本 |
| futures-util | 0.3.34 | 配对 WebSocket；已发布 2026-08-11，沿用 W3；[registry](https://crates.io/api/v1/crates/futures-util/0.3.34) |
| tokio-tungstenite | 0.26.2 | 配对 WebSocket；已发布 2025-02-18，沿用 W3；[registry](https://crates.io/api/v1/crates/tokio-tungstenite/0.26.2) |
| rustls | 0.23.45 | 复用 ring TLS provider；已发布 2026-09-14，沿用 W3；[registry](https://crates.io/api/v1/crates/rustls/0.23.45) |
| kv-server | 工作区路径 | helper 测试的进程内 relay harness，dev-dependency |
| kv-helper、kv-agent | 工作区路径 | CLI 测试使用真实 helper／桌面逻辑，dev-dependencies |

发布日期记录沿用 W9 已核实的 registry 记录；二维码未引入依赖。

## 契约补充及变更请求

1. 附录 C 采用共享 owner 意图，helper 填充授权字段；`GrantConfirmation.confirmations_left` 默认 1，常设 T2 准备返回 2，第一次标签确认交换新令牌和 1，第二次才返回 Grant。W9 已补充对应 schema／fixture。
2. PairSasResult 扩展 `binding`、一次性 `recovery_code`、`pair_error`。`/v1/pair/complete` 额外返回原始 `expires_at`，避免加入方延长配对期限。`/v1/auth/verify` 额外返回该 DK 的 `account_id`，供已初始化身份核对真实账户。公开字段应正式纳入附录 B/C；旧核心类型通过 Extra 保持兼容。
3. owner pending 历史扩展 `decision_seq`；Grant 列表通过 Extra 承载 `ledger/authority/usage/usage_status/usage_by_device/revocation_pending`。使用量是有获取时间的执行端快照。
4. `remote_settings` 是现有特权本地控制通道的操作，不向 MCP／relay-client 添加附录 C 能力。放宽设置需 owner 认证及可用 AK_s 的独立签名证明。
5. 私有 agent 增加公开 `remote_identity` 通知及 UI 请求入口；角色验证、签名 trust check 和二进制设备密钥通道沿用原有实现。

## 验证记录

使用隔离的 `CARGO_TARGET_DIR=/Users/guang/dev/keyvalet/rust/target-owner-integration`。CI 验证用已安装的 Rust 1.99.0；本机默认 stable 仍为 1.90.0。测试使用临时目录、软件设备密钥和注入的 OS／UI 边界，实际运行 W0 签名／HPKE、helper handler、SQLite、relay HTTP／WS，不依赖本机 KeyValet 安装、sudo、TPM 或 GUI。

新增回归包括：匿名注册→SAS 配对→一次审批→一次执行→重放拒绝；预算扣减→签名查询快照→传播撤销；已有身份加入且密钥不变；账户迁移中断恢复；首次注册断网重开原身份；T2 常设两轮独立确认；撤销调用中断后等待真实回执；未来执行端的全局 T1 补发及待撤销禁止补发；CLI／桌面连接真实 helper；审批衍生 Grant 的查询与撤销；watch 历史轮转不重复 hook；私有 UI 取消不产生批准。

真实 relay 流程断言 relay 数据库及日志不出现唯一请求明文标记，日志也不包含恢复码。

W7 原有约定范围（`remote.rs` 及 `args/output/relay/transport.rs`）的最新覆盖率：行 **1989/1989 = 100%**，函数 **191/191 = 100%**，region **3309/3407 = 97.12%**。系统适配层单独报告：行 49/431、函数 6/50。没有排除新增可单测逻辑来取得 100%；新增异常测试验证了恢复码无效、输出失败、两端确认错误／超时／取消和公开配置校验。

| 检查 | 结果及日志 |
| --- | --- |
| `cargo +1.99.0 fmt --all -- --check` | 通过，`fmt-final.log`；并行工作的一处 mobile 测试换行已按 rustfmt 整理 |
| `cargo +1.99.0 clippy --workspace --all-targets --locked -- -D warnings` | 通过，`final-clippy-4.log` |
| `cargo +1.99.0 build --workspace --locked` | 通过，`final-build-3.log` |
| `cargo +1.99.0 test --workspace --locked` | 第二轮 1246 通过、0 失败、10 忽略、66 个测试组，`final-tests-2.log` |
| 最后修正后的 `test -p kv-helper -p kv-cli -p kv-agent --locked` | 349 通过、0 失败、0 忽略，`final-owner-tests-2.log` |
| 最后修正后的相关 crate clippy／build | 通过，`owner-clippy-final.log`／`owner-build-final.log` |
| Windows GNU 相关 crate `check --all-targets --locked` | 交叉编译通过；初次及最后复查日志 `final-windows-check.log`／`windows-check-final.log`；未运行 Windows 硬件测试 |
| W7 约定覆盖率门禁 | 通过，`final-w7-coverage-4.log`；原始数据 `coverage/coverage.json` |

第一轮编译曾因磁盘不足失败；只用 Cargo 清理本轮生成的构建产物，保留源码及日志，关闭增量编译后重跑。CI 期间并行工作继续改动了 mobile／relay／Windows 等代码；一次 mobile 测试编译错误由其工作流修复，复查通过。workspace 的上述记录对应各次运行的源代码快照；本轮最后状态同步和 status 权限修正另有相关 crate 回归及覆盖率复查。W9 仍需在所有工作流停止修改后跑最终冻结 CI，而不能把早先部署产物当成本轮验收结果。

## 仍需实机或后续契约处理

- 实际 Touch ID／Hello、锁屏／唤醒、macOS 14、Windows TPM／服务 ACL，以及安装后的 Ubuntu↔Mac 流程没有在本轮用软件测试代替验收。Linux 跨 UID 读取 `/proc/<pid>/exe` 的进程认证问题仍是 OPEN-QUESTIONS D10，需要保持角色验证的 launcher／broker 方案。
- 所有设备丢失后的恢复路由、两审批端的完整配对形状、全局 T2 及硬件反回滚仍分别受 D08、D07、D05、T04 限制。
- 短寿命撤销 Directive 过期后，pending 状态仍保留。需要 owner 再次执行撤销以生成新签名；不在后台绕过 Strong 生成新的硬件签名。连接正常时的签名回执闭环已经测试，实际「一分钟内撤销」指标仍需 E08 测量。
- 有限 T2 现在也写入签名对象的标签 `confirm`，但附录 A.4 是否把它改为验证器必需字段仍需 D04 决策。
- 新的人类账户登录扩展不属于本轮匿名 V1 对接；启用该扩展的 relay 仍要求相应人类会话，helper 不绕过该要求。原生 Google／Apple 登录接入及官方实例验收见 D11／E09。
- W9 需要用包含本轮改动的最终源代码重新做安装／部署验收；以前的部署产物不能证明本轮新增流程已经上线。终端二维码、推送及移动后台链路维持各工作流原有未决项。

本轮关闭的是第 2、3 项的代码和真实模块接口验证；不据此宣称 M2/M5、硬件验收或整个仓库覆盖率 100%。

## 六项代码审查修复（2026-10-12）

对应用户「你说的6个，开始干」。以上验证记录是此前第 2、3 项的历史结果；本节记录随后六项修复及其独立验收。仍直接修改 main 工作树，没有 git 状态变更命令，也没有修改安装器或重新部署线上服务。

| 审查发现 | 修复后的行为与回归证据 |
| --- | --- |
| CLI 设备吊销只影响本机 | owner 使用真实 AK_s 签署 relay DeviceDeleteProof，把相同 Strong 证明放进加密 DeviceRevoke；SQLite 保存撤销意图、逐 peer 原始信封及 relay 完成状态。本机先撤销权威，peer 收到后撤销设备及其 Grant，relay 删除注册。测试覆盖三设备、600 条消息限流、首次失败后原密文重试、两执行端撤销以及完成后的幂等请求。裸 DK／Quick 签名、错误账户及目标均被拒绝。 |
| SQLite 回滚前已发布加密目录 | VaultMirror 先保存加密准备日志，SQLite 同事务保存提交标记，提交后才发布目录；重启按标记完成或丢弃日志。真实加密 vault 测试覆盖提交前／后的模拟崩溃及 SQLite 审计失败，确认拒绝的改名没有进入目录。完整审计跨库原子性和硬件反回滚仍是 T04。 |
| 手机没有真正完成 E2E 配对 | 手机发送加密 PairAccept／PairConfirm，保留原确认和信封供重试，等到真实 helper 的确认后才信任对端。Strong 确认签署本端完整 DeviceRecord，防止候选 AK 被 relay 替换；HTTP complete／finish 和单独的 peer 确认都不提交信任。真实手机核心↔helper↔relay 测试验证等待、双向确认和重复扫描。 |
| 设备改名破坏目录或 T2 标签 | label 与不可变密钥／能力分开核对；远程 DevicesRename 使用 SetDeviceLabel 并等已认证回执，更新执行端设置、目录和 owner 缓存。真实 relay 回归验证新标签用于常设 T2 两轮确认、授权在执行端安装／验证、重启及再次发起配对；DK／AK 保持不变。 |
| Grant 列表超过信封限制 | SQL 按 jti／cursor 分页，每页最多 100 条和 48 KiB 正文；超大单对象返回明确的有限元数据摘要，签名字段不被伪造。CLI 自动取完，手机以 Quick 签名续页并合并。125 张真实签发 Grant 的分页测试验证无重复、无遗漏和超大 scope；客户端拒绝重复游标。 |
| 新执行端无提示继承全局授权 | CLI 展示未过期全局授权数量并提供排除选项；任一端排除都写入签名 PairConfirm。双方保存排除状态，阻止旧 Grant 补发和未来全局 Grant 投递。测试覆盖保留／排除／无确认／错误输入、签名键集合校验以及手机不计入过期或已撤销 Grant。 |

并发回归另外暴露了上一轮配对轮询干扰下一轮的竞争。现代配对信封以 pairing_id 作为 id，轮询及状态变更绑定同一轮；旧确认返回 `wrong_pairing`，不会清空新配对。helper 的确认重试复用原始密文和签名，relay 对原期限内的同成员、同 SAS 有效确认返回成功；换 SAS 或伪造签名仍拒绝。

### 本次文件和依赖

- helper：`src/remote/{directory.rs,revocations.rs,pages.rs}`；`{mod.rs,engine.rs,bootstrap.rs,startup.rs,pairing.rs,pairing_relay.rs,ipc.rs,owner.rs,grants.rs,directives.rs,schema.sql}`；`tests/{owner_workflow.rs,six_fixes.rs,integrity_paths.rs,workflow.rs}` 及测试模块声明。
- 手机核心：`src/{engine.rs,relay.rs,tests.rs}`、`src/tests/helper_pairing.rs`、`Cargo.toml`。Candidate 的新字段是私有 Rust 状态，没有改动 Flutter／FRB 公共类型或生成绑定。
- 共享契约：`kv-core/src/remote/{pairing.rs,validation.rs,ipc.rs}`、`schemas/remote/{grant_list_result.schema.json,ipc_request.schema.json,pair_confirm_intent.schema.json}`、`kv-ipc/src/remote.rs`。
- CLI：`src/remote.rs`、`src/remote/{output.rs,tests.rs,live_helper_tests.rs}`；relay：`src/pairing.rs`、`src/tests.rs`、`src/tests/review.rs`。
- 文档：架构 §4、A.7、A.9、B、C.2；本报告与 OPEN-QUESTIONS 的 T01／T02／T04。
- 唯一新增依赖边是 `kv-mobile-core` 的 dev-dependency `kv-helper`（既有工作区路径），供真实跨模块配对测试使用；没有新增 registry 包或版本。`Cargo.lock` 的路径依赖边更新在用户已批准的范围内；工作树中其他工作流的依赖改动保留。

### 本次验收边界

最终验收日志放在 `rust/target-owner-integration/six-*`，使用 Rust 1.99.0，关闭增量编译及调试信息。测试仍使用临时加密 vault、真实 SQLite、HPKE／验签与本机内存 relay，仅注入硬件、UI 和进程边界；没有访问本机安装的 KeyValet。Windows 需特权 vault 所有权的新增测试带有明确的 ignore 说明。

新增契约已经回填架构，不扩大 MCP／relay-client 的 owner 权限。软件回归不代表实际 Touch ID／Hello／TPM、Linux D10 caller-auth、移动推送、原生安装或线上部署验收；W9 需在后续部署时采用包含本节修复的源码。离线 peer 的设备吊销消息可持续投递；需要新鲜 relay 删除证明时仍由 owner 重试。

| 最终检查 | 结果／证据 |
| --- | --- |
| 全工作区 fmt／clippy／build | 通过；`six-fmt-final-3.log`、`six-clippy-final-4.log`、`six-build-final-2.log`，均为 Rust 1.99.0；clippy 含 `--all-targets -- -D warnings`，build 使用 `--locked` |
| 全工作区 `test --workspace --locked` | **1269 通过、0 失败、10 忽略、66 组**；`six-workspace-tests-final-5.log`、`six-verification.json`。该轮冻结快照 466 个 Rust／SQL／契约／manifest 文件没有生产源码改动 |
| 最后的 CLI 测试与覆盖率复查 | 分页异常夹具补齐显式 `error: null` 并断言第二页调用，71 个单测和 3 个 CLI 测试通过；`six-cli-coverage-final.log`。此后仅修改了这处测试夹具，另跑全工作区 fmt 及 CLI all-targets clippy，通过 |
| W7 原约定可测逻辑范围 | **行 2066/2066 = 100%，函数 191/191 = 100%**；region **3431/3531 = 97.17%**。`six-cli-coverage-final.json`、`six-cli-coverage-gate.log`；系统适配层仍单独报告：行 49/431、函数 6/50 |
| 当前 relay 全生产 Rust 源码覆盖率复测 | 11 个模块，行 **2185/2373 = 92.08%**，函数 **295/330 = 89.39%**，region **3980/4408 = 90.29%**；`six-coverage.json`、`six-server-coverage-metrics.json`。后续新增人类账户模块及集成分支有未覆盖路径，不能继续套用 W2 早期 10 模块 100% 的历史结果 |
| 源码差异检查 | `git diff --check` 通过；全工作区验收后至覆盖率复查的唯一源码差异是 CLI 分页异常测试，生产源码一致 |

真实加密 vault／HTTP 的并发测试将等待预算设为 20 秒，以容纳一次 15 秒 HTTP 超时；超时诊断区分配对失败和未收到 SAS。没有把软件测试的等待时长用作 E08 的实际延迟结论。

配对信封 ID、完整签名 DeviceRecord 和排除标志需要 helper 与手机核心一起更新；旧配对客户端需要重新建立配对流程。先前已经建立的公钥目录和设备密钥不会因这次代码修改被替换。新增账户扩展的覆盖率缺口及原生验收仍按 OPEN-QUESTIONS 追踪。
