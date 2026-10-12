# W1–W5 联合接口验收

日期：2026-10-11。范围：用户追加授权的 W1–W5 接口检查、问题修复，以及修复后 W3 的 CI 可测逻辑 100% 行覆盖率验收。直接修改 main 工作树；没有执行 git 状态变更命令，没有修改安装脚本，也没有安装或启动真实服务。

本文区分模块间协议验收与已安装产品启用。集成测试实例化真实 W1 provider、W2 relay、W3 daemon、W4 状态机和 W5 MCP 客户端；OS 信任校验、vault 镜像及执行 runner 使用显式注入的测试实现。真实生产启用还需要下面列出的 bootstrap 和部署条件。

## 发现与修复

| 接口 | 问题 | 修复 |
| --- | --- | --- |
| W3 → W4 / W0 | 客户端请求的公钥查询没有共享 op 和 helper 接收方 | 新增 `remote.relay.identity` 的类型、schema、白名单和 handler；返回 public JWK、device/account ID，客户端在访问 relay 前核对两项配置绑定 |
| W4 → W3 | poll 在发出 IPC 响应前就标记已交付，丢响应可能丢消息；重连会重复返回已落盘信封 | 密文规范 JSON 摘要绑定 SQLite 持久回执；客户端落盘后发 `spooled`；relay 接受后发 `accepted`，再删除本地前缀；重复回执幂等 |
| W3 → W4 | 过期、已接受或审批已结束的磁盘队列头无法推进 | `inspect` 由 helper 判断连续失效前缀，客户端仅按 `retired_count` 删除；客户端不自行作策略判断 |
| W3 → W2 | relay 已提交但 HTTP 响应丢失后，同一密文重试返回 409 | 完整签名信封相同则成功返回，保留 ack 状态且不再次推送；同键不同密文仍冲突；请求 fan-out 可跨 helper 的批次边界提交 |
| W2 ↔ W3 ↔ W4 | cancel POST 丢弃 helper 签名信封，只发送空体；裸 relay 提示无法授权清理缓存 | 客户端原样发送签名取消信封，relay 验证 requester 与原 recipient 后转发；resolved/expired 后仍能投递短时有效的清理信封，不改变原审批执行权限 |
| W3 → W2 | 按 approval_id ack 会同时确认 request/escalate/cancel，可能提前确认未交给 helper 的取消信封 | 新增可选 `type` 选择器，W3 总是带实际信封类型；HTTP/WS ack 只更新对应行；旧省略 type 的批量调用保留兼容行为 |
| W3 → W4 | 永久非法信封可能反复重放并堵住重连 | 只有在永久拒绝已持久审计后返回 `ack: true`；存储、审计、密钥提供器暂时故障仍不 ack |
| W1 → W4 → W3 → W2 | presence.update 仅更新 helper 本机缓存，没有形成远程 hint | helper 把粗粒度 PresenceHint 签名、加密并送入同一 outbox；原始 signals 不出本机 |
| W4 入站 | 缺少 ApprovalEscalate handler；取消/升级缺少 payload ID 与 envelope ID 绑定 | 验证 ID 和原 requester；升级只产生交付提示，保持原审批请求不可变；已签发审批的请求重放不重新进入 UI 缓存 |
| W5 → W4 | 超时审计 op 不在白名单，状态没有 helper 等待策略 | 加入 `remote.client_timeout_observed` 的窄 MCP ACL；使用已认证 UID/父 PID 审计，忽略模型的身份字段；status 返回等待和 progress 上限 |
| W4 → W5 | 缺少审批可取结果的通知接收契约 | 已认证 MCP 可收到只含 approval_id/status 的非消费通知；获取结果仍走 remote.wait；冷连接通知显式 opt-in |
| W1/W4/W3 原生 IPC | Linux/Windows relay 专用端点、账户校验与公共路径不一致 | 共用 kv-platform 常量；Linux 专用 relay socket 严格限定服务 UID；Windows 专用 pipe/DACL、服务 SID、安装路径和 publisher 校验；macOS 使用独立 relay audit-token requirement |
| Windows W4/W5 | service 创建的 MCP worker 的父 PID 是 helper，不是原 agent | 在 OS 验证 worker 和 launcher 后、发送 ready 前注册 worker → launcher 实际父 PID 的绑定；保留进程句柄和 RAII 绑定，关闭时移除；不信任模型 PID |
| Windows W5 → W4 | Stop hook 原生入口直接放行，没有查询 pending | 复用 kv-platform 的已验证 helper pipe 和 OS 父 PID 查询，接入既有 remote framing、三次阻止上限与故障放行；原生读写限时 2 s，不触发 vault unlock |
| W3 / 工作区 TLS | rustls 同时启用 ring 与 AWS-LC 时，默认 WSS builder 无法自动选择 provider，可能 panic | 显式安装 ring 默认 provider，保留已有进程默认；loopback WSS 回归确认发送 TLS handshake，并把关闭连接报告为网络错误 |

共享 Appendix B/C、IPC allowlist 向量及 schema 生成源一起更新。新 W2/W3 应一起部署，以启用按信封类型确认的 ack 契约。

## 回归证据

- `kv-relay-client/src/tests/interfaces.rs`：真实 W1 SoftwareFileKey 创建、重开、公钥和 ECDH；真实 W2 注册、DK challenge 认证、SAS 双方确认；两个真实 W4 helper 经 IPC 与两个 W3 daemon 交互；W1 PresenceReporter 经批准角色 IPC 产生远程 hint；原请求密文到达审批端，强审批签名后原请求执行一次，实际 W5 HelperSession 获取原结果，第二次领取返回 `already_consumed`。最后检查双方磁盘队列为空。
- `kv-helper/src/remote/tests/acceptance.rs`：poll 响应丢失重复交付；审计故障回滚落盘回执；SQLite 真正关闭、重开后 spooled/accepted 状态保留；审批到期后只发可清理缓存的短时签名取消。
- `kv-helper/src/remote/tests/interfaces.rs` 和 `transport_edges.rs`：真实身份查询与 challenge 签名、超时审计、hook 同 agent 关联、非消费通知、半帧读取、权限边界、密文回执绑定、连续前缀检查、terminal ack 与审计故障。
- `kv-server/src/tests/interfaces.rs`：相同消息/回复/cancel 的重试，修改密文冲突，分批 fan-out，resolved/expired 状态下的签名取消，按 type ack 不确认同 ID 的另一条密文。`unit_tests/messages.rs` 验证满额时已有密文重试不新增计数。
- W3 客户端测试：落盘回执丢失后重复 poll 不重复写入磁盘；helper 回执失败时保留原队列；只有 helper 失效判断或 durable accepted 回执才能删除前缀；身份配置不匹配时不访问 relay、不签 challenge。
- WSS provider 回归使用真实 TLS ClientHello 与只读取握手后关闭的 loopback TCP peer；不关闭证书校验、不添加测试 CA、不需要外网。Windows Stop 的共享判断和 framing 有 CI 测试；新增原生 pipe 适配器只做跨目标检查，真实运行另列缺口。
- W3 原有真实时间断网测试：假 relay 完全停止 30 s，期间 0/10/20 s 各产生三条信封；重启后九条按 `message-0` 到 `message-8` 原顺序送达，队列为空。

测试仅使用仓库文件、临时目录、loopback listener 和明确注入的 OS 服务。没有访问已安装 helper、sudo、GUI、Touch ID、TPM 或 Windows Hello。

## 验证结果

最终验证使用 Rust 1.99.0、`CARGO_TARGET_DIR=/Users/guang/dev/keyvalet/rust/target-w3`、`CARGO_INCREMENTAL=0`、`CARGO_PROFILE_DEV_DEBUG=0` 和 `CARGO_PROFILE_TEST_DEBUG=0`。关闭调试符号只降低构建磁盘占用，未改变 debug assertions 或测试逻辑。所有命令退出码均为 0。

| 检查 | 结果与证据 |
| --- | --- |
| 工作区 `fmt --all -- --check` | PASS；[workspace-fmt.log](../../rust/target-w3/workspace-fmt.log) |
| 工作区 `clippy --workspace --all-targets --locked -- -D warnings` | PASS；[workspace-clippy.log](../../rust/target-w3/workspace-clippy.log) |
| 工作区 `build --workspace --locked` | PASS；[workspace-build.log](../../rust/target-w3/workspace-build.log) |
| 工作区 `test --workspace --locked` | **1000 passed，0 failed，8 ignored**，58 个测试组（含 doc tests）；[workspace-test.log](../../rust/target-w3/workspace-test.log)。8 个 ignored 属于现有硬件/安装/隔离测试，W3 没有 ignored |
| W3 全部测试与覆盖率门禁 | **60 passed，0 failed，0 ignored**；CI 可测逻辑 **1096/1096 行、134/134 函数，均为 100%**；[运行日志](../../rust/target-w3/coverage-interface.log)、[CI JSON](../../rust/target-w3/coverage-final-ci.json) |
| W3 全量 macOS 生产源码覆盖率 | **1132/1196 行（94.65%）**，138/146 函数（94.52%）；64 行未覆盖均为原生适配器/进程入口。LLVM region 为 1777/1950（91.13%），不声称分支 100%；[全量 JSON](../../rust/target-w3/coverage-final-full.json)、[HTML](../../rust/target-w3/coverage-html/html/index.html) |
| W3 真实时间断网 30 s | PASS；停 relay 后三波产生的九条密文全部按原顺序送达，两项断言分别验证接收顺序与本地队列为空 |
| 五个相关 crate 的 Windows GNU `clippy --all-targets --locked -- -D warnings` | PASS；`kv-relay-client`、`kv-helper`、`kv-agent`、`kv-mcp`、`kv-hook`；[Windows 日志](../../rust/target-w3/interfaces-windows-clippy.log) |
| 同五个 crate 的 Linux GNU `clippy --all-targets --locked -- -D warnings` | PASS；[Linux 日志](../../rust/target-w3/interfaces-linux-clippy.log) |
| W3 三平台二进制生成 | PASS；macOS arm64 Mach-O、Linux x86_64 ELF、Windows x86_64 PE；Linux/Windows 均完成交叉链接，[Linux build](../../rust/target-w3/relay-linux-build.log)、[Windows build](../../rust/target-w3/relay-windows-build.log) |
| LaunchAgent plist、coverage shell 语法、`git diff --check` | PASS；未执行服务注册或任何 git 状态变更命令 |

在 `rust/` 复现工作区检查：

```sh
export CARGO_TARGET_DIR=/Users/guang/dev/keyvalet/rust/target-w3
export CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0
cargo +1.99.0 fmt --all -- --check
cargo +1.99.0 clippy --workspace --all-targets --locked -- -D warnings
cargo +1.99.0 build --workspace --locked
cargo +1.99.0 test --workspace --locked
KV_RELAY_TOOLCHAIN=1.99.0 sh crates/kv-relay-client/coverage.sh
```

跨目标命令是 `cargo +1.99.0 clippy -p kv-relay-client -p kv-helper -p kv-agent -p kv-mcp -p kv-hook --all-targets --target <target> --locked -- -D warnings` 与 `cargo +1.99.0 build -p kv-relay-client --target <target> --locked`。本机已有 Windows MinGW 和 W4 的 Zig wrapper；它们只用于交叉编译，不是普通 CI 测试依赖。Linux 的 `CC_x86_64_unknown_linux_gnu` 和 linker 指向 `rust/target-w4/tooling/cc-linux`，`AR_x86_64_unknown_linux_gnu` 指向同目录 `ar`，Zig cache 均重定向到 target-w3；Windows 的 CC/linker 指向 `/opt/homebrew/bin/x86_64-w64-mingw32-gcc`。

100% 口径按用户确认限定为 W3 的 CI 可测逻辑行覆盖率；实际门禁还要求函数 100%。仅排除测试源码和 W3 报告列明的原生入口/适配器，所有配置、IPC、HTTP/WS、队列、失败/重试及 helper ack 逻辑仍计入。CI region 为 1728/1797（96.16%）；没有逐行业务代码排除或 `cfg(coverage)` 替代实现。

## 改动落点

| 组件 | 接口修复文件 |
| --- | --- |
| kv-ipc | `src/remote.rs` |
| kv-core | `src/remote/ipc.rs`、`src/remote/relay.rs`、remote IPC/ack schemas、IPC allowlist 向量和 `generate.py` |
| kv-platform | `src/paths.rs`、`src/linux.rs`、`src/peer_windows.rs` |
| kv-helper | `src/remote/{mod,engine,ipc,outbox,store,server,process}.rs`、`schema.sql`、remote 回归测试；`daemon_linux.rs`、`daemon_win.rs`、`mcp_win.rs` |
| kv-server | `src/messages.rs`、`src/presence.rs`、接口测试与原重发回归断言 |
| kv-relay-client | `Cargo.toml`（已有工作区 crate 的测试依赖与已有 rustls 的显式 provider 引用）、client/helper/queue/transport/platform/windows、测试 harness 和接口回归、README 与 service 说明 |
| kv-hook | Windows 专用的已有 kv-platform/tokio 依赖边、`src/stop.rs` 的受信 pipe 适配器 |
| Cargo.lock | 本轮接口修复只同步已有包之间的依赖边；未引入新的外部包 |
| 文档 | 架构 Appendix B/C、本报告及 W3 报告 |

W1/W4/W5 同工作树已有的并行改动保留；本报告不把它们全部归为 W3 的修改。

## 部署条件与未验证项

1. **生产 bootstrap 尚未启用**：daemon 尚未从 vault 的 AEAD 已认证元数据重开 DK/AK、构造并安装 RemoteHelper，也未把真实 credential policy/runner 与其执行绑定。没有元数据时仍返回 `remote_unavailable`；不会自动生成软件身份或放宽现有认证。新增 `Store::restore_verified_directory` 仅允许从可信 DeviceMirror 初始化空数据库，保留 tombstone，不是任意导入或绕过 SAS 的 IPC。
2. **W9 接入**：消费 `rust/crates/kv-relay-client/service/` 的现有模板，先配置 relay 账户/虚拟服务 SID、配置与队列权限，再重启 helper 创建专用端点，最后启动 relay-client。安装器未修改。macOS 仅在 signed daemon/agent 模式启用。
3. **原生运行验收**：跨目标类型检查不证明 systemd 服务账户、macOS 真 audit token 或 Windows SCM/SID/publisher/worker PID 绑定在真实安装中可运行。硬件 provider/原生 Hello、Touch ID/SE、TPM 以及 Windows NTFS 掉电语义仍需各平台环境。
4. **产品外部集成**：真实 Claude idle channel 唤醒和需联网认证的运行时实测、W9 的 CLI/透明代理入口仍按 W5 报告单列；本轮协议集成测试不将其称为已通过。
