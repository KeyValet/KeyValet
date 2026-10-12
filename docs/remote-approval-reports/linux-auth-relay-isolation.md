# Linux caller authentication and relay transport isolation

2026-10-12。对应整体审查后批准推进的第 1、2 项；恢复接口和审计事务由并行工作流负责。

## 实现

Linux 增加 `keyvalet-peer.service`，以 root 运行 `kv-helper --peer-broker`，仅监听 `/run/keyvalet-peer/peer.sock`。它没有网络地址族、vault 文件访问路径或密码学操作入口。helper 和 relay-client 继续使用原来的无登录系统账户，能力集合为空。

helper 把已经接受的 Unix socket 通过 `SCM_RIGHTS` 交给 broker。broker 先验证请求来自安装路径下的 helper 及其服务 UID，再从传入 socket 的 `SO_PEERCRED` 和 `SO_PEERPIDFD` 验证原始对端进程。检查安装路径、root 所有权、父目录权限、执行文件 inode、进程开始时间和存活状态；角色由该执行文件决定。helper 校验 broker 的 root 对端凭据，并再次核对返回的 socket PID/UID/GID、owner 与 relay UID。调用方提交的路径、PID、UID 和角色均不能充当证明。

该远程认证路径要求 Linux 6.5+ 的 `SO_PEERPIDFD`，不退回可被 PID 重用影响的 `pidfd_open(peer.pid)`。具体 UAPI 和实现见 [Linux v6.5 socket.h](https://raw.githubusercontent.com/torvalds/linux/v6.5/include/uapi/asm-generic/socket.h) 和 [sock.c](https://raw.githubusercontent.com/torvalds/linux/v6.5/net/core/sock.c)。本次原生验证使用 Ubuntu 24.04、Linux 6.8.0-101-generic。旧内核的远程角色认证失败关闭；普通本地凭证会话的 Polkit 路径不变。

helper 的生产依赖中移除 reqwest、rustls、tokio-tungstenite 和 futures-util。`pairing_relay` 现在是类型化 IPC 桥；设备注册、challenge/verify、配对 HTTP、临时 WS、typed ack、Strong 吊销 HTTP 都在 relay-client 的 `control_transport` 中执行。helper 持有身份签名提供器、Strong 授权与签名、解封、设备目录和持久化策略；会话令牌只留在 relay-client。

控制队列上限 8 条、请求期限 45 s，轮询上限 30 s。完成结果必须匹配请求类型，已完成或取消请求拒绝回执和签名；身份签名绑定请求 ID、helper 自己的 DK 公钥和首个 32 字节 challenge，同一 challenge 的重试返回同一签名，更换 challenge 被拒绝。没有为 relay-client 开放 AK 签名、解密或任意 HTTP 代理入口。长连接密文 outbox 及其原有持久回执继续使用原来的通路。

relay-client 服务在尚未配对、配置文件不存在或只有 relay URL 时也启动控制 worker。完整绑定出现后启动长连接，绑定改变时停止旧连接并重新打开同一密文队列。Linux、macOS 和 Windows 安装器已相应调整；安装的签名、服务身份和 vault ACL 检查保留。配对 token 的过期时间固定为首次创建时的值，Strong UI 或网络等待不会延长它。

## 文件

- `kv-platform/src/peer_broker.rs`、`lib.rs`、`paths.rs`：socket FD 认证与内核身份检查；`tests/protection_installers.rs` 补新服务的仓库模板 fixture。
- `kv-helper/src/peer_broker.rs`、`main.rs`、`remote/process.rs`：root broker 入口及调用方认证；`remote/relay_control.rs`、`server.rs`、`ipc.rs`：控制队列和冷启动 IPC；`pairing_relay.rs`、`pairing.rs`、`startup.rs`、`revocations.rs`：网络委托及原始配对期限。
- `kv-relay-client/src/lib.rs`、`control_transport.rs`、`controls.rs`、`control.rs`：可复用传输库和服务控制 worker；`app.rs`、`config.rs`、`helper.rs`、`main.rs`：配置生命周期和类型化 IPC；`tests/control.rs`、fake helper 与既有 owner 流程回归。
- `kv-core/src/remote/relay_control.rs`、`remote/mod.rs`、`kv-ipc/src/remote.rs`、IPC schema/fixture/generator：类型和仅 relay-client 可调用的 3 个新 op。
- `kv-cli/src/remote.rs`、`remote/output.rs`、`remote/tests.rs`：控制传输未就绪/忙碌返回退出码 5，使用 i18n 提示检查 relay-client。
- `scripts/linux/keyvalet-peer.service`、`keyvalet.service`、Linux 安装/卸载脚本、`scripts/install.sh`、`install.ps1`、relay-client Windows 服务模板：broker 生命周期及配对前控制 worker 启动。
- `rust/Cargo.lock`：现有包的依赖归属调整；并行恢复测试只做库入口和 trait 调用兼容修正，未重写恢复实现。共享 server 编译中的一处 SQL 参数引用修正也已保留。

## 依赖

没有新增 registry 包。下列依赖已在工作区和锁文件中使用；这里只调整直接依赖归属。

| 使用方 | 依赖 | 用途 |
| --- | --- | --- |
| helper | `url 2.5.8`，现有锁定版本 | 解析 relay URL 和配对 URI，不创建网络客户端 |
| relay-client | `kv-core`（workspace path，remote feature） | 共享公钥、信封和控制 DTO |
| relay-client | `zeroize =1.9.0` | HTTP 响应缓冲区和会话令牌 |
| helper 测试 | `kv-relay-client`（workspace path） | 运行生产传输库，模拟控制 IPC，不依赖本机安装 |

## 验证记录

Ubuntu 的非特权平台单测已通过。单独以 root 运行忽略的 `native_cross_uid_broker_preserves_roles_without_installing_keyvalet`，8 个真实进程/UID 用例通过：owner CLI、root CLI、MCP、hook、专用 relay UID 可认证；owner UID 启动的 relay、其他 UID 的 CLI、未知程序被拒绝。每个用例先断言 helper 用户读取对端 `/proc/<pid>/exe` 确实得到 PermissionDenied。测试在临时 root fixture 中复制执行文件并创建 socket，结束自动清理；没有修改远端已安装服务、vault 或 W9 环境。

本机测试产物位于 `rust/target-owner-integration/isolation-*`；原生测试使用单独的 `/tmp/keyvalet-owner-isolation-20261012`。安装器 Python 回归 8/8 通过，四份修改过的 shell 安装/卸载脚本的语法检查通过。

最终 Rust 1.99.0 验证结果：

- Mac：`cargo fmt --all -- --check`、`clippy --workspace --all-targets -- -D warnings`、`build --workspace --locked` 全过；`test --workspace --locked -j 2` 为 **1290 passed / 0 failed / 10 ignored，68 groups**。`-j 2` 仅限制并行编译以缓解共享工作区磁盘压力。
- Linux：`kv-platform`、`kv-helper`、`kv-relay-client` 的 clippy（all-targets、warnings denied）全过；测试 **410 passed / 0 failed / 6 ignored，11 groups**；helper/client 原生 build 通过。忽略的 root 跨 UID 测试单独运行通过，覆盖 8 个真实进程用例。
- `systemd-analyze verify` 通过。验证 fixture 仅把两个 unit 的 ExecStart 安装路径换成此次原生构建产物路径，以避免依赖或修改现有安装；其余 unit 内容保留。
- 注册和认证通过真实 helper 冷启动 IPC 与 relay-client worker 执行；断言 helper 收到的认证结果没有 `session_token`。配置缺失时不创建 spool，完整绑定出现和变更后自动连接/重连；控制队列容量、取消、过期、请求类型、重复/更换 challenge、错误结果形状和私钥提供器不匹配均有回归。
- 既有匿名注册、单例账户迁移/原密钥保留、两端 SAS、审批执行一次、Strong 吊销、配对原签名重试和数据库零明文检查通过。迁移发现的跨秒配对过期时间问题已修正，使用最初冻结的期限。

完整测试后再次校验 **536 份源码/契约/脚本**，无后续变化。结果保存于 `isolation-verification.json`、`isolation-source-after-workspace-test.json`；最后检查日志为 `isolation-fmt-final-2.log`、`isolation-clippy-final-2.log`、`isolation-build-final-3.log`、`isolation-workspace-tests-final-2.log`。早期两次广泛构建因磁盘耗尽中断，不计入通过结果；只清理本工作流生成缓存，保留源码、报告、覆盖率 JSON 与测试日志。

## 验收边界

原生 socket/UID/执行文件检查已验证；安装到 systemd 后的完整两机审批、Touch ID/Hello/TPM 实机授权和 Windows 原生运行仍需对应验收。该报告不将软件密钥或临时 fixture 的结果计为硬件审批验收。
