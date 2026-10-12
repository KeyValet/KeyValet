# Windows 原生安装与验收（2026-10-12）

Windows x64 的构建、自动测试、真实安装、普通账户访问、升级、卸载与重启验收通过。
Windows Hello 和远程审批的 PCP 双用途设备钥匙仍有未通过项，不能据此宣称 Windows 远程审批已完成硬件验收。

## 环境与源码

- 宿主机：`ssh ndu`，libvirt `qemu:///system`；虚拟机 `win11`。
- 客体：Windows 11 Pro，build `26200.9445`，x64；`ssh win11`，账户 `guang\win`。
- VM 配置为模拟 TPM 2.0；来宾报告 TPM Present/Ready/Enabled/Activated。该结果不构成物理 TPM 证明。
- 安装了 Rust/Cargo 1.99.0、Visual Studio Build Tools 17.14.41、PowerShell 7.6.6。
- 验收对象为当前工作树的源码快照，包含未提交改动，不是仅验证 HEAD。
- 基准 HEAD：`9d036b1b48a11883e641c5b5bbf7086da3314fad`；共 867 个快照文件。
- 最终测试源码指纹：`056e478315cdaf44ddb74ebab8b37a174d9a2624bfe639a5900df3f6347e574a`。
  指纹算法为按路径排序的 `path + NUL + SHA256(file) + LF` 再取 SHA256；文件清单保存在工具产物中。

## 已执行验证

所有 Rust 命令在 Windows/MSVC 上原生执行，使用独立 `CARGO_TARGET_DIR`，没有通过交叉编译代替执行。

| 检查 | 结果 |
| --- | --- |
| `cargo fmt --all -- --check` | 通过 |
| `cargo clippy --workspace --all-targets --locked -- -D warnings` | 通过 |
| `cargo build --workspace --locked` | 通过 |
| `cargo test --workspace --locked --no-fail-fast` | 1010 passed、0 failed、16 ignored |
| PowerShell 5.1 / 7 安装脚本、TOML 保留和 relay ACL 检查 | 两个版本均通过 |
| PowerShell 导出脚本的真实执行 | 两个版本均通过 |
| 中英文协议凭证文案 | 分别通过 |
| LocalSystem 下的四条 helper 配对、账户恢复、Grant 与吊销流程 | 4 passed |
| LocalSystem DPAPI 往返、PCP 单用途钥匙权限与清理 | 2 passed |
| 干净机器的实际安装与服务生命周期 | 通过 |
| 重启后的自动启动、已安装 CLI 状态、测试 profile 清理 | 通过 |

涉及特权目录、TPM、Hello 的测试保持 opt-in。普通测试不读取本机安装文件；SQLite 重启测试使用测试专用持久化 fixture，生产路径检查保留在真实 `Store::open` 中。
本轮没有测量或宣称整个仓库单测覆盖率 100%；W4 先前的覆盖率口径见 [W4 报告](remote-approval-reports/W4.md)。

实际安装测试包含：SYSTEM 服务身份与内核 pipe PID、七个二进制的文件哈希、未配对 relay 的独立虚拟账户与手动启动、WSL 资产完整性、真实非管理员账户的状态查询、另一个管理员的远程状态拒绝、错误 ACL/错误属主在停止服务前拒绝、同账户升级、SCM 停止与重启、默认卸载保留 vault、显式移除测试 vault。
普通账户探针在自己的批处理登录上下文运行，仅临时给该测试 SID 添加 `SeBatchLogonRight`，随后移除。任务、测试账户均删除；Windows 缓存的三个临时 profile 在客体重启后清理并复查。

## 本轮发现与修复

| 位置 | 修复 |
| --- | --- |
| `kv-mobile-core/src/store.rs` | 非 Unix 文件锁原先为空实现；补充真实锁、超时与释放，增加争用回归 |
| `kv-core/src/settings.rs` | Windows 并发读取可能令原子替换短暂失败；保留同一私有临时文件并进行有时限的原子重试 |
| `kv-vault/src/vault.rs` | 私有目录 ACL 原先没有向新文件继承，导致远程数据库被拒；验证已有敏感路径后恢复私有继承 |
| `kv-helper/src/daemon_win.rs` | 管理员通道漏接保护状态探针与 `remote.*`；补充身份检查后的路由和原始帧交接 |
| `kv-helper/src/remote/process.rs` | 远程 IPC 原先忽略安装器显式选择的 unsigned 开发标记；统一受保护标记、固定安装路径与属主校验 |
| `kv-relay-client/src/queue.rs` | Windows sharing/lock violation 正确映射为 busy；访问拒绝仍作为存储错误拒绝 |
| `kv-relay-client/src/windows.rs` | SCM 配置崩溃后重启动作所需句柄缺少 `SERVICE_START`，导致注册失败；补充该权限 |
| `kv-platform/src/device_key/windows.rs` | PCP 删除钥匙不接受 silent 标志；使用支持的删除参数，增加真实 TPM 清理回归 |
| `kv-cli/src/remote/system.rs` | 修复 Windows 条件编译下未使用参数导致的 Clippy 错误 |
| `kv-mcp/src/tools/protocols.rs`、`kv-platform/src/protection.rs` | 修复依赖英文界面的断言和不完整的未来版本测试数据 |
| `scripts/package-windows.ps1` | 本地包加入 server、relay-client 和服务资产，并正确使用 `CARGO_TARGET_DIR` |
| `scripts/uninstall.ps1` | 停止、等待并删除 relay 服务，保留默认 vault 留存行为 |
| `scripts/install.ps1`、`scripts/test-windows-service.ps1` | 修复 UTF-8 捕获，使用当前状态 JSON 契约，增加真实普通账户与跨账户拒绝验收 |

`kv-helper` 的持久化 fixture、Windows 特权测试标记、`kv-cli` 的状态回归和 relay 的断网/关闭断言同步调整。源码快照还同步了并行工作中已有的 server 冻结测试时钟修复，消除真实秒边界导致的配对单测误判；没有放宽生产到期规则。
没有新增 Rust 依赖，没有执行改变 git 状态的命令。

## 安装后的状态

- 安装位置：`C:\Program Files\KeyValet`；版本 `0.3.0`，unsigned development 包。
- 包 SHA256：`fdc4f61618b2c40c18f840a82070243b5310cf3df0e32795e0cb966a6121d930`。
- 属主：`guang\win`；用户级 MCP/hook 配置已由安装器写入，登录任务使用 `Limited`。
- `KeyValetHelper`：LocalSystem、Auto、Running；重启后仍自动运行。
- `KeyValetRelay`：`NT SERVICE\KeyValetRelay`、Manual、Stopped；尚未配对。
- `kv-cli status --json` / `status --summary` 正常返回本地保护信息；远程部分明确返回 `remote_unavailable`。
- 采用 `-SkipSetup`，没有创建 `master.key`、`vault.enc` 或以软件方式代替 Hello。

## 未通过项与变更请求

1. **W1 / kv-platform：PCP 双用途钥匙不可用。** LocalSystem 下 `pcp_raw_secret_spike` 被拒。
   `NCRYPT_KEY_USAGE_PROPERTY` 设置返回 `0x80090029`；PCP generic usage 设置也未成功。
   独立 ECDH 钥匙能产生 32 字节 raw secret，独立 ECDSA 钥匙能产生 64 字节签名，但该主机尚未通过“同一把 P-256 钥匙完成两种操作”的 V1 契约。
   请求继续实现/验证保持 W0 同钥匙契约的 Windows 硬件提供者，或另行评审协议变更。当前保留失败即拒绝；未启用隐式软件回退。
2. **W1 / Windows Hello：需交互验收。** 在真实 `win` 桌面 session 1、非提升 token 下，`KeyCredentialManager.IsSupportedAsync()` 返回 false。
   PIN 尚未完成设置与交互确认；Strong 创建、签名、取消及重复提示未验收。
3. 物理 TPM、Windows ARM64、真实手机/桌面远程审批、实际 AI 客户端操作和 live WSL 未在该 VM 上完成验收。
   此次包没有生产 Authenticode 签名，不是可发布的 Windows 生产产物。

## 证据位置

- 本机工具产物：`rust/target-w4/windows-native-20261012/`，已由 `.gitignore` 排除。
- 客体源码与日志：`C:\kv-native-20261012-bd8467\repo`、`...\logs`。
- 主要记录：`checks.json`、`windows-service-test.json`、`installed-owner.json`、`post-reboot.json`、`system-helper-result2.json`、`system-key-cleanup-result.json`、`pcp-capabilities*.json`、`tested-source-manifest.json`。

SCM 权限依据 [Microsoft ChangeServiceConfig2W 文档](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-changeserviceconfig2w)；测试账户登录权限通过 [LsaAddAccountRights](https://learn.microsoft.com/en-us/windows/win32/api/ntsecapi/nf-ntsecapi-lsaaddaccountrights) 添加并回收。原生执行结果以上述日志为准。
