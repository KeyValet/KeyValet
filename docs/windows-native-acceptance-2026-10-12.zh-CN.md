# Windows 原生安装与验收（2026-10-12）

Windows x64 的构建、自动测试、真实安装、普通账户访问、升级、卸载与重启验收通过。
下文第一轮记录为 K1 改动前结果；双 PCP 键及后续真机 Hello 结果见文末。原 VM 的 Windows Hello 仍等待 PIN；新真机的 AK_s 原生创建/签名及安装后 Hello vault 初始化/解锁通过，实际远程 Strong 链路未测。

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


## R2-B：K1 双 PCP 键（2026-10-12 追加）

K1 已实现：DeviceRecord 新增可选 dk_sig（P-256/ES256），身份验签统一选 dk_sig 或旧 dk_pub，HPKE 继续使用 dk_pub。
Windows DK 使用两个独立 PCP 对象，Quick 为第三个 PCP ECDSA 对象，Strong 保持 Hello RSA-2048/RS256。
新字段与嵌套未知字段进入完整记录 JCS；split SAS 绑定 ECDH 和签名公钥，旧记录的向量保持。
协议、schema、向量、跨归属机械替换和架构回写文字见 [R2-B 报告](remote-approval-reports/R2-B-windows.md)。

本轮使用 Windows/MSVC 原生执行，独立目录 C:\kv-r2b-20261012\target；没有交叉编译代替运行。
Mac 使用 Rust 1.99.0 和 rust/target-r2b，关闭调试符号和增量编译以降低共享机器的磁盘占用。
两端使用同一份 649 文件冻结快照，源码指纹为 `df4d03aed184a45ba76b546049ab73fa04639f562287a155bb0155fae2d75aaf`。
`cargo fmt --all -- --check`、`cargo clippy --workspace --all-targets -- -D warnings`、`cargo build --workspace --locked`、`cargo test --workspace --locked` 在两端全部通过。
Mac 为 1323 passed、0 failed、10 ignored；Windows 为 1079 passed、0 failed、25 ignored。计数汇总各测试程序与 doctest；特权原生测试在普通 CI 后单独显式执行。
完整清单、四条命令输出与结果 JSON 见 [R2-B 报告](remote-approval-reports/R2-B-windows.md)。最终报告与证据于测试后写入，不属于此冻结快照。

| 原生项 | 结果与证据 |
| --- | --- |
| LocalSystem 双 PCP 创建、持久化重开与角色/类型 pin | 通过；r2b-system-native.json |
| 独立身份 ES256 64 字节，错误 ECDH DK 公钥验签失败 | 通过 |
| ECDH raw secret 32 字节，与软件端共享点相同 | 通过 |
| HPKE 请求/响应、PCP Quick 决定、软件执行端按 ES256 验签 | 通过；最终已安装环境 62.5863 ms；不含桌面点击/公网 |
| 第二把创建失败时清理第一把，无软件 fallback | 通过 |
| 双键删除（flags=0）、删除后重开拒绝 | 通过 |
| 实际安装、普通 owner 状态、跨账户拒绝、ACL/错误 owner 拒绝、升级、SCM 重启、卸载默认保留/显式清理 | 11 项通过；r2b-windows-service-test.json |
| 已安装 CLI status --summary | 两把键存在时显示 pcp_ecdh=present、pcp_ecdsa=present；清理后库存为空 |
| Hello IsSupportedAsync | false；owner session 1、非提升 token，2026-10-12T14:46:33Z |
| Hello 创建、Strong、取消、重复提示及 Strong 跨平台 fixture | **等待 PIN**；用户确认未设置，未执行 |

VM 仍为模拟 TPM 2.0、x64、unsigned development 包。原生结果不替代物理 TPM、ARM64 或完整 TaskDialog 点击。
当前 owner 安装保持未初始化，没有 master.key 或 vault.enc；未配对 relay 为 Manual/Stopped。
最终冻结快照另行打包、同 owner 实际升级，并用最终测试二进制复验三项 LocalSystem PCP 测试，全部通过。
最终 unsigned development v0.3.0 ZIP SHA256 为 `755ab56a79a4246ccd27ce541e9dc35a382a41573b195028d83e2acf04c145f0`；helper 为 LocalSystem/Auto/Running。
安装器避免在无公共配置时自动启动失败的 relay；无绑定控制 worker 的 Windows 接线留给 R2-A。
安装回归删除了临时账户；Windows 仍缓存一个已删除测试账户的 profile，需在客体下次重启后清理（SID/路径保存在验收 JSON）。
证据位于 [assets](remote-approval-reports/assets/) 的 r2b-* 文件；原生工作日志在 C:\kv-r2b-20261012\logs。

## 2026-10-13：Windows 真机 Hello 补充

本节记录用户睡觉前的首轮结果；启动修复和正式初始化/解锁结果见下一节“恢复工作”。

用户提供 LENOVO 21LD / Windows 11 家庭版中文版 x64 / build 26200，owner `11516` 已设置 PIN，并实际配合指纹与取消。Intel TPM 为 Present / Ready / Enabled / Activated。采用同一 R2-B unsigned development 0.3.0 包，在非提升 owner 桌面完成 UAC 安装；helper 为 LocalSystem / Auto / Running，未配对 relay 保持 Manual / Stopped。

| 项 | 结果 |
| --- | --- |
| 桌面 session 13、非提升 IsSupportedAsync | true |
| 原生 AK_s 创建 / RSA-2048 / RS256 验签 | 通过；256-byte 签名；107.592 s 含用户操作 |
| 创建时取消 | 通过：OperationFailed，5.662 s；未到签名步骤 |
| vault 固定 challenge 与重复派生 | 后续原生复验通过：harness 1 passed / 0 failed，23.67 s；主密钥相同。原两次 90.331 s / 90.240 s timeout 保留，根因未完全证明 |
| 同一 AK_s 两次不同消息签名 | 通过：各 256-byte，生产 RS256 验签；28.278 s 总时间，用户报告两次提示 |
| 已有 AK_s 的签名取消 | 旧轮询 90.047 s 后 timeout 拒绝，未通过；完成回调对照版 7.861 s 返回 UserCanceled(3)，拒绝通过 |
| 新增 AK_s 测试密钥删除 | 通过：DeleteAsync 完成后 OpenAsync 为 NotFound；首轮 guard-only 删除未独立核对 |
| 已安装 protected worker | 未通过：0xc0000142；默认对象 DACL 的 cmd 控制亦失败，生产权限未放宽 |
| 最终已安装包的取消 / 正式 setup-hello / 实际 Strong 决定 | 未测；完整应用仍被 worker 启动故障阻断 |
| 原始日志取回与临时用户任务清理 | 完成：06:17:18Z 临时任务为 0，诊断服务不存在；正式服务/任务、备份保留；master.key / vault.enc 不存在 |

取消修复已回写 Windows Hello 等待实现：轮询前注册 WinRT 完成回调，订阅失败时取消并拒绝，预算和验签保持。新增可移植假 OS 回归；没有修改生产进程权限、安装逻辑或启用文件钥匙回退。最终源码提取等待策略后未再次在用户睡觉后的真机弹窗，已安装包仍为最初冻结产物。

四条自动检查在 Mac / Windows VM 执行，真机没有 Rust / MSVC，不将 VM 自动检查表述为真机执行。完整机器/产物指纹、自动检查结果、备份、对照与归属外变更请求见 [补充报告](remote-approval-reports/R2-B-physical-hello-2026-10-13.md)，原始结果与清理证据见 [证据索引](remote-approval-reports/assets/r2b-physical-hello-20261013-state.json)。原生子项成功不等于安装后的完整审批链路已通过。

本轮源码修复后的 Mac 四条全绿：1357 passed / 0 failed / 10 ignored。Windows/MSVC 的 fmt、build、test 通过：1102 passed / 0 failed / 25 ignored；Clippy 被当前 main 的 `kv-cli/src/remote/transport.rs:29` unused function 阻断。独立副本添加一行 `#[cfg(any(unix, test))]` 的候选使 Clippy 通过，已还原且没有改归属外 main 文件，变更请求列在补充报告 P04。这一轮不标“两端四条全绿”。


## 2026-10-13 恢复工作：进程隔离修复与正式 Hello vault

原默认 DACL 在 Windows 初始化阶段阻断 worker。现以服务设置的每次启动 token attribute 区分 worker 自访问和普通同账户进程访问，保持同账户内存、线程、token/default-thread 拒绝。CREATE_SUSPENDED 后在首条用户指令前设置实际 token 的 owner=SYSTEM 和 DACL，再恢复执行；未采用普通 owner GenericAll 回退。设置失败即拒绝，mitigation/Job/peer 检查保持。用户已授权此归属外修正及 CLI 一行 cfg。

| 项 | 本轮结果 | 证据 |
| --- | --- | --- |
| 实际升级 | 通过，10.660 s；unsigned development 0.3.0 native MSVC debug | 修复 ZIP e2db970c1678b5f120377ee83b3f026cc98dbfcee2416563bca07cc43d2d94b9；升级前 install/data 备份保留 |
| 正式 worker | 通过，session 13，parent=LocalSystem helper，持续运行 | 初始化/解锁后仍为同一 worker PID 7316 |
| 同账户访问边界 | 通过 | Hello 后 27 线程、264 项权限请求，262 项侵入性操作拒绝，仅 process query/wait 与 token query 通过 |
| 正式 setup-hello | 通过，exit 0，35.538 s | 恢复口令在本机输入；vault.enc 创建、master.key 不存在 |
| 正式 types 解锁 | 通过，exit 0，13.206 s | 实际 Hello + 服务 worker + vault AEAD 解锁，返回暂无凭证类型；不读取值 |
| 保护状态 | Windows Hello + OS 报告 TPM 证明成功 | windows_hello_tpm / os_reported / tpm_backed=true / device_binding=true / recovery_configured=true；不独立验证证书 |
| 远程身份 / Strong | 未测 | 尚未配对，PCP DK 两半 absent；本地 vault 不替代远程 Strong 决定 |
| 安装后取消 | 未测 | 原生完成回调取消对照已通过，正式包尚未做此负例 |
| Mac / Windows VM 四条 CI | 通过，Rust 1.99.0 | Mac 1357 passed / 0 failed / 10 ignored；Windows 1104 / 0 / 25；修复快照指纹 9979a2242f1ceebf05c43d731427338be7d1ff93e2ec80170186cc2925a56edd |

真机本身没有 Rust/MSVC，CI 在 Mac 和 Windows VM 执行。检查后共享工作树其他工作流继续改 CLI 配对参数/测试；这些变化没有包含在已测修复快照/安装包中。本轮启动和解锁证据对应上述精确包。首次读取因采集命令多加 --json 而在解锁后失败，已改用 types；原始错误保留，没有改产品验证。采集器曾共用结果文件名，前两项结果仅保留工具输出捕获 JSON 和原始 stdout，报告明确此限制。

完整变更、授权范围、backup/rollback、来源与清理见 [真机补充报告的恢复工作一节](remote-approval-reports/R2-B-physical-hello-2026-10-13.md)。本轮临时 setup/读取任务清理，正式服务、agent、新 vault 与全部备份保留。

## 2026-10-13–14 第三轮：T11 与 Windows 遗留项

Windows 未绑定 relay 保留已认证控制 worker。PermissionDenied 仅在 helper 对固定配置路径明确返回不存在时等待；存在但不可读、畸形配置、身份/协议失败保持拒绝。固定 relay SID 仅获实际 helper process/token 的查询权限；两者 DACL 必要修改，vault/目录/服务/protected worker 权限不放宽，原实际 PID/token/文件/publisher 校验保留。

| 项目 | 结果 | 证据 |
| --- | --- | --- |
| VM 有效测试签名包升级、未绑定 Auto/Running | 通过；5.0258 s，Application 1001 waiting_for_relay_binding | r3b-windows-vm-signed-upgrade-result.json |
| 无配置等待、存在但不可读非零退出 | 通过；7.1218218 s，vault DACL 保持 | r3b-windows-t11-negative-native.json |
| SYSTEM 双 PCP / 身份 ES256 / ECDH / HPKE / Quick | 通过；64-byte 身份签名、32-byte raw secret；Quick 软件 fixture 14.0729 ms；重开/清理通过，无软件回退 | r3b-windows-pcp-native-keys.json、pcp-system-result.json |
| metadata-only 权限 / 临时签名清理 | Authz 32 项；指定 SID 的 process/token query；测试后 VM Root 信任及非导出私钥删除 | r3b-windows-metadata-rights-test.log、certificate-cleanup.json |
| 真机已有 Hello vault 最终回调修复包升级 | 通过；15.1302 s；七个 EXE hash 匹配包；vault hash/目录 DACL 相同，master.key 不存在 | r3b-windows-physical-upgrade-callback-final.log、physical-post-closure.log |
| Hello 支持 / 创建 / T2 原生批准 / Strong | 通过；owner 非提升 session 13，IsSupported=true；第 6 轮创建 9.6695 s、批准 15.0833 s、签名 33.0293 s | r3b-windows-round6-owner-output-owner-{create,dialog,strong}-result.json |
| 真正重复 Hello 签名 | 第 5 轮通过；两次独立 RequestSign，15.5087 / 23.7601 s，经生产决定验签；第 6 轮为减少交互只重放已有签名 | r3b-windows-round5-owner-output-owner-{strong,repeat}-result.json |
| Windows Strong → 软件执行端加密/验签子项 | 通过；256-byte RS256、双向 HPKE、nonce 接受一次；replay/篡改/Quick-T2/错算法拒绝；接收验证 119.6296 ms | r3b-windows-round6-input-strong-verified.json |
| 独立 Hello 取消 / 删除 | 通过；Windows 原生按钮直接启动签名，UserCanceled(3)、2.2217 s、无签名；DeleteAsync 后 OpenAsync=NotFound；test 1/0 | r3b-windows-cancel-only-owner-sign-result.json、owner-cleanup-result.json、owner-owner.log |
| 单轮联合 fixture | 第 6 轮 exit 101/101 保留；取消首次返回 0，第二次 90.1104 s timeout/800705b4；不改写为该轮通过 | r3b-windows-round6-owner-output-owner-cancel-attempts.json、owner.log |
| 临时硬件密钥 / 任务清理 | PCP=0，第 4–6 轮 Hello alias 已 absent；独立取消 key 经 WinRT NotFound；测试任务=0；正式 agent/vault/所有备份保留 | r3b-windows-physical-round4-6-hello-artifact-cleanup.log、physical-post-closure.log |
| Mac / Windows VM 四项 CI | 全绿；Mac 1383/0/10，Windows 1126/0/26，各 69 组含 doctest | r3b-windows-{mac,windows}-ci-result.json |

VM T11 使用临时自签测试证书，保留精确 publisher 校验，测试后删除信任与私钥；不等于生产签名。真机最终为 unsigned development 包，relay Manual/Stopped，helper LocalSystem/Auto/Running；agent-only 开关不绕过 relay 校验。原 VM 仍未设置 PIN。

最终四项使用同一 610 文件快照，指纹 `fbf22e994313d82d246b96ccc8e480441f4c048b4ad715f8f8c5bd828f87bf0b`。Mac 为文件副本、target-r2b；Windows/MSVC 原生、独立 C:\kv-r2b-20261012\target。后续并行 owner/Touch ID 变动不归入该快照。中间手机测试跨秒 exp 与 CLI 异步计数 race 均保留原失败并只修测试；最终四项全量重跑。

最终开发 ZIP SHA256 `aaf1f851dcdd5d54bea8c7480049db71b6808b10e9e36a9b6977aa1ae163fbfc` 来自上述快照，VM/真机同 owner 更新。真机升级前新增一致备份 `C:\ProgramData\KeyValet-Backups\pre-r3b-callback-20261013T221017Z`；旧 5d02bf3b… 包、已初始化数据备份和所有原始目录保留可回滚。

等待实现记录有效 completion callback，先检查原 deadline，再 GetResults/固定公钥/RS256 验证；未知回调终态不释放完成信号，订阅失败与超时均拒绝，90 s cap/120 s 请求预算未延长。假 OS 红例证明旧策略忽略完成通知，但不能据此认定物理机 timeout 的唯一根因。独立取消使用临时诊断副本，只追加 ignored 测试和 cfg(test) 日志，生产等待/签名不改；说明窗口的准备时间不追加生产预算，不使用安装的 protected worker。

第 6 轮 Strong 请求至接收 223.6403 s 含人为门控/聊天等待；各签名秒数也含指纹操作，不是公网 p50/p95。当前可确认的是各硬件/加密/取消子项；联合 fixture 的历史失败完整保留。原始汇总和本轮 ZIP 均已取回，临时 key/task 清理完成。实际公网绑定/凭证 HTTP 执行、生产签名、Presence、ARM64、AI/WSL 仍未验收。

详见 [R3-B Windows 收尾报告](remote-approval-reports/R3-B-security-closure.md) 的回滚、文件行号、来源、完整收据和未决项；证据为 assets/r3b-windows-*。

## 2026-10-14：签名调查、公网预检与未签名 release 预览包

用户确认香港公司、已有 Azure、尚无 Windows 签名证书；调查后选择暂不购买签名服务，先评估未签名发布。本轮没有产生费用、提交组织验证、改变签名信任条件或上传公开 release。

| 项目 | 结果 / 数字 | 证据（remote-approval-reports/assets/） |
| --- | --- | --- |
| Windows/MSVC x64 release | 通过；295.3793 s、exit 0；原 610 文件已测快照，七个 EXE 摘要/大小一致、均 NotSigned | r3b-production-production-release-ready.json、production-release-verification.json |
| 未签名预览包 | 已准备；22,168,175 bytes；SHA256 3cd969a332bb6eb1678ac48fb0e4d300bb12075e104c4bc13b0e0651acf344aa；含预览说明与 unsigned marker | r3b-production-unsigned-preview-package.json |
| VM 同 owner 实际安装与状态 | 通过；七个安装摘要一致，--help/status --summary exit 0，未安装路径 status exit 3；helper LocalSystem/Auto/Running，relay Manual/Stopped；原 owner、data DACL、vault 状态保持 | 同上、r3b-production-unsigned-preview-install.log、unsigned-preview-status.log、unsigned-preview-portable-status.log |
| 真机 → 公网预检 | 默认 TLS 校验；health/providers 200，未认证 401、畸形 challenge/verify 400；七个条件通过；未注册设备或取得会话 | r3b-production-physical-public-relay-probe.json |
| metrics / 正式公网审批 | metrics 未通过，实际 401、要求 404；正式 Windows 公网审批未完成；未签名 relay 的 publisher 检查保留 | 同上 |
| 新 release 的 Hello / AI 客户端 | 未测；VM 仍无 PIN/vault；此前同源码开发包的真机 Hello 子项不改写为这次 release 的端到端验收 | r3b-production-unsigned-preview-package.json；上节真机记录 |

VM 的私有一致备份为 `C:\ProgramData\KeyValet-Backups\pre-unsigned-release-preview-20261013T231017Z`，历史备份全部保留。预览包只用于本地开发模式，要求显式 `-AllowUnsignedAgent`，Windows 远程配对/审批不可用。本次采集器曾误用未实现的 `--version`；保留原失败日志，最终使用实际支持的帮助与公开状态命令，没有放宽运行验证。浏览器下载/MOTW/SmartScreen 未测，ZIP 尚未上传 GitHub。详情见 [R3-B 报告 §8–9](remote-approval-reports/R3-B-security-closure.md)，新增证据为 assets/r3b-production-*。


## 2026-10-14：无需签名的代码收口

当前源码 Mac／Windows x64 的四条全工作区 CI 通过。LocalSystem PCP 双键、重开、部分创建失败清理、Quick／HPKE fixture 的三项原生测试通过；七个原生 EXE 的版本资源和签名输入已核对。T2 接收标签／全局拒绝、旧票失效处理和 ACK 前入站队列持久化已实现并回归通过。

VM 的安装／升级／重启／卸载等产品检查 11 项通过；首次临时测试 profile 未卸载，整轮保留失败，原始数据与服务已恢复，复验采用已有 defer 选项，VM 重启后仅清理本轮 profile；原数据与服务恢复。真机 AC=0、电量降至4%，当前包升级、protected MCP／Hello 和真实锁屏捕获暂未启动；原有 Hello 分项通过记录不改写为等待 PIN。

VM 非提升 owner 的 installed MCP Preflight／PreflightCrash 各5项通过：锁定状态、JSON-RPC、helper创建的worker和EOF／崩溃后回收；不含Hello解锁或实际导出文件。PS5.1／7 的合成导出值 fixture 均通过。验收包装脚本的 PackagePath／InstallSystem 误用已修正并后台复验，owner和DACL不变。

详见 [R3-B 无签名验收](remote-approval-reports/R3-B-unsigned-acceptance.md)。正式签名／公网绑定、真实 AI 客户端、WSL2／ARM64 桌面及完整恢复／轮换生命周期继续保持待验。

## 2026-10-14：恢复供电后的真实 TPM／MCP 续验

AC=1、电量21%后先一致备份到`C:\ProgramData\KeyValet-Backups\pre-r3b-unsigned-20261014T052910Z`，原安装／vault／owner／DACL及六个客户端配置副本保留；旧快照2包升级成功。真实LocalSystem双PCP、部分失败清理、身份签名／raw ECDH、Quick／HPKE三项通过，测试密钥已清理；不是正式设备登记。

非提升owner session13的安装MCP Success／Cancel／Crash通过8／7／7检查：真实Hello解锁、元数据查询、显式锁定，观察到Windows安全提示取消后的拒绝／locked，以及解锁后强制终止客户端的protected worker退出。16.9189／129.2902／29.5638s均含人工操作，取消项还含聊天回执等待；不作为纯密码学或公网延迟。首轮未见Hello提示不算取消；UTF8 BOM修复后Unicode工作目录核对通过。未读取实际凭证值或生成导出文件。

真实锁屏采集在第二次IsSupportedAsync访问违例，未通过。PDB定位及假SDK复现后，修复保留线程和服务进程MTA上下文；原生定向测试／Clippy通过，未知仍away。当前Mac空间不足15GiB暂停新构建，真机22端口可连但SSH无握手，修复部署／锁屏复验等待连接恢复。Cursor已安装但MCP失败；Claude下载收到地区不可用HTML；WSL两项组件Disabled、发行版0。

共享树随后改为Windows无签名发行，并加入WinUI／rejoin实现，正在重新冻结整合源码和跑原生全量；旧快照通过不等于新整包或公网通过。精确收据、失败保留、修复及未决项见[R3-B §8–9](remote-approval-reports/R3-B-unsigned-acceptance.md#8-供电恢复后的真机续验)，当前身份策略见[Windows支持](windows.md#windows-release-identity-policy)。
