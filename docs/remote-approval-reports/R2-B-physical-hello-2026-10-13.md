# R2-B 补充 — Windows 真机安装与 Hello 验收

2026-10-13。用户提供局域网 Windows 真机，并明确要求安装 KeyValet、测试 Windows Hello。实际安装、原生 RSA 创建/签名、重复签名、vault 重复派生通过；已有密钥的签名取消在完成回调对照版上通过，修复已回写源码。**安装后的本地 Hello 初始化和解锁已通过**：首轮 protected worker 以 0xc0000142 退出，恢复工作后已修复并升级。实际远程 Strong 决定尚未验收。未放宽生产权限，未启用文件钥匙回退，未新增依赖，未执行改变 git 状态的命令。

## 备份与回滚

- Windows 本机备份目录：`C:\ProgramData\KeyValet-Backups\pre-install-20261013T031715Z`。目录仅 SYSTEM / Administrators 可访问，备份保留。
- 安装前确认 `C:\Program Files\KeyValet`、`C:\ProgramData\KeyValet`、owner 的 `.keyvalet` 及安装器会管理的客户端配置文件均不存在。备份 `inventory.json` 记录各路径不存在，以及原用户 PATH；未读取或传输凭证值。
- 工具与原始日志目录：`C:\Users\11516\KeyValet-Test-20261013`。诊断源码另复制至上述受保护备份目录的 `startup-diagnostics`，SYSTEM 诊断只执行该副本。
- 回滚安装可在 owner 的提升 PowerShell 执行 `& 'C:\Users\11516\KeyValet-Test-20261013\package\keyvalet-v0.3.0-windows-x64\scripts\uninstall.ps1'`；默认保留 vault。此报告不授权删除未来存入的凭证库或备份。
- 原用户 PATH 为 `C:\Users\11516\AppData\Local\Microsoft\WindowsApps;`。若实际回滚，按 uninstaller 输出清理本轮新增的客户端配置与 PATH；原先不存在的配置仍须保留用户在安装后自行加入的内容。
- 电池中断后已恢复连接，原始日志与 JSON 已取回。两轮清理分别删除四个临时用户任务；2026-10-13T06:17:18Z 复查临时任务数为 0、临时诊断服务不存在。正式 `KeyValetAgent`、安装服务和全部备份保留，`master.key` / `vault.enc` 均不存在。见 [最终清理结果](assets/r2b-physical-hello-20261013-cleanup-after-resume-result.json)。

## 环境、产物与安装

| 项 | 事实 |
| --- | --- |
| 真机 | 用户提供的 LENOVO，model 21LD，Windows 11 家庭版中文版，x64，build 26200 |
| owner / 桌面 | `春有约花不误\11516`；session 13；Hello 探针与原生测试均为非提升 token |
| TPM | Present / Ready / Enabled / Activated 均 true；INTC，版本 700.19.5.2028；不据此推断本次 Hello 钥匙的 attestation |
| 包 | 0.3.0 unsigned development，来自 R2-B 已验收的 Windows/MSVC 构建 |
| ZIP SHA256 | `755ab56a79a4246ccd27ce541e9dc35a382a41573b195028d83e2acf04c145f0`；Mac 与 Windows 安装前分别核对 |
| 原生 agent 测试 EXE SHA256 | `297c1662b31fd696da5b970a9f4cc2f995f1a3c9a6d6258559a87221366eb4be`；2,947,584 bytes |
| 对应源码快照 | R2-B 的 649 文件快照，指纹 `df4d03aed184a45ba76b546049ab73fa04639f562287a155bb0155fae2d75aaf` |
| 源码核对 | Hello、remote agent、CLI、Windows helper、peer、process launcher 与 install.ps1 均与该快照一致 |
| 实际安装 | 03:19:21.780Z–03:19:54.305Z，32.525 s；从 owner 非提升桌面启动，用户完成 UAC；`-AllowUnsignedAgent -SkipSetup` |
| helper | LocalSystem / Auto / Running；最终清理后仍 Running |
| relay | `NT SERVICE\KeyValetRelay` / Manual / Stopped；尚未配对 |
| public status | 返回正常；provider=uninitialized；PCP 两半库存 absent；TPM 2.0 detected；remote_unavailable |

物理 Windows 本机没有 Rust / MSVC。安装复用上一轮已验收的冻结包；诊断 EXE 在 `ssh win11` 的 MSVC 环境原生编译后同步至真机。真机并未重跑全工作区四条 CI。开发包没有生产 Authenticode 签名。

临时原生测试先只加入静态阶段日志和两个 ignored 验收用例，随后对照注册 WinRT 完成回调；没有改变角色、公钥 pin、RSA 验签或操作预算。三个测试 EXE 的 SHA256 分别为：

- 仅阶段日志、连续签名：`0cd0b54b45d933e40a1569b7bf8b0b9c34360bcd4499e5148b9fecfcaf601012`。
- 分步创建与签名取消：`f76a68c3c269659f1eb1e8422448a4a2a14fd5dbb495d9a2bb9c089bf70b0770`。
- 完成回调对照：`187a6ba395a039cc840ed42789fc4f19b4738b57788d2d2bced9163f329fecd5`。

诊断源码/产物放在独立 `C:\kv-r2b-physical-20261013` 和 Mac `rust/target-r2b/physical-windows-20261013`。已安装的七个二进制保持原包版本；没有把临时测试程序作为审批进程安装。

## 首轮与完成回调对照验收结果

证据索引为 [状态与已捕获输出](assets/r2b-physical-hello-20261013-state.json)。[首轮文件清单](assets/r2b-physical-hello-20261013-evidence-manifest.json) 与 [恢复后文件清单](assets/r2b-physical-hello-20261013-resume-manifest.json) 记录 Windows 原文件 SHA256、编码及仓库证据 SHA256。文本转为 UTF-8/LF；首次 vault 采集中的 PowerShell 附加类型/Provider 元数据被移除，退出码和判定字段保持原值。原始文件仍保留在 Windows 和 Mac 忽略目录。

| 项 | 结果 | 数字 / 证据 |
| --- | --- | --- |
| owner 桌面 `IsSupportedAsync` | 通过：true | session 13，elevated=false，03:17:35Z |
| Hello AK_s 创建、RSA-2048 公钥校验、RS256 签名与验证 | 通过 | 首轮 `remote_hello_roundtrip`，exit 0；256-byte；107.592 s，含用户等待与指纹。[结果](assets/r2b-physical-hello-20261013-native-strong-result.json) |
| 固定 vault challenge 创建与重复派生 | 后续复验通过；首轮失败保留 | 原生 harness 为 1 passed / 0 failed，23.67 s；两个主密钥比较一致。[stdout](assets/r2b-physical-hello-20261013-diagnostic-vault.stdout.log)、[API 阶段](assets/r2b-physical-hello-20261013-diagnostic-vault.stderr.log) |
| 首轮 vault create 两次 timeout | 未通过，原因未完全确定 | 90.331 s / 90.240 s，均 exit 101、0x800705B4。后续成功不将这两次记录改成通过 |
| 创建时取消 | 通过：拒绝 | 用户确认取消；5.662 s；`remote_key.rs:186` 的 create 返回 OperationFailed，未到签名步骤 |
| 同一 AK_s 连续签名两个不同消息 | 通过 | 两次生产 RS256 校验、各 256-byte；28.278 s 总用时；RequestSign 等待 8.437 / 10.630 s；用户报告两次提示。[结果](assets/r2b-physical-hello-20261013-diagnostic-repeat-result.json) |
| 旧轮询等待：已有 AK_s 签名取消 | 未通过 | 用户确认取消后仍 Started，90.047 s 后 timeout 拒绝；外层判定为 false，不能依据 Rust harness 的一般错误断言判为取消通过。[结果](assets/r2b-physical-hello-20261013-diagnostic-cancel-result.json) |
| 完成回调对照：已有 AK_s 签名取消 | 通过：UserCanceled / 拒绝 | RequestSign 7.861 s，返回 KeyCredentialStatus(3)，用户确认取消；exit 0。104.083 s 总时间含创建、测试检查点等待。[结果](assets/r2b-physical-hello-20261013-diagnostic-callback-result.json) |
| 新增 AK_s 测试密钥删除 | 通过 | 连续签名与完成回调取消两例 DeleteAsync 完成后 OpenAsync 为 NotFound；没有枚举或删除用户其他 Hello 密钥 |
| 已安装 protected agent | 首轮未通过；恢复后启动复验通过 | 首轮三个 worker 退出 0xc0000142；新包正式 worker 运行且 253 项侵入性访问拒绝，见文末恢复结果 |
| 正式 setup-hello / vault 初始化 | 未测 | 安装使用 SkipSetup；没有要求用户输入恢复口令 |
| 实际远程 Strong 决定及执行端按 DeviceRecord 验签 | 未测 | 通过的是原生后端对测试消息的签名，尚未走安装后的审批 IPC / 公网链路 |

AK_s 原生测试调用生产 `create()` / `sign()`，内部使用生产 `hello_crypto` 校验 RSA-2048 和 PKCS#1 v1.5 / SHA-256；消息为测试 fixture，不是完整 ApprovalDecision。首轮既有测试仅在 guard 中调用 DeleteAsync，没有输出删除返回值，该轮删除仍未独立验证。新增测试明确要求删除完成且重新打开为 NotFound，不把这两种证据混为一谈。attestation API 的完成不代表已记录或独立验证其 attestation status。

首次恢复后的 vault 采集脚本使用 Start-Process / WaitForExit，丢失 ExitCode，故 JSON 中 exit_code=null、passed=false；[原生 stdout](assets/r2b-physical-hello-20261013-diagnostic-vault.stdout.log) 明确为 1 passed / 0 failed，两次签名均 Success。随后采集改用 `Start-Process -Wait` 和纯字符串读取，避免 PowerShell 元数据被序列化；没有修改第一份原始判定。

取消用例有意运行原本要求成功的 ignored 测试，Rust harness 的 exit 101 是预期负例；仅在日志为 OperationFailed、没有 timeout，且用户明确确认取消时，外层验收记录为拒绝通过。没有把该 harness 写成全绿。

## 发现的问题与变更请求

### P01：默认对象 DACL 导致应用在 DLL 初始化阶段退出

复现：正常 owner launcher 能完成服务握手，服务创建的 worker 随即以 `0xc0000142` 退出。Application / CodeIntegrity / Security-Mitigations 日志未提供对应 DLL 名称，故没有将问题归因于某个第三方 DLL。

进一步使用 SYSTEM 启动 Windows 自带 `cmd.exe /d /c exit 0`，复用生产 launcher 的 owner token、process/thread/token descriptor、TokenDefaultDacl 与 mitigation；控制实验不带 job-list attribute：

| 临时 cmd 控制 | exit |
| --- | --- |
| 生产默认 DACL：owner 仅 ReadControl + Synchronize，OWNER RIGHTS 仅 ReadControl | 0xc0000142 |
| 初始 thread 增加 QueryLimitedInformation | 0xc0000142 |
| 默认 thread 增加 QueryLimitedInformation；或与初始 thread 同时增加 | 0xc0000142 |
| 默认 mask 0x00120004 / 0x00120040 / 0x00120044 / 0x00120844 | 全部 0xc0000142 |
| 仅临时 cmd 的默认 DACL 改为 owner GenericAll | 0 |

这将失败条件缩小到通用于新建内核对象的默认 DACL，而非 Hello、Rust 或 job-list 的必要条件。[TOKEN_DEFAULT_DACL](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ntsetinformationtoken) 用于新对象的默认权限。具体失败的内核对象 / DLL 仍待定位。

**变更请求：W3 / `kv-platform/src/agent_process.rs`，尤其 worker_descriptors 与 launch_program。** 修复必须同时维持普通同用户进程无法读取/写入 worker 内存、操作 thread context、修改 token 默认 DACL 或新增 thread DACL 的边界。临时 cmd 的 GenericAll 对照只用于定位，未应用于 KeyValet；不得据此把生产权限放宽。可能需要调整保护实现，而不是把当前限制标为已通过。

充电后的重新观察仍记录两个 worker 退出 0xc0000142（PID 6520 / 16592），launcher exit 0。未改此归属外文件，也没有将 cmd 对照的 GenericAll 用于 KeyValet。

SYSTEM 诊断首次用临时 scheduled task，但该机任务一直 queued；已删除。随后从微软官方来源取得 [PsExec](https://learn.microsoft.com/en-us/sysinternals/downloads/psexec)，校验 Microsoft Corporation / Authenticode Valid 后执行受保护源码；两次返回 exit 0、临时诊断服务不存在。此工具未加入 KeyValet 包或依赖。

### P02：vault Hello create 阶段超时

两次原生 `hardware_roundtrip` 均在 `hello.rs:249` 的 `create(&Budget::new()).unwrap()` 返回 0x800705B4。此函数涵盖 RequestCreate、可选 attestation、公钥读取及第一次固定 challenge 签名；现有输出不足以进一步区分步骤，不能断言仅是用户未操作，也不能断言重复签名已经开始。

后续阶段日志记录 RequestCreate 完成 10.781 s、attestation API 完成 2.353 s、首次签名 0.108 s、第二次签名 10.194 s，原生比较通过。未改此流程的算法或参数，也没有证据将前两次 timeout 完全归因于某一步或用户操作。保留间歇性问题记录；日志没有输出 vault 主密钥或用于派生主密钥的签名值。

### P03：签名取消停留 Started；完成回调修复

先将创建与签名拆开，确认创建成功后才通过测试检查点发出签名取消请求。旧实现只轮询 IAsyncInfo.Status，取消后仍等待 90.047 s 并以 timeout 拒绝；注册完成回调的对照版返回 `KeyCredentialStatus::UserCanceled (3)`，耗时 7.861 s，并成功清理测试密钥。[微软状态定义](https://learn.microsoft.com/en-us/uwp/api/windows.security.credentials.keycredentialstatus?view=winrt-26100) 将 3 定义为用户取消；[RequestSignAsync](https://learn.microsoft.com/en-us/uwp/api/windows.security.credentials.keycredential.requestsignasync?view=winrt-26100) 返回异步操作结果。

源码修复：IAsyncOperation / IAsyncAction 在轮询前注册类型对应的 Completed handler；callback 本身不产生批准，只继续检查真实状态并读取 GetResults。注册失败时取消并拒绝。单步 90 s、请求总预算 120 s、attestation 10 s、清理 2 s 保持；订阅时间计入原 cap，RSA 验签、公钥 pin、角色及文件钥匙拒绝保持。

假 OS 复现不依赖真实 KeyValet、桌面或 Hello：生产等待策略由模拟“订阅前不发布终态”的异步生产者驱动。等价旧轮询在 [修复前日志](assets/r2b-physical-hello-20261013-completion-before-fix.log) 中因 Err(timeout) 失败；修复后的 [Windows 定向检查](assets/r2b-physical-hello-20261013-completion-after-fix.log) 通过。其余回归覆盖订阅拒绝、状态查询失败、取消失败时仍拒绝，以及订阅耗时不获得新 cap；同一套策略也在 Mac 普通测试执行。

最终源码经过等待策略提取后，尚未在用户睡觉后的真机再次弹窗；通过的是前述完成回调对照 EXE。也尚未覆盖安装的旧 agent 或解决 P01，所以不写成完整安装后的签名取消验收已通过。

### P04：当前 main 的 Windows Clippy 归属外阻断

全工作区 Windows 检查在 `kv-cli/src/remote/transport.rs:29` 失败：`unavailable_at` 在 Windows 非 test target 未使用，`-D warnings` 把 dead_code 作为错误。调用方为 Unix system runner，以及 `#[cfg(any(unix, test))]` 的 exchange_stream。

**变更请求：R2-A / R3-A、`rust/crates/kv-cli/src/remote/transport.rs:29`。** 在声明前加 `#[cfg(any(unix, test))]`，保持 Unix 生产调用及 Windows 测试调用；只加 cfg(unix) 会错误删掉 Windows 测试所需的函数。[精确的一行补丁](assets/r2b-physical-hello-20261013-cli-cfg-request.patch) 已准备。候选在独立 Windows 副本中让全工作区 Clippy 通过，测试结束立即还原副本；**main 未改此归属外文件**。[候选结果](assets/r2b-physical-hello-20261013-cli-cfg-candidate-result.json) 与 [Clippy 日志](assets/r2b-physical-hello-20261013-cli-cfg-candidate-clippy.log) 已保存。按原 R2-B 文件边界，停在该回写步骤，不用 allow(dead_code)、跳过 crate 或放宽检查替代。

## 改动与自动检查

| 文件 | 改动 |
| --- | --- |
| `rust/crates/kv-agent/src/hello.rs:19,51,58,80` | 接入等待策略与 WinRT operation/action 完成回调 |
| `rust/crates/kv-agent/src/hello/async_wait.rs` | 原等待轮询策略、订阅错误拒绝与五项可移植假 OS 回归 |
| `rust/crates/kv-agent/src/hello_logic.rs:11` | 仅 cfg(test) / 非 Windows 引入同一策略测试，普通 CI 不需要桌面 |
| `docs/windows.md` | 当前验证矩阵与真机局限 |
| `docs/windows-native-acceptance-2026-10-12.zh-CN.md` | 真机恢复后的结果追加 |
| 本报告与 `assets/r2b-physical-hello-20261013-*` | 原生 JSON、日志、源码、哈希与清理证据 |

没有修改 kv-core、kv-helper、kv-relay-client、kv-mobile-core 或 P01 的进程权限实现；本轮没有跨归属身份验签机械替换。原 R2-B 报告和 VM“等待 PIN”记录保持历史事实。

Mac 使用 `rust/target-r2b`，原默认 stable 为 1.90，全工作区检查显式使用已安装的 1.99.0；Windows/MSVC 使用独立 `C:\kv-r2b-hello-fix-20261013\target`，源码为 599 文件当前 main 快照，指纹 `f2ce1d3e44675ac57c870517407bcc636cb31986a14be131ecf2e98e125e5cc7`。快照后再次核对文件哈希无变动，源码清单见 [manifest](assets/r2b-physical-hello-20261013-hello-fix-source-manifest.json)。

| CI 命令 | Mac / Rust 1.99.0 | Windows / MSVC 1.99.0 |
| --- | --- | --- |
| cargo fmt --all -- --check | 通过 | 通过 |
| cargo clippy --workspace --all-targets -- -D warnings | 通过 | 未通过：P04；仅候选补丁对照通过 |
| cargo build --workspace --locked | 通过 | 通过 |
| cargo test --workspace --locked | 1357 passed / 0 failed / 10 ignored | 1102 passed / 0 failed / 25 ignored |

Mac 四条退出码均为 0，见 [Mac CI JSON](assets/r2b-physical-hello-20261013-mac-ci-result.json)。Windows 四条均执行，fmt/build/test 退出码为 0，Clippy 为 101，见 [Windows CI JSON](assets/r2b-physical-hello-20261013-windows-ci-result.json)；计数汇总各测试程序和 doctest，见 [两端汇总](assets/r2b-physical-hello-20261013-ci-summary.json)。Windows Hello 定向检查为 105 passed / 0 failed / 6 ignored（包含临时原生验收用例，普通执行保持 ignored）；P04 与 Hello 修复无关，但仍阻断“当前 main 两端四条全绿”的验收。

## 首轮结束时的未决项

1. P01 仍阻断完整应用。按原 R2-B 文件归属，需 W3 / 维护者修改 `kv-platform/src/agent_process.rs`；任何修复均须保留原进程、线程、token 与新线程的保护，再做真实桌面 WinRT 验收。
2. 用户已结束本次交互去睡觉，后续不再弹窗。最终源码/已安装包的 Hello setup、解锁、取消与真实 Strong 决定留待下一次 owner 桌面会话；不能用本轮 fixture 签名替代。
3. 首轮间歇性 vault create timeout 根因未完全证明；后续复验通过的事实单独保留。
4. 初轮既有测试的删除仅为 guard 调用，残留未独立核对；新增测试密钥的删除已有 NotFound 证据，不枚举或删除其他用户密钥。
5. P04 需对应文件 owner / 用户授权回写这一行 cfg；候选已验证且未留在 main。没有在报告中把候选 Clippy 通过写成当前 main 已通过。


## 用户恢复工作后的修复、升级与验收

用户于 2026-10-13 恢复工作，并明确授权“全部授权，以后不要再问了”。此授权覆盖本任务所需的归属外修正；P01 / P04 已回写，旧失败记录和候选副本结果保留。没有改 git 状态，没有新增依赖，没有放宽同账户进程、线程或令牌的访问边界。

### P01 修复与安全验证

`kv-platform/src/agent_process.rs:73` 增加由服务设置的每次启动随机 `KeyValetWorker` token security attribute。DACL 的条件 ACE 只向具有本次匹配 attribute 的执行上下文授予自访问；普通 owner 和其他 worker 保留元数据权限。设置 attribute 需要 SeTcbPrivilege；Win32 metadata 没有其完整 native ABI，使用现有 windows crate 的 SetTokenInformation 与 repr(C) 结构，没有新增 API 依赖。结构和权限约定核对 [Chromium 原始实现](https://chromium.googlesource.com/chromium/src/+/refs/tags/145.0.7632.1/base/win/access_token.cc)；条件 ACE 依据 [微软 SDDL 说明](https://learn.microsoft.com/en-us/windows/win32/secauthz/security-descriptor-definition-language-for-conditional-aces-)。

工作进程以 CREATE_SUSPENDED 创建。Windows 从默认 DACL 派生实际 child token 的对象权限，因此服务在第一条用户指令前设置该 token 的对象 owner=SYSTEM 与独立 DACL，再 ResumeThread。普通 owner 的 TOKEN_QUERY 保留；TOKEN_DUPLICATE、TOKEN_IMPERSONATE、TOKEN_ADJUST_DEFAULT、WRITE_DAC 与 WRITE_OWNER 均拒绝。只改 DACL 的中间对照仍让默认对象所有者获得隐式 WRITE_DAC，已在隔离测试发现并补齐 owner 设置；该中间版本没有安装。新线程的默认 ACL 继续含 OWNER RIGHTS，阻止普通 owner 的隐式 WRITE_DAC。创建前 mitigation、Job Object、owner SID、非提升 token、公钥 /角色 /预算 /helper peer 检查保持；设置或恢复失败即拒绝启动。

先写 CI 可执行的 Authz 假 OS 身份回归：“本 worker 能初始化自有对象，另一 worker 被拒绝”。[修复前失败](assets/r2b-physical-hello-20261013-resume3-worker-claim-before.log)，[修复后通过](assets/r2b-physical-hello-20261013-resume3-worker-claim-after.log)；增加真实普通 token 伪造 attribute 的负例，返回 ERROR_PRIVILEGE_NOT_HELD。原普通 owner 的 process/thread/token/default-thread AccessCheck 回归全部通过。测试不依赖安装、SYSTEM、GUI 或 Hello。定向 Windows 结果为 7 passed / 0 failed / 1 ignored；ignored 为既有 Job child fixture。

| 验证 | 结果 | 证据 |
| --- | --- | --- |
| 隔离 Windows cmd 初始化 | 通过，exit 0 | [48 项检查](assets/r2b-physical-hello-20261013-resume3-startup-access-final-result.json)；允许 process query/wait、token query，其余 46 项 ERROR_ACCESS_DENIED |
| 正式安装 worker | 启动通过 | kv-agent PID 7316，parent=LocalSystem helper PID 11836，session 13，--serve；18 s 观察无退出，随后仍 Running |
| 正式 worker 同账户访问边界 | 通过 | [真实访问检查](assets/r2b-physical-hello-20261013-resume3-installed-access-result.json)；26 个线程，255 项请求中仅 process query/wait 与 token query 成功，253 项侵入性操作拒绝 |
| 正式 setup-hello | 通过 | 35.538 s，exit 0；[捕获结果](assets/r2b-physical-hello-20261013-resume3-setup-captured-result.json)、[原生 stdout](assets/r2b-physical-hello-20261013-resume3-setup-current-visible.stdout.log)。恢复口令仅在本机 UI 输入 |
| 正式 Hello 解锁并读取类型 | 通过 | types，13.206 s，exit 0；[原生 stdout](assets/r2b-physical-hello-20261013-resume3-unlock-types.stdout.log)、[最终 harness 结果](assets/r2b-physical-hello-20261013-resume3-setup-current-result.json)；无凭证类型，未读取凭证值 |
| 创建时 attestation / 保护状态 | OS 报告成功 | [status](assets/r2b-physical-hello-20261013-resume3-status-after-setup.json)：provider=windows_hello、scheme=windows_hello_tpm、hardware=os_reported、tpm_backed=true；未独立验证证书；device_binding/recovery_configured=true，master.key 不存在 |
| Hello 操作后的进程访问边界 | 通过 | [操作后检查](assets/r2b-physical-hello-20261013-resume3-installed-access-after-setup.json)：27 线程、264 项请求，仅两项身份查询成功，262 项侵入性操作拒绝 |

首个采集器继承隐藏 console 输入，用户报告未见窗口；停止本轮 setup，确认 master.key/vault.enc 不存在，改为 Normal 窗口及空文件 stdin，触发系统恢复口令 UI；未改生产 CLI。第一次读取误用 list --json，Hello 解锁后将 --json 当作凭证类型而 exit 1；[错误保留](assets/r2b-physical-hello-20261013-resume3-unlock-current.stderr.log)，改为标准 types 后通过。采集脚本的三项操作沿用同一结果文件名，前两份 JSON 被随后运行覆盖；上表 setup JSON 明确标为当时远程工具输出的捕获记录，原始 stdout 保留，最终文件属于 types；没有伪称前两项原文件仍在。后续采集器须使用逐操作结果名。

上述检查只尝试打开所需权限的句柄，成功即关闭；没有读取内存、获取 thread context 或采集恢复口令值。临时 cmd 控制、两种 token owner 对照及正式进程检查均由经过 Microsoft / Authenticode Valid 核验的 PsExec 启动诊断上下文；临时 service 返回后不存在。

### 安装与备份

升级前增加备份 `C:\ProgramData\KeyValet-Backups\pre-upgrade-20261013T0935Z`，实际时间 09:27:52Z；保留先前所有备份。复制当前 install/data，记录 user .keyvalet 不存在；backup 为 SYSTEM / Administrators only。[清单](assets/r2b-physical-hello-20261013-resume3-pre-upgrade-backup.json)。需要回退二进制时，在 owner 的提升 PowerShell 用原冻结包的 install.ps1 加 `-PackagePath C:\Users\11516\KeyValet-Test-20261013\keyvalet-v0.3.0-windows-x64.zip -AllowUnsignedAgent -SkipSetup` 重新安装；它保留新 vault。预升级 data 副本仅供人工恢复，不得覆盖用户后来初始化或存入的新凭证。

修复包为原生 MSVC debug（CARGO_PROFILE_DEV_DEBUG=0）的 unsigned development 0.3.0，由现有 package-windows.ps1 生成；没有发布 release。ZIP SHA256 `e2db970c1678b5f120377ee83b3f026cc98dbfcee2416563bca07cc43d2d94b9`，38,308,449 bytes；[七个二进制哈希](assets/r2b-physical-hello-20261013-resume3-package-result.json)。Mac 中转及真机安装前核对 ZIP；installer SHA256 保持原值。包所需的 LICENSE / README / SECURITY / Windows 与 WSL 文档另列 [打包输入](assets/r2b-physical-hello-20261013-resume3-package-supplemental-source.json)，不改变 Rust 快照。

09:34:59Z–09:35:10Z 实际完成升级，10.660 s；从已授权 SSH 提升上下文调用 installer 的 InstallSystem，owner SID/profile 明确指定。helper Running/Auto/LocalSystem，relay Stopped/Manual/NT SERVICE\KeyValetRelay。重新启动正式 KeyValetAgent Limited/Interactive task，worker 启动通过。第一次 harness 调用因 PowerShell execution policy 拒绝，在任何安装变动前失败；随后以子 PowerShell 的 ExecutionPolicy Bypass 执行，没有修改系统全局执行策略。

### P04 与两端自动检查

`kv-cli/src/remote/transport.rs:29` 的已验证 cfg(any(unix,test)) 一行已获授权并回写。该文件原有其他工作流的改动保留；本轮只增加该 cfg。

| 命令 | Mac / Rust 1.99.0 | Windows VM / MSVC 1.99.0 |
| --- | --- | --- |
| cargo fmt --all -- --check | 通过 | 通过 |
| cargo clippy --workspace --all-targets -- -D warnings | 通过 | 通过 |
| cargo build --workspace --locked | 通过 | 通过 |
| cargo test --workspace --locked | 1357 passed / 0 failed / 10 ignored | 1104 passed / 0 failed / 25 ignored |

CI 日志中的两个静态配对 URI fixture 已脱敏；原日志留在忽略的 build 目录，manifest 同时记录原始与脱敏后的哈希。完整 [两端结果](assets/r2b-physical-hello-20261013-resume3-ci-summary.json) 与逐命令日志均保留。最终修复快照含 599 个源码/测试输入，指纹 `9979a2242f1ceebf05c43d731427338be7d1ff93e2ec80170186cc2925a56edd`，[manifest](assets/r2b-physical-hello-20261013-resume3-source-manifest.json) 说明计算格式。Mac target-r2b，Windows 独立 C:\kv-r2b-hello-fix-20261013\target。真机没有 Rust/MSVC，不把 VM CI 结果表述为真机执行。

四条完成后，共享工作树另一工作流继续修改 CLI remote/args.rs 和 remote/tests.rs；这些后续变动不在本次验收快照和已安装包中，本轮不覆盖它们，也不将上表写成这些后续变动已验证。原生运行与安全检查针对上述精确修复产物。

本次额外改动文件为 `kv-platform/src/agent_process.rs`（73: native attribute，141: 条件 DACL，406: 创建暂停/设置实际 token owner 与 DACL，670/690: 身份和伪造回归）及 `kv-cli/src/remote/transport.rs:29`。后续剩余：安装后 Hello 取消、真实 Strong 决定与跨执行端验签；原生取消对照和本地 vault 成功均不替代这些项目。当前 remote 未配对，PCP DK 两半 absent，不将 Hello vault 的 attestation 视为已创建远程 PCP 身份。


最终移除本轮 setup、visible setup、两个读取任务；正式 KeyValetAgent 与 LocalSystem helper 保留运行，新 vault、恢复配置及全部备份保留。证据见 [清理结果](assets/r2b-physical-hello-20261013-resume3-cleanup-result.json)。用户本轮不再需要重复操作；没有为了补采集器结果而重新初始化凭证库或重复创建永久 Hello 密钥。
