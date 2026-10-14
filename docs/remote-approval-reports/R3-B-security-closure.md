# R3-B Windows 收尾：T11、原生回归与 Hello T2

日期：2026-10-13–14（北京时间；收据时间为 UTC）。范围：用户要求继续的第三轮 D/E/F Windows 项，以及续接的生产签名调查、公网预检与未签名预览包。S01/S02、metrics 整改和 T12 的接收侧收口未在本报告完成，不能据此标为已关闭。

## 1. 备份与回滚

最终回调修复包升级前，真机 `192.168.1.182`、owner `11516` 停止 helper 后再次一致备份至 `C:\ProgramData\KeyValet-Backups\pre-r3b-callback-20261013T221017Z`，复制 install/data 后恢复服务；[备份收据](assets/r3b-windows-physical-pre-callback-backup.log)。

此前已初始化 Hello vault 的备份仍保留在
`C:\ProgramData\KeyValet-Backups\pre-r3b-initialized-20261013T144240Z`。
备份包含 `install`、`data`；访问仅 SYSTEM/Administrators；复制后 helper 恢复 Running。
所有早期备份保留，包括 `pre-install-20261013T031715Z` 和 `pre-upgrade-20261013T0935Z`。
早期副本尚未初始化 vault，数据回滚必须选择本轮已初始化副本。

VM 原安装备份为 `C:\ProgramData\KeyValet-Backups\pre-r3b-upgrade-20261013T133410Z`。
本轮采用同 owner 升级；正式 vault、owner 与登录任务保留。

真机回退二进制可运行本轮备份中的原安装器，使用原始本地包，保持 owner 和 vault：

```powershell
$oldPackage = 'C:\Users\11516\KeyValet-Test-20261013\r3b\keyvalet-final.zip'
$oldInstaller = 'C:\Users\11516\KeyValet-Test-20261013\r3b\package-final\keyvalet-v0.3.0-windows-x64\scripts\install.ps1'
& powershell.exe -NoProfile -ExecutionPolicy Bypass -File $oldInstaller `
  -InstallSystem -PackagePath $oldPackage `
  -OwnerSid 'S-1-5-21-3389053113-2113560702-4064643913-1001' `
  -OwnerProfile 'C:\Users\11516' -AllowUnsignedAgent -SkipSetup
```

上述保留的旧包 SHA256 为 `5d02bf3b726a6396bdc474ca64f35cb5fed773b0ac8124df979ff9aa24145e63`，命令只回退安装产物。若需要恢复数据，先停 helper，另存当前数据，再从本轮 `data` 副本恢复并重新应用安装器的私有 ACL；不得用未初始化的早期副本覆盖新 vault。

## 2. T11 的实现与认证边界

新增内部 op `remote.relay.config_presence`，参数严格为 `{}`，只允许经过原有 OS 身份、安装路径和 publisher 验证的 RelayClient。helper 在远程身份尚未初始化时即可回答固定 `RELAY_CONFIG` 的对象是否存在；返回严格布尔 `{exists}`。不接受调用方指定路径，不读取配置内容，不返回账户或设备字段。CLI/MCP/hook/approval-agent 均不能调用。

Windows relay 元数据读取遇到 PermissionDenied 时，仅对固定安装路径使用这个证明：helper 明确返回 `exists: false` 才进入等待绑定。存在但不可读、其他 I/O 错误、畸形配置、helper 不可达、不可信或响应不合约均保持错误。自定义路径不得使用固定路径的不存在证明。控制 worker 在无绑定时继续运行。

另一个真实阻断是虚拟 relay 账户不能查询 SYSTEM helper 的实际 token，导致既有管道服务端身份核验失败。保留原 `GetNamedPipeServerProcessId → actual token SID → executable file identity/path → publisher` 验证，给固定 `NT SERVICE\KeyValetRelay` SID 增加两项查询权限：实际 helper process 的 `PROCESS_QUERY_LIMITED_INFORMATION=0x1000`、实际 primary token 的 `TOKEN_QUERY=0x8`。失败即拒绝启动；不授予调试特权、内存访问、线程控制、token duplicate/impersonate 或 WRITE_DAC/WRITE_OWNER。Authz 回归以合成 SID/descriptor 验证 32 项权限，不依赖安装、服务账户或管理员。

**ACL 例外须保留：** R3 提示词 D 写了“不改 ACL”。本轮必要修正改变上述两个运行中内核对象的 DACL；vault/目录/服务 DACL、默认 token DACL 与 protected worker 的权限没有放宽。此处不能概括成“所有 ACL 未变”。用户此前已授权必要跨归属修正；架构回写需明确这两个 metadata-only 授权。

安装器仅为 Authenticode 有效、publisher 精确为 Simvito Limited 的 relay 配置 Auto/Running，包括未配对状态。`-AllowUnsignedAgent` 仍只适用于本地 agent/helper 开发路径；未签名 relay 保持 Manual/Stopped。应用事件 1001 为 `waiting_for_relay_binding`，1002 为 binding ready；失败事件只记录固定类别，不记录配置、令牌或 OS 任意错误文本。

## 3. 原生结果

| 项目 | 结果 / 数字 | 证据 |
| --- | --- | --- |
| VM 同 owner 实际升级与未绑定启动 | 通过；5.0258 s；临时有效测试签名 relay Auto/Running，独立虚拟账户，Application 1001 | [升级收据](assets/r3b-windows-vm-signed-upgrade-result.json) |
| 配置缺失等待 / 存在但不可读失败 | 通过；7.1218218 s；真实不可读配置退出非零，vault DACL 未变 | [负例](assets/r3b-windows-t11-negative-native.json) |
| LocalSystem 双 PCP 与 Quick | 通过；身份 ES256 64 bytes，raw secret 32 bytes、双方相等；HPKE；Quick ES256 14.0729 ms；错误 DK 公钥拒绝 | [PCP](assets/r3b-windows-pcp-native-keys.json) |
| PCP 重开 / 第二把失败清理 / 删除 | 通过；三项原生 test exit 0；无软件回退；CLI 两半存在时均 present | [SYSTEM 结果](assets/r3b-windows-pcp-system-result.json) |
| 临时测试签名清理 | 通过；VM Root trust 与非导出私钥均已删除 | [签名边界](assets/r3b-windows-signed-relay-fixture.json)、[清理](assets/r3b-windows-certificate-cleanup.json) |
| 真机最终回调修复包升级 | 通过；15.1302 s；aaf1f851…；七个安装文件与包摘要一致，vault hash / 目录 DACL 相同，master.key 不存在 | [升级](assets/r3b-windows-physical-upgrade-callback-final.log)、[安装后核对](assets/r3b-windows-physical-post-closure.log) |
| Hello IsSupported / AK_s 创建 / T2 原生批准 | 通过；owner session 13、非提升 token；IsSupported=true；RSA-2048/RS256；第 6 轮创建 9.6695 s、原生批准 15.0833 s | [创建](assets/r3b-windows-round6-owner-output-owner-create-result.json)、[批准](assets/r3b-windows-round6-owner-output-owner-dialog-result.json) |
| Strong 签名 / 真正重复签名 | 通过；第 6 轮签名 33.0293 s；第 5 轮独立 RequestSign 的两次签名 15.5087 / 23.7601 s，均经生产决定验签 | [当前 Strong](assets/r3b-windows-round6-owner-output-owner-strong-result.json)、[重复](assets/r3b-windows-round5-owner-output-owner-repeat-result.json) |
| Hello T2 → 软件执行端 | 通过加密/验签子项；256-byte RS256、双向 HPKE、nonce 只接受 1 次，replay / 摘要篡改 / Quick-T2 / wrong-alg 均拒绝；接收验证 119.6296 ms | [SYSTEM 接收收据](assets/r3b-windows-round6-input-strong-verified.json) |
| Hello 签名取消 / 删除 | 独立原生验收通过；UserCanceled(3)，2.2217 s，无签名；DeleteAsync 后 OpenAsync=NotFound；test 1/0、exit 0 | [取消](assets/r3b-windows-cancel-only-owner-sign-result.json)、[删除](assets/r3b-windows-cancel-only-owner-cleanup-result.json)、[日志](assets/r3b-windows-cancel-only-owner-owner.log) |
| 单轮联合 fixture | 第 6 轮仍 exit 101/101；取消第 1 次返回 Success(0)，第 2 次 90.1104 s timeout/800705b4，没有 UserCanceled；不得把独立取消通过改写为该轮 test exit 0 | [两次取消结果](assets/r3b-windows-round6-owner-output-owner-cancel-attempts.json)、[原始测试](assets/r3b-windows-round6-owner-output-owner.log) |
| 临时 PCP / Hello / 任务清理 | 通过；PCP=0；第 4–6 轮 Hello alias 均已 absent，独立取消 key 经 WinRT NotFound；测试任务=0；正式 agent/vault/所有备份保留 | [CNG 库存](assets/r3b-windows-physical-round4-6-hello-artifact-cleanup.log)、[最终任务与 vault](assets/r3b-windows-physical-post-closure.log) |
| Mac / Windows 四条 CI | 通过；Mac 1383/0/10，Windows 1126/0/26，各 69 组含 doctest | [Mac](assets/r3b-windows-mac-ci-result.json)、[Windows](assets/r3b-windows-windows-ci-result.json) |

VM 正向 T11 使用仅用于 VM 的临时自签代码签名证书；保留精确 publisher 校验，结束后删除 Root 信任与私钥。它不是生产 Windows 发布签名，也没有部署到用户真机。此前 VM 已恢复 unsigned 开发包；本次最终包又同 owner 升级，6.2153 s；新增一致备份 `C:\ProgramData\KeyValet-Backups\pre-r3b-callback-20261013T221753Z`，helper Running、relay Manual/Stopped，原备份和 vault DACL 保留。原 VM 未设置 PIN，仍未初始化 vault。

真机使用最终 unsigned development 包，原有本地 vault 保护为 Windows Hello + OS 报告 TPM 证明成功，不独立验证证明证书。vault SHA256 一直为 `9f163953f99bf1f31aa49e7a9744cf9e20a3b16e14ea8f3e4dc2b13286eeab7c`。正式远程身份尚未登记，PCP DK 两半 absent；不把 fixture 的临时 present 说成正式绑定。

软件执行端如实标 `software_key`。第 6 轮 SYSTEM 先接收真正 Hello 签出的完整 T2 JCS 决定，验证按 DeviceRecord 的 RS256、封装返回 HPKE 并在软件端验签/消费 nonce，随后立即保存 `strong-verified.json`。fixture 仍要求最终取消回执，不接受超时或测试关闭，因此该轮最后 exit 101，早期 Strong 收据和失败收据均保留。第 6 轮 `native_repeat=false`：为减少重复指纹，只重放已有签名验证 nonce；真正重复 Hello 签名由第 5 轮独立收据证明。固定向量里的 approver 标签 `dev_mac` 是逻辑 fixture 名，实际签名者是 Windows owner。

第 6 轮创建、批准、Strong 各为 **9.6695 / 15.0833 / 33.0293 s**，均含用户操作。SYSTEM 请求发出至接收子项完成 **223.6403 s**，包含人为门控/聊天等待；接收验证 **119.6296 ms**。这些不是公网延迟、p50/p95 或真实凭证 HTTP 执行指标。

第 6 轮取消首次返回 0 时，用户报告没有看到新提示；不能据此断言是谁误批或系统没有显示窗口。第二次返回超时，没有 CredentialStatus。为去掉聊天启动签名的延迟，用同一已测生产等待/签名代码的诊断副本单独补验：owner 创建临时 key 后，在 Windows 原生说明窗口点“开始取消测试”，立即请求签名，用户点击新安全窗口取消。当前代码取得 **UserCanceled(3)，2.2217 s**，无签名；创建 **10.9843 s**，test 总计 **24.22 s**。删除后 WinRT OpenAsync=NotFound。诊断只增加 ignored 测试和 cfg(test) 状态日志，没有改等待策略、签名、90 s cap / 120 s 请求预算。说明窗口的 300 s 等待属于测试准备，不给生产签名追加预算。它不使用安装的 protected worker，不能代替生产 bound relay/真实客户端验收。见 [诊断来源](assets/r3b-windows-cancel-only-build-console.log)、[精确测试](assets/r3b-windows-cancel-only-diagnostic.rs)、[清理](assets/r3b-windows-cancel-only-cleanup.json)。

历史失败保留：第 1 轮在 Mac 操作、Windows 返回 Unavailable；第 2 轮错误 fixture scope 被严格 UI 拒绝后修正；第 3 轮 owner 本地两次签名通过，取消时进程退出 0xc000013a，未完成接收收据。第 4 轮创建/原生批准后 Strong 90 s timeout；第 5 轮真实重复签名成功，取消却返回签名成功，整轮拒绝。没有用管理员编写的 `cancelled:false` 失败清理文件伪造 Hello 成功。所有相关临时 key/task 已清理，[逐轮汇总](assets/r3b-windows-native-closure-summary.json) 保留分项和整轮的区别。

SSH 曾出现 banner 超时，电池耗尽两次；充电恢复后此前原始汇总 ZIP、第 4–6 轮和独立取消 ZIP 均取回且核对 SHA256，见 [传输收据](assets/r3b-windows-evidence-retrieval.json)。未删除备份或原始运行目录。临时父 PowerShell 用线程执行状态保持测试期间唤醒，结束恢复原状态；没有改永久电源策略或伪造 presence。

## 4. 修复、测试与改动文件

| 修复 | 回归 | 文件 / 起始行 |
| --- | --- | --- |
| T11 PermissionDenied 被当作不可恢复配置错误 | 修复前红例；缺失、有对象/目录、解析失败、身份/协议错误与非固定路径负例 | `kv-relay-client/src/config.rs:17`、`app.rs:47`、`tests/config_presence.rs:6`；`kv-helper/src/remote/relay_config.rs:6` |
| SYSTEM helper 元数据不可查询 | Windows Authz 32 项；实际虚拟 relay 账户与签名二进制回归 | `kv-platform/src/relay_peer_access.rs:91`、`lib.rs:39`；`kv-helper/src/daemon_win.rs:517` |
| bootstrap 内部 op 接线 | 严格空参数、角色白名单、strict bool、schema/vector 一致性 | `kv-ipc/src/remote.rs:124,285`；helper `server.rs:218`、`ipc.rs:117`、`mod.rs`；relay `helper.rs:183`、`tests/helper.rs:55` |
| 未绑定服务没有稳定状态日志 / 未签名启动条件 | 原生升级、等待与配置拒绝 | relay `windows.rs:25`、`helper/native.rs`；`kv-platform/src/peer_windows.rs:203` 仅固定错误类别；`scripts/install.ps1:266`、`test-windows-service.ps1` |
| Strong fixture 与明确取消门控 / 分项收据 | opt-in / ignored；owner Limited 与 SYSTEM 分离，固定公开输入目录、独立 owner 输出目录 | `kv-agent/src/hello/remote_key.rs:225,317,387,422`、`remote/pcp_acceptance.rs:215,381`；`scripts/test-windows-hello-fixture.ps1` |
| T2 fixture 请求范围不一致 | Mac / Windows 共用无硬件红 / 绿测试，固定 requested_scope=per_use；JSON helper 同时供 kv-touchid 使用，无新增依赖 | `kv-agent/src/remote/tests.rs:47,57`、`remote/pcp_acceptance.rs:227`；[红例](assets/r3b-windows-t2-fixture-before.log)、[绿例](assets/r3b-windows-t2-fixture-after.log) |
| 测试控制台退出时缺乏精确清理信息 | 第 4–6 轮隐藏测试控制台，创建后保存 alias/JWK，各阶段保存公开收据；独立库存核对 | `kv-agent/src/hello/remote_key.rs:317`、`scripts/test-windows-hello-fixture.ps1:93` |
| 完成回调已到达但 Status 仍 Started 时被忽略 | 先红例再修，验证有效终态 callback、过期 callback 拒绝、未知回调终态不释放完成信号；真机 Strong 和独立取消通过 | `kv-agent/src/hello.rs:38,70,97`、`hello/async_wait.rs:4,34,46`；[红例](assets/r3b-windows-callback-status-before.log)、[绿例](assets/r3b-windows-callback-status-after.log) |
| 全 workspace 暴露第二处异步执行计数 race | Windows 原始 runner=0 保留；等待真实 executor 返回 executed 后再断言一次，最终两端全量重跑 | `kv-cli/src/remote/live_helper_tests.rs:444,450`；[原失败](assets/r3b-windows-callback-first-failed-windows-ci-4.log) |
| CI watch 测试在异步执行前断言执行数 | Windows workspace 捕获 runner=0；改为等待真实 helper 完成并检查 result=executed，再断言执行一次；Mac/Windows 单例通过 | `kv-cli/src/remote/live_helper_tests.rs:583,599` |
| 并行 owner 测试对 Arc 直接赋值导致编译失败 | 使用该测试已有唯一 Arc 的 get_mut，验证缺 Strong key 仍拒绝 | `kv-helper/src/remote/tests/owner.rs:114`；纯测试构造器修正 |
| 手机配对测试跨秒延长确认 exp 导致 300 s 超时 | 先以 1.1 s 跨秒稳定复现，再取原 pair.expires_at；只修测试，10 s 有界等待；原生产过期校验保留 | `kv-mobile-core/src/tests.rs:678,688,705`；[红例](assets/r3b-windows-mobile-pairing-expiry-before.log)、[绿例](assets/r3b-windows-mobile-pairing-expiry-after.log)、[workspace 原失败](assets/r3b-windows-mac-05043-failed-ci-4.log) |

附带同步 `kv-core/schemas/remote/ipc_request.schema.json`、`testdata/remote/{generate.py,ipc_contracts.json}` 的 op/白名单；本轮没有修改加密向量或添加依赖。`scripts/test-windows-scripts.ps1` 检查新增脚本解析；`test-windows-remote-keys.ps1` 保留显式 SYSTEM opt-in 和默认 CI 无硬件操作。

本次回调修正用原子完成信号记录非空 sender 的有效 AsyncStatus 终态（Completed/Canceled/Error）；先核对原 deadline，再释放等待，之后仍调用 GetResults 并验证 CredentialStatus、固定公钥和 RS256。未知回调终态不释放完成信号；注册失败、状态查询失败和超时均拒绝；没有给过期回调重开预算。确定性假 OS 红例证明等待策略缺陷，但不足以证明第 4/6 轮物理机 timeout 的唯一根因。

验收 fixture 先保存 Strong 跨端收据，再等待取消；每次误返回 Success 的取消尝试都记录为失败且丢弃签名，最多三次，每次必须新人工 gate。所有其他错误仍拒绝。独立取消诊断位于临时文件副本，追加 ignored 测试和 cfg(test) 回调状态日志，生产等待/签名未改；诊断 source/binary SHA256 单独列，不归入 workspace 610 文件快照。

跨归属必要改动：上述 kv-ipc、helper daemon/server/ipc/mod、platform lib/metadata module、relay app/config/helper、CLI 两处执行计数 test、helper owner test、mobile 测试有效期构造均逐项列明。mobile 的新增 push 测试接线来自并行工作流，本轮只改上述跨秒确认测试。已有全量授权，未再次申请权限。既有 caller/签名/nonce/exp/档位验证没有跳过。

接线文件补全（Rust 路径均相对 `rust/crates/`）：`kv-core/schemas/remote/ipc_request.schema.json:32`、`kv-core/testdata/remote/generate.py:439,575`、`ipc_contracts.json:27,76,90`；`kv-helper/src/remote/{server.rs:218,ipc.rs:117,mod.rs:25,relay_config.rs:6}`、`kv-helper/src/daemon_win.rs:517`；`kv-platform/src/{lib.rs:39,relay_peer_access.rs:88,peer_windows.rs:203}`；`kv-relay-client/src/{app.rs:47,config.rs:18,helper.rs:184,helper/native.rs,windows.rs:25,tests/helper.rs:55,tests/config_presence.rs:6}`。脚本为 `scripts/{install.ps1:261,test-windows-service.ps1,test-windows-remote-keys.ps1,test-windows-scripts.ps1:5,test-windows-hello-fixture.ps1:93}`。文档为本报告、`docs/windows.md`、`docs/windows-native-acceptance-2026-10-12.zh-CN.md`。未改 `kv-platform/src/pipe.rs`、其 Cargo.toml 或服务器/目录/vault 访问策略。

## 5. 最终 CI 与产物

最终 610 文件冻结快照指纹为 `fbf22e994313d82d246b96ccc8e480441f4c048b4ad715f8f8c5bd828f87bf0b`，见 [manifest](assets/r3b-windows-source-closure-manifest.json)。Mac 在 `rust/target-r2b/r3b-windows-20261013/mac-frozen/rust` 完整执行，VM 对同一快照逐个核对 SHA256 后 MSVC 原生执行；目录为文件副本，没有 git 状态变更命令。其后并行工作流改动 helper 的 directives/engine/grants/production/revocations 及 owner 测试、kv-touchid remote_agent，这些后续变动不在本次已测/已安装快照。文档和证据在检查后更新。

Mac target 为 `/Users/guang/dev/keyvalet/rust/target-r2b`，Windows 为 `C:\kv-r2b-20261012\target`。Rust 1.99.0；`CARGO_INCREMENTAL`、`CARGO_PROFILE_DEV_DEBUG`、`CARGO_PROFILE_TEST_DEBUG` 为 0。真机无 Rust/MSVC，自动检查在 Windows VM 执行。

| 命令 | Mac exit / 秒 | Windows exit / 秒 |
| --- | --- | --- |
| cargo fmt --all -- --check | 0 / 1.0480 | 0 / 1.2174 |
| cargo clippy --workspace --all-targets -- -D warnings | 0 / 2.9961 | 0 / 1.7377 |
| cargo build --workspace --locked | 0 / 3.5450 | 0 / 7.2486 |
| cargo test --workspace --locked | 0 / 287.3064 | 0 / 289.3448 |

Mac **1383 passed / 0 failed / 10 ignored**，Windows **1126 / 0 / 26**，各 69 组含 doctest。Root/Hello opt-in 另行验收，不计为普通 CI 硬件通过。crypto/schema/vector/RFC 9180 通过；本轮只同步 IPC op/白名单向量。见 [Mac 计数](assets/r3b-windows-mac-test-counts.json)、[Windows 计数](assets/r3b-windows-windows-test-counts.json)，完整输出为 `r3b-windows-{mac,windows}-ci-{1,2,3,4}.log`。

中间失败保留：手机配对确认跨秒错误 exp 已用红例复现并只修测试构造；Windows 完整检查又暴露 desktop approval 测试异步计数 race，先保留原失败，再等待真实执行结果。每次必要修正后最终四项全量重跑，没有仅凭失败单例变绿宣布 workspace 成功。[原 Windows 失败](assets/r3b-windows-callback-first-failed-windows-ci-4.log) 及此前 `before-callback-*` 结果均保留。

最终 unsigned development ZIP SHA256 为 **`aaf1f851dcdd5d54bea8c7480049db71b6808b10e9e36a9b6977aa1ae163fbfc`**，来自上述 fbf22e99… 快照。真机已安装，七个 EXE hash 与包完全一致；VM 同 owner 更新并保留原备份。见 [包](assets/r3b-windows-package-result.json)、[真机升级](assets/r3b-windows-physical-upgrade-callback-final.log)、[安装核对](assets/r3b-windows-physical-post-closure.log)、[VM 最终升级](assets/r3b-windows-vm-callback-upgrade-console.log)。未绕过发布签名，也未发布生产包。

旧 5d02bf3b… 包与 11d76b93… source manifest 仍保留作回滚/历史依据；T11/PCP 的 VM 收据来自该源。本次相对它只有 Hello 等待的生产修正，其余为 fixture/测试/脚本变化；T11 相关生产源 hash 相同。第 5 轮真实重复签名来自 fc8203f9… 中间快照，第 6 轮 Strong 来自最终 fbf22e99… owner/system 二进制，独立取消来自基于该快照且仅追加测试/日志的诊断副本；[来源汇总](assets/r3b-windows-native-closure-summary.json) 不混用这些哈希。

独立取消诊断没有写入主代码或增加依赖：临时复制已核对的 610 文件，追加 [ignored 测试](assets/r3b-windows-cancel-only-diagnostic.rs) 和 cfg(test) 回调状态日志，用 `cargo test -p kv-agent --bin kv-agent --locked --no-run` 构建；[构建来源](assets/r3b-windows-cancel-only-build-console.log)、[副本构建脚本](assets/r3b-windows-build-cancel-only-diagnostic.ps1)、[受保护 launcher](assets/r3b-windows-launch-cancel-only-diagnostic.ps1) 保留。没有把这个诊断追加到 CI 计数。

证据严格转 UTF-8，无关 PowerShell module progress 前缀剔除；原始 ZIP/log 保留。静态配对 URI 占位符也遮盖，无实际恢复码、配对/会话 token、PIN、口令、凭证或私钥。表格/本地链接检查见 [文档检查](assets/r3b-windows-doc-validation.json)，全部 `r3b-windows-*` 摘要见 [证据索引](assets/r3b-windows-evidence-index.json)。

## 6. 给 R3-E 的回写文字

“Windows relay 在未绑定时保留经认证的控制 worker。受保护配置目录的 PermissionDenied 不能被当作不存在；仅固定路径的 helper `remote.relay.config_presence` 明确返回 false 才等待绑定。配置存在且不可读仍退出报错。helper 仅给固定 relay service SID 查询自己的实际 process 与 primary token 元数据，保留管道实际进程/token/安装文件/publisher 验证，并保持 vault 和 worker 访问边界。有效签名的未绑定 relay 为 Auto/Running；未签名开发 relay 为 Manual/Stopped，agent-only 开发开关不能绕过 relay publisher 校验。”

§16 的 Windows T11 行需区分临时签名 VM 原生通过与生产签名待办。Hello 行可回写：“物理机 PIN 已设置，原生 RSA-2048/RS256 创建、T2 原生批准、真正重复签名通过；Windows Strong 决定经双向 HPKE 返回软件执行端，验签与单 nonce 消费通过，replay/篡改/Quick-T2/错算法拒绝。独立取消返回 UserCanceled(3)，2.22 s，无签名，删除后 NotFound。各分项有独立收据；联合 fixture 第 6 轮取消 timeout 的 exit 101 不改写为通过。当前包为 unsigned development，真实绑定公网 relay/AI 客户端验收仍待办。原 VM 等待 PIN。”

§2.3 / 附录 C 加 fixed-path 只读 op 和 RelayClient 白名单。等待策略写有效 completion 通知 + 有界状态查询，再 GetResults/验签；未知回调终态不释放完成信号，注册错误和超时保持拒绝。产品仍为 Windows development preview。

## 7. 未决项

1. 当前生产代码独立取消已通过，第 6 轮联合 fixture 的取消 timeout 仍是保留的失败事实；未确认当时点击的时间/窗口与 WinRT 状态，不能断言唯一根因。后续联合测试应由原生桌面按钮启动取消，保持原预算；本次不要求用户再重复整轮指纹。
2. SSH 曾在 Hello/下载期间 banner 超时，电池耗尽两次；取证和清理均完成，仍需排查连接稳定性。没有把已清理 key/task 留作待办。
3. 生产 Windows 签名证书及正式包的 bound relay/配对/公网 Strong、实际凭证 HTTP 执行；开发 relay 保持 Manual/Stopped。
4. 真机 Presence/锁屏、ARM64 硬件、AI 客户端/WSL 原生会话未验收；原 VM 仍等待 PIN。没有报告单次测量为 p50/p95。
5. S01/S02、metrics、T12 仍需各自安全收口证据；本报告只给 Windows D/E/F 的分项状态。

## 8. 生产签名与公网验收启动（2026-10-14）

用户明确要求继续生产签名与公网验收。当前确认的阻断是生产签名身份尚未申请；用户确认公司在香港、已有 Azure 账号，但没有 Windows 代码签名证书。

| 项目 | 结果 | 证据 |
| --- | --- | --- |
| 两台 Windows 签名资源 | CurrentUser/My 与 LocalMachine/My 均无 code-signing certificate；未导出或读取私钥；现有 relay NotSigned / Stopped | [真机](assets/r3b-production-physical-signing-inventory.json)、[VM](assets/r3b-production-vm-signing-inventory.json) |
| Mac / GitHub 可用资源 | 现有 Simvito 身份为 Apple Developer ID；gh 未登录，不能读取 protected release 的 secret 配置；公开 Windows package run=0，v0.3.0 无 Windows asset | [公开发布记录](assets/r3b-production-github-signing-availability.json) |
| Windows → 公网 HTTPS | 默认 TLS 校验、不安装 custom CA、不关闭证书验证；health/provider 200 | [真机公网预检](assets/r3b-production-physical-public-relay-probe.json) |
| 未认证与畸形请求 | approvals/account session/pair start 无 session 返回 401；空 challenge/verify 返回 400；未注册设备、未改账户 | 同上 |
| metrics 既定验收条件 | **未通过**；公网 /metrics 当前 401，原 R3 目标为 404；未读取 counter，也未将拒绝访问改成通过 | 同上 |
| 线上构建与配置 | kv-server 仍为 R2-A 产物 1eced902…，systemd/nginx hash 与前次相同；服务 active；未改部署、Cloudflare 或读取 Origin CA 私钥 | [预检汇总](assets/r3b-production-production-signing-preflight.json) |
| 待签名 release 构建 / 文件核对 | 通过；Windows/MSVC x64，295.3793 s，exit 0；七个程序大小与 SHA256 匹配，均 NotSigned；未执行生产签名 | [构建收据](assets/r3b-production-production-release-ready.json)、[核对](assets/r3b-production-production-release-verification.json)、[构建日志](assets/r3b-production-production-release-prepare.log) |
| 生产签名 / 正式 Windows 公网审批 | 未完成；不能以现有 unsigned 开发包或本机测试证书替代生产签名 | 同上 |

香港不在 Azure Artifact Signing Public Trust 的当前公司资格列表中；Azure 订阅本身不改变申请资格。[微软资格说明](https://learn.microsoft.com/en-us/azure/artifact-signing/quickstart)。不改公司注册地，不用 Private Trust/test profile 冒称生产公开信任。

可申请路线为商业 CA 的 OV Code Signing，申请人保持 Simvito Limited / HK，最终必须通过 CA 组织身份审核。SSL.com 的申请 country-code 列表接受 HK，[国家代码说明](https://www.ssl.com/country-codes/)；这不是该公司的颁发保证。候选为 OV $129/year + eSigner Tier 1 年付 $180（240 signatures/year），按当前标价预算约 **USD 309/year，未含税**，[证书价格](https://www.ssl.com/products/software-integrity/signing-service/)、[云签名价格](https://www.ssl.com/guide/esigner-pricing-for-code-signing/)。尚未创建付费订单、购买订阅、提交公司证明或联系销售。

用户随后明确选择“先不弄签名，看看可以发布使用吗”，暂不承担这笔费用。本轮停止付费签名申请，改为准备本地 unsigned preview；不将暂不签名解释成授权放宽 relay 的 publisher 验证。

云 CNG adapter 可将证书接入 Windows My store 并供 Signtool 使用，符合现有 thumbprint 签名入口，[官方 adapter 说明](https://www.ssl.com/downloads/)。私钥留在签名服务的 HSM；账号/2FA 不写入仓库、命令参数或证据。现有 protected workflow 的 PFX import 不能据此称已接入云签名；后续 CI 集成需要单独接线与验证。

后续验收顺序：取得有效的真实公司代码签名身份 → 七个 release PE SHA256 + RFC3161 时间戳签名 → Windows 默认信任链/精确 publisher 验证 → 一致备份后同 owner 安装、不传 AllowUnsignedAgent → unsigned marker 清除、未绑定 relay Auto/Running → 真实 Pair/SAS 与 PCP dk_sig auth → 通过公网 relay 的实际 Windows Quick/Hello Strong → nonce/重放/拒绝/取消/撤销及清理收据。每个阶段独立记录，缺签名资源时不绕过 publisher 或服务账户身份。

构建启动时 Mac 可用空间低于规定 15 GB，因此没有启动本机构建或源码修复。Windows VM 复用原 target，使用 §5 的已测 610 文件快照（fbf22e994313d82d246b96ccc8e480441f4c048b4ad715f8f8c5bd828f87bf0b）完成 release 构建；核对后仍有 66 GB 以上空间。待签名原始程序保留在 `C:\kv-r3b-windows-20261013\production-signing-ready`，未改写。随后只在 VM 安装了 §9 的未签名预览包。取回 ZIP 前复查 Mac 已恢复 16 GiB 可用；只取回约 21 MiB 产物及证据，未进行新的 Cargo 构建，[本地 ZIP 核对](assets/r3b-production-local-archive-verification.json)。此段仅完成公网 TLS/基础拒绝的预检，正式业务链路未完成。

## 9. 未签名预览发布可行性（2026-10-14）

可以准备并分发明确标注的 Windows x64 **未签名开发预览包**，不购买代码签名服务。当前支持边界是安装后的本地功能；Windows 远程配对/审批不可用，relay 保持 Manual/Stopped。安装要求显式 `-AllowUnsignedAgent`；owner、安装路径、祖先 ACL、worker 权限与设备密钥验证保留，状态继续如实标 unsigned。它不具备公开信任的发布者证明；通过浏览器下载后的 SmartScreen/组织策略可能阻止运行，[微软发行签名说明](https://learn.microsoft.com/en-us/windows/apps/package-and-deploy/code-signing-options)。本轮没有测浏览器下载产生的 MOTW/SmartScreen 行为。

| 项目 | 结果 / 数字 | 证据 |
| --- | --- | --- |
| release 预览 ZIP | 已准备；22,168,175 bytes；SHA256 3cd969a332bb6eb1678ac48fb0e4d300bb12075e104c4bc13b0e0651acf344aa；含七个程序、安装/卸载脚本、unsigned marker 与 WINDOWS-PREVIEW.txt | [预览包收据](assets/r3b-production-unsigned-preview-package.json) |
| VM 同 owner 安装 | 通过；七个安装文件与 release 输入 SHA256 一致；owner/data DACL/vault 存在状态不变；helper LocalSystem/Auto/Running；安装耗时未采集 | [安装日志](assets/r3b-production-unsigned-preview-install.log)、同上 |
| 支持的 CLI 命令 / 安装路径门禁 | 安装后的 --help、status --summary exit 0；未安装路径执行 status 被拒绝，exit 3 | [帮助](assets/r3b-production-unsigned-preview-help.log)、[状态](assets/r3b-production-unsigned-preview-status.log)、[路径负例](assets/r3b-production-unsigned-preview-portable-status.log) |
| 未签名 relay 角色 | 按预期拒绝；虚拟账户仍 Manual/Stopped；未注册远程身份，status 显示远程不可用 | 收据及状态日志 |
| Mac 取回 / 真机下载目录 | 通过；ZIP 28 entries、七个程序 hash 与构建一致；真机 ZIP 摘要一致，原 vault 摘要未变；仅复制产物，未升级真机 | [本地 ZIP](assets/r3b-production-local-archive-verification.json)、[真机收据](assets/r3b-production-physical-preview-download.json) |
| Hello / 真实客户端范围 | 同源码开发构建的真机初始化/解锁及硬件子项见 §3；本次 VM 仍无 PIN/vault，未将这些记成新 release 的 Hello 或真实 AI 客户端验收 | §3、状态日志 |
| 公网发布 | 尚未上传 GitHub 或创建 release；gh 未登录；现有 v0.3.0 线上 Windows assets 仍为空 | §8 公开发布记录 |

预览打包使用独立的 `C:\kv-r3b-windows-20261013\unsigned-preview-20261014\repo` 上下文和已核对的 release 程序，没有覆盖历史 ZIP 或备份，没有改 main 的代码/依赖/CI 发布工作流。原包与额外带预览说明的 ZIP 均保留。每个原始收据/日志的字节摘要和 UTF-8 规范化说明见 [本轮汇总](assets/r3b-production-readiness-summary.json)。采集器起初误用了 CLI 未实现的 `--version`，分别被安装路径和设备保护门禁拒绝；改用实际支持的 `--help` / `status --summary`，保留 [初次打包采集日志](assets/r3b-production-unsigned-preview-package-console.log)、[初次安装采集日志](assets/r3b-production-unsigned-preview-install-console.log)，没有为此修改 CLI 验证。

预览 ZIP 与 checksum 已取回 Mac 的 `rust/target-r2b/windows-public-20261014/`，并复制到真机 `C:\Users\11516\Downloads\KeyValet-Preview-20261014`，此处不启动安装。第一次第三方 SCP 连接关闭，随后 stdin 流传输超时；只终止精确匹配本次传输编码参数的一个自有 PowerShell 进程，[清理收据](assets/r3b-production-physical-own-transfer-cleanup.json)，不触碰 agent/helper/sshd。最终用常规 SCP 完成，真机 SHA256 与 VM/Mac 一致。包内 [预览说明](assets/r3b-production-WINDOWS-PREVIEW.txt) 列出安装步骤与验收边界。Windows ZIP 内的反斜杠路径在本地检查时先统一为斜杠，再验证唯一性、根目录和摘要；没有跳过路径检查。

CLI 帮助中的静态省略号配对链接占位符在展示证据中替换为 `pair-link`，规范化收据注明这一处替换；没有生成或收集真实配对链接。密钥/令牌扫描继续拒绝配对 URI，未增加豁免规则。

VM 升级前停止服务并保留一致的私有副本：`C:\ProgramData\KeyValet-Backups\pre-unsigned-release-preview-20261013T231017Z`，含 `install`、`data` 与 `before.json`。此前的所有备份保留。只回退此次 VM 二进制的管理员 PowerShell 命令如下；保持现有 owner/data，relay 仍为 Manual/Stopped：

```powershell
$backup = 'C:\ProgramData\KeyValet-Backups\pre-unsigned-release-preview-20261013T231017Z'
Stop-ScheduledTask -TaskName KeyValetAgent
Stop-Service KeyValetHelper
Copy-Item -Path "$backup\install\bin\*.exe" -Destination 'C:\Program Files\KeyValet\bin' -Force
Start-Service KeyValetHelper
Start-ScheduledTask -TaskName KeyValetAgent
```

恢复数据前须另存当前数据，不能用未初始化 VM 的副本覆盖真机 vault。

不付费的生产签名候选另有 SignPath Foundation：服务免费，但要求项目审核、可验证构建、公开签名策略、MFA 等；Apache-2.0 本身不保证获批。其证书由基金会作为 publisher，不能直接代替当前固定的 Simvito Limited 信任身份，需要单独评审项目发布身份与进程认证的接线，不能泛化为接受任意有效签名。[官方条件](https://signpath.org/terms)。Microsoft Store 的 MSIX 可由 Store 免费签包，但当前产品是 SCM 服务 + ZIP/PowerShell 安装器，尚非 MSIX；现有 EXE 路径仍要求签名，不能直接宣称 Store 解决了当前约束。[微软说明](https://learn.microsoft.com/en-us/windows/apps/package-and-deploy/code-signing-options)。本轮未向任何机构提交申请或发送消息。
