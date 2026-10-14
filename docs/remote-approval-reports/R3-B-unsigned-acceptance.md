# R3-B：无需生产签名的修复与 Windows 验收

日期：2026-10-14。直接修改 main 工作树，没有执行改变 git 状态的命令；本轮修复没有新增 Rust 依赖，也没有向真机加入测试签名根。§1–7 保留初次快照；续验与最新源码边界见 §8–10。共享树随后包含 WinUI 和 Windows 无签名发行策略的独立改动，不能用早期 CI 或旧包声称它们已实机通过。

## 1. 备份与构建范围

物理机覆盖升级前的新一致备份：`C:\ProgramData\KeyValet-Backups\pre-r3b-unsigned-20261014T052910Z`，完整 install/data，以及六个客户端配置文件的 runtime-configs 副本均保留。[备份](assets/r3b-unsigned-physical-pre-upgrade-backup.json)、[配置备份](assets/r3b-unsigned-physical-runtime-config-backup.json)。回滚时先停止正式 agent/helper/relay，另存当前 data；恢复该备份的 install/data 与原 DACL、owner.sid，再启动 helper/agent。此备份来自真机，不能换用未初始化 VM 的数据；恢复或删除硬件密钥不是文件回滚的一部分。

VM 原安装／数据已停服务一致备份到 `C:\ProgramData\KeyValet-Backups\pre-r3b-unsigned-20261014T015936Z`，见 [收据](assets/r3b-unsigned-vm-pre-service-backup.json)。原数据在安装回归后恢复；默认卸载保留 vault。现有备份不删除。原 VM 未初始化 Hello vault，不能代替物理机验收。

构建复用 Mac `rust/target-r2b` 与 Windows `C:\kv-r2b-20261012\target`；`CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0`，Rust 1.99.0。冻结源码及文件 SHA256 见 [快照 2](assets/r3b-unsigned-source-manifest-2.json)。第一次快照漏了 CLI 编译时包含的 deploy 模板，原生构建拒绝，补齐后重测。

Mac 旧快照的 Cargo fingerprints 曾错误复用缺少取消错误类型的编译产物；保存原 fingerprints 并强制当前源码编译，没有删除源码或备份。空间接近门槛时，将本工作流开始前的 106 个旧测试可执行文件共 1,834,761,032 bytes 保存到 VM，逐文件核对 SHA256 后释放本机副本。VM archive／解包文件均保留；日志、JSON、密钥目录和数据备份不动。[迁移与恢复位置](assets/r3b-unsigned-cache-relocation.json)

缓存恢复：从 VM 取回 `C:\kv-r3b-unsigned-20261014\preserved-old-mac-test-binaries.tar.gz`，解包到 Mac `rust/target-r2b/debug/deps`；先核对收据的 archive SHA256。旧指纹保存在 `rust/target-r2b/unsigned-preserved-fingerprints`，不用它替代当前源码验证。

## 2. 安全修复

### S01／S02：T2 接收验证与旧票

`verify_grant` 对有限／常设 T2 都要求 Strong、settings 来源、confirm 精确等于当前执行端标签；`aud=*` 或 `scope.level=global` 的 T2 拒绝。T1 全局票与旧 DeviceRecord 身份签名兼容不变。

先新增两个复现测试，旧接收器都返回 `Ok(())`，见 [修复前](assets/r3b-unsigned-t2-reproduction.log)。新增 missing/null/empty/wrong-label 与有限／常设 wildcard/global 负向向量；原 finite 正例加入签名标签，schema 同步。独立生成器只改 Grant 相关 schema／样例／验证向量，其他向量保持逐字节一致。[生成核对](assets/r3b-unsigned-vector-regeneration.json)

新增八个 Grant 向量：`finite_t2_missing_confirm`、`finite_t2_null_confirm`、`finite_t2_empty_confirm`、`finite_t2_wrong_confirm`、`finite_t2_global_star`、`finite_t2_credential_star`、`standing_t2_global_star`、`standing_t2_credential_star`。`finite_t2_settings` 正例补入签名标签；既有 `standing_t2_confirm` 与 `global_star`（T1）继续通过。签后篡改 confirm 的回归要求 InvalidSignature。

helper 安装／使用前重验沿用统一规则。启动升级把缺当前标签或全局 T2 的旧票标 revoked，写 revoked_jti 防止重装，并通过既有事务和 vault 审计检查点记录 `grant_invalidated`；有效 T1／T2 保留。不能用 UI 限制或旧向量宣布接收验证完成。

### 审批端重启后的入站请求

新增 `inbound_approvals`，保存原签名信封、已解封 ApprovalRequest、接收时间、升级提示、状态及审计 receipt_seq。签名／HPKE／发送方角色验证通过后，记录与 vault 检查点提交成功才允许 relay ACK；数据库／审计失败不 ACK、不更新内存待批表。

启动先验证审计链、vault 检查点／记录和设备目录，再核对最新入站收据哈希、信封身份签名、当前未吊销执行端、账号／接收端／ID／有效期。恢复不重新调用硬件 ECDH。取消、过期、已签发状态持久化；决定与 outbox／ledger 在同一事务提交，重启不重复签发。旧 waiting 行的回放与篡改拒绝；升级提示与原请求分开保存。authenticated presence 从 away 变 present 时重新呈现队列，最多五个原生窗口。

此项使用现有 vault AEAD 检查点，没有新增硬件反回滚承诺；不承诺外部 HTTP exactly-once。旧版本已 ACK 且完全丢失的请求无法凭空恢复。

回归先证明 ACK 后重启丢请求：[修复前](assets/r3b-unsigned-inbound-before-current.log)。随后覆盖恢复、取消／重投递、已签发 outbox、到期边界／吊销、篡改／旧快照、存储／审计失败不 ACK、升级提示及旧 T2 迁移，见 [相关 crate 全量测试](assets/r3b-unsigned-packages-tests-final.log)。一个旧测试直接改内存表，已改用真实签名信封接收；拒绝断言未放宽。

### T12：audit 页上限

`remote <device> audit` parser/help 收紧为 1..200，与 QueryAudit/helper 一致。复现验证 201／1000 原先被 parser 接受：[修复前](assets/r3b-unsigned-audit-limit-before.log)。接收上限没有提高。

## 3. 已完成的自动与原生验收

| 项目 | 结果 | 证据 |
| --- | --- | --- |
| Mac 全工作区 fmt/clippy/build/test | 通过；1416 passed / 0 failed / 10 ignored、69组，四项 exit 0 | [CI](assets/r3b-unsigned-mac-ci.json) |
| Windows x64 MSVC 全工作区四项 | 通过；1150 passed / 0 failed / 28 ignored、69组，四项 exit 0 | [CI](assets/r3b-unsigned-native-ci-result.json) |
| LocalSystem PCP 双键／失败清理／Quick HPKE fixture | 通过；三项原生测试 | [SYSTEM](assets/r3b-unsigned-vm-pcp.json) |
| 七个 Windows 程序与 PE 资源 | 通过；产品名 KeyValet、版本 0.3.0、固定原文件名 | [元数据](assets/r3b-unsigned-vm-pe-metadata.json) |
| PS 5.1 离线配置／脚本解析、签名输入 | 通过；七个固定未签名 EXE | [准备](assets/r3b-unsigned-vm-preparation.json) |
| VM 安装／升级／卸载 | 通过；11项、同owner升级／跨账户拒绝／默认保留vault；复验采用已有defer选项，重启后仅清理本轮1018／1019 profile。首次失败保留 | [复验](assets/r3b-unsigned-vm-final-service-regression.json)、[清理](assets/r3b-unsigned-vm-deferred-profile-cleanup-final.json) |
| Installed MCP 无 PIN 启动／EOF／Crash | 通过（VM 非提升 owner）；各5项，EOF整轮0.5444s／Crash整轮0.5077s，均观察到helper创建的worker并确认退出；不含解锁／文件导出 | [EOF](assets/r3b-unsigned-vm-mcp-eof.json)、[Crash](assets/r3b-unsigned-vm-mcp-crash.json) |
| 实际 PowerShell 执行导出格式 fixture | 通过；PS5.1 0.2363s、PS7 0.4469s，合成值的Unicode／引号／注入拒绝；不读取实际凭证 | [结果](assets/r3b-unsigned-vm-powershell-exports.json) |

## 4. 桌面、客户端与签名准备

`scripts/test-windows-desktop.ps1` 使用安装的 MCP launcher／service worker，在非提升 owner 桌面测试 initialize/tools、只读锁定状态、Hello 解锁或取消、元数据查询、显式锁定与 EOF/crash。Preflight／PreflightCrash 不发出 Hello，VM 的锁定状态和真实 protected worker 回收已通过；Success／Cancel／Crash 的解锁后生命周期仍需物理机。只记录固定断言和计时，不保存 MCP tool body、session ID、stderr 或凭证值。新 native presence ignored 测试采样真实 WTS／输入／显示／Hello 信号，要求 present→锁屏 away→解锁 present，CI 不调用它。

物理机的现有 Hello 初始化／解锁、Strong／重复签名／独立取消通过记录仍有效；没有把它们重复列为等待 PIN。当前新包的 protected MCP、在场与升级验收尚未启动：系统电量由 15% 降到 4%，此前 `GetSystemPowerStatus` 返回 AC=0，续连 SSH 不可达；维护者虽报告已接电源，仍待系统供电确认后升级。未修改电源策略或自动批准任何安全窗口。[状态](assets/r3b-unsigned-physical-ac-power.json)、[安装版本](assets/r3b-unsigned-physical-before-desktop.json)、[最新电量](assets/r3b-unsigned-physical-current-power.json)、[续连结果](assets/r3b-unsigned-physical-connectivity-final.json)

物理机未找到 Claude Code／Codex／Cursor；WSL exe 存在，不能据此宣布已安装发行版或 WSL2 桌面通过。[客户端资源](assets/r3b-unsigned-physical-power-clients.json)

Foundation 申请等待审核。新 workflow／prepare 脚本／固定 XML 输入已准备并原生核对；没有提交签名请求或改变 `Simvito Limited` 信任判断。[接线步骤](../windows-signpath-setup.zh-CN.md)

## 5. 未完成项

1. 初次包的物理升级、protected MCP Success／Cancel／Crash 与三项 PCP 已完成，见 §8。锁屏采集崩溃已修复并在原生定向测试通过，等待恢复 SSH 后部署／复验；新源码 Mac CI 等待空间。
2. 真实 AI 客户端及 WSL2；客户端安装／可用账号和发行版需要实际资源，协议 fixture 不代替它们。
3. 真机 ARM64、恢复／rebind／轮换完整生命周期与真实 gateway／导出文件后的清理；不能用未创建文件的 EOF 测试宣称导出清理通过。
4. Windows 注册／配对、公网真实请求、吊销／审计和 SmartScreen。当前共享树的无签名发行策略取消了证书前提，仍需新整包的真实验收；可选签名按当前 Windows 文档处理，旧包的 Manual/Stopped 记录保留。
5. S03 metrics 边界仍开放；本轮没有改变公网 nginx／Cloudflare 配置。

## 6. 改动范围与文档回写

核心改动位于 core 的 validation/tests/Grant schema/向量、helper 的 inbound/store schema/engine/ipc/owner/grants、CLI args/tests；七个原生包共用 Windows SDK version resource，沿用原 manifest。增加签名输入 workflow/XML/脚本和 desktop／presence 验收入口。最终核对见下表；1136 个 Rust 范围文件与已测 Windows 快照逐字节一致，见 [再次核对](assets/r3b-unsigned-current-rust-source-verification.json)。后续只修改文档／验收脚本；这些脚本已在原生 PS5.1运行，不沿用 CI 宣称 Hello 分项通过。

架构回写：K4 接收规则与迁移已经实现；入站审批 ACK 前持久化并以 vault 收据恢复；T11 无绑定控制 worker 已有临时可信 VM 签名通过记录，unsigned 仍停止；Hello 真机分项已有通过记录，生产公网闭环继续待验。R2/R3 原报告的历史失败保留。


| 文件／入口 | 修改 |
| --- | --- |
| `rust/crates/kv-core/src/remote/validation.rs:152` | 所有 T2 精确标签及 wildcard/global 拒绝 |
| `rust/crates/kv-core/tests/remote.rs:482,528`；schemas 的 grant／unsigned_grant／grant_list_result／grant_issue_result；testdata generate.py、grant_validation_cases.json、schema_samples.json | 修前复现、边界／篡改／有限与常设负例；其他向量不改 |
| `rust/crates/kv-helper/src/remote/inbound.rs:39,133`、schema.sql:63 | 持久入站与 vault 收据绑定，启动身份／权限核对 |
| `rust/crates/kv-helper/src/remote/engine.rs:313,1141`、ipc.rs:815、owner.rs:38、directives.rs:362 | ACK 前提交、恢复、取消／签发／过期、升级／唤醒／五窗口上限 |
| `rust/crates/kv-helper/src/remote/grants.rs:29` | 旧 K4 不兼容 T2 启动失效并禁止重装 |
| `rust/crates/kv-helper/src/remote/tests/inbound_recovery.rs:54`、transport_edges.rs；tests.rs:23／mod.rs:11 模块注册 | 持久化／回放／故障／迁移回归，旧人工内存 fixture 改走签名信封 |
| `rust/crates/kv-cli/src/remote/args.rs:782`、tests.rs:1092 | audit 1..200 和修前／边界回归 |
| `rust/windows-build.rs:1`、windows-version.rs:2；kv-helper／kv-hook／kv-server／kv-relay-client 的 build.rs:1 | 版本资源；原 agent/cli/mcp build.rs 保持原 include 与 manifest |
| `.github/signpath/windows-artifact.xml`、windows-signing-input workflow、prepare-windows-signing.ps1 | 七个固定可验证未签名输入，生产提交未启用 |
| `scripts/test-windows-desktop.ps1:1`、kv-agent/src/presence/windows.rs:50 | VM installed MCP Preflight／PreflightCrash 通过；Hello／WTS 真机入口待验 |

VM 回滚安装文件：停止 KeyValetAgent 和 KeyValetHelper，将 §1 backup/install/bin 中的 EXE 复制回受保护安装目录，重启 helper／agent；relay保持 unsigned Manual/Stopped。恢复数据前另存当前数据，再使用备份 data 及原 DACL，不能用未初始化 VM 数据覆盖物理机。验收包装脚本最初误用不存在的 ChecksumPath 参数；改为 PackagePath 后又遗漏 InstallSystem，后台任务错误进入 RunAs 交互入口。两次原数据均已放回，但自动重装未完成，已先用正确系统阶段命令恢复服务。随后修正包装脚本，以 S4U/Highest 后台任务单独复验同一恢复函数：exit 0、owner／DACL不变、helper Running／relay Stopped、自动恢复收据存在。见 [复验](assets/r3b-unsigned-vm-restore-verify.json)、[自动恢复](assets/r3b-unsigned-vm-automatic-restoration-final.json)及[最终清理](assets/r3b-unsigned-vm-final-cleanup.json)。首次 profile 失败和两处验收脚本错误保留。

文档更新了架构的 K4／T11／Hello 当前事实、入站持久化边界与 audit 上限，OPEN-QUESTIONS 的 S01/S02/T12 处置及仍开放资源，Windows 验证矩阵与 review 补充。66 个表格管道数一致，章节引用通过；总架构的三个外部引用另行验证。见 [文档检查](assets/r3b-unsigned-doc-check.json)。


## 7. 回写事实抽查

| 当前文档中的事实 | 对应证据 |
| --- | --- |
| 有限 T2 缺标签拒绝 | §2 修前红例、core两个回归及 grant_validation_cases |
| wildcard／global T2 拒绝 | §2 S02、有限／常设四个新增负向向量 |
| 旧不兼容 T2 失效并禁止重新安装 | §2 helper migration 回归，CI内 `r3b_legacy_t2_migration_retires_old_tickets_and_preserves_valid_authority` |
| 入站存储失败不 ACK | §2 CI内 `r3b_inbound_storage_or_audit_failure_never_acknowledges_the_request` |
| ACK 后重启恢复尚未决定的请求 | §2 CI内 `r3b_received_approval_survives_reopen_without_relay_redelivery` |
| 取消／签发不恢复 waiting | §2 CI内 cancelled／issued 两个恢复回归 |
| Mac／Windows 当前快照四项检查通过 | §3 两份CI JSON；§6 1136文件逐字节核对 |
| 原生 PCP 部分创建失败清理且无软件回退 | §3 SYSTEM PCP JSON第二项 |
| installed MCP EOF／Crash 后 protected worker退出 | §3 两份owner收据，各5项，明确hello_tested=false |
| 原安装／数据恢复、临时测试资源清理 | §1 backup、§6自动恢复复验与最终清理收据 |

抽查限于本轮有证据的行为；真实 AI 客户端、解锁后导出清理、物理睡眠／重启与正式签名公网不在“已通过”范围。

## 8. 供电恢复后的真机续验

系统重新确认 AC=1、电量21%，owner桌面session13；按 §1 先备份，再安装原生快照2的七个未签名程序。包 SHA256=`e2aab64b16b3ce1407e0e1c3c2fcec319168fbc080bcd9d4e9f8e6eac41336f0`，38,394,406 bytes。owner、vault hash与目录DACL不变；helper Running，旧策略relay Manual/Stopped。[升级收据](assets/r3b-unsigned-physical-upgrade-result.json)

| 真机项目 | 实际结果 | 数字／证据 |
| --- | --- | --- |
| LocalSystem 双PCP、重开、身份签名与ECDH | 通过，真实TPM，无软件回退 | 三项原生exit0；ES25664B、raw secret32B；[SYSTEM](assets/r3b-unsigned-physical-pcp.json) |
| PCP Quick与软件执行端HPKE | 通过，测试密钥已清理 | Quick132.1143ms；HPKE往返与双方raw一致；[原生收据](assets/r3b-unsigned-physical-pcp-native-keys.json)。这是临时fixture，不是正式登记身份 |
| installed MCP解锁、元数据、显式锁定与EOF | 通过，真实Hello，不读取凭证值 | 8检查，16.9188753s；[结果](assets/r3b-unsigned-physical-success.json) |
| installed MCP取消 | 通过拒绝／锁定／进程退出子项 | 操作者确认取消Windows安全窗口；7检查，5个有效MCP帧；[结果](assets/r3b-unsigned-physical-cancel-gated.json)。129.2901939s含聊天回执等待，不是Hello取消延迟，也不据此断言WinRT具体status |
| 解锁后客户端崩溃清理 | 通过 | 7检查，29.5637907s含人工操作，受保护worker退出；[结果](assets/r3b-unsigned-physical-crash.json) |
| Unicode项目目录与PS5.1 | 通过 | 验收脚本保存UTF8 BOM后，工作目录精确为project-工作目录；[重测](assets/r3b-unsigned-physical-utf8-preflight-result.json) |
| 锁屏／解锁在场 | 未通过，原生崩溃正在复验 | 首个样本保守away，随后0xc0000005；[样本](assets/r3b-unsigned-physical-presence-first.json)、[故障元数据](assets/r3b-unsigned-physical-presence-fault-metadata.json) |
| 真实客户端 | 部分完成，尚无模型工具调用通过 | Cursor2026.10.14-0f9edde已安装，version/help通过，list-tools返回MCP error；[探测](assets/r3b-unsigned-physical-client-probe2-result.json)。Claude安装URL返回地区不可用HTML；[诊断](assets/r3b-unsigned-physical-client-region-diagnostic.json)。Codex直接下载失败，未登录、未读取账号凭证 |
| WSL2 | 未测，组件与发行版尚未安装 | 两项可选功能Disabled、hypervisor=false、发行版0，固件虚拟化true；[前置状态](assets/r3b-unsigned-physical-wsl-prerequisites.json) |

首轮取消虽API拒绝且vault锁定，但操作者没有看见Hello；不算观察到取消。[原始输出](assets/r3b-unsigned-physical-cancel-first-raw.json)、[判定](assets/r3b-unsigned-physical-cancel-first-adjudication.json)。原因排查确认用途说明先于Hello、用途窗口预算30s；补明确说明及人工开始门控，没有扩大生产预算。取消验收现在同时要求isError、locked和严格bool人工回执；缺回执、未见提示、成功认证、unlocked均拒绝，原生PS5.1/7离线回归通过。[脚本回归](assets/r3b-unsigned-powershell-matcher-after.json)

## 9. 续验发现的修复与当前源码边界

### PowerShell hook漏检

新版Claude Code的PowerShell工具把命令放在tool_input.command，匹配Bash单独不会覆盖它。[官方契约](https://code.claude.com/docs/en/hooks#powershell)。先写运行时生成的格式fixture，Rust与旧JS都复现未触发确认，Windows安装matcher也失败；随后沿用Bash的检测／ask规则，补PowerShell与Windows遗漏的NotebookEdit matcher，不打印完整fixture或真实凭证。[Rust修前](assets/r3b-unsigned-powershell-hook-before.log)、[修后](assets/r3b-unsigned-powershell-hook-after.log)、[JS修前](assets/r3b-unsigned-powershell-legacy-before.log)、[修后](assets/r3b-unsigned-powershell-legacy-after.log)、[matcher修前](assets/r3b-unsigned-powershell-matcher-before.json)、[PS5.1/7修后](assets/r3b-unsigned-powershell-matcher-after.json)

改动：kv-hook/src/lib.rs的tool_text/tool_where及回归；claude-plugin/hooks/hooks.json、secrets.mjs、secrets.test.mjs；scripts/install.ps1及test-windows-scripts.ps1。真实Claude尚未可用，不能将模拟hook输入记作现场Claude阻断。

### WinRT上下文生命周期

PDB将访问违例定位到第二次KeyCredentialManager.IsSupportedAsync+0x10a，[符号收据](assets/r3b-unsigned-presence-fault-symbol.json)。原probe每轮RoInitialize/RoUninitialize，SDK静态factory会在下一轮复用。假SDK先复现：释放第一代上下文后的查询返回None，1失败；[修前](assets/r3b-unsigned-presence-before.log)。ThreadApartment现在保存成功初始化的租约到线程结束，支持结果仍每轮真实查询；初始化失败及不可用结果不变成available。服务主线程也保持MTA，覆盖Tokio blocking线程替换；Hello请求仍使用原签名、固定key与时限，没有软件回退。[原生修后](assets/r3b-unsigned-presence-after2.log)、[Clippy](assets/r3b-unsigned-presence-clippy2.log)、[构建](assets/r3b-unsigned-presence-after2.json)

改动：kv-agent/src/presence/windows_hello.rs、presence.rs、presence/windows.rs、hello.rs、remote_main.rs。源码修复已通过原生定向回归，真实锁屏复验仍未完成；不能用没有再次崩溃日志推断已修好。

Mac的PowerShell修复快照四项已通过，[收据](assets/r3b-unsigned-mac-ci-final.json)；后续生命周期修复和共享树Windows发行／WinUI／rejoin改动已不同于它。Mac空间低于15GiB门槛，停止新的构建，维护者选择先继续Windows，[空间记录](assets/r3b-unsigned-mac-space-blocked.json)。当前整合快照见[source manifest](assets/r3b-unsigned-source-manifest-integrated-formatted.json)，最新Windows四项正在重跑；不将任何较早快照冒充当前源码全绿。

真机22端口可连接但SSH无握手，已请求维护者Restart-Service sshd，无法靠现有通道安装新包。已通过的取消与解锁不重复；恢复连接后先核对整包源码与哈希，再只复验锁屏／解锁。Mac空间、Windows连接、客户端可用网络／账号、WSL2重启、物理ARM64和真实导出／恢复生命周期仍开放。

## 10. 整合检查与客户端续验

### 重新加入与历史审计

整合现行 rejoin 时发现三项兼容问题：helper/rejoin.rs引用未声明ulid依赖，改为验证26位规范大写Crockford编码和128位前导上限，路径／symlink验证保留；CLI Pair传入借用bool，改为解引用；Pair解析golden补rejoin=false。没有新增依赖。前两次原生编译失败日志保留：[未声明依赖](assets/r3b-unsigned-ci-integrated2-clippy-first.log)、[bool类型](assets/r3b-unsigned-ci-integrated3-clippy-first.log)。

CLI原来丢弃helper返回的archived_devices，导致重新加入后全量audit漏掉旧身份。本地和远端都逐身份读取历史页；远端仍经当前已认证peer发出QueryAudit，history_device是签名参数。档案列表最多16、唯一、非空，分页不能变化；每页账户／身份／固定头与检查点照常核对。嵌套历史、错误账户或设备拒绝；缺失的旧回执仍记录差异，保留非零退出，不将旧操作过滤成一致。改动：kv-cli/src/remote/audit.rs、audit_tests.rs、remote.rs、tests/snapshots/remote-parser.json；helper/src/remote/rejoin.rs的规范ID验证与假文件系统测试。

保留R3-A的旧身份缺失回执复现；另覆盖六类本地伪造selector／身份、远端历史正例及错误身份／账户／嵌套历史。新增远端正例最初误用directive_received，按实际helper事件改为directive_applied/iss，接收验证不改。

### 验收包装器与源码新鲜度

Windows PowerShell 5.1会将Cargo进度stderr包装为ErrorRecord；包装器现以进程退出码判断成功，非零仍终止。[首轮包装器结果](assets/r3b-unsigned-ci-integrated5-result.json)。随后完整工作区测试再次执行了旧CLI编译单元：源码快照tar的epoch时间戳早于Cargo指纹，造成不同编译单元的缓存复用。失败日志保留：[工作区失败](assets/r3b-unsigned-ci-integrated6-test-first.log)、[源码时间戳诊断](assets/r3b-unsigned-ci6-stale-cache-diagnostic.json)。

早期定向日志确有两项新增测试通过，但不能据此证明整合工作区用了当前编译单元；撤回它作为当前完整快照通过的依据。冻结工具改用当前时间戳，解包后再次更新输入mtime并逐文件验证SHA256；先要求四个明确测试名实际通过，再允许全工作区四项继续。新的1183文件快照：[manifest](assets/r3b-unsigned-source-manifest-integrated-ci7.json)，fingerprint=59fd39925f794b37b749e90afc4b2845d38ad09ca63589697ffa505cded93948。检查仍在运行，不能将旧包或候选混合包标成此快照产物。

### Codex官方原生客户端

GitHub直连下载失败后，使用官方@openai/codex的Windows发行包，SHA512与registry发布的integrity一致；解包后的codex.exe SHA256与官方GitHub发行校验值一致。[下载校验](assets/r3b-unsigned-codex-download-verification.json)、[解包与逐程序哈希](assets/r3b-unsigned-codex-extracted-result.json)。版本0.162.1与MCP帮助均exit0，[原生执行](assets/r3b-unsigned-codex-native-version-help.json)。

VM按owner安装到C:\Users\win\AppData\Local\Programs\OpenAI\Codex-0.162.1，不覆盖客户端配置，不改变PATH、不登录。[安装收据](assets/r3b-unsigned-codex-user-install-and-probe2.json)。MCP探测用官方app-server的initialize和mcpServerStatus/list，只发现工具定义，不创建模型任务或调用凭证工具；原始RPC、stderr留在内存，结果只保存固定断言与工具名称。[官方协议](https://github.com/openai/codex/blob/main/codex-rs/app-server/README.md#mcp-server-capabilities)。实际连接结果仍待收集；VM结果不能代替物理机客户端／模型验收。

当前发行策略来自共享树的Windows政策变更与AGENTS.md：默认unsigned，Authenticode可选。架构及OPEN-QUESTIONS已同步此来源，并保留新整包／公网待验边界；不再将申请签名作为继续工作的门槛。
