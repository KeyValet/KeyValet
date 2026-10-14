# 远程审批 V1 第三轮：真机闭环收尾的并行 prompt

前两轮（[第一轮](remote-approval-agent-prompts-2026-10.zh-CN.md)、[第二轮](remote-approval-agent-prompts-r2-2026-10.zh-CN.md)）之后的状态：代码、relay、推送、安装器、K1 协议、恢复与审计全部落地，`relay.keyvalet.dev` 与 push 服务在线，ndu / Mac / Windows VM / Pixel 7 都已安装；Android 的锁屏 Quick、指纹 Strong、30 s 升级、设置三步已在真机通过。**但 M2 仍是 0 次真实审批**：Mac 配对在 Strong 阶段以 `ipc_unavailable` 失败；手机重启后连不上 relay HTTPS；K4 决定的接收侧校验有两处还没落实（S01/S02）；Claude 等运行时因未登录没测到。第三轮只做这些收尾。

用法同前：每块整体复制给一个 agent。**R3-A 需要你在 Mac 旁边按 Touch ID，先跑完它第 A 步（无人值守的根因与修复）再约时间**；R3-B、R3-C 现在就能启动；R3-D 等你 `claude login` 之后启动；R3-E 最后。

本轮所有 prompt 共同遵守的两条新规则（磁盘已经满过一次）：

- **不新建 Cargo target 目录**。各自复用上一轮的目录（写在各自 prompt 里），并在每条 cargo 命令前设 `CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0`。开工先 `df -h /System/Volumes/Data`，剩余不足 15 GB 就停下来报告，不要删别人的目录。
- 已拍板的 K1–K4 决定（见第二轮文件顶部）不再讨论，照做。

需要你本人做的事（agent 碰到会停下来报告）：

1. 磁盘：此刻剩 59 GB，够本轮用；`rust/target-*` 仍占约 50 GB 可再生缓存。要清的话只删各目录里的 `debug/`、`release/`、交叉目标子目录，保留 `*.log`、`*.json`、`sdk-venv/`、`deployment/`、`tooling/` 和 R2-C 软件 fixture 的密钥目录（报告里引用了这些）。
2. R3-A 的 B 步需要你在 Mac 前约 30–40 分钟按 Touch ID，之后另找一个 2 小时合盖窗口。
3. R3-D 启动前执行 `claude login`（可选再登 Gemini / Grok）。
4. 可选：win11 里设 Hello PIN（R3-B 第 F 步）；Apple ASC 网页建 App 记录与 App Group（R3-C 第 F 步）；Play 上传 keystore（R3-C 第 E 步）。

---

## R3-A  M2 闭环（续）：Mac 配对 Strong 阶段修复与全表验收

```text
你是 KeyValet 仓库（/Users/guang/dev/keyvalet）「远程审批 V1」第三轮的 R3-A 工作流：接手 R2-A，把 Ubuntu ndu（执行端）× MacBook（审批端）的远程审批从「0 次真实审批」推到验收表全部有数字。

【现状（R2-A 已完成，不要重做）】
- ndu 与 Mac 已从当前 main 源码安装：ndu 三个服务（keyvalet / keyvalet-peer / keyvalet-relay）running；Mac 签名 daemon 模式，dev.keyvalet.helper / agent / relay running，三把 SE 键已创建。备份与回滚命令在 docs/remote-approval-reports/R2-A-m2-acceptance.md §1。
- 线上 relay 已对齐到当前 main 快照（SHA 1eced902…），push 服务 8788 在线。
- 配对第一轮：两端 SAS 相同、ndu 终端确认已提交，Mac CLI 在 Strong 阶段结束，配对未完成（assets/r2a-pair-attempt-1.json）。第二轮：Mac 侧 4.161 s 后 `ipc_unavailable`（assets/r2a-pair-native.json）。真实 use n=0。
- R2-A 修了一个安装器 bug（codesign -R requirement 少 `=`），已有 CI 复现测试。
- 用户此前看到的 Mac 对话框截图（W6）与 SE Strong 签名单测（v1-completion：remote_se_strong 3.66 s）都是真的，但都不是已安装产品路径上的。

【机器】本机 Mac（用户日常机，已装）、`ssh ndu`、`ssh simvito`（只读核对，不要再部署）。不要碰 Cloudflare、Origin CA 私钥。

【先读，不读完不要动手】
1. AGENTS.md。
2. docs/remote-approval-reports/R2-A-m2-acceptance.md 全文；R2-D-runtimes.md §D/§E（本地拒绝/取消/到期的类型化结果——「producer 是否准确区分按钮/取消/biometric failure」交给了你）；R2-E-docs.md「发现的冲突」（PairConfirm 历史差异）；owner-integration-23.md「匿名注册和配对」；linux-auth-relay-isolation.md。
3. docs/remote-approval-architecture-2026-10.zh-CN.md（R2-E 已回写到当前实现）：§2.3、§4、§6.5、§6.8、§6.10、§7.4–7.6、§16、附录 C。
4. 代码：rust/crates/kv-cli/src/remote/{relay,system,transport}.rs（pair 命令与 IPC 传输、`ipc_unavailable` 的产生点）；rust/crates/kv-helper/src/remote/{pairing,pairing_relay,owner,ipc,server,process}.rs；rust/crates/kv-agent/src/remote/**、kv-touchid/src/remote_agent.rs（Mac 上 Strong 对话框与 AK_s 签名路径）；rust/crates/kv-platform/src/{agent,paths}.rs（agent ↔ helper 私有通道、audit-token requirement）。

【硬性规则】
- 不执行任何改变 git 状态的命令；只读 git 可用。直接在 main 工作树改。
- 你拥有：rust/crates/kv-helper/src/remote/**（grants.rs 的 install/reload 再验证部分除外，归 R3-B）、rust/crates/kv-relay-client/**（windows.rs 除外，归 R3-B）、rust/crates/kv-cli/src/remote*（args.rs 的 audit --limit 范围除外，归 R3-B）、rust/crates/kv-agent/src/remote*、rust/crates/kv-touchid/src/remote*、rust/crates/kv-platform/src/{agent,peer_broker,linux,paths}.rs、scripts/install.sh 中 `--runtime-config` python 段以外的部分、scripts/linux/**、scripts/uninstall.sh、docs/linux.md。不碰 kv-core（R3-B）、kv-server、kv-push、mobile（R3-C）、kv-mcp/kv-hook/kv-proxy（R3-D）。
- CARGO_TARGET_DIR=/Users/guang/dev/keyvalet/rust/target-r2a（复用），每条 cargo 命令前 CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0；开工先 df -h，不足 15 GB 停下报告。
- 不新增依赖。不得为了跑通放宽：验签顺序、档位、nonce/exp、角色表、audit-token requirement、ptrace/能力策略、Strong 必须真实 userPresence 签名。
- 需要用户按 Touch ID 的步骤，必须先把一切准备好，再给用户一份「接下来 N 分钟你要做的事」清单（每步一句话：按什么、在哪台机器、看到什么算成功），然后等用户说开始。不要在用户不在时反复弹对话框。
- 报告与证据不得含恢复码、配对 token、会话令牌、凭证值。

【任务】
A. 无人值守阶段——根因与修复（不需要用户在场）：
   1. 复现 `ipc_unavailable`：从 kv-cli 的 pair 流程追到具体是哪条 IPC（owner → helper，还是 helper → agent 的 Strong 请求）在 4 s 左右失败；在 Mac 上用 `log show --predicate 'subsystem CONTAINS "keyvalet"' --last 2h`、helper/agent 的日志、`launchctl print gui/501/dev.keyvalet.agent` 定位。常见嫌疑：agent 的 audit-token requirement 在 daemon 模式下对 CLI 发起的 Strong 请求路由错误；pair 的 Strong 请求用了 relay 角色的 socket 而非 owner 通道；超时 4 s 太短把 Touch ID 弹窗等待当成不可用；agent 未在前台 GUI 会话。
   2. 先写 CI 可跑的复现测试（假 agent/假 helper，不依赖本机安装），再修，再在真机上验证修复——真机验证若需要 Touch ID，留到 B。
   3. 顺手核对 R2-D 交来的问题：Mac 对话框「拒绝」按钮、用户取消（Esc）、Touch ID 失败三种情况，helper 产出的本地结果分别是 denied / cancelled / expired-with-reason 中的哪一个，与 kv-mcp 的类型化映射一致；不一致则改 producer（kv-touchid/kv-agent/helper），不改 kv-mcp。
B. 用户在场阶段（约 30–40 分钟，先给清单再开始）：
   1. 配对：ndu `keyvalet pair --new` → Mac `keyvalet pair <kv-pair://…>` → 两端 SAS → Mac Touch ID。记录从第一条命令到两端 `devices list` 看到对方的用时。
   2. 首次远程 use：ndu 上用 Claude Code（若 Claude 未登录则用 `keyvalet run` + curl 走网关）对一个用户选定的只读 GET 凭证发请求 → Mac 弹框 → Touch ID → ndu 执行一次 → 结果返回。
   3. 连续 ≥20 次相同请求测 p50/p95（helper 发出请求到收到决定；用户按 Touch ID 的时间单列）。
   4. 拒绝一次；超时后 `credential_wait_approval` 一次；同一批准重放一次（必须被拒）；改参数一次（必须新审批）。
   5. 远程控制面各计时：`remote <ndu> mode per_session`、`remote <ndu> allow --credential … --until 1h`（Strong）、`grant list`、`remote <ndu> grant revoke-all`、`remote <ndu> lock`、`remote <ndu> unattended --include-sensitive --until 1h` 的两次标签确认、`remote <ndu> status/pending/grants/audit`；确认 ndu 本地 `/keyvalet:mode` 与远程 set_mode 共用设置后端。
   6. 在场：用户在 Mac 前时 ndu 请求先弹 Mac 框、手机静默（手机侧现象由 R3-C 复核，你只看 PresenceHint 与 Directive）；用户锁屏后 `remote <ndu> status` 显示 away，并由 R3-C 确认手机立即横幅。
C. 吊销与对账（可无人值守）：Mac `devices revoke <ndu>` → ndu 上的待用批准与 Grant 1 分钟内失效；反向 ndu 吊销 Mac；`keyvalet audit --remote` 两端对账差异为 0。吊销后需要重新配对才能继续 D，安排在 C 之后再配一次（需要用户再按一次 Touch ID，并入 B 的清单末尾或单独约）。
D. 2 小时合盖（用户给窗口）：合盖期间 ndu 产生 3–5 个请求（含 1 个 T2）；开盖后积压送达、每个只执行一次、过期的正确标 expired。
E. 每个 bug：复现测试 → 修复 → 真机复验；凡涉及认证/配对/bootstrap 的修复，报告里单独说明没有放宽。
F. 最终 rust/ 四条 CI 命令全绿；docs/linux.md 更新真实步骤。

【验收】§16 表与 docs/review 顶部表里这些行都有数字：pair → 首次远程批准 <10 分钟；p50 <3 s / p95 <8 s；吊销 1 分钟内失效；两端 audit 100% 对账；合盖 2 小时积压送达不重复；远程三项各 <5 s；本机优先投递。达不到阈值的如实写数字。

【报告：docs/remote-approval-reports/R3-A-m2-closure.md】
1. `ipc_unavailable` 根因、复现测试、修复文件、真机复验。2. 给用户的操作清单原文与实际执行记录。3. 验收表（每行：结果、数字、证据路径）。4. 本地结果 denied/cancelled/expired 的 producer 核对结论。5. 所有权外变更请求。6. 未决项。证据放 assets/r3a-*。
```

---

## R3-B  安全收口：K4 接收侧（S01/S02）、metrics 边界、CLI 上限、Windows 遗留项

```text
你是 KeyValet 仓库（/Users/guang/dev/keyvalet）「远程审批 V1」第三轮的 R3-B 工作流：把已拍板但接收侧还没落实的安全规则补上，并清掉几个边界性遗留项。全部是可以无人值守完成的工作，最后一步 Hello 看用户是否设了 PIN。

【已拍板的规则（K4，不讨论）】
- D04：有限期 T2 Grant（max_tier = T2 且 exp 非空）的**签名对象本身**必须包含标签确认证明（与常设 T2 相同的 confirm 字段），接收端验证器没有该证明即拒绝；不能靠「签发端有过交互」代替。
- D05：全局 T2（aud = `*` 或覆盖未来设备 且 max_tier = T2）接收端一律拒绝，重验证（reload/使用时）同样拒绝；签发端已拒绝不算数。
- D03：短期设置票保持 Strong。

【现状（R2-E 代码核对出的缺口）】
- rust/crates/kv-core/src/remote/validation.rs:189–206 一带：`exp.is_none() || max_tier == T2 || origin == "settings"` 的分支与 :195 只在 exp = null 时核对 confirm；:171/177 允许 `*` 与 global 而没有对 max_tier = T2 独立拒绝。helper 的 install_grant 与使用时重验证共用这些函数。
- S03：kv-server `/metrics`（src/http.rs:85、:151）走普通 Device 会话认证，没有 loopback 限制；nginx 通用转发，私有片段只屏蔽了 push。
- T12：kv-cli audit `--limit` 接受 1..1000（src/remote/args.rs:759/769），helper 页上限 200，大于 200 会被拒。
- T11：Windows 上未配对的 relay-client 控制 worker 因受保护目录读取失败而退出，服务保持 Manual/Stopped；Linux/macOS 的无绑定启动正常。
- Windows Hello：`KeyCredentialManager.IsSupportedAsync()` 为 false，等用户设 PIN。R2-B 的 K1 双 PCP 键已通过真机。

【先读，不读完不要动手】
1. AGENTS.md。
2. docs/remote-approval-architecture-2026-10.zh-CN.md §7.4–7.6、附录 A.4（Grant）、§8（relay API、附录 B 的 metrics 条目）、§9.3/附录 E（CLI）、§16；docs/remote-approval-reports/OPEN-QUESTIONS.md 的 S01/S02/S03/T11/T12；R2-B-windows.md「未决项」；R2-E-docs.md「发现的冲突与变更请求」。
3. 代码：rust/crates/kv-core/src/remote/{validation,types}.rs、testdata/remote/generate.py 与 grant_* 向量、schemas/remote/grant*.json；rust/crates/kv-helper/src/remote/grants.rs（install / reload / 使用时重验证的调用点）；rust/crates/kv-server/src/{http,state}.rs 与 deploy/relay/nginx.conf.template、push-private.nginx.conf；rust/crates/kv-cli/src/remote/args.rs；rust/crates/kv-relay-client/src/{windows,control,app}.rs；rust/crates/kv-agent/src/hello/**、src/remote/windows.rs、pcp_acceptance.rs。

【硬性规则】
- 不执行任何改变 git 状态的命令；只读 git 可用。直接在 main 工作树改。
- 你拥有：rust/crates/kv-core/src/remote/**、kv-core/testdata/remote/**、kv-core/schemas/remote/**；rust/crates/kv-helper/src/remote/grants.rs 中 install/reload/重验证的调用与其测试（其他 helper 文件归 R3-A）；rust/crates/kv-server/src/{http,state}.rs 的 metrics 部分与 deploy/relay/*.nginx.conf*；rust/crates/kv-cli/src/remote/args.rs 的 audit --limit 范围与对应测试、帮助文案；rust/crates/kv-relay-client/src/windows.rs（其他 relay-client 文件归 R3-A，需要改 app.rs/control.rs 写变更请求）；rust/crates/kv-agent/src/hello/**、src/remote/windows.rs、pcp_acceptance.rs；scripts/install.ps1、scripts/test-windows-*.ps1；docs/windows.md、docs/windows-native-acceptance-2026-10-12.zh-CN.md。
- CARGO_TARGET_DIR=/Users/guang/dev/keyvalet/rust/target-r2b（复用）；Windows 上复用 C:\kv-r2b-20261012\target；每条 cargo 命令前 CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0；开工先 df -h，不足 15 GB 停下报告。
- 不新增依赖。只收紧不放宽；任何旧票在新规则下不再有效时，reload 必须拒绝并审计 `grant_rejected_by_policy`，不得静默迁移成有效。
- 测试不得依赖本机安装；Windows 特权/Hello 测试 opt-in 或 #[ignore] 并写明运行方法。

【任务】
A. S01/S02 接收侧：改 validation.rs——(1) max_tier = T2 时无论 exp 是否为空都要求 confirm 证明且证明绑定 aud 与 jti；(2) aud = `*`、`exclude_global` 为假或任何覆盖未来设备的形态，只要 max_tier = T2 即 `invalid_grant: global_t2_forbidden`；(3) 设置来源短票仍要求 Strong 级签名。所有判断先于「覆盖判定」。新增负向向量：`grant_finite_t2_without_confirm.json`、`grant_global_t2_rejected.json`、`grant_future_devices_t2_rejected.json`、`grant_settings_quick_rejected.json`，正向 `grant_finite_t2_with_confirm.json`；generate.py 同步；schema 中 confirm 字段对 T2 标为必填（用 if/then）。helper grants.rs 的 install 与 reload 走同一验证器；加 reload 测试：数据库里预埋一张旧的无 confirm 有限 T2 票，启动后被拒并审计，对应覆盖判定返回不覆盖。
B. S03 metrics：把 `/metrics` 从公共 router 移到一个只绑 127.0.0.1 的独立监听端口（默认 8790，配置项 `metrics_listen`，可关），不要求认证也不暴露任何 ID；nginx 模板明确不转发它；kv-server 启动日志打印 metrics 地址。测试：公共 URL 的 /metrics 返回 404；loopback 端口返回文本。
C. T12：CLI `audit --limit` 范围改为 1..200，帮助文案与错误提示同步；>200 的输入给清晰错误而不是 helper 拒绝；对应快照/参数测试更新。
D. T11：Windows 无绑定启动——relay-client 在 Windows 下读取受保护配置目录失败且配置不存在时，进入「等待绑定」循环（与 Linux/macOS 一致）而不是退出；不改 ACL、不忽略真实权限错误（配置存在但不可读仍是错误并退出非零）。单元测试用假目录。若必须改 app.rs/control.rs，停在那一步写变更请求给 R3-A。
E. Windows 回归（`ssh win11`，MSVC 原生）：四条 CI 命令；install.ps1 升级后 relay 服务从 Manual/Stopped 变为 Running 且日志显示等待绑定；双 PCP 键状态仍为 present。
F. Hello 交互（用户已设 PIN 时；否则写「等待 PIN」）：owner 桌面会话里创建 AK_s（RS256）、签一次 Strong、取消一次、重复提示；Windows 审批端批一个软件执行端 fixture 的 T2 请求（Strong 用 Hello RS256）；记录各步耗时。
G. 把 §7.6 / A.4 需要回写的精确规则文字（验证顺序、错误码、向量清单）写在报告里，不直接改架构文档。

【验收】
- Mac 与 Windows 四条 CI 命令全绿；新负向向量全部被拒、正向通过；reload 拒绝旧票的测试通过。
- 公网 `https://relay.keyvalet.dev/metrics` 为 404（只读 curl 核对，不部署；部署归下一轮或 R3-A 统一）。
- CLI `audit --limit 201` 报错且文案清楚。
- Windows：relay-client 无绑定时 Running 并等待。

【报告：docs/remote-approval-reports/R3-B-security-closure.md】
改动文件；S01/S02 的新验证顺序与错误码；向量清单；metrics 新边界；T11/T12 结果；Windows 真机结果（含 Hello 或「等待 PIN」）；给 R3-E 的回写文字；变更请求；未决项。证据放 assets/r3b-*。
```

---

## R3-C  手机：relay HTTPS 失联根因、Android 可靠性复验、iOS 发行准备

```text
你是 KeyValet 仓库（/Users/guang/dev/keyvalet）「远程审批 V1」第三轮的 R3-C 工作流：接手 R2-C。Android 的核心手机流程已在 Pixel 7 真机通过，现在要修掉「手机重启后连不上 relay HTTPS」这个阻塞一切复验的问题，补齐可靠性项，并把 iOS 推进到资源允许的最远处。

【现状（R2-C 已完成，不要重做）】
- Pixel 7（Android 16）：扫码配对、锁屏 Quick（AK_q）、App 指纹 Strong（AK_s）、真实 30 s 静默→横幅升级（同 tag/id）、设置三步（切模式 / 1 小时票 / revoke-all）、「我不在电脑前」立即横幅、系统杀进程后 FCM 唤起、重启后 FCM token 持久化——全部通过，有截图/系统通知记录。
- relay → kv-push 路由、重试、CAS、token 生命周期（登录/轮换/退出/吊销/410）已实现并有假 HTTP 测试；kv-push 在 simvito 以 keyvalet-push.service 运行，127.0.0.1:8788，FCM 真实投递 202。
- **未通过**：重启并恢复网络后，App 的 relay HTTPS 请求持续失败（界面提示「暂时无法连接 relay」，连登录页的 `GET /v1/account/providers` 也失败），但同一时刻 FCM 能唤起后台 worker，拉取同样 retry=true。因此：远端退出清 token 未验、重登同 token 上传未验、重启后审批展示未验、1 小时离线未做。单次样本静默→横幅端到端约 35 s（定时器 30 s + 投递），≤30 s 预算未达。
- iOS：Rust iOS/iOS-sim 与 Runner/NSE 模拟器构建通过；iPhone 15 已无线配对、开发者模式开启，但当前 Xcode 无可用 DDI，真机 destination 构建失败；ASC API key 可用（团队 PWCRJPY7YC），已注册两个 Bundle ID 并启用 Push/App Groups/Apple 登录，但 App 记录、App Group 绑定、Time Sensitive 需网页完成；没有 App Store Connect App 记录与匹配 profile，TestFlight 归档失败。Apple 登录未配置。
- Play：没有上传 keystore，未生成签名 AAB。

【先读，不读完不要动手】
1. AGENTS.md。
2. docs/remote-approval-reports/R2-C-mobile.md 全文（尤其「token 与后台可靠性」「Android 真机表」「需要用户提供」）；v1-completion.md「实机与部署记录」；mobile/docs/{push-deployment,r2c-device-acceptance,account-login}.md；docs/mobile-console-setup.zh-CN.md。
3. docs/remote-approval-architecture-2026-10.zh-CN.md §3.3（账户与会话）、§6.10（投递）、§9.2/9.2.1、附录 B 的账户端点与错误体。
4. 代码：rust/crates/kv-mobile-core/src/{relay,account,engine,store,ffi}.rs（固定域名校验、TLS、会话恢复、错误映射到 UI 文案的位置）；mobile/lib/src/{controller.dart,auth/*}；mobile/packages/kv_native/android/.../nativebridge/{RelayMessagingService,PushSyncJob,QuickApprovalService,KvNativePlugin}.kt；mobile/android/app/src/main/AndroidManifest.xml 与 network security config（若有）；rust/crates/kv-server/src/{account,auth,push}.rs 的会话/403/401 路径；mobile/ios/KeyValetNSE、mobile/scripts/package-testflight.sh。

【硬性规则】
- 不执行任何改变 git 状态的命令；只读 git 可用。直接在 main 工作树改。
- 你拥有：mobile/**、rust/crates/kv-mobile-core/**、rust/crates/kv-push/**、rust/crates/kv-server/src/{push,push_tests}.rs 与 account.rs 中 push_token / 会话失效相关函数、deploy/relay/{keyvalet-push.service,push.conf,push.env.example}、docs/mobile-console-setup.zh-CN.md、mobile/docs/**。不碰 kv-server/src/{auth,pairing,http}.rs 的其他部分（R3-B 在改 metrics）、kv-core（R3-B）、kv-helper/kv-cli（R3-A）。
- CARGO_TARGET_DIR=/Users/guang/dev/keyvalet/rust/target-r2c（复用）；每条 cargo 命令前 CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0；mobile/build 复用；开工先 df -h，不足 15 GB 停下报告。
- Dart 不碰私钥/验签/信封；Strong 必须是 Keystore/SE 的生物识别门控签名；固定域名 relay.keyvalet.dev 不可配置（K3）。
- 不关闭 Android 包验证、不放宽 TLS 校验、不加「跳过证书」开关来绕过失联；根因必须落到具体一层（DNS / TLS / HTTP 状态 / 应用层会话 / 域名校验 / 网络权限）并有日志证据。
- 推送正文只允许元数据；日志 token 只打后 6 位。
- 缺用户资源的步骤：写精确清单，做不依赖它的部分，不用占位值冒充。

【任务】
A. HTTPS 失联根因（最高优先级）：
   1. 用 adb 在 Pixel 7 上分层探测：`adb shell` 内对 relay.keyvalet.dev 做 DNS（`getprop net.dns1`、`ping`/`nslookup` 若有）、TCP 443 连通、TLS 握手（若有 `openssl`/`curl`；没有就写一个最小 instrumentation 测试用 OkHttp/HttpsURLConnection GET /v1/health 并把异常类名与消息打到 logcat）；同时 App 内把 Rust 的 relay 错误原文（已白名单的静态错误码 + 异常类）打到 logcat。
   2. 对照服务器侧：simvito nginx access/error log 里该时间段有没有来自手机 IP 的请求、Cloudflare 侧是否 403（nginx 的 Cloudflare IP allowlist 与 real-ip 配置是否把某些来源拒了——v1-completion 提到「直连 origin 加伪造 CF 头 403」）。
   3. 嫌疑按先验排序：App 内固定域名/证书校验把 Cloudflare 轮换后的证书链拒了；Android 网络安全配置；IPv6-only 网络下 Cloudflare 解析；人类会话过期后 Rust 把 401 映射成了「无法连接」且登录页复用了同一失败状态；DNS 缓存负结果。逐个证伪，写出证据。
   4. 修复 + 回归测试（Rust 单测 + 假 HTTP 服务器；Android instrumentation 若适用）。
B. 复验（修复后，Pixel 7 真机）：远端退出清 token 与会话（relay 侧查无 token）；重新登录同一 SDK token 上传；重启后新审批正常显示；1 小时离线后上线与 relay 一致（需要用户同意手机断网 1 小时；不同意就记未测）。
C. ≤30 s 横幅预算：测 10 次「锁屏 + 不批」的静默→横幅间隔（手机侧记录）与端到端（执行端 escalate 发出 → 手机横幅）；分析差距来自执行端定时器、relay、FCM 还是手机侧；如果是 FCM 高优先级消息延迟，评估 escalate 改为 `priority: high` 加 `ttl` 的效果；不要把执行端 30 s 定时器改短。
D. 与 R3-A 联动（它配好 Mac × ndu 后）：Mac 在桌前 → 手机静默；Mac 锁屏 → 手机立即横幅；手机 Quick 批准 ndu 的真实凭证请求一次；记录计时。R3-A 未就绪前用软件执行端 fixture。
E. Play（用户给 keystore 路径与密码环境变量时）：`mobile/scripts/package-play.sh` 产签名 AAB，按 docs/mobile-console-setup 上传内部测试；拿到 Play 应用签名指纹后提醒用户登记 Android client 并同步 relay 配置；Play 包 Google 登录复验。没给就写清单。
F. iOS（尽可能推进）：
   1. 解决 Xcode DDI：检查 Xcode 版本与 iOS 26 匹配、`xcrun devicectl list devices`、必要时提示用户更新 Xcode 或下载 iOS 平台支持；能连上就用 Apple Development 身份装开发版到 iPhone 15，跑：Google 登录（iOS client 已有）、扫码配对软件 fixture、前台 WS 收请求、Face ID Strong、NSE 需要 APNs 所以只验前台。
   2. ASC 网页侧需要用户做的事列成清单（App 记录 dev.keyvalet.mobile、App Group group.dev.keyvalet.mobile 绑定两个 ID、Time Sensitive 能力、主 App 与 NSE 的开发/发行 profile、APNs key 文件路径与 Key ID、Sign in with Apple Services ID 与 callback）；每一条写清在哪个页面、填什么。
   3. 用户提供后：APNs 投递到 NSE → 解密 → passive/timeSensitive 通知 → 锁屏 Quick → App Face ID Strong；TestFlight 归档与上传（package-testflight.sh）。
G. 最终：四条 CI 命令、flutter analyze/test、iOS/Android 目标构建、APK 安装；更新 mobile/docs/r2c-device-acceptance.md 为 r3 版本。

【验收】
- A 的根因有分层证据与修复测试；B 四项在 Pixel 7 通过（1 小时离线项允许「未测，用户未安排」）。
- C 有 10 次样本的两组间隔与归因。
- iOS：至少给出 DDI 结论与 ASC 清单；资源到位则真机 Face ID Strong 通过。

【报告：docs/remote-approval-reports/R3-C-mobile-closure.md】
根因分析（分层证据）；修复与测试；Android 复验表；30 s 预算测量与归因；Play/iOS 状态与「需要用户提供」清单；变更请求；未决项。证据放 assets/r3c-*。
```

---

## R3-D  运行时实测（续）：Claude Code、channels、Gemini/Grok、Devin 配置同步

```text
你是 KeyValet 仓库（/Users/guang/dev/keyvalet）「远程审批 V1」第三轮的 R3-D 工作流：接手 R2-D，补齐运行时实测里缺的那几家。前提：用户已经执行 `claude login`（可能也登了 Gemini / Grok）。开工先逐个确认登录状态（最小调用），没登录的那家直接记「未登录，未测」，不要尝试登录、不要输入任何凭据。

【现状（R2-D 已完成，不要重做）】
- kv-proxy 两个连接数测试已修（`ulimit -n 256` 下 20/20），T08 三种类型化错误（403 denied / 409 cancelled / 410 expired、429 pending + Retry-After、x-should-retry: false）与断开后恢复已实现并有测试；官方 Python OpenAI/Anthropic SDK 的 HTTP/1.1 与 h2-only 走网关验证通过。
- 实测完成：Codex exec/TUI 0.162.1（4 分钟两组均完成；tool_timeout_sec 生效；Stop 九字段，block 后真实续等）、Devin CLI 3000.11.3（clientInfo rmcp/3.1.0；4 分钟完成；Stop 五字段，block → wait → 原结果；active=true 放行）。
- 未测：Claude Code CLI 2.1.282（OAuth 过期）、channels 三项（idle 唤醒 / busy 合并 / 不加 flag 静默丢弃，必须交互会话，`-p` 下 flag 被忽略）、Gemini CLI 0.39.1（未登录）、Grok 1.0.50（NotSignedIn）、cursor-agent（额度耗尽）、Claude Desktop / Cursor IDE（未安装）。
- T10：Devin 当前版本从独立全局 MCP 文件导入 `keyvalet`；R2-D 曾因此误连已安装 helper。安装器写 Devin 配置的位置需要与之同步；短 timeout 环境的隔离也要同步。
- 实验工具已就绪：rust/crates/kv-mcp/examples/approval_fixture.rs（真实 Rust Server + 附录 C FakeHelper）、tests/r2d_runtime_lab.py、r2d_codex_tui.py；kv-hook/examples/stop_fixture.rs；所有实验配置放私有 /tmp/kv-r3d-* 并用项目级配置屏蔽全局 server。

【先读，不读完不要动手】
1. AGENTS.md。
2. docs/remote-approval-reports/R2-D-runtimes.md 全文；docs/runtimes.md；docs/remote-approval-architecture-2026-10.zh-CN.md §6.9 全部、§9.4、附录 A.8。
3. Claude Code 官方 channels 文档（code.claude.com/docs/en/channels-reference）、hooks 文档（Stop 事件、stop_hook_active）、MCP 配置的 timeout 字段；Gemini CLI 的 MCP timeout 与 AfterAgent hook 文档；Grok 的 tool_timeout_sec 文档——以官方页面为准，记录访问日期。
4. 代码：rust/crates/kv-mcp/src/{approval,session,server,lib,fake_helper}.rs 与 examples/、tests/；rust/crates/kv-hook/src/{lib,stop}.rs 与 examples/；scripts/install.sh 的 `--runtime-config` python 段（约第 40–330 行，Devin/Claude/Codex/Gemini/Grok 的配置写入与收据）、.github/workflows/w9-install-tests.py。

【硬性规则】
- 不执行任何改变 git 状态的命令；只读 git 可用。直接在 main 工作树改。
- 你拥有：rust/crates/kv-mcp/**、rust/crates/kv-hook/**、rust/crates/kv-proxy/**、rust/crates/kv-protocols/**（仅超时提示字段）、docs/runtimes.md、scripts/install.sh 中 `--runtime-config` python 段（只改该段；改前先重新读取文件，因为 R3-A 可能同时在改其他段）、.github/workflows/w9-install-tests.py。不碰 kv-helper/kv-cli（R3-A）、kv-core（R3-B）、mobile（R3-C）。
- CARGO_TARGET_DIR=/Users/guang/dev/keyvalet/rust/target-r2d（复用）；每条 cargo 命令前 CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0；开工先 df -h，不足 15 GB 停下报告。
- 不新增依赖。实验只用用户已登录的工具与本仓库构建的 kv-mcp + FakeHelper；绝不连接已安装 helper 或真实 vault（先用项目级配置禁用全局 `keyvalet` server 并确认 initialize 来自 fixture）。实验结束恢复所有配置。
- 超时永远不映射成拒绝；不为迎合未观察到的行为改 Stop 输出 schema。

【任务】
A. Claude Code CLI（已登录时）：
   1. 「4 分钟 + 每 15 s progress」与「4 分钟 silent」各一次，记录 clientInfo.name/version、progressToken、是否被杀与时刻；再把 `.mcp.json` 的 keyvalet `timeout` 设成 30000 验证字段生效，设回 900000。
   2. 预算用尽返回 `approval_pending` 后模型是否调用 `credential_wait_approval`（fake helper 延迟 35 s、预算 10 s、不注册 Stop）。
   3. Stop hook：注册 claude-stop 模式，记录输入字段名、PPID 与 agent.pid 一致性、block 后是否续等、stop_hook_active=true 时放行。
   4. channels 三项（交互会话，不用 -p）：加 `--dangerously-load-development-channels server:keyvalet` 时，idle session 收到 `notifications/claude/channel` 是否被唤醒并取结果；busy 时是否合并到下一轮；不加 flag 时确认静默丢弃且无报错。每项录屏或 wire 日志。
B. Gemini CLI（已登录时）：4 分钟两组；`timeout` 字段生效；AfterAgent hook 的输入字段与 `{decision: deny, reason}` 是否被接受并续等。
C. Grok（已登录时）：4 分钟两组；`tool_timeout_sec` 生效；Stop 是否存在与字段。
D. cursor-agent（额度恢复时）：复核 W5 的 60 s 硬限是否仍在；stop 的 followup_message 是否接受。
E. 据实测修订 kv-mcp 预算表常量与 A.8 文案、kv-hook 输出；docs/runtimes.md 矩阵更新；§6.9.3 修订以「原文 → 新文 + 证据」列在报告里给 R3-E。
F. T10：安装器的 Devin 配置写入改到当前版本实际读取的全局 MCP 文件（以本机 Devin `--help`/文档核实路径），保留旧位置的清理；短 timeout 实验环境的项目级屏蔽写成可复用脚本（放 kv-mcp/tests/）；w9-install-tests.py 加 Devin 用例。
G. 最终四条 CI 命令全绿；`ulimit -n 256` 下 kv-proxy bounded 测试再跑 5 次确认仍稳定。

【验收】
- Claude Code 至少 A.1–A.3 有结果（登录后）；channels 三项有结果或精确写明哪一步不可用及原因。
- 运行时表至少新增 Claude 一家完整数据，使「Claude + 另外两家」门槛被满足（Codex、Devin 已有）。
- T10 有安装器测试。

【报告：docs/remote-approval-reports/R3-D-runtimes-closure.md】
登录状态核对；每家实测表（版本、两种阻塞、token、Stop 字段、配置字段实效、channels）；修订的常量/文案与理由；§6.9.3 原文→新文；T10 改动；未决项。证据放 assets/r3d-*。
```

---

## R3-E  文档回写（最后跑）

```text
你是 KeyValet 仓库（/Users/guang/dev/keyvalet）「远程审批 V1」第三轮的 R3-E 工作流：在 R3-A/B/C/D 报告齐全后，把本轮事实回写进架构、产品文档与开放问题，合并验收表。方法与上一轮 R2-E 相同（见 docs/remote-approval-reports/R2-E-docs.md 的「章节 → 修改 → 依据」表与检查脚本），这里只列本轮要点。

【先读】AGENTS.md；docs/remote-approval-architecture-2026-10.zh-CN.md 与 docs/remote-approval-product-2026-10.zh-CN.md 全文；docs/remote-approval-reports/{R2-E-docs,R3-A-m2-closure,R3-B-security-closure,R3-C-mobile-closure,R3-D-runtimes-closure,OPEN-QUESTIONS}.md；docs/review-2026-10.zh-CN.md 顶部表；第二轮 prompt 文件顶部 K1–K4。代码只作核对：kv-core validation.rs 的新规则、kv-server 的 metrics 监听、kv-cli args.rs 的 --limit、kv-mcp 预算常量。

【硬性规则】不执行任何改变 git 状态的命令。只改：docs/remote-approval-architecture-2026-10.zh-CN.md、docs/remote-approval-product-2026-10.zh-CN.md、docs/remote-approval-reports/OPEN-QUESTIONS.md、docs/review-2026-10.zh-CN.md 顶部验收表。不改代码、README、site、各报告原文。只写有证据的行为用现在时；验收没过的不写成通过；安全冲突不合理化。表格列数与交叉引用检查脚本复用 R2-E 的。

【任务】
A. §7.6 / 附录 A.4：按 R3-B 报告写入有限 T2 必须含 confirm、全局 T2 接收拒绝、验证顺序与错误码、新向量清单；S01/S02 在 OPEN-QUESTIONS 标已落实。
B. §8 / 附录 B：metrics 迁到 loopback 独立端口；S03 关闭。§9.3 / 附录 E：audit --limit 1..200；T12 关闭。§2.3：Windows 无绑定 worker 行为（T11）。
C. §16 与 review 顶部表：填入 R3-A 的全部数字（配对用时、p50/p95、吊销、对账、合盖、远程三项、在场）；R3-C 的 Android 复验、30 s 预算测量、iOS 状态；R3-B 的 Windows/Hello；R3-D 的运行时表。M2–M5 的状态按事实标注；若 M2 通过，写明通过日期与证据。
D. §6.9.3 / §9.4 / A.8：按 R3-D 的「原文 → 新文」替换；channels 结论如实。
E. §3.3 / §6.10 / §9.2：按 R3-C 写入失联根因与修复、token 生命周期复验结果、投递预算测量；iOS 进展。
F. §17.3 / §18：里程碑状态；开放问题两张表更新；若 M2/M3 已通过，新增「一周 dogfooding」的下一步条目。
G. 产品文档：§7 三状态表随之更新；FAQ 若有新事实（例如手机失联的原因与修复）补一条。

【验收】表格与交叉引用检查通过；随机抽 10 条新写的「已实现/已通过」句子逐条给出报告出处。

【报告：docs/remote-approval-reports/R3-E-docs.md】章节 → 修改 → 依据；冲突；仍开放；抽查 10 条。
```
