# R3-A — Ubuntu ndu × MacBook 远程审批收尾（进行中）

2026-10-13–14。本报告仍是执行记录，**不是 M2 全部验收通过声明**。05:18Z 已补成系统 Touch ID 取消的完整 installed path，以及 Mac→ndu 真实吊销：待用批准和 Grant 在 10.583576 s 内失效，执行 0 次；ndu 当前身份已吊销，历史保留。反向吊销、保留历史的重新配对、历史 audit 差异、手机投递与原生 biometric failure 仍未关闭，超阈值数字见 §3。未执行改变 git 状态的命令；直接在 main 工作树改动 R3-A 所有权内文件及本人明确授权的 SE 错误保真跨文件修复，无新增依赖。R2-A 安装、线上 relay 与备份不重做；没有部署 simvito，没有触碰 Cloudflare 或 Origin CA 私钥。

## 1. ipc_unavailable：定位、复现与修复状态

R2-A 第二轮的 4.161 s 是外层交互计时，不能当成 Touch ID 的等待预算。当前源码的 CLI owner 读取预算为 140 s，helper 私有 agent 请求预算为 130 s。`pair <URI>` 的第一条 IPC 是 owner → helper 的 `remote.pair.complete`，Strong 确认在后续 `remote.pair.confirm`。URI 与请求字段不写诊断错误。

本轮在**已安装产品**的只读路径复现：Mac `devices list --json` exit 5 / 0.005 s / `ipc_unavailable`；`status --json` exit 0 / 0.104 s（允许展示保护状态的 fallback，不能把 exit 0 当远程 IPC 成功）。随后普通用户对真实 `/var/run/keyvalet/helper.sock` 的连接直接得到 **ECONNREFUSED（errno 61，0.000048 s）**，尚未进入 helper 的角色检查或 Strong 请求。

helper / agent / relay 在 launchctl 都显示 running，PID 分别 89023 / 89025 / 89031；agent 与 relay 限于 Aqua 会话。四个安装二进制均通过既定 team `PWCRJPY7YC` / identifier 的严格验证；另对我们自己启动、停在 stdin 的已安装 root CLI 用 Security.framework 做动态代码检查，PID 与真实 socket audit token 两条路径的 requirement / code path 均通过。这两个诊断子进程未提交恢复输入、未向 relay 发请求、未触发 UI。

证据：[初始只读检查](assets/r3a-unattended-diagnostics.json)、[root 检查](assets/r3a-root-diagnostics.json)、[socket 拒绝](assets/r3a-owner-socket-connect.json)、[动态代码身份](assets/r3a-peer-code-probe.json)、[动态 audit-token 身份](assets/r3a-peer-audit-probe.json)。`log show --predicate 'subsystem CONTAINS "keyvalet"' --last 2h` 已执行；LaunchAgent/Daemon 没有配置 stdout/stderr 文件，不能用缺少应用日志证明请求被批准。历史失败窗口没有 helper/agent 请求事件。

**本轮根因：** socket 文件的创建时间仍是 helper 启动时间，监听 FD 仍存在；UNIX socket 表有 132 个 helper 条目，其中 128 个未处理帧（84 个 Recv-Q=28、44 个 Recv-Q=139），待接入队列已满。线程采样显示 agent 主线程等待下一条消息；helper 一条配对入站路径在持有状态锁时等待 agent-backed DK ECDH，另一条 timer 路径同步等待同一状态锁。后者卡住 Tokio I/O 驱动，前者的回包与超时无法推进，owner accept 停止，最终 `connect` 返回 ECONNREFUSED。不是 Strong 的 4 s 等待预算，也不是 audit-token requirement 失败。

[只读 FD/线程采样](assets/r3a-runtime-hang.json)、[监听队列表](assets/r3a-unix-listener.json)、[构建符号对应](assets/r3a-symbol-correspondence.json)。安装产物已 strip，没有匹配 dSYM；符号对应使用当前 unstripped release 的相同 36 字节机器码，明确记录 lock prologue 的两个候选，再由调用栈区分，不冒充完整符号化。

先添加 `r3a_state_lock_wait_does_not_stop_the_private_agent_reply_pump`：单 worker runtime、内存私有通道与假 agent、持锁的模拟 key operation、竞争状态锁的真实 helper timer；外部线程的 1 s deadline 在 runtime 卡住时仍可失败并清理。[修前](assets/r3a-runtime-lock-before.log) 1 failed / 1.01 s，[修后](assets/r3a-runtime-lock-after.log) 1 passed / 0.01 s。测试不读取安装、不需要 root、GUI 或 SE。

修复 `remote/engine.rs`：先 try_lock，只有竞争时在 MultiThread runtime 中用 block_in_place 交还 worker，再等待同一把锁；retired/poison 检查不变。`server.rs`、`bootstrap.rs` 的原始状态检查及 `relay_control.rs` 的 challenge job 锁使用同一等待桥，避免同类 agent 签名竞争。锁与签名仍在原授权边界内；未放宽角色表、验签、nonce/exp、设备身份、Strong、audit-token requirement。完整已安装配对复验仍需后面的 B。

签名修复包首次实际安装：helper / agent / relay PID 40325 / 40328 / 40331，三项 running；安装二进制哈希与签名 staging 收据一致。`devices list --json` 连续 5 次 exit 0，耗时 0.032491 / 0.019850 / 0.019793 / 0.017006 / 0.016626 s，owner IPC 5/5；未触发 Touch ID。[首次安装与复验](assets/r3a-native-install-023446.json)。这证明安装后的 owner 通道可读，不单凭此关闭真实配对的 ECDH/Strong 复验。

本轮准备脚本首次 bootstrap 停止：旧 helper 在 bootout 返回后仍未退出，launchd 日志记载 5 s 后发 SIGKILL；原 bootstrap stderr 未保留，清理时序是由日志和首次单元均未加载推断的原因。清理结束后，同样三个 plist bootstrap 均 exit 0；准备脚本已增加等旧 PID 退出再启动的步骤。[失败时状态](assets/r3a-bootstrap-failure.json)。回滚备份 `/private/var/backups/keyvalet-r3a-20261013T023446Z/state-and-install.tar`（root-only）；未改已有 vault、relay 绑定、运行时配置或三把 SE 键。

首次 R3-A 现场尝试：从 ndu 发出 pair --new 到脚本退出 3.031016 s，Mac `unauthorized` / exit 3，SAS 与 Touch ID 均未到达，[收据](assets/r3a-pair-024326.json)。只读核对 simvito 的 SQLite（只读 URI、SELECT 公开设备/状态字段），原 Mac `01M4S8KQ0GQ0GAJS06ZC7A8H17` 的 DK 公钥与 R2-A 相同，已在 00:04:43Z（08:04:43 +0800）被吊销，旧 accepted 配对到期为 00:04:15Z。[吊销状态](assets/r3a-relay-tombstone.json)。server `cleanup.rs` 对过期 accepted joiner 设置 revoked_at 并删除其会话；本轮未改该代码/数据库/线上服务，也未把旧身份重新设为有效。`unauthorized` 是旧候选已失效的保护结果，不是新一次 4 s UI timeout。

仅限未使用 singleton 的重新加入步骤已执行：停止前后八张授权/审批/nonce/outbox 表均为 0，完整旧 remote 目录归档，旧 SE 键与 server 墓碑保留，原 credential vault hash 不变。02:58 的尝试两端 SAS 相同，但驱动把空回车当取消，8.178304 s 退出、owner_confirmed=false；未发起 Strong 确认。[收据](assets/r3a-pair-025841.json)。该未完成候选随后正常到期并被吊销；03:16 再次按同样严格前提保留归档并走原生 fresh bootstrap，[归档收据](assets/r3a-fresh-approver-031618.json)。没有清除已使用授权历史、延长 exp 或恢复被吊销身份。

增加原生 CLI `pair --resume`，允许在原配对仍有效时重新显示同一 SAS 并继续原 `PairConfirm`：只查询 Status，不重复兑换 URI，不延长 TTL，仍要求本人核对 SAS、现有角色验证及审批端 AK_s userPresence。先添加假 helper 的 `r3a_pair_resume_confirms_the_live_sas_without_redeeming_a_token_again`；修前 unknown option / invalid_argument，修后验证 Status → PairConfirm → Status，拒绝到期、无候选与用户不确认。[修前](assets/r3a-pair-resume-before.log)、[修后](assets/r3a-pair-resume-after.log)。CLI `remote.rs` / `remote/args.rs` / `remote/tests.rs` 在 Mac 与 ndu 原生构建通过；ndu 实际旧候选 `pair --resume` 返回 expired / exit 4，未弹 UI。现场驱动改为读取 `/dev/tty`、空回车继续等候，只有明确非空否定才取消。

**真实配对复验通过：** 03:16:19.887Z 从 ndu 的已安装 `pair --new` 开始，用户核对相同 SAS 后确认，并完成 Mac 原生确认/Strong 路径；两边 CLI 均 exit 0，两边 `devices list` 都有活动的 ndu 与 Mac。总用时 **144.164769 s**，提交 SAS 确认在 **138.084913 s**；差值包含确认后签名、传输与目录检查，不能冒充独立 Touch ID 时间。[实机收据](assets/r3a-pair-031844.json)。本轮首次完成 pair=1；当时真实远程 use 仍为 0。Mac 原生凭证名称解锁 exit 0 / 2.897743 s，只记录名称，[目录收据](assets/r3a-mac-credential-catalog.json)。

首次 use 准备选定 `oauth2/outlook-hhstuhacker-graph` 与 `GET https://graph.microsoft.com/v1.0/me`。ndu 的凭证库为空，准备经 Mac 已安装 MCP 取得短期 Graph token，经 SSH/native MCP 存为仅限该主机的代理凭证；不迁移 refresh token，不保存 wire output。03:33 的尝试在 **50.332896 s** 后未取得 token；用户随后说明当时临时离开电脑，不能记本人取消或完成认证。[收据](assets/r3a-first-use-033445.json)。只读审批日志显示 T2/Strong 请求已生成，1 s 内被错误记为 user_cancelled；系统锁屏/屏保值均 unknown，实际 PresenceHint 持续 away，[审批诊断](assets/r3a-approval-diagnostics-033921.json)、[OS 快照](assets/r3a-native-mac-presence.json)。未强制改为 present。

复现并修复两个 producer 问题：原生视图把没有 HTTP Operation 的凭证读取/派生当成 invalid request；helper 把私有 UI 协议失败、不可用、明确取消统一记为 user_cancelled。`r3a_non_http_credential_use_reaches_the_dialog_with_its_original_strong_scope` 修前 InvalidRequest、修后沿用原 T2/Strong/per_use 进入 Dialog，且仍拒绝非空畸形 HTTP Operation；`r3a_private_ui_protocol_failure_is_not_a_user_cancellation` 修前 user_cancelled、修后保留固定白名单错误，未知/缺失错误为 unavailable。证据：[视图修前](assets/r3a-non-http-before.log)、[修后](assets/r3a-non-http-after.log)、[分类修前](assets/r3a-ui-classification-before.log)、[修后](assets/r3a-ui-classification-after.log)。修复在 agent `remote/view.rs`、helper `remote/production.rs` / `owner.rs` / `pairing.rs`；最后一处只改失败分类，配对确认仍要求 ok=true、confirmed=true 与实际 AK_s userPresence，未放宽认证或配对。

用户明确要求再试，修复包重新签名并安装；03:52:25Z 三服务 running、owner IPC 再次 5/5，[安装收据](assets/r3a-native-install.json)。用户提供了已安装产品的真实 T2/Strong 界面，[截图](assets/r3a-source-token-strong-dialog.png)；本人批准后 Mac 短期 token 获取成功，**23.113006 s**。这是 **Mac 自身的凭证使用准备**，不能计入 Ubuntu → Mac 的 GET 样本。随后的 ndu MCP 保存失败，Claude GET 尚未发出、ndu 测试凭证未创建，[收据](assets/r3a-first-use-035255.json)。

ndu 新卡点：IPC 的角色证明已用 root broker，但认证成功后的 ProductionRunner::attach 仍调用非 root SystemProcesses 读取父进程 `/proc/<pid>/exe`。真实已安装 MCP 和父 sshd 的文件均存在、root 能识别，服务 UID 对两者 readlink 均 exit 1；helper audit 已记 unlock=true，绑定阶段随后失败。[只读实机证明](assets/r3a-ndu-session-process-proof.json)。先写 `r3a_authenticated_broker_proof_survives_unprivileged_proc_denial`，修前 agent_unavailable，修后成功，另测无 broker、PID/UID/start/hash 改变均拒绝：[修前](assets/r3a-process-proof-before.log)、[修后](assets/r3a-process-proof-after.log)。

修复位于 helper `remote/process.rs` / `process_observer.rs` / `production.rs` / `mod.rs` 与 platform `peer_broker.rs`。进程证明请求只传入已接受的 socket FD，不传 PID/path/hash；broker 重核 helper 安装 inode、原始 peer 的 SO_PEERPIDFD/角色，从其真实父子关系得出目标，检查同 UID、pidfd/start/inode/hash，并在哈希后再核对 peer 与父子关系。helper 保存有界的原 fd/kernel socket cookie，每次使用只临时复制 CLOEXEC fd 并重新请求 broker，关闭、fd 复用、进程退出/exec/身份变化均失败关闭。helper/relay 不增能力、不接受调用方自报身份，不改角色表、ptrace 策略、签名、nonce/exp 或 Strong；没有新增依赖。Ubuntu 平台/helper 普通测试、clippy、release 构建 exit 0，[检查日志](assets/r3a-linux-process-check.log)；临时 root fixture 的原 8 个角色用例与新增 6 个进程证明用例通过，不依赖已安装 KeyValet，[原生 broker 测试](assets/r3a-linux-broker-native.log)。

04:19Z 已安装 ndu helper/broker；完整状态与旧 binary 备份在 `/var/backups/keyvalet-r3a-process-proof-20261013T041934Z`，root-only。准备驱动首次未收到最终收据、exit 1；随后只读核对确认安装 binary 与构建 hash 相同、三服务 active、原配对双方目录保留、owner IPC 5/5（0.001947–0.002760 s）。helper/relay 的 bounding/ambient capabilities 均为空，broker 保持原 CAP_SYS_PTRACE，[首次安装复核](assets/r3a-ndu-process-install-041934.json)、[首次驱动结果](assets/r3a-ndu-process-install-first-receipt.json)。本次安装未改配置或 vault；随后的真实认证后 attach 结果见下一段。

04:24Z 本人开始重试后，Mac token 授权 **9.278527 s**，ndu 的原生 MCP 成功保存 `api_key/r3a-graph-readonly`（proxy_only=true，仅 graph.microsoft.com）。ndu audit 的 unlock/set 均成功，原来失败的认证后 attach 已通过实机复验。随后 Claude 在进入工具前报错，整段 **203.139753 s**，HTTP tool call=0、GET=0，[收据](assets/r3a-first-use-042756.json)、[ndu auth/set](assets/r3a-ndu-first-use-auth.json)。无 MCP 的最小只读 API 诊断确认现有 provider 为 api.z.ai，连续 6 个 api_retry 均为 authentication_failed；未记录 provider token，[API 诊断](assets/r3a-claude-api-diagnostic.json)。CLI 本地 logged-in 标志不代表 provider 当前认证可用；没有将该失败归因于用户没输入密码，也没有把源 token 操作记为远程 GET。

按任务指定备用路径准备已安装 `keyvalet run + curl`，继续用已保存代理凭证，不再次取 Mac token。原生 root fixture 又验证 CLI 在 nondumpable 状态时仍可由原 broker 证明，不修改 ptrace 或 dumpable 策略，[原生复核](assets/r3a-nondumpable-process-after.log)。测试准备阶段曾错误断言 `/proc/PID` 目录应归 root，fixture 子进程提前失败；仅终止本测试后改正该断言，生产实现没有因这个假设变更，[准备失败](assets/r3a-nondumpable-process-before.log)。此后普通 CI 最终快照须重新核对该测试文件。

进程证明的连接持有方式也已补回归：永久保存 socket 副本会使 helper 结束原连接后，对端读不到 EOF。先测 `process_proof_does_not_keep_a_finished_helper_connection_open`，修前 WouldBlock，[失败](assets/r3a-process-proof-lifetime-before.log)；改为借用原 fd 并绑定 kernel SO_COOKIE，只在一次 broker 检查期间临时复制，另测同一进程的新 socket 替换同一个 fd 不能继承证明。Ubuntu 四个进程证明测试、clippy、release 均通过，[修后](assets/r3a-process-proof-lifetime-after.log)。04:53:04Z 修复再次安装，三服务 active、原目录保留，备份 `/var/backups/keyvalet-r3a-process-proof-20261013T045304Z`，[最新安装](assets/r3a-ndu-process-install.json)。同一真实 MCP 进程连续 10 次 locked status 读取成功（0.004342–0.008183 s），helper fd/socket 在测试前、MCP 仍活着时和退出后均为 **17/9**，认证请求 **0**，[实机复核](assets/r3a-ndu-proof-native-readback.json)。这次修复只收紧连接寿命与复用验证，没有放宽认证、角色或 ptrace。

### 本轮已复现并修复的代码问题

| 问题 / 修前复现 | 修复 | 目前验证 |
| --- | --- | --- |
| 私有 UI 取消/到期被 `ui_reply` 改写成 UI unavailable；[修前失败](assets/r3a-producer-before.log) | kv-agent `remote/agent.rs` 保留白名单取消/到期码；kv-touchid `remote_main.rs` 将明确取消/到期编码回子进程 stdout，agent 不再丢失类型 | 无 GUI 单测及工作区 CI 通过；[真实 Esc](assets/r3a-delivery-escape-native-verified.json) 为 user_cancelled，不签决定，最终按原 exp 到期、执行 0 |
| 原生认证桥把 child exit 1、进程失败等混为 denied；认证消息缺失类型；[修前失败](assets/r3a-ipc-and-auth-before.log) | 新增 kv-touchid `remote_auth.rs`，仅投影 approved/cancelled/failed/unsupported/unavailable/timeout；`remote_agent.rs` 接入；kv-platform `agent.rs` 保留 typed local codes | 注入 child/agent 单测通过；原生批准已成功，失败/取消细分尚未复验 |
| helper 的明确本地取消走错误通道，未输出 R2-D 已兼容的 cancelled；[修前失败](assets/r3a-local-result-before.log) | helper `remote/production.rs` 解码可信 typed gate error；`remote/pipeline.rs` 输出 `approval_expired + reason=cancelled`，不创建新审批；失败/等待超时保持待批路径 | [修后](assets/r3a-local-result-after.log)，工作区 CI 通过 |
| CLI 决定的私有 UI 将 `requested_scope` 写成对象，原生 renderer 要求 offered scope 字符串；[修前失败](assets/r3a-cli-decision-before.log) | helper `remote/production.rs` 使用 scope_option 字符串，并把所需 Strong 级别投影到 UI，不降低原请求级别 | [修后](assets/r3a-cli-decision-after.log)；真实 CLI 决定尚未复验 |
| Mac present 时，执行端发来的 silent 投递也被桌面跳过，延后到升级才弹窗；[修前失败](assets/r3a-local-first-before.log) | helper `remote/owner.rs` 对本机 verified present 保留桌面弹窗，仅把私有展示副本改成 banner；`engine.rs` 复用原保守 presence 计算 | [修后](assets/r3a-local-first-after.log)验证实际签名与取消不发决定；真实 OS 转换和 [Mac GET 投递/Deny](assets/r3a-delivery-escape-native-verified.json) 已验，手机 0 台，手机通知未验 |
| CLI IPC 错误无法定位具体 op / IO 阶段；[修前失败](assets/r3a-ipc-and-auth-before.log) | CLI `remote/transport.rs` / `system.rs` 附加固定 op、connect/write_request/read_response、ErrorKind；不附 URI、params 或 OS 错误原文 | [修后](assets/r3a-producer-after.log)，假 helper socket EOF 测试不依赖安装 |
| Mac agent 主线程等待私有 socket，distributed notifications 无法推进；[假 agent 修前失败](assets/r3a-presence-main-loop-before.log) | kv-touchid `remote_agent.rs` 主线程运行 CoreFoundation loop，原连接/认证逻辑移到同一进程的工作线程；保留退出码并在 worker panic 时失败关闭 | [定向回归](assets/r3a-presence-main-loop-after.log) 4/0；完整 CI 1398/0/10；23:26Z 已安装，23:47Z [完整锁屏周期](assets/r3a-presence-native-verified.json) present→away→present，锁屏→认证 away=8.160197 s、解锁→认证 present=6.782415 s |
| 指令等待超时只产生无指令 ID 的通用 IPC 错误；CLI 提示直接重试，审计不能解释结果未确认；[修前](assets/r3a-audit-closure-before.log) 新增 3 项失败 | helper `ipc.rs` 追加绑定 ID/peer/op/hash 的 `directive_wait_timeout`，不填 `result_ok`、不撤销原队列；CLI `audit.rs`/`output.rs` 展示认证快照内的超时/结果事实，先查询再决定重试 | [初次修后](assets/r3a-audit-closure-after.log) 21/0；最终 CI 1398/0/10；[安装路径复验](assets/r3a-audit-timeout-native-20261013T232726Z.json) 等待超时 10.181756 s、原 ID 晚到成功 15.759854 s、执行端应用 1 次；历史差异仍保留 |

上述修复没有改变验签顺序、档位、nonce/exp、角色表、audit-token requirement、ptrace/能力策略或 SE ACL。新的 LA typed prompt 仍只提供 UI 事实；配对/Grant/Directive/Strong 决定仍须原有 AK_s 的真实 userPresence 密钥签名。没有用 UI boolean 替代 Strong。


05:27Z 修正后的备用路径**首次真实远程批准并执行成功**：ndu native `run`/curl 收到 Mac 的 T2/Strong 网关批准与 T1/Quick GET 批准，两条均为 executed，各有 1 次 execution_started / completed。Strong scope=per_use，GET 实际 scope=per_credential（后续逐次测量须收紧或选 per_use）。已安装 `run` exit 0，当次启动到 HTTP 结果 **18.141896 s**；Graph 返回 **401**，因此真实 GET use=1、HTTP 200=0，不把它记为 API 成功。[运行收据](assets/r3a-first-run-052739.json)、[ndu 审批/audit](assets/r3a-first-run-ndu-audit.json)。按同一 helper 的毫秒 audit `ts` 测量请求发出至接收决定：Strong **5.320 s**，Quick GET **4.797 s**；内置秒级 approval_latency_ms 为 6000/5000，不能冒充精确计时。Quick 无 Touch ID，按压时间=0；Strong 的独立用户响应/按压时间未记录，不能把 5.320 s 全当按压。

从首次成功配对的第一条命令 03:16:19.887534Z 起算，首次远程 allow **7873.538466 s（131.226 分钟）**，首次 GET allow **7879.315466 s**；包括排障及本人等待，**未达到 <10 分钟**，不重新起钟隐藏这段时间。401 的具体原因仍待正常授权刷新复验，旧 token 到期时间未保存。更新驱动 [r3a-refresh-and-first-use.py](assets/r3a-refresh-and-first-use.py) 已准备，会要求原 Mac 真实 Strong 授权，保留 provider 的新 expires_at，只覆盖同一 host-restricted / proxy-only 代理，不传 refresh token，不改变审批 exp。通用同 PID/启动时间就绪桥的真实 ndu MCP 初始化和只读 status 已通过，认证/Touch ID 均 0，[预检](assets/r3a-mcp-ready-native-preflight.json)。


05:39Z 本人按 6–8 分钟更新清单开始后，Mac 正常更新短期 token **11.747488 s**，provider expires_at=**2026-10-13T06:40:05.179Z**；ndu 保存前返回 mcp_tool_rejected，未要求密码、未写入、GET 未重跑。[原收据](assets/r3a-refresh-first-054007.json)。根因是本工作流驱动在 template=bearer 请求中传入了 MCP 明确不支持的 attributes；`credential_set_impl` 在 helper 认证前拒绝该参数。该错误不归因于用户取消、密码或产品的覆盖确认。就绪 agent 曾注册并立即随客户端退出，服务保持 active。

另外，原驱动错误地把 `audit --remote` 的汇总当作原始事件列表，得到空列表后误报 matched=0 / differences=2；这些不是原生对账发现。CLI 实际 exit 0，但当时没保存其 comparison/endpoints 汇总，因此不凭推断填成 2/2。保留 [原错误采集](assets/r3a-first-run-mac-audit-collection-before.json) 与 [更正说明](assets/r3a-refresh-first-054007-errata.json)，待修正驱动重新读取。

两个驱动错误先补独立 CI 复现：模板参数 contract + 假 helper 认证调用，修前 1 failure / 修后 3 例通过，[修前](assets/r3a-refresh-params-before.log)、[修后](assets/r3a-refresh-params-after.log)；原生 audit JSON DTO 汇总、真实 finding、缺少端点三例，修前全部未通过 / 修后 3 例通过，[修前](assets/r3a-audit-report-before.log)、[修后](assets/r3a-audit-report-after.log)。修正仅在 assets 的 [参数构造](assets/r3a-refresh-params.py)、[汇总投影](assets/r3a-audit-report.py) 与现场驱动，expiry 保留在公开收据，不传不支持的保存字段。没有改 kv-mcp 或任何产品代码，没有去掉 overwrite=true / 真实覆盖确认，host/proxy-only、档位、角色、nonce/exp、audit-token 与 Strong userPresence 均保持要求。


05:56Z 修正参数后的真实复验：原生 `audit --remote` 汇总为 **matched=3 / findings=0 / unavailable=0，2 个 vault_authenticated_metadata 端点**，当前冻结快照对账 **100% / 差异 0**；不是按空列表自行推断。[原生 audit 汇总](assets/r3a-first-run-mac-audit.json)。MAC/ndu 快照各含 175/85 条事件，原生 CLI 验证并比较授权事实，后面的 B/C 新事实仍须再对账。Mac token 更新 **9.968292 s**，新 provider expiry **2026-10-13T06:56:45.885Z**；ndu 原生 MCP unlock/set 均成功、同一 proxy_only/Graph host 凭证更新完成，覆盖确认未被移除。随后 native run exit 0，**15.608164 s** 返回 HTTP **403**，[更新/运行收据](assets/r3a-refresh-first-055710.json)、[CLI 收据](assets/r3a-first-run-055710.json)。Strong/Quick 决定分别 **5.712 / 4.198 s**，均只执行一次，实际 GET scope=per_credential，[ndu audit](assets/r3a-second-run-ndu-audit.json)。gateway audit 403 没有本地拒绝的 reason 字段，与 gateway.rs 的已转发响应分支一致；403 来自上游，不记为审批拒绝。用户明确选择继续原 GET 测审批，403 单列；未自行修改 OAuth 权限或 URL。

06:13Z 本人按 8–12 分钟测量清单开始：远程切 `per_use` Strong 控制成功，CLI 到 ACK **5.566485 s**（>5 s，包含本人认证），原生 MCP 同一持久在线话取得 1 条 T1/Quick/per_use 批准并执行一次，HTTP 403；下一条得到签名 deny，MCP 准确返回 **approval_denied**，执行次数=0，驱动尊重拒绝并停止。[测量收据](assets/r3a-samples-061351.json)、[同一 helper audit](assets/r3a-samples-audit-061351.json)。这次允许样本 **19.349 s**，cohort n=1，单点 p50/p95=19.349 s，但**不满足 ≥20**、不作正式延迟验收。Quick 的 Touch ID 时间为 0；本人点击等待时间未独立测量。签名 deny 与类型化输出一致；尚未单独向本人核实第二个框的具体手势，不能凭此宣称已测 Esc 或 biometric failure。

本人随后表示要睡觉，现场窗口结束。本轮测量仅 **1 allow / 1 deny**，续等/重放/改参数尚未开始；真实 GET 累计 **3**（401 / 403 / 403），两次 gateway Strong 另计。06:21Z 核对测试 MCP/父进程均已退出、该 actor waiting=**0**，三服务仍 active，ndu 保留 `per_use`，[收尾检查](assets/r3a-night-cleanup.json)。没有为赶进度重发拒绝或留后台弹窗；**两小时合盖计时仍为 0**，用户离开电脑不是已获合盖窗口。余下现场工作等待本人再次在场。

### 醒后控制面准备中的修复（待新包实机复验）

本人明确选择「先补成两次，再实测」。旧桌面 helper 对有限 T2 返回 confirmations_left=1，CLI 在第一次标签后直接尝试签发；新 helper 对有限和常设均返回 2，第一次精确标签只交换新令牌与 1，第二次才签发。CLI 要求 2→1，检查令牌不同、同设备/同标签/同原截止时间，原 Grant exp 在第一轮后到期也立即拒绝；全部目标两轮完成且仍未到期才开始签发。未知/旧的一轮准备不做兼容降级。改动 `remote/owner.rs`、CLI `remote.rs`；[helper 修前](assets/r3a-helper-two-label-before.log)、[CLI 修前](assets/r3a-cli-two-label-before.log)、[helper 修后](assets/r3a-helper-controls-after.log)、[CLI 全回归](assets/r3a-cli-controls-regression-final.log)。第一次 CLI 复验的测试断言误写 cancelled，已按既有 user_cancelled 契约纠正，[说明](assets/r3a-cli-two-label-fixture-correction.json)，没有改产品错误契约来适配测试。

`remote <ndu> grant revoke-all` 旧解析只支持单票 revoke，现增加同一 RevokeAllGrants 的别名；不添加新的权限、调用者签名/发行者/nonce/exp 参数。`args.rs` 的 audit --limit 范围未改。[修前](assets/r3a-nested-revoke-before.log)、[修后](assets/r3a-nested-revoke-after.log)。状态 producer 旧字段只给 online，没有审批端 presence；现在只投影已验签且 120 s 内的 PresenceHint，缺失/过期保守 away，不影响投递策略、档位或签名。[修前](assets/r3a-status-presence-before.log)、[修后](assets/r3a-helper-controls-after.log)。

完整 CI 再现了旧 Strong 吊销 fixture 的 unknown_token：晚到 PairConfirm 在配对已完成时正确拒绝，但 IPC 没有把这类永久拒绝归为可确认收信；fixture 又绕过产品 IPC。因此不是单纯重跑即可关闭的记录。先用假 helper 确定性复现，[原低层路径失败](assets/r3a-late-pair-fixture-before.log)、[改走 IPC 仍失败](assets/r3a-late-pair-ipc-still-unacked.log)。修复仅在已持久审计拒绝后，对 PairAccept/PairConfirm 的 unknown_token 返回运输 ack；既有审计/存储失败仍不 ack。fixture 也使用真实 RelayInbound handler，只有字面 ack=true 才确认。目录保持原样，没有接受旧 SAS、旧 token、伪签名或新设备。[修后](assets/r3a-late-pair-fixture-after.log)。改动 `remote/ipc.rs` 与 `tests/owner_workflow.rs`，原验签/到期/角色/nonce 路径未变；新安装后还需配对/运输实机复核。

上述认证与配对相关改动没有放宽 Strong userPresence、档位、签名顺序、nonce/exp、角色、audit-token requirement 或 ptrace/能力策略；无新增依赖。新的四项 CI 与签名安装收据另列，不把 04:59 的旧快照冒充这些变更后的结果。

### 控制面实测发现的设置检查点缺口（已修复，仍待完整控制面复验）

12:59Z 原生 MCP 已读到远程 per_session，并将本地设置收紧为 per_use；原生 CLI 也读到同一后端。随后一小时 T1 Grant 在 Mac 完成真实 Strong 签发，但 ndu 以 audit_checkpoint_mismatch 回滚安装，远程 grants 查询返回 directive_result_timeout。根因是 `remote/settings.rs` 的 Backend::compare_and_write 和管理 control 使用普通 SQLite unchecked_transaction：setting_changed 记录在外层事务中写入，SQLite 提交后没有发布独立 vault 检查点。改为现有 Store::transaction，不改签名、档位、nonce/exp、调用者或任何验证规则。

先用临时目录、软件 fixture 和真实加密 vault 检查点复现：[修前](assets/r3a-settings-checkpoint-before.log) 1 个失败；[修后](assets/r3a-settings-checkpoint-after.log) 4 个审计回归通过，原 suffix rollback/缺失收据拒绝仍通过。此类 fixture 不连接本机安装、不需要 root 或 GUI。

ndu 的旧缺口仅为已确认的本地 per_use 设置记录：SQLite tip=1943，认证检查点=1942。一次性 [Linux 维护工具](../../scripts/linux/r3a-settings-checkpoint.rs) 不加入 runtime 或 IPC；绑定已观察的两个精确哈希、账户/设备和 setting_changed/by=local，要求唯一的一条后缀、整链有效且全部有独立 vault 收据，才经原 prepare/commit 协议补发检查点。正常 verify 不变，未接受任意新 tip。[三项工具回归](assets/r3a-settings-maintenance-test.log) 验证 dry-run 不写、错误锚点/记录拒绝、缺少收据拒绝。第一次 fixture 因临时根目录 0755 被原权限规则拒绝，[保留日志](assets/r3a-settings-maintenance-fixture-first.log)；改为让 Vault.prepare 创建私有子目录，没有放宽权限。

普通 sudo -u keyvalet 不带 systemd 的 TPM 附加组，初次 dry-run 安全失败；继承既有 helper 的 UID=994、GID=986、groups=108/986 后，[实机 dry-run](assets/r3a-settings-maintenance-dry-run-with-service-groups.json) 验证 1943 条记录、无写入。未改变服务用户组或能力策略。13:36:22Z 三服务停稳、完整 root-only 归档后补发该条检查点，安装修复后的 helper/CLI，再启动三服务；[备份与安装](assets/r3a-settings-repair-install.json)。没有恢复旧数据库、删除历史/nonce、重建身份或替换密钥，Strong 仍须真实 SE userPresence。此前合法签发的一小时 Grant 已由正常 relay 重投安装 1 次；[原生读回](assets/r3a-settings-native-readback.json) 显示 per_use、pending=0、unattended=false、relay connected、同 device/account，且管理 CLI 的 per_use 写入成功。原生 MCP 修复后的设置事务及整段控制面还需本人在场复验。

### 夜间 CI 复现的执行端吊销缺口（源码修复，尚未安装复验）

R3-A 对 C 的两设备拓扑补测试后，发现原 `revoke_owner_device` 的 fanout 明确排除了被吊销目标，且后续发送又过滤已经本地吊销的收件人。在线 ndu 会被 relay DELETE 断开，却没有收到审批端加密的 Strong 证明。另一方面，`revoke_device_rows` 只按 issuer/approver 撤销：当目标是本机执行身份，审批端仍活动，已批准未用请求仍为 approved_unused，Grant 仍可覆盖。修前 4 项为 **1 passed / 3 failed**，[复现](assets/r3a-executor-revocation-before.log)。其中一项使用临时真实 HTTP/WS relay 与软件测试键；另外三项使用内存 helper/假 runner，不访问安装、root 或 GUI。

修复仅在拥有的 helper remote 文件：`revocations.rs` 把目标纳入持久密文投递，并只允许该待办中的 DeviceRevoke 密文继续发往被撤销目标，随后才执行 relay DELETE；不允许给被撤销目标发 Grant/其他指令。`directives.rs` 在收到有效“吊销自己”证明时，将全部已安装 Grant 写入吊销表、取消待用请求、推进现有 epoch、清掉远程解锁并锁住会话；保留 nonce、完整审计与目录墓碑。`engine.rs` 在持有状态锁时拒绝已吊销执行身份的新请求；`grants.rs` 仅在覆盖入口检查本机墓碑，未改 R3-B 的 install/reload/签名重验证部分，迟到票或重启不能恢复覆盖。

**认证没有放宽：** DeviceRevoke 的原 AK_s Strong 证明、account/by/target/challenge 验证保持原样，Quick 证明仍拒绝；信封验签/HPKE/角色表、nonce/exp、Mac audit-token requirement、Linux 能力与 SE userPresence 均未修改。初始四项修后通过，[记录](assets/r3a-executor-revocation-after2.log)。又补了 SQLite 重启持久性与其他审批端 Grant 保留的检查；完整 CI 结果见 §3。最初持久性测试误用生产 `Store::open` 被 untrusted_state_directory 拒绝，改用仓库现有仅测试 `persistence_fixture`；未放宽生产路径权限。首轮 clippy 发现两个测试的锁变量作用域跨 await，已收窄词法作用域，[首轮记录](assets/r3a-executor-revocation-ci-summary.json)。编译/测试失败日志均保留。

以上仅证明在线测试连接会先收到证明，再收到 relay 的关闭帧。Accepted 是 relay 接收，不是目标已应用的回执；离线/背压下仍不能保证一分钟清除，不能把 CI 的耗时充作真机吊销时间。当前两端设备没有被本轮夜间工作吊销，C 完成吊销 n=0；17:26Z 反向原生命令只得到 key_unavailable（见夜间安装记录）。纯执行端 ndu 没有 AK_s，不能用 polkit/DK 冒充 relay 所需 Strong 签名；反向 owner 吊销及保留已用历史的重新配对路径仍须落实，旧的“未使用 singleton 归档”脚本不能用于本次已用身份。

## 2. 给用户的操作清单与实际记录

### 已发送并获「开始诊断」的清单原文

> Mac 的 sudo 缓存已失效，系统要求管理员密码；只读诊断脚本已备好。接下来约 3 分钟你要做的事：
> 1. 在聊天回复「开始诊断」，我再打开 Mac 的 Terminal。
> 2. 在 Mac Terminal 输入系统管理员密码，运行已准备好的只读状态与日志采集，密码不进入聊天或报告。
> 3. 等 Terminal 显示诊断完成；这一步不发起配对或 Touch ID 审批。

实际：用户回复「开始诊断」并输入管理员密码；root 状态/审计采集、两条动态代码身份检查与最后的 lsof/线程采样完成，UI 请求数 0。没有自动发起配对或反复弹审批框。

### 已发送的第一段 B 清单（用户已回复「开始」）

> 修复已安装，五次 owner IPC 检查均成功。先进行约 6 分钟的真实配对与凭证选择，接下来你要做的事：
> 1. 在 Mac 保持当前 Terminal 打开，我会运行 ndu 和 Mac 的已安装 pair 命令，看到两端安全码后再操作。
> 2. 在 Mac Terminal 核对两端六位安全码完全相同，输入 y 并回车，看到 Mac 配对确认框算成功。
> 3. 在 Mac 确认配对并按 Touch ID，看到 Terminal 显示两端 devices list 都有对方算成功。
> 4. 随后的 Mac 本地凭证解锁框再次按 Touch ID，看到凭证名称列表算成功。
> 5. 在聊天选择一个凭证名称与只读 GET URL，不发送凭证值。
> 请回复「开始」后我才运行；后续 20 次请求、控制面与吊销另约 25–35 分钟，两小时合盖另选窗口。

准备脚本 [r3a-live-pair.py](assets/r3a-live-pair.py) 已完成语法核对；用户回复「开始」后已在原 Terminal 启动，2026-10-13T02:41:56.575419+00:00；配对 URI 只在进程内存转交，收据白名单只保留两端 SAS 相等事实、用户确认、目录公开字段与计时。若产品输出新的恢复码，仅在 owner Terminal 显示，不进报告/文件/聊天。

### 已发送的继续配对清单（用户回复「开始」，本段已完成）

> 继续配对的修复与原生 CLI 已准备好，驱动已改为直接读取 Terminal 并忽略空回车。接下来约 7 分钟你要做的事：
> 1. 在 Mac Terminal 按系统提示输入 sudo 密码，看到旧的未完成候选被保留归档、凭证库校验不变。
> 2. 等待两端新安全码出现，亲自核对一致后输入 y 并回车；空回车会继续等待，输入 n 才取消。
> 3. 在 Mac 配对框确认并按 Touch ID，看到两端 devices list 有对方。
> 4. 随后的凭证解锁框按 Touch ID，看到凭证名称。
> 5. 在聊天选择凭证名称和只读 GET URL，不发凭证值。
> 回复「开始」后运行这段；不会改变任何吊销、验签或到期规则。

实际：用户回复「开始」，Terminal 执行签名 CLI 安装与候选归档；用户先输入空回车，驱动继续等待，随后收到 y；SAS 相等、owner_confirmed=true、两端目录核对成功。配对 144.164769 s，名称解锁 2.897743 s；用户随后选择 Outlook Graph 的只读 GET。ndu 已安装 Claude Code 的只读 `auth status` 显示 logged_in=true，将用 Claude Code 发起首次请求。

### 已发送的首次 use 清单（用户回复「开始」，后请求再试）

> 接下来约 6–8 分钟你要做的事：
> 1. 在 Mac 保持当前 Terminal 打开，回复「开始」后我运行首次请求脚本。
> 2. 在 Mac 对所选 Outlook 凭证的解锁与使用提示按 Touch ID，看到 Terminal 转入 ndu 凭证配置算成功。
> 3. 在该 Terminal 按 ndu 的 polkit 提示输入 ndu 用户 guang 的密码，看到代理凭证创建完成算成功；密码不要发到聊天。
> 4. Claude Code 开始请求后，若该 Terminal 再要求 ndu 解锁密码，直接在 Terminal 输入。
> 5. 在 Mac 核对来自 ndu 的 GET graph.microsoft.com/v1.0/me 请求并批准，看到 Terminal 返回一次 HTTP 结果。

实际：第一次 50.332896 s 未取得源 token，用户说明临时离开电脑并要求「你再来一次」；只读诊断后修复 non-HTTP 视图和错误分类。再试的真实 Mac 本机 T2/Strong 截图及成功 23.113006 s 已保存；随后 ndu 在 session attach 失败，HTTP 调用 0 次。没有在本人离开后重复弹窗。

### 已发送的 ndu 修复后重试清单（本人已回复「开始」）

> ndu 的会话绑定修复已安装并验证。接下来约 6–8 分钟你要做的事：
> 1. 回复「开始」后，我新开一个 Mac Terminal 运行首次请求脚本，请留在电脑前。
> 2. 在 Mac 对所选 Outlook 凭证的本地解锁、使用提示按 Touch ID，看到 Terminal 转入 ndu 配置算成功。
> 3. 在该 Terminal 按 ndu 的 polkit 提示输入 ndu 用户 guang 的密码，看到代理凭证创建完成算成功；密码不要发到聊天。
> 4. Claude Code 启动后，若该 Terminal 再要求 ndu 解锁密码，直接在 Terminal 输入。
> 5. Mac 出现来自 ndu 的 GET graph.microsoft.com/v1.0/me 审批时，选择「This request／仅本次」并按 Allow，按界面要求完成认证。
> 6. Terminal 显示 HTTP 调用 1 次、状态 200 算首次远程 use 成功；Mac 本机的 token 准备另计。

实际：本人回复「开始」，在 Mac 新 Terminal（15108）启动原生脚本；收据 [开始记录](assets/r3a-first-use-retry-start.json)。Mac token 与 ndu 保存成功，Claude provider 认证失败、工具调用 0；本人回复「我输入了，发了」。见上面的 203.139753 s 收据。

### 已发送的备用 run/curl 清单与首次结果

> 备用网关脚本已备好，复用 ndu 上仅限 Graph 的代理凭证；Claude 的 provider 认证失败另记。接下来约 4–6 分钟你要做的事：
> 1. 回复「开始」后，我在 Mac Terminal 启动已安装的 keyvalet run + curl。
> 2. 在该 Terminal 按 polkit 提示输入 ndu 用户 guang 的密码；若再次提示则按同样方式完成。
> 3. Mac 出现来自 ndu 的网关使用确认时，核对 api_key/r3a-graph-readonly，点击 Allow 并按 Touch ID。
> 4. 随后的 Mac GET graph.microsoft.com/v1.0/me 审批选择「This request／仅本次」并点击 Allow。
> 5. Terminal 显示 HTTP 200、run 退出码 0 算成功；响应体和令牌不会显示。
> 是否现在开始？

实际：本人回复「开始」，Terminal 15232 启动脚本；0.826287 s 内 unlock=false、CLI exit 1、HTTP/远程审批均 0，本人反馈没有看到解锁提示。[退出收据](assets/r3a-first-run-051738.json)、[认证诊断](assets/r3a-run-unlock-failure.json)。原驱动先运行 CLI 的立即认证，再找 PID 启动代理，认证代理来不及注册；这是现场驱动的顺序错误，不能记用户拒绝或密码错误。

先以无安装依赖的子进程/notify-fd 测试复现早启动、agent 注册失败、注册超时三个用例：[修前](assets/r3a-run-agent-order-before.log) 3 个用例未通过（2 failure / 1 error）；改为先等系统注册通知并确认 agent 仍运行，[修后](assets/r3a-run-agent-order-after.log) 3 个通过。修正驱动 [r3a-first-use-run.py](assets/r3a-first-use-run.py)、[代理](assets/r3a-run-agent.py)、[就绪桥](assets/r3a-run-readiness.py)。owner 进程先公布 PID/内核启动时间，代理只针对这两个值注册，成功后 exec 已安装 CLI，保持原 PID 与 UID；不通过 root wrapper 改变该主体。真实 ndu pkttyagent 注册预检 exit 0，认证请求/凭证请求/Touch ID 均 0，[预检](assets/r3a-run-agent-native-preflight.json)。未修改产品身份验证、polkit 策略或软件；修正后的真实 use 仍需本人开始。

### 修正启动顺序后的已发送清单

> 修正后的脚本已准备好。接下来约 4–6 分钟你要做的事：
> 1. 回复「开始」后，我在 Mac 打开新的 Terminal。
> 2. 等 Terminal 显示“ndu polkit 代理已就绪”，再按密码提示输入 ndu 用户 guang 的密码；密码只在 Terminal 输入。
> 3. Mac 出现来自 ndu 的 api_key/r3a-graph-readonly 网关确认时，点击 Allow 并按 Touch ID。
> 4. Mac 随后出现 GET graph.microsoft.com/v1.0/me 审批时，选择“This request／仅本次”并点击 Allow。
> 5. 等 Terminal 显示 HTTP 状态和退出码；HTTP 200 且退出码 0 算成功，其他结果我会据实诊断。
> 是否现在开始？

本人回复「开始」，执行修正后的同 PID/UID 就绪屏障驱动；最终结果另记，不预先算批准。

### 最新更新清单（已开始并完成）

> 脚本已修正，接下来约 6–8 分钟你要做的事：
> 1. 回复「开始」后，我打开 Mac Terminal；按系统提示在 Terminal 输入 Mac 管理员密码，随后看到原生双端审计的匹配数和差异数。
> 2. Mac 提示使用所选 Outlook 凭证更新短期 token 时，点击 Allow 并按 Touch ID。
> 3. Terminal 提示更新 ndu 的 Graph 代理凭证时，输入 ndu 用户 guang 的 polkit 密码，并按后续提示确认覆盖。
> 4. 看到“同一代理凭证更新完成”后，在 Terminal 输入随后出现的 ndu 解锁密码。
> 5. Mac 出现来自 ndu 的网关确认时，核对 api_key/r3a-graph-readonly，点击 Allow 并按 Touch ID。
> 6. Mac 出现 GET graph.microsoft.com/v1.0/me 时，选择“This request／仅本次”并点击 Allow。
> 7. Terminal 显示 HTTP 200 且 run 退出码 0 算 API 复验成功。
> 是否现在开始？

实际：本人回复开始；Terminal 15761 完成原生审计、更新与 GET，API 403，没有写成 200；实际 GET scope=per_credential。本人明确选择沿原 GET 继续测审批，403 单列。

### 最新测量清单（已开始，未满 20 次）

> 接下来约 8–12 分钟你要做的事：
> 1. 回复「开始」后，我打开 Mac Terminal；若要求 Mac 管理员密码，在 Terminal 输入。
> 2. Mac 确认把 ndu 切为 per_use 时，按提示完成 Touch ID。
> 3. Terminal 出现 ndu polkit 解锁时，输入 ndu 用户 guang 的密码。
> 4. Mac 连续出现 20 次相同 GET /v1.0/me 时，每次点击 Allow／仅本次；这些 Quick 请求无需 Touch ID，HTTP 403 单独记录。
> 5. Terminal 显示“拒绝用例”后，在下一条 Mac GET 框点击 Deny。
> 6. Terminal 显示“续等用例”后先别操作该框，等“已进入 credential_wait_approval”出现再点击 Allow。
> 7. 同一批准的第二次领取无需你操作，应返回 already_consumed。
> 8. Mac 出现新 GET /v1.0/me?$select=id 时，核对查询参数变化后点击 Allow。
> 9. Terminal 显示测量段完成算本段结束，我会用 helper audit 计算 p50/p95 并核对执行次数。
> 是否现在开始？

实际：本人回复开始；Terminal 16023 中远程 per_use 生效，一次 GET 批准、第二次签名拒绝，驱动停止，不自动重试。本人之后表示要睡觉；已保存部分数字并核对 actor 退出、waiting=0。没有把未执行的续等、重放和改参补成成功。

### 醒后继续清单与 20 次实际记录

> 接下来约 10–15 分钟你要做的事：
> 1. 回复「开始」后，我打开 Mac Terminal；如提示管理员密码，在该 Terminal 输入，看到双端审计结果。
> 2. Mac 出现所选 Outlook 凭证的解锁或 token 更新提示时，点击 Allow 并按 Touch ID。
> 3. Terminal 提示更新 ndu 的 Graph 代理凭证时，输入 ndu 用户 guang 的 polkit 密码，并确认覆盖。
> 4. Mac 提示把 ndu 设为 per_use 时，确认并按 Touch ID。
> 5. Terminal 再提示 ndu 解锁时，输入 ndu 用户 guang 的密码。
> 6. Mac 连续出现 20 次 GET /v1.0/me 时，每次选择“This request／仅本次”并点击 Allow；这些 Quick 请求无需 Touch ID，上游 403 单列。
> 7. 仅当 Terminal 显示“拒绝用例”后，在下一条 Mac GET 框点击 Deny。
> 8. Terminal 显示“续等用例”后先不操作，等“已进入 credential_wait_approval”出现再点击 Allow。
> 9. 同一批准再次领取无需操作，看到 already_consumed 算重放被拒。
> 10. Mac 出现 GET /v1.0/me?$select=id 时，核对新参数并选择仅本次批准，看到 Terminal 显示测量段完成算结束。
> 密码只在 Terminal 输入，不发到聊天。是否现在开始？

本人回复「开始」，09:00:55Z 打开 Terminal 16374。原生双端 audit 9/9 匹配、差异 0；按产品正常刷新短期 Graph token（12.164878 s），到期 10:01:26.779Z，公开 scopes 为 openid/email/Mail.Read/IMAP.AccessAsUser.All/profile，没有 Graph User.Read；保留本人选定 GET，不扩大 OAuth 权限。代理覆盖成功。再次 per_use 指令 5.332671 s；随后 20 次同一 GET 均 HTTP 403、T1/Quick/per_use、各执行 1 次。helper audit request→accepted 的 p50=3.0905 s、p95=6.0237 s（线性分位数）；Quick 不需要 Touch ID，0 s 单列，用户点击等待没有独立计时。见 [更新收据](assets/r3a-refresh-samples-090330.json)、[20 次收据](assets/r3a-samples-090330.json)、[原生 audit](assets/r3a-samples-audit-090330.json)。

第 21 条宣布拒绝的请求实际收到签名 allow，HTTP 403、执行 1 次，驱动按 sample_denial_not_observed 停止；已询问本人实际按钮，尚未把它归因为 producer bug 或算作拒绝通过。20 次同质样本不含这条。该 actor 已退出、waiting=0；用户关闭原 Terminal，原批准窗口内另开负面用例续测，在每条请求前等待 Terminal 回车，不重复 20 次。续等/重放/改参结果待回读。

### 负面用例续测的短清单（本人已回复「开始」）

> 接下来约 4–6 分钟你要做的事：
> 1. 回复「开始」后，我打开新的 Mac Terminal。
> 2. Terminal 显示“拒绝用例”时按一次回车；随后若提示 ndu 密码，输入 ndu 用户 guang 的密码，再在 Mac GET 框点击 Deny。
> 3. Terminal 显示“续等用例”时按回车，随后先不操作 Mac 框，等“已进入 credential_wait_approval”出现再点击 Allow／仅本次。
> 4. 同一批准再次领取无需操作，看到 already_consumed 算成功。
> 5. Terminal 显示“改参数用例”时按回车，在新的 GET /v1.0/me?$select=id 框选择仅本次并点击 Allow。
> 6. Terminal 显示“负面用例段完成”算结束。
> 是否现在开始？

现场暂停最初与 SSH 同时读取 Terminal，回车被 SSH 读取，未发新审批；假进程/pipe 测试复现 [修前](assets/r3a-terminal-lifecycle-before.log)，改为先结束输入代理、读到回车后重新注册，三个用例 [修后](assets/r3a-terminal-lifecycle-after.log) 通过。仅暂停 SSH 的尝试没有解决正在等待的读取，[未通过](assets/r3a-terminal-input-after.log) 保留；未部署该尝试。真实 Terminal 16907 的回车、ndu polkit 和明确 Deny 成功，approval_denied / execution=0，helper 9.983 s、调用含初始解锁 13.732512 s。[收据](assets/r3a-negative-092409.json)。下一条在 6.589 s 已取得 allow，尚未走到默认等待预算结束，因此该次不算续等通过。

原窗口内继续余下用例，把该 MCP 进程的 KEYVALET_WAIT_IN_CALL_S 设为 5；只改变首调用等待预算，不改变 request exp、档位或任何验证。13.655479 s 的首调用（含初始本地解锁）返回 approval_pending，沿用 ID 续等 12.029520 s 返回 HTTP 403；同 ID 再领 0.005954 s 返回 already_consumed，未重新执行；加 $select=id 后有不同审批 ID/query_keys，执行 1 次。[续等收据](assets/r3a-wait-092752.json)、[原生 request/decision/execution 核对](assets/r3a-wait-native-readback.json)。本轮重放是批准结果再次领取，不能称为重发截获的密文。累计 GET=27（401×1 / 403×26），API 200=0；待批与测试进程均清空。

### 控制面现场清单（本人已回复「开始」，正在执行）

> 接下来约 8–12 分钟你要做的事：
> 1. 回复「开始」后，我打开 Mac Terminal；若提示管理员密码，在那里输入，看到新包安装与 owner IPC 检查成功。
> 2. Mac 提示把 ndu 切为 per_session 时，确认并按 Touch ID。
> 3. Terminal 提示 ndu 解锁时，输入 ndu 用户 guang 的 polkit 密码，看到本地 MCP 设置与远程模式一致。
> 4. Mac 提示给 api_key/r3a-graph-readonly 签发一小时授权时，确认并按 Touch ID。
> 5. 等 Terminal 自动完成授权列表、全部收回、lock 和状态查询。
> 6. Mac 出现“无人值守／含敏感操作”确认时，核对目标 ndu 和一小时范围，确认并按 Touch ID。
> 7. Terminal 第一次要求执行端标签时，照提示输入完整标签并回车；第二次再输入同一标签并回车。
> 8. 最终签名若再要求 Touch ID，在 Mac 完成，看到 ndu unattended=true 算签发成功。
> 9. 等 Terminal 显示测试授权已收回、ndu 为 per_use、unattended=false 和双端审计结果，算本段结束。
> 密码只在 Terminal 输入，不发到聊天。是否现在开始？

12:37Z 准备复核：Mac 四个 staged 二进制均与签名收据哈希匹配，严格 team/identifier requirement 均 exit 0；agent/relay 仍 running。ndu 三服务 active，本地模式为 per_use。356 份源码与 11:02:44Z 四项 CI 快照一致。本人说「继续吧，r3-a」后重新发送本段清单，等明确「开始」再触发现场请求。12:43:41Z 本人回复「开始」，打开 Terminal 20925（ttys009），运行 `r3a-start-controls.py`。[Mac 安装](assets/r3a-controls-install-124348.json) 三服务 running、owner IPC 5/5（14–19 ms），status 119.996 ms。

首个驱动仅给全量 audit 30 秒，超时冒泡后尚未发任何控制请求即停止，[原始收据](assets/r3a-controls-124418.json)。假 subprocess 测试 [修前](assets/r3a-controls-audit-before.log) 失败，改为独立记录超时后 [修后](assets/r3a-controls-audit-after.log) 3 个通过；后续采集预算 120 秒不改变产品 request exp。原生双端 audit 实际 38.366326 秒、37/37 匹配/差异 0，[完整快照](assets/r3a-native-audit-extended-125228.json)。

per_session 原生指令/ACK=5.719533 秒，本地 CLI 读回相同模式；第一次 MCP 认证之后返回工具失败，记录 mcp_tool_rejected，未归因于用户未输密码。本人明确回复「输入了，并显示认证完成」。原窗口续测时原生 MCP 读取 per_session=3.110717 秒、收紧 per_use=0.008623 秒，两个方向共用设置后端的事实成立；[续测收据](assets/r3a-controls-130015.json)。Mac 一小时 Strong Grant 签发=3.141659 秒、本机 grant list=0.043336 秒；随后远程 grants=11.176476 秒/退出 4/directive_result_timeout，执行端安装被检查点规则拒绝。因此签发耗时单列，不能称批准后立即安装成功。控制面停止在 revoke-all/lock/unattended 之前，未自动重发 Strong；本人获知转入无人值守修复，可以离开电脑。后续维护恢复及安装见 §1；剩余现场用例须再次发清单并等待开始。

### 设置事务修复后的控制面清单（本人已开始，14:36–14:37Z 实测）

> 接下来约 8–12 分钟你要做的事：
> 1. 回复「开始」后，我打开 Mac Terminal；若提示 Mac 管理员密码，在该 Terminal 输入，看到修复包安装与五次 owner IPC 检查成功。
> 2. 等 Terminal 完成审计与旧测试授权收回，Mac 提示把 ndu 切为 per_session 时，确认并按 Touch ID。
> 3. Terminal 提示 ndu 解锁时，输入 ndu 用户 guang 的 polkit 密码，看到原生 MCP 读取 per_session 并收紧为 per_use。
> 4. Mac 提示给 api_key/r3a-graph-readonly 签发一小时授权时，核对目标并确认、按 Touch ID，看到远程 grants 查询返回该授权。
> 5. 等 Terminal 自动完成 revoke-all、lock、status/pending/grants/audit 查询，看到每项退出码。
> 6. Mac 提示一小时“无人值守／含敏感操作”时，核对执行端和一小时范围，确认并按 Touch ID。
> 7. Terminal 要求标签确认时，两次输入它显示的完整执行端标签并回车，看到进入最终签名。
> 8. 最终签名若要求 Touch ID，在 Mac 完成，看到 ndu unattended=true。
> 9. 等 Terminal 显示授权已收回、ndu 为 per_use、unattended=false 和双端审计数字，算本段结束。
> 密码只在 Terminal 输入，不发到聊天。是否现在开始？

驱动为 `r3a-start-settings-controls.py`，先运行 `r3a-install-settings.py` 安装匹配签名包并检查 IPC，再运行已隔离 audit 超时的 `r3a-controls.py`；一次性维护工具已从 ndu 安装目录移除，root-only 备份及源码仍保留。运行时能力复核：helper/relay 的 effective/permitted/ambient 全为空，peer broker 三者均只有 0x80000（SYS_PTRACE），[记录](assets/r3a-settings-capabilities-and-cleanup.json)。没有新增能力或修改策略。Mac 签名包于 14:36:18Z 安装，三服务 running，owner IPC 5/5 成功（14.178–27.654 ms），[安装](assets/r3a-settings-install-143621.json)。本人说「开始」后在 Terminal 22031 执行本段；[完整收据](assets/r3a-controls-143754.json)记录 11 条成功命令，以及无人值守退出 5 / ipc_unavailable。


实际：原生 MCP 读取 per_session（12.915432 s，包含 polkit）并收紧为 per_use（0.016881 s）；本地 CLI 与远程 status 双向核对通过，checkpoint 修复完成实机复验。一小时 T1 Grant 01M4TV4S3G3V4JQJKS47GWPP8Y 在远程 grants 中可见，随后 revoke-all 返回 grants_n=0，远程 grant 元数据保留 revoked_at。grant list=0.052712 s；status/pending/grants/audit=2.958694/2.733293/2.801576/3.890948 s。无人值守准备已到第一次原生标签提示，但 3.135483 s 内退出 ipc_unavailable，没有完成两个标签或最终 Grant；没有把它计通过。用户反馈 Touch ID 次数过多。15:04Z 只读 ndu 状态确认 per_use、pending=0、grants=0、unattended=false，[收尾状态](assets/r3a-controls-post-failure-ndu-status.json)。

**额外认证的已确认代码原因与修复：** ProductionRunner::local_authorize 把所有 owner Directive（含 Quick 查询及每一页 QueryAudit）都路由到 authenticate，Strong 则之后还执行真实 AK_s 签名。先写假 OwnerUi 回归，[修前 2 项失败](assets/r3a-owner-ui-confirmation-before.log)；改为真实操作确认后签名，并让已认证 owner 的四类元数据查询直接保留 Quick，仍由 publish_directive 用原 AK_q 签名。查询静默测试也先失败，[修前](assets/r3a-query-no-prompt-before.log)。普通确认只认 confirmed=true；错误/取消无权签发。没有 Strong 键时即使确认成功仍 key_unavailable、issued=0；旧 raw Directive 认证路径保留。修改文件为 remote/production.rs 与 tests/owner.rs；新包尚待安装和实机复验，不把 CI 当用户实际 Touch ID 次数。

**标签终端修复准备：** 当前收据只保留固定 ipc_unavailable，丢失底层错误阶段，不能凭 3 秒就断言 helper 不可用。CLI 标签通过 /dev/tty，驱动却用捕获 stdio 的 sudo 子进程；假 CLI 的前台终端用例修前失败，新的 root 驱动先取得已授权 sudo，再为 CLI 建独立前台 PTY，CLI JSON 走独立内存管道，原生提示和本人输入在 Terminal 转交。[修前](assets/r3a-label-command-before.log)、[修后 3 项](assets/r3a-label-command-after.log)。不代填标签、修改 token/PID 绑定或延长期限；签名与两轮确认仍由已安装 CLI/helper 执行。真实进程组预检与 T2 两轮尚待下一段开始；仍按现场未通过计。驱动新增 --unattended-only，引用本轮成功收据，不重复已完成的控制。

**审计收据修正：** 本段开头原生 audit exit=3 被驱动压成 native_audit_unavailable；原 CLI 用 exit=3/ok=false 也会返回真实的不一致报告。新增失败回归后保留这类报告的匹配/差异/不可达数字，[projection 修前](assets/r3a-audit-inconsistent-before.log)、[修后](assets/r3a-audit-inconsistent-after.log)、[collector 修前](assets/r3a-controls-audit-inconsistent-before.log)、[修后](assets/r3a-controls-audit-inconsistent-after.log)。旧 37/37 是 12:52Z 冻结快照；当前控制之后的完整对账仍未取得，不能外推差异 0。

### B/C 清单草案（尚未发送，不能视为已获「开始」）

现场链路排障、修复包安装与测量脚本全部就绪后，发送最终「接下来 30–40 分钟」版本；以下不授权现在触发 UI：

1. 在 Mac Terminal 输入管理员密码安装签名修复包，看到三服务与 owner IPC 检查成功。
2. 在 ndu Terminal 执行 `keyvalet pair --new`，在 Mac 加入该链接，看到两端六位 SAS。
3. 核对两端 SAS 完全相同后确认，点击 Mac 配对确认并按 Touch ID，看到两端 devices list 有对方。
4. 在 Mac 查看凭证名称并选定只读 GET 凭证/URL，按所需 Touch ID 完成配置，看到 ndu 只有已选测试凭证。
5. ndu 发起首次实际请求，在 Mac 核对来源、主机、方法与范围后批准，看到 ndu 返回一次结果。
6. 连续完成至少 20 次相同请求的 Mac 审批，看到每个 ndu 请求恰好一份结果，分别记录 UI/Touch ID 与端到端时间。
7. 在 Mac 拒绝一条请求、取消另一条请求并完成一个认证失败用例，看到各自准确的本地/远端结果。
8. 一条请求先等到调用预算结束，再批准并续等，看到原请求只执行一次、再次领取被拒、改参数出现新审批。
9. 在 Mac 完成切模式、1 小时票、查询、全部收回与 lock 的确认，看到 ndu 的设置/授权状态随回执改变。
10. 在 Mac 完成 unattended 的实现要求确认与标签输入，看到 ndu 状态与 T2 审计；有限票与常设两轮须分开记录。
11. 在 Mac 保持在场、随后锁屏，看到 ndu 的 PresenceHint/Directive 状态变化，手机现象由 R3-C 另验。
12. 在 Mac 完成吊销所需 Strong/标签确认，看到 ndu 的待用决定/Grant 失效，完成反向吊销能力核对与两端 audit 对账。
13. 按实际重新配对路径再核对 SAS 并按 Touch ID，成功后再约定合盖的两小时窗口。

没有在产品尚未支持的动作上伪造按钮、标签轮数或完成记录。只读 GET 默认是 T1/Quick，现场必须区分正常 Quick 样本与实际 Strong 签名，不能把按钮点击时间冒充 Touch ID 时间。

### 审计与在场修复的真实安装及锁屏补测清单

本人回复「开始」，按文末 5–7 分钟清单完成系统管理员认证、安装、只读超时用例及真实屏保/解锁。23:26:34Z 新包实际安装，owner IPC 5/5 成功（15.956–28.209 ms），三服务 running；[安装收据](assets/r3a-audit-presence-mac-install-20261013T232634Z.json)。只读 query_grants 等待超时后原 ID 收到晚到结果，应用次数为 1；[实机收据](assets/r3a-audit-timeout-native-20261013T232726Z.json)。本段未发凭证请求、KeyValet Touch ID=0。

首段 [真实 OS 观察](assets/r3a-presence-transitions-20261013T233228Z.json) 共 216 次读取（present=149、away=67）、4 个系统通知；解锁至首个认证 present=7.574238 s。第二轮锁屏未完成前，观察窗口 300 s 到期；保留原错误，不能把已恢复 present 当作整个在场投递验收。发现 SSH 状态轮询继承 Terminal stdin，可能与本人回车竞争；先用假 SSH 测试复现 2 项失败，再改为 stdin=DEVNULL，修后 2 项通过，不接触产品授权预算。

随后发送并获「开始锁屏验证」的清单原文，入口和授权记录见 [Terminal 收据](assets/r3a-presence-measure-terminal.json)：

> SSH 输入占用已修正，2 项无安装依赖的回归通过；在场已恢复 present，现在只补一轮锁屏计时。接下来约 2–3 分钟你要做的事：
> 1. 回复「开始锁屏验证」后，我在 Mac Terminal 运行只观察脚本，无需 sudo 或再次安装。
> 2. 等 Terminal 显示 baseline=present，再按 Control+Command+Q 锁屏，等 10 秒后正常解锁 Mac。
> 3. 回到同一 Terminal 按一次回车，看到 after_measured_unlock=present 和“在场信号诊断结束”算完成。
> 不发凭证请求，KeyValet Touch ID 请求为 0；系统解锁按日常方式完成。现在开始吗？

该轮 [真实收据](assets/r3a-presence-transitions-20261013T234012Z.json) 32 次均为 present，但解锁检查开始早于系统 locked 通知；locked 后仅观察约 1.5 s 就结束，没有 unlocked 通知或 away 样本，不记通过。新增提前回车的假事件/假 SSH 回归，修前 2 passed/1 failed、修后 3 passed/0 failed；脚本现在必须等真实 locked→unlocked 以及认证 away→present 读回，回车不作为解锁证据。修复仅为证据采集脚本，未改 Rust 产品或审批 TTL。

修正后的清单已发送并获新的「开始锁屏验证」，23:46:49Z 在同一 Terminal 开始、23:47:42Z 完成；[就绪与清单原文](assets/r3a-presence-measure-ready.json)、[启动与授权](assets/r3a-presence-measure-terminal-retry.json)：

> 锁屏观察脚本已修正，3 项假进程回归通过。接下来约 2–3 分钟你要做的事：
> 1. 回复「开始锁屏验证」后，我在 Mac Terminal 启动观察，无需 sudo、安装或 KeyValet Touch ID。
> 2. 等 baseline=present 后，按 Control+Command+Q 锁屏，保持 10 秒再正常解锁。
> 3. 回到同一 Terminal 按一次回车，等“在场信号诊断结束”；脚本会等真实锁屏、解锁和 ndu 状态读回，提前回车也不会结束。
> 现在开始这轮锁屏观察吗？

实际 [完整锁屏周期](assets/r3a-presence-transitions-20261013T234742Z.json) 收到真实 locked/unlocked 通知各 1 次，回调均在主线程；39 次认证读回（present=19、away=20），baseline 与最终 after_measured_unlock 均为 present，fixed_error=null。实际锁屏持续 28.473942 s；锁屏至远端首个 away=8.160197 s，解锁至远端首个 present=6.782415 s。功能转换通过，远端读回没有达到 5 s；包含信号处理、传输和 SSH 采样，不能当作本地 PresenceProbe 独立计时。无 sudo、安装、凭证操作或 KeyValet Touch ID，未验证手机通知或真实审批路由。[汇总](assets/r3a-presence-native-verified.json)。

## 3. 验收表

| 项目 | 结果 | 数字 | 证据 / 尚缺的测量 |
| --- | --- | --- | --- |
| pair → 首次远程批准 <10 分钟 | 真批准/执行通过；耗时未达标，API 401 | pair=1 / 144.164769 s；首次 allow=7873.538466 s；GET=27、HTTP 200=0 | [配对](assets/r3a-pair-031844.json)、[首次运行](assets/r3a-first-run-052739.json)、[audit 计时](assets/r3a-first-run-ndu-audit.json) |
| p50 <3 s / p95 <8 s，≥20 次 | 20 次已完成；p50 略超阈值、p95 达标 | n=20；p50=3.0905 s / p95=6.0237 s；20/20 T1 Quick、per_use、执行各 1 次；Quick Touch ID=0 s | [测量](assets/r3a-samples-090330.json)、[audit](assets/r3a-samples-audit-090330.json)；包含用户点击等待，未独立测点击耗时 |
| 拒绝/续等/重放/改参数 | 通过；重放是同一批准再次领取 | deny=3 / execution=0；wait=1 / execution=1；reclaim=1 / already_consumed / 0.005954 s；query-change=1 / 新 ID / execution=1 | [原 Deny](assets/r3a-negative-092409.json)、[新增 Mac Deny/Esc](assets/r3a-delivery-escape-native-verified.json)、[续等/重领/改参](assets/r3a-wait-092752.json)、[含 query_keys 的 audit](assets/r3a-wait-native-readback.json) |
| 双向吊销 ≤60 s | 正向达标；反向真机因缺少 AK_s 拒绝 | 正向完成=1；命令=9.100511 s、从命令开始到 ndu 失效读回=10.583576 s；待用批准 approved_unused→cancelled、执行 0，Grant revoked；反向完成=0 / key_unavailable / 0.226363 s（含 SSH） | [真实正向吊销](assets/r3a-se-revocation-native-verified.json)、[完整收据](assets/r3a-remaining-native-20261014T051814Z.json)、[反向预检](assets/r3a-executor-revocation-ndu-preflight-native.json)；已使用历史保留，未重置身份或重新配对 |
| 两端 audit 100%，差异 0 | 最后完整双端对账未通过；吊销后无法取得完整远程快照 | 吊销前完整 53/54=98.148148%，findings=1、端点=2/unavailable=0；吊销后 ndu 端点=1/unavailable=1、matched=0、findings=53，不能作为新完整双端差异；Mac 非交互 sudo 不可用；旧冻结快照 37/37=100% | [完整双端审计](assets/r3a-audit-timeout-native-20261013T232726Z.json)、[吊销后原生只读尝试](assets/r3a-post-revocation-native-audit.json)；新超时/晚到成功应用 1 次，旧 query_grants 缺接收记录未补造或过滤 |
| 合盖 2 小时积压送达、不重复、正确 expired | 本人取消实测，改为源码 review；未计实测通过 | 合盖计时=0 s、请求=0；原 review 缺口 1 项；当前共享源码已有入站持久化/恢复、相关 CI 7/7，当前 Mac helper 未部署该项 | [原 review](assets/r3a-lid-code-review-20261014.json)、[源码与部署边界复核](assets/r3a-lid-review-followup-20261014.json)；普通睡眠与 helper 重启是不同边界 |
| 三项远程控制各 <5 s | 最新一小时 Strong 签发超阈值；切模式/收回达标 | per_session=4.760682 s；最新 allow_1h=6.162329 s（此前 2.777137 s），吊销前已安装；最新 revoke-all ACK=4.992178 s（此前 2.817435 s）；lock=3.300604 s | [最新 Grant 签发及安装](assets/r3a-remaining-native-20261014T051814Z.json)、[原三项](assets/r3a-controls-143754.json)、[最新 revoke-all](assets/r3a-controls-213127.json)；含本人确认/Touch ID，签发到安装未独立计时 |
| 有限 T2 两轮标签及真实 Strong | 通过，已收回测试授权 | 成功=1；签发=16.629137 s（含人工确认/两轮标签/签名）；unattended=true/grants=1 → false/0；最终 per_use | [原生收据](assets/r3a-controls-213127.json)、[清单原文](assets/r3a-t2-return-retry-terminal.json)；此前 40.610067 s user_cancelled 与 190.074093 s 超时均保留 |
| 本机优先 / 锁屏 away | Mac 实际投递与锁屏转换已验；手机静默/横幅待 R3-C | 实际 present→Mac GET→Deny=1 / 5.038746 s、执行 0；已配手机=0，不能据此计手机静默通过；完整周期 39 次 present=19/away=20，锁屏→认证 away=8.160197 s、解锁→present=6.782415 s | [完整真实周期](assets/r3a-presence-native-verified.json)、[原始记录](assets/r3a-presence-transitions-20261013T234742Z.json)；[本轮实际投递](assets/r3a-delivery-escape-native-verified.json)；原 51 次 away 保留，重启后的初值限制仍开放 |
| SE 取消／biometric failure producer | 原生系统取消保真通过；认证失败仅软件验证 | 系统 Touch ID 取消=1 / key_operation_cancelled / 10.485434 s，新 Grant=0；真实 biometric failure=0；child 回归=3/3、NSError 分类=12/12 | [完整 installed path 取消](assets/r3a-se-revocation-native-verified.json)、[子进程回归](assets/r3a-se-child-hop-after.log)；不能把软件认证失败测试算作硬件实测 |
| 最终四条 CI | 当前整合源码全绿；原生安装包组件来源分别保留 | 四项 exit 0；1416 passed / 0 failed / 10 ignored、69 组；526 份源码/构建输入检查期间未变；clippy 额外 locked、Cargo 离线保护 | [06:02Z 全绿](assets/r3a-se-child-closure-ci9-summary.json)、[完整 test](assets/r3a-se-child-closure-ci9-test.log)、[最终源码核对](assets/r3a-final-source-check-ci9-20261014.json)；安装包继续按 ci5/既有组件快照溯源，未为新 Windows UI 再安装 |

使用 `rust/target-r2a` 和三项规定的 Cargo 环境变量。当地默认 stable 是 1.90.0；从官方 stable manifest 核对当前为 1.99.0（2026-10-01），四项均用 `cargo +1.99.0`。non-HTTP 修复后的首次 workspace test 在 Strong 吊销 fixture 的队列投递阶段报 unknown_token（晚到 PairConfirm 是目前怀疑，未完成稳定复现）；保留 [首次失败](assets/r3a-non-http-first-workspace-test.log)，该用例单独重跑通过，[单例日志](assets/r3a-ci-revoke-followup.log)，源码未变的整套重跑 03:56:43Z 通过（1345/0/10），[快照](assets/r3a-source-after-non-http-ci.json)。不删除失败或把重跑说成首次全绿。进程证明修复后的四项检查在 04:24:05Z 全部通过（1347/0/10）；连接关闭与 nondumpable fixture 修正后的当前四项检查在 **04:59:42Z 全部通过（1347/0/10，69 组）**，28 份 R3-A 源码在检查期间未变，[当前哈希](assets/r3a-source-after-proof-lifetime-ci.json)、[当前汇总](assets/r3a-final-ci-summary.json)。普通 CI 不需要安装、root 或 GUI；Root 跨 UID 测试为 ignored，并单独运行记录。

四个原生 release 二进制已构建并在 `rust/target-r2a/r3a-native-staging/bin` 用现有 Developer ID 签名；四份严格 team/identifier requirement 检查均通过，[签名构建收据](assets/r3a-signed-build.json)。四个二进制已覆盖安装并完成上面的 5/5 owner IPC 读取；resume CLI 也已安装。实际配对已通过，真实 GET 已批准执行 27 次、API 状态 401×1 / 403×26；不把源码测试记为远程批准。

## 4. 本地结果 producer 核对

| 输入事实 | 本轮 producer 行为 | 与 R2-D/MCP 的关系 |
| --- | --- | --- |
| 远程 Mac 对话框明确「拒绝」 | 生成按原最低级别签名的 deny 决定；执行端 denied | 正确，不能用取消/失败代替该决定；09:23Z Deny 执行 0；01:04Z 再验 approval_denied / 执行 0，5.038746 s |
| 远程 Mac 对话框 Esc | typed `remote_action_cancelled`，不签决定，保持原审批待批，到 exp 后 expired | 01:05Z 原生审计 remote_ui_rejected/user_cancelled，与 ndu waiting/执行 0 一致；关闭 UI 不等于撤销请求，不能提前报用户拒绝 |
| 明确本地 LA 取消 | typed `local_approval_cancelled` → `approval_expired + reason=cancelled` | MCP 已把该兼容形状解码为 cancelled；新 helper 单测验证 |
| LA 认证失败/锁定 | typed failed，不能 denied；保留已有未授权/待批路径 | CI 证明不混为拒绝；原生失败用例待测 |
| UI/transport 等待预算结束 | timeout/unavailable，exp 前仍待批 | 不提前改成 request expired 或 denied |
| request exp 到期 | 原 helper 到期状态机输出 expired | [原生 Esc 请求自然到期](assets/r3a-escape-expiry-native.json)，执行 0；两小时合盖实测已取消 |
| 允许普通确认后，取消系统 SE Touch ID | typed `key_operation_cancelled`；不签发 Grant | 05:16Z 完整 installed path 通过，10.485434 s、新 Grant=0；与拒绝及认证失败分开 |

**SE 细分的当前状态：** 六文件错误保真修复、额外 child hop 修复均已获本人明确授权，见 [六文件授权](assets/r3a-se-failure-scope-authorization.json)、[后续跨文件授权](assets/r3a-se-child-hop-scope-authorization.json)。fake FFI/agent 修前 3 项失败，修后通过；额外子进程桥修前 1 passed/2 failed，修后 3/3。01:05Z 系统取消仍 key_operation_failed / 8.531664 s 的失败保留。05:14Z 安装新 agent 后，05:16Z 同一 installed path 已真实返回 **key_operation_cancelled / 10.485434 s，新 Grant=0**；[实机证明](assets/r3a-se-revocation-native-verified.json)。`key_authentication_failed` 的原生最终认证失败仍未测；单次指纹不匹配但系统继续等待不等于最终失败。未知 NSError domain/code、崩溃/超时或有异常输出仍为通用失败，不从英文文本猜用户行为。原 Strong userPresence ACL、签名、role、nonce/exp、私有通道 audit-token requirement 均未放宽。

## 5. 所有权外变更请求

1. SE signer 的取消/认证失败细分：本人已授权六文件最小例外及后续 R3-A 必要跨文件修复，并要求不再逐次询问，见 §4。agent.rs 例外已应用且真机 SE 取消通过；此次仅保留系统明确错误，没有扩展角色/授权规则。
2. macOS presence 冷启动屏保/锁屏 unknown 位于原所有权外的 `kv-platform/src/presence/**`；后续必要修复已在本人授权范围内。当前保守 away 的初值限制仍存在，真实 OS 转换可恢复；未直接强制 present 或注入通知。
3. 后续 R3-A 必要的 daemon/main 跨文件修复同样已有本人授权；本轮未修改 `kv-helper/src/{main,daemon}.rs`，仍要求先有可复现证据，不放宽认证边界。
4. R3-C 的 mobile CI：两次 workspace 中 `executor_audit_is_bounded_metadata_and_stays_separate_from_local_issued_history` 在 tests.rs:1133 得到 directive_result 而预期 executor_applied；单例通过，[单例日志](assets/r3a-settings-mobile-ci-recheck.log)。第二次还在 helper_pairing.rs:111 得到 invalid_pair_confirmation 而预期 pair_key_mismatch。[完整失败](assets/r3a-settings-checkpoint-retry-ci2-test.log)，358 份源码检查期间未变。请求所有者稳定排序/时间边界及配对错误语义，不绕过这些测试、不越界修改 mobile。

5. R3-D 的 proxy CI：15:08Z 当前四项的 test 在 `kv-proxy/tests/gateway_flow.rs:645` 的 `a_chunked_upload_is_limited_before_the_sender_finishes` 遇到 ConnectionReset（OS 54），reqwest BodyWrite unwrap 失败；gateway_flow 为 24 passed / 1 failed。[完整日志](assets/r3a-owner-ui-ci2-test.log)，359 份源码检查期间未变。helper 新回归 5/5 和全部 200+16 项通过；mobile 本轮通过，先前两项偶发失败仍保留。请求对应所有者核对有界上传/提前 413 的客户端连接关闭竞态，不越界修改 kv-proxy、不忽略失败。

6. 反向 owner 吊销的产品契约：已安装 ndu 为纯执行端，只有 TPM DK，没有 AK_s；新包原生 `devices revoke <Mac>` 在 0.226363 s（含 SSH）返回 key_unavailable，设备/授权状态未变，[证据](assets/r3a-executor-revocation-ndu-preflight-native.json)。请 R3-B/R3-E 定义由现有审批端合法代签并执行 Strong DeviceDeleteProof 的命令路径，或明确纯执行端的能力边界；现有本机 AK_s 契约下不能把这条任务计为已完成，不用 DK/polkit/软件键代替 Strong，也不修改角色表来凑验收。

7. 历史未完成查询的对账契约：最新全量 authenticated audit 为 53 matched / 1 missing_receiver_record；13:00:05Z 的 query_grants ID=01M4TNJG10T64E6D72NQ0VMM7A，Mac result_ok=null，ndu 无对应 directive/audit。请 R3-B/R3-E 明确保留历史的失败/过期传输对账语义；不能删除旧 issuer 记录、补造 receiver 记录、缩窄 since，或放宽 nonce/exp 来凑 100%。[最新明细](assets/r3a-audit-timeout-native-20261013T232726Z.json)、[双端只读记录](assets/r3a-audit-one-directive-mac.json)。新查询已经真实复验等待超时和晚到回执，历史缺证据不可能从该成功用例倒推补齐。

8. 后续共享 Windows GUI 构建输入（已补成当前 CI）：05:48:43Z 的 kv-agent manifest/build/main 改动加入另一工作流的 Windows 依赖，原锁文件当时无这些 package；受约束 ci8 的离线解析失败保留。对应工作流于 05:52Z 更新锁文件后，R3-A 在 locked/offline 保护下的 ci9 四项通过，未编辑依赖声明/锁文件或覆盖其 GUI。该依赖决策属于对应工作流，R3-A 未引入产品依赖。[历史保护复查](assets/r3a-se-child-closure-ci8-summary.json)、[当前四项](assets/r3a-se-child-closure-ci9-summary.json)。

## 6. 未决项

当前实机已完成：配对、27 次远程 GET 批准/执行、20 次同质样本、Deny/续等/再次领取/改参、控制面与原生 MCP 共用设置后端、T2 两轮/真实签发/撤回、真实锁屏/解锁、Mac GET 投递、Esc 自然到期、系统 Touch ID 取消，以及 **Mac→ndu 正向吊销 10.583576 s / 待用批准与 Grant 均失效 / 执行 0**。最新四项 CI 于 06:02Z 全绿，1416/0/10、526 份源码/构建输入未变；后续共享依赖由对应工作流对齐后，R3-A 在 locked/offline 保护下重验通过，没有新增依赖或修改锁文件。[当前完整快照](assets/r3a-se-child-closure-ci9-summary.json)、[最终源码核对](assets/r3a-final-source-check-ci9-20261014.json)。

未关闭项如下；这些结论不把已完成的正向吊销或系统取消退回待测：

1. ndu 纯执行角色没有 AK_s，反向 Strong 吊销完成数为 0；保留已使用历史的合法重新加入/配对路径仍缺产品闭环。当前 ndu 身份确已吊销，不能恢复旧设备、旧 nonce 或用备份回滚解除吊销。
2. 最后完整双端审计 53/54、历史缺接收记录 1 条；吊销后原生远程查询不能取齐双端快照。需要保留历史的失败/结果未知对账契约，不能补造成功或缩窄窗口。
3. 手机静默/立即横幅仍待 R3-C，本账户活跃手机 0；Mac agent 冷启动 unknown 时仍保守 away，真实 OS 转换后可恢复。
4. 原生最终 biometric failure 尚未测，取消已完成；认证失败的软件类型保真已覆盖。普通远程 Esc 不签决定，原请求仍待批至原 exp，不能把它提前标为已拒绝。
5. 两小时合盖物理实测已按本人要求取消。源码 review 已完成；原审批端重启持久化缺口在共享源码中已有修复和 7 项 CI，但当前 Mac helper 未部署该项，不能称两小时实机积压通过。
6. 首次批准 131.226 分钟、p50=3.0905 s、最新一小时 Strong Grant=6.162329 s，均超过对应目标；HTTP 200=0，上游 401/403 独立记录。继续访问需正常更新已到期 Graph token，不延长 request exp 或扩大权限。

既有夜间状态和偶发 CI 失败继续作为历史保留；夜间未擅自发起人工认证，最终现场吊销仅在本人明确「开始」后执行。

历史准备快照：11:02:44Z 四项 CI 全绿（1363/0/10，69 组），356 份源码未变；Mac 新 helper/CLI 已 release 构建并签名，复用当前签名 agent/relay，四个严格 requirement 检查均通过，[签名包](assets/r3a-controls-signed-build.json)。ndu 11:10:47Z 安装新 helper/CLI，三服务 active、helper/relay 无能力、broker 仅 SYS_PTRACE，原两端 device_id 未变，[安装收据](assets/r3a-ndu-controls-install.json)。后续 Mac 14:36Z 设置包与 15:26Z owner UI 包的真实安装/控制记录见 §2；两轮 T2 标签尚未完成。

15:08Z 历史四项 fmt/clippy/build 均通过，test 因上面 R3-D proxy 用例失败；不能把它写成全绿。owner 回归 5/5 证明缺少 AK_s/AK_q 仍拒绝签发，普通确认不能代替签名。初版测试的 Arc 包装/可变借用编译问题已纠正，失败日志仍保留。该 helper 15:26Z 已安装，实际少弹了多少次 Touch ID 尚未完成成功控制用例计数。夜间吊销及重复认证修复的最新完整四项于 **17:04:34Z 全绿（1384/0/10，360 份源码未变）**，没有忽略 proxy/mobile 用例；该次通过不抹去其历史偶发失败与所有权外请求，也不关闭 B/C/D 真机验收。

### 只补无人值守的现场清单（已准备，等本人新的「开始」）

> 接下来约 4–6 分钟你要做的事：
> 1. 回复「开始」后，我打开新的 Mac Terminal；若提示管理员密码，只在 Terminal 输入，看到终端前台检查、安装与 5 次 owner IPC 成功。
> 2. Mac 出现“无人值守／含敏感操作”普通确认时，核对执行端和一小时范围，点击 Confirm／确认，然后在 SE 签名提示按一次 Touch ID。
> 3. Terminal 两次要求执行端标签时，每次亲自输入它显示的完整标签 keyvalet 并回车，看到第二轮确认结束。
> 4. Mac 最终 SE 签名提示再按一次 Touch ID，看到 unattended 命令退出 0、ndu unattended=true。
> 5. Mac 出现“收回全部远程授权”普通确认时点击 Confirm／确认，这一步无需 Touch ID。
> 6. 等 Terminal 显示 ndu 为 per_use、unattended=false，并显示双端审计匹配和差异数字，算本段结束。
> 预计 Touch ID 共 2 次；已成功的切模式、一小时 T1 授权、lock 和本地设置复验不重跑。是否现在开始？

此清单发送时，新 helper 已构建并按现有 Developer ID 签名，另外三项复用已安装二进制，四项严格 team/identifier requirement 通过，[签名包](assets/r3a-owner-ui-signed-build.json)、[就绪检查](assets/r3a-unattended-only-ready.json)。当时 fmt/clippy/build 通过、test 有上述所有权外 proxy 失败，5 条认证回归和 3 条前台 TTY 回归通过，尚未安装该包。随后安装与失败的实际结果见下一节；没有将 CI 的终端失败当作实机的精确根因。此清单只覆盖 B5 收尾，C 双向吊销、B6 在场与 D 两小时合盖另约窗口。

### 15:26Z 新包安装与 T2 首轮标签停止

本人回复「开始」，15:25:59Z 打开 Terminal 22251；新 helper 安装完成，SHA=77b82de845f7978011f76688fa49d8c68f9db9759e774aad6981847344bc8852，另外三个二进制未变，三服务 running、owner IPC 5/5（13.439–18.015 ms），[安装](assets/r3a-owner-ui-install-152606.json)。T2 Strong 准备到原生第一轮标签提示，但没有完成标签；190.074093 s 后驱动退出 label_command_timeout，Grant 签发=0，[收据](assets/r3a-controls-152917.json)。本人明确说明输入的是 aaa，而显示的执行端标签是 keyvalet；错误标签必须拒绝，不能代填或当有效确认。

先前的“前台进程组错误”假设未获原生支持：两种 [预检](assets/r3a-label-native-preflight.json) 均显示 process_group=foreground_group；常规控制终端 alias 的补充 CI 也通过，[记录](assets/r3a-label-tty-alias-before.log)。此前不能把独立 PTY 3 个测试通过称为本机故障已修复。

输入 aaa 却没有立即 user_cancelled，还需要修复驱动输入路径。新增模拟 sudo 的“stdin 接原 owner TTY、控制 TTY 另一个 PTY”测试，错误标签修前变为 label_command_timeout，[修前](assets/r3a-label-split-tty-before.log) 4 passed / 1 failed。驱动改为选内核 ttyname(0) 指定的真实 TTY，仅在 stdin 是 TTY 时使用，打开后核对设备相同；不读管道、代填标签或更改 sudoers/use_pty。新的全部 5 项回归通过，[修后](assets/r3a-label-split-tty-after.log)。该改变尚待原生输入诊断；真实根因仍须用诊断核对，不外推 CI。

15:31Z root-only 读取因 sudo 缓存失效安全失败，[记录](assets/r3a-controls-native-readback.json)，没有反复弹认证。ndu 只读 status 确认 per_use、pending=0、grants=0、unattended=false；没有在本人未再次开始时重弹 T2。准备输入诊断使用假 CLI，不调用 KeyValet，保存字节数/行结束符计数而不保存输入。新 Terminal 22681 的首条命令未启动，只有就绪 shell；再次发到该已就绪 tab，后续结果单独记录。

### 16:00Z 只读输入诊断与夜间工作边界

本人在 Terminal 完成系统认证并输入诊断用 aaa；[保留的原生诊断](assets/r3a-label-input-native-before-return-7ce016700762.json) 显示 label_prompt_detected=true，但 owner_input_bytes/CR/NL 均为 0，30 秒后 label_command_timeout，未调用 KeyValet、未请求 Touch ID。这次实际 process_group=36587、stdin_foreground_group=36586，stdin 的 /dev/ttys009 与控制终端是不同设备；它与先前两项前台预检不同，不能拿前台预检否定这次后台输入问题。用户输入仍留给之后的 shell，不能算作标签确认。

在等候标签时，原 select-only 读法不会主动发起终端 read；改成在同一期限内对核对过的 stdin TTY 做非阻塞 read，让正常终端作业控制处理后台读取，不强制更换前台进程组、不更改 sudoers/use_pty。新增“终端 readiness 不报告 owner 输入”假系统回归：重构的 select-only 基线为 6 passed / 1 error（label_command_timeout），[基线](assets/r3a-label-readiness-before.log)；修后全部 7 项通过，[回归](assets/r3a-label-readiness-after.log)。简单后台进程组 fixture 的修前 6 项本来就通过，[保留记录](assets/r3a-label-background-before.log)，不能把它写成已复现的失败。上述 read 修复尚未完成原生复验；下一次先用不调用 KeyValet 的输入诊断验证，再安排 T2 确认。

本人随后表示要睡觉；现场交互结束，夜间继续源码、假进程测试、只读状态、报告及已授权且不需要人工认证的 ndu 安装，不再启动密码提示或审批框。已核对本机没有 r3a-* Python 驱动在运行。这段休息没有约定合盖起止时间与请求清单，不能记入 D 的两小时验收。

### 夜间产物、ndu 安装与原生能力预检

联网设备吊销也有重复认证：新增 proof 原因的假 UI case 修前仍调用 authenticate 而不是 confirm，[修前](assets/r3a-device-revocation-ui-before.log)。`revocations.rs` 改用专属 `revoke_device_proof` 原因，`production.rs` 显示设备名称/ID、只接受 literal true 的普通确认；之后仍由原实际 AK_s 签署原 DeviceDeleteProof，并验证证明后才持久化/发送/DELETE。没有 relay 的本地吊销仍走原认证，不把一个普通按钮当 Strong。纯执行端缺键的回归修前认证计数=1，[修前](assets/r3a-device-revocation-preflight-before.log)；现在先检查实际 Strong provider/键，缺键时认证=0、relay 会话=0、目录不变。相关 11 项吊销测试通过，[修后](assets/r3a-device-revocation-ui-and-preflight-after.log)，最终四项 CI 全绿 1384/0/10。

Mac 新 helper 已 release 构建、Developer ID 签名，四份严格 team/identifier 验证通过；新 helper SHA=82864c8ed673e1d3510b7ce62eb9da84a95f40a5eec2751ba97befd6c02f909e，另外三个复用已安装产物，[签名包](assets/r3a-executor-revocation-signed-build.json)。[Mac 安装/备份脚本](assets/r3a-install-revocations-mac.py) 已准备，**未在本人睡觉时运行**；当前 Mac 仍是 15:26Z owner UI 包。

ndu 同一源快照原生 release build 与 6 项吊销回归通过，[Linux 构建](assets/r3a-executor-revocation-linux-build.json)。首次安装在 systemd 已 active、owner CLI exit 0 时把保护状态 fallback 误当 IPC 就绪，remote=null，自动回滚原 helper，[首次失败](assets/r3a-executor-revocation-ndu-install.json)。假 helper/假时钟先复现 2 error / 1 passed，[修前](assets/r3a-native-service-readiness-before.log)；安装脚本改为在固定 15 秒期限内等真正 remote 状态，3/3 通过，[修后](assets/r3a-native-service-readiness-after.log)。未放宽任何 daemon/socket/角色检查，也未把 status exit 0 单独当成功。

17:24:04Z 安装成功，helper SHA=296ea14dcd320d96cbcb8a6936971d6086ce7613d10b7a77147dd0d8e53a685a，CLI SHA 未变；vault.enc 前后 SHA 均为 5737b4e27e88d8041fac2f8a779197914c1efc294350c6e73ea5816c53a940d3，原 account/device ID 未变，三服务 active；helper/relay 能力为空、broker 仍仅 SYS_PTRACE，[安装](assets/r3a-executor-revocation-ndu-install2.json)。root-only 回滚备份 `/var/backups/keyvalet-r3a-revocations-20261013T172404Z`，停三服务后用其中 kv-helper 恢复原 root:root 0755 二进制，再启动 peer/helper/relay；本轮不修改 CLI、配置、vault 或历史。安装收据在 IPC 就绪时 relay 仍 offline，随后只读核对为 connected，不能省略这段启动窗口。

17:26:33Z 的反向原生预检 exit 3 / key_unavailable，0.226363 s 含 SSH，无认证提示、没有签发证明/完成吊销，前后 pending=0、grants=0、unattended=false、device_revocations_pending=0、身份/模式相同，[记录](assets/r3a-executor-revocation-ndu-preflight-native.json)。这只是安全拒绝的真机复验，不能称双向吊销通过。正向 Mac→ndu 的应用计时、重新配对、最新 audit 与 D 仍未执行。

### 醒后下一段草案（尚未发送，尚未取得新的「开始」）

> 接下来约 2 分钟你要做的事：
> 1. 回复「开始诊断」后，我打开已经就绪的 Mac Terminal，并运行不调用 KeyValet 的假 CLI 输入诊断。
> 2. 若 Terminal 要求 Mac 管理员密码，只在该 Terminal 输入；这段不要求 Touch ID。
> 3. 看到 Input diagnostic only 后输入 aaa 并回车，看到 dummy_line_received=true、fake_cli_exit=0 算成功。
> 4. 若诊断未成功，停在输入诊断，不发起产品审批。

只有这段实际通过才进入下一段 Mac 包安装与 T2 两次真实标签/两次 SE 签名；[续测入口](assets/r3a-resume-unattended-only.py) 检查原生 fake CLI 成功、四份已安装签名/哈希与 owner IPC，随后只执行剩余 T2 用例，不再自动重复安装或前面成功的控制面。该入口与 Mac 安装脚本都只做了语法检查，未运行；正式在场清单需届时发出，不能把本草案当批准。

17:45Z [夜间最终核对](assets/r3a-night-final-20261014.json)：360 份 Rust 源码仍与最终四项 CI 的快照完全相同；ndu relay connected、per_use、pending=0、grants=0、unattended=false。运行时 UID/groups 为 helper 994/[108,986]、relay 993/[985]；两者 CapEff=0，root broker CapEff=0x80000（仅 SYS_PTRACE）。没有在跑的 R3-A 驱动、没有夜间新审批/人工认证提示、完成吊销=0；Mac 的签名包仍仅 staged。B5 T2、B6、C 正向/合法反向路径/重新配对、最新 audit、D 和 producer 的原生 Esc/biometric failure 均未关闭，**R3-A 尚未完成**。


### 21:23Z 醒后原生输入复验

本人回到 Mac，收到以下清单后回复「开始诊断」，[清单原文及 Terminal 启动记录](assets/r3a-input-return-terminal.json)：

> 输入诊断已准备好。接下来约 2 分钟你要做的事：
> 1. 回复「开始诊断」后，我打开新的 Mac Terminal。
> 2. 如 Terminal 提示 sudo 密码，只在那里输入 Mac 管理员密码。
> 3. 看到“Input diagnostic only”后，在同一 Terminal 输入 aaa 并回车。
> 4. 等待“输入诊断结果”；fake_cli_exit 为 0、dummy_line_received 为 true 算成功。
> 这段调用 KeyValet 和 Touch ID 的次数均为 0；验证通过后再安排真实审批。现在开始这段诊断吗？

21:23:29Z 假 CLI 在真实 sudo 通道复验成功：[原生结果](assets/r3a-label-input-native-diagnostic.json) fake_cli_exit=0、dummy_line_received=true、owner_input_bytes=4、NL=1、issued=0，KeyValet 调用和 Touch ID 均为 0。stdin 仍与控制终端不同，SIGTTIN=default；读前 process_group=70802、foreground_group=70801，读后 foreground_group=70802。正常作业控制完成前台切换，修复不需要放宽 sudoers/use_pty，也没有代填任何产品标签。原失败收据完整保留，不能由这段假 CLI 成功推断 T2 签发已成功。

21:23:30Z [ndu 只读状态](assets/r3a-return-ndu-status.json) relay=connected、per_use、pending=0、grants=0、unattended=false、device_revocations_pending=0。随后发送并获本人「开始」的 Mac 安装与仅补 T2 清单，原文及启动记录在 [续测清单](assets/r3a-t2-return-terminal.json)，[续测入口](assets/r3a-continue-t2.py)。旧诊断窗口在发命令前已关闭，未启动驱动；新窗口先核对前台 shell 就绪，再启动脚本，没有重跑既有控制项。实际安装及 T2 结果见下节；此次所有四个安装二进制哈希均与签名包相同。


### 21:26–21:33Z Mac 安装、T2 完成与最新审计

[Mac 安装](assets/r3a-revocations-mac-install-212600.json) 完成：三服务 running，owner IPC 5/5（14.453–22.113 ms），四项哈希均匹配已审查签名包。helper 为 82864c8ed673e1d3510b7ce62eb9da84a95f40a5eec2751ba97befd6c02f909e，另外三项不变。root-only 备份位于 `/private/var/backups/keyvalet-r3a-revocations-20261013T212557Z`；回滚时先停三服务，按原二进制和 plist 恢复安装并重新启动，保留现有 vault/config/remote 历史。安装与只读 IPC 检查未触发 Touch ID。

第一轮续测 [收据](assets/r3a-controls-212642.json)：40.610067 s、exit 6/user_cancelled，已出现原生第二轮标签提示，未签发 Grant。本人表示忘了具体操作，只记得输入过一次 keyvalet；不能猜成第二轮错误标签或 SE 取消。ndu 回读 per_use、pending=0、grants=0、unattended=false，[只读记录](assets/r3a-t2-return-ndu-readback.json)。停止后没有自动重弹。再次发送并获「开始」的清单原文如下，[启动记录](assets/r3a-t2-return-retry-terminal.json)：

> 只重试 T2，脚本已核对，无需再次安装。接下来约 3–5 分钟你要做的事：
> 1. 回复「开始」后，我运行续测脚本；如 Mac Terminal 提示管理员密码，只在那里输入。
> 2. Mac 出现 T2 准备确认时，点击允许并完成第一次 Touch ID。
> 3. Terminal 出现“type executor label keyvalet to confirm”时，输入 keyvalet 并按一次回车。
> 4. 等 Terminal 出现“keyvalet again (2/2)”后，再输入一次 keyvalet 并按一次回车；两轮须在 120 秒内完成。
> 5. Mac 出现最终签发确认时，完成第二次 Touch ID。
> 6. 若弹撤回测试授权的普通确认框，点击允许；等 Terminal 显示 per_use、无人值守授权已收回，算结束。
> 现在开始吗？

第二轮 [原生收据](assets/r3a-controls-213127.json) 成功，未重复安装或其它控制项：两轮标签及原实际 Strong 签名共 16.629137 s，JTI=01M4VJS388MBYCZG5PN1THWWX9、scope=device/max_tier=T2、exp-nbf=3600 s。ndu grants 查询 2.499941 s，status 1.815870 s 确认 unattended=true、grants=1；随后 revoke-all ACK=4.992178 s，最终 status 1.747301 s 确认 per_use、unattended=false、grants=0、pending=0。没有将真实批准增加为 HTTP 执行样本；GET 仍为 27。签发总时长含人工操作，不能作为独立 Touch ID 耗时。

控制后的原生审计 exit 3，52 matched / 1 finding / 0 unavailable。非交互只读重查得到相同结果，31.559525 s，[差异明细](assets/r3a-native-audit-findings-213347.json)。两端均为 authenticated checkpoint；最新 T2 与撤回记录已对上。唯一差异是 13:00:05Z 的 query_grants，ID=01M4TNJG10T64E6D72NQ0VMM7A，Mac issued/result_ok=null，[Mac 只读记录](assets/r3a-audit-one-directive-mac.json)；ndu 没有该 ID 的 directives 或 audit 记录，[ndu 只读记录](assets/r3a-audit-one-directive-ndu.json)。当前签发路径原 Directive exp=now+60 s；不能延长旧 exp、补造接收事件、重写旧审计或更改 since 来让历史差异消失。需要以保留失败事实的对账契约处理该历史未完成查询；目前明确记最新对账 52/53=98.113208%，不是 100%。

[源码复核](assets/r3a-return-source-check.json) 发现此前全绿快照之后两份 Windows Hello 源码改变；未越界改动它们。为满足最终当前工作树四条 CI，按规定环境及同一 target 重新执行；21:41:47Z 全部 exit 0，1390 passed / 0 failed / 10 ignored、69 组，360 份源码检查期间不变，[当前检查](assets/r3a-return-ci-summary.json)、[源码快照](assets/r3a-return-ci-source.json)。


### 21:46–21:53Z 原生在场观察与磁盘停止

[清单原文及启动](assets/r3a-presence-return-terminal.json) 已发送，本人回复「开始在场」后才运行以下步骤：

> 在场信号脚本已准备好。接下来约 3–4 分钟你要做的事：
> 1. 回复「开始在场」后，我打开 Mac Terminal；这段不发起 KeyValet 审批、不要求管理员密码。
> 2. Terminal 提示准备好时按一次回车，系统会开启屏保；移动鼠标退出，并按系统提示正常解锁 Mac。
> 3. 回到同一 Terminal 按回车，等待显示 ndu 看到的 Mac 在场状态。
> 4. 按 Control+Command+Q 锁屏，等 10 秒后正常解锁，再回 Terminal 按回车。
> 5. 如果 Terminal 显示已确认 present，再按同样步骤锁屏 10 秒并解锁，回 Terminal 按回车完成计时。
> 脚本只观察真实 OS 通知和已安装程序的状态；若仍为 away，会停止并记录结果。现在开始吗？

[收据](assets/r3a-presence-transitions-214746.json)：71.618552 s、51 次已安装 ndu status，Mac 全部 away；baseline、after_screensaver、after_first_unlock 均 away，故停止，未进行第二次测量锁屏。未发 KeyValet 审批、未请求 KeyValet Touch ID、未发手机请求、未吊销设备。独立 CoreFoundation OS 通知观察器 events=0；它自己只运行后台线程事件循环，因此空事件不能证明本人没有锁屏或实际系统没有通知。

**新根因线索，尚待 CI 复现及修复：** Apple SDK `CFNotificationCenter.h:58–59` 明确要求 distributed notifications 的 main thread run loop 在 common mode 运行；官方 [AddObserver 文档](https://developer.apple.com/documentation/corefoundation/cfnotificationcenteraddobserver%28_%3A_%3A_%3A_%3A_%3A_%3A%29) 同样标明主线程注册投递。已安装入口走 `kv-touchid/src/remote_main.rs` → `remote_agent::run`，主线程直接执行阻塞 agent socket 的 hello/serve/read；OS observer 在 `kv-platform/src/presence/macos.rs` 后台开 run loop，不能代替主线程。计划在所拥有的 `kv-touchid/src/remote_agent.rs` 内用假 IO worker/假事件队列先复现，再让 socket 工作和主线程事件循环各自推进；保留未知 OS 信号为 away、全部 audit-token requirement 及 SE userPresence。没有在 CI 前先改 Rust 修复，也未放宽 presence 为强制 present。底层 OS 初始未知信号的契约仍归 presence 文件所有者。

21:51:58Z 空间仅 14.387 GB（decimal），已经低于本人明定的 15 GB；[磁盘记录](assets/r3a-current-disk.json)。按硬性规则停止进一步修复/编译/安装，只完成证据与报告。21:53Z 复核为 14.538 GB、R3-A 驱动=0，[最终记录](assets/r3a-return-final-20261014.json)。本轮回归检查结束后又有 `kv-agent/src/hello/remote_key.rs`、`kv-agent/src/remote/pcp_acceptance.rs`、`kv-cli/src/remote/live_helper_tests.rs` 三份源码变化；本轮没有编辑 Rust 源码，也不覆盖这些变化。1390/0/10 是 21:41Z 的全绿快照，**当前变化后的工作树未再检查**，不能宣称最终 F 已关闭。

当时的继续计划是恢复至少 15 GB 后先复现并修复主线程通知阻塞，再签名安装/原生复验，不重跑已完成的 T2 或 20 个样本。后续本人取消 D 实测并授权两处构建缓存清理；最新结果以下列记录为准。C 反向纯执行端缺 AK_s、保留已使用历史的重配路径和历史 query_grants 对账契约仍未关闭。R3-A 仍未完成。

### 22:04Z 后：主线程通知修复、审计独立日志核对与空间等待

本人指示继续处理「审计差异 1 条、51 次全为 away」，并明确「两小时合盖子，就不测试了，你自己review一遍得了」。D 因此改为源码 review，实际合盖计时与测试请求仍是 0，报告不把 review 计入两小时实机通过。

仅按本人授权清理 `target-r2a/release/deps` 与 `release/build`，在确认没有编译进程并取得 Cargo target 独占锁后释放 **1,313,386,496 bytes（1.313 GB）**；安装程序、签名 staging、证据和 root-only 备份均保留。[清理收据](assets/r3a-build-cache-cleanup-20261014.json) 当时 free=15.610 GB。之后可用空间再次下降。已列出的 43 个可重建测试可执行文件共约 0.847 GB **未删除**，本人随后选择「我先腾出至少 2 GB」。当前等待本人腾空间，不扩展清理授权。

在空间达到门槛时，先加入 `r3a_main_thread_notifications_progress_while_private_transport_waits`：假私有 IO worker 等主线程队列交付通知，基线按旧同步执行逻辑阻塞 dispatch，**0 passed / 1 failed，0.20 s**，[修前](assets/r3a-presence-main-loop-before.log)。随后在所有权内 `kv-touchid/src/remote_agent.rs` 改为主线程每轮等待至多 10 ms 后运行默认模式 CoreFoundation run loop；原 socket hello/serve、代码身份验证与认证子进程路径在同一 agent 进程的 `kv-agent-ipc` worker 运行。另测退出码 0/1/6 原样返回、worker panic 不能产生成功退出。定向筛选共 **4 passed / 0 failed**，[修后](assets/r3a-presence-main-loop-after.log)；该 crate 全 targets clippy exit 0，[日志](assets/r3a-presence-main-loop-clippy.log)。假测试不需要 GUI、root、安装或 SE，不把它记作真机 presence 成功。

这次调度修复**没有放宽认证**：不改变连接 peer UID、audit-token requirement、角色表、nonce/exp、验签顺序、档位和 Strong 的 SE userPresence；没有新增依赖；worker 与主线程共享原进程代码身份。未知锁屏/屏保信号仍按原契约为 away，未强制设 present。新 agent 尚未 release 构建、签名或安装；[构建停止收据](assets/r3a-presence-release-space-stop.json) 明确 release_build_started=false。下一次真机观察前也必须修正独立 Python observer 的主线程循环，避免拿它自己的空事件集误判系统。新实机复验=0。

审计继续核对了 SQLite 以外可能保留的事务回执：ndu 原生 CLI 日志尾部查询未找到该 ID，[尾部核对](assets/r3a-audit-independent-receipt-tail.json)；随后只读扫描 `/var/lib/keyvalet/audit.log` **19,029 bytes** 与 `/var/lib/keyvalet/remote/audit.log` **1,376,490 bytes**，该 ID 的公开记录数仍为 **0**，[全文件核对](assets/r3a-audit-independent-receipt-full-scan.json)。因此没有可用于修复历史缺接收记录的真实回执；最新 authenticated 全量仍为 **52/53、差异 1**。目前可证明的是 Mac 已签发、等待结果失败、ndu 无可核实的接收/应用记录；不能进一步断言从未投递或伪造接收成功。核心 compare 只配对 `directive_issued` 与 `directive_applied`，未完成传输的解释契约归 R3-B/R3-E（§5 请求 7）；本轮不越界改 compare，也不删除历史、过滤旧查询或改变 exp 来清零。

### 合盖路径 review（本人取消两小时实测）

[review 收据](assets/r3a-lid-code-review-20261014.json) 保存阅读时源码哈希及已读的现有回归名称；没有新运行这些测试，没有发 KeyValet 请求或 Touch ID。

relay-client 在离线期间独立轮询 helper，密文队列先落盘再回报 spooled；重新认证/重连使用 1–60 s 退避，每个新 session 先拉 relay waiting，再发送本地积压。队列通过独占锁、临时文件 fsync、原子替换及目录 fsync 保留已提交批次；只有 helper 的持久接受/退役回执才能删除队头，普通 WS 控制帧不能删密文。现有 sender outbox/queue 恢复测试覆盖这些边界。

helper 使用墙钟到期，在等待、已批准、批准未用阶段标 expired 并清理敏感 payload/result；取消有独立的有效投递窗口。执行前重验实际决定签名、档位、nonce/exp、当前设备权威、epoch、原请求摘要及原 agent。执行在调用 runner 前持锁领取，重复决定不会盲目再执行；若此后崩溃，可能没有执行或结果丢失，因此这里只能论证防重复执行，不能承诺端到端 exactly-once。

**review 缺口 1：审批端重启后的未决定请求。** `engine.rs` 的 `State.inbound_requests` 仅为内存 HashMap，启动时为空；`ApprovalRequest` 验证后写入该表，`RelayInbound` 可返回 ack=true，relay 随后退役消息。若此后 helper 重启，未决定的审批请求可能消失；普通合盖且进程内存保留不触发这一边界。现有「helper restart」回归测的是发送端 outbox 回执，不等于审批端已 ACK 入站请求的恢复证明。此项未新增复现测试、未实施修复，明确列为 review 未决项；用户要求的两小时物理实测已取消，不能据此关闭积压送达验收。

**05:33Z 后续源码复核：** 上段是原 review 时点的结论，原收据不改写。当前共享整合源码已有 R3-B 的 `remote/inbound.rs` 与 `tests/inbound_recovery.rs`：入站正文/已验信封、审计及 vault receipt 在 ACK 前一同提交；启动时重验 receipt/hash、原信封签名、当前 Execute 权威和原 exp，取消/已签发不复活为 waiting，升级状态保留。ci5 中相关恢复/失效/篡改/存储与审计失败回归 **7/7**。本轮只安装新 agent，Mac helper 复用旧组件哈希，**没有部署这项新 helper 修复，也没有两小时物理证据**。[复核与部署边界](assets/r3a-lid-review-followup-20261014.json)。

本段结束前 [空间与当前状态收据](assets/r3a-presence-await-owner-space-20261014.json) 为 free=14.421 GB，低于 15 GB。仅完成上述只读 review、证据与报告，继续暂停 release/签名/安装及完整 CI；没有删除额外测试产物，也没有新弹审批框。本人腾空间后先复查原始可用字节数，再继续新 agent 包与真机验证准备。

### 22:43–23:10Z 审计等待结果修复与签名包就绪

本人要求「那你继续啊」，并明确「你自己去腾空间啊」。仅清理本轮 `target-r2a/debug/{deps,build,examples,.fingerprint,incremental}` 可重建缓存，确认无编译/测试进程并持有 debug/release 两把 Cargo target 独占锁；释放 **3.971653632 GB**、free=18.210 GB，[首次清理](assets/r3a-debug-cache-cleanup-20261014.json)。完整 CI 结束后又释放同一范围 **3.030003712 GB** 以准备 release，[检查后清理](assets/r3a-post-ci-cache-cleanup-20261014.json)。安装程序、所有签名包、root-only 备份与证据保留；没有清理用户个人文件或修改 git 状态。

先加入 helper/CLI 回归后运行旧生产逻辑：[修前](assets/r3a-audit-closure-before.log) CLI 5 passed/2 failed、helper 13 passed/1 failed。缺口分别是没有带指令关联的超时事实、提示直接重试、缺接收记录没有结果未知解释。随后修复所有权内 `kv-helper/src/remote/ipc.rs`、`kv-cli/src/remote/{audit,output}.rs`；新增测试在 helper `remote/tests/audit.rs` 与 CLI `remote/audit_tests.rs`。初次修后 **21 passed/0 failed**，[日志](assets/r3a-audit-closure-after.log)，其后完整 CI 同时覆盖新加的 audit 不可用与未认证快照边界。

`directive_wait_timeout` 只记录原指令 ID、peer、op、完整签名对象的 JCS hash、固定 reason 与 state=unconfirmed。它描述原 10 s 结果等待预算的结束，不宣称执行端拒绝或从未执行；不填写 `issued_directives.result_ok`，不更改原 nonce/exp，也不移除队列。deadline 到达时再次持锁检查已到结果，避免在竞态中误报等待超时。审计不可用时失败关闭；以后从原实际 peer 来的、正常验证的成功/失败回执仍可提交，重复回执仍为 already_consumed。测试证明等待超时和晚到回执都不能把缺少 receiver 的核心 compare finding 变成匹配成功。

CLI 在原认证且完整的 issuer 快照中，按 ID/peer/op/hash 关联等待事实；结果回执另按原 ID/peer 展示 `result_ok`。未认证快照不能提供这一解释，未匹配的 peer/hash/op 也不能套用。输出 `directive_outcomes` 并解释「执行结果未确认，先查询远端状态与审计，再决定是否重试」，保留原 findings、匹配数、非零退出码与查询起点。**没有编辑 kv-core，没有过滤旧查询或补造 receiver 事件。** 旧 ID 因缺少真实结果与关联等待记录，仍为 unknown/缺接收记录；52/53 的真机数字尚未重新采集，§5 请求 7 的核心历史对账契约仍开放。

在场独立 Python 观察器亦改为主线程运行 CF loop、工作线程处理 Terminal/状态读取。[自检](assets/r3a-presence-observer-self-check-20261013T224825Z.json) 使用本进程独有的 `dev.keyvalet.r3a.observer-check.*` 名称，pump 前回调=0、pump 后主线程回调=1；不发送任何 `com.apple.*` 假锁屏/解锁通知，不调用 KeyValet，也不从这个自检推断真机 present 已成立。

**四项 CI 于 22:59:38Z 全绿：1398 passed / 0 failed / 10 ignored、69 组**，[当前快照](assets/r3a-audit-presence-ci-summary.json)；514 份源码/配置/SQL/fixture 文件检查期间及签名前均无变化。每个 Cargo 命令前采用规定三个环境变量与 target-r2a、Rust 1.99.0、原始可用字节至少 15×10⁹。本机 stable 是 1.90.0，因此按 AGENTS.md 使用较新的已安装 1.99.0 跑 clippy。release helper/CLI/touchid exit 0，[构建日志](assets/r3a-audit-presence-release.log)。

23:05Z [签名包](assets/r3a-audit-presence-signed-build.json) 已准备：helper SHA=987cee3a47d9a52617c4157c2e85dd0dd07b924b96d4958c3952e2394372e96d，CLI=25e3c622cd242540fdd23e40e8212408dc248c50ebf7c90f175f47e20693dbfa，agent/touchid=d18066e8dc6259d41d42b21cb598aa596ee1bda937cd4a55ea97fb69f0d16951；relay 复用已安装产物。四份现有 team/identifier strict requirement 均 exit 0。没有新增依赖或放宽验签顺序、档位、nonce/exp、角色、audit-token、ptrace/能力或 Strong userPresence。新包 **尚未安装**。

[就绪收据](assets/r3a-audit-presence-ready.json) 核对四份签名/哈希、四个原生脚本语法、当前源码与 CI 一致；free=17.519 GB，当前 sudo 上下文缓存不可用，未弹系统认证。准备好的 [入口](assets/r3a-start-audit-presence.py) 将先按现有边界安装新包；Mac/ndu 有待批时停止安装；原配置/vault/历史保留。随后仅发 1 条真实只读 query_grants，暂时暂停 Mac relay 让原等待预算超时，在 finally 恢复 relay，再核对原 ID 的晚到结果、ndu 应用 1 次及两端 authenticated audit。最后才由本人按清单操作真实屏保/锁屏。准备脚本不代填标签，不请求 Graph token，也不发凭证操作或 KeyValet Touch ID；安装需要本人在 Terminal 输入系统管理员密码，现场开始前不会运行。

### 审计/在场真机复验清单（已获「开始」并执行）

[原文及入口](assets/r3a-audit-presence-checklist.json)，发送时尚未执行；随后本人回复「开始」，23:26Z 安装与只读查询已实际完成。原文如下：

> 签名包和四项 CI 已准备好，接下来约 5–7 分钟你要做的事：
> 1. 回复「开始」后，我打开 Mac Terminal；若提示管理员密码，只在那里输入，看到 Signed R3-A binaries installed 和 Owner IPC: True 算安装成功。
> 2. 保持 Mac 开着，等待 Terminal 显示只读查询超时后恢复、ndu 应用 1 次及全量审计数字；这步不用点击审批。
> 3. Terminal 提示时按回车开启屏保，退出并正常解锁 Mac，再回同一 Terminal 按回车，看到 presence=present 算成功。
> 4. 按 Control+Command+Q 锁屏，等 10 秒正常解锁，再回 Terminal 按回车。
> 5. Terminal 显示已确认 present 后，再按同样步骤锁屏 10 秒、解锁并回车，看到在场信号诊断结束算完成。
> 这段不发凭证请求，KeyValet Touch ID 请求为 0；系统解锁按你日常方式完成。sudo 缓存已失效，安装需要你在 Terminal 完成系统认证，真实锁屏/解锁也需要你在 Mac 前。现在开始吗？

### 23:26–23:44Z：真实安装、超时晚到回执及在场恢复

本人回复「开始」后打开 Terminal，完成系统管理员认证；[安装收据](assets/r3a-audit-presence-mac-install-20261013T232634Z.json) 核对四个安装哈希与签名 staging 一致，helper/agent/relay 均 running，owner IPC 连续 5/5，15.956–28.209 ms。root-only 备份为 `/private/var/backups/keyvalet-r3a-audit-presence-20261013T232632Z`；若需回滚，只回滚该备份中的二进制/plist，保留安装后的当前 vault、配置、remote 历史与 nonce，不能回滚身份或授权状态。

实际暂停 Mac relay 后只发一条原生 query_grants，**10.181756 s** 返回 directive_result_timeout；finally 恢复 relay，原指令 ID=01M4VSDN0GX3403TAK56V9KXYP 于开始后 **15.759854 s** 收到真实验证的成功结果。issuer 原链顺序为 directive_issued seq=6589 → directive_wait_timeout seq=6590 → directive_result seq=6597；原 ID/peer/op/hash 关联一致，receiver directive_applied 表和审计各 **1** 条。[实机收据](assets/r3a-audit-timeout-native-20261013T232726Z.json) 的 native_timeout_case_passed=true，整段含全量对账 52.100208 s，无凭证使用或 KeyValet Touch ID。

同一 native authenticated audit 为 **53 matched / 1 finding，53/54=98.148148%，两端可达**。唯一 finding 仍为旧查询 01M4TNJG10T64E6D72NQ0VMM7A；其 wait_timeout_recorded=false、result_ok=null，旧版本没有可绑定的等待记录，不能凭本轮成功补造历史事实。结果未知解释与新等待日志已在安装产品上复验，历史缺接收证明仍如实保留，不能把这一条称为可恢复的漏写成功记录。

在场首段重新捕获了 4 个真实 OS 通知，ndu 216 次认证读取中 **present=149、away=67**，系统解锁至首个 present=**7.574238 s**。[原始记录](assets/r3a-presence-transitions-20261013T233228Z.json) 与 [派生摘要](assets/r3a-presence-installed-partial.json) 均保留；观察窗口到期时完整测量周期尚未完成。补测得到 32 个 present，但真实 locked 事件在检查末尾才出现，采集仅继续约 1.5 s，没有 unlocked 或 away；[原始记录](assets/r3a-presence-transitions-20261013T234012Z.json)。因此判定“始终 away”已经解除，锁屏周期仍未通过。

采集脚本的两项输入/时序缺口均先复现：SSH 继承 Terminal stdin 的 [修前 2 项失败](assets/r3a-presence-input-before.log) → DEVNULL 隔离后 [2 项通过](assets/r3a-presence-input-after.log)；提前回车结束观察的 [修前 2/1](assets/r3a-presence-early-enter-before.log) → 等真实 OS 周期和认证读回后 [3/0](assets/r3a-presence-early-enter-after.log)。等待时间是独立采集窗口，不改变产品签名/角色/nonce/exp 或 Strong 的真实 userPresence；没有发送假系统锁屏事件。

23:44Z 再次核对 [514 份源码快照](assets/r3a-audit-presence-source-native-check.json) 全部与当前全绿 CI 一致，后续只改 Python 证据采集与文档。本人再次回复「开始锁屏验证」，23:46Z 启动、23:47Z [完整锁屏周期通过](assets/r3a-presence-native-verified.json)，实际 39 次认证读取 present=19/away=20，锁屏→away 8.160197 s、解锁→present 6.782415 s。没有重装或触发 KeyValet Touch ID，真实本机优先审批/手机投递仍须独立验证。

23:48Z [收尾状态](assets/r3a-audit-presence-final-native.json)：Mac 三服务 running，ndu Mac presence=present、pending=0、grants=0、unattended=false；514 份源码仍与 CI 一致，可用空间 15.978 GB。R3-A 尚未完整验收，未关闭 §5/§6 的能力/历史对账、真实投递和 producer 原生细分未决项；本人取消的两小时物理测试不再安排。

### 00:05Z 后：producer 细分授权、复现与真实吊销准备

本人要求继续真实吊销、审批投递和 producer 细分。只读预检为 ndu per_use、pending=0、grants=0、unattended=false、Mac present；Mac 的工具上下文无管理员缓存，没有触发认证。[预检](assets/r3a-remaining-preflight.json)。helper 原有本地失败回归补充 `local_approval_failed → approval_pending`，执行器在失败后若被调用就 panic，不把 biometric failure 记成用户拒绝；这一快照四项 CI 全绿 **1398/0/10、69 组**，[记录](assets/r3a-remaining-ci-summary.json)。后续六文件修复已改变源码，此快照不是最后 F 的结果。

六文件原不在 R3-A 所有权内。先保存 [未应用的最小补丁](assets/r3a-se-failure-proposed.patch) 和 [规则/文件清单](assets/r3a-se-failure-scope-request.md)，本人明确回复「全都允许」后才写入：kv-touchid `enclave.swift`/`device_key.rs`，kv-platform `device_key/agent.rs`，kv-ipc `remote.rs`，kv-core `remote/error.rs`/`keys.rs`。[授权记录](assets/r3a-se-failure-scope-authorization.json)。此次例外仅为错误保真，不改变角色表、验证顺序、档位、nonce/exp、audit-token requirement、ptrace/能力或 Strong 的实际 SE userPresence。

fake 私有 agent 的 [修前](assets/r3a-se-failure-before.log) 0 passed/1 failed；fake SE FFI 的 [修前](assets/r3a-se-native-before.log) 0 passed/2 failed；原逻辑均返回 key_operation_failed。修复后 [相同筛选](assets/r3a-se-failure-after.log) 共 3 passed/0 failed，未知/英文 denied 仍是通用失败，且失败路径不返回签名材料。额外核心 signer adapter 用例检查错误可穿过真实 sign_object 入口，仍不能产生签名。

Swift 只根据明确的 NSError domain/code（最多 8 层 underlying NSError）分类；[12 项纯 NSError 回归](assets/r3a-se-status-test.log) 全部通过，无认证/密钥操作。不同 domain 的同一个数字不视为取消，过深或未知错误仍为通用失败。系统定义参考 Apple 的 [LAError authenticationFailed](https://developer.apple.com/documentation/localauthentication/laerror-swift.struct/code/authenticationfailed)、[userCancel](https://developer.apple.com/documentation/localauthentication/laerror-swift.struct/code/usercancel)、[errSecUserCanceled](https://developer.apple.com/documentation/security/errsecusercanceled) 与 [errSecAuthFailed](https://developer.apple.com/documentation/security/errsecauthfailed)。不从“不识别指纹”的中间提示或用户回忆推断最后的系统错误。

当前完整检查最初在新测试 `.err().expect()` 的 clippy 规则停止，[保留首轮](assets/r3a-se-closure-ci-summary.json)；改成固定消息的 let-else，避免打印任何成功返回的密钥/签名数据。修后 fmt/clippy/build 全部 exit 0；test 因 free<15 GB 在启动前停止，[保留空间停止](assets/r3a-se-closure-ci2-summary.json)。源码未变，按本人已给的自主清缓存授权清理约 1.822 GB Xcode ModuleCache，恢复到 16.329 GB，[收据](assets/r3a-se-module-cache-cleanup.json)，继续同一源码的 workspace test；最终 CI 另记，不重复已通过三项或隐藏中途失败。

[真机驱动](assets/r3a-native-remaining.py) 已准备：在场请求 Deny、第二条 Esc 且要求 Mac 真实 remote_ui_rejected/user_cancelled 审计与 ndu waiting/执行 0；SE 取消必须返回 key_operation_cancelled 才继续；关闭原执行进程后才由本人批准第三条，要求 approved_unused/执行 0；签发一小时 T1 Grant 后才吊销 ndu，并在 60 s 内读回该批准 cancelled 和该 Grant revoked_at。准备时 Native 安装/驱动尚未启动，预计成功 SE 签名 2 次，另取消 1 次，[阶段清单](assets/r3a-remaining-plan.json)。取消 D 后不安排物理合盖；不自动恢复被吊销身份，也不代签纯执行端缺失的 AK_s。

采集脚本先用临时 SQLite/fake MCP 加入秘密隔离测试，修前 1 passed/2 failed（自由 reason 可被导出），[日志](assets/r3a-remaining-evidence-before.log)；改成固定 reason/结果字段后 [3/0](assets/r3a-remaining-evidence-after.log)。生产 wire、签名票、凭证值、响应体和会话令牌均不写证据；没有因为真实 token 已过期而擅自刷新或增加权限。

**该签名包源码四项全绿：1402 passed/0 failed/10 ignored、69 组，516 份源码/Swift/配置/fixture 检查期间不变。** [汇总](assets/r3a-se-closure-final-ci-summary.json) 引用同一源码的 ci2 fmt/clippy/build，恢复空间后补 test；[源码快照](assets/r3a-se-closure-final-ci-source.json) 亦包含实际参与编译的 enclave.swift 和 Swift spike，未只核对 Rust。工作区 test 后再按已获授权清理本轮 debug 缓存 3.291 GB，恢复到 17.376 GB，[收据](assets/r3a-se-post-ci-cache-cleanup.json)。新的 helper/CLI/agent 已完成 release 构建及签名，四份严格 team/identifier requirement 全部通过，[签名包](assets/r3a-se-signed-build.json)，于 00:53Z 实际安装。[安装前复核](assets/r3a-se-remaining-ready.json) 当时核对 516 份源码与 CI 一致、空间 21.210 GB。[真实操作清单原文](assets/r3a-remaining-checklist.json) 获本人「开始」，安装和 ndu 解锁已执行；首条 GET 发起前因 away 停止，未完成投递、SE 取消或吊销。

### 00:53Z：producer 包安装成功，投递前在场检查停止

[安装收据](assets/r3a-se-mac-install-20261014T005346Z.json) 记录 helper/agent/relay running、owner IPC 5/5（14.819–20.562 ms），四份安装哈希与签名包一致；root-only 备份为 `/private/var/backups/keyvalet-r3a-se-20261014T005343Z`。现有 vault、配置、密钥与历史保持。本人随后完成 ndu polkit，看到 AUTHENTICATION COMPLETE；在 Terminal 回车后没有弹 Mac GET 框。[实际收据](assets/r3a-remaining-native-20261014T005404Z.json) 固定错误为 remaining_desktop_not_present_before_request，cases=0、commands=0、revocation_started=false，当前 pending=0。这次 GET 没有发出，不能归为弹框取消或验签失败。

新 agent 的锁屏/屏保通知缓存从 unknown 开始；本机只读 CGSession 快照中两个初值均为 null，而输入后 idle=0.004 s。源码按未知信号保守报告 away；ndu 初始 present 不能证明重启后的 agent 已有完整信号。此为仍开放的 macOS 冷启动初值限制，原成功锁屏周期不能跨重启外推。没有强制设置 present、发送假系统通知或放宽角色/认证。[无弹框定位收据](assets/r3a-remaining-no-dialog-20261014.json)。

续测采集脚本的假 transport [修前](assets/r3a-remaining-presence-before.log) 复现同一错误（1 项失败、3 项待新增方法错误）；改为只读取 authenticated status 并等待实际 present，超时仍停止，有异常 Grant/模式时也停止，[修后](assets/r3a-remaining-presence-after.log) 7 passed/0 failed，包含原证据隔离用例。新的 [续测入口](assets/r3a-resume-se-remaining.py) 不重装，先由本人操作真实屏保退出和锁屏/解锁，再继续剩余清单；每次启动核对已安装哈希与既定严格签名要求。

续测准备期间共享工作树新增了其他所有权的 Rust/fixture 改动，已在定位收据列出，不回退或覆盖。1402/0/10 描述已安装包对应的冻结源码；不能宣称后来的当前工作树仍与该 CI 快照一致，最终 F 须在整合源码上另复查。本次只改 Python 采集与文档，未再次部署程序或启动 Rust 构建。

本人随后明确回复「开始续测」；[续测清单原文](assets/r3a-remaining-resume-checklist.json) 和 [Terminal 派发](assets/r3a-remaining-resume-terminal.json) 已保存，01:03Z 在原空闲 Terminal 启动不重装入口，先进行真实屏保退出/锁屏解锁，再进入审批与吊销。开始时不预记任何用例通过；实际结果以续测收据为准。

### 01:03–01:05Z：实际 Mac 投递与 Esc 通过，SE 子进程传递遗漏

本人回复「开始续测」，在不重装入口操作真实屏保退出和锁屏/解锁；ndu 的 authenticated status 先读到 3 次 away，再于等待开始后 4.971034 s 读到 present。第一条请求前再次确认 present，实际 Mac GET 点击 Deny，CLI/MCP 返回 approval_denied，耗时 5.038746 s；ndu 同 ID 状态 denied、execution_started/completed 均 0。第二条 Mac GET 按 Esc，Mac 原生审计记录 remote_ui_rejected / user_cancelled，ndu 同 ID waiting / 执行 0。[原生驱动收据](assets/r3a-remaining-native-20261014T010532Z.json)、[实际只读核对](assets/r3a-delivery-escape-native-verified.json)。两端活跃手机=0，不能把桌面投递证据写成手机静默或横幅已通过；GET 实际执行总数仍为 27。

随后普通授权确认允许，系统 Touch ID 取消；本人明确核对该顺序，[本人事实记录](assets/r3a-se-cancel-owner-fact.json)。已安装 CLI exit 3 / key_operation_failed / 8.531664 s，native_se_cancel_verified=false；驱动停止在 unused approval/Grant/吊销之前，revocation_started=false。程序退出保留 Esc 待批，不改原 exp、不伪造取消决定。只读统一日志扫描 4155 个事件没有输出相关固定标记，[安全投影](assets/r3a-se-cancel-log-projection.json) 未存 raw message，不能凭缺日志推断实际 FFI 分类。

确认上一版补丁遗漏了额外边界：device_key::exit_code 把所有类型转为退出码 1，agent.rs 的 device_key 分支把所有非零退出再写成通用失败。原 six-file 的 fake FFI / fake private-agent 测试各自通过，未覆盖这条真实子进程桥；这是本轮修复遗漏，硬件失败记录保留。最小 agent.rs 提案先保存未应用补丁；本人回复「全部允许啊，以后不要再问我了」，[授权](assets/r3a-se-child-hop-scope-authorization.json) 覆盖此文件及后续 R3-A 必要跨文件修复，仍保留原认证/机器操作限制。

先添加 fake runner 与子进程退出回归，旧逻辑 [1 passed/2 failed](assets/r3a-se-child-hop-before.log)。之后为真实 typed DeviceKeyError 分配固定 child exit 3/4，agent 仅对正常结束、未超时、stdout 长度 0 的可信子进程结果保留 key_operation_cancelled / key_authentication_failed；未知码、非空失败输出、崩溃/超时仍为通用失败，无签名 payload。修改为 kv-touchid/src/device_key.rs 与 agent.rs，[3 passed/0 failed](assets/r3a-se-child-hop-after.log)。没有捕获或猜测 localized stderr，没有改变 trust check、audit-token、nonce/exp、role、SE ACL 或实际签名；Strong 仍必须真实 userPresence。当前四条 workspace CI 已开始，完成后才准备新签名包；未将新源码标为已经安装/硬件复验通过。

### 01:13–01:32Z：子进程修复与共享整合检查

本轮四项检查先遇到共享改动的格式差异，[ci1](assets/r3a-se-child-closure-ci-summary.json)；只格式化 fmt 指定文件。随后 [ci2](assets/r3a-se-child-closure-ci2-summary.json) 在新 inbound 清理逻辑的 E0502 借用冲突停止；对 State 两字段做同一锁下的分离借用，保持原 retain 条件，没有更改状态/授权行为。此期间共享 engine/transport 测试亦有更新，源码变化保留在收据，未回退。ci3 四项命令均 exit 0、1416/0/10，但有其他工作流 5 个源码变动，因此 [ci3](assets/r3a-se-child-closure-ci3-summary.json) 不记最终固定版本。ci4 的 Windows 在场原生测试格式差异也保留，[ci4](assets/r3a-se-child-closure-ci4-summary.json)。

格式整理后 [ci5](assets/r3a-se-child-closure-ci5-summary.json) 于 01:32:24Z 四项 exit 0，**1416 passed / 0 failed / 10 ignored、69 组；522 份源码/Swift/fixture 检查期间不变**。每条 Cargo 前原始可用字节为 17.417–17.426 GB，指定环境与 target-r2a 均保留。CI 不调用安装、sudo 或 Touch ID；纯子进程桥回归也不读取安装路径或猜 localized stderr。

[自然到期核对](assets/r3a-escape-expiry-native.json) 中，原 Esc 请求已按原 exp 转为 expired / execution_started=0 / completed=0；Deny 仍 denied / 执行 0。此为真实 helper 到期结果，不是两小时合盖，也不是重新发请求。下一段 [入口](assets/r3a-start-se-child-remaining.py) 对既有 Deny/Esc 状态及 producer 审计做只读核对，直接补剩余用例；新包只重建 agent，helper/CLI/relay 复用此前已安装哈希，分别保留各组件的 CI 来源，避免把整合中尚未部署的 helper 变更写成已安装事实。

01:34Z [新 agent 签名包](assets/r3a-se-child-signed-build.json) 已准备，helper/CLI/relay 三项与现有安装哈希完全一致，分别引用旧组件 CI；新 agent 引用当前 1416/0/10 的 ci5。四份严格 requirement 通过，[就绪](assets/r3a-se-child-remaining-ready.json) 的 522 份源码仍与检查快照一致、free=16.024 GB。当时未安装、不预记通过；05:14Z 本人开始后的真实安装/SE 取消/吊销结果见下文。[清单原文](assets/r3a-se-child-remaining-checklist.json) 保留，代码/跨文件修复不再请求许可，实际 Touch ID 段仍遵守本人原定「先准备清单、等开始」规则。

## 2026-10-14 05:14–05:18Z：系统 SE 取消与真实正向吊销完成

### 给本人的操作清单原文与实际执行

[清单收据](assets/r3a-se-child-remaining-checklist.json) 已在包、签名、四项 CI 和驱动备齐后发送；本人回复「开始」，[实际启动](assets/r3a-se-child-remaining-terminal.json) 于 05:14:07Z 在 Mac Terminal 27753、`ttys000` 执行。清单原文如下：

> 修复包、签名和四项 CI 已备好。接下来约 8–10 分钟你要做的事：
> 1. 回复「开始收尾」后，我在 Mac Terminal 安装新 agent；若要求管理员密码，只在那里输入，看到 Owner IPC: True。
> 2. Terminal 提示“在场恢复”时按回车开启屏保，保持 10 秒后退出；再按 Control+Command+Q 锁屏，保持 10 秒后正常解锁，回 Terminal 按回车等 presence=present。
> 3. Terminal 标明“SE 取消用例”时按回车，允许普通授权框，再取消系统 Touch ID；看到 key_operation_cancelled 算成功。
> 4. Terminal 提示 ndu polkit 时输入 ndu 用户 guang 的密码。
> 5. Terminal 标明“待用批准”时按回车，先不操作 Mac GET 框，等“执行进程已退出”后才点击 Allow／仅本次。
> 6. Terminal 标明“签发一小时 T1 Grant”时按回车，在 Mac 确认并完成第一次 Touch ID。
> 7. Terminal 标明“正向吊销”时按回车，核对设备 ID 末尾为 07FC（ndu）后确认并完成第二次 Touch ID，看到批准 cancelled、Grant 吊销和秒数。
> 8. Terminal 显示本段完成后保持窗口打开，我读取实际收据。
> 成功 KeyValet Touch ID 签名共两次，另取消一次系统认证；Deny 和 Esc 用例已通过，本段只读核对。按你原定的 Touch ID 现场规则，等你说开始后再运行。现在开始收尾吗？

[安装收据](assets/r3a-se-child-mac-install-20261014T051422Z.json) 确认 agent/touchid SHA-256 为 `38ec772533f9a9efecd48fb7e033042ceecce9722eaae4c6f39c340e22d60a8b`，其余三项与原安装完全一致；helper/agent/relay 均 running，owner IPC **5/5（13.629–22.104 ms）**。root-only 备份 `/private/var/backups/keyvalet-r3a-se-child-20261014T051419Z`；凭证库、配置、密钥和历史保留。此后发生真实设备吊销；回滚程序/服务时必须保留当前远程状态，不能恢复旧身份快照来解除吊销。

| 清单阶段 | 实际结果 | 数字／证据 |
| --- | --- | --- |
| 真实 OS 在场恢复 | ndu 认证读回 away→present，未注入通知 | 样本 away=0.598204 s、present=2.049881 s；不是新的完整锁屏延迟测量 |
| 普通确认允许→系统 Touch ID 取消 | `key_operation_cancelled`，CLI exit 3；没有签发新 Grant | **10.485434 s / 新 Grant=0**；先前 8.531664 s 通用失败保留 |
| ndu 会话解锁 | 本人完成原生 polkit；驱动继续 | 密码仅在 Terminal 输入，未保存认证输入 |
| 待用批准 | 原请求进程已退出后才由本人 Allow／仅本次 | ID `01M4WDEFV8J4NMV0MSMEF5DXCE`，approved_unused；执行 started/completed=0/0 |
| 一小时 T1 Grant | 真实 AK_s userPresence 签发，ndu 已安装 | JTI `01M4WDGQ4G1Y5X2WSA6N33F4NC`；**6.162329 s，超过 5 s** |
| Mac `devices revoke <ndu>` | 真实 Strong DeviceDeleteProof、CLI exit 0 | 命令 **9.100511 s**；从命令开始至 ndu 失效读回 **10.583576 s** |
| 吊销后读回 | ndu 自身 revoked_at 已设置；待用批准 cancelled、测试 Grant revoked_at 已设置 | 正向完成=1，执行=0；失效发生在原请求/Grant exp 前，不能归为自然到期 |

[完整原生收据](assets/r3a-remaining-native-20261014T051814Z.json)、[核验摘要](assets/r3a-se-revocation-native-verified.json)。本段成功 SE 签名 **2 次**（Grant、设备吊销），另取消 SE 认证 1 次；旧 Deny/Esc 仅核对状态及 producer 审计，没有重发。本段新增批准未执行，因此总真实 GET 执行仍为 **27**。本人随后提供的 Terminal 完整输出与收据一致。

### 吊销后的审计与保留历史

05:26Z 用两端已安装 CLI 只读尝试同一 `since=2026-10-13T05:26:00Z`、`limit=200` 的 `audit --remote`，没有缩窄窗口、过滤对端或发认证提示。[原生尝试收据](assets/r3a-post-revocation-native-audit.json)：Mac 工具进程的非交互 sudo 不可用；ndu 查询 exit 3，仅取得本地 vault-authenticated checkpoint（head seq=4090、entries=3407），对端 unavailable=1。该单端报告 matched=0/findings=53，不能拿来称新双端审计差异 53 条，也不能称 100% 对账。

最后一次取齐双端认证快照的完整对账仍是 **53/54=98.148148%，历史 missing_receiver_record=1**。正向吊销的原生批准/Grant 前后状态已分别证实，但不能用这些投影代替完整双端审计。被吊销的 ndu 和全部历史保留；没有清空 RemoteStore、恢复旧 nonce/设备、自动重新配对，或为反向吊销补软件/DK 签名。反向能力与保留历史的重新加入仍见 §5/§6。

05:33Z [最终源码核对](assets/r3a-final-source-check-20261014.json) 与 ci5 的 **522 份源码/Swift/fixture 全部一致**，四项仍对应 1416 passed / 0 failed / 10 ignored；本段后续只写文档与证据，没有新的 Rust 改动。真实 biometric failure、手机通知以及超阈值项目继续按 §3/§6 如实记录；本人取消的两小时物理测试不再安排。

### 05:39–05:52Z：最终原生状态与共享源码 CI 边界

05:39Z [最终原生只读核对](assets/r3a-final-native-state-20261014.json) 确认 Mac helper/agent/relay 仍 running，ndu device revoked_at、测试 Grant revoked_at、待用批准 cancelled 均保留，执行 started/completed=0/0；没有再次发起 UI、吊销或重置。此时共享树的 view.rs/build.rs/enclave.swift 三份源码已不同于 ci5，05:33Z 原快照仍作为历史保留，不冒充新源码通过。

按本人已有自主清理许可，仅删除 target-r2a/release/deps 和 release/build 可重建产物，释放 0.582 GB，四份签名 staging 哈希完全不变，[清理收据](assets/r3a-final-ci-space-cleanup-20261014.json)。ci6 首先记录新 view.rs 的格式失败；只按 rustfmt 调整这一处换行，没有回退共享逻辑，[保留失败](assets/r3a-se-child-closure-ci6-summary.json)。新 snapshot 额外包含 plist 构建输入。

[ci7](assets/r3a-se-child-closure-ci7-summary.json) 于 **05:48:02Z 四项 exit 0，1416 passed / 0 failed / 10 ignored、69 组，525 份源码/构建输入未变**；每条 Cargo 前可用空间 15.721–15.913 GB，规定环境、1.99.0 stable 和 target-r2a 保留。真机安装仍按各组件旧快照溯源，没有为了新 UI 再安装或重复 Strong 交互。

05:48:43Z 共享 Windows GUI 又修改 kv-agent Cargo.toml/build.rs/remote_main.rs；[后续源码核对](assets/r3a-final-source-check-ci7-20261014.json) 保留三个差异，不伪称新源码已通过。Windows 依赖不在当时的 Cargo.lock 中。为避免 R3-A 新增依赖或改变锁文件，[ci8](assets/r3a-se-child-closure-ci8-summary.json) 在原环境外增加 CARGO_NET_OFFLINE=true、clippy --locked：fmt exit 0，clippy 在未缓存的 windows-reference 解析处 exit 101，build/test 未运行；526 份输入在该次复查期间未变。这是当前依赖保护限制，不证明联网解析结果或 registry 可用性；没有回退外部改动或修改 Cargo.lock。**F 对最后完整快照通过，对随后变化的当前树仍开放**。

§3、架构 §16、review 顶部表和 docs/linux.md 已回写真机吊销/系统取消、最新控制超阈值及未决项，未用共享编译变化抹去已安装路径的真实验收。

### 06:02Z：依赖对齐后当前四项 CI 全绿

另一工作流于 05:52:35Z 更新 Windows GUI 的锁文件与相关源码；R3-A 没有编辑依赖声明或 Cargo.lock，原 ci7/ci8 锁文件哈希相同。保留其改动后，[ci9](assets/r3a-se-child-closure-ci9-summary.json) 使用规定三项 Cargo 环境、1.99.0 stable、target-r2a，并额外保留 CARGO_NET_OFFLINE=true 与 clippy --locked。**06:02:44Z fmt/clippy/build/test 全部 exit 0；1416 passed / 0 failed / 10 ignored、69 组；526 份源码/Swift/fixture/plist 构建输入检查期间未变**。每项前可用空间 15.391–15.620 GB。

[最终源码核对](assets/r3a-final-source-check-ci9-20261014.json) 仍匹配该快照，F 对此当前整合版本关闭；ci8 的临时保护失败仍作为历史保留。Mac 原生安装仍为已经过实机 SE 取消/正向吊销验证的组件哈希，没有为共享 UI 改动再安装或触发 Touch ID。当前 ndu 已吊销且历史保留，§6 的反向/重新加入、审计历史差异、手机、最终 biometric failure 与阈值未决项不因 CI 全绿而消失。
