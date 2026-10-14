# R2-D：运行时实测、连接测试与 T08 收尾

2026-10-12–13，macOS arm64，Rust **1.99.0 stable**。工作树保持 main；没有执行 commit、checkout、stash、reset、rebase、push 等 git 状态操作。

**代码与可运行账号的验证已完成；运行时验收尚未全部完成。** Claude 现有 OAuth 已过期，日常第三方 provider 的最小调用未回复；用户已明确把可用 Claude 启动配置的补充留到明天。Gemini / Grok 未登录，Cursor 额度耗尽，两个 IDE 未安装。本轮完成 Codex exec、Codex TUI、Devin 的托管模型实测，不能把 Codex 两种模式算作两个不同运行时来满足「Claude + 另外两个」门槛。channels 三项和另外三家的超时配置实效仍未测。

## 改动文件与范围

| 文件（相对仓库） | 改动 |
| --- | --- |
| `rust/crates/kv-proxy/src/gateway.rs` | 小容量测试驱动同一生产接纳路径；断开 / stop 回收验证；审批后的发送提取为独立函数；HTTP/2 authority 校验；接入响应恢复 |
| `rust/crates/kv-proxy/src/gateway/recovery.rs` | 会话内挂起操作、原请求绑定、断开后执行 / 响应保留、一次领取、撤销 / exp 清理、容量和响应大小限制 |
| `rust/crates/kv-proxy/src/transparent.rs` | 私有 semaphore 注入入口；显式等名额、断开后补位和 stop 关闭验证；生产仍为 64 |
| `rust/crates/kv-proxy/src/approval.rs` | typed local error 解码；明确区分拒绝、取消、到期；终态 JSON 和 SDK 禁止重试头 |
| `rust/crates/kv-proxy/tests/{approval,gateway_flow,recovery}.rs` | 两条 HTTP 路径的 typed errors、真实 TCP 断开 / 二进制结果 / 一次领取、SDK 重试绑定、撤销、请求不重放 |
| `rust/crates/kv-proxy/examples/sdk_fixture.rs`、`tests/r2d_sdk_lab.py` | 临时 vault、假审批 provider、真实网关与官方 Python SDK 的 HTTP/1.1 / h2-only 实验 |
| `rust/crates/kv-mcp/src/{approval,session,server,fake_helper}.rs` | 按已测 clientInfo.name/version 选预算；未测 Codex 50 s；15 s progress 常量；typed local outcomes / 旧 cancelled reason；显式 feature 下的探针记录 |
| `rust/crates/kv-mcp/src/approval_tests.rs`、`tests/snapshots/{approval_results,local_approval_results}.json` | 预算版本 / 覆盖 / 硬上限回归；中英文 A.8 与本地拒绝 / exp 到期的完整工具结果快照 |
| `rust/crates/kv-mcp/examples/approval_fixture.rs`、`tests/r2d_{runtime_lab,codex_tui}.py` | 真实 Rust Server + Appendix C FakeHelper；四分钟工具、续等、隔离配置、真实 TUI 与 Stop 探针 |
| `rust/crates/kv-hook/examples/stop_fixture.rs` | 真实 `handle_stop` + 私有 fake-helper socket；只记录实际字段名、PPID、active / loop_count 与输出 |
| `docs/runtimes.md` | 实测支持矩阵、预算和错误语义、SDK / 恢复边界 |
| 本报告、`assets/r2d-*` | 命令、版本、实测、CI 与变更请求证据 |

没有修改 kv-helper、kv-core 向量、mobile、架构文档、安装器、Cargo.toml 或 Cargo.lock。SDK 验证包只安装到 `rust/target-r2d/sdk-venv`，没有新增产品或仓库依赖。

## A：两个测试的根因、复现与修法

最初软限额为 1048575。改为 `ulimit -n 256` 后，在同一 test binary 中同时跑两条 `bounded` 测试：**20 / 20 轮失败**，包含原问题的 ConnectionRefused、ConnectionReset、os error 24。单独跑网关测试通过。

每条测试撑满 64 条 loopback 连接，客户端、服务端两个 fd 都属于同一测试进程：两组就要 256 个 fd，尚未计入两个监听器、Tokio 和其他测试。`accept` 失败会结束监听循环，随后新连接表现为拒绝；已有 fd 紧张时还可能直接产生 reset。透明代理仅 `yield_now`，也没有证明此前的连接都已占槽。reqwest 的连接池增加了与语义无关的资源占用。

修法：网关测试在启动前把自己的 semaphore 设置为 8，并先断言默认仍是 64；透明代理的公开 `start` 仍创建 64 个槽，测试经私有 `start_with_permits` 给同一接纳 / upgrade / stop 路径传入 8 个槽。二者等待实际 semaphore 名额变化，拒绝多余连接，释放名额，再接受新连接；网关用原始 TCP 验证 401，随后 shutdown 并验证原连接 EOF 与槽回收；透明代理断开一条、等待释放、补满，再发 stop 并检查每条现有连接关闭、监听任务结束、名额全部回收。只接受 EOF 或 ConnectionReset 作为主动关闭，其他 I/O 错误仍失败。没有删测试、加 ignore、增大生产上限或依赖端口不复用。

```sh
cd /Users/guang/dev/keyvalet/rust
export CARGO_TARGET_DIR=/Users/guang/dev/keyvalet/rust/target-r2d
ulimit -n 256
cargo +1.99.0 test -p kv-proxy --locked --lib bounded
```

证据：[原始复现](assets/r2d-proxy-before-repeat.log)、[修后 20 轮](assets/r2d-proxy-256-20.log)、[结构化结果](assets/r2d-proxy-256-20.json)。最终源码的重复验证记录在本报告末尾。

## B：实测环境和方法

[版本与环境](assets/r2d-versions.json)，[汇总](assets/r2d-runtime-summary.json)。所有有效实验使用现有 CLI 账号，未输入凭据、未构造本地模型 endpoint。模型由真实托管服务决定如何调用工具；工具端是本仓库编译的 Rust `kv-mcp::Server` 和已有 FakeHelper。

四分钟实验显式给服务器 300 s 预算、fake helper 在 240 s 批准，以测客户端边界；这不是产品默认预算。两个 alias 最终都调用真实 `credential_http_request`。silent alias 只移除用于发送 progress 的请求 / context token，记录收到的真实 token，但不发 progress。不会伪造 token。15–240 s 边界的竞争会让成功组出现 15 或 16 次通知。

有效 native 实验的 MCP 程序直接是 Rust fixture，父进程是实际运行时。Stop fixture 调用生产 `handle_stop` 逻辑，经临时 socket 查同一个 FakeHelper；它刻意不走已安装 helper 的签名 / peer 信任路径。输入只记录字段名，没有保存 last_assistant_message、transcript 内容。两次 Stop 的 PPID 与 MCP 记录的 agent.pid 相同。所有配置放在私有 `/tmp/kv-r2d-*` 中，实验结束删除；没有直接写用户全局配置或替换其他 server。

**隔离失误：** 第一批 Devin 的 `--config` 主配置中写了旧 `mcpServers`，当前版本从独立的全局 MCP 文件导入同名 `keyvalet`，导致一次合成调用误连已安装 helper，出现认证等待与冷却；该组已停止，未输入任何凭据，不能作为假 helper、超时、Stop 或模型文案证据。原记录保留在 `assets/r2d-runtime-before/devin-*` 并列为无效。本轮随后使用 `.devin/mcp_config.json` 禁用所有全局 server 的项目投影，使用唯一 `r2dprobe`，确认 Rust initialize 与调用记录后重测。当前全局 Devin `keyvalet` 仍指向已安装 `kv-mcp`。这次失误不等同于满足「从未触碰真实 vault」的硬性约束。

Codex exec 的早期 progress / silent 组有一个透明 wire relay，仍是 Rust Server / FakeHelper 和真实托管模型；其进程关联不用于 Stop 证据。后来 native 组、TUI 组和文案复测均直接启动 Rust fixture。最初 TUI 试验误用带引号的 CLI 点路径，配置解析阶段报 invalid transport，没有进入工具；`r2d-runtime-tui-final` 是修正后的实测。

| 运行时 / 版本 | 4 分钟 + progress | 4 分钟 silent | clientInfo.name / version；token | Stop 输入 / 接受证据 | channels |
| --- | --- | --- | --- | --- | --- |
| Claude Code CLI 2.1.282 | 未测：日常 api.muapi.ai / glm-5-3-flash-abliterated 的 HI 在 45 s 监督边界仍无回复；现有 Claude OAuth 刷新失败 1.269 s，未进入工具 | 未测 | 没有工具阶段的 initialize / token | 本轮未测 | 启用 flag 的 idle / busy，以及不加 flag 的丢弃均待可用会话 |
| Codex exec 0.162.1 | 240.015 s 完成；16 通知；另设 timeout=900 的 native 组 240.004 s 完成 | 240.006 s 完成；0 通知 | `codex-mcp-client` / `0.162.1`；两组 token=1 | 九字段；真实 block 后调用 wait，完成一次 10.002 s 续等；后续模型 stream 重连 / 监督结束，最终结果未取得 | 非 V1 channels 目标；不得由它推断 Claude 行为 |
| Codex TUI 0.162.1 | 240.007 s 完成；15 通知；无 per-server 扩大超时 | 240.012 s 完成；0 通知 | 同上；两组 token=1 | R2-D 的 Stop 是 exec；W5 的 TUI 证据仍属历史 | 同上 |
| Devin CLI 3000.11.3 (9c803229faa4) | 240.006 s 完成；16 通知 | 240.007 s 完成；0 通知 | `rmcp` / `3.1.0`；两组 token=1 | 五字段；block → wait → 原 HTTP 200；active=true 时 `{}` 放行 | 非 V1 channels 目标 |
| Gemini CLI 0.39.1 | 未进入工具：浏览器登录提示，45 s 由监督程序结束 | 未测 | 未测 | 未触发 AfterAgent | 非 V1 channels 目标 |
| cursor-agent 2026.10.01-e373342 | 未进入工具：先 Named models unavailable；指定 Auto 后 usage limit | 未测 | 本轮未测，不能用 W5 的 Cursor / 1.0.0 冒充本轮记录 | 未测 | 非 V1 channels 目标 |
| Grok Build 1.0.50 (c58f321264ba) | PATH 无 grok；现有 W5 native binary 的最小调用 NotSignedIn，0.514 s | 未测 | 未测 | 未测，不注册未经验证的 Stop | 非 V1 channels 目标 |
| Claude Desktop / Cursor IDE | `/Applications` 与用户 Applications 未安装 | 未测 | 未测 | 未测 | 未测 |

认证 / 额度 / 配置阶段失败不是工具超时。TUI 在工具完成后保留 20 s 再由监督退出，不表示四分钟工具被杀。四分钟成功只说明下界 ≥240 s；两种组都完成，不能据此声称 progress 重置空闲计时器，也不能证明 300 / 600 / 6000 s 的精确上界。

主要四分钟证据：[Codex 默认 progress](assets/r2d-runtime-before/codex-progress/wire.jsonl)、[silent](assets/r2d-runtime-before/codex-silent/wire.jsonl)、[TUI progress](assets/r2d-runtime-tui-final/codex-tui-progress/wire.jsonl)、[TUI silent](assets/r2d-runtime-tui-final/codex-tui-silent/wire.jsonl)、[Devin progress](assets/r2d-runtime-native-before/devin-progress/wire.jsonl)、[Devin silent](assets/r2d-runtime-native-before/devin-silent/wire.jsonl)。准备阶段的命令 / 退出 / 监督边界见 [auth](assets/r2d-auth)。

### next_steps 前后测

fake helper 延迟 35 s，调用预算 10 s，未注册 Stop。

| 运行时 | 原文：原调用 / 续等次数 / 执行次数 | 新文：原调用 / 续等次数 / 执行次数 | 结果 |
| --- | --- | --- | --- |
| Codex exec | 1 / 2 / 1 | 1 / 2 / 1 | 两组都拿到原 HTTP 200；不重发原请求 |
| Devin CLI（隔离后的有效组） | 1 / 2 / 1 | 1 / 3 / 1 | 两组都拿到原 HTTP 200；轮数差异来自模型回合时机，不是证明新文更优 |

新增一句：「没有其他独立工作时，请在结束本轮前调用续等工具。」原文已经能驱动这两个模型续等；没有把后测成功归因成未经对照证明的文案提升。[前测 Codex](assets/r2d-runtime-native-before/codex-pending/wire.jsonl)、[Devin](assets/r2d-runtime-native-before/devin-pending/wire.jsonl)、[后测](assets/r2d-runtime-after)。

### Stop 与配置边界

Codex Stop 字段：`cwd, hook_event_name, last_assistant_message, model, permission_mode, session_id, stop_hook_active, transcript_path, turn_id`。MCP agent.pid 与 hook PPID 均为 4875；输出 `decision=block` 后出现真实 `credential_wait_approval` RPC。该轮后来有托管模型 stream 断开和 180 s 监督退出，不能称为已经取得最终结果。[hook](assets/r2d-runtime-native-before/codex-stop/hook.jsonl)、[wire](assets/r2d-runtime-native-before/codex-stop/wire.jsonl)、[CLI](assets/r2d-runtime-native-before/codex-stop/stdout.log)。

Devin Stop 字段：`hook_event_name, last_assistant_message, prompt_id, session_id, stop_hook_active`。MCP agent.pid / hook PPID 均为 6850；block 后两次 wait 得到原结果，随后 active=true 的 Stop 输出 `{}`。[hook](assets/r2d-runtime-native-before/devin-stop/hook.jsonl)、[wire](assets/r2d-runtime-native-before/devin-stop/wire.jsonl)。生产 Stop schema 没有必要改变；只新增真实输出验证 fixture。Cursor / Gemini / Claude 的本轮活会话证据缺失，不能修改其输出 schema 来迎合未观察到的行为。

Codex `tool_timeout_sec=5` 实际返回 `timed out awaiting tools/call after 5s`；设为 900 后完成 240.004 s。[小值](assets/r2d-runtime-native-before/codex-timeout-small/stdout.log)、[900](assets/r2d-runtime-native-before/codex-timeout-large/wire.jsonl)。这是字段生效的证据，不证明精确默认上限。短值组没有记录到 MCP cancellation 通知，不能宣称实时 `client_timeout_observed` 已发生；该审计仍由 CI 的明确 timeout notification 测试验证。

Claude / Gemini `timeout` 与 Grok `tool_timeout_sec` 没有工具阶段证据，保持未测。[OpenAI 配置参考](https://learn.chatgpt.com/docs/config-file/config-reference)、[Gemini MCP timeout](https://geminicli.com/docs/tools/mcp-server/)、[Grok 配置](https://docs.x.ai/build/settings)仅为配置契约来源。Claude channels 必须在交互会话验证；开发 flag 在 `-p` 下被忽略，不能用 print 模式证明无 flag 的静默丢弃。[官方 channels reference](https://code.claude.com/docs/en/channels-reference)

## C：交 R2-E 的 §6.9.3 回写建议

不直接改架构文档。建议注明本轮的证据与未测范围，替换以下单元格 / 行：

| 原文 | 新文 | 证据 |
| --- | --- | --- |
| Claude CLI「2.1.282 在合成本地模型接口下两组均完成 240 s」 | 「W5 合成本地模型结果为历史 CLI 生命周期证据；R2-D 托管 OAuth 已过期，日常第三方 provider 的 HI 无回复，未进入工具。28 h / 30 min 仍为文档值，不能当实测」 | `r2d-auth/claude*.json`、stdout / stderr；用户延期 |
| Claude CLI「channels 声明/发送有 CI；交互式运行时提示不可用」 | 「能力声明 / 发送有 CI；本轮 idle 唤醒、busy 合并、不启用 flag 的静默丢弃均未测。需已登录交互会话，不能用 -p」 | 认证记录、官方 channels reference |
| Codex「默认 60 s；显式确认硬超时后 180 s」 | 「实际 `codex-mcp-client` / `0.162.1` 默认 180 s；未测名称 / 版本 50 s；显式确认 server 硬限 ≥190 s 可采用 180 s。更小确认上限 / 显式 override 优先」 | exec / TUI 两组均 ≥240 s；`client_budget` 精确匹配测试 |
| Codex「0.162.1 TUI/exec 两组均完成 240 s；精确默认上限未证实」 | 「R2-D 托管模型：exec 240.015 / 240.006 s，TUI 240.007 / 240.012 s；均有 token。源码 / 文档默认值与实际下界分列；不声称精确上界」 | 四组 wire，版本汇总 |
| Codex「tool_timeout_sec = 900」 | 「字段生效：5 s 触发 5 s timeout，900 s 允许 240 s 完成；安装器只写该条目的事实和效果验证分开」 | 小 / 大值试验 |
| Codex Stop「TUI 与 exec 均实测触发 Stop」 | 「W5 测过 TUI / exec；R2-D exec 九字段，block 后真实续等。最终回合受模型 stream 错误 / 监督结束影响，未取得最终结果」 | Stop hook / wire / CLI |
| Devin「3000.11.3 两组均完成 240 s」 | 「R2-D 有效隔离 + 托管模型 240.006 / 240.007 s，token=1，16 / 0 通知；实际 clientInfo rmcp / 3.1.0，仍默认 50 s」 | native wire、helper 执行计数 |
| Cursor CLI「两组约 60 s cancellation」 | 「保留 W5 60 s 历史测量；R2-D 账号 usage limit，未进入工具。不能拿本轮登录 / 额度退出证明工具时限」 | auth/cursor*；W5 |
| Gemini「600 s；代码有 progressReporter」 | 「600 s 为契约 / 源码值；R2-D 登录提示中止，timeout、token、AfterAgent 仍未实测」 | auth/gemini* |
| Grok「1.0.50 因未登录未进入工具」 | 「R2-D 缓存 native 同版本仍 NotSignedIn；6000 s / 字段实效仍未测」 | auth/grok*、version |
| HTTP「OpenAI/Anthropic SDK 600 s」 | 「Python OpenAI 3.29.0 / Anthropic 1.13.0 实际默认 read timeout=600、max_retries=2；真实 gateway HTTP/1.1 与 h2-only、wildcard 边界、三种终态均验证」 | SDK results 与命令 |

同时建议改 §6.9.2 / §9.4 / A.8：增加模型端 `approval_cancelled`；明确当前 IPC `approval_expired + reason=cancelled` 的兼容适配；区分 dialog wait timeout（exp 前 pending）和 request expiry；HTTP 到期采用 410 并禁止终态 SDK 自动重试；补上 gateway 恢复头、16 / 8 MiB 限制与同一活会话边界。

## D：T08 的本地错误与恢复

| 情况 | HTTP / JSON error.type | 理由 |
| --- | --- | --- |
| 用户明确拒绝 | 403 / `keyvalet_approval_denied` | 权限被明确拒绝，禁止绕路或索要 key |
| 明确本地取消 | 409 / `keyvalet_approval_cancelled` | 此请求已结束，没有授予权限；不是用户说「不」 |
| exp 到期、未收到决定 | 410 / `keyvalet_approval_expired` | 审批资源已作废。408 通常表示传输等待超时且会被 SDK 重试，易产生新弹窗；410 更符合资源生命周期 |
| 等待预算 / transport 超时但 exp 未到 | 429 / `keyvalet_approval_pending` | 仍可批准，`Retry-After: 30`，不映射成拒绝 |

终态带 `x-should-retry: false`，实测两个 SDK 的 409 都只到达 helper 一次。生产 helper 当前 `expired + reason: cancelled` 明示取消，前端适配后返回 cancelled。typed `local_approval_{denied,cancelled,expired}` 可直接解码；`local_approval_timeout` 必须附保留的 id / exp，exp 前 pending、exp 后 expired；不猜测英文错误里的 denied/cancelled 含义。

挂连接断开后，独立 task 继续等同一许可；批准后使用批准前的凭证记录对照和原始二进制 body，正常流式发送。如果原等待者已断开或此前拿到 429，收集并保留响应。相同 route token、epoch、凭证、method、URL、过滤后的 headers、原始 body 才能领取；`X-KeyValet-Approval-Id` 不进入 digest / 上游 headers；SDK retry-count 元数据也不进入绑定。修改 body 返回 mismatch，第二次领取返回 already_consumed。

没有 approval-ID header 的 SDK 重试也可合并同一活绑定、取得已经保留的结果，避免 background task 执行之后继续返回 pending。已完成的新意图可以新建审批；显式带 id 的重试始终指向旧票据。因此仍不承诺外部 HTTP exactly-once delivery。

内存上限 16 个 ticket、每条请求 ≤1 MiB、每条 detached response ≤8 MiB；超出 / 中断时返回 `keyvalet_response_unavailable`，不再次执行。完整响应在 exp 或 gateway revoke / shutdown 时清除。原响应向原等待者交付就计为已领取，后续断流不能保证取回；gateway / helper 重启也不保留。要覆盖这些边界需要 helper 持有实际响应 / 流结果的契约。

测试：[真实 TCP / 原始二进制 / 一次领取 / SDK 无 id 重试 / revoke](../../rust/crates/kv-proxy/tests/recovery.rs)，同文件模块的虚拟时间验证 exp 释放 zeroizing payload、超大响应不重放；[HTTP / transparent adapter 三种错误](../../rust/crates/kv-proxy/tests/approval.rs)。

### 官方 SDK 验证

OpenAI 3.29.0 用 httpx 0.28.1；Anthropic 1.13.0 当前用 httpx2 2.13.1，不能传 httpx.Client。两者均为 Python。验证没有联系真实 API：API URL 是网关允许的具体子域路径，网关是实际 Rust TCP server，helper 响应为合成数据，vault 是临时 legacy fixture。

```sh
cd /Users/guang/dev/keyvalet/rust
export CARGO_TARGET_DIR=/Users/guang/dev/keyvalet/rust/target-r2d
cargo +1.99.0 build -p kv-proxy --locked --example sdk_fixture
cd ..
rust/target-r2d/sdk-venv/bin/python rust/crates/kv-proxy/tests/r2d_sdk_lab.py \
  --fixture rust/target-r2d/debug/examples/sdk_fixture \
  --output docs/remote-approval-reports/assets/r2d-sdk-verified
```

[完整输出](assets/r2d-sdk-verified-output.log)、[结构化结果 / 版本 / 默认值](assets/r2d-sdk-verified/results.json)、[helper 请求记录](assets/r2d-sdk-verified/helper.jsonl)、[HTTP 版本与状态审计](assets/r2d-sdk-verified/audit.jsonl)。26 条记录包括 24 个请求用例和两条 SDK 默认设置检查。

输出摘要：两个 SDK 在 HTTP/1.1 与 `http1=False,http2=True` 下都取得 `SDK_GATEWAY_OK` / 200；denied / cancelled / expired 分别 403 / 409 / 410，error.type 正确、helper_requests=1；apex / evil-prefix 主机均 403、helper_requests=0。HTTP/2 `:authority` 不提供 HTTP/1 Host，原实现会误判 421，已修复，并继续检查两者与 loopback 地址匹配。透明代理 CONNECT 绑定保持显式 DNS；没有把 wildcard pattern 当成证书 SAN，也没有宣称透明 h2 支持。

## E：本地拒绝 / 过期快照

真实 MCP 客户端 + FakeHelper typed error 驱动完整 decoder / Requester / tool wrapper，`isError=false`。

| 状态 | 中文 next_steps 的核心差异 |
| --- | --- |
| `approval_denied` | 用户拒绝；不要重试、绕过审批或让用户粘贴密钥；说明原因 |
| `approval_expired` | 未收到决定；仍需结果时可重新发起，产生新审批；非必要不自动重发 |
| `approval_cancelled` | 明确本地取消但未授权；不视为拒绝；先确认是否需要新审批，不索要 key |

[完整本地快照](../../rust/crates/kv-mcp/tests/snapshots/local_approval_results.json)、[全部 A.8 中英文快照](../../rust/crates/kv-mcp/tests/snapshots/approval_results.json)。没有使用真实 vault 弹窗验证；producer 是否准确区分按钮 / 取消 / biometric failure 交 R2-A。

## helper / 安装器变更请求与未决项

1. **R2A-CR1，原生结果的类型保真：** 保留明确拒绝、取消、UI 等待超时、request exp 四种事实。拒绝仅来自用户拒绝按钮；biometric failure、进程 / socket 取消不能写 denied。优先返回普通 ToolResult；错误通道使用上述 `local_approval_*` JSON code，timeout 必须有可信 `approval_id` / `expires_at`。旧 ReadyMessage 的 error String 若携带该 JSON，本 MCP 端也可适配。当前 `expired + reason=cancelled` 已兼容，无需为本轮改 core 向量。
2. **R2A-CR2，跨会话恢复：** 本轮只在活 gateway session 内保存完整有限响应。若要 session / helper 重启后取回，定义 gateway → helper 的原请求 digest、响应状态 / 过滤 headers / body_encoding / 原始 bytes、exp、claim ack 及擦除契约；流中断后的交付问题须单独定义。一张一次性 permit 不能代替响应保存或外部副作用 exactly-once。
3. **R2E-CR1，安装器：** Devin 3000.3+ 的专用 MCP 文件路径需要核对 / 更新；不得只写 `--config` 主文件。若为某运行时配置非默认短超时，也给该 KeyValet 子进程传相同的 `KEYVALET_TOOL_TIMEOUT_SEC`，避免把客户端配置当成 initialize 自动可见的字段；保留其他 env / server / hook。
4. **E07，仍未关闭：** Claude 已登录交互 session 和至少第三个可用运行时；Claude idle / busy / 无 flag channels；Claude / Gemini / Grok 配置边界；Desktop / Cursor IDE；未测平台的 live Stop 和实际原生 UI。用户延期的 Claude 信息不能用等待时间自动视为已提供。
5. 默认客户端精确上界、progress 是否续命、实机签名 / Touch ID / Hello / polkit、远程手机审批与长期 dogfooding没有由这些测试证明。

## 最终验证

所有 cargo 在 `rust/`，`CARGO_TARGET_DIR=/Users/guang/dev/keyvalet/rust/target-r2d`。中间用 `-p` 限定；最终按 AGENTS.md 跑一次全工作区四条命令。runtime-probe feature 的 examples / all-targets clippy 另跑，见 [feature clippy](assets/r2d-clippy-final.log)。

第一次工作区 fmt / clippy 通过，build / test 因磁盘耗尽失败，保留在 `r2d-disk-full-*`。删除本轮 target-r2d 的可重建 incremental 缓存后，最终四条重新运行；使用 `CARGO_INCREMENTAL=0`、`CARGO_PROFILE_DEV_DEBUG=0`、`CARGO_PROFILE_TEST_DEBUG=0`，只关闭调试符号 / 增量缓存，不关闭 debug assertions 或减少测试。未清理其他工作流的产物。

最终工作区检查与第二次低限额 20 轮的结果，在 [最终检查汇总](assets/r2d-final-checks.json) 与对应日志中记录。报告验收状态由这些实际结果与前述未决项共同决定，不把测试通过称为运行时门槛全部完成。

最终结果：

| 检查 | 结果 / 用时 |
| --- | --- |
| fmt --workspace（fmt 为 --all） | exit 0 / 1.167 s |
| clippy --workspace（fmt 为 --all） | exit 0 / 31.542 s |
| build --workspace（fmt 为 --all） | exit 0 / 19.539 s |
| test --workspace（fmt 为 --all） | exit 0 / 295.547 s |
| ulimit -n 256，最终工作区 kv-proxy test binary 的两条 bounded 测试 | 20 / 20 轮通过，40 个测试结果通过 |
| 全工作区测试目标合计 | 1331 passed / 0 failed / 10 ignored（不是去重场景数） |
| 所有权范围源码哈希 | 最终四项前后 changed=[] |

[最终 20 轮原始输出](assets/r2d-final-proxy-256-20.log)、[结构化结果 / binary 路径](assets/r2d-final-proxy-256-20.json)、[测试合计](assets/r2d-final-test-totals.json)、[源码哈希对照](assets/r2d-final-source-after.json)、[最后阶段全局配置哈希对照](assets/r2d-global-config-after-final.json)。低限额复测直接使用本轮全工作区编译出来的最终测试程序，避免另一次 Cargo feature 组合重编译；实际执行的仍是两条测试及其正常并行调度。
