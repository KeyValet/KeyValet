# 远程审批 V1 第二轮：实机闭环的并行 prompt

第一轮（W0–W9，见 [remote-approval-agent-prompts-2026-10.zh-CN.md](remote-approval-agent-prompts-2026-10.zh-CN.md)）交付了契约、relay、helper、CLI、桌面、手机、安装器和软件级全链路测试，但 §16 的实机验收表基本还是「未通过 / 未测」。第二轮的目标只有一个：**把 M2（Ubuntu × MacBook）、M3（手机）、M4（Windows）在真机上跑通，并把事实回写进文档。**

用法同第一轮：每个代码块整块复制给一个 agent。R2-A、R2-B、R2-C、R2-D 并行启动；R2-E 在前四个报告齐后最后跑。

本轮已拍板、所有 prompt 都以此为准的决定（不同意的话，复制前先改）：

| 编号 | 决定 |
| --- | --- |
| K1 | Windows 的 PCP 做不了同一把 P-256 键既 ECDH 又 ECDSA（`0x80090029`）。协议改为：`DeviceRecord` 新增可选 `dk_sig: {pub, alg}`；有 `dk_sig` 时所有身份签名（relay challenge、配对、恢复）用它验，HPKE 仍用 `dk.pub`。Windows 的 DK = PCP ECDH 专用键 + PCP ECDSA 专用键；其他平台不变、不填 `dk_sig`。不做软件回退。 |
| K2 | 账户模型按已实现的接受：手机 App 必须 Google / Apple 登录；桌面与 CLI 仍是匿名注册 + 恢复码（`POST /v1/recovery`）；手机经 SAS 加入后账户归属该登录用户。 |
| K3 | 手机 App 地址固定为 `https://relay.keyvalet.dev`，不可配置。自托管 relay 因此只服务桌面审批端；文档与对外文案照此表述。 |
| K4 | D03 短期设置票保持 Strong；D04 收紧验证器：有限期 T2 Grant 的签名对象必须含标签确认证明；D05 全局 T2 继续拒绝；D06 跨操作 batch、D07 多审批方/quorum、D09 attestation 验证全部推到 V2；D08 由 `/v1/recovery` 关闭；D10 由 Linux peer broker 关闭；D01/D02 按现实现写进附录 B/C。 |

K1–K4 已于 2026-10-12 确认。下面四件需要用户本人动手的事**暂缓**，因此启动顺序为：**R2-B、R2-C、R2-D 现在就能启动**（缺资源的步骤会停下来报告，其余照做）；**R2-A 等第 4 项批准后再启动**（它的第一步就是覆盖安装）；R2-E 最后。

需要你本人动手、agent 做不了的事（各 prompt 遇到缺失会停下来报告，不会猜）：

1. `win11` 虚拟机里登录 `guang\win` 桌面，设置 Windows Hello PIN（R2-B 的交互验收前提）。
2. Apple：`dev.keyvalet.mobile` 主 App 与 `KeyValetNSE` 的 App Group 描述文件（团队 `PWCRJPY7YC`）、APNs 认证密钥 `.p8`、一台可连本机的 iPhone、Sign in with Apple 的 Services ID 配置。
3. Firebase：FCM HTTP v1 的服务账号 JSON 放到 `simvito` 上一个只有 root 可读的路径，把路径告诉 R2-C；不要贴进聊天或仓库。
4. 允许 R2-A 把当前 `main` 的构建**覆盖安装**到 `ndu` 的现有 KeyValet 服务和这台 MacBook 的现有安装（都会先备份 vault 与配置，并给出回滚命令）。

---

## R2-A  M2 实机闭环：Ubuntu 执行端 × MacBook 审批端

```text
你是 KeyValet 仓库（/Users/guang/dev/keyvalet）「远程审批 V1」第二轮的 R2-A 工作流：把 Ubuntu 服务器（执行端）× MacBook（审批端）的远程审批在真机上跑通，并逐项填写验收表。软件级全链路测试已经通过，你的工作是安装、联调、修 bug、测量，不是重写。

【机器与资源】
- 本机：Apple Silicon MacBook，macOS 14+，已安装 KeyValet（用户日常在用），有 Simvito Limited 的 Developer ID 签名身份（team PWCRJPY7YC，`security find-identity -v -p codesigning` 可见）。源码安装器会自动用它签名并启用 daemon 模式 + relay-client。
- `ssh ndu`：Ubuntu 24.04，Linux 6.8，有已安装并在用的 KeyValet 服务与 vault（TPM 模式）。这是用户真实的服务器，不是一次性环境。
- `ssh simvito`：公网 relay 主机。`https://relay.keyvalet.dev` 已部署：Cloudflare 橙色云 → nginx（Origin CA）→ kv-server 监听 127.0.0.1:8787。线上二进制可能落后于当前 main。
- 不要用 Tailscale、Caddy；不改 Cloudflare 设置。

【先读，不读完不要动手】
1. AGENTS.md：CI 四条命令；测试不得依赖本机安装；install.sh 单引号约束；签名与 daemon 模式。
2. docs/remote-approval-architecture-2026-10.zh-CN.md：§2（进程边界）、§4（配对）、§6.5（验证顺序）、§6.8（审批方选择）、§6.10（在场与投递）、§7.4–7.6（Grant / Directive）、§8.5（nginx + Cloudflare 部署）、§16（验收表，你要填的就是它）、附录 B/C/E。
3. docs/remote-approval-reports/：W9.md（安装器行为、已验证项、M5 未完成原因）、OPEN-QUESTIONS.md（尤其 D10、T01、T02、T04、E04、E08）、W1-W5-integration.md（接口修复与 bootstrap 条件）、linux-auth-relay-isolation.md（Linux peer broker：`keyvalet-peer.service`、SO_PEERPIDFD、relay-client 的 control transport）、owner-integration-23.md（owner IPC、匿名注册、配对、Grant 台账、撤销）。
4. docs/remote-recovery-audit.zh-CN.md（`keyvalet audit --remote` 对账与恢复接口）。
5. docs/linux.md「Remote approval V1」一节、docs/review-2026-10.zh-CN.md 顶部的验收表。
6. 代码入口：rust/crates/kv-cli/src/remote*（命令）、kv-helper/src/remote/{startup,bootstrap,pairing,pairing_relay,engine,owner,grants,directives}.rs、kv-relay-client/src/{app,control,control_transport}.rs、kv-platform/src/peer_broker.rs、scripts/install.sh 的 kv_remote_* 函数与 scripts/linux/。

【硬性规则】
- 不执行任何改变 git 状态的命令（不 commit / branch / stash / checkout / reset / rebase / push）；只读 git 可用。直接在 main 工作树改文件。
- 本轮并行的其他工作流各有所有权，你只能改：rust/crates/kv-helper/src/remote/**、rust/crates/kv-relay-client/**、rust/crates/kv-cli/src/remote*、rust/crates/kv-agent/src/remote*、rust/crates/kv-touchid/src/remote*、rust/crates/kv-platform/src/{peer_broker,linux,paths}.rs、scripts/install.sh、scripts/linux/**、scripts/uninstall.sh、docs/linux.md。不要碰 kv-core/src/remote 的类型与向量（R2-B 在改 DeviceRecord）、kv-server/src/{auth,account}.rs（R2-B/R2-C）、kv-push、mobile/、kv-proxy、kv-mcp、kv-hook（R2-D）。必须改别处时，写进报告「变更请求」并停在那一步。
- CARGO_TARGET_DIR=/Users/guang/dev/keyvalet/rust/target-r2a；本机验证用 -p 限定；全工作区四条命令在最终报告前跑一次。
- 不新增依赖。
- 任何验证失败都保持拒绝；不得为了跑通而放宽验签顺序、档位、nonce、exp、角色表或 ptrace/能力策略。
- 覆盖安装前必须备份：ndu 的 /var/lib/keyvalet、/etc/keyvalet、/var/lib/keyvalet-relay*；本机的 /var/db/keyvalet 与 ~/Library/Application Support/KeyValet。备份路径与回滚命令写进报告第一节。不要删除任何备份。
- 日志、报告、截图不得包含恢复码、配对 token、会话令牌、凭证值。恢复码只给用户看一次（终端），报告里写「已向用户显示」。
- simvito 上的 Origin CA 私钥不读、不拷。

【任务】
A. 线上 relay 对齐：核对 simvito 上 kv-server 的构建来源与当前 main 的差异（二进制哈希 vs 本地 `cargo build -p kv-server --release` 产物、`GET /v1/health`、`/v1/account/providers`）。落后则用当前 main 重新构建部署（systemd 单元与 nginx 配置不变，保留 account.env），记录前后哈希。
B. MacBook 审批端安装：`sh scripts/install.sh` 从源码安装（自动签名、daemon 模式、dev.keyvalet.relay LaunchAgent）。确认 `keyvalet status --summary` 显示本地保护与 relay 字段；确认 kv-touchid 的三把 SE 键（DK / AK_q / AK_s）已创建，AK_s 带 userPresence。
C. Ubuntu 执行端安装：在 ndu 上 `sh scripts/install.sh`（TPM 模式；不要 --software），确认 keyvalet / keyvalet-peer / keyvalet-relay 三个服务状态、用户与目录权限、`status --summary` 的 relay 字段；原有 vault 与凭据可继续解锁使用。
D. 配对：按 §4 与 CLI 实现，ndu `keyvalet pair --new`（匿名注册、恢复码只显示给用户），MacBook `keyvalet pair <kv-pair://…>`，两端核对 6 位 SAS，Mac 上 Touch ID 签 SAS。记录从输入命令到两端 `devices list` 都看到对方的用时。
E. 首次远程 use 审批：在 ndu 上用 Claude Code（或 `keyvalet run` / curl 走网关，用户说哪个就哪个；默认 Claude Code 的 `credential_http_request`）发一个 GET 请求用某个已存在凭证；MacBook 弹原生对话框 → Touch ID 批准 → ndu 执行一次 → agent 拿到结果。重复 ≥20 次测 p50 / p95（从 helper 发出请求到收到决定）。然后分别验证：拒绝、超时后 `credential_wait_approval`、同一批准不能用第二次、改参数产生新审批。
F. 远程控制面（§7.4–7.6）从 Mac 操作 ndu，各计时：`remote <ndu> mode per_session`、`remote <ndu> allow --credential … --until 1h`（Strong）、`grant list` 看预算、`remote <ndu> grant revoke-all`、`remote <ndu> lock`、`remote <ndu> unattended --include-sensitive --until 1h` 的二次输入标签流程、`remote <ndu> status/pending/grants/audit`。确认本地 `/keyvalet:mode` 与远程 set_mode 共用设置后端。
G. 在场与投递：Mac 在桌前（有输入、未锁屏）时 ndu 的请求先弹 Mac 对话框；锁屏后 presence 变 away（`remote <ndu> status` 里可见 hint）；`notify always-phone` 的设置能下发（手机侧由 R2-C 验证，你只确认 Directive 落地）。
H. 吊销与恢复：Mac 上 `devices revoke <ndu>` 后 ndu 的待用批准与 Grant 1 分钟内失效；反向吊销 Mac 后 Mac 签的票在 ndu 失效。`keyvalet audit --remote` 两端按 approval_id 对账，差异为 0。
I. 2 小时合盖：Mac 合盖 2 小时，期间 ndu 产生 3–5 个请求（含 1 个 T2）；开盖后积压送达、每个只执行一次、过期的正确标 expired。
J. 过程中每个 bug：先写复现测试（CI 可跑、用假 relay/假 OS 身份），再修，再在真机复验。涉及 D10/peer broker、startup bootstrap、pairing 的修复要特别说明没有放宽认证。
K. 最终在 rust/ 跑四条 CI 命令全绿；更新 docs/linux.md 的真实步骤与已知限制。

【验收（写进报告和 docs/review-2026-10.zh-CN.md 的对应行）】
§16 表与 review 表里这些行给出 通过 / 未通过 / 未测 + 数字 + 证据路径：pair → 首次远程批准 <10 分钟；Mac 审批 p50 <3 s / p95 <8 s；吊销 1 分钟内失效；两端 audit 100% 对账；合盖 2 小时积压送达不重复执行；远程切模式 / 签 1 小时票 / 全部收回各 <5 s；本机优先投递。

【报告：docs/remote-approval-reports/R2-A-m2-acceptance.md】
1. 备份路径与回滚命令。2. 线上 relay 前后哈希。3. 安装记录（两台机器的服务、权限、status 输出摘要）。4. 验收表（每行：结果、数字、证据文件）。5. 修复清单（bug → 复现测试 → 修复文件 → 真机复验）。6. 对 kv-core / kv-server / 其他所有权外的变更请求。7. 未解决问题与下一步。证据（日志、截图、计时 JSON）放 docs/remote-approval-reports/assets/r2a-*。
```

---

## R2-B  Windows：DK 签名键拆分（K1）与原生验收

```text
你是 KeyValet 仓库（/Users/guang/dev/keyvalet）「远程审批 V1」第二轮的 R2-B 工作流：按已拍板的 K1 决定改协议，让 Windows 执行端/审批端的硬件密钥真正可用，并完成 Windows 原生验收。

【背景事实（已在真机验证，不要再 spike）】
- Windows 11 VM（`ssh win11`，宿主 ndu，模拟 TPM 2.0，Rust 1.99.0 / MSVC / PowerShell 7）。当前 main 已能在其上通过四条 CI 命令并完成实际安装、LocalSystem 服务、升级、卸载（docs/windows-native-acceptance-2026-10-12.zh-CN.md）。
- **PCP 不允许同一把 P-256 键既 ECDH 又 ECDSA**：`NCRYPT_KEY_USAGE_PROPERTY` 返回 0x80090029，generic usage 也不行。独立 ECDH 键可得 32 字节 raw secret（BCRYPT_KDF_RAW_SECRET），独立 ECDSA 键可签 64 字节签名。
- Windows Hello `KeyCredentialManager.IsSupportedAsync()` 在 `guang\win` 桌面 session 1 返回 false，因为还没设置 PIN。用户会去设置；设置前 Hello 的交互验收做不了。

【K1 决定（照此实现，不要再评估替代方案）】
- `DeviceRecord` 新增可选字段 `dk_sig: { pub: JWK(P-256), alg: "ES256" }`。
- 有 `dk_sig` 时，所有「设备身份签名」——relay `/v1/auth/challenge→verify` 的 DK 签名、配对 PairStart/PairAccept 中的身份签名、`/v1/recovery` 的签名、relay-client control transport 里 `remote.sign_identity` 的产物——都用 `dk_sig.pub` 验；HPKE 解封继续用 `dk.pub` 做 ECDH。没有 `dk_sig` 时行为与现在完全一致（`dk.pub` 既签又 ECDH）。
- `DeviceKeyProvider` 的 Windows 实现：DK = PCP ECDH 专用键（`ecdh()`）+ PCP ECDSA 专用键（`sign()` 用于身份）；`public_jwk()` 返回 `dk.pub`，新增 `identity_sign_jwk()`（默认实现返回 None，Windows 返回 ECDSA 键公钥）。AK_q = PCP ECDSA 键，AK_s = Hello RSA-2048（RS256），不变。
- `dk_sig` 参与 DeviceRecord 的规范化与一切覆盖 DeviceRecord 的签名/摘要；未知字段规则不变。schema、测试向量、JSON 样例同步。
- 不做软件回退：PCP 任一键创建失败就报错，key_kind 不得标成硬件。

【先读，不读完不要动手】
1. AGENTS.md。
2. docs/remote-approval-architecture-2026-10.zh-CN.md：§3.1–3.2（三平台三把键与 alg）、§4（配对里的身份签名）、§6.2（规范化）、§8.2（challenge/verify）、附录 A.7（DeviceRecord）、附录 B（`/v1/devices`、`/v1/auth/*`、`/v1/recovery`）、附录 F（向量清单）。
3. docs/windows-native-acceptance-2026-10-12.zh-CN.md 全文；docs/windows.md；docs/remote-approval-reports/W1.md（Windows PCP/Hello 部分）、W0.md（向量生成约定）、OPEN-QUESTIONS.md E02。
4. 代码：rust/crates/kv-core/src/remote/{keys,relay,canonical,mod}.rs 与 schemas/remote/、testdata/remote/generate.py；rust/crates/kv-platform/src/device_key/windows.rs 与 src/protection.rs；rust/crates/kv-server/src/{auth,pairing,recovery}.rs（身份验签处）；rust/crates/kv-helper/src/remote/{pairing,platform_keys}.rs 中验证对端身份签名的函数；rust/crates/kv-mobile-core 里验证对端 DeviceRecord 的位置；rust/crates/kv-agent/src/hello/、src/remote/（Windows 对话框与 Hello 签名）。

【硬性规则】
- 不执行任何改变 git 状态的命令；只读 git 可用。直接在 main 工作树改。
- 你拥有：rust/crates/kv-core/src/remote/**、kv-core/schemas/remote/**、kv-core/testdata/remote/**、rust/crates/kv-platform/src/device_key/**、kv-platform/src/{protection,peer_windows}.rs、rust/crates/kv-server/src/{auth,pairing,recovery}.rs 中的身份验签部分、rust/crates/kv-agent/src/hello/** 与 src/remote/** 的 Windows 部分、scripts/install.ps1、scripts/uninstall.ps1、scripts/package-windows.ps1、scripts/test-windows-*.ps1、docs/windows.md、docs/windows-native-acceptance-2026-10-12.zh-CN.md。
- kv-helper 与 kv-relay-client 归 R2-A，kv-mobile-core 归 R2-C：你在这三处只允许做「把身份验签调用改为 kv-core 提供的新函数 `verify_identity_signature(&DeviceRecord, …)`」这一类最小机械替换，每处在报告列出文件与行数，不改其他逻辑。
- CARGO_TARGET_DIR=/Users/guang/dev/keyvalet/rust/target-r2b（Mac）；Windows 上用独立目录。-p 限定；最后全工作区四条命令在 Mac 和 Windows 各跑一次。
- 不新增依赖。
- 不得放宽任何验证；`dk_sig` 缺失时不得回退到「跳过身份验签」。

【任务】
A. kv-core：类型、规范化、`verify_identity_signature` 统一入口（有 dk_sig 用 dk_sig，否则 dk）、schema、JSON 样例、新增向量：`device_record_with_dk_sig_*`（正例；dk_sig 签名用 dk 验必须失败；篡改 dk_sig 字段签名失败；无 dk_sig 的旧记录照常）。RFC 9180 与既有向量全部不变地通过。
B. kv-platform Windows：两把 PCP 键的创建/持久化/删除（LocalSystem 上下文；删除用已验证可行的参数）、`ecdh()` 走 ECDH 键、`sign()` 走 ECDSA 键、`identity_sign_jwk()`；`protection.rs` 状态上报区分 `pcp_ecdh` / `pcp_ecdsa` 是否都存在。Hello RS256 AK_s 路径不变。
C. kv-server：注册时接受并存 `dk_sig`；challenge/verify、配对、recovery 的身份验签改用统一入口；旧记录兼容测试。
D. 最小替换：kv-helper 配对对端验签、kv-mobile-core 对端验签改用统一入口（见硬性规则）。
E. Windows 原生验收（`ssh win11`，源码快照同步过去，MSVC 原生执行）：四条 CI 命令；LocalSystem 下真实 PCP 双键创建 → 身份签名 → ECDH raw secret → HPKE 往返 → 清理；`install.ps1` 实际安装/升级/卸载回归；`status --summary` 显示两把 PCP 键状态。
F. Hello 交互验收（用户设好 PIN 后；没设就停在这里报告）：在 `win` 桌面会话用 kv-agent 创建 AK_s（RS256）、签一次 Strong 决定、取消、重复提示；记录 IsSupportedAsync、创建、签名各自结果。
G. 跨平台：Windows 作为审批端批一个来自软件执行端 fixture（或 R2-A 的 ndu，若其报告已就绪）的请求：Quick 用 PCP ECDSA、Strong 用 Hello RS256，ndu/fixture 按设备记录 alg 验签。记录延迟。
H. 文档：docs/windows.md 的密钥表（DK 两把、alg）、验证矩阵；windows-native-acceptance 追加本轮结果。向 R2-E 提供架构 §3.1 / 附录 A.7 需要回写的准确文字（放在报告里，不直接改架构文档）。

【验收】
- Mac 与 Windows 上 rust/ 的四条 CI 命令全绿。
- 新向量与旧向量全部通过；用 dk 公钥验 dk_sig 签名的用例必须失败。
- Windows VM 上：PCP 双键创建与身份签名/ECDH 成功，清理成功，无软件回退；安装/升级/卸载回归通过。
- Hello 交互项：通过，或明确写「等待 PIN」。

【报告：docs/remote-approval-reports/R2-B-windows.md】
改动文件；协议变更的精确描述（字段、规范化、验签规则）与向量清单；Windows 真机结果表；最小替换的文件/行号；给架构文档的回写文字；未决项。证据放 assets/r2b-*。
```

---

## R2-C  手机闭环：后台推送、Android 真机审批、iOS

```text
你是 KeyValet 仓库（/Users/guang/dev/keyvalet）「远程审批 V1」第二轮的 R2-C 工作流：把手机 App 从「前台 WS 软件测试通过」推进到「锁屏收到推送、Quick/Strong 真机批准、30 秒升级、设置三步」真机通过。Android 先行（Pixel 7 已连本机、Google 登录已真机通过），iOS 视用户提供的资源而定。

【已实现、不要重做】
- Flutter 工程 mobile/（Dart 约 9.2k 行，Swift/Kotlin 约 4k 行），`flutter analyze` / `flutter test`（40 项）通过；kv-mobile-core（Rust，flutter_rust_bridge + iOS 静态库绑定）、kv_native 插件（SE / Keystore 三把键、生物识别门控签名）、KeyValetNSE target、FirebaseMessagingService 骨架。
- Google 登录真机通过；Apple 登录未验证；App 地址固定 https://relay.keyvalet.dev（K3，不可配置，不要加配置项）。Android 包名 / iOS Bundle ID `dev.keyvalet.mobile`，团队 PWCRJPY7YC。
- Pixel 7 原生安全测试 2/2：跳过 CryptoObject 直接签 AK_s 被 Keystore 拒绝。
- kv-push（rust/crates/kv-push）：APNs/FCM 的元数据推送服务骨架（Silent/Banner 两档，只收 token + approval_id + delivery，拒绝任何审批正文）。relay 有 `POST /v1/devices/push-token`。
- 软件全链路：登录 → 双端配对 → silent → 真实 30 s escalate → Quick → T2 Strong → 1 小时 Grant → revoke-all 通过。
- 未完成（OPEN-QUESTIONS T03 / E05 / E06 / D09）：relay → kv-push 的路由没接；后台推送没接；iPhone / 描述文件 / APNs / FCM 服务账号未就绪；Play 内部测试未上传。

【先读，不读完不要动手】
1. AGENTS.md。
2. docs/remote-approval-architecture-2026-10.zh-CN.md：§6.10（投递：silent → 30 s escalate → banner；人在电脑前手机不响；`notify always-phone`）、§9.2 与 §9.2.1（页面、Flutter/Rust/原生分工、NSE 不跑 Flutter、双绑定）、§3.1 手机列、§8（relay API）、附录 A.6（PresenceHint）、A.8。
3. docs/remote-approval-product-2026-10.zh-CN.md §6、§6.2、J-R2、J-R4。
4. docs/remote-approval-reports/W8.md 全文（含「Google／Apple 登录与固定地址补充验收」）、OPEN-QUESTIONS.md、docs/mobile-console-setup.zh-CN.md、mobile/docs/account-login.md、mobile/README.md。
5. 代码：rust/crates/kv-server/src/{messages,presence,account,http,cleanup}.rs（审批创建/升级/取消的位置，push-token 存储）；rust/crates/kv-push/src/；rust/crates/kv-mobile-core/src/{engine,relay,account,store,ffi,api}.rs；mobile/lib/src/、mobile/android/app/src/main/kotlin/、mobile/ios/KeyValetNSE/、mobile/native/。

【硬性规则】
- 不执行任何改变 git 状态的命令；只读 git 可用。直接在 main 工作树改。
- 你拥有：rust/crates/kv-push/**、rust/crates/kv-mobile-core/**、mobile/**、rust/crates/kv-server/src/push*.rs（新建）与 messages.rs / cleanup.rs 中调用推送路由的新增行、kv-server/src/account.rs 中仅 push_token 相关函数、deploy/relay/ 下新增 kv-push 的 systemd 单元与 nginx location、docs/mobile-console-setup.zh-CN.md、mobile/docs/**。不要碰 kv-server/src/{auth,pairing,recovery}.rs（R2-B）、kv-core 类型与向量（R2-B；需要新对象就写变更请求）、kv-helper / kv-relay-client / kv-cli（R2-A）。
- CARGO_TARGET_DIR=/Users/guang/dev/keyvalet/rust/target-r2c；-p 限定；最后全工作区四条命令 + `flutter analyze` + `flutter test` + iOS/Android 目标 `cargo build` 各一次。
- Dart 不碰私钥、不验签、不解析信封；后台路径全部原生 + Rust；Strong 必须是 Keystore / SE 的生物识别门控签名，不接受 local_auth 式布尔值。
- 推送正文只允许元数据：approval_id、delivery.mode、to；审批内容只能在手机上解密后显示。kv-push 与 relay 的日志不出现 token 全文（只打印后 6 位）。
- 不得关闭 Android 系统的包验证来绕过 `INSTALL_FAILED_VERIFICATION_FAILURE`；用正常的签名 debug 构建或 Play 内部测试渠道安装。
- 任何需要用户提供的资源（APNs .p8、描述文件、FCM 服务账号路径、iPhone、Play 签名证书指纹）缺失时：把精确清单写进报告「需要用户提供」并继续做不依赖它的部分，不要用占位值冒充。
- 新依赖须已发布 ≥ 7 天并写入报告（名称/版本/发布日期/理由）。

【任务】
A. relay → kv-push 路由（T03）：kv-server 在 approval_request 创建、approval_escalate、approval_cancel、Directive 下发时，对每个 `to` 设备查 push token 与 presence，按 §6.10.2 决定 Silent / Banner，调用 kv-push（本机 loopback HTTP，带共享 bearer，配置在 account.env 同类文件）。失败重试 3 次指数退避；无 token 的设备跳过并计数。单元测试用假 kv-push。
B. push token 生命周期：手机登录/冷启动/FCM token 轮换时上传；退出登录、设备吊销、会话失效时 relay 删除 token；kv-push 收到 APNs 410 / FCM UNREGISTERED 时回调 relay 删除。测试覆盖。
C. kv-push 部署：systemd 单元（专用用户、只听 127.0.0.1:8788、EnvironmentFile 指向 root-only 文件，内含 APNs key 路径 / FCM 服务账号路径 / 共享 bearer）与 nginx 不暴露它（只 relay 本机调用）。部署到 simvito（`ssh simvito`），不改 Cloudflare。服务账号 / .p8 文件由用户放到服务器指定路径，你只配置路径。
D. Android 后台：FirebaseMessagingService 收 data message → 读本地密文队列或拉取 → Rust 解密 → 两个通知渠道（Silent：低优先级无声；Banner：高优先级 + 声音）→ 锁屏动作「允许 / 拒绝」走前台服务用 AK_q 签 Quick（仅 scope 允许 Quick 的请求）；Strong 请求的通知只带「打开」，进 App 走 BiometricPrompt + CryptoObject。approval_escalate 更新同一条通知（同 notification id）。设备重启后 token 仍有效。
E. Android 真机验收（Pixel 7 + 本机 Mac 作执行端：R2-A 把当前 main 装到本机后，本机就是已配对执行端；在此之前用软件执行端 fixture 经线上 relay）：扫码配对 → 一条 T0/T1 请求：手机静默、Mac 在桌前先弹 Mac 框；Mac 锁屏后再发一条：手机 30 s 内由 silent 升级为 banner → 锁屏 Quick 批准 → Mac/fixture 执行一次 → 第二次领取被拒；一条 T2：通知只能「打开」，App 内指纹 Strong 批准；设置页：切模式、签 1 小时票、revoke-all，各计时；「我不在电脑前」开关后手机立即 banner；退出登录后收不到推送。每步截图/录屏。
F. Play 内部测试：`mobile/scripts/package-play.sh` 产 .aab（签名材料由用户提供路径），按 docs/mobile-console-setup 上传步骤写清；拿到 Play 应用签名指纹后，提醒用户在 Google Cloud 登记对应 Android client 并同步 relay 配置。
G. iOS（资源到位时）：NSE 收 APNs mutable-content → 共享 App Group 的 Rust SQLite 解密 → interruptionLevel（silent → .passive，banner → .timeSensitive）→ threadIdentifier = approval_id；锁屏 `.authenticationRequired` 动作 → 主 App 后台 AK_q 签 Quick；Strong 进 App Face ID。Apple 登录真机验证。TestFlight 打包脚本与步骤。资源缺失则只做模拟器可验证部分并列清单。
H. 稳定性：手机离线 1 小时后上线，待批列表与 relay 一致；App 被系统杀死后推送仍能唤起；时钟偏差 ±5 分钟的提示。

【验收】
- 四条 CI 命令、flutter analyze/test、iOS/Android 目标构建全绿。
- 单元/集成：路由决策表（presence × delivery）、token 生命周期、kv-push 拒绝正文、410/UNREGISTERED 清理。
- Pixel 7 真机：E 中每一步通过并有截图/录屏；§16 的「iPhone / Android 锁屏 Quick、Strong、升级与设置三步」Android 列可填通过。
- iOS：通过，或精确的资源清单。

【报告：docs/remote-approval-reports/R2-C-mobile.md】
改动文件与新依赖表；路由与 token 生命周期的设计说明（含失败模式）；kv-push 部署记录（无秘密）；Android 真机验收表（每步截图路径、计时）；Play 上传状态；iOS 状态与「需要用户提供」清单；对 kv-core / relay API 的变更请求；未决项。证据放 assets/r2c-*。
```

---

## R2-D  agent 侧：运行时实测、proxy 稳定性、未闭合的本地语义

```text
你是 KeyValet 仓库（/Users/guang/dev/keyvalet）「远程审批 V1」第二轮的 R2-D 工作流：agent 可见一侧的收尾——修掉 kv-proxy 两个在本机不稳定的测试、把 §6.9.3 运行时预算表从「源码推断」变成「实测」、补齐 OPEN-QUESTIONS T08 的本地语义。

【已知现状】
- 当前 main 在本机：`cargo fmt / clippy / build` 全过；`cargo test --workspace --locked` 只有 kv-proxy 两个失败，都与连接数/文件描述符有关：
  - `gateway::tests::idle_connections_are_bounded_and_release_their_slots_on_disconnect`：reqwest ConnectionRefused 127.0.0.1:<port>
  - `transparent::capacity_tests::connection_capacity_is_bounded_and_stop_closes_existing_connections`：一次 ConnectionReset，一次 `Too many open files`（os error 24）
  其他机器（W9 的 Mac/Ubuntu）报告这两个通过，说明它们依赖 ulimit -n 或端口/时序。
- kv-mcp 已实现：按 clientInfo 查预算表、progress 通知、`credential_wait_approval`、`approval_pending` 等 A.8 状态、`claude/channel` 能力与通知、`client_timeout_observed` 审计。kv-hook 已实现 Stop 模式：stop/claude-stop、devin-stop、codex-stop、cursor-stop、gemini-after-agent。kv-proxy 已实现挂连接等待与 429 + Retry-After。
- §6.9.3 表中的数字大多来自文档和源码，E07 记录「W5 的登录失败不是工具超时；合成本地模型证据不能证明托管模型或 channels 行为」。本机有用户日常登录的 Claude Code、Codex、Cursor、Gemini CLI、Grok、Devin CLI 中的若干个；用之前先 `--version` 并确认已登录（`claude -p 'hi'` 之类的最小调用）。

【先读，不读完不要动手】
1. AGENTS.md。
2. docs/remote-approval-architecture-2026-10.zh-CN.md §6.9 全部（尤其 §6.9.3 表与「运行时实测清单」）、§9.4、§14、§16 测试 10–12、附录 A.8、附录 E。
3. docs/runtimes.md 全文；docs/remote-approval-reports/W5.md、OPEN-QUESTIONS.md T08 / E07。
4. 代码：rust/crates/kv-proxy/src/{gateway,transparent}.rs 的两个失败测试及其被测代码；rust/crates/kv-mcp/src/{approval,session,server,lib}.rs、src/tools/approval.rs、fake_helper.rs；rust/crates/kv-hook/src/stop.rs 与 tests/stop.rs；rust/crates/kv-protocols 中 client_timeout_hint_s。

【硬性规则】
- 不执行任何改变 git 状态的命令；只读 git 可用。直接在 main 工作树改。
- 你拥有：rust/crates/kv-proxy/**、rust/crates/kv-mcp/**、rust/crates/kv-hook/**、rust/crates/kv-protocols/**（仅超时提示字段相关）、docs/runtimes.md。不碰 kv-helper（R2-A）、kv-core 向量（R2-B）、mobile（R2-C）。需要 helper 侧配合的写变更请求。
- CARGO_TARGET_DIR=/Users/guang/dev/keyvalet/rust/target-r2d；-p 限定；最后全工作区四条命令跑一次。
- 不新增依赖。
- 修测试不是删测试：两个失败测试必须继续验证「连接数有上限、断开释放名额、stop 关闭现有连接」这三条语义；可以降低并发数、显式读取 `ulimit -n` 并据此选上限、用确定性等待替代 sleep，但不得把它们标 #[ignore]，也不得放宽被测代码的上限。
- 运行时实测只用用户已登录的工具，不输入任何凭据；每个实验的 MCP 服务器是本仓库构建的 kv-mcp 加一个假 helper（已有 fake_helper），不碰用户的真实 vault。实验配置写到临时目录或项目级配置，结束后恢复，不改用户全局配置的其他条目。
- 超时永远不映射为拒绝。

【任务】
A. kv-proxy 两个测试：找出对 ulimit / 端口 / 时序的依赖，改成在 `ulimit -n 256` 下也能稳定通过（本机先 `ulimit -n 256` 复现，再修），连续跑 20 次无失败。
B. 运行时实测（§16「运行时实测清单」），对本机能用且已登录的每个运行时：
   1. 「阻塞 4 分钟 + 每 15 s progress」与「阻塞 4 分钟不发 progress」两种工具各一次：是否被杀、何时、progressToken 是否存在、客户端 clientInfo.name/version；
   2. 预算用尽返回 `approval_pending` 后，模型是否按 next_steps 调用 `credential_wait_approval`（记录实际行为，不改文案前后各测一次）；
   3. Stop 类 hook 的真实输入 JSON 字段与我们输出被接受的证据（session 确实继续并调用了续等工具）；
   4. Claude Code：`--dangerously-load-development-channels server:keyvalet` 下 channels 通知能否唤醒空闲 session、忙时是否合并到下一轮；不加该标志时确认静默丢弃；
   5. Codex / Grok 的 `tool_timeout_sec`、Gemini 与 Claude 的 `timeout` 被安装器写入后是否真的生效（把值改小验证边界）。
   每个运行时记录版本号。装不了/没登录的写明。
C. 据实测修订：kv-mcp 的预算表常量、progress 间隔、A.8 文案；kv-hook 各运行时 Stop 输出 schema；docs/runtimes.md 的支持矩阵。把 §6.9.3 需要改的行以「原文 → 新文 + 证据」形式写进报告，交 R2-E 回写（不直接改架构文档）。
D. T08：网关/透明代理在审批被本地拒绝、取消、超时三种情况下返回类型化错误（JSON error.type 分别为 keyvalet_approval_denied / _cancelled / _expired，HTTP 403 / 409 / 408 或你论证的更合适状态码，写明理由）；挂连接期间客户端断开 → 批准到达后结果保留到 exp，可由带 approval_id 的重试取回一次；通配符主机与 h2-only SDK（至少验证 OpenAI 与 Anthropic 官方 SDK 各一个语言）走网关的实际行为。
E. 本地取消：用户在对话框点「拒绝」与审批 exp 到期两种情况，kv-mcp 返回的状态与 next_steps 不同（denied 明确说「不要绕路要 key」，expired 说「可重新发起」），快照测试。

【验收】
- 全工作区四条 CI 命令全绿；kv-proxy 两个测试在 `ulimit -n 256` 下连续 20 次通过。
- 运行时实测表（每行有版本、两种阻塞结果、progressToken、Stop 输入字段、channels 结果），至少覆盖 Claude Code CLI 与另外两个运行时。
- T08 三种类型化错误与重试取回有测试；SDK 验证有命令与输出。

【报告：docs/remote-approval-reports/R2-D-runtimes.md】
改动文件；两个测试的根因与修法；运行时实测表与 §6.9.3 修订建议（原文 → 新文 + 证据）；T08 的状态码决定与理由；对 helper 的变更请求；未决项。证据放 assets/r2d-*。
```

---

## R2-E  文档回写：架构、产品、开放问题（最后跑）

```text
你是 KeyValet 仓库（/Users/guang/dev/keyvalet）「远程审批 V1」第二轮的 R2-E 工作流：把两轮实现与验收的事实回写进架构与产品文档，让文档重新成为「现在是什么」而不是「当初打算什么」。你在 R2-A/B/C/D 的报告都写完之后启动。

【先读，不读完不要动手】
1. docs/remote-approval-architecture-2026-10.zh-CN.md 与 docs/remote-approval-product-2026-10.zh-CN.md 全文（这是你要改的对象，先知道它现在说了什么）。
2. docs/remote-approval-agent-prompts-r2-2026-10.zh-CN.md 顶部的 K1–K4 决定表（已拍板，照此回写）。
3. docs/remote-approval-reports/ 全部：W0–W9、W1-W5-integration、linux-auth-relay-isolation、owner-integration-23、OPEN-QUESTIONS、R2-A-m2-acceptance、R2-B-windows、R2-C-mobile、R2-D-runtimes；docs/remote-recovery-audit.zh-CN.md、docs/mobile-console-setup.zh-CN.md、docs/windows-native-acceptance-2026-10-12.zh-CN.md、mobile/docs/account-login.md；docs/review-2026-10.zh-CN.md 顶部验收表。
4. 代码只作核对：附录 B 对 rust/crates/kv-server/src/http.rs 的路由表；附录 C 对 rust/crates/kv-ipc/src/remote.rs 与 kv-core/src/remote/ipc.rs 的 op 列表与调用方白名单；附录 D 对 kv-helper/src/remote/schema.sql 与 kv-server/src/schema.sql；附录 E 对 `kv-cli --help` 各子命令。以代码为准。

【硬性规则】
- 不执行任何改变 git 状态的命令；只读 git 可用。直接在 main 工作树改。
- 你只改：docs/remote-approval-architecture-2026-10.zh-CN.md、docs/remote-approval-product-2026-10.zh-CN.md、docs/remote-approval-reports/OPEN-QUESTIONS.md、docs/review-2026-10.zh-CN.md 顶部验收表（把 R2 各报告的行合并进去）。不改代码、不改 README、不改 site/（对外文案由维护者另行处理）、不改 W0–W9 与 R2 报告原文。
- 只写已实现并有证据的行为用现在时；未实现的写「V2」或「计划中」；验收没过的不得写成通过。每处实质修改在行末不加注释，但在报告里列出「章节 → 改了什么 → 依据哪份报告的哪一节」。
- 不改变任何安全决策；若发现实现与安全原则冲突（例如某处放宽了档位），不要在文档里把它合理化，写进 OPEN-QUESTIONS 的「需要决定」。
- 表格列数一致；改完用脚本检查所有表的管道数与表头一致，并检查文内 §/附录交叉引用仍指向正确章节。

【任务】
A. 账户与身份（K2/K3）：§3.3 从「匿名账户、手机首次扫码即注册、不需要登录」改为「桌面/CLI 匿名注册 + 恢复码；手机 Google / Apple 登录（provider + subject 标识，DK 证明绑定 ID token），经 SAS 加入后账户归该用户；手机地址固定 relay.keyvalet.dev」；附录 B 增加 `/v1/account/*`、`/v1/recovery`、`/v1/devices/push-token` 等已实现端点与错误体；§8.5 加一段「自托管 relay 只服务桌面审批端」。
B. Windows 密钥（K1）：§3.1 表的 Windows 列改为 DK = PCP ECDH 键 + PCP ECDSA 身份签名键（`dk_sig`），说明 0x80090029 的事实；附录 A.7 加 `dk_sig`；§6.2 规范化说明；按 R2-B 报告的回写文字。Hello 交互验收结果如实写。
C. Linux 进程模型：§2.3 与 §2 拓扑加 `keyvalet-peer.service`（root、SO_PEERPIDFD、Linux 6.5+、只做调用方身份证明、无网络/无 vault 路径）；helper 不再有网络依赖，所有 HTTP/WS 在 relay-client 的 control transport；§12 威胁模型加 peer broker 一行。
D. 配对与 owner 控制面：§4 的 PairConfirm 签 JCS `{sas}`；§7.4–7.6 加入 Strong → 一次性准备令牌 → 精确标签 → 签发的 T2 流程（常设 T2 两次确认）、issued ledger、逐执行端撤销回执、`revocation_pending`、全局 T1 覆盖未来设备而 T2 不覆盖；附录 C 按 kv-ipc 现有 op 与白名单重写。
E. 审计与恢复：§11 加 `keyvalet audit --remote`、vault AEAD 检查点、不提供硬件反回滚的边界；§3.4 加 `/v1/recovery` 的语义与限制。
F. 投递与推送：按 R2-C 报告回写 §6.10.2 的实际路由实现、kv-push 的部署形态、token 生命周期；iOS 状态如实。
G. 运行时：按 R2-D 的「原文 → 新文」修 §6.9.3 表与 §9.4；docs/runtimes.md 已由 R2-D 改，保持一致。
H. §16 验收表：每行填入 R2 报告中的结果与数字；§17.3 里程碑 M0–M5 标注当前状态；§18 开放问题重写为「已决（K1–K4 与 D 系列的处置）/ 仍开放」两张表。
I. 产品文档：§3 平台与人群、§6.2 界面规划（手机登录页、固定地址、Android 先于 iOS 的现状）、§7 功能清单的「已实现 / 验收中 / V2」三列、§10 定价里「自托管 relay 只服务桌面审批端」的表述、FAQ 加「为什么手机要登录」「手机能连自建 relay 吗」。
J. OPEN-QUESTIONS：按 K1–K4 与各 R2 报告更新每条处置；新增本轮发现的开放项；review 文档顶部表合并 R2 的行。

【验收】
- 表格检查脚本通过；交叉引用检查通过；`grep -n 'Tailscale\|Caddy' docs/remote-approval-*.md` 只剩「不用」的否定句。
- 随机抽 10 条「已实现」的句子，每条都能在报告里找到对应证据（在报告里列出这 10 条与出处）。

【报告：docs/remote-approval-reports/R2-E-docs.md】
章节 → 修改 → 依据；发现的实现与设计冲突；仍开放的问题清单；抽查的 10 条。
```
