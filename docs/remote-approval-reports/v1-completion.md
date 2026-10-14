# Remote approval V1 — completion work

2026-10-12–13。接续 W0–W9 的共享 main 工作树，用户授权跨模块补齐实现及二维码依赖。未执行改变 git 状态的命令。以下区分源码回归、原生硬件检查和实际产品验收；§16 的目标不是通过记录。

## 本轮已实现

- relay 的 SQLite v3 `push_jobs` 持久队列与 `kv-push` 投递接线：只传 token、目标设备 ID、审批／消息 ID 和模式；不解析 `ct`。签名头中的 `push.mode` 由 helper 策略决定；默认控制消息静默，缺少提示的旧审批保守用 banner。每批最多并发 8 个，120 秒期限，初次加三次重试；尊重 429 Retry-After。410 清理旧 token 时比较原值，保留并发轮换的新 token。失去人类登录、登出或吊销会清理 token；签名取消仍可唤醒后台收取。
- 用户入口 `keyvalet relay recover <account-id> [--public-url URL] [--software] [--json]`。恢复码从隐藏输入或标准输入读取，不进入 argv。CLI 只提交 owner intent；helper 持有和核对 DK，relay-client 执行固定 recovery 请求。新恢复码先写入 vault AEAD 准备状态；失败沿用原设备密钥，响应丢失后以新 DK 认证并恢复同一新码。旧设备／会话注销不能擦除丢失设备上的离线 Grant。
- terminal 配对二维码：保留 URI，紧凑 Unicode QR 含 quiet zone；JSON 不含终端图案。编码失败保留可用的 URI 并显示说明。
- Windows split identity 的 SAS 绑定补强：包含双方 ECDH 与可选身份签名公钥及嵌套扩展。没有 `dk_sig` 的既有向量保持；Windows 原生提供者及配套向量由并行工作流提供，详见 [R2-B](R2-B-windows.md)。
- TestFlight 工具沿用 Simvito 的 ASC API-key `xcodebuild` 认证方式。密钥留在受保护的外部文件；App 和通知扩展分别校验团队、发行 profile、App Group 及生产能力；发行包和源码散列固定后才允许单独上传步骤。
- 部署资产增加专用非登录用户的 push 单元、systemd LoadCredential 与 provider 配置示例；nginx 使用实际 TCP 来源的 Cloudflare IP allowlist，避免共享 nginx 的 real-ip 改写绕过。

## 依赖

| 新依赖 | 用途 | 发布时间 | 约束 |
| --- | --- | --- | --- |
| qrcode 0.14.1 | CLI Unicode QR 编码 | 2024-07-05；[发布记录](https://docs.rs/crate/qrcode/0.14.1) | 固定版本，`default-features = false`，不引入 image；用户已批准新增及 Cargo.lock 更新 |

其他实现使用现有 workspace 依赖与 Node/Python 标准库，没有新增第三方签名工具。Node 测试及脚本不依赖本机 KeyValet 安装。

## 已验证的边界

| 检查 | 实测结果 |
| --- | --- |
| relay/push Linux 原生软件测试 | 通过；独立 `/tmp/keyvalet-owner-isolation-20261012` 源码、Cargo 与 target，未依赖服务器现有 KeyValet 安装 |
| push HTTP harness | 正常、503、429、410、token 轮换／删除、篡改签名提示及到期；SQLite 文件和日志无测试明文标记 |
| recovery helper/CLI | 首次恢复、失败保持原密钥、响应丢失后的恢复、错误配置绑定、隐藏输入、JSON 类型 roundtrip；临时 vault 与内存 relay |
| Mac Secure Enclave Strong | `remote_se_strong` 实际 userPresence 签名通过，1 项，3.66 秒；这不是公网端到端延迟 |
| Ubuntu TPM DK | `remote_tpm_roundtrip` 在 root 服务上下文通过，1 项，1.68 秒；普通 SSH 用户无设备权限的尝试未通过，未软件回退 |
| signing helper | 4 个 Node 回归通过，覆盖外部文件权限、认证参数及日志脱敏、团队／profile／能力拒绝、显式上传与构建号保持 |
| CLI 新逻辑覆盖率 | 2373/2373 行、214/214 函数（100%）；含审计。regions 3968/4073（97.42%），系统适配层 50/444 行、6/51 函数，按约定单独报告 |
| 工作区最终 CI | Rust 1.99.0：fmt --all -- --check、clippy --workspace --all-targets -- -D warnings、build/test --workspace --locked 全过；1332 passed / 0 failed / 10 ignored，69 组；检查期间 Rust 源码无变化 |

本轮构建与测试日志位于 `rust/target-owner-integration/completion-*.log`，未将包含个人账户或运行秘密的原始日志复制到公开报告。

## 命令示例

```sh
keyvalet pair --new
keyvalet relay recover acct_example --public-url https://relay.keyvalet.dev
keyvalet audit --remote --since 24h --json

# External ASC configuration has ASC_KEY_ID, ASC_ISSUER_ID and ASC_KEY_PATH;
# configuration and key are current-user-owned regular files with mode 600.
KV_ASC_CREDENTIALS=/protected/app-store-connect.env mobile/scripts/package-testflight.sh build 1
# Only after the IPA has been checked and upload has been requested:
KV_ASC_CREDENTIALS=/protected/app-store-connect.env mobile/scripts/package-testflight.sh upload
```

## 实机与部署记录

已核对 API key 所属团队为 PWCRJPY7YC（bundle seedId 与证书 OU 一致），并注册 `dev.keyvalet.mobile` 和 `dev.keyvalet.mobile.KeyValetNSE`，启用 Push／App Groups／Apple 登录。App Attest 与 Time Sensitive 不能经当前 ASC v1 capability enum 配置；App Group 绑定和 ASC App 记录也需网页完成。API-key 归档仍返回 authentication/profile 错误，未成功生成发行 IPA。iPhone 15 已无线配对、Developer Mode 开启；当前 Xcode 无可用 DDI 服务，普通真机 destination 构建失败。通用 iOS 发行归档不依赖此调试连接，但 TestFlight 仍需自己的 App 记录、主 App／NSE 的 profile 与 App Group。Apple API 无创建 App 记录接口；该项需要 ASC 网页完成。没有移除推送、App Attest 或 Apple 登录能力来规避签名失败。

官方 relay/push 服务与 nginx allowlist 已上线，保留既有 Google 登录配置和 relay 数据库。数据库在线备份位于服务器 root-only 的 `/var/backups/keyvalet-completion-20261012/`。实际监听 127.0.0.1:8787／8788；nginx -t 通过，公网 health 200，直连 origin 加伪造 CF 头 403，push 未认证的无效 JSON 也返回 401。真实 FCM provider 发送返回 202；这不是手机后台审批通过，也不是 APNs 通过。并行工作流统一 push 端口为 8788，本轮采用相同端口，不启动第二个 dispatcher。

## 尚需完成的验收

- 已安装 Ubuntu × MacBook 公网配对、原生 Strong、首次 use、1 小时 Grant／全部收回、两端审计与实际 p50/p95。
- 手机锁屏 Quick、Strong、静默到 30 秒升级和三项设置；Android 原生门禁、Google 登录及系统结束进程后的 FCM → Rust 空队列同步已通过，分别见 [W8](W8.md) 与 [R2-C](R2-C-mobile.md)。后者约 5.4／6.9 秒仅为唤醒探测，不是审批延迟。iOS 完整 UI 与后台 APNs 尚需发行安装和配置。
- Windows Hello PIN／生物识别及跨设备审批；PCP 双键的原生通过不能替代 Hello。
- Mac 合盖两小时、完整 OS presence 转换与一周 dogfooding。普通单测或模拟时钟不替代这些时间／硬件指标。
- 硬件单调反回滚、不同操作的签名批量承诺等开放设计项仍见 [OPEN-QUESTIONS](OPEN-QUESTIONS.md)。保持失败即拒绝，不降低 Strong 或扩大授权。

Mac 安装候选已从当前已构建二进制准备，并选择 `--no-setup` 保留既有 vault 初始化状态；Developer ID 的私钥操作曾等待系统钥匙串响应；改用 AGENTS.md 允许的同团队 Apple Development 身份，7 个二进制均严格验证通过、hardened runtime 与 identifier 匹配，未降低 daemon/agent/relay-client 的团队校验。`--no-setup` 安装候选已准备；系统管理员窗口未获得密码后超时，sudo 返回 no password was provided，安装未开始。仍需在系统窗口完成管理员认证；没有用开发候选宣称公开发行／公证通过。

## 改动文件

主要落点：`kv-server` 的 push/account/routes/schema 与 harness 测试，`kv-push` provider 错误及凭据文件，`kv-helper` recovery/bootstrap/startup/typed control，`kv-relay-client` recovery control，`kv-ipc` owner intent，`kv-core` recovery redacted Debug、SAS 与 IPC schema/vector，`kv-mobile-core` token 生命周期，以及 `kv-cli` recovery/QR/输出测试。部署与签名资产位于 `deploy/relay/`、`mobile/scripts/`、`mobile/ios/ExportOptions.example.plist`。`scripts/install.sh` 增加 Mac `--no-setup`，根脚本参数显式传入并保持单引号边界；安装器 8 项 Python 回归和 shell 语法通过。架构、恢复审计、review 与 OPEN ledger 同步更新。共享树并行修改另由对应报告说明，不能把全部 diff 归于本轮。

最终日志：`completion-current-clippy.log`、`completion-current-build.log`、`completion-current-tests.log`、`completion-ci-source.json`、`completion-test-totals.json`。签名工具 4 项与安装器 8 项测试通过。工作区现有并行改动保留；没有将本轮回归通过写成 M5 完成。

机器可读验证摘要：[v1-completion-verification.json](assets/v1-completion-verification.json)。Mac 安装与 Apple 注册问题都只请求必要的系统／账号操作，已完成构建、签名候选和可自动检查的前置工作。
