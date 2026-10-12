# R2-C：手机后台推送与真机审批

2026-10-12。进行中。仅在 main 工作树直接修改，没有执行改变 Git 状态的命令。
继承的 W8 软件/Google 登录结果不计作本轮锁屏验收。用户选择先完成 Android，
iOS/Play 缺项写入本报告。

## 当前状态

| 项目 | 状态 | 证据 |
| --- | --- | --- |
| relay 路由、重试、token 清理 | 实现中，测试待编译 | `src/push.rs`、`src/push_tests.rs` |
| Android 后台 | 原生 JobScheduler/通知更新已实现，待构建 | `PushSyncJob.kt` |
| kv-push 部署 | 专用用户/目录已创建，凭据待用户放置 | `/etc/keyvalet-push`：root:keyvalet-push、0750 |
| Pixel 7 | 在线，API 36；本轮 E 验收待开始 | 不沿用 W8 截图冒充本轮通过 |
| Play | 缺上传签名材料，不产伪签名 AAB | 用户选择先记录缺项 |
| iOS | 在线 iPhone 被检测到；本轮按用户选择只做无资源检查 | profiles/APNs 未就绪 |

## 设计与失败模式

详见 [推送部署与生命周期](../../mobile/docs/push-deployment.md)。执行端签名覆盖的
`push.mode` 是 §6.10 决策的元数据投影，relay 不读取 E2E PresenceHint，不把
WebSocket 在线误当人在桌前。手机通知内容和动作来自 Rust 验证后的解密结果。
失效 token 通过原始 HTTP 请求上的 410 同步回调、以旧 token 比较后删除，避免
轮换竞态。离线退出的远端撤销保留在加密发件箱。

## 需要用户提供

- simvito 上 `/etc/keyvalet-push/fcm-service-account.json`，root:keyvalet-push、0640，
  对 Firebase 项目 `simvito` 有 FCM HTTP v1 发送权限。已有本机文件不由本轮搬运。
- Android 上传签名 keystore 绝对路径、别名和安全环境中的两个密码变量；Play
  应用签名 SHA-1/SHA-256，以及内部测试上传/测试者访问。脚本不使用 debug 签名兜底。
- iOS（后续）：APNs `.p8` 服务器绝对路径及 Key ID；PWCRJPY7YC 团队主 App
  `dev.keyvalet.mobile` 与 NSE `dev.keyvalet.mobile.KeyValetNSE` 的 profiles，均授权
  `group.dev.keyvalet.mobile`；Apple Distribution 证书/私钥和真实 export plist；
  Sign in with Apple 主 App/Services ID 与固定 callback 配置；可用于安装和 Face ID
  操作的 iPhone。检测到在线设备不代表签名资源已就绪。
- 真机解锁、指纹/Face ID 操作由用户本人完成。

## 对 kv-core / relay API 的变更请求

- 编译发现 `remote/relay_control.rs` 的 Debug 派生要求 RecoverAccountRequest 和
  RecoverAccountResponse 实现 Debug，当前共享版本未实现。属于 R2-B，本轮不修改。
- 沿用 D03：1 小时设置 Grant 当前验证器要求 Strong，手机保持 Strong，不降级。
- 不新增审批正文或在场状态的公开 relay 字段。`to` 加入推送服务内部元数据请求；
  用户已授权对应现有 `src/tests/push.rs` 期望值更新。

## 新依赖

| 名称 | 版本 | 发布日期 | 理由 |
| --- | --- | --- | --- |
| 无 | — | — | Android 使用已有 API 31+ JobScheduler；Rust/Flutter 复用锁定依赖 |

## Android 真机验收

| 步骤 | 结果 | 计时 | 截图/录屏 |
| --- | --- | --- | --- |
| 扫码与双端 SAS | 待执行 | — | — |
| 在场静默、本机框优先 | 待执行 | — | — |
| 30 s 升级、同通知标识 | 待执行 | — | — |
| 锁屏 Quick、一次执行/二次拒领 | 待执行 | — | — |
| T2 仅打开、指纹 Strong | 待执行 | — | — |
| 切模式、1 小时票、revoke-all | 待执行 | — | — |
| 我不在电脑前：立即横幅 | 待执行 | — | — |
| 退出：token 删除、通知清除 | 待执行 | — | — |
| 系统杀进程后推送、重启 | 待执行 | — | — |
| 离线 1 小时同步、±5 分钟时钟提示 | 待执行 | — | — |

## 改动文件与验证

待最终检查后补齐精确清单、命令和结果；证据统一 `assets/r2c-*`。
