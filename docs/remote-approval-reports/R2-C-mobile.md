# R2-C：手机后台推送与真机审批

2026-10-12 至 13。路由、token 生命周期、原生后台实现和 simvito 部署配置已完成。
**Pixel 7 已通过配对、锁屏 Quick、App 指纹 Strong、真实升级和设置三步；重启后的 relay 恢复尚未通过。**
FCM 文件已由用户提供，真实元数据投递和系统结束进程后的原生/Rust 唤起同步通过。
本轮 SAS 400879 双端一致，手机 Strong 配对签名已验；Quick / Strong 均执行一次、第二次领取 Replay。
新版去重通知已由用户确认声音；同一 tag/id 的静默→横幅和真实后台审批唤起已有系统证据。
退出已验证本地清登录/通知及原生 login_required；当前远端撤销排队，relay 仍留 token/会话。
重新登录的 providers 请求也显示「暂时无法连接 relay」。Google 推送恢复不能替代这条 HTTPS 路径的验收。
用户选择先完成 Android，iOS/Play 缺项记录在本报告。W8 软件和 Google 登录不计作锁屏验收。

直接修改 main 工作树，没有执行改变 Git 状态的命令。其他工作流的共享树改动不归入本轮清单。
私钥、服务账号内容、bearer 和推送 token 全文未进入证据。

## 当前结果

| 项目 | 结果 | 证据 |
| --- | --- | --- |
| relay 路由与重试 | 假 HTTP 集成、真实 FCM 审批/升级/取消投递通过 | [Rust 测试](assets/r2c-mobile-server-tests.log)、[FCM](assets/r2c-fcm-final.json) |
| token 生命周期 | 登录/冷启动/轮换、离线退出、会话失效、吊销、410 CAS 删除已实现 | [生命周期](assets/r2c-token-lifecycle.log)、[上传竞态](assets/r2c-upload-race.log) |
| kv-push 部署 | 专用用户/二进制/环境文件/nginx 私有配置就绪；服务 active/enabled、8788 loopback | [部署](assets/r2c-push-activation.log)、[监听](assets/r2c-push-listener.log)、[最终状态](assets/r2c-live-state.log)、[nginx](assets/r2c-nginx-private.log) |
| Android 后台 | 原生 FCM → JobScheduler → Rust → 双渠道/Quick FGS 已构建 | [APK](assets/r2c-android-apk-build.log) |
| Pixel 7 门控 | 正常 Debug 安装成功；原生 2/2、0 skipped，跳过 CryptoObject 被拒 | [XML](assets/r2c-android-signing-gate.xml) |
| Android E 全流程 | 核心手机流程通过；重启拉取、远端退出清理未通过；真实 Mac 配对/GUI 待 R2-A | 见真机表 |
| Play | 无上传签名材料/Play 指纹，未生成签名 AAB、未上传 | 资源清单 |
| iOS | Rust iOS/iOS-sim 和 Runner/NSE 模拟器构建通过；硬件/Apple 登录未验 | [目标](assets/r2c-ios-native-build.log)、[模拟器](assets/r2c-ios-simulator-build.log) |

## 路由设计与失败模式

架构 §6.10.2 的人在场判定由执行端完成：本机或桌面 approver present → 手机 silent；
idle/away/unknown → banner；notify always-phone → banner。真实 30 秒未决由执行端发
同一 approval_id 的 approval_escalate。PresenceHint 是 E2E 正文，relay 只知道 WS 是否连接。

沿用执行端签名覆盖的 Envelope 扩展 `push: {mode}`，作为提供商投递元数据投影。
relay 不解密 PresenceHint，不把 WS 在线当作人在电脑前；手机正文、强度和动作全部来自
Rust 验证并解密的请求，不使用提供商自报模式作安全判断。

| 决策/信封 | 签名 hint | WS presence | relay 调度 |
| --- | --- | --- | --- |
| 本机/桌面 present | silent | 在线或离线 | Silent |
| idle/away/unknown、always-phone | banner | 在线或离线 | Banner |
| 旧客户端请求无 hint | 无 | 在线或离线 | 保守 Banner |
| 30 秒升级 | banner | 在线或离线 | Banner；同 approval_id |
| cancel、Directive/Result、Grant、DeviceRevoke | silent 或无 | 在线或离线 | Silent 控制更新 |

假 kv-push 测试覆盖 WS 在线/离线 × silent/banner/缺提示、bearer、to、幂等、Directive
静默、无正文；已有测试覆盖升级覆盖旧请求、取消及轮换。手机本地「我不在电脑前」
在解密后把 silent 当 banner，不发送 PresenceHint。

内部请求只有 `device_push_token`、`approval_id`、`to`、`delivery.mode`。FCM 仅 data
message，三个字段为 approval_id、delivery.mode、to，没有 notification 正文。
APNs 只含通用唤醒文案和元数据，真实正文由 NSE 解密后填写。kv-push 拒绝未知字段，
包括正文/密文；日志只含静态事件及 token 后六位，relay 只记录数量。

接受信封和持久 push job 同事务登记。初次发送加 3 次重试，退避 1/2/4 秒；每次 lease
重新读取 token。无 token 跳过并计数；升级/解决/取消退休旧请求唤醒，控制更新不错误依赖
approval waiting。推送失败不回滚审批创建，前台 WS 和上线拉取仍可用。

HTTP 超时 28 秒、租约 30 秒；job 最迟在 120 秒或信封 exp 到期。429 使用有界
Retry-After（60–3600 秒），超过 job 生命周期则放弃该唤醒。权限/配置错误保留 token，
普通错误耗尽预算后计数丢弃。详细配置见 [push-deployment.md](../../mobile/docs/push-deployment.md)。

## token 与后台可靠性

| 事件 | 手机 | relay |
| --- | --- | --- |
| 登录成功 | 清旧上传摘要，登记当前 token | 人类/设备会话绑定 token |
| 冷启动/FCM 轮换 | 原生保存 token，冷启动强制登记；network job 重试 | 替换设备 token |
| 退出 | 先清本地登录和通知；保留加密远端撤销 outbox | 在线退出清 token、会话、待发 job |
| 离线退出 | 不显示旧请求；上线/后台/冷启动重试撤销 | 撤销成功或旧会话失效后删除 |
| 人类会话到期 | Rust 拒绝快照、解密和后台动作 | 派发前/cleanup 清 token |
| 吊销、最后人类会话删除 | 进入失效路径 | SQLite trigger 同事务清 token/job |
| APNs 410 Unregistered / FCM UNREGISTERED | 下一次 SDK 登记可恢复 | 原授权请求返回 410；旧 token 比较删除 |

410 是原 bearer 请求上的同步失效回调，不新增公开删除端点。延迟 410 不删除已经轮换的
新 token。APNs 错 topic/权限、FCM permission denied 不清 token。清理旧会话保留较新会话。

上传摘要同时绑定 token 和人类会话。新增真实 HTTP 延迟测试：旧上传被服务器接受 →
响应延迟 → 退出并重登录 → 同 SDK token 回到新会话 → 旧响应不能把新会话标成已上传。
新会话再次上传后，服务器才恢复 token。

Android 后台全部原生 + Rust：Firebase 回调只校验唤醒元数据并调度 JobScheduler；
高优先级尝试 expedited job，普通 job 持久化并指数重试。Rust 用密文缓存/HTTPS 待批拉取，
不启动 Dart isolate；已有前台 WS 时不另开竞争连接。20 秒预算耗尽返回已验证缓存并要求
原生重试，不冒充同步成功。登录失效时不能展示缓存。
重启验收中发现后台先连 WS 会阻断独立 HTTPS 恢复，已调整为先拉取待批；
WS 暂时不可用时仍显示本次已验证的请求并重试控制消息。新增假 HTTP 测试让
/v1/presence 返回 503，确认新请求被拉取、解密、确认且 retry=true。
HTTP 明确拒绝时先恢复人类会话状态，已撤销会话立即清本地登录；原有负向回归通过。
原生日志只新增 retry 布尔值和白名单内的静态错误码，不输出任意异常文本。

Silent 为低优先级无声渠道；Banner 为高优先级、有声/振动渠道。升级保持同 tag/id，换
不可变渠道时取消再投递同标识。Quick 仅对 per_use Quick 请求提供允许/拒绝，动作要求
系统解锁，FGS 用 AK_q 签；Strong 通知只有打开，主 App 用 BiometricPrompt + 实际
Signature CryptoObject 签 AK_s。状态刷新清已关闭/过期通知。

已被提供商接受的投递无法召回；Android signed-out worker 清通知并拒绝显示。
原生通知计划相同则不重复提交，兼容后台 show→refresh 和前后台竞争；重启进程也比较系统 extras。
变化的正文仍更新，Silent→Banner 仍用同 tag/id 换渠道并响铃。
重启后 SDK token 保存并重新登记，硬件/密文数据需首次解锁。
本轮 boot_count 37→38，用户完成 PIN；服务器仅比较 token 摘要，确认 SDK token 相同。
Google/VPN 恢复后 native worker 被唤起，但审批拉取持续 retry=true；三条独立标题的
重启测试请求均未显示，旧缓存中的 cancel plans 不计作新请求恢复。
最终 APK 改为 HTTPS 先拉取后仍显示离线，登录页重新发起 Google 登录时同样提示
「暂时无法连接 relay」，还未进入 Google SDK。根因未归为提供商失败或 WS 单独失败。
退出后立即回到登录页、清通知，真实后续唤醒返回 login_required；relay token/会话仍在，
远端撤销待这台手机恢复 relay HTTPS 访问后重试，未通过服务器删除验收。系统结束后台进程后的真实 FCM
已验：真实审批 PID 16454 → 空 → FCM Receiver 新 PID 16720；Rust 解密后
生成静默通知并升级，用户批准后验 AK_q 签名。此前 plans=0 的探测只用于验证空队列唤起。am force-stop 属用户强制停止，会阻止投递直至重开 App，本轮未使用。
离线一小时按用户要求留待后续（手机当前仍需收发消息）；软件队列/重启/过期测试不能替代一小时真机计时。

## simvito 部署（无秘密）

- 专用用户/组 keyvalet-push，无登录 shell；`/etc/keyvalet-push` 为 root:keyvalet-push、0750。
  bearer 在服务器生成，未导出/打印；relay 服务用户加入该组。
- relay-bearer 为 root:root、0600；`/etc/keyvalet-push/provider.env` 为 root:root、0600。
  两个服务通过 LoadCredential 获得私有运行时文件，无需服务用户直接读取 root bearer。
- 本轮使用 [keyvalet-push.service](../../deploy/relay/keyvalet-push.service)、[push.conf](../../deploy/relay/push.conf)：
  专用用户、systemd 隔离、EnvironmentFile；只绑定 127.0.0.1:8788。
  relay 配置 URL `http://127.0.0.1:8788/v1/push` 和 bearer 文件路径。
- FCM 指向用户提供的 `/etc/keyvalet-push/fcm-service-account.json`，root:keyvalet-push、0640。
  keyvalet-push.service active/enabled，127.0.0.1:8788 有唯一 listener，9608 无 listener。
  早期 kv-push.service 已停用/删除，统一使用有 LoadCredential 的 keyvalet-push.service。
  实际认证投递 202、未认证投递 401；[FCM 探测](assets/r2c-fcm-after-kill.json)不创建审批。
- [nginx 片段](../../deploy/relay/push-private.nginx.conf) 已安装并 include，不代理 8788；
  公开 /v1/push 最终为 404，health 为 200，nginx -t 通过，Cloudflare 未修改。
  nginx -T 确认两个 deny location 已加载，没有指向 8788 的 proxy_pass。
- 服务器原无 Rust，工具链放 `/tmp/keyvalet-r2c-toolchain`，不改 shell profile；
  Linux 临时缓存限定构建 -p kv-server -p kv-push --locked。本机始终用指定 target-r2c。
  首次源快照与共享 lockfile 变化不一致；同步当前锁文件后 --locked 成功，未放宽锁定。
- 二进制 root:root、0755；原 relay 留备份，原子替换、重启，账户/OAuth 配置保留。
  keyvalet-relay-server.service active。现有其他站点 nginx 协议警告不影响语法检查。

| R2-C 部署时二进制 | SHA-256 |
| --- | --- |
| kv-server | `9a889580e6aa2cb0b04868382e0d5f86f8da93cabe980350f0575bc96b418fa1` |
| kv-push | `73ccc644701871f4026cac735129d7b8d698a827c2b1983cdcb0225d9f67d87d` |

R2-A 随后在 2026-10-13 07:33 部署其当前 main 快照，relay 现行 SHA-256 为
`1eced902770d81e9933c204c8830ca7d2c7565e3fc0105e93aeeb44c45f9eab0`；push 二进制与
8788 配置保留。本轮未恢复旧 relay；[最终只读收据](assets/r2c-live-final.json) 记录实际现行文件。

## Android 真机表

Pixel 7，Android 16/API 36，dev.keyvalet.mobile，正常签名 Debug APK；覆盖安装 Success。
两个 APK 检查 targetSdk 36、JNI 按名称加载、无本机链接路径。没有关闭系统包验证。
用户已解锁、扫码和按指纹，双方 SAS 400879 一致。所有批准来自真实手机签名，
锁屏动作按系统要求解锁；未绕过锁屏、系统包验证或生物识别。

| 步骤 | 结果 | 实测计时 | 证据 |
| --- | --- | --- | --- |
| 正常安装、登录态页面进入 | 通过；沿用已登录会话，未重做 Google 登录 | 页面未计时 | [页面](assets/r2c-android-start.png)、[安装](assets/r2c-android-install.log) |
| 跳过 CryptoObject 签 AK_s | 通过，2/2、0 skipped | 最终 XML 总计 1.242 s | [XML](assets/r2c-android-signing-gate.xml) |
| 扫码、双方 SAS、指纹配对 | 通过，验手机 Strong 签名 | 执行端确认→手机确认约 9 s | [SAS](assets/r2c-pair-sas.png)、[事件](assets/r2c-physical-events.json) |
| 手机静默、Mac 桌前先弹框 | 未验；R2-A 已安装，真实 Mac/ndu 配对确认待完成 | 未测 | [R2-A 状态](assets/r2a-interaction-status.json) |
| 锁屏后真实 30 s 升级、同通知 | 通过；新版用户确认有声音，Silent/High 保持 tag/id | 30 s 定时；含 HTTP 回包日志 31 s；原生横幅约 35 s、距静默约 29 s | [静默页面](assets/r2c-t1-silent-app.png)、[连续通知采样](assets/r2c-audio-upgrade-trace.json)、[历史](assets/r2c-notification-history.json) |
| 锁屏 Quick、执行一次/二次拒领 | 通过；用户确认从锁屏动作允许，AK_q 验签 | 首条请求→批准 37 s（含升级/用户解锁） | [完成页面](assets/r2c-quick-complete.png)、[事件](assets/r2c-physical-events.json) |
| T2 仅打开、App 指纹 Strong | 通过；通知 actions=1、用户确认打开/指纹；AK_s 验签 | 请求→批准 14 s（含用户指纹） | [详情](assets/r2c-t2-open.png)、[通知历史](assets/r2c-notification-history.json)、[事件](assets/r2c-physical-events.json) |
| 设置切模式 | 通过，per_use→remember:1h，执行端回报一致 | 约 5 s（含指纹） | [结果](assets/r2c-mode-complete.png)、[事件](assets/r2c-physical-events.json) |
| 签 1 小时票 | 通过，Strong 验签、hours=1 | 打开对话框→验签 ≤16 s（含用户操作） | [对话框](assets/r2c-grant-dialog.png)、[结果](assets/r2c-grant-complete.png)、[事件](assets/r2c-physical-events.json) |
| revoke-all | 通过，执行端 grants=0，回报票数归零 | 约 <1 s | [结果](assets/r2c-revoke-all-complete.png)、[事件](assets/r2c-physical-events.json) |
| 我不在电脑前：立即横幅 | 通过；signed silent 未等升级即进入 High 渠道 | 约 5 s（含 FCM 拉取；跨时钟） | [开关](assets/r2c-settings-away-on.png)、[通知](assets/r2c-away-notification.json)、[完成](assets/r2c-away-complete.png) |
| 退出清 token/不再显示推送 | 本地及原生拒显通过；relay token/会话仍在，远端删除未通过 | 确认→登录页约 1.1 s；后续真实唤醒 login_required | [页面](assets/r2c-logout-final.png)、[事件](assets/r2c-logout.json)、[relay](assets/r2c-logout-relay.json)、[原生日志](assets/r2c-reboot-background.log)、[采样](assets/r2c-signed-out-trace.json) |
| 系统结束进程后 FCM 唤起 | 通过真实审批：am kill→无 PID→FCM Receiver 新进程16720→原生/Rust 通知 | 请求→静默观察约 7 s；首次空队列探测约 5.4 s | [进程](assets/r2c-approval-process-kill.json)、[通知](assets/r2c-audio-upgrade-trace.json)、[系统事件](assets/r2c-android-notification-events.log) |
| 重启 token / 恢复投递 | boot 37→38、同 token、原生唤起通过；新审批拉取未通过 | 重启→首次解锁观察约 106 s（含用户 PIN） | [重启](assets/r2c-reboot.json)、[token](assets/r2c-reboot-token-after.json)、[通知采样](assets/r2c-reboot-recovery-trace.json)、[重登结果](assets/r2c-relogin-result.png) |
| 离线 1 小时后待批与 relay 一致 | 用户要求稍后安排：Pixel 7 仍需收发消息 | 未计时 | [安排](assets/r2c-physical-events.json) |
| ±5 分钟时钟提示 | 双向真机页面通过；用 signed envelope ±300 s 模拟，不改系统时钟 | 每条发出后约 10 s 内看到提示 | [−300 s](assets/r2c-clock-minus-300.png)、[+300 s](assets/r2c-clock-plus-300.png)、[事件](assets/r2c-physical-events.json) |

计时由服务端 202 完成时间与 Android 日志 epoch 相减，是单次样本并包含时钟误差，
不作为 30 秒升级性能验收。新版静默→横幅的手机记录间隔为 28.620 s；
从请求创建到横幅观察约 35 s，不能将真实 30 s 定时通过等同于 ≤30 s 端到端投递预算通过。

已保存 Quick/Strong/设置的真实 App 截图及系统通知记录；锁屏动作由用户确认，
未制作替代截图。曾因前台切换捕获其他 App 的截图立即删除，未进入证据。
截图工具校验焦点，只保留 KeyValet；通知工具只输出本包记录，不保存其他 App 通知正文。
首轮用户未听到声音，发现 FCM show 后 refresh 立即重复投递。新版合并相同通知计划，
保留同 tag/id 渠道升级；连续采样和系统 notification_alert beep=1/buzz=1、用户确认声音一致。
软件 [fixture](../../rust/crates/kv-mobile-core/examples/r2c_phone_fixture.rs) 已构建并注册线上 relay，
已完成扫码、真实 30 秒升级、硬件手机签名验证、nonce 二次消费 Replay 和设置确认。
私钥目录只留被忽略的 target。fixture execution counter 只算合成操作，不证明真实 Mac
凭证执行或 GUI 在场判定。R2-A 已在 07:37 覆盖安装签名的 helper/agent/relay，
00:05 UTC 收据显示真实配对尚待完成、远程 use=0。本轮按用户规则继续用已配对 fixture；
真实 Mac 在场/锁屏/凭证执行留待 R2-A 接通，未重复设置其执行端。
测试 fixture 已正常退出，软件私钥保留在忽略的 target 目录；未手动删除 relay 审批，
剩余合成请求按签名 exp 过期，不再发送新测试请求。
继续步骤见 [真机流程](../../mobile/docs/r2c-device-acceptance.md)。

## Play 与 iOS

Play 未上传。现有 [package-play.sh](../../mobile/scripts/package-play.sh) 要真实上传 keystore、
别名和两个密码，输出 mobile/dist/play-internal/；本轮未用伪材料构建或拿 Debug APK 冒充 AAB。
[控制台步骤](../mobile-console-setup.zh-CN.md) 已补实际状态。后续递增构建号，取得 **Play
应用签名** SHA-1/SHA-256，在 Google Cloud 登记 dev.keyvalet.mobile + 对应 SHA-1 的 Android
client，同步 relay KEYVALET_GOOGLE_ANDROID_CLIENT_ID，再验 Play 包 Google 登录。
上传证书和 Play 应用签名证书分别记录，当前 Debug 指纹不能代替 Play 指纹。

iOS NSE 独立于 Flutter，App Group Rust SQLite、公共键缓存、首次解锁后文件保护已接入；
Rust 解密结果决定 passive/timeSensitive、声音、threadIdentifier，Quick category 要求
authenticationRequired，Strong 进 App Face ID。真实锁屏/SE/取消通知/Apple 登录未验。
模拟器没有软件键兜底。按用户选择，未操作已检测到的在线 iPhone。
现有 [TestFlight 脚本](../../mobile/scripts/package-testflight.sh) 和步骤保留，未生成 IPA 或上传。

## 需要用户提供

FCM 已到位；以下列出已提供状态及后续资源。

1. **已提供**：simvito 的 `/etc/keyvalet-push/fcm-service-account.json`，root:keyvalet-push、0640；
   Firebase simvito（sender ID 527578968067）实际 FCM 发送通过。本轮只配置路径，未搬运本机私钥。
2. **Android 恢复窗口**：扫码/指纹和重启 PIN 已提供；Google/VPN 已由用户恢复，FCM 能唤起，
   但手机 App 仍不能完成 relay HTTPS 请求。需要确认 Pixel 7 可访问
   https://relay.keyvalet.dev/v1/health、恢复 App 的 relay 访问并完成重新 Google 登录；
   随后复验远端退出清 token、重登同 token 上传、重启后审批展示。手机当前留在登录页。
   用户要求连续一小时离线窗口稍后安排，未断开手机网络。R2-A 已安装，提供真实配对完成状态后
   继续验 Mac 实际执行/桌面框。
3. **Play 后续**：外部上传 keystore 绝对路径、别名，安全环境中的 KV_ANDROID_STORE_PASSWORD /
   KV_ANDROID_KEY_PASSWORD；Play 应用签名 SHA-1/SHA-256、上传权限和测试者加入链接。
4. **iOS 后续**：服务器 APNs .p8 绝对路径、真实 Key ID；团队 PWCRJPY7YC、topic
   dev.keyvalet.mobile、实际 sandbox/production；主 App 和 dev.keyvalet.mobile.KeyValetNSE
   匹配 profiles，均授权 group.dev.keyvalet.mobile，主 App 推送/Time Sensitive/Apple 登录能力；
   Apple Distribution 证书/私钥、真实 TestFlight export plist。
5. Apple 登录主 App/实际 Services ID 和固定 callback 配置；可安装 iPhone 与用户 Face ID
   操作时间。设备在线不代表 profiles 就绪。密码/私钥不要写入报告。

## 改动文件与新依赖

| 路径 | 本轮改动 |
| --- | --- |
| kv-push/src/{lib,main,tests}.rs | to、严格元数据、FCM data、8788、provider 失效/权限区分与测试 |
| kv-server/src/{push,push_tests}.rs | 路由、重试、CAS、生命周期 trigger、假 HTTP 测试 |
| kv-server/src/account.rs | 仅 push_token / remove_push_token：trigger、清 job |
| kv-server/src/cleanup.rs | 新增 token cleanup 调用；沿用已有 messages 入队调用 |
| kv-server/src/tests/push.rs | 用户授权的 to 期望值更新 |
| kv-mobile-core/src/{account,relay,ffi,engine,tests}.rs、src/tests/push.rs | 登记/会话竞态、离线退出 outbox、后台拉取/预算、通知上下文与时钟测试 |
| kv-mobile-core/examples/r2c_phone_fixture.rs | 线上软件执行端，验签/真实计时/一次性消费 |
| mobile/packages/kv_native/android/src/main/AndroidManifest.xml | 持久 job/后台声明 |
| Android nativebridge/{RelayMessagingService,PushSyncJob,QuickApprovalService,KvNativePlugin}.kt | 原生后台、渠道/升级/动作、token 冷启动、通知维护 |
| Android StrongSigningGateTest.kt | signed-out 后台 ABI/运行时校验，实际 Keystore 门控 |
| kv_native/lib/kv_native.dart、iOS Classes/{NativeRuntime,KeyStore,KvNativePlugin}.swift | 通知维护、公共缓存/App Group 保护，不降低签名 ACL |
| mobile/lib/src/controller.dart | 登录/退出/刷新维护通知，仅原生 ready 时调用 |
| mobile/scripts/{build-native.sh,verify.sh,generate-c-header.py,r2c-pairing-qr.swift,r2c-phone-evidence.py,r2c-notification-evidence.py,r2c-push-probe.py} | target-r2c、native ABI 说明、二维码/焦点保护与本包通知连续采样 |
| Android/iOS 插件与 NSE 的 kv_mobile.h | 同一生成器同步命令说明，C 函数 ABI 不变 |
| deploy/relay/{keyvalet-push.service,push.conf,push.env.example,push-private.nginx.conf} | 统一 LoadCredential / 8788 私有部署；移除早期 kv-push.service |
| deploy/relay/nginx.conf.template | 仅新增私有片段 include，保留共享树现有 Cloudflare 源站限制 |
| docs/mobile-console-setup.zh-CN.md、mobile/docs/{push-deployment,r2c-device-acceptance}.md、本报告/assets | 部署/发行/资源/真机步骤和证据 |

Rust 路径均以 rust/crates/ 为前缀；Android Kotlin 均在
mobile/packages/kv_native/android/src/main/kotlin/dev/keyvalet/nativebridge/。
已有 Flutter 页面、Rust/原生分工、硬件键骨架没有重做。

| 新依赖 | 版本 | 发布日期 | 理由 |
| --- | --- | --- | --- |
| 无新增运行/测试依赖 | — | — | 复用锁定依赖、Android API 31+ JobScheduler、系统 CoreImage、Python 标准库 |

## 最终验证

Rust 1.99.0；默认 1.90.0 较旧，显式用新稳定版。所有本机 Cargo 使用
CARGO_TARGET_DIR=/Users/guang/dev/keyvalet/rust/target-r2c，局部迭代限定 -p。
最后全工作区复核结果以 [汇总](assets/r2c-validation.json) 的退出码/时间为准。
HTTPS 先拉取的首次全套检查发现撤销会话仍返回 authentication_failed，已补同 WS 的
本地失效清理，37 项 mobile-core 测试及最终全套均通过。另有一次 kv-helper owner_workflow
测试报 unknown_token；独立重跑及最终完整工作区重跑通过，未修改归属外 helper。
保留[首次回归](assets/r2c-https-first-login-regression.log)与[套件失败](assets/r2c-workspace-helper-flake.log)，不掩盖重跑。

| 检查 | 结果 | 证据 |
| --- | --- | --- |
| cargo +1.99.0 fmt --all -- --check | 通过 | [fmt](assets/r2c-ci-fmt.log) |
| cargo +1.99.0 clippy --workspace --all-targets -- -D warnings | 通过 | [clippy](assets/r2c-ci-clippy.log) |
| cargo +1.99.0 build --workspace --locked | 通过 | [build](assets/r2c-ci-build.log) |
| cargo +1.99.0 test --workspace --locked | 通过 | [test](assets/r2c-ci-test.log) |
| flutter analyze / flutter test | 无问题、40/40 | [analyze](assets/r2c-flutter-analyze.log)、[test](assets/r2c-flutter-test.log) |
| cargo build -p kv-mobile-core -p kv-push --lib --locked --target aarch64-linux-android | 通过 | [Android](assets/r2c-android-native-build.log) |
| 同上，aarch64-apple-ios / aarch64-apple-ios-sim、XCFramework | 通过 | [iOS](assets/r2c-ios-native-build.log) |
| flutter build apk --debug --target-platform android-arm64、正常安装 | 通过 | [构建](assets/r2c-android-apk-build.log)、[安装](assets/r2c-android-install.log) |
| flutter build ios --simulator --no-codesign | 通过，含 NSE 编译 | [模拟器](assets/r2c-ios-simulator-build.log) |
| Android connectedDebugAndroidTest / APK 检查 | 2/2，targetSdk 36、JNI 检查通过 | [XML](assets/r2c-android-signing-gate.xml)、[打包](assets/r2c-android-package-check.log) |

定向核心测试 mobile-core 37、relay 98、kv-push 8；实机门控 2。
软件全链路的升级使用真实 30 秒。最终手机产物 SHA-256 为
`4b3ffb3b76d4f00790017eb317cb0e4382d253224465e417bbfa0c9f4bb07834`；
[恢复 APK 构建](assets/r2c-android-recovery-build.log)、[正常安装](assets/r2c-android-recovery-install.log)通过。
[打包阶段比对](assets/r2c-native-artifact-match.json)确认当前 Rust ELF 被打入 APK；
AGP 去符号前后分别比对，未把原始 ELF 与 stripped ELF 的正常差异当作缓存错误。构建缓存耗尽本机空间后只清理本轮三个跨编译目标的
可再生成缓存，保留 mobile/native、APK、证据、软件 fixture 私钥目录和运行进程。

## 变更请求与未决项

- **R2-B 协议登记**：记录现有签名 Envelope push.mode 元数据投影，与密文 delivery 一致、
  仅用于提供商投递；不新增 kv-core 对象。内部请求加 to，公共 relay API 不增加正文/人在场字段。
- **D03**：产品短时设置票提到 Quick，但现有验证器要求 Strong。1 小时票保留 Strong，
  请规范负责人统一，不降级验证器。
- **D09**：attestation unverified；生物登记后 AK_s 换键/重新配对、pair-finish 状态查询、
  硬件种类规范化仍待 R2-B 对接。本轮没有占位证明。
- **T03**：路由、生命周期与真实 FCM 已通过；配对后的锁屏 Quick/Strong 和同 ID 升级通过。
  重启后 FCM token 持久化/唤起通过；审批拉取与远端退出清理未通过，当前受手机 relay 访问恢复阻塞。
- **E05**：正常 Debug 安装、实机负向 Keystore 门控及正向 Quick/指纹 Strong 已通过。
  真实 Mac 桌前提示/凭证执行待 R2-A，本轮仅验软件执行端的一次性消费。
- **E06/发行**：FCM 已到位；iOS/APNs/Apple 登录、Play 签名/渠道见资源清单。
- 未改 OPEN-QUESTIONS 或 §16 原文；本报告给出 Android 锁屏 Quick、App Strong、升级和
  设置三步的通过证据。端到端横幅预算的单次样本约 35 s，≤30 s 预算仍待优化/复验。
  Android 整体稳定性仍需恢复手机 relay 访问，复验重启/退出及一小时离线窗口；
  不能据此关闭包含真实 Mac GUI、iOS 或发行渠道的跨工作流条目。
