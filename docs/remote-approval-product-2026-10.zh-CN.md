# 远程审批与多设备配对：产品文档

- 版本：V1 两轮实现与验收回写，2026-10-13。
- 配套：[架构与接口契约](remote-approval-architecture-2026-10.zh-CN.md)；本页说明用户、现有功能、使用边界和未完成验收，不作发布就绪声明。
- 现状：核心软件链路、CLI 与手机控制面已实现。Ubuntu × MacBook 安装完成，但 Strong 配对未完成、实际 use n=0；Android Pixel 7 对软件执行端的核心审批通过，重启拉取／远端退出未通过；Windows 双 PCP 与安装通过，Hello 等待 PIN。iOS／商店发行与全部时间指标尚未完成，M5 未完成。

---

## 1. 一句话

把凭证留在执行端的受保护 vault，把批准留在用户手边的设备；每次决定绑定真实请求，等待期间不放行。

## 2. 为什么做远程审批

既有本地审批要求人在执行端旁边：macOS 用 Touch ID／系统密码，Linux 用 polkit。服务器、无头 Mac 和长期任务需要用户在另一台设备看真实请求、决定批准范围。V1 已实现签名决定、端到端信封、等待恢复与远程设置；是否能在具体真机组合完成日常使用，要看验收表，不能从软件测试推断。

首个真实部署是 ndu Ubuntu 服务器 + MacBook，relay.keyvalet.dev 已上线。凭证不跨设备同步，服务器 root／Windows SYSTEM 仍不在防护范围。

## 3. 目标用户与平台

| 优先级 | 人群／场景 | 当前可用范围 | 验收边界 |
| --- | --- | --- | --- |
| P0 | Linux 服务器 + Mac 的个人开发者 | TPM 执行端、签名 Mac daemon／relay、owner CLI、原生审批 UI | 两端已安装，配对 Strong 未完成；首次真实凭证请求、延迟、吊销与审计未测 |
| P0 | 使用 Android 手机审批无头执行端的人 | Google 登录、扫码／SAS、锁屏 Quick、App 指纹 Strong、票与设置 | Pixel 7 × 软件 fixture 核心流程通过；真实 Mac/ndu 请求、重启恢复／远端退出及一小时离线未完成 |
| P0 | Windows 混合环境的个人开发者 | x64 系统服务、PCP 双 DK 与 Quick、PowerShell 安装／升级／卸载 | 模拟 TPM VM 通过；Hello 创建／Strong／取消／跨端 RS256 等待 PIN，生产签名发行待完成 |
| 验收中 | iPhone 审批用户 | Flutter／Rust／NSE 代码与 iOS/iOS-sim 构建 | SE、APNs、Apple 登录、TestFlight 发行未测，资源待齐 |
| V2 | 团队、Linux 桌面审批、云执行端 | 保留接口 | quorum、服务／组织信任根、Web 控制台、KMS／隔离执行尚未实现 |

同一桌面设备可有 execute／approve 两种能力；手机是审批端，不保存执行端凭证。Mac 原生弹窗与终端、手机 App 是现有入口，桌面图形设置页不做，托盘／菜单栏为 V2。

手机必须先 Google／Apple 登录，随后通过双方 SAS 加入执行端账户。手机固定官方 relay，地址不展示、不可编辑。**自托管 relay 只服务桌面审批端／CLI**。Android 先验，iOS 后续完成。Google Debug 登录曾通过；当前 R2-C 手机停在登录页，relay HTTPS 恢复仍待处理，Apple provider 尚未配置。

## 4. 用户故事与当前边界

1. 在另一台设备看谁发的请求、实际方法／主机／路径、风险和可选范围，再批准。
2. 明确给某凭证签有期限／预算的 T1 放行票，日常少被打扰；普通票不覆盖敏感 T2。
3. 离线或合盖时排队到请求到期，不因没人审批而放行；真实两小时合盖尚未测。
4. 未批时收到待批状态，批准后续等原结果；拒绝、取消、到期是不同事实。
5. 从审批端锁定、收紧模式或撤销票；离线目标显示撤销待确认，不能假报立即完成。
6. 查签发台账、预算快照与跨端审计；未取到使用量显示未知。
7. 用手机的实际硬件签名批准；登录成功或 UI 生物识别布尔值不能替代 Strong。
8. 明确开启逐执行端的 T2 无人值守时，单独 Strong 与精确标签确认；全局 T2 拒绝。

## 5. 用户旅程

以下是当前入口与流程；Ubuntu × MacBook 的整条旅程仍在验收，<10 分钟是目标。

### J-R1 第一次配对

1. 在执行端安装 KeyValet，Linux 远程角色认证要求内核 6.5+、keyvalet／keyvalet-peer／keyvalet-relay 三服务；硬件失败报错，软件保护必须显式选择。日常机器覆盖安装先按平台说明备份 vault／配置。
2. 桌面使用 keyvalet relay set-url https://relay.keyvalet.dev；桌面自托管可用自己的 HTTPS relay。relay install 只生成部署资产，证书、专用用户和服务激活仍须管理员完成。
3. 执行端 keyvalet pair --new 首次匿名注册，显示账户 ID、恢复码、URI 与 Unicode QR。恢复码只在终端保存一次，不放聊天、日志或截图。
4. Mac 使用 keyvalet pair <kv-pair://…>；手机先 Google／Apple 登录，再扫码。两端核对六位 SAS，纯执行端 owner 终端 y/N，审批端用 Strong 确认。
5. 双方有效确认后才建立信任；候选公钥、扫描成功或 HTTP complete 成功都不算配对完成。加入新执行端时展示全局 T1 票数量并可选择排除继承。

R2-A 首轮 SAS 一致、终端确认已交，但 209.526 s 后 Strong 阶段停止，首次 use 为0；Pixel 7 × fixture 配对约9 s并验手机 Strong。两种结果分开记录。

### J-R2 首次请求

审批 UI 已实现设备／系统／保护状态、agent、真实操作、凭证引用、agent 自述、风险、范围和时间提示。W6 的九类展示经用户核对，是真实预览截图，不代表公网请求执行。

执行端产生 unlock／use／admin 请求；unlock/admin、T2 和常设范围要求 Strong。当前生产风险适配保守：GET／HEAD／TOTP 为 T1，其余 use 为 T2、T3 管理拒绝，不能以某个示例 POST 当作 Quick 已可用。远程票据也不解密尚未解锁的 vault，实际凭证会话仍须原有受保护解锁路径。

批准后按原凭证版本、进程和完整请求绑定执行，nonce／结果只消费一次；显示的 purpose 是 agent 自述，不是权限依据。Mac/ndu 尚无真实凭证 use 样本；手机 fixture 的 Quick／Strong 各执行一次、二次领取 Replay 已通过。

### J-R3 减少打扰

```sh
keyvalet grant --to srv --credential github/default --hosts api.github.com --methods GET --budget 500/24h --until 24h
keyvalet grant list
```

独立签票需要 Strong，可限定 host/method/path/agent／预算／到期。弹窗的 session／remember 只从执行端提供的范围派生内部 T1 授权，保留原决定签名；它不能冒充可转发的新签名票。自动推荐「连续批几次后给24小时只读票」尚未实现，归 V2。

### J-R3b 远程控制面

| 操作 | 当前入口 | 最低审批要求／状态 |
| --- | --- | --- |
| 看状态／待批／票／审计 | remote srv status/pending/grants/audit | Quick；签名回执仅元数据，使用量带获取时间 |
| 切 per_use 收紧 | remote srv mode per_use | Quick |
| 切 remember 放宽 | remote srv mode remember:8h | Strong |
| 签1小时票 | remote srv allow --credential github/default --until 1h | **Strong**，短有效期不降级（K4/D03） |
| 签常设 T1／全局 T1 | remote srv allow --all --standing；remote '*' allow --all --standing | Strong；全局提示未来执行端，配对可排除 |
| 逐执行端 T2 无人值守 | remote srv unattended --include-sensitive --until 1h | Strong → 一次性准备令牌 → 精确标签 → 签发；不能全局覆盖未来设备 |
| 收回某票／全部 | remote srv grant revoke <jti> / revoke-all | Quick；逐目标回执，离线保留 revocation_pending |
| 锁定 | remote srv lock | Quick |
| 修改 TTL／batch／标签 | remote srv unlock-ttl/class/label | 收紧 Quick，放宽／新 class／改名 Strong，CLI为主要入口 |
| 强制手机横幅 | remote srv notify always-phone | Quick Directive，只改投递，不改权限 |

本地 /keyvalet:mode 与远程 SetMode 共用 helper 设置后端及 CAS，过时提案不能覆盖新状态。桌面 owner grant revoke 仍有 owner／Strong 认证路径，不能把“所有收回都免认证”作为承诺。

手机设置切模式、1小时票、revoke-all 对 fixture 功能通过，实测约5 s／≤16 s／<1 s（含用户操作），尚未满足三步各<5 s；Mac 控制面 n=0。T2 发行流程已有软件回归，接收验证尚缺 K4 的有限标签与全局拒绝条件，见 §9 和架构 §7.6，不能宣布安全栏全部完成。

### J-R4 批得晚时

- 调用内默认最多60 s，受运行时预算封顶；有客户端 progressToken 才每15 s发进度。
- 预算用尽返回 approval_pending，不表示拒绝。需要结果时调用 credential_wait_approval，返回原结果，不能重发原请求；只有 approved_retry_required 才允许同参数、同 approval_id 恢复。
- Stop hook 对同一 agent 的未到期待批最多阻止三次；Devin 真实 block 后续等得到结果，Codex exec 真实 block 后续等，但最终回合未取得结果。
- Claude channels 声明／发送有 CI；idle 唤醒、busy 合并、无 flag 丢弃均未测，不能承诺能自动唤醒每个会话。
- 拒绝为 approval_denied；明确取消为 approval_cancelled；请求到期为 approval_expired；只等候超时且 exp 未到仍待批。

Codex 0.162.1 的实测 clientInfo profile 默认180 s，其他未测 Codex／未知客户端50 s；四分钟实验完成的是 Codex 和 Devin 两家。Claude OAuth／日常 provider、Gemini 登录、Grok 登录、Cursor 额度限制使本轮未进工具；没有把它们当工具超时。完整矩阵见架构 §6.9.3 与 [runtimes.md](runtimes.md)。

HTTP 网关／透明代理挂连接55–540 s，pending 返回429＋Retry-After:30。明确拒绝／取消／到期为403／409／410，SDK终态禁止重试。同一活 gateway session、同凭证与原 method/URL/headers/body可一次领取有限保留响应；最多16 tickets、每响应8 MiB，不支持跨重启恢复或外部 HTTP exactly-once。

### J-R5 加设备

已信任审批端可 pair --new，加另一桌面或已登录手机，核对 SAS并用实际 AK_s签名。基础 fan-out与两 Strong设备记录交换已有模块测试；产品多审批方／quorum策略归V2。手机不能用自建relay URI加入官方产品。

### J-R6 丢失、吊销与恢复

devices revoke 使用 Strong证明，保存本机墓碑／逐peer消息并注销relay；待投递显示未完成。已安装设备一分钟失效目标未测，离线端不能承诺即时收到。锁定vault与 audit --remote 可查询已有记录。

全部设备会话丢失时，relay recover <account-id>从隐藏输入／stdin读取旧恢复码，DK证明绑定新设备与新码，成功原子注销旧注册并轮换码。它不恢复vault、凭证或硬件私钥，也不能擦除失联设备上的离线票；手机仍要人类登录。

### J-R7 relay 或手机网络故障

待批保留到exp，relay-client存持久密文队列；远程失败不降低认证。执行端owner可用已有本地审批后备。R2-C当前手机FCM能唤起，但relay HTTPS请求仍失败，重启拉取与远端退出删除未通过，不能用推送202掩盖。

### J-R8 升级与卸载

协议拒绝未知授权／未来版本处理，未知描述字段无损保留并参与签名。升级／卸载按平台安装器保存vault和规定的队列／备份；Windows11项生命周期回归通过。卸载不等于已经向所有peer／relay完成吊销，需显式owner吊销；不能写成自动清除所有远端授权。

## 6. 审批界面规范

| 内容 | 当前规则 |
| --- | --- |
| 来源 | 受信设备标签／OS／保护状态，software或unknown明确显示 |
| agent | 运行时、工作目录／仓库、系统用户；实际身份由OS认证 |
| 凭证 | 引用／名称／类型、proxy_only；不显示值 |
| 真实操作 | summary、方法／主机／路径／大小，作为主要内容 |
| agent 自述 | purpose明示自述，不能当真实操作或授权 |
| 风险 | T0/T1/T2、最低级别；T2突出且弹窗仅本次 |
| 范围 | 只展示scope_options，不能由UI新增权限 |
| 档位 | Quick点击；Strong使用真正AK_s操作；手机Strong通知只打开App |
| 异常 | 创建时间／时钟偏差／积压／无人值守；不把不同操作批合并当已实现 |

不显示凭证值、完整headers／body、私钥、恢复码或vault路径。Mac Strong为系统userPresence（Touch ID／系统密码），手机AK_s为生物绑定密钥；WindowsHello代码路径保留RS256，交互等待PIN。

### 6.1 选择范围的含义

| 选择 | 授权边界 | T2 | 最低要求 |
| --- | --- | --- | --- |
| 这一次 | 完整原请求，一次消费 | 按该请求 | T1可Quick，T2/unlock/admin Strong |
| 这个凭据本会话／本会话全部 | 当前agent/session内T1 | 不覆盖 | 原请求提供的Quick范围 |
| 记住1／8／24小时 | 提供的精确时长，当前凭证T1 | 不覆盖 | 弹窗按原请求；设置签票另为Strong |
| 凭证／执行端常设 | 直到撤销的T1范围 | 不覆盖 | Strong |
| 全局T1 | 未来经SAS信任且未排除的执行端 | 不覆盖 | Strong＋未来设备提示 |
| 逐执行端T2设置 | 显式范围、到期／常设，显示无人值守 | 可覆盖 | Strong＋精确标签；常设两轮确认；接收缺口未关闭 |

CLI unattended必须--until；常设T2为helper／手机签发逻辑，不能写成CLI已有--standing。finite/standing签名T2对象都应包含当前标签，global T2拒绝；实现冲突不降低这条已决规范。

### 6.2 界面现状与计划

手机先登录页（Google／Apple），登录后四页：待批／详情、设备／设置、活动、账户／退出及通知偏好。固定relay.keyvalet.dev不展示、不编辑；APK已在Pixel7正常安装，Android先完成核心流程，iOS仅有编译／模拟器证据。Debug APK不是Play签名AAB，未生成IPA或上传TestFlight。

| 入口 | 已实现 | 仍需验收／计划 |
| --- | --- | --- |
| CLI | 配对、列表、批准／拒绝、设置票、Directive、audit／恢复 | Ubuntu×Mac完整原生旅程与时间指标 |
| Mac原生弹窗 | 请求、范围、SAS、标签／全局提示；W6截图已核对 | 真实两端Touch ID配对／请求、锁屏、合盖 |
| Windows原生TaskDialog／Hello | UI代码、PCP身份／Quick和RS256签名路径 | Hello等待PIN，完整点击／物理TPM矩阵未验 |
| Android App／原生后台 | Google、扫码、Quick／指纹Strong、同ID升级、设置三步；原生后台由FCM→JobScheduler→Rust处理推送，不启动Dart isolate。 | relay恢复／远端退出未过，≤30 s横幅及各<5 s设置预算未过；Play发行待资源 |
| iOS App／NSE | Flutter/Rust/native、App Group、C ABI、通知计划和构建 | Apple／SE／APNs／锁屏／匹配profiles／TestFlight待验 |
| 桌面图形设置页 | 不做 | 托盘／菜单栏按需要为V2 |
| Web／团队 | 接口保留 | V2：团队目录、服务信任根、quorum、Web |

人在场策略用本用户图形会话、锁屏／屏保、输入idle、显示器／远程会话和审批通道五组信号；任一未知为away，变化五秒去抖、60秒刷新。它只改投递，不改授权：本机／桌面present令手机silent，away/idle/unknown令banner；执行端30秒未决发同ID升级。relay依据签名头的push.mode，不能把WS在线当人在桌前。手机“我不在电脑前”是本地呈现偏好，remote notify always-phone是另一条签名Directive。

Pixel7静默→升级声音与同tag/id通过，静默到横幅28.620 s、请求到横幅约35 s；真实Mac优先投递／锁屏away未测。iOSNSE不跑Flutter，后台验证／解密用同Rust库；AppAttest／PlayIntegrity只有原生适配器，验证归V2，不声称已有硬件证明。

## 7. 功能状态（V1）

每行将源码实现、实机验收和V2分开；“已实现”不表示整条旅程已通过。

| 功能 | 已实现 | 验收中 | V2／计划中 |
| --- | --- | --- | --- |
| relay／部署 | SQLite API、官方Cloudflare→nginx→loopback、WSS、桌面自托管资产 | 实际审批延迟未测；metrics边界S03 | Postgres／多实例、计费配额 |
| 配对／身份 | 匿名＋恢复码、手机Google/Apple＋DK证明、双SAS／完整记录 | Ubuntu×Mac未完成、Apple未验 | 多用户团队、显式跨provider链接／账户删除 |
| DK／签名 | Windowssplit DK、旧记录兼容、HPKE／ES256／RS256 | Hello等待PIN；物理TPM／全部ACL | 云KMS／隔离执行 |
| 请求与等待 | digest/nonce、Quick/Strong、pending/wait、Stop、progress、活gateway响应恢复 | 真实凭证use n=0；Claude／第三家／channels未过 | 跨gateway重启恢复／新的响应契约 |
| 远程控制面 | mode、Strong设置票、预算、逐目标撤销回执／pending、本地设置共享后端 | Mac三步n=0；手机三步预算未过 | 不同操作签名批授权、自动只读推荐 |
| T2安全栏 | Strong准备令牌、有限一次／常设两轮标签，发行端拒global T2 | 接收验证S01/S02缺口待修，不计完成 | 无全局T2放宽计划 |
| 推送／token | 独立kv-push、FCMdata、签名路由、CAS轮换／退出outbox | Android重启／远端退出未过；一小时离线未测 | — |
| Android | Debug正常安装、Google／硬件门控、Quick／Strong／升级／设置功能 | 真Mac联动、稳定性与预算、Play签名发行 | 公开上架计划中 |
| iOS | Rust与Runner/NSE构建、AppGroup／原生计划 | 真机SE／APNs／Apple、profile／IPA／TestFlight | 公开上架计划中 |
| 审计／恢复 | 固定头分页、签名摘要对账、vaultAEAD检查点、recovery CLI | 真实双端对账／设备丢失恢复未测 | 硬件单调计数器／外部见证 |
| 吊销／睡眠 | 墓碑、持久outbox、一次消费、过期处理 | 双向一分钟／真实两小时合盖未测 | — |
| 新审批者 | 基础fan-out、两Strong设备记录交换／验签 | 完整多设备OS投递未验 | 产品多审批方／quorum、service/org信任根、attestation验证 |
| 文档／CI | 四份R2报告；各快照工作区四项CI通过 | 当前M2–M5不完整，不能用计数推算 | 长期dogfooding后对外文案 |

## 8. V2 与未实现项

Linux桌面审批、云密钥／隔离执行、Mac替Linux执行、vault同步／手机OAuth添加凭证、不同操作批承诺、团队quorum／服务审批者、硬件attestation验证为V2。Web随团队，托盘按需求。账号删除／解绑、跨provider显式链接、Apple code exchange／refresh生命周期与正式商店发行为计划中；不是同邮箱自动合并。

不通过聊天机器人代签，不让relay解密审批内容，不以Root外能力承诺保护服务器root。

## 9. 安全规则与边界

- agent只能申请，不持审批私钥；批准绑定完整原请求与一次性nonce，范围只能收窄，T3保持拒绝。
- DK用于身份／信封和HPKE，不用于批准。Windows逻辑DK为两把PCP，任一失败报错；可选dk_sig只改身份验签选择，HPKE和AK算法不变。
- 放宽、独立设置票和预授权Strong，有限票也一样；收紧／远程撤票Quick。T2只从明确设置路径签发，准备令牌与精确标签绑定，常设两次确认，全局T2拒绝。
- **仍有已决安全要求未落实的接收缺口**：shared verify_grant对有限T2未强制confirm、对global T2无独立拒绝条件。发行端约束不能代替接收验证，OPEN S01/S02待负责人修复，不以文案解释为允许。
- 登录不是批准：provider+subject认人，DK认设备，AK认审批；跳过AndroidCryptoObject不能签AK_s，实机负向门控已通过。iOS尚未测。
- relay与Cloudflare能看路由／设备／人类身份和投递元数据，审批／授权正文为E2E密文；登录／恢复参数只由TLS保护。relay可丢消息或拒绝服务，不能替设备产生有效AK签名。
- root／SYSTEM／被攻破helper或rootbroker不在模型内；不承诺relay永远在线、Quick防已解锁设备被拿在手中、或全备份硬件反回滚。MacuserPresence允许系统密码，不写成只认生物特征。
- 授权一次领取不保证外部HTTP副作用exactly-once；流交付后断开、gateway/helper重启不能保证拿回原响应。

## 10. 定价与托管边界

| 档／方向 | 当前状态 | 范围 |
| --- | --- | --- |
| 开源／桌面自托管 | 现有代码与部署资产 | 自托管relay只服务桌面审批端／CLI；不能写成包含手机接自建relay |
| 官方relay与手机 | 已部署；Android核心验收，iOS待验 | 手机固定官方地址与Google／Apple登录；当前未执行套餐额度／计费 |
| Free官方合理使用额度 | 计划中 | 3台、每月2,000次等为既有定价目标，非当前限额代码或服务承诺 |
| 个人付费托管／Team | 计划中、价格未拍板 | 托管便利／团队治理；不按付费档降低设备验证与审批安全 |

安全规则不因套餐改变。TestFlight／Play打包脚本不等于可安装发行包已交付；不会拿Debug签名替代Play应用签名或生产证书。

## 11. 成功指标与真实结果

| 指标 | 目标 | 两轮后的当前结果 |
| --- | --- | --- |
| Ubuntu×Mac pair→首次use | <10分钟 | 未通过；209.526 s停止、use n=0 |
| Mac公网审批p50/p95 | <3 s／<8 s、≥20次 | 未测，n=0 |
| 吊销 | 双向1分钟内 | 未测 |
| 两端audit | 100%对账 | 未测，不能以0请求计100% |
| Mac合盖 | 2小时无重复、正确expired | 未测、未开始计时 |
| Mac三步设置 | 各<5 s | 未测，各n=0 |
| 手机三步设置 | 各<5 s | 功能通过，约5 s／≤16 s／<1 s，预算未过 |
| 本机优先 | 真GUI／锁屏变化 | 未测 |
| 一周／两周使用 | 预授权覆盖>80%、人工打扰可解释 | 未开始，不能从单测推算 |

数字与证据路径以架构 §16、review顶部表及[R2-A](remote-approval-reports/R2-A-m2-acceptance.md)、[R2-B](remote-approval-reports/R2-B-windows.md)、[R2-C](remote-approval-reports/R2-C-mobile.md)、[R2-D](remote-approval-reports/R2-D-runtimes.md)为准。尚不进入“完整真机验收通过”的推广结论；后续外部试用／付费验证是计划。

## 12. 仍需处理的问题

优先落实K4接收验证与metrics边界，再完成MacStrong配对、选定真实只读凭证请求和20次测量；安排吊销／审计／合盖。Android恢复relay HTTPS后复验重启与远端退出、安排离线窗口。Windows用户设置PIN后验Hello；iOS／Play补登录／推送／签名资源。运行时须有效Claude会话和第三家，复验channels及未测timeout／Stop。

完整设计处置、外部资源和技术债在[OPEN-QUESTIONS](remote-approval-reports/OPEN-QUESTIONS.md)。K1–K4已决定，不再把Windows双用途方案、手机是否登录、固定地址或短期票Quick当待拍板选项。

## 13. FAQ

**为什么手机要登录？** 手机产品用Google／Apple的已验证provider+subject确定用户归属，DK证明把一次性登录尝试和ID token绑到本机；双方SAS完成才加入执行端账户。登录不替代Quick／Strong，也不让手机拿执行端凭证值。GoogleDebug已实测，Apple还待配置／验收。

**手机能连自建relay吗？** 当前不能。手机地址固定relay.keyvalet.dev，不展示或提供编辑／API入口；自托管只服务桌面审批端和CLI。

**批得晚能续上吗？** 活session可用wait工具领取原结果；没有批准返回待批，过期后只能按需新建。Stop最多三次，Claudechannels live尚未测，不承诺所有客户端自动唤醒。HTTP恢复只限相同活gateway session及完整原绑定。

**是不是所有agent都验完？** 没有。Codex和Devin托管模型四分钟／续等有证据；Claude、Gemini、Grok、Cursor及两个IDE还有登录／额度／安装缺口。Codexexec/TUI算同一家，未满足Claude加另外两家的门槛。

**可以以后不再问吗？** 普通常设／全局T1票可以，敏感操作仍要Strong。逐执行端T2设置需Strong与精确标签，常设两轮，不支持全局T2；接收验证缺口仍待修，不能当安全栏已验收完毕。

**Windows能当审批端吗？** PCP身份与Quick对软件执行端的互操作已通过。Strong代码用HelloRSA-2048/RS256，当前VMIsSupportedAsync=false，用户未设PIN；创建、签名、取消及跨端Strong都记等待PIN。

**设备丢了能恢复什么？** 离线账户ID和恢复码可恢复relay账户并轮换新码／注销旧注册；不能恢复vault／凭证／硬件私钥，不能擦掉失联机器上的离线授权。audit的AEAD检查点也不是硬件反回滚。

**为什么不直接SSH去批？** 本地owner的polkit后备仍可用；远程入口的价值是请求主动送到手边并显示真实操作。root/SYSTEM不在防护范围。

**手机和桌面发行都准备好了吗？** Android当前为正常Debug安装的实机证据；Play签名AAB／TestFlightIPA尚未生成或上传，iOS真机与Windows生产签名仍待完成。
