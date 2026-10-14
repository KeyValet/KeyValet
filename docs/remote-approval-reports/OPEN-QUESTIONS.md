# Remote approval V1 — 当前开放项与处置

2026-10-13，合并 W0–W9、接口收口及 R2-A/B/C/D。原报告保留各自快照；后续证据可以替代早期未测状态，不能替代另一平台或端到端指标。M2–M5 未完成，K1–K4 已拍板。源码、软件／fixture、单项硬件与已安装产品验收分别记录。

## 需要决定／落实的安全冲突

K4 的安全决定不重开讨论。2026-10-14 的 R3-B 无签名修复已落实 S01/S02 接收条件、负向向量与旧票失效处理，Mac／Windows CI 通过。S03 的运维访问边界仍需明确并落实。

| ID | 发现与依据 | 已决规范／所需处置 |
| --- | --- | --- |
| S01 | 已修复：有限／常设 T2 都要求签入当前执行端标签；missing/null/empty/wrong-label／签后篡改拒绝 | helper 安装／使用前重验同规则；启动把旧缺标签票标失效并审计，有效 T1／T2 保留。两平台 CI 通过，见 [R3-B 无签名 §2](R3-B-unsigned-acceptance.md#2-安全修复) |
| S02 | 已修复：共享接收器拒绝 aud=*／global 的 T2，有限与常设都有负向向量 | 不影响 T1 未来设备继承；旧全局 T2 失效并禁止重装。见 [R3-B 无签名 §2](R3-B-unsigned-acceptance.md#2-安全修复) |
| S03 | 原文称 /metrics 仅loopback，但 http.rs guard实际要求Device会话，metrics函数没有peer地址检查；nginx通用location转发，push-private片段仅屏蔽push | 明确仅本地监控还是允许设备会话读取聚合指标；若保留原本地运维边界，应代码／nginx限源并负向验证。loopback监听不等于外部代理访问被禁 |

## 已决设计与接口处置

| ID | 来源／决定 | 当前处置与验收边界 |
| --- | --- | --- |
| K1 | R2决定表、R2-B／R3-B | Windows DK=PCP ECDH+ECDSA，optional dk_sig/P-256/ES256；坏字段拒绝，HPKE仍dk_pub，旧记录照常。六新向量／schema和双平台CI通过；物理 x64 Hello 分项通过，原 VM 未设 PIN，生产闭环待验 |
| K2 | W8账户补充、R2决定表 | 桌面匿名＋恢复码；手机Google/Apple，以provider+subject及DK绑定ID token；双方SAS后账户归用户，不按邮箱合并。GoogleDebug曾通过，Apple待验 |
| K3 | W8、R2-C | 手机固定relay.keyvalet.dev、无地址展示／修改入口；自托管只服务桌面。官方relay/push已部署，手机当前HTTPS恢复仍未过 |
| K4 | D系列处置 | D03保持Strong；D04签名有限T2标签、D05拒global T2的接收／重验已完成S01/S02；D06/D07/D09为V2；D08/D10源码缺口关闭；D01/D02按现实现回写B/C |
| D01 | W7-W9-01、W0 CR8、W4 CR05 | 按匿名注册、公开binding、保留失败注册后的加密provider与单例迁移日志回写。R2-A已安装两端及SAS交换，Strong配对未完成、use n=0；不是安装器制造ID |
| D02 | W7 IPC01、W6 CR4 | owner intents与Strong→一次性120s准备令牌→精确标签→签发；常设T2两轮已实现／软件测试。CLI不给issuer/nonce/alg/sig；原生Mac流程未验 |
| D03 | W8 CR2、W6、K4 | 已决：所有设置Grant包括1小时票保留Strong；R2-C真机验Strong，产品Quick文案已删除 |
| D04 | W0 CR5、W4 CR09、K4 | 有限／常设 T2 的发行、接收与使用前重验均签入／核对当前标签；S01 已有负向向量与旧票迁移，见 R3-B 无签名验收 |
| D05 | W7 wildcard、W6 CR5、K4 | 全局／通配 T2 的发行和接收均拒绝，S02 已修复；CLI 仍逐当前执行端确认／发票，未来设备不覆盖 |
| D06 | W4 CR08、K4 | V2：不同操作的签名batch。当前只合并相同完整绑定重试，不能批A执行B |
| D07 | W0 CR3/4、owner六项、K4 | V2：产品多审批方/quorum及service/org信任根。基础fan-out／双Strong完整记录确认已有软件回归，unsupported authority仍拒绝 |
| D08 | W2 CR5、v1-completion | 已关闭源码缺口：无旧会话的/v1/recovery、新DK证明、原子撤销／轮换，新码预存／同DK续接。真实丢设备恢复验收未测；不恢复vault／旧离线票 |
| D09 | W8 CR4–6、K4 | attestation challenge／验证为V2，当前unverified。pair-finish状态查询、生物登记导致换键／重配、硬件kind规范化为后续计划，错误仍拒绝，不做占位证明 |
| D10 | linux-auth-relay-isolation、R2-A §3 | 源码／原生身份验证缺口关闭：root broker、SO_PEERPIDFD、Linux6.5+，8用例通过；ndu已安装3服务，helper/client无caps，broker仅SYS_PTRACE/AF_UNIX。完整审批另属E08 |
| D11 | 后续账户要求、W8账户补充 | K2/K3已确认；手机人类登录不替代审批键。GoogleDebug实测曾通过，R2-C重启后HTTPS／重新登录受阻；Apple及生命周期另属E09 |

## 外部资源与人工验收

| ID | 来源 | 当前状态／下一步 |
| --- | --- | --- |
| E01 | W2/W9、R2-A §2、R2-C部署 | relay.keyvalet.dev、simvito、nginx/OriginCA/Cloudflare链路已通过，server现行hash见R2-A。8787/8788 loopback、push公网404／认证202；Origin私钥未读取／导出。审批延迟仍E08 |
| E02 | R2-B／R3-B原生结果 | VM 双 PCP与安装11项、物理 x64 Hello分项有历史通过记录。R3-B旧包的物理 SYSTEM PCP／Quick HPKE及protected MCP Success/Cancel/Crash已通过；锁屏采集访问违例，生命周期修复待真机复验。新 WinUI／无签名发行包、物理 ARM64及生产公网仍待验；原 VM 无 PIN。见 [无签名续验 §8–9](R3-B-unsigned-acceptance.md#8-供电恢复后的真机续验) |
| E03 | W1、v1-completion、R2-A §3–4 | MacSE独立userPresence 1项3.66s通过、三不同公钥和签名daemon安装通过；实际Strong配对未完成、use n=0。macOS14／锁屏DK与Quick ACL、完整presence／cancel仍待验 |
| E04 | isolation、v1-completion、R2-A §3 | ndu Linux6.8 broker8原生用例、TPM DK往返1项1.68s与已安装TPM解锁通过。原vault hash不变、凭证列表0，需用户选只读测试凭证；普通SSH用户TPM无权限时拒绝，无fallback。双端审批未完成 |
| E05 | W8、R2-C真机表 | Pixel7正常Debug安装、native2/2且0skip、GoogleDebug、扫码／锁屏Quick／AppStrong／同ID升级／设置功能通过。重启新审批拉取和远端退出删除未通过，恢复relay HTTPS后复验；真实Mac联动待R2-A |
| E06 | R2-C Play/iOS、mobile console | FCM服务账号已到位并真实发送。Play上传keystore／指纹／权限未齐，无签名AAB／上传。iOS/iOS-sim编译通过；AppGroup/profiles/APNs/ASC记录/发行证书/Apple配置及SE真机未齐，未生成IPA／TestFlight上传；已注册bundle IDs不等于发行就绪 |
| E07 | R2-D §B/C、未决项 | 只有Codex、Devin两家托管模型实测；ClaudeOAuth过期／日常provider无回复、用户延后，Gemini/Grok未登录、Cursor额度耗尽、IDE未安装。Claude三项channels、第三家、未测timeout／Stop仍缺，不把准备阶段退出当工具超时 |
| E08 | R2-A §4、R2-C真机表、R2-D | Macp50/p95 n=0、双向一分钟吊销／audit／两小时合盖／Mac三步各<5s／本机优先未测；一周／两周未开始。手机横幅约35s、设置约5/≤16/<1s未满足预算，一小时离线延后。单次fixture数字不能代替公网Mac矩阵 |
| E09 | W8账户补充、account-login、R2-C | GoogleWeb/Debug与真实登录历史通过；当前Pixel重新登录未进SDK，需先恢复relay访问。Apple provider仍未配置、实际登录未测；删除／解绑、显式跨provider链接、Applecode/refresh生命周期为计划中 |

## 技术债与集成验收

| ID | 来源 | 处置／剩余工作 |
| --- | --- | --- |
| T01 | owner integration、isolation、R2-A/B/C | bootstrap/匿名注册/单例迁移/原密钥保留/完整PeerRecord/SAS/轮次隔离／原信封重试已软件接线；Linux/Mac安装通过、Windows硬件项通过。MacStrong配对未过、手机只fixture，不能整体关闭 |
| T02 | owner integration管理／六项、R2-A/C | issued ledger、签名预算快照、approval_decision证明、逐peer撤销回执／pending、未来T1／排除、watch序号和分页已实现。原生Mac延迟／审计／吊销未测；短期撤销／删除challenge到期需owner重试，历史留存仍有限 |
| T03 | R2-C路由／token／真机表 | 签名hint、持久pushjobs、初次+3重试、CAS410、session/token竞态、私有push部署／真实FCM通过；AndroidQuick/Strong/升级通过。重启拉取与远端退出未通过，一小时离线／iOS未测，不能整体关闭 |
| T04 | remote-recovery-audit、v1-completion | 加密目录prepare/commit、vault独立AEAD审计检查点、收据／SQLite尾回滚拒绝、固定头对账实现并软件通过。全备份一起回滚与最终发布窗口没有硬件／外部锚点；手机同库链头、旧历史缺口保留 |
| T05 | W1、R2-A/B | macOS启动屏保初值、Linux精确idle／polkit证据／慢bus与五秒转换仍待原生矩阵；unknown保持Away、去抖变化立即发、60s为refresh，不是状态变化限速 |
| T06 | W1/W3/W5/W6/W7、R2 | 旧100%仅报告限定逻辑／源码快照，不代表当前native/Swift/Windows全路径；W2新增账户后已降至92.08%行的历史复测。R2CI与真机门控不自动关闭全源码覆盖率要求 |
| T07 | v1-completion、W7后续 | 已关闭：获批qrcode0.14.1、关闭imagefeature；UnicodeQR/quietzone、URI失败回退、JSON无图案均已实现／测试 |
| T08 | R2-D §D/E与最终验证 | 源码／SDK验收关闭：typed拒绝取消到期、兼容旧cancelled、403/409/410禁重试、活session有限响应一次领取、绑定改变拒绝、wildcard/h2与fd256回收20轮通过。跨重启/已交付断流/外部HTTP exactly-once不承诺；真实原生producer另待R2-A |
| T09 | W9 ownership、R2-A修复清单 | 新安装器移除模式／workflow wrapper已有回归；独立legacy卸载／bootstrap／打包入口仍待维护者完整核对，R2-A只报告requirement一行修复，不据此关闭所有旧入口 |
| T10 | R2-D R2E-CR1 | 核对Devin3000.3+专用mcp_config文件；main --config不隔离MCP。若客户端配置短timeout，KeyValet子进程同步KEYVALET_TOOL_TIMEOUT_SEC，保留其他env/server/hook。R2-E只记请求，不改安装器 |
| T11 | R3-B 原生结果及当前发行策略 | 无binding控制worker及不可读配置拒绝已有签名VM记录；旧unsigned包Manual/Stopped为历史行为。当前源码默认unsigned发行，relay Auto/Running等待绑定；调用方以OS PID/token SID、固定安装文件身份与受保护DACL认证，签名可选。新策略整包原生安装与正式绑定公网需复验；vault权限、档位及身份验签不变 |
| T12 | R3-B 无签名修复 | 已修复：remote audit parser/help 与 QueryAudit/helper 均 1..200；201／1000 在 CLI 拒绝，接收上限未提高；两平台 CI 通过 |

## 当前证据与下一步

R2-A的第二次交互报告检查点仍写等待管理员密码，而最新r2a-pair-native.json为ipc_unavailable；原报告不改，R2-E只把第一次已记录失败与use=0用于验收，后续错误诊断由R2-A补充。R2-C也从早期Google／退出通过推进到重启后网络失败，当前远端退出未过优先于旧冷启动记录。

S01/S02 与 T12 的冻结快照已有修复／两平台 CI；继续明确 S03，补真实请求矩阵、手机稳定性、新版 Windows 整包／protected 客户端及可用运行时账号。Windows 签名现为可选，不作为继续验收的前提。完整章节回写与证据抽查见[R2-E](R2-E-docs.md)。所有未测保持未测，拒绝条件保持，恢复码／配对token／会话令牌／凭证值不进入报告。

## 2026-10-14 新发现与收口

| ID | 状态 | 证据／下一步 |
| --- | --- | --- |
| T13 入站审批恢复 | 已实现并回归通过 | ACK 前持久化、vault 收据绑定、当前发送方签名／权限重验；取消／签发／过期不复活，升级提示保留。物理睡眠／重启与真实投递仍另验，见 R3-B 无签名 §2 |
| E10 Windows 桌面资源 | 已部分续验；等待SSH／空间／客户端 | AC=1后旧包升级、真实PCP与protected MCP Success/Cancel/Crash通过；锁屏采集崩溃。真机22可连但SSH无握手，Mac低于15GiB暂停新构建。Cursor安装但MCP失败；Claude下载返回地区不可用HTML，WSL功能Disabled／发行版0，见[R3-B §8–9](R3-B-unsigned-acceptance.md#8-供电恢复后的真机续验) |
| E11 Foundation 签名 | Windows改为无签名发行；签名可选 | 当前Windows文档记录申请未获批。源码按真实SID／安装文件身份／受保护ACL与服务创建子进程认证；旧publisher前提已由发行策略改动取代。新整包／公网仍需实际验收，不能用旧签名VM收据代替。见[Windows策略](../windows.md#windows-release-identity-policy) |
| T14 Windows WinRT生命周期 | 原生定向修复通过，真机待复验 | 第二次IsSupportedAsync访问违例；假SDK先红后绿，保留线程及服务MTA，初始化失败／未知仍away。当前Mac CI等待空间，详见R3-B §9 |
| T15 Claude PowerShell hook | 回归修复通过，现场待验 | command字段沿用原检测与ask，补Windows／插件matcher；Rust/JS与PS5.1/7有修前／修后证据，实际Claude尚不可用，详见R3-B §9 |
| T16 重新加入后的历史审计 | CLI已接线，当前源码回归重跑中 | 本地和远端archived_devices逐身份读取，固定账户／身份／分页头与检查点；缺失回执仍保留差异和非零退出。旧定向测试因Cargo缓存复用撤回通过结论，须核对新增测试实际执行，详见R3-B §10 |
