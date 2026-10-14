# R2-E — 两轮实现与验收的文档回写

2026-10-13。R2-A/B/C/D 报告均已提供后启动，完整阅读两份对象文档、K1–K4、全部第一轮／接口收口／第二轮报告及账户、恢复、手机、Windows 验收说明后修改。只改文档，未执行任何改变 git 状态的命令，未改代码／依赖、README、site、runtimes 或原报告。

架构与产品现在区分源码实现、软件／fixture、单项原生硬件与完整实机验收。**M2–M5 未完成**：Mac/ndu use n=0，Windows Hello 等待 PIN，Android 核心流程通过但重启拉取／远端退出未通过，iOS 未验；Codex／Devin 两家不能满足 Claude 加另外两家的门槛。没有补写未发生的审批、延迟或对账。

## 改动文件与范围

- [架构](../remote-approval-architecture-2026-10.zh-CN.md)：正文、验收、里程碑与附录 A–F。
- [产品](../remote-approval-product-2026-10.zh-CN.md)：平台／旅程／UI、三种状态的功能表、托管与 FAQ。
- [OPEN-QUESTIONS](OPEN-QUESTIONS.md)：K1–K4、D01–D11、E01–E09、T01–T12，以及 S01–S03。
- [review](../review-2026-10.zh-CN.md)：仅原 R2-A 顶部验收表合入四份 R2 行；前后文字和 W9 历史表保留。
- 本报告。检查脚本嵌在报告，未增加范围外脚本或改原证据。

## 章节 → 修改 → 依据

本表列出实质回写，纯排版不逐行注释。K1–K4 来源为 [R2 prompts 顶部决定表](../remote-approval-agent-prompts-r2-2026-10.zh-CN.md)；各报告原文保持历史快照。

| 章节 | 回写内容 | 报告及具体依据 |
| --- | --- | --- |
| 架构开头／§0–§1 | 改为2026-10-13当前状态；官方relay已上线、M2–M5未完成、目标与完成分开，设置票Strong；去掉全局T2与内部票伪新签名的表述 | R2-A §2–4/§7；R2-B「Windows原生结果」；R2-C「当前结果／Android真机表」；R2-D开头与§B；K1–K4 |
| 架构§2拓扑、§2.1/§2.3、§9.1 | 加root peer broker、Linux6.5+/SO_PEERPIDFD、传已连接FD／安装inode／UID，broker仅身份证明无vault/网络；helper移除relay网络直接依赖、HTTP/WS归control transport；Windows无绑定worker例外保留 | linux-auth-relay-isolation「实现／验证记录」8原生用例；R2-A §3三服务／能力；R2-B「未决项」第2项 |
| 架构§3.1 | Windows DK拆PCP ECDH与ECDSA、dk_sig与ES256、0x80090029原因、独立Quick／Hello RS256、provider方法、两键状态、硬件失败无隐式软件回退；SE独立Strong与锁屏未验分开 | R2-B「协议／Windows原生结果／给R2-E的架构回写文字」；windows-native-acceptance「未通过项」「R2-B追加」；v1-completion「已验证的边界」 |
| 架构§3.2 | PCP metadata v2 pin两句柄／公钥、半套清理与DeleteKey flags=0；以加密remote metadata／完整SQLite记录替代规划peers.json | R2-B「协议／给R2-E回写文字」；W5「生产接线与W1–W5交界」；owner integration「六项代码审查修复」跨库提交 |
| 架构§3.3、附录B账户 | 桌面匿名＋恢复码，手机provider+subject／DK绑定精确ID token，双SAS后归属，固定官方地址，设备／人类会话分开 | W8「Google/Apple补充 → 改动文件与接口／复核后修正的边界」；R2-C「token与后台可靠性／Play与iOS」；account-login「Protocol and storage」；K2/K3 |
| 架构§3.4 | 墓碑、Strong删除proof／持久peer投递与pending，/recovery无旧会话、新码先存、同事务轮换／撤销；不恢复vault／旧离线授权 | owner integration「管理／六项修复」；v1-completion「本轮已实现」恢复；remote-recovery-audit前四段；R2-A §4真实吊销未测 |
| 架构§4、A.7配对 | 最小PairConfirm为JCS {sas}而非ASCII；现代对象签完整DeviceRecord／exclude_global，加入只是候选；原期限／轮次／原信封重试；旧SAS与split新域 | W9「Cross-crate integration repairs」SAS；W0「Interpretations」第17项；owner integration「六项修复」；R2-B「协议／精确SAS输入」；R2-A §4与R2-C真机表 |
| 架构§5、§6.2/§6.5、A.1/A.7 | identity验签统一dk_sig或缺失时dk_pub，坏dk_sig拒绝；HPKE不改；AAD包含未知头、ct解码字节；记录完整JCS、Missing/null、嵌套扩展与旧向量 | R2-B「协议／向量与schema」；W0「Interpretations」第1–5/12–13项；W4「状态与验证位置」 |
| 架构§6.1/§6.3/§6.6 | 普通T1票不覆盖T2，显式设置T2另约束；内部授权保留原决定证明，不能伪造独立Grant签名；保守生产GET/HEAD/TOTP T1，其余use T2／T3拒绝 | W4「有意偏差」；W5「生产接线 → W4生产runner」；owner integration「审批和授权管理」；K4 |
| 架构§6.7/§6.8 | 相同完整绑定重试合并，不把不同操作合并当已实现；no_approver不冒充用户deny；显式T2授权仅按安全栏 | W4「有意偏差」；R2-D §D活session绑定；K4/D06，D04/D05缺口按代码核对 |
| 架构§6.9.1–§6.9.4、§9.4、A.8/E | cancelled／旧reason兼容、pending不等于拒绝、实际name/version预算；progress不声称续命；Claude/channels未测；Codex下界及配置实效、Devinrmcp保守；HTTP终态／有限响应边界 | R2-D §B、§C“原文→新文”、§D/§E；runtimes.md「Remote waiting」；W5「Agent可见行为／生产接线」 |
| 架构§6.10.2–§6.10.6 | 执行端决定signed push.mode，WS在线不判人在场；独立8788 push、metadata-only、重试／期限／CAS token与退出outbox；Android原生后台／同ID去重；iOS只编译；60s为刷新 | R2-C「路由设计／token与后台可靠性／simvito部署／Android真机表／Play与iOS」；W1「Contract decisions」refresh；R2-A §4本机投递未测 |
| 架构§7.2–§7.4 | 修正不存在token_revoke类型；设置短票Strong，自动推荐为V2；issued完整台账、signed使用快照、不伪造0、逐执行端回执／revocation_pending、未来T1／排除与分页 | owner integration「审批和授权管理／六项修复」；W7「Owner integration」；R2-C真机1小时Strong；K4/D03/D06 |
| 架构§7.5 | notify入操作表，Directive单目标／CLI通配展开，改名／新class Strong；共享本地后端CAS与拒绝过时提案；未知issuer不可授权 | W4「状态与验证位置」；owner integration「Owner IPC／审批和授权管理」；W7「Implementation」；W0「Interpretations」第8–10/19项 |
| 架构§7.6、A.4 | Strong准备120s令牌、有限一次／常设两轮标签；K4有限T2签名必须含confirm、global T2拒绝；明确接收S01/S02缺口，不用旧A.4覆盖K4 | owner integration「Owner IPC」及「仍需实机或后续契约处理」有限标签差异；K4/D04/D05；validation.rs:171/177/195与helper接收代码 |
| 架构§8.1–§8.5 | 当前官方也为SQLite，Postgres/多实例/计费为V2计划；14表／完整record；server/client状态目录分开；真实nginx/CF来源限制、push404；自建仅桌面，不再将100s写成CF保证 | W2「Implementation」；W9「Installer/deployment」；v1-completion「实机与部署」；R2-A §2现行hash／配置保留；R2-C「simvito部署」；K3 |
| 架构§9.2/§9.2.1 | 手机登录＋四页／固定地址不展示，手写C JSON ABI不是UniFFI；Android核心通过、iOS/发行未验；attestation只有适配器、V2验证，NSE性能未测 | W8「原生薄层与双绑定／Flutter页面／登录补充」；R2-C「Play与iOS／最终验证／资源清单」 |
| 架构§9.3、附录E | 实际CLI family/help/退出码／owner意图，recover隐藏输入与audit分页；unattended仅--until、无--standing；remote audit上限冲突登记T12 | W7「Implementation／JSON and exit／恢复与审计补齐」；v1-completion「命令示例」；R2-A §3；实际8个family help和args.rs核对 |
| 架构§10、附录D | 两种角色共用真实helper表，完整signed对象／usage／targets／outbox／audit；手机加密库界限；DDL逐字收录24/14表，dk_sig留完整record字段 | W4「改动文件／状态与验证位置」；owner integration「管理／六项修复」；W8「Rust核心与边界」；R2-B完整记录；两份schema.sql直接核对 |
| 架构§11 | audit --remote按完整签名摘要／固定头分页，缺口退出3；vault独立AEAD prepare/commit/发布；整体一致旧备份／窗口／手机同库锚点边界 | remote-recovery-audit全文；v1-completion「已验证的边界」；W7「恢复与跨端审计补齐」；R2-A §4真实对账未测 |
| 架构§12–§15 | broker威胁行、root仍不防，userPresence可系统密码；保留字段与key_kind实际形状、unsupported authority拒绝；失败先waiting检查、每wake5窗口；trait/HPKE/IPC/crate落点实际化 | linux-auth-relay-isolation「实现」；W1「Contract decisions」；W4「有意偏差」；W6「Contract decisions」；W0解释／向量；R2-B/D与各收口报告 |
| 架构§16、§17.3 | 合并四R2实测／数字／路径；功能与阈值分开、n=0不虚构统计／100%；M0/M1完成、M2–M5未完、不同快照CI不可横比 | R2-A §3–4/7；R2-B「Windows原生结果」；R2-C「Android真机表／最终验证」；R2-D §B/D/最终验证 |
| 架构§17.4、§18 | 两张“已决／仍开放”表；K1–K4、D01–11处置与V2范围；官方已上线而计费仍计划；新冲突不合理化 | K1–K4；owner/isolation/completion；四R2各“未决”节；OPEN分类 |
| 架构附录B | 25组合路由、Device/U认证分开、账户六端点／push-token／recovery、普通和账户错误体及no-store；metrics真实边界 | W2「Appendix B endpoint verification」；W8账户补充；R2-B统一identity；R2-C生命周期；http.rs/account.rs/error.rs |
| 架构附录C/C.1/C.2 | 完整29op及逐行五角色ACL、audit.list、owner intents、冷启动control、原始32Bchallenge、非消费通知与回执 | isolation「实现／验证记录」；owner integration「契约补充／六项修复」；v1-completion恢复；W1–W5「发现与修复」；kv-ipc/core IPC |
| 架构附录F | 当前crate非空骨架、生产自组合HPKE与dev参考；32JSON全清单与六K1新增；旧24字节不变与有意sample/IPC扩展分开，K4负向仍缺 | W0「Dependencies／Test vectors」；W9「Cross-crate repairs」；v1-completion新QR；R2-B「向量与schema」 |
| 产品开头／§1–§4 | 删“尚未实现”，改代码已实现／原生未完成；平台与用户按真实Android/Windows/Mac范围，登录／固定地址／桌面自建，用户故事不冒充验收 | 四R2开头／真机表；W8登录补充；K1–K3 |
| 产品§5 J-R1/J-R2 | 真实匿名／恢复码／QR／owner SAS流程与失败，UI预览和原生Strong／真实use区别；保守风险与vault解锁前提 | owner匿名配对；v1-completionQR；W6「Verification and screenshots」；W5「生产runner／未决边界」；R2-A §3–4、R2-C真机配对 |
| 产品J-R3/J-R3b、§6.1 | --until签票、设置一小时Strong；推荐V2；内部票证明、逐目标撤销回执、T2两阶段／常设两轮／无global T2，CLI不增加flag | owner管理／T2；R2-C设置三步；W7现有语法；K4 |
| 产品J-R4、§7运行时行 | pending/wait/Stop及真实托管范围，channels不承诺，HTTP活session有限恢复／终态禁重试，不保证全运行时自动续跑 | R2-D §B/C/D/E及未决；runtimes.md |
| 产品J-R5–J-R8 | 新设备继承／双端确认、吊销pending与一分钟未测、账户恢复不恢复vault、Android网络故障；卸载不假报自动远端吊销 | owner六项；remote-recovery-audit；R2-A §4；R2-C可靠性；W9「Installer and release behavior」、R2-B生命周期 |
| 产品§6/§6.2 | UI规则与登录四页、native/Rust后台，Android先于iOS；实际声音/35s与Mac在场未测分开；AppAttest/Integrity V2 | W6 UI九项用户核对；W8双绑定／Flutter页面／账户补充；R2-C真机表／Play/iOS |
| 产品§7–§8 | 每功能三状态“已实现／验收中／V2计划”，代码／阈值／发行分开；跨操作batch/quorum/attestation不再承诺V1 | K4；W0–W9后续处置；四R2未决 |
| 产品§9 | 不改变安全原则，有限/全局T2接收缺口公开；root/SYSTEM、TLS认证参数与E2E范围、userPresence与生物绑定、反回滚/HTTP边界 | R2-B协议；R2-C门控；R2-D §D；W1；remote-recovery-audit；K4及S01/S02 |
| 产品§10 | 桌面自建不包含手机；官方已部署但配额／价格未实现／未拍板，发行脚本不等于发行包 | K3；W2 plan metadata；W9／R2-A部署；R2-C Play/iOS |
| 产品§11–§13 | 真实指标未测／未过、后续资源优先级；FAQ手机为何登录、能否自建、运行时/Windows/PIN/恢复与发行范围 | 四R2验收／未决；account-login；remote-recovery-audit |
| OPEN全表 | 每条D/E/T更新：旧缺口的source closure与native pending分开；新增S01/S02/S03、T10/T11/T12，不以旧通过覆盖新失败 | K1–K4、owner/isolation/completion、四R2；本轮code核对 |
| review顶部表 | 仅合并R2数字与证据，保留W9原文；Android功能与预算、WindowsPIN、两个runtime及四份快照分开 | 四R2对应验收／最终检查表 |

## 发现的冲突与变更请求

| 项目 | 代码／历史事实 | 文档处置／负责人请求 |
| --- | --- | --- |
| S01有限T2 | [validation.rs](../../rust/crates/kv-core/src/remote/validation.rs):195只在exp=null核对confirm；helper install_grant／使用重验共用它。owner报告已指出旧接收规则，K4要求收紧 | 架构§7.6/A.4保留K4规范并标实现缺口，OPEN“需要决定／落实”列S01。协议负责人补拒绝／负向向量与旧票迁移；R2-E不改验证器 |
| S02全局T2 | 同文件:171/177允许*与global，未独立拒max_tier=T2；desktop/mobile发行拒绝与CLI展开不能代替接收检查 | 按K4继续拒绝的规范回写，接收侧未满足；协议/helper负责人补接收与重验拒绝，不合理化成支持未来global T2 |
| S03metrics | [http.rs](../../rust/crates/kv-server/src/http.rs):85/110与metrics函数：普通Device会话认证，无独立peer-loopback检查；nginx通用转发，私有片段只屏蔽push | 删除“代码已限制loopback”假事实；需要确定监控访问边界并落实。仅绑定127.0.0.1不是经nginx限源证明 |
| T12审计页上限 | [CLI args.rs](../../rust/crates/kv-cli/src/remote/args.rs):759/769接受1..1000；QueryAudit/helper页限200 | 记录CLI/help待收紧；当前>200拒绝，不提高helper上限迁就文案 |
| PairConfirm历史差异 | W6早期ASCII、W9最小JCS {sas}、owner后续完整device/exclude_global | 保留最小形状解释，同时明确现代全对象签名；不能删现代字段来字面签{sas}，否则放宽已实现绑定 |
| 报告时间点差异 | R2-A末尾仍写第二轮等密码；最新[第二轮证据](assets/r2a-pair-native.json)为ipc_unavailable/4.161s。R2-C旧登录／退出通过后又出现HTTPS失败 | 原报告不改；汇总只使用已记录首次失败、use=0与当前未过范围。第二轮准确根因和报告补充归R2-A，不编造Strong成功 |

以上为read-only核对，不运行危险请求或用软件fallback补“通过”。安全冲突不是重新请求降低档位的许可。

## 仍开放事项

- S01/S02落实K4接收验证；S03监控边界；T12CLI审计上限；T10Devin专用MCP文件／短timeout环境同步；T11Windows无绑定worker。
- R2-A完整MacStrong配对、真实凭证use／20次延迟、拒绝／续等／改参、控制面、锁屏、双向吊销／audit、两小时合盖；一周／两周未开始。
- R2-B Hello **等待PIN**，物理TPM／ARM64／完整TaskDialog与生产签名仍缺。
- R2-C恢复手机relay HTTPS，复验重启／退出远端删除、≤30s横幅／各<5s设置、一小时离线；iOS/APNs/Apple/匹配profiles、IPA/TestFlight与Play签名AAB待资源。
- R2-D有效Claude交互／第三家，channels三项、未测timeout/Stop/IDE；当前只有Codex与Devin。
- 硬件反回滚／手机库外锚点、原生presence与覆盖率、账户删除／解绑／跨provider链接／Apple生命周期；跨gateway重启响应契约为后续计划。

## 随机抽查10条实现声明

用Python random.Random(20261013).sample从22条当前实现声明抽10条；先确认引文存在于改后文档，再逐项找报告依据。范围限定和未验边界保留，不把软件签名结果扩大为真机完成。下面为抽中的原句／句中完整声明：

| # | 章节 | 抽查声明 | 对应报告与具体节 |
| --- | --- | --- | --- |
| 1 | 产品 §9 | 跳过AndroidCryptoObject不能签AK_s，实机负向门控已通过。 | [R2-C-mobile](R2-C-mobile.md)：Android 真机表，2/2 0 skipped |
| 2 | 架构 §6.10.3 | Quick 仅对 per_use Quick 开放允许／拒绝，动作要求系统解锁，FGS 用 AK_q 签； | [R2-C-mobile](R2-C-mobile.md)：token 与后台可靠性；Android 真机表 |
| 3 | 架构 C.1 | T2 准备令牌最长 120 秒，只保存哈希，绑定调用方 UID／PID／角色、完整意图和当前设备记录，失败的最终尝试也消费令牌。 | [owner-integration-23](owner-integration-23.md)：实现结果 → Owner IPC 和认证边界 |
| 4 | 产品 §3 | 手机固定官方 relay，地址不展示、不可编辑。 | [W8](W8.md)：Google／Apple 登录与固定地址补充 → 改动文件与接口 |
| 5 | 架构 §11 | 手机链头在同一加密库内，只查篡改／缺行，缺少库外锚点； | [v1-completion](v1-completion.md)：本轮已实现／已验证的边界；remote-recovery-audit末两段 |
| 6 | 架构 §6.9.2 | 每条请求 ≤1 MiB，最多 16 个 ticket，detached response ≤8 MiB； | [R2-D-runtimes](R2-D-runtimes.md)：D：T08 的本地错误与恢复 |
| 7 | 架构 §6.2 | K1 没有改变 RFC 9180 suite、原 ECDH 字节或旧向量。 | [R2-B-windows](R2-B-windows.md)：向量与 schema，24 个旧向量逐字节核对 |
| 8 | 产品 §6.2 | 原生后台由FCM→JobScheduler→Rust处理推送，不启动Dart isolate。 | [R2-C-mobile](R2-C-mobile.md)：token 与后台可靠性；系统结束进程后的真实审批唤起 |
| 9 | 架构 §7.4 | 离线、取消或未获回执时保留 revocation_pending；重试继续未完成目标，过期 Directive 需 owner 重签，不在后台绕过硬件授权。 | [owner-integration-23](owner-integration-23.md)：实现结果 → 审批和授权管理；仍需实机或后续契约处理 |
| 10 | 架构 §6.10.3 | APNs 410／FCM UNREGISTERED 比较发送时旧 token 后删除，不能删并发轮换的新 token；权限／配置错误保留 token。 | [R2-C-mobile](R2-C-mobile.md)：token 与后台可靠性 |

10/10有对应报告证据。抽查不代表未经测量的“所有源码覆盖率100%”，也不关闭S01/S02。

## 检查与复现

检查只读源码、Markdown和临时内存SQLite；CLI仅--help，无vault／网络操作。本轮文档修改不重新把Rust测试算作R2-E新验收，四项CI事实逐份引用A/B/C/D的冻结快照。

| 检查 | 结果 |
| --- | --- |
| 全部修改文档表格 | 通过；52张、612行，管道数／header delimiter逐表一致，含review历史表 |
| §／附录交叉引用 | 通过；架构／产品154条数字引用、37条附录引用，内部与总架构分别核对 |
| 相对链接／证据文件 | 通过；5份文档117个相对链接全部存在 |
| B路由 | 25/25方法路径，无缺／多 |
| C op／五角色ACL | 29/29；relay9、hook2、MCP4、owner15、agent7；逐项一致 |
| D DDL | 两代码块逐字等于源码；内存SQLite建表helper24/server14 |
| F向量 | 32/32 JSON文件名；6个K1新向量，无缺／多 |
| 旧网络替代词 | 全glob仅否定句及否定验收命令，没有引入替代部署 |
| 随机声明 | 10/10报告依据 |
| 文件边界 | 通过；范围外468份源码／脚本／文档聚合散列前后相同；review表后原文散列相同，替换只限该表 |

下面脚本在仓库根目录运行，报告之外不生成文件。cross-reference对架构／产品的正文数字与附录核对，跳过code fences，明确总架构引用核对architecture-2026-10.md：

```python
from pathlib import Path
import re
import sqlite3

arch = Path("docs/remote-approval-architecture-2026-10.zh-CN.md")
product = Path("docs/remote-approval-product-2026-10.zh-CN.md")
files = [
    arch, product,
    Path("docs/remote-approval-reports/OPEN-QUESTIONS.md"),
    Path("docs/review-2026-10.zh-CN.md"),
    Path("docs/remote-approval-reports/R2-E-docs.md"),
]
tables = rows = 0
for path in files:
    fenced = False
    block = []
    def check_table():
        global tables, rows
        if not block:
            return
        expected = len(re.findall(r"(?<!\\)\|", block[0][1]))
        assert len(block) >= 2
        assert re.fullmatch(r"\s*\|(?:\s*:?-{3,}:?\s*\|)+\s*", block[1][1])
        for line_no, text in block:
            assert len(re.findall(r"(?<!\\)\|", text)) == expected, (path, line_no)
        tables += 1
        rows += len(block)
    for line_no, line in enumerate(path.read_text().splitlines(), 1):
        if re.match(r"^\s*(```|~~~)", line):
            check_table()
            block = []
            fenced = not fenced
        elif not fenced and line.lstrip().startswith("|"):
            block.append((line_no, line))
        else:
            check_table()
            block = []
    check_table()
assert tables > 0
print("tables", tables, "rows", rows)

base = Path("docs/architecture-2026-10.md")
def sections(path):
    return set(re.findall(r"^#{1,6}\s+(\d+(?:\.\d+)*)(?=[.\s])", path.read_text(), re.M))
index = {p: sections(p) for p in (arch, product, base)}
numeric = appendices = 0
for path in (arch, product):
    fenced = False
    for line_no, line in enumerate(path.read_text().splitlines(), 1):
        if re.match(r"^\s*(```|~~~)", line):
            fenced = not fenced
            continue
        if fenced:
            continue
        for match in re.finditer(r"§\s*(\d+(?:\.\d+)*)", line):
            target = path
            before = line[:match.start()]
            if "总架构" in line or "architecture-2026-10.md]" in line:
                target = base
            elif path == product and "架构" in line:
                target = arch
            elif path == arch and "产品文档" in before and before.rfind("产品文档") > before.rfind("§"):
                target = product
            assert match.group(1) in index[target], (path, line_no, match.group(1))
            numeric += 1
        for match in re.finditer(r"(?:附录\s*|(?<![a-zA-Z]))([A-F])(?:\.(\d+))?", line):
            if match.group(2) is None and not match.group(0).startswith("附录"):
                continue
            key = match.group(1) + (("." + match.group(2)) if match.group(2) else "")
            assert re.search(r"^#{1,6}\s+(?:附录\s*)?" + re.escape(key) + r"(?=[.\s])", arch.read_text(), re.M)
            appendices += 1
print("section_refs", numeric, "appendix_refs", appendices)

body = arch.read_text()
ddl = body.split("## 附录 D. ", 1)[1].split("## 附录 E. ", 1)[0]
blocks = re.findall(r"```sql\n(.*?)\n```", ddl, re.S)
assert len(blocks) == 2
for source, expected, sql in zip(
    ("rust/crates/kv-helper/src/remote/schema.sql", "rust/crates/kv-server/src/schema.sql"),
    (24, 14), blocks
):
    assert sql == Path(source).read_text().rstrip()
    conn = sqlite3.connect(":memory:")
    conn.executescript(sql)
    count = conn.execute("SELECT count(*) FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'").fetchone()[0]
    assert count == expected
    conn.close()
print("DDL verbatim and executable", len(blocks))
```

附录B/C的自动核对另读取http.rs中.route方法及kv-ipc中operations!/五个 *_OPS数组，和文档行逐项比集合／角色；附录F比实际glob文件清单。没有忽略不匹配行或用空集合过门禁。

网络替代词检查按任务原命令：

```sh
grep -n 'Tailscale\|Caddy' docs/remote-approval-*.md
```

结果为架构“不用”、第一／第二轮prompts“不要／不引入”及该负向检查命令；prompts在本轮范围外，未修改。


边界复核聚合SHA256为a3ba371a1d450077293b757bd4045e68d9e35087ca8f1af27d0ea38bfc7a4424；review表后原文为afbb40883b3de7eae14938eb4a8a132ea5365e7963affbdbf5a5ba4ffcd36007，前后均一致。散列口径为rg列出的范围外Rust/SQL/TOML/lock/脚本/Markdown/Dart/Kotlin/Swift文件，未把忽略的构建缓存／二进制算作源码。
