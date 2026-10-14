# R2-B — Windows K1 双 PCP 键与原生验收

2026-10-12。直接修改 main 工作树；未执行改变 git 状态的命令，未新增依赖。用户追加授权了 IPC trait、DeviceRecord 构造器、server 身份验证接线、Windows Quick 选择、必要协议/验收测试、跨工作流纯格式与指定 Clippy 兼容修正。

## 协议

现有 wire 字段 `dk_pub` 表示 HPKE P-256 ECDH 公钥；新增可选 `dk_sig: {pub: JWK(P-256), alg: "ES256", ...扩展}`。
Rust 使用 `Optional<ApprovalKey>`：Missing 不序列化；null 保留其 JSON 形状，但注册和身份验证拒绝它。
`verify_identity_signature(&DeviceRecord, payload, signature)` 统一选择：合法 dk_sig 存在时只用其 pub；缺失时用原 dk_pub。算法错误、RSA/其他曲线、私钥字段、null、无效点与无效签名均失败，不跳过验签，不从坏 dk_sig 回退。

规则覆盖 challenge、账户登录 DK 证明、配对外层信封、recovery、普通信封，以及 helper/control transport 对 remote.sign_identity 结果的核对。HPKE 仍只用 dk_pub；批准仍只用对应 AK 与其 alg。
所有覆盖完整 DeviceRecord 的 JCS 签名、摘要与 authority 比较包含 dk_sig 和嵌套未知字段。旧记录 SAS 字节保持；split identity 的 SAS 使用新域 keyvalet-pair-v1-split-identity，排序双方 JCS({dk_pub, dk_sig}) 后绑定 token 和审批端 AK 公钥；无 dk_sig 的一方在此新形状中编码 null。它同时绑定 ECDH 与身份签名公钥及其扩展；完整记录还受 PairStart/PairAccept 外层签名与 authority 比较保护。RFC 9180 suite、raw ECDH 字节序与旧密码学向量保持。

IPC 与 typed core trait 新增 `identity_sign_jwk() -> Result<Option<...>>`，默认 None，blanket adapter 传递结果。Windows DK 返回独立 ECDSA 公钥；public_jwk 返回 ECDH 公钥；sign/ecdh 分别使用专用 PCP 句柄。verify_identity_provider 核对两把公钥。
PCP metadata version 2：key_name/public_jwk 为 ECDH；signing_key_name/identity_sign_jwk 为 ECDSA；Quick 是另外的 ECDSA 对象。重开核对命名空间、公钥和 P-256 blob 类型；SYSTEM/Administrators DACL 保留。创建守卫清理半套键；删除尝试两把，使用 NCryptDeleteKey(handle, 0)。旧的不成功 PCP v1 metadata 拒绝静默迁移；DPAPI 显式软件 provider 与 Hello RS256 各自契约保留。

## 向量与 schema

| 新向量 | 期望 |
| --- | --- |
| device_record_with_dk_sig_valid.json | JCS、SHA256、完整记录签名、未知字段 roundtrip 成功 |
| device_record_with_dk_sig_wrong_dk.json | dk_sig 验成功；dk_pub 验同一签名必为 invalid_signature |
| device_record_with_dk_sig_tampered.json | dk_sig 嵌套扩展篡改后完整记录签名失败 |
| device_record_with_dk_sig_legacy.json | 无 dk_sig 旧记录继续用 dk_pub；缺失字段保持缺失 |
| device_record_with_dk_sig_envelope.json | 新身份签名与旧 HPKE 接收键互操作；错误 DK 验签失败 |
| device_record_with_dk_sig_pair_sas.json | split SAS 为 503216；换签名公钥/扩展改变 SAS，旧 SAS 保持 |

六个文件均含 expect，由 generate.py 的独立 Python cryptography 生成。core keys 新增 6 个测试入口，与 pairing 的共享 SAS 用例一起覆盖这些向量及 null/RS256/RSA/私钥字段拒绝、provider 两键 pin、恢复证明。server 新增 3 个真实 HTTP 测试，覆盖注册持久化、新旧 challenge、配对 authority、信封、恢复轮换与篡改。
10 个 DeviceRecord schema 同步为可选非 null ES256/P-256 字段；additionalProperties 保持。DeviceRecord 与注册 JSON 样例包含 Windows 双 DK、Quick ES256、Strong RS256。
具体为 device_record、register_device_request、pair_offer、pair_accept、relay_pair_start_request、relay_pair_complete_request、relay_pair_complete_response、devices_list_result、ws_frame、recover_account_request.schema.json。与动手前副本逐字节比较，24 个既有 JSON 向量保持，包括 RFC 9180、旧 SAS、ES256/RS256 与 HPKE；schema_samples 为本轮有意更新，ipc_contracts 是 R2-A 的并行扩展。

## Windows 原生结果

Windows 11 Pro x64 VM、模拟 TPM 2.0、guang\win；Rust 1.99.0 / x86_64-pc-windows-msvc / PowerShell 7.6.6。
两端使用同一份 649 文件的冻结源码快照，指纹 `df4d03aed184a45ba76b546049ab73fa04639f562287a155bb0155fae2d75aaf`；最终报告与证据在测试后写入，文档后续变化不属于该快照。
其他工作流随后继续修改 CLI/Cargo 与 server/push 文件；这些后续变更不在本次 CI 快照中。本工作流的协议、PCP、验收测试与安装脚本在快照之后未再变化。
Mac 使用 Rust 1.99.0、`CARGO_TARGET_DIR=/Users/guang/dev/keyvalet/rust/target-r2b`；Windows 使用独立 `C:\kv-r2b-20261012\target`。两端关闭调试符号/增量编译，仅控制编译产物大小。普通 CI 未调用安装服务或原生 ignored 测试。

| rust/ 中的命令 | Mac | Windows/MSVC 原生 |
| --- | --- | --- |
| cargo fmt --all -- --check | 通过 | 通过 |
| cargo clippy --workspace --all-targets -- -D warnings | 通过 | 通过 |
| cargo build --workspace --locked | 通过 | 通过 |
| cargo test --workspace --locked | 1323 passed，0 failed，10 ignored | 1079 passed，0 failed，25 ignored |

计数汇总各测试程序与 doctest；Mac 命令显式使用 `cargo +1.99.0`。结果与全部输出见 [Mac checks](assets/r2b-mac-checks.json)、[Windows checks](assets/r2b-windows-checks.json)、[Mac test](assets/r2b-mac-test.log)、[Windows test](assets/r2b-windows-test.stdout.log)；完整快照清单见 [manifest](assets/r2b-tested-source-manifest.json)。

| 检查 | 结果 |
| --- | --- |
| SYSTEM PCP ECDH + 独立 ECDSA 创建、持久化重开 | 通过 |
| 身份 ES256 64 字节；错误 DK 验签失败 | 通过 |
| raw ECDH 32 字节，与软件执行端共享点一致 | 通过 |
| 软件执行端 → Windows HPKE → PCP Quick → 软件端按 alg 验签 | 通过；最终已安装包测得 62.5863 ms，不含 UI 点击与公网传输 |
| 两把键清理，清理后重开拒绝 | 通过 |
| 第二把创建失败时回收第一把，无软件 fallback | 通过；真实第一把 PCP 键加注入的第二把失败 |
| 实际安装、升级、卸载 | 11 项通过；包含普通 owner、跨账户与坏 ACL/属主拒绝 |
| 已安装 CLI 双键状态 | 创建期间 pcp_ecdh=present、pcp_ecdsa=present；清理后为空 |
| Hello IsSupportedAsync | false；session 1、非提升 owner token，2026-10-12T14:46:33Z |
| Hello AK_s 创建、Strong、取消、重复提示 | **等待 PIN**；用户确认尚未设置，未执行 |
| Windows Hello Strong → fixture RS256 | **等待 PIN**；软件 RS256 向量结果单独验证 |

最终 unsigned development v0.3.0 ZIP SHA256：`755ab56a79a4246ccd27ce541e9dc35a382a41573b195028d83e2acf04c145f0`。11 项生命周期回归在本轮开发包完成；最终冻结快照另行打包、同 owner 实际升级，再用其 native test 二进制复验三项 SYSTEM 测试。包不是生产签名发布产物。
当前 helper 为 LocalSystem/Auto/Running，未配对 relay 为独立虚拟账户/Manual/Stopped。没有创建 master.key、vault.enc 或 Hello 替代软件键；PCP 测试键与计划任务已清理，已安装库存两项为 absent。

证据：[SYSTEM 原生测试及二进制哈希](assets/r2b-system-native.json)、[HPKE/Quick/延迟](assets/r2b-native-keys.json)、[11 项安装回归](assets/r2b-windows-service-test.json)、[Hello 分项结果](assets/r2b-hello-availability.json)、[双键存在时 summary](assets/r2b-installed-summary.txt)、[清理后 status](assets/r2b-installed-status.json)、[服务](assets/r2b-installed-services.json)、[包哈希](assets/r2b-package-hash.json)、[已安装二进制哈希](assets/r2b-installed-binary-hashes.json)、[清理](assets/r2b-final-cleanup.json)。原始日志与源码在 `C:\kv-r2b-20261012`；本机工具产物在 `rust/target-r2b`。

## 改动文件

- core：src/remote/{types,keys,mod,envelope,relay,pairing}.rs；10 个包含 DeviceRecord 的 schema；testdata/remote/generate.py、schema_samples.json 与上述 6 个新向量。
- platform：src/device_key/windows.rs、src/protection.rs。新增 remote_identity.{pcp_ecdh,pcp_ecdsa,ready,evidence}；summary 区分两半存在/缺失/未知，依据实际 ECC public blob 类型。
- agent：src/remote/windows.rs、src/remote/pcp_acceptance.rs，opt-in 原生验收；src/remote/tests.rs:1325、tests/support/w0_flows.rs:173，样例改为 RS256 后按记录的 alg 验证/选择 fixture signer。
- server：src/{auth,account,messages,state}.rs 中身份验签/公钥验证；src/tests.rs 构造器与模块；src/tests/k1.rs。
- IPC：src/remote.rs 的默认 identity_sign_jwk。
- helper：src/remote/{pairing,relay_control,bootstrap,platform_keys,engine}.rs 最小 K1 接线；src/remote/tests.rs 构造器。
- relay-client：src/control_transport.rs 最小验签；src/tests/{control,recovery,interfaces}.rs 构造器。
- mobile-core：src/engine.rs、src/tests.rs、src/tests/helper_pairing.rs 只补 Missing。
- mobile-core examples/r2c_phone_fixture.rs:1,627,633：必要原生编译兼容；Unix 软件文件 fixture 加 cfg(unix)，非 Unix 明确退出，未在 Windows 引入宽松软件文件路径。
- CLI：src/remote/live_helper_tests.rs 只补 Missing。
- server/src/push_tests.rs：共享 fixture 补 Missing；已有锁断言放入局部作用域，消除 stable Clippy await_holding_lock，断言保持。
- helper src/remote/tests/production.rs:419：真实 gateway 集成 fixture 改用系统时间，避免固定向量时间被新增绝对到期检查拒绝；签名、原始 HTTP body 与单次执行断言保持。src/main.rs:1916：保护探针断言检查 result.ready 缺失，允许新公开库存 remote_identity.ready；秘密字段拒绝、未解锁和文件不变断言保持。
- 用户授权的纯格式整理：kv-cli/src/remote.rs、src/remote/review_tests.rs（后者为冻结快照后新增的 QR 用例）；kv-mcp 的 examples/approval_fixture.rs、src/{fake_helper,approval,approval_tests,session}.rs；kv-proxy 的 examples/sdk_fixture.rs、src/{gateway,approval,gateway/recovery}.rs、tests/{approval,recovery}.rs。kv-mcp/session.rs 的恒等 map_or_else 分支由其并行工作流改为 unwrap_or_else；本工作流确认 Clippy 通过，未重复改动其逻辑。
- scripts/test-windows-remote-keys.ps1；scripts/install.ps1 无公共绑定时保持 Windows relay Manual/Stopped。
- docs/windows.md、docs/windows-native-acceptance-2026-10-12.zh-CN.md、本报告；证据 assets/r2b-*。

## 跨归属最小替换与追加授权

| 文件/行号 | 修改 |
| --- | --- |
| helper remote/pairing.rs:238 | PairAccept 外层签名改统一入口 |
| helper remote/relay_control.rs:175 | 身份签名核对改统一入口；:399 补 Missing |
| relay-client control_transport.rs:338 | challenge 提交前用完整记录核对签名 |
| mobile 对端验证 | 原调用 shared envelope::open 已在 core 转统一入口，无重复逻辑修改 |
| mobile engine.rs:120、tests.rs:86、tests/helper_pairing.rs:272 | 各补 1 行 Missing |
| relay-client tests/control.rs:48、tests/recovery.rs:15、tests/interfaces.rs:240,258 | 只补 Missing |
| helper bootstrap.rs:369、engine.rs:266,1768、platform_keys.rs:80,93 | 追加授权：record 填真实 signing JWK；核对两键；PCP 创建/读取 Identity 与 Quick |

行号以本轮测试源码为准。IPC src/remote.rs:50 为默认方法；server src/state.rs:345、auth.rs:112,253、account.rs:449、messages.rs:46 为用户追加授权的身份验证接线。清单仅描述本工作流贡献；工作树同时存在 R2-A/R2-C/R2-D 改动，device_sas 的共享接线由相应工作流保留，本轮补验证与独立向量。

## 给 R2-E 的架构回写文字

§3.1 Windows DK 单元格与补充说明建议：

> Windows 11 的逻辑身份密钥 DK 由两把独立 PCP TPM P-256 持久键组成：ECDH 专用键用于 HPKE 解封，公钥为 DeviceRecord.dk_pub；ECDSA 专用键用于全部设备身份签名，公钥和算法为可选 DeviceRecord.dk_sig = {pub, alg: ES256}。AK_q 是另外一把 PCP ECDSA P-256，AK_s 仍为 owner 桌面会话中的 Hello RSA-2048/RS256。各角色互不替代；PCP 不提供用户在场门。任一键创建、读取或自检失败均报错，不自动转软件。DeviceKeyProvider.identity_sign_jwk 默认 None，Windows DK 返回专用 ECDSA 公钥；public_jwk 返回 HPKE ECDH 公钥。

§3.2：Windows DK metadata 同时 pin ECDH/ECDSA 两个持久化句柄名和公钥，随 helper/vault 的 AEAD 认证元数据存放。

附录 A.7 建议精确对象形状与规则：

> DeviceRecord = {device_id, label, os, key_kind, dk_pub: JWK(P-256), dk_sig?: {pub: JWK(P-256), alg: ES256, ...扩展}, ak_q: {pub, alg} | null, ak_s: {pub, alg} | null, caps, attestation, ...扩展}。dk_sig 缺失时保留原 DK 同时承担 ES256 验签与 ECDH 的规则；存在时全部设备身份签名仅用 dk_sig.pub 验证，HPKE 仍仅用 dk_pub。dk_sig 不接受 null、RSA、其他曲线或其他算法，无效值失败关闭，不回退旧 DK。dk_sig 及嵌套未知字段必须保留并参与包含 DeviceRecord 的 JCS 签名与摘要。

§4/§5/§8.2/附录 B 的“DK 签名”统一引用上述身份验签规则；审批 alg 与 HPKE suite 保持。附录 A.7 的 split SAS 明确新域与双方 {dk_pub,dk_sig} JCS 排序；旧记录保持原域。附录 F 加入上述 6 个向量。本工作流未直接修改架构文档。

附录 A.7 的 split SAS 输入精确定义：任一方有 dk_sig 时，`ASCII("keyvalet-pair-v1-split-identity") || raw_token_16 || sorted_jcs_identity_1 || sorted_jcs_identity_2 || JCS(approver.ak_q.pub 或 null) || JCS(approver.ak_s.pub)`；每个 identity 是 `{dk_pub, dk_sig}`，缺失 dk_sig 编码 null，以 JCS 字节排序两方。SHA256 结果作为无符号大端整数转十进制，左补零至至少六位并取前六位。双方均缺失 dk_sig 时保留原 `keyvalet-pair-v1` 输入。审批角色选择沿用 device_sas：joiner 有 AK_s 时选择 joiner，否则选择 initiator；没有 Strong 审批者则拒绝。

## 未决项

1. **等待 PIN**：Hello 创建、Strong、取消、重复提示及 Strong 跨平台 fixture。PIN 配置后在 owner 桌面交互执行。
2. 未配对 Windows relay 维持第一轮原生验收的 Manual/Stopped。共享自动启动控制 worker 在无公共配置时因受保护目录读取失败退出；R2-A 需接入 owner 配置 relay URL 后的启动步骤或提供 Windows 无绑定启动适配。本轮没有放宽目录 ACL、publisher 校验或忽略配置错误。
3. 此 VM 的模拟 TPM 原生结果不替代物理 TPM、ARM64 与完整 TaskDialog 点击矩阵。
4. 安装回归已删除临时账户与任务；Windows 仍缓存一个已删除测试账户的 loaded profile，需在客体下次重启后清理。具体 SID/路径保存在 r2b-windows-service-test.json；未为清理缓存重启 owner 桌面。
