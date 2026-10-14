# 账户恢复与跨端审计

全部设备丢失时，匿名 relay 账户通过 `POST /v1/recovery` 恢复，不需要旧设备会话。需要离线保存的账户 ID、恢复码和新设备持久保存的身份密钥 DK。账户恢复码与 vault 恢复长口令是独立凭据：此接口恢复 relay 账户归属，不恢复丢失的 vault 密文、凭证或硬件私钥。有人类登录要求的手机仍须走既有账户登录流程。

CLI 首次显示恢复码时也显示对应账户 ID，提醒一并离线保存；JSON 的 `pair_recovery` 结果包含 `account_id`。

```sh
keyvalet relay recover <account-id> --public-url https://relay.keyvalet.dev
# Only for an explicitly selected software identity on unsupported hardware:
keyvalet relay recover <account-id> --software --json
```

终端从隐藏输入读取旧恢复码，非交互用标准输入；没有 `--recovery-code` 参数，避免进入进程列表和 shell 历史。helper 先把新恢复码与目标账户、relay 和设备 ID 写入 vault AEAD 准备状态，再让 relay-client 发送请求。注册失败不重建身份密钥；相同设备重试保留相同新码。服务端已提交但响应丢失时，新 DK 认证成功且账户匹配后恢复同一新码并完成公开 binding 更新。输出成功才提醒离线保存新码。另一已有账户的身份拒绝直接覆写；硬件失败不隐式改用软件。正常成功退出 0，输入错误 2，网络不可达 5，用户取消 6；JSON 成功类型为 `relay_recovered`。

请求为 `{ account_id, recovery_code, new_recovery_code, device, nonce, sig }`。两项恢复码及 nonce 都是 32 随机字节的无填充 base64url；DK 用 ES256 签署 JCS `{ action: "recover_account", account_id, device, nonce, new_recovery_code_hash }`，最后一项为新码字符串的 SHA-256 hex。新码由调用端提前生成和保存，避免成功响应丢失时一起丢掉恢复凭据。

```rust,ignore
let request = RecoverAccountRequest::signed(account_id, old_code, new_device, dk)?;
// 发送前，把 request.new_recovery_code 保存到离线安全位置。
let restored = relay.recover_account(&request).await?;
// 使用新 DK 进行普通 challenge/verify，核对返回账户。
```

服务端限流、验签及 Argon2id 验证后，提交时再次比较账户原 hash，保证不同并发恢复只有一个成功。同一事务撤销旧设备及设备／人类登录会话、清除 push token、取消待处理审批、废止配对 token、删除旧消息，再登记新设备和轮换恢复码。失败保留旧码及原状态。仅保存恢复码 hash，HTTP 响应禁用缓存，秘密不进入日志。relay 恢复不能擦除丢失机器上的离线状态，旧本地授权仍依赖既有到期／吊销机制。

`keyvalet audit --remote` 读取本机审计，并用签名 `query_audit` Directive 查询已配对的桌面 helper 和手机。按审批 ID、Grant JTI、Directive ID 和两端设备关联记录，比较决定、digest、级别、操作和完整签名对象的 JCS 摘要。报告区分缺失签发／接收记录、重复记录、字段差异以及离线、吊销、历史不完整等查询缺口。

```sh
keyvalet audit --remote
keyvalet audit --remote --since 24h --json
keyvalet audit --remote --device srv --limit 100
```

默认核对完整目录；`--device` 限定已查询设备之间的关系。`--since` 支持相对时长或 RFC3339，省略时检查全部留存历史。`--limit` 是每页 1–200 条，CLI 自动拉完后续页；每端最多 100,000 条，超出报不完整。页正文最多约 48 KiB，只返回元数据。首个页面冻结 `through` 序号及 hash；查询期间新增记录留到下次。跨设备没有共同原子快照，时钟偏差、在途消息或已到期请求也可能表现为缺失。全部查询完整且无差异时退出 0；有差异／缺口时输出报告并退出 3，JSON `ok` 为 false。

桌面审计使用独立 vault AEAD 检查点：同步审计收据及准备检查点 → 提交 SQLite → 发布已提交检查点。中断后按 SQLite chain head 完成发布或丢弃准备状态。启动和查询检查全链、已提交检查点及 vault 留存收据；链篡改、单独恢复旧 SQLite、删除已提交尾部或留存范围内的收据都会拒绝。失败事务留下的独立收据不会成为已接受授权。已轮转掉的旧日志无法重新构造，SQLite 历史仍受最新链头约束。

这不提供硬件反回滚：SQLite、加密 metadata 和日志一起恢复到同一旧备份仍可通过；提交后、检查点最终发布前的恢复窗口也不能区分真实回滚与未提交事务。手机链头在同一加密数据库内，能检查篡改和缺行，没有库外回滚锚点。旧版手机升级前被 UI 历史轮转删除的记录无法补回；查询窗口涵盖升级前历史时标记 `history_complete: false`。完整反回滚仍需硬件单调计数器或外部可信见证。

回归测试使用临时目录、软件测试密钥和内存 relay，覆盖无会话恢复、失败原子回滚、并发单次消费、SDK 及会话缓存清除、跨端匹配／缺失／差异／离线、固定分页、手机验签与重放、检查点中断、SQLite 尾部回滚及收据缺失，不依赖已安装 KeyValet、root 或 GUI。
