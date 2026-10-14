# SE 子进程错误保真的一文件例外

尚未应用此文件变更。上一轮明确授权的六个文件未包含 `rust/crates/kv-touchid/src/agent.rs`；原 R3-A 所有权只包含此 crate 的 `src/remote*`。

已安装原生用例中，用户先允许普通 KeyValet 确认，再取消系统 Touch ID；CLI 8.531664 秒后仍为 key_operation_failed。源码定位：device_key::exit_code 丢弃细分，agent.rs::handle_request 的 device_key 分支再把所有非零退出转换为通用失败。前一处属于已授权 device_key.rs，本次请求只增加后一处的一文件例外。

[完整可审补丁](r3a-se-child-hop-proposed.patch) 含 fake runner 回归与最小结果映射。授权后先只添加测试，旧桥运行失败再修。测试不读取安装目录、没有 sudo 或 GUI。子进程保留两个专用固定退出码；agent 仅对既有真实 runner 验证过的 binary、正常退出、输出长度为 0、未超时的结果保留取消/认证失败。未知码、非空失败输出、崩溃和超时仍拒绝，无签名 payload。

不捕获/解析本地化 stderr，不修改 private channel、audit-token requirement、身份/角色、档位、nonce/exp、ptrace/能力、SE ACL、LA policy 或签名操作。Strong 仍须实际 userPresence；此改动不能生成任何权限。已有 Deny/Esc 成功不再重复。CryptoKit 本身若不提供明确分类，仍记通用失败，真机必须再次核对才算 producer 通过。
