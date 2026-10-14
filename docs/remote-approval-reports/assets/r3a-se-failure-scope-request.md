# SE 错误类型保真：待授权的最小例外

此补丁只保存在 assets，尚未应用；未修改 R3-A 所有权外文件。它不更改 ACL、密钥、LA policy、SE 签名、角色、audit-token、验签顺序或 nonce/exp。

当前损失发生在 NativeBridge 将所有非零状态转换为 OperationFailed、AgentTransport 将所有失败头转为 OperationFailed、核心 provider_error 同样只保留通用失败。Swift 还把 NSError domain 丢掉，只返回 code。

提案：仅当真实 NSError/underlying NSError 的 domain/code 明确是取消或认证失败，返回独立固定标签；最多遍历 8 层，未知 domain/code 仍是 OperationFailed。标签经现有可信私有通道和现有错误枚举传递；不存在成功签名时仍不得产生决定/Grant。真实框里的“不识别”提示不等于最终系统认证失败，不能从英文文本或用户点击记录推断系统类型。

需最小例外的文件：

- rust/crates/kv-ipc/src/remote.rs
- rust/crates/kv-core/src/remote/error.rs
- rust/crates/kv-core/src/remote/keys.rs
- rust/crates/kv-platform/src/device_key/agent.rs
- rust/crates/kv-touchid/src/device_key.rs
- rust/crates/kv-touchid/src/enclave.swift

批准后仍先添加无需安装/GUI 的失败回归（原生 fake FFI、fake agent、核心 provider），再应用修复、完整四项 CI、签名安装和真实取消复验。此提案尚未编译，不声称已完成修复；CryptoKit 只给通用错误时仍不能制造取消原因。
