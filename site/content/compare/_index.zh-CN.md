+++
title = "对比"
description = "KeyValet 与其他给 AI agent 提供凭证的方式相比如何。"
+++

- **[KeyValet 对比 1Password（面向 AI agent）](/zh-CN/compare/1password/)** —— 1Password 管你的登录，KeyValet 管 agent 的 API 调用。互补，而非竞争。
- **对比 Infisical Agent Vault、OneCLI、Clawvisor、Authsome** —— 计划中。一句话版本：它们都能让 key 不进 agent 的上下文，但代理和 agent 跑在同一个系统用户下，主密钥是文件或环境变量。KeyValet 的代理是独立的特权服务，钥匙在 Secure Enclave / TPM 里，逐次批准绑定到一次调用。
- **对比 `.env` 文件** —— 计划中。
