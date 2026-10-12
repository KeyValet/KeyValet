+++
title = "Compare"
description = "How KeyValet compares with other ways of giving credentials to AI agents."
+++

- **[KeyValet vs 1Password for AI agents](/compare/1password/)** — 1Password manages your logins; KeyValet manages your agent's API calls. Complementary, not competing.
- **vs Infisical Agent Vault, OneCLI, Clawvisor, Authsome** — planned. The short version: all of them keep the key out of the agent’s context, but run the broker as the same OS user as the agent with the master key in a file or environment variable. KeyValet’s broker is a separate privileged service, its key is in Secure Enclave / TPM, and each per-use approval is bound to one call.
- **vs `.env` files** — planned.
