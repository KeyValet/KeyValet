# R2-A — Ubuntu ndu × MacBook 已安装设备验收

2026-10-13。按当前 main 工作树联调；未运行任何改变 git 状态的命令，不新增依赖。本文只把实际执行的项目记为通过，其他项目保留未测或未通过。

## 1. 覆盖安装前备份与回滚

两份 root-only 备份均在停止原有服务后生成、检查 tar 可读并计算 SHA256；随后恢复原活动服务。没有删除备份。备份包含数据、原安装二进制、wrapper 与现有服务配置。

| 机器 | 备份路径 | SHA256 / 证据 |
| --- | --- | --- |
| ndu | /var/backups/keyvalet-r2a-20261013T072000/state-and-install.tar | 8be3079e58750526dcb9ad8d5642f27bcb11d56803f0f5a75f179d358b888392；[备份清单](assets/r2a-ndu-backup.json) |
| Mac | /private/var/backups/keyvalet-r2a-20261013T072000/state-and-install.tar | b8f3eb2fec124cdabd45b73f8ade50967176589ef791c57eea5447f5e36e47cd；[备份记录](assets/r2a-mac-backup.json) |

ndu 包含 /var/lib/keyvalet、/etc/keyvalet；备份时没有 /var/lib/keyvalet-relay* 目录，peer/relay 服务也尚未安装。Mac 包含 /var/db/keyvalet；~/Library/Application Support/KeyValet 当时不存在，已记录缺失状态。完整权限与活动服务清单保存在每台机器的 root-only backup/manifest.json；秘密文件本身没有复制到报告目录。

回滚命令仅供需要时由 owner 执行。本轮新数据先移到新的 root-only 目录，保留所有备份：

```sh
# ndu: run in the owner's SSH terminal
sudo systemctl stop keyvalet.service
sudo systemctl disable --now keyvalet-relay.service keyvalet-peer.service
R2A_ROLLBACK=/var/backups/keyvalet-r2a-postrun-$(date -u +%Y%m%dT%H%M%SZ)
sudo install -d -m 0700 "$R2A_ROLLBACK"
sudo mv /var/lib/keyvalet "$R2A_ROLLBACK/vault"
sudo mv /etc/keyvalet "$R2A_ROLLBACK/config"
sudo mv /usr/local/lib/keyvalet "$R2A_ROLLBACK/install"
sudo mv /etc/systemd/system/keyvalet-peer.service "$R2A_ROLLBACK/peer.service"
sudo mv /etc/systemd/system/keyvalet-relay.service "$R2A_ROLLBACK/relay.service"
sudo tar --acls --xattrs -xpf /var/backups/keyvalet-r2a-20261013T072000/state-and-install.tar -C /
sudo systemctl daemon-reload
sudo systemctl start keyvalet.service
```

```sh
# Mac: run in the owner's GUI terminal
sudo launchctl bootout system/dev.keyvalet.helper
launchctl bootout gui/501/dev.keyvalet.agent
launchctl bootout gui/501/dev.keyvalet.relay
R2A_ROLLBACK=/private/var/backups/keyvalet-r2a-postrun-$(date -u +%Y%m%dT%H%M%SZ)
sudo install -d -m 0700 "$R2A_ROLLBACK"
sudo mv /var/db/keyvalet "$R2A_ROLLBACK/vault"
sudo mv /usr/local/lib/keyvalet "$R2A_ROLLBACK/install"
sudo mv /Library/LaunchAgents/dev.keyvalet.relay.plist "$R2A_ROLLBACK/relay.plist"
# This app directory was absent before the installation; retain the new data separately.
if [ -d "$HOME/Library/Application Support/KeyValet" ]; then
  sudo mv "$HOME/Library/Application Support/KeyValet" "$R2A_ROLLBACK/app-data"
fi
sudo tar -xpf /private/var/backups/keyvalet-r2a-20261013T072000/state-and-install.tar -C /
sudo launchctl bootstrap system /Library/LaunchDaemons/dev.keyvalet.helper.plist
launchctl bootstrap gui/501 /Library/LaunchAgents/dev.keyvalet.agent.plist
```

恢复旧 wrapper、二进制和 vault 后重新打开客户端；新建 relay 单元保持 disabled，恢复时不自动启动。运行时配置的修改收据分别在 `/home/guang/.keyvalet/remote-runtime-state.json` 与 `/Users/guang/.keyvalet/remote-runtime-state.json`；各配置的 `.bak-keyvalet-remote` 备份仍保留，路径见 [ndu 收据](assets/r2a-ndu-runtime-receipt.json)、[Mac 收据](assets/r2a-mac-runtime-receipt.json)。若要撤销本轮运行时注册，先在对应 owner 的源码目录运行 `sh scripts/install.sh --runtime-config remove --home "$HOME" --project "$PWD"`，只撤销收据里的 KeyValet 配置项，不覆盖其他配置。Origin CA 私钥不读取、不复制。

## 2. 线上 relay 对齐

已用当前工作树源码快照在 ndu 原生构建、部署 Linux ELF。旧二进制没有足以反查提交的构建收据；跨平台产物不能直接用哈希判断提交相同，所以同时记录 Mac scoped build、Linux scoped build 与实际部署的 Linux workspace build。[构建产物](assets/r2a-local-server-builds.json)。

| 产物 | SHA256 |
| --- | --- |
| simvito 部署前 | 9dfdccb8947ea00a6eedfab80295f878b657040ac91f643d2a4d2593869d835d |
| 本机 `cargo +1.99.0 build -p kv-server --release --locked` | 21a10de9e24840eb5a553d4fce9f0697e7c7475a3b80d32e5fd71b2642d116a6 |
| ndu scoped release build | 9ae13442823f6f273a57ce9ff460cba0f5828c3c69b986aea7825614513fb9b2 |
| simvito 部署后（ndu workspace release 产物） | 1eced902770d81e9933c204c8830ca7d2c7565e3fc0105e93aeeb44c45f9eab0 |

源码快照 710 文件，清单指纹 4b6e698595f92071968ececf0dc3f909c85e08963541f6f718368df4075d0af3。workspace 构建的 feature 合并使 scoped ELF 与安装产物哈希不同；实际运行文件与上传产物一致。旧二进制与 relay 数据备份保留在 simvito `/var/backups/keyvalet-r2a-relay-20261013T073000`。systemd 单元、nginx 配置与 account.env 三个哈希均保持相同；只重启 relay-server，没有改 push、Cloudflare 或证书。[部署收据](assets/r2a-relay-deployment.json)。

部署前后公网 `/v1/health`、`/v1/account/providers` 都为 200；版本 0.3.0，Google 已配置、Apple 未配置。[部署前](assets/r2a-public-relay-before.json)、[部署后](assets/r2a-public-relay-after.json)。Origin CA 私钥未读取、未复制。

relay 回滚（owner 在 simvito 的终端执行，先保留本轮状态）：

```sh
sudo systemctl stop keyvalet-relay-server.service
R2A_RELAY_ROLLBACK=/var/backups/keyvalet-r2a-relay-postrun-$(date -u +%Y%m%dT%H%M%SZ)
sudo install -d -m 0700 "$R2A_RELAY_ROLLBACK"
sudo mv /var/lib/keyvalet-relay-server "$R2A_RELAY_ROLLBACK/state"
sudo cp -p /usr/local/lib/keyvalet/kv-server "$R2A_RELAY_ROLLBACK/kv-server"
sudo tar --acls --xattrs -xpf /var/backups/keyvalet-r2a-relay-20261013T073000/relay-state.tar -C /
sudo install -o root -g root -m 0755 /var/backups/keyvalet-r2a-relay-20261013T073000/kv-server.before /usr/local/lib/keyvalet/kv-server
sudo systemctl start keyvalet-relay-server.service
```

## 3. 安装记录

两台均运行 `sh scripts/install.sh` 从源码安装。ndu 没有使用 `--software`；Mac 自动用 Simvito Limited Developer ID（PWCRJPY7YC）签名，启用 daemon 模式。

| 机器 / 服务 | 真实状态与权限 |
| --- | --- |
| ndu helper | keyvalet:keyvalet，active/running，capability 集合为空 |
| ndu peer broker | root:keyvalet，active/running，仅 CAP_SYS_PTRACE，仅 AF_UNIX |
| ndu relay client | keyvalet-relay:keyvalet-relay，active/running，capability 集合为空 |
| ndu vault / relay state | UID 994 / 993，均 0700；config root 0755 |
| Mac helper / agent / relay | system/dev.keyvalet.helper、gui/501/dev.keyvalet.agent、gui/501/dev.keyvalet.relay 均 running；严格验签通过，team PWCRJPY7YC |

ndu `status --summary --json` 的 protection.provider=tpm2、device_binding=true、recovery_configured=true；硬件实现证据仍为 tpm_interface_only/unknown，没有虚报 TPM 物理类型。配对前 remote_error=remote_unavailable，relay URL 已设置到公网生产地址。[ndu 状态](assets/r2a-ndu-installed-before-pair.json)、[URL 设置](assets/r2a-ndu-relay-url.json)、[Mac 修复后签名与进程](assets/r2a-mac-installed-fixed.json)。

ndu 原 vault.enc 在备份与安装后的 SHA256 完全相同；新 CLI 用 TPM 成功打开，`types` 返回 0 条类型，另用 `list` 确认实际凭证名称列表也为空。[vault 保留证据](assets/r2a-ndu-vault-preservation.json)、[名称列表检查](assets/r2a-ndu-credential-catalog.json)。用户选择先查看 Mac 既有凭证名称，再选一个只读 GET 测试；尚未读取凭证值。

Mac 安装器实际执行的 `status --summary` 显示 Secure Enclave 硬件保护、Touch ID/系统密码认证、恢复口令已配置和 relay 未绑定时的 unavailable。[原安装状态摘要](assets/r2a-mac-installed-status.json)。真实 bootstrap 已创建 DK / AK_q / AK_s 三个不同的 P-256 公钥，DeviceRecord.key_kind=secure_enclave、两把审批键 alg=ES256；三个公钥记录见 [ndu 收到的候选 Mac 记录](assets/r2a-ndu-pair-status.json)。AK_s 的 userPresence 创建路径保持原有代码；本轮实际 Strong 签名/交互尚未完成，不能仅凭公钥创建声称 Strong 已通过。

四条工作区 CI 在 Mac 的独立 target-r2a、Rust 1.99.0 上均 exit 0：fmt 1.135 s、Clippy 66.679 s、build 38.906 s、test 338.655 s。1333 passed / 0 failed / 10 ignored，69 组；353 个 Rust/Cargo/native 源文件没有在检查期间变更。[命令与计时](assets/r2a-ci.json)、[测试汇总](assets/r2a-ci-summary.json)。

## 4. 实机验收表

| 项目 | 结果 | 数字 | 证据 / 原因 |
| --- | --- | --- | --- |
| pair 到首次远程批准 <10 分钟 | 未通过 | 首轮 209.526 s 后停止；实际 use n=0 | 两端 SAS 相同、终端确认已提交，但 Mac CLI 在 Strong 阶段结束，配对未完成；[首轮记录](assets/r2a-pair-attempt-1.json) |
| Mac 审批 p50 <3 s / p95 <8 s，≥20 次 | 未测 | n=0 | 联调中 |
| 拒绝、超时续等、单次消费、修改参数 | 未测 | — | 待实际请求 |
| 双向吊销在 1 分钟内失效 | 未测 | — | 待建立配对与授权 |
| 两端 audit 对账 100% | 未测 | — | 待实际请求历史 |
| 合盖 2 小时积压送达、不重复执行、过期 | 未测 | — | 用户已确认可配合，尚未开始计时 |
| 远程切模式、签 1 小时票、全部收回各 <5 s | 未测 | — | 待建立配对 |
| 本机优先投递与锁屏 away | 未测 | — | 待配对与原生对话框 |
| notify always-phone Directive 落地 | 未测 | — | 手机验证归 R2-C |

## 5. Bug、复现测试、修复与真机复验

本工作流新增代码改动相对启动前快照为：`scripts/install.sh:563` 一行 requirement 修正；`rust/crates/kv-cli/src/remote/review_tests.rs:9` 新增 49 行 CI 复现测试。文档改动为 `docs/linux.md` 的真实安装、broker、配对前状态与 vault 限制；本报告及 assets/r2a-*；按用户明确要求更新架构 §16 与 review 的验收表。没有修改 kv-core、kv-server、手机、proxy/MCP/hook，也没有改 helper/relay 的认证规则。

| Bug → 复现 | 修复 | 真机复验 |
| --- | --- | --- |
| Mac 首次安装 exit 0，但 relay LaunchAgent 未安装：`codesign -R` 把无 `=` 的要求字符串当成文件路径。先添加 CI 测试：复制并 ad-hoc 签名当前测试程序，验证安装器实际 requirement 应接受正确 identifier、拒绝错误 identifier；修复前失败。 | scripts/install.sh 的 requirement 增加 `=`；严格签名、team、identifier 条件保留。测试在 kv-cli/src/remote/review_tests.rs，不依赖本机安装、root、Developer ID 或 GUI。 | 修复后测试 1/1，通过；重新运行真实安装器后 helper/agent/relay 都 running，四个二进制严格验签通过。[失败日志](assets/r2a-repro-relay-requirement.log)、[通过日志](assets/r2a-fixed-relay-requirement.log)、[进程与签名](assets/r2a-mac-installed-fixed.json) |

本修复不涉及 D10、ptrace/能力策略、bootstrap 验证或配对认证。现有软件全链路与硬件 spike 作为前提，不替代实机结果。

## 6. 所有权外变更请求

暂无。按用户本轮明确要求，仅将验收结果回填架构 §16 和 review 对应验收行，不修改其协议正文。发现需改 kv-core/kv-server/其他归属的实现时，记录请求并停止该步骤。

## 7. 未解决问题与下一步

部署和两台安装完成，四条 CI 全绿。首轮匿名注册、硬件身份签名与 ECDH/SAS 已实际运行，两端 SAS 相同；恢复码已向用户显示，报告不保存其值。首轮在 Mac Strong 确认阶段未完成，暂未取得产品错误码；终端驱动已修正对 JSON 错误对象字段顺序的解析，准备新一轮取得准确原因，没有改变产品的认证或超时。

当前交互检查点：第二轮 Terminal 已打开，仍等待管理员密码，驱动尚未开始；Mac 名称检查延后到配对交互完成，避免叠加系统授权窗口。[检查点](assets/r2a-interaction-status.json)。

待完成：Mac 原生配对确认和 Strong 签名；选定并配置只读 GET 凭证；实际 Claude Code 首次请求与 ≥20 次计时；拒绝/续等/消费/改参数；F/G 控制面与在场；实际两小时合盖；最后双向吊销及 audit 对账。两小时尚未开始计时。用户不需在聊天提供密钥值、恢复码或配对 token。
