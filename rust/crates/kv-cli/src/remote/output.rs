//! Stable JSON output and terminal rendering of metadata and summaries.

use super::relay::{Health, Installed};
use kv_core::remote::ipc::DevicesListResult;
use kv_core::remote::{Decision, DirectiveResult, Extra, Grant};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub(super) struct PendingEntry {
    pub approval_id: String,
    #[serde(default)]
    pub summary: Option<String>,
    #[serde(default)]
    pub state: Option<String>,
    #[serde(flatten)]
    pub extra: Extra,
}

impl PendingEntry {
    pub fn summary(&self) -> String {
        self.summary.clone().unwrap_or_else(|| {
            self.extra
                .get("operation")
                .and_then(|op| op["summary"].as_str())
                .unwrap_or("")
                .to_owned()
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub(super) struct ApprovalHistory {
    pub approval_id: String,
    pub decision: Decision,
    #[serde(default)]
    pub summary: Option<String>,
    #[serde(flatten)]
    pub extra: Extra,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub(super) struct Pending {
    pub pending: Vec<PendingEntry>,
    #[serde(default)]
    pub recent: Vec<ApprovalHistory>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct RemoteStatus {
    pub relay: String,
    pub approvers: Vec<Value>,
    pub pending_n: u64,
    pub grants_n: u64,
    pub unattended: bool,
    pub runtime_budget_s: u64,
    #[serde(flatten)]
    pub extra: Extra,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct DeviceResult {
    pub device_id: String,
    pub result: DirectiveResult,
}

#[derive(Deserialize)]
pub(super) struct Sent {
    pub sent: bool,
}

pub(super) type ListedGrant = kv_ipc::remote::GrantMetadata;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "command", content = "result", rename_all = "snake_case")]
pub(super) enum Success {
    Help {
        text: String,
    },
    RelayInstall(Installed),
    RelayStatus(Health),
    RelayRecovered(kv_ipc::remote::AccountRecoverResult),
    RelaySetUrl {
        relay_url: String,
        config: PathBuf,
    },
    Pair {
        uri: Option<String>,
        sas: Option<String>,
        paired: bool,
    },
    PairRecovery {
        recovery_code: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        account_id: Option<String>,
    },
    PairGlobalGrants {
        count: u64,
    },
    Devices(DevicesListResult),
    DeviceRevoked {
        device_id: String,
    },
    DeviceRenamed {
        device_id: String,
        label: String,
    },
    Approvals(Pending),
    Decision {
        approval_id: String,
        decision: Decision,
        sent: bool,
    },
    GrantsIssued {
        grants: Vec<Grant>,
    },
    Grants(kv_ipc::remote::GrantListResult<ListedGrant>),
    GrantRevoked {
        jti: String,
    },
    Remote {
        results: Vec<DeviceResult>,
    },
    Audit(super::audit::Report),
    Status {
        protection: Value,
        remote: Option<RemoteStatus>,
        remote_error: Option<super::Error>,
        paired_devices_n: Option<usize>,
    },
}

impl PartialEq for Success {
    fn eq(&self, other: &Self) -> bool {
        serde_json::to_value(self).ok() == serde_json::to_value(other).ok()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct JsonSuccess {
    pub ok: bool,
    #[serde(flatten)]
    pub output: Success,
}

pub(super) fn terminal_text(text: &str) -> String {
    text.chars()
        .map(|c| if c.is_control() { '?' } else { c })
        .collect()
}

pub(super) fn render_error(error: &super::Error, json: bool) -> String {
    if json {
        return serde_json::json!({"ok":false,"error":error}).to_string();
    }
    let mut text = format!("keyvalet: {}", terminal_text(&error.message));
    if !error.completed_devices.is_empty() {
        let devices = error
            .completed_devices
            .iter()
            .map(|id| terminal_text(id))
            .collect::<Vec<_>>()
            .join(", ");
        text.push_str(&format!(
            "\n{} {devices}",
            kv_i18n::t("已完成的设备：", "Completed devices:")
        ));
    }
    text
}

pub(super) fn render(value: &Success, color: bool, summary: bool) -> String {
    let clean = terminal_text;
    match value {
        Success::Audit(report) => {
            let mut lines = vec![format!("{}: {} · matched={} · findings={} · unavailable={}",
                kv_i18n::t("远程审计", "Remote audit"), if report.consistent {"consistent"} else {"differences/incomplete"},
                report.comparison.matched,report.comparison.findings.len(),report.unavailable.len())];
            for finding in &report.comparison.findings {
                lines.push(format!("{} {} {} → {}: {} {}", clean(&finding.kind),clean(&finding.id),clean(&finding.issuer),clean(&finding.receiver),clean(&finding.problem),finding.fields.join(", ")));
            }
            for (device,code) in &report.unavailable { lines.push(format!("{}: {}",clean(device),clean(code))); }
            lines.push(kv_i18n::t("检查点不提供整套备份的硬件反回滚保证。", "Checkpoints do not provide hardware protection against restoring a complete backup."));
            lines.join("\n")
        }
        Success::Help { text } => text.clone(),
        Success::RelayInstall(result) => format!("{}\n{}\n{}\n{}", kv_i18n::t("已写出 relay 部署配置：", "Relay deployment configuration written:"), result.service.display(), result.nginx.display(), kv_i18n::t(
            "1. Cloudflare DNS：A/AAAA 指向源站，开启橙色云代理。\n2. SSL/TLS：选择 Full (strict)，将 Origin CA 证书放入 /etc/ssl/keyvalet-relay/{origin.pem,origin.key}。\n3. 防火墙：443 只放行 Cloudflare IP 段，8787 不对外。\n由安装器创建专用账户、安装 kv-server 并启动 systemd/nginx。",
            "1. Cloudflare DNS: point A/AAAA to the origin and enable the orange cloud proxy.\n2. SSL/TLS: select Full (strict) and place Origin CA certificates in /etc/ssl/keyvalet-relay/{origin.pem,origin.key}.\n3. Firewall: allow port 443 only from Cloudflare IP ranges; keep 8787 private.\nUse the installer to create the service account, install kv-server and start systemd/nginx.")),
        Success::RelayStatus(health) => format!("{} {}", kv_i18n::t("relay 正常，版本", "Relay healthy, version"), clean(&health.version)),
        Success::RelayRecovered(result) => format!("{} {}\n{} {}\n{}",
            kv_i18n::t("账户已恢复：", "Account recovered:"),clean(&result.binding.account_id),
            kv_i18n::t("请离线保存新的恢复码：", "Save the replacement recovery code offline:"),clean(&result.recovery_code),
            kv_i18n::t("旧设备的 relay 注册已撤销。请重新配对审批设备；此操作不恢复 vault。",
                "Previous relay device registrations are revoked. Pair approvers again; vault recovery is separate.")),
        Success::RelaySetUrl { relay_url, config } => format!("{} {}\n{}", kv_i18n::t("relay 地址已设置为", "Relay URL set to"), clean(relay_url), config.display()),
        Success::Pair { uri, sas, paired } => {
            if *paired { kv_i18n::t("配对完成。", "Pairing complete.") }
            else if let Some(uri) = uri { format!("{uri}\n{}", kv_i18n::t("请在另一台设备运行 keyvalet pair <此地址>。", "Run keyvalet pair <this URI> on the other device.")) }
            else { format!("{} {}", kv_i18n::t("安全码：", "Safety code:"), sas.as_deref().unwrap_or("")) }
        }
        Success::PairRecovery { recovery_code,account_id } => {
            let code=format!("{} {}",kv_i18n::t("请保存账户恢复码（仅显示这一次）：","Save this account recovery code (shown only once):"),clean(recovery_code));
            if let Some(account)=account_id {
                format!("{} {}\n{code}\n{}",kv_i18n::t("账户 ID：","Account ID:"),clean(account),kv_i18n::t("请把账户 ID 和恢复码一起离线保存。","Keep the account ID and recovery code together offline."))
            } else {code}
        }
        Success::PairGlobalGrants { count } => kv_i18n::t(&format!("账户内有 {count} 张全局授权将对此设备生效。"),&format!("{count} global grants will apply to this device.")),
        Success::Devices(list) => list.devices.iter().map(|d| format!("{}\t{}\t{}\t{}", clean(&d.device_id), clean(&d.label), clean(d.os.as_str()), if d.extra.get("revoked") == Some(&Value::Bool(true)) { kv_i18n::t("已吊销", "revoked") } else { kv_i18n::t("已配对", "paired") })).collect::<Vec<_>>().join("\n"),
        Success::DeviceRevoked { device_id } => format!("{} {}", kv_i18n::t("已吊销设备", "Device revoked:"), clean(device_id)),
        Success::DeviceRenamed { device_id, label } => format!("{} {} → {}", kv_i18n::t("设备已重命名", "Device renamed:"), clean(device_id), clean(label)),
        Success::Approvals(pending) => {
            let mut lines = pending.pending.iter().map(|p| format!("{}\t{}\t{}", clean(&p.approval_id), clean(p.state.as_deref().unwrap_or("waiting")), clean(&p.summary()))).collect::<Vec<_>>();
            lines.extend(pending.recent.iter().map(|p| format!("{}\t{}\t{}", clean(&p.approval_id), if p.decision == Decision::Allow { kv_i18n::t("已批准", "approved") } else { kv_i18n::t("已拒绝", "denied") }, clean(p.summary.as_deref().unwrap_or("")))));
            if lines.is_empty() { kv_i18n::t("没有待处理审批。", "No pending approvals.") } else { lines.join("\n") }
        }
        Success::Decision { approval_id, decision, .. } => format!("{} {}", if *decision == Decision::Allow { kv_i18n::t("已发送批准", "Approval sent:") } else { kv_i18n::t("已发送拒绝", "Denial sent:") }, clean(approval_id)),
        Success::GrantsIssued { grants } => grants.iter().map(|g| format!("{} {} → {}", kv_i18n::t("已签发授权", "Grant issued:"), clean(&g.jti), clean(&g.aud))).collect::<Vec<_>>().join("\n"),
        Success::Grants(list) => list.grants.iter().map(|g| format!("{}\t{}\t{}\t{}", clean(&g.jti), clean(&g.aud), g.exp.map_or_else(|| kv_i18n::t("常设", "standing"), |n| n.to_string()), clean(&serde_json::to_string(&g.extra).unwrap_or_default()))).collect::<Vec<_>>().join("\n"),
        Success::GrantRevoked { jti } => format!("{} {}", kv_i18n::t("已吊销授权", "Grant revoked:"), clean(jti)),
        Success::Remote { results } => results.iter().map(|r| {
            let state = clean(&serde_json::to_string(&r.result.state).unwrap_or_default());
            let unattended = if r.result.state.get("unattended") == Some(&Value::Bool(true)) {
                let text = kv_i18n::t("无人值守（含敏感操作）", "Unattended (including sensitive operations)");
                if color { format!("\n\u{1b}[31m{text}\u{1b}[0m") } else { format!("\n{text}") }
            } else { String::new() };
            format!("{}\t{state}{unattended}", clean(&r.device_id))
        }).collect::<Vec<_>>().join("\n"),
        Success::Status { protection, remote, remote_error, paired_devices_n } => {
            let local = if summary { kv_platform::protection::summary(protection) } else { serde_json::to_string_pretty(protection).unwrap_or_default() };
            let Some(remote) = remote else {
                return format!("{local}\n{} {}\n{} {}", kv_i18n::t("relay：", "Relay:"), kv_i18n::t("未知（远程 helper 未就绪）", "unknown (remote helper unavailable)"), kv_i18n::t("远程状态不可用：", "Remote status unavailable:"), remote_error.as_ref().map(|e|e.message.as_str()).unwrap_or(""));
            };
            let paired_devices_n = paired_devices_n.map_or_else(|| kv_i18n::t("未知", "unknown"), |n|n.to_string());
            let warning = if remote.unattended { kv_i18n::t("无人值守（含敏感操作）", "Unattended (including sensitive operations)") } else { kv_i18n::t("敏感操作仍需审批", "Sensitive operations require approval") };
            let warning = if color && remote.unattended { format!("\u{1b}[31m{warning}\u{1b}[0m") } else { warning };
            format!("{local}\n{} {}\n{} {paired_devices_n}\n{} {}\n{} {}\n{warning}", kv_i18n::t("relay：", "Relay:"), clean(&remote.relay), kv_i18n::t("已配对设备：", "Paired devices:"), kv_i18n::t("待处理审批：", "Pending approvals:"), remote.pending_n, kv_i18n::t("有效授权：", "Active grants:"), remote.grants_n)
        }
    }
}

pub(super) fn error_message(code: &str) -> String {
    match code {
        "expired" | "pair_timeout" | "timeout" | "directive_result_timeout" => kv_i18n::t("操作超时或已过期；请重试，配对请重新运行 pair --new", "The operation timed out or expired; retry, or run pair --new for pairing"),
        "pair_sas_mismatch" => kv_i18n::t("两端安全码不一致；配对已拒绝，请重新运行 pair --new", "Safety codes do not match; pairing was rejected, run pair --new again"),
        "unknown_token" => kv_i18n::t("配对 token 未知或已使用；请重新运行 pair --new", "The pairing token is unknown or used; run pair --new again"),
        "user_cancelled" | "strong_cancelled" | "authentication_cancelled" | "secondary_confirmation_required" => kv_i18n::t("用户取消认证或缺少二次确认；未发出授权", "Authentication was cancelled or secondary confirmation is missing; no authorization was issued"),
        "relay_unreachable" | "relay_offline" | "remote_unavailable" | "ipc_unavailable" => kv_i18n::t("relay 或 helper 不可达；请检查服务与 relay 地址", "The relay or helper is unreachable; check the service and relay URL"),
        "relay_unavailable" | "relay_busy" => kv_i18n::t("relay 传输暂时不可用；请稍后重试并检查 relay-client 服务", "Relay transport is temporarily unavailable; retry and check the relay-client service"),
        _ => kv_i18n::t(&format!("执行端或 helper 拒绝了操作（{}）", terminal_text(code)), &format!("The executor or helper rejected the operation ({})", terminal_text(code))),
    }
}
