use super::{display_text, text, Error, Level, Result};
use serde_json::{json, Value};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Platform {
    Macos,
    Windows,
}
impl Platform {
    pub fn authentication(self) -> &'static str {
        match self {
            Self::Macos => "Touch ID",
            Self::Windows => "Hello",
        }
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct DisplayContext {
    pub now: i64,
    pub created_at: Option<i64>,
    pub clock_skew_s: Option<i64>,
    pub backlog_count: usize,
    pub unattended: bool,
}
impl DisplayContext {
    pub fn from_json(value: &Value) -> Result<Self> {
        Ok(Self {
            now: value
                .get("now")
                .and_then(Value::as_i64)
                .unwrap_or_else(unix_seconds),
            created_at: optional_integer(value, "created_at")?,
            clock_skew_s: optional_integer(value, "clock_skew_s")?,
            backlog_count: match value.get("backlog_count") {
                None => 0,
                Some(v) => usize::try_from(v.as_u64().ok_or(Error::InvalidRequest)?)
                    .map_err(|_| Error::InvalidRequest)?,
            },
            unattended: match value.get("unattended") {
                None => false,
                Some(v) => v.as_bool().ok_or(Error::InvalidRequest)?,
            },
        })
    }
}

fn optional_integer(value: &Value, key: &str) -> Result<Option<i64>> {
    match value.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(value) => value.as_i64().map(Some).ok_or(Error::InvalidRequest),
    }
}

pub fn unix_seconds() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs().min(i64::MAX as u64) as i64)
        .unwrap_or(0)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Row {
    pub label: String,
    pub value: String,
    pub red: bool,
    pub secondary: bool,
    pub detail: bool,
}
impl Row {
    fn json(&self) -> Value {
        json!({"label":self.label,"value":self.value,"red":self.red,"secondary":self.secondary,"detail":self.detail})
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScopeChoice {
    pub value: String,
    pub label: String,
    pub allow_label: String,
    pub level: Level,
}

// No Debug: the original request contains audit-only hashes and opaque extensions.
#[derive(Clone)]
pub struct ApprovalView {
    pub heading: String,
    pub subtitle: String,
    pub request_target: Option<String>,
    pub details_label: String,
    pub reason_label: String,
    pub title: String,
    pub summary: String,
    pub rows: Vec<Row>,
    pub scopes: Vec<ScopeChoice>,
    pub selected: usize,
    pub scope_label: String,
    pub deny_label: String,
    pub reason_placeholder: String,
    pub title_red: bool,
    pub(crate) original: Value,
}

impl ApprovalView {
    pub fn new(input: &Value, context: DisplayContext, platform: Platform) -> Result<Self> {
        Self::with_text(input, context, platform, kv_i18n::t)
    }

    pub fn with_text(
        input: &Value,
        context: DisplayContext,
        platform: Platform,
        t: fn(&str, &str) -> String,
    ) -> Result<Self> {
        if !input.is_object() {
            return Err(Error::InvalidRequest);
        }
        let kind = text(input, "kind")?;
        let tier = text(input, "tier")?;
        if !matches!(kind, "use" | "unlock" | "admin") || !matches!(tier, "T0" | "T1" | "T2") {
            return Err(Error::InvalidRequest);
        }
        text(input, "approval_id")?;
        text(input, "digest")?;
        text(input, "nonce")?;
        let expires_at = input["exp"].as_i64().ok_or(Error::InvalidRequest)?;
        if expires_at < context.now {
            return Err(Error::Expired);
        }
        let minimum = Level::parse(text(input, "min_level")?)?;
        let requester = &input["requester"];
        let agent = &input["agent"];
        let label = display_text(text(requester, "label")?)?;
        text(requester, "device_id")?;
        let os = display_text(text(requester, "os")?)?;
        let runtime = display_text(text(agent, "runtime")?)?;
        let cwd = display_text(text(agent, "cwd")?)?;
        let user = display_text(text(agent, "user")?)?;
        agent["pid"]
            .as_u64()
            .filter(|pid| *pid <= u32::MAX as u64)
            .ok_or(Error::InvalidRequest)?;
        let protection = match text(&requester["protection"], "kind")? {
            value @ ("tpm2" | "secure_enclave" | "windows_hello" | "software_key") => value,
            _ => "unknown",
        };
        let mut rows = Vec::new();
        let mut add = |zh: &str, en: &str, value: String, red, secondary| {
            rows.push(Row {
                label: t(zh, en),
                value,
                red,
                secondary,
                // Keep identity, risk and all warnings visible. Collapse duplicate HTTP
                // metadata and process details using the fixed, untranslated row kind.
                detail: matches!(en, "Method / host" | "Path / size" | "Agent"),
            });
        };
        let credential = &input["credential"];
        let operation = &input["operation"];
        let credential_name = if kind == "unlock" {
            if !credential.is_null() || !operation.is_null() {
                return Err(Error::InvalidRequest);
            }
            t("凭证库", "credential vault")
        } else if credential.is_null() && kind == "admin" {
            t("设备设置", "device settings")
        } else {
            let name = display_text(text(credential, "display")?)?;
            let credential_kind = display_text(text(credential, "kind")?)?;
            text(credential, "ref")?;
            let proxy_only = credential["proxy_only"]
                .as_bool()
                .ok_or(Error::InvalidRequest)?;
            add(
                "凭证",
                "Credential",
                format!(
                    "{name} · {credential_kind} · {}",
                    if proxy_only {
                        t("仅经代理使用", "Proxy only")
                    } else {
                        t("允许直接使用", "Direct use allowed")
                    }
                ),
                false,
                false,
            );
            name
        };
        let mut request_target = None;
        let summary = if kind == "unlock" {
            add(
                "有效期",
                "Validity",
                t(
                    "由执行端的解锁期限设置决定",
                    "Determined by the executor's unlock duration",
                ),
                false,
                false,
            );
            t("开始使用凭证库", "Start using the credential vault")
        } else if kind == "use" && operation.is_null() {
            // Non-HTTP uses (read/derive a token, TOTP or AWS credentials) carry no
            // HTTP Operation. Preserve the original signed request and its tier/scopes.
            let summary = t("直接使用或派生凭证", "Read or derive a credential");
            add("操作", "Operation", summary.clone(), false, false);
            summary
        } else {
            let method = display_text(text(operation, "method")?)?;
            let host = display_text(text(operation, "host")?)?;
            let path = display_text(text(operation, "path")?)?;
            // CONTRACT: §6.3: path is public metadata, never an absolute URL or query values.
            if path.contains('?') || path.contains('#') || path.contains("://") {
                return Err(Error::InvalidRequest);
            }
            let bytes = operation["body_bytes"]
                .as_u64()
                .ok_or(Error::InvalidRequest)?;
            request_target = Some(format!("{method} {host}{path}"));
            let summary = display_text(text(operation, "summary")?)?;
            add(
                "方法 / 主机",
                "Method / host",
                format!("{method}  {host}"),
                false,
                false,
            );
            add(
                "路径 / 大小",
                "Path / size",
                format!("{path} · {bytes} B"),
                false,
                false,
            );
            if summary.trim().is_empty() {
                format!("{method} {host}{path} · {bytes} B")
            } else {
                summary
            }
        };
        add(
            "来自",
            "Source",
            format!("{label} · {os} · {protection}"),
            protection == "software_key",
            false,
        );
        if protection == "software_key" {
            add(
                "保护状态",
                "Protection",
                t(
                    "software_key：此设备使用软件密钥",
                    "software_key: this device uses software keys",
                ),
                true,
                false,
            );
        } else if protection == "unknown" {
            add(
                "保护状态",
                "Protection",
                t(
                    "unknown：无法识别设备保护状态",
                    "unknown: device protection is not recognized",
                ),
                true,
                false,
            );
        }
        add(
            "agent",
            "Agent",
            format!("{runtime} · {cwd} · {} {user}", t("用户", "User")),
            false,
            false,
        );
        add(
            "agent 自述",
            "Agent's description",
            display_text(text(input, "purpose")?)?,
            false,
            true,
        );
        add(
            "风险",
            "Risk",
            match tier {
                "T0" => t("只读（T0）", "Read only (T0)"),
                "T1" => t("普通写入（T1）", "Ordinary write (T1)"),
                _ => t(
                    "敏感（T2）：此类操作不能预授权",
                    "Sensitive (T2): this operation cannot be preauthorized",
                ),
            },
            tier == "T2",
            false,
        );
        if let Some(skew) = context.clock_skew_s.filter(|skew| skew.unsigned_abs() > 60) {
            add(
                "时钟偏差",
                "Clock offset",
                t(
                    &format!("发送方时钟偏差 {skew} 秒"),
                    &format!("Sender clock offset: {skew} seconds"),
                ),
                true,
                false,
            );
        }
        let merged = input["merged_count"]
            .as_u64()
            .filter(|n| *n > 0 && *n <= u32::MAX as u64)
            .ok_or(Error::InvalidRequest)?;
        if merged > 1 {
            add(
                "合并请求",
                "Merged requests",
                t(
                    &format!("合并了 {merged} 条请求"),
                    &format!("{merged} requests merged"),
                ),
                false,
                false,
            );
        }
        if context.backlog_count > 0 {
            let age = context
                .created_at
                .map(|created| context.now.saturating_sub(created).max(0) / 60);
            let value = match age {
                Some(minutes) => t(&format!("积压请求，发起于 {minutes} 分钟前；其余待批见 keyvalet approvals"),
                    &format!("Backlog request, started {minutes} minutes ago; see keyvalet approvals for the remaining requests")),
                None => t("积压请求；其余待批见 keyvalet approvals", "Backlog request; see keyvalet approvals for remaining requests"),
            };
            add("积压", "Backlog", value, false, false);
        }
        if context.unattended {
            add(
                "无人值守",
                "Unattended",
                t(
                    "无人值守（含敏感操作）",
                    "Unattended (includes sensitive operations)",
                ),
                true,
                false,
            );
        }
        let options = input["scope_options"]
            .as_array()
            .filter(|v| !v.is_empty())
            .ok_or(Error::InvalidScope)?;
        let requested = text(input, "requested_scope")?;
        let mut scopes = Vec::<ScopeChoice>::new();
        for option in options {
            let value = option.as_str().ok_or(Error::InvalidScope)?;
            if scopes.iter().any(|scope| scope.value == value)
                || (tier == "T2" && value != "per_use")
            {
                return Err(Error::InvalidScope);
            }
            let (zh, en) = scope_copy(value)?;
            let level = if kind != "use" || tier == "T2" || value.starts_with("standing:") {
                Level::Strong
            } else {
                minimum
            };
            let allow_label = if value.starts_with("standing:") {
                t(
                    &format!("一直允许（{}）", platform.authentication()),
                    &format!("Always allow ({})", platform.authentication()),
                )
            } else if level == Level::Strong {
                t(
                    &format!("允许（{}）", platform.authentication()),
                    &format!("Allow ({})", platform.authentication()),
                )
            } else {
                t("允许", "Allow")
            };
            scopes.push(ScopeChoice {
                value: value.into(),
                label: t(zh, en),
                allow_label,
                level,
            });
        }
        let selected = scopes
            .iter()
            .position(|scope| scope.value == requested)
            .ok_or(Error::InvalidScope)?;
        let title = if kind == "unlock" {
            t(
                &format!("{label} 上的 {runtime} 请求使用凭证库"),
                &format!("{runtime} on {label} requests access to the credential vault"),
            )
        } else {
            t(
                &format!("{label} 上的 {runtime} 请求使用 {credential_name}"),
                &format!("{runtime} on {label} requests use of {credential_name}"),
            )
        };
        let title = if context.unattended {
            format!(
                "{} · {title}",
                t(
                    "无人值守（含敏感操作）",
                    "Unattended (includes sensitive operations)"
                )
            )
        } else {
            title
        };
        Ok(Self {
            heading: if context.unattended {
                t(
                    "无人值守（含敏感操作）",
                    "Unattended (includes sensitive operations)",
                )
            } else {
                match kind {
                    "unlock" => t("凭据库解锁请求", "Vault unlock request"),
                    "admin" => t("设置变更请求", "Settings change request"),
                    _ => t("凭据使用请求", "Credential access request"),
                }
            },
            subtitle: t(
                &format!("{runtime} 请求"),
                &format!("Requested by {runtime}"),
            ),
            request_target,
            details_label: t("请求详情", "Request details"),
            reason_label: t("添加拒绝原因", "Add a reason for denial"),
            title,
            summary,
            rows,
            scopes,
            selected,
            scope_label: t("范围", "Scope"),
            deny_label: t("拒绝", "Deny"),
            reason_placeholder: t(
                "拒绝原因（可选，一句话）",
                "Reason for denial (optional, one sentence)",
            ),
            title_red: context.unattended,
            original: input.clone(),
        })
    }

    pub fn payload(&self) -> Value {
        json!({"kind":"approval","title":self.title,"summary":self.summary,
            "heading":self.heading,"subtitle":self.subtitle,"request_target":self.request_target,
            "details_label":self.details_label,"reason_label":self.reason_label,
            "rows":self.rows.iter().map(Row::json).collect::<Vec<_>>(),
            "scopes":self.scopes.iter().map(|scope|json!({"value":scope.value,"label":scope.label,"allow_label":scope.allow_label})).collect::<Vec<_>>(),
            "selected":self.selected,"scope_label":self.scope_label,"deny_label":self.deny_label,
            "reason_placeholder":self.reason_placeholder,"title_red":self.title_red})
    }
}

pub fn scope_copy(value: &str) -> Result<(&'static str, &'static str)> {
    Ok(match value {
        "per_use" => ("这一次", "This request"),
        "per_credential" => ("这个凭据本会话", "This credential for this session"),
        "per_session" => ("本会话全部", "All credentials for this session"),
        "remember:1h" => ("记住 1 小时", "Remember for 1 hour"),
        "remember:8h" => ("记住 8 小时", "Remember for 8 hours"),
        "remember:24h" => ("记住 24 小时", "Remember for 24 hours"),
        "standing:credential" => ("这个凭证以后都允许", "Always allow this credential"),
        "standing:device" => ("这台机器以后都允许", "Always allow this executor"),
        _ => return Err(Error::InvalidScope),
    })
}

#[derive(Clone)]
pub struct PairingView {
    pub title: String,
    pub sas: String,
    pub rows: Vec<Row>,
    pub allow_label: String,
    pub deny_label: String,
}
impl PairingView {
    pub fn new(peer: &Value, sas: &str, platform: Platform) -> Result<Self> {
        if sas.len() != 6 || !sas.bytes().all(|c| c.is_ascii_digit()) {
            return Err(Error::InvalidRequest);
        }
        let label = display_text(text(peer, "label")?)?;
        let os = display_text(text(peer, "os")?)?;
        let key_kind = display_text(text(peer, "key_kind")?)?;
        let caps = peer["caps"]
            .as_array()
            .ok_or(Error::InvalidRequest)?
            .iter()
            .map(|v| {
                v.as_str()
                    .ok_or(Error::InvalidRequest)
                    .and_then(display_text)
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(Self {
            title: kv_i18n::t(
                &format!("确认与 {label} 配对"),
                &format!("Confirm pairing with {label}"),
            ),
            sas: sas.into(),
            rows: vec![
                Row {
                    label: kv_i18n::t("对方设备", "Peer device"),
                    value: format!("{label} · {os} · {key_kind}"),
                    red: key_kind == "software",
                    secondary: false,
                    detail: false,
                },
                Row {
                    label: kv_i18n::t("能力", "Capabilities"),
                    value: caps.join(", "),
                    red: false,
                    secondary: false,
                    detail: false,
                },
                Row {
                    label: kv_i18n::t("核对", "Compare"),
                    value: kv_i18n::t(
                        "确认两台设备显示的 6 位数完全相同",
                        "Confirm that both devices show exactly the same six digits",
                    ),
                    red: false,
                    secondary: false,
                    detail: false,
                },
            ],
            allow_label: kv_i18n::t(
                &format!("确认配对（{}）", platform.authentication()),
                &format!("Confirm pairing ({})", platform.authentication()),
            ),
            deny_label: kv_i18n::t("取消", "Cancel"),
        })
    }
    pub fn payload(&self) -> Value {
        json!({"kind":"pairing","title":self.title,"summary":self.sas,"rows":self.rows.iter().map(Row::json).collect::<Vec<_>>(),"allow_label":self.allow_label,"deny_label":self.deny_label})
    }
}

pub struct ConfirmationView {
    pub label: String,
    pub title: String,
    pub message: String,
    pub allow_label: String,
    pub deny_label: String,
}
impl ConfirmationView {
    pub fn revocation(label: &str) -> Result<Self> {
        let label = display_text(label)?;
        if label.trim().is_empty() {
            return Err(Error::InvalidRequest);
        }
        Ok(Self {
            title: kv_i18n::t("吊销设备", "Revoke device"),
            message: kv_i18n::t(
                &format!("吊销后此设备将不能审批或执行远程请求。输入执行端标签 {label} 确认。"),
                &format!("The revoked device can no longer approve or execute remote requests. Type the executor label {label} to confirm.")),
            label,
            allow_label: kv_i18n::t("确认吊销", "Confirm revocation"),
            deny_label: kv_i18n::t("取消", "Cancel"),
        })
    }
    pub fn new(label: &str, _platform: Platform, standing: bool) -> Result<Self> {
        let label = display_text(label)?;
        if label.trim().is_empty() {
            return Err(Error::InvalidRequest);
        }
        Ok(Self {
            title: kv_i18n::t(
                "无人值守（含敏感操作）",
                "Unattended (includes sensitive operations)",
            ),
            message: if standing {
                kv_i18n::t(&format!("此授权直到吊销才到期。再次输入执行端标签 {label} 确认。"),&format!("This authorization remains until revoked. Type the executor label {label} again to confirm."))
            } else {
                kv_i18n::t(&format!("敏感操作也将自动放行。输入执行端标签 {label} 确认。"),&format!("Sensitive operations will also be allowed automatically. Type the executor label {label} to confirm."))
            },
            label,
            allow_label: kv_i18n::t("确认", "Confirm"),
            deny_label: kv_i18n::t("取消", "Cancel"),
        })
    }
    pub fn payload(&self) -> Value {
        json!({"kind":"confirmation","title":self.title,"summary":self.message,"label":self.label,"allow_label":self.allow_label,"deny_label":self.deny_label,"title_red":true})
    }
}

pub struct GlobalGrantView {
    pub title: String,
    pub message: String,
    pub allow_label: String,
    pub deny_label: String,
}
impl GlobalGrantView {
    pub fn new(platform: Platform) -> Self {
        Self {
            title: kv_i18n::t("所有机器以后都允许", "Always allow every executor"),
            message: kv_i18n::t("此授权包括账户内全部执行端，以及以后新配对的执行端。敏感操作仍需逐次审批。",
                "This authorization includes every executor in the account, including executors paired in the future. Sensitive operations still require individual approval."),
            allow_label: kv_i18n::t(&format!("继续（{}）", platform.authentication()), &format!("Continue ({})", platform.authentication())),
            deny_label: kv_i18n::t("取消", "Cancel"),
        }
    }
    pub fn payload(&self) -> Value {
        json!({"kind":"global_grant","title":self.title,"summary":self.message,"allow_label":self.allow_label,"deny_label":self.deny_label})
    }
}
