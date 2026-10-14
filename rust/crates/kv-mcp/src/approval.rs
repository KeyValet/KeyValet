//! Runtime budgets and the model-facing remote approval result contract.

use rmcp::model::{CallToolRequestParams, CallToolResult};
use serde_json::{json, Map, Value};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

pub const WAIT_TOOL: &str = "credential_wait_approval";
pub const UNKNOWN_BUDGET_S: u64 = 50;
pub const DEFAULT_PROGRESS_INTERVAL_S: u64 = 15;
/// R2-D measured both 240 s calls with the hosted model on exactly this client version.
/// Other versions keep the conservative table budget until separately verified.
pub const VERIFIED_CODEX_CLIENT: (&str, &str, u64) = ("codex-mcp-client", "0.162.1", 180);
pub const RUNTIME_BUDGETS: &[(&[&str], u64)] = &[
    (&["claude-code", "claude code", "claude-code-cli"], 180),
    (&["claude-desktop", "claude-ai", "claude code desktop"], 50),
    (&["codex", "codex-mcp-client", "codex-cli"], 50),
    (&["gemini-cli", "gemini"], 180),
    (&["cursor-ide", "cursor-vscode"], 120),
    // Cursor CLI also reports "Cursor"; an ambiguous name must use the hard-timeout budget.
    (&["cursor", "cursor-agent", "cursor-cli", "cursor-acp"], 50),
    (&["grok", "grok-build"], 180),
    (&["devin", "devin-cli"], 50),
];

pub fn runtime_budget(name: &str, server_timeout_s: Option<u64>) -> u64 {
    let name = name.trim().to_ascii_lowercase();
    let mut budget = RUNTIME_BUDGETS
        .iter()
        .find(|(names, _)| names.contains(&name.as_str()))
        .map(|(_, seconds)| *seconds)
        .unwrap_or(UNKNOWN_BUDGET_S);
    if ["codex", "codex-mcp-client", "codex-cli"].contains(&name.as_str())
        && server_timeout_s.is_some_and(|s| s >= 190)
    {
        budget = 180;
    }
    server_timeout_s
        .map(|s| budget.min(s.saturating_sub(10).max(1)))
        .unwrap_or(budget)
}

#[derive(Clone, Debug)]
pub struct ApprovalConfig {
    pub wait_in_call: Duration,
    pub wait_tool_max: Duration,
    pub progress_interval: Duration,
    pub runtime_overrides: HashMap<String, u64>,
    pub server_timeout_s: Option<u64>,
}

impl Default for ApprovalConfig {
    fn default() -> Self {
        Self {
            wait_in_call: Duration::from_secs(60),
            wait_tool_max: Duration::from_secs(600),
            progress_interval: Duration::from_secs(DEFAULT_PROGRESS_INTERVAL_S),
            runtime_overrides: HashMap::new(),
            server_timeout_s: None,
        }
    }
}

impl ApprovalConfig {
    pub fn from_env() -> Result<Self, String> {
        Self::from_lookup(|name| std::env::var(name))
    }

    pub(crate) fn from_lookup(
        read: impl Fn(&str) -> Result<String, std::env::VarError>,
    ) -> Result<Self, String> {
        let seconds = |name: &str, fallback: u64| -> Result<u64, String> {
            match read(name) {
                Err(std::env::VarError::NotPresent) => Ok(fallback),
                value => value
                    .ok()
                    .and_then(|v| v.parse::<u64>().ok())
                    .filter(|s| (1..=86_400).contains(s))
                    .ok_or_else(|| format!("{name} must be an integer from 1 to 86400")),
            }
        };
        let mut config = Self {
            wait_in_call: Duration::from_secs(seconds("KEYVALET_WAIT_IN_CALL_S", 60)?),
            wait_tool_max: Duration::from_secs(seconds("KEYVALET_WAIT_TOOL_MAX_S", 600)?.min(600)),
            progress_interval: Duration::from_secs(seconds(
                "KEYVALET_PROGRESS_INTERVAL_S",
                DEFAULT_PROGRESS_INTERVAL_S,
            )?),
            ..Self::default()
        };
        if !matches!(
            read("KEYVALET_TOOL_TIMEOUT_SEC"),
            Err(std::env::VarError::NotPresent)
        ) {
            config.server_timeout_s = Some(seconds("KEYVALET_TOOL_TIMEOUT_SEC", 60)?);
        }
        let overrides = match read("KEYVALET_RUNTIME_BUDGETS") {
            Ok(raw) => Some(raw),
            Err(std::env::VarError::NotPresent) => None,
            Err(_) => return Err("KEYVALET_RUNTIME_BUDGETS must be UTF-8 JSON".into()),
        };
        if let Some(raw) = overrides {
            let values: HashMap<String, u64> = serde_json::from_str(&raw)
                .map_err(|_| "KEYVALET_RUNTIME_BUDGETS must be a JSON object of seconds")?;
            if values.values().any(|s| !(1..=86_400).contains(s)) {
                return Err("KEYVALET_RUNTIME_BUDGETS values must be from 1 to 86400".into());
            }
            config.runtime_overrides = values
                .into_iter()
                .map(|(name, seconds)| (name.trim().to_ascii_lowercase(), seconds))
                .collect();
        }
        Ok(config)
    }

    pub fn budget(&self, name: &str) -> Duration {
        let budget = self
            .runtime_overrides
            .get(&name.trim().to_ascii_lowercase())
            .copied()
            .unwrap_or_else(|| runtime_budget(name, self.server_timeout_s));
        Duration::from_secs(
            self.server_timeout_s
                .map(|s| budget.min(s.saturating_sub(10).max(1)))
                .unwrap_or(budget),
        )
    }

    pub fn client_budget(&self, name: &str, version: &str) -> Duration {
        let normalized = name.trim().to_ascii_lowercase();
        if normalized == VERIFIED_CODEX_CLIENT.0
            && version == VERIFIED_CODEX_CLIENT.1
            && !self.runtime_overrides.contains_key(&normalized)
        {
            let seconds = self
                .server_timeout_s
                .map(|s| VERIFIED_CODEX_CLIENT.2.min(s.saturating_sub(10).max(1)))
                .unwrap_or(VERIFIED_CODEX_CLIENT.2);
            Duration::from_secs(seconds)
        } else {
            self.budget(name)
        }
    }
}

pub fn is_approval_result(value: &Value) -> bool {
    matches!(
        value.get("status").and_then(Value::as_str),
        Some(
            "ok" | "approval_pending"
                | "approval_denied"
                | "approval_cancelled"
                | "approval_expired"
                | "no_approver"
                | "approved_retry_required"
                | "still_pending"
                | "already_consumed"
        )
    )
}

pub fn is_pending(value: &Value) -> bool {
    matches!(
        value["status"].as_str(),
        Some("approval_pending" | "still_pending")
    )
}

/// Keep the copy in one place; both language snapshots exercise these exact strings.
pub fn next_steps(status: &str) -> (&'static str, &'static str) {
    match status {
        "ok" => (
            "请求已执行，结果已返回。不要重复发起同一请求。",
            "The request executed and its result is returned. Do not repeat the same request.",
        ),
        "approval_pending" | "still_pending" => (
            "用户还未决定，这不是拒绝。你可以先做不需要这条凭证的事。需要结果时调用 credential_wait_approval(approval_id)，批准后它直接返回本次请求的结果。没有其他独立工作时，请在结束本轮前调用续等工具。不要重复发起同一请求，不要向用户索要密钥。",
            "The user has not decided; this is not a denial. Continue work that does not need this credential. Call credential_wait_approval(approval_id) when you need the result; after approval it returns this request's result directly. If no independent work remains, call the wait tool before finishing this turn. Do not repeat the original request or ask the user for a key.",
        ),
        "approval_denied" => (
            "用户拒绝了这次请求。不要重试或绕过审批，不要让用户粘贴密钥。将拒绝原因告诉用户。",
            "The user denied this request. Do not retry or bypass approval, and do not ask the user to paste a key. Tell the user the reason for the denial.",
        ),
        "approval_expired" => (
            "这次请求已过期，没有收到决定。仍需结果时可重新发起，会产生新的审批提示；除非确有必要，不要自动重发。",
            "This request expired without a decision. You may start a new request if the result is still needed; this creates a new approval prompt. Do not resend automatically unless necessary.",
        ),
        "approval_cancelled" => (
            "本地审批已取消，未授予权限；这不表示用户拒绝。此请求已结束，若仍需结果，请先确认用户希望重新发起审批，不要索要密钥。",
            "Local approval was cancelled and no permission was granted; this is not a denial. This request ended. If the result is still needed, confirm that the user wants a new approval request. Do not ask for a key.",
        ),
        "no_approver" => (
            "没有可用的审批通道。请告诉用户配置审批设备，或通过 SSH 在执行端本地审批；不要索要密钥。",
            "No approval channel is available. Tell the user to configure an approval device or approve locally on the executor over SSH; do not ask for a key.",
        ),
        "approved_retry_required" => (
            "请求已批准，但 helper 重启后丢失了内存中的原请求。用完全相同的参数和这个 approval_id 重发原工具调用一次；不要更改请求，不要创建新的审批。",
            "Approval was granted, but the helper lost the original request from memory after restarting. Resend the original tool call once with identical arguments and this approval_id. Do not change the request or create a new approval.",
        ),
        "already_consumed" => (
            "这次批准的结果已被领取，请求不会再次执行。使用先前返回的结果；不要重复发起请求。",
            "This approval's result was already consumed and the request will not execute again. Use the previously returned result; do not repeat the request.",
        ),
        _ => ("", ""),
    }
}

/// Only typed helper outcomes describe an explicit local decision. A local timeout
/// requires the retained ID/expiry: it is pending until exp, and never denial.
pub(crate) fn local_outcome(error: &Value) -> Option<Value> {
    if let Some(encoded) = error.as_str() {
        let decoded: Value = serde_json::from_str(encoded).ok()?;
        return decoded
            .is_object()
            .then(|| local_outcome(&decoded))
            .flatten();
    }
    let status = match error["code"].as_str()? {
        "local_approval_denied" => "approval_denied",
        "local_approval_cancelled" => "approval_cancelled",
        "local_approval_expired" => "approval_expired",
        "local_approval_timeout" => {
            error["approval_id"].as_str().filter(|id| !id.is_empty())?;
            if error["expires_at"].as_i64()? <= unix_time() {
                "approval_expired"
            } else {
                "approval_pending"
            }
        }
        _ => return None,
    };
    let mut result = json!({"status":status});
    for name in ["approval_id", "expires_at", "reason"] {
        if let Some(value) = error.get(name) {
            result[name] = value.clone();
        }
    }
    Some(result)
}

pub(crate) fn normalize_helper_result(mut value: Value) -> Value {
    if value["status"] == "approval_expired" && value["reason"] == "cancelled" {
        value["status"] = json!("approval_cancelled");
    }
    value
}

pub fn tool_result(mut value: Value) -> CallToolResult {
    if let Some(status) = value["status"].as_str().map(str::to_owned) {
        let (zh, en) = next_steps(&status);
        value["next_steps"] = json!(kv_i18n::t(zh, en));
        if status == "already_consumed" && value["reason"] == "continuation_unavailable" {
            value["next_steps"] = json!(kv_i18n::t(
                "原工具上下文已清理，无法安全还原其结果。不要重复发起原请求。",
                "The original tool context was cleared; its result cannot be safely restored. Do not repeat the original request.",
            ));
        }
        if is_pending(&value) {
            value["wait_tool"] = json!(WAIT_TOOL);
        }
        if status != "ok" {
            value.as_object_mut().unwrap().remove("result");
        }
    }
    let mut result =
        CallToolResult::success(vec![rmcp::model::ContentBlock::text(value.to_string())]);
    result.is_error = Some(false);
    result
}

pub(crate) const RESULT_PREFIX: &str = "[KEYVALET_APPROVAL_RESULT]";

#[derive(Clone)]
pub(crate) struct ResumeResult {
    pub op: String,
    pub params: Map<String, Value>,
    pub value: Value,
}

impl Drop for ResumeResult {
    fn drop(&mut self) {
        self.params.values_mut().for_each(scrub_value);
        scrub_value(&mut self.value);
    }
}

#[derive(Clone)]
pub(crate) struct PendingCall {
    pub request: CallToolRequestParams,
    pub op: String,
    pub params: Map<String, Value>,
    pub expires_at: i64,
}

impl Drop for PendingCall {
    fn drop(&mut self) {
        if let Some(arguments) = self.request.arguments.as_mut() {
            arguments.values_mut().for_each(scrub_value);
        }
        self.params.values_mut().for_each(scrub_value);
    }
}

pub(crate) fn scrub_value(value: &mut Value) {
    use zeroize::Zeroize;
    match value {
        Value::String(s) => s.zeroize(),
        Value::Array(items) => items.iter_mut().for_each(scrub_value),
        Value::Object(items) => items.values_mut().for_each(scrub_value),
        _ => {}
    }
}

/// Request metadata is task-local, so concurrent calls cannot exchange approval IDs or results.
pub(crate) struct ToolContext {
    pub request: CallToolRequestParams,
    pub deadline: tokio::time::Instant,
    pub resume: Mutex<Option<ResumeResult>>,
    pub pending: Arc<Mutex<Option<(Value, PendingCall)>>>,
}

tokio::task_local! {
    pub(crate) static TOOL_CONTEXT: ToolContext;
}

pub(crate) fn remember_pending(value: &Value, op: &str, params: &Map<String, Value>) {
    let _ = TOOL_CONTEXT.try_with(|context| {
        *context.pending.lock().unwrap() = Some((
            value.clone(),
            PendingCall {
                request: context.request.clone(),
                op: op.into(),
                params: params.clone(),
                expires_at: value["expires_at"].as_i64().unwrap_or(0),
            },
        ));
    });
}

pub(crate) fn clear_pending() {
    let _ = TOOL_CONTEXT.try_with(|context| context.pending.lock().unwrap().take());
}

pub(crate) fn is_usage_tool(name: &str) -> bool {
    matches!(
        name,
        "credential_http_request"
            | "credential_test"
            | "credential_get"
            | "credential_export_file"
            | "credential_access_token"
            | "credential_totp_code"
            | "credential_aws_credentials"
            | "credential_gateway"
            | "credential_imap_test"
            | "credential_graph_mail_test"
    )
}

pub fn visible_tool(mut tool: rmcp::model::Tool) -> rmcp::model::Tool {
    if tool.name == WAIT_TOOL {
        Arc::make_mut(&mut tool.input_schema)["properties"]["max_wait_s"] =
            json!({"type": "integer", "minimum": 5, "maximum": 600});
    }
    if is_usage_tool(&tool.name) {
        let schema = Arc::make_mut(&mut tool.input_schema);
        if let Some(properties) = schema.get_mut("properties").and_then(Value::as_object_mut) {
            properties.insert("approval_id".into(), json!({
                "type": "string", "description": kv_i18n::t(
                    "仅 approved_retry_required 时填写：用相同参数恢复已批准的原请求，不会创建新的审批。",
                    "Only for approved_retry_required: resume the approved original request with identical arguments, without creating a new approval.",
                ),
            }));
        }
    }
    tool
}

pub(crate) fn resuming(op: &str, params: &Map<String, Value>) -> Option<Value> {
    TOOL_CONTEXT
        .try_with(|context| {
            let mut resume = context.resume.lock().unwrap();
            if resume
                .as_ref()
                .is_some_and(|r| r.op == op && r.params == *params)
            {
                resume.take().map(|mut r| std::mem::take(&mut r.value))
            } else {
                None
            }
        })
        .ok()
        .flatten()
}

pub(crate) fn approval_id() -> Option<Value> {
    TOOL_CONTEXT
        .try_with(|context| {
            context
                .request
                .arguments
                .as_ref()?
                .get("approval_id")
                .cloned()
        })
        .ok()
        .flatten()
}

pub(crate) fn frontend(op: &str, params: &Map<String, Value>) -> Option<Value> {
    TOOL_CONTEXT
        .try_with(|context| {
            let mut arguments = context.request.arguments.clone().unwrap_or_default();
            if let Some(host) = params.get("frontend_host") {
                arguments.insert("host".into(), host.clone());
            }
            kv_ipc::continuation::FrontendContinuation::capture(
                &context.request.name,
                op,
                &arguments,
            )
            .and_then(|value| serde_json::to_value(value).ok())
        })
        .ok()
        .flatten()
}

pub(crate) fn remaining(fallback: Duration) -> Duration {
    TOOL_CONTEXT
        .try_with(|context| {
            context
                .deadline
                .saturating_duration_since(tokio::time::Instant::now())
        })
        .unwrap_or(fallback)
        .min(fallback)
}

pub(crate) fn unix_time() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}
