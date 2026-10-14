use super::engine::FullRequest;
use super::{Error, Preference, Result};
use super::{GrantUse, RemoteHelper};
use kv_core::remote::canonical::{jcs, CanonicalRequest};
use kv_core::remote::*;
use serde_json::{json, Value};
use std::sync::Arc;

/// Inputs come from the helper's identity and policy stages, never from relay or UI metadata.
pub struct ApprovalInput {
    pub canonical: CanonicalRequest,
    pub credential: Option<Credential>,
    pub operation: Option<Operation>,
    pub tier: Tier,
    pub min_level: ApprovalLevel,
    pub scope_options: Vec<ScopeOption>,
    pub requested_scope: ScopeOption,
    pub session_id: String,
    pub full_request: FullRequest,
    pub auto_allowed: bool,
    pub local_channel_available: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Selection {
    Auto,
    Grant(Vec<String>),
    Local,
    RemoteDevice,
    NoApprover,
}

impl RemoteHelper {
    /// Called after OS identity, template host constraints and policy risk classification.
    /// This same entry point serves a tool call and the proxy's held HTTP connection.
    pub async fn run(
        self: &Arc<Self>,
        input: ApprovalInput,
        hosts: Vec<String>,
        methods: Vec<String>,
        runtime_budget_s: u64,
    ) -> Result<ToolResult> {
        let result = self
            .run_inner(input, hosts, methods, runtime_budget_s)
            .await;
        if let Err(error) = result {
            self.reject(&*self.lock()?, "approval_rejected", error, "")?;
        }
        result
    }

    async fn run_inner(
        self: &Arc<Self>,
        mut input: ApprovalInput,
        hosts: Vec<String>,
        methods: Vec<String>,
        runtime_budget_s: u64,
    ) -> Result<ToolResult> {
        input.canonical.nonce = super::engine::random_nonce()?;
        input.canonical.exp = self
            .services
            .clock
            .now()
            .saturating_add(self.config.default_exp_s as i64);
        input.canonical.extra.insert(
            "execution_sha256".into(),
            json!(input.full_request.binding_digest()?),
        );
        input
            .canonical
            .extra
            .insert("session_id".into(), json!(input.session_id));
        input.canonical.extra.insert(
            "unlock_ttl_s".into(),
            json!(self
                .lock()?
                .store
                .setting::<u64>("unlock_ttl")?
                .unwrap_or(self.config.unlock_ttl_s)),
        );
        input.canonical =
            kv_core::remote::canonical::from_json(&input.canonical.canonical_bytes()?)?;
        let auto = input.auto_allowed
            && input.tier == Tier::T0
            && input.canonical.kind == ApprovalKind::Use;
        let coverage = if auto {
            Vec::new()
        } else {
            self.cover_and_debit(&GrantUse {
                canonical: input.canonical.clone(),
                tier: input.tier,
                template_allowed_hosts: hosts,
                policy_allowed_methods: methods,
                body_bytes: input
                    .operation
                    .as_ref()
                    .map_or(0, |operation| operation.body_bytes),
                session_id: input.session_id.clone(),
            })?
            .jtis
        };
        let paired = self
            .lock()?
            .store
            .devices(&self.account)?
            .iter()
            .any(super::engine::is_approver);
        match select(
            auto,
            coverage,
            input.local_channel_available,
            self.config.prefer,
            paired,
        ) {
            Selection::Auto | Selection::Grant(_) => {
                self.run_authorized(input, "grant_or_auto").await
            }
            Selection::Local => {
                let authorization = self.services.runner.local_authorize("local_approval", json!({"session_id": input.session_id, "kind": input.canonical.kind,
                    "digest": input.canonical.digest()?, "credential": input.credential, "operation": input.operation,
                    "tier": input.tier, "purpose": input.canonical.purpose}));
                let level = match tokio::time::timeout(
                    std::time::Duration::from_secs(self.config.call_budget_s(runtime_budget_s)),
                    authorization,
                )
                .await
                {
                    Ok(Ok(level)) => level,
                    Ok(Err(Error("local_approval_denied"))) => {
                        self.audit(
                            &*self.lock()?,
                            "local_approval_denied",
                            json!({"session":input.session_id}),
                        )?;
                        return serde_json::from_value(json!({"status":"approval_denied"}))
                            .map_err(Into::into);
                    }
                    Ok(Err(Error("local_approval_cancelled"))) => {
                        self.audit(
                            &*self.lock()?,
                            "local_approval_cancelled",
                            json!({"session":input.session_id}),
                        )?;
                        // Preserve the existing expired-with-reason cancellation contract,
                        // which the MCP/HTTP adapters already decode as cancelled.
                        return serde_json::from_value(
                            json!({"status":"approval_expired","reason":"cancelled"}),
                        )
                        .map_err(Into::into);
                    }
                    Err(_)
                    | Ok(Err(Error(
                        "local_approval_timeout"
                        | "local_approval_unavailable"
                        | "local_approval_failed",
                    ))) => {
                        let uid = input.canonical.agent.uid;
                        let pid = input.canonical.agent.pid;
                        let request = match self.submit(input) {
                            Ok(request) => request,
                            Err(Error("no_approver")) => {
                                return Ok(plain_result(ToolStatus::NoApprover, Optional::Missing))
                            }
                            Err(error) => return Err(error),
                        };
                        let mut result = self.result(&request.approval_id, uid, pid, true)?;
                        if result.status == ToolStatus::StillPending {
                            result.status = ToolStatus::ApprovalPending;
                        }
                        return Ok(result);
                    }
                    Ok(Err(error)) => return Err(error),
                };
                let required =
                    if input.tier == Tier::T2 || input.canonical.kind != ApprovalKind::Use {
                        ApprovalLevel::Strong
                    } else {
                        input.min_level
                    };
                if level < required {
                    self.reject(
                        &*self.lock()?,
                        "approval_rejected",
                        Error("insufficient_level"),
                        "",
                    )?;
                    return Err(Error("insufficient_level"));
                }
                self.run_authorized(input, "local").await
            }
            Selection::RemoteDevice => {
                let uid = input.canonical.agent.uid;
                let pid = input.canonical.agent.pid;
                let request = self.submit(input)?;
                let mut result = self
                    .wait(
                        &request.approval_id,
                        self.config
                            .call_budget_s(runtime_budget_s)
                            .saturating_mul(1000),
                        runtime_budget_s,
                        uid,
                        pid,
                    )
                    .await?;
                if result.status == ToolStatus::StillPending {
                    result.status = ToolStatus::ApprovalPending;
                }
                Ok(result)
            }
            Selection::NoApprover => {
                self.reject(
                    &*self.lock()?,
                    "approval_rejected",
                    Error("no_approver"),
                    "",
                )?;
                Ok(plain_result(ToolStatus::NoApprover, Optional::Missing))
            }
        }
    }

    async fn run_authorized(&self, input: ApprovalInput, path: &str) -> Result<ToolResult> {
        self.audit(
            &*self.lock()?,
            "use",
            json!({"digest": input.canonical.digest()?, "tier": input.tier, "approval_path": path}),
        )?;
        let value = self
            .services
            .runner
            .execute(super::Execution {
                canonical: input.canonical,
                full_request: input.full_request,
                approval_id: String::new(),
            })
            .await?;
        Ok(plain_result(ToolStatus::Ok, Optional::Value(value)))
    }

    pub async fn wait_http(
        self: &Arc<Self>,
        id: &str,
        host_hint_s: Option<u64>,
        uid: u32,
        agent_pid: u32,
    ) -> Result<ToolResult> {
        let wait_s = self.config.http_budget_s(host_hint_s);
        // HTTP's separate budget is not constrained by an MCP tool timeout.
        self.wait(
            id,
            wait_s.saturating_mul(1000),
            wait_s.saturating_add(10),
            uid,
            agent_pid,
        )
        .await
    }
}

fn plain_result(status: ToolStatus, result: Optional<Value>) -> ToolResult {
    ToolResult {
        status,
        approval_id: Optional::Missing,
        expires_at: Optional::Missing,
        approver: Optional::Missing,
        wait_tool: Optional::Missing,
        next_steps: Optional::Missing,
        result,
        extra: Extra::new(),
    }
}

pub fn select(
    auto: bool,
    grants: Vec<String>,
    local_available: bool,
    prefer: Preference,
    paired_approvers: bool,
) -> Selection {
    if auto {
        Selection::Auto
    } else if !grants.is_empty() {
        Selection::Grant(grants)
    } else if local_available && prefer != Preference::Remote {
        Selection::Local
    } else if paired_approvers {
        Selection::RemoteDevice
    } else {
        Selection::NoApprover
    }
}

pub(crate) fn scope_options(input: &ApprovalInput) -> Vec<ScopeOption> {
    if input.tier == Tier::T2 || input.canonical.kind != ApprovalKind::Use {
        return vec![ScopeOption::PerUse];
    }
    let mut options = vec![ScopeOption::PerUse];
    for option in &input.scope_options {
        if !options.contains(option) {
            options.push(*option);
        }
    }
    options
}

pub(crate) fn validate_decision_scope(
    decision: &ApprovalDecision,
    request: &ApprovalRequest,
) -> Result<()> {
    if request.tier == Tier::T2 && decision.scope.mode != ScopeMode::PerUse {
        return Err(Error("invalid_scope"));
    }
    let option = match (decision.scope.mode, decision.scope.level) {
        (ScopeMode::PerUse, _) => ScopeOption::PerUse,
        (ScopeMode::PerCredential, DecisionScopeLevel::Credential) => ScopeOption::PerCredential,
        (ScopeMode::PerSession, _) => ScopeOption::PerSession,
        (ScopeMode::Remember, DecisionScopeLevel::Credential) => {
            match decision.scope.until.checked_sub(decision.issued_at) {
                Some(3600) => ScopeOption::Remember1h,
                Some(28800) => ScopeOption::Remember8h,
                Some(86400) => ScopeOption::Remember24h,
                _ => return Err(Error("invalid_scope")),
            }
        }
        (ScopeMode::Standing, DecisionScopeLevel::Credential) => ScopeOption::StandingCredential,
        (ScopeMode::Standing, DecisionScopeLevel::Device) => ScopeOption::StandingDevice,
        _ => return Err(Error("invalid_scope")),
    };
    if !request.scope_options.contains(&option) {
        return Err(Error("invalid_scope"));
    }
    Ok(())
}

/// Include all canonical extensions; only the fresh nonce and expiration may change on retry.
pub fn retry_binding(canonical: &CanonicalRequest) -> Result<Vec<u8>> {
    let bytes = canonical.canonical_bytes()?;
    let mut value: serde_json::Value = serde_json::from_slice(&bytes)?;
    let object = value.as_object_mut().ok_or(Error("invalid_json"))?;
    object.remove("nonce");
    object.remove("exp");
    jcs(&value).map_err(Into::into)
}

/// Globs only express narrowing. A star never matches a slash; a double star may.
pub(crate) fn glob(pattern: &str, value: &str) -> bool {
    let pattern = pattern.as_bytes();
    let value = value.as_bytes();
    let mut previous = vec![false; value.len() + 1];
    previous[0] = true;
    let mut index = 0;
    while index < pattern.len() {
        let mut next = vec![false; value.len() + 1];
        match pattern[index] {
            b'*' => {
                let recursive = pattern.get(index + 1) == Some(&b'*');
                index += usize::from(recursive);
                next[0] = previous[0];
                for j in 1..=value.len() {
                    next[j] = previous[j] || (next[j - 1] && (recursive || value[j - 1] != b'/'));
                }
            }
            byte => {
                for j in 1..=value.len() {
                    next[j] = previous[j - 1] && value[j - 1] == byte;
                }
            }
        }
        previous = next;
        index += 1;
    }
    previous[value.len()]
}
