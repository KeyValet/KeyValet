//! Caller identity is supplied by the process transport, never deserialized from IPC.
use super::engine::{directory, new_id, random_nonce, Hint};
use super::store::{decode, encode, PendingState};
use super::{Error, RemoteHelper, Result};
use kv_core::remote::canonical::{from_json, jcs, sha256_hex};
use kv_core::remote::ipc::{DecideIntent, Unsigned};
use kv_core::remote::keys::{decode_b64, encode_b64, sign_object};
use kv_core::remote::validation::{approval_key, verify_grant};
use kv_core::remote::*;
use kv_ipc::remote::{allowed_ops, Caller, Op, Request, Response};
use rusqlite::{params, OptionalExtension};
use serde::de::DeserializeOwned;
use serde_json::{json, Value};
use std::sync::Arc;
use std::time::Duration;

#[derive(Clone, Copy)]
pub struct CallerContext {
    role: Caller,
    uid: u32,
    agent_pid: u32,
    runtime_budget_s: u64,
}

impl CallerContext {
    /// The real IPC runner must authenticate executable, OS peer credentials and owner first.
    /// MCP/Hook agent_pid is the authenticated peer's actual parent, not a JSON parameter.
    pub fn authenticated(role: Caller, uid: u32, agent_pid: u32, runtime_budget_s: u64) -> Self {
        Self {
            role,
            uid,
            agent_pid,
            runtime_budget_s: runtime_budget_s.min(86400),
        }
    }

    pub fn role(self) -> Caller {
        self.role
    }

    pub fn uid(self) -> u32 {
        self.uid
    }

    pub fn agent_pid(self) -> u32 {
        self.agent_pid
    }

    pub fn runtime_budget_s(self) -> u64 {
        self.runtime_budget_s
    }
}

impl RemoteHelper {
    /// Approval notifications never claim a result or expose operation parameters.
    pub async fn next_approval_notice(
        &self,
        context: CallerContext,
        seen: &mut std::collections::HashSet<String>,
    ) -> Result<Value> {
        let result = self.next_approval_notice_inner(context, seen).await;
        if let Err(error) = result.as_ref() {
            self.reject(&*self.lock()?, "approval_notification_rejected", *error, "")?;
        }
        result
    }

    async fn next_approval_notice_inner(
        &self,
        context: CallerContext,
        seen: &mut std::collections::HashSet<String>,
    ) -> Result<Value> {
        if context.role != Caller::Mcp {
            return Err(Error("forbidden"));
        }
        loop {
            let notified = self.changed.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            self.tick()?;
            {
                let state = self.lock()?;
                let ids = state
                    .store
                    .pending_ids_for_agent(context.agent_pid, self.services.clock.now())?;
                seen.retain(|id| ids.contains(id));
                for id in ids {
                    let entry = state.store.pending(&id)?;
                    if self.owns(&entry, context.uid, context.agent_pid).is_err()
                        || entry.request.exp < self.services.clock.now()
                        || entry.claimed_at.is_some()
                        || (entry.state == PendingState::Executed
                            && !state.executing.contains(&id)
                            && !state.results.contains_key(&id))
                        || !matches!(
                            entry.state,
                            PendingState::Approved
                                | PendingState::ApprovedUnused
                                | PendingState::Executed
                        )
                        || !seen.insert(id.clone())
                    {
                        continue;
                    }
                    return Ok(json!({"op": kv_ipc::remote::APPROVAL_RESOLVED,
                        "params": {"approval_id": id,
                            "status": if entry.state == PendingState::ApprovedUnused {
                                "approved_retry_required"
                            } else { "ok" }}}));
                }
            }
            notified.await;
        }
    }

    pub async fn handle(self: &Arc<Self>, context: CallerContext, request: Request) -> Response {
        if super::relay_control::is_control(request.op) {
            return super::relay_control::handle(context.role, request.op, request.params).await;
        }
        if self.lock().is_ok_and(|state| state.retired) {
            return Response::err("remote_identity_changed", "remote_identity_changed");
        }
        if !allowed_ops(context.role).contains(&request.op) {
            if let Ok(state) = self.lock() {
                let _ = self.audit(
                    &state,
                    "ipc_rejected",
                    json!({"remote_op": request.op, "reason": "forbidden", "ok": false}),
                );
            }
            return Response::err("forbidden", "forbidden");
        }
        let op = request.op;
        match self.handle_allowed(context, request).await {
            Ok(value) => Response::ok(value),
            Err(error) => {
                if let Ok(state) = self.lock() {
                    if self
                        .audit(
                            &state,
                            "ipc_rejected",
                            json!({"remote_op": op, "reason": error.code(), "ok": false}),
                        )
                        .is_err()
                    {
                        return Response::err("audit_unavailable", "audit_unavailable");
                    }
                }
                Response::err(error.code(), error.code())
            }
        }
    }

    async fn handle_allowed(
        self: &Arc<Self>,
        context: CallerContext,
        request: Request,
    ) -> Result<Value> {
        self.tick()?;
        let value = request.params;
        match request.op {
            Op::AccountRecover => super::startup::recover(context, Some(self.clone()), value).await,
            Op::AuditList => {
                let args: QueryAuditArgs = parse(value)?;
                let state = self.lock()?;
                Ok(serde_json::to_value(state.store.audit_page(
                    &args,
                    &self.account,
                    &self.local.device_id,
                    self.services.audit.as_ref(),
                )?)?)
            }
            Op::RelayControlPoll | Op::RelayControlComplete | Op::RelayControlSign => {
                Err(Error("forbidden"))
            }
            Op::RelayInbound => {
                let params: kv_core::remote::ipc::RelayInboundParams = match parse(value) {
                    Ok(params) => params,
                    Err(error) => {
                        self.reject(&*self.lock()?, "remote_message_rejected", error, "")?;
                        return Ok(json!({"ack": true}));
                    }
                };
                // inbound audits rejection before returning. Transient provider/storage/audit
                // failures stay unacked; a durably audited terminal rejection cannot poison replay.
                match self.inbound(params.envelope).await {
                    Ok(()) => Ok(json!({"ack": true})),
                    Err(error) if terminal_delivery(error) => Ok(json!({"ack": true})),
                    Err(error) => Err(error),
                }
            }
            Op::RelayIdentity => Ok(json!({"dk_pub": self.local.dk_pub,
                "device_id": self.local.device_id, "account_id": self.account})),
            Op::RelayOutboundAck => {
                let params: kv_ipc::remote::RelayOutboundAckParams<Envelope> = parse(value)?;
                Ok(json!({"retired_count": self.outbound_ack(params)?}))
            }
            Op::RelayOutboundPoll => {
                let params: kv_ipc::remote::RelayOutboundPollParams = parse(value)?;
                Ok(json!({"envelopes": self.outbound_poll(params.max_wait_ms).await?}))
            }
            Op::RelayStatus => {
                let params: kv_ipc::remote::RelayStatusParams = parse(value)?;
                let mut state = self.lock()?;
                state.relay_connected = params.connected;
                // last_error is untrusted relay text and can contain ciphertext or identifiers.
                self.audit(
                    &state,
                    if params.connected {
                        "relay_connected"
                    } else {
                        "relay_disconnected"
                    },
                    json!({}),
                )?;
                drop(state);
                self.changed.notify_waiters();
                Ok(json!({}))
            }
            Op::SignIdentity => {
                let params: kv_ipc::remote::SignIdentityParams = parse(value)?;
                let payload = decode_b64(&params.payload_b64)?;
                // The relay authentication challenge is exactly 32 random bytes. Do not expose
                // a general DK signing oracle for envelope or control-message payloads.
                if payload.len() != 32 {
                    return Err(Error("invalid_identity_challenge"));
                }
                let signature = self
                    .services
                    .identity
                    .sign(SignatureAlgorithm::ES256, &payload)?;
                Ok(json!({"sig_b64": encode_b64(&signature)}))
            }
            Op::PresenceUpdate => {
                let hint: PresenceHint = parse(value)?;
                let mut state = self.lock()?;
                let now = self.services.clock.now();
                let woke = hint.state == Presence::Present
                    && state
                        .local_hint
                        .as_ref()
                        .is_none_or(|old| old.hint.state != Presence::Present);
                if hint.device_id != self.local.device_id
                    || hint.sent_at > now.saturating_add(60)
                    || now.saturating_sub(hint.sent_at) > 120
                {
                    return Err(Error("invalid_presence_hint"));
                }
                if state
                    .local_hint
                    .as_ref()
                    .is_some_and(|old| hint.sent_at <= old.hint.sent_at)
                {
                    return Err(Error("stale_presence_hint"));
                }
                let id = new_id(now)?;
                let tx = state.store.transaction(self.services.audit.as_ref())?;
                for peer in state.store.devices(&self.account)? {
                    if peer.device_id != self.local.device_id {
                        state.store.queue(&self.seal(
                            &peer,
                            EnvelopeType::PresenceHint,
                            &id,
                            now.saturating_add(120),
                            &hint,
                        )?)?;
                    }
                }
                self.audit(&state, "presence_updated", json!({"state":hint.state}))?;
                tx.commit()?;
                state.local_hint = Some(Hint {
                    hint,
                    received_at: now,
                });
                self.changed.notify_waiters();
                drop(state);
                if woke && self.services.runner.has_private_ui() {
                    let helper = self.clone();
                    tokio::spawn(async move {
                        let _ = helper
                            .services
                            .runner
                            .private_ui("remote_wake", json!({}))
                            .await;
                    });
                }
                Ok(json!({}))
            }
            Op::PendingList => {
                let params: kv_ipc::remote::PendingListParams = parse(value)?;
                let state = self.lock()?;
                let pid = if context.role == Caller::Mcp {
                    if params.agent_pid.is_some_and(|pid| pid != context.agent_pid) {
                        return Err(Error("forbidden"));
                    }
                    Some(context.agent_pid)
                } else {
                    params.agent_pid
                };
                let mut pending = Vec::new();
                for id in state.store.pending_ids()? {
                    let entry = state.store.pending(&id)?;
                    if entry.canonical.agent.uid != context.uid
                        || pid.is_some_and(|pid| pid != entry.canonical.agent.pid)
                        || !matches!(
                            entry.state,
                            PendingState::Waiting
                                | PendingState::Approved
                                | PendingState::ApprovedUnused
                        )
                    {
                        continue;
                    }
                    pending.push(serde_json::to_value(entry.request)?);
                }
                if context.role == Caller::CliOwner {
                    pending.extend(
                        state
                            .inbound_requests
                            .values()
                            .map(serde_json::to_value)
                            .collect::<std::result::Result<Vec<_>, _>>()?,
                    );
                }
                drop(state);
                if context.role == Caller::CliOwner {
                    Ok(json!({"pending": pending, "recent":self.recent_decisions()?}))
                } else {
                    Ok(json!({"pending": pending}))
                }
            }
            Op::PendingForAgent => {
                let params: kv_ipc::remote::PendingForAgentParams = parse(value)?;
                if params.agent_pid != context.agent_pid {
                    return Err(Error("forbidden"));
                }
                let state = self.lock()?;
                let mut pending = Vec::new();
                for id in state
                    .store
                    .pending_ids_for_agent(context.agent_pid, self.services.clock.now())?
                {
                    let entry = state.store.pending(&id)?;
                    if self.owns(&entry, context.uid, context.agent_pid).is_err()
                        || entry.claimed_at.is_some()
                        || !matches!(
                            entry.state,
                            PendingState::Waiting
                                | PendingState::Approved
                                | PendingState::ApprovedUnused
                        )
                    {
                        continue;
                    }
                    let blocks: u32 = state.store.db.query_row(
                        "SELECT stop_hook_blocks FROM pending_approvals WHERE id=?1",
                        [&id],
                        |r| r.get(0),
                    )?;
                    pending.push(json!({"approval_id": id, "expires_at": entry.request.exp, "stop_hook_blocks": blocks}));
                }
                Ok(json!({"pending": pending}))
            }
            Op::PendingStopBlock => {
                let params: kv_ipc::remote::ApprovalIdParams = parse(value)?;
                let state = self.lock()?;
                let entry = state.store.pending(&params.approval_id)?;
                self.owns(&entry, context.uid, context.agent_pid)?;
                let active = matches!(
                    entry.state,
                    PendingState::Waiting | PendingState::Approved | PendingState::ApprovedUnused
                ) && entry.request.exp >= self.services.clock.now()
                    && entry.claimed_at.is_none();
                let transaction = state.store.transaction(self.services.audit.as_ref())?;
                let changed = if active {
                    transaction.execute("UPDATE pending_approvals SET stop_hook_blocks=stop_hook_blocks+1 WHERE id=?1 AND stop_hook_blocks<?2",
                    params![params.approval_id, self.config.stop_hook_max_blocks])?
                } else {
                    0
                };
                let blocks: u32 = transaction.query_row(
                    "SELECT stop_hook_blocks FROM pending_approvals WHERE id=?1",
                    [&params.approval_id],
                    |r| r.get(0),
                )?;
                // The UPDATE predicate already enforces blocks < max; zero changes for a
                // live row means the budget is exhausted.
                if active && changed == 0 {
                    let key = format!("stop_exhausted:{}", params.approval_id);
                    if state.store.setting::<bool>(&key)?.is_none() {
                        state
                            .store
                            .set_setting(&key, &true, "local", self.services.clock.now())?;
                        self.audit(
                            &state,
                            "stop_hook_exhausted",
                            json!({"approval_id":params.approval_id,
                            "agent_pid":context.agent_pid,"blocks":blocks}),
                        )?;
                    }
                }
                transaction.commit()?;
                Ok(
                    json!({"allowed": changed == 1, "blocks_left": self.config.stop_hook_max_blocks.saturating_sub(blocks)}),
                )
            }
            Op::Wait => {
                let params: kv_ipc::remote::WaitParams = parse(value)?;
                let budget = params
                    .extra
                    .get("runtime_budget_s")
                    .and_then(Value::as_u64)
                    .unwrap_or(context.runtime_budget_s.min(50))
                    .min(context.runtime_budget_s);
                // The established transport cancels in-flight work when its peer disappears.
                // A cancelled wait is an observed disconnect, never a denial of approval.
                let result = self
                    .wait(
                        &params.approval_id,
                        params.max_wait_ms,
                        budget,
                        context.uid,
                        context.agent_pid,
                    )
                    .await;
                Ok(serde_json::to_value(result?)?)
            }
            Op::Decide => {
                self.issue_decision(parse(value)?).await?;
                Ok(json!({"sent": true}))
            }
            Op::GrantIssue => {
                if value.get("source").is_some() {
                    return self.issue_grant_intent(context, parse(value)?).await;
                }
                let grant: Unsigned<Grant> = parse(value)?;
                if grant.0.scope.max_tier == Tier::T2 {
                    return Err(Error("secondary_confirmation_required"));
                }
                Ok(json!({"grant": self.issue_grant(grant.0).await?}))
            }
            Op::GrantList => {
                let query: kv_ipc::remote::GrantListParams = parse(value)?;
                let installed = self.installed_grants_page(&*self.lock()?, &query)?;
                let mut grants = self.issued_grants_page(&query)?;
                for local in installed {
                    if let Some(issued) =
                        grants.iter_mut().find(|grant| grant["jti"] == local["jti"])
                    {
                        issued["installed"] = json!(true);
                        issued["local_usage"] = json!({"budget_left":local["budget_left"],"uses_n":local["uses_n"],
                            "last_used_at":local["last_used_at"],"revoked_at":local["revoked_at"],"device_id":self.local.device_id});
                    } else {
                        grants.push(local);
                    }
                }
                super::pages::page(grants, &query)
            }
            Op::GrantRevoke => {
                let params: kv_ipc::remote::GrantRevokeParams = parse(value)?;
                self.revoke_owner_grant(&params.jti).await?;
                Ok(json!({}))
            }
            Op::DirectiveIssue => {
                if value.get("iss").is_none() {
                    return Ok(json!({"result":self.issue_directive_intent(parse(value)?).await?}));
                }
                let directive: Unsigned<Directive> = parse(value)?;
                Ok(json!({"result": self.issue_directive(directive.0).await?}))
            }
            Op::PairStart => {
                if super::startup::current().is_some()
                    && super::server::runtime()
                        .is_some_and(|current| std::sync::Arc::ptr_eq(&current, self))
                {
                    return super::startup::pair_existing(
                        self.clone(),
                        context,
                        Op::PairStart,
                        value,
                    )
                    .await;
                }
                let relay_url = value
                    .get("relay_url")
                    .and_then(Value::as_str)
                    .ok_or(Error("invalid_relay_url"))?;
                if self.lock()?.store.setting::<String>("relay_url")?.is_some() {
                    let mut result = self.pair_start_network(relay_url).await?;
                    result.extra.insert("binding".into(),json!({"relay_url":relay_url,"device_id":self.local.device_id,"account_id":self.account}));
                    Ok(serde_json::to_value(result)?)
                } else {
                    Ok(serde_json::to_value(self.pair_start(relay_url)?)?)
                }
            }
            Op::PairComplete => {
                if value.get("uri").is_some() {
                    return super::startup::pair_existing(
                        self.clone(),
                        context,
                        Op::PairComplete,
                        value,
                    )
                    .await;
                }
                Ok(serde_json::to_value(self.pair_complete(parse(value)?)?)?)
            }
            Op::PairConfirm => {
                if value.get("confirmed").is_some() {
                    if self
                        .lock()?
                        .pairing
                        .as_ref()
                        .is_some_and(|pairing| pairing.transport.is_some())
                    {
                        self.pair_confirm_owner(parse(value)?).await?;
                    } else {
                        let intent: kv_ipc::remote::PairConfirmIntent = parse(value)?;
                        if !intent.confirmed {
                            return Err(Error("user_cancelled"));
                        }
                        self.pair_confirm_terminal(&PairConfirm {
                            sas: intent.sas,
                            sig: String::new(),
                            extra: json!({"exclude_global":intent.exclude_global})
                                .as_object()
                                .unwrap()
                                .clone(),
                        })?;
                    }
                    return Ok(json!({}));
                }
                if context.role == Caller::CliOwner {
                    self.pair_confirm_terminal(&parse(value)?)?;
                } else {
                    self.pair_confirm_signed(&parse(value)?)?;
                }
                Ok(json!({}))
            }
            Op::DevicesList => Ok(
                json!({"devices": directory(&self.lock()?.store)?.into_iter().map(|(device, revoked)| {
                let mut value = serde_json::to_value(device).unwrap_or(Value::Null);
                value["revoked"] = json!(revoked); value["attestation_status"] = json!("unverified"); value
            }).collect::<Vec<_>>()}),
            ),
            Op::DevicesRevoke => {
                let params: kv_ipc::remote::DeviceIdParams = parse(value)?;
                self.revoke_owner_device(&params.device_id).await?;
                Ok(json!({}))
            }
            Op::DevicesRename => {
                let params: kv_ipc::remote::DeviceRenameParams = parse(value)?;
                if params.label.is_empty() {
                    return Err(Error("invalid_device_label"));
                }
                let remote_target = {
                    let state = self.lock()?;
                    params.device_id != self.local.device_id
                        && state.store.setting::<String>("relay_url")?.is_some()
                        && state
                            .store
                            .device(&params.device_id, &self.account)?
                            .caps
                            .contains(&Capability::Execute)
                };
                if remote_target {
                    let result = self
                        .issue_directive_intent(kv_core::remote::ipc::DirectiveIntent {
                            kind: DirectiveKind::Directive,
                            aud: params.device_id,
                            op: DirectiveOp::SetDeviceLabel,
                            args: json!({"label":params.label}).as_object().unwrap().clone(),
                        })
                        .await?;
                    if !result.ok {
                        return Err(Error("device_rename_failed"));
                    }
                    return Ok(json!({}));
                }
                self.services
                    .runner
                    .local_authorize(
                        "rename_device",
                        json!({"device_id": params.device_id, "label": params.label}),
                    )
                    .await
                    .and_then(require_strong)?;
                let state = self.lock()?;
                let transaction = state.store.transaction(self.services.audit.as_ref())?;
                self.rename_device_rows(&state, &params.device_id, &params.label)?;
                let directory_update = self.stage_directory(&state)?;
                self.audit(
                    &state,
                    "device_renamed",
                    json!({"device_id": params.device_id, "by": "local"}),
                )?;
                transaction.commit()?;
                directory_update.commit()?;
                Ok(json!({}))
            }
            Op::Status => {
                let state = self.lock()?;
                let mut status = self.status_locked(&state, context.runtime_budget_s)?;
                if context.role == Caller::CliOwner {
                    status["pairing"] = self.pairing_status(&state)?;
                }
                Ok(status)
            }
            Op::ClientTimeoutObserved => {
                // Model-provided text, PID, request id and clientInfo are not audit authority.
                self.audit(
                    &*self.lock()?,
                    "client_timeout_observed",
                    json!({"agent_pid":context.agent_pid,"uid":context.uid,"runtime_budget_s":50}),
                )?;
                Ok(json!({}))
            }
        }
    }

    pub async fn outbound_poll(&self, max_wait_ms: u64) -> Result<Vec<Envelope>> {
        let deadline = tokio::time::Instant::now() + Duration::from_millis(max_wait_ms.min(30000));
        loop {
            let notified = self.changed.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            self.tick()?;
            let messages = {
                let state = self.lock()?;
                let rows = {
                    let mut statement = state.store.db.prepare(
                        "SELECT seq, envelope_json FROM remote_outbox WHERE exp>=?1 ORDER BY seq",
                    )?;
                    let rows = statement.query_map([self.services.clock.now()], |r| {
                        Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?))
                    })?;
                    rows.collect::<std::result::Result<Vec<_>, _>>()?
                };
                let mut messages = Vec::new();
                let mut bytes = 256usize;
                for (_, encoded) in rows {
                    let receipt: Option<String> = state
                        .store
                        .db
                        .query_row(
                            "SELECT stage FROM remote_outbox_receipts WHERE envelope_hash=?1",
                            [kv_core::remote::canonical::sha256_hex(encoded.as_bytes())],
                            |r| r.get(0),
                        )
                        .optional()?;
                    if receipt.is_some_and(|stage| stage != "pending") {
                        continue;
                    }
                    if bytes.saturating_add(encoded.len() + 1) >= kv_ipc::MAX_LINE_BYTES {
                        break;
                    }
                    bytes += encoded.len() + 1;
                    messages.push(decode(&encoded)?);
                    if messages.len() >= 64 {
                        break;
                    }
                }
                messages
            };
            if !messages.is_empty() || tokio::time::Instant::now() >= deadline {
                return Ok(messages);
            }
            tokio::select! { _ = &mut notified => {}, _ = tokio::time::sleep_until(deadline) => {} }
        }
    }

    pub(crate) async fn issue_decision(&self, params: DecideIntent) -> Result<()> {
        self.issue_selected_decision(params, false).await
    }

    pub(crate) async fn issue_selected_decision(
        &self,
        params: DecideIntent,
        already_selected: bool,
    ) -> Result<()> {
        let request = {
            self.lock()?
                .inbound_requests
                .get(&params.approval_id)
                .cloned()
                .ok_or(Error("not_waiting"))?
        };
        if request.exp < self.services.clock.now() {
            return Err(Error("expired"));
        }
        let scope = match params.scope_option.as_deref() {
            Some(option) => super::owner::decision_scope(option, self.services.clock.now())?,
            None => params.scope,
        };
        let minimum = if request.kind != ApprovalKind::Use
            || request.tier == Tier::T2
            || scope.mode == ScopeMode::Standing
        {
            ApprovalLevel::Strong
        } else {
            request.min_level
        };
        let mut level = params.level.unwrap_or(minimum);
        if level < minimum {
            return Err(Error("insufficient_level"));
        }
        if level == ApprovalLevel::Quick && approval_key(&self.local, level).is_err() {
            level = ApprovalLevel::Strong;
        }
        if params.reason.as_ref().is_some_and(|reason| {
            reason.chars().count() > 512 || reason.chars().any(char::is_control)
        }) {
            return Err(Error("invalid_approval_request"));
        }
        let mut decision = ApprovalDecision {
            approval_id: request.approval_id.clone(),
            digest: request.digest.clone(),
            nonce: request.nonce.clone(),
            decision: params.decision,
            level,
            scope,
            approver: self.local.device_id.clone(),
            approver_kind: ApproverKind::Device,
            quorum: Optional::Missing,
            issued_at: self.services.clock.now(),
            reason: params.reason.map_or(Optional::Missing, Optional::Value),
            sig: String::new(),
            extra: Extra::new(),
        };
        super::pipeline::validate_decision_scope(&decision, &request)?;
        if !already_selected {
            let unattended = self.status_locked(&*self.lock()?, 60)?["unattended"].clone();
            self.services
            .runner
            .local_authorize(
                "remote_decide",
                json!({"request": request, "decision": decision.decision, "scope": decision.scope,
                    "scope_option":params.scope_option,"minimum_level":decision.level,"unattended":unattended}),
            )
            .await
            .and_then(|level| {
                if level >= decision.level {
                    Ok(())
                } else {
                    Err(Error("insufficient_level"))
                }
            })?;
        }
        let duration = decision.scope.until.saturating_sub(decision.issued_at);
        decision.issued_at = self.services.clock.now();
        if decision.scope.mode == ScopeMode::Remember {
            decision.scope.until = decision.issued_at.saturating_add(duration);
        }
        super::pipeline::validate_decision_scope(&decision, &request)?;
        let provider = self.approval_provider(level)?;
        decision.sig = sign_object(&decision, approval_key(&self.local, level)?.alg, provider)?;
        let mut state = self.lock()?;
        if state.inbound_requests.get(&params.approval_id) != Some(&request) {
            return Err(Error("not_waiting"));
        }
        if request.exp < self.services.clock.now() {
            return Err(Error("expired"));
        }
        let peer = state
            .store
            .device(&request.requester.device_id, &self.account)?;
        let transaction = state.store.transaction(self.services.audit.as_ref())?;
        transaction.execute("INSERT INTO issued_approvals (approval_id, peer, kind, digest, decision, level, scope_json, issued_at, summary_text) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![decision.approval_id, peer.device_id, encode(&request.kind)?.trim_matches('"'), decision.digest,
                encode(&decision.decision)?.trim_matches('"'), encode(&decision.level)?.trim_matches('"'), encode(&decision.scope)?, decision.issued_at,
                request.operation.as_ref().map(|operation| operation.summary.as_str()).unwrap_or("")])?;
        transaction.execute(
            "INSERT INTO approval_history(approval_id) VALUES(?1)",
            [&decision.approval_id],
        )?;
        state.store.queue(&self.seal(
            &peer,
            EnvelopeType::ApprovalDecision,
            &decision.approval_id,
            request.exp,
            &decision,
        )?)?;
        self.audit(&state, "remote_approval_issued", json!({"approval_id": decision.approval_id, "digest": decision.digest, "peer": peer.device_id,
            "approval_level": decision.level, "decision": decision.decision, "decision_hash": sha256_hex(&jcs(&decision)?)}))?;
        transaction.commit()?;
        state.inbound_requests.remove(&params.approval_id);
        self.changed.notify_waiters();
        Ok(())
    }

    async fn issue_grant(&self, grant: Grant) -> Result<Grant> {
        if grant.iss != self.local.device_id || grant.iss_kind != IssuerKind::Device {
            return Err(Error("wrong_sender"));
        }
        let level = ApprovalLevel::Strong;
        let peers = self.execution_peers(&grant.aud)?;
        if grant.scope.max_tier == Tier::T2
            && peers
                .iter()
                .any(|peer| grant.confirm.as_value() != Some(&peer.label))
        {
            return Err(Error("secondary_confirmation_required"));
        }
        self.services
            .runner
            .local_authorize(
                "issue_grant",
                serde_json::to_value(Unsigned(grant.clone()))?,
            )
            .await
            .and_then(|actual| {
                if actual >= level {
                    Ok(())
                } else {
                    Err(Error("insufficient_level"))
                }
            })?;
        let key = approval_key(&self.local, level)?;
        if grant.iss_alg != key.alg {
            return Err(Error("unsupported_algorithm"));
        }
        self.sign_and_send_grant(grant, &peers)
    }

    pub(crate) fn sign_and_send_grant(
        &self,
        mut grant: Grant,
        peers: &[DeviceRecord],
    ) -> Result<Grant> {
        let level = ApprovalLevel::Strong;
        let key = approval_key(&self.local, level)?;
        grant.sig = sign_object(&grant, key.alg, self.approval_provider(level)?)?;
        for peer in peers {
            verify_grant(
                &grant,
                &peer.device_id,
                &peer.label,
                &self.local,
                level,
                self.services.clock.now(),
            )?;
        }
        let state = self.lock()?;
        for peer in peers {
            if state.store.device(&peer.device_id, &self.account)? != *peer
                || (grant.aud == "*"
                    && state
                        .store
                        .setting::<bool>(&format!("global_excluded:{}", peer.device_id))?
                        .unwrap_or(false))
            {
                return Err(Error("wrong_recipient"));
            }
        }
        let transaction = state.store.transaction(self.services.audit.as_ref())?;
        transaction.execute("INSERT INTO issued_grants (jti, peer, level, credential, max_tier, exp, origin, issued_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![grant.jti, grant.aud, encode(&level)?.trim_matches('"'), grant.scope.credential.as_value(), encode(&grant.scope.max_tier)?.trim_matches('"'),
                grant.exp, grant.origin, self.services.clock.now()])?;
        transaction.execute(
            "INSERT INTO issued_grant_objects(jti,object_json,issued_at) VALUES(?1,?2,?3)",
            params![grant.jti, encode(&grant)?, self.services.clock.now()],
        )?;
        for peer in peers {
            if peer.device_id == self.local.device_id {
                self.save_grant(&state, &grant, &json!({"kind":"grant","level":level}), None)?;
                self.audit(
                    &state,
                    "grant_installed",
                    json!({"jti":grant.jti,"iss":grant.iss,"max_tier":grant.scope.max_tier,"grant_hash":sha256_hex(&jcs(&grant)?)}),
                )?;
                continue;
            }
            state.store.queue(
                &self.seal(
                    peer,
                    EnvelopeType::Grant,
                    &grant.jti,
                    grant
                        .exp
                        .unwrap_or_else(|| self.services.clock.now().saturating_add(86400)),
                    &grant,
                )?,
            )?;
        }
        self.audit(
            &state,
            "grant_issued",
            json!({"jti": grant.jti, "iss": grant.iss, "aud": grant.aud, "recipients":peers.iter().map(|p|&p.device_id).collect::<Vec<_>>(), "max_tier": grant.scope.max_tier, "grant_hash":sha256_hex(&jcs(&grant)?)}),
        )?;
        transaction.commit()?;
        self.changed.notify_waiters();
        Ok(grant)
    }

    async fn issue_directive(&self, directive: Directive) -> Result<DirectiveResult> {
        let level = self
            .services
            .runner
            .local_authorize(
                "issue_directive",
                serde_json::to_value(Unsigned(directive.clone()))?,
            )
            .await?;
        self.publish_directive(directive, level).await
    }

    pub(crate) async fn send_directive(
        &self,
        directive: Directive,
        minimum: ApprovalLevel,
    ) -> Result<DirectiveResult> {
        let actual = self
            .services
            .runner
            .local_authorize(
                "issue_directive",
                json!({"directive":Unsigned(directive.clone()),"minimum_level":minimum}),
            )
            .await?;
        if actual < minimum {
            return Err(Error("insufficient_level"));
        }
        self.publish_directive(directive, minimum).await
    }

    async fn publish_directive(
        &self,
        mut directive: Directive,
        level: ApprovalLevel,
    ) -> Result<DirectiveResult> {
        if directive.iss != self.local.device_id || directive.iss_kind != IssuerKind::Device {
            return Err(Error("wrong_sender"));
        }
        let peers = {
            self.lock()?
                .store
                .devices(&self.account)?
                .into_iter()
                .filter(|peer| {
                    peer.caps.contains(&Capability::Execute)
                        && (directive.aud == "*" || directive.aud == peer.device_id)
                })
                .collect::<Vec<_>>()
        };
        // A single DirectiveResult cannot represent independent results from a broadcast.
        if peers.len() != 1 {
            return Err(Error("directive_requires_single_peer"));
        }
        let key = approval_key(&self.local, level)?;
        if key.alg != directive.iss_alg {
            return Err(Error("unsupported_algorithm"));
        }
        if directive.id.is_empty() {
            directive.id = new_id(self.services.clock.now())?;
        }
        if directive.nonce.is_empty() {
            directive.nonce = random_nonce()?;
        }
        if directive.exp < self.services.clock.now()
            || directive.exp > self.services.clock.now().saturating_add(600)
        {
            return Err(Error("expired"));
        }
        directive.sig = sign_object(&directive, key.alg, self.approval_provider(level)?)?;
        {
            let state = self.lock()?;
            let transaction = state.store.transaction(self.services.audit.as_ref())?;
            transaction.execute(
                "INSERT INTO issued_directives (id, peer, op, issued_at) VALUES (?1, ?2, ?3, ?4)",
                params![
                    directive.id,
                    peers[0].device_id,
                    encode(&directive.op)?.trim_matches('"'),
                    self.services.clock.now()
                ],
            )?;
            transaction.execute(
                "INSERT INTO issued_directive_objects(id,object_json) VALUES(?1,?2)",
                params![directive.id, encode(&directive)?],
            )?;
            if peers[0].device_id != self.local.device_id {
                state.store.queue(&self.seal(
                    &peers[0],
                    EnvelopeType::Directive,
                    &directive.id,
                    directive.exp,
                    &directive,
                )?)?;
            }
            self.audit(&state, "directive_issued", json!({"id": directive.id, "directive_op": directive.op, "peer": peers[0].device_id, "directive_hash":sha256_hex(&jcs(&directive)?)}))?;
            transaction.commit()?;
        }
        self.changed.notify_waiters();
        if peers[0].device_id == self.local.device_id {
            let result = self.apply_directive(&directive, level)?;
            let state = self.lock()?;
            let tx = state.store.transaction(self.services.audit.as_ref())?;
            tx.execute(
                "UPDATE issued_directives SET result_ok=?1,result_summary=?2 WHERE id=?3",
                params![result.ok, result.error, result.id],
            )?;
            self.cache_directive_result(&state, &peers[0], &result)?;
            self.audit(
                &state,
                "directive_result",
                json!({"id":result.id,"peer":self.local.device_id,"ok":result.ok}),
            )?;
            tx.commit()?;
            return Ok(result);
        }
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        loop {
            let notified = self.changed.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if let Some((_, result)) = self.lock()?.directive_results.remove(&directive.id) {
                return Ok(result);
            }
            if tokio::time::Instant::now() >= deadline {
                return Err(Error("directive_result_timeout"));
            }
            tokio::select! { _ = &mut notified => {}, _ = tokio::time::sleep_until(deadline) => {} }
        }
    }

    pub(crate) fn approval_provider(
        &self,
        level: ApprovalLevel,
    ) -> Result<&(dyn DeviceKeyProvider + Send + Sync)> {
        match level {
            ApprovalLevel::Quick => self.services.quick.as_deref(),
            ApprovalLevel::Strong => self.services.strong.as_deref(),
        }
        .ok_or(Error("key_unavailable"))
    }
}

fn parse<T: DeserializeOwned>(value: Value) -> Result<T> {
    from_json(&jcs(&value)?).map_err(Into::into)
}
fn require_strong(level: ApprovalLevel) -> Result<()> {
    if level == ApprovalLevel::Strong {
        Ok(())
    } else {
        Err(Error("insufficient_level"))
    }
}

fn terminal_delivery(error: Error) -> bool {
    matches!(
        error.code(),
        "unsupported_version"
            | "unsupported_type"
            | "global_grant_excluded"
            | "pair_key_mismatch"
            | "wrong_pairing"
            | "wrong_recipient"
            | "wrong_account"
            | "wrong_sender"
            | "unpaired_device"
            | "untrusted_device"
            | "revoked_device"
            | "unsupported_authority"
            | "expired"
            | "invalid_json"
            | "invalid_encoding"
            | "invalid_key"
            | "unsupported_algorithm"
            | "invalid_signature"
            | "decryption_failed"
            | "payload_too_large"
            | "digest_mismatch"
            | "nonce_mismatch"
            | "insufficient_level"
            | "invalid_scope"
            | "invalid_grant"
            | "invalid_directive"
            | "missing_state"
            | "replay"
            | "not_waiting"
            | "already_consumed"
            | "invalid_approval_request"
            | "unexpected_directive_result"
            | "stale_presence_hint"
    )
}
