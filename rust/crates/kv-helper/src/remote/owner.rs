//! Public owner intents are completed and authorized only inside the helper.

use super::engine::{new_id, random_nonce};
use super::ipc::CallerContext;
use super::store::{decode, encode};
use super::{Error, RemoteHelper, Result};
use kv_core::remote::canonical::{jcs, sha256_hex};
use kv_core::remote::ipc::{DirectiveIntent, GrantConfirmation, GrantIntent, GrantSource};
use kv_core::remote::keys::{sign_object, verify_object};
use kv_core::remote::validation::{approval_key, directive_required_level, DirectiveState};
use kv_core::remote::*;
use kv_ipc::remote::Caller;
use rusqlite::{params, OptionalExtension};
use serde_json::{json, Value};

pub(crate) struct Confirmation {
    draft_hash: String,
    grant: Grant,
    peer: DeviceRecord,
    uid: u32,
    pid: u32,
    role: Caller,
    confirmations_left: u8,
    pub expires_at: i64,
}

impl RemoteHelper {
    pub(crate) fn present_incoming(
        self: &std::sync::Arc<Self>,
        id: &str,
        escalated: bool,
    ) -> Result<()> {
        let mut request = {
            let mut state = self.lock()?;
            let Some(request) = state.inbound_requests.get(id).cloned() else {
                return Ok(());
            };
            if (!escalated && request.delivery.mode == DeliveryMode::Silent)
                || !state.presenting.insert(id.into())
            {
                return Ok(());
            }
            request
        };
        if escalated {
            request.delivery.mode = DeliveryMode::Banner;
        }
        let helper = self.clone();
        tokio::spawn(async move {
            let result = async {
                let unattended = helper.status_locked(&*helper.lock()?, 60)?["unattended"].clone();
                let reply = helper
                    .services
                    .runner
                    .private_ui(
                        "remote_approval",
                        json!({
                            "request":request, "context":{"now":helper.services.clock.now(),
                                "unattended":unattended}
                        }),
                    )
                    .await?;
                if reply["ok"] != true {
                    return Err(Error("user_cancelled"));
                }
                let params: kv_core::remote::ipc::DecideIntent =
                    serde_json::from_value(reply["params"].clone())?;
                if params.approval_id != request.approval_id {
                    return Err(Error("invalid_approval_request"));
                }
                helper.issue_selected_decision(params, true).await
            }
            .await;
            if let Ok(mut state) = helper.lock() {
                state.presenting.remove(&request.approval_id);
                if let Err(error) = result {
                    let _ =
                        helper.reject(&state, "remote_ui_rejected", error, &request.approval_id);
                }
            }
        });
        Ok(())
    }
    pub(crate) fn cache_directive_result(
        &self,
        state: &super::engine::State,
        peer: &DeviceRecord,
        result: &DirectiveResult,
    ) -> Result<()> {
        let object: Option<String> = state
            .store
            .db
            .query_row(
                "SELECT object_json FROM issued_directive_objects WHERE id=?1",
                [&result.id],
                |r| r.get(0),
            )
            .optional()?;
        let Some(object) = object else {
            return Ok(());
        };
        let directive: Directive = decode(&object)?;
        if !result.ok {
            return Ok(());
        }
        let now = self.services.clock.now();
        match directive.op {
            DirectiveOp::SetDeviceLabel => {
                if let Some(label) = directive.args.get("label").and_then(Value::as_str) {
                    if result.state.get("label").and_then(Value::as_str) != Some(label) {
                        return Err(Error("unexpected_directive_result"));
                    }
                    self.rename_device_rows(state, &peer.device_id, label)?;
                }
            }
            DirectiveOp::QueryStatus => {
                if let Some(label) = result.state.get("label").and_then(Value::as_str) {
                    self.rename_device_rows(state, &peer.device_id, label)?;
                }
                let current = DirectiveStateWire {
                    mode: result
                        .state
                        .get("mode")
                        .and_then(Value::as_str)
                        .map(str::to_owned),
                    unlock_ttl_s: result.state.get("unlock_ttl_s").and_then(Value::as_u64),
                    classes: Default::default(),
                };
                state.store.set_setting(
                    &format!("peer_settings:{}", peer.device_id),
                    &current,
                    "remote",
                    now,
                )?;
                state.store.db.execute("INSERT INTO peer_state_cache(peer,mode,unattended,grants_count,pending_count,fetched_at)
                    VALUES(?1,?2,?3,?4,?5,?6) ON CONFLICT(peer) DO UPDATE SET mode=excluded.mode,unattended=excluded.unattended,
                    grants_count=excluded.grants_count,pending_count=excluded.pending_count,fetched_at=excluded.fetched_at",
                    params![peer.device_id,current.mode,result.state.get("unattended").and_then(Value::as_bool),
                        result.state.get("grants_n").and_then(Value::as_u64),result.state.get("pending_n").and_then(Value::as_u64),now])?;
            }
            DirectiveOp::QueryGrants => {
                if let Some(grants) = result.state.get("grants").and_then(Value::as_array) {
                    for grant in grants.iter().take(200) {
                        let Some(jti) = grant["jti"].as_str() else {
                            continue;
                        };
                        // A derived approval Grant is reported as executor state, never as a
                        // newly signed Grant. Correlate it with our own signed Allow history.
                        if let Some(id) = grant["origin"]
                            .as_str()
                            .and_then(|s| s.strip_prefix("approval:"))
                        {
                            let approved:bool = state.store.db.query_row("SELECT EXISTS(SELECT 1 FROM issued_approvals
                                WHERE approval_id=?1 AND peer=?2 AND decision='allow' AND scope_json IS NOT NULL)",
                                params![id,peer.device_id],|r|r.get(0))?;
                            if approved
                                && grant["object_omitted"] != true
                                && grant["iss"] == self.local.device_id
                                && jti == format!("approval:{id}")
                                && grant["sig"] == ""
                                && grant["scope"]["max_tier"] == "T1"
                            {
                                let object: Grant = serde_json::from_value(grant.clone())?;
                                state.store.db.execute("INSERT OR IGNORE INTO issued_grants
                                    (jti,peer,level,credential,max_tier,exp,origin,issued_at)
                                    SELECT ?1,?2,level,?3,'T1',?4,?5,?6 FROM issued_approvals WHERE approval_id=?7",
                                    params![jti,peer.device_id,object.scope.credential.as_value(),object.exp,object.origin,object.nbf,id])?;
                                state.store.db.execute("INSERT OR IGNORE INTO issued_grant_objects(jti,object_json,issued_at) VALUES(?1,?2,?3)",
                                    params![jti,encode(&object)?,object.nbf])?;
                            }
                        }
                        let issued: bool = state.store.db.query_row(
                            "SELECT EXISTS(SELECT 1 FROM issued_grants WHERE jti=?1 AND (peer=?2 OR peer='*'))",
                            params![jti,peer.device_id],|r|r.get(0))?;
                        if !issued {
                            continue;
                        }
                        if let Some(revoked) = grant["revoked_at"].as_i64() {
                            state.store.db.execute("UPDATE issued_grants SET revoked_at=COALESCE(revoked_at,?1) WHERE jti=?2 AND peer=?3",
                                params![revoked,jti,peer.device_id])?;
                            state.store.db.execute("UPDATE issued_grant_objects SET revoked_at=COALESCE(revoked_at,?1) WHERE jti IN
                                (SELECT jti FROM issued_grants WHERE jti=?2 AND peer=?3)",params![revoked,jti,peer.device_id])?;
                        }
                        let usage = json!({"budget_left":grant["budget_left"],"uses_n":grant["uses_n"],
                            "last_used_at":grant["last_used_at"],"revoked_at":grant["revoked_at"],"fetched_at":now,"device_id":peer.device_id});
                        state.store.db.execute("INSERT INTO issued_grant_usage(jti,peer,usage_json,fetched_at) VALUES(?1,?2,?3,?4)
                            ON CONFLICT(jti,peer) DO UPDATE SET usage_json=excluded.usage_json,fetched_at=excluded.fetched_at",
                            params![jti,peer.device_id,encode(&usage)?,now])?;
                    }
                }
            }
            DirectiveOp::RevokeGrant | DirectiveOp::RevokeAllGrants => {
                let jti = directive.args.get("jti").and_then(Value::as_str);
                state.store.db.execute("UPDATE issued_grants SET revoked_at=COALESCE(revoked_at,?1) WHERE peer=?2 AND (?3 IS NULL OR jti=?3)",params![now,peer.device_id,jti])?;
                state.store.db.execute("UPDATE issued_grant_objects SET revoked_at=COALESCE(revoked_at,?1) WHERE jti IN
                    (SELECT jti FROM issued_grants WHERE peer=?2 AND (?3 IS NULL OR jti=?3))",params![now,peer.device_id,jti])?;
                state.store.db.execute("UPDATE issued_grant_revocation_targets SET confirmed_at=COALESCE(confirmed_at,?1)
                    WHERE peer=?2 AND (?3 IS NULL OR jti=?3)",params![now,peer.device_id,jti])?;
                state.store.db.execute("UPDATE issued_grant_revocations SET confirmed_at=?1 WHERE confirmed_at IS NULL AND NOT EXISTS
                    (SELECT 1 FROM issued_grant_revocation_targets t WHERE t.jti=issued_grant_revocations.jti AND t.confirmed_at IS NULL)",[now])?;
                state.store.db.execute(
                    "UPDATE issued_grants SET revoked_at=COALESCE(revoked_at,?1) WHERE jti IN
                    (SELECT jti FROM issued_grant_revocations WHERE confirmed_at IS NOT NULL)",
                    [now],
                )?;
                state.store.db.execute("UPDATE issued_grant_objects SET revoked_at=COALESCE(revoked_at,?1) WHERE jti IN
                    (SELECT jti FROM issued_grant_revocations WHERE confirmed_at IS NOT NULL)",[now])?;
            }
            _ => {}
        }
        Ok(())
    }
    pub(crate) async fn issue_grant_intent(
        &self,
        context: CallerContext,
        mut intent: GrantIntent,
    ) -> Result<Value> {
        let now = self.services.clock.now();
        if intent.origin != "settings"
            || intent.nbf > now
            || intent.exp.is_some_and(|exp| exp <= now)
            || (intent.scope.level == GrantScopeLevel::Credential
                && intent
                    .scope
                    .credential
                    .as_value()
                    .is_none_or(String::is_empty))
            || (intent.scope.level == GrantScopeLevel::Global) != (intent.aud == "*")
            || intent
                .budget
                .as_ref()
                .is_some_and(|budget| budget.calls == 0 || budget.bytes.as_value() == Some(&0))
        {
            return Err(Error("invalid_grant"));
        }
        if intent.scope.max_tier == Tier::T2
            && (intent.source != GrantSource::Settings || intent.aud == "*")
        {
            return Err(Error("secondary_confirmation_required"));
        }
        let token = intent.confirmation_token.take();
        let label = intent.confirm.take();
        let draft_hash = sha256_hex(&jcs(&intent)?);
        let peers = self.execution_peers(&intent.aud)?;
        let key = approval_key(&self.local, ApprovalLevel::Strong)?;
        let mut grant = Grant {
            kind: GrantKind::Grant,
            jti: new_id(now)?,
            iss: self.local.device_id.clone(),
            iss_alg: key.alg,
            iss_kind: IssuerKind::Device,
            aud: intent.aud.clone(),
            scope: intent.scope.clone(),
            budget: intent
                .budget
                .clone()
                .map_or(Optional::Missing, Optional::Value),
            nbf: now,
            exp: intent.exp,
            origin: "settings".into(),
            confirm: Optional::Missing,
            sig: String::new(),
            extra: Extra::new(),
        };
        if intent.scope.max_tier == Tier::T2 {
            if let Some(token) = token {
                // Consume before validation: even a failed final attempt cannot reuse a proof.
                let prepared = self
                    .lock()?
                    .confirmations
                    .remove(&sha256_hex(token.as_bytes()))
                    .ok_or(Error("secondary_confirmation_required"))?;
                if prepared.expires_at <= now {
                    return Err(Error("expired"));
                }
                if prepared.uid != context.uid()
                    || prepared.pid != context.agent_pid()
                    || prepared.role != context.role()
                    || prepared.draft_hash != draft_hash
                    || peers.len() != 1
                    || prepared.peer != peers[0]
                    || label.as_deref() != Some(prepared.peer.label.as_str())
                {
                    return Err(Error("secondary_confirmation_required"));
                }
                grant = prepared.grant;
                if prepared.confirmations_left > 1 {
                    let token = random_nonce()?;
                    let response = GrantConfirmation {
                        confirmation_token: token.clone(),
                        expires_at: prepared.expires_at,
                        device_id: prepared.peer.device_id.clone(),
                        label: prepared.peer.label.clone(),
                        confirmations_left: prepared.confirmations_left - 1,
                    };
                    self.lock()?.confirmations.insert(
                        sha256_hex(token.as_bytes()),
                        Confirmation {
                            grant,
                            confirmations_left: prepared.confirmations_left - 1,
                            ..prepared
                        },
                    );
                    return Ok(serde_json::to_value(response)?);
                }
                grant.confirm = Optional::Value(prepared.peer.label);
            } else {
                if label.is_some() {
                    return Err(Error("secondary_confirmation_required"));
                }
                self.authorize_strong("prepare_grant", json!({"intent":intent}))
                    .await?;
                // This proof is a different domain from a Grant. Preparation cannot produce
                // an executable signed Grant, even if the UI leaks the intermediate signature.
                let proof = json!({"action":"prepare_grant", "draft_hash":draft_hash,
                    "device_id":peers[0].device_id, "label":peers[0].label,
                    "nonce":random_nonce()?});
                let sig = sign_object(
                    &proof,
                    key.alg,
                    self.approval_provider(ApprovalLevel::Strong)?,
                )?;
                verify_object(&proof, &sig, key)?;
                let now = self.services.clock.now();
                if intent.exp.is_some_and(|exp| exp <= now) {
                    return Err(Error("expired"));
                }
                if self.execution_peers(&intent.aud)? != peers {
                    return Err(Error("secondary_confirmation_required"));
                }
                let token = random_nonce()?;
                let expires_at = now.saturating_add(120).min(intent.exp.unwrap_or(i64::MAX));
                let mut state = self.lock()?;
                state
                    .confirmations
                    .retain(|_, entry| entry.expires_at > now);
                if state.confirmations.len() >= 100 {
                    return Err(Error("rate_limited"));
                }
                state.confirmations.insert(
                    sha256_hex(token.as_bytes()),
                    Confirmation {
                        draft_hash,
                        grant,
                        peer: peers[0].clone(),
                        uid: context.uid(),
                        pid: context.agent_pid(),
                        role: context.role(),
                        confirmations_left: if intent.exp.is_none() { 2 } else { 1 },
                        expires_at,
                    },
                );
                return Ok(serde_json::to_value(GrantConfirmation {
                    confirmation_token: token,
                    expires_at,
                    device_id: peers[0].device_id.clone(),
                    label: peers[0].label.clone(),
                    confirmations_left: if intent.exp.is_none() { 2 } else { 1 },
                })?);
            }
        } else {
            if token.is_some() || label.is_some() {
                return Err(Error("invalid_grant"));
            }
            self.authorize_strong("issue_grant", json!({"intent":intent}))
                .await?;
        }
        let grant = self.sign_and_send_grant(grant, &peers)?;
        Ok(json!({"grant":grant}))
    }

    pub(crate) fn execution_peers(&self, audience: &str) -> Result<Vec<DeviceRecord>> {
        let state = self.lock()?;
        let candidates = state
            .store
            .devices(&self.account)?
            .into_iter()
            .filter(|peer| {
                peer.caps.contains(&Capability::Execute)
                    && (audience == "*" || audience == peer.device_id)
            })
            .collect::<Vec<_>>();
        let mut peers = Vec::new();
        for peer in candidates {
            if audience == "*"
                && state
                    .store
                    .setting::<bool>(&format!("global_excluded:{}", peer.device_id))?
                    .unwrap_or(false)
            {
                continue;
            }
            peers.push(peer);
        }
        if peers.is_empty() {
            return Err(Error("wrong_recipient"));
        }
        Ok(peers)
    }

    pub(crate) async fn authorize_strong(
        &self,
        reason: &'static str,
        binding: Value,
    ) -> Result<()> {
        if self
            .services
            .runner
            .local_authorize(reason, binding)
            .await?
            != ApprovalLevel::Strong
        {
            return Err(Error("insufficient_level"));
        }
        Ok(())
    }

    pub(crate) async fn issue_directive_intent(
        &self,
        intent: DirectiveIntent,
    ) -> Result<DirectiveResult> {
        let peers = self.execution_peers(&intent.aud)?;
        if peers.len() != 1 {
            return Err(Error("directive_requires_single_peer"));
        }
        let mut directive = Directive {
            kind: DirectiveKind::Directive,
            id: new_id(self.services.clock.now())?,
            iss: self.local.device_id.clone(),
            iss_alg: SignatureAlgorithm::ES256,
            iss_kind: IssuerKind::Device,
            aud: intent.aud,
            op: intent.op,
            args: intent.args,
            nonce: random_nonce()?,
            exp: self.services.clock.now().saturating_add(60),
            sig: String::new(),
            extra: Extra::new(),
        };
        let cached = self
            .lock()?
            .store
            .setting::<DirectiveStateWire>(&format!("peer_settings:{}", peers[0].device_id))?;
        let mut level =
            match directive_required_level(&directive, &cached.map(Into::into).unwrap_or_default())
            {
                Ok(level) => level,
                Err(RemoteError::MissingState) => ApprovalLevel::Strong,
                Err(error) => return Err(error.into()),
            };
        if approval_key(&self.local, level).is_err() && level == ApprovalLevel::Quick {
            level = ApprovalLevel::Strong;
        }
        directive.iss_alg = approval_key(&self.local, level)?.alg;
        self.send_directive(directive, level).await
    }

    /// Bounded history belongs only to the owner, never an MCP agent's pending view.
    pub(crate) fn recent_decisions(&self) -> Result<Vec<Value>> {
        let state = self.lock()?;
        let mut stmt = state.store.db.prepare(
            "SELECT a.approval_id,a.decision,a.summary_text,a.issued_at,h.seq FROM issued_approvals a
             LEFT JOIN approval_history h ON h.approval_id=a.approval_id ORDER BY a.issued_at DESC,a.approval_id DESC LIMIT 200")?;
        let rows = stmt.query_map([], |row| Ok(json!({"approval_id":row.get::<_,String>(0)?,
            "decision":row.get::<_,String>(1)?, "summary":row.get::<_,String>(2)?, "issued_at":row.get::<_,i64>(3)?,"decision_seq":row.get::<_,Option<u64>>(4)?})))?;
        rows.collect::<std::result::Result<Vec<_>, _>>()
            .map_err(Into::into)
    }

    pub(crate) fn issued_grants_page(
        &self,
        query: &kv_ipc::remote::GrantListParams,
    ) -> Result<Vec<Value>> {
        super::pages::validate(query)?;
        let state = self.lock()?;
        let mut stmt = state.store.db.prepare(
            "SELECT object_json,revoked_at,issued_at FROM issued_grant_objects WHERE jti>?1 ORDER BY jti LIMIT ?2")?;
        let rows = stmt.query_map(
            params![
                query.after.as_deref().unwrap_or(""),
                u32::from(query.limit) + 1
            ],
            |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, Option<i64>>(1)?,
                    r.get::<_, i64>(2)?,
                ))
            },
        )?;
        rows.map(|row| {
            let (object, revoked, issued_at) = row?;
            let mut value: Value = decode(&object)?;
            value["revoked_at"] = json!(revoked);
            value["issued_at"] = json!(issued_at);
            value["ledger"] = json!("issued");
            if value["sig"]=="" && value["origin"].as_str().is_some_and(|s|s.starts_with("approval:")) {
                value["authority"] = json!("approval_decision");
            }
            let pending: bool = state.store.db.query_row("SELECT EXISTS(SELECT 1 FROM issued_grant_revocations
                WHERE jti=?1 AND confirmed_at IS NULL)",[value["jti"].as_str().ok_or(Error("invalid_grant"))?],|r|r.get(0))?;
            value["revocation_pending"] = json!(pending);
            // Remote usage is populated only from an authenticated query_grants response.
            let usage: Option<String> = state.store.db.query_row(
                "SELECT usage_json FROM issued_grant_usage WHERE jti=?1 ORDER BY fetched_at DESC LIMIT 1",
                [value["jti"].as_str().ok_or(Error("invalid_grant"))?], |row| row.get(0)).optional()?;
            value["usage"] = usage.as_deref().map(decode::<Value>).transpose()?.unwrap_or(Value::Null);
            value["usage_status"] = json!(if usage.is_some() { "snapshot" } else { "not_fetched" });
            for field in ["budget_left","uses_n","last_used_at"] {
                value[field] = value["usage"][field].clone();
            }
            let mut usages = state.store.db.prepare("SELECT usage_json FROM issued_grant_usage WHERE jti=?1 ORDER BY peer")?;
            value["usage_by_device"] = json!(usages.query_map([value["jti"].as_str().ok_or(Error("invalid_grant"))?],|r|r.get::<_,String>(0))?
                .map(|r|decode::<Value>(&r?)).collect::<Result<Vec<_>>>()?);
            Ok(value)
        }).collect()
    }

    pub(crate) async fn revoke_owner_grant(&self, jti: &str) -> Result<()> {
        let audience: Option<String> = self
            .lock()?
            .store
            .db
            .query_row("SELECT peer FROM issued_grants WHERE jti=?1", [jti], |r| {
                r.get(0)
            })
            .optional()?;
        if let Some(audience) = audience {
            let revoked: bool = self.lock()?.store.db.query_row(
                "SELECT revoked_at IS NOT NULL FROM issued_grants WHERE jti=?1",
                [jti],
                |r| r.get(0),
            )?;
            if revoked {
                return Ok(());
            }
            let peers = self.execution_peers(&audience)?;
            self.authorize_strong("revoke_grant", json!({"jti":jti}))
                .await?;
            let proof = json!({"action":"revoke_grant","jti":jti,"nonce":random_nonce()?});
            let key = approval_key(&self.local, ApprovalLevel::Strong)?;
            let sig = sign_object(
                &proof,
                key.alg,
                self.approval_provider(ApprovalLevel::Strong)?,
            )?;
            verify_object(&proof, &sig, key)?;
            {
                let state = self.lock()?;
                let tx = state.store.transaction(self.services.audit.as_ref())?;
                tx.execute("INSERT OR IGNORE INTO issued_grant_revocations(jti,requested_at) VALUES(?1,?2)",params![jti,self.services.clock.now()])?;
                for peer in &peers {
                    tx.execute("INSERT OR IGNORE INTO issued_grant_revocation_targets(jti,peer) VALUES(?1,?2)",params![jti,peer.device_id])?;
                }
                self.audit(&state, "grant_revocation_requested", json!({"jti":jti}))?;
                tx.commit()?;
            }
            // A wildcard is expanded into separately acknowledged, signed directives.
            for peer in peers {
                let confirmed: bool = self.lock()?.store.db.query_row(
                    "SELECT confirmed_at IS NOT NULL FROM issued_grant_revocation_targets
                    WHERE jti=?1 AND peer=?2",
                    params![jti, peer.device_id],
                    |r| r.get(0),
                )?;
                if confirmed {
                    continue;
                }
                let result = self
                    .issue_directive_intent(DirectiveIntent {
                        kind: DirectiveKind::Directive,
                        aud: peer.device_id,
                        op: DirectiveOp::RevokeGrant,
                        args: json!({"jti":jti}).as_object().unwrap().clone(),
                    })
                    .await?;
                if !result.ok {
                    return Err(Error("grant_revoke_failed"));
                }
            }
            let state = self.lock()?;
            let tx = state.store.transaction(self.services.audit.as_ref())?;
            tx.execute(
                "UPDATE issued_grants SET revoked_at=?1 WHERE jti=?2",
                params![self.services.clock.now(), jti],
            )?;
            tx.execute(
                "UPDATE issued_grant_objects SET revoked_at=?1 WHERE jti=?2",
                params![self.services.clock.now(), jti],
            )?;
            tx.execute(
                "UPDATE issued_grant_revocations SET confirmed_at=?1 WHERE jti=?2",
                params![self.services.clock.now(), jti],
            )?;
            self.audit(
                &state,
                "grant_revoked",
                json!({"jti":jti,"by":"local","propagated":true}),
            )?;
            tx.commit()?;
            Ok(())
        } else {
            self.services
                .runner
                .local_authorize("revoke_grant", json!({"jti":jti}))
                .await?;
            self.revoke_grant(jti, "local")
        }
    }
}

#[derive(serde::Serialize, serde::Deserialize)]
pub(crate) struct DirectiveStateWire {
    pub mode: Option<String>,
    pub unlock_ttl_s: Option<u64>,
    #[serde(default)]
    pub classes: std::collections::BTreeMap<String, (Value, u64)>,
}
impl From<DirectiveStateWire> for DirectiveState {
    fn from(value: DirectiveStateWire) -> Self {
        Self {
            mode: value.mode,
            unlock_ttl_s: value.unlock_ttl_s,
            classes: value.classes,
        }
    }
}

pub(crate) fn decision_scope(option: &str, now: i64) -> Result<DecisionScope> {
    let (mode, level, seconds) = match option {
        "per_use" => (ScopeMode::PerUse, DecisionScopeLevel::Credential, 0),
        "per_credential" => (ScopeMode::PerCredential, DecisionScopeLevel::Credential, 0),
        "per_session" => (ScopeMode::PerSession, DecisionScopeLevel::Device, 0),
        "remember:1h" => (ScopeMode::Remember, DecisionScopeLevel::Credential, 3600),
        "remember:8h" => (ScopeMode::Remember, DecisionScopeLevel::Credential, 28800),
        "remember:24h" => (ScopeMode::Remember, DecisionScopeLevel::Credential, 86400),
        "standing:credential" => (ScopeMode::Standing, DecisionScopeLevel::Credential, 0),
        "standing:device" => (ScopeMode::Standing, DecisionScopeLevel::Device, 0),
        _ => return Err(Error("invalid_scope")),
    };
    Ok(DecisionScope {
        mode,
        level,
        until: if seconds == 0 {
            0
        } else {
            now.saturating_add(seconds)
        },
        extra: Extra::new(),
    })
}
