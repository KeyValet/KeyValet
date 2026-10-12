use super::pairing::Pairing;
use super::pipeline::{retry_binding, scope_options};
use super::store::{decode, encode, Pending, PendingState};
use super::{ApprovalConfig, ApprovalInput, Error, Result, Store};
use kv_core::remote::canonical::{from_json, jcs, sha256_hex, CanonicalRequest};
use kv_core::remote::keys::{decode_b64, encode_b64, verify_object};
use kv_core::remote::validation::{approval_key, verify_decision};
use kv_core::remote::*;
use rusqlite::{params, OptionalExtension};
use serde_json::{json, Map, Value};
use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;
use tokio::sync::Notify;
use zeroize::Zeroizing;

struct WaitObservation {
    helper: Arc<RemoteHelper>,
    uid: u32,
    agent_pid: u32,
    finished: bool,
}
impl Drop for WaitObservation {
    fn drop(&mut self) {
        if !self.finished {
            if let Ok(state) = self.helper.lock() {
                let _ = self.helper.audit(
                    &state,
                    "client_timeout_observed",
                    json!({
                        "agent_pid":self.agent_pid,"uid":self.uid,
                        "reason":"client_disconnected_while_waiting","runtime_budget_s":50,
                    }),
                );
            }
        }
    }
}

pub trait Clock: Send + Sync {
    fn now(&self) -> i64;
}

pub struct SystemClock;
impl Clock for SystemClock {
    fn now(&self) -> i64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|time| time.as_secs().min(i64::MAX as u64) as i64)
            .unwrap_or(0)
    }
}

pub trait AuditSink: Send + Sync {
    fn append(&self, entry: Map<String, Value>) -> Result<()>;
    fn verify_records(&self, _records: &[Value]) -> Result<()> {
        Ok(())
    }
    fn verify_checkpoint(&self, _head: &kv_core::remote::audit::AuditHead) -> Result<()> {
        Ok(())
    }
    fn prepare_checkpoint(
        &self,
        _old: &kv_core::remote::audit::AuditHead,
        _next: &kv_core::remote::audit::AuditHead,
    ) -> Result<()> {
        Ok(())
    }
    fn commit_checkpoint(&self, _head: &kv_core::remote::audit::AuditHead) -> Result<()> {
        Ok(())
    }
    fn abort_checkpoint(&self, _head: &kv_core::remote::audit::AuditHead) -> Result<()> {
        Ok(())
    }
    fn checkpoint_kind(&self) -> &'static str {
        "unavailable"
    }
}

impl AuditSink for kv_vault::Vault {
    fn verify_records(&self, records: &[Value]) -> Result<()> {
        super::audit::verify_records(self, records)
    }
    fn append(&self, entry: Map<String, Value>) -> Result<()> {
        self.audit(entry).map_err(|_| Error("audit_unavailable"))
    }
    fn verify_checkpoint(&self, head: &kv_core::remote::audit::AuditHead) -> Result<()> {
        super::audit::verify(self, head)
    }
    fn prepare_checkpoint(
        &self,
        old: &kv_core::remote::audit::AuditHead,
        next: &kv_core::remote::audit::AuditHead,
    ) -> Result<()> {
        super::audit::prepare(self, old, next)
    }
    fn commit_checkpoint(&self, head: &kv_core::remote::audit::AuditHead) -> Result<()> {
        super::audit::commit(self, head)
    }
    fn abort_checkpoint(&self, head: &kv_core::remote::audit::AuditHead) -> Result<()> {
        super::audit::abort(self, head)
    }
    fn checkpoint_kind(&self) -> &'static str {
        "vault_authenticated_metadata"
    }
}

/// The vault owner implements an atomic AEAD metadata replacement and verification here.
/// Tombstones are retained so old approvals cannot regain authority after a restart.
pub trait DeviceMirror: Send + Sync {
    fn replace(&self, account: &str, records: &[(DeviceRecord, bool)]) -> Result<()>;
    fn verify(&self, account: &str, records: &[(DeviceRecord, bool)]) -> Result<()>;
    /// Production mirrors journal the proposed directory until its SQLite marker commits.
    fn prepare(&self, account: &str, records: &[(DeviceRecord, bool)], _id: &str) -> Result<bool> {
        self.replace(account, records)?;
        Ok(true)
    }
    fn commit(&self, _id: &str) -> Result<()> {
        Ok(())
    }
    fn abort(&self, _id: &str) -> Result<()> {
        Ok(())
    }
}

pub trait RequestRunner: Send + Sync {
    fn has_private_ui(&self) -> bool {
        false
    }
    fn private_ui(
        &self,
        _op: &'static str,
        _fields: Value,
    ) -> Pin<Box<dyn Future<Output = Result<Value>> + Send + '_>> {
        Box::pin(async { Err(Error("remote_ui_unavailable")) })
    }
    fn execute(
        &self,
        request: Execution,
    ) -> Pin<Box<dyn Future<Output = Result<Value>> + Send + '_>>;
    fn agent_alive(&self, _uid: u32, _pid: u32, _exe_sha256: &str) -> bool;
    fn lock_sessions(&self) -> Result<()>;
    fn local_authorize(
        &self,
        reason: &'static str,
        binding: Value,
    ) -> Pin<Box<dyn Future<Output = Result<ApprovalLevel>> + Send + '_>>;
}

/// No Debug or Serialize implementation: execution parameters must never reach disk or logs.
pub struct FullRequest {
    pub op: String,
    params: Zeroizing<Vec<u8>>,
}

impl FullRequest {
    pub fn new(op: impl Into<String>, mut params: Map<String, Value>) -> Result<Self> {
        // Retry and runtime transport data are not operation parameters.
        for key in [
            "approval_id",
            "nonce",
            "exp",
            "runtime_budget_s",
            "max_wait_ms",
            "wait_in_call_ms",
            "agent",
        ] {
            params.remove(key);
        }
        let bytes = Zeroizing::new(jcs(&params)?);
        kv_vault::scrub_json(&mut Value::Object(params));
        if bytes.len() > 1024 * 1024 {
            return Err(Error("payload_too_large"));
        }
        Ok(Self {
            op: op.into(),
            params: bytes,
        })
    }

    pub fn params(&self) -> Result<Map<String, Value>> {
        from_json(&self.params).map_err(Into::into)
    }

    pub fn binding_digest(&self) -> Result<String> {
        let mut bytes = self.op.as_bytes().to_vec();
        bytes.push(0);
        bytes.extend_from_slice(&self.params);
        let digest = sha256_hex(&bytes);
        zeroize::Zeroize::zeroize(&mut bytes);
        Ok(digest)
    }
}

pub struct Execution {
    pub canonical: CanonicalRequest,
    pub full_request: FullRequest,
    pub approval_id: String,
}

pub struct Services {
    pub identity: Arc<dyn DeviceKeyProvider + Send + Sync>,
    pub quick: Option<Arc<dyn DeviceKeyProvider + Send + Sync>>,
    pub strong: Option<Arc<dyn DeviceKeyProvider + Send + Sync>>,
    pub presence: Arc<dyn PresenceProbe + Send + Sync>,
    pub mirror: Arc<dyn DeviceMirror>,
    pub audit: Arc<dyn AuditSink>,
    pub runner: Arc<dyn RequestRunner>,
    pub clock: Arc<dyn Clock>,
}

pub(crate) struct Hint {
    pub hint: PresenceHint,
    pub received_at: i64,
}

pub(crate) struct State {
    pub store: Store,
    pub full: HashMap<String, FullRequest>,
    pub results: HashMap<String, Value>,
    pub executing: HashSet<String>,
    pub hints: HashMap<String, Hint>,
    pub local_hint: Option<Hint>,
    pub pairing: Option<Pairing>,
    pub relay_connected: bool,
    pub inbound_requests: HashMap<String, ApprovalRequest>,
    pub directive_results: HashMap<String, (String, DirectiveResult)>,
    pub confirmations: HashMap<String, super::owner::Confirmation>,
    pub presenting: HashSet<String>,
    pub pair_result: Option<Value>,
    pub retired: bool,
}

impl Drop for State {
    fn drop(&mut self) {
        for value in self.results.values_mut() {
            kv_vault::scrub_json(value);
        }
    }
}

pub struct RemoteHelper {
    pub(crate) state: Mutex<State>,
    pub(crate) local: DeviceRecord,
    pub(crate) account: String,
    pub(crate) config: ApprovalConfig,
    pub(crate) services: Services,
    pub(crate) changed: Notify,
}

impl RemoteHelper {
    /// This is the only provider switch point. Hardware failures never create software keys.
    pub fn new(
        store: Store,
        local: DeviceRecord,
        account: String,
        config: ApprovalConfig,
        services: Services,
    ) -> Result<Arc<Self>> {
        config.validate()?;
        store.verify_audit()?;
        services.audit.verify_checkpoint(&store.audit_head()?)?;
        services.audit.verify_records(&store.audit_records()?)?;
        kv_core::remote::keys::verify_identity_provider(&local, services.identity.as_ref())?;
        if account.is_empty()
            || local.device_id.is_empty()
            || services.identity.public_jwk()? != local.dk_pub
            || services.identity.key_kind() != local.key_kind
        {
            return Err(Error("invalid_local_identity"));
        }
        validate_device(&local)?;
        for (provider, key) in [
            (&services.quick, &local.ak_q),
            (&services.strong, &local.ak_s),
        ] {
            if let Some(provider) = provider {
                if key.as_ref().map(|key| &key.r#pub) != Some(&provider.public_jwk()?) {
                    return Err(Error("invalid_local_identity"));
                }
            }
        }
        services.mirror.verify(&account, &directory(&store)?)?;
        if store.setting::<String>("mode")?.is_none() {
            store.set_setting("mode", &"per_credential", "local", services.clock.now())?;
        }
        if store.setting::<u64>("epoch")?.is_none() {
            store.set_setting("epoch", &0u64, "local", services.clock.now())?;
        }
        Ok(Arc::new(Self {
            state: Mutex::new(State {
                store,
                full: HashMap::new(),
                results: HashMap::new(),
                executing: HashSet::new(),
                hints: HashMap::new(),
                local_hint: None,
                pairing: None,
                relay_connected: false,
                inbound_requests: HashMap::new(),
                directive_results: HashMap::new(),
                confirmations: HashMap::new(),
                presenting: HashSet::new(),
                pair_result: None,
                retired: false,
            }),
            local,
            account,
            config,
            services,
            changed: Notify::new(),
        }))
    }

    pub(crate) fn lock(&self) -> Result<MutexGuard<'_, State>> {
        match self.state.lock() {
            Ok(state) if state.retired => Err(Error("remote_identity_changed")),
            Ok(state) => Ok(state),
            Err(poisoned) => {
                let mut state = poisoned.into_inner();
                state.full.clear();
                state.pairing = None;
                for (_, mut value) in state.results.drain() {
                    kv_vault::scrub_json(&mut value);
                }
                drop(state);
                // The poisoned SQLite owner cannot be used. Record fixed metadata through
                // the independent vault audit sink without recovering authorization state.
                let _ = self.services.audit.append(
                    json!({"op":"remote_state_rejected",
                    "reason":"state_unavailable","ok":false,"ts_unix":self.services.clock.now()})
                    .as_object()
                    .cloned()
                    .unwrap_or_default(),
                );
                Err(Error("state_unavailable"))
            }
        }
    }

    pub(crate) fn audit(&self, state: &State, event: &str, fields: Value) -> Result<()> {
        let mut entry = fields.as_object().cloned().unwrap_or_default();
        entry.insert("op".into(), json!(event));
        entry.insert("account_id".into(), json!(self.account));
        entry.insert("source_device".into(), json!(self.local.device_id));
        let result = state.store.audit(
            self.services.audit.as_ref(),
            entry,
            self.services.clock.now(),
        );
        if result == Err(Error("state_unavailable")) {
            // Preserve evidence in the independent vault sink when the SQLite audit is broken.
            // This compensating record never makes the original operation successful.
            let _ = self.services.audit.append(
                json!({"op":"remote_audit_rejected", "event":event,
                    "reason":"state_unavailable", "ok":false,
                    "ts_unix":self.services.clock.now()})
                .as_object()
                .cloned()
                .unwrap_or_default(),
            );
        }
        result
    }

    pub(crate) fn reject(&self, state: &State, event: &str, error: Error, id: &str) -> Result<()> {
        self.audit(
            state,
            event,
            json!({"ok": false, "reason": error.code(), "approval_id": id}),
        )
    }

    pub(crate) fn seal<T: serde::Serialize>(
        &self,
        peer: &DeviceRecord,
        kind: EnvelopeType,
        id: &str,
        exp: i64,
        value: &T,
    ) -> Result<Envelope> {
        let plaintext = Zeroizing::new(jcs(value)?);
        let mut extra = Extra::new();
        if matches!(peer.os, Os::Ios | Os::Android) {
            let mode = match kind {
                EnvelopeType::ApprovalRequest => {
                    Some(from_json::<ApprovalRequest>(&plaintext)?.delivery.mode)
                }
                EnvelopeType::ApprovalEscalate => Some(DeliveryMode::Banner),
                EnvelopeType::ApprovalCancel => Some(DeliveryMode::Silent),
                _ => None,
            };
            if let Some(mode) = mode {
                extra.insert("push".into(), json!({"mode":mode}));
            }
        }
        kv_core::remote::envelope::seal(
            EnvelopeHeader {
                v: 1,
                r#type: kind,
                id: id.into(),
                account: self.account.clone(),
                from: self.local.device_id.clone(),
                to: peer.device_id.clone(),
                created_at: self.services.clock.now(),
                exp,
                extra,
            },
            &plaintext,
            &peer.dk_pub,
            self.services.identity.as_ref(),
        )
        .map_err(Into::into)
    }

    pub fn submit(self: &Arc<Self>, input: ApprovalInput) -> Result<ApprovalRequest> {
        let result = self.submit_inner(input);
        if let Err(error) = result {
            let state = self.lock()?;
            self.reject(&state, "approval_rejected", error, "")?;
        }
        result
    }

    fn submit_inner(self: &Arc<Self>, mut input: ApprovalInput) -> Result<ApprovalRequest> {
        let now = self.services.clock.now();
        self.tick()?;
        if input.canonical.v != 1
            || input.canonical.requester != self.local.device_id
            || input.canonical.agent.pid == 0
            || input.session_id.is_empty()
        {
            return Err(Error("invalid_request_identity"));
        }
        input.canonical.nonce = random_nonce()?;
        input.canonical.exp = now
            .checked_add(self.expiration_s(&input)? as i64)
            .ok_or(Error("invalid_json"))?;
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
        let canonical: CanonicalRequest = from_json(&input.canonical.canonical_bytes()?)?;
        let options = scope_options(&input);
        let mut state = self.lock()?;
        // Merge only requests with exactly the same execution and identity binding. A credential
        // alone is not an execution binding; differing operations must be independently approved.
        if input.tier <= Tier::T1 && canonical.kind == ApprovalKind::Use {
            for id in state.store.pending_ids()? {
                let pending = state.store.pending(&id)?;
                if pending.state == PendingState::Waiting
                    && pending.request.tier <= Tier::T1
                    && pending.session_id == input.session_id
                    && now.saturating_sub(pending.created_at) < 30
                    && retry_binding(&pending.canonical)? == retry_binding(&canonical)?
                {
                    let mut request = pending.request;
                    request.merged_count = request.merged_count.saturating_add(1);
                    state.store.db.execute("UPDATE pending_approvals SET request_json=?1 WHERE id=?2 AND state='waiting'",
                        params![encode(&request)?, id])?;
                    return Ok(request);
                }
            }
        }
        let id = new_id(now)?;
        let level = if canonical.kind != ApprovalKind::Use || input.tier == Tier::T2 {
            ApprovalLevel::Strong
        } else {
            input.min_level
        };
        let requested_scope = if options.contains(&input.requested_scope) {
            input.requested_scope
        } else {
            ScopeOption::PerUse
        };
        let request = ApprovalRequest {
            approval_id: id.clone(),
            kind: canonical.kind,
            digest: canonical.digest()?,
            nonce: canonical.nonce.clone(),
            exp: canonical.exp,
            requester: Requester {
                device_id: self.local.device_id.clone(),
                label: self.label(&state)?,
                os: self.local.os.clone(),
                protection: Protection {
                    kind: protection_kind(&self.local.key_kind),
                    attestation: self
                        .local
                        .attestation
                        .clone()
                        .map_or(Optional::Null, Optional::Value),
                    extra: Extra::new(),
                },
                extra: Extra::new(),
            },
            agent: Agent {
                runtime: serde_json::from_value(json!(canonical.agent.runtime))?,
                cwd: canonical.agent.repo_or_cwd.clone(),
                user: canonical.agent.uid.to_string(),
                pid: canonical.agent.pid,
                extra: Extra::new(),
            },
            credential: input.credential,
            operation: input.operation,
            purpose: canonical.purpose.clone(),
            tier: input.tier,
            min_level: level,
            scope_options: options,
            requested_scope,
            merged_count: 1,
            delivery: Delivery {
                mode: DeliveryMode::Banner,
                escalate_after_s: self.escalate_after_s(&state)?,
                extra: Extra::new(),
            },
            extra: Extra::new(),
        };
        validate_display(&request, &canonical)?;
        let peers = state
            .store
            .devices(&self.account)?
            .into_iter()
            .filter(is_approver)
            .collect::<Vec<_>>();
        if peers.is_empty() {
            return Err(Error("no_approver"));
        }
        if !peers.iter().any(|peer| approval_key(peer, level).is_ok()) {
            return Err(Error("no_approver"));
        }
        let mut silent_peers = Vec::new();
        let envelopes = peers
            .iter()
            .map(|peer| {
                let mut delivered = request.clone();
                delivered.delivery = self.delivery(&state, peer, &peers, now)?;
                if delivered.delivery.mode == DeliveryMode::Silent {
                    silent_peers.push(peer.device_id.clone());
                }
                self.seal(
                    peer,
                    EnvelopeType::ApprovalRequest,
                    &id,
                    request.exp,
                    &delivered,
                )
            })
            .collect::<Result<Vec<_>>>()?;
        let epoch = state.store.setting::<u64>("epoch")?.unwrap_or(0);
        let transaction = state.store.transaction(self.services.audit.as_ref())?;
        transaction.execute(
            "INSERT INTO pending_approvals (id, kind, digest, nonce, canonical_json, exp, state, created_at,
             agent_pid, agent_runtime, request_json, session_id, epoch) VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'waiting', ?7, ?8, ?9, ?10, ?11, ?12)",
            params![id, encode(&request.kind)?.trim_matches('"'), request.digest, request.nonce, encode(&canonical)?, request.exp, now,
                canonical.agent.pid, canonical.agent.runtime, encode(&request)?, input.session_id, epoch],
        )?;
        for envelope in envelopes {
            state.store.queue(&envelope)?;
        }
        state
            .store
            .set_setting(&format!("delivery:{id}"), &silent_peers, "local", now)?;
        self.audit(&state, "approval_requested", json!({"approval_id": id, "kind": request.kind, "digest": request.digest,
            "tier": request.tier, "min_level": request.min_level, "agent_pid": canonical.agent.pid}))?;
        transaction.commit()?;
        state.full.insert(id, input.full_request);
        drop(state);
        self.changed.notify_waiters();
        Ok(request)
    }

    fn expiration_s(&self, input: &ApprovalInput) -> Result<u64> {
        let state = self.lock()?;
        let mut expiry = None;
        let classes = state
            .store
            .setting::<Value>("classes")?
            .unwrap_or_else(|| json!({}));
        for class in &self.config.class {
            if classes.get(&class.name).is_some() {
                continue;
            }
            if class.r#match.credential.as_deref().is_none_or(|pattern| {
                input
                    .canonical
                    .credential
                    .as_deref()
                    .is_some_and(|name| super::pipeline::glob(pattern, name))
            }) && class.r#match.host.as_deref().is_none_or(|host| {
                input
                    .canonical
                    .host
                    .as_deref()
                    .is_some_and(|name| host.eq_ignore_ascii_case(name))
            }) {
                expiry = Some(expiry.map_or(class.exp_s, |value: u64| value.min(class.exp_s)));
            }
        }
        for class in classes
            .as_object()
            .into_iter()
            .flat_map(|value| value.values())
        {
            let matches = class["match"]["credential"].as_str().is_none_or(|pattern| {
                input
                    .canonical
                    .credential
                    .as_deref()
                    .is_some_and(|name| super::pipeline::glob(pattern, name))
            }) && class["match"]["host"].as_str().is_none_or(|host| {
                input
                    .canonical
                    .host
                    .as_deref()
                    .is_some_and(|name| host.eq_ignore_ascii_case(name))
            });
            if matches {
                let seconds = class["exp_s"]
                    .as_u64()
                    .ok_or(Error("invalid_approval_class"))?;
                expiry = Some(expiry.map_or(seconds, |value| value.min(seconds)));
            }
        }
        Ok(expiry.unwrap_or(self.config.default_exp_s).min(86400))
    }

    pub(crate) fn label(&self, state: &State) -> Result<String> {
        Ok(state
            .store
            .setting("device_label")?
            .unwrap_or_else(|| self.local.label.clone()))
    }

    pub(crate) fn escalate_after_s(&self, state: &State) -> Result<u32> {
        Ok(state
            .store
            .setting::<u32>("presence.escalate_after_s")?
            .unwrap_or(30)
            .max(1))
    }

    fn presence(&self, state: &State, now: i64) -> Presence {
        if let Some(hint) = &state.local_hint {
            if now.saturating_sub(hint.received_at) <= 120 {
                return hint.hint.state;
            }
        }
        let probe = self.services.presence.state();
        let signals = &probe.signals;
        // A fake or malfunctioning probe cannot label incomplete raw signals as present.
        let complete = signals.graphical_session == Some(true)
            && signals.session_active == Some(true)
            && signals.screen_locked == Some(false)
            && signals.screensaver_active == Some(false)
            && signals.idle_seconds.is_some()
            && signals.display_connected.is_some()
            && signals.display_awake.is_some()
            && signals.remote_session_active.is_some()
            && signals.approval_channel_available == Some(true)
            && ((signals.display_connected == Some(true) && signals.display_awake == Some(true))
                || signals.remote_session_active == Some(true));
        if complete {
            probe.state
        } else {
            Presence::Away
        }
    }

    pub fn local_channel_available(&self) -> Result<bool> {
        Ok(self.presence(&*self.lock()?, self.services.clock.now()) == Presence::Present)
    }

    pub fn unlock_ttl_s(&self) -> u64 {
        self.lock()
            .ok()
            .and_then(|state| state.store.setting::<u64>("unlock_ttl").ok().flatten())
            .unwrap_or(self.config.unlock_ttl_s)
    }

    pub fn http_wait_s(&self) -> u64 {
        self.config.http_wait_s
    }

    fn delivery(
        &self,
        state: &State,
        peer: &DeviceRecord,
        peers: &[DeviceRecord],
        now: i64,
    ) -> Result<Delivery> {
        let policy = state
            .store
            .setting::<NotifyPolicy>("notify")?
            .unwrap_or(NotifyPolicy::PreferLocal);
        let phone = matches!(peer.os, Os::Ios | Os::Android);
        let desktop_present = peers.iter().any(|peer| {
            matches!(peer.os, Os::Macos | Os::Windows | Os::Linux)
                && state.hints.get(&peer.device_id).is_some_and(|hint| {
                    hint.hint.state == Presence::Present
                        && now.saturating_sub(hint.received_at) <= 120
                })
        });
        let mode = if policy == NotifyPolicy::Both || (phone && policy == NotifyPolicy::AlwaysPhone)
        {
            DeliveryMode::Banner
        } else if self.presence(state, now) == Presence::Present || (phone && desktop_present) {
            DeliveryMode::Silent
        } else {
            DeliveryMode::Banner
        };
        Ok(Delivery {
            mode,
            escalate_after_s: self.escalate_after_s(state)?,
            extra: Extra::new(),
        })
    }

    pub fn tick(&self) -> Result<()> {
        let result = self.tick_inner();
        if let Err(error) = result {
            let mut state = self.lock()?;
            state.full.clear();
            for (_, mut value) in state.results.drain() {
                kv_vault::scrub_json(&mut value);
            }
            self.reject(&state, "remote_timer_rejected", error, "")?;
        }
        result
    }

    fn tick_inner(&self) -> Result<()> {
        let now = self.services.clock.now();
        let mut state = self.lock()?;
        let mut changed = false;
        state
            .confirmations
            .retain(|_, entry| entry.expires_at > now);
        if state
            .pairing
            .as_ref()
            .is_some_and(|pairing| pairing.exp < now)
        {
            self.pair_failed(&mut state, Error("expired"))?;
            self.audit(&state, "pair_expired", json!({"reason": "expired"}))?;
            changed = true;
        }
        for id in state.store.pending_ids()? {
            let pending = state.store.pending(&id)?;
            if pending.request.exp < now {
                state.full.remove(&id);
                if let Some(mut value) = state.results.remove(&id) {
                    kv_vault::scrub_json(&mut value);
                }
                if matches!(
                    pending.state,
                    PendingState::Waiting | PendingState::Approved | PendingState::ApprovedUnused
                ) {
                    self.cancel_locked(&mut state, &id, PendingState::Expired)?;
                    changed = true;
                }
            } else if pending.state == PendingState::Waiting
                && now.saturating_sub(pending.created_at)
                    >= i64::from(self.escalate_after_s(&state)?)
            {
                let escalated: Option<i64> = state.store.db.query_row(
                    "SELECT escalated_at FROM pending_approvals WHERE id=?1",
                    [&id],
                    |r| r.get(0),
                )?;
                if escalated.is_none() {
                    let peers = state
                        .store
                        .devices(&self.account)?
                        .into_iter()
                        .filter(is_approver)
                        .collect::<Vec<_>>();
                    let transaction = state.store.transaction(self.services.audit.as_ref())?;
                    let silent: Vec<String> = state
                        .store
                        .setting(&format!("delivery:{id}"))?
                        .unwrap_or_default();
                    for peer in &peers {
                        if silent.contains(&peer.device_id) {
                            state.store.queue(&self.seal(
                                peer,
                                EnvelopeType::ApprovalEscalate,
                                &id,
                                pending.request.exp,
                                &ApprovalEscalate {
                                    approval_id: id.clone(),
                                    extra: Extra::new(),
                                },
                            )?)?;
                        }
                    }
                    transaction.execute("UPDATE pending_approvals SET escalated_at=?1 WHERE id=?2 AND state='waiting'", params![now, id])?;
                    transaction.commit()?;
                    changed = true;
                }
            }
        }
        state
            .store
            .db
            .execute("DELETE FROM remote_outbox WHERE exp < ?1", [now])?;
        state
            .inbound_requests
            .retain(|_, request| request.exp >= now);
        drop(state);
        if changed {
            self.changed.notify_waiters();
        }
        Ok(())
    }

    pub(crate) fn cancel_locked(
        &self,
        state: &mut State,
        id: &str,
        next: PendingState,
    ) -> Result<()> {
        let transaction = state.store.transaction(self.services.audit.as_ref())?;
        self.cancel_in_transaction(state, id, next)?;
        transaction.commit()?;
        state.full.remove(id);
        Ok(())
    }

    pub(crate) fn cancel_in_transaction(
        &self,
        state: &State,
        id: &str,
        next: PendingState,
    ) -> Result<()> {
        let now = self.services.clock.now();
        let pending = state.store.pending(id)?;
        if !matches!(
            pending.state,
            PendingState::Waiting | PendingState::Approved | PendingState::ApprovedUnused
        ) {
            return Err(Error("already_consumed"));
        }
        state.store.db.execute(
            "UPDATE pending_approvals SET state=?1, resolved_at=?2 WHERE id=?3",
            params![next.as_str(), now, id],
        )?;
        for peer in state
            .store
            .devices(&self.account)?
            .iter()
            .filter(|p| is_approver(p))
        {
            state.store.queue(&self.seal(
                peer,
                EnvelopeType::ApprovalCancel,
                id,
                // Cancellation must remain deliverable after the approval itself expires.
                now.saturating_add(60),
                &ApprovalCancel {
                    approval_id: id.into(),
                    extra: Extra::new(),
                },
            )?)?;
        }
        self.audit(
            state,
            if next == PendingState::Expired {
                "approval_expired"
            } else {
                "approval_cancelled"
            },
            json!({"approval_id": id}),
        )?;
        Ok(())
    }

    /// Steps 1 through 8 of §6.5. No nonce or scope mutation precedes key verification.
    pub async fn inbound(self: &Arc<Self>, envelope: Envelope) -> Result<()> {
        let id = envelope.id.clone();
        let result = self.receive(&envelope);
        if let Err(error) = result {
            let state = self.lock()?;
            self.reject(&state, "remote_message_rejected", error, &id)?;
            return Err(error);
        }
        self.changed.notify_waiters();
        if envelope.r#type == EnvelopeType::ApprovalDecision {
            if let Err(error) = self.schedule_execution(&id) {
                let state = self.lock()?;
                self.reject(&state, "approval_execution_rejected", error, &id)?;
                return Err(error);
            }
        }
        if self.services.runner.has_private_ui()
            && matches!(
                envelope.r#type,
                EnvelopeType::ApprovalRequest | EnvelopeType::ApprovalEscalate
            )
        {
            self.present_incoming(
                &envelope.id,
                envelope.r#type == EnvelopeType::ApprovalEscalate,
            )?;
        }
        Ok(())
    }

    fn receive(&self, envelope: &Envelope) -> Result<()> {
        let now = self.services.clock.now();
        let mut state = self.lock()?;
        if envelope.v != 1 {
            return Err(Error("unsupported_version"));
        }
        if envelope.to != self.local.device_id {
            return Err(Error("wrong_recipient"));
        }
        if envelope.account != self.account {
            return Err(Error("wrong_account"));
        }
        if matches!(
            envelope.r#type,
            EnvelopeType::PairAccept | EnvelopeType::PairConfirm
        ) {
            return self.receive_pairing(&mut state, envelope);
        }
        // Step 1: sender trust before expiration, signature, or HPKE operations.
        let device = state.store.device(&envelope.from, &self.account)?;
        if !is_approver(&device) && envelope.r#type == EnvelopeType::ApprovalDecision {
            return Err(Error("unsupported_authority"));
        }
        let plaintext = kv_core::remote::envelope::open(
            envelope,
            &self.local.device_id,
            self.services.identity.as_ref(),
            &device,
            now,
        )?;
        match envelope.r#type {
            EnvelopeType::ApprovalDecision => {
                let decision: ApprovalDecision = from_json(&plaintext)?;
                if decision.approval_id != envelope.id {
                    return Err(Error("not_waiting"));
                }
                self.accept_decision(&mut state, &device, &decision, envelope.created_at, now)
            }
            EnvelopeType::Grant => {
                let grant: Grant = from_json(&plaintext)?;
                self.install_grant_locked(&state, &grant, &device, None)
            }
            EnvelopeType::Directive => {
                let directive: Directive = from_json(&plaintext)?;
                if directive.id != envelope.id {
                    return Err(Error("invalid_directive"));
                }
                let result = self.apply_directive_locked(&mut state, &directive, &device, None);
                let response = match result {
                    Ok(result) => result,
                    Err(error) => {
                        self.reject(&state, "directive_rejected", error, &directive.id)?;
                        DirectiveResult {
                            id: directive.id.clone(),
                            ok: false,
                            error: Some(error.code().into()),
                            state: Extra::new(),
                            extra: Extra::new(),
                        }
                    }
                };
                state.store.queue(&self.seal(
                    &device,
                    EnvelopeType::DirectiveResult,
                    &directive.id,
                    now.saturating_add(60),
                    &response,
                )?)?;
                Ok(())
            }
            EnvelopeType::PresenceHint => {
                let hint: PresenceHint = from_json(&plaintext)?;
                if hint.device_id != device.device_id
                    || hint.sent_at > now.saturating_add(60)
                    || now.saturating_sub(hint.sent_at) > 120
                {
                    return Err(Error("invalid_presence_hint"));
                }
                if state
                    .hints
                    .get(&device.device_id)
                    .is_some_and(|old| hint.sent_at <= old.hint.sent_at)
                {
                    return Err(Error("stale_presence_hint"));
                }
                state.hints.insert(
                    device.device_id.clone(),
                    Hint {
                        hint,
                        received_at: now,
                    },
                );
                Ok(())
            }
            EnvelopeType::ApprovalRequest => {
                let request: ApprovalRequest = from_json(&plaintext)?;
                if request.requester.device_id != device.device_id
                    || request.approval_id != envelope.id
                    || request.exp > envelope.exp
                    || request.exp < now
                    || !device.caps.contains(&Capability::Execute)
                {
                    return Err(Error("invalid_approval_request"));
                }
                let issued: bool = state.store.db.query_row(
                    "SELECT EXISTS(SELECT 1 FROM issued_approvals WHERE approval_id=?1)",
                    [&request.approval_id],
                    |row| row.get(0),
                )?;
                if issued {
                    return Err(Error("already_consumed"));
                }
                if state
                    .inbound_requests
                    .get(&request.approval_id)
                    .is_some_and(|previous| previous != &request)
                {
                    return Err(Error("invalid_approval_request"));
                }
                state
                    .inbound_requests
                    .insert(request.approval_id.clone(), request);
                Ok(())
            }
            EnvelopeType::ApprovalCancel => {
                let cancel: ApprovalCancel = from_json(&plaintext)?;
                if cancel.approval_id != envelope.id {
                    return Err(Error("invalid_approval_request"));
                }
                if state
                    .inbound_requests
                    .get(&cancel.approval_id)
                    .is_some_and(|r| r.requester.device_id == device.device_id)
                {
                    state.inbound_requests.remove(&cancel.approval_id);
                }
                Ok(())
            }
            EnvelopeType::ApprovalEscalate => {
                let escalate: ApprovalEscalate = from_json(&plaintext)?;
                if escalate.approval_id != envelope.id {
                    return Err(Error("invalid_approval_request"));
                }
                let request = state
                    .inbound_requests
                    .get_mut(&escalate.approval_id)
                    .ok_or(Error("not_waiting"))?;
                if request.requester.device_id != device.device_id {
                    return Err(Error("wrong_sender"));
                }
                // The signed request remains immutable. Escalation is a separate delivery hint.
                self.audit(
                    &state,
                    "approval_escalated",
                    json!({"approval_id":escalate.approval_id}),
                )?;
                Ok(())
            }
            EnvelopeType::DirectiveResult => {
                let result: DirectiveResult = from_json(&plaintext)?;
                if result.id != envelope.id {
                    return Err(Error("unexpected_directive_result"));
                }
                let expected: Option<(String, Option<bool>)> = state
                    .store
                    .db
                    .query_row(
                        "SELECT peer, result_ok FROM issued_directives WHERE id=?1",
                        [&result.id],
                        |r| Ok((r.get(0)?, r.get(1)?)),
                    )
                    .optional()?;
                let Some((peer, received)) = expected else {
                    return Err(Error("unexpected_directive_result"));
                };
                if peer != device.device_id {
                    return Err(Error("unexpected_directive_result"));
                }
                if received.is_some() {
                    return Err(Error("already_consumed"));
                }
                let transaction = state.store.transaction(self.services.audit.as_ref())?;
                transaction.execute("UPDATE issued_directives SET result_ok=?1, result_summary=?2 WHERE id=?3 AND result_ok IS NULL",
                    params![result.ok, result.error, result.id])?;
                self.cache_directive_result(&state, &device, &result)?;
                let directory_update = self.stage_directory(&state)?;
                self.audit(
                    &state,
                    "directive_result",
                    json!({"id": result.id,"peer":device.device_id,"ok":result.ok}),
                )?;
                transaction.commit()?;
                directory_update.commit()?;
                state
                    .directive_results
                    .insert(result.id.clone(), (device.device_id, result));
                Ok(())
            }
            EnvelopeType::DeviceRevoke => {
                let revoked: DeviceRevoke = from_json(&plaintext)?;
                kv_core::remote::validation::verify_device_revoke(
                    &revoked,
                    &device,
                    &self.account,
                )?;
                let known: bool = state.store.db.query_row(
                    "SELECT EXISTS(SELECT 1 FROM devices WHERE id=?1)",
                    [&revoked.device_id],
                    |r| r.get(0),
                )?;
                if known {
                    let tx = state.store.transaction(self.services.audit.as_ref())?;
                    let cancelled =
                        self.revoke_device_rows(&state, &revoked.device_id, &device.device_id)?;
                    let update = self.stage_directory(&state)?;
                    tx.commit()?;
                    update.commit()?;
                    Self::clear_revoked_device_state(&mut state, &revoked.device_id, cancelled);
                }
                Ok(())
            }
            _ => Err(Error("unsupported_type")),
        }
    }

    pub(crate) fn accept_decision(
        &self,
        state: &mut State,
        device: &DeviceRecord,
        decision: &ApprovalDecision,
        created_at: i64,
        now: i64,
    ) -> Result<()> {
        // Step 2: pending exists and is waiting, including after a helper restart.
        let pending = state.store.pending(&decision.approval_id)?;
        if pending.state != PendingState::Waiting {
            return Err(Error("not_waiting"));
        }
        // Step 3: bind the signed digest/nonce to the complete canonical snapshot.
        if pending.request.exp < now {
            return Err(Error("expired"));
        }
        if pending.canonical.digest()? != pending.request.digest
            || decision.digest != pending.request.digest
            || pending.canonical.exp != pending.request.exp
            || pending.canonical.kind != pending.request.kind
            || pending.canonical.requester != pending.request.requester.device_id
        {
            return Err(Error("digest_mismatch"));
        }
        if decision.nonce != pending.request.nonce
            || pending.canonical.nonce != pending.request.nonce
        {
            return Err(Error("nonce_mismatch"));
        }
        // Step 4: authority level is independent of presence and delivery.
        let required = if pending.request.kind != ApprovalKind::Use
            || pending.request.tier == Tier::T2
            || decision.scope.mode == ScopeMode::Standing
        {
            ApprovalLevel::Strong
        } else {
            pending.request.min_level
        };
        if decision.level < required {
            return Err(Error("insufficient_level"));
        }
        // Step 5: only the recorded approval key for this level may verify the whole object.
        if decision.approver_kind != ApproverKind::Device || decision.quorum.as_value().is_some() {
            return Err(Error("unsupported_authority"));
        }
        if decision.approver != device.device_id {
            return Err(Error("wrong_sender"));
        }
        verify_object(
            decision,
            &decision.sig,
            approval_key(device, decision.level)?,
        )?;
        let transaction = state.store.transaction(self.services.audit.as_ref())?;
        // Step 6: insert is atomic with the state transition and derived authorization.
        state
            .store
            .consume_nonce(&decision.nonce, &decision.digest, now, pending.request.exp)?;
        // Step 7: W0 validates the offered scope, after the atomic nonce insert, never before it.
        verify_decision(decision, &pending.request, &pending.canonical, device, now)?;
        if decision.decision == Decision::Allow {
            self.derive_grant_locked(state, &pending, decision)?;
        }
        let alive = self.services.runner.agent_alive(
            pending.canonical.agent.uid,
            pending.canonical.agent.pid,
            &pending.canonical.agent.exe_sha256,
        );
        let next = if decision.decision == Decision::Deny {
            PendingState::Denied
        } else if alive {
            PendingState::Approved
        } else {
            PendingState::ApprovedUnused
        };
        transaction.execute("UPDATE pending_approvals SET state=?1, resolved_at=?2, approver=?3, level=?4, scope_json=?5, decision_json=?6 WHERE id=?7 AND state='waiting'",
            params![next.as_str(), now, device.device_id, encode(&decision.level)?.trim_matches('"'), encode(&decision.scope)?, encode(decision)?, decision.approval_id])?;
        // Step 8: fail closed if the persistent audit or its existing vault sink is unavailable.
        self.audit(state, if decision.decision == Decision::Allow { "remote_approval_accepted" } else { "remote_approval_denied" }, json!({
            "approval_id": decision.approval_id, "digest": decision.digest, "approver_device": device.device_id, "decision": decision.decision, "decision_hash": sha256_hex(&jcs(decision)?),
            "approval_level": decision.level, "approval_latency_ms": now.saturating_sub(pending.created_at).saturating_mul(1000),
            "approval_path": "remote", "unattended_t2": false, "relay_clock_skew_s": now.saturating_sub(created_at), "state": next.as_str()
        }))?;
        for peer in state
            .store
            .devices(&self.account)?
            .iter()
            .filter(|peer| is_approver(peer))
        {
            state.store.queue(&self.seal(
                peer,
                EnvelopeType::ApprovalCancel,
                &decision.approval_id,
                now.saturating_add(60).min(pending.request.exp),
                &ApprovalCancel {
                    approval_id: decision.approval_id.clone(),
                    extra: Extra::new(),
                },
            )?)?;
        }
        transaction.commit()?;
        if decision.decision == Decision::Deny {
            state.full.remove(&decision.approval_id);
        }
        Ok(())
    }

    pub async fn execute_approved(self: &Arc<Self>, id: &str) -> Result<()> {
        let execution = {
            let mut state = self.lock()?;
            let pending = state.store.pending(id)?;
            if pending.state != PendingState::Approved
                || pending.request.exp < self.services.clock.now()
            {
                return Ok(());
            }
            if pending.epoch != state.store.setting::<u64>("epoch")?.unwrap_or(0) {
                self.reject(
                    &state,
                    "approval_execution_rejected",
                    Error("authorization_revoked"),
                    id,
                )?;
                self.cancel_locked(&mut state, id, PendingState::Cancelled)?;
                return Err(Error("authorization_revoked"));
            }
            let authority = (|| {
                let decision = pending.decision.as_ref().ok_or(Error("invalid_decision"))?;
                let device = state.store.device(&decision.approver, &self.account)?;
                verify_decision(
                    decision,
                    &pending.request,
                    &pending.canonical,
                    &device,
                    self.services.clock.now(),
                )?;
                if decision.decision != Decision::Allow {
                    return Err(Error("invalid_decision"));
                }
                Ok(())
            })();
            if let Err(error) = authority {
                self.reject(&state, "approval_execution_rejected", error, id)?;
                self.cancel_locked(&mut state, id, PendingState::Cancelled)?;
                return Err(error);
            }
            if !self.services.runner.agent_alive(
                pending.canonical.agent.uid,
                pending.canonical.agent.pid,
                &pending.canonical.agent.exe_sha256,
            ) {
                state.store.db.execute("UPDATE pending_approvals SET state='approved_unused' WHERE id=?1 AND state='approved'", [id])?;
                return Ok(());
            }
            let Some(full_request) = state.full.remove(id) else {
                return Ok(());
            };
            if pending
                .canonical
                .extra
                .get("execution_sha256")
                .and_then(Value::as_str)
                != Some(&full_request.binding_digest()?)
            {
                self.reject(
                    &state,
                    "approval_execution_rejected",
                    Error("digest_mismatch"),
                    id,
                )?;
                return Err(Error("digest_mismatch"));
            }
            // Claim before calling any runner. Crash after this point is never retried blindly.
            state.store.db.execute(
                "UPDATE pending_approvals SET state='executed' WHERE id=?1 AND state='approved'",
                [id],
            )?;
            self.audit(&state, "approval_execution_started", json!({"approval_id": id, "digest": pending.request.digest, "approval_path": "remote"}))?;
            state.executing.insert(id.into());
            Execution {
                canonical: pending.canonical,
                full_request,
                approval_id: id.into(),
            }
        };
        let mut result = self.services.runner.execute(execution).await;
        let mut state = match self.lock() {
            Ok(state) => state,
            Err(error) => {
                if let Ok(value) = &mut result {
                    kv_vault::scrub_json(value);
                }
                return Err(error);
            }
        };
        state.executing.remove(id);
        let mut value = match result {
            Ok(mut value) => {
                if let Err(error) = self.audit(
                    &state,
                    "approval_execution_completed",
                    json!({"approval_id": id, "ok": true}),
                ) {
                    kv_vault::scrub_json(&mut value);
                    return Err(error);
                }
                value
            }
            Err(error) => {
                self.reject(&state, "approval_execution_failed", error, id)?;
                json!({"ok": false, "error": {"code": error.code()}})
            }
        };
        // Expired results are never retained, even if a long-running operation finishes later.
        let pending = match state.store.pending(id) {
            Ok(pending) => pending,
            Err(error) => {
                kv_vault::scrub_json(&mut value);
                return Err(error);
            }
        };
        if pending.request.exp >= self.services.clock.now() {
            state.results.insert(id.into(), value);
        } else {
            kv_vault::scrub_json(&mut value);
        }
        drop(state);
        self.changed.notify_waiters();
        Ok(())
    }

    pub(crate) fn schedule_execution(self: &Arc<Self>, id: &str) -> Result<()> {
        let state = self.lock()?;
        let pending = state.store.pending(id)?;
        if pending.state == PendingState::Approved && state.full.contains_key(id) {
            let helper = self.clone();
            let id = id.to_owned();
            tokio::spawn(async move {
                if let Err(error) = helper.execute_approved(&id).await {
                    if let Ok(state) = helper.lock() {
                        let _ = helper.reject(&state, "approval_execution_rejected", error, &id);
                    }
                    helper.changed.notify_waiters();
                }
            });
        }
        Ok(())
    }

    /// Restore only helper-owned transport fields after a verified caller resends the same use.
    pub fn retry_canonical(
        &self,
        id: &str,
        mut canonical: CanonicalRequest,
        full: &FullRequest,
        uid: u32,
        agent_pid: u32,
    ) -> Result<CanonicalRequest> {
        let state = self.lock()?;
        let pending = state.store.pending(id)?;
        self.owns(&pending, uid, agent_pid)?;
        for field in ["session_id", "unlock_ttl_s"] {
            if let Some(value) = pending.canonical.extra.get(field) {
                canonical.extra.insert(field.into(), value.clone());
            }
        }
        canonical
            .extra
            .insert("execution_sha256".into(), json!(full.binding_digest()?));
        if retry_binding(&canonical)? != retry_binding(&pending.canonical)? {
            return Err(Error("digest_mismatch"));
        }
        Ok(canonical)
    }

    pub async fn retry(
        self: &Arc<Self>,
        id: &str,
        canonical: &CanonicalRequest,
        full: FullRequest,
        uid: u32,
        agent_pid: u32,
    ) -> Result<ToolResult> {
        self.tick()?;
        {
            let mut state = self.lock()?;
            let pending = state.store.pending(id)?;
            self.owns(&pending, uid, agent_pid)?;
            if pending.state != PendingState::Approved {
                return self.result_locked(&mut state, id, true);
            }
            if pending.request.exp < self.services.clock.now() {
                self.cancel_locked(&mut state, id, PendingState::Expired)?;
                return self.result_locked(&mut state, id, true);
            }
            let mut retry = canonical.clone();
            retry
                .extra
                .insert("execution_sha256".into(), json!(full.binding_digest()?));
            if retry_binding(&pending.canonical)? != retry_binding(&retry)? {
                self.reject(
                    &state,
                    "approval_retry_rejected",
                    Error("digest_mismatch"),
                    id,
                )?;
                return Err(Error("digest_mismatch"));
            }
            state.full.entry(id.into()).or_insert(full);
        }
        self.execute_approved(id).await?;
        self.result(id, uid, agent_pid, true)
    }

    pub(crate) fn owns(&self, pending: &Pending, uid: u32, agent_pid: u32) -> Result<()> {
        if pending.canonical.agent.uid != uid || pending.canonical.agent.pid != agent_pid {
            Err(Error("forbidden"))
        } else {
            Ok(())
        }
    }

    pub fn result(&self, id: &str, uid: u32, agent_pid: u32, claim: bool) -> Result<ToolResult> {
        self.tick()?;
        let mut state = self.lock()?;
        self.owns(&state.store.pending(id)?, uid, agent_pid)?;
        self.result_locked(&mut state, id, claim)
    }

    pub(crate) fn result_locked(
        &self,
        state: &mut State,
        id: &str,
        claim: bool,
    ) -> Result<ToolResult> {
        let pending = state.store.pending(id)?;
        let mut result = ToolResult {
            status: ToolStatus::ApprovalPending,
            approval_id: Optional::Value(id.into()),
            expires_at: Optional::Value(pending.request.exp),
            approver: Optional::Missing,
            wait_tool: Optional::Missing,
            next_steps: Optional::Missing,
            result: Optional::Missing,
            extra: Extra::new(),
        };
        result.status = match pending.state {
            PendingState::Waiting => ToolStatus::ApprovalPending,
            PendingState::Denied => ToolStatus::ApprovalDenied,
            PendingState::Cancelled => {
                result.extra.insert("reason".into(), json!("cancelled"));
                ToolStatus::ApprovalExpired
            }
            PendingState::Expired => ToolStatus::ApprovalExpired,
            PendingState::Approved if state.full.contains_key(id) => ToolStatus::StillPending,
            PendingState::Approved | PendingState::ApprovedUnused => {
                ToolStatus::ApprovedRetryRequired
            }
            PendingState::Executed if state.executing.contains(id) => ToolStatus::StillPending,
            PendingState::Executed
                if pending.claimed_at.is_some() || !state.results.contains_key(id) =>
            {
                ToolStatus::AlreadyConsumed
            }
            PendingState::Executed => {
                if claim {
                    state.store.db.execute("UPDATE pending_approvals SET claimed_at=?1 WHERE id=?2 AND claimed_at IS NULL", params![self.services.clock.now(), id])?;
                    result.result =
                        Optional::Value(state.results.remove(id).ok_or(Error("already_consumed"))?);
                    if let Some(frontend) = pending.canonical.extra.get("frontend") {
                        result.extra.insert("frontend".into(), frontend.clone());
                    }
                }
                ToolStatus::Ok
            }
        };
        if matches!(
            result.status,
            ToolStatus::ApprovalPending | ToolStatus::StillPending
        ) {
            let peers = state.store.devices(&self.account)?;
            if let Some(peer) = peers.iter().find(|p| is_approver(p)) {
                result.approver = Optional::Value(ToolApprover {
                    label: peer.label.clone(),
                    online: state.relay_connected
                        && state.hints.get(&peer.device_id).is_some_and(|hint| {
                            self.services.clock.now().saturating_sub(hint.received_at) <= 120
                        }),
                    extra: Extra::new(),
                });
            }
            result.wait_tool = Optional::Value("credential_wait_approval".into());
            result.next_steps = Optional::Value(kv_i18n::t("请继续其他工作，需要结果时调用 credential_wait_approval。不要重复请求，也不要索要密钥。", "Continue other work; call credential_wait_approval to retrieve this request's result. Do not repeat the request or ask for keys."));
        }
        Ok(result)
    }

    pub async fn wait(
        self: &Arc<Self>,
        id: &str,
        max_wait_ms: u64,
        runtime_budget_s: u64,
        uid: u32,
        agent_pid: u32,
    ) -> Result<ToolResult> {
        self.owns(&self.lock()?.store.pending(id)?, uid, agent_pid)?;
        let mut observation = WaitObservation {
            helper: self.clone(),
            uid,
            agent_pid,
            finished: false,
        };
        let result = self
            .wait_inner(id, max_wait_ms, runtime_budget_s, uid, agent_pid)
            .await;
        observation.finished = true;
        result
    }

    async fn wait_inner(
        self: &Arc<Self>,
        id: &str,
        max_wait_ms: u64,
        runtime_budget_s: u64,
        uid: u32,
        agent_pid: u32,
    ) -> Result<ToolResult> {
        let budget = self.config.wait_budget_ms(max_wait_ms, runtime_budget_s);
        let deadline = tokio::time::Instant::now() + Duration::from_millis(budget);
        loop {
            let notified = self.changed.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            self.schedule_execution(id)?;
            let mut result = self.result(id, uid, agent_pid, true)?;
            if !matches!(
                result.status,
                ToolStatus::ApprovalPending | ToolStatus::StillPending
            ) {
                return Ok(result);
            }
            let offline_waiting = {
                let state = self.lock()?;
                !state.relay_connected && state.store.pending(id)?.state == PendingState::Waiting
            };
            if tokio::time::Instant::now() >= deadline || offline_waiting {
                result.status = ToolStatus::StillPending;
                return Ok(result);
            }
            tokio::select! {
                _ = &mut notified => {},
                _ = tokio::time::sleep_until(deadline) => {},
                _ = tokio::time::sleep(Duration::from_secs(1)) => {},
            }
        }
    }

    pub fn start_timer(self: &Arc<Self>) -> tokio::task::JoinHandle<()> {
        let helper = Arc::downgrade(self);
        tokio::spawn(async move {
            let mut timer = tokio::time::interval(Duration::from_secs(1));
            loop {
                timer.tick().await;
                let Some(helper) = helper.upgrade() else {
                    return;
                };
                if helper.tick().is_err() {
                    // tick clears retained data on failure, including a poisoned owner.
                    helper.changed.notify_waiters();
                }
            }
        })
    }

    pub fn audit_entries(&self) -> Result<Vec<Value>> {
        self.lock()?.store.audit_entries()
    }

    fn decision_snapshot(
        &self,
        request: &ApprovalRequest,
    ) -> kv_core::remote::Result<Option<ApprovalDecision>> {
        let result = (|| {
            self.tick()?;
            let pending = self.lock()?.store.pending(&request.approval_id)?;
            if pending.request.digest != request.digest {
                return Err(Error("digest_mismatch"));
            }
            if let Some(decision) = pending.decision {
                return Ok(Some(decision));
            }
            if pending.state != PendingState::Waiting {
                return Err(Error("not_waiting"));
            }
            Ok(None)
        })();
        result.map_err(|error| match error.code() {
            "digest_mismatch" => RemoteError::DigestMismatch,
            "not_waiting" => RemoteError::NotWaiting,
            _ => RemoteError::KeyOperationFailed,
        })
    }

    /// The connection owner calls this when its authenticated agent session ends.
    pub fn close_session(&self, session: &str) -> Result<()> {
        let mut state = self.lock()?;
        let now = self.services.clock.now();
        let ids = state.store.pending_ids()?;
        let transaction = state.store.transaction(self.services.audit.as_ref())?;
        let mut cancelled = Vec::new();
        for id in ids {
            let pending = state.store.pending(&id)?;
            if pending.session_id == session
                && matches!(
                    pending.state,
                    PendingState::Waiting | PendingState::Approved | PendingState::ApprovedUnused
                )
            {
                self.cancel_in_transaction(&state, &id, PendingState::Cancelled)?;
                cancelled.push(id);
            }
        }
        transaction.execute(
            "UPDATE grants SET revoked_at=COALESCE(revoked_at,?1) WHERE session_id=?2",
            params![now, session],
        )?;
        transaction.execute(
            "DELETE FROM settings WHERE key=?1",
            [format!("unlock:{session}")],
        )?;
        self.audit(&state, "remote_session_closed", json!({"session":session}))?;
        transaction.commit()?;
        for id in cancelled {
            state.full.remove(&id);
        }
        self.changed.notify_waiters();
        Ok(())
    }

    pub fn unlock_until(&self, session: &str) -> Result<Option<i64>> {
        let until = self
            .lock()?
            .store
            .setting::<i64>(&format!("unlock:{session}"))?;
        Ok(until.filter(|until| *until >= self.services.clock.now()))
    }
}

pub struct RemoteDevice {
    pub helper: Arc<RemoteHelper>,
}

impl Approver for RemoteDevice {
    fn approver_kind(&self) -> ApproverKind {
        ApproverKind::Device
    }
    async fn approve(
        &self,
        request: &ApprovalRequest,
    ) -> kv_core::remote::Result<ApprovalDecision> {
        loop {
            let notified = self.helper.changed.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if let Some(decision) = self.helper.decision_snapshot(request)? {
                return Ok(decision);
            }
            tokio::select! { _ = &mut notified => {}, _ = tokio::time::sleep(Duration::from_secs(1)) => {} }
        }
    }
}

pub(crate) fn random_nonce() -> Result<String> {
    // A fresh cryptographic P-256 key supplies entropy without exporting its private scalar.
    let entropy = SoftwareDeviceKey::generate_p256().public_jwk()?;
    let hash = sha256_hex(&jcs(&entropy)?);
    // sha256_hex returns lowercase ASCII hex. Decode that fixed output without a fallible
    // parser whose error would imply a broken hash implementation, not invalid caller data.
    let nibble = |byte: u8| {
        if byte <= b'9' {
            byte - b'0'
        } else {
            byte - b'a' + 10
        }
    };
    let bytes: Vec<u8> = hash
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .take(16)
        .map(|pair| (nibble(pair[0]) << 4) | nibble(pair[1]))
        .collect();
    Ok(encode_b64(&bytes))
}

pub(crate) fn new_id(now: i64) -> Result<String> {
    let mut bytes = [0u8; 16];
    let milliseconds = now.max(0).saturating_mul(1000) as u64;
    bytes[..6].copy_from_slice(&milliseconds.to_be_bytes()[2..]);
    bytes[6..].copy_from_slice(&decode_b64(&random_nonce()?)?[..10]);
    let mut number = u128::from_be_bytes(bytes);
    let alphabet = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
    let mut output = [b'0'; 26];
    for byte in output.iter_mut().rev() {
        *byte = alphabet[(number & 31) as usize];
        number >>= 5;
    }
    Ok(output.iter().map(|byte| char::from(*byte)).collect())
}

pub(crate) fn is_approver(device: &DeviceRecord) -> bool {
    device.caps.contains(&Capability::ApproveQuick)
        || device.caps.contains(&Capability::ApproveStrong)
}

pub(crate) fn validate_device(device: &DeviceRecord) -> Result<()> {
    kv_core::remote::keys::p256_public_sec1(&device.dk_pub)?;
    let identity = kv_core::remote::keys::identity_verifying_jwk(device)?;
    for (level, key) in [
        (ApprovalLevel::Quick, &device.ak_q),
        (ApprovalLevel::Strong, &device.ak_s),
    ] {
        if let Some(key) = key {
            match key.alg {
                SignatureAlgorithm::ES256 => {
                    kv_core::remote::keys::p256_public_sec1(&key.r#pub)?;
                }
                SignatureAlgorithm::RS256 => {
                    kv_core::remote::keys::rsa_public_key(&key.r#pub)?;
                }
            }
            if key.r#pub == device.dk_pub || &key.r#pub == identity {
                return Err(Error("identity_cannot_approve"));
            }
        }
        let capability = if level == ApprovalLevel::Quick {
            Capability::ApproveQuick
        } else {
            Capability::ApproveStrong
        };
        if device.caps.contains(&capability) != key.is_some() {
            return Err(Error("invalid_device_capabilities"));
        }
    }
    if device
        .ak_q
        .as_ref()
        .zip(device.ak_s.as_ref())
        .is_some_and(|(q, s)| q.r#pub == s.r#pub)
    {
        return Err(Error("approval_keys_not_distinct"));
    }
    Ok(())
}

pub(crate) fn directory(store: &Store) -> Result<Vec<(DeviceRecord, bool)>> {
    let mut statement = store
        .db
        .prepare("SELECT record_json, revoked_at FROM devices ORDER BY id")?;
    let rows = statement.query_map([], |r| {
        Ok((r.get::<_, String>(0)?, r.get::<_, Option<i64>>(1)?))
    })?;
    rows.map(|row| {
        let (record, revoked) = row?;
        Ok((decode(&record)?, revoked.is_some()))
    })
    .collect()
}

fn protection_kind(kind: &KeyKind) -> ProtectionKind {
    match kind {
        KeyKind::Tpm2 => ProtectionKind::Tpm2,
        KeyKind::SecureEnclave => ProtectionKind::SecureEnclave,
        KeyKind::WindowsHello | KeyKind::PcpTpm => ProtectionKind::WindowsHello,
        KeyKind::Software => ProtectionKind::SoftwareKey,
        _ => ProtectionKind::Unknown(kind.as_str().into()),
    }
}

fn validate_display(request: &ApprovalRequest, canonical: &CanonicalRequest) -> Result<()> {
    if request.kind == ApprovalKind::Unlock {
        if request.credential.is_some()
            || request.operation.is_some()
            || canonical.credential.is_some()
        {
            return Err(Error("invalid_approval_request"));
        }
    } else if request.kind == ApprovalKind::Use {
        if request.credential.as_ref().map(|c| &c.r#ref) != canonical.credential.as_ref() {
            return Err(Error("digest_mismatch"));
        }
        if let Some(operation) = &request.operation {
            if canonical.method.as_ref() != Some(&operation.method)
                || canonical.host.as_ref() != Some(&operation.host)
                || canonical.path.as_ref() != Some(&operation.path)
                || canonical.query_keys != operation.query_keys
            {
                return Err(Error("digest_mismatch"));
            }
        }
    }
    Ok(())
}

pub(crate) fn signing_level<T: serde::Serialize>(
    value: &T,
    sig: &str,
    alg: SignatureAlgorithm,
    device: &DeviceRecord,
) -> Result<ApprovalLevel> {
    let mut matching_algorithm = false;
    for level in [ApprovalLevel::Strong, ApprovalLevel::Quick] {
        if let Ok(key) = approval_key(device, level) {
            if key.alg == alg {
                matching_algorithm = true;
                if verify_object(value, sig, key).is_ok() {
                    return Ok(level);
                }
            }
        }
    }
    Err(Error(if matching_algorithm {
        "invalid_signature"
    } else {
        "unsupported_algorithm"
    }))
}
