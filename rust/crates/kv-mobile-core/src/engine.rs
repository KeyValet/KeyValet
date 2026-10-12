use crate::{new_id, now, view::*, Error, Result, Store};
use kv_core::remote::{
    self as remote,
    canonical::{from_json, jcs, sha256_hex},
    keys::{decode_b64, encode_b64, sign_object},
    *,
};
use serde::{Deserialize, Serialize};
use std::{
    path::Path,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
};
use zeroize::Zeroizing;

pub type Key = Arc<dyn DeviceKeyProvider + Send + Sync>;
pub struct MobileKeys {
    pub identity: Key,
    pub quick: Key,
    pub strong: Key,
}
pub struct MobileCore {
    pub(crate) store: Store,
    pub(crate) keys: MobileKeys,
    pub(crate) own: DeviceRecord,
    pub(crate) connected: AtomicBool,
    pub(crate) login_required: AtomicBool,
}

#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct Pending {
    pub request: ApprovalRequest,
    pub created_at: i64,
    pub skew: bool,
    pub escalated: bool,
}
#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct Candidate {
    pub peer: DeviceRecord,
    pub account: String,
    pub pairing_id: String,
    pub sas: String,
    pub exp: i64,
    #[serde(default)]
    pub local_confirm: Option<PairConfirm>,
    #[serde(default)]
    pub peer_confirmed: bool,
    #[serde(default)]
    pub exclude_global: bool,
    #[serde(default)]
    pub peer_exclude_global: bool,
    #[serde(default)]
    pub accept: Option<Envelope>,
    #[serde(default)]
    pub confirmation_envelope: Option<Envelope>,
    #[serde(default)]
    pub finish_sent: bool,
    #[serde(default)]
    pub token_hash: Option<String>,
}
#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct IssuedGrant {
    pub grant: Grant,
    pub revoked: bool,
}
#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct IssuedDirective {
    pub directive: Directive,
    pub level: ApprovalLevel,
}

impl MobileCore {
    pub fn open(directory: &Path, keys: MobileKeys, label: &str, os: Os) -> Result<Self> {
        let dk = keys.identity.public_jwk()?;
        let q = keys.quick.public_jwk()?;
        let s = keys.strong.public_jwk()?;
        if dk == q || dk == s || q == s {
            return Err(Error("distinct_keys_required"));
        }
        let public = remote::keys::p256_public_sec1(&dk)?;
        let shared = keys.identity.ecdh(&public)?;
        let mut storage_key = Zeroizing::new([0; 32]);
        hkdf::Hkdf::<sha2::Sha256>::new(Some(b"keyvalet/mobile/storage/v1"), shared.as_ref())
            .expand(&public, storage_key.as_mut())
            .map_err(|_| Error("invalid_key"))?;
        let store = Store::open(directory, storage_key)?;
        let own = store.transaction(|db| {
            if let Some(own) = store.get::<DeviceRecord>(db, "meta", "own")? {
                if own.dk_pub != dk
                    || own.ak_q.as_ref().map(|k| &k.r#pub) != Some(&q)
                    || own.ak_s.as_ref().map(|k| &k.r#pub) != Some(&s)
                {
                    return Err(Error("identity_changed"));
                }
                let mut settings: SettingsView = store
                    .get(db, "meta", "settings")?
                    .ok_or(Error("storage_integrity"))?;
                if (!cfg!(test) && settings.relay_url != crate::RELAY_URL)
                    || settings.relay_url == "https://relay.example.com/"
                {
                    if !store.list::<DeviceRecord>(db, "peers")?.is_empty() {
                        return Err(Error("fixed_relay_migration_required"));
                    }
                    settings.relay_url = SettingsView::default().relay_url;
                    store.put(db, "meta", "settings", &settings, 0)?;
                }
                return Ok(own);
            }
            if label.trim().is_empty() || label.len() > 120 {
                return Err(Error("invalid_label"));
            }
            let own = DeviceRecord {
                device_id: format!("dev_{}", new_id()),
                label: label.into(),
                os,
                key_kind: keys.identity.key_kind(),
                dk_pub: dk,
                dk_sig: kv_core::remote::Optional::Missing,
                ak_q: Some(ApprovalKey {
                    r#pub: q,
                    alg: SignatureAlgorithm::ES256,
                    extra: Extra::new(),
                }),
                ak_s: Some(ApprovalKey {
                    r#pub: s,
                    alg: SignatureAlgorithm::ES256,
                    extra: Extra::new(),
                }),
                caps: vec![Capability::ApproveQuick, Capability::ApproveStrong],
                attestation: None,
                extra: Extra::new(),
            };
            store.put(db, "meta", "own", &own, 0)?;
            store.put(db, "meta", "settings", &SettingsView::default(), 0)?;
            Ok(own)
        })?;
        store.transaction(|db| {
            if store.get::<kv_core::remote::audit::AuditHead>(db,"meta","audit_head")?.is_none() {
                let incomplete:bool=db.query_row("SELECT EXISTS(SELECT 1 FROM records WHERE bucket IN ('issued_decisions','issued_grants','issued_directives'))",[],|row|row.get(0))?;
                store.put(db,"meta","audit_history_incomplete",&incomplete,0)?;
                store.put(db,"meta","audit_started_at",&now().saturating_add(1),0)?;
                store.put(db,"meta","audit_head",&kv_core::remote::audit::AuditHead::default(),0)?;
            }
            Ok(())
        })?;
        Ok(Self {
            // Existing issued ledgers cannot reconstruct delivery bindings after UI history
            // rotation. Record that boundary instead of declaring an empty audit complete.
            store,
            keys,
            own,
            connected: AtomicBool::new(false),
            // Software protocol fixtures opt into authentication explicitly.
            // Every production constructor and both native bindings require it.
            login_required: AtomicBool::new(!cfg!(test)),
        })
    }

    pub fn device(&self) -> &DeviceRecord {
        &self.own
    }
    pub(crate) fn account(&self) -> Result<String> {
        self.store.transaction(|db| {
            self.store
                .get(db, "meta", "account")?
                .ok_or(Error("pairing_required"))
        })
    }
    pub fn settings(&self) -> Result<SettingsView> {
        self.store.transaction(|db| {
            self.store
                .get(db, "meta", "settings")?
                .ok_or(Error("storage_integrity"))
        })
    }
    pub fn set_preferences(&self, away: bool, notifications: bool, locale: &str) -> Result<()> {
        if !matches!(locale, "en" | "zh") {
            return Err(Error("unsupported_locale"));
        }
        self.store.transaction(|db| {
            let mut settings: SettingsView = self
                .store
                .get(db, "meta", "settings")?
                .ok_or(Error("storage_integrity"))?;
            settings.away_from_computer = away;
            settings.notifications = notifications;
            settings.locale = locale.into();
            self.store.put(db, "meta", "settings", &settings, 0)
        })
    }
    pub fn set_relay(&self, relay: &str) -> Result<()> {
        let canonical = crate::relay::validate_app_relay(relay, cfg!(test))?.to_string();
        self.store.transaction(|db| {
            let mut settings: SettingsView = self
                .store
                .get(db, "meta", "settings")?
                .ok_or(Error("storage_integrity"))?;
            if canonical != settings.relay_url
                && !self.store.list::<DeviceRecord>(db, "peers")?.is_empty()
            {
                return Err(Error("relay_bound_to_pairing"));
            }
            settings.relay_url = canonical;
            self.store.put(db, "meta", "settings", &settings, 0)
        })
    }

    pub(crate) fn save_candidate(&self, candidate: &Candidate) -> Result<PairingView> {
        if !candidate.peer.caps.contains(&Capability::Execute) {
            return Err(Error("executor_required"));
        }
        self.store.transaction(|db| {
            self.store
                .put(db, "meta", "candidate", candidate, candidate.exp)?;
            self.store
                .put(db, "meta", "account", &candidate.account, 0)?;
            let global_grants = self
                .store
                .list::<IssuedGrant>(db, "issued_grants")?
                .iter()
                .filter(|(_, g)| {
                    g.grant.aud == "*" && !g.revoked && g.grant.exp.is_none_or(|exp| exp >= now())
                })
                .count() as u32;
            Ok(PairingView {
                pairing_id: candidate.pairing_id.clone(),
                peer_label: candidate.peer.label.clone(),
                sas: candidate.sas.clone(),
                expires_at: candidate.exp,
                global_grants,
            })
        })
    }
    pub(crate) fn candidate(&self) -> Result<Candidate> {
        self.store.transaction(|db| {
            self.store
                .get(db, "meta", "candidate")?
                .ok_or(Error("pairing_required"))
        })
    }

    pub(crate) fn pairing_envelope<T: Serialize>(
        &self,
        candidate: &Candidate,
        kind: EnvelopeType,
        payload: &T,
    ) -> Result<Envelope> {
        Ok(remote::envelope::seal(
            EnvelopeHeader {
                v: 1,
                r#type: kind,
                id: candidate.pairing_id.clone(),
                account: candidate.account.clone(),
                from: self.own.device_id.clone(),
                to: candidate.peer.device_id.clone(),
                created_at: now(),
                exp: candidate.exp,
                extra: Extra::new(),
            },
            &jcs(payload)?,
            &candidate.peer.dk_pub,
            self.keys.identity.as_ref(),
        )?)
    }
    pub(crate) fn trust_candidate(
        &self,
        candidate: &Candidate,
        exclude_global: bool,
    ) -> Result<()> {
        self.ensure_login()?;
        let globals = self
            .store
            .transaction(|db| self.store.list::<IssuedGrant>(db, "issued_grants"))?;
        let mut envelopes = Vec::new();
        if !exclude_global {
            for (_, issued) in globals {
                let g = issued.grant;
                if g.aud == "*" && !issued.revoked && g.exp.is_none_or(|e| e > now()) {
                    envelopes.push(remote::envelope::seal(
                        EnvelopeHeader {
                            v: 1,
                            r#type: EnvelopeType::Grant,
                            id: g.jti.clone(),
                            account: candidate.account.clone(),
                            from: self.own.device_id.clone(),
                            to: candidate.peer.device_id.clone(),
                            created_at: now(),
                            exp: g.exp.unwrap_or(now() + 86400).min(now() + 86400),
                            extra: Extra::new(),
                        },
                        &jcs(&g)?,
                        &candidate.peer.dk_pub,
                        self.keys.identity.as_ref(),
                    )?);
                }
            }
        }
        self.store.transaction(|db| {
            if candidate.exp <= now() {
                return Err(Error("pairing_expired"));
            }
            self.store
                .put(db, "peers", &candidate.peer.device_id, &candidate.peer, 0)?;
            for envelope in &envelopes {
                self.enqueue(db, envelope)?;
            }
            self.store.put(
                db,
                "exclusions",
                &candidate.peer.device_id,
                &exclude_global,
                0,
            )?;
            Store::delete(db, "meta", "candidate")?;
            self.activity(
                db,
                &candidate.pairing_id,
                &candidate.peer.device_id,
                "pair",
                "Device paired",
                true,
            )
        })
    }

    pub(crate) fn peer(&self, id: &str) -> Result<DeviceRecord> {
        self.store.transaction(|db| {
            self.store
                .get(db, "peers", id)?
                .ok_or(Error("unpaired_sender"))
        })
    }

    /// No caller may supply a key, level, nonce, digest or arbitrary signed payload.
    pub fn decide(
        &self,
        id: &str,
        scope: &str,
        allow: bool,
        reason: &str,
        background: bool,
    ) -> Result<String> {
        self.ensure_login()?;
        let pending: Pending = self.store.transaction(|db| {
            self.store
                .get(db, "pending", id)?
                .ok_or(Error("not_waiting"))
        })?;
        let request = &pending.request;
        if request.exp <= now() {
            return Err(Error("approval_expired"));
        }
        let selected: ScopeOption =
            serde_json::from_value(scope.into()).map_err(|_| Error("invalid_scope"))?;
        if !request.scope_options.contains(&selected)
            || (request.tier == Tier::T2 && selected != ScopeOption::PerUse)
        {
            return Err(Error("invalid_scope"));
        }
        let standing = matches!(
            selected,
            ScopeOption::StandingCredential | ScopeOption::StandingDevice
        );
        let strong = request.min_level == ApprovalLevel::Strong
            || request.tier == Tier::T2
            || request.kind != ApprovalKind::Use
            || standing;
        if background && (strong || selected != ScopeOption::PerUse) {
            return Err(Error("open_app_required"));
        }
        if reason.len() > 512 {
            return Err(Error("invalid_reason"));
        }
        let issued = now();
        let (mode, level, until) = match selected {
            ScopeOption::PerUse => (ScopeMode::PerUse, DecisionScopeLevel::Credential, 0),
            ScopeOption::PerCredential => {
                (ScopeMode::PerCredential, DecisionScopeLevel::Credential, 0)
            }
            ScopeOption::PerSession => (ScopeMode::PerSession, DecisionScopeLevel::Device, 0),
            ScopeOption::Remember1h => (
                ScopeMode::Remember,
                DecisionScopeLevel::Credential,
                issued + 3600,
            ),
            ScopeOption::Remember8h => (
                ScopeMode::Remember,
                DecisionScopeLevel::Credential,
                issued + 28800,
            ),
            ScopeOption::Remember24h => (
                ScopeMode::Remember,
                DecisionScopeLevel::Credential,
                issued + 86400,
            ),
            ScopeOption::StandingCredential => {
                (ScopeMode::Standing, DecisionScopeLevel::Credential, 0)
            }
            ScopeOption::StandingDevice => (ScopeMode::Standing, DecisionScopeLevel::Device, 0),
        };
        let level_key = if strong {
            ApprovalLevel::Strong
        } else {
            ApprovalLevel::Quick
        };
        let mut decision = ApprovalDecision {
            approval_id: id.into(),
            digest: request.digest.clone(),
            nonce: request.nonce.clone(),
            decision: if allow {
                Decision::Allow
            } else {
                Decision::Deny
            },
            level: level_key,
            scope: DecisionScope {
                mode,
                level,
                until,
                extra: Extra::new(),
            },
            approver: self.own.device_id.clone(),
            approver_kind: ApproverKind::Device,
            quorum: Optional::Missing,
            issued_at: issued,
            reason: if reason.is_empty() {
                Optional::Missing
            } else {
                Optional::Value(reason.into())
            },
            sig: String::new(),
            extra: Extra::new(),
        };
        decision.sig = sign_object(&decision, SignatureAlgorithm::ES256, self.signer(level_key))?;
        let envelope = self.seal(
            EnvelopeType::ApprovalDecision,
            id,
            &request.requester.device_id,
            &decision,
            request.exp,
        )?;
        self.store.transaction(|db| {
            // Biometric UI may take time; recheck immutable state under the cross-process lock.
            let current: Pending = self
                .store
                .get(db, "pending", id)?
                .ok_or(Error("not_waiting"))?;
            if current.request != *request || request.exp <= now() {
                return Err(Error("not_waiting"));
            }
            self.enqueue(db, &envelope)?;
            self.store.put(db, "issued_decisions", id, &decision, 0)?;
            self.audit_event(db,serde_json::json!({"op":"remote_approval_issued","approval_id":decision.approval_id,"digest":decision.digest,"peer":request.requester.device_id,"approval_level":decision.level,"decision":decision.decision,"decision_hash":sha256_hex(&jcs(&decision)?)}))?;
            Store::delete(db, "pending", id)?;
            self.store
                .put(db, "closed", id, &request.requester.device_id, request.exp)?;
            self.activity(
                db,
                id,
                &request.requester.device_id,
                "decision",
                if allow { "Allowed" } else { "Denied" },
                false,
            )
        })?;
        Ok(id.into())
    }

    pub fn issue_grant(&self, input: &GrantInput) -> Result<String> {
        self.ensure_login()?;
        let global = input.scope == "global";
        let peers: Vec<DeviceRecord> = if global {
            self.store.transaction(|db| {
                let mut peers = Vec::new();
                for (id, peer) in self.store.list::<DeviceRecord>(db, "peers")? {
                    if !self
                        .store
                        .get::<bool>(db, "exclusions", &id)?
                        .unwrap_or(false)
                    {
                        peers.push(peer);
                    }
                }
                Ok(peers)
            })?
        } else {
            vec![self.peer(&input.device_id)?]
        };
        if peers.is_empty() || peers.iter().any(|p| !p.caps.contains(&Capability::Execute)) {
            return Err(Error("executor_required"));
        }
        let scope = match input.scope.as_str() {
            "credential" => GrantScopeLevel::Credential,
            "device" => GrantScopeLevel::Device,
            "global" => GrantScopeLevel::Global,
            _ => return Err(Error("invalid_scope")),
        };
        if scope == GrantScopeLevel::Credential
            && (input.credential.is_empty() || input.credential.len() > 256)
        {
            return Err(Error("credential_required"));
        }
        if !input.standing && !(1..=168).contains(&input.hours) {
            return Err(Error("invalid_expiry"));
        }
        if input.sensitive && (global || input.confirmation != peers[0].label) {
            return Err(Error("confirmation_required"));
        }
        // Settings origin always requires Strong under W0's verifier, including short tickets.
        // Product J-R3b's Quick one-hour settings ticket requires a shared contract change.
        let mut grant = Grant {
            kind: GrantKind::Grant,
            jti: new_id(),
            iss: self.own.device_id.clone(),
            iss_alg: SignatureAlgorithm::ES256,
            iss_kind: IssuerKind::Device,
            aud: if global {
                "*".into()
            } else {
                input.device_id.clone()
            },
            scope: GrantScope {
                level: scope,
                credential: if input.credential.is_empty() {
                    Optional::Missing
                } else {
                    Optional::Value(input.credential.clone())
                },
                hosts: Optional::Missing,
                methods: Optional::Missing,
                paths: Optional::Missing,
                agent: Optional::Missing,
                max_tier: if input.sensitive { Tier::T2 } else { Tier::T1 },
                extra: Extra::new(),
            },
            budget: if input.calls == 0 {
                Optional::Missing
            } else {
                Optional::Value(Budget {
                    calls: u64::from(input.calls),
                    per: BudgetPeriod::OneHour,
                    bytes: Optional::Missing,
                    extra: Extra::new(),
                })
            },
            nbf: now(),
            exp: if input.standing {
                None
            } else {
                Some(now() + i64::from(input.hours) * 3600)
            },
            origin: "settings".into(),
            confirm: if input.sensitive {
                Optional::Value(input.confirmation.clone())
            } else {
                Optional::Missing
            },
            sig: String::new(),
            extra: Extra::new(),
        };
        grant.sig = sign_object(
            &grant,
            SignatureAlgorithm::ES256,
            self.signer(ApprovalLevel::Strong),
        )?;
        let envelopes = peers
            .iter()
            .map(|p| {
                self.seal(
                    EnvelopeType::Grant,
                    &grant.jti,
                    &p.device_id,
                    &grant,
                    grant.exp.unwrap_or(now() + 86400).min(now() + 86400),
                )
            })
            .collect::<Result<Vec<_>>>()?;
        self.store.transaction(|db| {
            for envelope in &envelopes {
                self.enqueue(db, envelope)?;
            }
            self.store.put(
                db,
                "issued_grants",
                &grant.jti,
                &IssuedGrant {
                    grant: grant.clone(),
                    revoked: false,
                },
                0,
            )?;
            self.audit_event(db,serde_json::json!({"op":"grant_issued","jti":grant.jti,"iss":grant.iss,"aud":grant.aud,"recipients":peers.iter().map(|p|&p.device_id).collect::<Vec<_>>(),"max_tier":grant.scope.max_tier,"grant_hash":sha256_hex(&jcs(&grant)?)}))?;
            self.activity(
                db,
                &grant.jti,
                &input.device_id,
                "grant",
                if input.sensitive {
                    "Unattended grant"
                } else {
                    "Grant issued"
                },
                false,
            )
        })?;
        Ok(grant.jti)
    }

    pub fn directive(
        &self,
        peer_id: &str,
        op: DirectiveOp,
        mut args: Extra,
        confirmation: &str,
    ) -> Result<String> {
        self.ensure_login()?;
        let peer = self.peer(peer_id)?;
        if op == DirectiveOp::RevokeDevice && confirmation != peer.label {
            return Err(Error("confirmation_required"));
        }
        if op == DirectiveOp::RevokeDevice {
            args.insert("confirm".into(), confirmation.into());
        }
        let mut directive = Directive {
            kind: DirectiveKind::Directive,
            id: new_id(),
            iss: self.own.device_id.clone(),
            iss_alg: SignatureAlgorithm::ES256,
            iss_kind: IssuerKind::Device,
            aud: peer_id.into(),
            op,
            args,
            nonce: random_nonce(),
            exp: now() + 300,
            sig: String::new(),
            extra: Extra::new(),
        };
        let state: DeviceView = self.store.transaction(|db| {
            Ok(self
                .store
                .get(db, "device_state", peer_id)?
                .unwrap_or_default())
        })?;
        let current = remote::validation::DirectiveState {
            mode: if state.mode.is_empty() {
                None
            } else {
                Some(state.mode)
            },
            unlock_ttl_s: if state.unlock_ttl_s == 0 {
                None
            } else {
                Some(u64::from(state.unlock_ttl_s))
            },
            classes: Default::default(),
        };
        let level = match remote::validation::directive_required_level(&directive, &current) {
            Ok(level) => level,
            Err(RemoteError::MissingState) => ApprovalLevel::Strong,
            Err(error) => return Err(error.into()),
        };
        directive.sig = sign_object(&directive, SignatureAlgorithm::ES256, self.signer(level))?;
        let envelope = self.seal(
            EnvelopeType::Directive,
            &directive.id,
            peer_id,
            &directive,
            directive.exp,
        )?;
        self.store.transaction(|db| {
            self.enqueue(db, &envelope)?;
            self.store.put(
                db,
                "issued_directives",
                &directive.id,
                &IssuedDirective {
                    directive: directive.clone(),
                    level,
                },
                0,
            )?;
            self.audit_event(db,serde_json::json!({"op":"directive_issued","id":directive.id,"peer":peer_id,"directive_op":directive.op,"directive_hash":sha256_hex(&jcs(&directive)?)}))?;
            self.activity(
                db,
                &directive.id,
                peer_id,
                "directive",
                &serde_json::to_string(&op)?.replace('"', ""),
                false,
            )
        })?;
        Ok(directive.id)
    }

    fn signer(&self, level: ApprovalLevel) -> &(dyn DeviceKeyProvider + Send + Sync) {
        if level == ApprovalLevel::Strong {
            self.keys.strong.as_ref()
        } else {
            self.keys.quick.as_ref()
        }
    }
    fn seal<T: Serialize>(
        &self,
        kind: EnvelopeType,
        id: &str,
        peer_id: &str,
        payload: &T,
        exp: i64,
    ) -> Result<Envelope> {
        let peer = self.peer(peer_id)?;
        Ok(remote::envelope::seal(
            EnvelopeHeader {
                v: 1,
                r#type: kind,
                id: id.into(),
                account: self.account()?,
                from: self.own.device_id.clone(),
                to: peer_id.into(),
                created_at: now(),
                exp,
                extra: Extra::new(),
            },
            &jcs(payload)?,
            &peer.dk_pub,
            self.keys.identity.as_ref(),
        )?)
    }
    pub(crate) fn enqueue(&self, db: &rusqlite::Connection, envelope: &Envelope) -> Result<()> {
        // Recheck after hardware authentication and under the shared database lock.
        self.ensure_login_in(db)?;
        if self.store.list::<Envelope>(db, "outbox")?.len() >= 500 {
            return Err(Error("queue_full"));
        }
        self.store.put(
            db,
            "outbox",
            &format!(
                "{}:{}:{}",
                envelope.id,
                envelope.r#type.as_str(),
                envelope.to
            ),
            envelope,
            envelope.exp,
        )
    }
    fn activity(
        &self,
        db: &rusqlite::Connection,
        id: &str,
        peer: &str,
        kind: &str,
        summary: &str,
        delivered: bool,
    ) -> Result<()> {
        let value = ActivityView {
            id: id.into(),
            device_id: peer.into(),
            kind: kind.into(),
            summary: summary.into(),
            at: now(),
            delivered,
        };
        self.store.put(db, "activity", id, &value, 0)
    }

    pub fn receive(&self, bytes: &[u8]) -> Result<Option<NotificationView>> {
        self.ensure_login()?;
        if bytes.len() > remote::envelope::MAX_ENVELOPE_BYTES {
            return Err(Error("invalid_envelope"));
        }
        let envelope: Envelope = from_json(bytes)?;
        if envelope.account != self.account()? {
            return Err(Error("wrong_account"));
        }
        if envelope.r#type == EnvelopeType::PairConfirm {
            return self.receive_pair_confirm(&envelope).map(|()| None);
        }
        if self
            .candidate()
            .is_ok_and(|candidate| candidate.peer.device_id == envelope.from)
        {
            return Err(Error("pairing_pending"));
        }
        let peer = self.peer(&envelope.from)?;
        let plaintext = remote::envelope::open(
            &envelope,
            &self.own.device_id,
            self.keys.identity.as_ref(),
            &peer,
            now(),
        )?;
        let receipt = format!(
            "{}:{}:{}",
            envelope.from,
            envelope.id,
            envelope.r#type.as_str()
        );
        let hash = sha256_hex(&jcs(&envelope)?);
        self.store.transaction(|db| {
            Store::expire(db, now())?;
            if let Some(previous) = self.store.get::<String>(db, "inbox", &receipt)? {
                if previous != hash {
                    return Err(Error("replay_conflict"));
                }
                return Ok(None);
            }
            let settings: SettingsView = self
                .store
                .get(db, "meta", "settings")?
                .ok_or(Error("storage_integrity"))?;
            let mut result = None;
            match envelope.r#type {
                EnvelopeType::Directive => {
                    let directive: Directive = from_json(&plaintext)?;
                    self.answer_audit(db, &envelope, &peer, &directive)?;
                }
                EnvelopeType::ApprovalRequest => {
                    let request: ApprovalRequest = from_json(&plaintext)?;
                    validate_request(&request, &envelope)?;
                    if request.requester.label != peer.label
                        || request.requester.os != peer.os
                        || request.requester.protection.kind.as_str()
                            != if peer.key_kind == KeyKind::Software {
                                "software_key"
                            } else {
                                peer.key_kind.as_str()
                            }
                    {
                        return Err(Error("requester_mismatch"));
                    }
                    if self
                        .store
                        .get::<String>(db, "closed", &request.approval_id)?
                        .as_deref()
                        != Some(envelope.from.as_str())
                    {
                        let existing: Option<Pending> =
                            self.store.get(db, "pending", &request.approval_id)?;
                        if existing.as_ref().is_some_and(|p| p.request != request) {
                            return Err(Error("replay_conflict"));
                        }
                        let escalated = self
                            .store
                            .get::<String>(db, "escalations", &request.approval_id)?
                            .is_some_and(|s| s == envelope.from);
                        let pending = Pending {
                            request,
                            created_at: envelope.created_at,
                            skew: now().abs_diff(envelope.created_at) > 60,
                            escalated,
                        };
                        result = Some(notification(&approval_view(&pending, &settings), &settings));
                        self.store.put(
                            db,
                            "pending",
                            &pending.request.approval_id,
                            &pending,
                            pending.request.exp,
                        )?;
                    }
                }
                EnvelopeType::ApprovalEscalate => {
                    let control: ApprovalEscalate = from_json(&plaintext)?;
                    if control.approval_id != envelope.id {
                        return Err(Error("invalid_binding"));
                    }
                    if let Some(mut pending) =
                        self.store.get::<Pending>(db, "pending", &envelope.id)?
                    {
                        if pending.request.requester.device_id != envelope.from {
                            return Err(Error("wrong_requester"));
                        }
                        pending.escalated = true;
                        result = Some(notification(&approval_view(&pending, &settings), &settings));
                        self.store.put(
                            db,
                            "pending",
                            &envelope.id,
                            &pending,
                            pending.request.exp,
                        )?;
                    } else {
                        self.store.put(
                            db,
                            "escalations",
                            &envelope.id,
                            &envelope.from,
                            envelope.exp,
                        )?;
                    }
                }
                EnvelopeType::ApprovalCancel => {
                    let control: ApprovalCancel = from_json(&plaintext)?;
                    if control.approval_id != envelope.id {
                        return Err(Error("invalid_binding"));
                    }
                    if let Some(pending) = self.store.get::<Pending>(db, "pending", &envelope.id)? {
                        if pending.request.requester.device_id != envelope.from {
                            return Err(Error("wrong_requester"));
                        }
                    }
                    Store::delete(db, "pending", &envelope.id)?;
                    self.store
                        .put(db, "closed", &envelope.id, &envelope.from, now() + 86400)?;
                    result = Some(cancel_notification(&envelope.id));
                }
                EnvelopeType::DirectiveResult => {
                    let response: DirectiveResult = from_json(&plaintext)?;
                    let issued: IssuedDirective = self
                        .store
                        .get(db, "issued_directives", &response.id)?
                        .ok_or(Error("unsolicited_result"))?;
                    if response.id != envelope.id || issued.directive.aud != envelope.from {
                        return Err(Error("invalid_binding"));
                    }
                    if response.ok {
                        self.apply_result(db, &peer, &issued.directive, &response)?;
                    }
                    self.activity(
                        db,
                        &response.id,
                        &peer.device_id,
                        "directive_result",
                        if response.ok { "Applied" } else { "Rejected" },
                        true,
                    )?;
                }
                EnvelopeType::PresenceHint => {
                    let hint: PresenceHint = from_json(&plaintext)?;
                    if hint.device_id != peer.device_id {
                        return Err(Error("invalid_binding"));
                    }
                    if hint.sent_at > now() + 60 || hint.sent_at < now() - 120 {
                        return Err(Error("stale_presence"));
                    }
                    self.store.put(
                        db,
                        "presence",
                        &peer.device_id,
                        &(hint.state == Presence::Present),
                        hint.sent_at + 120,
                    )?;
                }
                EnvelopeType::DeviceRevoke => {
                    let value: DeviceRevoke = from_json(&plaintext)?;
                    remote::validation::verify_device_revoke(&value, &peer, &envelope.account)?;
                    Store::delete(db, "peers", &value.device_id)?;
                    for (key, pending) in self.store.list::<Pending>(db, "pending")? {
                        if pending.request.requester.device_id == value.device_id {
                            Store::delete(db, "pending", &key)?;
                        }
                    }
                    for (key, outgoing) in self.store.list::<Envelope>(db, "outbox")? {
                        if outgoing.to == value.device_id {
                            Store::delete(db, "outbox", &key)?;
                        }
                    }
                }
                _ => return Err(Error("unsupported_message")),
            }
            self.store
                .put(db, "inbox", &receipt, &hash, now() + 7 * 86400)?;
            Ok(result)
        })
    }

    fn receive_pair_confirm(&self, envelope: &Envelope) -> Result<()> {
        let candidate = self.candidate()?;
        if envelope.from != candidate.peer.device_id
            || envelope.id != candidate.pairing_id
            || envelope.exp > candidate.exp
            || candidate.exp <= now()
        {
            return Err(Error("invalid_pair_confirmation"));
        }
        let plaintext = remote::envelope::open(
            envelope,
            &self.own.device_id,
            self.keys.identity.as_ref(),
            &candidate.peer,
            now(),
        )?;
        let confirm: PairConfirm = from_json(&plaintext)?;
        if let Some(key) = &candidate.peer.ak_s {
            remote::pairing::verify_confirm(&confirm, &candidate.sas, key)?;
            let record: DeviceRecord = serde_json::from_value(
                confirm
                    .extra
                    .get("device")
                    .cloned()
                    .ok_or(Error("pair_key_mismatch"))?,
            )?;
            if !remote::validation::same_device_authority(&candidate.peer, &record) {
                return Err(Error("pair_key_mismatch"));
            }
        } else if !confirm.sig.is_empty() || confirm.sas != candidate.sas {
            return Err(Error("sas_mismatch"));
        }
        self.store.transaction(|db| {
            let mut current: Candidate = self
                .store
                .get(db, "meta", "candidate")?
                .ok_or(Error("pairing_required"))?;
            if current.sas != candidate.sas || current.peer != candidate.peer {
                return Err(Error("invalid_pair_confirmation"));
            }
            current.peer_confirmed = true;
            current.peer_exclude_global |=
                confirm.extra.get("exclude_global") == Some(&serde_json::json!(true));
            if let Some(value) = confirm.extra.get("device") {
                let record: DeviceRecord = serde_json::from_value(value.clone())?;
                if !remote::validation::same_device_authority(&candidate.peer, &record) {
                    return Err(Error("pair_key_mismatch"));
                }
                current.peer.label = record.label;
            }
            self.store
                .put(db, "meta", "candidate", &current, current.exp)
        })
    }

    fn apply_result(
        &self,
        db: &rusqlite::Connection,
        peer: &DeviceRecord,
        directive: &Directive,
        response: &DirectiveResult,
    ) -> Result<()> {
        let mut state: DeviceView = self
            .store
            .get(db, "device_state", &peer.device_id)?
            .unwrap_or_default();
        if let Some(mode) = response
            .state
            .get("mode")
            .and_then(serde_json::Value::as_str)
        {
            state.mode = mode.chars().take(64).collect();
        }
        if let Some(ttl) = response
            .state
            .get("unlock_ttl_s")
            .and_then(serde_json::Value::as_u64)
        {
            state.unlock_ttl_s = ttl.min(86400) as u32;
        }
        if let Some(unattended) = response
            .state
            .get("unattended")
            .and_then(serde_json::Value::as_bool)
        {
            state.unattended = unattended;
        }
        if let Some(count) = response
            .state
            .get("unattended_t2")
            .and_then(serde_json::Value::as_u64)
        {
            state.unattended_count = count.min(u64::from(u32::MAX)) as u32;
        }
        if directive.op == DirectiveOp::QueryGrants {
            let mut views = Vec::new();
            let values = response
                .state
                .get("grants")
                .and_then(serde_json::Value::as_array)
                .ok_or(Error("invalid_result"))?;
            if values.len() > 500 {
                return Err(Error("invalid_result"));
            }
            for value in values {
                if !value["revoked_at"].is_null() {
                    continue;
                }
                let exp = value["exp"].as_i64();
                if exp.is_some_and(|e| e <= now()) {
                    continue;
                }
                let id = value["jti"]
                    .as_str()
                    .filter(|s| s.len() <= 128)
                    .ok_or(Error("invalid_result"))?;
                views.push(GrantView {
                    id: id.into(),
                    credential: value["scope"]["credential"]
                        .as_str()
                        .unwrap_or("")
                        .chars()
                        .take(256)
                        .collect(),
                    level: value["scope"]["level"]
                        .as_str()
                        .unwrap_or("")
                        .chars()
                        .take(32)
                        .collect(),
                    max_tier: value["scope"]["max_tier"]
                        .as_str()
                        .unwrap_or("")
                        .chars()
                        .take(8)
                        .collect(),
                    expires_at: exp,
                    origin: value["origin"]
                        .as_str()
                        .unwrap_or("")
                        .chars()
                        .take(32)
                        .collect(),
                    remaining_calls: value["budget_left"]["calls_left"]
                        .as_u64()
                        .map(|v| v.min(u64::from(u32::MAX)) as u32),
                    pending_delivery: false,
                });
            }
            if directive
                .args
                .get("after")
                .and_then(serde_json::Value::as_str)
                .is_some()
            {
                let mut previous: Vec<GrantView> = self
                    .store
                    .get(db, "reported_grants", &peer.device_id)?
                    .unwrap_or_default();
                for view in &views {
                    previous.retain(|old| old.id != view.id);
                }
                previous.extend(views);
                views = previous;
            }
            self.store
                .put(db, "reported_grants", &peer.device_id, &views, now() + 120)?;
            if let Some(cursor) = response
                .state
                .get("next_cursor")
                .and_then(serde_json::Value::as_str)
            {
                if cursor.len() > 256
                    || directive
                        .args
                        .get("after")
                        .and_then(serde_json::Value::as_str)
                        .is_some_and(|after| cursor <= after)
                    || values.last().and_then(|value| value["jti"].as_str()) != Some(cursor)
                {
                    return Err(Error("invalid_result"));
                }
                let mut next = Directive {
                    kind: DirectiveKind::Directive,
                    id: new_id(),
                    iss: self.own.device_id.clone(),
                    iss_alg: SignatureAlgorithm::ES256,
                    iss_kind: IssuerKind::Device,
                    aud: peer.device_id.clone(),
                    op: DirectiveOp::QueryGrants,
                    args: serde_json::json!({"after":cursor})
                        .as_object()
                        .unwrap()
                        .clone(),
                    nonce: new_id(),
                    exp: now() + 60,
                    sig: String::new(),
                    extra: Extra::new(),
                };
                next.sig = sign_object(&next, SignatureAlgorithm::ES256, self.keys.quick.as_ref())?;
                let envelope = remote::envelope::seal(
                    EnvelopeHeader {
                        v: 1,
                        r#type: EnvelopeType::Directive,
                        id: next.id.clone(),
                        account: self
                            .store
                            .get::<String>(db, "meta", "account")?
                            .ok_or(Error("pairing_required"))?,
                        from: self.own.device_id.clone(),
                        to: peer.device_id.clone(),
                        created_at: now(),
                        exp: next.exp,
                        extra: Extra::new(),
                    },
                    &jcs(&next)?,
                    &peer.dk_pub,
                    self.keys.identity.as_ref(),
                )?;
                self.enqueue(db, &envelope)?;
                self.store.put(
                    db,
                    "issued_directives",
                    &next.id.clone(),
                    &IssuedDirective {
                        directive: next,
                        level: ApprovalLevel::Quick,
                    },
                    0,
                )?;
            }
        }
        if directive.op == DirectiveOp::QueryAudit {
            let entries = response
                .state
                .get("entries")
                .and_then(serde_json::Value::as_array)
                .ok_or(Error("invalid_result"))?;
            if entries.len() > 200 {
                return Err(Error("invalid_result"));
            }
            let mut views = Vec::new();
            for entry in entries {
                let at = entry["ts_unix"]
                    .as_i64()
                    .filter(|ts| *ts >= 0 && *ts <= now() + 60)
                    .ok_or(Error("invalid_result"))?;
                let op = entry["op"]
                    .as_str()
                    .filter(|s| {
                        !s.is_empty()
                            && s.len() <= 64
                            && s.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'_')
                    })
                    .ok_or(Error("invalid_result"))?;
                // Display only whitelisted metadata; neither arbitrary audit extras nor
                // credential/request contents can enter the shared public view model.
                views.push(ActivityView {
                    id: sha256_hex(&jcs(entry)?),
                    device_id: peer.device_id.clone(),
                    kind: match entry["ok"].as_bool() {
                        Some(true) => "executor_applied",
                        Some(false) => "executor_rejected",
                        None => "executor_activity",
                    }
                    .into(),
                    summary: op.into(),
                    at,
                    delivered: true,
                });
            }
            self.store.put(
                db,
                "reported_activity",
                &peer.device_id,
                &views,
                now() + 300,
            )?;
        }
        match directive.op {
            DirectiveOp::RevokeAllGrants | DirectiveOp::RevokeGrant => {
                if let Some(mut reported) =
                    self.store
                        .get::<Vec<GrantView>>(db, "reported_grants", &peer.device_id)?
                {
                    if directive.op == DirectiveOp::RevokeAllGrants {
                        reported.clear();
                    } else {
                        let revoked = directive
                            .args
                            .get("jti")
                            .and_then(serde_json::Value::as_str);
                        reported.retain(|g| Some(g.id.as_str()) != revoked);
                    }
                    self.store.put(
                        db,
                        "reported_grants",
                        &peer.device_id,
                        &reported,
                        now() + 120,
                    )?;
                }
                for (id, mut grant) in self.store.list::<IssuedGrant>(db, "issued_grants")? {
                    if (grant.grant.aud == peer.device_id || grant.grant.aud == "*")
                        && (directive.op == DirectiveOp::RevokeAllGrants
                            || directive
                                .args
                                .get("jti")
                                .and_then(serde_json::Value::as_str)
                                == Some(&id))
                    {
                        if grant.grant.aud == "*" {
                            self.store.put(
                                db,
                                "grant_revoked",
                                &format!("{id}:{}", peer.device_id),
                                &true,
                                0,
                            )?;
                        } else {
                            grant.revoked = true;
                            self.store.put(db, "issued_grants", &id, &grant, 0)?;
                        }
                    }
                }
            }
            DirectiveOp::RevokeDevice => {
                Store::delete(db, "peers", &peer.device_id)?;
            }
            _ => {}
        }
        self.store
            .put(db, "device_state", &peer.device_id, &state, 0)
    }

    pub fn snapshot(&self) -> Result<Snapshot> {
        self.store.transaction(|db| {
            self.ensure_login_in(db)?;
            Store::expire(db, now())?;
            let settings: SettingsView = self
                .store
                .get(db, "meta", "settings")?
                .ok_or(Error("storage_integrity"))?;
            let pending = self
                .store
                .list::<Pending>(db, "pending")?
                .into_iter()
                .map(|(_, p)| approval_view(&p, &settings))
                .collect();
            let mut activity: Vec<ActivityView> = self
                .store
                .list(db, "activity")?
                .into_iter()
                .map(|(_, a)| a)
                .collect();
            activity.reverse();
            activity.truncate(200);
            let issued = self.store.list::<IssuedGrant>(db, "issued_grants")?;
            let devices = self
                .store
                .list::<DeviceRecord>(db, "peers")?
                .into_iter()
                .map(|(_, p)| {
                    let mut view: DeviceView = self
                        .store
                        .get(db, "device_state", &p.device_id)?
                        .unwrap_or_default();
                    view.id = p.device_id.clone();
                    view.label = p.label;
                    view.os = p.os.as_str().into();
                    view.protection = p.key_kind.as_str().into();
                    view.online = self
                        .store
                        .get::<bool>(db, "presence", &p.device_id)?
                        .unwrap_or(false);
                    view.grants = issued
                        .iter()
                        .filter(|(_, g)| {
                            !g.revoked
                                && (g.grant.aud == p.device_id || g.grant.aud == "*")
                                && g.grant.exp.is_none_or(|e| e > now())
                        })
                        .map(|(_, g)| GrantView {
                            id: g.grant.jti.clone(),
                            credential: g
                                .grant
                                .scope
                                .credential
                                .as_value()
                                .cloned()
                                .unwrap_or_default(),
                            level: serde_json::to_string(&g.grant.scope.level)
                                .unwrap_or_default()
                                .replace('"', ""),
                            max_tier: format!("{:?}", g.grant.scope.max_tier),
                            expires_at: g.grant.exp,
                            origin: g.grant.origin.clone(),
                            remaining_calls: None,
                            pending_delivery: true,
                        })
                        .collect();
                    let mut allowed = Vec::new();
                    for grant in view.grants {
                        if !self
                            .store
                            .get::<bool>(
                                db,
                                "grant_revoked",
                                &format!("{}:{}", grant.id, p.device_id),
                            )?
                            .unwrap_or(false)
                        {
                            allowed.push(grant);
                        }
                    }
                    view.grants = allowed;
                    if let Some(reported) =
                        self.store
                            .get::<Vec<GrantView>>(db, "reported_grants", &p.device_id)?
                    {
                        for grant in reported {
                            view.grants.retain(|g| g.id != grant.id);
                            view.grants.push(grant);
                        }
                    }
                    view.recent_activity = activity
                        .iter()
                        .filter(|a| a.device_id == p.device_id)
                        .take(10)
                        .cloned()
                        .collect();
                    if let Some(reported) = self.store.get::<Vec<ActivityView>>(
                        db,
                        "reported_activity",
                        &p.device_id,
                    )? {
                        view.recent_activity.extend(reported);
                        view.recent_activity
                            .sort_by_key(|a| std::cmp::Reverse(a.at));
                        view.recent_activity.truncate(10);
                    }
                    Ok(view)
                })
                .collect::<Result<Vec<_>>>()?;
            Ok(Snapshot {
                pending,
                devices,
                activity,
                settings,
                connected: self.connected.load(Ordering::Relaxed),
            })
        })
    }

    pub fn diagnostic(&self) -> Result<String> {
        self.ensure_login()?;
        let snapshot = self.snapshot()?;
        // No IDs, labels, purpose, credentials, public/private keys, envelopes or tokens.
        Ok(serde_json::json!({"schema":1,"connected":snapshot.connected,"pending_count":snapshot.pending.len(),
            "paired_count":snapshot.devices.len(),"activity_count":snapshot.activity.len(),"away":snapshot.settings.away_from_computer}).to_string())
    }
    pub(crate) fn notifications(&self) -> Result<Vec<NotificationView>> {
        self.store.transaction(|db| {
            self.ensure_login_in(db)?;
            Store::expire(db, now())?;
            let settings: SettingsView = self
                .store
                .get(db, "meta", "settings")?
                .ok_or(Error("storage_integrity"))?;
            let mut plans = self
                .store
                .list::<Pending>(db, "pending")?
                .into_iter()
                .map(|(_, pending)| notification(&approval_view(&pending, &settings), &settings))
                .collect::<Vec<_>>();
            // Closing an approval is durable even if the relay ack or native notification
            // callback fails. Subsequent background runs must still remove its old banner.
            plans.extend(
                self.store
                    .list::<String>(db, "closed")?
                    .into_iter()
                    .map(|(id, _)| cancel_notification(&id)),
            );
            Ok(plans)
        })
    }
    pub(crate) fn reject(&self, envelope: &Envelope, reason: &str) -> Result<()> {
        self.store.transaction(|db| {
            let receipt = format!(
                "{}:{}:{}",
                envelope.from,
                envelope.id,
                envelope.r#type.as_str()
            );
            self.store.put(
                db,
                "inbox",
                &receipt,
                &sha256_hex(&jcs(envelope)?),
                envelope.exp.max(now() + 60),
            )?;
            self.activity(db, &envelope.id, &envelope.from, "rejected", reason, true)
        })
    }
    pub(crate) fn outbound(&self) -> Result<Vec<(String, Envelope)>> {
        self.store.transaction(|db| {
            Store::expire(db, now())?;
            self.store.list(db, "outbox")
        })
    }
    pub(crate) fn accepted(&self, key: &str, envelope: &Envelope) -> Result<()> {
        self.store.transaction(|db| {
            Store::delete(db, "outbox", key)?;
            if let Some(mut activity) =
                self.store
                    .get::<ActivityView>(db, "activity", &envelope.id)?
            {
                activity.delivered = true;
                self.store.put(db, "activity", &activity.id, &activity, 0)?;
            }
            Ok(())
        })
    }
}

pub(crate) fn random_nonce() -> String {
    use rand_core::RngCore;
    let mut nonce = [0; 16];
    rand_core::OsRng.fill_bytes(&mut nonce);
    encode_b64(&nonce)
}
fn validate_request(request: &ApprovalRequest, envelope: &Envelope) -> Result<()> {
    if request.purpose.len() > 4096
        || request
            .operation
            .as_ref()
            .is_some_and(|o| o.summary.len() > 4096 || o.host.len() > 256 || o.path.len() > 4096)
        || request.scope_options.len() > 8
        || request.approval_id != envelope.id
        || request.requester.device_id != envelope.from
        || request.exp != envelope.exp
        || request.exp <= now()
        || request.exp > now() + 86400 + 60
        || request.digest.len() != 64
        || !request.digest.bytes().all(|c| c.is_ascii_hexdigit())
        || decode_b64(&request.nonce)?.len() != 16
        || request.scope_options.is_empty()
        || !request.scope_options.contains(&request.requested_scope)
        || request.merged_count == 0
        || (request.tier == Tier::T2 && request.scope_options != vec![ScopeOption::PerUse])
    {
        return Err(Error("invalid_request"));
    }
    Ok(())
}
fn approval_view(p: &Pending, settings: &SettingsView) -> ApprovalView {
    let r = &p.request;
    let credential = r.credential.as_ref();
    let operation = r.operation.as_ref();
    ApprovalView {
        id: r.approval_id.clone(),
        kind: serde_json::to_string(&r.kind)
            .unwrap_or_default()
            .replace('"', ""),
        requester_id: r.requester.device_id.clone(),
        requester_label: r.requester.label.clone(),
        os: r.requester.os.as_str().into(),
        protection: r.requester.protection.kind.as_str().into(),
        software_warning: r.requester.protection.kind == ProtectionKind::SoftwareKey,
        runtime: r.agent.runtime.as_str().into(),
        cwd: r.agent.cwd.clone(),
        user: r.agent.user.clone(),
        agent_pid: r.agent.pid,
        credential_ref: credential.map(|c| c.r#ref.clone()).unwrap_or_default(),
        credential_name: credential.map(|c| c.display.clone()).unwrap_or_default(),
        credential_kind: credential
            .map(|c| c.kind.as_str().into())
            .unwrap_or_default(),
        proxy_only: credential.is_some_and(|c| c.proxy_only),
        summary: operation
            .map(|o| o.summary.clone())
            .unwrap_or_else(|| "Unlock / Admin".into()),
        method: operation.map(|o| o.method.clone()).unwrap_or_default(),
        host: operation.map(|o| o.host.clone()).unwrap_or_default(),
        path: operation.map(|o| o.path.clone()).unwrap_or_default(),
        query_keys: operation.map(|o| o.query_keys.clone()).unwrap_or_default(),
        body_bytes: operation
            .map(|o| o.body_bytes.min(u64::from(u32::MAX)) as u32)
            .unwrap_or(0),
        purpose: r.purpose.clone(),
        tier: format!("{:?}", r.tier),
        strong: r.min_level == ApprovalLevel::Strong
            || r.tier == Tier::T2
            || r.kind != ApprovalKind::Use,
        scope_options: r
            .scope_options
            .iter()
            .map(|s| {
                serde_json::to_string(s)
                    .unwrap_or_default()
                    .replace('"', "")
            })
            .collect(),
        requested_scope: serde_json::to_string(&r.requested_scope)
            .unwrap_or_default()
            .replace('"', ""),
        merged_count: r.merged_count,
        expires_at: r.exp,
        created_at: p.created_at,
        clock_skew: p.skew,
        banner: settings.notifications
            && (settings.away_from_computer
                || p.escalated
                || r.delivery.mode == DeliveryMode::Banner),
        escalated: p.escalated,
    }
}
fn cancel_notification(id: &str) -> NotificationView {
    NotificationView {
        approval_id: id.into(),
        title: String::new(),
        body: String::new(),
        banner: false,
        quick_allowed: false,
        expires_at: now(),
        cancel: true,
    }
}

fn notification(view: &ApprovalView, settings: &SettingsView) -> NotificationView {
    let zh = settings.locale == "zh";
    NotificationView {
        approval_id: view.id.clone(),
        title: format!("{} · {}", view.requester_label, view.runtime),
        body: format!(
            "{}\n{} {}{} · {} bytes\n{}: {}\n{} · {}",
            view.summary,
            view.method,
            view.host,
            view.path,
            view.body_bytes,
            if zh {
                "agent 自述"
            } else {
                "Agent stated purpose"
            },
            view.purpose,
            view.tier,
            view.protection
        ),
        banner: view.banner,
        quick_allowed: !view.strong && view.scope_options.iter().any(|s| s == "per_use"),
        expires_at: view.expires_at,
        cancel: false,
    }
}
