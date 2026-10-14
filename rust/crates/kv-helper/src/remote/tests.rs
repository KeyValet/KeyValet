use super::engine::directory;
use super::ipc::CallerContext;
use super::store::{encode, PendingState};
use super::Result;
use super::*;
use kv_core::remote::canonical::{from_json, jcs, sha256_hex, CanonicalRequest};
use kv_core::remote::keys::{decode_b64, sign_object};
use kv_core::remote::*;
use kv_ipc::remote::{Caller, Op, PresenceState, Request};
use rusqlite::params;
use serde_json::{json, Map, Value};
use std::future::Future;
use std::pin::Pin;
use std::sync::{
    atomic::{AtomicBool, AtomicI64, AtomicUsize, Ordering},
    Arc, Mutex,
};

mod acceptance;
mod audit;
mod boundaries;
pub(super) mod control_transport;
mod inbound_recovery;
mod integrity_paths;
mod interfaces;
mod owner;
mod owner_contracts;
mod owner_workflow;
mod production;
mod recovery;
mod review;
mod revocations;
mod security_edges;
mod six_fixes;
mod sql_faults;
mod transport_edges;
mod workflow;

fn fixture(name: &str) -> Value {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../kv-core/testdata/remote")
        .join(name);
    from_json(&std::fs::read(path).unwrap()).unwrap()
}

fn key(name: &str) -> Arc<SoftwareDeviceKey> {
    let data = fixture("decision_valid.json");
    Arc::new(
        SoftwareDeviceKey::from_p256_bytes(
            &decode_b64(data["keys"][name]["private_scalar"].as_str().unwrap()).unwrap(),
        )
        .unwrap(),
    )
}

struct FakeClock(AtomicI64);
impl Clock for FakeClock {
    fn now(&self) -> i64 {
        self.0.load(Ordering::SeqCst)
    }
}

#[derive(Default)]
struct FakeAudit {
    entries: Mutex<Vec<Value>>,
    fail: AtomicBool,
}
impl AuditSink for FakeAudit {
    fn append(&self, entry: Map<String, Value>) -> Result<()> {
        if self.fail.load(Ordering::SeqCst) {
            return Err(Error("audit_unavailable"));
        }
        self.entries.lock().unwrap().push(Value::Object(entry));
        Ok(())
    }
}

#[derive(Default)]
struct FakeMirror(Mutex<Vec<(DeviceRecord, bool)>>);
impl DeviceMirror for FakeMirror {
    fn replace(&self, _account: &str, records: &[(DeviceRecord, bool)]) -> Result<()> {
        *self.0.lock().unwrap() = records.to_vec();
        Ok(())
    }
    fn verify(&self, _account: &str, records: &[(DeviceRecord, bool)]) -> Result<()> {
        if *self.0.lock().unwrap() == records {
            Ok(())
        } else {
            Err(Error("device_directory_mismatch"))
        }
    }
}

struct FakePresence(Mutex<PresenceState>);
impl PresenceProbe for FakePresence {
    fn state(&self) -> PresenceState {
        self.0.lock().unwrap().clone()
    }
}

struct FakeRunner {
    calls: AtomicUsize,
    alive: AtomicBool,
    locked: AtomicBool,
    fail: AtomicBool,
    level: Mutex<ApprovalLevel>,
    after_execute: Mutex<Option<Box<dyn FnOnce() + Send>>>,
    after_authorize: Mutex<Option<Box<dyn FnOnce() + Send>>>,
}
impl Default for FakeRunner {
    fn default() -> Self {
        Self {
            calls: AtomicUsize::new(0),
            alive: AtomicBool::new(true),
            locked: AtomicBool::new(false),
            fail: AtomicBool::new(false),
            level: Mutex::new(ApprovalLevel::Strong),
            after_execute: Mutex::new(None),
            after_authorize: Mutex::new(None),
        }
    }
}
impl RequestRunner for FakeRunner {
    fn execute(
        &self,
        request: Execution,
    ) -> Pin<Box<dyn Future<Output = Result<Value>> + Send + '_>> {
        Box::pin(async move {
            self.calls.fetch_add(1, Ordering::SeqCst);
            if let Some(after) = self.after_execute.lock().unwrap().take() {
                after();
            }
            if self.fail.load(Ordering::SeqCst) {
                return Err(Error("execution_unavailable"));
            }
            Ok(json!({"result": "executed", "op": request.full_request.op}))
        })
    }
    fn agent_alive(&self, _uid: u32, _pid: u32, _exe: &str) -> bool {
        self.alive.load(Ordering::SeqCst)
    }
    fn lock_sessions(&self) -> Result<()> {
        self.locked.store(true, Ordering::SeqCst);
        Ok(())
    }
    fn local_authorize(
        &self,
        _reason: &'static str,
        _binding: Value,
    ) -> Pin<Box<dyn Future<Output = Result<ApprovalLevel>> + Send + '_>> {
        Box::pin(async {
            if let Some(after) = self.after_authorize.lock().unwrap().take() {
                after();
            }
            Ok(*self.level.lock().unwrap())
        })
    }
}

pub(super) struct Harness {
    pub(super) helper: Arc<RemoteHelper>,
    clock: Arc<FakeClock>,
    audit: Arc<FakeAudit>,
    runner: Arc<FakeRunner>,
    mirror: Arc<FakeMirror>,
    presence: Arc<FakePresence>,
    peer: DeviceRecord,
}

impl Harness {
    fn spooled(&self, envelopes: &[Envelope]) {
        if !envelopes.is_empty() {
            self.helper
                .outbound_ack(kv_ipc::remote::RelayOutboundAckParams {
                    envelopes: envelopes.to_vec(),
                    stage: kv_ipc::remote::OutboundStage::Spooled,
                    extra: Extra::new(),
                })
                .unwrap();
        }
    }

    pub(super) fn new() -> Self {
        Self::with(
            Store::memory().unwrap(),
            fixture("decision_valid.json")["now"].as_i64().unwrap(),
            true,
        )
    }
    fn with(store: Store, now: i64, paired: bool) -> Self {
        let peer: DeviceRecord =
            serde_json::from_value(fixture("decision_valid.json")["device"].clone()).unwrap();
        if paired {
            store.insert_device(&peer, "account", now).unwrap();
        }
        Self::from_store(store, now, peer)
    }
    fn from_store(store: Store, now: i64, peer: DeviceRecord) -> Self {
        let local = DeviceRecord {
            device_id: "dev_srv".into(),
            label: "srv".into(),
            os: Os::Linux,
            key_kind: KeyKind::Software,
            dk_pub: key("sender").public_jwk().unwrap(),
            dk_sig: kv_core::remote::Optional::Missing,
            ak_q: None,
            ak_s: None,
            caps: vec![Capability::Execute],
            attestation: None,
            extra: Extra::new(),
        };
        let clock = Arc::new(FakeClock(AtomicI64::new(now)));
        let audit = Arc::new(FakeAudit::default());
        let runner = Arc::new(FakeRunner::default());
        let mirror = Arc::new(FakeMirror(Mutex::new(directory(&store).unwrap())));
        let presence = Arc::new(FakePresence(Mutex::new(PresenceState {
            state: Presence::Away,
            since: now,
            signals: kv_platform::presence::unavailable_signals(),
            extra: Extra::new(),
        })));
        let helper = RemoteHelper::new(
            store,
            local,
            "account".into(),
            ApprovalConfig::default(),
            Services {
                identity: key("sender"),
                quick: None,
                strong: None,
                clock: clock.clone(),
                audit: audit.clone(),
                runner: runner.clone(),
                mirror: mirror.clone(),
                presence: presence.clone(),
            },
        )
        .unwrap();
        Self {
            helper,
            clock,
            audit,
            runner,
            mirror,
            presence,
            peer,
        }
    }
    fn input(&self, tier: Tier, marker: &str) -> ApprovalInput {
        let data = fixture("decision_valid.json");
        ApprovalInput {
            canonical: serde_json::from_value(data["canonical"].clone()).unwrap(),
            credential: serde_json::from_value(data["request"]["credential"].clone()).unwrap(),
            operation: serde_json::from_value(data["request"]["operation"].clone()).unwrap(),
            tier,
            min_level: ApprovalLevel::Quick,
            scope_options: serde_json::from_value(data["request"]["scope_options"].clone())
                .unwrap(),
            requested_scope: ScopeOption::PerCredential,
            session_id: "session".into(),
            full_request: FullRequest::new(
                "proxy",
                json!({"body": marker, "credential": "github/default"})
                    .as_object()
                    .unwrap()
                    .clone(),
            )
            .unwrap(),
            auto_allowed: false,
            local_channel_available: false,
        }
    }
    fn decision(
        &self,
        request: &ApprovalRequest,
        level: ApprovalLevel,
        scope: ScopeMode,
    ) -> ApprovalDecision {
        let mut decision = ApprovalDecision {
            approval_id: request.approval_id.clone(),
            digest: request.digest.clone(),
            nonce: request.nonce.clone(),
            decision: Decision::Allow,
            level,
            scope: DecisionScope {
                mode: scope,
                level: DecisionScopeLevel::Credential,
                until: 0,
                extra: Extra::new(),
            },
            approver: self.peer.device_id.clone(),
            approver_kind: ApproverKind::Device,
            quorum: Optional::Missing,
            issued_at: self.clock.now(),
            reason: Optional::Missing,
            sig: String::new(),
            extra: Extra::new(),
        };
        decision.sig = sign_object(
            &decision,
            SignatureAlgorithm::ES256,
            key(if level == ApprovalLevel::Strong {
                "strong"
            } else {
                "quick"
            })
            .as_ref(),
        )
        .unwrap();
        decision
    }
    fn envelope<T: serde::Serialize>(&self, kind: EnvelopeType, id: &str, value: &T) -> Envelope {
        kv_core::remote::envelope::seal(
            EnvelopeHeader {
                v: 1,
                r#type: kind,
                id: id.into(),
                account: "account".into(),
                from: self.peer.device_id.clone(),
                to: "dev_srv".into(),
                created_at: self.clock.now(),
                exp: self.clock.now() + 600,
                extra: Extra::new(),
            },
            &jcs(value).unwrap(),
            &self.helper.local.dk_pub,
            key("recipient").as_ref(),
        )
        .unwrap()
    }
    fn reason(&self, code: &str) {
        assert!(
            self.helper
                .audit_entries()
                .unwrap()
                .iter()
                .any(|entry| entry["reason"] == code),
            "missing audit reason {code}"
        );
    }
    fn seed(&self, request: &ApprovalRequest, canonical: &CanonicalRequest) {
        self.helper.lock().unwrap().store.db.execute("INSERT INTO pending_approvals (id,kind,digest,nonce,canonical_json,exp,state,created_at,agent_pid,agent_runtime,request_json,session_id,epoch) VALUES (?1,'use',?2,?3,?4,?5,'waiting',?6,?7,?8,?9,'session',0)",
            params![request.approval_id, request.digest, request.nonce, encode(canonical).unwrap(), request.exp, self.clock.now(), canonical.agent.pid,
                canonical.agent.runtime, encode(request).unwrap()]).unwrap();
    }
    async fn exchange(&self, role: Caller, op: Op, value: Value) -> Value {
        serde_json::to_value(
            self.helper
                .handle(
                    CallerContext::authenticated(role, 501, 4242, 50),
                    Request {
                        op,
                        params: value,
                        extra: Extra::new(),
                    },
                )
                .await,
        )
        .unwrap()
    }
}

#[tokio::test]
async fn all_w0_decision_vectors_match_expect_and_audit_every_failure() {
    let suite = fixture("decision_validation_cases.json");
    for (case, expected) in suite["cases"]
        .as_array()
        .unwrap()
        .iter()
        .zip(suite["expect"].as_array().unwrap())
    {
        let h = Harness::with(
            Store::memory().unwrap(),
            case["now"].as_i64().unwrap(),
            false,
        );
        let device: DeviceRecord = serde_json::from_value(case["device"].clone()).unwrap();
        h.helper
            .lock()
            .unwrap()
            .store
            .insert_device(&device, "account", h.clock.now())
            .unwrap();
        let request: ApprovalRequest = serde_json::from_value(case["request"].clone()).unwrap();
        h.seed(
            &request,
            &serde_json::from_value(suite["canonical"].clone()).unwrap(),
        );
        let decision: ApprovalDecision = serde_json::from_value(case["decision"].clone()).unwrap();
        let result = h
            .helper
            .inbound(h.envelope(
                EnvelopeType::ApprovalDecision,
                &decision.approval_id,
                &decision,
            ))
            .await;
        match expected["error"].as_str() {
            Some(code) => {
                assert_eq!(result.unwrap_err().code(), code, "{}", case["name"]);
                h.reason(code);
            }
            None => {
                result.unwrap_or_else(|error| panic!("{}: {error}", case["name"]));
            }
        }
    }
    for name in ["decision_valid.json", "decision_wrong_key.json"] {
        let data = fixture(name);
        let h = Harness::new();
        let request = serde_json::from_value(data["request"].clone()).unwrap();
        h.seed(
            &request,
            &serde_json::from_value(data["canonical"].clone()).unwrap(),
        );
        let decision: ApprovalDecision = serde_json::from_value(data["decision"].clone()).unwrap();
        let result = h
            .helper
            .inbound(h.envelope(
                EnvelopeType::ApprovalDecision,
                &decision.approval_id,
                &decision,
            ))
            .await;
        if let Some(code) = data["expect"]["error"].as_str() {
            assert_eq!(result.unwrap_err().code(), code);
            h.reason(code);
        } else {
            result.unwrap();
        }
    }
}

#[tokio::test]
async fn w0_replay_vector_and_live_second_ticket_follow_the_fixed_order() {
    let data = fixture("decision_replayed.json");
    let h = Harness::new();
    let request: ApprovalRequest = serde_json::from_value(data["request"].clone()).unwrap();
    h.seed(
        &request,
        &serde_json::from_value(data["canonical"].clone()).unwrap(),
    );
    let decision: ApprovalDecision = serde_json::from_value(data["decision"].clone()).unwrap();
    let envelope = h.envelope(
        EnvelopeType::ApprovalDecision,
        &decision.approval_id,
        &decision,
    );
    h.helper.inbound(envelope.clone()).await.unwrap();
    assert_eq!(
        h.helper.inbound(envelope.clone()).await.unwrap_err(),
        Error("not_waiting")
    );
    h.reason("not_waiting");
    // The W0 standalone nonce replay vector supplies a waiting record for the second attempt.
    h.helper
        .lock()
        .unwrap()
        .store
        .db
        .execute("UPDATE pending_approvals SET state='waiting'", [])
        .unwrap();
    assert_eq!(
        h.helper.inbound(envelope).await.unwrap_err(),
        Error("replay")
    );
    h.reason("replay");
    assert_eq!(
        h.helper
            .lock()
            .unwrap()
            .store
            .db
            .query_row("SELECT COUNT(*) FROM nonces", [], |r| r.get::<_, u64>(0))
            .unwrap(),
        data["expect"]["consumed"].as_u64().unwrap()
    );
}

#[test]
fn all_w0_grant_vectors_match_expect_and_audit_every_failure() {
    let suite = fixture("grant_validation_cases.json");
    for (case, expected) in suite["cases"]
        .as_array()
        .unwrap()
        .iter()
        .zip(suite["expect"].as_array().unwrap())
    {
        let h = Harness::with(
            Store::memory().unwrap(),
            suite["now"].as_i64().unwrap(),
            false,
        );
        h.helper
            .lock()
            .unwrap()
            .store
            .insert_device(
                &serde_json::from_value(case["device"].clone()).unwrap(),
                "account",
                h.clock.now(),
            )
            .unwrap();
        let result = h.helper.install_grant(
            &serde_json::from_value(case["grant"].clone()).unwrap(),
            serde_json::from_value(case["level"].clone()).unwrap(),
        );
        if let Some(code) = expected["error"].as_str() {
            assert_eq!(result.unwrap_err().code(), code, "{}", case["name"]);
            h.reason(code);
        } else {
            result.unwrap_or_else(|error| panic!("{}: {error}", case["name"]));
        }
    }
    for name in ["grant_standing_t1.json", "grant_t2_requires_settings.json"] {
        let data = fixture(name);
        let h = Harness::with(
            Store::memory().unwrap(),
            data["now"].as_i64().unwrap(),
            false,
        );
        h.helper
            .lock()
            .unwrap()
            .store
            .insert_device(
                &serde_json::from_value(data["device"].clone()).unwrap(),
                "account",
                h.clock.now(),
            )
            .unwrap();
        let result = h.helper.install_grant(
            &serde_json::from_value(data["grant"].clone()).unwrap(),
            serde_json::from_value(data["level"].clone()).unwrap(),
        );
        if let Some(code) = data["expect"]["error"].as_str() {
            assert_eq!(result.unwrap_err().code(), code);
            h.reason(code);
        } else {
            result.unwrap();
        }
    }
}

#[test]
fn all_w0_directive_vectors_match_expect_and_audit_every_failure() {
    for name in [
        "directive_tighten_quick_ok.json",
        "directive_loosen_quick_rejected.json",
    ] {
        let data = fixture(name);
        let h = Harness::with(
            Store::memory().unwrap(),
            data["now"].as_i64().unwrap(),
            false,
        );
        h.helper
            .lock()
            .unwrap()
            .store
            .insert_device(
                &serde_json::from_value(data["device"].clone()).unwrap(),
                "account",
                h.clock.now(),
            )
            .unwrap();
        h.helper
            .lock()
            .unwrap()
            .store
            .set_setting("mode", &data["current"]["mode"], "local", h.clock.now())
            .unwrap();
        let result = h.helper.apply_directive(
            &serde_json::from_value(data["directive"].clone()).unwrap(),
            serde_json::from_value(data["level"].clone()).unwrap(),
        );
        if let Some(code) = data["expect"]["error"].as_str() {
            assert_eq!(result.unwrap_err().code(), code);
            h.reason(code);
        } else {
            result.unwrap();
        }
    }
}

#[tokio::test]
async fn all_five_attacks_are_denied_and_audited() {
    // Approval for A cannot authorize body B, even when HTTP display fields are identical.
    let h = Harness::new();
    let request = h.helper.submit(h.input(Tier::T1, "A")).unwrap();
    let decision = h.decision(&request, ApprovalLevel::Quick, ScopeMode::PerUse);
    h.helper.lock().unwrap().full.remove(&request.approval_id);
    h.helper
        .inbound(h.envelope(
            EnvelopeType::ApprovalDecision,
            &request.approval_id,
            &decision,
        ))
        .await
        .unwrap();
    let canonical = h
        .helper
        .lock()
        .unwrap()
        .store
        .pending(&request.approval_id)
        .unwrap()
        .canonical;
    let full = h.input(Tier::T1, "B").full_request;
    assert_eq!(
        h.helper
            .retry(&request.approval_id, &canonical, full, 501, 4242)
            .await
            .unwrap_err(),
        Error("digest_mismatch")
    );
    h.reason("digest_mismatch");
    assert_eq!(h.runner.calls.load(Ordering::SeqCst), 0);
    let full = h.input(Tier::T1, "A").full_request;
    assert_eq!(
        h.helper
            .retry(&request.approval_id, &canonical, full, 501, 4242)
            .await
            .unwrap()
            .status,
        ToolStatus::Ok
    );
    assert_eq!(
        h.helper
            .retry(
                &request.approval_id,
                &canonical,
                h.input(Tier::T1, "A").full_request,
                501,
                4242
            )
            .await
            .unwrap()
            .status,
        ToolStatus::AlreadyConsumed
    );
    assert_eq!(h.runner.calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        h.helper
            .inbound(h.envelope(
                EnvelopeType::ApprovalDecision,
                &request.approval_id,
                &decision
            ))
            .await
            .unwrap_err(),
        Error("not_waiting")
    );
    h.reason("not_waiting");

    let h = Harness::new();
    let request = h.helper.submit(h.input(Tier::T2, "A")).unwrap();
    assert_eq!(request.scope_options, vec![ScopeOption::PerUse]);
    let decision = h.decision(&request, ApprovalLevel::Quick, ScopeMode::PerUse);
    assert_eq!(
        h.helper
            .inbound(h.envelope(
                EnvelopeType::ApprovalDecision,
                &request.approval_id,
                &decision
            ))
            .await
            .unwrap_err(),
        Error("insufficient_level")
    );
    h.reason("insufficient_level");
    let strong = h.decision(&request, ApprovalLevel::Strong, ScopeMode::PerUse);
    h.helper.revoke_device(&h.peer.device_id, "local").unwrap();
    assert_eq!(
        h.helper
            .inbound(h.envelope(
                EnvelopeType::ApprovalDecision,
                &request.approval_id,
                &strong
            ))
            .await
            .unwrap_err(),
        Error("revoked_device")
    );
    h.reason("revoked_device");
    let mirror = h.mirror.0.lock().unwrap();
    assert!(mirror
        .iter()
        .any(|(device, revoked)| device.device_id == h.peer.device_id && *revoked));
    drop(mirror);

    let data = fixture("directive_loosen_quick_rejected.json");
    let h = Harness::new();
    h.helper
        .set_mode_local("per_use", ApprovalLevel::Strong)
        .unwrap();
    let directive: Directive = serde_json::from_value(data["directive"].clone()).unwrap();
    assert_eq!(
        h.helper
            .apply_directive(&directive, ApprovalLevel::Quick)
            .unwrap_err(),
        Error("insufficient_level")
    );
    h.reason("insufficient_level");
}

#[tokio::test]
async fn verification_order_stops_at_the_first_failure() {
    let h = Harness::new();
    let request = h.helper.submit(h.input(Tier::T2, "A")).unwrap();
    let mut decision = h.decision(&request, ApprovalLevel::Quick, ScopeMode::Standing);
    decision.digest = "0".repeat(64);
    decision.nonce = "bad-nonce".into();
    decision.sig.clear();
    assert_eq!(
        h.helper
            .inbound(h.envelope(
                EnvelopeType::ApprovalDecision,
                &request.approval_id,
                &decision
            ))
            .await
            .unwrap_err(),
        Error("digest_mismatch")
    );
    h.reason("digest_mismatch");
    decision.digest = request.digest.clone();
    assert_eq!(
        h.helper
            .inbound(h.envelope(
                EnvelopeType::ApprovalDecision,
                &request.approval_id,
                &decision
            ))
            .await
            .unwrap_err(),
        Error("nonce_mismatch")
    );
    h.reason("nonce_mismatch");
    decision.nonce = request.nonce.clone();
    assert_eq!(
        h.helper
            .inbound(h.envelope(
                EnvelopeType::ApprovalDecision,
                &request.approval_id,
                &decision
            ))
            .await
            .unwrap_err(),
        Error("insufficient_level")
    );
    h.reason("insufficient_level");
    decision.level = ApprovalLevel::Strong;
    assert!(h
        .helper
        .inbound(h.envelope(
            EnvelopeType::ApprovalDecision,
            &request.approval_id,
            &decision
        ))
        .await
        .is_err());
    h.reason("invalid_signature");
    decision.sig =
        sign_object(&decision, SignatureAlgorithm::ES256, key("strong").as_ref()).unwrap();
    h.helper
        .lock()
        .unwrap()
        .store
        .consume_nonce(
            &decision.nonce,
            &decision.digest,
            h.clock.now(),
            request.exp,
        )
        .unwrap();
    assert_eq!(
        h.helper
            .inbound(h.envelope(
                EnvelopeType::ApprovalDecision,
                &request.approval_id,
                &decision
            ))
            .await
            .unwrap_err(),
        Error("replay")
    );
    h.reason("replay");
    // Invalid scope is checked only after the nonce table (and cannot execute).
    h.helper
        .lock()
        .unwrap()
        .store
        .db
        .execute("DELETE FROM nonces", [])
        .unwrap();
    assert_eq!(
        h.helper
            .inbound(h.envelope(
                EnvelopeType::ApprovalDecision,
                &request.approval_id,
                &decision
            ))
            .await
            .unwrap_err(),
        Error("invalid_scope")
    );
    h.reason("invalid_scope");
    assert_eq!(h.runner.calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn pairing_requires_both_terminal_and_signed_strong_confirmation_and_consumes_token() {
    let h = Harness::with(Store::memory().unwrap(), 1760200012, false);
    let start = h.helper.pair_start("https://relay.example.net").unwrap();
    assert!(start.extra["uri"]
        .as_str()
        .unwrap()
        .starts_with("kv-pair://relay.example.net/"));
    let accept = PairAccept {
        token: start.extra["token"].as_str().unwrap().into(),
        joiner: h.peer.clone(),
        extra: Extra::new(),
    };
    let sas = h.helper.pair_complete(accept.clone()).unwrap().sas;
    h.helper
        .pair_confirm_terminal(&PairConfirm {
            sas: sas.clone(),
            sig: String::new(),
            extra: Extra::new(),
        })
        .unwrap();
    assert!(h
        .helper
        .lock()
        .unwrap()
        .store
        .devices("account")
        .unwrap()
        .is_empty());
    let signed = kv_core::remote::pairing::sign_confirm(
        &sas,
        SignatureAlgorithm::ES256,
        key("strong").as_ref(),
    )
    .unwrap();
    let envelope = h.envelope(EnvelopeType::PairConfirm, "pair", &signed);
    h.helper.inbound(envelope).await.unwrap();
    assert_eq!(
        h.helper.lock().unwrap().store.devices("account").unwrap(),
        vec![h.peer.clone()]
    );
    assert_eq!(
        h.helper.pair_complete(accept).unwrap_err(),
        Error("unknown_token")
    );
    h.reason("unknown_token");
    assert!(!encode(&h.helper.audit_entries().unwrap())
        .unwrap()
        .contains(start.extra["token"].as_str().unwrap()));
}

#[test]
fn pairing_mismatch_expiration_and_duplicate_accept_discard_the_session() {
    for failure in ["mismatch", "expired", "duplicate"] {
        let h = Harness::with(Store::memory().unwrap(), 1760200012, false);
        let start = h.helper.pair_start("https://relay.example.net").unwrap();
        let accept = PairAccept {
            token: start.extra["token"].as_str().unwrap().into(),
            joiner: h.peer.clone(),
            extra: Extra::new(),
        };
        let code = match failure {
            "mismatch" => {
                h.helper.pair_complete(accept).unwrap();
                h.helper
                    .pair_confirm_terminal(&PairConfirm {
                        sas: "9999999".into(),
                        sig: String::new(),
                        extra: Extra::new(),
                    })
                    .unwrap_err()
                    .code()
            }
            "expired" => {
                h.clock.0.fetch_add(601, Ordering::SeqCst);
                h.helper.pair_complete(accept).unwrap_err().code()
            }
            _ => {
                h.helper.pair_complete(accept.clone()).unwrap();
                h.helper.pair_complete(accept).unwrap_err().code()
            }
        };
        h.reason(code);
        assert!(h.helper.lock().unwrap().pairing.is_none());
        assert!(h
            .helper
            .lock()
            .unwrap()
            .store
            .devices("account")
            .unwrap()
            .is_empty());
    }
}

#[tokio::test]
async fn approved_wait_returns_original_result_once_and_dead_agents_remain_unused() {
    let h = Harness::new();
    let request = h
        .helper
        .submit(h.input(Tier::T1, "unique body never logged"))
        .unwrap();
    let decision = h.decision(&request, ApprovalLevel::Quick, ScopeMode::PerUse);
    h.helper
        .inbound(h.envelope(
            EnvelopeType::ApprovalDecision,
            &request.approval_id,
            &decision,
        ))
        .await
        .unwrap();
    let result = h
        .helper
        .wait(&request.approval_id, 1000, 50, 501, 4242)
        .await
        .unwrap();
    assert_eq!(result.status, ToolStatus::Ok);
    assert_eq!(result.result.as_value().unwrap()["result"], "executed");
    assert_eq!(
        h.helper
            .wait(&request.approval_id, 0, 50, 501, 4242)
            .await
            .unwrap()
            .status,
        ToolStatus::AlreadyConsumed
    );
    assert_eq!(h.runner.calls.load(Ordering::SeqCst), 1);
    assert!(!encode(&h.helper.audit_entries().unwrap())
        .unwrap()
        .contains("unique body never logged"));
    let request = h.helper.submit(h.input(Tier::T1, "dead agent")).unwrap();
    h.runner.alive.store(false, Ordering::SeqCst);
    let decision = h.decision(&request, ApprovalLevel::Quick, ScopeMode::PerUse);
    h.helper
        .inbound(h.envelope(
            EnvelopeType::ApprovalDecision,
            &request.approval_id,
            &decision,
        ))
        .await
        .unwrap();
    assert_eq!(
        h.helper
            .lock()
            .unwrap()
            .store
            .pending(&request.approval_id)
            .unwrap()
            .state,
        PendingState::ApprovedUnused
    );
    assert_eq!(
        h.helper
            .wait(&request.approval_id, 0, 50, 501, 4242)
            .await
            .unwrap()
            .status,
        ToolStatus::ApprovedRetryRequired
    );
}

#[tokio::test]
async fn timeout_is_pending_denial_is_denied_and_expiration_clears_memory_and_sends_cancel() {
    let h = Harness::new();
    let request = h.helper.submit(h.input(Tier::T1, "A")).unwrap();
    let result = h
        .helper
        .wait(&request.approval_id, 30000, 10, 501, 4242)
        .await
        .unwrap();
    assert_eq!(result.status, ToolStatus::StillPending);
    let mut deny = h.decision(&request, ApprovalLevel::Quick, ScopeMode::PerUse);
    deny.decision = Decision::Deny;
    deny.sig = sign_object(&deny, SignatureAlgorithm::ES256, key("quick").as_ref()).unwrap();
    h.helper
        .inbound(h.envelope(EnvelopeType::ApprovalDecision, &request.approval_id, &deny))
        .await
        .unwrap();
    assert_eq!(
        h.helper
            .result(&request.approval_id, 501, 4242, true)
            .unwrap()
            .status,
        ToolStatus::ApprovalDenied
    );
    let request = h.helper.submit(h.input(Tier::T1, "B")).unwrap();
    h.clock.0.store(request.exp + 1, Ordering::SeqCst);
    h.helper.tick().unwrap();
    assert_eq!(
        h.helper
            .result(&request.approval_id, 501, 4242, true)
            .unwrap()
            .status,
        ToolStatus::ApprovalExpired
    );
    assert!(!h
        .helper
        .lock()
        .unwrap()
        .full
        .contains_key(&request.approval_id));
    let envelopes = h.helper.outbound_poll(0).await.unwrap();
    assert!(envelopes
        .iter()
        .any(|envelope| envelope.r#type == EnvelopeType::ApprovalCancel
            && envelope.id == request.approval_id));
}

#[tokio::test]
async fn outbox_reconnect_and_restart_keep_encrypted_requests_but_never_full_bodies() {
    let dir = tempfile::tempdir().unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let path = dir.path().join("state.db");
    let h = Harness::with(Store::persistence_fixture(&path).unwrap(), 1760200012, true);
    let request = h
        .helper
        .submit(h.input(Tier::T1, "SECRET_UNIQUE_BODY_MARKER"))
        .unwrap();
    let outgoing = h.helper.outbound_poll(0).await.unwrap();
    assert_eq!(outgoing.len(), 1);
    // Losing the response before a durable spool receipt must replay identical ciphertext.
    assert_eq!(h.helper.outbound_poll(0).await.unwrap(), outgoing);
    h.exchange(
        Caller::RelayClient,
        Op::RelayStatus,
        json!({"connected":false,"last_error":null,"since":1760200012}),
    )
    .await;
    assert_eq!(h.helper.outbound_poll(0).await.unwrap().len(), 1);
    h.spooled(&outgoing);
    assert!(h.helper.outbound_poll(0).await.unwrap().is_empty());
    let decision = h.decision(&request, ApprovalLevel::Quick, ScopeMode::PerUse);
    h.helper.lock().unwrap().full.clear();
    h.helper
        .inbound(h.envelope(
            EnvelopeType::ApprovalDecision,
            &request.approval_id,
            &decision,
        ))
        .await
        .unwrap();
    let now = h.clock.now();
    let peer = h.peer.clone();
    drop(h);
    let h = Harness::from_store(Store::persistence_fixture(&path).unwrap(), now, peer);
    assert_eq!(
        h.helper
            .result(&request.approval_id, 501, 4242, true)
            .unwrap()
            .status,
        ToolStatus::ApprovedRetryRequired
    );
    let canonical = h
        .helper
        .lock()
        .unwrap()
        .store
        .pending(&request.approval_id)
        .unwrap()
        .canonical;
    let result = h
        .helper
        .retry(
            &request.approval_id,
            &canonical,
            h.input(Tier::T1, "SECRET_UNIQUE_BODY_MARKER").full_request,
            501,
            4242,
        )
        .await
        .unwrap();
    assert_eq!(result.status, ToolStatus::Ok);
    assert_eq!(h.runner.calls.load(Ordering::SeqCst), 1);
    for file in std::fs::read_dir(dir.path()).unwrap() {
        let bytes = std::fs::read(file.unwrap().path()).unwrap();
        assert!(!bytes
            .windows(b"SECRET_UNIQUE_BODY_MARKER".len())
            .any(|window| window == b"SECRET_UNIQUE_BODY_MARKER"));
    }
}

#[tokio::test]
async fn every_ipc_role_is_rejected_outside_its_w0_allowlist_before_parsing() {
    let h = Harness::new();
    for (role, allowed) in kv_ipc::remote::CALLER_OPS {
        for op in kv_ipc::remote::OPS {
            if allowed.contains(op) {
                continue;
            }
            let response = h
                .exchange(
                    *role,
                    *op,
                    json!({"caller":"cli-owner","uid":0,"invalid":"payload"}),
                )
                .await;
            assert_eq!(response["error"]["code"], "forbidden", "{role:?} {op:?}");
        }
    }
    h.reason("forbidden");
    let response = h
        .exchange(
            Caller::RelayClient,
            Op::SignIdentity,
            json!({"payload_b64":kv_core::remote::keys::encode_b64(b"not a challenge")}),
        )
        .await;
    assert_eq!(response["error"]["code"], "invalid_identity_challenge");
    h.reason("invalid_identity_challenge");
}

#[tokio::test]
async fn stop_hook_counter_is_atomic_bounded_and_scoped_to_authenticated_parent() {
    let h = Harness::new();
    let request = h.helper.submit(h.input(Tier::T1, "A")).unwrap();
    assert_eq!(
        h.exchange(Caller::Hook, Op::PendingForAgent, json!({"agent_pid":999}))
            .await["error"]["code"],
        "forbidden"
    );
    for left in [2, 1, 0] {
        let response = h
            .exchange(
                Caller::Hook,
                Op::PendingStopBlock,
                json!({"approval_id":request.approval_id}),
            )
            .await;
        assert_eq!(response["result"]["allowed"], true);
        assert_eq!(response["result"]["blocks_left"], left);
    }
    assert_eq!(
        h.exchange(
            Caller::Hook,
            Op::PendingStopBlock,
            json!({"approval_id":request.approval_id})
        )
        .await["result"]["allowed"],
        false
    );
    h.clock.0.store(request.exp + 1, Ordering::SeqCst);
    assert_eq!(
        h.exchange(Caller::Hook, Op::PendingForAgent, json!({"agent_pid":4242}))
            .await["result"]["pending"],
        json!([])
    );
}
