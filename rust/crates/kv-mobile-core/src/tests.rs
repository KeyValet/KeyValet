//! Tests use only software keys, temporary storage and W2's in-process relay.
#[path = "tests/account.rs"]
mod accounts;
#[path = "tests/audit.rs"]
mod audit;
#[path = "tests/helper_pairing.rs"]
mod helper_pairing;
#[path = "tests/push.rs"]
mod push;
use super::*;
use crate::{api::directive_args, engine::Candidate, view::*};
use kv_core::remote::{
    self as remote,
    canonical::{from_json, jcs, CanonicalRequest},
    keys::{decode_b64, encode_b64, verify_object},
    *,
};
use serde_json::{json, Value};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};

struct GatedKey {
    key: SoftwareDeviceKey,
    unlocked: AtomicBool,
}
impl DeviceKeyProvider for GatedKey {
    fn public_jwk(&self) -> remote::Result<PublicJwk> {
        self.key.public_jwk()
    }
    fn sign(&self, alg: SignatureAlgorithm, payload: &[u8]) -> remote::Result<Vec<u8>> {
        if !self.unlocked.swap(false, Ordering::SeqCst) {
            return Err(RemoteError::KeyOperationFailed);
        }
        DeviceKeyProvider::sign(&self.key, alg, payload)
    }
    fn ecdh(&self, _: &[u8]) -> remote::Result<zeroize::Zeroizing<[u8; 32]>> {
        Err(RemoteError::UnsupportedAlgorithm)
    }
    fn key_kind(&self) -> KeyKind {
        KeyKind::Software
    }
    fn presence_kind(&self) -> PresenceKind {
        PresenceKind::Biometric
    }
}
struct Fixture {
    _directory: tempfile::TempDir,
    core: Arc<MobileCore>,
    dk: Arc<SoftwareDeviceKey>,
    q: Arc<SoftwareDeviceKey>,
    s: Arc<GatedKey>,
    executor: Arc<SoftwareDeviceKey>,
    peer: DeviceRecord,
}
impl Fixture {
    fn new() -> Self {
        let directory = tempfile::tempdir().unwrap();
        let dk = Arc::new(SoftwareDeviceKey::generate_p256());
        let q = Arc::new(SoftwareDeviceKey::generate_p256());
        let s = Arc::new(GatedKey {
            key: SoftwareDeviceKey::generate_p256(),
            unlocked: AtomicBool::new(false),
        });
        let core = Arc::new(
            MobileCore::open(
                directory.path(),
                MobileKeys {
                    identity: dk.clone(),
                    quick: q.clone(),
                    strong: s.clone(),
                },
                "CI phone",
                Os::Ios,
            )
            .unwrap(),
        );
        let executor = Arc::new(SoftwareDeviceKey::generate_p256());
        let peer = DeviceRecord {
            device_id: format!("dev_{}", new_id()),
            label: "CI executor".into(),
            os: Os::Linux,
            key_kind: KeyKind::Software,
            dk_pub: executor.public_jwk().unwrap(),
            dk_sig: kv_core::remote::Optional::Missing,
            ak_q: None,
            ak_s: None,
            caps: vec![Capability::Execute],
            attestation: None,
            extra: Extra::new(),
        };
        let candidate = Candidate {
            peer: peer.clone(),
            account: "acct_test".into(),
            pairing_id: new_id(),
            sas: "123456".into(),
            exp: now() + 300,
            local_confirm: None,
            peer_confirmed: false,
            exclude_global: false,
            peer_exclude_global: false,
            accept: None,
            confirmation_envelope: None,
            finish_sent: false,
            token_hash: None,
        };
        core.save_candidate(&candidate).unwrap();
        core.trust_candidate(&candidate, false).unwrap();
        Self {
            _directory: directory,
            core,
            dk,
            q,
            s,
            executor,
            peer,
        }
    }
    fn authorize(&self) {
        self.s.unlocked.store(true, Ordering::SeqCst);
    }
    fn envelope<T: serde::Serialize>(
        &self,
        kind: EnvelopeType,
        id: &str,
        payload: &T,
        exp: i64,
    ) -> Envelope {
        remote::envelope::seal(
            EnvelopeHeader {
                v: 1,
                r#type: kind,
                id: id.into(),
                account: self.core.account().unwrap(),
                from: self.peer.device_id.clone(),
                to: self.core.device().device_id.clone(),
                created_at: now(),
                exp,
                extra: Extra::new(),
            },
            &jcs(payload).unwrap(),
            &self.core.device().dk_pub,
            self.executor.as_ref(),
        )
        .unwrap()
    }
    fn receive<T: serde::Serialize>(
        &self,
        kind: EnvelopeType,
        id: &str,
        payload: &T,
        exp: i64,
    ) -> crate::Result<Option<NotificationView>> {
        self.core
            .receive(&serde_json::to_vec(&self.envelope(kind, id, payload, exp)).unwrap())
    }
    fn request(&self, tier: Tier) -> (ApprovalRequest, CanonicalRequest) {
        let nonce = crate::engine::random_nonce();
        let exp = now() + 600;
        let canonical:CanonicalRequest=serde_json::from_value(json!({"v":1,"kind":"use","requester":self.peer.device_id,"credential":"github/default", "action":{"kind":"http"},"method":"GET","host":"api.github.com","path":"/user","query_keys":[],"body_sha256":null,"headers_digest":null,
            "agent":{"runtime":"codex","repo_or_cwd":"/tmp/ci-repo","uid":501,"pid":42,"exe_sha256":"0".repeat(64)},"purpose":"Check the profile","nonce":nonce,"exp":exp})).unwrap();
        let request = ApprovalRequest {
            approval_id: new_id(),
            kind: ApprovalKind::Use,
            digest: canonical.digest().unwrap(),
            nonce,
            exp,
            requester: Requester {
                device_id: self.peer.device_id.clone(),
                label: self.peer.label.clone(),
                os: Os::Linux,
                protection: Protection {
                    kind: ProtectionKind::SoftwareKey,
                    attestation: Optional::Missing,
                    extra: Extra::new(),
                },
                extra: Extra::new(),
            },
            agent: Agent {
                runtime: AgentRuntime::Codex,
                cwd: "/tmp/ci-repo".into(),
                user: "ci".into(),
                pid: 42,
                extra: Extra::new(),
            },
            credential: Some(Credential {
                r#ref: "github/default".into(),
                kind: CredentialKind::Static,
                display: "GitHub".into(),
                proxy_only: true,
                extra: Extra::new(),
            }),
            operation: Some(Operation {
                summary: "Read GitHub profile".into(),
                method: "GET".into(),
                host: "api.github.com".into(),
                path: "/user".into(),
                query_keys: vec![],
                body_bytes: 0,
                extra: Extra::new(),
            }),
            purpose: canonical.purpose.clone(),
            tier,
            min_level: if tier == Tier::T2 {
                ApprovalLevel::Strong
            } else {
                ApprovalLevel::Quick
            },
            scope_options: if tier == Tier::T2 {
                vec![ScopeOption::PerUse]
            } else {
                vec![
                    ScopeOption::PerUse,
                    ScopeOption::Remember1h,
                    ScopeOption::StandingCredential,
                ]
            },
            requested_scope: ScopeOption::PerUse,
            merged_count: 1,
            delivery: Delivery {
                mode: DeliveryMode::Silent,
                escalate_after_s: 30,
                extra: Extra::new(),
            },
            extra: Extra::new(),
        };
        (request, canonical)
    }
    fn open_outbound<T: serde::de::DeserializeOwned>(&self) -> T {
        let envelope = self.core.outbound().unwrap().last().unwrap().1.clone();
        from_json(
            &remote::envelope::open(
                &envelope,
                &self.peer.device_id,
                self.executor.as_ref(),
                self.core.device(),
                now(),
            )
            .unwrap(),
        )
        .unwrap()
    }
}

#[test]
fn silent_escalation_away_and_cancel_follow_verified_envelopes() {
    let f = Fixture::new();
    let (r, _) = f.request(Tier::T1);
    let envelope = f.envelope(EnvelopeType::ApprovalRequest, &r.approval_id, &r, r.exp);
    let bytes = serde_json::to_vec(&envelope).unwrap();
    let view = f.core.receive(&bytes).unwrap().unwrap();
    assert!(!view.banner);
    assert!(view.quick_allowed);
    assert!(f.core.receive(&bytes).unwrap().is_none());
    let escalate = ApprovalEscalate {
        approval_id: r.approval_id.clone(),
        extra: Extra::new(),
    };
    assert!(
        f.receive(
            EnvelopeType::ApprovalEscalate,
            &r.approval_id,
            &escalate,
            r.exp
        )
        .unwrap()
        .unwrap()
        .banner
    );
    assert!(f.core.snapshot().unwrap().pending[0].escalated);
    let cancel = ApprovalCancel {
        approval_id: r.approval_id.clone(),
        extra: Extra::new(),
    };
    assert!(
        f.receive(EnvelopeType::ApprovalCancel, &r.approval_id, &cancel, r.exp)
            .unwrap()
            .unwrap()
            .cancel
    );
    assert!(f.core.snapshot().unwrap().pending.is_empty());
    let (r, _) = f.request(Tier::T1);
    f.core.set_preferences(true, true, "zh").unwrap();
    let view = f
        .receive(EnvelopeType::ApprovalRequest, &r.approval_id, &r, r.exp)
        .unwrap()
        .unwrap();
    assert!(view.banner);
    assert!(view.body.contains("agent 自述"));
    f.core.set_preferences(true, false, "en").unwrap();
    assert!(!f.core.snapshot().unwrap().pending[0].banner);
}
#[test]
fn early_escalate_reordering_and_clock_skew_are_visible() {
    let f = Fixture::new();
    let (r, _) = f.request(Tier::T1);
    f.receive(
        EnvelopeType::ApprovalEscalate,
        &r.approval_id,
        &json!({"approval_id":r.approval_id,"reason":"no_response"}),
        r.exp,
    )
    .unwrap();
    assert!(
        f.receive(EnvelopeType::ApprovalRequest, &r.approval_id, &r, r.exp)
            .unwrap()
            .unwrap()
            .banner
    );
    let view = f.core.snapshot().unwrap().pending.remove(0);
    assert!(view.escalated);
    assert!(!view.clock_skew);
}
#[test]
fn quick_decision_binds_digest_nonce_scope_and_consumes_pending() {
    let f = Fixture::new();
    let (r, canonical) = f.request(Tier::T1);
    f.receive(EnvelopeType::ApprovalRequest, &r.approval_id, &r, r.exp)
        .unwrap();
    assert_eq!(
        f.core
            .decide(&r.approval_id, "standing:device", true, "", false),
        Err(Error("invalid_scope"))
    );
    f.core
        .decide(&r.approval_id, "per_use", true, "", true)
        .unwrap();
    let decision: ApprovalDecision = f.open_outbound();
    assert_eq!(decision.level, ApprovalLevel::Quick);
    remote::validation::verify_decision(&decision, &r, &canonical, f.core.device(), now()).unwrap();
    assert_eq!(
        f.core.decide(&r.approval_id, "per_use", true, "", true),
        Err(Error("not_waiting"))
    );
    assert!(f.core.snapshot().unwrap().pending.is_empty());
}
#[test]
fn strong_cannot_be_signed_by_tampered_ui_or_background_worker() {
    let f = Fixture::new();
    let (r, canonical) = f.request(Tier::T2);
    f.receive(EnvelopeType::ApprovalRequest, &r.approval_id, &r, r.exp)
        .unwrap();
    assert_eq!(
        f.core.decide(&r.approval_id, "per_use", true, "", true),
        Err(Error("open_app_required"))
    );
    assert_eq!(
        f.core.decide(&r.approval_id, "per_use", true, "", false),
        Err(Error("hardware_unavailable"))
    );
    assert!(f.core.outbound().unwrap().is_empty());
    assert_eq!(f.core.snapshot().unwrap().pending.len(), 1);
    f.authorize();
    f.core
        .decide(&r.approval_id, "per_use", true, "", false)
        .unwrap();
    let decision: ApprovalDecision = f.open_outbound();
    remote::validation::verify_decision(&decision, &r, &canonical, f.core.device(), now()).unwrap();
    assert_eq!(decision.level, ApprovalLevel::Strong);
}
fn grant_input(f: &Fixture) -> GrantInput {
    GrantInput {
        device_id: f.peer.device_id.clone(),
        credential: "github/default".into(),
        scope: "credential".into(),
        hours: 1,
        standing: false,
        sensitive: false,
        confirmation: String::new(),
        calls: 10,
    }
}
#[test]
fn grants_are_strong_settings_objects_and_sensitive_grants_require_label() {
    let f = Fixture::new();
    let mut input = grant_input(&f);
    assert_eq!(
        f.core.issue_grant(&input),
        Err(Error("hardware_unavailable"))
    );
    f.authorize();
    f.core.issue_grant(&input).unwrap();
    let grant: Grant = f.open_outbound();
    assert_eq!(grant.exp.unwrap() - grant.nbf, 3600);
    assert_eq!(grant.origin, "settings");
    remote::validation::verify_grant(
        &grant,
        &f.peer.device_id,
        &f.peer.label,
        f.core.device(),
        ApprovalLevel::Strong,
        now(),
    )
    .unwrap();
    assert_eq!(
        f.core.snapshot().unwrap().devices[0].grants[0].remaining_calls,
        None
    );
    input.sensitive = true;
    assert_eq!(
        f.core.issue_grant(&input),
        Err(Error("confirmation_required"))
    );
    input.confirmation = f.peer.label.clone();
    input.hours = 168;
    f.authorize();
    f.core.issue_grant(&input).unwrap();
    let grant: Grant = f.open_outbound();
    assert_eq!(grant.scope.max_tier, Tier::T2);
    assert_eq!(grant.exp.unwrap() - grant.nbf, 7 * 86400);
    remote::validation::verify_grant(
        &grant,
        &f.peer.device_id,
        &f.peer.label,
        f.core.device(),
        ApprovalLevel::Strong,
        now(),
    )
    .unwrap();
}
#[test]
fn tightening_directives_are_quick_and_loosened_mode_requires_hardware() {
    let f = Fixture::new();
    let (op, args) = directive_args("revoke_all_grants", "").unwrap();
    f.core.directive(&f.peer.device_id, op, args, "").unwrap();
    let d: Directive = f.open_outbound();
    verify_object(&d, &d.sig, f.core.device().ak_q.as_ref().unwrap()).unwrap();
    let (op, args) = directive_args("set_mode", "remember:0h").unwrap();
    assert_eq!(
        f.core.directive(&f.peer.device_id, op, args.clone(), ""),
        Err(Error("hardware_unavailable"))
    );
    f.authorize();
    f.core.directive(&f.peer.device_id, op, args, "").unwrap();
    let d: Directive = f.open_outbound();
    verify_object(&d, &d.sig, f.core.device().ak_s.as_ref().unwrap()).unwrap();
    assert_eq!(
        f.core.directive(
            &f.peer.device_id,
            DirectiveOp::RevokeDevice,
            Extra::new(),
            "wrong"
        ),
        Err(Error("confirmation_required"))
    );
    assert!(directive_args("set_class", "").is_err());
    assert!(directive_args("invalid", "").is_err());
}
#[test]
fn database_and_wal_do_not_contain_approval_plaintext_and_survive_restart() {
    let f = Fixture::new();
    let (mut r, _) = f.request(Tier::T1);
    r.purpose = "NEVER_WRITE_THIS_PLAINTEXT".into();
    f.receive(EnvelopeType::ApprovalRequest, &r.approval_id, &r, r.exp)
        .unwrap();
    for entry in std::fs::read_dir(f._directory.path()).unwrap() {
        let bytes = std::fs::read(entry.unwrap().path()).unwrap();
        assert!(!bytes
            .windows(r.purpose.len())
            .any(|w| w == r.purpose.as_bytes()));
    }
    let second = MobileCore::open(
        f._directory.path(),
        MobileKeys {
            identity: f.dk.clone(),
            quick: f.q.clone(),
            strong: f.s.clone(),
        },
        "unused",
        Os::Ios,
    )
    .unwrap();
    assert_eq!(second.device(), f.core.device());
    assert_eq!(second.snapshot().unwrap().pending[0].purpose, r.purpose);
    second
        .decide(&r.approval_id, "per_use", false, "", true)
        .unwrap();
    assert_eq!(f.core.outbound().unwrap().len(), 1);
    let diagnostic = f.core.diagnostic().unwrap();
    assert!(!diagnostic.contains("github"));
    assert!(!diagnostic.contains("CI phone"));
    assert!(!diagnostic.contains(&r.purpose));
}
#[test]
fn encrypted_storage_authenticates_rows_and_rejects_symlinks() {
    let directory = tempfile::tempdir().unwrap();
    let store = Store::open(directory.path(), zeroize::Zeroizing::new([9; 32])).unwrap();
    store
        .transaction(|db| store.put(db, "test", "a", &"secret", 0))
        .unwrap();
    let db = rusqlite::Connection::open(directory.path().join("mobile.sqlite3")).unwrap();
    db.execute("UPDATE records SET key='b'", []).unwrap();
    assert_eq!(
        store.transaction(|db| store.get::<String>(db, "test", "b")),
        Err(Error("storage_integrity"))
    );
    #[cfg(unix)]
    {
        let outer = tempfile::tempdir().unwrap();
        let link = outer.path().join("linked");
        std::os::unix::fs::symlink(directory.path(), &link).unwrap();
        assert!(Store::open(&link, zeroize::Zeroizing::new([9; 32])).is_err());
    }
}
#[test]
fn rejected_ciphertext_never_changes_pending_or_exposes_secrets() {
    let f = Fixture::new();
    let (r, _) = f.request(Tier::T1);
    let mut e = f.envelope(EnvelopeType::ApprovalRequest, &r.approval_id, &r, r.exp);
    e.ct.push('A');
    assert_eq!(
        f.core.receive(&serde_json::to_vec(&e).unwrap()),
        Err(Error("verification_failed"))
    );
    assert!(f.core.snapshot().unwrap().pending.is_empty());
    let mut bad = r.clone();
    bad.digest = "bad".into();
    assert!(f
        .receive(
            EnvelopeType::ApprovalRequest,
            &bad.approval_id,
            &bad,
            bad.exp
        )
        .is_err());
    let mut bad = r.clone();
    bad.requester.protection.kind = ProtectionKind::SecureEnclave;
    assert!(f
        .receive(
            EnvelopeType::ApprovalRequest,
            &bad.approval_id,
            &bad,
            bad.exp
        )
        .is_err());
}
#[test]
fn uri_validation_rejects_remote_plaintext_and_noncanonical_tokens() {
    assert!(PairUri::parse("kv-pair://relay.example.com/AAAAAAAAAAAAAAAAAAAAAAAAAA").is_ok());
    for invalid in [
        "kv-pair://u:p@relay.example.com/AAAAAAAAAAAAAAAAAAAAAAAAAA",
        "kv-pair://relay.example.com/AAAAAAAAAAAAAAAAAAAAAAAAAB",
        "kv-pair://relay.example.com/AAAAAAAAAAAAAAAAAAAAAAAAAA?x=1",
    ] {
        assert!(PairUri::parse(invalid).is_err());
    }
    assert!(crate::relay::validate_url("http://relay.example.com/").is_err());
    assert!(crate::relay::validate_url("http://127.0.0.1:1234/").is_ok());
    assert!(crate::relay::validate_url("https://relay.example.com/path").is_err());
}

async fn post(
    http: &reqwest::Client,
    base: &url::Url,
    path: &str,
    token: Option<&str>,
    body: Value,
) -> Value {
    let mut request = http.post(base.join(path).unwrap()).json(&body);
    if let Some(token) = token {
        request = request.header("authorization", format!("Device {token}"));
    }
    let response = request.send().await.unwrap();
    let status = response.status();
    let result = response.json::<Value>().await.unwrap();
    assert!(status.is_success(), "{path}: {status} {result}");
    result
}
async fn authenticate(
    http: &reqwest::Client,
    base: &url::Url,
    record: &DeviceRecord,
    key: &SoftwareDeviceKey,
) -> String {
    let challenge = post(
        http,
        base,
        "v1/auth/challenge",
        None,
        json!({"device_id":record.device_id}),
    )
    .await;
    let signature = DeviceKeyProvider::sign(
        key,
        SignatureAlgorithm::ES256,
        &decode_b64(challenge["challenge"].as_str().unwrap()).unwrap(),
    )
    .unwrap();
    post(http,base,"v1/auth/verify",None,json!({"device_id":record.device_id,"challenge":challenge["challenge"],"sig":encode_b64(&signature)})).await["session_token"].as_str().unwrap().into()
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn w2_pairing_silent_thirty_seconds_escalation_quick_strong_grant_revoke_all() {
    let f = Fixture::new();
    let issuer = accounts::issuer();
    let (base, server) = accounts::server(&issuer);
    let http = reqwest::Client::new();
    let registration = post(
        &http,
        &base,
        "v1/devices",
        None,
        serde_json::to_value(&f.peer).unwrap(),
    )
    .await;
    let executor_token = authenticate(&http, &base, &f.peer, &f.executor).await;
    let raw = [7_u8; 16];
    let started=post(&http,&base,"v1/pair/start",Some(&executor_token),json!({"token_hash":remote::canonical::sha256_hex(&raw),"initiator":f.peer,"exp":now()+300})).await;
    f.core
        .store
        .transaction(|db| {
            Store::delete(db, "peers", &f.peer.device_id)?;
            Ok(())
        })
        .unwrap();
    let relay = Relay::new(f.core.clone()).unwrap();
    f.core.set_relay(base.as_str()).unwrap();
    f.core.require_account_login();
    let attempt = relay.account_begin("google").await.unwrap();
    let token = accounts::token(&issuer, "google", "ci-owner", "", now());
    assert!(
        relay
            .account_finish(&attempt.attempt_id, &token, "", "")
            .await
            .unwrap()
            .signed_in
    );
    let pair = relay
        .begin_pair_at(base.clone(), raw.to_vec())
        .await
        .unwrap();
    assert_eq!(f.core.account().unwrap(), registration["account_id"]);
    assert_eq!(pair.pairing_id, started["pairing_id"]);
    let owner_count = || {
        server.inspect(|db| {
            db.query_row(
                "SELECT COUNT(*) FROM account_owners WHERE account_id=?1",
                [registration["account_id"].as_str().unwrap()],
                |r| r.get::<_, i64>(0),
            )
            .unwrap()
        })
    };
    assert_eq!(
        owner_count(),
        0,
        "a QR scan cannot claim executor ownership"
    );
    let renewed = relay.account_begin("google").await.unwrap();
    relay
        .account_finish(
            &renewed.attempt_id,
            &accounts::token(&issuer, "google", "ci-owner", "", now()),
            "",
            "",
        )
        .await
        .unwrap();
    assert_eq!(
        owner_count(),
        0,
        "signing in while SAS is pending cannot claim ownership"
    );
    let confirm = PairConfirm {
        sas: pair.sas.clone(),
        sig: String::new(),
        extra: Extra::new(),
    };
    post(
        &http,
        &base,
        "v1/pair/finish",
        Some(&executor_token),
        json!({"pairing_id":pair.pairing_id,"confirm":confirm}),
    )
    .await;
    // A confirmation cannot extend the pairing expiry after the wall clock advances.
    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
    let executor_confirmation = remote::envelope::seal(
        EnvelopeHeader {
            v: 1,
            r#type: EnvelopeType::PairConfirm,
            id: pair.pairing_id.clone(),
            account: registration["account_id"].as_str().unwrap().into(),
            from: f.peer.device_id.clone(),
            to: f.core.own.device_id.clone(),
            created_at: now(),
            exp: pair.expires_at,
            extra: Extra::new(),
        },
        &jcs(&confirm).unwrap(),
        &f.core.own.dk_pub,
        f.executor.as_ref(),
    )
    .unwrap();
    post(
        &http,
        &base,
        "v1/messages",
        Some(&executor_token),
        json!({"envelopes":[executor_confirmation]}),
    )
    .await;
    f.authorize();
    tokio::time::timeout(
        std::time::Duration::from_secs(10),
        relay.confirm_pair(&pair.sas, false),
    )
    .await
    .expect("the in-process peer confirmation must arrive")
    .unwrap();
    assert_eq!(owner_count(), 1);
    let stranger = Fixture::new();
    stranger
        .core
        .store
        .transaction(|db| Store::delete(db, "peers", &stranger.peer.device_id))
        .unwrap();
    stranger.core.set_relay(base.as_str()).unwrap();
    stranger.core.require_account_login();
    let stranger_relay = Relay::new(stranger.core.clone()).unwrap();
    let attempt = stranger_relay.account_begin("google").await.unwrap();
    stranger_relay
        .account_finish(
            &attempt.attempt_id,
            &accounts::token(&issuer, "google", "other-owner", "", now()),
            "",
            "",
        )
        .await
        .unwrap();
    let untrusted_token = [9_u8; 16];
    post(&http,&base,"v1/pair/start",Some(&executor_token),
        json!({"token_hash":remote::canonical::sha256_hex(&untrusted_token),"initiator":f.peer,"exp":now()+300})).await;
    assert!(
        stranger_relay
            .begin_pair_at(base.clone(), untrusted_token.to_vec())
            .await
            .is_err(),
        "another verified user cannot join the claimed account"
    );
    assert_eq!(owner_count(), 1);
    let (r, canonical) = f.request(Tier::T1);
    let e = f.envelope(EnvelopeType::ApprovalRequest, &r.approval_id, &r, r.exp);
    post(
        &http,
        &base,
        "v1/approvals",
        Some(&executor_token),
        json!({"id":r.approval_id,"exp":r.exp,"envelopes":[e]}),
    )
    .await;
    let plans = relay.sync_background().await.unwrap();
    assert!(!plans[0].banner);
    // Real wall-clock acceptance; no paused Tokio clock can hide transport or expiry bugs.
    tokio::time::sleep(std::time::Duration::from_secs(30)).await;
    let escalate = f.envelope(
        EnvelopeType::ApprovalEscalate,
        &r.approval_id,
        &json!({"approval_id":r.approval_id,"reason":"no_response"}),
        r.exp,
    );
    post(
        &http,
        &base,
        "v1/approvals",
        Some(&executor_token),
        json!({"id":r.approval_id,"exp":r.exp,"envelopes":[escalate]}),
    )
    .await;
    assert!(relay.sync_background().await.unwrap()[0].banner);
    f.core
        .decide(&r.approval_id, "per_use", true, "", true)
        .unwrap();
    let decision: ApprovalDecision = f.open_outbound();
    remote::validation::verify_decision(&decision, &r, &canonical, f.core.device(), now()).unwrap();
    relay.flush().await.unwrap();
    let (r, canonical) = f.request(Tier::T2);
    let e = f.envelope(EnvelopeType::ApprovalRequest, &r.approval_id, &r, r.exp);
    post(
        &http,
        &base,
        "v1/approvals",
        Some(&executor_token),
        json!({"id":r.approval_id,"exp":r.exp,"envelopes":[e]}),
    )
    .await;
    assert!(!relay.sync_background().await.unwrap()[0].quick_allowed);
    assert!(f
        .core
        .decide(&r.approval_id, "per_use", true, "", true)
        .is_err());
    f.authorize();
    f.core
        .decide(&r.approval_id, "per_use", true, "", false)
        .unwrap();
    let decision: ApprovalDecision = f.open_outbound();
    remote::validation::verify_decision(&decision, &r, &canonical, f.core.device(), now()).unwrap();
    relay.flush().await.unwrap();
    f.authorize();
    f.core.issue_grant(&grant_input(&f)).unwrap();
    let grant: Grant = f.open_outbound();
    remote::validation::verify_grant(
        &grant,
        &f.peer.device_id,
        &f.peer.label,
        f.core.device(),
        ApprovalLevel::Strong,
        now(),
    )
    .unwrap();
    relay.flush().await.unwrap();
    f.core
        .directive(
            &f.peer.device_id,
            DirectiveOp::RevokeAllGrants,
            Extra::new(),
            "",
        )
        .unwrap();
    let directive: Directive = f.open_outbound();
    remote::validation::verify_directive(
        &directive,
        &f.peer.device_id,
        f.core.device(),
        ApprovalLevel::Quick,
        now(),
        &remote::validation::DirectiveState::default(),
    )
    .unwrap();
    relay.flush().await.unwrap();
    let (cancelled, _) = f.request(Tier::T1);
    post(
        &http,
        &base,
        "v1/approvals",
        Some(&executor_token),
        json!({"id":cancelled.approval_id,"exp":cancelled.exp,"envelopes":[f.envelope(EnvelopeType::ApprovalRequest,&cancelled.approval_id,&cancelled,cancelled.exp)]}),
    )
    .await;
    relay.sync_background().await.unwrap();
    // W2's real HTTP/WS transport remains live; only the cancellation ack fails with a storage error.
    server.inspect(|db| {
        db.execute_batch(
            "CREATE TRIGGER fail_cancel_ack BEFORE UPDATE OF acked_at ON messages
            WHEN NEW.type='approval_cancel' AND NEW.acked_at IS NOT NULL
            BEGIN SELECT RAISE(ABORT,'injected ack failure'); END;",
        )
        .unwrap();
    });
    post(
        &http,
        &base,
        &format!("v1/approvals/{}/cancel", cancelled.approval_id),
        Some(&executor_token),
        json!({"envelope":f.envelope(EnvelopeType::ApprovalCancel,&cancelled.approval_id,&json!({"approval_id":cancelled.approval_id}),cancelled.exp)}),
    )
    .await;
    let cancelled_plan = relay.sync_background().await.unwrap();
    assert!(
        cancelled_plan
            .iter()
            .find(|plan| plan.approval_id == cancelled.approval_id)
            .unwrap()
            .cancel
    );
    assert!(f.core.snapshot().unwrap().pending.is_empty());
    server.inspect(|db| {
        let unacked: i64 = db
            .query_row(
                "SELECT count(*) FROM messages WHERE type='approval_cancel' AND acked_at IS NULL",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(unacked, 1);
        db.execute_batch("DROP TRIGGER fail_cancel_ack").unwrap();
    });
    // Retry a byte-identical envelope. Its durable tombstone still cancels the native banner.
    assert!(relay
        .sync_background()
        .await
        .unwrap()
        .iter()
        .any(|plan| plan.approval_id == cancelled.approval_id && plan.cancel));
    server.inspect(|db| {
        let acked: i64 = db
            .query_row(
                "SELECT count(*) FROM messages WHERE acked_at IS NOT NULL",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert!(acked >= 3);
    });
    // Lifecycle restart must create a live foreground socket after aborting the old task.
    for _ in 0..2 {
        relay.start();
        tokio::time::timeout(std::time::Duration::from_secs(3), async {
            while !f.core.snapshot().unwrap().connected {
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        relay.stop();
        assert!(!f.core.snapshot().unwrap().connected);
    }
    server.shutdown().await;
}

unsafe extern "C" fn vector_key_callback(
    slot: u32,
    operation: u32,
    input: *const u8,
    size: usize,
    output: *mut u8,
    capacity: usize,
) -> isize {
    let mut scalar = [0; 32];
    scalar[31] = (slot + 2) as u8;
    let key = SoftwareDeviceKey::from_p256_bytes(&scalar).unwrap();
    // SAFETY: the native adapter supplies valid buffers for each callback operation.
    let input = unsafe { std::slice::from_raw_parts(input, size) };
    let bytes = match operation {
        0 => remote::keys::p256_public_sec1(&key.public_jwk().unwrap()).unwrap(),
        1 => DeviceKeyProvider::sign(&key, SignatureAlgorithm::ES256, input).unwrap(),
        2 => DeviceKeyProvider::ecdh(&key, input).unwrap().to_vec(),
        _ => return -1,
    };
    if bytes.len() > capacity {
        return -1;
    }
    // SAFETY: capacity has been checked and the destination belongs to the caller.
    unsafe {
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), output, bytes.len());
    }
    bytes.len() as isize
}
#[test]
fn w0_vectors_decrypt_through_the_native_callback_and_bind_all_pairing_keys() {
    let vector: Value = serde_json::from_str(include_str!(
        "../../kv-core/testdata/remote/envelope_roundtrip.json"
    ))
    .unwrap();
    let key = crate::hardware::NativeKey {
        slot: 0,
        callback: vector_key_callback,
        kind: "secure_enclave".into(),
    };
    let recipient: DeviceRecord = serde_json::from_value(vector["recipient"].clone()).unwrap();
    let sender: DeviceRecord = serde_json::from_value(vector["sender"].clone()).unwrap();
    assert_eq!(key.public_jwk().unwrap(), recipient.dk_pub);
    let envelope: Envelope = serde_json::from_value(vector["envelope"].clone()).unwrap();
    let plaintext = remote::envelope::open(
        &envelope,
        &recipient.device_id,
        &key,
        &sender,
        vector["now"].as_i64().unwrap(),
    )
    .unwrap();
    assert_eq!(
        plaintext.as_slice(),
        vector["expect"]["plaintext"].as_str().unwrap().as_bytes()
    );
    let signature =
        DeviceKeyProvider::sign(&key, SignatureAlgorithm::ES256, b"callback probe").unwrap();
    remote::keys::verify_signature(
        SignatureAlgorithm::ES256,
        &recipient.dk_pub,
        b"callback probe",
        &signature,
    )
    .unwrap();
    let strong = crate::hardware::NativeKey {
        slot: 2,
        callback: vector_key_callback,
        kind: "secure_enclave".into(),
    };
    assert!(DeviceKeyProvider::ecdh(
        &strong,
        &remote::keys::p256_public_sec1(&recipient.dk_pub).unwrap()
    )
    .is_err());
    assert!(DeviceKeyProvider::sign(&key, SignatureAlgorithm::RS256, b"probe").is_err());
    let v: Value =
        serde_json::from_str(include_str!("../../kv-core/testdata/remote/pair_sas.json")).unwrap();
    let initiator: DeviceRecord = serde_json::from_value(v["initiator"].clone()).unwrap();
    let joiner: DeviceRecord = serde_json::from_value(v["joiner"].clone()).unwrap();
    let token = decode_b64(v["token"].as_str().unwrap()).unwrap();
    let sas = remote::pairing::sas(
        &token,
        &initiator.dk_pub,
        &joiner.dk_pub,
        joiner.ak_q.as_ref().map(|k| &k.r#pub),
        joiner.ak_s.as_ref().map(|k| &k.r#pub),
    )
    .unwrap();
    assert_eq!(sas, v["expect"]["sas"]);
    let confirm: PairConfirm = serde_json::from_value(v["confirm"].clone()).unwrap();
    remote::pairing::verify_confirm(&confirm, &sas, joiner.ak_s.as_ref().unwrap()).unwrap();
    let altered = remote::pairing::sas(
        &token,
        &initiator.dk_pub,
        &joiner.dk_pub,
        None,
        joiner.ak_s.as_ref().map(|k| &k.r#pub),
    )
    .unwrap();
    assert_ne!(altered, sas);
}
#[test]
fn reported_budget_presence_and_revocation_results_update_the_same_device() {
    let f = Fixture::new();
    f.authorize();
    f.core.issue_grant(&grant_input(&f)).unwrap();
    let grant: Grant = f.open_outbound();
    let query = f
        .core
        .directive(
            &f.peer.device_id,
            DirectiveOp::QueryGrants,
            Extra::new(),
            "",
        )
        .unwrap();
    let mut reported = serde_json::to_value(&grant).unwrap();
    reported["budget_left"] = json!({"calls_left":3});
    reported["authority"] = json!("must not reach public models");
    let response = DirectiveResult {
        id: query.clone(),
        ok: true,
        error: None,
        state: serde_json::from_value(
            json!({"mode":"remember:1h","unlock_ttl_s":300,"grants":[reported]}),
        )
        .unwrap(),
        extra: Extra::new(),
    };
    f.receive(
        EnvelopeType::DirectiveResult,
        &query,
        &response,
        now() + 300,
    )
    .unwrap();
    let device = f.core.snapshot().unwrap().devices.remove(0);
    assert_eq!(device.grants[0].remaining_calls, Some(3));
    assert!(!device.grants[0].pending_delivery);
    assert!(!serde_json::to_string(&device)
        .unwrap()
        .contains("authority"));
    let hint = PresenceHint {
        device_id: f.peer.device_id.clone(),
        state: Presence::Present,
        since: now(),
        sent_at: now(),
        extra: Extra::new(),
    };
    f.receive(EnvelopeType::PresenceHint, &new_id(), &hint, now() + 120)
        .unwrap();
    let device = f.core.snapshot().unwrap().devices.remove(0);
    assert!(device.online);
    assert_eq!(device.mode, "remember:1h");
    let revoke = f
        .core
        .directive(
            &f.peer.device_id,
            DirectiveOp::RevokeAllGrants,
            Extra::new(),
            "",
        )
        .unwrap();
    let result = DirectiveResult {
        id: revoke.clone(),
        ok: true,
        error: None,
        state: Extra::new(),
        extra: Extra::new(),
    };
    f.receive(EnvelopeType::DirectiveResult, &revoke, &result, now() + 300)
        .unwrap();
    assert!(f.core.snapshot().unwrap().devices[0].grants.is_empty());
    let unsolicited = new_id();
    let result = DirectiveResult {
        id: unsolicited.clone(),
        ..result
    };
    assert_eq!(
        f.receive(
            EnvelopeType::DirectiveResult,
            &unsolicited,
            &result,
            now() + 300
        ),
        Err(Error("unsolicited_result"))
    );
}
#[test]
fn audit_retention_keeps_the_latest_entries_and_never_truncates_durable_state() {
    let directory = tempfile::tempdir().unwrap();
    let store = Store::open(directory.path(), zeroize::Zeroizing::new([3; 32])).unwrap();
    store
        .transaction(|db| {
            for n in 0..2100 {
                store.put(db, "activity", &n.to_string(), &n, 0)?;
                store.put(db, "issued_test", &n.to_string(), &n, 0)?;
            }
            assert_eq!(store.list::<u32>(db, "issued_test")?.len(), 2100);
            let history = store.list::<u32>(db, "activity")?;
            assert_eq!(history.len(), 200);
            assert_eq!(history[0].1, 1900);
            assert_eq!(history[199].1, 2099);
            Ok(())
        })
        .unwrap();
}

#[test]
fn executor_audit_is_bounded_metadata_and_stays_separate_from_local_issued_history() {
    let f = Fixture::new();
    let (op, args) = directive_args("query_audit", "").unwrap();
    let query = f
        .core
        .directive(&f.peer.device_id, op, args.clone(), "")
        .unwrap();
    let result = DirectiveResult {
        id: query.clone(), ok: true, error: None,
        state: serde_json::from_value(json!({"entries":[
            {"op":"request_allowed","ts_unix":now()+1,"ok":true,"credential_value":"never expose this value","body":"private body"},
            {"op":"request_denied","ts_unix":now()+2,"ok":false}
        ]})).unwrap(),
        extra: Extra::new(),
    };
    f.receive(EnvelopeType::DirectiveResult, &query, &result, now() + 300)
        .unwrap();
    let snapshot = f.core.snapshot().unwrap();
    let recent = &snapshot.devices[0].recent_activity;
    assert_eq!(recent[0].kind, "executor_rejected");
    assert_eq!(recent[1].kind, "executor_applied");
    assert_eq!(recent[1].summary, "request_allowed");
    let public = serde_json::to_string(&snapshot).unwrap();
    assert!(!public.contains("never expose this value"));
    assert!(!public.contains("private body"));
    assert!(!public.contains("credential_value"));
    assert!(snapshot
        .activity
        .iter()
        .all(|a| !a.kind.starts_with("executor_")));
    let query = f.core.directive(&f.peer.device_id, op, args, "").unwrap();
    let result = DirectiveResult {
        id: query.clone(),
        state: serde_json::from_value(
            json!({"entries":vec![json!({"op":"event","ts_unix":now()});201]}),
        )
        .unwrap(),
        ..result
    };
    assert_eq!(
        f.receive(EnvelopeType::DirectiveResult, &query, &result, now() + 300),
        Err(Error("invalid_result"))
    );
}
#[test]
fn native_c_abi_rejects_arbitrary_signing_and_exports_only_shared_public_models() {
    fn call(command: &str) -> Value {
        let input = std::ffi::CString::new(command).unwrap();
        // SAFETY: input lives until the call returns; returned allocation is freed exactly once.
        unsafe {
            let output = crate::ffi::kv_mobile_call(input.as_ptr());
            let value =
                serde_json::from_slice(std::ffi::CStr::from_ptr(output).to_bytes()).unwrap();
            crate::ffi::kv_mobile_free(output);
            value
        }
    }
    let directory = tempfile::tempdir().unwrap();
    let input = std::ffi::CString::new(
        json!({"directory":directory.path(),"label":"ABI test","os":"ios","key_kind":"software"})
            .to_string(),
    )
    .unwrap();
    // SAFETY: the callback has static lifetime and fulfills the native buffer contract.
    unsafe {
        let output = crate::ffi::kv_mobile_open(input.as_ptr(), Some(vector_key_callback));
        let result: Value =
            serde_json::from_slice(std::ffi::CStr::from_ptr(output).to_bytes()).unwrap();
        crate::ffi::kv_mobile_free(output);
        assert_eq!(result["ok"], true);
    }
    let snapshot = call(r#"{"op":"snapshot"}"#);
    assert_eq!(snapshot["ok"], false);
    assert_eq!(snapshot["error"], "login_required");
    let account = call(r#"{"op":"account_status"}"#);
    assert_eq!(account["ok"], true);
    let model: AccountView = serde_json::from_value(account["result"].clone()).unwrap();
    assert!(!model.signed_in);
    assert!(!account.to_string().contains("session_token"));
    for invalid in [
        r#"{"op":"sign","slot":2,"payload":"bypass"}"#,
        r#"{"op":"quick_decision","approval_id":"a","allow":true,"scope":"standing:device"}"#,
        r#"{"op":"push_token","platform":"apns","token":"\n"}"#,
    ] {
        assert_eq!(call(invalid)["ok"], false);
    }
}

#[tokio::test]
async fn throttled_and_unavailable_relay_preserve_ciphertext_fifo_across_restart() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let f = Fixture::new();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}/", listener.local_addr().unwrap());
    f.core
        .store
        .transaction(|db| {
            let mut s: SettingsView = f.core.store.get(db, "meta", "settings")?.unwrap();
            s.relay_url = url;
            f.core.store.put(db, "meta", "settings", &s, 0)
        })
        .unwrap();
    let first = f
        .core
        .directive(&f.peer.device_id, DirectiveOp::Lock, Extra::new(), "")
        .unwrap();
    let second = f
        .core
        .directive(
            &f.peer.device_id,
            DirectiveOp::RevokeAllGrants,
            Extra::new(),
            "",
        )
        .unwrap();
    let attempts = Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
    let observed = attempts.clone();
    let task = tokio::spawn(async move {
        let mut failed = 0;
        loop {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut input = Vec::new();
            let mut buffer = [0; 4096];
            let (end, length) = loop {
                let n = stream.read(&mut buffer).await.unwrap();
                assert_ne!(n, 0);
                input.extend(&buffer[..n]);
                assert!(input.len() < 128 * 1024);
                if let Some(end) = input.windows(4).position(|w| w == b"\r\n\r\n") {
                    let headers = std::str::from_utf8(&input[..end]).unwrap();
                    let length = headers
                        .lines()
                        .find_map(|l| {
                            l.to_ascii_lowercase()
                                .strip_prefix("content-length:")
                                .map(|v| v.trim().parse::<usize>().unwrap())
                        })
                        .unwrap_or(0);
                    break (end + 4, length);
                }
            };
            while input.len() < end + length {
                let n = stream.read(&mut buffer).await.unwrap();
                assert_ne!(n, 0);
                input.extend(&buffer[..n]);
            }
            let path = std::str::from_utf8(&input[..end])
                .unwrap()
                .split_whitespace()
                .nth(1)
                .unwrap();
            let body: Value = serde_json::from_slice(&input[end..end + length]).unwrap();
            let (status, response) = match path {
                "/v1/auth/challenge" => {
                    (200, json!({"challenge":encode_b64(&[9;32]),"exp":now()+60}))
                }
                "/v1/auth/verify" => (
                    200,
                    json!({"session_token":"test-session","exp":now()+3600}),
                ),
                "/v1/messages" => {
                    assert!(body["envelopes"][0].get("ct").is_some());
                    assert!(body["envelopes"][0].get("purpose").is_none());
                    observed
                        .lock()
                        .unwrap()
                        .push(body["envelopes"][0]["id"].as_str().unwrap().into());
                    let status = match failed {
                        0 => 429,
                        1 => 503,
                        _ => 200,
                    };
                    failed += 1;
                    (status, json!({"accepted":1}))
                }
                _ => panic!("unexpected fake relay route"),
            };
            let body = response.to_string();
            let wire=format!("HTTP/1.1 {status} Test\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",body.len());
            stream.write_all(wire.as_bytes()).await.unwrap();
        }
    });
    let relay = Relay::new(f.core.clone()).unwrap();
    assert_eq!(relay.flush().await, Err(Error("rate_limited")));
    assert_eq!(relay.flush().await, Err(Error("relay_unavailable")));
    assert_eq!(f.core.outbound().unwrap().len(), 2);
    let recovered = Arc::new(
        MobileCore::open(
            f._directory.path(),
            MobileKeys {
                identity: f.dk.clone(),
                quick: f.q.clone(),
                strong: f.s.clone(),
            },
            "unused",
            Os::Ios,
        )
        .unwrap(),
    );
    let relay = Relay::new(recovered.clone()).unwrap();
    let (a, b) = tokio::join!(relay.flush(), relay.flush());
    a.unwrap();
    b.unwrap();
    assert!(recovered.outbound().unwrap().is_empty());
    assert_eq!(
        *attempts.lock().unwrap(),
        vec![first.clone(), first.clone(), first, second]
    );
    task.abort();
}

#[test]
fn malformed_native_signature_is_rejected_before_it_can_be_queued() {
    unsafe extern "C" fn bad_signature(
        slot: u32,
        operation: u32,
        input: *const u8,
        size: usize,
        output: *mut u8,
        capacity: usize,
    ) -> isize {
        if operation == 1 && capacity == 64 {
            // SAFETY: callback output is writable for capacity bytes.
            unsafe {
                std::ptr::write_bytes(output, 0, capacity);
            }
            64
        } else {
            // SAFETY: this forwards the same validated callback buffers.
            unsafe { vector_key_callback(slot, operation, input, size, output, capacity) }
        }
    }
    let key = crate::hardware::NativeKey {
        slot: 2,
        callback: bad_signature,
        kind: "secure_enclave".into(),
    };
    assert_eq!(
        DeviceKeyProvider::sign(&key, SignatureAlgorithm::ES256, b"bad SDK signature"),
        Err(RemoteError::KeyOperationFailed)
    );
}

#[tokio::test]
async fn native_background_can_display_verified_cached_requests_while_relay_is_offline() {
    let f = Fixture::new();
    let (request, _) = f.request(Tier::T1);
    f.receive(
        EnvelopeType::ApprovalRequest,
        &request.approval_id,
        &request,
        request.exp,
    )
    .unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    drop(listener);
    f.core
        .store
        .transaction(|db| {
            let mut settings: SettingsView = f.core.store.get(db, "meta", "settings")?.unwrap();
            settings.relay_url = format!("http://{address}/");
            f.core.store.put(db, "meta", "settings", &settings, 0)
        })
        .unwrap();
    let relay = Relay::new(f.core.clone()).unwrap();
    let plans = relay.sync_background().await.unwrap();
    assert_eq!(plans.len(), 1);
    assert_eq!(plans[0].approval_id, request.approval_id);
    assert!(!plans[0].banner);
    f.core.set_preferences(true, true, "en").unwrap();
    assert!(relay.sync_background().await.unwrap()[0].banner);
    assert!(!f.core.snapshot().unwrap().connected);
    f.receive(
        EnvelopeType::ApprovalCancel,
        &request.approval_id,
        &json!({"approval_id":request.approval_id}),
        request.exp,
    )
    .unwrap();
    let recovered = Arc::new(
        MobileCore::open(
            f._directory.path(),
            MobileKeys {
                identity: f.dk.clone(),
                quick: f.q.clone(),
                strong: f.s.clone(),
            },
            "CI phone",
            Os::Ios,
        )
        .unwrap(),
    );
    let plans = Relay::new(recovered)
        .unwrap()
        .sync_background()
        .await
        .unwrap();
    assert_eq!(plans.len(), 1);
    assert_eq!(plans[0].approval_id, request.approval_id);
    assert!(plans[0].cancel);
}
