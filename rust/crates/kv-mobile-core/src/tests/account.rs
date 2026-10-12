use super::*;
#[test]
fn production_relay_is_fixed_and_only_internal_ci_paths_accept_loopback() {
    use crate::relay::validate_app_relay;
    assert!(validate_app_relay(crate::RELAY_URL, false).is_ok());
    for address in ["https://other.example/", "http://127.0.0.1:1/"] {
        assert_eq!(
            validate_app_relay(address, false),
            Err(Error("fixed_relay"))
        );
    }
    assert!(validate_app_relay("http://127.0.0.1:1/", true).is_ok());
    assert_eq!(
        validate_app_relay("https://other.example/", true),
        Err(Error("fixed_relay"))
    );
}

#[test]
fn stale_server_refusal_cannot_delete_a_newer_session_or_pending_sign_in() {
    let f = Fixture::new();
    f.core.require_account_login();
    let session = crate::account::Session {
        session_token: "b".repeat(43),
        expires_at: now() + 600,
        relay_url: crate::RELAY_URL.into(),
        user: crate::account::User {
            id: "owner".into(),
            provider: "google".into(),
            email: "owner@example.test".into(),
            display_name: "Owner".into(),
        },
    };
    f.core
        .store
        .transaction(|db| {
            f.core
                .store
                .put(db, "meta", "account_session", &session, 0)?;
            f.core
                .store
                .put(db, "meta", "login_attempt", &json!({"id":"new-attempt"}), 0)
        })
        .unwrap();
    f.core.clear_login_if(&"a".repeat(43)).unwrap();
    assert!(f.core.account_view().unwrap().signed_in);
    assert!(f.core.snapshot().is_ok());
    f.core.clear_login_if(&session.session_token).unwrap();
    assert!(!f.core.account_view().unwrap().signed_in);
    assert_eq!(
        f.core
            .store
            .transaction(|db| f.core.store.get::<Value>(db, "meta", "login_attempt"))
            .unwrap(),
        Some(json!({"id":"new-attempt"}))
    );
}

pub(super) fn issuer() -> SoftwareDeviceKey {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../kv-core/testdata/remote/test_keys.json");
    let keys: Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    SoftwareDeviceKey::from_rsa_pkcs8_der(
        &decode_b64(keys["rsa_pkcs8_der"].as_str().unwrap()).unwrap(),
    )
    .unwrap()
}
pub(super) fn server(key: &SoftwareDeviceKey) -> (url::Url, kv_server::Handle) {
    let mut jwk = key.public_jwk().unwrap();
    jwk.extra.insert("kid".into(), json!("ci-issuer"));
    kv_server::spawn_test_relay_with_accounts(
        kv_server::AccountConfig {
            required: true,
            google_web_client_id: "ci-web".into(),
            google_ios_client_id: "ci-ios".into(),
            google_android_client_id: "ci-android".into(),
            apple_app_id: "ci-apple".into(),
            apple_services_id: "ci-service".into(),
        },
        vec![
            ("google".into(), vec![jwk.clone()]),
            ("apple".into(), vec![jwk]),
        ],
    )
}
pub(super) fn token(
    key: &SoftwareDeviceKey,
    provider: &str,
    subject: &str,
    nonce: &str,
    at: i64,
) -> String {
    let (issuer, audience) = if provider == "google" {
        ("https://accounts.google.com", "ci-web")
    } else {
        ("https://appleid.apple.com", "ci-apple")
    };
    let claims = json!({"iss":issuer,"aud":audience,"iat":at,"exp":at+600,"sub":subject,
        "email":"owner@example.test","email_verified":true,"nonce":nonce,"name":"CI Owner"});
    let payload = format!(
        "{}.{}",
        encode_b64(br#"{"alg":"RS256","kid":"ci-issuer"}"#),
        encode_b64(&serde_json::to_vec(&claims).unwrap())
    );
    format!(
        "{payload}.{}",
        encode_b64(
            &DeviceKeyProvider::sign(key, SignatureAlgorithm::RS256, payload.as_bytes()).unwrap()
        )
    )
}
fn configure(f: &Fixture, base: &url::Url) {
    // These tests start before pairing; the shared fixture's synthetic peer is removed.
    f.core
        .store
        .transaction(|db| Store::delete(db, "peers", &f.peer.device_id))
        .unwrap();
    f.core.set_relay(base.as_str()).unwrap();
    f.core.require_account_login();
}

#[tokio::test]
async fn login_gates_native_data_keys_and_transport_and_persists_only_encrypted_session() {
    let f = Fixture::new();
    let key = issuer();
    let (base, handle) = server(&key);
    configure(&f, &base);
    let relay = Relay::new(f.core.clone()).unwrap();
    assert_eq!(f.core.snapshot(), Err(Error("login_required")));
    assert_eq!(
        f.core.decide("missing", "per_use", true, "", true),
        Err(Error("login_required"))
    );
    assert_eq!(
        f.core
            .directive(&f.peer.device_id, DirectiveOp::Lock, Extra::new(), ""),
        Err(Error("login_required"))
    );
    assert_eq!(f.core.receive(b"{}"), Err(Error("login_required")));
    assert_eq!(relay.authenticate().await, Err(Error("login_required")));
    assert_eq!(relay.sync_background().await, Err(Error("login_required")));
    let http = reqwest::Client::new();
    let response = http
        .post(base.join("v1/devices").unwrap())
        .json(f.core.device())
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 401);
    let attempt = relay.account_begin("google").await.unwrap();
    f.core
        .store
        .transaction(|db| {
            f.core.store.put(
                db,
                "meta",
                "push_token",
                &json!({"platform":"apns","token":"ci-push-token"}),
                0,
            )
        })
        .unwrap();
    let jwt = token(&key, "google", "ci-owner", "", now());
    assert_eq!(
        relay.account_finish("wrong", &jwt, "", "").await,
        Err(Error("invalid_login_attempt"))
    );
    let view = relay
        .account_finish(&attempt.attempt_id, &jwt, "", "")
        .await
        .unwrap();
    assert!(view.signed_in);
    handle.inspect(|db| {
        let push: Vec<u8> = db
            .query_row(
                "SELECT push_token FROM devices WHERE id=?1",
                [&f.core.device().device_id],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(
            serde_json::from_slice::<Value>(&push).unwrap()["token"],
            "ci-push-token"
        );
    });
    let session = f.core.login_session().unwrap().unwrap();
    let device_token = relay.authenticate().await.unwrap();
    assert_eq!(device_token.len(), 43);
    assert!(relay.account_restore().await.unwrap().signed_in);
    assert!(!serde_json::to_string(&view)
        .unwrap()
        .contains(&session.session_token));
    let second = MobileCore::open(
        f._directory.path(),
        MobileKeys {
            identity: f.dk.clone(),
            quick: f.q.clone(),
            strong: f.s.clone(),
        },
        "ignored",
        Os::Ios,
    )
    .unwrap();
    second.require_account_login();
    assert_eq!(second.account_view().unwrap(), view);
    assert!(second.snapshot().is_ok());
    for entry in std::fs::read_dir(f._directory.path()).unwrap() {
        let bytes = std::fs::read(entry.unwrap().path()).unwrap();
        for secret in [&session.session_token, &jwt, "owner@example.test"] {
            assert!(!bytes
                .windows(secret.len())
                .any(|window| window == secret.as_bytes()));
        }
    }
    let session_hash = remote::canonical::sha256_hex(session.session_token.as_bytes());
    handle.inspect(|db| {
        assert_eq!(
            db.query_row(
                "SELECT COUNT(*) FROM account_sessions WHERE token_hash=?1",
                [&session_hash],
                |r| r.get::<_, i64>(0)
            )
            .unwrap(),
            1
        );
    });
    relay.account_logout().await.unwrap();
    assert!(!f.core.account_view().unwrap().signed_in);
    assert_eq!(second.snapshot(), Err(Error("login_required")));
    let response = http
        .get(base.join("v1/approvals?state=waiting").unwrap())
        .header("authorization", format!("Device {device_token}"))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 401);
    assert_eq!(
        relay
            .account_finish(&attempt.attempt_id, &jwt, "", "")
            .await,
        Err(Error("login_attempt_expired"))
    );
    handle.shutdown().await;
}

#[tokio::test]
async fn apple_nonce_state_expiry_and_provider_subject_prevent_account_substitution() {
    let f = Fixture::new();
    let key = issuer();
    let (base, handle) = server(&key);
    configure(&f, &base);
    let relay = Relay::new(f.core.clone()).unwrap();
    let attempt = relay.account_begin("apple").await.unwrap();
    let wrong = token(&key, "apple", "ci-owner", "different-nonce", now());
    assert_eq!(
        relay
            .account_finish(&attempt.attempt_id, &wrong, &attempt.state, "")
            .await,
        Err(Error("login_required"))
    );
    let jwt = token(&key, "apple", "ci-owner", &attempt.nonce_hash, now());
    assert_eq!(
        relay
            .account_finish(&attempt.attempt_id, &jwt, "other-state", "")
            .await,
        Err(Error("invalid_login_attempt"))
    );
    let expired = token(&key, "apple", "ci-owner", &attempt.nonce_hash, now() - 600);
    assert_eq!(
        relay
            .account_finish(&attempt.attempt_id, &expired, &attempt.state, "")
            .await,
        Err(Error("login_required"))
    );
    assert!(
        relay
            .account_finish(&attempt.attempt_id, &jwt, &attempt.state, "")
            .await
            .unwrap()
            .signed_in
    );
    relay.account_logout().await.unwrap();
    // Equal email is deliberately not sufficient to link identities.
    let attempt = relay.account_begin("google").await.unwrap();
    let different = token(&key, "google", "another-subject", "", now());
    assert_eq!(
        relay
            .account_finish(&attempt.attempt_id, &different, "", "")
            .await,
        Err(Error("login_account_conflict"))
    );
    assert!(!f.core.account_view().unwrap().signed_in);
    assert_eq!(
        handle.inspect(|db| db
            .query_row("SELECT COUNT(*) FROM login_users", [], |r| r
                .get::<_, i64>(0))
            .unwrap()),
        1
    );
    handle.shutdown().await;
}

#[tokio::test]
async fn verified_sessions_restore_offline_and_server_revocation_clears_native_access() {
    let f = Fixture::new();
    let key = issuer();
    let (base, handle) = server(&key);
    configure(&f, &base);
    let relay = Relay::new(f.core.clone()).unwrap();
    let attempt = relay.account_begin("google").await.unwrap();
    let jwt = token(&key, "google", "ci-owner", "", now());
    relay
        .account_finish(&attempt.attempt_id, &jwt, "", "")
        .await
        .unwrap();
    handle.advance_time(std::time::Duration::from_secs(31 * 86400));
    assert!(!relay.account_restore().await.unwrap().signed_in);
    assert_eq!(f.core.snapshot(), Err(Error("login_required")));
    handle.shutdown().await;
    // An offline relay cannot erase a session already verified by it.
    let session = crate::account::Session {
        session_token: "a".repeat(43),
        expires_at: now() + 600,
        user: crate::account::User {
            id: "verified-user".into(),
            provider: "google".into(),
            email: "owner@example.test".into(),
            display_name: "Owner".into(),
        },
        relay_url: base.to_string(),
    };
    f.core
        .store
        .transaction(|db| f.core.store.put(db, "meta", "account_session", &session, 0))
        .unwrap();
    assert!(relay.account_restore().await.unwrap().signed_in);
    f.core
        .store
        .transaction(|db| {
            let mut expired = session.clone();
            expired.expires_at = now() - 1;
            f.core.store.put(db, "meta", "account_session", &expired, 0)
        })
        .unwrap();
    assert!(!relay.account_restore().await.unwrap().signed_in);
}

#[tokio::test]
async fn a_revoked_user_session_cannot_fall_back_to_cached_native_notifications() {
    let f = Fixture::new();
    let key = issuer();
    let (base, handle) = server(&key);
    configure(&f, &base);
    let relay = Relay::new(f.core.clone()).unwrap();
    let attempt = relay.account_begin("google").await.unwrap();
    relay
        .account_finish(
            &attempt.attempt_id,
            &token(&key, "google", "ci-owner", "", now()),
            "",
            "",
        )
        .await
        .unwrap();
    // Keep a cached DK token, exactly as a native notification action would.
    relay.authenticate().await.unwrap();
    let session = f.core.login_session().unwrap().unwrap();
    let response = reqwest::Client::new()
        .post(base.join("v1/account/logout").unwrap())
        .bearer_auth(&session.session_token)
        .json(&json!({}))
        .send()
        .await
        .unwrap();
    assert!(response.status().is_success());
    assert_eq!(relay.sync_background().await, Err(Error("login_required")));
    assert!(!f.core.account_view().unwrap().signed_in);
    handle.shutdown().await;
}

struct CancelDuringProof {
    key: SoftwareDeviceKey,
    core: std::sync::Mutex<Option<std::sync::Weak<MobileCore>>>,
}
impl DeviceKeyProvider for CancelDuringProof {
    fn public_jwk(&self) -> remote::Result<PublicJwk> {
        self.key.public_jwk()
    }
    fn sign(&self, alg: SignatureAlgorithm, payload: &[u8]) -> remote::Result<Vec<u8>> {
        if let Some(core) = self.core.lock().unwrap().take().and_then(|c| c.upgrade()) {
            core.clear_login().unwrap();
        }
        DeviceKeyProvider::sign(&self.key, alg, payload)
    }
    fn ecdh(&self, peer: &[u8]) -> remote::Result<zeroize::Zeroizing<[u8; 32]>> {
        DeviceKeyProvider::ecdh(&self.key, peer)
    }
    fn key_kind(&self) -> KeyKind {
        KeyKind::Software
    }
    fn presence_kind(&self) -> PresenceKind {
        PresenceKind::None
    }
}

#[tokio::test]
async fn logout_during_login_proof_revokes_the_unused_server_session() {
    let directory = tempfile::tempdir().unwrap();
    let dk = Arc::new(CancelDuringProof {
        key: SoftwareDeviceKey::generate_p256(),
        core: Default::default(),
    });
    let core = Arc::new(
        MobileCore::open(
            directory.path(),
            MobileKeys {
                identity: dk.clone(),
                quick: Arc::new(SoftwareDeviceKey::generate_p256()),
                strong: Arc::new(SoftwareDeviceKey::generate_p256()),
            },
            "CI phone",
            Os::Ios,
        )
        .unwrap(),
    );
    let key = issuer();
    let (base, handle) = server(&key);
    core.set_relay(base.as_str()).unwrap();
    core.require_account_login();
    let relay = Relay::new(core.clone()).unwrap();
    let attempt = relay.account_begin("google").await.unwrap();
    *dk.core.lock().unwrap() = Some(Arc::downgrade(&core));
    assert_eq!(
        relay
            .account_finish(
                &attempt.attempt_id,
                &token(&key, "google", "ci-owner", "", now()),
                "",
                ""
            )
            .await,
        Err(Error("login_attempt_expired"))
    );
    assert!(!core.account_view().unwrap().signed_in);
    assert_eq!(
        handle.inspect(|db| db
            .query_row("SELECT COUNT(*) FROM account_sessions", [], |r| r
                .get::<_, i64>(0))
            .unwrap()),
        0
    );
    handle.shutdown().await;
}
