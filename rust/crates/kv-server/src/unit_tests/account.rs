use super::*;
use kv_core::remote::keys::encode_b64;
use kv_core::remote::{DeviceKeyProvider, SoftwareDeviceKey};

fn issuer() -> SoftwareDeviceKey {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../kv-core/testdata/remote/test_keys.json");
    let keys: Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    SoftwareDeviceKey::from_rsa_pkcs8_der(
        &decode_b64(keys["rsa_pkcs8_der"].as_str().unwrap()).unwrap(),
    )
    .unwrap()
}

fn token(key: &SoftwareDeviceKey, header: &Value, claims: &Value) -> String {
    let payload = format!(
        "{}.{}",
        encode_b64(&serde_json::to_vec(header).unwrap()),
        encode_b64(&serde_json::to_vec(claims).unwrap())
    );
    let signature = key
        .sign(SignatureAlgorithm::RS256, payload.as_bytes())
        .unwrap();
    format!("{payload}.{}", encode_b64(&signature))
}

#[test]
fn identity_tokens_require_verified_issuer_audience_time_and_nonce() {
    let signer = issuer();
    let key = signer.public_jwk().unwrap();
    let header = json!({"alg":"RS256","kid":"test-only"});
    let claims = json!({"iss":"https://appleid.apple.com","aud":"test-app",
        "iat":1000,"exp":1600,"sub":"test-subject","email":"Owner@Example.test",
        "email_verified":"true","nonce":"test-nonce","name":" Test\nOwner "});
    let validate = |header: &Value, claims: &Value| {
        verify_token(
            &token(&signer, header, claims),
            &key,
            "apple",
            "test-app",
            &["test-app"],
            "test-nonce",
            1100,
        )
    };
    let identity = validate(&header, &claims).unwrap();
    assert_eq!(identity.email, "owner@example.test");
    assert_eq!(identity.name, "TestOwner");
    for (field, value) in [
        ("iss", json!("https://example.test")),
        ("aud", json!("other-app")),
        ("iat", json!(1200)),
        ("exp", json!(1100)),
        ("nbf", json!(1200)),
        ("sub", json!("")),
        ("azp", json!("other-app")),
        ("nonce", json!("other-nonce")),
        ("email_verified", json!(false)),
        ("email", json!("bad address@example.test")),
    ] {
        let mut altered = claims.clone();
        altered[field] = value;
        assert!(validate(&header, &altered).is_err(), "accepted {field}");
    }
    for (field, value) in [
        ("alg", json!("none")),
        ("jku", json!("https://example.test")),
        ("jwk", json!({})),
        ("crit", json!([])),
    ] {
        let mut altered = header.clone();
        altered[field] = value;
        assert!(validate(&altered, &claims).is_err(), "accepted {field}");
    }
    let mut google = claims;
    google["iss"] = json!("https://accounts.google.com");
    google["email_verified"] = json!(true);
    assert!(verify_token(
        &token(&signer, &header, &google),
        &key,
        "google",
        "test-app",
        &["test-app"],
        "unused",
        1100
    )
    .is_ok());
    assert!(verify_token("invalid", &key, "google", "test-app", &[], "unused", 1100).is_err());
}

fn configured_state(signer: &SoftwareDeviceKey) -> Arc<RelayState> {
    let mut key = signer.public_jwk().unwrap();
    key.extra.insert("kid".into(), json!("test-only"));
    let state = RelayState::new_with_accounts(
        Connection::open_in_memory().unwrap(),
        true,
        AccountConfig {
            required: true,
            google_web_client_id: "test-web".into(),
            google_ios_client_id: "test-ios".into(),
            google_android_client_id: "test-android".into(),
            apple_app_id: "test-app".into(),
            apple_services_id: "test-service".into(),
        },
    )
    .unwrap();
    state.accounts.seed_test_keys(
        vec![
            ("google".into(), vec![key.clone()]),
            ("apple".into(), vec![key]),
        ],
        state.now(),
    );
    state
}
async fn login_attempt(state: &Arc<RelayState>, device: &DeviceRecord, provider: &str) -> Value {
    begin(
        State(state.clone()),
        ConnectInfo("127.0.0.1:1".parse().unwrap()),
        HeaderMap::new(),
        Wire(StartRequest {
            provider: provider.into(),
            device: device.clone(),
        }),
    )
    .await
    .unwrap()
    .0
}
fn proof_request(
    start: &Value,
    device: &DeviceRecord,
    dk: &SoftwareDeviceKey,
    jwt: String,
    provider: &str,
) -> FinishRequest {
    let hash = sha256_hex(jwt.as_bytes());
    let proof = jcs(&LoginProof {
        purpose: "keyvalet-account-login-v1",
        attempt_id: start["attempt_id"].as_str().unwrap(),
        provider,
        device_id: &device.device_id,
        identity_token_hash: &hash,
        state: start["state"].as_str().unwrap(),
    })
    .unwrap();
    FinishRequest {
        attempt_id: start["attempt_id"].as_str().unwrap().into(),
        identity_token: jwt,
        state: start["state"].as_str().unwrap().into(),
        signature: encode_b64(&dk.sign(SignatureAlgorithm::ES256, &proof).unwrap()),
        display_name: String::new(),
    }
}

#[test]
fn google_native_presenters_are_allowed_only_when_registered_and_signatures_are_mandatory() {
    let signer = issuer();
    let key = signer.public_jwk().unwrap();
    let header = json!({"alg":"RS256","kid":"test-only"});
    let mut claims = json!({"iss":"accounts.google.com","aud":"test-web","iat":1000,"exp":1600,
        "sub":"owner","email":"owner@example.test","email_verified":true,"azp":"test-ios"});
    let verify = |claims: &Value| {
        verify_token(
            &token(&signer, &header, claims),
            &key,
            "google",
            "test-web",
            &["test-web", "test-ios", "test-android"],
            "",
            1100,
        )
    };
    assert!(verify(&claims).is_ok());
    claims["azp"] = json!("test-android");
    assert!(verify(&claims).is_ok());
    claims["azp"] = json!("other-app");
    assert!(verify(&claims).is_err());
    claims["azp"] = json!("test-web");
    claims["email_verified"] = json!("true");
    assert!(verify(&claims).is_err());
    let mut tampered = token(&signer, &header, &claims);
    tampered.push('A');
    assert!(verify_token(
        &tampered,
        &key,
        "google",
        "test-web",
        &["test-web"],
        "",
        1100
    )
    .is_err());
    for invalid in ["a.b.c", "...", "e30.e30.", ""] {
        assert!(
            verify_token(invalid, &key, "google", "test-web", &["test-web"], "", 1100).is_err()
        );
    }
}

#[tokio::test]
async fn identities_use_provider_subject_and_device_proof_instead_of_matching_email() {
    let signer = issuer();
    let state = configured_state(&signer);
    let mut users = Vec::new();
    for (index, subject) in ["alice", "bob", "alice"].iter().enumerate() {
        let dk = SoftwareDeviceKey::generate_p256();
        let mut device = crate::tests::fixture().principal.device;
        device.device_id = format!("test-phone-{index}");
        device.os = Os::Ios;
        device.dk_pub = dk.public_jwk().unwrap();
        let start = login_attempt(&state, &device, "google").await;
        let jwt = token(
            &signer,
            &json!({"alg":"RS256","kid":"test-only"}),
            &json!({"iss":"https://accounts.google.com","aud":"test-web","azp":"test-ios",
                "iat":state.now(),"exp":state.now()+600,"sub":subject,
                "email":"shared@example.test","email_verified":true}),
        );
        let wrong = SoftwareDeviceKey::generate_p256();
        assert!(finish(
            State(state.clone()),
            ConnectInfo("127.0.0.1:1".parse().unwrap()),
            HeaderMap::new(),
            Wire(proof_request(
                &start,
                &device,
                &wrong,
                jwt.clone(),
                "google"
            ))
        )
        .await
        .is_err());
        let result = finish(
            State(state.clone()),
            ConnectInfo("127.0.0.1:1".parse().unwrap()),
            HeaderMap::new(),
            Wire(proof_request(&start, &device, &dk, jwt, "google")),
        )
        .await
        .unwrap()
        .0;
        users.push(result["user"]["id"].clone());
        assert_eq!(result["user"]["email"], "shared@example.test");
    }
    assert_ne!(users[0], users[1]);
    assert_eq!(users[0], users[2]);
    state
        .with(|data, _| {
            assert_eq!(
                data.db
                    .query_row("SELECT COUNT(*) FROM login_users", [], |r| r
                        .get::<_, i64>(0))?,
                2
            );
            Ok(())
        })
        .unwrap();
}

#[tokio::test]
async fn apple_callback_validates_one_use_state_and_cannot_choose_a_redirect_package() {
    let signer = issuer();
    let state = configured_state(&signer);
    let mut device = crate::tests::fixture().principal.device;
    device.os = Os::Android;
    let start = login_attempt(&state, &device, "apple").await;
    let callback = |body: String| {
        axum::http::Request::builder()
            .method("POST")
            .header("content-type", "application/x-www-form-urlencoded")
            .body(axum::body::Body::from(body))
            .unwrap()
    };
    let mut body = url::form_urlencoded::Serializer::new(String::new());
    body.append_pair("state", start["state"].as_str().unwrap());
    body.append_pair("error_description", "#Intent;package=attacker.app;end");
    body.append_pair("redirect_uri", "https://attacker.example");
    let response = apple_callback(State(state.clone()), callback(body.finish()))
        .await
        .unwrap();
    assert_eq!(response.status(), 303);
    assert_eq!(response.headers()["cache-control"], "no-store");
    let redirect = response.headers()["location"].to_str().unwrap();
    assert!(redirect.ends_with("#Intent;package=dev.keyvalet.mobile;scheme=signinwithapple;end"));
    assert!(!redirect.contains("https://attacker"));
    assert!(redirect.contains("%23Intent"));
    assert!(
        apple_callback(State(state.clone()), callback("state=unknown".into()))
            .await
            .is_err()
    );
    let state_value = start["state"].as_str().unwrap();
    assert!(apple_callback(
        State(state.clone()),
        callback(format!("state={state_value}&state={state_value}"))
    )
    .await
    .is_err());
    state.advance(601);
    assert!(
        apple_callback(State(state), callback(format!("state={state_value}")))
            .await
            .is_err()
    );
}

#[tokio::test]
async fn account_sign_in_is_device_bound_single_use_and_logout_revokes_session() {
    let signer = issuer();
    let mut key = signer.public_jwk().unwrap();
    key.extra.insert("kid".into(), json!("test-only"));
    let state = RelayState::new_with_accounts(
        Connection::open_in_memory().unwrap(),
        true,
        AccountConfig {
            required: true,
            google_web_client_id: "test-app".into(),
            ..Default::default()
        },
    )
    .unwrap();
    state
        .accounts
        .seed_test_keys(vec![("google".into(), vec![key])], state.now());
    let dk = SoftwareDeviceKey::generate_p256();
    let mut device = crate::tests::fixture().principal.device;
    device.os = Os::Android;
    device.dk_pub = dk.public_jwk().unwrap();
    let peer: SocketAddr = "127.0.0.1:12345".parse().unwrap();
    let Json(start) = begin(
        State(state.clone()),
        ConnectInfo(peer),
        HeaderMap::new(),
        Wire(StartRequest {
            provider: "google".into(),
            device: device.clone(),
        }),
    )
    .await
    .unwrap();
    let now = state.now();
    let identity_token = token(
        &signer,
        &json!({"alg":"RS256","kid":"test-only"}),
        &json!({"iss":"https://accounts.google.com","aud":"test-app","iat":now,
            "exp":now+600,"sub":"test-subject","email":"owner@example.test",
            "email_verified":true}),
    );
    let attempt = start["attempt_id"].as_str().unwrap();
    let login_state = start["state"].as_str().unwrap();
    let hash = sha256_hex(identity_token.as_bytes());
    let payload = jcs(&LoginProof {
        purpose: "keyvalet-account-login-v1",
        attempt_id: attempt,
        provider: "google",
        device_id: &device.device_id,
        identity_token_hash: &hash,
        state: login_state,
    })
    .unwrap();
    let signature = encode_b64(&dk.sign(SignatureAlgorithm::ES256, &payload).unwrap());
    let request = || {
        Wire(FinishRequest {
            attempt_id: attempt.into(),
            identity_token: identity_token.clone(),
            state: login_state.into(),
            signature: signature.clone(),
            display_name: String::new(),
        })
    };
    let Json(signed_in) = finish(
        State(state.clone()),
        ConnectInfo(peer),
        HeaderMap::new(),
        request(),
    )
    .await
    .unwrap();
    assert!(finish(
        State(state.clone()),
        ConnectInfo(peer),
        HeaderMap::new(),
        request()
    )
    .await
    .is_err());
    let raw = signed_in["session_token"].as_str().unwrap();
    let mut device_headers = HeaderMap::new();
    device_headers.insert(USER_HEADER, raw.parse().unwrap());
    state
        .with(|data, now| {
            assert!(require_device_user(&data.db, &device, &HeaderMap::new(), now).is_err());
            assert!(require_device_user(&data.db, &device, &device_headers, now).is_ok());
            Ok(())
        })
        .unwrap();
    let mut user_headers = HeaderMap::new();
    user_headers.insert("authorization", format!("Bearer {raw}").parse().unwrap());
    assert!(session(State(state.clone()), user_headers.clone())
        .await
        .is_ok());
    assert!(logout(State(state.clone()), user_headers.clone())
        .await
        .is_ok());
    assert!(session(State(state.clone()), user_headers).await.is_err());
    state
        .with(|data, now| {
            assert!(require_device_user(&data.db, &device, &device_headers, now).is_err());
            Ok(())
        })
        .unwrap();
    assert!(state
        .log
        .lock()
        .unwrap()
        .iter()
        .all(|line| !line.contains(raw)));
}
