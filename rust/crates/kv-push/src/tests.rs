use super::*;
fn request(mode: Mode) -> PushRequest {
    PushRequest {
        device_push_token: PushToken::Apns {
            token: "a".repeat(64),
        },
        approval_id: "01ARZ3NDEKTSV4RRFFQ69G5FAV".into(),
        to: "dev_test_phone".into(),
        delivery: Delivery { mode },
    }
}
#[test]
fn apns_is_mutable_metadata_only_for_both_delivery_modes() {
    for mode in [Mode::Silent, Mode::Banner] {
        let r = request(mode);
        r.validate().unwrap();
        let body = r.apns_payload();
        assert_eq!(body["aps"]["mutable-content"], 1);
        assert_eq!(body["aps"]["interruption-level"], "passive");
        assert!(body["aps"].get("sound").is_none());
        assert!(body.get("envelope").is_none());
        assert!(body.get("credential").is_none());
        assert_eq!(body["approval_id"], r.approval_id);
        assert_eq!(
            body["delivery"]["mode"],
            if mode == Mode::Silent {
                "silent"
            } else {
                "banner"
            }
        );
    }
}
#[test]
fn fcm_has_no_notification_block_or_approval_content() {
    let r = request(Mode::Silent);
    let body = r.fcm_payload("test-token");
    assert!(body["message"].get("notification").is_none());
    assert_eq!(body["message"]["data"].as_object().unwrap().len(), 3);
    assert_eq!(body["message"]["data"]["delivery.mode"], "silent");
    assert_eq!(body["message"]["data"]["to"], r.to);
    assert_eq!(body["message"]["android"]["collapse_key"], r.approval_id);
}
#[test]
fn unknown_content_invalid_tokens_and_header_injection_are_rejected() {
    let mut value = serde_json::to_value(request(Mode::Banner)).unwrap();
    value["envelope"] = json!({"ct":"secret"});
    assert!(serde_json::from_value::<PushRequest>(value).is_err());
    let mut r = request(Mode::Banner);
    r.approval_id = "../../bad".into();
    assert_eq!(r.validate(), Err(Error::Invalid));
    r = request(Mode::Banner);
    r.device_push_token = PushToken::Apns {
        token: "\n".repeat(64),
    };
    assert!(r.validate().is_err());
    r.device_push_token = PushToken::Fcm {
        token: "a".repeat(4097),
    };
    assert!(r.validate().is_err());
    r.device_push_token = PushToken::Fcm {
        token: "valid_FCM-token:1234".into(),
    };
    assert!(r.validate().is_ok());
    assert!(router(Dispatcher::new(None, None).unwrap(), "short".into()).is_err());
}
#[test]
fn status_maps_throttling_without_returning_provider_bodies() {
    assert_eq!(
        check_status(reqwest::StatusCode::TOO_MANY_REQUESTS),
        Err(Error::Throttled { retry_after_s: 60 })
    );
    assert_eq!(
        check_status(reqwest::StatusCode::SERVICE_UNAVAILABLE),
        Err(Error::Provider)
    );
    assert!(check_status(reqwest::StatusCode::OK).is_ok());
}
#[tokio::test]
async fn service_authentication_and_json_contract_are_enforced_over_http() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let token = "test-relay-bearer".repeat(3);
    let app = router(Dispatcher::new(None, None).unwrap(), token.clone()).unwrap();
    let task = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    let http = reqwest::Client::new();
    let url = format!("http://{address}/v1/push");
    assert_eq!(
        http.post(&url)
            .json(&request(Mode::Silent))
            .send()
            .await
            .unwrap()
            .status(),
        401
    );
    assert_eq!(
        http.post(&url)
            .bearer_auth(&token)
            .json(&request(Mode::Silent))
            .send()
            .await
            .unwrap()
            .status(),
        502
    );
    let mut value = serde_json::to_value(request(Mode::Silent)).unwrap();
    value["approval_contents"] = "forbidden".into();
    assert_eq!(
        http.post(&url)
            .bearer_auth(&token)
            .json(&value)
            .send()
            .await
            .unwrap()
            .status(),
        422
    );
    let mut r = request(Mode::Silent);
    r.approval_id = "bad".into();
    assert_eq!(
        http.post(&url)
            .bearer_auth(&token)
            .json(&r)
            .send()
            .await
            .unwrap()
            .status(),
        400
    );
    task.abort();
}

#[derive(Default)]
struct ProviderState {
    requests: std::sync::Mutex<Vec<(String, HeaderMap, Vec<u8>)>>,
    status: std::sync::atomic::AtomicU16,
    oversized: std::sync::atomic::AtomicBool,
    body: std::sync::Mutex<Option<Value>>,
}
async fn fake_provider(
    State(state): State<Arc<ProviderState>>,
    uri: axum::http::Uri,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> axum::response::Response {
    use axum::response::IntoResponse;
    use std::sync::atomic::Ordering;
    state
        .requests
        .lock()
        .unwrap()
        .push((uri.path().into(), headers, body.to_vec()));
    if uri.path() == "/oauth" {
        if state.oversized.load(Ordering::SeqCst) {
            return (StatusCode::OK, "x".repeat(16385)).into_response();
        }
        return Json(json!({"access_token":"provider-access-token", "expires_in":3600}))
            .into_response();
    }
    let status = StatusCode::from_u16(state.status.load(Ordering::SeqCst)).unwrap();
    if let Some(body) = state.body.lock().unwrap().clone() {
        return (status, Json(body)).into_response();
    }
    (status, "provider body must not escape").into_response()
}

#[tokio::test]
async fn apns_410_and_fcm_unregistered_callback_without_deleting_on_permission_errors() {
    let (base, state, task) = start_provider().await;
    let mut apns = Dispatcher::new(
        Some(ApnsConfig {
            team: "PWCRJPY7YC".into(),
            key_id: "test".into(),
            topic: "dev.keyvalet.mobile".into(),
            sandbox: true,
            key: SigningKey::from_slice(&[7; 32]).unwrap(),
        }),
        None,
    )
    .unwrap();
    apns.apns_url = format!("{base}/device/");
    state.status.store(410, std::sync::atomic::Ordering::SeqCst);
    *state.body.lock().unwrap() = Some(json!({"reason":"Unregistered"}));
    assert_eq!(
        apns.send(&request(Mode::Silent)).await,
        Err(Error::InvalidToken)
    );
    state.status.store(403, std::sync::atomic::Ordering::SeqCst);
    *state.body.lock().unwrap() = Some(json!({"reason":"InvalidProviderToken"}));
    assert_eq!(
        apns.send(&request(Mode::Banner)).await,
        Err(Error::Provider)
    );
    let fixture: Value =
        serde_json::from_str(include_str!("../../kv-core/testdata/remote/test_keys.json")).unwrap();
    let key = RsaPrivateKey::from_pkcs8_der(
        &URL_SAFE_NO_PAD
            .decode(fixture["rsa_pkcs8_der"].as_str().unwrap())
            .unwrap(),
    )
    .unwrap();
    let mut fcm = Dispatcher::new(
        None,
        Some(FcmConfig {
            project: "test".into(),
            email: "test@example.test".into(),
            key,
        }),
    )
    .unwrap();
    fcm.oauth_url = format!("{base}/oauth");
    fcm.fcm_url = format!("{base}/messages");
    let mut r = request(Mode::Banner);
    r.device_push_token = PushToken::Fcm {
        token: "test-registration-token".into(),
    };
    state.status.store(404, std::sync::atomic::Ordering::SeqCst);
    *state.body.lock().unwrap() = Some(
        json!({"error":{"details":[{"@type":"type.googleapis.com/google.firebase.fcm.v1.FcmError","errorCode":"UNREGISTERED"}]}}),
    );
    let bearer = "r2c-test-bearer".repeat(3);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}/v1/push", listener.local_addr().unwrap());
    let app = router(fcm, bearer.clone()).unwrap();
    let service = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    let response = reqwest::Client::new()
        .post(&url)
        .bearer_auth(&bearer)
        .json(&r)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 410);
    assert!(response.text().await.unwrap().is_empty());
    state.status.store(403, std::sync::atomic::Ordering::SeqCst);
    *state.body.lock().unwrap() = Some(
        json!({"error":{"details":[{"@type":"type.googleapis.com/google.firebase.fcm.v1.FcmError","errorCode":"SENDER_ID_MISMATCH"}]}}),
    );
    assert_eq!(
        reqwest::Client::new()
            .post(&url)
            .bearer_auth(&bearer)
            .json(&r)
            .send()
            .await
            .unwrap()
            .status(),
        502
    );
    task.abort();
    service.abort();
}
async fn start_provider() -> (String, Arc<ProviderState>, tokio::task::JoinHandle<()>) {
    let state = Arc::new(ProviderState::default());
    state.status.store(200, std::sync::atomic::Ordering::SeqCst);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let app = Router::new()
        .route("/oauth", post(fake_provider))
        .route("/{*path}", post(fake_provider))
        .with_state(state.clone());
    let task = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (base, state, task)
}
fn jwt_parts(jwt: &str) -> (String, Value, Value, Vec<u8>) {
    let parts: Vec<_> = jwt.split('.').collect();
    assert_eq!(parts.len(), 3);
    (
        format!("{}.{}", parts[0], parts[1]),
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[0]).unwrap()).unwrap(),
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[1]).unwrap()).unwrap(),
        URL_SAFE_NO_PAD.decode(parts[2]).unwrap(),
    )
}
#[tokio::test]
async fn apns_transport_signs_es256_sets_headers_and_preserves_provider_errors() {
    use p256::ecdsa::signature::Verifier;
    let key = SigningKey::from_slice(&[7; 32]).unwrap();
    let public = *key.verifying_key();
    let (base, state, task) = start_provider().await;
    let mut dispatcher = Dispatcher::new(
        Some(ApnsConfig {
            team: "PWCRJPY7YC".into(),
            key_id: "TEST_KEY".into(),
            topic: "dev.keyvalet.mobile".into(),
            sandbox: true,
            key,
        }),
        None,
    )
    .unwrap();
    assert!(dispatcher.apns_url.contains("sandbox"));
    dispatcher.apns_url = format!("{base}/device/");
    let r = request(Mode::Silent);
    dispatcher.send(&r).await.unwrap();
    {
        let records = state.requests.lock().unwrap();
        let (path, headers, body) = &records[0];
        assert_eq!(path, &format!("/device/{}", "a".repeat(64)));
        assert_eq!(headers["apns-topic"], "dev.keyvalet.mobile");
        assert_eq!(headers["apns-push-type"], "alert");
        assert_eq!(headers["apns-collapse-id"], r.approval_id);
        let (input, header, claims, signature) = jwt_parts(
            headers["authorization"]
                .to_str()
                .unwrap()
                .strip_prefix("Bearer ")
                .unwrap(),
        );
        assert_eq!(header["alg"], "ES256");
        assert_eq!(header["kid"], "TEST_KEY");
        assert_eq!(claims["iss"], "PWCRJPY7YC");
        assert!(claims["iat"].as_u64().unwrap().abs_diff(now()) <= 2);
        public
            .verify(
                input.as_bytes(),
                &Signature::from_slice(&signature).unwrap(),
            )
            .unwrap();
        assert_eq!(
            serde_json::from_slice::<Value>(body).unwrap(),
            r.apns_payload()
        );
    }
    state.status.store(429, std::sync::atomic::Ordering::SeqCst);
    assert_eq!(
        dispatcher.send(&r).await,
        Err(Error::Throttled { retry_after_s: 60 })
    );
    state.status.store(503, std::sync::atomic::Ordering::SeqCst);
    assert_eq!(dispatcher.send(&r).await, Err(Error::Provider));
    task.abort();
}
#[tokio::test]
async fn fcm_transport_verifies_rs256_oauth_cache_and_bounds_token_responses() {
    use p256::ecdsa::signature::Verifier;
    let fixture: Value =
        serde_json::from_str(include_str!("../../kv-core/testdata/remote/test_keys.json")).unwrap();
    let key = RsaPrivateKey::from_pkcs8_der(
        &URL_SAFE_NO_PAD
            .decode(fixture["rsa_pkcs8_der"].as_str().unwrap())
            .unwrap(),
    )
    .unwrap();
    let public = rsa::pkcs1v15::VerifyingKey::<sha2::Sha256>::new(rsa::RsaPublicKey::from(&key));
    let (base, state, task) = start_provider().await;
    let mut dispatcher = Dispatcher::new(
        None,
        Some(FcmConfig {
            project: "test-project".into(),
            email: "test@example.com".into(),
            key,
        }),
    )
    .unwrap();
    dispatcher.oauth_url = format!("{base}/oauth");
    dispatcher.fcm_url = format!("{base}/messages");
    let mut r = request(Mode::Banner);
    r.device_push_token = PushToken::Fcm {
        token: "valid-test-fcm-token".into(),
    };
    dispatcher.send(&r).await.unwrap();
    dispatcher.send(&r).await.unwrap();
    {
        let records = state.requests.lock().unwrap();
        assert_eq!(records.iter().filter(|r| r.0 == "/oauth").count(), 1);
        let form = String::from_utf8(records[0].2.clone()).unwrap();
        // Decode the application/x-www-form-urlencoded assertion without adding a URL crate.
        let assertion = form
            .split('&')
            .find_map(|p| p.strip_prefix("assertion="))
            .unwrap();
        let (input, header, claims, signature) = jwt_parts(assertion);
        assert_eq!(header["alg"], "RS256");
        assert_eq!(claims["aud"], "https://oauth2.googleapis.com/token");
        assert_eq!(
            claims["scope"],
            "https://www.googleapis.com/auth/firebase.messaging"
        );
        public
            .verify(
                input.as_bytes(),
                &rsa::pkcs1v15::Signature::try_from(signature.as_slice()).unwrap(),
            )
            .unwrap();
        for (_, headers, body) in records.iter().skip(1) {
            assert_eq!(headers["authorization"], "Bearer provider-access-token");
            assert_eq!(
                serde_json::from_slice::<Value>(body).unwrap(),
                r.fcm_payload("valid-test-fcm-token")
            );
        }
    }
    *dispatcher.access.lock().await = None;
    state
        .oversized
        .store(true, std::sync::atomic::Ordering::SeqCst);
    assert_eq!(dispatcher.send(&r).await, Err(Error::Provider));
    assert!(dispatcher.access.lock().await.is_none());
    task.abort();
}
