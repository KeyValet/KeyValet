use super::*;
use axum::http::HeaderMap;
use kv_core::remote::relay::ErrorCode;
use kv_core::remote::RemoteError;

fn headers(device: &Device) -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(
        "authorization",
        format!("Device {}", device.token).parse().unwrap(),
    );
    headers
}

#[test]
fn errors_are_static_and_map_every_remote_failure() {
    use crate::error::ApiError;
    for (cause, code) in [
        (RemoteError::PayloadTooLarge, ErrorCode::PayloadTooLarge),
        (RemoteError::Expired, ErrorCode::Expired),
        (RemoteError::Replay, ErrorCode::Conflict),
        (RemoteError::NotWaiting, ErrorCode::Conflict),
        (RemoteError::InvalidSignature, ErrorCode::BadEnvelope),
    ] {
        assert_eq!(ApiError::from(cause).body().error.code, code);
    }
    let error = serde_json::from_str::<Value>("PRIVATE-INVALID-JSON").unwrap_err();
    let error = ApiError::from(error);
    assert_eq!(error.code, ErrorCode::BadEnvelope);
    assert!(!format!("{error:?}").contains("PRIVATE-INVALID-JSON"));
    let error = Connection::open_in_memory()
        .unwrap()
        .execute("SELECT PRIVATE_SQL_CONTENT", [])
        .unwrap_err();
    let error = ApiError::from(error);
    assert_eq!(error.code, ErrorCode::Conflict);
    assert!(!format!("{error:?}").contains("PRIVATE_SQL_CONTENT"));
    assert_eq!(
        CleanupStats::default(),
        CleanupStats {
            messages: 0,
            approvals: 0,
            expired_approvals: 0,
            sessions: 0,
            pairings: 0,
        }
    );
}

#[test]
fn device_validation_rejects_bad_identity_keys_and_capabilities() {
    let device = Device::new("validation", true);
    let mut records = Vec::new();
    for id in ["", "dev bad", "dev/../../secret"] {
        let mut record = device.record.clone();
        record.device_id = id.into();
        records.push(record);
    }
    let mut record = device.record.clone();
    record.device_id = "A".repeat(129);
    records.push(record);
    let mut record = device.record.clone();
    record.label = "A".repeat(257);
    records.push(record);
    let mut record = device.record.clone();
    record.caps = vec![Capability::Execute; 33];
    records.push(record);
    let mut record = device.record.clone();
    record.dk_pub.kty = "invalid".into();
    records.push(record);
    let mut record = device.record.clone();
    record.ak_s.as_mut().unwrap().r#pub = device.record.dk_pub.clone();
    records.push(record);
    let mut record = device.record.clone();
    record.ak_q = record.ak_s.clone();
    records.push(record);
    for strong in [true, false] {
        let mut record = device.record.clone();
        if strong {
            record.ak_s = None;
        } else {
            record.ak_q = None;
        }
        records.push(record);
    }
    for private in ["d", "p", "q", "dp", "dq", "qi", "oth", "k"] {
        for which in 0..3 {
            let mut record = device.record.clone();
            let key = match which {
                0 => &mut record.dk_pub,
                1 => &mut record.ak_q.as_mut().unwrap().r#pub,
                _ => &mut record.ak_s.as_mut().unwrap().r#pub,
            };
            key.extra
                .insert(private.into(), json!("PRIVATE-KEY-MATERIAL"));
            records.push(record);
        }
    }
    for record in records {
        assert!(
            state::validate_device(&record).is_err(),
            "accepted {record:?}"
        );
    }
    assert!(state::validate_device(&device.record).is_ok());
    for id in [
        "",
        "A",
        "80000000000000000000000000",
        "0IIIIIIIIIIIIIIIIIIIIIIIII",
    ] {
        assert!(!state::valid_id(id));
    }
    assert!(state::valid_id(&state::ulid(-1)));
}

#[test]
fn metadata_logging_and_poisoned_storage_fail_closed() {
    let state = state::State::new(Connection::open_in_memory().unwrap(), true).unwrap();
    state.event("test_metadata", 12);
    assert_eq!(*state.log.lock().unwrap(), ["event=test_metadata count=12"]);
    state::State::new(Connection::open_in_memory().unwrap(), false)
        .unwrap()
        .event("test_metadata", 12);
    let operation = |_: &mut state::Data, _: i64| Ok(());
    state.with(operation).unwrap();
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _guard = state.data.lock().unwrap();
        panic!("simulate a failed storage worker");
    }));
    assert_eq!(state.with(operation).unwrap_err().code, ErrorCode::Conflict);
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _guard = state.log.lock().unwrap();
        panic!("simulate a failed log collector");
    }));
    state.event("after_poison", 1);
}

#[tokio::test]
async fn bounded_presence_removes_closed_and_slow_consumers() {
    let state = state::State::new(Connection::open_in_memory().unwrap(), true).unwrap();
    state
        .with(|data, _| {
            let (sender, receiver) = tokio::sync::mpsc::channel(1);
            data.presence.insert(
                "closed".into(),
                state::Presence {
                    connection: "first".into(),
                    sender,
                },
            );
            drop(receiver);
            assert!(!data.send("closed", json!({"t":"pong"})));
            assert!(!data.presence.contains_key("closed"));
            let (sender, mut receiver) = tokio::sync::mpsc::channel(1);
            data.presence.insert(
                "slow".into(),
                state::Presence {
                    connection: "second".into(),
                    sender,
                },
            );
            assert!(data.send("slow", json!({"t":"pong"})));
            assert!(!data.send("slow", json!({"t":"pong"})));
            assert!(!data.presence.contains_key("slow"));
            assert!(matches!(receiver.try_recv(), Ok(state::Outbound::Frame(_))));
            assert!(matches!(
                receiver.try_recv(),
                Err(tokio::sync::mpsc::error::TryRecvError::Disconnected)
            ));
            Ok(())
        })
        .unwrap();
}

#[test]
fn sliding_window_recovers_at_the_boundary_without_double_bursts() {
    let state = state::State::new(Connection::open_in_memory().unwrap(), true).unwrap();
    state
        .with(|data, _| {
            data.rate("key".into(), 100, 59, 60)?;
            data.rate("key".into(), 159, 1, 60)?;
            assert_eq!(
                data.rate("key".into(), 159, 1, 60).unwrap_err().code,
                ErrorCode::RateLimited
            );
            data.rate("key".into(), 160, 59, 60)?;
            assert_eq!(
                data.rate("key".into(), 160, 1, 60).unwrap_err().code,
                ErrorCode::RateLimited
            );
            data.rate("another".into(), 220, 60, 60)?;
            Ok(())
        })
        .unwrap();
}

#[tokio::test]
async fn registration_rejects_duplicates_and_preserves_public_push_metadata() {
    let (base, relay) = spawn_test_relay();
    let client = Client::new(base);
    let mut device = Device::new("register", false);
    let mut request = serde_json::to_value(&device.record).unwrap();
    request["attestation"] =
        json!({"kind":"future_public_attestation","doc":{"opaque_public_record":true}});
    request["push_token"] = json!({"provider":"test", "token":"public-push-token"});
    let response = client.post("/v1/devices", None, request.clone()).await;
    device.account = response["account_id"].as_str().unwrap().into();
    assert_error(
        &client
            .call(Method::POST, "/v1/devices", None, Some(request))
            .await,
        StatusCode::CONFLICT,
        "conflict",
    );
    relay.inspect(|db| {
        assert_eq!(
            db.query_row("SELECT COUNT(*) FROM accounts", [], |row| row
                .get::<_, i64>(0))
                .unwrap(),
            1
        );
        let push: Vec<u8> = db
            .query_row("SELECT push_token FROM devices", [], |row| row.get(0))
            .unwrap();
        assert_eq!(
            serde_json::from_slice::<Value>(&push).unwrap(),
            json!({"provider":"test", "token":"public-push-token"})
        );
        let attestation: Vec<u8> = db
            .query_row("SELECT attestation FROM devices", [], |row| row.get(0))
            .unwrap();
        assert_eq!(
            serde_json::from_slice::<Value>(&attestation).unwrap()["doc"],
            json!({"opaque_public_record":true})
        );
    });
    let mut invalid = device.record.clone();
    invalid.device_id = "bad/name".into();
    assert_error(
        &client
            .call(
                Method::POST,
                "/v1/devices",
                None,
                Some(serde_json::to_value(invalid).unwrap()),
            )
            .await,
        StatusCode::BAD_REQUEST,
        "bad_envelope",
    );
    relay.shutdown().await;
}

#[tokio::test]
async fn challenges_reject_unknown_devices_mismatches_and_invalid_encodings() {
    let (base, relay) = spawn_test_relay();
    let client = Client::new(base);
    for path in ["/v1/auth/challenge", "/v1/auth/verify"] {
        let request = json!({"device_id":"missing", "challenge":"invalid", "sig":"invalid"});
        assert_error(
            &client.call(Method::POST, path, None, Some(request)).await,
            StatusCode::UNAUTHORIZED,
            "unauthorized",
        );
    }
    let mut device = Device::new("challenge", false);
    client.register(&mut device).await;
    client
        .post(
            "/v1/auth/challenge",
            None,
            json!({"device_id":device.record.device_id}),
        )
        .await;
    assert_error(&client.call(Method::POST, "/v1/auth/verify", None, Some(json!({"device_id":device.record.device_id, "challenge":state::random_token(32), "sig":"AA"}))).await, StatusCode::UNAUTHORIZED, "unauthorized");
    for challenge in ["not+base64", "AA"] {
        relay
            .state
            .with(|data, current| {
                data.challenges.insert(
                    device.record.device_id.clone(),
                    state::Challenge {
                        hash: sha256_hex(challenge.as_bytes()),
                        exp: current + 60,
                    },
                );
                Ok(())
            })
            .unwrap();
        assert_error(&client.call(Method::POST, "/v1/auth/verify", None, Some(json!({"device_id":device.record.device_id, "challenge":challenge, "sig":"not+base64"}))).await, StatusCode::UNAUTHORIZED, "unauthorized");
    }
    let challenge = client
        .post(
            "/v1/auth/challenge",
            None,
            json!({"device_id":device.record.device_id}),
        )
        .await;
    assert_error(&client.call(Method::POST, "/v1/auth/verify", None, Some(json!({"device_id":device.record.device_id, "challenge":challenge["challenge"], "sig":"not+base64"}))).await, StatusCode::UNAUTHORIZED, "unauthorized");
    relay.shutdown().await;
}

#[tokio::test]
async fn api_rejects_wrong_content_type_method_and_upgrade_shapes() {
    let (base, relay) = spawn_test_relay();
    let client = Client::new(base);
    let mut device = Device::new("http", false);
    client.register(&mut device).await;
    let response = client
        .http
        .post(client.base.join("/v1/messages").unwrap())
        .header("authorization", format!("Device {}", device.token))
        .body("{}")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        response.json::<Value>().await.unwrap()["error"]["code"],
        "bad_envelope"
    );
    assert_error(
        &client.call(Method::PATCH, "/v1/health", None, None).await,
        StatusCode::BAD_REQUEST,
        "bad_envelope",
    );
    let response = client
        .http
        .get(client.base.join("/v1/presence").unwrap())
        .header("authorization", format!("Device {}", device.token))
        .header("sec-websocket-protocol", "other, kv-relay-v1")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    relay.shutdown().await;
}

async fn pending_pair(
    client: &Client,
    initiator: &Device,
    joiner: &mut Device,
) -> (String, String) {
    let token = state::random_token(16);
    let start = client.post("/v1/pair/start", Some(&initiator.token),
        json!({"token_hash":sha256_hex(&decode_b64(&token).unwrap()), "initiator":initiator.record, "exp":now()+600})).await;
    client
        .post(
            "/v1/pair/complete",
            None,
            json!({"token":token,"joiner":joiner.record}),
        )
        .await;
    joiner.account = initiator.account.clone();
    joiner.token = client.login(joiner).await;
    (start["pairing_id"].as_str().unwrap().into(), token)
}

#[tokio::test]
async fn pairing_checks_start_shape_expiry_token_reuse_and_pending_capacity() {
    let (base, relay) = spawn_test_relay();
    let boundary_time = relay.freeze_time();
    let client = Client::new(base);
    let mut initiator = Device::new("initiator", false);
    client.register(&mut initiator).await;
    let hash = sha256_hex(&decode_b64(&state::random_token(16)).unwrap());
    let valid = json!({"token_hash":hash,"initiator":initiator.record,"exp":boundary_time+600});
    for (field, value, status, code) in [
        (
            "token_hash",
            json!("a"),
            StatusCode::BAD_REQUEST,
            "bad_envelope",
        ),
        (
            "token_hash",
            json!("Z".repeat(64)),
            StatusCode::BAD_REQUEST,
            "bad_envelope",
        ),
        ("exp", json!(boundary_time - 1), StatusCode::GONE, "expired"),
        (
            "exp",
            json!(boundary_time + 601),
            StatusCode::BAD_REQUEST,
            "bad_envelope",
        ),
    ] {
        let mut request = valid.clone();
        request[field] = value;
        assert_error(
            &client
                .call(
                    Method::POST,
                    "/v1/pair/start",
                    Some(&initiator.token),
                    Some(request),
                )
                .await,
            status,
            code,
        );
    }
    let mut request = valid.clone();
    request["initiator"]["dk_pub"] =
        json!(SoftwareDeviceKey::generate_p256().public_jwk().unwrap());
    assert_error(
        &client
            .call(
                Method::POST,
                "/v1/pair/start",
                Some(&initiator.token),
                Some(request),
            )
            .await,
        StatusCode::BAD_REQUEST,
        "bad_envelope",
    );
    client
        .post("/v1/pair/start", Some(&initiator.token), valid.clone())
        .await;
    assert_error(
        &client
            .call(
                Method::POST,
                "/v1/pair/start",
                Some(&initiator.token),
                Some(valid),
            )
            .await,
        StatusCode::CONFLICT,
        "conflict",
    );
    // Advance just the rate window; outstanding offers remain live and count toward ten.
    relay.advance_time(Duration::from_secs(61));
    for index in 1..=10 {
        let request = json!({"token_hash":sha256_hex(&decode_b64(&state::random_token(16)).unwrap()),"initiator":initiator.record,"exp":boundary_time+61+600});
        let response = client
            .call(
                Method::POST,
                "/v1/pair/start",
                Some(&initiator.token),
                Some(request),
            )
            .await;
        if index == 10 {
            assert_error(&response, StatusCode::TOO_MANY_REQUESTS, "rate_limited");
        } else {
            assert_eq!(response.0, StatusCode::OK);
        }
    }
    relay.shutdown().await;
}

#[tokio::test]
async fn pairing_completion_rejects_bad_tokens_identity_and_registered_history() {
    let (base, relay) = spawn_test_relay();
    let client = Client::new(base);
    let mut initiator = Device::new("initiator", false);
    client.register(&mut initiator).await;
    let joiner = Device::new("joiner", true);
    for (token, status, code) in [
        ("AA".into(), StatusCode::BAD_REQUEST, "bad_envelope"),
        ("not+base64".into(), StatusCode::BAD_REQUEST, "bad_envelope"),
        (state::random_token(16), StatusCode::NOT_FOUND, "not_found"),
    ] {
        assert_error(
            &client
                .call(
                    Method::POST,
                    "/v1/pair/complete",
                    None,
                    Some(json!({"token":token, "joiner":joiner.record})),
                )
                .await,
            status,
            code,
        );
    }
    let token = state::random_token(16);
    let start = json!({"token_hash":sha256_hex(&decode_b64(&token).unwrap()),"initiator":initiator.record,"exp":now()+600});
    client
        .post("/v1/pair/start", Some(&initiator.token), start)
        .await;
    assert_error(
        &client
            .call(
                Method::POST,
                "/v1/pair/complete",
                None,
                Some(json!({"token":token,"joiner":initiator.record})),
            )
            .await,
        StatusCode::FORBIDDEN,
        "forbidden",
    );
    let mut registered = Device::new("registered", true);
    client.register(&mut registered).await;
    let request = json!({"token":token,"joiner":registered.record});
    assert_error(
        &client
            .call(
                Method::POST,
                "/v1/pair/complete",
                None,
                Some(request.clone()),
            )
            .await,
        StatusCode::UNAUTHORIZED,
        "unauthorized",
    );
    let mut changed = request.clone();
    changed["joiner"]["dk_pub"] = json!(SoftwareDeviceKey::generate_p256().public_jwk().unwrap());
    assert_error(
        &client
            .call(
                Method::POST,
                "/v1/pair/complete",
                Some(&registered.token),
                Some(changed),
            )
            .await,
        StatusCode::FORBIDDEN,
        "forbidden",
    );
    let message = registered.seal(
        &registered,
        &state::ulid(now()),
        EnvelopeType::Grant,
        now() + 300,
        &json!({}),
    );
    client
        .post(
            "/v1/messages",
            Some(&registered.token),
            json!({"envelopes":[message]}),
        )
        .await;
    assert_error(
        &client
            .call(
                Method::POST,
                "/v1/pair/complete",
                Some(&registered.token),
                Some(request),
            )
            .await,
        StatusCode::CONFLICT,
        "conflict",
    );
    relay.advance_time(Duration::from_secs(601));
    assert_error(
        &client
            .call(
                Method::POST,
                "/v1/pair/complete",
                None,
                Some(json!({"token":token,"joiner":joiner.record})),
            )
            .await,
        StatusCode::GONE,
        "expired",
    );
    relay.shutdown().await;
}

#[tokio::test]
async fn pairing_accepts_current_labels_without_changing_registered_authority() {
    let (base, relay) = spawn_test_relay();
    let client = Client::new(base);
    let mut initiator = Device::new("renamed-initiator", false);
    let mut joiner = Device::new("renamed-joiner", true);
    client.register(&mut initiator).await;
    client.register(&mut joiner).await;
    let token = state::random_token(16);
    let mut current_initiator = initiator.record.clone();
    current_initiator.label = "Current initiator label".into();
    let started = client.post("/v1/pair/start", Some(&initiator.token), json!({"token_hash":sha256_hex(&decode_b64(&token).unwrap()),"initiator":current_initiator,"exp":now()+600})).await;
    let mut current_joiner = joiner.record.clone();
    current_joiner.label = "Current joiner label".into();
    let completed = client
        .post(
            "/v1/pair/complete",
            Some(&joiner.token),
            json!({"token":token,"joiner":current_joiner}),
        )
        .await;
    assert_eq!(completed["pairing_id"], started["pairing_id"]);
    assert_eq!(completed["initiator"], json!(current_initiator));
    relay.inspect(|db| {
        let registered = crate::state::device(db, &joiner.record.device_id)
            .unwrap()
            .1;
        assert!(kv_core::remote::validation::same_device_authority(
            &registered,
            &current_joiner
        ));
    });
    relay.shutdown().await;
}

#[tokio::test]
async fn pairing_confirmation_enforces_partner_signature_and_a_single_sas_attempt() {
    let (base, relay) = spawn_test_relay();
    let client = Client::new(base);
    let (initiator, existing) = two_devices(&client).await;
    let mut outsider = Device::new("outsider", false);
    client.register(&mut outsider).await;
    let mut joiner = Device::new("pending", true);
    let (id, _) = pending_pair(&client, &initiator, &mut joiner).await;
    let finish = |sas: &str| json!({"pairing_id":id, "confirm":joiner.confirm(sas)});
    for (device, request, status, code) in [
        (
            &outsider,
            finish("123456"),
            StatusCode::FORBIDDEN,
            "forbidden",
        ),
        (
            &existing,
            finish("123456"),
            StatusCode::FORBIDDEN,
            "forbidden",
        ),
        (
            &joiner,
            json!({"pairing_id":id,"confirm":{"sas":"abc123","sig":""}}),
            StatusCode::BAD_REQUEST,
            "bad_envelope",
        ),
        (
            &joiner,
            json!({"pairing_id":id,"confirm":{"sas":"123456","sig":"AA"}}),
            StatusCode::FORBIDDEN,
            "forbidden",
        ),
        (
            &initiator,
            json!({"pairing_id":id,"confirm":{"sas":"123456","sig":"AA"}}),
            StatusCode::FORBIDDEN,
            "forbidden",
        ),
        (
            &initiator,
            json!({"pairing_id":"missing","confirm":initiator.confirm("123456")}),
            StatusCode::NOT_FOUND,
            "not_found",
        ),
    ] {
        assert_error(
            &client
                .call(
                    Method::POST,
                    "/v1/pair/finish",
                    Some(&device.token),
                    Some(request),
                )
                .await,
            status,
            code,
        );
    }
    client
        .post(
            "/v1/pair/finish",
            Some(&initiator.token),
            json!({"pairing_id":id,"confirm":initiator.confirm("123456")}),
        )
        .await;
    assert_eq!(
        client
            .call(
                Method::POST,
                "/v1/pair/finish",
                Some(&initiator.token),
                Some(json!({"pairing_id":id,"confirm":initiator.confirm("123456")}))
            )
            .await
            .0,
        StatusCode::OK
    );
    let mut socket = client.socket(&joiner).await;
    assert_error(
        &client
            .call(
                Method::POST,
                "/v1/pair/finish",
                Some(&joiner.token),
                Some(finish("654321")),
            )
            .await,
        StatusCode::CONFLICT,
        "conflict",
    );
    // The failed SAS cannot be retried, even with the initiator's correct number.
    assert_error(
        &client
            .call(
                Method::POST,
                "/v1/pair/finish",
                Some(&joiner.token),
                Some(finish("123456")),
            )
            .await,
        StatusCode::UNAUTHORIZED,
        "unauthorized",
    );
    assert_error(
        &client
            .call(
                Method::POST,
                "/v1/pair/finish",
                Some(&initiator.token),
                Some(json!({"pairing_id":id,"confirm":initiator.confirm("123456")})),
            )
            .await,
        StatusCode::GONE,
        "expired",
    );
    tokio::time::timeout(Duration::from_secs(2), async {
        while let Some(frame) = socket.next().await {
            if matches!(frame, Ok(Message::Close(_)) | Err(_)) {
                return;
            }
        }
    })
    .await
    .unwrap();
    relay.inspect(|db| {
        assert_eq!(
            db.query_row(
                "SELECT state FROM pairings WHERE pairing_id=?1",
                [&id],
                |r| r.get::<_, String>(0)
            )
            .unwrap(),
            "expired"
        );
        assert!(db
            .query_row(
                "SELECT token_hash IS NULL FROM pairings WHERE pairing_id=?1",
                [&id],
                |r| r.get::<_, bool>(0)
            )
            .unwrap());
    });
    relay.shutdown().await;
}

#[tokio::test]
async fn pending_joiners_exchange_only_pairing_envelopes_with_their_partner() {
    let (base, relay) = spawn_test_relay();
    let client = Client::new(base);
    let (initiator, other) = two_devices(&client).await;
    let mut joiner = Device::new("pending", true);
    let (id, _) = pending_pair(&client, &initiator, &mut joiner).await;
    for (from, to, kind, allowed) in [
        (&joiner, &initiator, EnvelopeType::PairConfirm, true),
        (&initiator, &joiner, EnvelopeType::PairOffer, true),
        (&other, &joiner, EnvelopeType::PairAccept, false),
        (&joiner, &other, EnvelopeType::PairConfirm, false),
        (&joiner, &initiator, EnvelopeType::Grant, false),
        (&initiator, &joiner, EnvelopeType::Grant, false),
    ] {
        let envelope = from.seal(to, &state::ulid(now()), kind, now() + 300, &json!({}));
        let response = client
            .call(
                Method::POST,
                "/v1/messages",
                Some(&from.token),
                Some(json!({"envelopes":[envelope]})),
            )
            .await;
        if allowed {
            assert_eq!(response.0, StatusCode::OK);
        } else {
            assert_error(&response, StatusCode::FORBIDDEN, "forbidden");
        }
    }
    let envelope = initiator.seal(
        &joiner,
        &state::ulid(now()),
        EnvelopeType::ApprovalRequest,
        now() + 300,
        &json!({}),
    );
    assert_error(
        &client
            .call(
                Method::POST,
                "/v1/approvals",
                Some(&initiator.token),
                Some(json!({"id":envelope.id,"exp":envelope.exp,"envelopes":[envelope]})),
            )
            .await,
        StatusCode::FORBIDDEN,
        "forbidden",
    );
    // Reconnection replays the accepted joiner's public record to the initiator.
    let mut socket = client.socket(&initiator).await;
    assert_eq!(receive(&mut socket).await["t"], "envelope");
    let pair = receive(&mut socket).await;
    assert_eq!(
        pair,
        json!({"t":"pair_accept","pairing_id":id,"joiner":joiner.record})
    );
    relay.advance_time(Duration::from_secs(601));
    relay.cleanup();
    assert_error(
        &client
            .call(
                Method::GET,
                "/v1/approvals?state=waiting",
                Some(&joiner.token),
                None,
            )
            .await,
        StatusCode::UNAUTHORIZED,
        "unauthorized",
    );
    relay.shutdown().await;
}

#[tokio::test]
async fn approval_escalations_require_the_original_requester_and_recipients() {
    let (base, relay) = spawn_test_relay();
    let client = Client::new(base);
    let (executor, approver) = two_devices(&client).await;
    let mut other = Device::new("other", true);
    client.pair(&executor, &mut other, false, None).await;
    let id = state::ulid(now());
    let exp = now() + 300;
    let original = executor.seal(
        &approver,
        &id,
        EnvelopeType::ApprovalRequest,
        exp,
        &json!({}),
    );
    let request = json!({"id":id,"exp":exp,"envelopes":[original]});
    client
        .post("/v1/approvals", Some(&executor.token), request.clone())
        .await;
    assert_eq!(
        client
            .post("/v1/approvals", Some(&executor.token), request)
            .await["accepted"],
        1
    );
    for (from, to, timestamp, status) in [
        (&approver, &executor, exp, StatusCode::FORBIDDEN),
        (&executor, &other, exp, StatusCode::FORBIDDEN),
        (&executor, &approver, exp - 1, StatusCode::FORBIDDEN),
        (&executor, &approver, exp, StatusCode::OK),
    ] {
        let envelope = from.seal(
            to,
            &id,
            EnvelopeType::ApprovalEscalate,
            timestamp,
            &json!({}),
        );
        let request = json!({"id":id,"exp":timestamp,"envelopes":[envelope]});
        let response = client
            .call(
                Method::POST,
                "/v1/approvals",
                Some(&from.token),
                Some(request),
            )
            .await;
        assert_eq!(response.0, status, "{}", response.1);
    }
    client
        .post(
            "/v1/messages/ack",
            Some(&approver.token),
            json!({"ids":[id]}),
        )
        .await;
    let waiting = client
        .call(
            Method::GET,
            "/v1/approvals?state=waiting",
            Some(&approver.token),
            None,
        )
        .await;
    assert_eq!(waiting.1["envelopes"].as_array().unwrap().len(), 2);
    let reply = other.seal(
        &executor,
        &id,
        EnvelopeType::ApprovalDecision,
        exp,
        &json!({}),
    );
    assert_error(
        &client
            .call(
                Method::POST,
                &format!("/v1/approvals/{id}/reply"),
                Some(&other.token),
                Some(json!({"envelope":reply})),
            )
            .await,
        StatusCode::FORBIDDEN,
        "forbidden",
    );
    relay.shutdown().await;
}

#[tokio::test]
async fn malformed_approval_message_and_ack_batches_are_rejected_atomically() {
    let (base, relay) = spawn_test_relay();
    let client = Client::new(base);
    let (executor, approver) = two_devices(&client).await;
    let envelope = executor.seal(
        &approver,
        &state::ulid(now()),
        EnvelopeType::ApprovalRequest,
        now() + 300,
        &json!({}),
    );
    let valid = json!({"id":envelope.id,"exp":envelope.exp,"envelopes":[envelope]});
    for request in [
        json!({"id":"invalid","exp":now()+300,"envelopes":[]}),
        json!({"id":envelope.id,"exp":now()-1,"envelopes":[]}),
        json!({"id":envelope.id,"exp":envelope.exp,"envelopes":vec![&envelope;501]}),
    ] {
        let response = client
            .call(
                Method::POST,
                "/v1/approvals",
                Some(&executor.token),
                Some(request.clone()),
            )
            .await;
        if request["exp"].as_i64().unwrap() < now() {
            assert_error(&response, StatusCode::GONE, "expired");
        } else if request["envelopes"].as_array().unwrap().len() > 500 {
            assert_error(&response, StatusCode::TOO_MANY_REQUESTS, "rate_limited");
        } else {
            assert_error(&response, StatusCode::BAD_REQUEST, "bad_envelope");
        }
    }
    for (field, value) in [
        ("v", json!(2)),
        ("id", json!(state::ulid(now()))),
        ("exp", json!(envelope.exp - 1)),
        ("type", json!("grant")),
    ] {
        let mut request = valid.clone();
        request["envelopes"][0][field] = value;
        assert_error(
            &client
                .call(
                    Method::POST,
                    "/v1/approvals",
                    Some(&executor.token),
                    Some(request),
                )
                .await,
            StatusCode::BAD_REQUEST,
            "bad_envelope",
        );
    }
    let request = json!({"id":envelope.id,"exp":envelope.exp,"envelopes":[envelope,envelope]});
    assert_error(
        &client
            .call(
                Method::POST,
                "/v1/approvals",
                Some(&executor.token),
                Some(request),
            )
            .await,
        StatusCode::BAD_REQUEST,
        "bad_envelope",
    );
    for (envelopes, status, code) in [
        (Vec::new(), StatusCode::BAD_REQUEST, "bad_envelope"),
        (
            vec![envelope.clone(); 501],
            StatusCode::TOO_MANY_REQUESTS,
            "rate_limited",
        ),
        (
            vec![envelope.clone()],
            StatusCode::BAD_REQUEST,
            "bad_envelope",
        ),
    ] {
        assert_error(
            &client
                .call(
                    Method::POST,
                    "/v1/messages",
                    Some(&executor.token),
                    Some(json!({"envelopes":envelopes})),
                )
                .await,
            status,
            code,
        );
    }
    let grant = executor.seal(
        &approver,
        &state::ulid(now()),
        EnvelopeType::Grant,
        now() + 300,
        &json!({}),
    );
    for (field, value, status, code) in [
        (
            "id",
            json!("invalid"),
            StatusCode::BAD_REQUEST,
            "bad_envelope",
        ),
        (
            "created_at",
            json!(grant.exp + 1),
            StatusCode::BAD_REQUEST,
            "bad_envelope",
        ),
        (
            "created_at",
            json!(i64::MAX),
            StatusCode::BAD_REQUEST,
            "bad_envelope",
        ),
        (
            "exp",
            json!(i64::MAX),
            StatusCode::BAD_REQUEST,
            "bad_envelope",
        ),
        ("enc", json!("AA"), StatusCode::BAD_REQUEST, "bad_envelope"),
        ("to", json!("missing"), StatusCode::NOT_FOUND, "not_found"),
    ] {
        let mut request = serde_json::to_value(&grant).unwrap();
        request[field] = value;
        assert_error(
            &client
                .call(
                    Method::POST,
                    "/v1/messages",
                    Some(&executor.token),
                    Some(json!({"envelopes":[request]})),
                )
                .await,
            status,
            code,
        );
    }
    client
        .post(
            "/v1/messages",
            Some(&executor.token),
            json!({"envelopes":[grant]}),
        )
        .await;
    for ids in [
        vec!["invalid".to_string()],
        vec![grant.id.clone(); 501],
        vec![grant.id.clone(), state::ulid(now())],
    ] {
        let response = client
            .call(
                Method::POST,
                "/v1/messages/ack",
                Some(&approver.token),
                Some(json!({"ids":ids})),
            )
            .await;
        assert!(!response.0.is_success());
    }
    relay.inspect(|db| {
        assert!(db
            .query_row("SELECT acked_at IS NULL FROM messages", [], |r| r
                .get::<_, bool>(0))
            .unwrap())
    });
    client
        .post("/v1/approvals", Some(&executor.token), valid)
        .await;
    assert_error(
        &client
            .call(
                Method::POST,
                &format!("/v1/approvals/{}/cancel", envelope.id),
                Some(&executor.token),
                Some(json!({"extra":true})),
            )
            .await,
        StatusCode::BAD_REQUEST,
        "bad_envelope",
    );
    let mut reply = approver.seal(
        &executor,
        &envelope.id,
        EnvelopeType::ApprovalDecision,
        envelope.exp,
        &json!({}),
    );
    reply.to = approver.record.device_id.clone();
    assert_error(
        &client
            .call(
                Method::POST,
                &format!("/v1/approvals/{}/reply", envelope.id),
                Some(&approver.token),
                Some(json!({"envelope":reply})),
            )
            .await,
        StatusCode::BAD_REQUEST,
        "bad_envelope",
    );
    assert_error(
        &client
            .call(
                Method::POST,
                "/v1/approvals/missing/cancel",
                Some(&executor.token),
                Some(json!({})),
            )
            .await,
        StatusCode::NOT_FOUND,
        "not_found",
    );
    relay.shutdown().await;
}

#[tokio::test]
async fn recovery_and_strong_revocation_fail_closed_and_notify_cancelled_requests() {
    let (base, relay) = spawn_test_relay();
    let client = Client::new(base);
    let mut executor = Device::new("executor", false);
    let recovery = client.register(&mut executor).await;
    let mut approver = Device::new("approver", true);
    client.pair(&executor, &mut approver, false, None).await;
    let mut outsider = Device::new("outsider", false);
    client.register(&mut outsider).await;
    let path = format!("/v1/devices/{}", executor.record.device_id);
    for (caller, request, code) in [
        (
            &outsider,
            json!({"by":"recovery","recovery_code":recovery}),
            "forbidden",
        ),
        (&executor, json!({"by":"device"}), "forbidden"),
        (&approver, json!({"by":"recovery"}), "forbidden"),
        (
            &approver,
            json!({"by":"recovery","recovery_code":"wrong-code"}),
            "forbidden",
        ),
    ] {
        assert_error(
            &client
                .call(Method::DELETE, &path, Some(&caller.token), Some(request))
                .await,
            StatusCode::FORBIDDEN,
            code,
        );
    }
    let challenge = client
        .post(
            "/v1/auth/challenge",
            None,
            json!({"device_id":approver.record.device_id}),
        )
        .await;
    for sig in [None, Some("AA")] {
        let mut request = client
            .http
            .delete(client.base.join(&path).unwrap())
            .header("authorization", format!("Device {}", approver.token))
            .header("x-kv-challenge", challenge["challenge"].as_str().unwrap())
            .json(&json!({"by":"device"}));
        if let Some(sig) = sig {
            request = request.header("x-kv-strong-signature", sig);
        }
        let response = request.send().await.unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }
    let mut socket = client.socket(&approver).await;
    let id = state::ulid(now());
    let envelope = executor.seal(
        &approver,
        &id,
        EnvelopeType::ApprovalRequest,
        now() + 300,
        &json!({}),
    );
    client
        .post(
            "/v1/approvals",
            Some(&executor.token),
            json!({"id":id,"exp":envelope.exp,"envelopes":[envelope]}),
        )
        .await;
    assert_eq!(receive(&mut socket).await["t"], "envelope");
    let response = client
        .call(
            Method::DELETE,
            &path,
            Some(&approver.token),
            Some(json!({"by":"recovery","recovery_code":recovery})),
        )
        .await;
    assert_eq!(response.0, StatusCode::OK);
    assert_eq!(
        receive(&mut socket).await,
        json!({"t":"approval_cancel","id":id})
    );
    assert_eq!(
        client
            .call(
                Method::GET,
                "/v1/approvals?state=waiting",
                Some(&approver.token),
                None
            )
            .await
            .1,
        json!({"envelopes":[]})
    );
    relay.shutdown().await;
}

#[tokio::test]
async fn storage_and_worker_failures_return_only_static_errors() {
    let (base, relay) = spawn_test_relay();
    let client = Client::new(base);
    let (executor, approver) = two_devices(&client).await;
    // A failed CPU worker must not expose its panic text to the API or logs.
    let join = tokio::task::spawn_blocking(|| panic!("PRIVATE-WORKER-CONTENT"))
        .await
        .unwrap_err();
    let error = crate::error::ApiError::from(join);
    assert_eq!(error.code, ErrorCode::Conflict);
    assert!(!format!("{error:?}").contains("PRIVATE-WORKER-CONTENT"));
    relay
        .state
        .with(|data, _| {
            data.db.execute(
                "UPDATE accounts SET recovery_hash='not-a-PHC-hash' WHERE id=?1",
                [&executor.account],
            )?;
            Ok(())
        })
        .unwrap();
    assert_error(
        &client
            .call(
                Method::DELETE,
                &format!("/v1/devices/{}", approver.record.device_id),
                Some(&executor.token),
                Some(json!({"by":"recovery","recovery_code":"anything"})),
            )
            .await,
        StatusCode::CONFLICT,
        "conflict",
    );
    let challenge = client
        .post(
            "/v1/auth/challenge",
            None,
            json!({"device_id":executor.record.device_id}),
        )
        .await;
    let sig = executor
        .dk
        .sign(
            SignatureAlgorithm::ES256,
            &decode_b64(challenge["challenge"].as_str().unwrap()).unwrap(),
        )
        .unwrap();
    relay
        .state
        .with(|data, _| {
            data.db.pragma_update(None, "query_only", true)?;
            Ok(())
        })
        .unwrap();
    assert_error(&client.call(Method::POST, "/v1/auth/verify", None, Some(json!({"device_id":executor.record.device_id,"challenge":challenge["challenge"],"sig":encode_b64(&sig)}))).await, StatusCode::CONFLICT, "conflict");
    relay
        .state
        .with(|data, _| {
            data.db.pragma_update(None, "query_only", false)?;
            data.db.execute(
                "UPDATE devices SET record=x'00' WHERE id=?1",
                [&executor.record.device_id],
            )?;
            Ok(())
        })
        .unwrap();
    assert_error(
        &client
            .call(Method::GET, "/metrics", Some(&executor.token), None)
            .await,
        StatusCode::BAD_REQUEST,
        "bad_envelope",
    );
    assert!(relay.logs().iter().all(|line| !line.contains("PRIVATE")));
    relay.shutdown().await;
}

#[tokio::test]
async fn expiry_cancels_pending_pairing_and_terminal_only_finish_requires_execute() {
    let (base, relay) = spawn_test_relay();
    let client = Client::new(base);
    let mut initiator = Device::new("initiator", false);
    client.register(&mut initiator).await;
    let mut joiner = Device::new("quick_only", true);
    joiner.record.ak_s = None;
    joiner.strong = None;
    joiner.record.caps = vec![Capability::ApproveQuick];
    let (id, _) = pending_pair(&client, &initiator, &mut joiner).await;
    assert_error(
        &client
            .call(
                Method::POST,
                "/v1/pair/finish",
                Some(&joiner.token),
                Some(json!({"pairing_id":id,"confirm":joiner.confirm("123456")})),
            )
            .await,
        StatusCode::FORBIDDEN,
        "forbidden",
    );
    relay.advance_time(Duration::from_secs(601));
    assert_error(
        &client
            .call(
                Method::POST,
                "/v1/pair/finish",
                Some(&initiator.token),
                Some(json!({"pairing_id":id,"confirm":initiator.confirm("123456")})),
            )
            .await,
        StatusCode::GONE,
        "expired",
    );
    relay.cleanup();
    relay.inspect(|db| {
        assert!(db
            .query_row(
                "SELECT revoked_at IS NOT NULL FROM devices WHERE id=?1",
                [&joiner.record.device_id],
                |r| r.get::<_, bool>(0)
            )
            .unwrap());
    });
    relay.shutdown().await;
}

#[tokio::test]
async fn cached_principals_are_rechecked_after_revocation_and_account_migration() {
    let (base, relay) = spawn_test_relay();
    let client = Client::new(base);
    let mut device = Device::new("cached", false);
    client.register(&mut device).await;
    relay
        .state
        .with(|data, current| {
            let principal = data.authenticate(&headers(&device), current)?;
            data.db.execute(
                "DELETE FROM sessions WHERE device_id=?1",
                [&device.record.device_id],
            )?;
            assert_eq!(
                data.check(&principal, current, false).unwrap_err().code,
                ErrorCode::Unauthorized
            );
            Ok(())
        })
        .unwrap();
    relay.shutdown().await;
}

#[test]
fn duplicate_and_missing_cloudflare_headers_are_not_trusted() {
    let peer: SocketAddr = "127.0.0.1:1".parse().unwrap();
    let mut headers = HeaderMap::new();
    assert_eq!(state::client_ip(peer, &headers), peer.ip());
    headers.append("cf-connecting-ip", "192.0.2.1".parse().unwrap());
    headers.append("cf-connecting-ip", "192.0.2.2".parse().unwrap());
    assert_eq!(state::client_ip(peer, &headers), peer.ip());
}

#[tokio::test]
async fn production_startup_rejects_exposure_corrupt_storage_and_a_busy_port() {
    let directory = tempfile::tempdir().unwrap();
    let invalid = run("0.0.0.0:0".parse().unwrap(), directory.path(), async {})
        .await
        .unwrap_err();
    assert_eq!(invalid.kind(), std::io::ErrorKind::InvalidInput);
    let storage = directory.path().join("storage");
    std::fs::create_dir(&storage).unwrap();
    let db = storage.join("relay.sqlite3");
    std::fs::create_dir(&db).unwrap();
    assert!(run("127.0.0.1:0".parse().unwrap(), &storage, async {})
        .await
        .unwrap_err()
        .to_string()
        .contains("cannot open"));
    std::fs::remove_dir(&db).unwrap();
    std::fs::write(&db, b"PRIVATE-CORRUPT-DATABASE").unwrap();
    let error = run("127.0.0.1:0".parse().unwrap(), &storage, async {})
        .await
        .unwrap_err();
    assert!(error.to_string().contains("cannot initialize"));
    assert!(!error.to_string().contains("PRIVATE"));
    std::fs::remove_file(&db).unwrap();
    let busy = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    assert!(run(busy.local_addr().unwrap(), &storage, async {})
        .await
        .is_err());
}

#[tokio::test(start_paused = true)]
async fn background_cleanup_recovers_after_a_storage_failure_and_prunes_challenges() {
    let (_base, relay) = spawn_test_relay();
    relay
        .state
        .with(|data, now| {
            data.db.pragma_update(None, "query_only", true)?;
            data.challenges.insert(
                "live".into(),
                state::Challenge {
                    hash: "test hash".into(),
                    exp: now + 60,
                },
            );
            data.challenges.insert(
                "expired".into(),
                state::Challenge {
                    hash: "test hash".into(),
                    exp: now - 1,
                },
            );
            Ok(())
        })
        .unwrap();
    tokio::task::yield_now().await;
    assert!(relay
        .logs()
        .iter()
        .any(|line| line == "event=cleanup_failed count=1"));
    relay
        .state
        .with(|data, _| {
            data.db.pragma_update(None, "query_only", false)?;
            Ok(())
        })
        .unwrap();
    tokio::time::advance(Duration::from_secs(30)).await;
    tokio::task::yield_now().await;
    assert!(relay
        .logs()
        .iter()
        .any(|line| line == "event=cleanup count=0"));
    relay
        .state
        .with(|data, _| {
            assert!(data.challenges.contains_key("live"));
            assert!(!data.challenges.contains_key("expired"));
            Ok(())
        })
        .unwrap();
    relay.shutdown().await;
}

#[tokio::test]
async fn websocket_ip_and_device_upgrade_limits_return_the_contract_error() {
    let (base, relay) = spawn_test_relay();
    let client = Client::new(base);
    let mut device = Device::new("ws_limit", false);
    client.register(&mut device).await;
    for ip in [true, false] {
        relay
            .state
            .with(|data, now| {
                if ip {
                    data.rate("ws_ip:127.0.0.1".into(), now, 60, 60)?;
                } else {
                    data.rate(format!("ws:{}", device.record.device_id), now, 10, 10)?;
                }
                Ok(())
            })
            .unwrap();
        let mut url = client.base.join("/v1/presence").unwrap();
        url.set_scheme("ws").unwrap();
        let mut request = url.as_str().into_client_request().unwrap();
        request.headers_mut().insert(
            "authorization",
            format!("Device {}", device.token).parse().unwrap(),
        );
        request
            .headers_mut()
            .insert("sec-websocket-protocol", "kv-relay-v1".parse().unwrap());
        let error = connect_async(request).await.unwrap_err();
        let tokio_tungstenite::tungstenite::Error::Http(response) = error else {
            panic!("expected HTTP 429")
        };
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(response.headers()["retry-after"], "60");
        assert_eq!(
            serde_json::from_slice::<Value>(response.body().as_ref().unwrap()).unwrap()["error"]
                ["code"],
            "rate_limited"
        );
        relay.advance_time(Duration::from_secs(61));
    }
    relay.shutdown().await;
}

#[test]
fn cached_session_storage_failures_fail_closed() {
    let fixture = crate::tests::fixture();
    fixture
        .state
        .with(|data, now| {
            data.db.execute_batch("DROP TABLE sessions")?;
            assert_eq!(
                data.check(&fixture.principal, now, false).unwrap_err().code,
                ErrorCode::Conflict
            );
            Ok(())
        })
        .unwrap();
}

#[tokio::test]
async fn corrupt_recovery_hash_types_and_missing_pair_partners_are_rejected() {
    let (base, relay) = spawn_test_relay();
    let client = Client::new(base);
    let mut initiator = Device::new("initiator", false);
    client.register(&mut initiator).await;
    let mut joiner = Device::new("joiner", true);
    let (id, _) = pending_pair(&client, &initiator, &mut joiner).await;
    relay
        .state
        .with(|data, _| {
            data.db
                .execute("UPDATE accounts SET recovery_hash=x'00'", [])?;
            data.db.execute(
                "UPDATE pairings SET joiner_device=NULL WHERE pairing_id=?1",
                [&id],
            )?;
            Ok(())
        })
        .unwrap();
    assert_error(
        &client
            .call(
                Method::DELETE,
                &format!("/v1/devices/{}", initiator.record.device_id),
                Some(&initiator.token),
                Some(json!({"by":"recovery","recovery_code":"test"})),
            )
            .await,
        StatusCode::CONFLICT,
        "conflict",
    );
    assert_error(
        &client
            .call(
                Method::POST,
                "/v1/pair/finish",
                Some(&initiator.token),
                Some(json!({"pairing_id":id,"confirm":initiator.confirm("123456")})),
            )
            .await,
        StatusCode::CONFLICT,
        "conflict",
    );
    relay.shutdown().await;
}

#[tokio::test]
async fn registration_rate_and_failed_revocation_leave_storage_unchanged() {
    let (base, relay) = spawn_test_relay();
    let client = Client::new(base);
    let mut executor = Device::new("executor", false);
    let recovery = client.register(&mut executor).await;
    let mut approver = Device::new("approver", true);
    client.pair(&executor, &mut approver, false, None).await;
    relay.state.with(|data, now| {
        data.rate("register:127.0.0.1".into(), now, 9, 10)?;
        data.db.execute_batch("CREATE TRIGGER failed_revoke BEFORE UPDATE OF revoked_at ON devices BEGIN SELECT RAISE(ABORT,'PRIVATE-REVOKE-ERROR'); END;")?;
        Ok(())
    }).unwrap();
    let extra = Device::new("extra", false);
    assert_error(
        &client
            .call(
                Method::POST,
                "/v1/devices",
                None,
                Some(serde_json::to_value(extra.record).unwrap()),
            )
            .await,
        StatusCode::TOO_MANY_REQUESTS,
        "rate_limited",
    );
    assert_error(
        &client
            .call(
                Method::DELETE,
                &format!("/v1/devices/{}", approver.record.device_id),
                Some(&executor.token),
                Some(json!({"by":"recovery","recovery_code":recovery})),
            )
            .await,
        StatusCode::CONFLICT,
        "conflict",
    );
    assert_eq!(
        client
            .call(
                Method::GET,
                "/v1/approvals?state=waiting",
                Some(&approver.token),
                None
            )
            .await
            .0,
        StatusCode::OK
    );
    relay.inspect(|db| {
        assert_eq!(
            db.query_row("SELECT COUNT(*) FROM accounts", [], |r| r.get::<_, i64>(0))
                .unwrap(),
            1
        );
        assert_eq!(
            db.query_row(
                "SELECT COUNT(*) FROM devices WHERE revoked_at IS NULL",
                [],
                |r| r.get::<_, i64>(0)
            )
            .unwrap(),
            2
        );
    });
    assert!(relay.logs().iter().all(|line| !line.contains("PRIVATE")));
    relay.shutdown().await;
}

#[tokio::test]
async fn replacing_presence_does_not_consume_a_live_authentication_challenge() {
    let (base, relay) = spawn_test_relay();
    let client = Client::new(base);
    let mut device = Device::new("reconnect_challenge", false);
    client.register(&mut device).await;
    let _previous = client.socket(&device).await;
    let challenge = client
        .post(
            "/v1/auth/challenge",
            None,
            json!({"device_id":device.record.device_id}),
        )
        .await;
    let _replacement = client.socket(&device).await;
    let sig = device
        .dk
        .sign(
            SignatureAlgorithm::ES256,
            &decode_b64(challenge["challenge"].as_str().unwrap()).unwrap(),
        )
        .unwrap();
    let request = json!({"device_id":device.record.device_id,"challenge":challenge["challenge"],"sig":encode_b64(&sig)});
    let response = client
        .call(Method::POST, "/v1/auth/verify", None, Some(request.clone()))
        .await;
    assert_eq!(response.0, StatusCode::OK);
    assert_error(
        &client
            .call(Method::POST, "/v1/auth/verify", None, Some(request))
            .await,
        StatusCode::UNAUTHORIZED,
        "unauthorized",
    );
    relay.shutdown().await;
}
