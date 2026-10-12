use super::*;
use kv_core::remote::Optional;

fn split_device(name: &str) -> (Device, SoftwareDeviceKey) {
    let mut device = Device::new(name, false);
    let agreement = SoftwareDeviceKey::generate_p256();
    device.record.dk_sig = Optional::Value(kv_core::remote::ApprovalKey {
        r#pub: device.dk.public_jwk().unwrap(),
        alg: SignatureAlgorithm::ES256,
        extra: json!({"future_identity":{"bound":true}})
            .as_object()
            .unwrap()
            .clone(),
    });
    device.record.dk_pub = agreement.public_jwk().unwrap();
    device.record.os = Os::Windows;
    (device, agreement)
}

#[tokio::test]
async fn registration_auth_pairing_and_envelopes_use_dk_sig_with_legacy_peers() {
    let (base, relay) = spawn_test_relay();
    let client = Client::new(base);
    let (mut split, agreement) = split_device("k1_windows");
    client.register(&mut split).await;
    relay.inspect(|db| {
        assert_eq!(
            state::device(db, &split.record.device_id).unwrap().1,
            split.record
        );
    });
    let challenge = client
        .post(
            "/v1/auth/challenge",
            None,
            json!({"device_id":split.record.device_id}),
        )
        .await;
    let bytes = decode_b64(challenge["challenge"].as_str().unwrap()).unwrap();
    let request = |signature: Vec<u8>| json!({"device_id":split.record.device_id,"challenge":challenge["challenge"],"sig":encode_b64(&signature)});
    let wrong = request(agreement.sign(SignatureAlgorithm::ES256, &bytes).unwrap());
    assert_error(
        &client
            .call(Method::POST, "/v1/auth/verify", None, Some(wrong))
            .await,
        StatusCode::UNAUTHORIZED,
        "unauthorized",
    );
    client
        .post(
            "/v1/auth/verify",
            None,
            request(split.dk.sign(SignatureAlgorithm::ES256, &bytes).unwrap()),
        )
        .await;
    let mut peer = Device::new("k1_legacy_approver", true);
    client.register(&mut peer).await;
    client.pair(&split, &mut peer, true, None).await;
    let envelope = split.seal(
        &peer,
        "01J9W000000000000000000001",
        EnvelopeType::DirectiveResult,
        now() + 300,
        &json!({"ok":true}),
    );
    client
        .post(
            "/v1/messages",
            Some(&split.token),
            json!({"envelopes":[envelope]}),
        )
        .await;
    let mut wrong = envelope.clone();
    wrong.id = "01J9W000000000000000000002".into();
    wrong.sig = encode_b64(
        &agreement
            .sign(
                SignatureAlgorithm::ES256,
                &wrong.signature_payload().unwrap(),
            )
            .unwrap(),
    );
    let (status, _) = client
        .call(
            Method::POST,
            "/v1/messages",
            Some(&split.token),
            Some(json!({"envelopes":[wrong]})),
        )
        .await;
    assert!(!status.is_success());
    let mut changed = split.record.clone();
    if let Optional::Value(key) = &mut changed.dk_sig {
        key.extra
            .insert("future_identity".into(), json!({"bound":false}));
    }
    let (status, _) = client
        .call(
            Method::POST,
            "/v1/pair/start",
            Some(&split.token),
            Some(json!({"token_hash":"0".repeat(64),"initiator":changed,"exp":now()+300})),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    relay.shutdown().await;
}

#[tokio::test]
async fn registration_rejects_invalid_dk_sig_and_identity_as_approval_key() {
    let (base, relay) = spawn_test_relay();
    let client = Client::new(base);
    let (device, _) = split_device("k1_invalid");
    let original = serde_json::to_value(&device.record).unwrap();
    for bad in [
        Value::Null,
        json!({"pub":original["dk_pub"],"alg":"RS256"}),
        json!({"pub":{"kty":"EC","crv":"P-256","x":"AA","y":"AA"},"alg":"ES256"}),
    ] {
        let mut request = original.clone();
        request["dk_sig"] = bad;
        let (status, _) = client
            .call(Method::POST, "/v1/devices", None, Some(request))
            .await;
        assert!(!status.is_success());
    }
    let mut request = original;
    request["ak_q"] = request["dk_sig"].clone();
    request["caps"] = json!(["execute", "approve_quick"]);
    let (status, _) = client
        .call(Method::POST, "/v1/devices", None, Some(request))
        .await;
    assert!(!status.is_success());
    relay.shutdown().await;
}

#[tokio::test]
async fn recovery_binds_dk_sig_and_rotates_to_a_split_identity_without_a_session() {
    let (base, relay) = spawn_test_relay();
    let client = Client::new(base);
    let mut legacy = Device::new("k1_old", false);
    let code = client.register(&mut legacy).await;
    let (replacement, agreement) = split_device("k1_replacement");
    let nonce = state::random_token(32);
    let next = state::random_token(32);
    let proof = kv_core::remote::relay::RecoverAccountProof {
        action: kv_core::remote::relay::RecoverAccountAction::RecoverAccount,
        account_id: legacy.account.clone(),
        device: replacement.record.clone(),
        nonce: nonce.clone(),
        new_recovery_code_hash: sha256_hex(next.as_bytes()),
    };
    let bytes = kv_core::remote::canonical::jcs(&proof).unwrap();
    let mut request = json!({"account_id":legacy.account,"recovery_code":code,"new_recovery_code":next,"device":replacement.record,"nonce":nonce,"sig":encode_b64(&agreement.sign(SignatureAlgorithm::ES256, &bytes).unwrap())});
    assert_error(
        &client
            .call(Method::POST, "/v1/recovery", None, Some(request.clone()))
            .await,
        StatusCode::FORBIDDEN,
        "forbidden",
    );
    request["sig"] = json!(encode_b64(
        &replacement
            .dk
            .sign(SignatureAlgorithm::ES256, &bytes)
            .unwrap()
    ));
    let mut tampered = request.clone();
    tampered["device"]["dk_sig"]["future_identity"]["bound"] = json!(false);
    assert_error(
        &client
            .call(Method::POST, "/v1/recovery", None, Some(tampered))
            .await,
        StatusCode::FORBIDDEN,
        "forbidden",
    );
    client.post("/v1/recovery", None, request).await;
    assert!(!client.login(&replacement).await.is_empty());
    relay.shutdown().await;
}
