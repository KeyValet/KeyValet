use super::*;
use kv_core::remote::relay::{RecoverAccountAction, RecoverAccountProof};

fn request(device: &Device, account: &str, code: &str) -> Value {
    let nonce = state::random_token(32);
    let new_code = state::random_token(32);
    let proof = RecoverAccountProof {
        action: RecoverAccountAction::RecoverAccount,
        account_id: account.into(),
        device: device.record.clone(),
        nonce: nonce.clone(),
        new_recovery_code_hash: kv_core::remote::canonical::sha256_hex(new_code.as_bytes()),
    };
    let sig = device
        .dk
        .sign(
            SignatureAlgorithm::ES256,
            &kv_core::remote::canonical::jcs(&proof).unwrap(),
        )
        .unwrap();
    json!({"account_id":account,"recovery_code":code,"new_recovery_code":new_code,"device":device.record,"nonce":nonce,"sig":encode_b64(&sig)})
}

#[tokio::test]
async fn lost_all_devices_recovers_without_a_session_and_invalidates_old_authority() {
    let (base, relay) = spawn_test_relay();
    let client = Client::new(base);
    let mut old = Device::new("lost", false);
    let code = client.register(&mut old).await;
    let mut other = Device::new("lost_phone", true);
    client.pair(&old, &mut other, true, None).await;
    // No valid sessions survive. Recovery does not use Device authentication.
    relay.inspect(|db| db.execute("DELETE FROM sessions", []).unwrap());
    let new = Device::new("replacement", false);
    let body = request(&new, &old.account, &code);
    let (status, response) = client
        .call(Method::POST, "/v1/recovery", None, Some(body.clone()))
        .await;
    assert_eq!(status, StatusCode::OK, "{response}");
    assert_eq!(response["account_id"], old.account);
    assert_ne!(response["recovery_code"], code);
    let token = client.login(&new).await;
    assert!(!token.is_empty());
    for lost in [&old, &other] {
        let (status, _) = client
            .call(
                Method::POST,
                "/v1/auth/challenge",
                None,
                Some(json!({"device_id":lost.record.device_id})),
            )
            .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }
    let (status, _) = client
        .call(Method::POST, "/v1/recovery", None, Some(body))
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    relay.inspect(|db| {
        let active: i64 = db
            .query_row(
                "SELECT COUNT(*) FROM devices WHERE account_id=?1 AND revoked_at IS NULL",
                [&old.account],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(active, 1);
        let hash: String = db
            .query_row(
                "SELECT recovery_hash FROM accounts WHERE id=?1",
                [&old.account],
                |r| r.get(0),
            )
            .unwrap();
        assert!(!hash.contains(&code));
    });
    let logs = relay.logs().join("\n");
    assert!(!logs.contains(&code));
    assert!(!logs.contains(response["recovery_code"].as_str().unwrap()));
    relay.shutdown().await;
}

#[tokio::test]
async fn recovery_rejects_wrong_codes_key_substitution_and_device_conflicts_atomically() {
    let (base, relay) = spawn_test_relay();
    let client = Client::new(base);
    let mut old = Device::new("lost", false);
    let code = client.register(&mut old).await;
    let new = Device::new("new", false);
    let mut tampered = request(&new, &old.account, &code);
    tampered["device"]["label"] = json!("substituted");
    for body in [
        tampered,
        request(&new, &old.account, &state::random_token(32)),
        request(&old, &old.account, &code),
    ] {
        let (status, _) = client
            .call(Method::POST, "/v1/recovery", None, Some(body))
            .await;
        assert!(!status.is_success());
        // A failed replacement must not consume the code, revoke devices or remove sessions.
        let (status, _) = client
            .call(
                Method::GET,
                "/v1/approvals?state=waiting",
                Some(&old.token),
                None,
            )
            .await;
        assert_eq!(status, StatusCode::OK);
    }
    let (status, _) = client
        .call(
            Method::POST,
            "/v1/recovery",
            None,
            Some(request(&new, &old.account, &code)),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    relay.shutdown().await;
}

#[tokio::test]
async fn concurrent_recovery_consumes_the_code_exactly_once() {
    let (base, relay) = spawn_test_relay();
    let client = Client::new(base);
    let mut old = Device::new("lost", false);
    let code = client.register(&mut old).await;
    let a = Device::new("new_a", false);
    let b = Device::new("new_b", false);
    let (a, b) = tokio::join!(
        client.call(
            Method::POST,
            "/v1/recovery",
            None,
            Some(request(&a, &old.account, &code))
        ),
        client.call(
            Method::POST,
            "/v1/recovery",
            None,
            Some(request(&b, &old.account, &code))
        )
    );
    assert_eq!(
        usize::from(a.0.is_success()) + usize::from(b.0.is_success()),
        1
    );
    relay.shutdown().await;
}
