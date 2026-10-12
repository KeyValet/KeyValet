//! Transport retries never alter ciphertext, reset acknowledgements or duplicate delivery.
use super::*;

#[tokio::test]
async fn identical_message_retry_is_idempotent_after_ack_and_changed_ciphertext_conflicts() {
    let (base, relay) = spawn_test_relay();
    let client = Client::new(base);
    let (executor, approver) = two_devices(&client).await;
    let id = state::ulid(now());
    let envelope = executor.seal(
        &approver,
        &id,
        EnvelopeType::PresenceHint,
        now() + 300,
        &json!({"state":"away"}),
    );
    let body = json!({"envelopes":[envelope]});
    for _ in 0..2 {
        assert_eq!(
            client
                .post("/v1/messages", Some(&executor.token), body.clone())
                .await["accepted"],
            1
        );
    }
    client
        .post(
            "/v1/messages/ack",
            Some(&approver.token),
            json!({"ids":[id]}),
        )
        .await;
    client
        .post("/v1/messages", Some(&executor.token), body)
        .await;
    let changed = executor.seal(
        &approver,
        &id,
        EnvelopeType::PresenceHint,
        envelope.exp,
        &json!({"state":"present"}),
    );
    assert_error(
        &client
            .call(
                Method::POST,
                "/v1/messages",
                Some(&executor.token),
                Some(json!({"envelopes":[changed]})),
            )
            .await,
        StatusCode::CONFLICT,
        "conflict",
    );
    relay.inspect(|db| {
        let (count, acked): (i64, i64) = db
            .query_row(
                "SELECT COUNT(*),SUM(acked_at IS NOT NULL) FROM messages WHERE id=?1",
                [&id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!((count, acked), (1, 1));
    });
    relay.shutdown().await;
}

#[tokio::test]
async fn split_fanout_replies_and_signed_cancel_survive_lost_http_responses() {
    let (base, relay) = spawn_test_relay();
    let client = Client::new(base);
    let (executor, approver) = two_devices(&client).await;
    let mut other = Device::new("other-recipient", true);
    client.pair(&executor, &mut other, false, None).await;
    let id = state::ulid(now());
    let exp = now() + 300;
    let request = executor.seal(
        &approver,
        &id,
        EnvelopeType::ApprovalRequest,
        exp,
        &json!({}),
    );
    let first = json!({"id":id,"exp":exp,"envelopes":[request]});
    client
        .post("/v1/approvals", Some(&executor.token), first.clone())
        .await;
    let other_request = executor.seal(&other, &id, EnvelopeType::ApprovalRequest, exp, &json!({}));
    client
        .post(
            "/v1/approvals",
            Some(&executor.token),
            json!({"id":id,"exp":exp,"envelopes":[other_request]}),
        )
        .await;
    let decision = approver.seal(
        &executor,
        &id,
        EnvelopeType::ApprovalDecision,
        exp,
        &json!({"decision":"allow"}),
    );
    let reply_path = format!("/v1/approvals/{id}/reply");
    for _ in 0..2 {
        client
            .post(
                &reply_path,
                Some(&approver.token),
                json!({"envelope":decision}),
            )
            .await;
    }
    client
        .post("/v1/approvals", Some(&executor.token), first)
        .await;
    let changed = approver.seal(
        &executor,
        &id,
        EnvelopeType::ApprovalDecision,
        exp,
        &json!({"decision":"deny"}),
    );
    assert_error(
        &client
            .call(
                Method::POST,
                &reply_path,
                Some(&approver.token),
                Some(json!({"envelope":changed})),
            )
            .await,
        StatusCode::CONFLICT,
        "conflict",
    );
    // A relay resolution hint cannot clear an approver's cache. The requester must send its
    // helper-signed cancellation, even after the first decision resolved the relay row.
    let cancel = executor.seal(
        &other,
        &id,
        EnvelopeType::ApprovalCancel,
        exp,
        &json!({"approval_id":id}),
    );
    let cancel_path = format!("/v1/approvals/{id}/cancel");
    for _ in 0..2 {
        client
            .post(
                &cancel_path,
                Some(&executor.token),
                json!({"envelope":cancel}),
            )
            .await;
    }
    assert_error(
        &client
            .call(
                Method::POST,
                &cancel_path,
                Some(&executor.token),
                Some(json!({})),
            )
            .await,
        StatusCode::CONFLICT,
        "conflict",
    );
    let changed = executor.seal(
        &other,
        &id,
        EnvelopeType::ApprovalCancel,
        exp,
        &json!({"approval_id":"different"}),
    );
    assert_error(
        &client
            .call(
                Method::POST,
                &cancel_path,
                Some(&executor.token),
                Some(json!({"envelope":changed})),
            )
            .await,
        StatusCode::CONFLICT,
        "conflict",
    );
    relay.inspect(|db| {
        let current: String = db
            .query_row("SELECT state FROM approvals WHERE id=?1", [&id], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(current, "resolved");
        let count: i64 = db
            .query_row("SELECT COUNT(*) FROM messages WHERE id=?1", [&id], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(count, 4);
    });
    relay.shutdown().await;
}

#[tokio::test]
async fn expired_approval_accepts_signed_cleanup_and_typed_ack_never_confirms_another_ciphertext() {
    let (base, relay) = spawn_test_relay();
    let client = Client::new(base);
    let (executor, approver) = two_devices(&client).await;
    let id = state::ulid(now());
    let exp = now() + 1;
    let request = executor.seal(
        &approver,
        &id,
        EnvelopeType::ApprovalRequest,
        exp,
        &json!({}),
    );
    client
        .post(
            "/v1/approvals",
            Some(&executor.token),
            json!({"id":id,"exp":exp,"envelopes":[request]}),
        )
        .await;
    relay.advance_time(Duration::from_secs(2));
    relay.cleanup();
    let cancel = executor.seal(
        &approver,
        &id,
        EnvelopeType::ApprovalCancel,
        now() + 60,
        &json!({"approval_id":id}),
    );
    let path = format!("/v1/approvals/{id}/cancel");
    for _ in 0..2 {
        client
            .post(&path, Some(&executor.token), json!({"envelope":cancel}))
            .await;
    }
    assert_error(
        &client
            .call(Method::POST, &path, Some(&executor.token), Some(json!({})))
            .await,
        StatusCode::GONE,
        "expired",
    );
    client
        .post(
            "/v1/messages/ack",
            Some(&approver.token),
            json!({"ids":[id],"type":"approval_request"}),
        )
        .await;
    relay.inspect(|db| {
        assert!(db
            .query_row(
                "SELECT acked_at IS NULL FROM messages WHERE id=?1 AND type='approval_cancel'",
                [&id],
                |row| row.get::<_, bool>(0)
            )
            .unwrap());
        assert_eq!(
            db.query_row("SELECT state FROM approvals WHERE id=?1", [&id], |row| {
                row.get::<_, String>(0)
            })
            .unwrap(),
            "expired"
        );
    });
    for selector in [json!(null), json!(false), json!(17)] {
        assert_error(
            &client
                .call(
                    Method::POST,
                    "/v1/messages/ack",
                    Some(&approver.token),
                    Some(json!({"ids":[id],"type":selector})),
                )
                .await,
            StatusCode::BAD_REQUEST,
            "bad_envelope",
        );
    }
    assert_error(
        &client
            .call(
                Method::POST,
                "/v1/messages/ack",
                Some(&approver.token),
                Some(json!({"ids":[id],"type":"directive"})),
            )
            .await,
        StatusCode::NOT_FOUND,
        "not_found",
    );
    client
        .post(
            "/v1/messages/ack",
            Some(&approver.token),
            json!({"ids":[id],"type":"approval_cancel"}),
        )
        .await;
    relay.shutdown().await;
}

#[tokio::test]
async fn typed_ack_preserves_opaque_future_envelope_types() {
    let (base, relay) = spawn_test_relay();
    let client = Client::new(base);
    let (executor, approver) = two_devices(&client).await;
    for kind in [String::new(), "future-envelope-type-".repeat(20)] {
        let id = state::ulid(now());
        let mut envelope = executor.seal(
            &approver,
            &id,
            EnvelopeType::PresenceHint,
            now() + 60,
            &json!({}),
        );
        // Simulate a newer sender: W0 deliberately cannot originate an unknown type,
        // but its relay verifier must preserve that sender's authenticated envelope.
        envelope.r#type = EnvelopeType::Unknown(kind.clone());
        let aad = envelope.aad().unwrap();
        let (enc, ct) = kv_core::remote::hpke::seal(
            &SoftwareDeviceKey::generate_p256(),
            &kv_core::remote::keys::p256_public_sec1(&approver.record.dk_pub).unwrap(),
            &aad,
            b"{}",
        )
        .unwrap();
        envelope.enc = kv_core::remote::keys::encode_b64(&enc);
        envelope.ct = kv_core::remote::keys::encode_b64(&ct);
        envelope.sig = kv_core::remote::keys::encode_b64(
            &kv_core::remote::keys::DeviceKeyProvider::sign(
                &executor.dk,
                SignatureAlgorithm::ES256,
                &envelope.signature_payload().unwrap(),
            )
            .unwrap(),
        );
        client
            .post(
                "/v1/messages",
                Some(&executor.token),
                json!({"envelopes":[envelope]}),
            )
            .await;
        client
            .post(
                "/v1/messages/ack",
                Some(&approver.token),
                json!({"ids":[id],"type":kind}),
            )
            .await;
        relay.inspect(|db| {
            assert!(db
                .query_row(
                    "SELECT acked_at IS NOT NULL FROM messages WHERE id=?1",
                    [&id],
                    |row| row.get::<_, bool>(0)
                )
                .unwrap())
        });
    }
    relay.shutdown().await;
}
