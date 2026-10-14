//! Device removal must invalidate authority on the execution device itself.
use super::*;

fn insert_local(h: &Harness) {
    h.helper
        .lock()
        .unwrap()
        .store
        .insert_device(&h.helper.local, &h.helper.account, h.clock.now())
        .unwrap();
}

fn revoke_envelope(h: &Harness, target: &str, level: ApprovalLevel) -> Envelope {
    let proof = kv_core::remote::relay::DeviceDeleteProof {
        action: kv_core::remote::relay::DeviceDeleteAction::RevokeDevice,
        account: h.helper.account.clone(),
        by: h.peer.device_id.clone(),
        device_id: target.into(),
        challenge: kv_core::remote::keys::encode_b64(&[4; 32]),
        extra: Extra::new(),
    };
    let signature = sign_object(
        &proof,
        SignatureAlgorithm::ES256,
        key(if level == ApprovalLevel::Strong {
            "strong"
        } else {
            "quick"
        })
        .as_ref(),
    )
    .unwrap();
    h.envelope(
        EnvelopeType::DeviceRevoke,
        "executor-revocation",
        &DeviceRevoke {
            device_id: target.into(),
            extra: json!({"proof":proof,"sig":signature})
                .as_object()
                .unwrap()
                .clone(),
        },
    )
}

fn usage(h: &Harness) -> GrantUse {
    GrantUse {
        canonical: h.input(Tier::T1, "same-request").canonical,
        tier: Tier::T1,
        template_allowed_hosts: vec!["api.github.com".into()],
        policy_allowed_methods: vec!["POST".into()],
        body_bytes: 1,
        session_id: "session".into(),
    }
}

#[tokio::test]
async fn executor_revocation_cancels_unused_approval_and_tombstones_all_grants() {
    let h = Harness::new();
    insert_local(&h);
    let grant = super::workflow::signed_grant(&h, "active-before-revocation", Tier::T1, 10);
    h.helper
        .install_grant(&grant, ApprovalLevel::Strong)
        .unwrap();
    assert_eq!(
        h.helper.cover_and_debit(&usage(&h)).unwrap().jtis,
        vec![grant.jti.clone()]
    );
    h.runner.alive.store(false, Ordering::SeqCst);
    let request = h
        .helper
        .submit(h.input(Tier::T1, "unused-approved-request"))
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

    h.helper
        .inbound(revoke_envelope(
            &h,
            &h.helper.local.device_id,
            ApprovalLevel::Strong,
        ))
        .await
        .unwrap();
    {
        let state = h.helper.lock().unwrap();
        assert_eq!(
            state.store.pending(&request.approval_id).unwrap().state,
            PendingState::Cancelled
        );
        assert_eq!(
            state
                .store
                .device(&h.helper.local.device_id, &h.helper.account)
                .unwrap_err()
                .code(),
            "revoked_device"
        );
        let revoked: bool = state
            .store
            .db
            .query_row(
                "SELECT revoked_at IS NOT NULL FROM grants WHERE jti=?1",
                [&grant.jti],
                |row| row.get(0),
            )
            .unwrap();
        assert!(revoked);
        let nonce_consumed: bool = state
            .store
            .db
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM nonces WHERE nonce=?1)",
                [&request.nonce],
                |row| row.get(0),
            )
            .unwrap();
        assert!(
            nonce_consumed,
            "device removal must preserve consumed nonce history"
        );
        assert!(!state.full.contains_key(&request.approval_id));
    }
    h.helper
        .execute_approved(&request.approval_id)
        .await
        .unwrap();
    assert_eq!(h.runner.calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn executor_revocation_prevents_late_grant_use_and_new_remote_requests() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("remote.sqlite");
    let h = Harness::with(
        Store::persistence_fixture(&path).unwrap(),
        fixture("decision_valid.json")["now"].as_i64().unwrap(),
        true,
    );
    insert_local(&h);
    h.helper
        .inbound(revoke_envelope(
            &h,
            &h.helper.local.device_id,
            ApprovalLevel::Strong,
        ))
        .await
        .unwrap();
    // A signed grant already in transit cannot restore an execution identity.
    let grant = super::workflow::signed_grant(&h, "late-but-valid-signature", Tier::T1, 10);
    h.helper
        .install_grant(&grant, ApprovalLevel::Strong)
        .unwrap();
    assert_eq!(
        h.helper.cover_and_debit(&usage(&h)).unwrap_err().code(),
        "revoked_device"
    );
    assert_eq!(
        h.helper
            .submit(h.input(Tier::T1, "after-revocation"))
            .unwrap_err()
            .code(),
        "revoked_device"
    );
    assert_eq!(h.runner.calls.load(Ordering::SeqCst), 0);
    let peer = h.peer.clone();
    let now = h.clock.now();
    drop(h);
    let reopened = Harness::from_store(Store::persistence_fixture(&path).unwrap(), now, peer);
    assert_eq!(
        reopened
            .helper
            .cover_and_debit(&usage(&reopened))
            .unwrap_err()
            .code(),
        "revoked_device"
    );
    assert_eq!(
        reopened
            .helper
            .submit(reopened.input(Tier::T1, "after-restart"))
            .unwrap_err()
            .code(),
        "revoked_device"
    );
}

#[tokio::test]
async fn executor_revocation_of_one_issuer_preserves_other_issuers_authority() {
    let h = Harness::new();
    insert_local(&h);
    let first = super::workflow::signed_grant(&h, "removed-issuer", Tier::T1, 10);
    h.helper
        .install_grant(&first, ApprovalLevel::Strong)
        .unwrap();
    let mut other = h.peer.clone();
    other.device_id = "other-paired-approver".into();
    h.helper
        .lock()
        .unwrap()
        .store
        .insert_device(&other, &h.helper.account, h.clock.now())
        .unwrap();
    let mut second = super::workflow::signed_grant(&h, "remaining-issuer", Tier::T1, 10);
    second.iss = other.device_id;
    second.sig = sign_object(&second, SignatureAlgorithm::ES256, key("strong").as_ref()).unwrap();
    h.helper
        .install_grant(&second, ApprovalLevel::Strong)
        .unwrap();
    h.helper
        .inbound(revoke_envelope(
            &h,
            &h.peer.device_id,
            ApprovalLevel::Strong,
        ))
        .await
        .unwrap();
    assert_eq!(
        h.helper.cover_and_debit(&usage(&h)).unwrap().jtis,
        vec![second.jti]
    );
    assert!(!h.runner.locked.load(Ordering::SeqCst));
}

#[tokio::test]
async fn executor_revocation_rejects_quick_proof_without_invalidating_existing_authority() {
    let h = Harness::new();
    insert_local(&h);
    let grant = super::workflow::signed_grant(&h, "still-authorized", Tier::T1, 10);
    h.helper
        .install_grant(&grant, ApprovalLevel::Strong)
        .unwrap();
    assert!(h
        .helper
        .inbound(revoke_envelope(
            &h,
            &h.helper.local.device_id,
            ApprovalLevel::Quick
        ))
        .await
        .is_err());
    assert!(h
        .helper
        .lock()
        .unwrap()
        .store
        .device(&h.helper.local.device_id, &h.helper.account)
        .is_ok());
    assert_eq!(
        h.helper.cover_and_debit(&usage(&h)).unwrap().jtis,
        vec![grant.jti]
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn executor_revocation_without_a_strong_key_does_not_request_authentication_or_a_relay_session(
) {
    use crate::remote::pairing_relay::RelayApi;
    use kv_core::remote::relay::{RegisterDeviceRequest, RegisterDeviceResponse};
    let h = Harness::new();
    let (url, server) = kv_server::spawn_test_relay();
    let relay = RelayApi::new(url.as_str()).unwrap();
    let _: RegisterDeviceResponse = relay
        .post(
            "v1/devices",
            &RegisterDeviceRequest {
                device: h.helper.local.clone(),
                push_token: Optional::Missing,
            },
            None,
        )
        .await
        .unwrap();
    h.helper
        .lock()
        .unwrap()
        .store
        .set_setting("relay_url", &url.as_str(), "local", h.clock.now())
        .unwrap();
    let authorizations = Arc::new(AtomicUsize::new(0));
    let count = authorizations.clone();
    *h.runner.after_authorize.lock().unwrap() = Some(Box::new(move || {
        count.fetch_add(1, Ordering::SeqCst);
    }));
    let result = h.helper.revoke_owner_device(&h.peer.device_id).await;
    assert_eq!(
        authorizations.load(Ordering::SeqCst),
        0,
        "an execution-only identity cannot provide the required AK_s proof"
    );
    assert_eq!(result.unwrap_err().code(), "key_unavailable");
    assert_eq!(
        server.inspect(|db| db
            .query_row("SELECT COUNT(*) FROM sessions", [], |row| row
                .get::<_, u64>(0))
            .unwrap()),
        0
    );
    assert!(h
        .helper
        .lock()
        .unwrap()
        .store
        .device(&h.peer.device_id, &h.helper.account)
        .is_ok());
    server.shutdown().await;
}
