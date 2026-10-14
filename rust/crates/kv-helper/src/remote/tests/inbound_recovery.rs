use super::boundaries::signing_harness;
use super::*;
use kv_core::remote::ipc::DecideIntent;

fn reopen(h: &Harness, path: &std::path::Path) -> Result<Arc<RemoteHelper>> {
    RemoteHelper::new(
        Store::persistence_fixture(path)?,
        h.helper.local.clone(),
        h.helper.account.clone(),
        h.helper.config.clone(),
        Services {
            identity: h.helper.services.identity.clone(),
            quick: h.helper.services.quick.clone(),
            strong: h.helper.services.strong.clone(),
            clock: h.clock.clone(),
            audit: h.audit.clone(),
            runner: h.runner.clone(),
            mirror: h.mirror.clone(),
            presence: h.presence.clone(),
        },
    )
}

fn persistent(path: &std::path::Path) -> Harness {
    let mut h = signing_harness();
    let records = directory(&h.helper.lock().unwrap().store).unwrap();
    *h.mirror.0.lock().unwrap() = records.clone();
    Store::persistence_fixture(path)
        .unwrap()
        .restore_verified_directory(
            &h.helper.account,
            &records,
            h.mirror.as_ref(),
            h.clock.now(),
        )
        .unwrap();
    h.helper = reopen(&h, path).unwrap();
    h
}

fn incoming(h: &Harness) -> (ApprovalRequest, Envelope) {
    let mut request: ApprovalRequest =
        serde_json::from_value(fixture("decision_valid.json")["request"].clone()).unwrap();
    request.requester.device_id = h.peer.device_id.clone();
    let envelope = h.envelope(
        EnvelopeType::ApprovalRequest,
        &request.approval_id,
        &request,
    );
    (request, envelope)
}

#[tokio::test]
async fn r3b_received_approval_survives_reopen_without_relay_redelivery() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("remote.sqlite3");
    let h = persistent(&path);
    let (request, envelope) = incoming(&h);
    let receipt = h
        .exchange(
            Caller::RelayClient,
            Op::RelayInbound,
            json!({"envelope":envelope}),
        )
        .await;
    assert_eq!(receipt["result"]["ack"], true);
    // A successful receipt lets the relay retire its copy. Restart must recover
    // from local durable state, without another message or a fake OS identity.
    let restored = reopen(&h, &path).unwrap();
    assert!(restored
        .lock()
        .unwrap()
        .inbound_requests
        .get(&request.approval_id)
        .is_some_and(|pending| pending == &request));
}

#[tokio::test]
async fn r3b_cancelled_inbound_does_not_resurrect_after_restart_or_redelivery() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("remote.sqlite3");
    let h = persistent(&path);
    let (request, envelope) = incoming(&h);
    h.helper.inbound(envelope.clone()).await.unwrap();
    h.helper
        .inbound(h.envelope(
            EnvelopeType::ApprovalCancel,
            &request.approval_id,
            &ApprovalCancel {
                approval_id: request.approval_id.clone(),
                extra: Extra::new(),
            },
        ))
        .await
        .unwrap();
    let restored = reopen(&h, &path).unwrap();
    assert!(restored.lock().unwrap().inbound_requests.is_empty());
    assert_eq!(
        restored.inbound(envelope).await.unwrap_err().code(),
        "already_consumed"
    );
}

#[tokio::test]
async fn r3b_issued_inbound_recovers_only_the_outbound_decision() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("remote.sqlite3");
    let h = persistent(&path);
    let (request, envelope) = incoming(&h);
    h.helper.inbound(envelope.clone()).await.unwrap();
    h.helper
        .issue_decision(DecideIntent {
            approval_id: request.approval_id.clone(),
            decision: Decision::Allow,
            level: Some(ApprovalLevel::Strong),
            scope_option: Some("per_use".into()),
            scope: DecisionScope {
                mode: ScopeMode::PerUse,
                level: DecisionScopeLevel::Credential,
                until: 0,
                extra: Extra::new(),
            },
            reason: None,
        })
        .await
        .unwrap();
    let restored = reopen(&h, &path).unwrap();
    assert!(restored.lock().unwrap().inbound_requests.is_empty());
    let outbox = restored.outbound_poll(0).await.unwrap();
    assert_eq!(outbox.len(), 1);
    assert_eq!(outbox[0].r#type, EnvelopeType::ApprovalDecision);
    assert_eq!(
        restored.inbound(envelope).await.unwrap_err().code(),
        "already_consumed"
    );
}

#[tokio::test]
async fn r3b_inbound_expiry_boundary_and_revoked_sender_remain_closed() {
    for revoked in [false, true] {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("remote.sqlite3");
        let h = persistent(&path);
        let (request, envelope) = incoming(&h);
        h.helper.inbound(envelope).await.unwrap();
        if revoked {
            h.helper.revoke_device(&h.peer.device_id, "local").unwrap();
        } else {
            h.clock.0.store(request.exp, Ordering::SeqCst);
            assert!(reopen(&h, &path)
                .unwrap()
                .lock()
                .unwrap()
                .inbound_requests
                .contains_key(&request.approval_id));
            h.clock.0.store(request.exp + 1, Ordering::SeqCst);
        }
        let restored = reopen(&h, &path).unwrap();
        assert!(restored.lock().unwrap().inbound_requests.is_empty());
        restored.tick().unwrap();
        assert!(restored.lock().unwrap().inbound_requests.is_empty());
    }
}

#[tokio::test]
async fn r3b_inbound_tampering_and_old_waiting_snapshot_fail_recovery() {
    for rollback in [false, true] {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("remote.sqlite3");
        let h = persistent(&path);
        let (request, envelope) = incoming(&h);
        h.helper.inbound(envelope).await.unwrap();
        let (mut object, sequence): (String, u64) = h
            .helper
            .lock()
            .unwrap()
            .store
            .db
            .query_row(
                "SELECT object_json,receipt_seq FROM inbound_approvals WHERE id=?1",
                [&request.approval_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        if rollback {
            h.helper
                .inbound(h.envelope(
                    EnvelopeType::ApprovalCancel,
                    &request.approval_id,
                    &ApprovalCancel {
                        approval_id: request.approval_id.clone(),
                        extra: Extra::new(),
                    },
                ))
                .await
                .unwrap();
        } else {
            let mut value: Value = serde_json::from_str(&object).unwrap();
            value["request"]["digest"] = json!("0".repeat(64));
            object = encode(&value).unwrap();
        }
        h.helper.lock().unwrap().store.db.execute(
            "UPDATE inbound_approvals SET object_json=?1,state='waiting',receipt_seq=?2 WHERE id=?3",
            params![object, sequence, request.approval_id],
        ).unwrap();
        assert_eq!(
            reopen(&h, &path).err().unwrap().code(),
            "inbound_state_mismatch"
        );
    }
}

#[tokio::test]
async fn r3b_inbound_storage_or_audit_failure_never_acknowledges_the_request() {
    for audit_failure in [false, true] {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("remote.sqlite3");
        let h = persistent(&path);
        let (_, envelope) = incoming(&h);
        if audit_failure {
            h.audit.fail.store(true, Ordering::SeqCst);
        } else {
            h.helper
                .lock()
                .unwrap()
                .store
                .db
                .execute_batch(
                    "CREATE TEMP TRIGGER fail_inbound BEFORE INSERT ON inbound_approvals
                 BEGIN SELECT RAISE(ABORT,'fixture storage failure'); END;",
                )
                .unwrap();
        }
        let receipt = h
            .exchange(
                Caller::RelayClient,
                Op::RelayInbound,
                json!({"envelope":envelope}),
            )
            .await;
        assert_ne!(receipt["result"]["ack"], true);
        {
            let state = h.helper.lock().unwrap();
            assert!(state.inbound_requests.is_empty());
            let count: u64 = state
                .store
                .db
                .query_row("SELECT COUNT(*) FROM inbound_approvals", [], |row| {
                    row.get(0)
                })
                .unwrap();
            assert_eq!(count, 0);
        }
        h.audit.fail.store(false, Ordering::SeqCst);
        if !audit_failure {
            h.helper
                .lock()
                .unwrap()
                .store
                .db
                .execute_batch("DROP TRIGGER fail_inbound;")
                .unwrap();
        }
        let retry = h
            .exchange(
                Caller::RelayClient,
                Op::RelayInbound,
                json!({"envelope":envelope}),
            )
            .await;
        assert_eq!(retry["result"]["ack"], true);
        assert_eq!(
            reopen(&h, &path)
                .unwrap()
                .lock()
                .unwrap()
                .inbound_requests
                .len(),
            1
        );
    }
}

#[tokio::test]
async fn r3b_inbound_escalation_survives_restart_without_changing_the_request() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("remote.sqlite3");
    let h = persistent(&path);
    let (request, envelope) = incoming(&h);
    h.helper.inbound(envelope).await.unwrap();
    h.helper
        .inbound(h.envelope(
            EnvelopeType::ApprovalEscalate,
            &request.approval_id,
            &ApprovalEscalate {
                approval_id: request.approval_id.clone(),
                extra: Extra::new(),
            },
        ))
        .await
        .unwrap();
    let restored = reopen(&h, &path).unwrap();
    let state = restored.lock().unwrap();
    assert!(state.inbound_escalated.contains(&request.approval_id));
    assert!(state
        .inbound_requests
        .get(&request.approval_id)
        .is_some_and(|value| value == &request));
}

#[test]
fn r3b_legacy_t2_migration_retires_old_tickets_and_preserves_valid_authority() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("remote.sqlite3");
    let h = persistent(&path);
    for (id, tier, confirm, global) in [
        ("legacy-finite", Tier::T2, Optional::Missing, false),
        (
            "legacy-global",
            Tier::T2,
            Optional::Value("srv".into()),
            true,
        ),
        ("valid-t2", Tier::T2, Optional::Value("srv".into()), false),
        ("valid-t1", Tier::T1, Optional::Missing, false),
    ] {
        let mut grant = super::workflow::signed_grant(&h, id, tier, 3);
        grant.confirm = confirm;
        if global {
            grant.aud = "*".into();
            grant.scope.level = GrantScopeLevel::Global;
        }
        grant.sig = sign_object(&grant, SignatureAlgorithm::ES256, key("strong").as_ref()).unwrap();
        // Seed signed records as the previous receiver did; the current installer
        // must reject them. Startup migration makes the refusal visible in the ledger.
        let state = h.helper.lock().unwrap();
        let transaction = state.store.transaction(h.audit.as_ref()).unwrap();
        h.helper
            .save_grant(
                &state,
                &grant,
                &json!({"kind":"grant","level":"strong"}),
                None,
            )
            .unwrap();
        h.helper
            .audit(&state, "grant_installed", json!({"jti":id}))
            .unwrap();
        transaction.commit().unwrap();
    }
    let restored = reopen(&h, &path).unwrap();
    let state = restored.lock().unwrap();
    for (id, retired) in [
        ("legacy-finite", true),
        ("legacy-global", true),
        ("valid-t2", false),
        ("valid-t1", false),
    ] {
        let revoked: bool = state
            .store
            .db
            .query_row(
                "SELECT revoked_at IS NOT NULL FROM grants WHERE jti=?1",
                [id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(revoked, retired);
    }
}
