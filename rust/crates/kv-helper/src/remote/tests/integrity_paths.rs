use super::boundaries::signing_harness;
use super::*;

fn inbound_request(h: &Harness, id: &str) -> ApprovalRequest {
    let mut request: ApprovalRequest =
        serde_json::from_value(fixture("decision_valid.json")["request"].clone()).unwrap();
    request.approval_id = id.into();
    request.requester.device_id = h.peer.device_id.clone();
    request.exp = h.clock.now() + 60;
    request
}

#[tokio::test]
async fn incoming_requests_are_immutable_and_cannot_be_reissued_after_a_signed_decision() {
    let h = signing_harness();
    let request = inbound_request(&h, "immutable");
    let envelope = h.envelope(
        EnvelopeType::ApprovalRequest,
        &request.approval_id,
        &request,
    );
    h.helper.inbound(envelope.clone()).await.unwrap();
    h.helper.inbound(envelope.clone()).await.unwrap();
    let mut changed = request.clone();
    changed.extra.insert("changed".into(), json!(true));
    assert_eq!(
        h.helper
            .inbound(h.envelope(
                EnvelopeType::ApprovalRequest,
                &request.approval_id,
                &changed
            ))
            .await
            .unwrap_err()
            .code(),
        "invalid_approval_request"
    );
    h.reason("invalid_approval_request");
    assert_eq!(
        h.helper.lock().unwrap().inbound_requests[&request.approval_id],
        request
    );
    let response = h.exchange(Caller::CliOwner, Op::Decide, json!({"approval_id":request.approval_id,"decision":"allow","level":"strong","scope":{"mode":"per_use","level":"credential","until":0}})).await;
    assert_eq!(response["ok"], true);
    assert_eq!(
        h.helper.inbound(envelope).await.unwrap_err().code(),
        "already_consumed"
    );
    h.reason("already_consumed");
    assert_eq!(h.runner.calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn missing_inbound_ledgers_and_unsupported_signed_messages_are_rejected_and_audited() {
    for kind in [
        EnvelopeType::ApprovalRequest,
        EnvelopeType::DirectiveResult,
        EnvelopeType::DeviceRevoke,
    ] {
        let h = signing_harness();
        let (payload, expected) = if kind == EnvelopeType::ApprovalRequest {
            h.helper
                .lock()
                .unwrap()
                .store
                .db
                .execute_batch("DROP TABLE issued_approvals")
                .unwrap();
            (json!(inbound_request(&h, "missing")), "state_unavailable")
        } else if kind == EnvelopeType::DirectiveResult {
            h.helper
                .lock()
                .unwrap()
                .store
                .db
                .execute_batch("DROP TABLE issued_directives")
                .unwrap();
            (
                json!(DirectiveResult {
                    id: "missing".into(),
                    ok: true,
                    error: None,
                    state: Extra::new(),
                    extra: Extra::new()
                }),
                "state_unavailable",
            )
        } else {
            (
                json!({}),
                if kind == EnvelopeType::DeviceRevoke {
                    "invalid_json"
                } else {
                    "unsupported_type"
                },
            )
        };
        assert_eq!(
            h.helper
                .inbound(h.envelope(kind, "missing", &payload))
                .await
                .unwrap_err()
                .code(),
            expected
        );
        h.reason(expected);
        assert_eq!(h.runner.calls.load(Ordering::SeqCst), 0);
    }
}

#[tokio::test]
async fn malformed_pair_ciphertext_aborts_pairing_without_creating_directory_authority() {
    let h = Harness::with(
        Store::memory().unwrap(),
        fixture("decision_valid.json")["now"].as_i64().unwrap(),
        false,
    );
    let offer = h.helper.pair_start("https://relay.example").unwrap();
    let mut envelope = h.envelope(
        EnvelopeType::PairAccept,
        "corrupt-pair",
        &json!({"token":offer.extra["token"],"joiner":h.peer}),
    );
    envelope.exp = offer.extra["expires_at"].as_i64().unwrap();
    let mut bytes = decode_b64(&envelope.ct).unwrap();
    bytes[0] ^= 1;
    envelope.ct = kv_core::remote::keys::encode_b64(&bytes);
    envelope.sig =
        sign_object(&envelope, SignatureAlgorithm::ES256, key("sender").as_ref()).unwrap();
    assert_eq!(
        h.helper.inbound(envelope).await.unwrap_err().code(),
        "decryption_failed"
    );
    h.reason("decryption_failed");
    assert!(h.helper.lock().unwrap().pairing.is_none());
    assert!(h
        .helper
        .lock()
        .unwrap()
        .store
        .devices("account")
        .unwrap()
        .is_empty());
}

#[tokio::test]
async fn r3a_status_exposes_only_live_verified_approver_presence() {
    let h = Harness::new();
    h.helper.lock().unwrap().relay_connected = true;
    for presence in [Presence::Present, Presence::Away] {
        let hint = PresenceHint {
            device_id: h.peer.device_id.clone(),
            state: presence,
            since: h.clock.now(),
            sent_at: h.clock.now(),
            extra: Extra::new(),
        };
        let id = if presence == Presence::Present {
            "status-present"
        } else {
            "status-away"
        };
        h.helper
            .inbound(h.envelope(EnvelopeType::PresenceHint, id, &hint))
            .await
            .unwrap();
        let status = h.exchange(Caller::Mcp, Op::Status, json!({})).await;
        assert_eq!(
            status["result"]["approvers"][0]["presence"],
            json!(presence)
        );
        h.clock.0.fetch_add(1, Ordering::SeqCst);
    }
    let hint = PresenceHint {
        device_id: h.peer.device_id.clone(),
        state: Presence::Present,
        since: h.clock.now(),
        sent_at: h.clock.now(),
        extra: Extra::new(),
    };
    h.helper
        .inbound(h.envelope(
            EnvelopeType::PresenceHint,
            "status-expiring-presence",
            &hint,
        ))
        .await
        .unwrap();
    h.clock.0.fetch_add(121, Ordering::SeqCst);
    let status = h.exchange(Caller::Mcp, Op::Status, json!({})).await;
    assert_eq!(status["result"]["approvers"][0]["presence"], "away");
}

#[tokio::test]
async fn pending_and_status_online_metadata_respect_hint_lifetime_and_presence_skips_self() {
    let h = Harness::new();
    let request = h.helper.submit(h.input(Tier::T1, "online")).unwrap();
    h.helper.lock().unwrap().relay_connected = true;
    let hint = PresenceHint {
        device_id: h.peer.device_id.clone(),
        state: Presence::Away,
        since: h.clock.now(),
        sent_at: h.clock.now(),
        extra: Extra::new(),
    };
    h.helper
        .inbound(h.envelope(EnvelopeType::PresenceHint, "hint", &hint))
        .await
        .unwrap();
    for (age, online) in [(0, true), (121, false)] {
        h.clock.0.store(hint.sent_at + age, Ordering::SeqCst);
        let result = h
            .helper
            .result(&request.approval_id, 501, 4242, false)
            .unwrap();
        assert_eq!(result.approver.as_value().unwrap().online, online);
        let status = h.exchange(Caller::Mcp, Op::Status, json!({})).await;
        assert_eq!(status["result"]["approvers"][0]["online"], online);
    }
    let first = h.helper.outbound_poll(0).await.unwrap();
    h.spooled(&first);
    h.helper
        .lock()
        .unwrap()
        .store
        .insert_device(&h.helper.local, "account", h.clock.now())
        .unwrap();
    let response = h
        .exchange(
            Caller::ApprovalAgent,
            Op::PresenceUpdate,
            json!(PresenceHint {
                device_id: h.helper.local.device_id.clone(),
                state: Presence::Away,
                since: h.clock.now(),
                sent_at: h.clock.now(),
                extra: Extra::new()
            }),
        )
        .await;
    assert_eq!(response["ok"], true);
    let outgoing = h.helper.outbound_poll(0).await.unwrap();
    assert_eq!(outgoing.len(), 1);
    assert_eq!(outgoing[0].to, h.peer.device_id);
    assert_eq!(outgoing[0].r#type, EnvelopeType::PresenceHint);
}

#[tokio::test]
async fn resolution_notices_skip_lost_results_but_can_announce_execution_or_retained_results() {
    let h = Harness::new();
    let lost = h.helper.submit(h.input(Tier::T1, "lost")).unwrap();
    let active = h.helper.submit(h.input(Tier::T1, "active")).unwrap();
    let ready = h.helper.submit(h.input(Tier::T1, "ready")).unwrap();
    {
        let mut state = h.helper.lock().unwrap();
        state
            .store
            .db
            .execute("UPDATE pending_approvals SET state='executed'", [])
            .unwrap();
        // Inspect the lost result before either ready result, independently of random IDs.
        state
            .store
            .db
            .execute(
                "UPDATE pending_approvals SET created_at=?1 WHERE id=?2",
                params![h.clock.now() - 1, lost.approval_id],
            )
            .unwrap();
        state.executing.insert(active.approval_id.clone());
        state
            .results
            .insert(ready.approval_id.clone(), json!({"synthetic":"result"}));
    }
    let context = CallerContext::authenticated(Caller::Mcp, 501, 4242, 50);
    let mut seen = std::collections::HashSet::new();
    let first = h
        .helper
        .next_approval_notice(context, &mut seen)
        .await
        .unwrap();
    let second = h
        .helper
        .next_approval_notice(context, &mut seen)
        .await
        .unwrap();
    let ids: std::collections::HashSet<_> = [
        first["params"]["approval_id"].as_str().unwrap(),
        second["params"]["approval_id"].as_str().unwrap(),
    ]
    .into_iter()
    .collect();
    assert_eq!(
        ids,
        [active.approval_id.as_str(), ready.approval_id.as_str()]
            .into_iter()
            .collect()
    );
    assert!(!seen.contains(&lost.approval_id));
    assert!(h
        .helper
        .lock()
        .unwrap()
        .results
        .contains_key(&ready.approval_id));
}

#[tokio::test]
async fn notification_query_and_client_timeout_audit_storage_failures_are_rejected() {
    let h = Harness::new();
    h.helper
        .lock()
        .unwrap()
        .store
        .db
        .execute_batch("DROP TABLE pending_approvals")
        .unwrap();
    let mut seen = std::collections::HashSet::new();
    assert_eq!(
        h.helper
            .next_approval_notice(
                CallerContext::authenticated(Caller::Mcp, 501, 4242, 50),
                &mut seen
            )
            .await
            .unwrap_err()
            .code(),
        "state_unavailable"
    );
    h.reason("state_unavailable");
    let h = Harness::new();
    h.helper
        .lock()
        .unwrap()
        .store
        .db
        .execute_batch("DROP TABLE remote_audit")
        .unwrap();
    let response = h
        .exchange(Caller::Mcp, Op::ClientTimeoutObserved, json!({}))
        .await;
    assert_eq!(response["error"]["code"], "audit_unavailable");
    assert!(h
        .audit
        .entries
        .lock()
        .unwrap()
        .iter()
        .any(|entry| entry["op"] == "remote_audit_rejected"
            && entry["event"] == "client_timeout_observed"
            && entry["reason"] == "state_unavailable"));
}

#[test]
fn matched_classes_choose_the_shortest_lifetime_and_settings_u64_are_decoded() {
    for configured in [false, true] {
        let mut h = Harness::new();
        let classes = json!({"one":{"match":{"credential":"github/**"},"exp_s":50},"two":{"match":{"host":"api.github.com"},"exp_s":25}});
        if configured {
            Arc::get_mut(&mut h.helper).unwrap().config = ApprovalConfig::from_toml("[approval]\n[[approval.class]]\nname='one'\nmatch.credential='github/**'\nexp_s=50\n[[approval.class]]\nname='two'\nmatch.host='api.github.com'\nexp_s=25").unwrap();
        } else {
            h.helper
                .lock()
                .unwrap()
                .store
                .set_setting("classes", &classes, "local", h.clock.now())
                .unwrap();
        }
        h.helper
            .lock()
            .unwrap()
            .store
            .set_setting("unlock_ttl", &3600_u64, "local", h.clock.now())
            .unwrap();
        let request = h.helper.submit(h.input(Tier::T1, "shortest")).unwrap();
        assert_eq!(request.exp - h.clock.now(), 25);
        assert_eq!(
            h.helper
                .lock()
                .unwrap()
                .store
                .setting::<u64>("unlock_ttl")
                .unwrap(),
            Some(3600)
        );
    }
}

#[test]
fn request_protection_metadata_preserves_tpm_and_secure_enclave_without_claiming_attestation() {
    for (kind, expected) in [
        (KeyKind::Tpm2, ProtectionKind::Tpm2),
        (KeyKind::SecureEnclave, ProtectionKind::SecureEnclave),
    ] {
        let mut h = Harness::new();
        Arc::get_mut(&mut h.helper).unwrap().local.key_kind = kind;
        let request = h.helper.submit(h.input(Tier::T1, "metadata")).unwrap();
        assert_eq!(request.requester.protection.kind, expected);
        assert_eq!(request.requester.protection.attestation, Optional::Null);
    }
}

#[tokio::test]
async fn every_notification_storage_failure_is_audited_without_claiming_a_result() {
    let mut failures = 0;
    for at in 1..240 {
        let h = Harness::new();
        let pending = h.helper.submit(h.input(Tier::T1, "notice")).unwrap();
        h.helper
            .lock()
            .unwrap()
            .store
            .db
            .execute("UPDATE pending_approvals SET state='approved_unused'", [])
            .unwrap();
        let denied = super::sql_faults::deny_once(&h.helper, at);
        let mut seen = std::collections::HashSet::new();
        let result = h
            .helper
            .next_approval_notice(
                CallerContext::authenticated(Caller::Mcp, 501, 4242, 50),
                &mut seen,
            )
            .await;
        if !denied.load(Ordering::SeqCst) {
            assert_eq!(
                result.unwrap()["params"]["approval_id"],
                pending.approval_id
            );
            break;
        }
        failures += 1;
        assert_eq!(result.unwrap_err().code(), "state_unavailable");
        h.reason("state_unavailable");
        assert_eq!(h.runner.calls.load(Ordering::SeqCst), 0);
        assert!(h
            .helper
            .lock()
            .unwrap()
            .store
            .pending(&pending.approval_id)
            .unwrap()
            .claimed_at
            .is_none());
    }
    assert!(failures > 10);
}

#[tokio::test]
async fn a_signed_device_revocation_invalidates_its_unused_approval_and_preserves_unsigned_work() {
    let h = Harness::new();
    h.runner.alive.store(false, Ordering::SeqCst);
    let waiting = h.helper.submit(h.input(Tier::T1, "unsigned")).unwrap();
    let approved = h.helper.submit(h.input(Tier::T1, "signed")).unwrap();
    let decision = h.decision(&approved, ApprovalLevel::Strong, ScopeMode::PerUse);
    h.helper
        .inbound(h.envelope(
            EnvelopeType::ApprovalDecision,
            &approved.approval_id,
            &decision,
        ))
        .await
        .unwrap();
    let directive = super::workflow::signed_directive(
        &h,
        DirectiveOp::RevokeDevice,
        json!({"device_id":h.peer.device_id,"confirm":h.helper.local.label}),
        ApprovalLevel::Strong,
    );
    h.helper
        .apply_directive(&directive, ApprovalLevel::Strong)
        .unwrap();
    let state = h.helper.lock().unwrap();
    assert_eq!(
        state.store.pending(&approved.approval_id).unwrap().state,
        PendingState::Cancelled
    );
    assert_eq!(
        state.store.pending(&waiting.approval_id).unwrap().state,
        PendingState::Waiting
    );
    assert!(!state.full.contains_key(&approved.approval_id));
    assert!(state.full.contains_key(&waiting.approval_id));
    assert_eq!(h.runner.calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn lock_cancels_and_audits_waiting_work_without_rewriting_executed_work() {
    let h = Harness::new();
    let executed = h.helper.submit(h.input(Tier::T1, "executed")).unwrap();
    let decision = h.decision(&executed, ApprovalLevel::Strong, ScopeMode::PerUse);
    h.helper
        .inbound(h.envelope(
            EnvelopeType::ApprovalDecision,
            &executed.approval_id,
            &decision,
        ))
        .await
        .unwrap();
    h.helper
        .execute_approved(&executed.approval_id)
        .await
        .unwrap();
    let waiting = h.helper.submit(h.input(Tier::T1, "waiting")).unwrap();
    let directive =
        super::workflow::signed_directive(&h, DirectiveOp::Lock, json!({}), ApprovalLevel::Quick);
    h.helper
        .apply_directive(&directive, ApprovalLevel::Quick)
        .unwrap();
    let state = h.helper.lock().unwrap();
    assert_eq!(
        state.store.pending(&executed.approval_id).unwrap().state,
        PendingState::Executed
    );
    assert_eq!(
        state.store.pending(&waiting.approval_id).unwrap().state,
        PendingState::Cancelled
    );
    assert!(!state.full.contains_key(&waiting.approval_id));
    assert!(state
        .store
        .audit_entries()
        .unwrap()
        .iter()
        .any(|event| event["op"] == "approval_cancelled"
            && event["approval_id"] == waiting.approval_id));
}
