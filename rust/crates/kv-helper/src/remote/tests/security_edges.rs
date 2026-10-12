use super::boundaries::signing_harness;
use super::sql_faults::deny_once;
use super::workflow::{present_signals, signed_directive, signed_grant};
use super::*;

#[tokio::test]
async fn false_display_signals_and_away_desktop_hints_do_not_silence_phone_delivery() {
    for (connected, awake, remote, expected) in [
        (false, true, false, DeliveryMode::Banner),
        (true, false, false, DeliveryMode::Banner),
        (false, false, true, DeliveryMode::Silent),
    ] {
        let h = Harness::new();
        let mut signals = present_signals();
        signals.display_connected = Some(connected);
        signals.display_awake = Some(awake);
        signals.remote_session_active = Some(remote);
        *h.presence.0.lock().unwrap() = PresenceState {
            state: Presence::Present,
            since: h.clock.now(),
            signals,
            extra: Extra::new(),
        };
        h.helper.submit(h.input(Tier::T1, "A")).unwrap();
        let outgoing = h.helper.outbound_poll(0).await.unwrap();
        let bytes = envelope::open(
            &outgoing[0],
            &h.peer.device_id,
            key("recipient").as_ref(),
            &h.helper.local,
            h.clock.now(),
        )
        .unwrap();
        assert_eq!(
            from_json::<ApprovalRequest>(&bytes).unwrap().delivery.mode,
            expected
        );
    }
    let h = Harness::new();
    let mut desktop = h.peer.clone();
    desktop.device_id = "desktop".into();
    desktop.os = Os::Linux;
    let mut phone = h.peer.clone();
    phone.device_id = "phone".into();
    phone.os = Os::Ios;
    {
        let mut state = h.helper.lock().unwrap();
        state
            .store
            .insert_device(&desktop, "account", h.clock.now())
            .unwrap();
        state
            .store
            .insert_device(&phone, "account", h.clock.now())
            .unwrap();
        state.hints.insert(
            desktop.device_id.clone(),
            super::super::engine::Hint {
                hint: PresenceHint {
                    device_id: desktop.device_id.clone(),
                    state: Presence::Away,
                    since: h.clock.now(),
                    sent_at: h.clock.now(),
                    extra: Extra::new(),
                },
                received_at: h.clock.now(),
            },
        );
    }
    h.helper.submit(h.input(Tier::T1, "A")).unwrap();
    for outgoing in h.helper.outbound_poll(0).await.unwrap() {
        let bytes = envelope::open(
            &outgoing,
            &outgoing.to,
            key("recipient").as_ref(),
            &h.helper.local,
            h.clock.now(),
        )
        .unwrap();
        assert_eq!(
            from_json::<ApprovalRequest>(&bytes).unwrap().delivery.mode,
            DeliveryMode::Banner
        );
    }
}

#[test]
fn stored_classes_match_credential_and_host_and_reject_malformed_expiry() {
    for (criteria, expected) in [
        (
            json!({"credential":"github/**", "host":"API.GITHUB.COM"}),
            25,
        ),
        (
            json!({"credential":"different/**", "host":"api.github.com"}),
            600,
        ),
        (json!({"host":"different.example"}), 600),
        (json!({"credential":"github/**"}), 25),
    ] {
        let h = Harness::new();
        h.helper
            .lock()
            .unwrap()
            .store
            .set_setting(
                "classes",
                &json!({"fixture":{"match":criteria,"exp_s":25}}),
                "local",
                h.clock.now(),
            )
            .unwrap();
        let request = h.helper.submit(h.input(Tier::T1, "A")).unwrap();
        assert_eq!(request.exp - h.clock.now(), expected);
    }
    let h = Harness::new();
    h.helper
        .lock()
        .unwrap()
        .store
        .set_setting(
            "classes",
            &json!({"fixture":{"match":{},"exp_s":"invalid"}}),
            "local",
            h.clock.now(),
        )
        .unwrap();
    assert_eq!(
        h.helper
            .submit(h.input(Tier::T1, "A"))
            .err()
            .unwrap()
            .code(),
        "invalid_approval_class"
    );
    h.reason("invalid_approval_class");
}

#[tokio::test]
async fn an_offline_relay_returns_pending_before_a_positive_call_deadline() {
    let h = Harness::new();
    let request = h.helper.submit(h.input(Tier::T1, "A")).unwrap();
    let result = h
        .helper
        .wait(&request.approval_id, 1000, 50, 501, 4242)
        .await
        .unwrap();
    assert_eq!(result.status, ToolStatus::StillPending);
    assert_eq!(h.runner.calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn stop_exhaustion_is_audited_once_and_status_advertises_the_same_wait_policy() {
    let h = Harness::new();
    let request = h.helper.submit(h.input(Tier::T1, "A")).unwrap();
    for attempt in 0..6 {
        let response = h
            .helper
            .handle(
                CallerContext::authenticated(Caller::Hook, 501, 4242, 50),
                Request {
                    op: Op::PendingStopBlock,
                    params: json!({"approval_id":request.approval_id}),
                    extra: Extra::new(),
                },
            )
            .await;
        let value = serde_json::to_value(response).unwrap();
        assert_eq!(value["result"]["allowed"], attempt < 3);
    }
    assert_eq!(
        h.helper
            .audit_entries()
            .unwrap()
            .iter()
            .filter(|entry| entry["op"] == "stop_hook_exhausted")
            .count(),
        1
    );
    let value = serde_json::to_value(
        h.helper
            .handle(
                CallerContext::authenticated(Caller::Mcp, 501, 42, 50),
                Request {
                    op: Op::Status,
                    params: json!({}),
                    extra: Extra::new(),
                },
            )
            .await,
    )
    .unwrap();
    assert_eq!(
        value["result"]["approval"],
        json!({"wait_in_call_s":60,"wait_tool_max_s":600,"progress_interval_s":15})
    );
}

#[tokio::test]
async fn corrupted_grant_authority_and_invalid_policy_limits_never_install_wider_scope() {
    let h = Harness::new();
    let grant = signed_grant(&h, "unknown-authority", Tier::T1, 3);
    h.helper
        .install_grant(&grant, ApprovalLevel::Strong)
        .unwrap();
    h.helper
        .lock()
        .unwrap()
        .store
        .db
        .execute("UPDATE grants SET authority_json='{}'", [])
        .unwrap();
    let input = h.input(Tier::T1, "A");
    let usage = GrantUse {
        canonical: input.canonical.clone(),
        tier: Tier::T1,
        template_allowed_hosts: vec!["api.github.com".into()],
        policy_allowed_methods: vec![input.canonical.method.clone().unwrap()],
        body_bytes: 1,
        session_id: "session".into(),
    };
    assert!(h.helper.cover_and_debit(&usage).unwrap().jtis.is_empty());
    h.reason("unsupported_authority");
    for limits in [
        json!({"hosts":["api.github.com"],"methods":["POST"]}),
        json!({"hosts":"invalid"}),
        json!({"methods":[1]}),
    ] {
        let h = Harness::new();
        let mut input = h.input(Tier::T1, "A");
        input
            .canonical
            .extra
            .insert("grant_limits".into(), limits.clone());
        let request = h.helper.submit(input).unwrap();
        h.runner.alive.store(false, Ordering::SeqCst);
        let decision = h.decision(&request, ApprovalLevel::Strong, ScopeMode::PerCredential);
        let result = h
            .helper
            .inbound(h.envelope(
                EnvelopeType::ApprovalDecision,
                &request.approval_id,
                &decision,
            ))
            .await;
        if limits["hosts"].is_string() || limits["methods"][0].is_number() {
            assert_eq!(result.unwrap_err().code(), "invalid_json");
            h.reason("invalid_json");
            assert_eq!(
                h.helper
                    .lock()
                    .unwrap()
                    .store
                    .pending(&request.approval_id)
                    .unwrap()
                    .state,
                PendingState::Waiting
            );
        } else {
            result.unwrap();
            let state = h.helper.lock().unwrap();
            let encoded: String = state
                .store
                .db
                .query_row("SELECT object_json FROM grants", [], |row| row.get(0))
                .unwrap();
            let grant: Grant = super::super::store::decode(&encoded).unwrap();
            assert_eq!(
                grant.scope.hosts,
                Optional::Value(vec!["api.github.com".into()])
            );
            assert_eq!(grant.scope.methods, Optional::Value(vec!["POST".into()]));
        }
        assert_eq!(h.runner.calls.load(Ordering::SeqCst), 0);
    }
}

#[tokio::test]
async fn a_standing_grant_issuer_preserves_null_expiry_and_public_metadata() {
    let h = signing_harness();
    let mut grant = signed_grant(&h, "standing-issued", Tier::T1, 2);
    grant.iss = h.helper.local.device_id.clone();
    grant.aud = h.peer.device_id.clone();
    grant.exp = None;
    grant.budget = Optional::Null;
    grant.origin = "settings".into();
    let mut peer = h.peer.clone();
    peer.caps.push(Capability::Execute);
    h.helper
        .lock()
        .unwrap()
        .store
        .db
        .execute(
            "UPDATE devices SET record_json=?1 WHERE id=?2",
            params![encode(&peer).unwrap(), peer.device_id],
        )
        .unwrap();
    let response = h
        .helper
        .handle(
            CallerContext::authenticated(Caller::CliOwner, 501, 42, 50),
            Request {
                op: Op::GrantIssue,
                params: serde_json::to_value(kv_core::remote::ipc::Unsigned(grant)).unwrap(),
                extra: Extra::new(),
            },
        )
        .await;
    let value = serde_json::to_value(response).unwrap();
    assert_eq!(value["ok"], true, "{value}");
    assert!(value["result"]["grant"]["exp"].is_null());
    let outgoing = h.helper.outbound_poll(0).await.unwrap();
    assert_eq!(outgoing[0].exp, h.clock.now() + 86400);
}

#[tokio::test]
async fn pipeline_failures_are_audited_and_never_call_the_runner_after_audit_failure() {
    for case in 0..4 {
        let h = Harness::new();
        let mut input = h.input(Tier::T1, "A");
        let reason = match case {
            0 => {
                h.helper
                    .lock()
                    .unwrap()
                    .store
                    .db
                    .execute_batch("DROP TABLE grants")
                    .unwrap();
                "state_unavailable"
            }
            1 => {
                input.local_channel_available = true;
                *h.runner.level.lock().unwrap() = ApprovalLevel::Quick;
                input.tier = Tier::T2;
                h.audit.fail.store(true, Ordering::SeqCst);
                "audit_unavailable"
            }
            2 => {
                h.helper
                    .lock()
                    .unwrap()
                    .store
                    .db
                    .execute("UPDATE devices SET revoked_at=1", [])
                    .unwrap();
                h.audit.fail.store(true, Ordering::SeqCst);
                "audit_unavailable"
            }
            _ => {
                input.auto_allowed = true;
                input.tier = Tier::T0;
                h.audit.fail.store(true, Ordering::SeqCst);
                "audit_unavailable"
            }
        };
        assert_eq!(
            h.helper
                .run(
                    input,
                    vec!["api.github.com".into()],
                    vec!["POST".into()],
                    50
                )
                .await
                .unwrap_err()
                .code(),
            reason
        );
        assert_eq!(h.runner.calls.load(Ordering::SeqCst), 0);
        if case == 0 {
            h.reason(reason);
        }
    }
}

#[tokio::test]
async fn approver_wait_checks_unknown_ids_and_rechecks_storage_after_timer_yield() {
    let h = Harness::new();
    let mut request = h.helper.submit(h.input(Tier::T1, "A")).unwrap();
    request.approval_id = "unknown".into();
    assert_eq!(
        RemoteDevice {
            helper: h.helper.clone()
        }
        .approve(&request)
        .await
        .unwrap_err(),
        RemoteError::NotWaiting
    );
    let h = Harness::new();
    let request = h.helper.submit(h.input(Tier::T1, "A")).unwrap();
    let helper = h.helper.clone();
    let task = tokio::spawn(async move { RemoteDevice { helper }.approve(&request).await });
    tokio::task::yield_now().await;
    h.helper
        .lock()
        .unwrap()
        .store
        .db
        .execute_batch("DROP TABLE remote_outbox")
        .unwrap();
    assert_eq!(
        task.await.unwrap().unwrap_err(),
        RemoteError::KeyOperationFailed
    );
    h.reason("state_unavailable");
}

#[test]
fn pairing_rejects_unexpected_envelope_types_and_unrepresentable_candidate_fields() {
    for case in 0..2 {
        let h = Harness::with(
            Store::memory().unwrap(),
            fixture("decision_valid.json")["now"].as_i64().unwrap(),
            false,
        );
        let offer = h.helper.pair_start("https://relay.example").unwrap();
        let reason = if case == 0 {
            let envelope = h.envelope(EnvelopeType::Grant, "pair", &json!({}));
            assert_eq!(
                h.helper
                    .receive_pairing(&mut h.helper.lock().unwrap(), &envelope)
                    .unwrap_err()
                    .code(),
                "unsupported_type"
            );
            "unsupported_type"
        } else {
            let mut peer = h.peer.clone();
            peer.dk_pub
                .extra
                .insert("unrepresentable".into(), json!(9007199254740993u64));
            let accept = PairAccept {
                token: offer.extra["token"].as_str().unwrap().into(),
                joiner: peer,
                extra: Extra::new(),
            };
            assert_eq!(
                h.helper.pair_complete(accept).unwrap_err().code(),
                "invalid_json"
            );
            "invalid_json"
        };
        h.reason(reason);
        assert!(h.helper.lock().unwrap().pairing.is_none());
    }
}

#[test]
fn device_validation_accepts_recorded_rs256_and_request_labels_all_key_protection_kinds() {
    let rsa: DeviceRecord =
        serde_json::from_value(fixture("rs256_decision.json")["device"].clone()).unwrap();
    super::super::engine::validate_device(&rsa).unwrap();
    for (kind, expected) in [
        (KeyKind::WindowsHello, ProtectionKind::WindowsHello),
        (KeyKind::PcpTpm, ProtectionKind::WindowsHello),
        (
            KeyKind::Unknown("future_hardware".into()),
            ProtectionKind::Unknown("future_hardware".into()),
        ),
    ] {
        let mut h = Harness::new();
        Arc::get_mut(&mut h.helper).unwrap().local.key_kind = kind;
        assert_eq!(
            h.helper
                .submit(h.input(Tier::T1, "A"))
                .unwrap()
                .requester
                .protection
                .kind,
            expected
        );
    }
}

#[test]
fn a_poisoned_state_clears_unclaimed_results_as_well_as_original_bodies() {
    let h = Harness::new();
    h.helper.submit(h.input(Tier::T1, "A")).unwrap();
    h.helper
        .lock()
        .unwrap()
        .results
        .insert("orphan".into(), json!({"result":"synthetic secret"}));
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _state = h.helper.state.lock().unwrap();
        panic!("simulated worker failure");
    }));
    assert_eq!(h.helper.lock().err().unwrap().code(), "state_unavailable");
    let state = h.helper.state.lock().err().unwrap().into_inner();
    assert!(state.full.is_empty());
    assert!(state.results.is_empty());
}

#[tokio::test]
async fn t2_budget_audit_failure_rolls_back_every_debit() {
    for at in 1..180 {
        let h = Harness::new();
        let grant = signed_grant(&h, "t2-fault", Tier::T2, 3);
        h.helper
            .install_grant(&grant, ApprovalLevel::Strong)
            .unwrap();
        let input = h.input(Tier::T2, "A");
        let usage = GrantUse {
            canonical: input.canonical.clone(),
            tier: Tier::T2,
            template_allowed_hosts: vec!["api.github.com".into()],
            policy_allowed_methods: vec![input.canonical.method.unwrap()],
            body_bytes: 1,
            session_id: "session".into(),
        };
        let denied = deny_once(&h.helper, at);
        let result = h.helper.cover_and_debit(&usage);
        if !denied.load(Ordering::SeqCst) {
            result.unwrap();
            break;
        }
        match result {
            Err(error) => assert_eq!(error.code(), "state_unavailable"),
            Ok(coverage) => assert!(coverage.jtis.is_empty()),
        }
        h.reason("state_unavailable");
        let encoded: Option<String> = h
            .helper
            .lock()
            .unwrap()
            .store
            .db
            .query_row("SELECT budget_left_json FROM grants", [], |r| r.get(0))
            .unwrap();
        assert!(
            encoded.is_none(),
            "a failed transaction persisted a budget debit"
        );
    }
}

#[test]
fn lock_and_revocation_storage_failures_do_not_leave_partial_authority() {
    for revoke in [false, true] {
        for at in 1..260 {
            let h = Harness::new();
            let request = h.helper.submit(h.input(Tier::T1, "A")).unwrap();
            let decision = h.decision(&request, ApprovalLevel::Strong, ScopeMode::PerCredential);
            h.runner.alive.store(false, Ordering::SeqCst);
            h.helper
                .accept_decision(
                    &mut h.helper.lock().unwrap(),
                    &h.peer,
                    &decision,
                    h.clock.now(),
                    h.clock.now(),
                )
                .unwrap();
            let directive =
                signed_directive(&h, DirectiveOp::Lock, json!({}), ApprovalLevel::Quick);
            let denied = deny_once(&h.helper, at);
            let result = if revoke {
                h.helper.revoke_device(&h.peer.device_id, "local")
            } else {
                h.helper
                    .apply_directive(&directive, ApprovalLevel::Quick)
                    .map(|_| ())
            };
            if !denied.load(Ordering::SeqCst) {
                result.unwrap();
                break;
            }
            assert_eq!(result.unwrap_err().code(), "state_unavailable");
            h.reason("state_unavailable");
            let state = h.helper.lock().unwrap();
            assert!(state.store.device(&h.peer.device_id, "account").is_ok());
            assert_eq!(
                state.store.pending(&request.approval_id).unwrap().state,
                PendingState::ApprovedUnused
            );
        }
    }
}
