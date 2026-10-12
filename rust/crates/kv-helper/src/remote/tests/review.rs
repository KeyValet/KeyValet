use super::boundaries::signing_harness;
use super::workflow::{signed_directive, signed_grant};
use super::*;
use kv_core::remote::validation::verify_decision;

fn accept_without_scheduling(h: &Harness, request: &ApprovalRequest, scope: ScopeMode) {
    let decision = h.decision(request, ApprovalLevel::Strong, scope);
    let mut state = h.helper.lock().unwrap();
    h.helper
        .accept_decision(&mut state, &h.peer, &decision, h.clock.now(), h.clock.now())
        .unwrap();
}

#[tokio::test]
async fn corrupted_snapshot_fields_are_checked_even_when_the_digest_is_self_consistent() {
    for variant in 0..4 {
        let h = Harness::new();
        let mut request = h.helper.submit(h.input(Tier::T1, "A")).unwrap();
        let mut canonical = h
            .helper
            .lock()
            .unwrap()
            .store
            .pending(&request.approval_id)
            .unwrap()
            .canonical;
        match variant {
            0 => canonical.exp += 1,
            1 => canonical.kind = ApprovalKind::Admin,
            2 => canonical.requester = "another-device".into(),
            _ => canonical.nonce = "different".into(),
        }
        request.digest = canonical.digest().unwrap();
        h.helper
            .lock()
            .unwrap()
            .store
            .db
            .execute(
                "UPDATE pending_approvals SET canonical_json=?1, request_json=?2",
                params![encode(&canonical).unwrap(), encode(&request).unwrap()],
            )
            .unwrap();
        let decision = h.decision(&request, ApprovalLevel::Strong, ScopeMode::PerUse);
        let error = h
            .helper
            .inbound(h.envelope(
                EnvelopeType::ApprovalDecision,
                &request.approval_id,
                &decision,
            ))
            .await
            .unwrap_err();
        let reason = if variant == 3 {
            "nonce_mismatch"
        } else {
            "digest_mismatch"
        };
        assert_eq!(error.code(), reason);
        h.reason(reason);
        assert_eq!(h.runner.calls.load(Ordering::SeqCst), 0);
    }
}

#[test]
fn display_and_request_identity_failures_are_audited_before_delivery() {
    for variant in 0..11 {
        let h = Harness::new();
        let mut input = h.input(Tier::T1, "A");
        let expected = match variant {
            0 => {
                input.canonical.v = 2;
                "invalid_request_identity"
            }
            1 => {
                input.canonical.requester = "other".into();
                "invalid_request_identity"
            }
            2 => {
                input.canonical.agent.pid = 0;
                "invalid_request_identity"
            }
            3 => {
                input.session_id.clear();
                "invalid_request_identity"
            }
            4..=6 => {
                input.canonical.kind = ApprovalKind::Unlock;
                input.credential = None;
                input.operation = None;
                if variant != 6 {
                    input.canonical.credential = None;
                }
                if variant == 4 {
                    input.credential = h.input(Tier::T1, "A").credential;
                }
                if variant == 5 {
                    input.operation = h.input(Tier::T1, "A").operation;
                }
                "invalid_approval_request"
            }
            7 => {
                input.operation.as_mut().unwrap().method = "DELETE".into();
                "digest_mismatch"
            }
            8 => {
                input.operation.as_mut().unwrap().host = "other.example".into();
                "digest_mismatch"
            }
            9 => {
                input.operation.as_mut().unwrap().path = "/other".into();
                "digest_mismatch"
            }
            _ => {
                input
                    .operation
                    .as_mut()
                    .unwrap()
                    .query_keys
                    .push("other".into());
                "digest_mismatch"
            }
        };
        assert_eq!(h.helper.submit(input).unwrap_err().code(), expected);
        h.reason(expected);
        assert!(h
            .helper
            .lock()
            .unwrap()
            .store
            .pending_ids()
            .unwrap()
            .is_empty());
    }
}

#[tokio::test]
async fn directive_sender_broadcast_and_duplicate_result_are_bound_to_one_issued_operation() {
    let h = Harness::new();
    let mut directive = signed_directive(
        &h,
        DirectiveOp::QueryStatus,
        json!({}),
        ApprovalLevel::Quick,
    );
    directive.iss = "other-device".into();
    directive.sig =
        sign_object(&directive, SignatureAlgorithm::ES256, key("quick").as_ref()).unwrap();
    h.helper
        .inbound(h.envelope(EnvelopeType::Directive, &directive.id, &directive))
        .await
        .unwrap();
    h.reason("wrong_sender");
    let mut directive = signed_directive(
        &h,
        DirectiveOp::QueryStatus,
        json!({}),
        ApprovalLevel::Quick,
    );
    directive.aud = "*".into();
    directive.sig =
        sign_object(&directive, SignatureAlgorithm::ES256, key("quick").as_ref()).unwrap();
    assert!(
        h.helper
            .apply_directive(&directive, ApprovalLevel::Quick)
            .unwrap()
            .ok
    );
    let result = DirectiveResult {
        id: "issued".into(),
        ok: true,
        error: None,
        state: Extra::new(),
        extra: Extra::new(),
    };
    h.helper
        .lock()
        .unwrap()
        .store
        .db
        .execute(
            "INSERT INTO issued_directives (id,peer,op,issued_at) VALUES (?1,?2,'query_state',?3)",
            params![result.id, h.peer.device_id, h.clock.now()],
        )
        .unwrap();
    h.helper
        .inbound(h.envelope(EnvelopeType::DirectiveResult, &result.id, &result))
        .await
        .unwrap();
    let mut other = result.clone();
    other.ok = false;
    assert_eq!(
        h.helper
            .inbound(h.envelope(EnvelopeType::DirectiveResult, &result.id, &other))
            .await
            .unwrap_err()
            .code(),
        "already_consumed"
    );
    h.reason("already_consumed");
    assert!(h.helper.lock().unwrap().directive_results[&result.id].1.ok);
    assert_eq!(
        h.helper
            .inbound(h.envelope(EnvelopeType::DirectiveResult, "wrong-id", &result))
            .await
            .unwrap_err()
            .code(),
        "unexpected_directive_result"
    );
    h.reason("unexpected_directive_result");
}

#[tokio::test]
async fn execution_completion_cleans_values_after_expiry_audit_failure_or_missing_pending() {
    for variant in 0..3 {
        let h = Harness::new();
        let request = h.helper.submit(h.input(Tier::T1, "A")).unwrap();
        accept_without_scheduling(&h, &request, ScopeMode::PerUse);
        let helper = h.helper.clone();
        let clock = h.clock.clone();
        let audit = h.audit.clone();
        let id = request.approval_id.clone();
        *h.runner.after_execute.lock().unwrap() = Some(Box::new(move || match variant {
            0 => clock.0.store(request.exp + 1, Ordering::SeqCst),
            1 => audit.fail.store(true, Ordering::SeqCst),
            _ => {
                helper
                    .lock()
                    .unwrap()
                    .store
                    .db
                    .execute("DELETE FROM pending_approvals WHERE id=?1", [&id])
                    .unwrap();
            }
        }));
        let result = h.helper.execute_approved(&request.approval_id).await;
        if variant == 0 {
            result.unwrap();
        } else {
            assert_eq!(
                result.unwrap_err().code(),
                if variant == 1 {
                    "audit_unavailable"
                } else {
                    "not_waiting"
                }
            );
        }
        assert_eq!(h.runner.calls.load(Ordering::SeqCst), 1);
        assert!(h.helper.lock().unwrap().results.is_empty());
    }
}

#[tokio::test]
async fn timer_drops_retained_bodies_on_storage_failure_and_exits_when_helper_is_dropped() {
    let h = Harness::new();
    h.helper.submit(h.input(Tier::T1, "A")).unwrap();
    h.helper
        .lock()
        .unwrap()
        .results
        .insert("orphan".into(), json!({"marker":"clear on failure"}));
    h.helper
        .lock()
        .unwrap()
        .store
        .db
        .execute_batch("DROP TABLE remote_outbox")
        .unwrap();
    let timer = h.helper.start_timer();
    tokio::time::timeout(std::time::Duration::from_secs(3), async {
        loop {
            if h.helper.lock().unwrap().full.is_empty() {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    timer.abort();
    let h = Harness::new();
    let timer = h.helper.start_timer();
    drop(h);
    tokio::time::timeout(std::time::Duration::from_secs(3), timer)
        .await
        .unwrap()
        .unwrap();
}

#[test]
fn stored_derived_authority_cannot_expand_any_original_signed_field() {
    for variant in 0..7 {
        let h = Harness::new();
        let request = h.helper.submit(h.input(Tier::T1, "A")).unwrap();
        accept_without_scheduling(&h, &request, ScopeMode::PerCredential);
        let state = h.helper.lock().unwrap();
        let (object, authority): (String, String) = state
            .store
            .db
            .query_row("SELECT object_json,authority_json FROM grants", [], |r| {
                Ok((r.get(0)?, r.get(1)?))
            })
            .unwrap();
        let mut grant: Grant = super::super::store::decode(&object).unwrap();
        let mut authority: Value = super::super::store::decode(&authority).unwrap();
        let mut decision: ApprovalDecision =
            serde_json::from_value(authority["decision"].clone()).unwrap();
        match variant {
            0 => decision.sig = "invalid".into(),
            1 => {
                decision.decision = Decision::Deny;
                decision.sig =
                    sign_object(&decision, SignatureAlgorithm::ES256, key("strong").as_ref())
                        .unwrap();
            }
            2 => {
                let mut canonical: CanonicalRequest =
                    serde_json::from_value(authority["canonical"].clone()).unwrap();
                canonical.purpose = "another purpose".into();
                decision.digest = canonical.digest().unwrap();
                decision.sig =
                    sign_object(&decision, SignatureAlgorithm::ES256, key("strong").as_ref())
                        .unwrap();
                authority["canonical"] = json!(canonical);
                authority["request"]["digest"] = json!(decision.digest);
            }
            3 => authority["request"]["future"] = json!(true),
            4 => {
                let mut changed = decision.clone();
                changed.reason = Optional::Value("different".into());
                state
                    .store
                    .db
                    .execute(
                        "UPDATE pending_approvals SET decision_json=?1",
                        [encode(&changed).unwrap()],
                    )
                    .unwrap();
            }
            5 => {
                state
                    .store
                    .db
                    .execute("UPDATE grants SET session_id='different'", [])
                    .unwrap();
            }
            _ => {
                grant.exp = Some(h.clock.now() + 86400);
            }
        }
        authority["decision"] = json!(decision);
        if variant != 0 {
            let req: ApprovalRequest =
                serde_json::from_value(authority["request"].clone()).unwrap();
            let canonical: CanonicalRequest =
                serde_json::from_value(authority["canonical"].clone()).unwrap();
            verify_decision(&decision, &req, &canonical, &h.peer, h.clock.now()).unwrap();
        }
        state
            .store
            .db
            .execute(
                "UPDATE grants SET object_json=?1,authority_json=?2",
                params![encode(&grant).unwrap(), encode(&authority).unwrap()],
            )
            .unwrap();
        let canonical = state.store.pending(&request.approval_id).unwrap().canonical;
        drop(state);
        let coverage = h
            .helper
            .cover_and_debit(&GrantUse {
                canonical,
                tier: Tier::T1,
                template_allowed_hosts: vec!["api.github.com".into()],
                policy_allowed_methods: vec!["GET".into()],
                body_bytes: 0,
                session_id: "session".into(),
            })
            .unwrap();
        assert!(coverage.jtis.is_empty(), "variant {variant}");
        h.reason("invalid_grant");
    }
}

#[tokio::test]
async fn local_pipeline_requires_strong_unlock_and_t1_auto_flag_does_not_skip_approval() {
    let h = Harness::new();
    *h.runner.level.lock().unwrap() = ApprovalLevel::Quick;
    let mut input = h.input(Tier::T1, "A");
    input.auto_allowed = true;
    input.local_channel_available = true;
    assert_eq!(
        h.helper
            .run(input, vec![], vec![], 50)
            .await
            .unwrap()
            .status,
        ToolStatus::Ok
    );
    let mut input = h.input(Tier::T1, "A");
    input.canonical.kind = ApprovalKind::Unlock;
    input.credential = None;
    input.operation = None;
    input.canonical.credential = None;
    input.local_channel_available = true;
    assert_eq!(
        h.helper
            .run(input, vec![], vec![], 50)
            .await
            .unwrap_err()
            .code(),
        "insufficient_level"
    );
    h.reason("insufficient_level");
}

#[tokio::test]
async fn local_decision_scope_must_be_offered_and_t2_stays_per_use() {
    for (tier, scope) in [
        (Tier::T2, ScopeMode::PerCredential),
        (Tier::T1, ScopeMode::Standing),
    ] {
        let h = signing_harness();
        let mut request: ApprovalRequest =
            serde_json::from_value(fixture("decision_valid.json")["request"].clone()).unwrap();
        request.requester.device_id = h.peer.device_id.clone();
        request.tier = tier;
        request.scope_options = vec![ScopeOption::PerUse];
        let id = request.approval_id.clone();
        h.helper
            .inbound(h.envelope(EnvelopeType::ApprovalRequest, &id, &request))
            .await
            .unwrap();
        let mut scope = json!(h.decision(&request, ApprovalLevel::Strong, scope).scope);
        if tier == Tier::T1 {
            scope["level"] = json!("credential");
        }
        let response = h
            .exchange(
                Caller::CliOwner,
                Op::Decide,
                json!({"approval_id":id,"decision":"allow","level":"strong","scope":scope}),
            )
            .await;
        assert_eq!(response["error"]["code"], "invalid_scope");
        h.reason("invalid_scope");
    }
}

#[test]
fn pairing_sas_mismatch_in_terminal_or_signed_confirmation_discards_the_candidate() {
    for signed in [false, true] {
        let h = Harness::with(Store::memory().unwrap(), 1_800_000_000, false);
        let offer = h.helper.pair_start("https://relay.example.org").unwrap();
        h.helper
            .pair_complete(PairAccept {
                token: offer.extra["token"].as_str().unwrap().into(),
                joiner: h.peer.clone(),
                extra: Extra::new(),
            })
            .unwrap();
        let confirm = if signed {
            kv_core::remote::pairing::sign_confirm(
                "000000",
                SignatureAlgorithm::ES256,
                key("strong").as_ref(),
            )
            .unwrap()
        } else {
            PairConfirm {
                sas: "000000".into(),
                sig: String::new(),
                extra: Extra::new(),
            }
        };
        let result = if signed {
            h.helper.pair_confirm_signed(&confirm)
        } else {
            h.helper.pair_confirm_terminal(&confirm)
        };
        assert_eq!(result.unwrap_err().code(), "pair_sas_mismatch");
        h.reason("pair_sas_mismatch");
        assert!(h.helper.lock().unwrap().pairing.is_none());
    }
}

#[test]
fn non_regular_database_file_is_rejected_without_opening_sqlite() {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.sqlite");
        let bytes = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(bytes.as_ptr(), 0o600) }, 0);
        assert!(Store::open(&path).is_err());
        assert_eq!(
            super::super::store::validate_file(&std::fs::symlink_metadata(&path).unwrap())
                .unwrap_err()
                .code(),
            "untrusted_state_file"
        );
    }
}

#[tokio::test]
async fn pending_queries_filter_completed_claimed_and_other_user_entries() {
    let h = Harness::new();
    for (index, uid, state, claimed) in [
        (0, 502, "waiting", false),
        (1, 501, "denied", false),
        (2, 501, "approved", true),
    ] {
        let mut input = h.input(Tier::T1, &index.to_string());
        input.canonical.agent.uid = uid;
        let request = h.helper.submit(input).unwrap();
        h.helper
            .lock()
            .unwrap()
            .store
            .db
            .execute(
                "UPDATE pending_approvals SET state=?1,claimed_at=?2 WHERE id=?3",
                params![state, claimed.then_some(h.clock.now()), request.approval_id],
            )
            .unwrap();
        if index == 2 {
            assert_eq!(
                h.exchange(
                    Caller::Hook,
                    Op::PendingStopBlock,
                    json!({"approval_id":request.approval_id})
                )
                .await["result"]["allowed"],
                false
            );
        }
    }
    assert!(
        h.exchange(Caller::Mcp, Op::PendingList, json!({})).await["result"]["pending"]
            .as_array()
            .unwrap()
            .iter()
            .all(|r| r["agent"]["user"] == "501")
    );
    assert!(h
        .exchange(Caller::Hook, Op::PendingForAgent, json!({"agent_pid":4242}))
        .await["result"]["pending"]
        .as_array()
        .unwrap()
        .is_empty());
    let h = Harness::new();
    let request = h.helper.submit(h.input(Tier::T1, "A")).unwrap();
    assert_eq!(
        h.helper
            .result(&request.approval_id, 501, 999, false)
            .unwrap_err()
            .code(),
        "forbidden"
    );
    h.helper
        .lock()
        .unwrap()
        .store
        .db
        .execute("UPDATE pending_approvals SET state='executed'", [])
        .unwrap();
    assert_eq!(
        h.helper
            .result(&request.approval_id, 501, 4242, false)
            .unwrap()
            .status,
        ToolStatus::AlreadyConsumed
    );
    let mut state = h.helper.lock().unwrap();
    state.executing.insert(request.approval_id.clone());
    assert_eq!(
        h.helper
            .result_locked(&mut state, &request.approval_id, false)
            .unwrap()
            .status,
        ToolStatus::StillPending
    );
    state.executing.clear();
    assert_eq!(
        h.helper
            .cancel_locked(&mut state, &request.approval_id, PendingState::Cancelled)
            .unwrap_err()
            .code(),
        "already_consumed"
    );
    drop(state);
    h.helper.close_session("unrelated").unwrap();
}

#[tokio::test]
async fn outbox_polls_bound_count_and_bytes_and_durable_receipts_prevent_redelivery() {
    let h = Harness::new();
    let mut envelope = h.envelope(
        EnvelopeType::ApprovalCancel,
        "queued",
        &ApprovalCancel {
            approval_id: "queued".into(),
            extra: Extra::new(),
        },
    );
    {
        let state = h.helper.lock().unwrap();
        for index in 0..65 {
            let outgoing = h.envelope(
                EnvelopeType::ApprovalCancel,
                &format!("queued-{index}"),
                &ApprovalCancel {
                    approval_id: format!("queued-{index}"),
                    extra: Extra::new(),
                },
            );
            state.store.queue(&outgoing).unwrap();
        }
    }
    let outgoing = h.helper.outbound_poll(0).await.unwrap();
    assert_eq!(outgoing.len(), 64);
    h.spooled(&outgoing);
    let remaining = h.helper.outbound_poll(0).await.unwrap();
    assert_eq!(remaining.len(), 1);
    h.spooled(&remaining);
    h.exchange(
        Caller::RelayClient,
        Op::RelayStatus,
        json!({"connected":true}),
    )
    .await;
    h.exchange(
        Caller::RelayClient,
        Op::RelayStatus,
        json!({"connected":true}),
    )
    .await;
    assert!(h.helper.outbound_poll(0).await.unwrap().is_empty());
    envelope.ct = "A".repeat(kv_ipc::MAX_LINE_BYTES);
    h.helper.lock().unwrap().store.queue(&envelope).unwrap();
    assert!(h.helper.outbound_poll(0).await.unwrap().is_empty());
}

#[tokio::test]
async fn receiver_rejects_mismatched_directive_id_and_foreign_result_peer() {
    let h = Harness::new();
    let directive = signed_directive(
        &h,
        DirectiveOp::QueryStatus,
        json!({}),
        ApprovalLevel::Quick,
    );
    assert_eq!(
        h.helper
            .inbound(h.envelope(EnvelopeType::Directive, "wrong", &directive))
            .await
            .unwrap_err()
            .code(),
        "invalid_directive"
    );
    h.reason("invalid_directive");
    h.helper.lock().unwrap().store.db.execute("INSERT INTO issued_directives(id,peer,op,issued_at) VALUES ('foreign','other','query_status',1)",[]).unwrap();
    let result = DirectiveResult {
        id: "foreign".into(),
        ok: true,
        error: None,
        state: Extra::new(),
        extra: Extra::new(),
    };
    assert_eq!(
        h.helper
            .inbound(h.envelope(EnvelopeType::DirectiveResult, &result.id, &result))
            .await
            .unwrap_err()
            .code(),
        "unexpected_directive_result"
    );
    h.reason("unexpected_directive_result");
    let mut device = h.peer.clone();
    device.caps.clear();
    device.ak_q = None;
    device.ak_s = None;
    h.helper
        .lock()
        .unwrap()
        .store
        .db
        .execute(
            "UPDATE devices SET record_json=?1",
            [encode(&device).unwrap()],
        )
        .unwrap();
    h.helper
        .inbound(h.envelope(
            EnvelopeType::PresenceHint,
            "hint",
            &PresenceHint {
                device_id: h.peer.device_id.clone(),
                state: Presence::Away,
                sent_at: h.clock.now(),
                since: h.clock.now(),
                extra: Extra::new(),
            },
        ))
        .await
        .unwrap();
    let request = h.input(Tier::T1, "A");
    let mut canonical = request.canonical.clone();
    canonical.nonce = "nonce".into();
    canonical.exp = h.clock.now() + 600;
    let pending: ApprovalRequest =
        serde_json::from_value(fixture("decision_valid.json")["request"].clone()).unwrap();
    let mut pending = pending;
    pending.digest = canonical.digest().unwrap();
    pending.nonce = canonical.nonce.clone();
    pending.exp = canonical.exp;
    h.seed(&pending, &canonical);
    assert!(h
        .helper
        .result(&pending.approval_id, 501, 4242, false)
        .unwrap()
        .approver
        .as_value()
        .is_none());
}

#[test]
fn device_wide_grant_and_non_http_use_require_no_unstated_host_or_method() {
    let h = Harness::new();
    let mut grant = signed_grant(&h, "wide", Tier::T1, 10);
    grant.scope.level = GrantScopeLevel::Device;
    grant.scope.credential = Optional::Null;
    grant.scope.hosts = Optional::Null;
    grant.scope.methods = Optional::Null;
    grant.scope.paths = Optional::Null;
    grant.sig = sign_object(&grant, SignatureAlgorithm::ES256, key("strong").as_ref()).unwrap();
    h.helper
        .install_grant(&grant, ApprovalLevel::Strong)
        .unwrap();
    let mut canonical = h.input(Tier::T1, "A").canonical;
    canonical.host = None;
    canonical.method = None;
    canonical.path = None;
    canonical.query_keys.clear();
    assert_eq!(
        h.helper
            .cover_and_debit(&GrantUse {
                canonical,
                tier: Tier::T1,
                template_allowed_hosts: vec![],
                policy_allowed_methods: vec![],
                body_bytes: 0,
                session_id: "session".into()
            })
            .unwrap()
            .jtis,
        vec!["wide"]
    );
    let full = FullRequest::new(
        "use",
        json!({"body":"kept","approval_id":"removed","runtime_budget_s":10})
            .as_object()
            .unwrap()
            .clone(),
    )
    .unwrap();
    assert_eq!(
        full.params().unwrap(),
        json!({"body":"kept"}).as_object().unwrap().clone()
    );
    for state in [
        PendingState::Waiting,
        PendingState::Approved,
        PendingState::ApprovedUnused,
        PendingState::Executed,
        PendingState::Denied,
        PendingState::Expired,
        PendingState::Cancelled,
    ] {
        assert!(!state.as_str().is_empty());
    }
    let mut input = h.input(Tier::T1, "B");
    input.credential.as_mut().unwrap().r#ref = "other".into();
    assert_eq!(
        h.helper.submit(input).unwrap_err().code(),
        "digest_mismatch"
    );
    h.reason("digest_mismatch");
    let mut input = h.input(Tier::T1, "C");
    input.operation = None;
    h.helper.submit(input).unwrap();
}

#[test]
fn native_vault_audit_sink_writes_only_metadata_to_a_temporary_vault() {
    let directory = tempfile::tempdir().unwrap();
    let vault = kv_vault::Vault::new(directory.path().join("vault"));
    kv_platform::fs::ensure_private_dir(&vault.dir).unwrap();
    AuditSink::append(
        &vault,
        json!({"op":"remote_test","approval_id":"metadata"})
            .as_object()
            .unwrap()
            .clone(),
    )
    .unwrap();
    let path = vault.dir.join("audit.log");
    assert!(path.exists());
}

#[tokio::test]
async fn relay_wrong_protocol_and_signing_algorithm_failures_are_audited() {
    let h = Harness::new();
    let result = super::super::server::serve(
        std::io::Cursor::new(b"{\"op\":\"relay\",\"protocol\":1}\n"),
        tokio::io::sink(),
        CallerContext::authenticated(Caller::RelayClient, 501, 4242, 50),
        Some(h.helper.clone()),
    )
    .await;
    assert_eq!(result.unwrap_err().code(), "forbidden");
    h.reason("forbidden");
    for alg in [SignatureAlgorithm::ES256, SignatureAlgorithm::RS256] {
        let mut grant = signed_grant(&h, "invalid", Tier::T1, 1);
        grant.iss_alg = alg;
        grant.sig = kv_core::remote::keys::encode_b64(&[0; 64]);
        assert_eq!(
            h.helper
                .inbound(h.envelope(EnvelopeType::Grant, &grant.jti, &grant))
                .await
                .unwrap_err()
                .code(),
            if alg == SignatureAlgorithm::ES256 {
                "invalid_signature"
            } else {
                "unsupported_algorithm"
            }
        );
        h.reason(if alg == SignatureAlgorithm::ES256 {
            "invalid_signature"
        } else {
            "unsupported_algorithm"
        });
        let mut directive = signed_directive(
            &h,
            DirectiveOp::QueryStatus,
            json!({}),
            ApprovalLevel::Quick,
        );
        directive.iss_alg = alg;
        directive.sig = kv_core::remote::keys::encode_b64(&[0; 64]);
        h.helper
            .inbound(h.envelope(EnvelopeType::Directive, &directive.id, &directive))
            .await
            .unwrap();
        h.reason(if alg == SignatureAlgorithm::ES256 {
            "invalid_signature"
        } else {
            "unsupported_algorithm"
        });
    }
    let h = Harness::with(Store::memory().unwrap(), 1_800_000_000, false);
    let offer = h.helper.pair_start("https://relay.example.org").unwrap();
    let sas = h
        .helper
        .pair_complete(PairAccept {
            token: offer.extra["token"].as_str().unwrap().into(),
            joiner: h.peer.clone(),
            extra: Extra::new(),
        })
        .unwrap()
        .sas;
    assert_eq!(
        h.helper
            .pair_confirm_signed(&PairConfirm {
                sas: sas.clone(),
                sig: kv_core::remote::keys::encode_b64(&[0; 64]),
                extra: Extra::new()
            })
            .unwrap_err()
            .code(),
        "invalid_signature"
    );
    h.reason("invalid_signature");
    h.helper.pair_start("https://relay.example.org").unwrap();
    assert_eq!(
        h.helper
            .pair_confirm_terminal(&PairConfirm {
                sas,
                sig: "not-empty".into(),
                extra: Extra::new()
            })
            .unwrap_err()
            .code(),
        "pair_sas_mismatch"
    );
    h.reason("pair_sas_mismatch");
}

#[tokio::test]
async fn decision_issuer_accepts_every_offered_scope_and_rechecks_prompt_races() {
    for (mode, level, seconds) in [
        (ScopeMode::PerUse, DecisionScopeLevel::Credential, 0),
        (ScopeMode::PerCredential, DecisionScopeLevel::Credential, 0),
        (ScopeMode::PerSession, DecisionScopeLevel::Credential, 0),
        (ScopeMode::Remember, DecisionScopeLevel::Credential, 3600),
        (ScopeMode::Remember, DecisionScopeLevel::Credential, 28800),
        (ScopeMode::Remember, DecisionScopeLevel::Credential, 86400),
        (ScopeMode::Standing, DecisionScopeLevel::Device, 0),
        (ScopeMode::Remember, DecisionScopeLevel::Device, 3600),
    ] {
        let h = signing_harness();
        let mut request: ApprovalRequest =
            serde_json::from_value(fixture("decision_valid.json")["request"].clone()).unwrap();
        request.requester.device_id = h.peer.device_id.clone();
        if mode == ScopeMode::PerUse {
            request.tier = Tier::T2;
        }
        let id = request.approval_id.clone();
        h.helper
            .inbound(h.envelope(EnvelopeType::ApprovalRequest, &id, &request))
            .await
            .unwrap();
        let response=h.exchange(Caller::CliOwner,Op::Decide,json!({"approval_id":id,"decision":"allow","level":"strong","scope":{"mode":mode,"level":level,"until":if seconds==0 {0}else{h.clock.now()+seconds}}})).await;
        if mode == ScopeMode::Remember && level == DecisionScopeLevel::Device {
            assert_eq!(response["error"]["code"], "invalid_scope");
            h.reason("invalid_scope");
        } else {
            assert_eq!(response["ok"], true, "{response}");
        }
    }
    for variant in 0..3 {
        let h = signing_harness();
        let mut request: ApprovalRequest =
            serde_json::from_value(fixture("decision_valid.json")["request"].clone()).unwrap();
        request.requester.device_id = h.peer.device_id.clone();
        if variant == 2 {
            request.kind = ApprovalKind::Unlock;
            request.credential = None;
            request.operation = None;
        }
        let id = request.approval_id.clone();
        h.helper
            .inbound(h.envelope(EnvelopeType::ApprovalRequest, &id, &request))
            .await
            .unwrap();
        let helper = h.helper.clone();
        let clock = h.clock.clone();
        let target = id.clone();
        let exp = request.exp;
        *h.runner.after_authorize.lock().unwrap() = Some(Box::new(move || {
            if variant == 0 {
                helper.lock().unwrap().inbound_requests.remove(&target);
            } else {
                clock.0.store(exp + 1, Ordering::SeqCst);
            }
        }));
        let response=h.exchange(Caller::CliOwner,Op::Decide,json!({"approval_id":id,"decision":"allow","level":"strong","scope":{"mode":"per_use","level":"credential","until":0}})).await;
        let expected = if variant == 0 {
            "not_waiting"
        } else {
            "expired"
        };
        assert_eq!(response["error"]["code"], expected);
        h.reason(expected);
    }
}

fn poison(helper: &RemoteHelper) {
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _guard = helper.state.lock().unwrap();
        panic!("test state poisoning");
    }));
    assert!(result.is_err());
}

#[tokio::test]
async fn poisoned_state_denies_clears_bodies_and_never_recovers_authority() {
    for failure in [false, true] {
        let h = Harness::new();
        let request = h.helper.submit(h.input(Tier::T1, "A")).unwrap();
        accept_without_scheduling(&h, &request, ScopeMode::PerUse);
        let helper = h.helper.clone();
        *h.runner.after_execute.lock().unwrap() = Some(Box::new(move || poison(&helper)));
        h.runner.fail.store(failure, Ordering::SeqCst);
        assert_eq!(
            h.helper
                .execute_approved(&request.approval_id)
                .await
                .unwrap_err()
                .code(),
            "state_unavailable"
        );
        assert_eq!(
            h.helper.submit(h.input(Tier::T1, "B")).unwrap_err().code(),
            "state_unavailable"
        );
        assert_eq!(
            h.exchange(Caller::Mcp, Op::DevicesList, json!({})).await["error"]["code"],
            "forbidden"
        );
        assert_eq!(
            h.exchange(Caller::Mcp, Op::Status, json!({})).await["error"]["code"],
            "state_unavailable"
        );
        let timer = h.helper.start_timer();
        tokio::task::yield_now().await;
        timer.abort();
        let state = match h.helper.state.lock() {
            Err(poisoned) => poisoned.into_inner(),
            Ok(_) => panic!("state must remain poisoned"),
        };
        assert!(state.full.is_empty());
        assert!(state.results.is_empty());
    }
    let h = Harness::new();
    h.audit.fail.store(true, Ordering::SeqCst);
    assert_eq!(
        h.exchange(Caller::Mcp, Op::Wait, json!({})).await["error"]["code"],
        "audit_unavailable"
    );
    let h = Harness::new();
    h.helper
        .lock()
        .unwrap()
        .results
        .insert("orphan".into(), json!({"marker":"result"}));
    drop(h);
}

#[tokio::test]
async fn approved_state_without_a_signed_allow_or_with_an_invalid_signature_never_executes() {
    for variant in 0..3 {
        let h = Harness::new();
        let request = h.helper.submit(h.input(Tier::T1, "A")).unwrap();
        if variant == 0 {
            h.helper
                .lock()
                .unwrap()
                .store
                .db
                .execute("UPDATE pending_approvals SET state='approved'", [])
                .unwrap();
        } else {
            accept_without_scheduling(&h, &request, ScopeMode::PerUse);
            let mut decision = h.decision(&request, ApprovalLevel::Strong, ScopeMode::PerUse);
            if variant == 1 {
                decision.decision = Decision::Deny;
                decision.sig =
                    sign_object(&decision, SignatureAlgorithm::ES256, key("strong").as_ref())
                        .unwrap();
            } else {
                decision.sig = kv_core::remote::keys::encode_b64(&[0; 64]);
            }
            h.helper
                .lock()
                .unwrap()
                .store
                .db
                .execute(
                    "UPDATE pending_approvals SET decision_json=?1",
                    [encode(&decision).unwrap()],
                )
                .unwrap();
        }
        let error = h
            .helper
            .execute_approved(&request.approval_id)
            .await
            .unwrap_err();
        assert_eq!(
            error.code(),
            if variant == 2 {
                "invalid_signature"
            } else {
                "invalid_decision"
            }
        );
        h.reason(error.code());
        assert_eq!(h.runner.calls.load(Ordering::SeqCst), 0);
    }
}

struct AdvancingClock {
    calls: AtomicUsize,
    before: i64,
    after: i64,
}
impl Clock for AdvancingClock {
    fn now(&self) -> i64 {
        if self.calls.fetch_add(1, Ordering::SeqCst) == 0 {
            self.before
        } else {
            self.after
        }
    }
}

#[tokio::test]
async fn time_jump_between_tick_and_operation_expires_decision_retry_and_stop_block() {
    for operation in 0..3 {
        let mut h = if operation == 0 {
            signing_harness()
        } else {
            Harness::new()
        };
        let request = if operation == 0 {
            let mut request: ApprovalRequest =
                serde_json::from_value(fixture("decision_valid.json")["request"].clone()).unwrap();
            request.requester.device_id = h.peer.device_id.clone();
            h.helper
                .inbound(h.envelope(
                    EnvelopeType::ApprovalRequest,
                    &request.approval_id,
                    &request,
                ))
                .await
                .unwrap();
            request
        } else {
            h.helper.submit(h.input(Tier::T1, "A")).unwrap()
        };
        if operation == 1 {
            accept_without_scheduling(&h, &request, ScopeMode::PerUse);
        }
        Arc::get_mut(&mut h.helper).unwrap().services.clock = Arc::new(AdvancingClock {
            calls: AtomicUsize::new(0),
            before: h.clock.now(),
            after: request.exp + 1,
        });
        if operation == 0 {
            let result=h.exchange(Caller::CliOwner,Op::Decide,json!({"approval_id":request.approval_id,"decision":"allow","level":"strong","scope":{"mode":"per_use","level":"credential","until":0}})).await;
            assert_eq!(result["error"]["code"], "expired");
            h.reason("expired");
        } else if operation == 1 {
            let canonical = h
                .helper
                .lock()
                .unwrap()
                .store
                .pending(&request.approval_id)
                .unwrap()
                .canonical;
            assert_eq!(
                h.helper
                    .retry(
                        &request.approval_id,
                        &canonical,
                        h.input(Tier::T1, "A").full_request,
                        501,
                        4242
                    )
                    .await
                    .unwrap()
                    .status,
                ToolStatus::ApprovalExpired
            );
        } else {
            assert_eq!(
                h.exchange(
                    Caller::Hook,
                    Op::PendingStopBlock,
                    json!({"approval_id":request.approval_id})
                )
                .await["result"]["allowed"],
                false
            );
        }
        assert_eq!(h.runner.calls.load(Ordering::SeqCst), 0);
    }
}

#[tokio::test]
async fn issuer_fanout_filters_capabilities_and_audience_and_broadcast_results_time_out() {
    let h = signing_harness();
    let mut non_executor = h.peer.clone();
    non_executor.device_id = "non-executor".into();
    h.helper
        .lock()
        .unwrap()
        .store
        .insert_device(&non_executor, "account", h.clock.now())
        .unwrap();
    let mut grant = signed_grant(&h, "issued-wide", Tier::T1, 1);
    grant.iss = h.helper.local.device_id.clone();
    grant.aud = "*".into();
    assert_eq!(
        h.exchange(
            Caller::CliOwner,
            Op::GrantIssue,
            json!(kv_core::remote::ipc::Unsigned(grant.clone()))
        )
        .await["ok"],
        true
    );
    let mut directive = signed_directive(
        &h,
        DirectiveOp::QueryStatus,
        json!({}),
        ApprovalLevel::Quick,
    );
    directive.iss = h.helper.local.device_id.clone();
    directive.aud = "*".into();
    let result = h
        .exchange(
            Caller::CliOwner,
            Op::DirectiveIssue,
            json!(kv_core::remote::ipc::Unsigned(directive.clone())),
        )
        .await;
    assert_eq!(result["error"]["code"], "directive_result_timeout");
    h.reason("directive_result_timeout");
    for operation in [Op::GrantIssue, Op::DirectiveIssue] {
        let body = if operation == Op::GrantIssue {
            grant.iss_kind = IssuerKind::Service;
            json!(kv_core::remote::ipc::Unsigned(grant.clone()))
        } else {
            directive.iss_kind = IssuerKind::Service;
            json!(kv_core::remote::ipc::Unsigned(directive.clone()))
        };
        assert_eq!(
            h.exchange(Caller::CliOwner, operation, body).await["error"]["code"],
            "wrong_sender"
        );
        h.reason("wrong_sender");
    }
    h.exchange(
        Caller::RelayClient,
        Op::RelayStatus,
        json!({"connected":true}),
    )
    .await;
    h.exchange(
        Caller::RelayClient,
        Op::RelayStatus,
        json!({"connected":true}),
    )
    .await;
    for _ in 0..5 {
        h.exchange(
            Caller::Hook,
            Op::PendingStopBlock,
            json!({"approval_id":"unknown"}),
        )
        .await;
    }
}

#[test]
fn constructor_accepts_matching_approval_providers_and_records_unknown_attestation_without_verifying_it(
) {
    let h = signing_harness();
    let store = Store::memory().unwrap();
    let mut peer = h.peer.clone();
    peer.attestation = Some(Attestation {
        kind: AttestationKind::Unknown("future".into()),
        doc: json!({"evidence":"unverified"}),
        extra: Extra::new(),
    });
    store
        .insert_device(&peer, "account", h.clock.now())
        .unwrap();
    assert_eq!(
        store
            .insert_device(&peer, "account", h.clock.now())
            .unwrap_err()
            .code(),
        "state_unavailable"
    );
    let mirror = Arc::new(FakeMirror(Mutex::new(directory(&store).unwrap())));
    let helper = RemoteHelper::new(
        store,
        h.helper.local.clone(),
        "account".into(),
        ApprovalConfig::default(),
        Services {
            identity: key("sender"),
            quick: Some(key("quick")),
            strong: Some(key("strong")),
            presence: h.presence.clone(),
            mirror,
            audit: h.audit.clone(),
            runner: h.runner.clone(),
            clock: h.clock.clone(),
        },
    )
    .unwrap();
    assert_eq!(
        helper.lock().unwrap().store.devices("account").unwrap()[0].attestation,
        peer.attestation
    );
    let mut local = h.helper.local.clone();
    local.key_kind = KeyKind::Tpm2;
    let store = Store::memory().unwrap();
    let mirror = Arc::new(FakeMirror(Mutex::new(vec![])));
    assert_eq!(
        RemoteHelper::new(
            store,
            local,
            "account".into(),
            ApprovalConfig::default(),
            Services {
                identity: key("sender"),
                quick: Some(key("quick")),
                strong: Some(key("strong")),
                presence: h.presence.clone(),
                mirror,
                audit: h.audit.clone(),
                runner: h.runner.clone(),
                clock: h.clock.clone()
            }
        )
        .err()
        .unwrap()
        .code(),
        "invalid_local_identity"
    );
    let path = tempfile::tempdir().unwrap();
    let vault = kv_vault::Vault::new(path.path().join("does-not-exist"));
    assert_eq!(
        AuditSink::append(&vault, Map::new()).unwrap_err().code(),
        "audit_unavailable"
    );
}

#[test]
fn runtime_install_without_a_tokio_runtime_fails_before_installing_or_retaining_requests() {
    let h = Harness::new();
    assert_eq!(
        super::super::server::install_runtime(h.helper.clone())
            .unwrap_err()
            .code(),
        "runtime_unavailable"
    );
}

#[tokio::test]
async fn incomplete_approval_keys_do_not_match_signatures_even_with_valid_identity_envelopes() {
    for has_strong in [true, false] {
        let h = Harness::new();
        let mut peer = h.peer.clone();
        peer.ak_q = None;
        peer.caps.retain(|c| *c != Capability::ApproveQuick);
        if !has_strong {
            peer.ak_s = None;
            peer.caps.retain(|c| *c != Capability::ApproveStrong);
        }
        h.helper
            .lock()
            .unwrap()
            .store
            .db
            .execute(
                "UPDATE devices SET record_json=?1",
                [encode(&peer).unwrap()],
            )
            .unwrap();
        let mut grant = signed_grant(&h, "missing-approval-key", Tier::T1, 1);
        grant.sig = kv_core::remote::keys::encode_b64(&[0; 64]);
        let reason = if has_strong {
            "invalid_signature"
        } else {
            "unsupported_algorithm"
        };
        assert_eq!(
            h.helper
                .inbound(h.envelope(EnvelopeType::Grant, &grant.jti, &grant))
                .await
                .unwrap_err()
                .code(),
            reason
        );
        h.reason(reason);
        let mut directive = signed_directive(
            &h,
            DirectiveOp::QueryStatus,
            json!({}),
            ApprovalLevel::Quick,
        );
        directive.sig = kv_core::remote::keys::encode_b64(&[0; 64]);
        h.helper
            .inbound(h.envelope(EnvelopeType::Directive, &directive.id, &directive))
            .await
            .unwrap();
        h.reason(reason);
    }
}

#[tokio::test]
async fn schedule_failure_is_audited_and_poisoned_timer_cannot_retain_body_or_results() {
    let h = Harness::new();
    let request = h.helper.submit(h.input(Tier::T1, "A")).unwrap();
    accept_without_scheduling(&h, &request, ScopeMode::PerUse);
    h.helper.schedule_execution(&request.approval_id).unwrap();
    h.helper
        .lock()
        .unwrap()
        .store
        .set_setting("epoch", &1u64, "local", h.clock.now())
        .unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(3), async {
        loop {
            if h.helper
                .lock()
                .unwrap()
                .store
                .pending(&request.approval_id)
                .unwrap()
                .state
                == PendingState::Cancelled
            {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    h.reason("authorization_revoked");
    let h = Harness::new();
    let request = h.helper.submit(h.input(Tier::T1, "A")).unwrap();
    accept_without_scheduling(&h, &request, ScopeMode::PerUse);
    let helper = h.helper.clone();
    *h.runner.after_execute.lock().unwrap() = Some(Box::new(move || poison(&helper)));
    h.helper.schedule_execution(&request.approval_id).unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(3), async {
        while !h.helper.state.is_poisoned() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    let before = h.audit.entries.lock().unwrap().len();
    let timer = h.helper.start_timer();
    tokio::time::timeout(std::time::Duration::from_secs(3), async {
        while h.audit.entries.lock().unwrap().len() <= before {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    timer.abort();
    assert!(h
        .audit
        .entries
        .lock()
        .unwrap()
        .iter()
        .any(|e| e["reason"] == "state_unavailable"));
}
