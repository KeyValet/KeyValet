use super::super::pipeline::select;
use super::workflow::{signed_directive, signed_grant};
use super::*;
use kv_core::remote::ipc::Unsigned;

#[test]
fn each_configuration_boundary_rejects_invalid_input() {
    for field in ["default_exp_s", "unlock_ttl_s", "progress_interval_s"] {
        assert!(ApprovalConfig::from_toml(&format!("[approval]\n{field}=0")).is_err());
    }
    for field in [
        "default_exp_s",
        "unlock_ttl_s",
        "wait_tool_max_s",
        "wait_in_call_s",
        "http_wait_s",
    ] {
        assert!(ApprovalConfig::from_toml(&format!("[approval]\n{field}=86401")).is_err());
    }
    for text in ["[approval]\nstop_hook_max_blocks=101", "[approval]\nprefer='invalid'", "[approval]\nunknown=1", "[[approval.class]]\nname=''\nmatch.host='x'\nexp_s=1", "[[approval.class]]\nname='x'\nmatch.host='x'\nexp_s=0", "[[approval.class]]\nname='x'\nmatch.host='x'\nexp_s=86401", "[[approval.class]]\nname='x'\nmatch={}\nexp_s=1", "[[approval.class]]\nname='x'\nmatch.host='x'\nexp_s=1\n[[approval.class]]\nname='x'\nmatch.host='x'\nexp_s=1"] {
        assert!(ApprovalConfig::from_toml(text).is_err(), "{text}");
    }
    assert!(ApprovalConfig::from_toml(
        "[[approval.class]]\nname='host'\nmatch.host='example.org'\nexp_s=1"
    )
    .is_ok());
    assert!(ApprovalConfig::from_toml("").is_ok());
    assert_eq!(Preference::default(), Preference::Auto);
    assert!(super::super::SystemClock.now() > 0);
    assert_eq!(format!("{}", Error("reason")), "reason");
    let error: Error = serde_json::from_str::<Value>("invalid").unwrap_err().into();
    assert_eq!(error.code(), "invalid_json");
}

#[test]
fn approver_selection_exercises_every_priority() {
    for preference in [Preference::Auto, Preference::Local, Preference::Remote] {
        assert_eq!(
            select(true, vec!["grant".into()], true, preference, true),
            Selection::Auto
        );
        assert_eq!(
            select(false, vec!["grant".into()], true, preference, true),
            Selection::Grant(vec!["grant".into()])
        );
        assert_eq!(
            select(false, vec![], false, preference, true),
            Selection::RemoteDevice
        );
        assert_eq!(
            select(false, vec![], false, preference, false),
            Selection::NoApprover
        );
    }
    assert_eq!(
        select(false, vec![], true, Preference::Auto, true),
        Selection::Local
    );
    assert_eq!(
        select(false, vec![], true, Preference::Remote, true),
        Selection::RemoteDevice
    );
    assert_eq!(
        select(false, vec![], true, Preference::Remote, false),
        Selection::NoApprover
    );
}

#[tokio::test]
async fn pipeline_auto_local_grant_remote_and_no_approver() {
    let h = Harness::new();
    let mut input = h.input(Tier::T0, "A");
    input.auto_allowed = true;
    assert_eq!(
        h.helper
            .run(input, vec![], vec![], 50)
            .await
            .unwrap()
            .status,
        ToolStatus::Ok
    );
    let mut input = h.input(Tier::T1, "A");
    input.local_channel_available = true;
    assert_eq!(
        h.helper
            .run(input, vec![], vec![], 50)
            .await
            .unwrap()
            .status,
        ToolStatus::Ok
    );
    *h.runner.level.lock().unwrap() = ApprovalLevel::Quick;
    let mut input = h.input(Tier::T2, "A");
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
    h.helper
        .install_grant(
            &signed_grant(&h, "pipeline", Tier::T1, 2),
            ApprovalLevel::Strong,
        )
        .unwrap();
    let input = h.input(Tier::T1, "A");
    let host = input.canonical.host.clone().unwrap();
    let method = input.canonical.method.clone().unwrap();
    assert_eq!(
        h.helper
            .run(input, vec![host], vec![method], 50)
            .await
            .unwrap()
            .status,
        ToolStatus::Ok
    );
    assert_eq!(
        h.helper
            .run(h.input(Tier::T2, "A"), vec![], vec![], 10)
            .await
            .unwrap()
            .status,
        ToolStatus::ApprovalPending
    );
    let h = Harness::with(Store::memory().unwrap(), 1_800_000_000, false);
    assert_eq!(
        h.helper
            .run(h.input(Tier::T1, "A"), vec![], vec![], 50)
            .await
            .unwrap()
            .status,
        ToolStatus::NoApprover
    );
    h.reason("no_approver");
}

#[tokio::test]
async fn approval_inside_call_budget_executes_and_http_wait_uses_same_result() {
    let h = Harness::new();
    h.helper.lock().unwrap().relay_connected = true;
    let helper = h.helper.clone();
    let input = h.input(Tier::T1, "A");
    let task = tokio::spawn(async move { helper.run(input, vec![], vec![], 11).await });
    let request = loop {
        let messages = h.helper.outbound_poll(10).await.unwrap();
        if let Some(envelope) = messages
            .iter()
            .find(|envelope| envelope.r#type == EnvelopeType::ApprovalRequest)
        {
            let bytes = kv_core::remote::envelope::open(
                envelope,
                &h.peer.device_id,
                key("recipient").as_ref(),
                &h.helper.local,
                h.clock.now(),
            )
            .unwrap();
            break from_json::<ApprovalRequest>(&bytes).unwrap();
        }
    };
    let decision = h.decision(&request, ApprovalLevel::Quick, ScopeMode::PerUse);
    h.helper
        .inbound(h.envelope(
            EnvelopeType::ApprovalDecision,
            &request.approval_id,
            &decision,
        ))
        .await
        .unwrap();
    assert_eq!(task.await.unwrap().unwrap().status, ToolStatus::Ok);
    assert_eq!(h.runner.calls.load(Ordering::SeqCst), 1);
    let request = h.helper.submit(h.input(Tier::T1, "B")).unwrap();
    assert_eq!(
        h.helper
            .wait_http(&request.approval_id, Some(60), 501, 4242)
            .await
            .unwrap()
            .status,
        ToolStatus::StillPending
    );
}

#[tokio::test]
async fn envelope_step_one_rejects_every_untrusted_header_or_ciphertext() {
    for variant in 0..8 {
        let h = Harness::new();
        let request = h.helper.submit(h.input(Tier::T1, "A")).unwrap();
        let decision = h.decision(&request, ApprovalLevel::Quick, ScopeMode::PerUse);
        let mut envelope = h.envelope(
            EnvelopeType::ApprovalDecision,
            &request.approval_id,
            &decision,
        );
        let expected = match variant {
            0 => {
                envelope.to = "other".into();
                "wrong_recipient"
            }
            1 => {
                envelope.account = "other".into();
                "wrong_account"
            }
            2 => {
                envelope.from = "other".into();
                "unpaired_device"
            }
            3 => {
                envelope.sig = kv_core::remote::keys::encode_b64(&[0; 64]);
                "invalid_signature"
            }
            4 => {
                envelope.exp = h.clock.now() - 1;
                envelope.sig = kv_core::remote::keys::encode_b64(
                    &DeviceKeyProvider::sign(
                        key("recipient").as_ref(),
                        SignatureAlgorithm::ES256,
                        &envelope.signature_payload().unwrap(),
                    )
                    .unwrap(),
                );
                "expired"
            }
            5 => {
                envelope.ct = "AAAA".into();
                envelope.sig = kv_core::remote::keys::encode_b64(
                    &DeviceKeyProvider::sign(
                        key("recipient").as_ref(),
                        SignatureAlgorithm::ES256,
                        &envelope.signature_payload().unwrap(),
                    )
                    .unwrap(),
                );
                "decryption_failed"
            }
            6 => {
                envelope = h.envelope(EnvelopeType::ApprovalDecision, "other", &decision);
                "not_waiting"
            }
            _ => {
                h.helper.revoke_device(&h.peer.device_id, "local").unwrap();
                "revoked_device"
            }
        };
        let error = h.helper.inbound(envelope).await.unwrap_err();
        assert_eq!(error.code(), expected, "variant {variant}");
        h.reason(expected);
        assert_eq!(h.runner.calls.load(Ordering::SeqCst), 0);
    }
}

#[tokio::test]
async fn grant_and_directive_envelopes_apply_and_result_returns_to_sender() {
    let h = Harness::new();
    let grant = signed_grant(&h, "inbound", Tier::T1, 1);
    h.helper
        .inbound(h.envelope(EnvelopeType::Grant, &grant.jti, &grant))
        .await
        .unwrap();
    for (op, args) in [
        (DirectiveOp::QueryStatus, json!({})),
        (DirectiveOp::QueryGrants, json!({})),
        (DirectiveOp::QueryPending, json!({})),
        (DirectiveOp::SetDeviceLabel, json!({"label":"renamed"})),
        (DirectiveOp::RevokeGrant, json!({"jti":"inbound"})),
        (DirectiveOp::RevokeAllGrants, json!({})),
    ] {
        let directive = signed_directive(&h, op, args, ApprovalLevel::Strong);
        h.helper
            .inbound(h.envelope(EnvelopeType::Directive, &directive.id, &directive))
            .await
            .unwrap();
    }
    let directive = signed_directive(
        &h,
        DirectiveOp::SetMode,
        json!({"mode":"per_session"}),
        ApprovalLevel::Quick,
    );
    h.helper
        .inbound(h.envelope(EnvelopeType::Directive, &directive.id, &directive))
        .await
        .unwrap();
    h.reason("insufficient_level");
    let messages = h.helper.outbound_poll(0).await.unwrap();
    assert!(messages
        .iter()
        .any(|envelope| envelope.r#type == EnvelopeType::DirectiveResult));
}

#[tokio::test]
async fn remote_signer_uses_recorded_keys_and_audits_both_ends() {
    let mut h = Harness::new();
    let helper = Arc::get_mut(&mut h.helper).unwrap();
    helper.local.ak_q = h.peer.ak_q.clone();
    helper.local.ak_s = h.peer.ak_s.clone();
    helper
        .local
        .caps
        .extend([Capability::ApproveQuick, Capability::ApproveStrong]);
    helper.services.quick = Some(key("quick"));
    helper.services.strong = Some(key("strong"));
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
    let mut request: ApprovalRequest =
        serde_json::from_value(fixture("decision_valid.json")["request"].clone()).unwrap();
    request.approval_id = "incoming".into();
    request.requester.device_id = peer.device_id.clone();
    h.helper
        .inbound(h.envelope(EnvelopeType::ApprovalRequest, "incoming", &request))
        .await
        .unwrap();
    let args = json!({"approval_id":"incoming","decision":"allow","level":"quick","scope":{"mode":"per_use","level":"credential","until":0}});
    let response = h.exchange(Caller::ApprovalAgent, Op::Decide, args).await;
    assert_eq!(response["ok"], true, "{response}");
    assert!(h
        .helper
        .audit_entries()
        .unwrap()
        .iter()
        .any(|e| e["op"] == "remote_approval_issued"));
    let envelopes = h.helper.outbound_poll(0).await.unwrap();
    let decision = envelopes
        .iter()
        .find(|e| e.r#type == EnvelopeType::ApprovalDecision)
        .unwrap();
    let bytes = kv_core::remote::envelope::open(
        decision,
        &peer.device_id,
        key("recipient").as_ref(),
        &h.helper.local,
        h.clock.now(),
    )
    .unwrap();
    let decision: ApprovalDecision = from_json(&bytes).unwrap();
    kv_core::remote::keys::verify_object(
        &decision,
        &decision.sig,
        h.helper.local.ak_q.as_ref().unwrap(),
    )
    .unwrap();
    let mut grant = signed_grant(&h, "issued", Tier::T1, 2);
    grant.iss = h.helper.local.device_id.clone();
    grant.aud = peer.device_id.clone();
    grant.sig.clear();
    let response = h
        .exchange(
            Caller::CliOwner,
            Op::GrantIssue,
            serde_json::to_value(Unsigned(grant)).unwrap(),
        )
        .await;
    assert_eq!(response["ok"], true, "{response}");
}

#[tokio::test]
async fn presence_cache_checks_identity_time_and_monotonicity() {
    for variant in 0..4 {
        let h = Harness::new();
        let mut hint = PresenceHint {
            device_id: h.peer.device_id.clone(),
            state: Presence::Present,
            since: h.clock.now(),
            sent_at: h.clock.now(),
            extra: Extra::new(),
        };
        let expected = match variant {
            0 => {
                hint.device_id = "other".into();
                "invalid_presence_hint"
            }
            1 => {
                hint.sent_at += 61;
                "invalid_presence_hint"
            }
            2 => {
                hint.sent_at -= 121;
                "invalid_presence_hint"
            }
            _ => {
                h.helper
                    .inbound(h.envelope(EnvelopeType::PresenceHint, "hint", &hint))
                    .await
                    .unwrap();
                "stale_presence_hint"
            }
        };
        let error = h
            .helper
            .inbound(h.envelope(EnvelopeType::PresenceHint, "hint", &hint))
            .await
            .unwrap_err();
        assert_eq!(error.code(), expected);
        h.reason(expected);
    }
}

#[tokio::test]
async fn fake_relay_pipe_supports_handshake_acl_and_numbered_responses() {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    let h = Harness::new();
    let (client, server) = tokio::io::duplex(4096);
    let helper = h.helper.clone();
    let job = tokio::spawn(async move {
        super::super::server::serve(
            server,
            tokio::io::sink(),
            CallerContext::authenticated(Caller::RelayClient, 501, 4242, 50),
            Some(helper),
        )
        .await
    });
    let mut client = client;
    client.write_all(b"{\"op\":\"relay\",\"protocol\":4}\n{\"op\":\"remote.relay.status\",\"params\":{\"connected\":true,\"since\":1}}\n").await.unwrap();
    client.shutdown().await.unwrap();
    assert!(job.await.unwrap().is_ok());
    for role in [Caller::CliOwner, Caller::RelayClient] {
        let (client, server) = tokio::io::duplex(4096);
        let (reader, writer) = tokio::io::split(server);
        let helper = h.helper.clone();
        let job = tokio::spawn(async move {
            super::super::server::serve(
                reader,
                writer,
                CallerContext::authenticated(role, 501, 4242, 50),
                Some(helper),
            )
            .await
        });
        let (reader, mut writer) = tokio::io::split(client);
        writer
            .write_all(b"{\"op\":\"remote.status\",\"id\":17,\"params\":{}}\n")
            .await
            .unwrap();
        let mut line = String::new();
        BufReader::new(reader).read_line(&mut line).await.unwrap();
        let response: Value = from_json(line.as_bytes()).unwrap();
        assert_eq!(response["id"], 17);
        assert_eq!(response["ok"], role == Caller::CliOwner);
        writer.shutdown().await.unwrap();
        assert!(job.await.unwrap().is_ok());
    }
    for (input, expected) in [
        ("{invalid}\n", "invalid_json"),
        (
            "{\"op\":\"remote.unknown\",\"id\":9}\n",
            "invalid_remote_op",
        ),
        ("{\"op\":\"relay\",\"protocol\":3}\n", "forbidden"),
        ("{\"op\":\"relay\",\"protocol\":4}\n", "forbidden"),
    ] {
        let result = super::super::server::serve(
            input.as_bytes(),
            tokio::io::sink(),
            CallerContext::authenticated(Caller::CliOwner, 501, 4242, 50),
            Some(h.helper.clone()),
        )
        .await;
        assert_eq!(result.unwrap_err().code(), expected);
    }
    for role in [Caller::CliOwner, Caller::RelayClient] {
        let mut output = Vec::new();
        super::super::server::serve(
            b"{\"op\":\"remote.status\",\"params\":{}}\n".as_slice(),
            &mut output,
            CallerContext::authenticated(role, 501, 4242, 50),
            None,
        )
        .await
        .unwrap();
        let value: Value = from_json(&output).unwrap();
        assert_eq!(
            value["error"]["code"],
            if role == Caller::CliOwner {
                "remote_unavailable"
            } else {
                "forbidden"
            }
        );
    }
}

#[tokio::test]
async fn framing_rejects_truncated_and_oversized_frames_and_accepts_chunking() {
    use tokio::io::BufReader;
    assert!(
        super::super::server::read_frame(&mut BufReader::new(b"".as_slice()))
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(
        super::super::server::read_frame(&mut BufReader::new(b"{\"op\":".as_slice()))
            .await
            .unwrap_err()
            .code(),
        "truncated_frame"
    );
    let bytes = vec![b'A'; kv_ipc::MAX_LINE_BYTES + 1];
    assert_eq!(
        super::super::server::read_frame(&mut BufReader::new(bytes.as_slice()))
            .await
            .unwrap_err()
            .code(),
        "payload_too_large"
    );
    let mut reader = BufReader::with_capacity(2, b"{}\n{}\n".as_slice());
    for _ in 0..2 {
        assert_eq!(
            &**super::super::server::read_frame(&mut reader)
                .await
                .unwrap()
                .as_ref()
                .unwrap(),
            b"{}"
        );
    }
}

#[test]
fn startup_rejects_changed_audit_chain_and_derived_grant_scope() {
    let h = Harness::new();
    h.helper
        .set_mode_local("per_use", ApprovalLevel::Quick)
        .unwrap();
    let state = h.helper.lock().unwrap();
    state.store.verify_audit().unwrap();
    state
        .store
        .db
        .execute("UPDATE remote_audit SET prev_hash='tampered'", [])
        .unwrap();
    assert_eq!(
        state.store.verify_audit().unwrap_err().code(),
        "audit_chain_mismatch"
    );
    drop(state);
    let h = Harness::new();
    let request = h.helper.submit(h.input(Tier::T1, "A")).unwrap();
    let decision = h.decision(&request, ApprovalLevel::Quick, ScopeMode::PerCredential);
    h.helper
        .accept_decision(
            &mut h.helper.lock().unwrap(),
            &h.peer,
            &decision,
            h.clock.now(),
            h.clock.now(),
        )
        .unwrap();
    let state = h.helper.lock().unwrap();
    let mut grant: Value = serde_json::from_str(
        &state
            .store
            .db
            .query_row("SELECT object_json FROM grants", [], |row| {
                row.get::<_, String>(0)
            })
            .unwrap(),
    )
    .unwrap();
    grant["scope"]["level"] = json!("device");
    grant["scope"].as_object_mut().unwrap().remove("credential");
    state
        .store
        .db
        .execute(
            "UPDATE grants SET object_json=?1",
            [encode(&grant).unwrap()],
        )
        .unwrap();
    drop(state);
    let input = h.input(Tier::T1, "B");
    let usage = GrantUse {
        canonical: input.canonical,
        tier: Tier::T1,
        template_allowed_hosts: vec!["api.github.com".into()],
        policy_allowed_methods: vec!["POST".into()],
        body_bytes: 1,
        session_id: "session".into(),
    };
    assert!(h.helper.cover_and_debit(&usage).unwrap().jtis.is_empty());
    h.reason("invalid_grant");
}

#[tokio::test]
async fn runner_failure_is_audited_and_result_claimed_once() {
    let h = Harness::new();
    h.runner.fail.store(true, Ordering::SeqCst);
    let request = h.helper.submit(h.input(Tier::T1, "A")).unwrap();
    let decision = h.decision(&request, ApprovalLevel::Quick, ScopeMode::PerUse);
    h.helper
        .inbound(h.envelope(
            EnvelopeType::ApprovalDecision,
            &request.approval_id,
            &decision,
        ))
        .await
        .unwrap();
    let result = h
        .helper
        .wait(&request.approval_id, 500, 11, 501, 4242)
        .await
        .unwrap();
    assert_eq!(result.status, ToolStatus::Ok);
    assert_eq!(
        result.result.as_value().unwrap()["error"]["code"],
        "execution_unavailable"
    );
    h.reason("execution_unavailable");
    assert_eq!(
        h.helper
            .result(&request.approval_id, 501, 4242, true)
            .unwrap()
            .status,
        ToolStatus::AlreadyConsumed
    );
}

pub(super) fn signing_harness() -> Harness {
    let mut h = Harness::new();
    let helper = Arc::get_mut(&mut h.helper).unwrap();
    helper.local.ak_q = h.peer.ak_q.clone();
    helper.local.ak_s = h.peer.ak_s.clone();
    helper
        .local
        .caps
        .extend([Capability::ApproveQuick, Capability::ApproveStrong]);
    helper.services.quick = Some(key("quick"));
    helper.services.strong = Some(key("strong"));
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
    h
}

#[tokio::test]
async fn directive_issuer_waits_for_verified_result_and_keeps_metadata_ledger() {
    let h = signing_harness();
    let mut directive = signed_directive(
        &h,
        DirectiveOp::QueryStatus,
        json!({}),
        ApprovalLevel::Strong,
    );
    directive.iss = h.helper.local.device_id.clone();
    directive.aud = h.peer.device_id.clone();
    directive.id.clear();
    directive.nonce.clear();
    directive.sig.clear();
    let helper = h.helper.clone();
    let params = serde_json::to_value(Unsigned(directive)).unwrap();
    let job = tokio::spawn(async move {
        helper
            .handle(
                CallerContext::authenticated(Caller::CliOwner, 501, 4242, 50),
                Request {
                    op: Op::DirectiveIssue,
                    params,
                    extra: Extra::new(),
                },
            )
            .await
    });
    let messages = h.helper.outbound_poll(500).await.unwrap();
    let envelope = messages
        .iter()
        .find(|e| e.r#type == EnvelopeType::Directive)
        .unwrap();
    let result = DirectiveResult {
        id: envelope.id.clone(),
        ok: true,
        error: None,
        state: json!({"mode":"per_use"}).as_object().unwrap().clone(),
        extra: Extra::new(),
    };
    h.helper
        .inbound(h.envelope(EnvelopeType::DirectiveResult, &result.id, &result))
        .await
        .unwrap();
    assert_eq!(
        serde_json::to_value(job.await.unwrap()).unwrap()["ok"],
        true
    );
    assert!(h
        .helper
        .lock()
        .unwrap()
        .store
        .db
        .query_row("SELECT result_ok FROM issued_directives", [], |row| row
            .get::<_, bool>(0))
        .unwrap());
    assert!(h
        .helper
        .audit_entries()
        .unwrap()
        .iter()
        .any(|e| e["op"] == "directive_result"));
    let unexpected = DirectiveResult {
        id: "unknown".into(),
        ..result
    };
    assert_eq!(
        h.helper
            .inbound(h.envelope(EnvelopeType::DirectiveResult, "unknown", &unexpected))
            .await
            .unwrap_err()
            .code(),
        "unexpected_directive_result"
    );
    h.reason("unexpected_directive_result");
}

#[tokio::test]
async fn authenticated_ipc_operations_validate_fields_and_ownership() {
    let h = Harness::new();
    let request = h.helper.submit(h.input(Tier::T1, "A")).unwrap();
    for (role, op, args) in [
        (
            Caller::RelayClient,
            Op::RelayStatus,
            json!({"connected":false,"since":1,"last_error":"never-log-this"}),
        ),
        (
            Caller::RelayClient,
            Op::RelayStatus,
            json!({"connected":true,"since":1}),
        ),
        (
            Caller::RelayClient,
            Op::RelayOutboundPoll,
            json!({"max_wait_ms":0}),
        ),
        (
            Caller::RelayClient,
            Op::SignIdentity,
            json!({"payload_b64":kv_core::remote::keys::encode_b64(&[1;32])}),
        ),
        (Caller::CliOwner, Op::PendingList, json!({})),
        (Caller::Mcp, Op::PendingList, json!({"agent_pid":4242})),
        (Caller::CliOwner, Op::DevicesList, json!({})),
        (Caller::CliOwner, Op::GrantList, json!({})),
        (
            Caller::CliOwner,
            Op::DevicesRename,
            json!({"device_id":h.peer.device_id,"label":"renamed"}),
        ),
        (Caller::CliOwner, Op::GrantRevoke, json!({"jti":"unknown"})),
        (
            Caller::Mcp,
            Op::Wait,
            json!({"approval_id":request.approval_id,"max_wait_ms":0,"runtime_budget_s":10}),
        ),
    ] {
        let response = h.exchange(role, op, args).await;
        assert_eq!(response["ok"], true, "{op:?}: {response}");
    }
    for (role, op, args, expected) in [
        (
            Caller::Mcp,
            Op::PendingList,
            json!({"agent_pid":1}),
            "forbidden",
        ),
        (
            Caller::CliOwner,
            Op::DevicesRename,
            json!({"device_id":h.peer.device_id,"label":""}),
            "invalid_device_label",
        ),
        (
            Caller::RelayClient,
            Op::RelayStatus,
            json!({"connected":"invalid"}),
            "invalid_json",
        ),
        (
            Caller::RelayClient,
            Op::SignIdentity,
            json!({"payload_b64":"AAA"}),
            "invalid_identity_challenge",
        ),
    ] {
        let response = h.exchange(role, op, args).await;
        assert_eq!(response["error"]["code"], expected, "{response}");
        h.reason(expected);
    }
    assert!(!encode(&h.helper.audit_entries().unwrap())
        .unwrap()
        .contains("never-log-this"));
    let hint = PresenceHint {
        device_id: "dev_srv".into(),
        state: Presence::Present,
        since: h.clock.now(),
        sent_at: h.clock.now(),
        extra: Extra::new(),
    };
    assert_eq!(
        h.exchange(
            Caller::ApprovalAgent,
            Op::PresenceUpdate,
            serde_json::to_value(&hint).unwrap()
        )
        .await["ok"],
        true
    );
    assert_eq!(
        h.exchange(
            Caller::ApprovalAgent,
            Op::PresenceUpdate,
            serde_json::to_value(&hint).unwrap()
        )
        .await["error"]["code"],
        "stale_presence_hint"
    );
    for variant in 0..3 {
        let mut hint = hint.clone();
        match variant {
            0 => hint.device_id = "other".into(),
            1 => hint.sent_at += 61,
            _ => hint.sent_at -= 121,
        };
        assert_eq!(
            h.exchange(
                Caller::ApprovalAgent,
                Op::PresenceUpdate,
                serde_json::to_value(hint).unwrap()
            )
            .await["error"]["code"],
            "invalid_presence_hint"
        );
    }
    *h.runner.level.lock().unwrap() = ApprovalLevel::Quick;
    assert_eq!(
        h.exchange(
            Caller::CliOwner,
            Op::DevicesRevoke,
            json!({"device_id":h.peer.device_id})
        )
        .await["error"]["code"],
        "insufficient_level"
    );
    *h.runner.level.lock().unwrap() = ApprovalLevel::Strong;
    assert_eq!(
        h.exchange(
            Caller::CliOwner,
            Op::DevicesRevoke,
            json!({"device_id":h.peer.device_id})
        )
        .await["ok"],
        true
    );
}

#[tokio::test]
async fn local_issuer_rejects_wrong_authority_alg_level_expiration_and_confirmation() {
    for variant in 0..7 {
        let h = signing_harness();
        let mut grant = signed_grant(&h, "issue", Tier::T1, 2);
        grant.iss = h.helper.local.device_id.clone();
        grant.aud = h.peer.device_id.clone();
        grant.sig.clear();
        let expected = match variant {
            0 => {
                grant.iss = "other".into();
                "wrong_sender"
            }
            1 => {
                grant.aud = "other".into();
                "wrong_recipient"
            }
            2 => {
                grant.scope.max_tier = Tier::T2;
                grant.confirm = Optional::Missing;
                "secondary_confirmation_required"
            }
            3 => {
                *h.runner.level.lock().unwrap() = ApprovalLevel::Quick;
                "insufficient_level"
            }
            4 => {
                grant.iss_alg = SignatureAlgorithm::RS256;
                "unsupported_algorithm"
            }
            5 => {
                grant.exp = Some(h.clock.now() - 1);
                "expired"
            }
            _ => {
                grant.scope.max_tier = Tier::T2;
                grant.confirm = Optional::Value(h.peer.label.clone());
                "secondary_confirmation_required"
            }
        };
        let response = h
            .exchange(
                Caller::CliOwner,
                Op::GrantIssue,
                serde_json::to_value(Unsigned(grant)).unwrap(),
            )
            .await;
        if expected == "ok" {
            assert_eq!(response["ok"], true, "{response}");
        } else {
            assert_eq!(response["error"]["code"], expected, "{response}");
            h.reason(expected);
        }
    }
    for variant in 0..5 {
        let h = signing_harness();
        let mut directive = signed_directive(
            &h,
            DirectiveOp::QueryStatus,
            json!({}),
            ApprovalLevel::Strong,
        );
        directive.iss = h.helper.local.device_id.clone();
        directive.aud = h.peer.device_id.clone();
        directive.sig.clear();
        let expected = match variant {
            0 => {
                directive.iss = "other".into();
                "wrong_sender"
            }
            1 => {
                directive.aud = "other".into();
                "directive_requires_single_peer"
            }
            2 => {
                directive.iss_alg = SignatureAlgorithm::RS256;
                "unsupported_algorithm"
            }
            3 => {
                directive.exp = h.clock.now() - 1;
                "expired"
            }
            _ => {
                directive.exp = h.clock.now() + 601;
                "expired"
            }
        };
        let response = h
            .exchange(
                Caller::CliOwner,
                Op::DirectiveIssue,
                serde_json::to_value(Unsigned(directive)).unwrap(),
            )
            .await;
        assert_eq!(response["error"]["code"], expected, "{response}");
        h.reason(expected);
    }
}

#[tokio::test]
async fn unlock_admin_and_expiration_classes_keep_scope_and_lifetime() {
    for kind in [ApprovalKind::Unlock, ApprovalKind::Admin] {
        let h = Harness::new();
        let mut input = h.input(Tier::T0, "A");
        input.canonical.kind = kind;
        input.canonical.credential = None;
        input.canonical.method = None;
        input.canonical.host = None;
        input.canonical.path = None;
        input.credential = None;
        input.operation = None;
        let request = h.helper.submit(input).unwrap();
        assert_eq!(request.min_level, ApprovalLevel::Strong);
        assert_eq!(request.scope_options, vec![ScopeOption::PerUse]);
        let decision = h.decision(&request, ApprovalLevel::Strong, ScopeMode::PerUse);
        h.helper
            .accept_decision(
                &mut h.helper.lock().unwrap(),
                &h.peer,
                &decision,
                h.clock.now(),
                h.clock.now(),
            )
            .unwrap();
        if kind == ApprovalKind::Unlock {
            assert_eq!(
                h.helper.unlock_until("session").unwrap(),
                Some(h.clock.now() + 43200)
            );
        }
        h.helper.close_session("session").unwrap();
        assert!(h.helper.unlock_until("session").unwrap().is_none());
    }
    let mut h = Harness::new();
    Arc::get_mut(&mut h.helper).unwrap().config.class = vec![ApprovalClass {
        name: "github".into(),
        r#match: ClassMatch {
            credential: Some("github/*".into()),
            host: None,
        },
        exp_s: 900,
    }];
    let request = h.helper.submit(h.input(Tier::T1, "A")).unwrap();
    assert_eq!(request.exp - h.clock.now(), 900);
    let directive = signed_directive(
        &h,
        DirectiveOp::SetClass,
        json!({"name":"github","match":{"credential":"github/*"},"exp_s":1200}),
        ApprovalLevel::Strong,
    );
    h.helper
        .apply_directive(&directive, ApprovalLevel::Strong)
        .unwrap();
    let request = h.helper.submit(h.input(Tier::T1, "B")).unwrap();
    assert_eq!(request.exp - h.clock.now(), 1200);
    let mut bad = h.input(Tier::T1, "bad");
    bad.canonical.kind = ApprovalKind::Unlock;
    assert_eq!(
        h.helper.submit(bad).unwrap_err().code(),
        "invalid_approval_request"
    );
}

#[tokio::test]
async fn remote_device_approver_observes_decision_and_rejects_expired_or_mismatched_request() {
    let h = Harness::new();
    let request = h.helper.submit(h.input(Tier::T1, "A")).unwrap();
    let approver = RemoteDevice {
        helper: h.helper.clone(),
    };
    assert_eq!(approver.approver_kind(), ApproverKind::Device);
    let mut wrong = request.clone();
    wrong.digest = "other".into();
    assert_eq!(
        approver.approve(&wrong).await.unwrap_err(),
        RemoteError::DigestMismatch
    );
    let helper = h.helper.clone();
    let waiting = request.clone();
    let task = tokio::spawn(async move { RemoteDevice { helper }.approve(&waiting).await });
    tokio::task::yield_now().await;
    let decision = h.decision(&request, ApprovalLevel::Quick, ScopeMode::PerUse);
    h.helper
        .inbound(h.envelope(
            EnvelopeType::ApprovalDecision,
            &request.approval_id,
            &decision,
        ))
        .await
        .unwrap();
    assert_eq!(task.await.unwrap().unwrap(), decision);
    let request = h.helper.submit(h.input(Tier::T1, "B")).unwrap();
    h.clock.0.store(request.exp + 1, Ordering::SeqCst);
    assert_eq!(
        approver.approve(&request).await.unwrap_err(),
        RemoteError::NotWaiting
    );
    let timer = h.helper.start_timer();
    timer.abort();
}

#[tokio::test]
async fn storage_rejects_untrusted_paths_and_device_directory_rows() {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{symlink, PermissionsExt};
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("state.db");
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
        assert_eq!(
            Store::open(&target).err().unwrap().code(),
            "untrusted_state_directory"
        );
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::write(&target, b"").unwrap();
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(
            Store::open(&target).err().unwrap().code(),
            "untrusted_state_file"
        );
        std::fs::remove_file(&target).unwrap();
        symlink("other", &target).unwrap();
        assert!(Store::open(&target).is_err());
        std::fs::remove_file(&target).unwrap();
        symlink(dir.path(), dir.path().join("alias")).unwrap();
        assert_eq!(
            Store::open(&dir.path().join("alias/state.db"))
                .err()
                .unwrap()
                .code(),
            "untrusted_state_directory"
        );
        std::fs::remove_file(&target).ok();
        std::fs::create_dir(&target).unwrap();
        assert!(Store::open(&target).is_err());
    }
    let h = Harness::new();
    let state = h.helper.lock().unwrap();
    for (trust, account, expected) in [
        ("pending", "account", "untrusted_device"),
        ("verified_sas", "other", "untrusted_device"),
        ("revoked", "account", "revoked_device"),
    ] {
        state
            .store
            .db
            .execute(
                "UPDATE devices SET trust=?1,account_id=?2 WHERE id=?3",
                params![trust, account, h.peer.device_id],
            )
            .unwrap();
        assert_eq!(
            state
                .store
                .device(&h.peer.device_id, "account")
                .unwrap_err()
                .code(),
            expected
        );
    }
    assert_eq!(
        state.store.device("unknown", "account").unwrap_err().code(),
        "unpaired_device"
    );
    drop(state);
    let h = Harness::new();
    let request = h.helper.submit(h.input(Tier::T1, "A")).unwrap();
    h.helper
        .lock()
        .unwrap()
        .store
        .db
        .execute("UPDATE pending_approvals SET state='invalid'", [])
        .unwrap();
    assert_eq!(
        h.helper
            .lock()
            .unwrap()
            .store
            .pending(&request.approval_id)
            .err()
            .unwrap()
            .code(),
        "invalid_pending_state"
    );
}

#[test]
fn device_constructor_rejects_invalid_key_separation_caps_and_provider_identity() {
    for variant in 0..9 {
        let h = Harness::new();
        let store = Store::memory().unwrap();
        store
            .insert_device(&h.peer, "account", h.clock.now())
            .unwrap();
        let mut local = h.helper.local.clone();
        let mut account = "account".to_owned();
        let mut quick = None;
        let mut strong = None;
        let expected = match variant {
            0 => {
                account.clear();
                "invalid_local_identity"
            }
            1 => {
                local.device_id.clear();
                "invalid_local_identity"
            }
            2 => {
                local.dk_pub = h.peer.dk_pub.clone();
                "invalid_local_identity"
            }
            3 => {
                local.ak_q = Some(ApprovalKey {
                    r#pub: local.dk_pub.clone(),
                    alg: SignatureAlgorithm::ES256,
                    extra: Extra::new(),
                });
                local.caps.push(Capability::ApproveQuick);
                "identity_cannot_approve"
            }
            4 => {
                local.caps.push(Capability::ApproveStrong);
                "invalid_device_capabilities"
            }
            5 => {
                local.ak_q = h.peer.ak_q.clone();
                local.ak_s = local.ak_q.clone();
                local
                    .caps
                    .extend([Capability::ApproveQuick, Capability::ApproveStrong]);
                "approval_keys_not_distinct"
            }
            6 => {
                local.ak_q = h.peer.ak_q.clone();
                local.caps.push(Capability::ApproveQuick);
                quick = Some(key("strong") as Arc<dyn DeviceKeyProvider + Send + Sync>);
                "invalid_local_identity"
            }
            7 => {
                local.ak_s = h.peer.ak_s.clone();
                local.caps.push(Capability::ApproveStrong);
                strong = Some(key("quick") as Arc<dyn DeviceKeyProvider + Send + Sync>);
                "invalid_local_identity"
            }
            _ => {
                h.mirror.0.lock().unwrap().clear();
                "device_directory_mismatch"
            }
        };
        let result = RemoteHelper::new(
            store,
            local,
            account,
            ApprovalConfig::default(),
            Services {
                identity: key("sender"),
                quick,
                strong,
                presence: h.presence.clone(),
                mirror: h.mirror.clone(),
                audit: h.audit.clone(),
                runner: h.runner.clone(),
                clock: h.clock.clone(),
            },
        );
        assert_eq!(result.err().unwrap().code(), expected, "variant {variant}");
    }
    #[cfg(unix)]
    for (owner, mode, service, private) in [
        (1, 0o700, 1, true),
        (1, 0o600, 1, true),
        (2, 0o700, 1, false),
        (1, 0o755, 1, false),
    ] {
        assert_eq!(
            super::super::store::unix_private(owner, mode, service),
            private
        );
    }
}

#[tokio::test]
async fn pending_snapshot_corruption_stops_before_signature_and_nonce_use() {
    for variant in 0..6 {
        let h = Harness::new();
        let request = h.helper.submit(h.input(Tier::T1, "A")).unwrap();
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
            2 => canonical.requester = "other".into(),
            3 => canonical.nonce = "different".into(),
            4 => canonical.purpose = "changed".into(),
            _ => canonical.agent.uid += 1,
        };
        h.helper
            .lock()
            .unwrap()
            .store
            .db
            .execute(
                "UPDATE pending_approvals SET canonical_json=?1",
                [encode(&canonical).unwrap()],
            )
            .unwrap();
        let decision = h.decision(&request, ApprovalLevel::Quick, ScopeMode::PerUse);
        assert_eq!(
            h.helper
                .inbound(h.envelope(
                    EnvelopeType::ApprovalDecision,
                    &request.approval_id,
                    &decision
                ))
                .await
                .unwrap_err()
                .code(),
            "digest_mismatch"
        );
        h.reason("digest_mismatch");
        assert_eq!(
            h.helper
                .lock()
                .unwrap()
                .store
                .db
                .query_row("SELECT COUNT(*) FROM nonces", [], |row| row
                    .get::<_, u32>(0))
                .unwrap(),
            0
        );
    }
}

#[tokio::test]
async fn unsigned_inputs_never_accept_supplied_signatures_and_unavailable_keys_do_not_fallback() {
    let h = Harness::new();
    let grant = signed_grant(&h, "bad", Tier::T1, 1);
    assert_eq!(
        h.exchange(
            Caller::CliOwner,
            Op::GrantIssue,
            serde_json::to_value(grant).unwrap()
        )
        .await["error"]["code"],
        "invalid_json"
    );
    h.reason("invalid_json");
    let mut h = signing_harness();
    Arc::get_mut(&mut h.helper).unwrap().services.strong = None;
    let mut grant = signed_grant(&h, "missing", Tier::T1, 1);
    grant.iss = h.helper.local.device_id.clone();
    grant.aud = h.peer.device_id.clone();
    grant.sig.clear();
    assert_eq!(
        h.exchange(
            Caller::CliOwner,
            Op::GrantIssue,
            serde_json::to_value(Unsigned(grant)).unwrap()
        )
        .await["error"]["code"],
        "key_unavailable"
    );
    h.reason("key_unavailable");
    assert!(h.helper.outbound_poll(0).await.unwrap().is_empty());
}

#[tokio::test]
async fn decision_issuer_rechecks_waiting_and_scope_before_signing() {
    for variant in 0..6 {
        let h = signing_harness();
        let mut request: ApprovalRequest =
            serde_json::from_value(fixture("decision_valid.json")["request"].clone()).unwrap();
        request.requester.device_id = h.peer.device_id.clone();
        request.approval_id = "incoming".into();
        if variant == 1 {
            request.exp = h.clock.now() - 1;
        }
        if variant == 2 {
            request.tier = Tier::T2;
        }
        h.helper
            .lock()
            .unwrap()
            .inbound_requests
            .insert("incoming".into(), request);
        let mut args = json!({"approval_id":"incoming","decision":"allow","level":"quick","scope":{"mode":"per_use","level":"credential","until":0}});
        let expected = match variant {
            0 => {
                args["approval_id"] = json!("missing");
                "not_waiting"
            }
            1 => "not_waiting",
            2 => "insufficient_level",
            3 => {
                args["scope"]["mode"] = json!("remember");
                args["scope"]["until"] = json!(h.clock.now() + 1);
                "invalid_scope"
            }
            4 => {
                *h.runner.level.lock().unwrap() = ApprovalLevel::Quick;
                args["level"] = json!("strong");
                "insufficient_level"
            }
            _ => {
                args["scope"]["mode"] = json!("standing");
                "insufficient_level"
            }
        };
        let response = h.exchange(Caller::ApprovalAgent, Op::Decide, args).await;
        assert_eq!(
            response["error"]["code"], expected,
            "variant {variant}: {response}"
        );
        h.reason(expected);
    }
}

#[test]
fn all_directive_failure_levels_algorithms_audiences_and_class_fields_are_audited() {
    for variant in 0..9 {
        let h = Harness::new();
        let mut directive = signed_directive(
            &h,
            DirectiveOp::QueryStatus,
            json!({}),
            ApprovalLevel::Strong,
        );
        let expected = match variant {
            0 => {
                directive.iss_kind = IssuerKind::Unknown("bad".into());
                "unsupported_authority"
            }
            1 => {
                directive.iss = "other".into();
                "unpaired_device"
            }
            2 => {
                directive.iss_alg = SignatureAlgorithm::RS256;
                "unsupported_algorithm"
            }
            3 => {
                directive.aud = "other".into();
                "wrong_recipient"
            }
            4 => {
                directive.op = DirectiveOp::SetClass;
                directive.args = json!({"name":"","match":{"host":"x"},"exp_s":1})
                    .as_object()
                    .unwrap()
                    .clone();
                "invalid_approval_class"
            }
            5 => {
                directive.op = DirectiveOp::SetClass;
                directive.args = json!({"name":"x","match":{},"exp_s":1})
                    .as_object()
                    .unwrap()
                    .clone();
                "invalid_approval_class"
            }
            6 => {
                directive.op = DirectiveOp::SetClass;
                directive.args = json!({"name":"x","match":{"unknown":"x"},"exp_s":1})
                    .as_object()
                    .unwrap()
                    .clone();
                "invalid_approval_class"
            }
            7 => {
                directive.op = DirectiveOp::SetClass;
                directive.args = json!({"name":"x","match":{"host":2},"exp_s":1})
                    .as_object()
                    .unwrap()
                    .clone();
                "invalid_approval_class"
            }
            _ => {
                directive.op = DirectiveOp::SetMode;
                directive.args = json!({"mode":"invalid"}).as_object().unwrap().clone();
                "invalid_directive"
            }
        };
        directive.sig = sign_object(
            &directive,
            SignatureAlgorithm::ES256,
            key("strong").as_ref(),
        )
        .unwrap();
        assert_eq!(
            h.helper
                .apply_directive(&directive, ApprovalLevel::Strong)
                .unwrap_err()
                .code(),
            expected,
            "variant {variant}"
        );
        h.reason(expected);
    }
}

#[test]
fn directive_dangerous_confirmation_and_cancelled_or_completed_ids() {
    let h = Harness::new();
    let request = h.helper.submit(h.input(Tier::T1, "A")).unwrap();
    let cancel = signed_directive(
        &h,
        DirectiveOp::CancelApproval,
        json!({"approval_id":request.approval_id}),
        ApprovalLevel::Quick,
    );
    h.helper
        .apply_directive(&cancel, ApprovalLevel::Quick)
        .unwrap();
    let cancel = signed_directive(
        &h,
        DirectiveOp::CancelApproval,
        json!({"approval_id":request.approval_id}),
        ApprovalLevel::Quick,
    );
    assert_eq!(
        h.helper
            .apply_directive(&cancel, ApprovalLevel::Quick)
            .unwrap_err()
            .code(),
        "already_consumed"
    );
    h.reason("already_consumed");
    let directive = signed_directive(
        &h,
        DirectiveOp::RevokeDevice,
        json!({"device_id":h.peer.device_id,"confirm":"srv"}),
        ApprovalLevel::Strong,
    );
    h.helper
        .apply_directive(&directive, ApprovalLevel::Strong)
        .unwrap();
    assert_eq!(
        h.helper
            .lock()
            .unwrap()
            .store
            .device(&h.peer.device_id, "account")
            .unwrap_err()
            .code(),
        "revoked_device"
    );
}

#[tokio::test]
async fn execution_rechecks_epoch_liveness_expiration_and_full_binding() {
    for variant in 0..6 {
        let h = Harness::new();
        let request = h.helper.submit(h.input(Tier::T1, "A")).unwrap();
        let decision = h.decision(&request, ApprovalLevel::Quick, ScopeMode::PerUse);
        h.helper
            .accept_decision(
                &mut h.helper.lock().unwrap(),
                &h.peer,
                &decision,
                h.clock.now(),
                h.clock.now(),
            )
            .unwrap();
        match variant {
            0 => h
                .helper
                .lock()
                .unwrap()
                .store
                .set_setting("epoch", &1u64, "local", h.clock.now())
                .unwrap(),
            1 => h.runner.alive.store(false, Ordering::SeqCst),
            2 => {
                h.helper.lock().unwrap().full.clear();
            }
            3 => {
                h.helper.lock().unwrap().full.insert(
                    request.approval_id.clone(),
                    FullRequest::new("proxy", json!({"body":"B"}).as_object().unwrap().clone())
                        .unwrap(),
                );
            }
            4 => h.clock.0.store(request.exp + 1, Ordering::SeqCst),
            _ => {
                h.helper
                    .lock()
                    .unwrap()
                    .store
                    .db
                    .execute("UPDATE devices SET revoked_at=1", [])
                    .unwrap();
            }
        }
        let result = h.helper.execute_approved(&request.approval_id).await;
        match variant {
            0 => {
                assert_eq!(result.unwrap_err().code(), "authorization_revoked");
                h.reason("authorization_revoked");
            }
            3 => {
                assert_eq!(result.unwrap_err().code(), "digest_mismatch");
                h.reason("digest_mismatch");
            }
            5 => {
                assert_eq!(result.unwrap_err().code(), "revoked_device");
                h.reason("revoked_device");
            }
            _ => result.unwrap(),
        };
        assert_eq!(h.runner.calls.load(Ordering::SeqCst), 0);
        if variant == 1 {
            assert_eq!(
                h.helper
                    .result(&request.approval_id, 501, 4242, true)
                    .unwrap()
                    .status,
                ToolStatus::ApprovedRetryRequired
            );
        }
    }
}

#[tokio::test]
async fn pending_filters_and_claim_false_do_not_leak_another_agents_result() {
    let h = Harness::new();
    let request = h.helper.submit(h.input(Tier::T1, "A")).unwrap();
    let mut input = h.input(Tier::T1, "B");
    input.canonical.agent.pid = 4243;
    input.session_id = "other".into();
    h.helper.submit(input).unwrap();
    let response = h.exchange(Caller::Mcp, Op::PendingList, json!({})).await;
    assert_eq!(response["result"]["pending"].as_array().unwrap().len(), 1);
    let response = h
        .exchange(Caller::Hook, Op::PendingForAgent, json!({"agent_pid":4242}))
        .await;
    assert_eq!(response["result"]["pending"].as_array().unwrap().len(), 1);
    {
        let state = h.helper.lock().unwrap();
        assert_eq!(
            h.helper
                .pending_summaries(&state, Some(4242))
                .unwrap()
                .len(),
            1
        );
        assert!(h
            .helper
            .pending_summaries(&state, Some(1))
            .unwrap()
            .is_empty());
    }
    let decision = h.decision(&request, ApprovalLevel::Quick, ScopeMode::PerUse);
    h.helper
        .accept_decision(
            &mut h.helper.lock().unwrap(),
            &h.peer,
            &decision,
            h.clock.now(),
            h.clock.now(),
        )
        .unwrap();
    h.helper
        .execute_approved(&request.approval_id)
        .await
        .unwrap();
    assert_eq!(
        h.helper
            .result(&request.approval_id, 501, 4242, false)
            .unwrap()
            .status,
        ToolStatus::Ok
    );
    assert_eq!(
        h.helper
            .wait(&request.approval_id, 0, 10, 501, 4243)
            .await
            .unwrap_err()
            .code(),
        "forbidden"
    );
    assert_eq!(
        h.helper
            .result(&request.approval_id, 501, 4242, true)
            .unwrap()
            .status,
        ToolStatus::Ok
    );
    let response = h
        .exchange(
            Caller::Hook,
            Op::PendingStopBlock,
            json!({"approval_id":request.approval_id}),
        )
        .await;
    assert_eq!(response["result"]["allowed"], false);
}

#[tokio::test]
async fn short_merged_grant_never_covers_an_operation_outside_the_signed_binding() {
    let h = Harness::new();
    let mut request = h.helper.submit(h.input(Tier::T1, "A")).unwrap();
    for _ in 0..2 {
        request = h.helper.submit(h.input(Tier::T1, "A")).unwrap();
    }
    let decision = h.decision(&request, ApprovalLevel::Quick, ScopeMode::PerUse);
    h.helper
        .accept_decision(
            &mut h.helper.lock().unwrap(),
            &h.peer,
            &decision,
            h.clock.now(),
            h.clock.now(),
        )
        .unwrap();
    let canonical = h
        .helper
        .lock()
        .unwrap()
        .store
        .pending(&request.approval_id)
        .unwrap()
        .canonical;
    let mut usage = GrantUse {
        canonical: canonical.clone(),
        tier: Tier::T1,
        template_allowed_hosts: vec![canonical.host.clone().unwrap()],
        policy_allowed_methods: vec![canonical.method.clone().unwrap()],
        body_bytes: 0,
        session_id: "session".into(),
    };
    assert_eq!(h.helper.cover_and_debit(&usage).unwrap().jtis.len(), 1);
    usage.canonical.purpose = "different operation".into();
    assert!(h.helper.cover_and_debit(&usage).unwrap().jtis.is_empty());
}

#[tokio::test]
async fn expired_presence_and_terminal_cancellation_do_not_preserve_results() {
    let h = Harness::new();
    let hint = PresenceHint {
        device_id: "dev_srv".into(),
        state: Presence::Present,
        since: h.clock.now(),
        sent_at: h.clock.now(),
        extra: Extra::new(),
    };
    h.exchange(
        Caller::ApprovalAgent,
        Op::PresenceUpdate,
        serde_json::to_value(hint).unwrap(),
    )
    .await;
    let request = h.helper.submit(h.input(Tier::T1, "A")).unwrap();
    let envelopes = h.helper.outbound_poll(0).await.unwrap();
    let envelope = envelopes
        .iter()
        .find(|envelope| {
            envelope.id == request.approval_id && envelope.r#type == EnvelopeType::ApprovalRequest
        })
        .unwrap();
    let data = kv_core::remote::envelope::open(
        envelope,
        &h.peer.device_id,
        key("recipient").as_ref(),
        &h.helper.local,
        h.clock.now(),
    )
    .unwrap();
    assert_eq!(
        from_json::<ApprovalRequest>(&data).unwrap().delivery.mode,
        DeliveryMode::Silent
    );
    h.clock.0.fetch_add(121, Ordering::SeqCst);
    let request2 = h.helper.submit(h.input(Tier::T1, "B")).unwrap();
    let envelopes = h.helper.outbound_poll(0).await.unwrap();
    let envelope = envelopes
        .iter()
        .find(|e| e.id == request2.approval_id && e.r#type == EnvelopeType::ApprovalRequest)
        .unwrap();
    let data = kv_core::remote::envelope::open(
        envelope,
        &h.peer.device_id,
        key("recipient").as_ref(),
        &h.helper.local,
        h.clock.now(),
    )
    .unwrap();
    assert_eq!(
        from_json::<ApprovalRequest>(&data).unwrap().delivery.mode,
        DeliveryMode::Banner
    );
    h.helper.close_session("session").unwrap();
    assert_eq!(
        h.helper
            .result(&request.approval_id, 501, 4242, true)
            .unwrap()
            .status,
        ToolStatus::ApprovalExpired
    );
}

#[tokio::test]
async fn cached_request_requires_executing_peer_and_matching_cancel_sender() {
    let h = signing_harness();
    let mut request: ApprovalRequest =
        serde_json::from_value(fixture("decision_valid.json")["request"].clone()).unwrap();
    request.requester.device_id = h.peer.device_id.clone();
    let id = request.approval_id.clone();
    h.helper
        .inbound(h.envelope(EnvelopeType::ApprovalRequest, &id, &request))
        .await
        .unwrap();
    let cancel = ApprovalCancel {
        approval_id: id.clone(),
        extra: Extra::new(),
    };
    h.helper
        .inbound(h.envelope(EnvelopeType::ApprovalCancel, &id, &cancel))
        .await
        .unwrap();
    assert!(h.helper.lock().unwrap().inbound_requests.is_empty());
    h.helper
        .inbound(h.envelope(EnvelopeType::ApprovalCancel, &id, &cancel))
        .await
        .unwrap();
    for variant in 0..5 {
        let h = signing_harness();
        let mut request = request.clone();
        match variant {
            0 => request.requester.device_id = "other".into(),
            1 => request.approval_id = "other".into(),
            2 => request.exp += 601,
            3 => request.exp = h.clock.now() - 1,
            _ => {
                h.helper
                    .lock()
                    .unwrap()
                    .store
                    .db
                    .execute(
                        "UPDATE devices SET record_json=?1",
                        [encode(&h.peer).unwrap()],
                    )
                    .unwrap();
            }
        };
        assert_eq!(
            h.helper
                .inbound(h.envelope(EnvelopeType::ApprovalRequest, &id, &request))
                .await
                .unwrap_err()
                .code(),
            "invalid_approval_request"
        );
        h.reason("invalid_approval_request");
    }
}

#[tokio::test]
async fn paired_executor_identity_key_is_insufficient_approval_authority() {
    let h = Harness::new();
    let mut peer = h.peer.clone();
    peer.caps = vec![Capability::Execute];
    peer.ak_q = None;
    peer.ak_s = None;
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
    let data = fixture("decision_valid.json");
    let decision: ApprovalDecision = serde_json::from_value(data["decision"].clone()).unwrap();
    assert_eq!(
        h.helper
            .inbound(h.envelope(
                EnvelopeType::ApprovalDecision,
                &decision.approval_id,
                &decision
            ))
            .await
            .unwrap_err()
            .code(),
        "unsupported_authority"
    );
    h.reason("unsupported_authority");
    assert_eq!(
        h.helper.submit(h.input(Tier::T1, "A")).unwrap_err().code(),
        "no_approver"
    );
    h.reason("no_approver");
}

#[test]
fn local_mode_quick_cannot_loosen_and_device_cannot_revoke_itself() {
    let h = Harness::new();
    h.helper
        .set_mode_local("per_use", ApprovalLevel::Quick)
        .unwrap();
    assert_eq!(
        h.helper
            .set_mode_local("per_session", ApprovalLevel::Quick)
            .unwrap_err()
            .code(),
        "insufficient_level"
    );
    h.reason("insufficient_level");
    assert_eq!(
        h.helper
            .revoke_device(&h.helper.local.device_id, "local")
            .unwrap_err()
            .code(),
        "unpaired_device"
    );
}

#[tokio::test]
async fn remote_backend_install_is_single_assignment_and_frame_failures_are_audited() {
    let h = Harness::new();
    super::super::server::install_runtime(h.helper.clone()).unwrap();
    assert!(super::super::server::runtime().is_some());
    assert_eq!(
        super::super::server::install_runtime(h.helper.clone())
            .unwrap_err()
            .code(),
        "remote_already_initialized"
    );
    let result = super::super::server::serve(
        b"truncated".as_slice(),
        tokio::io::sink(),
        CallerContext::authenticated(Caller::CliOwner, 501, 4242, 50),
        Some(h.helper.clone()),
    )
    .await;
    assert_eq!(result.unwrap_err().code(), "truncated_frame");
    h.reason("truncated_frame");
    let result = super::super::server::serve(
        b"{\"op\":\"remote.invalid\"}\n".as_slice(),
        tokio::io::sink(),
        CallerContext::authenticated(Caller::CliOwner, 501, 4242, 50),
        None,
    )
    .await;
    assert_eq!(result.unwrap_err().code(), "invalid_remote_op");
}

#[tokio::test]
async fn pairing_accept_and_agent_confirmation_work_over_the_fake_pipe_and_audit_rejections() {
    let h = Harness::with(Store::memory().unwrap(), 1_800_000_000, false);
    let response = h
        .exchange(
            Caller::CliOwner,
            Op::PairStart,
            json!({"relay_url":"https://relay.example.org"}),
        )
        .await;
    assert_eq!(response["ok"], true);
    let token = response["result"]["token"].as_str().unwrap();
    let accept = PairAccept {
        token: token.into(),
        joiner: h.peer.clone(),
        extra: Extra::new(),
    };
    h.helper
        .inbound(h.envelope(EnvelopeType::PairAccept, "pair", &accept))
        .await
        .unwrap();
    let sas = h.exchange(Caller::CliOwner, Op::Status, json!({})).await["result"]["pairing"]["sas"]
        .as_str()
        .unwrap()
        .to_owned();
    let confirm = kv_core::remote::pairing::sign_confirm(
        &sas,
        SignatureAlgorithm::ES256,
        key("strong").as_ref(),
    )
    .unwrap();
    assert_eq!(
        h.exchange(
            Caller::ApprovalAgent,
            Op::PairConfirm,
            serde_json::to_value(confirm).unwrap()
        )
        .await["ok"],
        true
    );
    let terminal = PairConfirm {
        sas: sas.clone(),
        sig: String::new(),
        extra: Extra::new(),
    };
    assert_eq!(
        h.exchange(
            Caller::CliOwner,
            Op::PairConfirm,
            serde_json::to_value(terminal).unwrap()
        )
        .await["ok"],
        true
    );
    assert!(h
        .helper
        .lock()
        .unwrap()
        .store
        .device(&h.peer.device_id, "account")
        .is_ok());
    for relay in [
        "http://relay.example.org",
        "https://",
        "https://relay.example.org/path",
        "https://owner@relay.example.org",
    ] {
        let result = h
            .exchange(Caller::CliOwner, Op::PairStart, json!({"relay_url":relay}))
            .await;
        assert_eq!(result["error"]["code"], "invalid_relay_url");
        h.reason("invalid_relay_url");
    }
    assert_eq!(super::super::pairing::base32(b""), "");
    assert_eq!(super::super::pairing::base32(b"foo"), "MZXW6");
    assert_eq!(super::super::pairing::base32(b"abcde"), "MFRGGZDF");
}

#[tokio::test]
async fn pairing_rejects_wrong_tokens_known_devices_and_missing_strong_capability() {
    for variant in 0..6 {
        let h = Harness::with(Store::memory().unwrap(), 1_800_000_000, variant == 4);
        let offer = h.helper.pair_start("https://relay.example.org").unwrap();
        let mut accept = PairAccept {
            token: offer.extra["token"].as_str().unwrap().into(),
            joiner: h.peer.clone(),
            extra: Extra::new(),
        };
        let expected = match variant {
            0 => {
                accept.token = kv_core::remote::keys::encode_b64(&[0; 8]);
                "unknown_token"
            }
            1 => {
                accept.token = kv_core::remote::keys::encode_b64(&[0; 16]);
                "unknown_token"
            }
            2 => {
                accept.joiner.device_id.clear();
                "strong_key_required"
            }
            3 => {
                accept.joiner.device_id = h.helper.local.device_id.clone();
                "strong_key_required"
            }
            4 => "device_already_known",
            _ => {
                accept.joiner.ak_s = None;
                accept
                    .joiner
                    .caps
                    .retain(|c| *c != Capability::ApproveStrong);
                "strong_key_required"
            }
        };
        assert_eq!(h.helper.pair_complete(accept).unwrap_err().code(), expected);
        h.reason(expected);
        assert!(h.helper.lock().unwrap().pairing.is_none());
    }
}

#[tokio::test]
async fn pairing_envelope_validates_expiration_size_sender_and_confirm_stage() {
    for variant in 0..6 {
        let h = Harness::with(Store::memory().unwrap(), 1_800_000_000, false);
        let offer = h.helper.pair_start("https://relay.example.org").unwrap();
        let mut accept = PairAccept {
            token: offer.extra["token"].as_str().unwrap().into(),
            joiner: h.peer.clone(),
            extra: Extra::new(),
        };
        if variant == 3 {
            accept.joiner.device_id = "different".into();
        }
        let mut envelope = h.envelope(EnvelopeType::PairAccept, "pair", &accept);
        let expected = match variant {
            0 => {
                envelope.exp += 1;
                "invalid_pair_expiration"
            }
            1 => {
                envelope.exp = h.clock.now() - 1;
                "expired"
            }
            2 => {
                envelope.ct = "A".repeat(90_000);
                "payload_too_large"
            }
            3 => "wrong_sender",
            4 => {
                envelope = h.envelope(
                    EnvelopeType::PairConfirm,
                    "pair",
                    &PairConfirm {
                        sas: "000000".into(),
                        sig: String::new(),
                        extra: Extra::new(),
                    },
                );
                "pair_not_accepted"
            }
            _ => {
                h.clock.0.fetch_add(601, Ordering::SeqCst);
                "expired"
            }
        };
        assert_eq!(
            h.helper.inbound(envelope).await.unwrap_err().code(),
            expected,
            "variant {variant}"
        );
        h.reason(expected);
        assert!(h.helper.lock().unwrap().pairing.is_none());
    }
}

#[tokio::test]
async fn pairing_terminal_and_signed_confirmation_are_one_time_and_expire() {
    for variant in 0..4 {
        let h = Harness::with(Store::memory().unwrap(), 1_800_000_000, false);
        let offer = h.helper.pair_start("https://relay.example.org").unwrap();
        let accept = PairAccept {
            token: offer.extra["token"].as_str().unwrap().into(),
            joiner: h.peer.clone(),
            extra: Extra::new(),
        };
        let sas = h.helper.pair_complete(accept).unwrap().sas;
        let terminal = PairConfirm {
            sas: sas.clone(),
            sig: String::new(),
            extra: Extra::new(),
        };
        let signed = kv_core::remote::pairing::sign_confirm(
            &sas,
            SignatureAlgorithm::ES256,
            key("strong").as_ref(),
        )
        .unwrap();
        let error = match variant {
            0 => {
                h.helper.pair_confirm_terminal(&terminal).unwrap();
                h.helper.pair_confirm_terminal(&terminal).unwrap_err()
            }
            1 => {
                h.helper.pair_confirm_signed(&signed).unwrap();
                h.helper.pair_confirm_signed(&signed).unwrap_err()
            }
            2 => {
                h.clock.0.fetch_add(601, Ordering::SeqCst);
                h.helper.pair_confirm_terminal(&terminal).unwrap_err()
            }
            _ => {
                h.clock.0.fetch_add(601, Ordering::SeqCst);
                h.helper.pair_confirm_signed(&signed).unwrap_err()
            }
        };
        let expected = if variant < 2 { "replay" } else { "expired" };
        assert_eq!(error.code(), expected);
        h.reason(expected);
    }
    let h = Harness::with(Store::memory().unwrap(), 1_800_000_000, false);
    h.helper.pair_start("https://relay.example.org").unwrap();
    h.clock.0.fetch_add(601, Ordering::SeqCst);
    h.helper.tick().unwrap();
    assert!(h.helper.lock().unwrap().pairing.is_none());
    h.reason("expired");
}

#[test]
fn grant_installer_rejects_empty_replayed_or_revoked_jti_and_audits_bad_stored_signatures() {
    let h = Harness::new();
    let mut grant = signed_grant(&h, "", Tier::T1, 2);
    grant.sig = sign_object(&grant, SignatureAlgorithm::ES256, key("strong").as_ref()).unwrap();
    assert_eq!(
        h.helper
            .install_grant(&grant, ApprovalLevel::Strong)
            .unwrap_err()
            .code(),
        "invalid_grant"
    );
    h.reason("invalid_grant");
    let grant = signed_grant(&h, "repeat", Tier::T1, 2);
    h.helper
        .install_grant(&grant, ApprovalLevel::Strong)
        .unwrap();
    assert_eq!(
        h.helper
            .install_grant(&grant, ApprovalLevel::Strong)
            .unwrap_err()
            .code(),
        "replay"
    );
    h.reason("replay");
    h.helper.revoke_grant(&grant.jti, "local").unwrap();
    assert_eq!(
        h.helper
            .install_grant(&grant, ApprovalLevel::Strong)
            .unwrap_err()
            .code(),
        "revoked_grant"
    );
    h.reason("revoked_grant");
    let grant = signed_grant(&h, "bad", Tier::T1, 2);
    h.helper
        .install_grant(&grant, ApprovalLevel::Strong)
        .unwrap();
    let mut value = serde_json::to_value(grant).unwrap();
    value["scope"]["max_tier"] = json!("T2");
    h.helper
        .lock()
        .unwrap()
        .store
        .db
        .execute(
            "UPDATE grants SET object_json=?1 WHERE jti='bad'",
            [encode(&value).unwrap()],
        )
        .unwrap();
    let input = h.input(Tier::T1, "A");
    let usage = GrantUse {
        canonical: input.canonical,
        tier: Tier::T1,
        template_allowed_hosts: vec!["api.github.com".into()],
        policy_allowed_methods: vec!["POST".into()],
        body_bytes: 0,
        session_id: "session".into(),
    };
    assert!(h.helper.cover_and_debit(&usage).unwrap().jtis.is_empty());
    h.reason("invalid_signature");
}

#[test]
fn grant_scope_checks_kind_tier_credential_host_method_path_and_agent_independently() {
    for variant in 0..9 {
        let h = Harness::new();
        let mut grant = signed_grant(&h, "scope", Tier::T1, 2);
        let mut canonical = h.input(Tier::T1, "A").canonical;
        let mut tier = Tier::T1;
        match variant {
            0 => canonical.kind = ApprovalKind::Admin,
            1 => tier = Tier::T2,
            2 => canonical.credential = Some("other/default".into()),
            3 => canonical.host = Some("other.example.org".into()),
            4 => canonical.host = None,
            5 => canonical.method = None,
            6 => canonical.path = None,
            7 => grant.scope.agent = Optional::Value("wrong:agent".into()),
            _ => {
                grant.scope.agent = Optional::Value(format!(
                    "{}:{}",
                    canonical.agent.runtime, canonical.agent.repo_or_cwd
                ));
                grant.budget = Optional::Missing;
                grant.scope.paths = Optional::Missing;
                grant.scope.hosts = Optional::Missing;
                grant.scope.methods = Optional::Missing;
            }
        };
        grant.sig = sign_object(&grant, SignatureAlgorithm::ES256, key("strong").as_ref()).unwrap();
        h.helper
            .install_grant(&grant, ApprovalLevel::Strong)
            .unwrap();
        let usage = GrantUse {
            canonical,
            tier,
            template_allowed_hosts: vec!["api.github.com".into()],
            policy_allowed_methods: vec!["POST".into()],
            body_bytes: 0,
            session_id: "session".into(),
        };
        assert_eq!(
            !h.helper.cover_and_debit(&usage).unwrap().jtis.is_empty(),
            variant == 8,
            "variant {variant}"
        );
    }
}

#[test]
fn budget_windows_reset_without_amplifying_calls_or_byte_allowance() {
    for per in [BudgetPeriod::OneDay, BudgetPeriod::SevenDays] {
        let h = Harness::new();
        let mut grant = signed_grant(&h, "window", Tier::T1, 2);
        let period = if per == BudgetPeriod::OneDay {
            86400
        } else {
            604800
        };
        grant.exp = Some(h.clock.now() + period * 2);
        grant.budget = Optional::Value(Budget {
            calls: 2,
            per,
            bytes: Optional::Missing,
            extra: Extra::new(),
        });
        grant.sig = sign_object(&grant, SignatureAlgorithm::ES256, key("strong").as_ref()).unwrap();
        h.helper
            .install_grant(&grant, ApprovalLevel::Strong)
            .unwrap();
        let input = h.input(Tier::T1, "A");
        let usage = GrantUse {
            canonical: input.canonical,
            tier: Tier::T1,
            template_allowed_hosts: vec!["api.github.com".into()],
            policy_allowed_methods: vec!["POST".into()],
            body_bytes: 0,
            session_id: "session".into(),
        };
        for _ in 0..2 {
            assert_eq!(h.helper.cover_and_debit(&usage).unwrap().jtis.len(), 1);
        }
        assert!(h.helper.cover_and_debit(&usage).unwrap().jtis.is_empty());
        h.clock.0.fetch_add(period, Ordering::SeqCst);
        assert_eq!(h.helper.cover_and_debit(&usage).unwrap().jtis.len(), 1);
    }
    let h = Harness::new();
    let grant = signed_grant(&h, "bytes", Tier::T1, 10);
    h.helper
        .install_grant(&grant, ApprovalLevel::Strong)
        .unwrap();
    let input = h.input(Tier::T1, "A");
    let mut usage = GrantUse {
        canonical: input.canonical,
        tier: Tier::T1,
        template_allowed_hosts: vec!["api.github.com".into()],
        policy_allowed_methods: vec!["POST".into()],
        body_bytes: 101,
        session_id: "session".into(),
    };
    assert!(h.helper.cover_and_debit(&usage).unwrap().jtis.is_empty());
    usage.body_bytes = 100;
    assert_eq!(h.helper.cover_and_debit(&usage).unwrap().jtis.len(), 1);
    assert!(h
        .helper
        .audit_entries()
        .unwrap()
        .iter()
        .any(|e| e["op"] == "grant_exhausted"));
}

struct BrokenIo;
impl tokio::io::AsyncRead for BrokenIo {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
        _buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::task::Poll::Ready(Err(std::io::Error::other("fixture I/O failure")))
    }
}
impl tokio::io::AsyncWrite for BrokenIo {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
        _buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::task::Poll::Ready(Err(std::io::Error::other("fixture I/O failure")))
    }
    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::task::Poll::Ready(Ok(()))
    }
    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::task::Poll::Ready(Ok(()))
    }
}

#[tokio::test]
async fn ipc_stream_errors_do_not_panic_or_expose_payloads() {
    let h = Harness::new();
    let caller = CallerContext::authenticated(Caller::CliOwner, 501, 4242, 50);
    assert_eq!(
        super::super::server::serve(BrokenIo, tokio::io::sink(), caller, Some(h.helper.clone()))
            .await
            .unwrap_err()
            .code(),
        "ipc_unavailable"
    );
    h.reason("ipc_unavailable");
    assert_eq!(
        super::super::server::serve(
            b"{\"op\":\"remote.status\",\"params\":{}}\n".as_slice(),
            BrokenIo,
            caller,
            Some(h.helper.clone())
        )
        .await
        .unwrap_err()
        .code(),
        "ipc_unavailable"
    );
    let max = vec![b'A'; kv_ipc::MAX_LINE_BYTES + 1];
    assert_eq!(
        super::super::server::serve(
            max.as_slice(),
            tokio::io::sink(),
            caller,
            Some(h.helper.clone())
        )
        .await
        .unwrap_err()
        .code(),
        "payload_too_large"
    );
    h.reason("payload_too_large");
}

#[tokio::test]
async fn delivery_phone_desktop_cache_and_class_non_matches_are_conservative() {
    let mut h = Harness::new();
    let mut desktop = h.peer.clone();
    desktop.os = Os::Macos;
    let mut phone = h.peer.clone();
    phone.os = Os::Android;
    phone.device_id = "phone".into();
    {
        let state = h.helper.lock().unwrap();
        state
            .store
            .db
            .execute(
                "UPDATE devices SET record_json=?1 WHERE id=?2",
                params![encode(&desktop).unwrap(), desktop.device_id],
            )
            .unwrap();
        state
            .store
            .insert_device(&phone, "account", h.clock.now())
            .unwrap();
    }
    let hint = PresenceHint {
        device_id: desktop.device_id.clone(),
        state: Presence::Present,
        since: h.clock.now(),
        sent_at: h.clock.now(),
        extra: Extra::new(),
    };
    h.helper
        .inbound(h.envelope(EnvelopeType::PresenceHint, "hint", &hint))
        .await
        .unwrap();
    let request = h.helper.submit(h.input(Tier::T1, "A")).unwrap();
    let messages = h.helper.outbound_poll(0).await.unwrap();
    let envelope = messages
        .iter()
        .find(|e| e.to == "phone" && e.id == request.approval_id)
        .unwrap();
    let body = kv_core::remote::envelope::open(
        envelope,
        "phone",
        key("recipient").as_ref(),
        &h.helper.local,
        h.clock.now(),
    )
    .unwrap();
    assert_eq!(
        from_json::<ApprovalRequest>(&body).unwrap().delivery.mode,
        DeliveryMode::Silent
    );
    assert!(h
        .helper
        .result(&request.approval_id, 501, 4242, false)
        .unwrap()
        .approver
        .as_value()
        .is_some());
    h.clock.0.fetch_add(121, Ordering::SeqCst);
    {
        let state = h.helper.lock().unwrap();
        state
            .store
            .set_setting("notify", &NotifyPolicy::Both, "local", h.clock.now())
            .unwrap();
    }
    Arc::get_mut(&mut h.helper).unwrap().config.class = vec![
        ApprovalClass {
            name: "not-this".into(),
            r#match: ClassMatch {
                credential: Some("other/*".into()),
                host: None,
            },
            exp_s: 1,
        },
        ApprovalClass {
            name: "other-host".into(),
            r#match: ClassMatch {
                credential: None,
                host: Some("other.example.org".into()),
            },
            exp_s: 1,
        },
    ];
    let request = h.helper.submit(h.input(Tier::T1, "B")).unwrap();
    assert_eq!(request.exp - h.clock.now(), 600);
    let messages = h.helper.outbound_poll(0).await.unwrap();
    for envelope in messages
        .iter()
        .filter(|e| e.id == request.approval_id && e.r#type == EnvelopeType::ApprovalRequest)
    {
        let body = kv_core::remote::envelope::open(
            envelope,
            &envelope.to,
            key("recipient").as_ref(),
            &h.helper.local,
            h.clock.now(),
        )
        .unwrap();
        assert_eq!(
            from_json::<ApprovalRequest>(&body).unwrap().delivery.mode,
            DeliveryMode::Banner
        );
    }
}

#[test]
fn same_session_window_and_capability_checks_do_not_merge_unrelated_pending_requests() {
    let h = Harness::new();
    let first = h.helper.submit(h.input(Tier::T1, "A")).unwrap();
    let mut other = h.input(Tier::T1, "A");
    other.session_id = "different".into();
    assert_ne!(
        h.helper.submit(other).unwrap().approval_id,
        first.approval_id
    );
    h.clock.0.fetch_add(31, Ordering::SeqCst);
    assert_ne!(
        h.helper.submit(h.input(Tier::T1, "A")).unwrap().approval_id,
        first.approval_id
    );
    let request = h.helper.submit(h.input(Tier::T2, "B")).unwrap();
    assert_ne!(
        h.helper.submit(h.input(Tier::T1, "B")).unwrap().approval_id,
        request.approval_id
    );
    let h = Harness::new();
    let mut device = h.peer.clone();
    device.ak_s = None;
    device.caps.retain(|c| *c != Capability::ApproveStrong);
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
    let error = h.helper.submit(h.input(Tier::T2, "A")).unwrap_err();
    assert_eq!(error.code(), "no_approver");
    h.reason("no_approver");
}

#[tokio::test]
async fn original_body_is_retained_on_timeout_and_retry_waiting_or_expired_does_not_execute() {
    let h = Harness::new();
    h.helper.lock().unwrap().relay_connected = true;
    let request = h.helper.submit(h.input(Tier::T1, "A")).unwrap();
    assert_eq!(
        h.helper
            .wait(&request.approval_id, 1, 11, 501, 4242)
            .await
            .unwrap()
            .status,
        ToolStatus::StillPending
    );
    let canonical = h
        .helper
        .lock()
        .unwrap()
        .store
        .pending(&request.approval_id)
        .unwrap()
        .canonical;
    let result = h
        .helper
        .retry(
            &request.approval_id,
            &canonical,
            h.input(Tier::T1, "A").full_request,
            501,
            4242,
        )
        .await
        .unwrap();
    assert_eq!(result.status, ToolStatus::ApprovalPending);
    h.clock.0.store(request.exp + 1, Ordering::SeqCst);
    h.helper.tick().unwrap();
    let result = h
        .helper
        .retry(
            &request.approval_id,
            &canonical,
            h.input(Tier::T1, "A").full_request,
            501,
            4242,
        )
        .await
        .unwrap();
    assert_eq!(result.status, ToolStatus::ApprovalExpired);
    assert_eq!(h.runner.calls.load(Ordering::SeqCst), 0);
}
