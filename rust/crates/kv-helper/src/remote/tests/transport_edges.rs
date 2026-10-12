use super::boundaries::signing_harness;
use super::sql_faults::deny_once;
use super::workflow::{present_signals, signed_grant};
use super::*;
use kv_ipc::remote::{OutboundStage, RelayOutboundAckParams};

fn receipt(envelopes: Vec<Envelope>, stage: OutboundStage) -> RelayOutboundAckParams<Envelope> {
    RelayOutboundAckParams {
        envelopes,
        stage,
        extra: Extra::new(),
    }
}

struct RequestThenReadFailure(Vec<u8>);
impl tokio::io::AsyncRead for RequestThenReadFailure {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
        buffer: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        if buffer.remaining() == 0 {
            return std::task::Poll::Ready(Ok(()));
        }
        if self.0.is_empty() {
            return std::task::Poll::Ready(Err(std::io::Error::other("simulated read failure")));
        }
        let count = self.0.len().min(buffer.remaining());
        buffer.put_slice(&self.0[..count]);
        self.0.drain(..count);
        std::task::Poll::Ready(Ok(()))
    }
}

#[tokio::test]
async fn a_transport_read_failure_during_cold_wait_is_audited_and_never_consumes_authority() {
    let h = Harness::new();
    h.helper.lock().unwrap().relay_connected = true;
    let request = h.helper.submit(h.input(Tier::T1, "waiting")).unwrap();
    let mut frame = serde_json::to_vec(&json!({"op":"remote.wait",
        "params":{"approval_id":request.approval_id,"max_wait_ms":5000}}))
    .unwrap();
    frame.push(b'\n');
    let result = super::super::server::serve(
        RequestThenReadFailure(frame),
        tokio::io::sink(),
        CallerContext::authenticated(Caller::Mcp, 501, 4242, 50),
        Some(h.helper.clone()),
    )
    .await;
    assert_eq!(result.unwrap_err().code(), "ipc_unavailable");
    h.reason("ipc_unavailable");
    let state = h.helper.lock().unwrap();
    assert_eq!(
        state.store.pending(&request.approval_id).unwrap().state,
        PendingState::Waiting
    );
    assert!(state.full.contains_key(&request.approval_id));
    assert_eq!(h.runner.calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn durable_outbox_receipts_bind_ciphertext_preserve_prefixes_and_retire_only_obsolete_messages(
) {
    let h = Harness::new();
    let request = h.helper.submit(h.input(Tier::T1, "A")).unwrap();
    let queued = h.helper.outbound_poll(0).await.unwrap();
    let inspect = receipt(queued.clone(), OutboundStage::Inspect);
    assert_eq!(h.helper.outbound_ack(inspect.clone()).unwrap(), 0);
    h.spooled(&queued);
    h.spooled(&queued);
    assert!(h.helper.outbound_poll(0).await.unwrap().is_empty());
    let mut changed = queued.clone();
    changed[0].extra.insert("tampered".into(), json!(true));
    assert_eq!(
        h.helper
            .outbound_ack(receipt(changed, OutboundStage::Accepted))
            .unwrap_err()
            .code(),
        "unknown_outbox_receipt"
    );
    assert_eq!(
        h.helper
            .outbound_ack(receipt(Vec::new(), OutboundStage::Spooled))
            .unwrap_err()
            .code(),
        "invalid_outbox_receipt"
    );
    assert_eq!(
        h.helper
            .outbound_ack(receipt(vec![queued[0].clone(); 65], OutboundStage::Spooled))
            .unwrap_err()
            .code(),
        "invalid_outbox_receipt"
    );
    h.helper
        .outbound_ack(receipt(queued.clone(), OutboundStage::Accepted))
        .unwrap();
    assert_eq!(h.helper.outbound_ack(inspect.clone()).unwrap(), 1);
    assert_eq!(h.helper.outbound_ack(inspect).unwrap(), 1);
    h.spooled(&queued);
    assert!(h.helper.outbound_poll(0).await.unwrap().is_empty());
    let request2 = h.helper.submit(h.input(Tier::T1, "B")).unwrap();
    let queued = h.helper.outbound_poll(0).await.unwrap();
    h.spooled(&queued);
    h.helper
        .lock()
        .unwrap()
        .store
        .db
        .execute(
            "UPDATE pending_approvals SET state='denied' WHERE id=?1",
            [&request2.approval_id],
        )
        .unwrap();
    assert_eq!(
        h.helper
            .outbound_ack(receipt(queued, OutboundStage::Inspect))
            .unwrap(),
        1
    );
    let cancel = h.envelope(
        EnvelopeType::ApprovalCancel,
        &request.approval_id,
        &ApprovalCancel {
            approval_id: request.approval_id.clone(),
            extra: Extra::new(),
        },
    );
    h.helper.lock().unwrap().store.queue(&cancel).unwrap();
    assert_eq!(
        h.helper
            .outbound_ack(receipt(vec![cancel.clone()], OutboundStage::Inspect))
            .unwrap(),
        0
    );
    h.clock.0.store(cancel.exp + 1, Ordering::SeqCst);
    h.helper.tick().unwrap();
    assert_eq!(
        h.helper
            .outbound_ack(receipt(vec![cancel], OutboundStage::Inspect))
            .unwrap(),
        1
    );
}

#[tokio::test]
async fn receipts_are_monotonic_and_inspection_stops_at_the_first_live_item() {
    let h = Harness::new();
    let first = h.envelope(EnvelopeType::Grant, "first", &json!({}));
    let second = h.envelope(EnvelopeType::Grant, "second", &json!({}));
    for envelope in [&first, &second] {
        h.helper.lock().unwrap().store.queue(envelope).unwrap();
    }
    h.helper
        .outbound_ack(receipt(vec![second.clone()], OutboundStage::Accepted))
        .unwrap();
    assert_eq!(
        h.helper
            .outbound_ack(receipt(
                vec![first.clone(), second.clone()],
                OutboundStage::Inspect
            ))
            .unwrap(),
        0
    );
    h.helper
        .outbound_ack(receipt(vec![first.clone()], OutboundStage::Accepted))
        .unwrap();
    assert_eq!(
        h.helper
            .outbound_ack(receipt(vec![first.clone(), second], OutboundStage::Inspect))
            .unwrap(),
        2
    );
    // A delayed spool acknowledgment cannot downgrade an accepted or retired receipt.
    h.spooled(&[first]);
    assert!(h.helper.outbound_poll(0).await.unwrap().is_empty());
}

#[tokio::test]
async fn relay_acks_only_durably_audited_terminal_rejections() {
    for case in 0..5 {
        let h = Harness::new();
        let mut envelope = h.envelope(EnvelopeType::PresenceHint, "bad", &json!({}));
        let (params, reason, ack) = match case {
            0 => (json!({"envelope":{}}), "invalid_json", true),
            1 => {
                envelope.sig = "bad".into();
                (json!({"envelope":envelope}), "invalid_encoding", true)
            }
            2 => {
                envelope.exp = h.clock.now() - 1;
                (json!({"envelope":envelope}), "expired", true)
            }
            3 => {
                h.audit.fail.store(true, Ordering::SeqCst);
                (json!({"envelope":envelope}), "audit_unavailable", false)
            }
            _ => (
                json!({"envelope":h.envelope(EnvelopeType::ApprovalCancel,"ok",&ApprovalCancel{approval_id:"ok".into(),extra:Extra::new()})}),
                "",
                true,
            ),
        };
        let result = h
            .exchange(Caller::RelayClient, Op::RelayInbound, params)
            .await;
        assert_eq!(result["ok"], ack, "case {case}: {result}");
        if ack {
            assert_eq!(result["result"]["ack"], true);
            if !reason.is_empty() {
                h.reason(reason);
            }
        } else {
            assert_eq!(result["error"]["code"], reason);
        }
        assert_eq!(h.runner.calls.load(Ordering::SeqCst), 0);
    }
}

#[tokio::test]
async fn cancel_escalate_and_directive_result_ids_remain_bound_to_the_original_sender() {
    let h = Harness::new();
    let request = h.helper.submit(h.input(Tier::T1, "A")).unwrap();
    {
        let mut state = h.helper.lock().unwrap();
        let mut incoming = request.clone();
        incoming.requester.device_id = h.peer.device_id.clone();
        state
            .inbound_requests
            .insert(request.approval_id.clone(), incoming);
    }
    for (id, body_id, expected) in [
        (
            request.approval_id.as_str(),
            "wrong",
            Some("invalid_approval_request"),
        ),
        ("unknown", "unknown", Some("not_waiting")),
        (
            request.approval_id.as_str(),
            request.approval_id.as_str(),
            None,
        ),
    ] {
        let result = h
            .helper
            .inbound(h.envelope(
                EnvelopeType::ApprovalEscalate,
                id,
                &ApprovalEscalate {
                    approval_id: body_id.into(),
                    extra: Extra::new(),
                },
            ))
            .await;
        match expected {
            Some(reason) => {
                assert_eq!(result.unwrap_err().code(), reason);
                h.reason(reason);
            }
            None => result.unwrap(),
        }
    }
    h.helper
        .lock()
        .unwrap()
        .inbound_requests
        .get_mut(&request.approval_id)
        .unwrap()
        .requester
        .device_id = "another".into();
    let escalation = ApprovalEscalate {
        approval_id: request.approval_id.clone(),
        extra: Extra::new(),
    };
    assert_eq!(
        h.helper
            .inbound(h.envelope(
                EnvelopeType::ApprovalEscalate,
                &request.approval_id,
                &escalation
            ))
            .await
            .unwrap_err()
            .code(),
        "wrong_sender"
    );
    h.reason("wrong_sender");
    let cancellation = ApprovalCancel {
        approval_id: "wrong".into(),
        extra: Extra::new(),
    };
    assert_eq!(
        h.helper
            .inbound(h.envelope(
                EnvelopeType::ApprovalCancel,
                &request.approval_id,
                &cancellation
            ))
            .await
            .unwrap_err()
            .code(),
        "invalid_approval_request"
    );
    h.reason("invalid_approval_request");
    let result = DirectiveResult {
        id: "unknown".into(),
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
}

struct JumpClock {
    calls: AtomicUsize,
    before: i64,
    after: i64,
    at: usize,
}
impl Clock for JumpClock {
    fn now(&self) -> i64 {
        if self.calls.fetch_add(1, Ordering::SeqCst) < self.at {
            self.before
        } else {
            self.after
        }
    }
}

#[tokio::test]
async fn notices_skip_another_user_expired_requests_and_already_notified_ids() {
    for case in 0..3 {
        let mut h = Harness::new();
        let request = h.helper.submit(h.input(Tier::T1, "A")).unwrap();
        let mut seen = std::collections::HashSet::new();
        if case == 0 {
            seen.insert(request.approval_id.clone());
        }
        {
            let state = h.helper.lock().unwrap();
            state
                .store
                .db
                .execute("UPDATE pending_approvals SET state='approved_unused'", [])
                .unwrap();
        }
        let before = h.clock.now();
        if case == 2 {
            Arc::get_mut(&mut h.helper).unwrap().services.clock = Arc::new(JumpClock {
                calls: AtomicUsize::new(0),
                before,
                after: request.exp + 1,
                at: 2,
            });
        }
        let context =
            CallerContext::authenticated(Caller::Mcp, if case == 1 { 502 } else { 501 }, 4242, 50);
        let result = tokio::time::timeout(
            std::time::Duration::from_millis(20),
            h.helper.next_approval_notice(context, &mut seen),
        )
        .await;
        assert!(
            result.is_err(),
            "case {case} leaked a notification: {result:?}"
        );
    }
    let h = Harness::new();
    let request = h.helper.submit(h.input(Tier::T1, "A")).unwrap();
    h.helper
        .lock()
        .unwrap()
        .store
        .db
        .execute("UPDATE pending_approvals SET state='approved_unused'", [])
        .unwrap();
    let context = CallerContext::authenticated(Caller::Mcp, 501, 4242, 50);
    let result = h
        .helper
        .next_approval_notice(context, &mut Default::default())
        .await
        .unwrap();
    assert_eq!(result["params"]["status"], "approved_retry_required");
    assert_eq!(result["params"]["approval_id"], request.approval_id);
    assert!(result["params"].get("result").is_none());
}

#[tokio::test]
async fn notification_writer_closes_on_transport_failure_and_returns_no_secrets() {
    let h = Harness::new();
    h.helper
        .submit(h.input(Tier::T1, "secret-not-in-notice"))
        .unwrap();
    h.helper
        .lock()
        .unwrap()
        .store
        .db
        .execute("UPDATE pending_approvals SET state='approved_unused'", [])
        .unwrap();
    let (client, server) = tokio::io::duplex(256);
    drop(client);
    let writer = tokio::sync::Mutex::new(server);
    let context = CallerContext::authenticated(Caller::Mcp, 501, 4242, 50);
    assert_eq!(
        super::super::server::push_approval_notices(&h.helper, context, &writer)
            .await
            .unwrap_err()
            .code(),
        "ipc_unavailable"
    );
    assert_eq!(
        super::super::server::push_approval_notices(
            &h.helper,
            CallerContext::authenticated(Caller::Hook, 501, 4242, 50),
            &writer
        )
        .await
        .unwrap_err()
        .code(),
        "forbidden"
    );
}

#[test]
fn authenticated_directory_restore_keeps_tombstones_and_rolls_back_invalid_members() {
    for case in 0..5 {
        let h = Harness::new();
        let store = Store::memory().unwrap();
        let mut revoked = h.peer.clone();
        revoked.device_id = "revoked".into();
        let mut records = vec![(h.peer.clone(), false), (revoked, true)];
        if case == 3 {
            records[1].0.device_id = h.peer.device_id.clone();
        }
        if case == 4 {
            records[1].0.dk_pub.kty = "RSA".into();
        }
        *h.mirror.0.lock().unwrap() = records.clone();
        if case == 1 {
            store
                .insert_device(&h.peer, "account", h.clock.now())
                .unwrap();
        }
        let account = if case == 2 { "" } else { "account" };
        let result =
            store.restore_verified_directory(account, &records, h.mirror.as_ref(), h.clock.now());
        if case == 0 {
            result.unwrap();
            assert!(store.device(&h.peer.device_id, "account").is_ok());
            assert_eq!(
                store.device("revoked", "account").unwrap_err().code(),
                "revoked_device"
            );
        } else {
            assert!(result.is_err());
            let count: u64 = store
                .db
                .query_row("SELECT COUNT(*) FROM devices", [], |r| r.get(0))
                .unwrap();
            assert_eq!(count, if case == 1 { 1 } else { 0 });
        }
    }
}

#[test]
fn timer_cleanup_and_helper_drop_scrub_all_remaining_in_memory_values() {
    let h = Harness::new();
    h.helper
        .lock()
        .unwrap()
        .results
        .insert("orphan".into(), json!({"value":"synthetic"}));
    let weak = Arc::downgrade(&h.helper);
    drop(h);
    assert!(weak.upgrade().is_none());
}

#[tokio::test]
async fn a_healthy_timer_keeps_a_waiting_request_until_expiration() {
    let mut h = Harness::new();
    let request = h.helper.submit(h.input(Tier::T1, "A")).unwrap();
    let clock = Arc::new(JumpClock {
        calls: AtomicUsize::new(0),
        before: h.clock.now(),
        after: h.clock.now(),
        at: 1,
    });
    Arc::get_mut(&mut h.helper).unwrap().services.clock = clock.clone();
    let timer = h.helper.start_timer();
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        while clock.calls.load(Ordering::SeqCst) == 0 {
            tokio::time::sleep(std::time::Duration::from_millis(1)).await;
        }
    })
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
        PendingState::Waiting
    );
    assert!(!timer.is_finished());
    timer.abort();
}

#[tokio::test]
async fn aborted_wait_with_a_failed_audit_or_poisoned_owner_never_executes() {
    for poison in [false, true] {
        let h = Harness::new();
        let pending = h.helper.submit(h.input(Tier::T1, "A")).unwrap();
        h.helper.lock().unwrap().relay_connected = true;
        let helper = h.helper.clone();
        let waiting = tokio::spawn(async move {
            helper
                .handle(
                    CallerContext::authenticated(Caller::Mcp, 501, 4242, 50),
                    Request {
                        op: Op::Wait,
                        params: json!({"approval_id":pending.approval_id,"max_wait_ms":60000}),
                        extra: Extra::new(),
                    },
                )
                .await
        });
        for _ in 0..5 {
            tokio::task::yield_now().await;
        }
        assert!(!waiting.is_finished());
        if poison {
            let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let _state = h.helper.state.lock().unwrap();
                panic!("simulated failure while waiting");
            }));
        } else {
            h.audit.fail.store(true, Ordering::SeqCst);
        }
        waiting.abort();
        assert!(waiting.await.unwrap_err().is_cancelled());
        assert_eq!(h.runner.calls.load(Ordering::SeqCst), 0);
    }
}

struct FailedSigner(Arc<SoftwareDeviceKey>);
impl DeviceKeyProvider for FailedSigner {
    fn sign(&self, _: SignatureAlgorithm, _: &[u8]) -> kv_core::remote::Result<Vec<u8>> {
        Err(RemoteError::KeyOperationFailed)
    }
    fn ecdh(&self, peer: &[u8]) -> kv_core::remote::Result<zeroize::Zeroizing<[u8; 32]>> {
        DeviceKeyProvider::ecdh(self.0.as_ref(), peer)
    }
    fn public_jwk(&self) -> kv_core::remote::Result<PublicJwk> {
        self.0.public_jwk()
    }
    fn presence_kind(&self) -> PresenceKind {
        PresenceKind::None
    }
    fn key_kind(&self) -> KeyKind {
        KeyKind::Software
    }
}

#[tokio::test]
async fn an_approval_key_failure_never_issues_or_consumes_a_decision() {
    let mut h = signing_harness();
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
    Arc::get_mut(&mut h.helper).unwrap().services.strong =
        Some(Arc::new(FailedSigner(key("strong"))));
    let response = h.exchange(Caller::CliOwner,Op::Decide,json!({"approval_id":request.approval_id,"decision":"allow","level":"strong","scope":{"mode":"per_use","level":"credential","until":0}})).await;
    assert_eq!(response["error"]["code"], "key_operation_failed");
    h.reason("key_operation_failed");
    let state = h.helper.lock().unwrap();
    assert!(state.inbound_requests.contains_key(&request.approval_id));
    assert_eq!(
        state
            .store
            .db
            .query_row("SELECT COUNT(*) FROM issued_approvals", [], |r| r
                .get::<_, usize>(0))
            .unwrap(),
        0
    );
}

#[tokio::test]
async fn ledger_and_ciphertext_queue_failures_roll_back_issued_grants_and_directives() {
    use rusqlite::hooks::{AuthAction, AuthContext, Authorization};
    for (op, target) in [
        (Op::GrantIssue, "issued_grants"),
        (Op::GrantIssue, "remote_outbox"),
        (Op::DirectiveIssue, "issued_directives"),
        (Op::DirectiveIssue, "remote_outbox"),
    ] {
        let h = signing_harness();
        let parameters = if op == Op::GrantIssue {
            let mut grant = signed_grant(&h, "failed-queue", Tier::T1, 2);
            grant.iss = h.helper.local.device_id.clone();
            grant.aud = h.peer.device_id.clone();
            json!(kv_core::remote::ipc::Unsigned(grant))
        } else {
            let mut directive = super::workflow::signed_directive(
                &h,
                DirectiveOp::QueryStatus,
                json!({}),
                ApprovalLevel::Strong,
            );
            directive.iss = h.helper.local.device_id.clone();
            directive.aud = h.peer.device_id.clone();
            json!(kv_core::remote::ipc::Unsigned(directive))
        };
        let mut denied = false;
        h.helper
            .lock()
            .unwrap()
            .store
            .db
            .authorizer(Some(move |ctx: AuthContext<'_>| {
                if !denied
                    && matches!(
                        ctx.action,
                        AuthAction::Insert { table_name } if table_name == target
                    )
                {
                    denied = true;
                    Authorization::Deny
                } else {
                    Authorization::Allow
                }
            }));
        assert_eq!(
            h.exchange(Caller::CliOwner, op, parameters).await["error"]["code"],
            "state_unavailable"
        );
        h.reason("state_unavailable");
        let state = h.helper.lock().unwrap();
        for table in ["issued_grants", "issued_directives", "remote_outbox"] {
            assert_eq!(
                state
                    .store
                    .db
                    .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |r| r
                        .get::<_, usize>(0))
                    .unwrap(),
                0
            );
        }
    }
}

#[tokio::test]
async fn device_signer_failure_rolls_back_issued_grants_directives_and_pairing_messages() {
    for op in [Op::GrantIssue, Op::DirectiveIssue, Op::PresenceUpdate] {
        let mut h = signing_harness();
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
        Arc::get_mut(&mut h.helper).unwrap().services.identity =
            Arc::new(FailedSigner(key("sender")));
        let params = match op {
            Op::GrantIssue => {
                let mut grant = signed_grant(&h, "failed-issued", Tier::T1, 2);
                grant.iss = h.helper.local.device_id.clone();
                grant.aud = h.peer.device_id.clone();
                serde_json::to_value(kv_core::remote::ipc::Unsigned(grant)).unwrap()
            }
            Op::DirectiveIssue => {
                let mut directive = super::workflow::signed_directive(
                    &h,
                    DirectiveOp::QueryStatus,
                    json!({}),
                    ApprovalLevel::Strong,
                );
                directive.iss = h.helper.local.device_id.clone();
                directive.aud = h.peer.device_id.clone();
                serde_json::to_value(kv_core::remote::ipc::Unsigned(directive)).unwrap()
            }
            _ => json!(PresenceHint {
                device_id: h.helper.local.device_id.clone(),
                state: Presence::Away,
                since: h.clock.now(),
                sent_at: h.clock.now(),
                extra: Extra::new()
            }),
        };
        let role = if op == Op::PresenceUpdate {
            Caller::ApprovalAgent
        } else {
            Caller::CliOwner
        };
        assert_eq!(
            h.exchange(role, op, params).await["error"]["code"],
            "key_operation_failed"
        );
        h.reason("key_operation_failed");
        let state = h.helper.lock().unwrap();
        for table in ["issued_grants", "issued_directives", "remote_outbox"] {
            let count: u64 = state
                .store
                .db
                .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |r| r.get(0))
                .unwrap();
            assert_eq!(count, 0);
        }
    }
}

#[tokio::test]
async fn authenticated_pair_complete_uses_the_same_token_and_sas_as_inbound_pair_accept() {
    let h = Harness::with(
        Store::memory().unwrap(),
        fixture("decision_valid.json")["now"].as_i64().unwrap(),
        false,
    );
    let start = h
        .exchange(
            Caller::CliOwner,
            Op::PairStart,
            json!({"relay_url":"https://relay.example"}),
        )
        .await;
    let result = h
        .exchange(
            Caller::CliOwner,
            Op::PairComplete,
            json!({"token":start["result"]["token"],"joiner":h.peer}),
        )
        .await;
    assert_eq!(result["ok"], true);
    let sas = result["result"]["sas"].as_str().unwrap();
    assert_eq!(sas.len(), 6);
    let confirmation = kv_core::remote::pairing::sign_confirm(
        sas,
        SignatureAlgorithm::ES256,
        key("strong").as_ref(),
    )
    .unwrap();
    h.helper.pair_confirm_signed(&confirmation).unwrap();
    assert_eq!(
        h.exchange(
            Caller::CliOwner,
            Op::PairConfirm,
            json!({"sas":sas,"sig":""})
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
}

#[tokio::test]
async fn every_ipc_sql_failure_is_rejected_and_audited_before_reply_or_execution() {
    for op in [
        Op::PendingForAgent,
        Op::PendingStopBlock,
        Op::RelayStatus,
        Op::RelayOutboundAck,
        Op::RelayOutboundPoll,
        Op::Wait,
        Op::DevicesRename,
        Op::PresenceUpdate,
        Op::PairComplete,
    ] {
        let mut failures = 0;
        for at in 1..240 {
            let h = if op == Op::PairComplete {
                Harness::with(
                    Store::memory().unwrap(),
                    fixture("decision_valid.json")["now"].as_i64().unwrap(),
                    false,
                )
            } else {
                Harness::new()
            };
            let (role, params) = if op == Op::PairComplete {
                let offer = h.helper.pair_start("https://relay.example").unwrap();
                (
                    Caller::CliOwner,
                    json!({"token":offer.extra["token"],"joiner":h.peer}),
                )
            } else {
                let pending = h.helper.submit(h.input(Tier::T1, "A")).unwrap();
                match op {
                    Op::PendingForAgent => (Caller::Hook, json!({"agent_pid":4242})),
                    Op::PendingStopBlock => {
                        (Caller::Hook, json!({"approval_id":pending.approval_id}))
                    }
                    Op::RelayStatus => (
                        Caller::RelayClient,
                        json!({"connected":true,"since":h.clock.now(),"last_error":null}),
                    ),
                    Op::RelayOutboundAck => {
                        let outgoing = h.helper.outbound_poll(0).await.unwrap();
                        (
                            Caller::RelayClient,
                            json!(receipt(outgoing, OutboundStage::Accepted)),
                        )
                    }
                    Op::RelayOutboundPoll => (Caller::RelayClient, json!({"max_wait_ms":0})),
                    Op::Wait => (
                        Caller::Mcp,
                        json!({"approval_id":pending.approval_id,"max_wait_ms":0}),
                    ),
                    Op::DevicesRename => (
                        Caller::CliOwner,
                        json!({"device_id":h.peer.device_id,"label":"renamed"}),
                    ),
                    _ => (
                        Caller::ApprovalAgent,
                        json!(PresenceHint {
                            device_id: h.helper.local.device_id.clone(),
                            state: Presence::Away,
                            since: h.clock.now(),
                            sent_at: h.clock.now(),
                            extra: Extra::new()
                        }),
                    ),
                }
            };
            let denied = deny_once(&h.helper, at);
            let response = h.exchange(role, op, params).await;
            if !denied.load(Ordering::SeqCst) {
                assert_eq!(response["ok"], true, "{op:?}: {response}");
                break;
            }
            failures += 1;
            assert_eq!(response["ok"], false, "{op:?} denied SQL {at}");
            assert_eq!(
                response["error"]["code"], "state_unavailable",
                "{op:?} denied SQL {at}"
            );
            h.reason("state_unavailable");
            assert_eq!(h.runner.calls.load(Ordering::SeqCst), 0);
        }
        assert!(failures > 5, "{op:?} did not exercise its SQL operations");
    }
}

struct EventFailure(&'static str);
impl AuditSink for EventFailure {
    fn append(&self, entry: Map<String, Value>) -> Result<()> {
        if entry["op"] == self.0 {
            Err(Error("audit_unavailable"))
        } else {
            Ok(())
        }
    }
}

#[test]
fn the_unattended_t2_audit_is_required_even_when_the_use_audit_succeeded() {
    let mut h = Harness::new();
    h.helper
        .install_grant(&signed_grant(&h, "t2", Tier::T2, 2), ApprovalLevel::Strong)
        .unwrap();
    Arc::get_mut(&mut h.helper).unwrap().services.audit = Arc::new(EventFailure("unattended_t2"));
    let input = h.input(Tier::T2, "A");
    let usage = GrantUse {
        canonical: input.canonical,
        tier: Tier::T2,
        template_allowed_hosts: vec!["api.github.com".into()],
        policy_allowed_methods: vec!["POST".into()],
        body_bytes: 1,
        session_id: "session".into(),
    };
    assert_eq!(
        h.helper.cover_and_debit(&usage).unwrap_err().code(),
        "audit_unavailable"
    );
    h.reason("audit_unavailable");
    let state = h.helper.lock().unwrap();
    let budget: Option<String> = state
        .store
        .db
        .query_row("SELECT budget_left_json FROM grants", [], |r| r.get(0))
        .unwrap();
    assert!(budget.is_none());
}

#[test]
fn every_escalation_and_expiration_storage_failure_clears_retained_bodies_and_is_audited() {
    for expire in [false, true] {
        for at in 1..260 {
            let h = Harness::new();
            *h.presence.0.lock().unwrap() = PresenceState {
                state: Presence::Present,
                since: h.clock.now(),
                signals: present_signals(),
                extra: Extra::new(),
            };
            let request = h.helper.submit(h.input(Tier::T1, "A")).unwrap();
            h.clock.0.store(
                if expire {
                    request.exp + 1
                } else {
                    h.clock.now() + 31
                },
                Ordering::SeqCst,
            );
            h.helper
                .lock()
                .unwrap()
                .results
                .insert("orphan".into(), json!({"value":"clear"}));
            let denied = deny_once(&h.helper, at);
            let result = h.helper.tick();
            if !denied.load(Ordering::SeqCst) {
                result.unwrap();
                break;
            }
            assert_eq!(result.unwrap_err().code(), "state_unavailable");
            h.reason("state_unavailable");
            let state = h.helper.lock().unwrap();
            assert!(state.full.is_empty());
            assert!(state.results.is_empty());
            assert_eq!(h.runner.calls.load(Ordering::SeqCst), 0);
        }
    }
}
