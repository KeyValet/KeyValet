//! Cross-workflow boundaries use real IPC, signatures and state, with injectable OS services.
use super::*;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

fn caller(h: &Harness, role: Caller) -> CallerContext {
    let agent = h.input(Tier::T1, "boundary").canonical.agent;
    CallerContext::authenticated(role, agent.uid, agent.pid, 210)
}

async fn request(h: &Harness, role: Caller, op: Op, params: Value) -> Value {
    serde_json::to_value(
        h.helper
            .handle(
                caller(h, role),
                Request {
                    op,
                    params,
                    extra: Extra::new(),
                },
            )
            .await,
    )
    .unwrap()
}

#[test]
fn mcp_transport_hints_do_not_change_execution_binding() {
    let parameters = json!({"credential":"github/default", "body":"approved-body"});
    let first = FullRequest::new("httpRequest", parameters.as_object().unwrap().clone()).unwrap();
    let mut second = parameters.as_object().unwrap().clone();
    second.extend(
        json!({"approval_id":"id", "runtime_budget_s":60,
        "wait_in_call_ms":50000, "max_wait_ms":60000,
        "agent":{"pid":123,"runtime":"claude-code"}})
        .as_object()
        .unwrap()
        .clone(),
    );
    let second = FullRequest::new("httpRequest", second).unwrap();
    assert_eq!(
        first.binding_digest().unwrap(),
        second.binding_digest().unwrap()
    );
    assert_eq!(first.params().unwrap(), second.params().unwrap());
    let changed = FullRequest::new(
        "httpRequest",
        json!({"credential":"github/default",
        "body":"different-body"})
        .as_object()
        .unwrap()
        .clone(),
    )
    .unwrap();
    assert_ne!(
        first.binding_digest().unwrap(),
        changed.binding_digest().unwrap()
    );
}

#[tokio::test]
async fn a_cancelled_wait_is_audited_without_denial_or_consumption() {
    let h = Harness::new();
    h.helper.lock().unwrap().relay_connected = true;
    let pending = h.helper.submit(h.input(Tier::T1, "boundary")).unwrap();
    let context = caller(&h, Caller::Mcp);
    let helper = h.helper.clone();
    let params = json!({"approval_id": pending.approval_id, "max_wait_ms":60000,
        "runtime_budget_s":210});
    let waiting = tokio::spawn(async move {
        helper
            .handle(
                context,
                Request {
                    op: Op::Wait,
                    params,
                    extra: Extra::new(),
                },
            )
            .await
    });
    for _ in 0..5 {
        tokio::task::yield_now().await;
    }
    assert!(!waiting.is_finished());
    waiting.abort();
    assert!(waiting.await.unwrap_err().is_cancelled());
    assert_eq!(
        h.helper
            .lock()
            .unwrap()
            .store
            .pending(&pending.approval_id)
            .unwrap()
            .state,
        PendingState::Waiting
    );
    assert_eq!(h.runner.calls.load(Ordering::SeqCst), 0);
    assert!(h
        .audit
        .entries
        .lock()
        .unwrap()
        .iter()
        .any(|event| event["op"] == "client_timeout_observed"
            && event["reason"] == "client_disconnected_while_waiting"));
}

#[tokio::test]
async fn cold_ipc_disconnect_cancels_only_the_wait_and_records_the_observation() {
    let h = Harness::new();
    h.helper.lock().unwrap().relay_connected = true;
    let pending = h.helper.submit(h.input(Tier::T1, "boundary")).unwrap();
    let context = caller(&h, Caller::Mcp);
    let (mut client, server) = tokio::io::duplex(4096);
    let (reader, writer) = tokio::io::split(server);
    let helper = h.helper.clone();
    let serving = tokio::spawn(async move {
        super::super::server::serve(reader, writer, context, Some(helper)).await
    });
    let frame = format!(
        "{}\n",
        json!({"id":1,"op":"remote.wait","params":{
            "approval_id":pending.approval_id,"max_wait_ms":60000,"runtime_budget_s":210}})
    );
    client.write_all(frame.as_bytes()).await.unwrap();
    for _ in 0..5 {
        tokio::task::yield_now().await;
    }
    assert!(!serving.is_finished());
    client.shutdown().await.unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(2), serving)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    let state = h.helper.lock().unwrap();
    let entry = state.store.pending(&pending.approval_id).unwrap();
    assert_eq!(entry.state, PendingState::Waiting);
    assert!(entry.claimed_at.is_none());
    drop(state);
    assert_eq!(h.runner.calls.load(Ordering::SeqCst), 0);
    assert_eq!(
        h.audit
            .entries
            .lock()
            .unwrap()
            .iter()
            .filter(|event| event["op"] == "client_timeout_observed"
                && event["reason"] == "client_disconnected_while_waiting")
            .count(),
        1
    );
}

#[tokio::test]
async fn cold_ipc_wait_preserves_a_pipelined_partial_request() {
    let h = Harness::new();
    h.helper.lock().unwrap().relay_connected = true;
    let pending = h.helper.submit(h.input(Tier::T1, "boundary")).unwrap();
    let (client, server) = tokio::io::duplex(4096);
    let (reader, writer) = tokio::io::split(server);
    let helper = h.helper.clone();
    let context = caller(&h, Caller::Mcp);
    let serving = tokio::spawn(async move {
        super::super::server::serve(reader, writer, context, Some(helper)).await
    });
    let mut client = BufReader::new(client);
    let frame = format!(
        "{}\n{{\"id\":2,\"op\":",
        json!({"id":1,"op":"remote.wait","params":{
            "approval_id":pending.approval_id,"max_wait_ms":60000,"runtime_budget_s":210}})
    );
    client.get_mut().write_all(frame.as_bytes()).await.unwrap();
    for _ in 0..5 {
        tokio::task::yield_now().await;
    }
    let decision = h.decision(&pending, ApprovalLevel::Quick, ScopeMode::PerUse);
    h.helper
        .inbound(h.envelope(
            EnvelopeType::ApprovalDecision,
            &pending.approval_id,
            &decision,
        ))
        .await
        .unwrap();
    let mut line = String::new();
    tokio::time::timeout(
        std::time::Duration::from_secs(2),
        client.read_line(&mut line),
    )
    .await
    .unwrap()
    .unwrap();
    let response: Value = serde_json::from_str(&line).unwrap();
    assert_eq!(response["id"], 1);
    assert_eq!(response["result"]["status"], "ok");
    client
        .get_mut()
        .write_all(b"\"remote.status\",\"params\":{}}\n")
        .await
        .unwrap();
    line.clear();
    tokio::time::timeout(
        std::time::Duration::from_secs(2),
        client.read_line(&mut line),
    )
    .await
    .unwrap()
    .unwrap();
    let response: Value = serde_json::from_str(&line).unwrap();
    assert_eq!(response["id"], 2);
    assert_eq!(response["ok"], true);
    client.get_mut().shutdown().await.unwrap();
    serving.await.unwrap().unwrap();
    assert_eq!(h.runner.calls.load(Ordering::SeqCst), 1);
    assert!(!h
        .audit
        .entries
        .lock()
        .unwrap()
        .iter()
        .any(|event| event["op"] == "client_timeout_observed"));
}

#[tokio::test]
async fn relay_identity_and_runtime_policy_have_real_authenticated_receivers() {
    let h = Harness::new();
    let identity = request(&h, Caller::RelayClient, Op::RelayIdentity, json!({})).await;
    assert_eq!(identity["ok"], true);
    assert_eq!(
        identity["result"]["dk_pub"],
        serde_json::to_value(&h.helper.local.dk_pub).unwrap()
    );
    assert!(identity["result"]["dk_pub"].get("d").is_none());
    let challenge = vec![17; 32];
    let signature = request(
        &h,
        Caller::RelayClient,
        Op::SignIdentity,
        json!({"payload_b64":kv_core::remote::keys::encode_b64(&challenge)}),
    )
    .await;
    kv_core::remote::keys::verify_signature(
        SignatureAlgorithm::ES256,
        &serde_json::from_value(identity["result"]["dk_pub"].clone()).unwrap(),
        &challenge,
        &decode_b64(signature["result"]["sig_b64"].as_str().unwrap()).unwrap(),
    )
    .unwrap();
    assert_eq!(
        request(&h, Caller::Mcp, Op::RelayIdentity, json!({})).await["error"]["code"],
        "forbidden"
    );
    let status = request(&h, Caller::Mcp, Op::Status, json!({})).await;
    assert_eq!(
        status["result"]["approval"],
        json!({
        "wait_in_call_s":60,"wait_tool_max_s":600,"progress_interval_s":15})
    );
    assert_eq!(
        request(
            &h,
            Caller::Mcp,
            Op::ClientTimeoutObserved,
            json!({"agent_pid":0,"clientInfo":{"name":"untrusted"}})
        )
        .await["ok"],
        true
    );
    let audit = h.audit.entries.lock().unwrap();
    let event = audit
        .iter()
        .find(|event| event["op"] == "client_timeout_observed")
        .unwrap();
    assert_eq!(
        event["agent_pid"],
        h.input(Tier::T1, "").canonical.agent.pid
    );
    assert!(event.get("clientInfo").is_none());
}

#[tokio::test]
async fn hook_stop_counter_and_wait_share_the_same_agent_identity() {
    let h = Harness::new();
    let input = h.input(Tier::T1, "boundary");
    let pid = input.canonical.agent.pid;
    let pending = h.helper.submit(input).unwrap();
    let list = request(
        &h,
        Caller::Hook,
        Op::PendingForAgent,
        json!({"agent_pid":pid}),
    )
    .await;
    assert_eq!(
        list["result"]["pending"][0]["approval_id"],
        pending.approval_id
    );
    assert_eq!(
        request(
            &h,
            Caller::Hook,
            Op::PendingForAgent,
            json!({"agent_pid":pid+1})
        )
        .await["error"]["code"],
        "forbidden"
    );
    for expected in [true, true, true, false] {
        let result = request(
            &h,
            Caller::Hook,
            Op::PendingStopBlock,
            json!({"approval_id":pending.approval_id}),
        )
        .await;
        assert_eq!(result["result"]["allowed"], expected);
    }
    let waiting = request(
        &h,
        Caller::Mcp,
        Op::Wait,
        json!({"approval_id":pending.approval_id,"max_wait_ms":0,"runtime_budget_s":60}),
    )
    .await;
    assert_eq!(waiting["ok"], true);
    assert_eq!(waiting["result"]["status"], "still_pending");
    assert_eq!(h.runner.calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn idle_approval_notice_is_non_consuming_and_preserves_a_partial_ipc_frame() {
    let h = Harness::new();
    let input = h.input(Tier::T1, "private-body-never-in-notice");
    let uid = input.canonical.agent.uid;
    let pid = input.canonical.agent.pid;
    let pending = h.helper.submit(input).unwrap();
    let (client, server) = tokio::io::duplex(4096);
    let (reader, writer) = tokio::io::split(server);
    let helper = h.helper.clone();
    let context = caller(&h, Caller::Mcp);
    let serving = tokio::spawn(async move {
        super::super::server::serve(reader, writer, context, Some(helper)).await
    });
    let mut client = BufReader::new(client);
    client
        .get_mut()
        .write_all(b"{\"op\":\"remote.status\",\"params\":{},\"notifications\":true}\n")
        .await
        .unwrap();
    let mut line = String::new();
    client.read_line(&mut line).await.unwrap();
    assert_eq!(serde_json::from_str::<Value>(&line).unwrap()["ok"], true);
    client
        .get_mut()
        .write_all(b"{\"id\":9,\"op\":")
        .await
        .unwrap();
    let decision = h.decision(&pending, ApprovalLevel::Quick, ScopeMode::PerUse);
    h.helper
        .inbound(h.envelope(
            EnvelopeType::ApprovalDecision,
            &pending.approval_id,
            &decision,
        ))
        .await
        .unwrap();
    line.clear();
    tokio::time::timeout(
        std::time::Duration::from_secs(2),
        client.read_line(&mut line),
    )
    .await
    .unwrap()
    .unwrap();
    let notice: Value = serde_json::from_str(&line).unwrap();
    assert_eq!(
        notice,
        json!({"op":kv_ipc::remote::APPROVAL_RESOLVED,
        "params":{"approval_id":pending.approval_id,"status":"ok"}})
    );
    let rest = format!(
        "\"remote.wait\",\"params\":{}}}\n",
        json!({"approval_id":pending.approval_id,"max_wait_ms":1000,"runtime_budget_s":210})
    );
    client.get_mut().write_all(rest.as_bytes()).await.unwrap();
    line.clear();
    tokio::time::timeout(
        std::time::Duration::from_secs(2),
        client.read_line(&mut line),
    )
    .await
    .unwrap()
    .unwrap();
    let result: Value = serde_json::from_str(&line).unwrap();
    assert_eq!(result["id"], 9);
    assert_eq!(result["result"]["status"], "ok");
    assert_eq!(result["result"]["result"]["result"], "executed");
    assert_eq!(
        h.helper
            .result(&pending.approval_id, uid, pid, true)
            .unwrap()
            .status,
        ToolStatus::AlreadyConsumed
    );
    assert_eq!(h.runner.calls.load(Ordering::SeqCst), 1);
    // A new MCP connection must not wake an idle agent for an already consumed result.
    assert!(tokio::time::timeout(
        std::time::Duration::from_millis(10),
        h.helper
            .next_approval_notice(context, &mut Default::default())
    )
    .await
    .is_err());
    client.get_mut().shutdown().await.unwrap();
    serving.await.unwrap().unwrap();
    assert_eq!(
        h.helper
            .next_approval_notice(caller(&h, Caller::Hook), &mut Default::default())
            .await
            .unwrap_err()
            .code(),
        "forbidden"
    );
}
