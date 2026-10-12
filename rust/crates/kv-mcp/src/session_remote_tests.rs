//! Remote session logic uses byte transports, never installed helpers or trust fixtures.
use super::*;
use serde_json::json;
use std::collections::VecDeque;

enum Script {
    Reply(String),
    Delay(Duration),
    Disconnect,
}

fn scripted(scripts: Vec<Script>) -> HelperSession {
    let scripts = Arc::new(std::sync::Mutex::new(VecDeque::from(scripts)));
    let mut session = HelperSession::new(Duration::ZERO);
    session.connector = Some(Arc::new(move || {
        let script = scripts
            .lock()
            .unwrap()
            .pop_front()
            .expect("Unexpected helper connection");
        let (client, server) = tokio::io::duplex(256);
        let (reader, writer) = tokio::io::split(client);
        if matches!(script, Script::Disconnect) {
            drop(server);
        } else {
            tokio::spawn(async move {
                let mut server = BufReader::new(server);
                let mut line = String::new();
                if server.read_line(&mut line).await.unwrap_or(0) == 0 {
                    return;
                }
                let request: Value = serde_json::from_str(&line).unwrap();
                assert!(
                    request["op"].as_str().unwrap().starts_with("remote.")
                        || request["op"] == "auth"
                        || request["op"] == "protection"
                );
                match script {
                    Script::Reply(reply) => {
                        let _ = server.get_mut().write_all(reply.as_bytes()).await;
                    }
                    Script::Delay(delay) => tokio::time::sleep(delay).await,
                    Script::Disconnect => unreachable!(),
                }
            });
        }
        Box::pin(async move {
            Ok((
                Transport::Socket {
                    writer: Box::new(writer),
                },
                Box::new(reader) as Box<dyn AsyncRead + Unpin + Send>,
                None,
                true,
            ))
        })
    }));
    session
}

#[tokio::test(start_paused = true)]
async fn public_queries_accept_appendix_c_frames_and_reject_malformed_or_truncated_replies() {
    for frame in [
        r#"{"ok":true,"result":{"relay":"offline"}}"#,
        r#"{"id":1,"ok":true,"result":{"relay":"offline"}}"#,
    ] {
        let session = scripted(vec![Script::Reply(format!("{frame}\n"))]);
        assert_eq!(
            session
                .remote_request(kv_ipc::remote::STATUS, Map::new(), Duration::from_secs(5))
                .await
                .unwrap()["relay"],
            "offline"
        );
        assert!(!session.inner.lock().await.ready);
    }
    for frame in [
        "not JSON\n",
        "{}\n",
        "{\"ok\":true}\n",
        "{\"ok\":false}\n",
        "{\"id\":2,\"ok\":true,\"result\":{}}\n",
        "{\"ok\":true,\"result\":{}}",
    ] {
        let session = scripted(vec![Script::Reply(frame.into())]);
        assert!(session
            .remote_request(kv_ipc::remote::STATUS, Map::new(), Duration::from_secs(5))
            .await
            .unwrap_err()
            .0
            .contains("Malformed"));
    }
    let session = scripted(vec![Script::Reply(format!(
        "{}\n",
        "x".repeat(kv_ipc::MAX_LINE_BYTES + 1)
    ))]);
    assert!(session
        .remote_request(kv_ipc::remote::STATUS, Map::new(), Duration::from_secs(5))
        .await
        .is_err());
}

#[tokio::test(start_paused = true)]
async fn public_errors_and_timeouts_leave_the_approval_pending_and_do_not_unlock() {
    let session = scripted(vec![
        Script::Reply(
            "{\"ok\":false,\"error\":{\"code\":\"offline\",\"message\":\"offline\"}}\n".into(),
        ),
        Script::Delay(Duration::from_secs(30)),
        Script::Disconnect,
    ]);
    assert!(session.remote_status().await["status_error"]
        .as_str()
        .unwrap()
        .contains("offline"));
    assert!(session
        .remote_request(kv_ipc::remote::STATUS, Map::new(), Duration::from_secs(5))
        .await
        .is_err());
    let session = scripted(vec![
        Script::Delay(Duration::from_secs(30)),
        Script::Reply("{\"ok\":false,\"error\":\"unavailable\"}\n".into()),
    ]);
    let pending = session
        .wait_approval("synthetic-id", Duration::from_secs(5))
        .await
        .unwrap();
    assert_eq!(pending["status"], "still_pending");
    assert_eq!(pending["approval_id"], "synthetic-id");
    assert!(session
        .wait_approval("synthetic-id", Duration::from_secs(5))
        .await
        .unwrap_err()
        .0
        .contains("unavailable"));
    assert!(!session.inner.lock().await.ready);
}

#[tokio::test(start_paused = true)]
async fn failed_policy_negotiation_retries_and_only_reduces_the_configured_limits() {
    let session = scripted(vec![
        Script::Reply("{\"ok\":false,\"error\":\"offline\"}\n".into()),
        Script::Reply(format!(
            "{}\n",
            json!({"ok":true,"result":{"approval":{"wait_in_call_s":20,"wait_tool_max_s":30,"progress_interval_s":5}}})
        )),
    ]);
    session.negotiate_policy().await;
    assert!(!session.remote.policy_loaded.load(Ordering::Relaxed));
    session.negotiate_policy().await;
    assert_eq!(session.in_call_wait(), Duration::from_secs(20));
    assert_eq!(session.wait_tool_limit(Some(10)), Duration::from_secs(10));
    assert_eq!(session.wait_tool_limit(None), Duration::from_secs(30));
    assert_eq!(session.progress_interval(), Duration::from_secs(5));
    session.negotiate_policy().await;
}

#[tokio::test(start_paused = true)]
async fn cached_results_are_one_shot_expire_and_are_erased_on_lock_or_drop() {
    let session = HelperSession::new(Duration::ZERO);
    session
        .remote
        .cache_completed("ignored".into(), json!({"status":"still_pending"}));
    assert!(session.remote.take_completed("ignored").is_none());
    session.remote.cache_completed(
        "expired".into(),
        json!({"status":"ok","expires_at":approval::unix_time()-1,"result":"synthetic-secret"}),
    );
    assert!(session.remote.take_completed("expired").is_none());
    session.remote.cache_completed(
        "timer".into(),
        json!({"status":"ok","expires_at":approval::unix_time()+5,"result":"synthetic-secret"}),
    );
    tokio::time::advance(Duration::from_secs(6)).await;
    tokio::task::yield_now().await;
    assert!(session.remote.take_completed("timer").is_none());
    session.remote.cache_completed(
        "one-shot".into(),
        json!({"status":"ok","result":"synthetic-secret"}),
    );
    assert_eq!(
        session
            .wait_approval("one-shot", Duration::from_secs(5))
            .await
            .unwrap()["result"],
        "synthetic-secret"
    );
    assert!(session.remote.take_completed("one-shot").is_none());
    session.remote.cache_completed(
        "locked".into(),
        json!({"status":"ok","result":"synthetic-secret"}),
    );
    session.lock().await;
    assert!(session.remote.take_completed("locked").is_none());
    session.remote.cache_completed(
        "dropped".into(),
        json!({"status":"ok","result":"synthetic-secret"}),
    );
    let weak = Arc::downgrade(&session.remote);
    drop(session);
    assert!(weak.upgrade().is_none());
    tokio::time::advance(Duration::from_secs(601)).await;
    tokio::task::yield_now().await;
}

#[tokio::test]
async fn legacy_and_structured_correlated_errors_are_decoded_without_changing_the_status() {
    assert_eq!(
        decode_response("{\"id\":9,\"ok\":false,\"error\":\"unavailable\"}").unwrap(),
        (9, Err("unavailable".into()))
    );
    assert!(decode_response(
        "{\"id\":9,\"ok\":false,\"error\":{\"code\":\"offline\",\"message\":\"offline\"}}"
    )
    .unwrap()
    .1
    .unwrap_err()
    .contains("offline"));
    let session = scripted(vec![Script::Reply(format!(
        "{}\n",
        json!({"ready":true,"protocol":PROTOCOL_VERSION+1})
    ))]);
    assert!(session
        .do_unlock("Synthetic handshake test", None)
        .await
        .is_err());
}

#[tokio::test]
async fn a_missing_approval_id_does_not_emit_a_channel_or_reaudit_a_timeout() {
    let session = scripted(vec![Script::Reply("{\"ok\":true,\"result\":{}}\n".into())]);
    session.remote.approved(&json!({"status":"ok"})).await;
    assert!(session.remote.notified.lock().unwrap().is_empty());
    session
        .remote
        .approved(&json!({"status":"ok", "approval_id": "fixture-id"}))
        .await;
    session
        .remote
        .approved(&json!({"status":"ok", "approval_id": "fixture-id"}))
        .await;
    assert_eq!(session.remote.notified.lock().unwrap().len(), 1);
    session
        .client_timeout_observed(&rmcp::model::RequestId::Number(4))
        .await;
    session
        .client_timeout_observed(&rmcp::model::RequestId::Number(5))
        .await;
    assert_eq!(session.runtime_budget(), Duration::from_secs(50));
}

#[tokio::test(start_paused = true)]
async fn status_projects_appendix_c_approval_requests_into_agent_visible_summaries() {
    let session = scripted(vec![Script::Reply("{\"ok\":true,\"result\":{\"relay\":\"connected\",\"grants_n\":2}}\n".into()), Script::Reply("{\"ok\":true,\"result\":{\"pending\":[{\"id\":\"01J00000000000000000000000\",\"operation\":{\"summary\":\"Fixture request\",\"body\":\"hidden\"},\"exp\":123}]}}\n".into())]);
    let value = session.remote_status().await;
    assert_eq!(
        value["pending"],
        json!([{"approval_id": "01J00000000000000000000000", "summary": "Fixture request", "expires_at": 123}])
    );
    assert_eq!(value["grants"], 2);
    let session = scripted(vec![
        Script::Reply("{\"ok\":true,\"result\":{}}\n".into()),
        Script::Reply("{\"ok\":false,\"error\":\"offline\"}\n".into()),
    ]);
    assert_eq!(session.remote_status().await["pending"], json!([]));
}

#[tokio::test(start_paused = true)]
async fn protection_uses_the_injected_trusted_connector() {
    let protection: Value = serde_json::from_str(include_str!(
        "../../kv-ipc/tests/fixtures/hello-protection.json"
    ))
    .unwrap();
    let session = scripted(vec![Script::Reply(format!(
        "{}\n",
        json!({"id": 0, "ok": true, "result": {"protocol": PROTOCOL_VERSION, "vault_protection": protection}})
    ))]);
    assert!(session.protection().await.is_ok());
    assert!(!session.inner.lock().await.ready);
}

#[tokio::test(start_paused = true)]
async fn reader_rejects_a_valid_json_frame_without_protocol_fields() {
    let (client, mut peer) = tokio::io::duplex(1024);
    let session = HelperSession::with_test_transport(ApprovalConfig::default(), client).await;
    peer.write_all(b"{}\n").await.unwrap();
    for _ in 0..10 {
        tokio::task::yield_now().await;
    }
    assert!(!session.inner.lock().await.ready);
}

#[tokio::test(start_paused = true)]
async fn legacy_grants_retry_once_and_remote_grants_return_the_retained_request() {
    for case in [
        "legacy",
        "remote",
        "wait-error",
        "missing-id",
        "metadata",
        "no-wait",
    ] {
        let (client, peer) = tokio::io::duplex(64 * 1024);
        let config = ApprovalConfig {
            wait_in_call: if case == "no-wait" {
                Duration::ZERO
            } else {
                Duration::from_secs(60)
            },
            ..Default::default()
        };
        let session = HelperSession::with_test_transport(config, client).await;
        let calls = Arc::new(std::sync::Mutex::new(Vec::new()));
        let observed = calls.clone();
        let helper = tokio::spawn(async move {
            let mut peer = BufReader::new(peer);
            let mut line = String::new();
            let mut granted = false;
            while peer.read_line(&mut line).await.unwrap_or(0) > 0 {
                let request: Value = serde_json::from_str(&line).unwrap();
                line.clear();
                observed.lock().unwrap().push(request.clone());
                let response = match request["op"].as_str().unwrap() {
                    "remote.status" | "list" => json!({"ok": true, "result": {}}),
                    "get" if case == "missing-id" => {
                        json!({"ok": true, "result": {"status": "approval_pending"}})
                    }
                    "get" if case == "wait-error" || case == "no-wait" => {
                        json!({"ok": true, "result": {"status": "approval_pending", "approval_id": "fixture-id"}})
                    }
                    "get" if !granted => {
                        json!({"ok": false, "error": format!("{GRANT_REQUIRED_PREFIX}api_key/fixture")})
                    }
                    "grant" => {
                        assert_eq!(request["params"]["operation"], "get");
                        assert_eq!(request["params"]["request"]["name"], "fixture");
                        granted = true;
                        if case == "remote" {
                            json!({"ok": true, "result": {"status": "ok", "approval_id": "fixture-id", "result": {"value": "synthetic-secret"}}})
                        } else {
                            json!({"ok": true, "result": {}})
                        }
                    }
                    "get" => json!({"ok": true, "result": {"value": "synthetic-secret"}}),
                    "remote.wait" => json!({"ok": false, "error": "transport unavailable"}),
                    other => panic!("Unexpected operation: {other}"),
                };
                let mut response = response;
                response["id"] = request["id"].clone();
                if peer
                    .get_mut()
                    .write_all(format!("{response}\n").as_bytes())
                    .await
                    .is_err()
                {
                    break;
                }
            }
        });
        let op = if case == "metadata" { "list" } else { "get" };
        let value = session
            .request_value(
                op,
                json!({"type": "api_key", "name": "fixture"})
                    .as_object()
                    .unwrap()
                    .clone(),
                "Synthetic test",
                None,
            )
            .await;
        match case {
            "wait-error" => assert!(value.unwrap_err().0.contains("unavailable")),
            "missing-id" | "no-wait" => assert_eq!(value.unwrap()["status"], "approval_pending"),
            "metadata" => assert_eq!(value.unwrap(), json!({})),
            _ => assert_eq!(value.unwrap()["value"], "synthetic-secret"),
        }
        let calls = calls.lock().unwrap();
        assert_eq!(
            calls.iter().filter(|v| v["op"] == "grant").count(),
            usize::from(case == "legacy" || case == "remote")
        );
        assert_eq!(
            calls.iter().filter(|v| v["op"] == "get").count(),
            if case == "metadata" {
                0
            } else if case == "legacy" {
                2
            } else {
                1
            }
        );
        helper.abort();
    }
}

#[tokio::test(start_paused = true)]
async fn orphan_cache_is_bounded_and_never_replaces_an_unclaimed_original_result() {
    let session = HelperSession::new(Duration::ZERO);
    for index in 0..kv_ipc::MAX_IN_FLIGHT_REQUESTS {
        session.remote.cache_completed(
            index.to_string(),
            json!({"status": "ok", "result": "original"}),
        );
    }
    session
        .remote
        .cache_completed("0".into(), json!({"status": "ok", "result": "replacement"}));
    session.remote.cache_completed(
        "overflow".into(),
        json!({"status": "ok", "result": "excess"}),
    );
    assert_eq!(
        session.remote.take_completed("0").unwrap()["result"],
        "original"
    );
    assert!(session.remote.take_completed("overflow").is_none());
    assert_eq!(
        session.remote.completed.lock().unwrap().len(),
        kv_ipc::MAX_IN_FLIGHT_REQUESTS - 1
    );
}

#[tokio::test(start_paused = true)]
async fn a_fake_session_public_probe_cannot_connect_to_the_machine_installation() {
    let (client, mut peer) = tokio::io::duplex(1024);
    let session = HelperSession::with_test_transport(ApprovalConfig::default(), client).await;
    assert!(session
        .protection()
        .await
        .unwrap_err()
        .0
        .contains("Synthetic helper"));
    assert!(session.inner.lock().await.ready);
    assert!(
        tokio::time::timeout(Duration::from_secs(1), peer.read(&mut [0]))
            .await
            .is_err()
    );
}

#[tokio::test(start_paused = true)]
async fn restored_file_lifetimes_follow_result_expiry_and_connection_generation() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    for behavior in ["expire", "drop", "generation", "ready"] {
        let session = Arc::new(HelperSession::new(Duration::ZERO));
        let activated = Arc::new(AtomicUsize::new(0));
        let cleaned = Arc::new(AtomicUsize::new(0));
        let a = activated.clone();
        let c = cleaned.clone();
        session
            .approval_files(
                approval::unix_time() + 10,
                move || {
                    a.fetch_add(1, Ordering::SeqCst);
                },
                move || {
                    c.fetch_add(1, Ordering::SeqCst);
                },
            )
            .await;
        assert_eq!(activated.load(Ordering::SeqCst), 1);
        match behavior {
            "generation" => session.inner.lock().await.generation += 1,
            "ready" => session.inner.lock().await.ready = true,
            _ => {}
        }
        let retained = if behavior == "drop" {
            drop(session);
            None
        } else {
            Some(session)
        };
        tokio::task::yield_now().await;
        tokio::time::advance(Duration::from_secs(11)).await;
        tokio::task::yield_now().await;
        assert_eq!(
            cleaned.load(Ordering::SeqCst),
            usize::from(behavior == "expire")
        );
        drop(retained);
    }
    let session = HelperSession::new(Duration::ZERO);
    let cleaned = Arc::new(AtomicUsize::new(0));
    let c = cleaned.clone();
    session
        .approval_files(
            approval::unix_time(),
            || {},
            move || {
                c.fetch_add(1, Ordering::SeqCst);
            },
        )
        .await;
    tokio::task::yield_now().await;
    tokio::time::advance(Duration::from_secs(1)).await;
    tokio::task::yield_now().await;
    assert_eq!(cleaned.load(Ordering::SeqCst), 1);
    session.inner.lock().await.ready = true;
    session.activate_approval_files(approval::unix_time()).await;
}
