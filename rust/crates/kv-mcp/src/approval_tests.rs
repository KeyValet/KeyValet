//! CI exercises the actual rmcp server with byte streams and an Appendix C fake helper.
use crate::approval::{self, ApprovalConfig};
use crate::fake_helper::{FakeHelper, Scenario, APPROVAL_ID};
use crate::server::Server;
use crate::session::HelperSession;
use rmcp::ServiceExt;
use serde_json::{json, Value};
use std::sync::{atomic::Ordering, Arc};
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

struct Client {
    reader: tokio::io::Lines<BufReader<tokio::io::ReadHalf<tokio::io::DuplexStream>>>,
    writer: tokio::io::WriteHalf<tokio::io::DuplexStream>,
    next_id: u64,
    notifications: Vec<Value>,
    task: tokio::task::JoinHandle<()>,
    helper_task: tokio::task::JoinHandle<()>,
    server: Server,
    helper: Arc<FakeHelper>,
}

impl Drop for Client {
    fn drop(&mut self) {
        self.task.abort();
        self.helper_task.abort();
    }
}

impl Client {
    async fn new(name: &str, scenario: Scenario, config: ApprovalConfig) -> Self {
        let helper = FakeHelper::new(scenario);
        Self::attach(name, helper, config).await
    }

    async fn attach(name: &str, helper: Arc<FakeHelper>, config: ApprovalConfig) -> Self {
        let (session, peer) = tokio::io::duplex(1024 * 1024);
        let helper_task = helper.serve(peer);
        let session = HelperSession::with_test_transport(config, session).await;
        let server = Server::new(session);
        let (server_io, client_io) = tokio::io::duplex(1024 * 1024);
        let service = server.clone();
        let task = tokio::spawn(async move {
            let (reader, writer) = tokio::io::split(server_io);
            service
                .serve((reader, writer))
                .await
                .unwrap()
                .waiting()
                .await
                .unwrap();
        });
        let (reader, writer) = tokio::io::split(client_io);
        let mut client = Self {
            reader: BufReader::new(reader).lines(),
            writer,
            next_id: 1,
            notifications: Vec::new(),
            task,
            helper_task,
            server,
            helper,
        };
        let id = client.send("initialize", json!({"protocolVersion": "2025-11-25", "capabilities": {}, "clientInfo": {"name": name, "version": "fixture"}})).await;
        let initialized = client.response(id).await;
        assert_eq!(
            initialized["capabilities"]["experimental"]["claude/channel"],
            json!({})
        );
        client.notify("notifications/initialized", json!({})).await;
        client
    }

    async fn send(&mut self, method: &str, params: Value) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        let frame = json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params});
        self.writer
            .write_all(format!("{frame}\n").as_bytes())
            .await
            .unwrap();
        id
    }

    async fn notify(&mut self, method: &str, params: Value) {
        let frame = json!({"jsonrpc": "2.0", "method": method, "params": params});
        self.writer
            .write_all(format!("{frame}\n").as_bytes())
            .await
            .unwrap();
    }

    async fn frame(&mut self, id: u64) -> Value {
        loop {
            let line = self.reader.next_line().await.unwrap().unwrap();
            let value: Value = serde_json::from_str(&line).unwrap();
            if value["id"] == id {
                return value;
            }
            self.notifications.push(value);
        }
    }

    async fn response(&mut self, id: u64) -> Value {
        let frame = self.frame(id).await;
        assert!(
            frame.get("error").is_none(),
            "Unexpected MCP error: {frame}"
        );
        frame["result"].clone()
    }

    async fn call(&mut self, name: &str, args: Value, token: Option<Value>) -> Value {
        let mut params = json!({"name": name, "arguments": args});
        if let Some(token) = token {
            params["_meta"] = json!({"progressToken": token});
        }
        let id = self.send("tools/call", params).await;
        let result = self.response(id).await;
        assert_ne!(result["isError"], true, "Unexpected tool error: {result}");
        let text = result["content"][0]["text"].as_str().unwrap();
        // Existing success tools have a human-readable prefix; approval results are pure JSON.
        serde_json::from_str(text)
            .unwrap_or_else(|_| serde_json::from_str(text.split_once('\n').unwrap().1).unwrap())
    }
}

fn http_args() -> Value {
    json!({"type": "api_key", "name": "fixture", "purpose": "Synthetic approval test", "method": "POST", "url": "https://example.test/request", "body": {"test": true}})
}

#[tokio::test(start_paused = true)]
async fn approval_within_budget_returns_original_result_and_regular_progress() {
    let config = ApprovalConfig {
        wait_in_call: Duration::from_secs(180),
        ..Default::default()
    };
    let mut client = Client::new(
        "claude-code",
        Scenario::ApproveAfter(Duration::from_secs(45)),
        config,
    )
    .await;
    let value = client
        .call(
            "credential_http_request",
            http_args(),
            Some(json!("progress-token")),
        )
        .await;
    assert_eq!(value["status"], 200);
    assert_eq!(value["body"], "synthetic upstream result");
    assert_eq!(client.helper.executions.load(Ordering::SeqCst), 1);
    let progress: Vec<_> = client
        .notifications
        .iter()
        .filter(|n| n["method"] == "notifications/progress")
        .collect();
    assert!(progress.len() >= 2);
    for (index, notification) in progress.iter().enumerate() {
        assert_eq!(notification["params"]["progressToken"], "progress-token");
        assert_eq!(
            notification["params"]["progress"].as_f64(),
            Some(((index + 1) * 15) as f64)
        );
        assert!(notification["params"]["message"]
            .as_str()
            .unwrap()
            .contains(&((index + 1) * 15).to_string()));
    }
    assert!(client
        .notifications
        .iter()
        .any(|n| n["method"] == "notifications/claude/channel"
            && n["params"]["meta"]["approval_id"] == APPROVAL_ID));
}

#[tokio::test(start_paused = true)]
async fn no_token_produces_no_progress_and_offline_returns_immediately() {
    for scenario in [
        Scenario::ApproveAfter(Duration::from_secs(30)),
        Scenario::Offline,
    ] {
        let mut client = Client::new("unknown", scenario, ApprovalConfig::default()).await;
        let started = tokio::time::Instant::now();
        let value = client
            .call("credential_http_request", http_args(), None)
            .await;
        if value["status"] == "approval_pending" {
            assert_eq!(started.elapsed(), Duration::ZERO);
        }
        assert!(!client
            .notifications
            .iter()
            .any(|n| n["method"] == "notifications/progress"));
    }
}

#[tokio::test(start_paused = true)]
async fn exhausted_budget_waits_resumes_once_and_then_is_already_consumed() {
    let mut client = Client::new(
        "unknown",
        Scenario::ApproveAfter(Duration::from_secs(75)),
        ApprovalConfig::default(),
    )
    .await;
    let started = tokio::time::Instant::now();
    let pending = client
        .call("credential_http_request", http_args(), Some(json!(0)))
        .await;
    assert_eq!(pending["status"], "approval_pending");
    assert_eq!(pending["wait_tool"], approval::WAIT_TOOL);
    assert_eq!(started.elapsed(), Duration::from_secs(50));
    assert!(client.server.pending_tool(APPROVAL_ID));
    let result = client
        .call(
            approval::WAIT_TOOL,
            json!({"approval_id": APPROVAL_ID, "max_wait_s": 600}),
            Some(json!(42)),
        )
        .await;
    assert_eq!(result["status"], 200);
    assert!(!client.server.pending_tool(APPROVAL_ID));
    let consumed = client
        .call(
            approval::WAIT_TOOL,
            json!({"approval_id": APPROVAL_ID}),
            None,
        )
        .await;
    assert_eq!(consumed["status"], "already_consumed");
    assert_eq!(client.helper.executions.load(Ordering::SeqCst), 1);
    assert!(client
        .helper
        .requests
        .lock()
        .unwrap()
        .iter()
        .filter(|r| r["op"] == "remote.wait")
        .all(|r| r["params"]["max_wait_ms"].as_u64().unwrap() <= 50_000));
}

#[tokio::test(start_paused = true)]
async fn every_terminal_approval_state_is_a_normal_tool_result() {
    for (scenario, status) in [
        (Scenario::Denied, "approval_denied"),
        (Scenario::Expired, "approval_expired"),
        (Scenario::Cancelled, "approval_cancelled"),
        (Scenario::NoApprover, "no_approver"),
    ] {
        let mut client = Client::new("unknown", scenario, ApprovalConfig::default()).await;
        let result = client
            .call("credential_http_request", http_args(), None)
            .await;
        assert_eq!(result["status"], status);
        assert!(result["next_steps"].is_string());
        assert_eq!(client.helper.executions.load(Ordering::SeqCst), 0);
    }
}

#[tokio::test]
async fn local_dialog_denial_and_request_expiry_match_their_distinct_result_snapshots() {
    let snapshot: Value = serde_json::from_str(include_str!(
        "../tests/snapshots/local_approval_results.json"
    ))
    .unwrap();
    for (scenario, name) in [
        (Scenario::LocalDenied, "dialog_denied"),
        (Scenario::LocalExpired, "request_expired"),
    ] {
        let mut client = Client::new("unknown", scenario, ApprovalConfig::default()).await;
        let id = client
            .send(
                "tools/call",
                json!({"name":"credential_http_request","arguments":http_args()}),
            )
            .await;
        let result = client.response(id).await;
        assert_eq!(result["isError"], snapshot[name]["isError"]);
        let value: Value =
            serde_json::from_str(result["content"][0]["text"].as_str().unwrap()).unwrap();
        let steps = &snapshot[name]["next_steps"];
        assert_eq!(
            value,
            json!({"status":snapshot[name]["status"],"approval_id":APPROVAL_ID,
            "next_steps":kv_i18n::t(steps["zh"].as_str().unwrap(),steps["en"].as_str().unwrap())})
        );
        assert_eq!(client.helper.executions.load(Ordering::SeqCst), 0);
    }
    assert!(approval::local_outcome(&json!({"code":"local_approval_timeout"})).is_none());
    assert_eq!(
        approval::local_outcome(
            &json!({"code":"local_approval_timeout","approval_id":APPROVAL_ID,"expires_at":0})
        )
        .unwrap()["status"],
        "approval_expired"
    );
    assert_eq!(approval::local_outcome(&json!({"code":"local_approval_timeout","approval_id":APPROVAL_ID,"expires_at":i64::MAX})).unwrap()["status"],"approval_pending");
    assert!(approval::local_outcome(&json!({"message":"denied or timed out"})).is_none());
}

#[test]
fn verified_client_budget_requires_the_measured_name_and_version_and_obeys_explicit_caps() {
    let config = ApprovalConfig::default();
    assert_eq!(
        config
            .client_budget("codex-mcp-client", "0.162.1")
            .as_secs(),
        180
    );
    for version in ["fixture", "0.161.0", "0.163.0", ""] {
        assert_eq!(
            config.client_budget("codex-mcp-client", version).as_secs(),
            50
        );
    }
    let capped = ApprovalConfig {
        server_timeout_s: Some(60),
        ..Default::default()
    };
    assert_eq!(
        capped
            .client_budget("codex-mcp-client", "0.162.1")
            .as_secs(),
        50
    );
    let explicit = ApprovalConfig {
        runtime_overrides: [("codex-mcp-client".into(), 42)].into(),
        ..Default::default()
    };
    assert_eq!(
        explicit
            .client_budget("codex-mcp-client", "0.162.1")
            .as_secs(),
        42
    );
}

#[tokio::test(start_paused = true)]
async fn helper_restart_requires_identical_retry_and_executes_only_once() {
    let mut client = Client::new(
        "unknown",
        Scenario::RestartAfter(Duration::from_secs(75)),
        ApprovalConfig::default(),
    )
    .await;
    assert_eq!(
        client
            .call("credential_http_request", http_args(), None)
            .await["status"],
        "approval_pending"
    );
    let result = client
        .call(
            approval::WAIT_TOOL,
            json!({"approval_id": APPROVAL_ID}),
            None,
        )
        .await;
    assert_eq!(result["status"], "approved_retry_required");
    let mut retry = http_args();
    retry["approval_id"] = json!(APPROVAL_ID);
    assert_eq!(
        client
            .call("credential_http_request", retry.clone(), None)
            .await["status"],
        200
    );
    assert_eq!(
        client.call("credential_http_request", retry, None).await["status"],
        "already_consumed"
    );
    assert_eq!(client.helper.executions.load(Ordering::SeqCst), 1);
}

#[tokio::test(start_paused = true)]
async fn wait_restores_typed_tool_postprocessing_instead_of_returning_an_intermediate_token() {
    let mut client = Client::new(
        "unknown",
        Scenario::ApproveAfter(Duration::from_secs(75)),
        ApprovalConfig::default(),
    )
    .await;
    let args = json!({"type": "oauth2", "name": "fixture", "purpose": "Synthetic mail approval test", "format": "xoauth2", "username": "fixture@example.test"});
    assert_eq!(
        client.call("credential_access_token", args, None).await["status"],
        "approval_pending"
    );
    let result = client
        .call(
            approval::WAIT_TOOL,
            json!({"approval_id": APPROVAL_ID}),
            None,
        )
        .await;
    assert!(result["xoauth2"].is_string());
    assert_eq!(result["username"], "fixture@example.test");
    assert_eq!(client.helper.executions.load(Ordering::SeqCst), 1);
}

#[tokio::test(start_paused = true)]
async fn early_client_timeout_preserves_the_original_result_and_downgrades_until_restart() {
    let config = ApprovalConfig {
        wait_in_call: Duration::from_secs(180),
        ..Default::default()
    };
    let mut client = Client::new(
        "claude-code",
        Scenario::ApproveAfter(Duration::from_secs(45)),
        config,
    )
    .await;
    let id = client.send("tools/call", json!({"name": "credential_http_request", "arguments": http_args(), "_meta": {"progressToken": "cancel-probe"}})).await;
    loop {
        let value: Value =
            serde_json::from_str(&client.reader.next_line().await.unwrap().unwrap()).unwrap();
        let progress = value["method"] == "notifications/progress";
        client.notifications.push(value);
        if progress {
            break;
        }
    }
    client
        .notify(
            "notifications/cancelled",
            json!({"requestId": id, "reason": "Request timed out before the configured budget"}),
        )
        .await;
    let status = client.call("credential_status", json!({}), None).await;
    assert_eq!(status["remote_approval"]["runtime_budget_s"], 50);
    assert!(client.server.pending_tool(APPROVAL_ID));
    assert_eq!(client.helper.executions.load(Ordering::SeqCst), 0);
    tokio::time::advance(Duration::from_secs(30)).await;
    for _ in 0..20 {
        tokio::task::yield_now().await;
    }
    let result = client
        .call(
            approval::WAIT_TOOL,
            json!({"approval_id": APPROVAL_ID}),
            None,
        )
        .await;
    assert_eq!(result["body"], "synthetic upstream result");
    assert_eq!(client.helper.executions.load(Ordering::SeqCst), 1);
    assert_eq!(
        client
            .call(
                approval::WAIT_TOOL,
                json!({"approval_id": APPROVAL_ID}),
                None
            )
            .await["status"],
        "already_consumed"
    );
    assert!(client
        .helper
        .requests
        .lock()
        .unwrap()
        .iter()
        .any(|r| r["op"] == "remote.client_timeout_observed"
            && r["params"]["clientInfo"]["name"] == "claude-code"));
    let restarted = Client::new("claude-code", Scenario::Never, ApprovalConfig::default()).await;
    assert_eq!(restarted.server.session.runtime_budget().as_secs(), 180);
}

#[tokio::test(start_paused = true)]
async fn approval_arriving_after_pending_notifies_an_idle_session_without_consuming_the_result() {
    let mut client = Client::new(
        "unknown",
        Scenario::ApproveAfter(Duration::from_secs(75)),
        ApprovalConfig::default(),
    )
    .await;
    assert_eq!(
        client
            .call("credential_http_request", http_args(), None)
            .await["status"],
        "approval_pending"
    );
    loop {
        let value: Value =
            serde_json::from_str(&client.reader.next_line().await.unwrap().unwrap()).unwrap();
        if value["method"] == "notifications/claude/channel" {
            assert_eq!(value["params"]["meta"]["approval_id"], APPROVAL_ID);
            assert!(value["params"]["content"]
                .as_str()
                .unwrap()
                .contains(approval::WAIT_TOOL));
            break;
        }
    }
    assert_eq!(client.helper.executions.load(Ordering::SeqCst), 0);
    assert_eq!(
        client
            .call(
                approval::WAIT_TOOL,
                json!({"approval_id": APPROVAL_ID}),
                None
            )
            .await["body"],
        "synthetic upstream result"
    );
    assert_eq!(client.helper.executions.load(Ordering::SeqCst), 1);
}

#[tokio::test(start_paused = true)]
async fn initialize_selects_the_table_and_status_includes_remote_approval() {
    for (names, budget) in approval::RUNTIME_BUDGETS {
        let client = Client::new(names[0], Scenario::Never, ApprovalConfig::default()).await;
        assert_eq!(client.server.session.runtime_budget().as_secs(), *budget);
    }
    let mut client = Client::new(
        "unlisted-client",
        Scenario::Never,
        ApprovalConfig::default(),
    )
    .await;
    let status = client.call("credential_status", json!({}), None).await;
    assert_eq!(status["remote_approval"]["runtime_budget_s"], 50);
    assert_eq!(status["remote_approval"]["relay"], "connected");
    let id = client.send("tools/list", json!({})).await;
    let listed = client.response(id).await;
    let tools = listed["tools"].as_array().unwrap();
    let wait = tools
        .iter()
        .find(|t| t["name"] == approval::WAIT_TOOL)
        .unwrap();
    assert_eq!(wait["inputSchema"]["required"], json!(["approval_id"]));
    assert_eq!(
        wait["inputSchema"]["properties"]["max_wait_s"]["minimum"],
        5
    );
    assert_eq!(
        wait["inputSchema"]["properties"]["max_wait_s"]["maximum"],
        600
    );
    let http = tools
        .iter()
        .find(|t| t["name"] == "credential_http_request")
        .unwrap();
    assert_eq!(
        http["inputSchema"]["properties"]["approval_id"]["type"],
        "string"
    );
}

#[test]
fn configuration_overrides_are_explicit_and_unknown_clients_remain_conservative() {
    assert_eq!(approval::runtime_budget("codex-mcp-client", None), 50);
    assert_eq!(approval::runtime_budget("codex-mcp-client", Some(900)), 180);
    assert_eq!(approval::runtime_budget("claude-code", Some(60)), 50);
    assert_eq!(approval::runtime_budget("unknown", Some(900)), 50);
    let config = ApprovalConfig {
        runtime_overrides: [("unknown".into(), 75)].into(),
        ..Default::default()
    };
    assert_eq!(config.budget("UNKNOWN"), Duration::from_secs(75));
}

#[test]
fn environment_configuration_validates_overrides_without_mutating_the_process_environment() {
    fn config(values: &[(&str, &str)]) -> Result<ApprovalConfig, String> {
        ApprovalConfig::from_lookup(|name| {
            values
                .iter()
                .find(|(key, _)| *key == name)
                .map(|(_, value)| value.to_string())
                .ok_or(std::env::VarError::NotPresent)
        })
    }
    let defaults = config(&[]).unwrap();
    assert_eq!(defaults.wait_in_call.as_secs(), 60);
    let configured = config(&[
        ("KEYVALET_WAIT_IN_CALL_S", "180"),
        ("KEYVALET_WAIT_TOOL_MAX_S", "700"),
        ("KEYVALET_PROGRESS_INTERVAL_S", "20"),
        ("KEYVALET_TOOL_TIMEOUT_SEC", "900"),
        ("KEYVALET_RUNTIME_BUDGETS", r#"{"  Custom CLIENT ":75}"#),
    ])
    .unwrap();
    assert_eq!(configured.wait_in_call.as_secs(), 180);
    assert_eq!(configured.wait_tool_max.as_secs(), 600);
    assert_eq!(configured.progress_interval.as_secs(), 20);
    assert_eq!(configured.budget("custom client").as_secs(), 75);
    assert_eq!(configured.budget("codex-mcp-client").as_secs(), 180);
    for name in [
        "KEYVALET_WAIT_IN_CALL_S",
        "KEYVALET_WAIT_TOOL_MAX_S",
        "KEYVALET_PROGRESS_INTERVAL_S",
        "KEYVALET_TOOL_TIMEOUT_SEC",
    ] {
        for invalid in ["0", "-1", "1.5", "86401", "oops"] {
            assert!(config(&[(name, invalid)]).unwrap_err().contains(name));
        }
    }
    for invalid in ["[]", "oops", r#"{"custom":0}"#, r#"{"custom":86401}"#] {
        assert!(config(&[("KEYVALET_RUNTIME_BUDGETS", invalid)]).is_err());
    }
    let unicode = ApprovalConfig::from_lookup(|_| {
        Err(std::env::VarError::NotUnicode(std::ffi::OsString::from(
            "invalid",
        )))
    });
    assert!(unicode.is_err());
    let unicode_map = ApprovalConfig::from_lookup(|name| {
        if name == "KEYVALET_RUNTIME_BUDGETS" {
            Err(std::env::VarError::NotUnicode(std::ffi::OsString::from(
                "invalid",
            )))
        } else {
            Err(std::env::VarError::NotPresent)
        }
    });
    assert!(unicode_map.unwrap_err().contains("UTF-8"));
}

#[test]
fn unrecognized_states_and_scrubbing_preserve_the_non_approval_contract() {
    assert!(!approval::is_approval_result(&json!({"status": 200})));
    assert_eq!(approval::next_steps("other"), ("", ""));
    let result = approval::tool_result(json!({"synthetic": true}));
    assert_eq!(
        serde_json::to_value(result).unwrap()["content"][0]["text"],
        r#"{"synthetic":true}"#
    );
    let mut value =
        json!({"array": ["synthetic-value", {"nested": "synthetic-token"}, 4, true, null]});
    approval::scrub_value(&mut value);
    assert_eq!(value, json!({"array": ["", {"nested": ""}, 4, true, null]}));
}

#[test]
fn every_a8_status_has_both_language_snapshots_and_normal_mcp_semantics() {
    let snapshot: Value =
        serde_json::from_str(include_str!("../tests/snapshots/approval_results.json")).unwrap();
    for status in [
        "ok",
        "approval_pending",
        "approval_denied",
        "approval_cancelled",
        "approval_expired",
        "no_approver",
        "approved_retry_required",
        "still_pending",
        "already_consumed",
    ] {
        let (zh, en) = approval::next_steps(status);
        assert_eq!(snapshot[status], json!({"zh": zh, "en": en}));
        let result = approval::tool_result(
            json!({"status": status, "approval_id": APPROVAL_ID, "result": {"test": true}, "next_steps": "untrusted helper copy"}),
        );
        assert_eq!(result.is_error, Some(false));
        let text = serde_json::to_value(&result).unwrap()["content"][0]["text"]
            .as_str()
            .unwrap()
            .to_owned();
        let value: Value = serde_json::from_str(&text).unwrap();
        assert!([zh, en].contains(&value["next_steps"].as_str().unwrap()));
        assert_eq!(value.get("result").is_some(), status == "ok");
    }
}

#[tokio::test(start_paused = true)]
async fn schemas_validate_wait_and_resume_ids_before_the_helper_receives_a_request() {
    use rmcp::handler::server::ServerHandler;
    let mut client = Client::new("unknown", Scenario::Never, ApprovalConfig::default()).await;
    assert!(client.server.get_tool("missing").is_none());
    assert!(client
        .server
        .get_tool(approval::WAIT_TOOL)
        .unwrap()
        .input_schema["properties"]["max_wait_s"]
        .get("maximum")
        .is_some());
    for args in [
        json!({}),
        json!({"approval_id": ""}),
        json!({"approval_id": APPROVAL_ID, "max_wait_s": 4}),
        json!({"approval_id": APPROVAL_ID, "max_wait_s": 601}),
        json!({"approval_id": APPROVAL_ID, "max_wait_s": null}),
        json!({"approval_id": APPROVAL_ID, "max_wait_s": 5.5}),
    ] {
        let id = client
            .send(
                "tools/call",
                json!({"name": approval::WAIT_TOOL, "arguments": args}),
            )
            .await;
        assert!(client.frame(id).await.get("error").is_some());
    }
    for approval_id in [json!(""), json!(null), json!(42)] {
        let mut args = http_args();
        args["approval_id"] = approval_id;
        let id = client
            .send(
                "tools/call",
                json!({"name": "credential_http_request", "arguments": args}),
            )
            .await;
        assert!(client.frame(id).await.get("error").is_some());
    }
    assert!(!client
        .helper
        .requests
        .lock()
        .unwrap()
        .iter()
        .any(|r| r["op"] == "remote.wait" || r["op"] == "httpRequest"));
    client
        .notify(
            "notifications/cancelled",
            json!({"requestId": 999, "reason": "User cancelled"}),
        )
        .await;
    client
        .notify("notifications/cancelled", json!({"reason": "timeout"}))
        .await;
    let status = client.call("credential_status", json!({}), None).await;
    assert_eq!(status["remote_approval"]["runtime_budget_s"], 50);
    assert!(!client
        .helper
        .requests
        .lock()
        .unwrap()
        .iter()
        .any(|r| r["op"] == "remote.client_timeout_observed"));
}

#[tokio::test(start_paused = true)]
async fn retained_tool_context_expires_and_wait_without_a_context_still_returns_an_envelope() {
    let mut client = Client::new("unknown", Scenario::Never, ApprovalConfig::default()).await;
    assert_eq!(
        client
            .call("credential_http_request", http_args(), None)
            .await["status"],
        "approval_pending"
    );
    assert!(client.server.pending_tool(APPROVAL_ID));
    tokio::time::advance(Duration::from_secs(601)).await;
    tokio::task::yield_now().await;
    assert!(!client.server.pending_tool(APPROVAL_ID));
    assert_eq!(
        client
            .call(
                approval::WAIT_TOOL,
                json!({"approval_id": APPROVAL_ID}),
                None
            )
            .await["status"],
        "approval_expired"
    );
    let mut client = Client::new(
        "unknown",
        Scenario::ApproveAfter(Duration::ZERO),
        ApprovalConfig::default(),
    )
    .await;
    // The helper can also retain a request submitted by another front end.
    let value = client
        .server
        .session
        .remote_request(
            "httpRequest",
            http_args().as_object().unwrap().clone(),
            Duration::from_secs(5),
        )
        .await
        .unwrap();
    assert_eq!(value["status"], "approval_pending");
    assert_eq!(
        client
            .call(
                approval::WAIT_TOOL,
                json!({"approval_id": APPROVAL_ID}),
                None
            )
            .await["status"],
        "ok"
    );
}

#[test]
fn an_explicit_runtime_override_cannot_exceed_a_confirmed_server_hard_timeout() {
    let config = ApprovalConfig {
        runtime_overrides: [("custom".into(), 180)].into(),
        server_timeout_s: Some(60),
        ..Default::default()
    };
    assert_eq!(config.budget("custom"), Duration::from_secs(50));
}

#[tokio::test(start_paused = true)]
async fn helper_policy_negotiation_counts_toward_the_request_runtime_budget() {
    let mut client = Client::new("unknown", Scenario::Never, ApprovalConfig::default()).await;
    client
        .helper
        .policy_delay_ms
        .store(10_000, Ordering::SeqCst);
    let started = tokio::time::Instant::now();
    assert_eq!(
        client
            .call(
                "credential_http_request",
                http_args(),
                Some(json!("policy-budget"))
            )
            .await["status"],
        "approval_pending"
    );
    assert_eq!(started.elapsed(), Duration::from_secs(50));
    assert_eq!(client.helper.executions.load(Ordering::SeqCst), 0);
}

#[tokio::test(start_paused = true)]
async fn progress_covers_policy_discovery_without_gaps_or_duplicate_ticks() {
    let config = ApprovalConfig {
        progress_interval: Duration::from_secs(1),
        ..Default::default()
    };
    let mut client = Client::new("unknown", Scenario::Never, config).await;
    client.helper.policy_delay_ms.store(3_000, Ordering::SeqCst);
    let value = client
        .call(
            "credential_http_request",
            http_args(),
            Some(json!("discovery")),
        )
        .await;
    assert_eq!(value["status"], "approval_pending");
    let progress: Vec<_> = client
        .notifications
        .iter()
        .filter(|notice| notice["method"] == "notifications/progress")
        .map(|notice| {
            assert_eq!(notice["params"]["progressToken"], "discovery");
            notice["params"]["progress"].as_f64().unwrap()
        })
        .collect();
    assert!((49..=50).contains(&progress.len()));
    assert_eq!(
        progress,
        (1..=progress.len())
            .map(|second| second as f64)
            .collect::<Vec<_>>()
    );
    assert_eq!(client.helper.executions.load(Ordering::SeqCst), 0);
}

#[tokio::test(start_paused = true)]
async fn cancellation_during_policy_discovery_never_starts_the_usage_operation() {
    let config = ApprovalConfig {
        progress_interval: Duration::from_secs(1),
        ..Default::default()
    };
    let mut client = Client::new("claude-code", Scenario::Never, config).await;
    client.helper.policy_delay_ms.store(3_000, Ordering::SeqCst);
    let id = client
        .send(
            "tools/call",
            json!({"name":"credential_http_request",
            "arguments":http_args(),"_meta":{"progressToken":"discovery-cancel"}}),
        )
        .await;
    let progress: Value =
        serde_json::from_str(&client.reader.next_line().await.unwrap().unwrap()).unwrap();
    assert_eq!(progress["method"], "notifications/progress");
    assert_eq!(progress["params"]["progress"], 1.0);
    client
        .notify(
            "notifications/cancelled",
            json!({"requestId":id,"reason":"User cancelled"}),
        )
        .await;
    // MCP discards the cancelled request's response. A new status call confirms that
    // the server remains usable and the cancelled usage operation never reaches the helper.
    for _ in 0..5 {
        tokio::task::yield_now().await;
    }
    client.helper.policy_delay_ms.store(0, Ordering::SeqCst);
    let status = client.call("credential_status", json!({}), None).await;
    assert_eq!(status["remote_approval"]["runtime_budget_s"], 180);
    assert!(!client
        .helper
        .requests
        .lock()
        .unwrap()
        .iter()
        .any(|request| matches!(request["op"].as_str(), Some("httpRequest" | "remote.wait"))));
    assert_eq!(
        client.server.session.runtime_budget(),
        Duration::from_secs(180)
    );
    assert_eq!(client.helper.executions.load(Ordering::SeqCst), 0);
    assert!(
        client
            .helper
            .requests
            .lock()
            .unwrap()
            .iter()
            .filter(|request| request["op"] == "remote.status")
            .count()
            >= 3
    );
}

#[tokio::test(start_paused = true)]
async fn a_lost_export_formatter_never_returns_a_raw_credential_to_the_model() {
    let mut client = Client::new(
        "unknown",
        Scenario::ApproveAfter(Duration::ZERO),
        ApprovalConfig::default(),
    )
    .await;
    assert_eq!(
        client
            .server
            .session
            .remote_request(
                "get",
                json!({"type": "api_key", "name": "fixture"})
                    .as_object()
                    .unwrap()
                    .clone(),
                Duration::from_secs(5)
            )
            .await
            .unwrap()["status"],
        "approval_pending"
    );
    let value = client
        .call(
            approval::WAIT_TOOL,
            json!({"approval_id": APPROVAL_ID}),
            None,
        )
        .await;
    assert_eq!(value["status"], "already_consumed");
    assert_eq!(value["reason"], "continuation_unavailable");
    assert!(value.get("result").is_none());
    assert!(!value.to_string().contains("synthetic-private-value"));
    assert_eq!(client.helper.executions.load(Ordering::SeqCst), 1);
}

#[tokio::test(start_paused = true)]
async fn a_fresh_mcp_connection_restores_the_original_formatter_and_consumes_once() {
    for (tool, extra, result) in [
        (
            "credential_access_token",
            json!({"format":"xoauth2","username":"fixture@example.test"}),
            None,
        ),
        ("credential_get", json!({}), None),
        (
            "credential_export_file",
            json!({}),
            Some(json!({"type":"api_key","name":"fixture","value":""})),
        ),
        (
            "credential_gateway",
            json!({}),
            Some(json!({"type":"api_key","name":"fixture"})),
        ),
    ] {
        let helper = FakeHelper::new(Scenario::ApproveAfter(Duration::from_secs(65)));
        let mut old = Client::attach("unknown", helper.clone(), ApprovalConfig::default()).await;
        let mut args = json!({"type":"api_key","name":"fixture","purpose":"Synthetic cross-connection recovery"});
        args.as_object_mut()
            .unwrap()
            .extend(extra.as_object().unwrap().clone());
        let pending = old.call(tool, args, None).await;
        assert_eq!(pending["status"], "approval_pending");
        drop(old);
        *helper.result_override.lock().unwrap() = result;
        let mut fresh = Client::attach("unknown", helper.clone(), ApprovalConfig::default()).await;
        let id = fresh
            .send(
                "tools/call",
                json!({"name":"credential_wait_approval","arguments":{"approval_id":APPROVAL_ID}}),
            )
            .await;
        let value = fresh.response(id).await;
        let text = value["content"][0]["text"].as_str().unwrap();
        match tool {
            "credential_access_token" => assert!(text.contains("xoauth2")),
            "credential_get" => assert!(text.contains("synthetic-private-value")),
            "credential_export_file" => {
                assert!(!text.contains("synthetic-private-value"));
                assert_eq!(value["isError"], true);
            }
            _ => assert!(text.contains("already_consumed")),
        }
        assert_eq!(helper.executions.load(Ordering::SeqCst), 1);
        let consumed = fresh
            .call(
                "credential_wait_approval",
                json!({"approval_id":APPROVAL_ID}),
                None,
            )
            .await;
        assert_eq!(consumed["status"], "already_consumed");
    }
}

#[tokio::test(start_paused = true)]
async fn resolved_imap_host_is_preserved_in_the_approval_continuation() {
    let mut client = Client::new("unknown", Scenario::Never, ApprovalConfig::default()).await;
    let pending = client
        .call(
            "credential_imap_test",
            json!({"type":"oauth2","name":"fixture","purpose":"Verify mailbox approval"}),
            None,
        )
        .await;
    assert_eq!(pending["status"], "approval_pending");
    let requests = client.helper.requests.lock().unwrap();
    let token = requests
        .iter()
        .find(|request| request["op"] == "accessToken")
        .unwrap();
    assert_eq!(
        token["params"]["frontend"]["options"]["host"],
        "outlook.office365.com"
    );
}
