//! Appendix C fake helper. No installed paths, authentication prompts, or real credentials.

use serde_json::{json, Map, Value};
use std::sync::atomic::{AtomicI64, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};

pub const APPROVAL_ID: &str = "01J00000000000000000000000";

/// Metadata-only recording for the explicitly compiled live runtime fixture.
pub fn probe_event(event: &str, mut fields: Value) {
    use std::io::Write;
    static START: std::sync::OnceLock<std::time::Instant> = std::sync::OnceLock::new();
    static LOG: Mutex<()> = Mutex::new(());
    let Ok(path) = std::env::var("R2D_WIRE_LOG") else {
        return;
    };
    let _guard = LOG.lock().unwrap();
    fields["event"] = json!(event);
    fields["elapsed_s"] = json!(START
        .get_or_init(std::time::Instant::now)
        .elapsed()
        .as_secs_f64());
    if let Ok(mut file) = std::fs::OpenOptions::new()
        .append(true)
        .create(true)
        .open(path)
    {
        let _ = writeln!(file, "{fields}");
    }
}

#[derive(Clone)]
pub enum Scenario {
    ApproveAfter(Duration),
    RestartAfter(Duration),
    Denied,
    Expired,
    LocalDenied,
    LocalExpired,
    Cancelled,
    NoApprover,
    Offline,
    Never,
}

struct Pending {
    op: String,
    params: Map<String, Value>,
    submitted: tokio::time::Instant,
    consumed: bool,
    blocks: u64,
}

pub struct FakeHelper {
    scenario: Scenario,
    pending: Mutex<Option<Pending>>,
    pub requests: Mutex<Vec<Value>>,
    pub executions: AtomicUsize,
    expires_at: AtomicI64,
    pub policy_delay_ms: AtomicU64,
    pub result_override: Mutex<Option<Value>>,
}

impl FakeHelper {
    pub fn new(scenario: Scenario) -> Arc<Self> {
        Arc::new(Self {
            scenario,
            pending: Mutex::new(None),
            requests: Mutex::new(Vec::new()),
            executions: AtomicUsize::new(0),
            expires_at: AtomicI64::new(crate::approval::unix_time() + 600),
            policy_delay_ms: AtomicU64::new(0),
            result_override: Mutex::new(None),
        })
    }

    fn pending_result(&self, status: &str) -> Value {
        json!({"status": status, "approval_id": APPROVAL_ID,
            "expires_at": self.expires_at.load(Ordering::SeqCst),
            "approver": {"label": "Fixture MacBook", "online": !matches!(self.scenario, Scenario::Offline)},
            "relay": if matches!(self.scenario, Scenario::Offline) {"offline"} else {"connected"},
        })
    }

    fn execute(&self) -> Value {
        let mut pending = self.pending.lock().unwrap();
        let pending = pending.as_mut().unwrap();
        if pending.consumed {
            return self.pending_result("already_consumed");
        }
        pending.consumed = true;
        self.executions.fetch_add(1, Ordering::SeqCst);
        let result = self.result_override.lock().unwrap().clone().unwrap_or_else(|| match pending.op.as_str() {
            "get" => {
                json!({"type": pending.params["type"], "name": pending.params["name"], "value": "synthetic-private-value", "fields": {}})
            }
            "accessToken" => {
                json!({"access_token": "synthetic-access-token", "account": "fixture@example.test", "expires_in": 3600})
            }
            "totp" => json!({"code": "123456", "remaining": 30}),
            _ => {
                json!({"status": 200, "body": "synthetic upstream result", "headers": {}, "body_encoding": "text", "truncated": false})
            }
        });
        let mut value = json!({"status": "ok", "approval_id": APPROVAL_ID, "result": result});
        if let Some(frontend) = pending.params.get("frontend") {
            value["frontend"] = frontend.clone();
        }
        value
    }

    async fn request(&self, op: &str, params: Map<String, Value>) -> Value {
        match op {
            "remote.status" => {
                tokio::time::sleep(Duration::from_millis(
                    self.policy_delay_ms.load(Ordering::SeqCst),
                ))
                .await;
                json!({"relay": "connected", "approvers": [{"label": "Fixture MacBook", "online": true}], "pending_n": 1, "grants_n": 0, "unattended": false, "runtime_budget_s": 180,
                "approval": {"wait_in_call_s": 600, "wait_tool_max_s": 600, "progress_interval_s": 15}})
            }
            "remote.pending.list" => {
                let pending = self.pending.lock().unwrap();
                let entries = pending.as_ref().filter(|p| !p.consumed).map(|_| vec![json!({"approval_id": APPROVAL_ID, "summary": "Synthetic HTTP request", "expires_at": self.expires_at.load(Ordering::SeqCst)})]).unwrap_or_default();
                json!({"pending": entries})
            }
            "remote.pending.for_agent" => {
                let pending = self.pending.lock().unwrap();
                json!({"pending": pending.as_ref().filter(|p| !p.consumed).map(|p| vec![json!({"approval_id": APPROVAL_ID, "expires_at": self.expires_at.load(Ordering::SeqCst), "stop_hook_blocks": p.blocks})]).unwrap_or_default()})
            }
            "remote.pending.stop_block" => {
                let mut pending = self.pending.lock().unwrap();
                let Some(pending) = pending.as_mut() else {
                    return json!({"allowed": false, "blocks_left": 0});
                };
                let allowed = pending.blocks < 3 && !pending.consumed;
                if allowed {
                    pending.blocks += 1;
                }
                json!({"allowed": allowed, "blocks_left": 3 - pending.blocks})
            }
            "remote.client_timeout_observed" => json!({}),
            "remote.wait" => {
                let Some(submitted) = self.pending.lock().unwrap().as_ref().map(|p| p.submitted)
                else {
                    return self.pending_result("approval_expired");
                };
                if submitted.elapsed() >= Duration::from_secs(600) {
                    return self.pending_result("approval_expired");
                }
                let wait = Duration::from_millis(params["max_wait_ms"].as_u64().unwrap());
                match self.scenario {
                    Scenario::ApproveAfter(delay) | Scenario::RestartAfter(delay) => {
                        let decision = tokio::time::sleep_until(submitted + delay);
                        tokio::pin!(decision);
                        tokio::select! {
                            biased;
                            _ = &mut decision => {
                                if matches!(self.scenario, Scenario::RestartAfter(_)) {
                                    self.pending_result("approved_retry_required")
                                } else { self.execute() }
                            }
                            _ = tokio::time::sleep(wait) => self.pending_result("still_pending"),
                        }
                    }
                    Scenario::Denied => self.pending_result("approval_denied"),
                    Scenario::Expired => self.pending_result("approval_expired"),
                    Scenario::Cancelled => {
                        let mut value = self.pending_result("approval_expired");
                        value["reason"] = json!("cancelled");
                        value
                    }
                    Scenario::NoApprover => self.pending_result("no_approver"),
                    _ => {
                        tokio::time::sleep(wait).await;
                        self.pending_result("still_pending")
                    }
                }
            }
            "list" => json!([]),
            "sessionInfo" => {
                json!({"grant_mode": "per_session", "vault_protection": serde_json::from_str::<Value>(include_str!("../../kv-ipc/tests/fixtures/hello-protection.json")).unwrap()})
            }
            "info" => {
                json!({"type": params["type"], "name": params["name"], "kind": "oauth2", "config": {"provider":"microsoft"}})
            }
            "exists" => json!(true),
            _ => {
                let status = match self.scenario {
                    Scenario::Denied => Some("approval_denied"),
                    Scenario::Expired => Some("approval_expired"),
                    Scenario::Cancelled => {
                        let mut value = self.pending_result("approval_expired");
                        value["reason"] = json!("cancelled");
                        return value;
                    }
                    Scenario::NoApprover => Some("no_approver"),
                    _ => None,
                };
                if let Some(status) = status {
                    return self.pending_result(status);
                }
                if params.get("approval_id").and_then(Value::as_str) == Some(APPROVAL_ID) {
                    let identical = self.pending.lock().unwrap().as_ref().is_some_and(|p| {
                        p.op == op && action_params(&p.params) == action_params(&params)
                    });
                    if identical {
                        return self.execute();
                    }
                    return json!({"status": "approval_pending", "approval_id": "01J00000000000000000000001", "expires_at": self.expires_at.load(Ordering::SeqCst), "relay": "offline"});
                }
                *self.pending.lock().unwrap() = Some(Pending {
                    op: op.into(),
                    params,
                    submitted: tokio::time::Instant::now(),
                    consumed: false,
                    blocks: 0,
                });
                self.pending_result("approval_pending")
            }
        }
    }

    pub fn serve(
        self: &Arc<Self>,
        stream: impl AsyncRead + AsyncWrite + Unpin + Send + 'static,
    ) -> tokio::task::JoinHandle<()> {
        let helper = self.clone();
        tokio::spawn(async move {
            let (read, write) = tokio::io::split(stream);
            let writer = Arc::new(tokio::sync::Mutex::new(write));
            let mut lines = BufReader::new(read).lines();
            let mut calls = tokio::task::JoinSet::new();
            while let Ok(Some(line)) = lines.next_line().await {
                let request: kv_ipc::Request = serde_json::from_str(&line).unwrap();
                helper
                    .requests
                    .lock()
                    .unwrap()
                    .push(serde_json::to_value(&request).unwrap());
                let helper = helper.clone();
                let writer = writer.clone();
                calls.spawn(async move {
                    let announce = !request.op.starts_with("remote.");
                    let result = helper.request(&request.op, request.params).await;
                    let local = if request.op == "httpRequest" { match helper.scenario {
                        Scenario::LocalDenied => Some("local_approval_denied"),
                        Scenario::LocalExpired => Some("local_approval_expired"),
                        _ => None,
                    }} else {None};
                    let frame = format!(
                        "{}\n",
                        if let Some(code)=local {json!({"id": request.id,"ok":false,"error":{"code":code,"approval_id":APPROVAL_ID}})} else {json!({"id": request.id, "ok": true, "result": result})}
                    );
                    let _ = writer.lock().await.write_all(frame.as_bytes()).await;
                    if announce && crate::approval::is_pending(&result) {
                        if let Scenario::ApproveAfter(delay) | Scenario::RestartAfter(delay) = helper.scenario {
                            tokio::time::sleep(delay).await;
                            let frame = format!("{}\n", json!({"op": "remote.approval.resolved", "params": {"status": "approved", "approval_id": APPROVAL_ID}}));
                            let _ = writer.lock().await.write_all(frame.as_bytes()).await;
                        }
                    }
                });
            }
            calls.abort_all();
        })
    }
}

fn action_params(params: &Map<String, Value>) -> Map<String, Value> {
    let mut params = params.clone();
    for key in [
        "approval_id",
        "agent",
        "wait_in_call_ms",
        "runtime_budget_s",
    ] {
        params.remove(key);
    }
    params
}
