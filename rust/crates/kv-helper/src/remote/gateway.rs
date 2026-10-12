//! The gateway obtains a one-use authorization; only the gateway sends the HTTP request.

use super::production::ProductionRunner;
use super::{FullRequest, RemoteHelper};
use kv_proxy::approval::{ApprovalProvider, ApprovalRequest};
use serde_json::{json, Map, Value};
use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

type Reply<'a> = Pin<Box<dyn Future<Output = std::result::Result<Value, String>> + Send + 'a>>;

pub struct Provider {
    pub helper: Arc<RemoteHelper>,
    pub runner: Arc<ProductionRunner>,
    pub session: String,
    pub uid: u32,
    pub agent_pid: u32,
    approvals: tokio::sync::Mutex<HashMap<String, (String, i64)>>,
}

impl Provider {
    pub fn new(
        helper: Arc<RemoteHelper>,
        runner: Arc<ProductionRunner>,
        session: String,
        uid: u32,
        agent_pid: u32,
    ) -> Self {
        Self {
            helper,
            runner,
            session,
            uid,
            agent_pid,
            approvals: tokio::sync::Mutex::new(HashMap::new()),
        }
    }
    fn render(mut value: Value) -> Value {
        if value["status"] == "ok" && value["result"]["http_forward_authorized"] == true {
            value.as_object_mut().unwrap().remove("result");
        }
        value
    }
}

impl ApprovalProvider for Provider {
    fn authorize(&self, request: ApprovalRequest) -> Reply<'_> {
        Box::pin(async move {
            let mut params: Map<String, Value> = json!({"type":request.credential_type,"name":request.credential_name,"method":request.method,"url":request.url,"headers":request.headers,"purpose":request.purpose.unwrap_or_else(|| "Use the credential through the session gateway".into())}).as_object().unwrap().clone();
            if !request.body.is_empty() {
                // The gateway retains the exact bytes until forwarding. This internal permit
                // binds their digest and size without encoding secrets in a second request.
                params.insert("body".into(), json!({"sha256":kv_core::remote::canonical::sha256_hex(&request.body),"bytes":request.body.len()}));
            }
            let full =
                FullRequest::new("gatewayForward", params.clone()).map_err(|e| e.to_string())?;
            let digest = full.binding_digest().map_err(|e| e.to_string())?;
            // Serialize creation, including the initial helper call: concurrent SDK retries
            // must join one ticket before either caller can insert it in the cache.
            let mut approvals = self.approvals.lock().await;
            let now = self.helper.services.clock.now();
            approvals.retain(|_, (_, expires_at)| *expires_at > now);
            let previous = approvals.get(&digest).cloned();
            if let Some((id, _)) = previous {
                let result = self
                    .helper
                    .wait(&id, 0, 10, self.uid, self.agent_pid)
                    .await
                    .map_err(|e| e.to_string())?;
                let value = serde_json::to_value(result).unwrap();
                if !kv_proxy::approval::is_pending(&value) {
                    approvals.remove(&digest);
                }
                return Ok(Self::render(value));
            }
            if approvals.len() >= 128 {
                return Err("Too many gateway approval requests".into());
            }
            let (mut input, hosts, methods) = self
                .runner
                .prepare(&self.helper, &self.session, "httpRequest", params, false)
                .map_err(|e| e.to_string())?;
            input.full_request = full;
            input.canonical.body_sha256 = (!request.body.is_empty())
                .then(|| kv_core::remote::canonical::sha256_hex(&request.body));
            if let Some(operation) = &mut input.operation {
                operation.body_bytes = request.body.len() as u64;
            }
            let value = self
                .helper
                .run(input, hosts, methods, 0)
                .await
                .map_err(|e| e.to_string())?;
            let value = serde_json::to_value(value).unwrap();
            if let Some(id) = value["approval_id"].as_str() {
                approvals.insert(
                    digest,
                    (id.into(), value["expires_at"].as_i64().unwrap_or(now)),
                );
            }
            Ok(Self::render(value))
        })
    }
    fn wait(&self, approval_id: String, max_wait: Duration) -> Reply<'_> {
        Box::pin(async move {
            let result = self
                .helper
                .wait(
                    &approval_id,
                    max_wait.as_millis().min(600_000) as u64,
                    max_wait.as_secs().saturating_add(10),
                    self.uid,
                    self.agent_pid,
                )
                .await
                .map_err(|e| e.to_string())?;
            let value = serde_json::to_value(result).unwrap();
            if !kv_proxy::approval::is_pending(&value) {
                self.approvals
                    .lock()
                    .await
                    .retain(|_, (id, _)| id != &approval_id);
            }
            Ok(Self::render(value))
        })
    }
}
