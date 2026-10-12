use crate::approval::{self, PendingCall, ResumeResult, ToolContext, TOOL_CONTEXT};
use crate::session::HelperSession;
use rmcp::handler::server::router::tool::ToolRouter;
use rmcp::model::{
    CallToolRequestParams, CallToolResponse, ProgressNotificationParam, RequestParamsMeta,
};
use rmcp::service::RequestContext;
use rmcp::RoleServer;
use serde_json::Value;
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::Mutex;

struct PendingRecorder {
    pending: Arc<Mutex<Option<(Value, PendingCall)>>>,
    calls: Arc<Mutex<HashMap<String, PendingCall>>>,
}

impl Drop for PendingRecorder {
    fn drop(&mut self) {
        if let Some((value, saved)) = self.pending.lock().unwrap().take() {
            if let Some(id) = value["approval_id"].as_str() {
                let mut calls = self.calls.lock().unwrap();
                calls.retain(|_, saved| saved.expires_at > approval::unix_time());
                if saved.expires_at > approval::unix_time()
                    && serde_json::to_vec(&saved.request).is_ok_and(|v| v.len() <= 1024 * 1024)
                    && calls.len() < kv_ipc::MAX_IN_FLIGHT_REQUESTS
                {
                    let expires_at = saved.expires_at;
                    calls.insert(id.into(), saved);
                    let calls = Arc::downgrade(&self.calls);
                    let id = id.to_owned();
                    let deadline = tokio::time::Instant::now()
                        + std::time::Duration::from_secs(
                            (expires_at - approval::unix_time()).max(0) as u64,
                        );
                    tokio::spawn(async move {
                        tokio::time::sleep_until(deadline).await;
                        if let Some(calls) = calls.upgrade() {
                            calls.lock().unwrap().remove(&id);
                        }
                    });
                }
            }
        }
    }
}

#[derive(Clone)]
pub struct Server {
    pub session: Arc<HelperSession>,
    pub tool_router: ToolRouter<Server>,
    pending: Arc<Mutex<HashMap<String, PendingCall>>>,
}

impl Server {
    pub fn new(session: Arc<HelperSession>) -> Self {
        Self {
            session,
            tool_router: Self::basic_tool_router()
                + Self::http_tool_router()
                + Self::mail_tool_router()
                + Self::protocols_tool_router()
                + Self::approval_tool_router(),
            pending: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Wrap the router once, including typed handlers, so progress and recovery are consistent.
    pub async fn dispatch(
        &self,
        request: CallToolRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<CallToolResponse, rmcp::ErrorData> {
        if request.name == approval::WAIT_TOOL {
            serde_json::from_value::<crate::tools::approval::WaitArgs>(Value::Object(
                request.arguments.clone().unwrap_or_default(),
            ))
            .map_err(|error| rmcp::ErrorData::invalid_params(error.to_string(), None))?;
        }
        if approval::is_usage_tool(&request.name)
            && request
                .arguments
                .as_ref()
                .and_then(|args| args.get("approval_id"))
                .is_some_and(|id| id.as_str().is_none_or(|id| id.trim().is_empty()))
        {
            return Err(rmcp::ErrorData::invalid_params(kv_i18n::t(
                "approval_id 必须是非空字符串，仅 approved_retry_required 时填写",
                "approval_id must be a nonempty string; supply it only for approved_retry_required",
            ), None));
        }
        let started = tokio::time::Instant::now();
        let deadline = started + self.session.runtime_budget();
        let mut progress_at = started;
        if self
            .with_progress(
                &request,
                &context,
                started,
                &mut progress_at,
                self.session.negotiate_policy(),
            )
            .await
            .is_none()
        {
            return Ok(
                approval::tool_result(serde_json::json!({"status": "approval_pending"})).into(),
            );
        }
        self.with_progress(
            &request,
            &context,
            started,
            &mut progress_at,
            self.route(request.clone(), context.clone(), None, deadline),
        )
        .await
        .unwrap_or_else(|| {
            Ok(approval::tool_result(serde_json::json!({"status": "approval_pending"})).into())
        })
    }

    pub(crate) async fn resume_approval(
        &self,
        args: crate::tools::approval::WaitArgs,
        context: RequestContext<RoleServer>,
    ) -> Result<CallToolResponse, rmcp::ErrorData> {
        if args.max_wait_s.is_some_and(|s| !(5..=600).contains(&s)) || args.approval_id.is_empty() {
            return Err(rmcp::ErrorData::invalid_params(
                kv_i18n::t(
                    "approval_id 必填，max_wait_s 必须是 5 到 600 之间的整数",
                    "approval_id is required and max_wait_s must be an integer from 5 to 600",
                ),
                None,
            ));
        }
        let wait = approval::remaining(self.session.wait_tool_limit(args.max_wait_s));
        let mut value = self
            .session
            .wait_approval(&args.approval_id, wait)
            .await
            .map_err(|e| rmcp::ErrorData::internal_error(e.to_string(), None))?;
        if value["status"] == "ok" {
            let saved = self.pending.lock().unwrap().remove(&args.approval_id);
            if let Some(mut saved) = saved {
                let resume = ResumeResult {
                    op: std::mem::take(&mut saved.op),
                    params: std::mem::take(&mut saved.params),
                    value: value
                        .as_object_mut()
                        .and_then(|v| v.remove("result"))
                        .unwrap_or(Value::Null),
                };
                return self
                    .route(
                        saved.request.clone(),
                        context,
                        Some(resume),
                        tokio::time::Instant::now()
                            + approval::remaining(self.session.runtime_budget()),
                    )
                    .await;
            }
            if let Some(frontend) = value.as_object_mut().and_then(|v| v.remove("frontend")) {
                if matches!(
                    frontend["tool"].as_str(),
                    Some("credential_export_file" | "credential_gateway")
                ) {
                    self.session
                        .activate_approval_files(
                            value["expires_at"]
                                .as_i64()
                                .unwrap_or_else(|| approval::unix_time() + 600),
                        )
                        .await;
                }
                let result = value
                    .as_object_mut()
                    .and_then(|v| v.remove("result"))
                    .unwrap_or(Value::Null);
                if let Some(restored) =
                    crate::continuation::restore(&self.session.session_id, frontend, result).await
                {
                    return Ok(restored.into());
                }
            }
            // Only a completed HTTP response is safe without a retained formatter.
            // In particular, a retained "get" may belong to export_file: never expose its value.
            if !value["result"]["status"].is_u64() || !value["result"]["body"].is_string() {
                value["status"] = serde_json::json!("already_consumed");
                value["reason"] = serde_json::json!("continuation_unavailable");
            }
        } else if !approval::is_pending(&value) {
            self.pending.lock().unwrap().remove(&args.approval_id);
        }
        Ok(approval::tool_result(value).into())
    }

    async fn route(
        &self,
        request: CallToolRequestParams,
        context: RequestContext<RoleServer>,
        resume: Option<ResumeResult>,
        deadline: tokio::time::Instant,
    ) -> Result<CallToolResponse, rmcp::ErrorData> {
        let pending = Arc::new(Mutex::new(None));
        let _recorder = PendingRecorder {
            pending: pending.clone(),
            calls: self.pending.clone(),
        };
        let tool_context = ToolContext {
            request: request.clone(),
            deadline,
            resume: Mutex::new(resume),
            pending: pending.clone(),
        };
        let call = self
            .tool_router
            .call(rmcp::handler::server::tool::ToolCallContext::new(
                self,
                request,
                context.clone(),
            ));
        TOOL_CONTEXT.scope(tool_context, call).await
    }

    async fn with_progress<F, T>(
        &self,
        request: &CallToolRequestParams,
        context: &RequestContext<RoleServer>,
        started: tokio::time::Instant,
        progress_at: &mut tokio::time::Instant,
        future: F,
    ) -> Option<T>
    where
        F: std::future::Future<Output = T>,
    {
        let token = request
            .progress_token()
            .or_else(|| context.meta.get_progress_token());
        let interval = self.session.progress_interval();
        let mut ticks = tokio::time::interval_at(*progress_at + interval, interval);
        ticks.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        tokio::pin!(future);
        loop {
            tokio::select! {
                biased;
                result = &mut future => return Some(result),
                _ = context.ct.cancelled() => return None,
                _ = ticks.tick(), if token.is_some() => {
                    *progress_at = tokio::time::Instant::now();
                    let seconds = started.elapsed().as_secs();
                    let message = kv_i18n::t(
                        &format!("等待 KeyValet 审批（已等待 {seconds} 秒）"),
                        &format!("Waiting for KeyValet approval ({seconds} s elapsed)"),
                    );
                    let _ = context.peer.notify_progress(ProgressNotificationParam::new(token.clone().unwrap(), started.elapsed().as_secs_f64()).with_message(message)).await;
                }
            }
        }
    }

    #[cfg(test)]
    pub fn pending_tool(&self, id: &str) -> bool {
        self.pending.lock().unwrap().contains_key(id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn saved(expires_at: i64, argument: Value) -> PendingCall {
        PendingCall {
            request: serde_json::from_value(
                serde_json::json!({"name": "fixture", "arguments": {"body": argument}}),
            )
            .unwrap(),
            op: "fixture".into(),
            params: Default::default(),
            expires_at,
        }
    }

    #[tokio::test]
    async fn missing_expired_oversized_and_excess_contexts_are_not_retained() {
        for case in ["missing-id", "expired", "oversized", "full"] {
            let calls = Arc::new(Mutex::new(HashMap::new()));
            let expires_at = approval::unix_time() + 600;
            if case == "full" {
                for n in 0..kv_ipc::MAX_IN_FLIGHT_REQUESTS {
                    calls
                        .lock()
                        .unwrap()
                        .insert(n.to_string(), saved(expires_at, Value::Null));
                }
            }
            let recorder = PendingRecorder {
                pending: Arc::new(Mutex::new(Some((
                    if case == "missing-id" {
                        serde_json::json!({})
                    } else {
                        serde_json::json!({"approval_id": "fixture-id"})
                    },
                    saved(
                        if case == "expired" { 0 } else { expires_at },
                        if case == "oversized" {
                            Value::String("x".repeat(1024 * 1024 + 1))
                        } else {
                            Value::Null
                        },
                    ),
                )))),
                calls: calls.clone(),
            };
            drop(recorder);
            assert!(!calls.lock().unwrap().contains_key("fixture-id"));
        }
    }

    #[tokio::test(start_paused = true)]
    async fn expiry_task_holds_no_session_or_pending_owner_alive() {
        let calls = Arc::new(Mutex::new(HashMap::new()));
        let weak = Arc::downgrade(&calls);
        let recorder = PendingRecorder {
            pending: Arc::new(Mutex::new(Some((
                serde_json::json!({"approval_id": "fixture-id"}),
                PendingCall {
                    request: serde_json::from_value(
                        serde_json::json!({"name": "fixture", "arguments": {}}),
                    )
                    .unwrap(),
                    op: "fixture".into(),
                    params: Default::default(),
                    expires_at: approval::unix_time() + 1,
                },
            )))),
            calls: calls.clone(),
        };
        drop(recorder);
        drop(calls);
        assert!(weak.upgrade().is_none());
        tokio::time::advance(std::time::Duration::from_secs(2)).await;
        tokio::task::yield_now().await;
    }
}
