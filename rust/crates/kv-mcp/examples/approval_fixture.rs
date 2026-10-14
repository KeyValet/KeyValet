//! Explicit development fixture for live runtimes; never touches the installed helper.
use kv_mcp::{
    approval::ApprovalConfig,
    fake_helper::{FakeHelper, Scenario},
    server::Server,
    session::HelperSession,
};
use rmcp::ServiceExt;
use std::time::Duration;

#[derive(Clone)]
struct Fixture(Server);

impl rmcp::ServerHandler for Fixture {
    fn get_info(&self) -> rmcp::model::ServerConfig {
        self.0.get_info()
    }

    async fn initialize(
        &self,
        request: rmcp::model::InitializeRequestParams,
        context: rmcp::service::RequestContext<rmcp::RoleServer>,
    ) -> Result<rmcp::model::InitializeResult, rmcp::ErrorData> {
        kv_mcp::fake_helper::probe_event(
            "initialize",
            serde_json::json!({"client_info":request.client_info,"agent_pid":kv_mcp::session::agent_pid()}),
        );
        self.0.initialize(request, context).await
    }

    async fn list_tools(
        &self,
        request: Option<rmcp::model::PaginatedRequestParams>,
        context: rmcp::service::RequestContext<rmcp::RoleServer>,
    ) -> Result<rmcp::model::ListToolsResult, rmcp::ErrorData> {
        let mut result = self.0.list_tools(request, context).await?;
        result.tools.retain(|tool| {
            matches!(
                tool.name.as_ref(),
                "credential_http_request" | "credential_wait_approval"
            )
        });
        for kind in ["progress", "silent"] {
            result.tools.push(serde_json::from_value(serde_json::json!({"name":format!("r2d_block_{kind}"), "description":format!("Call once: a synthetic HTTP request waits four minutes for approval with {kind} notifications."), "inputSchema":{"type":"object","properties":{}}})).unwrap());
        }
        Ok(result)
    }

    async fn call_tool(
        &self,
        mut request: rmcp::model::CallToolRequestParams,
        mut context: rmcp::service::RequestContext<rmcp::RoleServer>,
    ) -> Result<rmcp::model::CallToolResponse, rmcp::ErrorData> {
        use rmcp::model::RequestParamsMeta;
        let name = request.name.clone();
        let token = request
            .progress_token()
            .or_else(|| context.meta.get_progress_token());
        let started = std::time::Instant::now();
        kv_mcp::fake_helper::probe_event(
            "tool_started",
            serde_json::json!({"tool":name,"progress_token":token}),
        );
        if name == "r2d_block_silent" {
            context.meta.remove("progressToken");
            if let Some(meta) = request.meta.as_mut() {
                meta.remove("progressToken");
            }
        }
        if matches!(name.as_ref(), "r2d_block_progress" | "r2d_block_silent") {
            request.name = "credential_http_request".into();
            request.arguments=Some(serde_json::json!({"type":"api_key","name":"fixture","method":"POST","url":"https://example.test/request","body":{"fixture":true},"purpose":"R2-D synthetic four-minute approval experiment"}).as_object().unwrap().clone());
        }
        let response = self.0.call_tool(request, context).await;
        let result = match &response {
            Ok(rmcp::model::CallToolResponse::Complete(result)) => {
                serde_json::to_value(result).ok()
            }
            _ => None,
        };
        kv_mcp::fake_helper::probe_event(
            "tool_completed",
            serde_json::json!({"tool":name,"wait_s":started.elapsed().as_secs_f64(),"result":result}),
        );
        response
    }

    async fn on_cancelled(
        &self,
        notification: rmcp::model::CancelledNotificationParam,
        context: rmcp::service::NotificationContext<rmcp::RoleServer>,
    ) {
        kv_mcp::fake_helper::probe_event("cancelled", serde_json::json!({"params":notification}));
        self.0.on_cancelled(notification, context).await;
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let delay: u64 = std::env::var("W5_APPROVE_AFTER_S")
        .unwrap_or_else(|_| "180".into())
        .parse()?;
    let config = ApprovalConfig::from_env().map_err(anyhow::Error::msg)?;
    let (session_stream, helper_stream) = tokio::io::duplex(1024 * 1024);
    let helper = FakeHelper::new(Scenario::ApproveAfter(Duration::from_secs(delay)));
    let task = helper.serve(helper_stream);
    #[cfg(unix)]
    if let Ok(path) = std::env::var("R2D_HELPER_SOCKET") {
        use std::os::unix::fs::PermissionsExt;
        let listener = tokio::net::UnixListener::bind(&path)?;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
        let helper = helper.clone();
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                helper.serve(stream);
            }
        });
    }
    if let Ok(path) = std::env::var("R2D_HELPER_LOG") {
        let helper = helper.clone();
        tokio::spawn(async move {
            let mut count = (usize::MAX, usize::MAX);
            loop {
                {
                    let requests = helper.requests.lock().unwrap();
                    let executions = helper.executions.load(std::sync::atomic::Ordering::SeqCst);
                    if (requests.len(), executions) != count {
                        count = (requests.len(), executions);
                        // Only operation names and counts; never retain request bodies or secrets.
                        let summary = serde_json::json!({
                            "operations": requests.iter().map(|r| r["op"].clone()).collect::<Vec<_>>(),
                            "executions": helper.executions.load(std::sync::atomic::Ordering::SeqCst),
                        });
                        let _ = std::fs::write(&path, format!("{summary}\n"));
                    }
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        });
    }
    let session = HelperSession::with_test_transport(config, session_stream).await;
    let server = Server::new(session.clone());
    let service = Fixture(server).serve(rmcp::transport::stdio()).await?;
    service.waiting().await?;
    session.lock().await;
    task.abort();
    Ok(())
}
