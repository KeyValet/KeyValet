//! Explicit development fixture for live runtimes; never touches the installed helper.
use kv_mcp::{
    approval::ApprovalConfig,
    fake_helper::{FakeHelper, Scenario},
    server::Server,
    session::HelperSession,
};
use rmcp::ServiceExt;
use std::time::Duration;

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
            let mut count = usize::MAX;
            loop {
                {
                let requests = helper.requests.lock().unwrap();
                if requests.len() != count {
                    count = requests.len();
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
    let service = server.serve(rmcp::transport::stdio()).await?;
    service.waiting().await?;
    session.lock().await;
    task.abort();
    Ok(())
}
