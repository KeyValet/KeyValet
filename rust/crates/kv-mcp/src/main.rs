//! MCP stdio entry point.

#[cfg(windows)]
use kv_mcp::windows_mcp;
use kv_mcp::{approval, gateway_env, server::Server, session};
use rmcp::ServiceExt;
use std::sync::Arc;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    #[cfg(windows)]
    let worker_channel = match windows_mcp::start().await {
        Ok(Some(channel)) => channel,
        // Tokio's blocking stdin reader cannot be cancelled when the service closes stdout.
        // Exit after the launcher has dropped its channel, without waiting for that reader.
        Ok(None) => std::process::exit(0),
        Err(e) => {
            eprintln!("keyvalet-mcp: {e}");
            std::process::exit(1);
        }
    };
    #[cfg(unix)]
    unsafe {
        libc::umask(0o077);
        let limit = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        libc::setrlimit(libc::RLIMIT_CORE, &limit);
    }
    // Keep an ordinary same-user parent from reading the MCP process's memory.
    // SO_PEERCRED and polkit's /proc/PID/status UID lookup remain available.
    #[cfg(target_os = "linux")]
    if unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0 as libc::c_ulong) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    gateway_env::purge_legacy_records();
    // Both the `ring` and `aws-lc-rs` crypto provider features end up enabled in this binary
    // (kv-mcp's own rustls dependency asks for `ring` directly -- used by mail.rs's manual
    // ClientConfig::builder() for IMAP -- while reqwest/hyper-rustls's transitive rustls
    // dependency pulls in `aws-lc-rs` by default; Cargo's feature unification turns both on for
    // the single resolved rustls crate). With both present, rustls refuses to guess which one a
    // plain `ClientConfig::builder()` should use -- it panics (which aborts, in a release build)
    // the first time anything calls it, which is exactly what crashed kv-mcp the first time
    // credential_imap_test actually ran this code path live. Installing one explicitly here,
    // before anything else can touch TLS, removes the ambiguity process-wide for every caller
    // (ours and reqwest's).
    let _ = rustls::crypto::ring::default_provider().install_default();
    let ttl = session::parse_ttl_minutes(
        std::env::var("KEYVALET_SESSION_TTL_MINUTES")
            .ok()
            .as_deref(),
    )?;
    let config = approval::ApprovalConfig::from_env().map_err(anyhow::Error::msg)?;
    let session = Arc::new(session::HelperSession::with_config(ttl, config));
    let server = Server::new(session.clone());

    // Lock and exit immediately when the session ends (the client closes stdin or sends a signal).
    // Otherwise the sudo child process's pipe keeps this process alive, leaving the unlocked root
    // helper lingering too.
    async fn shutdown(session: Arc<session::HelperSession>) -> ! {
        session.lock().await; // End the root helper immediately (security-sensitive, don't wait)
        gateway_env::cleanup_gateway_env();
        std::process::exit(0);
    }
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        for kind in [
            SignalKind::terminate(),
            SignalKind::interrupt(),
            SignalKind::hangup(),
        ] {
            if let Ok(mut sig) = signal(kind) {
                let session = session.clone();
                tokio::spawn(async move {
                    sig.recv().await;
                    shutdown(session).await;
                });
            }
        }
    }

    #[cfg(not(windows))]
    let service = server.serve(rmcp::transport::stdio()).await?;
    #[cfg(windows)]
    let service = server.serve(worker_channel).await?;
    let waited = service.waiting().await;
    // Run cleanup to completion here: a task spawned now might never be polled before the
    // runtime shuts down, leaving exported files behind.
    if let Err(e) = waited {
        eprintln!("keyvalet-mcp: {e}");
    }
    shutdown(session).await
}
