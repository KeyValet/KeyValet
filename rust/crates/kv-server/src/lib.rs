//! An opaque, single-instance remote approval relay and an in-process integration harness.

mod account;
mod auth;
mod cleanup;
mod error;
mod http;
mod messages;
mod pairing;
mod presence;
mod push;
mod state;

pub use account::AccountConfig;
pub use cleanup::CleanupStats;
pub use push::PushStats;
pub use state::{HEARTBEAT, IDLE_TIMEOUT};
pub use url::Url;

use axum::Extension;
use rusqlite::Connection;
use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::sync::watch;
use tokio::task::JoinHandle;

/// Owns the test relay. Dropping it requests shutdown of HTTP, sockets and cleanup.
pub struct Handle {
    state: Arc<state::State>,
    push: Option<Arc<push::Transport>>,
    shutdown: watch::Sender<bool>,
    tasks: Vec<JoinHandle<()>>,
}

impl Handle {
    /// Pumps the durable push queue into a caller-owned loopback test dispatcher.
    pub async fn flush_push(&self) -> io::Result<PushStats> {
        match &self.push {
            Some(push) => push
                .drain(&self.state)
                .await
                .map_err(|_| io::Error::other("push queue failed")),
            None => Ok(PushStats::default()),
        }
    }
    /// Freeze wall-clock expiry for deterministic boundary tests; Tokio transport time stays live.
    pub fn freeze_time(&self) -> i64 {
        self.state.freeze_test_clock()
    }
    pub async fn shutdown(mut self) {
        let _ = self.shutdown.send(true);
        for task in self.tasks.drain(..) {
            let _ = task.await;
        }
    }

    /// Advances application expiry for deterministic tests, without sleeping for days.
    pub fn advance_time(&self, duration: Duration) {
        self.state
            .advance(duration.as_secs().min(i64::MAX as u64) as i64);
    }

    /// Runs the same cleanup operation used by the background worker.
    pub fn cleanup(&self) -> CleanupStats {
        cleanup::cleanup(&self.state).expect("test relay cleanup failed")
    }

    /// Captured metadata-only log lines. Production logging never accumulates in memory.
    pub fn logs(&self) -> Vec<String> {
        self.state.log.lock().unwrap().clone()
    }

    /// Runs a read-only inspection against the harness database.
    pub fn inspect<T>(&self, f: impl FnOnce(&Connection) -> T) -> T {
        let data = self.state.data.lock().unwrap();
        f(&data.db)
    }
}

impl Drop for Handle {
    fn drop(&mut self) {
        let _ = self.shutdown.send(true);
    }
}

/// Starts an in-memory relay on a random loopback port inside an existing Tokio runtime.
///
/// ```no_run
/// #[tokio::main]
/// async fn main() {
///     let (url, relay) = kv_server::spawn_test_relay();
///     assert!(url.as_str().starts_with("http://127.0.0.1:"));
///     relay.shutdown().await;
/// }
/// ```
pub fn spawn_test_relay() -> (Url, Handle) {
    spawn_test(Connection::open_in_memory().expect("open test database"))
}

/// In-process OAuth harness using caller-owned issuer keys and no provider credentials.
pub fn spawn_test_relay_with_accounts(
    config: AccountConfig,
    keys: Vec<(String, Vec<kv_core::remote::PublicJwk>)>,
) -> (Url, Handle) {
    let listener = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind test relay");
    listener
        .set_nonblocking(true)
        .expect("nonblocking listener");
    let address = listener.local_addr().unwrap();
    let listener = TcpListener::from_std(listener).expect("test relay requires Tokio");
    let state =
        state::State::new_with_accounts(Connection::open_in_memory().unwrap(), true, config)
            .expect("test accounts");
    state.accounts.seed_test_keys(keys, state.now());
    (
        Url::parse(&format!("http://{address}/")).unwrap(),
        start(listener, state, None),
    )
}

/// A disk-backed variant for persistence and ciphertext-only storage tests.
pub fn spawn_test_relay_with_data(path: impl AsRef<Path>) -> (Url, Handle) {
    spawn_test(Connection::open(path).expect("open test database"))
}

fn spawn_test(db: Connection) -> (Url, Handle) {
    spawn_test_with_push(db, None)
}

/// Starts an in-memory relay with a loopback metadata dispatcher. Tests explicitly call
/// `Handle::flush_push`; production pumps the same queue every second.
pub fn spawn_test_relay_with_push(dispatcher: Url, bearer: String) -> (Url, Handle) {
    let push = push::Transport::new(dispatcher, bearer).expect("valid test push dispatcher");
    spawn_test_with_push(
        Connection::open_in_memory().expect("open test database"),
        Some(push),
    )
}

fn spawn_test_with_push(db: Connection, push: Option<Arc<push::Transport>>) -> (Url, Handle) {
    let listener = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind test relay");
    listener
        .set_nonblocking(true)
        .expect("nonblocking listener");
    let address = listener.local_addr().unwrap();
    let listener = TcpListener::from_std(listener).expect("test relay requires a Tokio runtime");
    let state = state::State::new(db, true).expect("initialize test relay");
    let handle = start(listener, state, push);
    (Url::parse(&format!("http://{address}/")).unwrap(), handle)
}

fn start(
    listener: TcpListener,
    state: Arc<state::State>,
    push: Option<Arc<push::Transport>>,
) -> Handle {
    let (shutdown, receiver) = watch::channel(false);
    let router = http::router(state.clone()).layer(Extension(presence::Shutdown(receiver.clone())));
    let mut http_shutdown = receiver.clone();
    let server = tokio::spawn(async move {
        // Axum retries listener errors internally and completes successfully on shutdown.
        let _ = axum::serve(
            listener,
            router.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .with_graceful_shutdown(async move {
            let _ = http_shutdown.changed().await;
        })
        .await;
    });
    let cleanup_state = state.clone();
    let mut push_shutdown = receiver.clone();
    let worker = tokio::spawn(async move {
        let mut shutdown = receiver;
        let mut interval = tokio::time::interval(Duration::from_secs(30));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                _ = shutdown.changed() => break,
                _ = interval.tick() => match cleanup::cleanup(&cleanup_state) {
                    Ok(stats) => cleanup_state.event("cleanup", stats.messages + stats.approvals),
                    Err(_) => cleanup_state.event("cleanup_failed", 1),
                }
            }
        }
    });
    let mut tasks = vec![server, worker];
    if !state.capture_logs {
        if let Some(transport) = push.clone() {
            let push_state = state.clone();
            tasks.push(tokio::spawn(async move {
                let mut interval = tokio::time::interval(Duration::from_secs(1));
                interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
                loop {
                    tokio::select! {
                        _ = push_shutdown.changed() => break,
                        _ = interval.tick() => if transport.drain(&push_state).await.is_err() {
                            push_state.event("push_queue_failed",1);
                        }
                    }
                }
            }));
        }
    }
    Handle {
        state,
        push,
        shutdown,
        tasks,
    }
}

/// Starts the production relay. The caller supplies its shutdown policy.
pub async fn run(
    listen: SocketAddr,
    data: impl AsRef<Path>,
    shutdown: impl std::future::Future<Output = ()>,
) -> io::Result<()> {
    if listen.ip() != std::net::IpAddr::V4(Ipv4Addr::LOCALHOST) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "relay must listen on 127.0.0.1",
        ));
    }
    let db = prepare_storage(data.as_ref(), private_permissions)?;
    let state = state::State::new_with_accounts(db, false, AccountConfig::from_env())
        .map_err(|_| io::Error::other("cannot initialize relay database"))?;
    let listener = TcpListener::bind(listen).await?;
    let handle = start(listener, state, push::Transport::from_env()?);
    eprintln!("event=relay_started count=1");
    shutdown.await;
    handle.shutdown().await;
    Ok(())
}

fn private_permissions(path: &Path, mode: u32) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
    }
    #[cfg(not(unix))]
    {
        let _ = (path, mode);
        Ok(())
    }
}

fn prepare_storage(
    data: &Path,
    permissions: fn(&Path, u32) -> io::Result<()>,
) -> io::Result<Connection> {
    std::fs::create_dir_all(data)?;
    permissions(data, 0o700)?;
    let db_path = data.join("relay.sqlite3");
    let db =
        Connection::open(&db_path).map_err(|_| io::Error::other("cannot open relay database"))?;
    permissions(&db_path, 0o600)?;
    Ok(db)
}

#[cfg(test)]
mod tests;
