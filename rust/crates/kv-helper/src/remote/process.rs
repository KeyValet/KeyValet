//! Trust checks run only in the real process transport.
use super::ipc::CallerContext;
use super::{Error, Result};
#[cfg(not(target_os = "linux"))]
use kv_ipc::remote::Caller;

#[cfg(unix)]
pub fn authenticate_peer(
    fd: std::os::fd::RawFd,
    owner_uid: u32,
    relay_uid: Option<u32>,
) -> Result<CallerContext> {
    #[cfg(target_os = "macos")]
    {
        let uid = kv_platform::peer::peer_uid(fd).map_err(|_| Error("untrusted_caller"))?;
        let token =
            kv_platform::peer::peer_audit_token(fd).map_err(|_| Error("untrusted_caller"))?;
        for (binary, identifier, role) in [
            ("kv-relay-client", "relay-client", Caller::RelayClient),
            ("kv-mcp", "mcp", Caller::Mcp),
            ("kv-hook", "hook", Caller::Hook),
            ("kv-cli", "cli", Caller::CliOwner),
            ("kv-touchid", "touchid", Caller::ApprovalAgent),
        ] {
            if uid != owner_uid
                && !(role == Caller::RelayClient && Some(uid) == relay_uid)
                && !(role == Caller::CliOwner && uid == 0)
            {
                continue;
            }
            let path = if role == Caller::RelayClient {
                kv_platform::paths::RELAY_BIN.to_owned()
            } else {
                format!("{}/bin/{binary}", kv_platform::paths::INSTALL_DIR)
            };
            if kv_platform::trust::untrusted_reason(std::path::Path::new(&path)).is_some() {
                continue;
            }
            let requirement = if role == Caller::RelayClient {
                kv_platform::paths::RELAY_REQUIREMENT.to_owned()
            } else {
                format!("identifier \"dev.keyvalet.{identifier}\" and anchor apple generic and certificate leaf[subject.OU] = \"{}\"", kv_platform::paths::TEAM_ID)
            };
            if kv_platform::peer::verify_peer_code(&token, &requirement, &path).is_ok() {
                let parent = if role == Caller::CliOwner {
                    token[5]
                } else {
                    parent_pid(token[5])?
                };
                return Ok(CallerContext::authenticated(role, owner_uid, parent, 86400));
            }
        }
    }
    #[cfg(target_os = "linux")]
    {
        let identity = kv_platform::peer_broker::authenticate_at(
            fd,
            std::path::Path::new(kv_platform::paths::PEER_BROKER_SOCKET),
        )
        .map_err(|_| Error("untrusted_caller"))?;
        if !kv_platform::peer_broker::permits(
            identity.role,
            identity.peer.uid,
            owner_uid,
            relay_uid,
        ) {
            return Err(Error("untrusted_caller"));
        }
        if matches!(
            identity.role,
            kv_ipc::remote::Caller::Mcp | kv_ipc::remote::Caller::CliOwner
        ) {
            linux_proofs::register(fd, identity)?;
        }
        Ok(CallerContext::authenticated(
            identity.role,
            owner_uid,
            identity.parent_pid,
            86400,
        ))
    }
    #[cfg(not(target_os = "linux"))]
    Err(Error("untrusted_caller"))
}

#[cfg(target_os = "linux")]
pub(super) fn inspect_linux_agent(pid: u32) -> Result<super::production::ProcessIdentity> {
    linux_proofs::inspect(pid)
}

#[cfg(target_os = "linux")]
mod linux_proofs {
    use super::{Error, Result};
    use crate::remote::production::ProcessIdentity;
    use kv_platform::peer_broker::Identity;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
    use std::sync::{Arc, Mutex, OnceLock};

    struct Connection {
        fd: RawFd,
        cookie: u64,
        expected: Identity,
    }

    impl Connection {
        fn new(fd: RawFd, expected: Identity) -> Result<Self> {
            Ok(Self {
                fd,
                cookie: socket_cookie(fd)?,
                expected,
            })
        }

        fn live(&self) -> bool {
            socket_cookie(self.fd).ok() == Some(self.cookie) && open(self.fd)
        }

        fn inspection_socket(&self) -> Result<OwnedFd> {
            // The daemon owns the original fd. Duplicate it only while inspecting;
            // retaining a duplicate would prevent the daemon's close from reaching its peer.
            let cloned = unsafe { libc::fcntl(self.fd, libc::F_DUPFD_CLOEXEC, 3) };
            if cloned < 0 {
                return Err(Error("agent_unavailable"));
            }
            let fd = unsafe { OwnedFd::from_raw_fd(cloned) };
            // Compare the cloned socket's kernel cookie after dup. This covers the original
            // fd closing and being reused, including a new socket from the same process.
            if socket_cookie(fd.as_raw_fd())? != self.cookie || !open(fd.as_raw_fd()) {
                return Err(Error("agent_unavailable"));
            }
            Ok(fd)
        }
    }

    fn socket_cookie(fd: RawFd) -> Result<u64> {
        let mut cookie = 0u64;
        let mut length = std::mem::size_of_val(&cookie) as libc::socklen_t;
        if unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_COOKIE,
                (&mut cookie as *mut u64).cast(),
                &mut length,
            )
        } != 0
            || length as usize != std::mem::size_of::<u64>()
            || cookie == 0
        {
            return Err(Error("agent_unavailable"));
        }
        Ok(cookie)
    }

    fn connections() -> &'static Mutex<Vec<Arc<Connection>>> {
        static CONNECTIONS: OnceLock<Mutex<Vec<Arc<Connection>>>> = OnceLock::new();
        CONNECTIONS.get_or_init(|| Mutex::new(Vec::new()))
    }

    fn open(fd: RawFd) -> bool {
        let mut byte = 0u8;
        let count = unsafe {
            libc::recv(
                fd,
                (&mut byte as *mut u8).cast(),
                1,
                libc::MSG_PEEK | libc::MSG_DONTWAIT,
            )
        };
        count > 0
            || (count < 0
                && std::io::Error::last_os_error().kind() == std::io::ErrorKind::WouldBlock)
    }

    pub(super) fn register(fd: RawFd, expected: Identity) -> Result<()> {
        let mut entries = connections()
            .lock()
            .map_err(|_| Error("agent_unavailable"))?;
        entries.retain(|entry| entry.live());
        if entries.iter().any(|entry| entry.expected == expected) {
            return Ok(());
        }
        if entries.len() >= 128 {
            return Err(Error("session_unavailable"));
        }
        entries.push(Arc::new(Connection::new(fd, expected)?));
        Ok(())
    }

    pub(super) fn inspect(pid: u32) -> Result<ProcessIdentity> {
        // Release the registry mutex before broker IO. The socket cookie binds each
        // entry to the original live fd, not a cached hash or caller-supplied PID claim.
        let entries = connections()
            .lock()
            .map_err(|_| Error("agent_unavailable"))?
            .iter()
            .filter(|entry| entry.expected.parent_pid == pid)
            .cloned()
            .collect::<Vec<_>>();
        for entry in entries.into_iter().rev() {
            let Ok(fd) = entry.inspection_socket() else {
                continue;
            };
            let proof = kv_platform::peer_broker::inspect_agent_at(
                fd.as_raw_fd(),
                std::path::Path::new(kv_platform::paths::PEER_BROKER_SOCKET),
            );
            if let Ok(proof) = proof {
                if proof.identity != entry.expected {
                    continue;
                }
                return Ok(ProcessIdentity {
                    uid: proof.agent.uid,
                    pid: proof.agent.pid,
                    start_time: proof.agent.start_time,
                    exe_sha256: proof.agent.exe_sha256,
                });
            }
        }
        Err(Error("agent_unavailable"))
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::io::Read;
        use std::os::unix::net::UnixStream;

        #[test]
        fn process_proof_does_not_keep_a_finished_helper_connection_open() {
            let (accepted, mut client) = UnixStream::pair().unwrap();
            let identity = Identity {
                peer: kv_platform::peer::peer_credentials(accepted.as_raw_fd()).unwrap(),
                role: kv_ipc::remote::Caller::Mcp,
                parent_pid: 42,
            };
            let _proof = Connection::new(accepted.as_raw_fd(), identity).unwrap();
            client
                .set_read_timeout(Some(std::time::Duration::from_millis(20)))
                .unwrap();
            drop(accepted);
            assert_eq!(client.read(&mut [0u8]).unwrap(), 0);
        }

        #[test]
        fn a_reused_fd_from_the_same_peer_cannot_inherit_the_socket_proof() {
            let (accepted, _client) = UnixStream::pair().unwrap();
            let identity = Identity {
                peer: kv_platform::peer::peer_credentials(accepted.as_raw_fd()).unwrap(),
                role: kv_ipc::remote::Caller::Mcp,
                parent_pid: 42,
            };
            let proof = Connection::new(accepted.as_raw_fd(), identity).unwrap();
            assert!(proof.live());
            let (replacement, _replacement_peer) = UnixStream::pair().unwrap();
            assert_eq!(
                kv_platform::peer::peer_credentials(replacement.as_raw_fd()).unwrap(),
                identity.peer
            );
            // Replace only this test's still-owned fd; no unrelated descriptor can be closed.
            assert_eq!(
                unsafe { libc::dup2(replacement.as_raw_fd(), accepted.as_raw_fd()) },
                accepted.as_raw_fd()
            );
            assert!(!proof.live());
            assert!(proof.inspection_socket().is_err());
        }
    }
}

#[cfg(target_os = "macos")]
fn parent_pid(pid: u32) -> Result<u32> {
    #[cfg(target_os = "linux")]
    {
        let stat = std::fs::read_to_string(format!("/proc/{pid}/stat"))
            .map_err(|_| Error("untrusted_caller"))?;
        stat.rsplit_once(')')
            .and_then(|(_, rest)| rest.split_whitespace().nth(1))
            .and_then(|pid| pid.parse().ok())
            .filter(|pid| *pid > 0)
            .ok_or(Error("untrusted_caller"))
    }
    #[cfg(target_os = "macos")]
    {
        if kv_platform::trust::untrusted_reason(std::path::Path::new("/bin/ps")).is_some() {
            return Err(Error("untrusted_caller"));
        }
        let output = std::process::Command::new("/bin/ps")
            .env_clear()
            .args(["-p", &pid.to_string(), "-o", "ppid="])
            .output()
            .map_err(|_| Error("untrusted_caller"))?;
        if !output.status.success() {
            return Err(Error("untrusted_caller"));
        }
        String::from_utf8(output.stdout)
            .ok()
            .and_then(|pid| pid.trim().parse().ok())
            .filter(|pid| *pid > 0)
            .ok_or(Error("untrusted_caller"))
    }
}

#[cfg(windows)]
pub fn authenticate_windows_relay_peer(
    peer: &kv_platform::peer::PeerIdentity,
    relay_sid: &[u8],
) -> Result<CallerContext> {
    use kv_platform::trust::{same_file_path, trusted_path};
    if !kv_platform::peer::sid_equal(&peer.sid, relay_sid)
        || !same_file_path(
            &peer.exe_path,
            std::path::Path::new(kv_platform::paths::RELAY_BIN),
        )
        || !trusted_path(&peer.exe_path)
    {
        return Err(Error("untrusted_caller"));
    }
    Ok(CallerContext::authenticated(
        Caller::RelayClient,
        0,
        0,
        86400,
    ))
}

#[cfg(windows)]
pub fn authenticate_windows_peer(
    peer: &kv_platform::peer::PeerIdentity,
    owner_sid: &[u8],
) -> Result<CallerContext> {
    use kv_platform::trust::{same_file_path, trusted_path};
    use std::path::Path;
    if !kv_platform::peer::sid_equal(&peer.sid, owner_sid) || !trusted_path(&peer.exe_path) {
        return Err(Error("untrusted_caller"));
    }
    for (binary, role) in [
        ("kv-mcp.exe", Caller::Mcp),
        ("kv-hook.exe", Caller::Hook),
        ("kv-cli.exe", Caller::CliOwner),
        ("kv-agent.exe", Caller::ApprovalAgent),
    ] {
        let path = Path::new(kv_platform::paths::INSTALL_DIR)
            .join("bin")
            .join(binary);
        if same_file_path(&peer.exe_path, &path) {
            let parent = if role == Caller::Mcp {
                mcp_workers()
                    .lock()
                    .map_err(|_| Error("untrusted_caller"))?
                    .get(&peer.pid)
                    .copied()
            } else {
                None
            };
            return Ok(CallerContext::authenticated(
                role,
                0,
                if role == Caller::CliOwner {
                    peer.pid
                } else {
                    parent.map_or_else(|| windows_parent_pid(peer.pid), Ok)?
                },
                86400,
            ));
        }
    }
    Err(Error("untrusted_caller"))
}

#[cfg(windows)]
fn mcp_workers() -> &'static std::sync::Mutex<std::collections::HashMap<u32, u32>> {
    static WORKERS: std::sync::OnceLock<std::sync::Mutex<std::collections::HashMap<u32, u32>>> =
        std::sync::OnceLock::new();
    WORKERS.get_or_init(Default::default)
}

/// Held alongside the service-owned process handle, so a recycled PID cannot inherit a binding.
#[cfg(windows)]
pub struct McpWorkerBinding(u32);

#[cfg(windows)]
impl Drop for McpWorkerBinding {
    fn drop(&mut self) {
        if let Ok(mut workers) = mcp_workers().lock() {
            workers.remove(&self.0);
        }
    }
}

/// Bind a verified service-created worker to the authenticated launcher's actual parent.
/// Neither PID is accepted from IPC JSON. Call before sending the worker's ready response.
#[cfg(windows)]
pub fn bind_windows_mcp_worker(worker_pid: u32, launcher_pid: u32) -> Result<McpWorkerBinding> {
    let parent = windows_parent_pid(launcher_pid)?;
    let mut workers = mcp_workers()
        .lock()
        .map_err(|_| Error("untrusted_caller"))?;
    if worker_pid == 0 || workers.contains_key(&worker_pid) {
        return Err(Error("untrusted_caller"));
    }
    workers.insert(worker_pid, parent);
    Ok(McpWorkerBinding(worker_pid))
}

#[cfg(windows)]
fn windows_parent_pid(pid: u32) -> Result<u32> {
    kv_platform::peer::parent_pid(pid).map_err(|_| Error("untrusted_caller"))
}
