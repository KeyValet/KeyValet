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
    use kv_platform::trust::{same_file_path, trusted_path, verify_publisher};
    if !kv_platform::peer::sid_equal(&peer.sid, relay_sid)
        || !same_file_path(
            &peer.exe_path,
            std::path::Path::new(kv_platform::paths::RELAY_BIN),
        )
        || !trusted_path(&peer.exe_path)
        || verify_publisher(&peer.exe_path, kv_platform::paths::AGENT_PUBLISHER).is_err()
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
    use kv_platform::trust::{
        allow_unsigned_agent, same_file_path, trusted_path, verify_publisher,
    };
    use std::path::Path;
    let unsigned = allow_unsigned_agent(Path::new(kv_platform::paths::ALLOW_UNSIGNED_AGENT));
    if !kv_platform::peer::sid_equal(&peer.sid, owner_sid)
        || !trusted_path(&peer.exe_path)
        || (!unsigned
            && verify_publisher(&peer.exe_path, kv_platform::paths::AGENT_PUBLISHER).is_err())
    {
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
