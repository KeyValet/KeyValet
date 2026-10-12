//! Stop adapters share only their pending query and counting logic, not their output schema.

use serde_json::{json, Value};
use std::io;

pub const MAX_BLOCKS: u64 = 3;

pub fn is_stop_mode(mode: &str) -> bool {
    matches!(
        mode,
        "stop"
            | "claude-stop"
            | "devin-stop"
            | "codex-stop"
            | "cursor-stop"
            | "gemini-after-agent"
            | "gemini-stop"
    )
}

pub struct StopOutput {
    pub value: Value,
    /// A session without pending approvals stays completely silent.
    pub had_pending: bool,
}

pub fn handle_stop(
    mode: &str,
    input: &Value,
    agent_pid: u32,
    now: i64,
    mut request: impl FnMut(&str, Value) -> io::Result<Value>,
) -> StopOutput {
    let allow = |had_pending| StopOutput {
        value: json!({}),
        had_pending,
    };
    if !is_stop_mode(mode) {
        return allow(false);
    }
    let active = input
        .get("stop_hook_active")
        .or_else(|| input.get("stopHookActive"));
    let loops = input.get("loop_count").or_else(|| input.get("loopCount"));
    if active.and_then(Value::as_bool) == Some(true)
        || loops.and_then(Value::as_u64).unwrap_or(0) >= MAX_BLOCKS
    {
        return allow(false);
    }
    let Ok(result) = request("remote.pending.for_agent", json!({"agent_pid": agent_pid})) else {
        return allow(false);
    };
    let Some(pending) = result["pending"].as_array() else {
        return allow(false);
    };
    if pending.is_empty() {
        return allow(false);
    }
    let mut ids = Vec::new();
    for item in pending {
        let Some(id) = item["approval_id"].as_str() else {
            continue;
        };
        if !valid_id(id)
            || item["expires_at"].as_i64().unwrap_or(0) <= now
            || item["stop_hook_blocks"].as_u64().unwrap_or(MAX_BLOCKS) >= MAX_BLOCKS
            || ids.iter().any(|known| known == id)
        {
            continue;
        }
        if request("remote.pending.stop_block", json!({"approval_id": id}))
            .ok()
            .is_some_and(|v| v["allowed"] == true)
        {
            ids.push(id.to_owned());
        }
    }
    if ids.is_empty() {
        return allow(true);
    }
    let calls = ids
        .iter()
        .map(|id| format!("credential_wait_approval({})", json!(id)))
        .collect::<Vec<_>>()
        .join("; ");
    let reason = format!("Do not stop yet: KeyValet approval is pending, not denied. Call {calls} (one approval at a time) to get the original request's result after approval. Do not repeat the original request or ask the user for a key.");
    let value = match mode {
        "cursor-stop" => json!({"followup_message": reason}),
        "gemini-after-agent" | "gemini-stop" => json!({"decision": "deny", "reason": reason}),
        _ => json!({"decision": "block", "reason": reason}),
    };
    StopOutput {
        value,
        had_pending: true,
    }
}

fn valid_id(id: &str) -> bool {
    id.len() == 26
        && id.as_bytes()[0] <= b'7'
        && id
            .bytes()
            .all(|c| b"0123456789ABCDEFGHJKMNPQRSTVWXYZ".contains(&c))
}

/// Single-flight Appendix C framing also accepts the helper's optional correlation ID.
#[cfg(any(unix, windows, test))]
struct RemoteClient<S> {
    stream: std::io::BufReader<S>,
    next_id: u64,
}

#[cfg(any(unix, windows, test))]
impl<S: io::Read + io::Write> RemoteClient<S> {
    fn new(stream: S) -> Self {
        Self {
            stream: std::io::BufReader::new(stream),
            next_id: 0,
        }
    }

    fn request(&mut self, op: &str, params: Value) -> io::Result<Value> {
        use io::{BufRead, Read};
        self.next_id += 1;
        writeln!(
            self.stream.get_mut(),
            "{}",
            json!({"id": self.next_id, "op": op, "params": params})
        )?;
        let mut frame = String::new();
        (&mut self.stream).take(64 * 1024).read_line(&mut frame)?;
        if !frame.ends_with('\n') {
            return Err(io::Error::other("Incomplete helper response"));
        }
        let mut response: Value = serde_json::from_str(&frame).map_err(io::Error::other)?;
        if response.get("id").is_some_and(|id| id != self.next_id) || response["ok"] != true {
            return Err(io::Error::other("Invalid helper response"));
        }
        response
            .as_object_mut()
            .and_then(|v| v.remove("result"))
            .ok_or_else(|| io::Error::other("Missing helper result"))
    }
}

/// The transport is read-only except for the helper's atomic per-approval stop counter.
/// Its trust check stays here; tests drive the same logic and framing with fake runners.
#[cfg(unix)]
pub fn run_stop(mode: &str, input: &Value) -> StopOutput {
    use std::os::unix::fs::{FileTypeExt, MetadataExt};
    use std::os::unix::net::UnixStream;
    use std::time::Duration;

    #[cfg(target_os = "macos")]
    const SOCKET: &str = "/var/run/keyvalet/helper.sock";
    #[cfg(not(target_os = "macos"))]
    const SOCKET: &str = "/run/keyvalet/helper.sock";
    let mut stream: Option<RemoteClient<UnixStream>> = None;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;
    handle_stop(
        mode,
        input,
        std::os::unix::process::parent_id(),
        now,
        |op, params| {
            if stream.is_none() {
                let metadata = std::fs::symlink_metadata(SOCKET)?;
                // The real daemon deliberately uses mode 0666; its kernel peer is the authority.
                if !metadata.file_type().is_socket() {
                    return Err(io::Error::other("Untrusted helper socket"));
                }
                let socket = UnixStream::connect(SOCKET)?;
                socket.set_read_timeout(Some(Duration::from_secs(2)))?;
                socket.set_write_timeout(Some(Duration::from_secs(2)))?;
                verify_peer(&socket, metadata.uid())?;
                stream = Some(RemoteClient::new(socket));
            }
            stream.as_mut().unwrap().request(op, params)
        },
    )
}

#[cfg(target_os = "macos")]
fn verify_peer(socket: &std::os::unix::net::UnixStream, owner: u32) -> io::Result<()> {
    use std::os::fd::AsRawFd;
    unsafe extern "C" {
        fn getpeereid(fd: i32, uid: *mut u32, gid: *mut u32) -> i32;
    }
    let (mut uid, mut gid) = (u32::MAX, u32::MAX);
    // SAFETY: getpeereid writes two uid_t values; the socket remains alive throughout the call.
    if owner != 0 || unsafe { getpeereid(socket.as_raw_fd(), &mut uid, &mut gid) } != 0 || uid != 0
    {
        return Err(io::Error::other("Helper peer is not root"));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn verify_peer(socket: &std::os::unix::net::UnixStream, owner: u32) -> io::Result<()> {
    use std::os::fd::AsRawFd;
    #[repr(C)]
    struct Credentials {
        pid: i32,
        uid: u32,
        gid: u32,
    }
    unsafe extern "C" {
        fn getsockopt(
            fd: i32,
            level: i32,
            name: i32,
            value: *mut std::ffi::c_void,
            len: *mut u32,
        ) -> i32;
    }
    let uid = std::fs::read_to_string("/etc/passwd")?
        .lines()
        .find_map(|line| {
            let mut fields = line.split(':');
            (fields.next()? == "keyvalet")
                .then(|| fields.nth(1)?.parse::<u32>().ok())
                .flatten()
        })
        .ok_or_else(|| io::Error::other("KeyValet service account is missing"))?;
    let mut credentials = Credentials {
        pid: 0,
        uid: u32::MAX,
        gid: u32::MAX,
    };
    let mut size = std::mem::size_of::<Credentials>() as u32;
    // SAFETY: SO_PEERCRED writes a Linux ucred into a correctly sized buffer.
    let result = unsafe {
        getsockopt(
            socket.as_raw_fd(),
            1,
            17,
            (&mut credentials as *mut Credentials).cast(),
            &mut size,
        )
    };
    if result != 0 || credentials.uid != uid || owner != uid {
        return Err(io::Error::other("Untrusted KeyValet service peer"));
    }
    Ok(())
}

#[cfg(windows)]
pub fn run_stop(mode: &str, input: &Value) -> StopOutput {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;
    let parent = kv_platform::peer::parent_pid(std::process::id());
    let mut stream: Option<RemoteClient<native_windows::Pipe>> = None;
    handle_stop(
        mode,
        input,
        parent.as_ref().copied().unwrap_or(0),
        now,
        |op, params| {
            if parent.is_err() {
                return Err(io::Error::other("Agent parent unavailable"));
            }
            if stream.is_none() {
                stream = Some(RemoteClient::new(native_windows::Pipe::connect()?));
            }
            stream.as_mut().unwrap().request(op, params)
        },
    )
}

#[cfg(windows)]
mod native_windows {
    use std::{io, time::Duration};
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::windows::named_pipe::NamedPipeClient,
    };

    pub(super) struct Pipe {
        runtime: Option<tokio::runtime::Runtime>,
        socket: NamedPipeClient,
    }

    impl Pipe {
        pub(super) fn connect() -> io::Result<Self> {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()?;
            let socket = runtime.block_on(kv_platform::pipe::connect_service(
                kv_platform::paths::HELPER_PIPE,
            ));
            match socket {
                Ok(socket) => Ok(Self {
                    runtime: Some(runtime),
                    socket,
                }),
                Err(error) => {
                    runtime.shutdown_timeout(Duration::from_millis(10));
                    Err(error)
                }
            }
        }
    }

    impl io::Read for Pipe {
        fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
            self.runtime.as_ref().unwrap().block_on(async {
                tokio::time::timeout(Duration::from_secs(2), self.socket.read(bytes))
                    .await
                    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "Helper read timed out"))?
            })
        }
    }

    impl io::Write for Pipe {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.runtime.as_ref().unwrap().block_on(async {
                tokio::time::timeout(Duration::from_secs(2), self.socket.write(bytes))
                    .await
                    .map_err(|_| {
                        io::Error::new(io::ErrorKind::TimedOut, "Helper write timed out")
                    })?
            })
        }
        fn flush(&mut self) -> io::Result<()> {
            self.runtime.as_ref().unwrap().block_on(async {
                tokio::time::timeout(Duration::from_secs(2), self.socket.flush())
                    .await
                    .map_err(|_| {
                        io::Error::new(io::ErrorKind::TimedOut, "Helper flush timed out")
                    })?
            })
        }
    }

    impl Drop for Pipe {
        fn drop(&mut self) {
            if let Some(runtime) = self.runtime.take() {
                runtime.shutdown_timeout(Duration::from_millis(10));
            }
        }
    }
}

#[cfg(not(any(unix, windows)))]
pub fn run_stop(_mode: &str, _input: &Value) -> StopOutput {
    StopOutput {
        value: json!({}),
        had_pending: false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    struct Wire {
        input: io::Cursor<Vec<u8>>,
        output: Vec<u8>,
        fail_write: bool,
    }
    impl io::Read for Wire {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            self.input.read(buf)
        }
    }
    impl io::Write for Wire {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            if self.fail_write {
                return Err(io::Error::other("closed"));
            }
            self.output.extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    #[test]
    fn framing_accepts_native_and_correlated_replies_and_bounds_invalid_frames() {
        for frame in [
            "{\"ok\":true,\"result\":{}}\n",
            "{\"id\":1,\"ok\":true,\"result\":{}}\n",
        ] {
            let mut client = RemoteClient::new(Wire {
                input: io::Cursor::new(frame.as_bytes().to_vec()),
                output: vec![],
                fail_write: false,
            });
            assert_eq!(
                client
                    .request("remote.pending.for_agent", json!({"agent_pid": 42}))
                    .unwrap(),
                json!({})
            );
            let sent: Value = serde_json::from_slice(&client.stream.get_ref().output).unwrap();
            assert_eq!(
                sent,
                json!({"id": 1, "op": "remote.pending.for_agent", "params": {"agent_pid": 42}})
            );
        }
        for frame in [
            "{\"ok\":true}\n".into(),
            "{\"id\":2,\"ok\":true,\"result\":{}}\n".into(),
            "{\"ok\":false}\n".into(),
            "not JSON\n".into(),
            "{}".into(),
            "x".repeat(65 * 1024),
        ] {
            let mut client = RemoteClient::new(Wire {
                input: io::Cursor::new(frame.into_bytes()),
                output: vec![],
                fail_write: false,
            });
            assert!(client
                .request("remote.pending.for_agent", json!({}))
                .is_err());
        }
        let mut client = RemoteClient::new(Wire {
            input: io::Cursor::new(vec![]),
            output: vec![],
            fail_write: true,
        });
        assert!(client
            .request("remote.pending.for_agent", json!({}))
            .is_err());
    }
}
