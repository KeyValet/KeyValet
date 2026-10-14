//! Linux peer inspection delegated to a root broker. Only a connected socket is accepted as
//! evidence: paths, PIDs, UIDs and roles supplied by a client are never authoritative.
use crate::peer::{peer_credentials, PeerCredentials};
use kv_ipc::remote::Caller;
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::fs::MetadataExt;
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::Duration;

const REQUEST: &[u8; 5] = b"KVPA\x01";
const PROCESS_REQUEST: &[u8; 5] = b"KVPA\x02";
const LIMIT: usize = 512;
const TIMEOUT: Duration = Duration::from_secs(2);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Identity {
    pub peer: PeerCredentials,
    pub role: Caller,
    pub parent_pid: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentProcess {
    pub uid: u32,
    pub pid: u32,
    pub start_time: u64,
    pub exe_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessProof {
    pub identity: Identity,
    pub agent: AgentProcess,
}

pub struct Policy {
    pub helper_uid: u32,
    pub owner_uid: u32,
    pub relay_uid: Option<u32>,
    pub install: PathBuf,
}

fn denied() -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, "untrusted caller")
}

pub fn permits(role: Caller, uid: u32, owner: u32, relay: Option<u32>) -> bool {
    if role == Caller::RelayClient {
        Some(uid) == relay
    } else {
        uid == owner || (role == Caller::CliOwner && uid == 0)
    }
}

/// Keep a pidfd open while checking both process lifetime and the executable's inode. This
/// rejects PID reuse, exit during inspection, deleted/replaced executables and writable code.
fn inspect(peer: PeerCredentials, install: &Path) -> io::Result<(String, u32)> {
    let start = crate::peer::process_start_time(peer.pid)?;
    let proc_path = format!("/proc/{}/exe", peer.pid);
    let path = std::fs::read_link(&proc_path)?;
    if path.parent() != Some(install) || crate::trust::untrusted_reason(&path).is_some() {
        return Err(denied());
    }
    let executable = std::fs::File::open(proc_path)?;
    let actual = executable.metadata()?;
    let expected = std::fs::metadata(&path)?;
    if actual.dev() != expected.dev() || actual.ino() != expected.ino() {
        return Err(denied());
    }
    let stat = std::fs::read_to_string(format!("/proc/{}/stat", peer.pid))?;
    let parent = stat
        .rsplit_once(')')
        .and_then(|(_, rest)| rest.split_whitespace().nth(1))
        .and_then(|value| value.parse::<u32>().ok())
        .filter(|pid| *pid != 0)
        .ok_or_else(denied)?;
    if crate::peer::process_start_time(peer.pid)? != start
        || std::fs::read_link(format!("/proc/{}/exe", peer.pid))? != path
        || std::fs::metadata(format!("/proc/{}/exe", peer.pid))?.ino() != actual.ino()
    {
        return Err(denied());
    }
    Ok((
        path.file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(denied)?
            .into(),
        parent,
    ))
}

/// Linux 6.5+ returns a pidfd for the process captured by SO_PEERCRED, including when that
/// process has exited. pidfd_open(peer.pid) would allow a recycled PID to authenticate an old
/// connection, so older kernels fail closed rather than falling back to a pathname claim.
fn peer_pidfd(fd: RawFd) -> io::Result<OwnedFd> {
    const SO_PEERPIDFD: libc::c_int = 77;
    let mut pidfd: RawFd = -1;
    let mut length = std::mem::size_of::<RawFd>() as libc::socklen_t;
    if unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            SO_PEERPIDFD,
            (&mut pidfd as *mut RawFd).cast(),
            &mut length,
        )
    } != 0
    {
        return Err(io::Error::last_os_error());
    }
    if pidfd < 0 || length as usize != std::mem::size_of::<RawFd>() {
        return Err(denied());
    }
    Ok(unsafe { OwnedFd::from_raw_fd(pidfd) })
}
fn alive(pidfd: &OwnedFd) -> io::Result<()> {
    let mut poll = libc::pollfd {
        fd: pidfd.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    if unsafe { libc::poll(&mut poll, 1, 0) } != 0 {
        return Err(denied());
    }
    Ok(())
}

fn identify(
    fd: RawFd,
    policy: &Policy,
    inspect: impl FnOnce(PeerCredentials, &Path) -> io::Result<(String, u32)>,
) -> io::Result<Identity> {
    let pidfd = peer_pidfd(fd)?;
    alive(&pidfd)?;
    let peer = peer_credentials(fd)?;
    if peer.uid != policy.owner_uid && Some(peer.uid) != policy.relay_uid && peer.uid != 0 {
        return Err(denied());
    }
    let (binary, parent_pid) = inspect(peer, &policy.install)?;
    alive(&pidfd)?;
    let role = match binary.as_str() {
        "kv-relay-client" => Caller::RelayClient,
        "kv-cli" => Caller::CliOwner,
        "kv-mcp" => Caller::Mcp,
        "kv-hook" => Caller::Hook,
        "kv-agent" => Caller::ApprovalAgent,
        _ => return Err(denied()),
    };
    if !permits(role, peer.uid, policy.owner_uid, policy.relay_uid) || parent_pid == 0 {
        return Err(denied());
    }
    Ok(Identity {
        peer,
        role,
        parent_pid: if role == Caller::CliOwner {
            peer.pid
        } else {
            parent_pid
        },
    })
}

fn send_fd(stream: &UnixStream, fd: RawFd) -> io::Result<()> {
    send_request(stream, fd, REQUEST)
}

fn send_request(stream: &UnixStream, fd: RawFd, request: &[u8; 5]) -> io::Result<()> {
    let mut bytes = *request;
    let mut iov = libc::iovec {
        iov_base: bytes.as_mut_ptr().cast(),
        iov_len: bytes.len(),
    };
    // The usize buffer provides the alignment required by cmsghdr.
    let mut control = [0usize; 8];
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control.as_mut_ptr().cast();
    msg.msg_controllen = unsafe { libc::CMSG_SPACE(std::mem::size_of::<RawFd>() as u32) } as usize;
    unsafe {
        let header = libc::CMSG_FIRSTHDR(&msg);
        (*header).cmsg_level = libc::SOL_SOCKET;
        (*header).cmsg_type = libc::SCM_RIGHTS;
        (*header).cmsg_len = libc::CMSG_LEN(std::mem::size_of::<RawFd>() as u32) as usize;
        std::ptr::write_unaligned(libc::CMSG_DATA(header).cast::<RawFd>(), fd);
    }
    if unsafe { libc::sendmsg(stream.as_raw_fd(), &msg, libc::MSG_NOSIGNAL) }
        != REQUEST.len() as isize
    {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(test)]
fn receive_fd(stream: &mut UnixStream) -> io::Result<OwnedFd> {
    let (fd, request) = receive_request(stream)?;
    if request != *REQUEST {
        return Err(denied());
    }
    Ok(fd)
}

fn receive_request(stream: &mut UnixStream) -> io::Result<(OwnedFd, [u8; 5])> {
    let mut bytes = [0u8; REQUEST.len()];
    let mut iov = libc::iovec {
        iov_base: bytes.as_mut_ptr().cast(),
        iov_len: bytes.len(),
    };
    let mut control = [0usize; 16];
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control.as_mut_ptr().cast();
    msg.msg_controllen = std::mem::size_of_val(&control);
    let count = unsafe { libc::recvmsg(stream.as_raw_fd(), &mut msg, libc::MSG_CMSG_CLOEXEC) };
    if count <= 0 {
        return Err(denied());
    }
    let mut descriptors = Vec::new();
    let mut malformed = msg.msg_flags & (libc::MSG_CTRUNC | libc::MSG_TRUNC) != 0;
    unsafe {
        let mut header = libc::CMSG_FIRSTHDR(&msg);
        while !header.is_null() {
            let length = (*header)
                .cmsg_len
                .saturating_sub(libc::CMSG_LEN(0) as usize);
            if (*header).cmsg_level == libc::SOL_SOCKET && (*header).cmsg_type == libc::SCM_RIGHTS {
                malformed |= !length.is_multiple_of(std::mem::size_of::<RawFd>());
                for index in 0..length / std::mem::size_of::<RawFd>() {
                    let offset = index * std::mem::size_of::<RawFd>();
                    let fd = std::ptr::read_unaligned(
                        libc::CMSG_DATA(header).add(offset).cast::<RawFd>(),
                    );
                    descriptors.push(OwnedFd::from_raw_fd(fd));
                }
            } else {
                malformed = true;
            }
            header = libc::CMSG_NXTHDR(&msg, header);
        }
    }
    stream.read_exact(&mut bytes[count as usize..])?;
    if malformed || (bytes != *REQUEST && bytes != *PROCESS_REQUEST) || descriptors.len() != 1 {
        return Err(denied());
    }
    Ok((descriptors.pop().expect("one descriptor"), bytes))
}

fn configure(stream: &UnixStream) -> io::Result<()> {
    stream.set_read_timeout(Some(TIMEOUT))?;
    stream.set_write_timeout(Some(TIMEOUT))
}

/// The broker's root SO_PEERCRED is mandatory even if its socket path is replaced. The reply
/// must match the credentials of the socket we passed, not an independently chosen process.
pub fn authenticate_at(fd: RawFd, path: &Path) -> io::Result<Identity> {
    let (identity, _) = exchange(fd, path, false)?;
    Ok(identity)
}

/// Inspect only the live parent of the caller proved by this connected socket.
/// The request carries no PID/path/hash. Every use revalidates the kernel peer and role.
pub fn inspect_agent_at(fd: RawFd, path: &Path) -> io::Result<ProcessProof> {
    let (identity, value) = exchange(fd, path, true)?;
    let value = &value["agent"];
    let number = |key: &str| -> io::Result<u32> {
        value[key]
            .as_u64()
            .and_then(|value| u32::try_from(value).ok())
            .ok_or_else(denied)
    };
    let agent = AgentProcess {
        uid: number("uid")?,
        pid: number("pid")?,
        start_time: value["start_time"].as_u64().ok_or_else(denied)?,
        exe_sha256: value["exe_sha256"].as_str().ok_or_else(denied)?.into(),
    };
    validate_agent(identity, &agent)?;
    Ok(ProcessProof { identity, agent })
}

fn exchange(fd: RawFd, path: &Path, process: bool) -> io::Result<(Identity, serde_json::Value)> {
    let peer = peer_credentials(fd)?;
    let mut broker = UnixStream::connect(path)?;
    configure(&broker)?;
    if peer_credentials(broker.as_raw_fd())?.uid != 0 {
        return Err(denied());
    }
    if process {
        send_request(&broker, fd, PROCESS_REQUEST)?;
    } else {
        send_fd(&broker, fd)?;
    }
    let mut length = [0; 4];
    broker.read_exact(&mut length)?;
    let length = u32::from_be_bytes(length) as usize;
    if length == 0 || length > LIMIT {
        return Err(denied());
    }
    let mut bytes = vec![0; length];
    broker.read_exact(&mut bytes)?;
    let value: serde_json::Value = serde_json::from_slice(&bytes).map_err(|_| denied())?;
    let role = match value["role"].as_str() {
        Some("relay_client") => Caller::RelayClient,
        Some("cli_owner") => Caller::CliOwner,
        Some("mcp") => Caller::Mcp,
        Some("hook") => Caller::Hook,
        Some("approval_agent") => Caller::ApprovalAgent,
        _ => return Err(denied()),
    };
    if value["pid"] != peer.pid || value["uid"] != peer.uid || value["gid"] != peer.gid {
        return Err(denied());
    }
    let parent_pid = value["parent_pid"]
        .as_u64()
        .and_then(|pid| u32::try_from(pid).ok())
        .filter(|pid| *pid != 0)
        .ok_or_else(denied)?;
    let identity = Identity {
        peer,
        role,
        parent_pid,
    };
    Ok((identity, value))
}

fn validate_agent(identity: Identity, agent: &AgentProcess) -> io::Result<()> {
    if !matches!(identity.role, Caller::Mcp | Caller::CliOwner)
        || agent.pid != identity.parent_pid
        || agent.uid != identity.peer.uid
        || agent.pid == 0
        || agent.start_time == 0
        || agent.exe_sha256.len() != 64
        || !agent
            .exe_sha256
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(denied());
    }
    Ok(())
}

fn inspect_agent(identity: Identity) -> io::Result<AgentProcess> {
    use sha2::{Digest, Sha256};
    let pid = identity.parent_pid;
    if !matches!(identity.role, Caller::Mcp | Caller::CliOwner) || pid == 0 {
        return Err(denied());
    }
    // The parent PID comes from the kernel relationship of an authenticated peer.
    // pidfd, start time and inode checks cover exit, PID reuse and exec during hashing.
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let pidfd = unsafe { OwnedFd::from_raw_fd(fd as RawFd) };
    alive(&pidfd)?;
    let start_time = crate::peer::process_start_time(pid)?;
    let process = PathBuf::from(format!("/proc/{pid}"));
    let uid = std::fs::metadata(&process)?.uid();
    if uid != identity.peer.uid {
        return Err(denied());
    }
    let executable = process.join("exe");
    let path = std::fs::read_link(&executable)?;
    if std::fs::symlink_metadata(&path)?.file_type().is_symlink() {
        return Err(denied());
    }
    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(&path)?;
    let before = file.metadata()?;
    let mapped = std::fs::metadata(&executable)?;
    const MAX_EXECUTABLE: u64 = 1024 * 1024 * 1024;
    if !before.is_file()
        || before.len() > MAX_EXECUTABLE
        || before.dev() != mapped.dev()
        || before.ino() != mapped.ino()
    {
        return Err(denied());
    }
    let mut hasher = Sha256::new();
    let mut bytes = 0u64;
    let mut buffer = [0u8; 65536];
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        bytes += count as u64;
        if bytes > MAX_EXECUTABLE {
            return Err(denied());
        }
        hasher.update(&buffer[..count]);
    }
    let after = file.metadata()?;
    let current = std::fs::metadata(&executable)?;
    alive(&pidfd)?;
    if bytes != before.len()
        || before.len() != after.len()
        || before.modified()? != after.modified()?
        || current.dev() != before.dev()
        || current.ino() != before.ino()
        || std::fs::read_link(&executable)? != path
        || std::fs::metadata(&process)?.uid() != uid
        || crate::peer::process_start_time(pid)? != start_time
    {
        return Err(denied());
    }
    let agent = AgentProcess {
        uid,
        pid,
        start_time,
        exe_sha256: hasher
            .finalize()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect(),
    };
    validate_agent(identity, &agent)?;
    Ok(agent)
}

/// Call only in the root broker. The helper itself is checked against its installed inode.
pub fn serve_one(mut stream: UnixStream, policy: &Policy) -> io::Result<()> {
    configure(&stream)?;
    let pidfd = peer_pidfd(stream.as_raw_fd())?;
    alive(&pidfd)?;
    let caller = peer_credentials(stream.as_raw_fd())?;
    if caller.uid != policy.helper_uid || inspect(caller, &policy.install)?.0 != "kv-helper" {
        return Err(denied());
    }
    alive(&pidfd)?;
    let (fd, request) = receive_request(&mut stream)?;
    let identity = identify(fd.as_raw_fd(), policy, inspect)?;
    let role = match identity.role {
        Caller::RelayClient => "relay_client",
        Caller::CliOwner => "cli_owner",
        Caller::Mcp => "mcp",
        Caller::Hook => "hook",
        Caller::ApprovalAgent => "approval_agent",
    };
    let mut value = serde_json::json!({"pid":identity.peer.pid,
        "uid":identity.peer.uid,"gid":identity.peer.gid,"role":role,
        "parent_pid":identity.parent_pid});
    if request == *PROCESS_REQUEST {
        let agent = inspect_agent(identity)?;
        // The parent relationship and installed peer must still be the same after hashing.
        if identify(fd.as_raw_fd(), policy, inspect)? != identity {
            return Err(denied());
        }
        value["agent"] = serde_json::json!({"uid":agent.uid,"pid":agent.pid,
            "start_time":agent.start_time,"exe_sha256":agent.exe_sha256});
    }
    alive(&pidfd)?;
    let bytes = serde_json::to_vec(&value)?;
    if bytes.len() > LIMIT {
        return Err(denied());
    }
    stream.write_all(&(bytes.len() as u32).to_be_bytes())?;
    stream.write_all(&bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn process_proofs_are_limited_to_the_authenticated_callers_own_parent() {
        let identity = Identity {
            peer: PeerCredentials {
                uid: 1000,
                gid: 1000,
                pid: 123,
            },
            role: Caller::Mcp,
            parent_pid: 42,
        };
        let agent = AgentProcess {
            uid: 1000,
            pid: 42,
            start_time: 1234,
            exe_sha256: "a".repeat(64),
        };
        validate_agent(identity, &agent).unwrap();
        for changed in [
            AgentProcess {
                uid: 0,
                ..agent.clone()
            },
            AgentProcess {
                pid: 43,
                ..agent.clone()
            },
            AgentProcess {
                start_time: 0,
                ..agent.clone()
            },
            AgentProcess {
                exe_sha256: "untrusted hash".into(),
                ..agent.clone()
            },
        ] {
            assert!(validate_agent(identity, &changed).is_err());
        }
        for role in [Caller::RelayClient, Caller::Hook, Caller::ApprovalAgent] {
            assert!(validate_agent(Identity { role, ..identity }, &agent).is_err());
        }
    }

    #[test]
    fn a_process_snapshot_checks_pidfd_start_and_the_mapped_executable_without_an_install() {
        let pid = std::process::id();
        let identity = Identity {
            peer: PeerCredentials {
                pid,
                uid: unsafe { libc::getuid() },
                gid: unsafe { libc::getgid() },
            },
            role: Caller::CliOwner,
            parent_pid: pid,
        };
        let actual = inspect_agent(identity).unwrap();
        assert_eq!(actual.pid, pid);
        assert_eq!(actual.uid, identity.peer.uid);
        assert_eq!(
            actual.start_time,
            crate::peer::process_start_time(pid).unwrap()
        );
        assert_eq!(actual.exe_sha256.len(), 64);
    }

    #[test]
    fn uid_and_role_policy_keeps_owner_and_relay_separate() {
        for role in [
            Caller::RelayClient,
            Caller::CliOwner,
            Caller::Mcp,
            Caller::Hook,
            Caller::ApprovalAgent,
        ] {
            for uid in [0, 1000, 101, 102, 2000] {
                assert_eq!(
                    permits(role, uid, 1000, Some(102)),
                    if role == Caller::RelayClient {
                        uid == 102
                    } else {
                        uid == 1000 || (role == Caller::CliOwner && uid == 0)
                    }
                );
            }
        }
        assert!(!permits(Caller::RelayClient, 102, 1000, None));
    }
    #[test]
    fn transferred_socket_retains_kernel_peer_identity_and_cloexec() {
        let (socket, _) = UnixStream::pair().unwrap();
        let (sender, mut receiver) = UnixStream::pair().unwrap();
        send_fd(&sender, socket.as_raw_fd()).unwrap();
        let fd = receive_fd(&mut receiver).unwrap();
        assert_eq!(
            peer_credentials(fd.as_raw_fd()).unwrap(),
            peer_credentials(socket.as_raw_fd()).unwrap()
        );
        assert_ne!(
            unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFD) } & libc::FD_CLOEXEC,
            0
        );
        let peer = peer_credentials(fd.as_raw_fd()).unwrap();
        let policy = Policy {
            helper_uid: peer.uid,
            owner_uid: peer.uid,
            relay_uid: None,
            install: "/unused".into(),
        };
        let identity = identify(fd.as_raw_fd(), &policy, |actual, _| {
            assert_eq!(actual, peer);
            Ok(("kv-mcp".into(), 42))
        })
        .unwrap();
        assert_eq!(identity.role, Caller::Mcp);
        assert_eq!(identity.parent_pid, 42);
        assert!(identify(fd.as_raw_fd(), &policy, |_, _| Ok(("fake-cli".into(), 42))).is_err());
        assert!(identify(fd.as_raw_fd(), &policy, |_, _| Ok((
            "kv-relay-client".into(),
            42
        )))
        .is_err());
    }
    #[test]
    fn requests_without_a_socket_descriptor_are_rejected() {
        let (mut sender, mut receiver) = UnixStream::pair().unwrap();
        sender.write_all(REQUEST).unwrap();
        assert!(receive_fd(&mut receiver).is_err());
        let (sender, mut receiver) = UnixStream::pair().unwrap();
        let file = std::fs::File::open("/dev/null").unwrap();
        send_fd(&sender, file.as_raw_fd()).unwrap();
        let fd = receive_fd(&mut receiver).unwrap();
        assert!(peer_credentials(fd.as_raw_fd()).is_err());
    }

    #[test]
    #[ignore = "Linux 6.5+, root and Python 3 required; run cargo test -p kv-platform native_cross_uid_broker -- --ignored"]
    fn native_cross_uid_broker_preserves_roles_without_installing_keyvalet() {
        use std::os::unix::{fs::PermissionsExt, process::CommandExt};
        use std::process::{Command, Stdio};
        assert_eq!(unsafe { libc::geteuid() }, 0);
        // /var/lib has trusted parents; unlike /tmp, its root-owned chain can exercise
        // the production inode/trust checks. Every artifact belongs to this temporary fixture.
        let directory = tempfile::tempdir_in("/var/lib").unwrap();
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
        let install = directory.path().join("bin");
        std::fs::create_dir(&install).unwrap();
        std::fs::set_permissions(&install, std::fs::Permissions::from_mode(0o755)).unwrap();
        let python = std::fs::canonicalize("/usr/bin/python3").unwrap();
        for binary in [
            "kv-helper",
            "kv-cli",
            "kv-mcp",
            "kv-hook",
            "kv-relay-client",
            "unknown",
        ] {
            std::fs::copy(&python, install.join(binary)).unwrap();
            std::fs::set_permissions(install.join(binary), std::fs::Permissions::from_mode(0o755))
                .unwrap();
        }
        let front_path = directory.path().join("helper.sock");
        let broker_path = directory.path().join("peer.sock");
        let front = std::os::unix::net::UnixListener::bind(&front_path).unwrap();
        let broker = std::os::unix::net::UnixListener::bind(&broker_path).unwrap();
        for path in [&front_path, &broker_path] {
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o666)).unwrap();
        }
        let policy = Policy {
            helper_uid: 60001,
            owner_uid: 60002,
            relay_uid: Some(60003),
            install: install.clone(),
        };
        let helper_code = r#"
import array,json,os,socket,struct,sys
front=socket.socket(fileno=0)
client,_=front.accept()
pid,uid,gid=struct.unpack('3i',client.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))
try:
    os.readlink('/proc/%d/exe'%pid)
    raise AssertionError('cross-uid proc unexpectedly readable')
except PermissionError:
    print('proc-denied',flush=True)
s=socket.socket(socket.AF_UNIX);s.connect(sys.argv[1])
s.sendmsg([b'KVPA'+bytes([int(sys.argv[2])])],[(socket.SOL_SOCKET,socket.SCM_RIGHTS,array.array('i',[client.fileno()]))])
size=s.recv(4)
if size:
    length=struct.unpack('!I',size)[0];data=b''
    while len(data)<length: data+=s.recv(length-len(data))
    value=json.loads(data);assert value['pid']==pid and value['uid']==uid and value['gid']==gid
    if sys.argv[2]=='2':
        agent=value['agent'];assert agent['pid']==value['parent_pid'] and agent['uid']==uid
        assert agent['start_time']>0 and len(agent['exe_sha256'])==64
    print(value['role'],flush=True)
else: print('denied',flush=True)
client.sendall(b'done')
"#;
        for (binary, uid, version, owner_parent, expected) in [
            ("kv-cli", 60002, "1", false, Some("cli_owner")),
            ("kv-cli", 0, "1", false, Some("cli_owner")),
            ("kv-mcp", 60002, "1", false, Some("mcp")),
            ("kv-hook", 60002, "1", false, Some("hook")),
            ("kv-relay-client", 60003, "1", false, Some("relay_client")),
            ("kv-relay-client", 60002, "1", false, None),
            ("kv-cli", 60004, "1", false, None),
            ("unknown", 60002, "1", false, None),
            ("kv-cli", 60002, "2", false, Some("cli_owner")),
            ("kv-cli", 0, "2", false, Some("cli_owner")),
            ("kv-mcp", 60002, "2", true, Some("mcp")),
            ("kv-mcp", 60002, "2", false, None),
            ("kv-hook", 60002, "2", false, None),
            ("kv-relay-client", 60003, "2", false, None),
        ] {
            let fd = unsafe { libc::fcntl(front.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 3) };
            assert!(fd >= 0);
            let passed = unsafe { OwnedFd::from_raw_fd(fd) };
            let helper = Command::new(install.join("kv-helper"))
                .env_clear()
                .env("PYTHONHOME", "/usr")
                .args(["-c", helper_code])
                .arg(&broker_path)
                .arg(version)
                .uid(60001)
                .gid(60001)
                .stdin(Stdio::from(passed))
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap();
            let client_code = if binary == "kv-cli" && uid == 60002 && version == "2" {
                // Keep the dropped CLI nondumpable, as after its real sudo/setuid path.
                // This must work through the broker without changing ptrace policy.
                "import ctypes,socket,sys;assert ctypes.CDLL(None).prctl(4,0,0,0,0)==0;s=socket.socket(socket.AF_UNIX);s.connect(sys.argv[1]);assert s.recv(4)==b'done'"
            } else {
                "import socket,sys;s=socket.socket(socket.AF_UNIX);s.connect(sys.argv[1]);assert s.recv(4)==b'done'"
            };
            let mut command = if owner_parent {
                let mut command = Command::new(&python);
                command.args([
                    "-c",
                    "import subprocess,sys;sys.exit(subprocess.call(sys.argv[1:]))",
                ]);
                command.arg(install.join(binary));
                command
            } else {
                Command::new(install.join(binary))
            };
            let mut client = command
                .env_clear()
                .env("PYTHONHOME", "/usr")
                .args(["-c", client_code])
                .arg(&front_path)
                .uid(uid)
                .gid(uid)
                .spawn()
                .unwrap();
            let (stream, _) = broker.accept().unwrap();
            let result = serve_one(stream, &policy);
            assert_eq!(
                result.is_ok(),
                expected.is_some(),
                "{binary}, uid {uid}, version {version}: {result:?}"
            );
            let output = helper.wait_with_output().unwrap();
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
            let output = String::from_utf8(output.stdout).unwrap();
            assert!(output.contains("proc-denied"));
            assert!(output.contains(expected.unwrap_or("denied")), "{output}");
            assert!(client.wait().unwrap().success());
        }
    }
}
