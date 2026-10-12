//! Real transport and process runner. Installation trust is never checked by fake-host tests.

use super::output::{self, JsonSuccess, Success};
use super::relay::{self, RelayUrl};
#[cfg(any(unix, test))]
pub(super) use super::transport::exchange_stream;
use super::transport::unavailable;
use super::{Error, Host, Result};
use kv_core::remote::ipc::{Request, Response};
use serde_json::Value;
#[cfg(windows)]
use std::io::BufRead;
use std::io::{IsTerminal, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

static STOPPED: AtomicBool = AtomicBool::new(false);

pub(super) struct System {
    pub summary: bool,
}

#[cfg(unix)]
extern "C" fn stop(_: libc::c_int) {
    STOPPED.store(true, Ordering::Relaxed);
}

impl System {
    pub fn new() -> Self {
        STOPPED.store(false, Ordering::Relaxed);
        #[cfg(unix)]
        unsafe {
            libc::signal(libc::SIGINT, stop as *const () as libc::sighandler_t);
        }
        Self { summary: false }
    }

    pub fn verify(&self) -> Result<()> {
        let current = std::env::current_exe().map_err(unavailable)?;
        #[cfg(windows)]
        if kv_platform::peer::self_identity().is_some_and(|peer| !peer.elevated)
            && current == Path::new(kv_platform::paths::CLI_BIN)
            && kv_platform::trust::untrusted_reason(&current).is_none()
        {
            // The helper authenticates the installed owner's SID for every remote op.
            // Local system writes still require the filesystem's administrator permission.
            return Ok(());
        }
        kv_platform::trust::verify_root_environment(
            &current,
            Path::new(kv_platform::paths::CLI_BIN),
            &[],
        )
        .map_err(|_| {
            Error::new(
                "untrusted_cli",
                "请通过已安装的 keyvalet 命令运行",
                "Run this command through the installed keyvalet CLI",
            )
        })
    }
}

#[cfg(unix)]
pub(crate) fn verify_helper(stream: &std::os::unix::net::UnixStream) -> Result<()> {
    use std::os::fd::AsRawFd;
    let fd = stream.as_raw_fd();
    let uid = kv_platform::peer::peer_uid(fd).map_err(|_| {
        Error::new(
            "untrusted_helper",
            "无法确认 helper 身份",
            "Cannot verify the helper identity",
        )
    })?;
    #[cfg(target_os = "linux")]
    let expected = kv_platform::linux::LinuxHost::system()
        .service_identity()
        .map_err(|_| Error::protocol())?
        .0;
    #[cfg(target_os = "macos")]
    let expected = 0;
    if uid != expected {
        return Err(Error::new(
            "untrusted_helper",
            "helper 的身份不正确",
            "The helper identity is invalid",
        ));
    }
    #[cfg(target_os = "macos")]
    {
        let token = kv_platform::peer::peer_audit_token(fd).map_err(|_| Error::protocol())?;
        let requirement = format!(
            "identifier \"{}\" and anchor apple generic and certificate leaf[subject.OU] = \"{}\"",
            kv_platform::paths::DAEMON_LABEL,
            kv_platform::paths::TEAM_ID
        );
        kv_platform::peer::verify_peer_code(&token, &requirement, kv_platform::paths::HELPER_BIN)
            .map_err(|_| {
            Error::new(
                "untrusted_helper",
                "helper 的代码签名不正确",
                "The helper code signature is invalid",
            )
        })?;
    }
    Ok(())
}

pub(crate) fn shared_settings(params: Value) -> Result<kv_core::settings::Settings> {
    #[cfg(unix)]
    let reply = {
        let mut stream = std::os::unix::net::UnixStream::connect(kv_platform::paths::HELPER_SOCKET)
            .map_err(unavailable)?;
        verify_helper(&stream)?;
        stream
            .set_read_timeout(Some(Duration::from_secs(180)))
            .map_err(unavailable)?;
        stream
            .set_write_timeout(Some(Duration::from_secs(5)))
            .map_err(unavailable)?;
        stream
            .write_all(&kv_ipc::agent::encode_line(
                &serde_json::json!({"op":"control","command":"remote_settings","params":params}),
            ))
            .map_err(unavailable)?;
        let mut reader = std::io::BufReader::new(stream);
        let mut bytes = Vec::new();
        loop {
            let mut byte = [0];
            if reader.read(&mut byte).map_err(unavailable)? == 0
                || bytes.len() >= kv_ipc::agent::MAX_LINE_BYTES
            {
                return Err(Error::protocol());
            }
            bytes.push(byte[0]);
            if byte[0] == b'\n' {
                break;
            }
        }
        serde_json::from_slice::<Value>(&bytes).map_err(|_| Error::protocol())?
    };
    #[cfg(windows)]
    let reply = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(unavailable)?
        .block_on(kv_platform::windows::control_request(
            "remote_settings",
            params,
        ))
        .map_err(unavailable)?
        .0;
    if reply["ok"] != true {
        let code = reply["error"].as_str().ok_or_else(Error::protocol)?;
        return Err(Error {
            code: code.into(),
            message: output::error_message(code),
            completed_devices: Vec::new(),
        });
    }
    serde_json::from_value(reply["result"].clone()).map_err(|_| Error::protocol())
}

#[cfg(target_os = "macos")]
fn user_home() -> Result<PathBuf> {
    let uid = kv_platform::user::invoking_user()
        .map(|p| p.0)
        .unwrap_or_else(|| unsafe { libc::getuid() });
    let mut record: libc::passwd = unsafe { std::mem::zeroed() };
    let mut buffer = vec![0u8; 65536];
    let mut result = std::ptr::null_mut();
    let rc = unsafe {
        libc::getpwuid_r(
            uid,
            &mut record,
            buffer.as_mut_ptr().cast(),
            buffer.len(),
            &mut result,
        )
    };
    if rc != 0 || result.is_null() || record.pw_dir.is_null() {
        return Err(Error::new(
            "invalid_config",
            "找不到用户配置目录",
            "Cannot locate the user's configuration directory",
        ));
    }
    let path = unsafe { std::ffi::CStr::from_ptr(record.pw_dir) }
        .to_str()
        .map_err(|_| Error::protocol())?;
    Ok(PathBuf::from(path))
}

#[cfg(target_os = "macos")]
fn write_as_invoking_user(write: impl FnOnce() -> Result<()>) -> Result<()> {
    let Some((uid, gid)) = kv_platform::user::invoking_user() else {
        return write();
    };
    // File commands run before any workers start. The child permanently drops root,
    // so user-controlled home directories cannot redirect a root write.
    let child = unsafe { libc::fork() };
    if child < 0 {
        return Err(relay::io_error(std::io::Error::last_os_error()));
    }
    if child == 0 {
        let written = kv_platform::user::drop_to(uid, gid)().is_ok() && write().is_ok();
        unsafe {
            libc::_exit(if written { 0 } else { 1 });
        }
    }
    let mut status = 0;
    loop {
        if unsafe { libc::waitpid(child, &mut status, 0) } >= 0 {
            break;
        }
        if std::io::Error::last_os_error().kind() != std::io::ErrorKind::Interrupted {
            return Err(relay::io_error(std::io::Error::last_os_error()));
        }
    }
    if libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0 {
        Ok(())
    } else {
        Err(relay::io_error(std::io::Error::other(
            "configuration write failed",
        )))
    }
}

impl Host for System {
    fn verify(&mut self) -> Result<()> {
        System::verify(self)
    }

    fn configure(&mut self, summary: bool) {
        self.summary = summary;
    }

    fn exchange(&mut self, request: Request) -> Result<Response> {
        #[cfg(unix)]
        {
            let mut stream =
                std::os::unix::net::UnixStream::connect(kv_platform::paths::HELPER_SOCKET)
                    .map_err(unavailable)?;
            verify_helper(&stream)?;
            stream
                .set_read_timeout(Some(Duration::from_secs(140)))
                .map_err(unavailable)?;
            stream
                .set_write_timeout(Some(Duration::from_secs(5)))
                .map_err(unavailable)?;
            exchange_stream(&mut stream, &request)
        }
        #[cfg(windows)]
        {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(unavailable)?;
            runtime.block_on(async {
                tokio::time::timeout(Duration::from_secs(140), async {
                    let mut pipe =
                        kv_platform::pipe::connect_service(kv_platform::paths::HELPER_PIPE)
                            .await
                            .map_err(unavailable)?;
                    let bytes = super::transport::encode_request(&request)?;
                    pipe.write_all(&bytes).await.map_err(unavailable)?;
                    let mut reply = Vec::new();
                    loop {
                        let byte = pipe.read_u8().await.map_err(unavailable)?;
                        if reply.len() as u64 >= super::transport::FRAME_LIMIT {
                            return Err(Error::protocol());
                        }
                        reply.push(byte);
                        if byte == b'\n' {
                            break;
                        }
                    }
                    super::transport::decode_response(&reply)
                })
                .await
                .map_err(|_| {
                    Error::new(
                        "timeout",
                        "helper 响应超时",
                        "The helper response timed out",
                    )
                })?
            })
        }
    }

    fn now(&self) -> i64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64
    }

    fn config_path(&self) -> Result<PathBuf> {
        #[cfg(target_os = "macos")]
        {
            Ok(user_home()?.join("Library/Application Support/KeyValet/relay-client.toml"))
        }
        #[cfg(any(target_os = "linux", windows))]
        {
            Ok(kv_platform::paths::RELAY_CONFIG.into())
        }
    }

    fn install_root(&self) -> Result<PathBuf> {
        #[cfg(target_os = "linux")]
        {
            Ok("/".into())
        }
        #[cfg(not(target_os = "linux"))]
        {
            Ok(self
                .config_path()?
                .parent()
                .ok_or_else(Error::protocol)?
                .join("relay-install"))
        }
    }

    fn confirmation(&mut self, prompt: &str, timeout: Duration) -> Result<Option<String>> {
        #[cfg(unix)]
        {
            use std::os::fd::AsRawFd;
            let mut tty = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open("/dev/tty")
                .map_err(|_| Error::cancelled())?;
            if !tty.is_terminal() {
                return Err(Error::cancelled());
            }
            tty.write_all(prompt.as_bytes()).map_err(unavailable)?;
            tty.flush().map_err(unavailable)?;
            let deadline = Instant::now() + timeout;
            let mut answer = Vec::new();
            loop {
                if STOPPED.load(Ordering::Relaxed) {
                    return Err(Error::cancelled());
                }
                let remaining = deadline.saturating_duration_since(Instant::now());
                if remaining.is_zero() {
                    return Ok(None);
                }
                let mut poll = libc::pollfd {
                    fd: tty.as_raw_fd(),
                    events: libc::POLLIN,
                    revents: 0,
                };
                let ready =
                    unsafe { libc::poll(&mut poll, 1, remaining.as_millis().min(100) as i32) };
                if ready < 0 {
                    if std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
                        continue;
                    }
                    return Err(Error::cancelled());
                }
                if ready == 0 {
                    continue;
                }
                let mut byte = [0];
                if tty.read(&mut byte).map_err(unavailable)? == 0 {
                    return Ok(None);
                }
                if byte[0] == b'\n' {
                    break;
                }
                if answer.len() >= 4096 {
                    return Err(Error::cancelled());
                }
                answer.push(byte[0]);
            }
            Ok(String::from_utf8(answer)
                .ok()
                .map(|s| s.trim_end_matches('\r').to_owned()))
        }
        #[cfg(windows)]
        {
            if !std::io::stdin().is_terminal() {
                return Err(Error::cancelled());
            }
            eprint!("{prompt}");
            std::io::stderr().flush().map_err(unavailable)?;
            let (sender, receiver) = std::sync::mpsc::channel();
            std::thread::spawn(move || {
                let mut input = String::new();
                let result = std::io::stdin().lock().take(4097).read_line(&mut input);
                let _ = sender.send(if matches!(result,Ok(n) if n>0 && n<=4096) {
                    Some(input.trim_end_matches(['\r', '\n']).to_owned())
                } else {
                    None
                });
            });
            Ok(receiver.recv_timeout(timeout).unwrap_or(None))
        }
    }

    fn secret(&mut self, prompt: &str) -> Result<Option<String>> {
        let code = if std::io::stdin().is_terminal() {
            rpassword::prompt_password(prompt).map_err(unavailable)?
        } else {
            let mut input = zeroize::Zeroizing::new(String::new());
            std::io::stdin().take(256).read_to_string(&mut input).map_err(unavailable)?;
            input.trim_end_matches(['\r','\n']).to_owned()
        };
        Ok(Some(code))
    }

    fn notice(&mut self, text: &str) -> Result<()> {
        eprintln!("{text}");
        Ok(())
    }

    fn emit(&mut self, value: &Success, json: bool) -> Result<()> {
        let text = if json {
            serde_json::to_string(&JsonSuccess {
                ok: !matches!(value, Success::Audit(report) if !report.consistent),
                output: value.clone(),
            })
            .map_err(|_| Error::protocol())?
        } else {
            output::render(value, std::io::stdout().is_terminal(), self.summary)
        };
        writeln!(std::io::stdout(), "{text}").map_err(unavailable)
    }

    fn wait(&mut self, duration: Duration) -> bool {
        let deadline = Instant::now() + duration;
        while Instant::now() < deadline && !STOPPED.load(Ordering::Relaxed) {
            std::thread::sleep(
                deadline
                    .saturating_duration_since(Instant::now())
                    .min(Duration::from_millis(100)),
            );
        }
        !STOPPED.load(Ordering::Relaxed)
    }

    fn health(&mut self, url: &str) -> Result<relay::Health> {
        let url = RelayUrl::parse(url)?;
        if url.scheme == "http" {
            return http_health(&url);
        }
        let mut command = std::process::Command::new(curl_path());
        command.args([
            "--disable",
            "--silent",
            "--show-error",
            "--fail",
            "--proto",
            "=https",
            "--connect-timeout",
            "3",
            "--max-time",
            "5",
            &url.health_url(),
        ]);
        command
            .env_clear()
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null());
        let mut child = command.spawn().map_err(|_| {
            Error::new(
                "relay_unreachable",
                "健康检查需要系统 curl；请安装 curl 后重试",
                "Health checks require system curl; install curl and retry",
            )
        })?;
        let mut body = Vec::new();
        let read = child
            .stdout
            .take()
            .ok_or_else(relay::health_error)?
            .take(64 * 1024 + 1)
            .read_to_end(&mut body);
        if read.is_err() || body.len() > 64 * 1024 {
            let _ = child.kill();
            let _ = child.wait();
            return Err(relay::health_error());
        }
        if !child.wait().map_err(|_| relay::health_error())?.success() {
            return Err(Error::new(
                "relay_unreachable",
                "relay 健康检查不可达；请检查 Cloudflare 与 nginx",
                "The relay health check is unreachable; check Cloudflare and nginx",
            ));
        }
        relay::parse_health(&body)
    }

    fn hook(&mut self, command: &str, id: &str, summary: &str) -> Result<()> {
        #[cfg(unix)]
        let mut process = {
            let mut process = std::process::Command::new("/bin/sh");
            process.args(["-c", command, "keyvalet-on-approve", id, summary]);
            if unsafe { libc::geteuid() } == 0 {
                use std::os::unix::process::CommandExt;
                let (uid, gid) = kv_platform::user::invoking_user().ok_or_else(|| {
                    Error::new(
                        "hook_requires_owner",
                        "批准后的命令必须以 vault 用户运行",
                        "Approval hooks must run as the vault owner",
                    )
                })?;
                unsafe {
                    process.pre_exec(kv_platform::user::drop_to(uid, gid));
                }
            }
            process
        };
        #[cfg(windows)]
        let mut process = {
            if kv_platform::peer::self_identity().is_none_or(|p| p.elevated) {
                return Err(Error::new(
                    "hook_requires_owner",
                    "批准后的命令需要非管理员用户会话",
                    "Approval hooks require a non-elevated user session",
                ));
            }
            let mut process = std::process::Command::new(
                r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            );
            process.args(["-NoProfile","-NonInteractive","-Command","& ([ScriptBlock]::Create($env:KEYVALET_APPROVAL_COMMAND)) $env:KEYVALET_APPROVAL_ID $env:KEYVALET_APPROVAL_SUMMARY"]);
            process
                .env("KEYVALET_APPROVAL_COMMAND", command)
                .env("KEYVALET_APPROVAL_ID", id)
                .env("KEYVALET_APPROVAL_SUMMARY", summary);
            process
        };
        // Hook output goes to stderr so --json remains a stream of complete CLI objects.
        #[cfg(unix)]
        process.env_clear();
        process
            .env("PATH", "/usr/bin:/bin")
            .current_dir("/")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null());
        if process.status().map_err(unavailable)?.success() {
            Ok(())
        } else {
            Err(Error::new(
                "hook_failed",
                "批准后的命令执行失败",
                "The approval hook failed",
            ))
        }
    }

    fn protection(&mut self) -> Result<Value> {
        #[cfg(windows)]
        {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(unavailable)?
                .block_on(kv_platform::protection::service_status())
                .map_err(unavailable)
        }
        #[cfg(unix)]
        {
            let vault = kv_vault::Vault::new(kv_platform::paths::VAULT_DIR);
            #[cfg(target_os = "linux")]
            let vault = vault
                .owned_by(
                    kv_platform::linux::LinuxHost::system()
                        .verify_vault_owner()
                        .map_err(|_| {
                            Error::new(
                                "local_status_unavailable",
                                "无法确认本机凭证库属主",
                                "Cannot verify the local vault owner",
                            )
                        })?,
                )
                .map_err(|_| {
                    Error::new(
                        "local_status_unavailable",
                        "无法读取本机保护状态",
                        "Cannot read local protection status",
                    )
                })?;
            let mut view = kv_platform::protection::status(&vault).map_err(|_| {
                Error::new(
                    "local_status_unavailable",
                    "无法读取本机保护状态",
                    "Cannot read local protection status",
                )
            })?;
            view["binding_excluded_from_backups"] =
                serde_json::json!(vault.binding_backup_exclusion().unwrap_or(None));
            Ok(view)
        }
    }

    fn set_url(&mut self, path: &Path, url: &str) -> Result<()> {
        write_public_config(path, || relay::Config::set_url(path, url))
    }

    fn set_binding(
        &mut self,
        path: &Path,
        binding: &kv_core::remote::ipc::RelayBinding,
    ) -> Result<()> {
        write_public_config(path, || relay::Config::set_binding(path, binding))
    }

    fn install(
        &mut self,
        root: &Path,
        listen: &str,
        data: &Path,
        url: &str,
    ) -> Result<relay::Installed> {
        #[cfg(target_os = "macos")]
        {
            write_as_invoking_user(|| relay::install(root, listen, data, url).map(|_| ()))?;
            Ok(relay::describe_install(root, listen, data, url))
        }
        #[cfg(not(target_os = "macos"))]
        {
            relay::install(root, listen, data, url)
        }
    }
}

fn write_public_config(path: &Path, work: impl FnOnce() -> Result<()>) -> Result<()> {
    #[cfg(windows)]
    let _ = path;
    #[cfg(target_os = "macos")]
    {
        let _ = path;
        write_as_invoking_user(work)
    }
    #[cfg(not(target_os = "macos"))]
    {
        #[cfg(target_os = "linux")]
        let new_parent = path
            .parent()
            .filter(|parent| !parent.exists())
            .map(Path::to_owned);
        work()?;
        #[cfg(target_os = "linux")]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o644))
                .map_err(relay::io_error)?;
            if let Some(parent) = new_parent {
                std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o755))
                    .map_err(relay::io_error)?;
            }
        }
        Ok(())
    }
}

fn curl_path() -> &'static str {
    #[cfg(unix)]
    {
        "/usr/bin/curl"
    }
    #[cfg(windows)]
    {
        r"C:\Windows\System32\curl.exe"
    }
}

pub(super) fn run_system(argv: &[String]) -> i32 {
    let json = argv.iter().any(|s| s == "--json");
    let mut host = System::new();
    match super::run(&mut host, argv) {
        Ok(()) => 0,
        Err(error) => {
            if error.code == "audit_findings" {
                return error.exit_code();
            }
            let text = output::render_error(&error, json);
            if json {
                println!("{text}");
            } else {
                eprintln!("{text}");
            }
            error.exit_code()
        }
    }
}

pub(super) fn http_health(url: &RelayUrl) -> Result<relay::Health> {
    let ip: std::net::IpAddr = url.host.parse().map_err(|_| relay::health_error())?;
    let mut stream = std::net::TcpStream::connect_timeout(
        &std::net::SocketAddr::new(ip, url.port),
        Duration::from_secs(5),
    )
    .map_err(|_| {
        Error::new(
            "relay_unreachable",
            "relay 不可达",
            "The relay is unreachable",
        )
    })?;
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .map_err(|_| relay::health_error())?;
    stream
        .set_write_timeout(Some(Duration::from_secs(5)))
        .map_err(|_| relay::health_error())?;
    super::transport::http_health(&mut stream, url)
}
