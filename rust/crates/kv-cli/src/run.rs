//! Explicit credential bindings for an unprivileged HTTPS child process.

use kv_proxy::transparent::gateway::{Binding, GatewayBackend, LeafSigner};
use kv_proxy::transparent::{BoxFuture, Listener};
use serde_json::{json, Value};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::sync::{mpsc, oneshot};

type Result<T> = std::result::Result<T, String>;
type Reply = oneshot::Sender<Result<Value>>;
trait Io: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Io for T {}

struct Client {
    writer: tokio::sync::Mutex<tokio::io::WriteHalf<Box<dyn Io>>>,
    requests: Arc<Mutex<HashMap<u64, Reply>>>,
    next: AtomicU64,
    reader: tokio::task::JoinHandle<()>,
}

impl Drop for Client {
    fn drop(&mut self) {
        self.reader.abort();
    }
}

async fn frame(reader: &mut (impl AsyncBufRead + Unpin)) -> Result<Value> {
    let mut bytes = Vec::new();
    loop {
        let available = reader
            .fill_buf()
            .await
            .map_err(|_| "Helper connection failed")?;
        if available.is_empty() {
            return Err("Helper connection closed".into());
        }
        let newline = available.iter().position(|byte| *byte == b'\n');
        let count = newline.map_or(available.len(), |index| index + 1);
        if bytes.len() + count > 1024 * 1024 {
            return Err("Helper response exceeds 1 MiB".into());
        }
        bytes.extend_from_slice(&available[..count]);
        reader.consume(count);
        if newline.is_some() {
            break;
        }
    }
    serde_json::from_slice(&bytes).map_err(|_| "Invalid helper response".into())
}

impl Client {
    async fn open(
        stream: Box<dyn Io>,
        session: String,
        notices: mpsc::UnboundedSender<String>,
    ) -> Result<Arc<Self>> {
        let (reader, mut writer) = tokio::io::split(stream);
        let mut reader = BufReader::new(reader);
        let auth = kv_core::AuthMessage {
            op: "auth".into(),
            purpose: "Run a child with explicit KeyValet HTTPS credential bindings".into(),
            requested_mode: None,
            lang: Some(kv_i18n::lang().as_str().into()),
            credential: None,
            cwd: std::env::current_dir()
                .map_err(|_| "Cannot determine the current directory")?
                .display()
                .to_string(),
            ppid: 0,
            session,
            client: "keyvalet-run".into(),
        };
        let mut bytes = serde_json::to_vec(&auth).map_err(|_| "Invalid authentication request")?;
        bytes.push(b'\n');
        writer
            .write_all(&bytes)
            .await
            .map_err(|_| "Cannot authenticate to the helper")?;
        let ready = tokio::time::timeout(Duration::from_secs(180), frame(&mut reader))
            .await
            .map_err(|_| "Helper authentication timed out")??;
        if ready["ready"] != true
            || ready["protocol"].as_u64() != Some(kv_core::PROTOCOL_VERSION as u64)
        {
            return Err("Helper authentication failed; check the local approval prompt".into());
        }
        let requests = Arc::new(Mutex::new(HashMap::<u64, Reply>::new()));
        let pending = requests.clone();
        let task = tokio::spawn(async move {
            while let Ok(mut value) = frame(&mut reader).await {
                if value["op"] == "gateway.approval_pending" {
                    if let Some(label) = value["params"]["label"].as_str() {
                        let _ = notices.send(label.into());
                    }
                    continue;
                }
                let Some(id) = value["id"].as_u64() else {
                    break;
                };
                if let Some(reply) = pending.lock().unwrap().remove(&id) {
                    let result = if value["ok"] == true {
                        value
                            .as_object_mut()
                            .and_then(|v| v.remove("result"))
                            .ok_or_else(|| "Missing helper result".into())
                    } else {
                        Err("Helper rejected the proxy request".into())
                    };
                    let _ = reply.send(result);
                }
                kv_vault::scrub_json(&mut value);
            }
            pending.lock().unwrap().clear();
        });
        Ok(Arc::new(Self {
            writer: tokio::sync::Mutex::new(writer),
            requests,
            next: AtomicU64::new(1),
            reader: task,
        }))
    }

    async fn request(&self, op: &str, params: Value) -> Result<Value> {
        if self.reader.is_finished() {
            return Err("Helper connection closed".into());
        }
        let id = self.next.fetch_add(1, Ordering::Relaxed);
        let (sender, receiver) = oneshot::channel();
        {
            let mut requests = self.requests.lock().unwrap();
            if requests.len() >= 32 {
                return Err("Too many proxy control requests".into());
            }
            requests.insert(id, sender);
        }
        struct Pending<'a>(&'a Mutex<HashMap<u64, Reply>>, u64);
        impl Drop for Pending<'_> {
            fn drop(&mut self) {
                self.0.lock().unwrap().remove(&self.1);
            }
        }
        let _pending = Pending(&self.requests, id);
        let mut bytes = serde_json::to_vec(&json!({"id":id,"op":op,"params":params}))
            .map_err(|_| "Invalid proxy control request")?;
        bytes.push(b'\n');
        if bytes.len() > 1024 * 1024 {
            return Err("Proxy control request exceeds 1 MiB".into());
        }
        self.writer
            .lock()
            .await
            .write_all(&bytes)
            .await
            .map_err(|_| "Cannot write to the helper")?;
        tokio::time::timeout(Duration::from_secs(70), receiver)
            .await
            .map_err(|_| "Proxy control request timed out")?
            .map_err(|_| "Helper connection closed")?
    }

    async fn gateway(&self, ty: &str, name: &str) -> Result<Value> {
        let mut value = self.request("gatewayOpen", json!({"type":ty,"name":name,"purpose":"Open an explicit HTTPS proxy binding for the child process","runtime_budget_s":70,"wait_in_call_ms":60000})).await?;
        for _ in 0..10 {
            match value["status"].as_str() {
                Some("approval_pending" | "still_pending") => {
                    let id = value["approval_id"].as_str().ok_or("Missing approval ID")?;
                    eprintln!(
                        "{}",
                        kv_i18n::t("正在等待网关审批…", "Waiting for gateway approval…")
                    );
                    value = self.request("proxyWait", json!({"approval_id":id})).await?;
                }
                Some("ok") => {
                    return value
                        .as_object_mut()
                        .and_then(|v| v.remove("result"))
                        .ok_or_else(|| "Missing gateway result".into())
                }
                None => return Ok(value),
                _ => return Err("Gateway approval did not authorize this binding".into()),
            }
        }
        Err("Gateway approval is still pending; the child has not started".into())
    }
}

impl LeafSigner for Client {
    fn sign(
        &self,
        ty: String,
        name: String,
        host: String,
        csr: String,
    ) -> BoxFuture<'_, Result<Vec<u8>>> {
        Box::pin(async move {
            let value = self
                .request(
                    "proxySignLeaf",
                    json!({"type":ty,"name":name,"host":host,"csr":csr}),
                )
                .await?;
            kv_core::remote::keys::decode_b64(
                value["certificate"]
                    .as_str()
                    .ok_or("Missing proxy leaf certificate")?,
            )
            .map_err(|_| "Invalid proxy leaf certificate".into())
        })
    }
}

struct Options {
    inject: Vec<(String, String)>,
    command: Vec<String>,
}
fn parse(args: &[String]) -> Result<Options> {
    let separator = args.iter().position(|arg| arg == "--").ok_or(
        "Usage: keyvalet run --inject <type/name> [--inject <type/name>] -- <command> [args]",
    )?;
    let mut inject = Vec::new();
    let mut index = 0;
    while index < separator {
        if args[index] != "--inject" {
            return Err("Unknown run option".into());
        }
        let (ty, name) = args
            .get(index + 1)
            .filter(|_| index + 1 < separator)
            .and_then(|value| value.split_once('/'))
            .filter(|(ty, name)| !ty.is_empty() && !name.is_empty() && !name.contains('/'))
            .ok_or("--inject requires type/name")?;
        if inject
            .iter()
            .any(|value| value == &(ty.into(), name.into()))
        {
            return Err("Duplicate credential binding".into());
        }
        inject.push((ty.into(), name.into()));
        index += 2;
    }
    if inject.is_empty() || inject.len() > 16 || separator + 1 == args.len() {
        return Err("A command and 1–16 explicit credential bindings are required".into());
    }
    Ok(Options {
        inject,
        command: args[separator + 1..].to_vec(),
    })
}

struct PublicCertificate(PathBuf);
impl Drop for PublicCertificate {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
impl PublicCertificate {
    fn create(session: &str, certificate: &str) -> Result<Self> {
        use std::io::Write;
        let directory = std::env::temp_dir().join(format!("keyvalet-{session}"));
        std::fs::create_dir(&directory)
            .map_err(|_| "Cannot create the proxy certificate directory")?;
        let storage = Self(directory);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&storage.0, std::fs::Permissions::from_mode(0o700))
                .map_err(|_| "Cannot protect the certificate directory")?;
        }
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(storage.path())
            .map_err(|_| "Cannot create the proxy certificate file")?;
        // Append the system roots for clients whose CA environment variable replaces their store.
        for path in ["/etc/ssl/cert.pem", "/etc/ssl/certs/ca-certificates.crt"] {
            if let Ok(metadata) = std::fs::metadata(path) {
                if metadata.is_file() && metadata.len() <= 4 * 1024 * 1024 {
                    let roots =
                        std::fs::read(path).map_err(|_| "Cannot read the system CA bundle")?;
                    file.write_all(&roots)
                        .map_err(|_| "Cannot write the CA bundle")?;
                    break;
                }
            }
        }
        file.write_all(certificate.as_bytes())
            .map_err(|_| "Cannot write the proxy CA")?;
        Ok(storage)
    }
    fn path(&self) -> PathBuf {
        self.0.join("ca.pem")
    }
}

async fn connect() -> Result<Box<dyn Io>> {
    #[cfg(unix)]
    {
        let stream = std::os::unix::net::UnixStream::connect(kv_platform::paths::HELPER_SOCKET)
            .map_err(|_| "The KeyValet daemon is not running")?;
        crate::remote::system::verify_helper(&stream).map_err(|e| e.message)?;
        stream
            .set_nonblocking(true)
            .map_err(|_| "Cannot configure the helper connection")?;
        Ok(Box::new(
            tokio::net::UnixStream::from_std(stream)
                .map_err(|_| "Cannot open the helper connection")?,
        ))
    }
    #[cfg(windows)]
    {
        Ok(Box::new(
            kv_platform::pipe::connect_service(kv_platform::paths::HELPER_PIPE)
                .await
                .map_err(|_| "Cannot verify the helper service")?,
        ))
    }
}

pub fn system(args: &[String]) -> Result<i32> {
    let options = parse(args)?;
    let current = std::env::current_exe().map_err(|_| "Cannot determine the CLI path")?;
    if current != Path::new(kv_platform::paths::CLI_BIN)
        || kv_platform::trust::untrusted_reason(&current).is_some()
    {
        return Err("Run this command through the installed keyvalet CLI".into());
    }
    #[cfg(unix)]
    if unsafe { libc::geteuid() } == 0 {
        let (uid, gid) = kv_platform::user::invoking_user()
            .ok_or("Run keyvalet run from an unprivileged user account")?;
        kv_platform::user::drop_to(uid, gid)().map_err(|_| "Cannot drop root privileges")?;
    }
    #[cfg(windows)]
    if kv_platform::peer::self_identity().is_none_or(|peer| peer.elevated) {
        return Err("Run keyvalet run from an unelevated terminal".into());
    }
    tokio::runtime::Runtime::new()
        .map_err(|_| "Cannot start the proxy runtime")?
        .block_on(async move {
            let session =
                kv_proxy::run::session_id().map_err(|_| "Cannot create the proxy session")?;
            let (notices, received) = mpsc::unbounded_channel();
            let client = Client::open(connect().await?, session.clone(), notices).await?;
            let ca = client.request("proxyCertificate", json!({})).await?;
            let certificate = ca["certificate"]
                .as_str()
                .filter(|certificate| certificate.len() <= 16 * 1024)
                .ok_or("Invalid proxy CA certificate")?;
            let ca = PublicCertificate::create(&session, certificate)?;
            let mut bindings = Vec::new();
            let mut hosts = HashSet::new();
            let mut sdk_keys = Vec::new();
            for (ty, name) in options.inject {
                let gateway = kv_vault::SecretJson(client.gateway(&ty, &name).await?);
                let base = gateway["base"].as_str().ok_or("Missing gateway address")?;
                let token = gateway["token"].as_str().ok_or("Missing gateway token")?;
                if let Some(key) = kv_proxy::run::sdk_key_env(gateway["template"].as_str()) {
                    sdk_keys.push(key);
                }
                for host in gateway["allowed_hosts"]
                    .as_array()
                    .ok_or("Missing gateway hosts")?
                {
                    let host = host.as_str().ok_or("Invalid gateway host")?.to_owned();
                    if !hosts.insert(host.clone()) {
                        return Err("Two credentials cannot bind the same host".into());
                    }
                    bindings.push(Binding {
                        credential_type: ty.clone(),
                        name: name.clone(),
                        host,
                        base: base.into(),
                        token: zeroize::Zeroizing::new(token.into()),
                    });
                }
            }
            let backend = Arc::new(GatewayBackend::new(bindings, client)?);
            let listener = Listener::start(hosts, backend).await?;
            let mut command = tokio::process::Command::new(&options.command[0]);
            command.args(&options.command[1..]);
            let proxy = listener.proxy_url();
            for key in sdk_keys {
                command.env(key, "keyvalet-session-proxy");
            }
            for key in ["HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy"] {
                command.env(key, &proxy);
            }
            for key in [
                "SSL_CERT_FILE",
                "REQUESTS_CA_BUNDLE",
                "CURL_CA_BUNDLE",
                "NODE_EXTRA_CA_CERTS",
            ] {
                command.env(key, ca.path());
            }
            command
                .env("NODE_USE_ENV_PROXY", "1")
                .env("NO_PROXY", "")
                .env("no_proxy", "");
            let status = kv_proxy::run::run_with_approval_notices(&mut command, received)
                .await
                .map_err(|_| "Cannot run the child process")?;
            Ok(status.code().unwrap_or(1))
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn explicit_bindings_and_command_are_required() {
        let parse_strings =
            |args: &[&str]| parse(&args.iter().map(|arg| (*arg).into()).collect::<Vec<_>>());
        for args in [
            &[][..],
            &["--", "echo"],
            &["--inject", "bad", "--", "echo"],
            &["--inject", "a/b", "--"],
            &["--inject", "a/b", "--inject", "a/b", "--", "echo"],
        ] {
            assert!(parse_strings(args).is_err());
        }
        let options =
            parse_strings(&["--inject", "api_key/openai", "--", "python", "script.py"]).unwrap();
        assert_eq!(options.inject, vec![("api_key".into(), "openai".into())]);
        assert_eq!(options.command, vec!["python", "script.py"]);
    }
}

#[cfg(test)]
mod ipc_tests {
    use super::*;
    #[test]
    fn proxy_control_replies_are_correlated_and_wait_notices_do_not_consume_them() {
        tokio::runtime::Runtime::new().unwrap().block_on(async {
            let (client_io, helper_io) = tokio::io::duplex(4096);
            let helper = tokio::spawn(async move {
                let (reader, mut writer) = tokio::io::split(helper_io);
                let mut reader = BufReader::new(reader);
                assert_eq!(frame(&mut reader).await.unwrap()["op"], "auth");
                writer.write_all(format!("{}\n",json!({"ready":true,"protocol":kv_core::PROTOCOL_VERSION})).as_bytes()).await.unwrap();
                let first = frame(&mut reader).await.unwrap();
                let second = frame(&mut reader).await.unwrap();
                writer.write_all(format!("{}\n{}\n{}\n",json!({"op":"gateway.approval_pending","params":{"label":"Fixture Mac"}}),json!({"id":second["id"],"ok":true,"result":{"request":second["op"]}}),json!({"id":first["id"],"ok":true,"result":{"request":first["op"]}})).as_bytes()).await.unwrap();
            });
            let (notices, mut received) = mpsc::unbounded_channel();
            let client = Client::open(Box::new(client_io), "CI-session".into(), notices).await.unwrap();
            let (first, second) = tokio::join!(client.request("proxyCertificate",json!({})),client.request("proxySignLeaf",json!({"host":"api.example.com","csr":"synthetic"})));
            assert_eq!(first.unwrap()["request"], "proxyCertificate");
            assert_eq!(second.unwrap()["request"], "proxySignLeaf");
            assert_eq!(received.recv().await.unwrap(), "Fixture Mac");
            helper.await.unwrap();
            tokio::task::yield_now().await;
            assert!(client.request("proxyCertificate",json!({})).await.is_err());
        });
    }
    #[test]
    fn response_framing_rejects_eof_invalid_json_and_oversized_frames() {
        tokio::runtime::Runtime::new().unwrap().block_on(async {
            for bytes in [
                b"".to_vec(),
                b"invalid\n".to_vec(),
                vec![b'x'; 1024 * 1024 + 1],
            ] {
                let mut reader = BufReader::new(bytes.as_slice());
                assert!(frame(&mut reader).await.is_err());
            }
        });
    }
}
