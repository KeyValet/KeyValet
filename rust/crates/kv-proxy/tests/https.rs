#![cfg(unix)]
//! Real TLS sockets and temporary encrypted CA storage; no installed daemon or GUI.

use http_body_util::{BodyExt, Full};
use kv_proxy::certificates::{valid_host, CertificateAuthority, LeafRequest};
use kv_proxy::transparent::{Backend, BoxFuture, Bytes, HeaderMap, HttpBody, Listener, Response};
use kv_vault::Vault;
use serde_json::json;
use std::sync::{Arc, Mutex};

fn vault() -> (tempfile::TempDir, Vault) {
    use std::os::unix::fs::PermissionsExt;
    let directory = tempfile::tempdir().unwrap();
    let vault = Vault::new(directory.path().join("vault"));
    vault.prepare().unwrap();
    std::fs::write(vault.dir.join("master.key"), [8; 32]).unwrap();
    std::fs::set_permissions(
        vault.dir.join("master.key"),
        std::fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    vault.init_legacy().unwrap();
    (directory, vault)
}

#[test]
fn ca_survives_reopening_and_rejects_csr_escalation() {
    let (_directory, vault) = vault();
    let authority = CertificateAuthority::open(&vault).unwrap();
    let reopened = CertificateAuthority::open(&vault).unwrap();
    assert_eq!(authority.certificate(), reopened.certificate());
    assert!(!std::fs::read_to_string(vault.dir.join("vault.enc"))
        .unwrap()
        .contains("PRIVATE KEY"));
    let leaf = LeafRequest::new("api.example.com").unwrap();
    assert!(authority.sign_leaf("other.example.com", &leaf.csr).is_err());
    assert!(authority
        .sign_leaf("api.example.com", &"x".repeat(16385))
        .is_err());
    assert!(authority
        .sign_leaf("api.example.com", "invalid CSR")
        .is_err());
    assert!(authority
        .sign_leaf("https://api.example.com", &leaf.csr)
        .is_err());
    let certificate = authority.sign_leaf("api.example.com", &leaf.csr).unwrap();
    assert!(LeafRequest::new("api.example.com")
        .unwrap()
        .accept(certificate.clone())
        .is_err());
    leaf.accept(certificate).unwrap();
    let key = rcgen::KeyPair::generate().unwrap();
    let params =
        rcgen::CertificateParams::new(vec!["api.example.com".into(), "other.example.com".into()])
            .unwrap();
    let csr = params.serialize_request(&key).unwrap().pem().unwrap();
    assert!(authority.sign_leaf("api.example.com", &csr).is_err());
    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P384_SHA384).unwrap();
    let csr = rcgen::CertificateParams::new(vec!["api.example.com".into()])
        .unwrap()
        .serialize_request(&key)
        .unwrap()
        .pem()
        .unwrap();
    assert!(authority.sign_leaf("api.example.com", &csr).is_err());
    for host in [
        "",
        "localhost",
        "a..com",
        "-a.com",
        "a-.com",
        "a.com:443",
        "*.com",
        "a/com",
        &format!("{}.com", "a".repeat(64)),
    ] {
        assert!(!valid_host(host));
        assert!(LeafRequest::new(host).is_err());
    }
    let old = vault.authenticated_metadata("proxy_ca").unwrap().unwrap();
    vault
        .replace_authenticated_metadata(
            "proxy_ca",
            Some(&old),
            json!({"certificate":"bad","private_key":"bad"}),
        )
        .unwrap();
    assert!(CertificateAuthority::open(&vault).is_err());
}

struct FakeBackend {
    authority: CertificateAuthority,
    requests: Mutex<Vec<(String, String, String, Bytes)>>,
}
impl Backend for FakeBackend {
    fn leaf(&self, host: String, csr: String) -> BoxFuture<'_, Result<Vec<u8>, String>> {
        Box::pin(async move { self.authority.sign_leaf(&host, &csr) })
    }
    fn send(
        &self,
        host: String,
        method: String,
        path: String,
        _: HeaderMap,
        body: Bytes,
    ) -> BoxFuture<'_, Result<Response<HttpBody>, String>> {
        Box::pin(async move {
            self.requests
                .lock()
                .unwrap()
                .push((host, method, path, body));
            Ok(Response::new(
                Full::new(Bytes::from_static(b"approved once"))
                    .map_err(|never| match never {})
                    .boxed(),
            ))
        })
    }
}

#[tokio::test]
async fn https_connect_authenticates_then_preserves_original_request_bytes() {
    let (_directory, vault) = vault();
    let backend = Arc::new(FakeBackend {
        authority: CertificateAuthority::open(&vault).unwrap(),
        requests: Mutex::new(Vec::new()),
    });
    let listener = Listener::start(["api.example.com".into()].into(), backend.clone())
        .await
        .unwrap();
    let client = reqwest::Client::builder()
        .no_proxy()
        .add_root_certificate(
            reqwest::Certificate::from_pem(backend.authority.certificate().as_bytes()).unwrap(),
        )
        .proxy(reqwest::Proxy::all(listener.proxy_url()).unwrap())
        .build()
        .unwrap();
    let bytes = vec![0, 255, 128, 1, 2];
    let response = client
        .post("https://api.example.com/v1/test?q=unchanged")
        .body(bytes.clone())
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    assert_eq!(response.text().await.unwrap(), "approved once");
    {
        let requests = backend.requests.lock().unwrap();
        assert_eq!(requests.len(), 1);
        assert_eq!(
            (&requests[0].0, &requests[0].1, &requests[0].2),
            (
                &"api.example.com".into(),
                &"POST".into(),
                &"/v1/test?q=unchanged".into()
            )
        );
        assert_eq!(requests[0].3, bytes);
    }
    let response = client
        .get("https://api.example.com/host-attack")
        .header("host", "other.example.com")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 400);
    assert_eq!(backend.requests.lock().unwrap().len(), 1);
    let address = listener.address;
    drop(listener);
    tokio::task::yield_now().await;
    assert!(tokio::net::TcpStream::connect(address).await.is_err());
}

#[tokio::test]
async fn proxy_control_rejects_missing_authentication_and_invalid_bindings() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let (_directory, vault) = vault();
    let backend = Arc::new(FakeBackend {
        authority: CertificateAuthority::open(&vault).unwrap(),
        requests: Mutex::new(Vec::new()),
    });
    assert!(Listener::start(Default::default(), backend.clone())
        .await
        .is_err());
    assert!(
        Listener::start(["*.example.com".into()].into(), backend.clone())
            .await
            .is_err()
    );
    let listener = Listener::start(["api.example.com".into()].into(), backend)
        .await
        .unwrap();
    let token = listener
        .proxy_url()
        .split("//")
        .nth(1)
        .unwrap()
        .split('@')
        .next()
        .unwrap()
        .to_owned();
    for (request, status) in [
        ("CONNECT api.example.com:443 HTTP/1.1\r\nHost: api.example.com:443\r\n\r\n".into(), "407"),
        (format!("GET / HTTP/1.1\r\nHost: api.example.com\r\nProxy-Authorization: Bearer {token}\r\n\r\n"), "405"),
        (format!("CONNECT api.example.com:80 HTTP/1.1\r\nHost: api.example.com\r\nProxy-Authorization: Bearer {token}\r\n\r\n"), "400"),
    ] {
        let mut socket = tokio::net::TcpStream::connect(listener.address).await.unwrap();
        socket.write_all(request.as_bytes()).await.unwrap();
        let mut bytes = vec![0; 2048];
        let size = socket.read(&mut bytes).await.unwrap();
        assert!(String::from_utf8_lossy(&bytes[..size]).contains(status));
    }
}

#[derive(Default)]
struct Signer(Mutex<Vec<(String, String, String)>>);
impl kv_proxy::transparent::gateway::LeafSigner for Signer {
    fn sign(
        &self,
        ty: String,
        name: String,
        host: String,
        _: String,
    ) -> BoxFuture<'_, Result<Vec<u8>, String>> {
        Box::pin(async move {
            self.0.lock().unwrap().push((ty, name, host));
            Ok(vec![1, 2, 3])
        })
    }
}
fn binding(base: &str) -> kv_proxy::transparent::gateway::Binding {
    kv_proxy::transparent::gateway::Binding {
        credential_type: "api_key".into(),
        name: "service".into(),
        host: "api.example.com".into(),
        base: base.into(),
        token: zeroize::Zeroizing::new("kv_synthetic-session".into()),
    }
}

#[tokio::test]
async fn user_backend_keeps_credential_binding_and_streams_only_through_helper_gateway() {
    use kv_proxy::transparent::gateway::GatewayBackend;
    use wiremock::matchers::{body_bytes, header, method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};
    let server = MockServer::start().await;
    let signer = Arc::new(Signer::default());
    let backend = GatewayBackend::new(vec![binding(&server.uri())], signer.clone()).unwrap();
    assert_eq!(
        backend
            .leaf("api.example.com".into(), "CSR".into())
            .await
            .unwrap(),
        vec![1, 2, 3]
    );
    assert_eq!(
        signer.0.lock().unwrap()[0],
        ("api_key".into(), "service".into(), "api.example.com".into())
    );
    assert!(backend
        .leaf("other.example.com".into(), "CSR".into())
        .await
        .is_err());
    Mock::given(method("POST"))
        .and(path("/api.example.com/v1/resource"))
        .and(header("authorization", "Bearer kv_synthetic-session"))
        .and(body_bytes(vec![0, 255, 1]))
        .respond_with(ResponseTemplate::new(202).set_body_string("streamed"))
        .expect(1)
        .mount(&server)
        .await;
    let mut headers = HeaderMap::new();
    headers.insert("host", "other.example.com".parse().unwrap());
    headers.insert("authorization", "Bearer child-placeholder".parse().unwrap());
    let response = backend
        .send(
            "api.example.com".into(),
            "POST".into(),
            "/v1/resource".into(),
            headers,
            Bytes::from(vec![0, 255, 1]),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), 202);
    assert_eq!(
        response.into_body().collect().await.unwrap().to_bytes(),
        "streamed"
    );
    for (host, method, path) in [
        ("other.example.com", "GET", "/"),
        ("api.example.com", "bad\nmethod", "/"),
        ("api.example.com", "GET", "relative"),
        ("api.example.com", "GET", "/path#fragment"),
    ] {
        assert!(backend
            .send(
                host.into(),
                method.into(),
                path.into(),
                HeaderMap::new(),
                Bytes::new()
            )
            .await
            .is_err());
    }
    for base in [
        "invalid",
        "https://127.0.0.1:9000",
        "http://192.0.2.1:9000",
        "http://127.0.0.1",
        "http://127.0.0.1:9000/path",
        "http://127.0.0.1:9000?query",
        "http://127.0.0.1:9000#fragment",
        "http://user@127.0.0.1:9000",
        "http://user:password@127.0.0.1:9000",
    ] {
        assert!(GatewayBackend::new(vec![binding(base)], signer.clone()).is_err());
    }
    assert!(GatewayBackend::new(Vec::new(), signer.clone()).is_err());
    assert!(
        GatewayBackend::new(vec![binding(&server.uri()), binding(&server.uri())], signer).is_err()
    );
    assert_eq!(
        kv_proxy::run::sdk_key_env(Some("openai")),
        Some("OPENAI_API_KEY")
    );
    assert_eq!(
        kv_proxy::run::sdk_key_env(Some("anthropic")),
        Some("ANTHROPIC_API_KEY")
    );
    assert_eq!(kv_proxy::run::sdk_key_env(None), None);
    assert_eq!(kv_proxy::run::sdk_key_env(Some("other")), None);
    assert!(kv_proxy::run::session_id().unwrap().starts_with("run-"));
}

struct FaultBackend {
    signing: Option<CertificateAuthority>,
    upstream: Option<std::net::SocketAddr>,
}
impl Backend for FaultBackend {
    fn leaf(&self, host: String, csr: String) -> BoxFuture<'_, Result<Vec<u8>, String>> {
        Box::pin(async move {
            match &self.signing {
                Some(ca) => ca.sign_leaf(&host, &csr),
                None => Err("synthetic signing failure".into()),
            }
        })
    }
    fn dial(&self, _: String) -> BoxFuture<'_, std::io::Result<tokio::net::TcpStream>> {
        Box::pin(async move {
            match self.upstream {
                Some(address) => tokio::net::TcpStream::connect(address).await,
                None => Err(std::io::Error::new(
                    std::io::ErrorKind::NotConnected,
                    "synthetic upstream unavailable",
                )),
            }
        })
    }
    fn send(
        &self,
        _: String,
        _: String,
        _: String,
        _: HeaderMap,
        _: Bytes,
    ) -> BoxFuture<'_, Result<Response<HttpBody>, String>> {
        Box::pin(async { Err("synthetic forwarding failure".into()) })
    }
}
async fn connect_raw(listener: &Listener, host: &str) -> (tokio::net::TcpStream, String) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let token = listener
        .proxy_url()
        .split("//")
        .nth(1)
        .unwrap()
        .split('@')
        .next()
        .unwrap()
        .to_owned();
    let mut socket = tokio::net::TcpStream::connect(listener.address)
        .await
        .unwrap();
    socket.write_all(format!("CONNECT {host}:443 HTTP/1.1\r\nHost: {host}:443\r\nProxy-Authorization: Bearer {token}\r\n\r\n").as_bytes()).await.unwrap();
    let mut header = Vec::new();
    while !header.ends_with(b"\r\n\r\n") {
        header.push(socket.read_u8().await.unwrap());
        assert!(header.len() <= 2048);
    }
    (socket, String::from_utf8(header).unwrap())
}
#[tokio::test]
async fn signer_failure_and_tls_protocol_failure_close_without_forwarding() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = Listener::start(
        ["api.example.com".into()].into(),
        Arc::new(FaultBackend {
            signing: None,
            upstream: None,
        }),
    )
    .await
    .unwrap();
    let (_, header) = connect_raw(&listener, "api.example.com").await;
    assert!(header.starts_with("HTTP/1.1 502"));
    let (_tmp, vault) = vault();
    let backend = Arc::new(FaultBackend {
        signing: Some(CertificateAuthority::open(&vault).unwrap()),
        upstream: None,
    });
    let listener = Listener::start(["api.example.com".into()].into(), backend.clone())
        .await
        .unwrap();
    let (mut socket, header) = connect_raw(&listener, "api.example.com").await;
    assert!(header.starts_with("HTTP/1.1 200"));
    socket
        .write_all(b"invalid TLS protocol bytes")
        .await
        .unwrap();
    let mut alert = Vec::new();
    let _ = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        socket.read_to_end(&mut alert),
    )
    .await
    .unwrap();
    assert!(
        alert.is_empty() || alert[0] == 21,
        "only a TLS alert may precede closing"
    );
    let client = reqwest::Client::builder()
        .no_proxy()
        .add_root_certificate(
            reqwest::Certificate::from_pem(
                backend.signing.as_ref().unwrap().certificate().as_bytes(),
            )
            .unwrap(),
        )
        .proxy(reqwest::Proxy::all(listener.proxy_url()).unwrap())
        .build()
        .unwrap();
    assert_eq!(
        client
            .post("https://api.example.com/too-large")
            .body(vec![0; 1024 * 1024 + 1])
            .send()
            .await
            .unwrap()
            .status(),
        413
    );
    assert_eq!(
        client
            .get("https://api.example.com/upstream-failure")
            .send()
            .await
            .unwrap()
            .status(),
        502
    );
}
#[tokio::test]
async fn an_unbound_dial_failure_closes_the_established_tunnel_without_injection() {
    use tokio::io::AsyncReadExt;
    let listener = Listener::start(
        ["api.example.com".into()].into(),
        Arc::new(FaultBackend {
            signing: None,
            upstream: None,
        }),
    )
    .await
    .unwrap();
    let (mut socket, header) = connect_raw(&listener, "unbound.example.com").await;
    assert!(header.starts_with("HTTP/1.1 200"));
    let mut bytes = Vec::new();
    tokio::time::timeout(
        std::time::Duration::from_secs(2),
        socket.read_to_end(&mut bytes),
    )
    .await
    .unwrap()
    .unwrap();
    assert!(bytes.is_empty());
}

#[tokio::test]
async fn unbound_connect_is_a_byte_preserving_tunnel_without_credential_injection() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let upstream = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = upstream.local_addr().unwrap();
    let task = tokio::spawn(async move {
        let (mut socket, _) = upstream.accept().await.unwrap();
        let mut bytes = [0; 4];
        socket.read_exact(&mut bytes).await.unwrap();
        assert_eq!(&bytes, b"ping");
        socket.write_all(b"pong").await.unwrap();
    });
    let listener = Listener::start(
        ["api.example.com".into()].into(),
        Arc::new(FaultBackend {
            signing: None,
            upstream: Some(address),
        }),
    )
    .await
    .unwrap();
    let (mut socket, header) = connect_raw(&listener, "unbound.example.com").await;
    assert!(header.starts_with("HTTP/1.1 200"));
    socket.write_all(b"ping").await.unwrap();
    let mut bytes = [0; 4];
    socket.read_exact(&mut bytes).await.unwrap();
    assert_eq!(&bytes, b"pong");
    socket.shutdown().await.unwrap();
    let mut trailing = Vec::new();
    tokio::time::timeout(
        std::time::Duration::from_secs(2),
        socket.read_to_end(&mut trailing),
    )
    .await
    .unwrap()
    .unwrap();
    assert!(trailing.is_empty());
    task.await.unwrap();
}
