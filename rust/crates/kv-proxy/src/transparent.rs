//! The transparent listener calls this adapter before forwarding an intercepted HTTP request.

pub mod gateway;

pub use crate::approval::HttpBody;
use crate::approval::{self, ApprovalLayer, ApprovalRequest, HttpApprovalError};
use hyper::StatusCode;
pub use hyper::{HeaderMap, Response};
use std::future::Future;
use tokio::net::TcpStream;

pub use bytes::Bytes;
pub use futures_util::future::BoxFuture;
use http_body_util::{BodyExt, Full, Limited};
use hyper::{Method, Request};
use std::collections::HashSet;
use std::sync::Arc;

pub trait Backend: Send + Sync {
    fn leaf(&self, host: String, csr: String) -> BoxFuture<'_, Result<Vec<u8>, String>>;
    fn tls(
        &self,
        host: String,
    ) -> BoxFuture<'_, Result<tokio_rustls::rustls::ServerConfig, String>> {
        Box::pin(async move {
            let leaf = crate::certificates::LeafRequest::new(&host)?;
            let certificate = self.leaf(host, leaf.csr.clone()).await?;
            leaf.accept(certificate)
        })
    }
    /// The native DNS/TCP dial is separate from the CONNECT binding decision.
    fn dial(&self, host: String) -> BoxFuture<'_, std::io::Result<TcpStream>> {
        Box::pin(async move { TcpStream::connect((host.as_str(), 443)).await })
    }
    fn send(
        &self,
        host: String,
        method: String,
        path: String,
        headers: hyper::HeaderMap,
        body: Bytes,
    ) -> BoxFuture<'_, Result<Response<HttpBody>, String>>;
}

pub struct Listener {
    pub address: std::net::SocketAddr,
    token: zeroize::Zeroizing<String>,
    stop: tokio::sync::watch::Sender<bool>,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for Listener {
    fn drop(&mut self) {
        let _ = self.stop.send(true);
        self.task.abort();
    }
}

impl Listener {
    pub async fn start(hosts: HashSet<String>, backend: Arc<dyn Backend>) -> Result<Self, String> {
        Self::start_with_permits(hosts, backend, Arc::new(tokio::sync::Semaphore::new(64))).await
    }

    // Private injection seam: capacity tests use the identical accept/upgrade/stop path
    // without opening 128 descriptors alongside the gateway's capacity test.
    async fn start_with_permits(
        hosts: HashSet<String>,
        backend: Arc<dyn Backend>,
        permits: Arc<tokio::sync::Semaphore>,
    ) -> Result<Self, String> {
        if hosts.is_empty()
            || hosts.len() > 100
            || hosts
                .iter()
                .any(|host| !crate::certificates::valid_host(host))
        {
            return Err("Explicit proxy bindings require valid HTTPS hosts".into());
        }
        let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .map_err(|_| "Cannot bind the session proxy")?;
        let address = listener
            .local_addr()
            .map_err(|_| "Cannot read the session proxy address")?;
        let mut random = [0u8; 32];
        getrandom::getrandom(&mut random).map_err(|_| "Cannot create the session proxy token")?;
        let token = zeroize::Zeroizing::new(
            random
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>(),
        );
        use zeroize::Zeroize;
        random.zeroize();
        let authentication = token.clone();
        let hosts = Arc::new(hosts);
        let (stop, stopped) = tokio::sync::watch::channel(false);
        let task = tokio::spawn(async move {
            let mut connections = tokio::task::JoinSet::new();
            let mut shutdown = stopped.clone();
            while let Some(connection) = tokio::select! {
                _ = shutdown.changed() => None,
                accepted = listener.accept() => accepted.ok().map(|(connection, _)| connection),
            } {
                while connections.try_join_next().is_some() {}
                let Ok(permit) = permits.clone().try_acquire_owned() else {
                    continue;
                };
                if approval::configure_keepalive(&connection).is_err() {
                    continue;
                }
                let token = authentication.clone();
                let hosts = hosts.clone();
                let backend = backend.clone();
                let stopped = stopped.clone();
                connections.spawn(async move {
                    let permit = Arc::new(permit);
                    let mut shutdown = stopped.clone();
                    let service = hyper::service::service_fn(move |request| connect(request, token.clone(), hosts.clone(), backend.clone(), permit.clone(), stopped.clone()));
                    let server = hyper::server::conn::http1::Builder::new();
                    tokio::select! {
                        _ = shutdown.changed() => {},
                        _ = server.serve_connection(hyper_util::rt::TokioIo::new(connection), service).with_upgrades() => {},
                    }
                });
            }
        });
        Ok(Self {
            address,
            token,
            stop,
            task,
        })
    }

    pub fn proxy_url(&self) -> String {
        format!("http://{}@{}", self.token.as_str(), self.address)
    }
}

fn response(status: StatusCode, text: &'static str) -> Response<HttpBody> {
    let mut reply = Response::new(
        Full::new(Bytes::from_static(text.as_bytes()))
            .map_err(|never| match never {})
            .boxed(),
    );
    *reply.status_mut() = status;
    reply
}

fn authenticated(headers: &hyper::HeaderMap, token: &str) -> bool {
    use base64::Engine;
    let Some(header) = headers
        .get(hyper::header::PROXY_AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
    else {
        return false;
    };
    if let Some(bearer) = header.strip_prefix("Bearer ") {
        return bearer == token;
    }
    header
        .strip_prefix("Basic ")
        .and_then(|encoded| {
            base64::engine::general_purpose::STANDARD
                .decode(encoded)
                .ok()
        })
        .is_some_and(|bytes| bytes == format!("{token}:").as_bytes())
}

async fn connect<B: Send + 'static>(
    mut request: Request<B>,
    token: zeroize::Zeroizing<String>,
    hosts: Arc<HashSet<String>>,
    backend: Arc<dyn Backend>,
    permit: Arc<tokio::sync::OwnedSemaphorePermit>,
    mut stopped: tokio::sync::watch::Receiver<bool>,
) -> Result<Response<HttpBody>, std::convert::Infallible> {
    if !authenticated(request.headers(), &token) {
        return Ok(response(
            StatusCode::PROXY_AUTHENTICATION_REQUIRED,
            "Session proxy authentication is required",
        ));
    }
    if request.method() != Method::CONNECT {
        return Ok(response(
            StatusCode::METHOD_NOT_ALLOWED,
            "Use HTTPS CONNECT",
        ));
    }
    let Some(authority) = request.uri().authority() else {
        return Ok(response(StatusCode::BAD_REQUEST, "Invalid CONNECT target"));
    };
    let host = authority.host().to_ascii_lowercase();
    if authority.port_u16() != Some(443) || !crate::certificates::valid_host(&host) {
        return Ok(response(
            StatusCode::BAD_REQUEST,
            "CONNECT requires an HTTPS host on port 443",
        ));
    }
    let bound = hosts.contains(&host);
    let tls = if bound {
        match backend.tls(host.clone()).await {
            Ok(config) => Some(config),
            Err(_) => {
                return Ok(response(
                    StatusCode::BAD_GATEWAY,
                    "Cannot authorize proxy TLS certificate",
                ))
            }
        }
    } else {
        None
    };
    let upgraded = hyper::upgrade::on(&mut request);
    tokio::spawn(async move {
        let _permit = permit;
        let connection = async move {
            let Ok(upgraded) = upgraded.await else {
                return;
            };
            let mut io = hyper_util::rt::TokioIo::new(upgraded);
            if let Some(config) = tls {
                let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
                let Ok(Ok(tls)) =
                    tokio::time::timeout(std::time::Duration::from_secs(10), acceptor.accept(io))
                        .await
                else {
                    return;
                };
                let service = hyper::service::service_fn(move |request| {
                    intercepted(request, host.clone(), backend.clone())
                });
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(hyper_util::rt::TokioIo::new(tls), service)
                    .await;
            } else {
                let Ok(Ok(mut upstream)) =
                    tokio::time::timeout(std::time::Duration::from_secs(10), backend.dial(host))
                        .await
                else {
                    return;
                };
                let _ = tokio::io::copy_bidirectional(&mut io, &mut upstream).await;
            }
        };
        tokio::select! { _ = stopped.changed() => {}, _ = connection => {} }
    });
    Ok(response(StatusCode::OK, ""))
}

async fn intercepted<B>(
    request: Request<B>,
    host: String,
    backend: Arc<dyn Backend>,
) -> Result<Response<HttpBody>, std::convert::Infallible>
where
    B: hyper::body::Body<Data = Bytes> + Send + 'static,
    B::Error: std::error::Error + Send + Sync + 'static,
{
    if request.uri().authority().is_some_and(|authority| {
        authority.host() != host || authority.port_u16().is_some_and(|port| port != 443)
    }) || request
        .headers()
        .get(hyper::header::HOST)
        .and_then(|host| host.to_str().ok())
        .is_none_or(|header| header != host && header != format!("{host}:443"))
    {
        return Ok(response(
            StatusCode::BAD_REQUEST,
            "Request host does not match the CONNECT binding",
        ));
    }
    let (parts, body) = request.into_parts();
    let body = match Limited::new(body, 1024 * 1024).collect().await {
        Ok(body) => body.to_bytes(),
        Err(_) => {
            return Ok(response(
                StatusCode::PAYLOAD_TOO_LARGE,
                "Approval request body exceeds 1 MiB",
            ))
        }
    };
    let path = parts
        .uri
        .path_and_query()
        .map_or("/", |path| path.as_str())
        .to_owned();
    Ok(
        match backend
            .send(host, parts.method.to_string(), path, parts.headers, body)
            .await
        {
            Ok(response) => response,
            Err(_) => response(
                StatusCode::BAD_GATEWAY,
                "The credential gateway request failed",
            ),
        },
    )
}

/// Wait without writing HTTP bytes. A retained helper result replaces forwarding entirely.
pub async fn forward_after_approval<F, Fut>(
    connection: &TcpStream,
    layer: &ApprovalLayer,
    request: ApprovalRequest,
    host_hint_s: Option<u64>,
    forward: F,
) -> Result<Response<HttpBody>, HttpApprovalError>
where
    F: FnOnce() -> Fut,
    Fut: Future<Output = Result<Response<HttpBody>, HttpApprovalError>>,
{
    approval::check_keepalive(approval::configure_keepalive(connection))?;
    let decision = layer
        .authorize(request, host_hint_s)
        .await
        .map_err(|message| HttpApprovalError {
            status: StatusCode::BAD_GATEWAY,
            message,
        })?;
    match approval::http_response(&decision)? {
        Some(response) => Ok(approval::boxed_response(response)),
        None => forward().await,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    pub(super) struct Boundary;
    impl Backend for Boundary {
        fn leaf(&self, _: String, _: String) -> BoxFuture<'_, Result<Vec<u8>, String>> {
            Box::pin(async { Err("synthetic signer unavailable".into()) })
        }
        fn tls(
            &self,
            _: String,
        ) -> BoxFuture<'_, Result<tokio_rustls::rustls::ServerConfig, String>> {
            Box::pin(async {
                Ok(
                    tokio_rustls::rustls::ServerConfig::builder_with_provider(Arc::new(
                        tokio_rustls::rustls::crypto::ring::default_provider(),
                    ))
                    .with_safe_default_protocol_versions()
                    .unwrap()
                    .with_no_client_auth()
                    .with_cert_resolver(Arc::new(
                        tokio_rustls::rustls::server::ResolvesServerCertUsingSni::new(),
                    )),
                )
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
            Box::pin(async { Err("synthetic upstream failure".into()) })
        }
    }
    #[tokio::test]
    async fn request_authority_body_limits_and_upstream_failure_are_checked_before_forwarding() {
        for (uri, size, expected) in [
            ("https://other.example.com/path", 0, 400),
            ("https://api.example.com:444/path", 0, 400),
            ("/path", 1024 * 1024 + 1, 413),
            ("/path", 0, 502),
        ] {
            let request = Request::builder()
                .uri(uri)
                .header("host", "api.example.com")
                .body(Full::new(Bytes::from(vec![0; size])))
                .unwrap();
            assert_eq!(
                intercepted(request, "api.example.com".into(), Arc::new(Boundary))
                    .await
                    .unwrap()
                    .status(),
                expected
            );
        }
    }
    #[tokio::test]
    async fn a_connect_without_a_hyper_upgrade_is_closed_and_missing_authority_is_rejected() {
        let semaphore = Arc::new(tokio::sync::Semaphore::new(1));
        let permit = Arc::new(semaphore.clone().acquire_owned().await.unwrap());
        let (_stop, stopped) = tokio::sync::watch::channel(false);
        for (uri, expected) in [("/relative", 400), ("api.example.com:443", 200)] {
            let request = Request::builder()
                .method(Method::CONNECT)
                .uri(uri)
                .header("proxy-authorization", "Bearer token")
                .body(Full::new(Bytes::new()))
                .unwrap();
            let result = connect(
                request,
                zeroize::Zeroizing::new("token".into()),
                Arc::new(["api.example.com".into()].into()),
                Arc::new(Boundary),
                permit.clone(),
                stopped.clone(),
            )
            .await
            .unwrap();
            assert_eq!(result.status(), expected);
        }
        tokio::task::yield_now().await;
    }
}

#[cfg(test)]
mod capacity_tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    struct Tunnel(std::net::SocketAddr);
    impl Backend for Tunnel {
        fn leaf(&self, _: String, _: String) -> BoxFuture<'_, Result<Vec<u8>, String>> {
            Box::pin(async { Err("An unbound tunnel must not request a certificate".into()) })
        }
        fn send(
            &self,
            _: String,
            _: String,
            _: String,
            _: HeaderMap,
            _: Bytes,
        ) -> BoxFuture<'_, Result<Response<HttpBody>, String>> {
            Box::pin(async { Err("An unbound tunnel must not inject credentials".into()) })
        }
        fn dial(&self, _: String) -> BoxFuture<'_, std::io::Result<TcpStream>> {
            Box::pin(async { TcpStream::connect(self.0).await })
        }
    }

    #[tokio::test]
    async fn an_unbound_tunnel_releases_its_connection_slot_after_both_sides_close() {
        let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let backend = Arc::new(Tunnel(upstream.local_addr().unwrap()));
        let upstream_task = tokio::spawn(async move {
            let (mut socket, _) = upstream.accept().await.unwrap();
            let mut bytes = [0; 4];
            socket.read_exact(&mut bytes).await.unwrap();
            assert_eq!(&bytes, b"ping");
            socket.write_all(b"pong").await.unwrap();
            socket.shutdown().await.unwrap();
            let mut trailing = Vec::new();
            socket.read_to_end(&mut trailing).await.unwrap();
            assert!(trailing.is_empty());
        });
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let slots = Arc::new(tokio::sync::Semaphore::new(1));
        let permit = Arc::new(slots.clone().acquire_owned().await.unwrap());
        let (_stop, stopped) = tokio::sync::watch::channel(false);
        let server = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            let service = hyper::service::service_fn(move |request| {
                connect(
                    request,
                    zeroize::Zeroizing::new("token".into()),
                    Arc::new(HashSet::new()),
                    backend.clone(),
                    permit.clone(),
                    stopped.clone(),
                )
            });
            hyper::server::conn::http1::Builder::new()
                .serve_connection(hyper_util::rt::TokioIo::new(socket), service)
                .with_upgrades()
                .await
                .unwrap();
        });
        let mut socket = TcpStream::connect(address).await.unwrap();
        socket
            .write_all(b"CONNECT unbound.example.com:443 HTTP/1.1\r\nHost: unbound.example.com:443\r\nProxy-Authorization: Bearer token\r\n\r\n")
            .await
            .unwrap();
        let mut headers = Vec::new();
        while !headers.ends_with(b"\r\n\r\n") {
            headers.push(socket.read_u8().await.unwrap());
        }
        assert!(headers.starts_with(b"HTTP/1.1 200"));
        socket.write_all(b"ping").await.unwrap();
        socket.shutdown().await.unwrap();
        let mut reply = Vec::new();
        socket.read_to_end(&mut reply).await.unwrap();
        assert_eq!(reply, b"pong");
        upstream_task.await.unwrap();
        server.await.unwrap();
        let returned = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            slots.clone().acquire_owned(),
        )
        .await
        .expect("The completed tunnel must release its connection slot")
        .unwrap();
        assert_eq!(returned.num_permits(), 1);
    }

    #[tokio::test]
    async fn connection_capacity_is_bounded_and_stop_closes_existing_connections() {
        const CAPACITY: usize = 8;
        let slots = Arc::new(tokio::sync::Semaphore::new(CAPACITY));
        let listener = Listener::start_with_permits(
            ["api.example.com".into()].into(),
            Arc::new(super::tests::Boundary),
            slots.clone(),
        )
        .await
        .unwrap();
        let mut connections = Vec::new();
        for _ in 0..CAPACITY {
            connections.push(TcpStream::connect(listener.address).await.unwrap());
        }
        wait_for_slots(&slots, 0).await;
        let mut refused = TcpStream::connect(listener.address).await.unwrap();
        let result =
            tokio::time::timeout(std::time::Duration::from_secs(2), refused.read(&mut [0]))
                .await
                .unwrap();
        assert!(
            matches!(result, Ok(0))
                || result.is_err_and(|e| e.kind() == std::io::ErrorKind::ConnectionReset)
        );
        drop(refused);
        drop(connections.pop());
        wait_for_slots(&slots, 1).await;
        connections.push(TcpStream::connect(listener.address).await.unwrap());
        wait_for_slots(&slots, 0).await;
        listener.stop.send(true).unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            while !listener.task.is_finished() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        for mut socket in connections {
            let result =
                tokio::time::timeout(std::time::Duration::from_secs(2), socket.read(&mut [0]))
                    .await
                    .unwrap();
            assert!(
                matches!(result, Ok(0))
                    || result.is_err_and(|e| e.kind() == std::io::ErrorKind::ConnectionReset)
            );
        }
        wait_for_slots(&slots, CAPACITY).await;
    }

    async fn wait_for_slots(slots: &tokio::sync::Semaphore, expected: usize) {
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            while slots.available_permits() != expected {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("connection permits must converge after accept, disconnect or stop");
    }
}
