use std::{
    collections::VecDeque,
    sync::{Arc, Mutex},
};

use serde_json::{json, Value};
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
    net::TcpListener,
    task::JoinHandle,
};

use super::*;
use crate::tests::harness::{envelope, FakeHelper};

#[derive(Clone)]
pub(crate) struct HttpReply(pub Vec<u8>);

impl HttpReply {
    pub(crate) fn json(value: Value) -> Self {
        let bytes = serde_json::to_vec(&value).unwrap();
        Self(format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n{}", bytes.len(), String::from_utf8(bytes).unwrap()).into_bytes())
    }
}

pub(crate) struct HttpFixture {
    pub(crate) config: Config,
    pub(crate) requests: Arc<Mutex<Vec<(String, Value)>>>,
    task: JoinHandle<()>,
}

impl HttpFixture {
    pub(crate) async fn start(replies: Vec<HttpReply>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let config = Config {
            relay_url: format!("http://{}/", listener.local_addr().unwrap()),
            device_id: "dev-client".into(),
            account_id: "acct-test".into(),
        };
        let requests = Arc::new(Mutex::new(Vec::new()));
        let task_requests = requests.clone();
        let task = tokio::spawn(async move {
            let mut replies: VecDeque<_> = replies.into();
            while let Some(reply) = replies.pop_front() {
                let (stream, _) = listener.accept().await.unwrap();
                let mut stream = BufReader::new(stream);
                let mut first = String::new();
                stream.read_line(&mut first).await.unwrap();
                let mut length = 0;
                loop {
                    let mut header = String::new();
                    stream.read_line(&mut header).await.unwrap();
                    if header == "\r\n" {
                        break;
                    }
                    let (name, value) = header.split_once(':').unwrap();
                    if name.eq_ignore_ascii_case("content-length") {
                        length = value.trim().parse().unwrap();
                    }
                }
                let mut bytes = vec![0; length];
                stream.read_exact(&mut bytes).await.unwrap();
                let body = if bytes.is_empty() {
                    Value::Null
                } else {
                    serde_json::from_slice(&bytes).unwrap()
                };
                task_requests
                    .lock()
                    .unwrap()
                    .push((first.split_whitespace().nth(1).unwrap().into(), body));
                let _ = stream.write_all(&reply.0).await;
                let _ = stream.shutdown().await;
            }
        });
        Self {
            config,
            requests,
            task,
        }
    }
}

impl Drop for HttpFixture {
    fn drop(&mut self) {
        self.task.abort();
    }
}

fn session() -> Session {
    Session {
        token: "session-test".into(),
        exp: unix_now() + 3600,
    }
}

#[tokio::test]
async fn response_bounds_handle_declared_chunked_truncated_and_invalid_bodies() {
    for (reply, limit, expected) in [
        (
            HttpReply(b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n{}".to_vec()),
            5,
            "relay_protocol_error",
        ),
        (
            HttpReply(
                b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n6\r\n[1, 2]\r\n0\r\n\r\n"
                    .to_vec(),
            ),
            5,
            "relay_protocol_error",
        ),
        (
            HttpReply(b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\n{}".to_vec()),
            100,
            "relay_unreachable",
        ),
        (
            HttpReply(b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nbad".to_vec()),
            100,
            "relay_protocol_error",
        ),
        (
            HttpReply(
                b"HTTP/1.1 503 Unavailable\r\nRetry-After: 8\r\nContent-Length: 0\r\n\r\n".to_vec(),
            ),
            100,
            "relay_http_503",
        ),
    ] {
        let server = HttpFixture::start(vec![reply]).await;
        let error =
            Relay::response::<Value>(reqwest::Client::new().get(&server.config.relay_url), limit)
                .await
                .unwrap_err();
        assert_eq!(error.to_string(), expected);
        if expected == "relay_http_503" {
            assert_eq!(error.retry_after(), Some(Duration::from_secs(8)));
        }
    }
}

#[tokio::test]
async fn expired_and_malformed_challenges_never_reach_helper_signing() {
    let helper = FakeHelper::start(Arc::new(Mutex::new(Vec::new())), false).await;
    for value in [
        json!({"challenge":URL_SAFE_NO_PAD.encode([9;32]),"exp":0}),
        json!({"challenge":"AA","exp":unix_now()+60}),
        json!({"challenge":"bad==","exp":unix_now()+60}),
    ] {
        let server = HttpFixture::start(vec![HttpReply::json(value)]).await;
        let relay = Relay::new(&server.config).unwrap();
        assert!(matches!(
            relay.authenticate(&helper.client(false)).await,
            Err(Error::RelayProtocol)
        ));
    }
    assert!(helper.data.lock().unwrap().signed.is_empty());
}

#[tokio::test]
async fn helper_identity_must_match_both_configured_device_and_account_before_network_auth() {
    let helper = FakeHelper::start(Arc::new(Mutex::new(Vec::new())), false).await;
    let config = Config {
        relay_url: "http://127.0.0.1:1/".into(),
        device_id: "dev-client".into(),
        account_id: "acct-test".into(),
    };
    let relay = Relay::new(&config).unwrap();
    for device_mismatch in [true, false] {
        {
            let mut data = helper.data.lock().unwrap();
            data.device_id = if device_mismatch {
                "different-device"
            } else {
                "dev-client"
            }
            .into();
            data.account_id = if device_mismatch {
                "acct-test"
            } else {
                "different-account"
            }
            .into();
        }
        assert!(matches!(
            relay.authenticate(&helper.client(false)).await,
            Err(Error::IdentityUnavailable)
        ));
    }
    assert!(helper.data.lock().unwrap().signed.is_empty());
}

#[tokio::test]
async fn verify_rejects_empty_oversized_or_imminently_expired_sessions() {
    let helper = FakeHelper::start(Arc::new(Mutex::new(Vec::new())), false).await;
    for value in [
        json!({"session_token":"","exp":unix_now()+3600}),
        json!({"session_token":"A".repeat(4097),"exp":unix_now()+3600}),
        json!({"session_token":"valid","exp":unix_now()+60}),
    ] {
        let server = HttpFixture::start(vec![
            HttpReply::json(
                json!({"challenge":URL_SAFE_NO_PAD.encode([9;32]),"exp":unix_now()+60}),
            ),
            HttpReply::json(value),
        ])
        .await;
        let relay = Relay::new(&server.config).unwrap();
        assert!(matches!(
            relay.authenticate(&helper.client(false)).await,
            Err(Error::RelayProtocol)
        ));
    }
    assert_eq!(helper.data.lock().unwrap().signed.len(), 3);
}

#[tokio::test]
async fn websocket_handshake_honors_http_cooldown_and_requires_negotiated_subprotocol() {
    let server = HttpFixture::start(vec![HttpReply(
        b"HTTP/1.1 429 Limited\r\nRetry-After: 3\r\nContent-Length: 0\r\n\r\n".to_vec(),
    )])
    .await;
    let relay = Relay::new(&server.config).unwrap();
    let error = relay.socket(&session()).await.err().unwrap();
    assert_eq!(error.to_string(), "relay_http_429");
    assert_eq!(error.retry_after(), Some(Duration::from_secs(3)));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let config = Config {
        relay_url: format!("http://{}/", listener.local_addr().unwrap()),
        ..server.config.clone()
    };
    let task = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let socket = tokio_tungstenite::accept_async(stream).await.unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;
        drop(socket);
    });
    assert!(matches!(
        Relay::new(&config).unwrap().socket(&session()).await,
        Err(Error::RelayProtocol)
    ));
    task.abort();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let config = Config {
        relay_url: format!("http://{}/", listener.local_addr().unwrap()),
        ..config
    };
    drop(listener);
    assert!(matches!(
        Relay::new(&config).unwrap().socket(&session()).await,
        Err(Error::Network)
    ));
}

#[tokio::test]
async fn https_uses_wss_and_rejects_tokens_with_header_control_characters() {
    let config = Config {
        relay_url: "https://relay.example.com/".into(),
        device_id: "dev".into(),
        account_id: "acct".into(),
    };
    let relay = Relay::new(&config).unwrap();
    let session = Session {
        token: "bad\r\ntoken".into(),
        exp: unix_now() + 3600,
    };
    assert!(matches!(
        relay.socket(&session).await,
        Err(Error::RelayProtocol)
    ));
    assert!(matches!(
        relay.waiting(&session).await,
        Err(Error::RelayProtocol)
    ));
}

#[tokio::test]
async fn wss_constructs_tls_with_unified_workspace_crypto_features_and_rejects_a_plain_peer() {
    use tokio::io::AsyncReadExt;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let relay = Relay::new(&Config {
        relay_url: format!("https://{}/", listener.local_addr().unwrap()),
        device_id: "dev-client".into(),
        account_id: "acct-test".into(),
    })
    .unwrap();
    let peer = tokio::spawn(async move {
        let (mut connection, _) = listener.accept().await.unwrap();
        let mut record = [0; 5];
        connection.read_exact(&mut record).await.unwrap();
        assert_eq!(record[0], 22); // TLS handshake record, never a plaintext WS upgrade.
    });
    assert!(matches!(
        relay.socket(&session()).await,
        Err(Error::Network)
    ));
    peer.await.unwrap();
}

#[tokio::test]
async fn replies_cancellations_and_acks_require_explicit_success() {
    let server = HttpFixture::start(vec![
        HttpReply::json(json!({"ok":false})),
        HttpReply::json(json!({"ok":true})),
        HttpReply::json(json!({"ok":false})),
        HttpReply::json(json!({"ok":true})),
        HttpReply::json(json!({"ok":false})),
        HttpReply::json(json!({"ok":true})),
    ])
    .await;
    let relay = Relay::new(&server.config).unwrap();
    let session = session();
    for route in [
        Route::Reply("a/b ?#".into()),
        Route::Cancel("approval-1".into()),
    ] {
        let group = Group { count: 1, route };
        assert!(matches!(
            relay
                .send(&session, &group, &[envelope(1, "approval_decision")])
                .await,
            Err(Error::RelayProtocol)
        ));
        relay
            .send(&session, &group, &[envelope(1, "approval_decision")])
            .await
            .unwrap();
    }
    assert!(matches!(
        relay.ack(&session, "inbound-1", "approval_request").await,
        Err(Error::RelayProtocol)
    ));
    relay
        .ack(&session, "inbound-1", "approval_request")
        .await
        .unwrap();
    let requests = server.requests.lock().unwrap();
    assert_eq!(requests[0].0, "/v1/approvals/a%2Fb%20%3F%23/reply");
    assert_eq!(requests[0].1["envelope"]["ct"], "ZW5jcnlwdGVk");
    assert_eq!(requests[2].0, "/v1/approvals/approval-1/cancel");
    assert_eq!(requests[2].1["envelope"]["ct"], "ZW5jcnlwdGVk");
    assert_eq!(
        requests[4].1,
        json!({"ids":["inbound-1"],"type":"approval_request"})
    );
}

#[tokio::test]
async fn empty_or_inconsistent_groups_fail_before_network_or_indexing() {
    let config = Config {
        relay_url: "http://127.0.0.1:1/".into(),
        device_id: "dev".into(),
        account_id: "acct".into(),
    };
    let relay = Relay::new(&config).unwrap();
    let group = Group {
        count: 1,
        route: Route::Reply("id".into()),
    };
    assert!(matches!(
        relay.send(&session(), &group, &[]).await,
        Err(Error::QueueCorrupt)
    ));
    assert!(matches!(
        relay
            .send(
                &session(),
                &group,
                &[envelope(1, "grant"), envelope(2, "grant")]
            )
            .await,
        Err(Error::QueueCorrupt)
    ));
    assert!(matches!(Group::first(&[]), Err(Error::QueueCorrupt)));
    let invalid: Envelope = serde_json::from_value(json!({"type":"grant"})).unwrap();
    assert!(matches!(
        Group::first(&[invalid]),
        Err(Error::RelayProtocol)
    ));
}
