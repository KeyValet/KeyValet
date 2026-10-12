use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
};

use serde_json::Value;
use tokio::io::{AsyncRead, ReadBuf};

use super::*;

struct FailingIo {
    flush_only: bool,
}

impl AsyncWrite for FailingIo {
    fn poll_write(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        Poll::Ready(if self.flush_only {
            Ok(bytes.len())
        } else {
            Err(io::Error::from(io::ErrorKind::BrokenPipe))
        })
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Err(io::Error::from(io::ErrorKind::BrokenPipe)))
    }
    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

impl AsyncRead for FailingIo {
    fn poll_read(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        _: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Poll::Ready(Err(io::Error::from(io::ErrorKind::ConnectionReset)))
    }
}

struct Unserializable;
impl Serialize for Unserializable {
    fn serialize<S: serde::Serializer>(&self, _: S) -> std::result::Result<S::Ok, S::Error> {
        Err(serde::ser::Error::custom("peer secret must not escape"))
    }
}

#[tokio::test]
async fn json_lines_handle_serialization_limits_io_failures_and_eof() {
    let mut writer = tokio::io::sink();
    write_json(&mut writer, &Value::Null).await.unwrap();
    assert!(matches!(
        write_json(
            &mut writer,
            &serde_json::json!("A".repeat(kv_ipc::MAX_LINE_BYTES))
        )
        .await,
        Err(Error::HelperProtocol)
    ));
    assert!(matches!(
        write_json(&mut writer, &Unserializable).await,
        Err(Error::HelperProtocol)
    ));
    assert!(matches!(
        write_json(&mut writer, &"A".repeat(kv_ipc::MAX_LINE_BYTES)).await,
        Err(Error::HelperProtocol)
    ));
    for flush_only in [false, true] {
        assert!(matches!(
            write_json(&mut FailingIo { flush_only }, &Value::Null).await,
            Err(Error::HelperUnavailable)
        ));
    }
    assert!(matches!(
        read_json::<Value>(&mut BufReader::new(FailingIo { flush_only: false })).await,
        Err(Error::HelperUnavailable)
    ));
    for bytes in [b"".as_slice(), b"invalid\n", b"{}", b"{\"v\":1}\n"] {
        let result = read_json::<Value>(&mut BufReader::new(bytes)).await;
        if bytes.ends_with(b"\n") && bytes.starts_with(b"{") {
            assert_eq!(result.unwrap()["v"], 1);
        } else {
            assert!(matches!(result, Err(Error::HelperProtocol)));
        }
    }
}

#[tokio::test]
async fn helper_exchange_propagates_greeting_and_request_write_failures() {
    for handshake in [false, true] {
        let helper = Helper::for_test(PathBuf::new(), handshake);
        assert!(matches!(
            helper
                .exchange_on::<Value>(Box::new(FailingIo { flush_only: false }), &Value::Null)
                .await,
            Err(Error::HelperUnavailable)
        ));
    }
}

#[cfg(unix)]
struct Unary {
    helper: Helper,
    _directory: tempfile::TempDir,
    task: tokio::task::JoinHandle<()>,
}

#[cfg(unix)]
impl Unary {
    async fn start(reply: Value, greeting: Option<Value>) -> Self {
        let directory = tempfile::tempdir().unwrap();
        let endpoint = directory.path().join("unary.sock");
        let listener = tokio::net::UnixListener::bind(&endpoint).unwrap();
        let handshake = greeting.is_some();
        let task = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut stream = BufReader::new(stream);
            if let Some(greeting) = greeting {
                let _: Value = read_json(&mut stream).await.unwrap();
                write_json(&mut stream, &greeting).await.unwrap();
            }
            if read_json::<Value>(&mut stream).await.is_ok() {
                let _ = write_json(&mut stream, &reply).await;
            }
        });
        Self {
            helper: Helper::for_test(endpoint, handshake),
            _directory: directory,
            task,
        }
    }
}

#[cfg(unix)]
impl Drop for Unary {
    fn drop(&mut self) {
        self.task.abort();
    }
}

#[cfg(unix)]
#[tokio::test]
async fn ipc_wrapper_rejects_ambiguous_results_and_unapproved_handshakes() {
    let unary = Unary::start(
        serde_json::json!({"ok":true,"result":{"public":"value"}}),
        Some(serde_json::json!({"ready":true,"protocol":4})),
    )
    .await;
    assert_eq!(
        unary
            .helper
            .exchange::<Value>(&Value::Null, Duration::ZERO)
            .await
            .unwrap(),
        serde_json::json!({"public":"value"})
    );
    for reply in [
        serde_json::json!("not a response object"),
        serde_json::json!({"ok":true}),
        serde_json::json!({"ok":false}),
        serde_json::json!({"ok":true,"result":{},"error":{"code":"bad","message":"secret"}}),
        serde_json::json!({"ok":false,"result":{},"error":{"code":"bad","message":"secret"}}),
        serde_json::json!({"ok":true,"result":null}),
    ] {
        let unary = Unary::start(reply, None).await;
        assert!(matches!(
            unary
                .helper
                .exchange::<Value>(&Value::Null, Duration::ZERO)
                .await,
            Err(Error::HelperProtocol)
        ));
    }
    for greeting in [
        serde_json::json!({"ready":true,"protocol":3}),
        serde_json::json!({"ready":false,"reason":"secret"}),
    ] {
        let unary = Unary::start(serde_json::json!({"ok":true,"result":{}}), Some(greeting)).await;
        assert!(matches!(
            unary
                .helper
                .exchange::<Value>(&Value::Null, Duration::ZERO)
                .await,
            Err(Error::HelperProtocol)
        ));
    }
    let unary = Unary::start(
        serde_json::json!({"ok":false,"error":{"code":"secret","message":"secret"}}),
        None,
    )
    .await;
    assert!(matches!(
        unary
            .helper
            .exchange::<Value>(&Value::Null, Duration::ZERO)
            .await,
        Err(Error::HelperRejected)
    ));
    let unary = Unary::start(
        serde_json::json!({"ok":false,"error":{"code":"failed","message":"secret"}}),
        None,
    )
    .await;
    let state = remote::RelayStatusParams {
        connected: false,
        last_error: None,
        since: 0,
        extra: Extra::new(),
    };
    assert!(matches!(
        unary.helper.status(state).await,
        Err(Error::HelperRejected)
    ));
}

#[cfg(unix)]
#[tokio::test]
async fn identity_requires_only_a_public_p256_representation() {
    let public = serde_json::json!({"kty":"EC","crv":"P-256","x":URL_SAFE_NO_PAD.encode([1;32]),"y":URL_SAFE_NO_PAD.encode([2;32])});
    for (field, value) in [
        ("kty", serde_json::json!("RSA")),
        ("crv", serde_json::json!("P-384")),
        ("d", serde_json::json!("private")),
        ("x", serde_json::json!("bad==")),
        ("y", serde_json::json!("AA")),
        ("x", Value::Null),
    ] {
        let mut invalid = public.clone();
        invalid[field] = value;
        let unary = Unary::start(
            serde_json::json!({"ok":true,"result":{"dk_pub":invalid,"device_id":"dev-client","account_id":"acct-test"}}),
            None,
        )
        .await;
        assert!(matches!(
            unary.helper.identity().await,
            Err(Error::IdentityUnavailable)
        ));
    }
    let unary = Unary::start(
        serde_json::json!({"ok":true,"result":{"dk_pub":public,"device_id":"dev-client","account_id":"acct-test"}}),
        None,
    )
    .await;
    unary.helper.identity().await.unwrap();
    let unary = Unary::start(
        serde_json::json!({"ok":false,"error":{"code":"missing","message":"secret"}}),
        None,
    )
    .await;
    assert!(matches!(
        unary.helper.identity().await,
        Err(Error::IdentityUnavailable)
    ));
}

#[cfg(unix)]
#[tokio::test]
async fn outbox_receipts_reject_unbounded_or_inconsistent_retired_counts() {
    use remote::OutboundStage::{Accepted, Inspect, Spooled};
    let envelope = crate::tests::harness::envelope(1, "presence_hint");
    for (stage, count, valid) in [
        (Spooled, 0, true),
        (Accepted, 0, true),
        (Inspect, 1, true),
        (Spooled, 1, false),
        (Accepted, 1, false),
        (Inspect, 2, false),
    ] {
        let unary = Unary::start(
            serde_json::json!({"ok":true,"result":{"retired_count":count}}),
            None,
        )
        .await;
        let result = unary
            .helper
            .receipt(std::slice::from_ref(&envelope), stage)
            .await;
        if valid {
            assert_eq!(result.unwrap(), count);
        } else {
            assert!(matches!(result, Err(Error::HelperProtocol)));
        }
    }
    let unary = Unary::start(serde_json::json!({"ok":false,"error":{"code":"unknown_outbox_receipt","message":"unknown"}}),None).await;
    assert!(matches!(
        unary.helper.receipt(&[envelope], Accepted).await,
        Err(Error::HelperRejected)
    ));
}

#[cfg(unix)]
#[tokio::test]
async fn identity_signature_fails_closed_on_invalid_encoding_or_helper_error() {
    for sig in ["", "bad=="] {
        let unary = Unary::start(
            serde_json::json!({"ok":true,"result":{"sig_b64":sig}}),
            None,
        )
        .await;
        assert!(matches!(
            unary.helper.sign("AA".into()).await,
            Err(Error::HelperProtocol)
        ));
    }
    let unary = Unary::start(
        serde_json::json!({"ok":false,"error":{"code":"failed","message":"secret"}}),
        None,
    )
    .await;
    assert!(matches!(
        unary.helper.sign("AA".into()).await,
        Err(Error::IdentityUnavailable)
    ));
}

#[cfg(unix)]
#[tokio::test(start_paused = true)]
async fn helper_timeout_and_unavailable_socket_are_retriable() {
    let directory = tempfile::tempdir().unwrap();
    let endpoint = directory.path().join("stalled.sock");
    let helper = Helper::for_test(endpoint.clone(), false);
    assert!(matches!(helper.poll().await, Err(Error::HelperUnavailable)));
    let listener = tokio::net::UnixListener::bind(endpoint).unwrap();
    let task = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut stream = BufReader::new(stream);
        let _: Value = read_json(&mut stream).await.unwrap();
        std::future::pending::<()>().await;
    });
    assert!(matches!(
        helper.exchange::<Value>(&Value::Null, Duration::ZERO).await,
        Err(Error::HelperUnavailable)
    ));
    task.abort();
}
