use bytes::Bytes;
use futures_util::future::BoxFuture;
use http_body_util::BodyExt;
use kv_proxy::approval::{self, ApprovalLayer, ApprovalProvider, ApprovalRequest};
use serde_json::{json, Value};
use std::sync::Arc;
use std::time::Duration;

const ID: &str = "01J00000000000000000000000";
struct FakeHelper {
    approve_after: Option<Duration>,
}
impl ApprovalProvider for FakeHelper {
    fn authorize(&self, _request: ApprovalRequest) -> BoxFuture<'_, Result<Value, String>> {
        Box::pin(async {
            Ok(
                json!({"status": "approval_pending", "approval_id": ID, "approver": {"label": "Fixture MacBook", "online": true}}),
            )
        })
    }
    fn wait(
        &self,
        _approval_id: String,
        max_wait: Duration,
    ) -> BoxFuture<'_, Result<Value, String>> {
        Box::pin(async move {
            match self.approve_after {
                Some(delay) => {
                    tokio::time::sleep(delay).await;
                    Ok(json!({"status": "ok"}))
                }
                None => {
                    tokio::time::sleep(max_wait).await;
                    Ok(json!({"status": "still_pending", "approval_id": ID}))
                }
            }
        })
    }
}

fn request() -> ApprovalRequest {
    ApprovalRequest {
        credential_type: "api_key".into(),
        credential_name: "fixture".into(),
        method: "POST".into(),
        url: "https://example.test/request".into(),
        headers: Default::default(),
        body: Bytes::from_static(b"synthetic request"),
        purpose: Some("Synthetic approval test".into()),
    }
}

struct ScriptedProvider {
    initial: Result<Value, String>,
    waited: Result<Value, String>,
    initial_delay: Duration,
    wait_delay: Duration,
}
impl ApprovalProvider for ScriptedProvider {
    fn authorize(&self, _: ApprovalRequest) -> BoxFuture<'_, Result<Value, String>> {
        Box::pin(async {
            tokio::time::sleep(self.initial_delay).await;
            self.initial.clone()
        })
    }
    fn wait(&self, _: String, _: Duration) -> BoxFuture<'_, Result<Value, String>> {
        Box::pin(async {
            tokio::time::sleep(self.wait_delay).await;
            self.waited.clone()
        })
    }
}
fn scripted_layer(
    initial: Result<Value, String>,
    waited: Result<Value, String>,
    initial_delay: Duration,
    wait_delay: Duration,
) -> ApprovalLayer {
    ApprovalLayer {
        provider: Arc::new(ScriptedProvider {
            initial,
            waited,
            initial_delay,
            wait_delay,
        }),
        http_wait: Duration::from_secs(1),
        notice: None,
    }
}

#[tokio::test(start_paused = true)]
async fn terminal_offline_malformed_and_transport_results_follow_the_wait_contract() {
    let pending = json!({"status": "approval_pending", "approval_id": ID});
    for state in ["approval_denied", "approval_expired", "no_approver", "ok"] {
        let layer = scripted_layer(
            Ok(json!({"status": state})),
            Err("must not wait".into()),
            Duration::ZERO,
            Duration::ZERO,
        );
        assert_eq!(
            layer.authorize(request(), None).await.unwrap()["status"],
            state
        );
    }
    let layer = scripted_layer(
        Ok(json!({"status": "approval_pending", "approval_id": ID, "relay": "offline"})),
        Err("must not wait".into()),
        Duration::ZERO,
        Duration::ZERO,
    );
    assert!(approval::is_pending(
        &layer.authorize(request(), None).await.unwrap()
    ));
    for initial in [
        Err("disconnected".into()),
        Ok(json!({"status": "approval_pending", "approval_id": "bad"})),
    ] {
        assert!(
            scripted_layer(initial, Ok(pending.clone()), Duration::ZERO, Duration::ZERO)
                .authorize(request(), None)
                .await
                .is_err()
        );
    }
    for waited in [
        Err("disconnected".into()),
        Ok(json!({"status": "still_pending", "approval_id": "changed"})),
    ] {
        assert!(
            scripted_layer(Ok(pending.clone()), waited, Duration::ZERO, Duration::ZERO)
                .authorize(request(), None)
                .await
                .is_err()
        );
    }
    for waited in [
        Err("Remote wait timed out".into()),
        Err("Timeout".into()),
        Ok(pending.clone()),
    ] {
        let value = scripted_layer(Ok(pending.clone()), waited, Duration::ZERO, Duration::ZERO)
            .authorize(request(), None)
            .await
            .unwrap();
        assert!(approval::is_pending(&value));
    }
    let started = tokio::time::Instant::now();
    assert!(scripted_layer(
        Ok(pending.clone()),
        Ok(pending.clone()),
        Duration::from_secs(30),
        Duration::ZERO
    )
    .authorize(request(), None)
    .await
    .is_err());
    assert_eq!(started.elapsed(), Duration::from_secs(1));
    assert!(approval::is_pending(
        &scripted_layer(
            Ok(pending.clone()),
            Ok(pending),
            Duration::ZERO,
            Duration::from_secs(30)
        )
        .authorize(request(), None)
        .await
        .unwrap()
    ));
    let mut output = Vec::new();
    approval::write_wait_notice(&mut output, "Device\n\r\u{1b}").unwrap();
    assert_eq!(String::from_utf8(output).unwrap().lines().count(), 1);
}

#[tokio::test]
async fn approved_http_results_and_terminal_errors_are_validated_without_replaying_http() {
    assert!(approval::http_response(&json!({"status": "ok"}))
        .unwrap()
        .is_none());
    assert!(
        approval::http_response(&json!({"status": "ok", "result": null}))
            .unwrap()
            .is_none()
    );
    for (state, status) in [
        ("approval_denied", 403),
        ("approval_cancelled", 409),
        ("approval_expired", 410),
        ("no_approver", 503),
    ] {
        let response = approval::http_response(&json!({"status": state, "approval_id": ID}))
            .unwrap()
            .unwrap();
        assert_eq!(response.status().as_u16(), status);
        assert_eq!(response.headers()["x-should-retry"], "false");
        let body: Value =
            serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes())
                .unwrap();
        assert_eq!(body["error"]["type"], format!("keyvalet_{state}"));
        assert_eq!(body["error"]["approval_id"], ID);
    }
    assert_eq!(
        approval::http_response(&json!({"status":"already_consumed"}))
            .unwrap_err()
            .status,
        502
    );
    let response =
        approval::http_response(&json!({"status": "approval_pending", "approval_id": ID}))
            .unwrap()
            .unwrap();
    assert_eq!(response.status(), 429);
    assert_eq!(
        approval::http_response(&json!({"status": "still_pending", "approval_id": "bad"}))
            .unwrap_err()
            .status,
        502
    );
    let response = approval::http_response(&json!({"status": "ok", "result": {"status": 201, "body": "SGVsbG8=", "body_encoding": "base64", "headers": {"content-type": "text/plain", "set-cookie": "redacted", "connection": "close", "x-fixture": 123}}})).unwrap().unwrap();
    assert_eq!(response.status(), 201);
    assert_eq!(response.headers()["content-type"], "text/plain");
    assert!(response.headers().get("set-cookie").is_none());
    assert_eq!(
        response.into_body().collect().await.unwrap().to_bytes(),
        "Hello"
    );
    let response = approval::http_response(
        &json!({"status": "ok", "result": {"status": 200, "body": "plain"}}),
    )
    .unwrap()
    .unwrap();
    assert_eq!(
        response.into_body().collect().await.unwrap().to_bytes(),
        "plain"
    );
    for result in [
        json!({"status": 99999, "body": "x"}),
        json!({"status": 99, "body": "x"}),
        json!({"status": 200}),
        json!({"status": 200, "body": "!", "body_encoding": "base64"}),
        json!({"status": 200, "body": "x", "headers": {"x-bad": "\n"}}),
    ] {
        assert!(approval::http_response(&json!({"status": "ok", "result": result})).is_err());
    }
}

#[tokio::test]
async fn transparent_adapter_waits_silently_and_forwards_only_authorization_only_results() {
    use http_body_util::Full;
    use hyper::Response;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::io::AsyncReadExt;
    let pending = json!({"status": "approval_pending", "approval_id": ID});
    for (decision, expected, forwards) in [
        (json!({"status": "ok"}), 200, 1),
        (
            json!({"status": "ok", "result": {"status": 201, "body": "retained"}}),
            201,
            0,
        ),
        (pending.clone(), 429, 0),
    ] {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut client = tokio::net::TcpStream::connect(listener.local_addr().unwrap())
            .await
            .unwrap();
        let (stream, _) = listener.accept().await.unwrap();
        let layer = scripted_layer(
            Ok(pending.clone()),
            Ok(decision),
            Duration::ZERO,
            Duration::from_millis(40),
        );
        let count = Arc::new(AtomicUsize::new(0));
        let counted = count.clone();
        let task = tokio::spawn(async move {
            kv_proxy::transparent::forward_after_approval(
                &stream,
                &layer,
                request(),
                Some(61),
                || async {
                    counted.fetch_add(1, Ordering::SeqCst);
                    Ok(Response::new(
                        Full::new(Bytes::from_static(b"forwarded"))
                            .map_err(|never| match never {})
                            .boxed(),
                    ))
                },
            )
            .await
        });
        let mut byte = [0];
        assert!(
            tokio::time::timeout(Duration::from_millis(20), client.read(&mut byte))
                .await
                .is_err()
        );
        assert_eq!(task.await.unwrap().unwrap().status(), expected);
        assert_eq!(count.load(Ordering::SeqCst), forwards);
    }
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let _client = tokio::net::TcpStream::connect(listener.local_addr().unwrap())
        .await
        .unwrap();
    let (stream, _) = listener.accept().await.unwrap();
    for decision in [Err("offline".into())] {
        let layer = scripted_layer(
            decision,
            Err("unused".into()),
            Duration::ZERO,
            Duration::ZERO,
        );
        assert!(kv_proxy::transparent::forward_after_approval(
            &stream,
            &layer,
            request(),
            None,
            || async { panic!("Must not forward") }
        )
        .await
        .is_err());
    }
    for (state, status) in [
        ("approval_denied", 403),
        ("approval_cancelled", 409),
        ("approval_expired", 410),
    ] {
        let layer = scripted_layer(
            Ok(json!({"status":state,"approval_id":ID})),
            Err("unused".into()),
            Duration::ZERO,
            Duration::ZERO,
        );
        let response = kv_proxy::transparent::forward_after_approval(
            &stream,
            &layer,
            request(),
            None,
            || async { panic!("Must not forward a terminal outcome") },
        )
        .await
        .unwrap();
        assert_eq!(response.status(), status);
        let body: Value =
            serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes())
                .unwrap();
        assert_eq!(body["error"]["type"], format!("keyvalet_{state}"));
    }
}

#[tokio::test]
async fn typed_local_outcomes_are_distinct_and_a_transport_timeout_remains_pending() {
    let layer = scripted_layer(
        Ok(json!({"status":"approval_expired","reason":"cancelled","approval_id":ID})),
        Err("must not wait".into()),
        Duration::ZERO,
        Duration::ZERO,
    );
    assert_eq!(
        layer.authorize(request(), None).await.unwrap()["status"],
        "approval_cancelled"
    );
    for (code, state) in [
        ("local_approval_denied", "approval_denied"),
        ("local_approval_cancelled", "approval_cancelled"),
        ("local_approval_expired", "approval_expired"),
    ] {
        let layer = scripted_layer(
            Err(json!({"code":code,"approval_id":ID}).to_string()),
            Err("must not wait".into()),
            Duration::ZERO,
            Duration::ZERO,
        );
        assert_eq!(
            layer.authorize(request(), None).await.unwrap()["status"],
            state
        );
    }
    let layer = scripted_layer(
        Ok(json!({"status":"approval_pending","approval_id":ID})),
        Err("Local approval wait timed out".into()),
        Duration::ZERO,
        Duration::ZERO,
    );
    assert_eq!(
        layer.authorize(request(), None).await.unwrap()["status"],
        "approval_pending"
    );
    for (expiry, state) in [(0, "approval_expired"), (i64::MAX, "approval_pending")] {
        let layer = scripted_layer(
            Err(
                json!({"code":"local_approval_timeout","approval_id":ID,"expires_at":expiry})
                    .to_string(),
            ),
            Err("Transport wait timed out".into()),
            Duration::ZERO,
            Duration::ZERO,
        );
        assert_eq!(
            layer.authorize(request(), None).await.unwrap()["status"],
            state
        );
    }
}

#[tokio::test(start_paused = true)]
async fn host_hints_and_policy_cap_waiting_without_turning_timeout_into_denial() {
    assert_eq!(
        approval::http_wait_limit(approval::HTTP_WAIT, Some(600)),
        Duration::from_secs(540)
    );
    assert_eq!(
        approval::http_wait_limit(approval::HTTP_WAIT, None),
        Duration::from_secs(55)
    );
    assert_eq!(
        approval::http_wait_limit(approval::HTTP_WAIT, Some(60)),
        Duration::ZERO
    );
    assert_eq!(
        approval::http_wait_limit(Duration::from_secs(30), Some(600)),
        Duration::from_secs(30)
    );
    let layer = ApprovalLayer {
        provider: Arc::new(FakeHelper {
            approve_after: None,
        }),
        http_wait: approval::HTTP_WAIT,
        notice: None,
    };
    for (hint, expected) in [(None, 55), (Some(600), 540), (Some(65), 5)] {
        let started = tokio::time::Instant::now();
        let result = layer.authorize(request(), hint).await.unwrap();
        assert!(approval::is_pending(&result));
        assert_eq!(started.elapsed(), Duration::from_secs(expected));
    }
}

#[tokio::test(start_paused = true)]
async fn approval_during_the_wait_continues_and_emits_one_stderr_notice() {
    let notices = Arc::new(std::sync::Mutex::new(Vec::new()));
    let captured = notices.clone();
    let layer = ApprovalLayer {
        provider: Arc::new(FakeHelper {
            approve_after: Some(Duration::from_secs(180)),
        }),
        http_wait: approval::HTTP_WAIT,
        notice: Some(Arc::new(move |label, id| {
            assert_eq!(id, ID);
            approval::write_wait_notice(&mut *captured.lock().unwrap(), label).unwrap();
        })),
    };
    let started = tokio::time::Instant::now();
    assert_eq!(
        layer.authorize(request(), Some(600)).await.unwrap()["status"],
        "ok"
    );
    assert_eq!(started.elapsed(), Duration::from_secs(180));
    let output = String::from_utf8(notices.lock().unwrap().clone()).unwrap();
    assert_eq!(output.lines().count(), 1);
    assert!(output.contains("KeyValet:") && output.contains("Fixture MacBook"));
}

#[tokio::test]
async fn pending_http_response_has_the_exact_retry_contract() {
    let response = approval::pending_response(ID).unwrap();
    assert_eq!(response.status(), 429);
    assert_eq!(response.headers()["retry-after"], "30");
    assert_eq!(
        response.headers()["x-keyvalet-approval"],
        format!("pending; id={ID}")
    );
    let body = response.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(
        serde_json::from_slice::<Value>(&body).unwrap(),
        json!({"error": {"type": "keyvalet_approval_pending", "approval_id": ID}})
    );
    assert!(approval::pending_response("bad\r\nheader").is_err());
}

#[cfg(unix)]
#[tokio::test]
async fn keepalives_use_kernel_options_and_never_send_application_bytes() {
    use std::os::fd::AsRawFd;
    use tokio::io::AsyncReadExt;
    unsafe extern "C" {
        fn getsockopt(
            fd: i32,
            level: i32,
            name: i32,
            value: *mut std::ffi::c_void,
            len: *mut u32,
        ) -> i32;
    }
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mut client = tokio::net::TcpStream::connect(listener.local_addr().unwrap())
        .await
        .unwrap();
    let (stream, _) = listener.accept().await.unwrap();
    approval::configure_keepalive(&stream).unwrap();
    #[cfg(target_os = "macos")]
    let options = [(0xffff, 8, 1), (6, 0x10, 20), (6, 0x101, 20)];
    #[cfg(target_os = "linux")]
    let options = [(1, 9, 1), (6, 4, 20), (6, 5, 20)];
    for (level, option, expected) in options {
        let mut value = 0i32;
        let mut size = 4u32;
        // SAFETY: a four-byte integer buffer is valid for these socket options.
        assert_eq!(
            unsafe {
                getsockopt(
                    stream.as_raw_fd(),
                    level,
                    option,
                    (&mut value as *mut i32).cast(),
                    &mut size,
                )
            },
            0
        );
        if expected == 1 {
            assert_ne!(value, 0);
        } else {
            assert_eq!(value, expected);
        }
    }
    assert!(
        tokio::time::timeout(Duration::from_millis(30), client.read(&mut [0u8; 1]))
            .await
            .is_err()
    );
}
