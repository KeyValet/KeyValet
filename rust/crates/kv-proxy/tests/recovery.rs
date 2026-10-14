#![cfg(unix)]
//! Real downstream disconnects, helper decisions and once-only response recovery.
use bytes::Bytes;
use futures_util::future::BoxFuture;
use kv_proxy::{
    approval::{ApprovalLayer, ApprovalProvider, ApprovalRequest},
    gateway::Gateway,
};
use kv_vault::{SetParams, Vault};
use serde_json::{json, Value};
use std::{
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    time::Duration,
};
use tokio::io::AsyncWriteExt;
use wiremock::{
    matchers::{method, path},
    Mock, MockServer, ResponseTemplate,
};

const ID: &str = "01J00000000000000000000000";
struct Decision {
    submitted: tokio::sync::Notify,
    outcome: tokio::sync::watch::Sender<Option<&'static str>>,
    authorizations: AtomicUsize,
    waits: AtomicUsize,
    expiry: i64,
}
impl Decision {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            submitted: tokio::sync::Notify::new(),
            outcome: tokio::sync::watch::channel(None).0,
            authorizations: AtomicUsize::new(0),
            waits: AtomicUsize::new(0),
            expiry: now() + 600,
        })
    }
}
fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}
impl ApprovalProvider for Decision {
    fn authorize(&self, _: ApprovalRequest) -> BoxFuture<'_, Result<Value, String>> {
        Box::pin(async move {
            self.authorizations.fetch_add(1, Ordering::SeqCst);
            self.submitted.notify_one();
            Ok(json!({"status":"approval_pending","approval_id":ID,"expires_at":self.expiry}))
        })
    }
    fn wait(&self, _: String, wait: Duration) -> BoxFuture<'_, Result<Value, String>> {
        Box::pin(async move {
            self.waits.fetch_add(1, Ordering::SeqCst);
            let mut changes = self.outcome.subscribe();
            let result = tokio::time::timeout(wait, async {
                while changes.borrow().is_none() {
                    changes.changed().await.unwrap();
                }
                let state = changes.borrow().unwrap();
                json!({"status":state,"approval_id":ID,"expires_at":self.expiry})
            })
            .await;
            Ok(result.unwrap_or_else(
                |_| json!({"status":"still_pending","approval_id":ID,"expires_at":self.expiry}),
            ))
        })
    }
}
struct Confirmation;
impl kv_platform::Confirmer for Confirmation {
    async fn confirm(&self, _: &str, _: &str) -> bool {
        true
    }
}
async fn gateway(helper: Arc<Decision>) -> (tempfile::TempDir, Gateway) {
    let dir = tempfile::tempdir().unwrap();
    let vault = Arc::new(Vault::new(dir.path().join("vault")));
    vault.prepare().unwrap();
    std::fs::write(vault.dir.join("master.key"), [7u8; 32]).unwrap();
    kv_platform::fs::set_private_permissions(&vault.dir.join("master.key")).unwrap();
    vault.init_legacy().unwrap();
    vault
        .set(SetParams {
            r#type: "api_key".into(),
            name: "fixture".into(),
            value: Some("synthetic-recovery-secret".into()),
            ..Default::default()
        })
        .unwrap();
    let inject = json!({"headers":{"Authorization":"Bearer {{value}}"}});
    let hosts = json!(["127.0.0.1"]);
    kv_proxy::manage::configure_http(
        &vault,
        kv_proxy::manage::ConfigureHttpParams {
            r#type: "api_key",
            name: "fixture",
            purpose: "fixture",
            remove: false,
            inject: Some(&inject),
            allowed_hosts: Some(&hosts),
            proxy_only: None,
            test: None,
        },
        &Confirmation,
    )
    .await
    .unwrap();
    (
        dir,
        Gateway::new(vault, Arc::new(|_| {}), None).with_approval(ApprovalLayer {
            provider: helper,
            http_wait: Duration::from_millis(50),
            notice: None,
        }),
    )
}

// This binary's tests run serially around the process-global loopback carve-out.
static LOOPBACK: std::sync::Mutex<()> = std::sync::Mutex::new(());
struct Loopback(std::sync::MutexGuard<'static, ()>);
impl Loopback {
    fn new() -> Self {
        let guard = LOOPBACK.lock().unwrap();
        kv_protocols::http::allow_insecure_loopback_for_tests(true);
        Self(guard)
    }
}
impl Drop for Loopback {
    fn drop(&mut self) {
        let _ = &self.0;
        kv_protocols::http::allow_insecure_loopback_for_tests(false)
    }
}

#[tokio::test]
async fn disconnect_during_approval_retains_exact_binary_response_and_retries_claim_it_once() {
    let _loopback = Loopback::new();
    let upstream = MockServer::start().await;
    let helper = Decision::new();
    let (_dir, gateway) = gateway(helper.clone()).await;
    let entry = gateway
        .open("api_key", "fixture", Some("Synthetic recovery"))
        .await
        .unwrap();
    let request_body = Bytes::from_static(&[0, 255, 13, 10]);
    Mock::given(method("POST"))
        .and(path("/once"))
        .and(|r: &wiremock::Request| {
            r.body == [0, 255, 13, 10] && !r.headers.contains_key("x-keyvalet-approval-id")
        })
        .respond_with(
            ResponseTemplate::new(201)
                .set_body_bytes([0, 254, 13, 10])
                .insert_header("x-fixture", "retained"),
        )
        .expect(1)
        .mount(&upstream)
        .await;
    let route = format!("/127.0.0.1:{}/once", upstream.address().port());
    let mut socket = tokio::net::TcpStream::connect(("127.0.0.1", entry.port))
        .await
        .unwrap();
    socket.write_all(format!("POST {route} HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nAuthorization: Bearer {}\r\nAccept: */*\r\nContent-Length: 4\r\n\r\n",entry.port,entry.token).as_bytes()).await.unwrap();
    socket.write_all(&request_body).await.unwrap();
    tokio::time::timeout(Duration::from_secs(2), helper.submitted.notified())
        .await
        .unwrap();
    drop(socket);
    // A changed body cannot consume another request's approved response.
    let client = reqwest::Client::builder().no_proxy().build().unwrap();
    let retry = |body: Bytes| {
        client
            .post(format!("{}{route}", entry.base))
            .bearer_auth(&entry.token)
            .header("x-keyvalet-approval-id", ID)
            .body(body)
    };
    let mismatch = retry(Bytes::from_static(b"changed")).send().await.unwrap();
    assert_eq!(mismatch.status(), 409);
    assert_eq!(
        mismatch.json::<Value>().await.unwrap()["error"]["type"],
        "keyvalet_approval_mismatch"
    );
    helper.outcome.send_replace(Some("ok"));
    let response = tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let response = retry(request_body.clone()).send().await.unwrap();
            if response.status() != 429 {
                break response;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert_eq!(response.status(), 201);
    assert_eq!(response.headers()["x-fixture"], "retained");
    assert_eq!(
        response.bytes().await.unwrap(),
        Bytes::from_static(&[0, 254, 13, 10])
    );
    let consumed = retry(request_body).send().await.unwrap();
    assert_eq!(consumed.status(), 409);
    assert_eq!(
        consumed.json::<Value>().await.unwrap()["error"]["type"],
        "keyvalet_approval_already_consumed"
    );
    assert_eq!(helper.authorizations.load(Ordering::SeqCst), 1);
    assert_eq!(upstream.received_requests().await.unwrap().len(), 1);
    gateway.shutdown().await;
}

#[tokio::test]
async fn gateway_terminal_local_outcomes_are_typed_and_never_forward() {
    let _loopback = Loopback::new();
    let upstream = MockServer::start().await;
    for (state, status) in [
        ("approval_denied", 403),
        ("approval_cancelled", 409),
        ("approval_expired", 410),
    ] {
        let helper = Decision::new();
        helper.outcome.send_replace(Some(state));
        let (_dir, gateway) = gateway(helper).await;
        let entry = gateway.open("api_key", "fixture", None).await.unwrap();
        let response = reqwest::Client::new()
            .post(format!(
                "{}/127.0.0.1:{}/terminal",
                entry.base,
                upstream.address().port()
            ))
            .bearer_auth(entry.token)
            .body("synthetic")
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), status);
        assert_eq!(response.headers()["x-should-retry"], "false");
        assert_eq!(
            response.json::<Value>().await.unwrap()["error"]["type"],
            format!("keyvalet_{state}")
        );
        gateway.shutdown().await;
    }
    assert!(upstream.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn revocation_during_detached_wait_discards_the_ticket_without_executing() {
    let _loopback = Loopback::new();
    let upstream = MockServer::start().await;
    let helper = Decision::new();
    let (_dir, gateway) = gateway(helper.clone()).await;
    let entry = gateway.open("api_key", "fixture", None).await.unwrap();
    let client = reqwest::Client::new();
    let response = client
        .post(format!(
            "{}/127.0.0.1:{}/revoked",
            entry.base,
            upstream.address().port()
        ))
        .bearer_auth(&entry.token)
        .body("synthetic")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 429);
    gateway.revoke_all();
    helper.outcome.send_replace(Some("ok"));
    let response = client
        .post(format!(
            "{}/127.0.0.1:{}/revoked",
            entry.base,
            upstream.address().port()
        ))
        .bearer_auth(entry.token)
        .header("x-keyvalet-approval-id", ID)
        .body("synthetic")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 401);
    gateway.shutdown().await;
    assert!(upstream.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn an_sdk_retry_without_an_id_gets_the_result_after_the_http_wait_budget_expires() {
    let _loopback = Loopback::new();
    let upstream = MockServer::start().await;
    let helper = Decision::new();
    Mock::given(method("POST"))
        .and(path("/sdk-retry"))
        .respond_with(ResponseTemplate::new(200).set_body_string("original result"))
        .expect(1)
        .mount(&upstream)
        .await;
    let (_dir, gateway) = gateway(helper.clone()).await;
    let entry = gateway.open("api_key", "fixture", None).await.unwrap();
    let client = reqwest::Client::new();
    let request = |attempt: &str| {
        client
            .post(format!(
                "{}/127.0.0.1:{}/sdk-retry",
                entry.base,
                upstream.address().port()
            ))
            .bearer_auth(&entry.token)
            .header("x-stainless-retry-count", attempt)
            .body("same request")
    };
    let response = request("0").send().await.unwrap();
    assert_eq!(response.status(), 429);
    assert_eq!(response.headers()["retry-after"], "30");
    helper.outcome.send_replace(Some("ok"));
    let response = tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let response = request("1").send().await.unwrap();
            if response.status() != 429 {
                break response;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert_eq!(response.status(), 200);
    assert_eq!(response.text().await.unwrap(), "original result");
    assert_eq!(helper.authorizations.load(Ordering::SeqCst), 1);
    assert_eq!(upstream.received_requests().await.unwrap().len(), 1);
    gateway.shutdown().await;
}
