use super::*;
use axum::{extract::State, routing::post, Json, Router};
use std::sync::{
    atomic::{AtomicU16, Ordering},
    Arc,
};

#[derive(Default)]
struct Dispatcher {
    requests: Mutex<Vec<Value>>,
    status: AtomicU16,
}
async fn receive(
    State(state): State<Arc<Dispatcher>>,
    headers: axum::http::HeaderMap,
    Json(value): Json<Value>,
) -> axum::http::StatusCode {
    assert_eq!(
        headers["authorization"],
        format!("Bearer {}", "test-bearer".repeat(4))
    );
    state.requests.lock().unwrap().push(value);
    axum::http::StatusCode::from_u16(state.status.load(Ordering::SeqCst)).unwrap()
}
async fn start() -> (Client, Handle, Arc<Dispatcher>, tokio::task::JoinHandle<()>) {
    let state = Arc::new(Dispatcher::default());
    state.status.store(202, Ordering::SeqCst);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = Url::parse(&format!(
        "http://{}/v1/push",
        listener.local_addr().unwrap()
    ))
    .unwrap();
    let app = Router::new()
        .route("/v1/push", post(receive))
        .with_state(state.clone());
    let task = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let (base, relay) = spawn_test_relay_with_push(url, "test-bearer".repeat(4));
    (Client::new(base), relay, state, task)
}
fn sealed(
    from: &Device,
    to: &Device,
    id: &str,
    kind: EnvelopeType,
    mode: &str,
    exp: i64,
) -> Envelope {
    let mut extra = Extra::new();
    extra.insert("push".into(), json!({"mode":mode}));
    envelope::seal(
        EnvelopeHeader {
            v: 1,
            r#type: kind,
            id: id.into(),
            account: from.account.clone(),
            from: from.record.device_id.clone(),
            to: to.record.device_id.clone(),
            created_at: now(),
            exp,
            extra,
        },
        &jcs(&json!({"private":"opaque-marker-74ce8a","host":"private.invalid"})).unwrap(),
        &to.record.dk_pub,
        &from.dk,
    )
    .unwrap()
}
async fn devices(client: &Client) -> (Device, Device) {
    let mut executor = Device::new("push_executor", false);
    client.register(&mut executor).await;
    let mut phone = Device::new("push_phone", true);
    phone.record.os = Os::Android;
    client.register(&mut phone).await;
    client.pair(&executor, &mut phone, true, None).await;
    client
        .post(
            "/v1/devices/push-token",
            Some(&phone.token),
            json!({"platform":"fcm","token":"original-test-token"}),
        )
        .await;
    (executor, phone)
}

#[tokio::test]
async fn signed_push_metadata_is_durable_idempotent_and_never_contains_approval_plaintext() {
    let (client, relay, dispatcher, task) = start().await;
    let (executor, phone) = devices(&client).await;
    relay.freeze_time();
    let exp = now() + 600;
    let id = state::ulid(now());
    let request = sealed(
        &executor,
        &phone,
        &id,
        EnvelopeType::ApprovalRequest,
        "silent",
        exp,
    );
    let body = json!({"id":id,"exp":request.exp,"envelopes":[request]});
    client
        .post("/v1/approvals", Some(&executor.token), body.clone())
        .await;
    assert_eq!(relay.flush_push().await.unwrap().sent, 1);
    client
        .post("/v1/approvals", Some(&executor.token), body)
        .await;
    assert_eq!(relay.flush_push().await.unwrap().attempted, 0);
    let records = dispatcher.requests.lock().unwrap().clone();
    assert_eq!(
        records,
        [
            json!({"device_push_token":{"platform":"fcm","token":"original-test-token"},
        "approval_id":id,"to":phone.record.device_id,"delivery":{"mode":"silent"}})
        ]
    );
    let plaintext = envelope::open(
        &request,
        &phone.record.device_id,
        &phone.dk,
        &executor.record,
        now(),
    )
    .unwrap();
    assert!(String::from_utf8_lossy(&plaintext).contains("opaque-marker-74ce8a"));
    let dump = relay.inspect(|db| {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("relay.sqlite3");
        db.backup(rusqlite::DatabaseName::Main, &path, None)
            .unwrap();
        std::fs::read(path).unwrap()
    });
    for marker in ["opaque-marker-74ce8a", "private.invalid"] {
        assert!(!String::from_utf8_lossy(&dump).contains(marker));
        assert!(!serde_json::to_string(&records).unwrap().contains(marker));
        assert!(!relay.logs().join("\n").contains(marker));
    }
    relay.shutdown().await;
    task.abort();
}

#[tokio::test]
async fn push_retries_use_current_rotated_tokens_and_expire_without_blocking_approvals() {
    let (client, relay, dispatcher, task) = start().await;
    let (executor, phone) = devices(&client).await;
    relay.freeze_time();
    let exp = now() + 600;
    let id = state::ulid(now());
    let request = sealed(
        &executor,
        &phone,
        &id,
        EnvelopeType::ApprovalRequest,
        "banner",
        exp,
    );
    client
        .post(
            "/v1/approvals",
            Some(&executor.token),
            json!({"id":id,"exp":request.exp,"envelopes":[request]}),
        )
        .await;
    dispatcher.status.store(503, Ordering::SeqCst);
    assert_eq!(relay.flush_push().await.unwrap().retried, 1);
    assert_eq!(relay.flush_push().await.unwrap().attempted, 0);
    client
        .post(
            "/v1/devices/push-token",
            Some(&phone.token),
            json!({"platform":"fcm","token":"rotated-test-token"}),
        )
        .await;
    relay.advance_time(Duration::from_secs(3));
    dispatcher.status.store(202, Ordering::SeqCst);
    assert_eq!(relay.flush_push().await.unwrap().sent, 1);
    assert_eq!(
        dispatcher.requests.lock().unwrap()[1]["device_push_token"]["token"],
        "rotated-test-token"
    );
    let request = sealed(
        &executor,
        &phone,
        &id,
        EnvelopeType::ApprovalEscalate,
        "banner",
        exp,
    );
    client
        .post(
            "/v1/approvals",
            Some(&executor.token),
            json!({"id":id,"exp":request.exp,"envelopes":[request]}),
        )
        .await;
    dispatcher.status.store(429, Ordering::SeqCst);
    assert_eq!(relay.flush_push().await.unwrap().retried, 1);
    relay.advance_time(Duration::from_secs(30));
    assert_eq!(relay.flush_push().await.unwrap().attempted, 0);
    relay.advance_time(Duration::from_secs(31));
    dispatcher.status.store(410, Ordering::SeqCst);
    assert_eq!(relay.flush_push().await.unwrap().tokens_removed, 1);
    assert!(relay
        .inspect(|db| db
            .query_row(
                "SELECT push_token FROM devices WHERE id=?1",
                [&phone.record.device_id],
                |row| row.get::<_, Option<Vec<u8>>>(0)
            )
            .unwrap())
        .is_none());
    let cancel = sealed(
        &executor,
        &phone,
        &id,
        EnvelopeType::ApprovalCancel,
        "silent",
        exp,
    );
    client
        .post(
            &format!("/v1/approvals/{id}/cancel"),
            Some(&executor.token),
            json!({"envelope":cancel}),
        )
        .await;
    assert_eq!(relay.flush_push().await.unwrap().attempted, 0);
    relay.advance_time(Duration::from_secs(200));
    relay.cleanup();
    assert_eq!(
        relay.inspect(|db| db
            .query_row("SELECT COUNT(*) FROM push_jobs", [], |row| row
                .get::<_, i64>(0))
            .unwrap()),
        0
    );
    relay.shutdown().await;
    task.abort();
}

#[tokio::test]
async fn superseded_pushes_and_invalid_or_tampered_hints_are_rejected() {
    let (client, relay, dispatcher, task) = start().await;
    let (executor, phone) = devices(&client).await;
    relay.freeze_time();
    let exp = now() + 600;
    let id = state::ulid(now());
    let request = sealed(
        &executor,
        &phone,
        &id,
        EnvelopeType::ApprovalRequest,
        "silent",
        exp,
    );
    let mut tampered = request.clone();
    tampered
        .extra
        .insert("push".into(), json!({"mode":"banner"}));
    assert!(client
        .call(
            Method::POST,
            "/v1/approvals",
            Some(&executor.token),
            Some(json!({"id":id,"exp":tampered.exp,"envelopes":[tampered]}))
        )
        .await
        .0
        .is_client_error());
    client
        .post(
            "/v1/approvals",
            Some(&executor.token),
            json!({"id":id,"exp":request.exp,"envelopes":[request]}),
        )
        .await;
    let mut escalation = sealed(
        &executor,
        &phone,
        &id,
        EnvelopeType::ApprovalEscalate,
        "silent",
        exp,
    );
    assert_eq!(
        client
            .call(
                Method::POST,
                "/v1/approvals",
                Some(&executor.token),
                Some(json!({"id":id,"exp":escalation.exp,"envelopes":[escalation]}))
            )
            .await
            .0,
        StatusCode::BAD_REQUEST
    );
    escalation = sealed(
        &executor,
        &phone,
        &id,
        EnvelopeType::ApprovalEscalate,
        "banner",
        exp,
    );
    client
        .post(
            "/v1/approvals",
            Some(&executor.token),
            json!({"id":id,"exp":escalation.exp,"envelopes":[escalation]}),
        )
        .await;
    let cancel = sealed(
        &executor,
        &phone,
        &id,
        EnvelopeType::ApprovalCancel,
        "silent",
        exp,
    );
    client
        .post(
            &format!("/v1/approvals/{id}/cancel"),
            Some(&executor.token),
            json!({"envelope":cancel}),
        )
        .await;
    assert_eq!(relay.flush_push().await.unwrap().sent, 1);
    assert_eq!(
        dispatcher.requests.lock().unwrap()[0]["delivery"]["mode"],
        "silent"
    );
    assert_eq!(
        client
            .call(
                Method::DELETE,
                "/v1/devices/push-token",
                Some(&phone.token),
                None
            )
            .await
            .1,
        json!({"ok":true})
    );
    assert_eq!(
        client
            .call(Method::DELETE, "/v1/devices/push-token", None, None)
            .await
            .0,
        StatusCode::UNAUTHORIZED
    );
    relay.shutdown().await;
    task.abort();
}
