use super::*;
use axum::{extract::State as HttpState, routing::post, Json, Router};
use kv_core::remote::{
    canonical::jcs, envelope, DeviceKeyProvider, DeviceRecord, EnvelopeHeader, Extra, Os,
    SoftwareDeviceKey,
};
use std::sync::{
    atomic::{AtomicBool, AtomicU16, Ordering},
    Mutex,
};
use tokio::sync::Notify;

#[derive(Default)]
struct Fake {
    records: Mutex<Vec<Value>>,
    status: AtomicU16,
    hold: AtomicBool,
    received: Notify,
    release: Notify,
}
async fn receive(
    HttpState(fake): HttpState<Arc<Fake>>,
    headers: axum::http::HeaderMap,
    Json(value): Json<Value>,
) -> StatusCode {
    assert_eq!(
        headers["authorization"],
        format!("Bearer {}", "r2c-test-bearer".repeat(3))
    );
    fake.records.lock().unwrap().push(value);
    fake.received.notify_one();
    if fake.hold.load(Ordering::SeqCst) {
        fake.release.notified().await;
    }
    StatusCode::from_u16(fake.status.load(Ordering::SeqCst)).unwrap()
}
struct Harness {
    relay: crate::Handle,
    base: Url,
    fake: Arc<Fake>,
    task: tokio::task::JoinHandle<()>,
    key: SoftwareDeviceKey,
    sender: DeviceRecord,
    phone: DeviceRecord,
    token: String,
}
impl Harness {
    async fn new() -> Self {
        let fake = Arc::new(Fake::default());
        fake.status.store(202, Ordering::SeqCst);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = Url::parse(&format!(
            "http://{}/v1/push",
            listener.local_addr().unwrap()
        ))
        .unwrap();
        let app = Router::new()
            .route("/v1/push", post(receive))
            .with_state(fake.clone());
        let task = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        let (base, relay) = crate::spawn_test_relay_with_push(url, "r2c-test-bearer".repeat(3));
        relay.freeze_time();
        let key = SoftwareDeviceKey::generate_p256();
        let sender = DeviceRecord {
            device_id: "dev_r2c_executor".into(),
            label: "Fixture".into(),
            os: Os::Linux,
            key_kind: kv_core::remote::KeyKind::Software,
            dk_pub: key.public_jwk().unwrap(),
            dk_sig: kv_core::remote::Optional::Missing,
            ak_q: None,
            ak_s: None,
            caps: vec![kv_core::remote::Capability::Execute],
            attestation: None,
            extra: Extra::new(),
        };
        let mut phone = sender.clone();
        phone.device_id = "dev_r2c_phone".into();
        phone.os = Os::Android;
        phone.dk_pub = SoftwareDeviceKey::generate_p256().public_jwk().unwrap();
        let token = crate::state::random_token(32);
        relay.inspect(|db| {
            db.execute(
                "INSERT INTO accounts(id,created_at,recovery_hash) VALUES('acct_r2c',0,'test')",
                [],
            )
            .unwrap();
            for device in [&sender, &phone] {
                crate::state::insert_device(db, "acct_r2c", device, None, relay.state.now())
                    .unwrap();
            }
            db.execute(
                "INSERT INTO sessions(token_hash,device_id,exp) VALUES(?1,?2,?3)",
                params![
                    kv_core::remote::canonical::sha256_hex(token.as_bytes()),
                    sender.device_id,
                    i64::MAX
                ],
            )
            .unwrap();
            db.execute(
                "UPDATE devices SET push_token=?1 WHERE id=?2",
                params![
                    serde_json::to_vec(&json!({"platform":"fcm","token":"r2c-original-token"}))
                        .unwrap(),
                    phone.device_id
                ],
            )
            .unwrap();
        });
        Self {
            relay,
            base,
            fake,
            task,
            key,
            sender,
            phone,
            token,
        }
    }
    fn seal(&self, id: &str, kind: EnvelopeType, mode: Option<DeliveryMode>) -> Envelope {
        let mut extra = Extra::new();
        if let Some(mode) = mode {
            extra.insert("push".into(), json!({"mode":mode}));
        }
        envelope::seal(
            EnvelopeHeader {
                v: 1,
                r#type: kind,
                id: id.into(),
                account: "acct_r2c".into(),
                from: self.sender.device_id.clone(),
                to: self.phone.device_id.clone(),
                created_at: self.relay.state.now(),
                exp: self.relay.state.now() + 600,
                extra,
            },
            &jcs(&json!({"private":"r2c-opaque-content"})).unwrap(),
            &self.phone.dk_pub,
            &self.key,
        )
        .unwrap()
    }
    async fn submit(&self, envelope: Envelope) {
        let path = if envelope.r#type == EnvelopeType::Directive {
            "v1/messages"
        } else {
            "v1/approvals"
        };
        let body = if path == "v1/messages" {
            json!({"envelopes":[envelope]})
        } else {
            json!({"id":envelope.id,"exp":envelope.exp,"envelopes":[envelope]})
        };
        let response = reqwest::Client::new()
            .post(self.base.join(path).unwrap())
            .header("authorization", format!("Device {}", self.token))
            .json(&body)
            .send()
            .await
            .unwrap();
        assert_eq!(
            response.status(),
            StatusCode::OK,
            "{}",
            response.text().await.unwrap()
        );
    }
    async fn close(self) {
        self.relay.shutdown().await;
        self.task.abort();
    }
}

#[tokio::test]
async fn connectivity_does_not_override_signed_delivery_and_directives_wake_silently() {
    let h = Harness::new().await;
    for connected in [false, true] {
        let (sender, _receiver) = tokio::sync::mpsc::channel(128);
        h.relay
            .state
            .with(|data, _| {
                data.presence.clear();
                if connected {
                    data.presence.insert(
                        h.phone.device_id.clone(),
                        crate::state::Presence {
                            connection: "test".into(),
                            sender: sender.clone(),
                        },
                    );
                }
                Ok(())
            })
            .unwrap();
        for mode in [None, Some(DeliveryMode::Silent), Some(DeliveryMode::Banner)] {
            let id = crate::state::ulid(h.relay.state.now());
            let envelope = h.seal(&id, EnvelopeType::ApprovalRequest, mode);
            h.submit(envelope.clone()).await;
            let stats = h.relay.flush_push().await.unwrap();
            assert_eq!(stats.sent, 1);
            assert_eq!(stats.ws_connected, usize::from(connected));
            {
                let records = h.fake.records.lock().unwrap();
                let sent = records.last().unwrap();
                assert_eq!(
                    sent["delivery"]["mode"],
                    json!(mode.unwrap_or(DeliveryMode::Banner))
                );
                assert_eq!(sent["to"], h.phone.device_id);
                assert!(!sent.to_string().contains("r2c-opaque-content"));
            }
            h.submit(envelope).await;
            assert_eq!(h.relay.flush_push().await.unwrap().attempted, 0);
        }
    }
    h.submit(h.seal(
        &crate::state::ulid(h.relay.state.now()),
        EnvelopeType::Directive,
        None,
    ))
    .await;
    assert_eq!(h.relay.flush_push().await.unwrap().sent, 1);
    assert_eq!(
        h.fake.records.lock().unwrap().last().unwrap()["delivery"]["mode"],
        "silent"
    );
    assert!(!h.relay.logs().join("\n").contains("r2c-original-token"));
    h.close().await;
}

#[tokio::test]
async fn retry_budget_is_initial_attempt_plus_three_exponential_retries() {
    let h = Harness::new().await;
    h.fake.status.store(503, Ordering::SeqCst);
    h.submit(h.seal(
        &crate::state::ulid(h.relay.state.now()),
        EnvelopeType::ApprovalRequest,
        None,
    ))
    .await;
    for delay in [1, 2, 4] {
        assert_eq!(h.relay.flush_push().await.unwrap().retried, 1);
        assert_eq!(h.relay.flush_push().await.unwrap().attempted, 0);
        h.relay.advance_time(Duration::from_secs(delay));
    }
    assert_eq!(h.relay.flush_push().await.unwrap().dropped, 1);
    h.relay.advance_time(Duration::from_secs(30));
    assert_eq!(h.relay.flush_push().await.unwrap().attempted, 0);
    assert_eq!(h.fake.records.lock().unwrap().len(), 4);
    h.close().await;
}

#[tokio::test]
async fn invalid_token_callback_is_compare_and_delete_and_missing_tokens_are_counted() {
    let h = Harness::new().await;
    h.submit(h.seal(
        &crate::state::ulid(h.relay.state.now()),
        EnvelopeType::ApprovalRequest,
        None,
    ))
    .await;
    h.fake.status.store(410, Ordering::SeqCst);
    h.fake.hold.store(true, Ordering::SeqCst);
    let (result, ()) = tokio::join!(h.relay.flush_push(), async {
        tokio::time::timeout(Duration::from_secs(5), h.fake.received.notified())
            .await
            .unwrap();
        h.relay.inspect(|db| {
            db.execute(
                "UPDATE devices SET push_token=?1 WHERE id=?2",
                params![
                    serde_json::to_vec(&json!({"platform":"fcm","token":"r2c-rotated-token"}))
                        .unwrap(),
                    h.phone.device_id
                ],
            )
            .unwrap();
        });
        h.fake.release.notify_one();
    });
    assert_eq!(result.unwrap().tokens_removed, 0);
    h.fake.hold.store(false, Ordering::SeqCst);
    h.submit(h.seal(
        &crate::state::ulid(h.relay.state.now()),
        EnvelopeType::ApprovalRequest,
        None,
    ))
    .await;
    assert_eq!(h.relay.flush_push().await.unwrap().tokens_removed, 1);
    h.submit(h.seal(
        &crate::state::ulid(h.relay.state.now()),
        EnvelopeType::ApprovalRequest,
        None,
    ))
    .await;
    assert_eq!(h.relay.flush_push().await.unwrap().skipped_no_token, 1);
    h.close().await;
}

#[test]
fn expired_human_sessions_and_revoked_devices_remove_tokens_before_dispatch() {
    let fixture = crate::tests::fixture();
    fixture
        .state
        .with(|data, now| {
            data.db.execute(
                "UPDATE devices SET os='android',push_token=?1 WHERE id=?2",
                params![b"test-token", fixture.principal.device.device_id],
            )?;
            assert_eq!(cleanup_tokens(&data.db, now, false)?, 0);
            assert_eq!(cleanup_tokens(&data.db, now, true)?, 1);
            data.db.execute(
                "INSERT INTO login_users(id,provider,subject,email,display_name,created_at)
                 VALUES('usr_r2c','google','r2c-session-owner','','',?1)",
                [now],
            )?;
            data.db.execute(
                "INSERT INTO account_sessions(token_hash,user_id,device_id,exp,created_at)
                 VALUES('r2c-expired','usr_r2c',?1,?2,?2)",
                params![fixture.principal.device.device_id, now],
            )?;
            let set_token = || {
                data.db.execute(
                    "UPDATE devices SET push_token=?1 WHERE id=?2",
                    params![b"test-token", fixture.principal.device.device_id],
                )
            };
            set_token()?;
            assert_eq!(cleanup_tokens(&data.db, now, true)?, 1);
            data.db.execute(
                "INSERT INTO account_sessions(token_hash,user_id,device_id,exp,created_at)
                 VALUES('r2c-current','usr_r2c',?1,?2,?3)",
                params![fixture.principal.device.device_id, now + 600, now],
            )?;
            set_token()?;
            assert_eq!(cleanup_tokens(&data.db, now, true)?, 0);
            let token = || {
                data.db.query_row(
                    "SELECT push_token FROM devices WHERE id=?1",
                    [&fixture.principal.device.device_id],
                    |row| row.get::<_, Option<Vec<u8>>>(0),
                )
            };
            // Cleaning an old session cannot invalidate the current login's token.
            data.db.execute(
                "DELETE FROM account_sessions WHERE token_hash='r2c-expired'",
                [],
            )?;
            assert!(token()?.is_some());
            // Removal is atomic with deletion of the last human session, without a worker tick.
            data.db.execute(
                "DELETE FROM account_sessions WHERE token_hash='r2c-current'",
                [],
            )?;
            assert!(token()?.is_none());
            data.db.execute(
                "UPDATE devices SET push_token=?1,revoked_at=?2 WHERE id=?3",
                params![b"test-token", now, fixture.principal.device.device_id],
            )?;
            assert!(data
                .db
                .query_row(
                    "SELECT push_token FROM devices WHERE id=?1",
                    [&fixture.principal.device.device_id],
                    |row| row.get::<_, Option<Vec<u8>>>(0)
                )?
                .is_none());
            assert_eq!(cleanup_tokens(&data.db, now, false)?, 0);
            Ok(())
        })
        .unwrap();
}
