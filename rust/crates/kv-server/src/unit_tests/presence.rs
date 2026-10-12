use super::*;
use crate::tests::{fixture, Fixture};
use kv_core::remote::relay::ErrorCode;
use std::collections::VecDeque;
use std::sync::Mutex;

#[derive(Default)]
struct Socket {
    incoming: VecDeque<Message>,
    sent: Arc<Mutex<Vec<Message>>>,
    attempts: usize,
    fail_at: Option<usize>,
    stall_at: Option<usize>,
    before_receive: Option<Box<dyn FnOnce() + Send>>,
}

impl RelaySocket for Socket {
    fn send(&mut self, message: Message) -> SocketFuture<'_, std::result::Result<(), axum::Error>> {
        Box::pin(async move {
            let attempt = self.attempts;
            self.attempts += 1;
            if self.fail_at == Some(attempt) {
                return Err(axum::Error::new(std::io::Error::other(
                    "test transport closed",
                )));
            }
            if self.stall_at == Some(attempt) {
                return std::future::pending().await;
            }
            self.sent.lock().unwrap().push(message);
            Ok(())
        })
    }

    fn recv(&mut self) -> SocketFuture<'_, Option<std::result::Result<Message, axum::Error>>> {
        Box::pin(async move {
            if let Some(action) = self.before_receive.take() {
                action();
            }
            if let Some(message) = self.incoming.pop_front() {
                return Some(Ok(message));
            }
            std::future::pending().await
        })
    }
}

async fn run(fixture: &Fixture, socket: Socket) -> Vec<Message> {
    let sent = socket.sent.clone();
    let (_shutdown, receiver) = watch::channel(false);
    serve(
        Box::new(socket),
        fixture.state.clone(),
        fixture.principal.clone(),
        receiver,
    )
    .await;
    assert!(fixture
        .state
        .with(|data, _| Ok(data.presence.is_empty()))
        .unwrap());
    let messages = sent.lock().unwrap().clone();
    messages
}

#[tokio::test(start_paused = true)]
async fn raw_control_frames_and_invalid_application_frames_obey_the_protocol() {
    let fixture = fixture();
    let sent = run(
        &fixture,
        Socket {
            incoming: VecDeque::from([
                Message::Ping(vec![1, 2].into()),
                Message::Pong(Vec::new().into()),
                Message::Text("not JSON".into()),
                Message::Binary(Vec::new().into()),
            ]),
            ..Socket::default()
        },
    )
    .await;
    assert!(matches!(&sent[0], Message::Pong(bytes) if bytes.as_ref()==[1,2]));
    let Message::Text(error) = &sent[1] else {
        panic!("missing protocol error")
    };
    assert_eq!(
        serde_json::from_str::<Value>(error).unwrap()["error"]["code"],
        "bad_envelope"
    );
    assert!(matches!(sent.last(), Some(Message::Close(_))));
}

#[tokio::test(start_paused = true)]
async fn failed_initial_replay_and_stalled_writes_remove_presence() {
    for stall in [false, true] {
        let fixture = fixture();
        fixture
            .state
            .with(|data, now| {
                send_messages(
                    data,
                    &fixture.principal,
                    std::slice::from_ref(&fixture.envelope),
                    now,
                )
            })
            .unwrap();
        let begin = Instant::now();
        let sent = run(
            &fixture,
            Socket {
                fail_at: (!stall).then_some(0),
                stall_at: stall.then_some(0),
                ..Socket::default()
            },
        )
        .await;
        assert!(sent.is_empty());
        if stall {
            assert_eq!(begin.elapsed(), Duration::from_secs(5));
        }
        fixture
            .state
            .with(|data, _| {
                assert!(data
                    .db
                    .query_row("SELECT acked_at IS NULL FROM messages", [], |r| r
                        .get::<_, bool>(0))?);
                Ok(())
            })
            .unwrap();
    }
}

#[tokio::test(start_paused = true)]
async fn shutdown_interrupts_a_stalled_initial_replay_without_waiting_for_its_timeout() {
    let fixture = fixture();
    fixture
        .state
        .with(|data, now| {
            send_messages(
                data,
                &fixture.principal,
                std::slice::from_ref(&fixture.envelope),
                now,
            )
        })
        .unwrap();
    let (shutdown, receiver) = watch::channel(false);
    shutdown.send(true).unwrap();
    let begin = Instant::now();
    serve(
        Box::new(Socket {
            stall_at: Some(0),
            ..Socket::default()
        }),
        fixture.state.clone(),
        fixture.principal.clone(),
        receiver,
    )
    .await;
    assert_eq!(begin.elapsed(), Duration::ZERO);
    assert!(fixture
        .state
        .with(|data, _| Ok(data.presence.is_empty()))
        .unwrap());
}

#[tokio::test(start_paused = true)]
async fn failed_heartbeat_pong_and_error_writes_terminate_the_connection() {
    for incoming in [
        VecDeque::new(),
        VecDeque::from([Message::Ping(Vec::new().into())]),
        VecDeque::from([Message::Text("not JSON".into())]),
    ] {
        let fixture = fixture();
        let sent = run(
            &fixture,
            Socket {
                incoming,
                fail_at: Some(0),
                ..Socket::default()
            },
        )
        .await;
        assert!(matches!(sent.last(), Some(Message::Close(_))));
    }
}

#[tokio::test(start_paused = true)]
async fn heartbeat_disconnects_a_session_that_expires_after_upgrade() {
    let fixture = fixture();
    let state = fixture.state.clone();
    let sent = run(
        &fixture,
        Socket {
            before_receive: Some(Box::new(move || {
                state.advance(crate::state::SESSION_TTL + 1)
            })),
            ..Socket::default()
        },
    )
    .await;
    assert!(matches!(sent.as_slice(), [Message::Close(_)]));
}

#[tokio::test(start_paused = true)]
async fn queued_frame_failures_and_explicit_disconnects_terminate_the_connection() {
    for close in [false, true] {
        let fixture = fixture();
        let state = fixture.state.clone();
        let device = fixture.principal.device.device_id.clone();
        let sent = run(
            &fixture,
            Socket {
                fail_at: Some(0),
                before_receive: Some(Box::new(move || {
                    state
                        .with(|data, _| {
                            if close {
                                data.disconnect(&device);
                            } else {
                                assert!(data.send(&device, json!({"t":"pong"})));
                            }
                            Ok(())
                        })
                        .unwrap();
                })),
                ..Socket::default()
            },
        )
        .await;
        assert!(sent.len() <= 1);
    }
}

#[tokio::test(start_paused = true)]
async fn reconnect_failures_leave_no_stale_online_entry() {
    let fixture = fixture();
    fixture
        .state
        .with(|data, _| {
            data.db.pragma_update(None, "query_only", true)?;
            Ok(())
        })
        .unwrap();
    let sent = run(&fixture, Socket::default()).await;
    assert!(sent.is_empty());
}

#[tokio::test]
async fn a_failed_replacement_preserves_the_previous_connection() {
    let fixture = fixture();
    let (old, _old_receiver) = mpsc::channel(1);
    fixture
        .state
        .with(|data, _| {
            data.presence.insert(
                fixture.principal.device.device_id.clone(),
                Presence {
                    connection: "old".into(),
                    sender: old,
                },
            );
            data.db.pragma_update(None, "query_only", true)?;
            Ok(())
        })
        .unwrap();
    let (replacement, _) = mpsc::channel(1);
    assert_eq!(
        reconnect(
            &fixture.state,
            &fixture.principal,
            "replacement",
            replacement
        )
        .unwrap_err()
        .code,
        ErrorCode::Conflict
    );
    fixture
        .state
        .with(|data, _| {
            assert_eq!(
                data.presence[&fixture.principal.device.device_id].connection,
                "old"
            );
            Ok(())
        })
        .unwrap();
}

#[test]
fn application_errors_do_not_ack_and_read_only_storage_rejects_heartbeat_updates() {
    let fixture = fixture();
    let mut envelope = fixture.envelope.clone();
    envelope.r#type = kv_core::remote::EnvelopeType::ApprovalRequest;
    assert_eq!(
        incoming(
            &fixture.state,
            &fixture.principal,
            json!({"t":"envelope","envelope":envelope})
                .to_string()
                .as_bytes()
        )
        .unwrap_err()
        .code,
        ErrorCode::BadEnvelope
    );
    assert_eq!(
        incoming(&fixture.state, &fixture.principal, b"{\"t\":\"pong\"}").unwrap(),
        json!({"t":"pong"})
    );
    fixture
        .state
        .with(|data, _| {
            data.db.pragma_update(None, "query_only", true)?;
            Ok(())
        })
        .unwrap();
    assert_eq!(
        incoming(&fixture.state, &fixture.principal, b"{\"t\":\"ping\"}")
            .unwrap_err()
            .code,
        ErrorCode::Conflict
    );
}

fn replay_fixture() -> Fixture {
    let fixture = fixture();
    let mut joiner = crate::tests::fixture().principal.device;
    joiner.device_id = "dev_replay_joiner".into();
    fixture.state.with(|data, now| {
        crate::state::insert_device(&data.db, &fixture.principal.account, &joiner, None, now)?;
        data.db.execute("INSERT INTO messages(id,account_id,from_device,to_device,type,envelope,created_at,exp) VALUES(?1,?2,?3,?3,'grant',?4,?5,?6)",
            params![fixture.envelope.id, fixture.principal.account, fixture.principal.device.device_id, serde_json::to_vec(&fixture.envelope).unwrap(), now, now+300])?;
        data.db.execute("INSERT INTO pairings(pairing_id,account_id,initiator_device,initiator_pubs,joiner_device,joiner_pubs,state,exp) VALUES(?1,?2,?3,?4,?5,?6,'accepted',?7)",
            params![crate::state::ulid(now), fixture.principal.account, fixture.principal.device.device_id, serde_json::to_vec(&fixture.principal.device).unwrap(), joiner.device_id, serde_json::to_vec(&joiner).unwrap(), now+300])?;
        Ok(())
    }).unwrap();
    fixture
}

#[test]
fn reconnect_query_faults_preserve_the_previous_connection_and_corrupt_rows_fail_closed() {
    use rusqlite::hooks::{AuthContext, Authorization};
    use std::sync::atomic::{AtomicUsize, Ordering};
    let fixture = replay_fixture();
    let count = Arc::new(AtomicUsize::new(0));
    let baseline = crate::tests::regions::copy_state(&fixture.state);
    {
        let counter = count.clone();
        baseline
            .data
            .lock()
            .unwrap()
            .db
            .authorizer(Some(move |_: AuthContext<'_>| {
                counter.fetch_add(1, Ordering::Relaxed);
                Authorization::Allow
            }));
    }
    let (sender, _receiver) = mpsc::channel(128);
    assert_eq!(
        reconnect(&baseline, &fixture.principal, "baseline", sender)
            .unwrap()
            .len(),
        2
    );
    for fail_at in 1..=count.load(Ordering::Relaxed) {
        let relay = crate::tests::regions::copy_state(&fixture.state);
        let (old_sender, mut old_receiver) = mpsc::channel(128);
        relay
            .with(|data, _| {
                data.presence.insert(
                    fixture.principal.device.device_id.clone(),
                    Presence {
                        connection: "old".into(),
                        sender: old_sender,
                    },
                );
                let mut calls = 0;
                data.db.authorizer(Some(move |_: AuthContext<'_>| {
                    calls += 1;
                    if calls == fail_at {
                        Authorization::Deny
                    } else {
                        Authorization::Allow
                    }
                }));
                Ok(())
            })
            .unwrap();
        let (sender, _receiver) = mpsc::channel(128);
        assert!(reconnect(&relay, &fixture.principal, "replacement", sender).is_err());
        assert_eq!(
            relay.data.lock().unwrap().presence[&fixture.principal.device.device_id].connection,
            "old"
        );
        assert!(old_receiver.try_recv().is_err());
    }
    for (table, column, value) in [
        ("messages", "envelope", "42"),
        ("messages", "envelope", "x'00'"),
        ("pairings", "pairing_id", "x'00'"),
        ("pairings", "joiner_pubs", "42"),
        ("pairings", "joiner_pubs", "x'00'"),
    ] {
        let relay = crate::tests::regions::copy_state(&fixture.state);
        relay
            .with(|data, _| {
                data.db
                    .execute(&format!("UPDATE {table} SET {column}={value}"), [])?;
                Ok(())
            })
            .unwrap();
        let (sender, _receiver) = mpsc::channel(128);
        assert!(reconnect(&relay, &fixture.principal, "corrupt", sender).is_err());
        assert!(relay.data.lock().unwrap().presence.is_empty());
    }
}

#[test]
fn incoming_ack_and_cached_authentication_failures_never_acknowledge() {
    let fixture = fixture();
    assert_eq!(
        incoming(
            &fixture.state,
            &fixture.principal,
            json!({"t":"ack","id":fixture.envelope.id})
                .to_string()
                .as_bytes()
        )
        .unwrap_err()
        .code,
        ErrorCode::NotFound
    );
    fixture
        .state
        .with(|data, _| {
            data.db.execute("DELETE FROM sessions", [])?;
            Ok(())
        })
        .unwrap();
    assert_eq!(
        incoming(&fixture.state, &fixture.principal, b"{\"t\":\"ping\"}")
            .unwrap_err()
            .code,
        ErrorCode::Unauthorized
    );
}

#[tokio::test]
async fn presence_upgrade_authenticates_without_an_outer_middleware_guard() {
    let fixture = fixture();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (_shutdown, receiver) = watch::channel(false);
    let router = axum::Router::new()
        .route("/v1/presence", axum::routing::get(upgrade))
        .layer(axum::Extension(Shutdown(receiver)))
        .with_state(fixture.state);
    let server = tokio::spawn(async move {
        axum::serve(
            listener,
            router.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await
        .unwrap();
    });
    use tokio_tungstenite::tungstenite::client::IntoClientRequest;
    let mut request = format!("ws://{address}/v1/presence")
        .into_client_request()
        .unwrap();
    request
        .headers_mut()
        .insert("sec-websocket-protocol", "kv-relay-v1".parse().unwrap());
    let error = tokio_tungstenite::connect_async(request).await.unwrap_err();
    let tokio_tungstenite::tungstenite::Error::Http(response) = error else {
        panic!("expected an authentication error")
    };
    assert_eq!(response.status(), axum::http::StatusCode::UNAUTHORIZED);
    server.abort();
    let _ = server.await;
}

#[tokio::test(start_paused = true)]
async fn unanswered_heartbeats_close_at_the_idle_deadline_and_stalled_pings_time_out() {
    let fixture = fixture();
    let start = Instant::now();
    let sent = run(&fixture, Socket::default()).await;
    assert_eq!(Instant::now() - start, IDLE_TIMEOUT);
    assert_eq!(
        sent.iter()
            .filter(|frame| matches!(frame, Message::Ping(_)))
            .count(),
        3
    );
    assert!(matches!(sent.last(), Some(Message::Close(_))));
    let fixture = crate::tests::fixture();
    let start = Instant::now();
    let sent = run(
        &fixture,
        Socket {
            stall_at: Some(0),
            ..Socket::default()
        },
    )
    .await;
    assert_eq!(Instant::now() - start, HEARTBEAT + Duration::from_secs(5));
    assert!(matches!(sent.as_slice(), [Message::Close(_)]));
}
