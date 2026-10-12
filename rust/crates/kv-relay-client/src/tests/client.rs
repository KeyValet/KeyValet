use std::sync::{Arc, Mutex};

use serde_json::{json, Value};
use tokio::net::TcpListener;
use tokio_tungstenite::{tungstenite::protocol::Role, MaybeTlsStream, WebSocketStream};

use super::*;
use crate::{config::Config, tests::harness::*};

async fn socket_pair() -> (Socket, WebSocketStream<tokio::net::TcpStream>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let outgoing = tokio::net::TcpStream::connect(listener.local_addr().unwrap())
        .await
        .unwrap();
    let (incoming, _) = listener.accept().await.unwrap();
    let client =
        WebSocketStream::from_raw_socket(MaybeTlsStream::Plain(outgoing), Role::Client, None).await;
    let server = WebSocketStream::from_raw_socket(incoming, Role::Server, None).await;
    (client, server)
}

fn client(helper: Helper, queue: Queue) -> Client {
    let config = Config {
        relay_url: "http://127.0.0.1:1/".into(),
        device_id: "dev".into(),
        account_id: "acct".into(),
    };
    Client::new(helper, Relay::new(&config).unwrap(), queue).with_timing(fast_timing())
}

#[tokio::test]
async fn websocket_controls_do_not_dequeue_ciphertext_and_close_reconnects() {
    let helper = FakeHelper::start(Arc::new(Mutex::new(Vec::new())), false).await;
    let directory = tempfile::tempdir().unwrap();
    let queue = Queue::open(directory.path()).unwrap();
    queue.append(vec![envelope(1, "grant")]).await.unwrap();
    let client = client(helper.client(false), queue.clone());
    let (socket, mut server) = socket_pair().await;
    let (tx, mut rx) = mpsc::channel(8);
    let (_shutdown, receiver) = watch::channel(false);
    let pump = tokio::spawn(async move { client.pump(socket, tx, receiver).await });
    server
        .send(Message::Ping(vec![1, 2, 3].into()))
        .await
        .unwrap();
    assert!(
        matches!(server.next().await.unwrap().unwrap(), Message::Pong(data) if data.as_ref() == [1,2,3])
    );
    server.send(Message::Pong(Vec::new().into())).await.unwrap();
    server
        .send(Message::Text("{\"t\":\"pong\"}".into()))
        .await
        .unwrap();
    server
        .send(Message::Text("{\"t\":\"ack\",\"id\":\"message-1\"}".into()))
        .await
        .unwrap();
    for hint in [
        "{\"t\":\"pair_accept\",\"pairing_id\":\"untrusted\",\"joiner\":{}}",
        "{\"t\":\"approval_cancel\",\"id\":\"message-1\"}",
    ] {
        server.send(Message::Text(hint.into())).await.unwrap();
    }
    let original = envelope(99, "grant");
    server
        .send(Message::Text(
            format!("{{\"t\":\"envelope\",\"envelope\":{}}}", original.0.get()).into(),
        ))
        .await
        .unwrap();
    assert_eq!(rx.recv().await.unwrap().0.get(), original.0.get());
    assert_eq!(queue.front().await.unwrap().unwrap().envelopes.len(), 1);
    server.close(None).await.unwrap();
    assert!(matches!(pump.await.unwrap(), Err(Error::Network)));
}

#[tokio::test]
async fn malformed_frames_and_congestion_reconnect_without_authorizing_ack() {
    let helper = FakeHelper::start(Arc::new(Mutex::new(Vec::new())), false).await;
    let directory = tempfile::tempdir().unwrap();
    for frame in [
        Message::Text("bad".into()),
        Message::Text("{\"t\":\"unknown\"}".into()),
        Message::Text("{\"t\":\"envelope\"}".into()),
        Message::Binary(vec![1].into()),
    ] {
        let client = client(helper.client(false), Queue::open(directory.path()).unwrap());
        let (socket, mut server) = socket_pair().await;
        let (tx, _rx) = mpsc::channel(8);
        let (_shutdown, receiver) = watch::channel(false);
        let pump = tokio::spawn(async move { client.pump(socket, tx, receiver).await });
        server.send(frame).await.unwrap();
        assert!(matches!(pump.await.unwrap(), Err(Error::RelayProtocol)));
    }
    let client = client(helper.client(false), Queue::open(directory.path()).unwrap());
    let (socket, mut server) = socket_pair().await;
    let (tx, _rx) = mpsc::channel(1);
    let (_shutdown, receiver) = watch::channel(false);
    let pump = tokio::spawn(async move { client.pump(socket, tx, receiver).await });
    for n in 0..2 {
        server
            .send(Message::Text(
                format!(
                    "{{\"t\":\"envelope\",\"envelope\":{}}}",
                    envelope(n, "grant").0.get()
                )
                .into(),
            ))
            .await
            .unwrap();
    }
    assert!(matches!(pump.await.unwrap(), Err(Error::Network)));
    assert!(helper.data.lock().unwrap().received.is_empty());
}

#[tokio::test]
async fn pump_shutdown_closes_socket_and_closed_shutdown_channels_stop_workers() {
    let helper = FakeHelper::start(Arc::new(Mutex::new(Vec::new())), false).await;
    let directory = tempfile::tempdir().unwrap();
    let client = client(helper.client(false), Queue::open(directory.path()).unwrap());
    let (socket, mut server) = socket_pair().await;
    let (tx, _rx) = mpsc::channel(8);
    let (_shutdown, receiver) = watch::channel(true);
    client.pump(socket, tx, receiver).await.unwrap();
    assert!(matches!(
        server.next().await.unwrap().unwrap(),
        Message::Close(_)
    ));
    let (shutdown, mut receiver) = watch::channel(false);
    drop(shutdown);
    stopped(&mut receiver).await;
    assert!(sleep_or_stop(Duration::from_secs(60), &mut receiver).await);
    let (_shutdown, mut receiver) = watch::channel(false);
    assert!(!sleep_or_stop(Duration::ZERO, &mut receiver).await);
}

#[tokio::test]
async fn poll_failures_report_sanitized_state_and_shutdown_interrupts_backoff() {
    let events = Arc::new(Mutex::new(Vec::new()));
    let helper = FakeHelper::start(events.clone(), false).await;
    helper.data.lock().unwrap().reply_overrides.insert(
        kv_ipc::remote::RELAY_OUTBOUND_POLL.into(),
        json!({"ok":false,"error":{"code":"secret","message":"secret"}}),
    );
    let directory = tempfile::tempdir().unwrap();
    let client = client(helper.client(false), Queue::open(directory.path()).unwrap());
    let state = client.state.subscribe();
    let (shutdown, receiver) = watch::channel(false);
    let task = tokio::spawn(async move { client.poll_outbound(receiver).await });
    wait_for(|| state.borrow().last_error.as_deref() == Some("helper_rejected_request")).await;
    assert!(!state.borrow().connected);
    wait_for(|| {
        events
            .lock()
            .unwrap()
            .iter()
            .filter(|event| event.as_str() == "override:remote.relay.outbound.poll")
            .count()
            >= 2
    })
    .await;
    shutdown.send(true).unwrap();
    task.await.unwrap().unwrap();
}

#[tokio::test]
async fn invalid_outbox_fails_client_without_losing_an_existing_commit() {
    let helper = FakeHelper::start(Arc::new(Mutex::new(Vec::new())), false).await;
    let directory = tempfile::tempdir().unwrap();
    let queue = Queue::open(directory.path()).unwrap();
    queue.append(vec![envelope(1, "grant")]).await.unwrap();
    let invalid: Envelope =
        serde_json::from_value(json!({"id":"bad","credential":"plaintext"})).unwrap();
    helper.enqueue(vec![invalid]);
    let client = client(helper.client(false), queue.clone());
    let (_shutdown, receiver) = watch::channel(false);
    assert!(matches!(
        client.run(receiver).await,
        Err(Error::HelperProtocol)
    ));
    assert_eq!(queue.front().await.unwrap().unwrap().envelopes.len(), 1);
    assert_eq!(
        helper
            .data
            .lock()
            .unwrap()
            .statuses
            .last()
            .unwrap()
            .last_error
            .as_deref(),
        Some("helper_protocol_error")
    );
}

#[tokio::test]
async fn session_renewal_reauthenticates_and_preserves_waiting_before_queue_order() {
    let helper = FakeHelper::start(Arc::new(Mutex::new(Vec::new())), false).await;
    let state = RelayState::new(&helper);
    state.data.lock().unwrap().session_lifetime = 62;
    let relay = FakeRelay::start(state.clone()).await;
    let directory = tempfile::tempdir().unwrap();
    let running = RunningClient::start(
        helper.client(false),
        relay.config(),
        Queue::open(directory.path()).unwrap(),
        fast_timing(),
    );
    wait_for(|| state.data.lock().unwrap().connections >= 2).await;
    assert!(helper.data.lock().unwrap().signed.len() >= 2);
    running.stop().await;
    relay.stop().await;
}

#[tokio::test]
async fn already_stopped_connections_and_sender_exit_without_network() {
    let helper = FakeHelper::start(Arc::new(Mutex::new(Vec::new())), false).await;
    let directory = tempfile::tempdir().unwrap();
    let client = client(helper.client(false), Queue::open(directory.path()).unwrap());
    let (_shutdown, receiver) = watch::channel(true);
    client.connections(receiver.clone()).await.unwrap();
    let (_ready, ready) = watch::channel(true);
    // Obtain a session from a local fake relay, then test cancellation before any queue request.
    let state = RelayState::new(&helper);
    let relay = FakeRelay::start(state).await;
    let session = Relay::new(&relay.config())
        .unwrap()
        .authenticate(&helper.client(false))
        .await
        .unwrap();
    client
        .send_queue(&session, ready, receiver.clone())
        .await
        .unwrap();
    let (ready, ready_rx) = watch::channel(false);
    let (tx, rx) = mpsc::channel(8);
    client.deliver(&session, rx, ready, receiver).await.unwrap();
    assert!(!*ready_rx.borrow());
    drop(tx);
    relay.stop().await;
}

#[tokio::test]
async fn closed_waiting_gate_and_closed_inbound_channel_trigger_reconnect() {
    let helper = FakeHelper::start(Arc::new(Mutex::new(Vec::new())), false).await;
    let state = RelayState::new(&helper);
    let relay = FakeRelay::start(state).await;
    let directory = tempfile::tempdir().unwrap();
    let network = Relay::new(&relay.config()).unwrap();
    let session = network.authenticate(&helper.client(false)).await.unwrap();
    let client = Client::new(
        helper.client(false),
        network,
        Queue::open(directory.path()).unwrap(),
    );
    let (_shutdown, receiver) = watch::channel(false);
    let (ready, ready_rx) = watch::channel(false);
    drop(ready);
    assert!(matches!(
        client
            .send_queue(&session, ready_rx, receiver.clone())
            .await,
        Err(Error::Network)
    ));
    let (tx, rx) = mpsc::channel(8);
    drop(tx);
    let (ready, ready_rx) = watch::channel(false);
    assert!(matches!(
        client.deliver(&session, rx, ready, receiver).await,
        Err(Error::Network)
    ));
    assert!(*ready_rx.borrow());
    relay.stop().await;
}

#[tokio::test]
async fn extreme_session_expiry_cannot_overflow_the_renewal_timer() {
    let helper = FakeHelper::start(Arc::new(Mutex::new(Vec::new())), false).await;
    let state = RelayState::new(&helper);
    let relay = FakeRelay::start(state).await;
    let directory = tempfile::tempdir().unwrap();
    let network = Relay::new(&relay.config()).unwrap();
    let mut session = network.authenticate(&helper.client(false)).await.unwrap();
    let client = Client::new(
        helper.client(false),
        network,
        Queue::open(directory.path()).unwrap(),
    );
    for exp in [i64::MIN, i64::MAX] {
        session.exp = exp;
        let (socket, _server) = socket_pair().await;
        let (_shutdown, receiver) = watch::channel(true);
        client.session(socket, &session, receiver).await.unwrap();
    }
    relay.stop().await;
}

#[tokio::test]
async fn a_lost_spool_receipt_retries_without_duplicating_the_ciphertext_commit() {
    let helper = FakeHelper::start(Arc::new(Mutex::new(Vec::new())), false).await;
    let directory = tempfile::tempdir().unwrap();
    let queue = Queue::open(directory.path()).unwrap();
    let batch = vec![envelope(1, "grant")];
    {
        let mut data = helper.data.lock().unwrap();
        data.outgoing.extend([batch.clone(), batch]);
        data.receipt_failures
            .push_back(kv_ipc::remote::OutboundStage::Spooled);
    }
    let client = client(helper.client(false), queue.clone());
    let (shutdown, receiver) = watch::channel(false);
    let polling = tokio::spawn(async move { client.poll_outbound(receiver).await });
    tokio::time::timeout(Duration::from_secs(5), async {
        while helper.data.lock().unwrap().receipts.len() < 2 {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap();
    shutdown.send(true).unwrap();
    polling.await.unwrap().unwrap();
    let committed = queue.front().await.unwrap().unwrap();
    assert_eq!(committed.envelopes.len(), 1);
    queue.complete_prefix(committed.sequence, 1).await.unwrap();
    assert!(queue.front().await.unwrap().is_none());
}

#[tokio::test]
async fn shutdown_interrupts_a_failed_spool_receipt_backoff_and_preserves_the_commit() {
    let helper = FakeHelper::start(Arc::new(Mutex::new(Vec::new())), false).await;
    {
        let mut data = helper.data.lock().unwrap();
        data.outgoing.push_back(vec![envelope(1, "grant")]);
        data.receipt_failures
            .push_back(kv_ipc::remote::OutboundStage::Spooled);
    }
    let directory = tempfile::tempdir().unwrap();
    let queue = Queue::open(directory.path()).unwrap();
    let mut client = client(helper.client(false), queue.clone());
    client.timing.initial_backoff = Duration::from_secs(60);
    client.timing.maximum_backoff = Duration::from_secs(60);
    let state = client.state.subscribe();
    let (shutdown, receiver) = watch::channel(false);
    let polling = tokio::spawn(async move { client.poll_outbound(receiver).await });
    wait_for(|| state.borrow().last_error.as_deref() == Some("helper_rejected_request")).await;
    shutdown.send(true).unwrap();
    tokio::time::timeout(Duration::from_secs(2), polling)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(queue.front().await.unwrap().unwrap().envelopes.len(), 1);
}

#[tokio::test]
async fn only_helper_retirement_or_durable_acceptance_can_remove_a_queued_prefix() {
    let helper = FakeHelper::start(Arc::new(Mutex::new(Vec::new())), false).await;
    let relay_state = RelayState::new(&helper);
    let relay = FakeRelay::start(relay_state.clone()).await;
    let directory = tempfile::tempdir().unwrap();
    let queue = Queue::open(directory.path()).unwrap();
    queue
        .append((1..=3).map(|n| envelope(n, "grant")).collect())
        .await
        .unwrap();
    {
        let mut data = helper.data.lock().unwrap();
        data.retired_prefixes.push_back(1);
        data.receipt_failures
            .push_back(kv_ipc::remote::OutboundStage::Accepted);
    }
    let client = Client::new(
        helper.client(false),
        Relay::new(&relay.config()).unwrap(),
        queue.clone(),
    );
    let session = Relay::new(&relay.config())
        .unwrap()
        .authenticate(&helper.client(false))
        .await
        .unwrap();
    let (_ready, gate) = watch::channel(true);
    let (shutdown, receiver) = watch::channel(false);
    assert!(matches!(
        client
            .send_queue(&session, gate.clone(), receiver.clone())
            .await,
        Err(Error::HelperRejected)
    ));
    assert_eq!(
        queue
            .front()
            .await
            .unwrap()
            .unwrap()
            .envelopes
            .iter()
            .map(id)
            .collect::<Vec<_>>(),
        ["message-2", "message-3"]
    );
    assert_eq!(
        relay_state
            .data
            .lock()
            .unwrap()
            .received
            .iter()
            .map(|raw| {
                serde_json::from_str::<Value>(raw).unwrap()["id"]
                    .as_str()
                    .unwrap()
                    .to_owned()
            })
            .collect::<Vec<_>>(),
        ["message-2", "message-3"]
    );
    let (result, ()) = tokio::join!(client.send_queue(&session, gate, receiver), async {
        wait_for_queue_empty(&queue).await;
        shutdown.send(true).unwrap();
    });
    result.unwrap();
    relay.stop().await;
}
