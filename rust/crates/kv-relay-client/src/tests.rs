// Local fake helper and relay tests; no installed files, root, GUI or hardware are used.

mod config_presence;
#[cfg(unix)]
mod control;
mod coverage;
pub(crate) mod harness;
#[cfg(unix)]
mod interfaces;
mod recovery;

use std::{
    fs,
    sync::{Arc, Mutex},
    time::{Duration, SystemTime},
};

use serde_json::{json, value::RawValue, Value};

use crate::{
    backoff::Backoff,
    client::Timing,
    config::Config,
    envelope::Envelope,
    error::Error,
    helper,
    queue::Queue,
    transport::{self, Group, Route},
};
use harness::*;

fn events() -> Events {
    Arc::new(Mutex::new(Vec::new()))
}

#[test]
fn backoff_caps_at_sixty_seconds_and_honors_server_cooldowns() {
    let mut backoff = Backoff::new(Duration::from_secs(1), Duration::from_secs(60));
    let delays: Vec<_> = (0..9).map(|_| backoff.delay(None).as_secs()).collect();
    assert_eq!(delays, [1, 2, 4, 8, 16, 32, 60, 60, 60]);
    backoff.reset();
    assert_eq!(
        backoff.delay(Some(Duration::from_secs(120))),
        Duration::from_secs(120)
    );
    assert_eq!(backoff.delay(None), Duration::from_secs(2));
}

#[test]
fn retry_after_supports_seconds_and_http_dates() {
    let mut headers = reqwest::header::HeaderMap::new();
    headers.insert(reqwest::header::RETRY_AFTER, "75".parse().unwrap());
    assert_eq!(
        transport::retry_after(&headers),
        Some(Duration::from_secs(75))
    );
    let date = httpdate::fmt_http_date(SystemTime::now() + Duration::from_secs(120));
    headers.insert(reqwest::header::RETRY_AFTER, date.parse().unwrap());
    let delay = transport::retry_after(&headers).unwrap();
    assert!(delay > Duration::from_secs(118) && delay <= Duration::from_secs(120));
    headers.insert(reqwest::header::RETRY_AFTER, "invalid".parse().unwrap());
    assert!(transport::retry_after(&headers).is_none());
}

#[test]
fn toml_configuration_rejects_invalid_or_ambiguous_inputs() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("relay-client.toml");
    fs::write(&path, "relay_url = 'https://relay.example.com/base'\ndevice_id = 'dev_test'\naccount_id = 'acct_test'\n").unwrap();
    let config = Config::load(&path).unwrap();
    assert_eq!(
        config.base_url().unwrap().as_str(),
        "https://relay.example.com/base/"
    );
    for invalid in [
        "relay_url = 'http://relay.example.com'\ndevice_id='dev'\naccount_id='acct'",
        "relay_url = 'https://user:password@relay.example.com'\ndevice_id='dev'\naccount_id='acct'",
        "relay_url = 'https://relay.example.com?token=secret'\ndevice_id='dev'\naccount_id='acct'",
        "relay_url = 'https://relay.example.com'\ndevice_id=''\naccount_id='acct'",
        "relay_url = 'https://relay.example.com'\ndevice_id='dev'\naccount_id='acct'\nprivate_key='secret'",
        "relay_url = 'https://relay.example.com'\ndevice_id='dev'\ndevice_id='other'\naccount_id='acct'",
    ] {
        fs::write(&path, invalid).unwrap();
        assert!(matches!(Config::load(&path), Err(Error::Config)));
    }
    fs::write(&path, "x".repeat(16 * 1024 + 1)).unwrap();
    assert!(matches!(Config::load(&path), Err(Error::Config)));
}

#[tokio::test]
async fn queue_survives_restart_and_partial_batch_completion() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("queue");
    let first = envelope(1, "directive");
    let raw = first.0.get().replace(",", ", ");
    let first = Envelope(RawValue::from_string(raw.clone()).unwrap());
    let queue = Queue::open(&path).unwrap();
    assert!(matches!(Queue::open(&path), Err(Error::QueueBusy)));
    queue
        .append(vec![first, envelope(2, "grant"), envelope(3, "directive")])
        .await
        .unwrap();
    queue.append(vec![envelope(4, "directive")]).await.unwrap();
    let batch = queue.front().await.unwrap().unwrap();
    assert_eq!(batch.envelopes[0].0.get(), raw);
    queue.complete_prefix(batch.sequence, 1).await.unwrap();
    drop(queue);
    let queue = Queue::open(&path).unwrap();
    let batch = queue.front().await.unwrap().unwrap();
    assert_eq!(
        batch.envelopes.iter().map(id).collect::<Vec<_>>(),
        ["message-2", "message-3"]
    );
    queue.complete_prefix(batch.sequence, 2).await.unwrap();
    let batch = queue.front().await.unwrap().unwrap();
    assert_eq!(id(&batch.envelopes[0]), "message-4");
    queue.complete_prefix(batch.sequence, 1).await.unwrap();
    assert!(queue.front().await.unwrap().is_none());
}

#[tokio::test]
async fn queue_recovers_complete_temporary_files_and_preserves_corrupt_files() {
    let directory = tempfile::tempdir().unwrap();
    let temporary = directory.path().join("00000000000000000004.tmp");
    fs::write(
        &temporary,
        serde_json::to_vec(&[envelope(4, "grant")]).unwrap(),
    )
    .unwrap();
    let queue = Queue::open(directory.path()).unwrap();
    assert_eq!(queue.front().await.unwrap().unwrap().sequence, 4);
    drop(queue);
    let corrupt = directory.path().join("00000000000000000005.json");
    fs::write(&corrupt, b"[broken").unwrap();
    assert!(matches!(
        Queue::open(directory.path()),
        Err(Error::QueueCorrupt)
    ));
    assert_eq!(fs::read(corrupt).unwrap(), b"[broken");
}

#[tokio::test]
async fn queue_refuses_plaintext_or_invalid_helper_output() {
    let directory = tempfile::tempdir().unwrap();
    let queue = Queue::open(directory.path()).unwrap();
    let plaintext: Envelope = serde_json::from_value(json!({"id":"bad", "type":"grant", "exp":1,
        "credential":"must not reach disk"}))
    .unwrap();
    assert!(matches!(
        queue.append(vec![plaintext]).await,
        Err(Error::HelperProtocol)
    ));
    assert!(queue.front().await.unwrap().is_none());
    assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 1);
}

#[cfg(unix)]
#[tokio::test]
async fn queue_rejects_symlinks_and_uses_private_permissions() {
    use std::os::unix::fs::{symlink, PermissionsExt};
    let directory = tempfile::tempdir().unwrap();
    let real = directory.path().join("real");
    let link = directory.path().join("link");
    fs::create_dir(&real).unwrap();
    symlink(&real, &link).unwrap();
    assert!(matches!(Queue::open(&link), Err(Error::QueueCorrupt)));
    let queue = Queue::open(&real).unwrap();
    queue.append(vec![envelope(1, "grant")]).await.unwrap();
    assert_eq!(
        fs::metadata(&real).unwrap().permissions().mode() & 0o777,
        0o700
    );
    let committed = real.join("00000000000000000001.json");
    assert_eq!(
        fs::metadata(&committed).unwrap().permissions().mode() & 0o777,
        0o600
    );
    drop(queue);
    fs::remove_file(&committed).unwrap();
    symlink(directory.path().join("unrelated"), &committed).unwrap();
    assert!(matches!(Queue::open(&real), Err(Error::QueueCorrupt)));
}

#[tokio::test]
async fn ipc_requires_a_complete_bounded_json_line() {
    use tokio::io::{AsyncWriteExt, BufReader};
    for bytes in [
        b"{\"ok\":true}".to_vec(),
        vec![b'x'; kv_ipc::MAX_LINE_BYTES + 1],
    ] {
        let (mut writer, reader) = tokio::io::duplex(4096);
        let task = tokio::spawn(async move {
            let _ = writer.write_all(&bytes).await;
        });
        let error = helper::read_json::<Value>(&mut BufReader::new(reader))
            .await
            .unwrap_err();
        assert!(matches!(error, Error::HelperProtocol));
        task.await.unwrap();
    }
}

#[tokio::test]
async fn authentication_uses_helper_identity_and_signature_before_websocket() {
    let events = events();
    let helper = FakeHelper::start(events.clone(), true).await;
    let state = RelayState::new(&helper);
    let relay = FakeRelay::start(state.clone()).await;
    let directory = tempfile::tempdir().unwrap();
    let queue = Queue::open(directory.path()).unwrap();
    helper.enqueue(vec![envelope(1, "approval_request")]);
    let client = RunningClient::start(
        helper.client(true),
        relay.config(),
        queue.clone(),
        fast_timing(),
    );
    wait_for(|| received_ids(&state).len() == 1 && state.data.lock().unwrap().pings >= 2).await;
    wait_for(|| {
        helper
            .data
            .lock()
            .unwrap()
            .statuses
            .iter()
            .filter(|status| status.connected)
            .count()
            >= 2
    })
    .await;
    {
        let log = events.lock().unwrap();
        let positions: Vec<_> = [
            "identity",
            "challenge",
            "sign",
            "verify",
            "ws",
            "waiting",
            "post",
        ]
        .iter()
        .map(|name| log.iter().position(|event| event == name).unwrap())
        .collect();
        assert!(positions.windows(2).all(|pair| pair[0] < pair[1]));
        assert!(log.iter().any(|event| event == "select-relay"));
    }
    assert_eq!(helper.data.lock().unwrap().signed, [vec![9; 32]]);
    wait_for(|| received_ids(&state) == ["message-1"]).await;
    wait_for_queue_empty(&queue).await;
    client.stop().await;
    assert!(queue.front().await.unwrap().is_none());
    assert!(
        !helper
            .data
            .lock()
            .unwrap()
            .statuses
            .last()
            .unwrap()
            .connected
    );
    relay.stop().await;
}

#[tokio::test]
async fn waiting_and_websocket_ack_require_helper_true_and_preserve_future_envelopes() {
    let events = events();
    let helper = FakeHelper::start(events.clone(), false).await;
    helper.data.lock().unwrap().ack = Some(false);
    let state = RelayState::new(&helper);
    state
        .data
        .lock()
        .unwrap()
        .waiting
        .push(envelope(77, "approval_request"));
    let relay = FakeRelay::start(state.clone()).await;
    let directory = tempfile::tempdir().unwrap();
    let queue = Queue::open(directory.path()).unwrap();
    helper.enqueue(vec![envelope(1, "grant")]);
    let client = RunningClient::start(
        helper.client(false),
        relay.config(),
        queue.clone(),
        fast_timing(),
    );
    wait_for(|| !helper.data.lock().unwrap().received.is_empty()).await;
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(state.data.lock().unwrap().acknowledgments.is_empty());
    assert!(received_ids(&state).is_empty());
    assert!(queue.front().await.unwrap().is_some());
    helper.data.lock().unwrap().ack = None;
    wait_for(|| {
        helper
            .data
            .lock()
            .unwrap()
            .statuses
            .iter()
            .any(|status| status.last_error.as_deref() == Some("helper_rejected_request"))
    })
    .await;
    assert!(state.data.lock().unwrap().acknowledgments.is_empty());
    helper.data.lock().unwrap().ack = Some(true);
    wait_for(|| {
        received_ids(&state) == ["message-1"]
            && state
                .data
                .lock()
                .unwrap()
                .acknowledgments
                .contains(&"message-77".into())
    })
    .await;
    {
        let log = events.lock().unwrap();
        assert!(
            log.iter()
                .position(|event| event == "ack:message-77")
                .unwrap()
                < log.iter().position(|event| event == "post").unwrap()
        );
    }
    let raw = "{ \"v\":999, \"type\":\"future\", \"id\":\"future-id\", \"exp\":0, \"extension\":{\"opaque\":true} }";
    state.push(Envelope(RawValue::from_string(raw.into()).unwrap()));
    wait_for(|| {
        state
            .data
            .lock()
            .unwrap()
            .acknowledgments
            .contains(&"future-id".into())
    })
    .await;
    assert!(helper
        .data
        .lock()
        .unwrap()
        .received
        .iter()
        .any(|received| received == raw));
    client.stop().await;
    relay.stop().await;
}

#[tokio::test]
async fn slow_helper_does_not_block_heartbeat_and_missing_pong_reconnects() {
    let helper = FakeHelper::start(events(), false).await;
    helper.data.lock().unwrap().inbound_delay = Duration::from_millis(600);
    let state = RelayState::new(&helper);
    state
        .data
        .lock()
        .unwrap()
        .waiting
        .push(envelope(1, "grant"));
    let relay = FakeRelay::start(state.clone()).await;
    let directory = tempfile::tempdir().unwrap();
    let client = RunningClient::start(
        helper.client(false),
        relay.config(),
        Queue::open(directory.path()).unwrap(),
        fast_timing(),
    );
    wait_for(|| state.data.lock().unwrap().pings >= 2).await;
    assert!(state.data.lock().unwrap().acknowledgments.is_empty());
    wait_for(|| !state.data.lock().unwrap().acknowledgments.is_empty()).await;
    state.data.lock().unwrap().pong = false;
    wait_for(|| state.data.lock().unwrap().connections >= 2).await;
    assert!(helper.data.lock().unwrap().statuses.iter().any(
        |status| !status.connected && status.last_error.as_deref() == Some("relay_unreachable")
    ));
    state.data.lock().unwrap().pong = true;
    client.stop().await;
    relay.stop().await;
}

#[tokio::test]
async fn malformed_envelope_is_still_inspected_by_helper_before_transport_ack() {
    let helper = FakeHelper::start(events(), false).await;
    let state = RelayState::new(&helper);
    let relay = FakeRelay::start(state.clone()).await;
    let directory = tempfile::tempdir().unwrap();
    let client = RunningClient::start(
        helper.client(false),
        relay.config(),
        Queue::open(directory.path()).unwrap(),
        fast_timing(),
    );
    wait_for(|| state.data.lock().unwrap().connections >= 1).await;
    let raw = "{ \"v\":999, \"ct\":\"AA\" }";
    state.push(Envelope(RawValue::from_string(raw.into()).unwrap()));
    wait_for(|| {
        helper
            .data
            .lock()
            .unwrap()
            .received
            .iter()
            .any(|received| received == raw)
    })
    .await;
    assert!(state.data.lock().unwrap().acknowledgments.is_empty());
    client.stop().await;
    relay.stop().await;
}

#[tokio::test]
async fn rate_limit_and_server_errors_delay_the_same_fifo_prefix() {
    let helper = FakeHelper::start(events(), false).await;
    let state = RelayState::new(&helper);
    state.data.lock().unwrap().failures.extend([
        Failure {
            path: "/v1/messages",
            status: 429,
            retry_after: Some(1),
        },
        Failure {
            path: "/v1/messages",
            status: 503,
            retry_after: None,
        },
    ]);
    let relay = FakeRelay::start(state.clone()).await;
    let directory = tempfile::tempdir().unwrap();
    let queue = Queue::open(directory.path()).unwrap();
    let mut timing = fast_timing();
    timing.heartbeat = Duration::from_secs(10);
    timing.initial_backoff = Duration::from_millis(40);
    helper.enqueue(vec![envelope(1, "grant")]);
    let client = RunningClient::start(helper.client(false), relay.config(), queue.clone(), timing);
    wait_for(|| !state.data.lock().unwrap().attempts.is_empty()).await;
    helper.enqueue(vec![envelope(2, "directive"), envelope(3, "grant")]);
    wait_for(|| helper.data.lock().unwrap().outgoing.is_empty()).await;
    assert!(received_ids(&state).is_empty());
    assert!(queue.front().await.unwrap().is_some());
    wait_for(|| received_ids(&state).len() == 3).await;
    {
        let data = state.data.lock().unwrap();
        assert_eq!(
            data.attempts[..3]
                .iter()
                .map(|(_, ids)| ids.clone())
                .collect::<Vec<_>>(),
            [vec!["message-1"], vec!["message-1"], vec!["message-1"]]
        );
        assert!(data.attempts[1].0 - data.attempts[0].0 >= Duration::from_millis(990));
        assert!(data.attempts[2].0 - data.attempts[1].0 >= Duration::from_millis(75));
    }
    assert_eq!(
        received_ids(&state),
        ["message-1", "message-2", "message-3"]
    );
    assert!(helper
        .data
        .lock()
        .unwrap()
        .statuses
        .iter()
        .any(|status| status.last_error.as_deref() == Some("relay_http_429")));
    wait_for_queue_empty(&queue).await;
    client.stop().await;
    relay.stop().await;
}

#[tokio::test]
async fn partial_acceptance_and_conflict_never_discard_a_queue_prefix() {
    let helper = FakeHelper::start(events(), false).await;
    let state = RelayState::new(&helper);
    state.data.lock().unwrap().partial_accept = true;
    let relay = FakeRelay::start(state.clone()).await;
    let directory = tempfile::tempdir().unwrap();
    let queue = Queue::open(directory.path()).unwrap();
    helper.enqueue(vec![envelope(1, "grant"), envelope(2, "directive")]);
    let client = RunningClient::start(
        helper.client(false),
        relay.config(),
        queue.clone(),
        fast_timing(),
    );
    wait_for(|| state.data.lock().unwrap().attempts.len() >= 2).await;
    assert_eq!(queue.front().await.unwrap().unwrap().envelopes.len(), 2);
    {
        let mut data = state.data.lock().unwrap();
        data.partial_accept = false;
        data.failures.push_back(Failure {
            path: "/v1/messages",
            status: 409,
            retry_after: None,
        });
    }
    wait_for(|| {
        helper
            .data
            .lock()
            .unwrap()
            .statuses
            .iter()
            .any(|status| status.last_error.as_deref() == Some("relay_http_409"))
    })
    .await;
    assert_eq!(queue.front().await.unwrap().unwrap().envelopes.len(), 2);
    wait_for(|| received_ids(&state).len() == 2).await;
    wait_for_queue_empty(&queue).await;
    client.stop().await;
    relay.stop().await;
}

#[tokio::test]
async fn client_restart_recovers_ciphertext_without_persisting_tokens() {
    let helper = FakeHelper::start(events(), false).await;
    let state = RelayState::new(&helper);
    let relay = FakeRelay::start(state.clone()).await;
    let address = relay.address;
    let config = relay.config();
    relay.stop().await;
    let directory = tempfile::tempdir().unwrap();
    let queue = Queue::open(directory.path()).unwrap();
    helper.enqueue(vec![envelope(1, "grant"), envelope(2, "directive")]);
    let client = RunningClient::start(
        helper.client(false),
        config.clone(),
        queue.clone(),
        fast_timing(),
    );
    wait_for(|| directory.path().join("00000000000000000001.json").exists()).await;
    client.stop().await;
    let bytes = fs::read(directory.path().join("00000000000000000001.json")).unwrap();
    let envelopes: Vec<Envelope> = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(
        envelopes.iter().map(id).collect::<Vec<_>>(),
        ["message-1", "message-2"]
    );
    assert!(!String::from_utf8(bytes)
        .unwrap()
        .contains("session-memory-only"));
    drop(queue);
    let queue = Queue::open(directory.path()).unwrap();
    let relay = FakeRelay::at(address, state.clone()).await;
    let client = RunningClient::start(helper.client(false), config, queue.clone(), fast_timing());
    wait_for(|| received_ids(&state).len() == 2).await;
    wait_for_queue_empty(&queue).await;
    client.stop().await;
    assert!(queue.front().await.unwrap().is_none());
    relay.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn thirty_second_relay_outage_delivers_every_envelope_in_order() {
    let helper = FakeHelper::start(events(), false).await;
    let state = RelayState::new(&helper);
    let relay = FakeRelay::start(state.clone()).await;
    let address = relay.address;
    let config = relay.config();
    let directory = tempfile::tempdir().unwrap();
    let queue = Queue::open(directory.path()).unwrap();
    let client = RunningClient::start(
        helper.client(false),
        config,
        queue.clone(),
        Timing::default(),
    );
    wait_for(|| state.data.lock().unwrap().connections == 1).await;
    relay.stop().await;
    for wave in 0..3 {
        helper.enqueue(
            (wave * 3..wave * 3 + 3)
                .map(|n| envelope(n, "grant"))
                .collect(),
        );
        tokio::time::sleep(Duration::from_secs(10)).await;
    }
    assert!(helper.data.lock().unwrap().statuses.iter().any(
        |status| !status.connected && status.last_error.as_deref() == Some("relay_unreachable")
    ));
    let files = fs::read_dir(directory.path())
        .unwrap()
        .filter(|entry| {
            entry
                .as_ref()
                .unwrap()
                .path()
                .extension()
                .is_some_and(|ext| ext == "json")
        })
        .count();
    assert_eq!(files, 3);
    let relay = FakeRelay::at(address, state.clone()).await;
    // Restoring the listener does not wake an outstanding production reconnect backoff.
    wait_for_timeout(
        Timing::default().maximum_backoff + Duration::from_secs(5),
        || received_ids(&state).len() == 9,
    )
    .await;
    assert_eq!(
        received_ids(&state),
        (0..9).map(|n| format!("message-{n}")).collect::<Vec<_>>()
    );
    wait_for_queue_empty(&queue).await;
    client.stop().await;
    assert!(queue.front().await.unwrap().is_none());
    relay.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn w2_relay_authenticates_delivers_waiting_messages_and_resolves_approval_reply() {
    use kv_core::remote::{self, keys::DeviceKeyProvider};
    let helper = FakeHelper::start(events(), false).await;
    let (url, server) = kv_server::spawn_test_relay();
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../kv-core/testdata/remote/envelope_roundtrip.json");
    let vector: Value = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
    let mut device = vector["sender"].clone();
    device["device_id"] = json!("dev-client");
    device["dk_pub"] = serde_json::to_value(helper.key.public_jwk().unwrap()).unwrap();
    let registration: Value = reqwest::Client::new()
        .post(url.join("v1/devices").unwrap())
        .json(&device)
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    let config = Config {
        relay_url: url.to_string(),
        device_id: "dev-client".into(),
        account_id: registration["account_id"].as_str().unwrap().into(),
    };
    let expiration = transport::unix_now() + 3600;
    helper.data.lock().unwrap().account_id = config.account_id.clone();
    let make_envelope = |id: &str, kind: remote::EnvelopeType| {
        let sealed = remote::envelope::seal(
            remote::EnvelopeHeader {
                v: 1,
                r#type: kind,
                id: id.into(),
                account: config.account_id.clone(),
                from: config.device_id.clone(),
                to: config.device_id.clone(),
                created_at: transport::unix_now(),
                exp: expiration,
                extra: remote::Extra::new(),
            },
            b"opaque test payload",
            &helper.key.public_jwk().unwrap(),
            helper.key.as_ref(),
        )
        .unwrap();
        serde_json::from_str::<Envelope>(&serde_json::to_string(&sealed).unwrap()).unwrap()
    };
    let approval_id = "01ARZ3NDEKTSV4RRFFQ69G5FAV";
    let approval = make_envelope(approval_id, remote::EnvelopeType::ApprovalRequest);
    let relay = transport::Relay::new(&config).unwrap();
    let session = relay.authenticate(&helper.client(false)).await.unwrap();
    let group = Group::first(std::slice::from_ref(&approval)).unwrap();
    relay.send(&session, &group, &[approval]).await.unwrap();
    let directory = tempfile::tempdir().unwrap();
    let queue = Queue::open(directory.path()).unwrap();
    helper.enqueue(vec![make_envelope(
        "01ARZ3NDEKTSV4RRFFQ69G5FAW",
        remote::EnvelopeType::Grant,
    )]);
    let client = RunningClient::start(
        helper.client(false),
        config.clone(),
        queue.clone(),
        fast_timing(),
    );
    wait_for(|| {
        server.inspect(|db| {
            db.query_row(
                "SELECT COUNT(*) FROM messages WHERE acked_at IS NOT NULL",
                [],
                |row| row.get::<_, i64>(0),
            )
            .unwrap()
        }) == 2
    })
    .await;
    assert_eq!(
        serde_json::from_str::<Value>(&helper.data.lock().unwrap().received[0]).unwrap()["type"],
        "approval_request"
    );
    helper.enqueue(vec![make_envelope(
        approval_id,
        remote::EnvelopeType::ApprovalDecision,
    )]);
    wait_for(|| {
        server.inspect(|db| {
            db.query_row(
                "SELECT COUNT(*) FROM approvals WHERE state='resolved'",
                [],
                |row| row.get::<_, i64>(0),
            )
            .unwrap()
        }) == 1
    })
    .await;
    wait_for_queue_empty(&queue).await;
    client.stop().await;
    assert!(queue.front().await.unwrap().is_none());
    assert!(helper
        .data
        .lock()
        .unwrap()
        .signed
        .iter()
        .all(|challenge| challenge.len() == 32));
    server.shutdown().await;
}

#[test]
fn routing_keeps_fanout_batches_and_reply_cancel_semantics() {
    let request = envelope(1, "approval_request");
    let mut fanout: Value = serde_json::from_str(request.0.get()).unwrap();
    fanout["to"] = json!("dev-another");
    let fanout = serde_json::from_value(fanout).unwrap();
    let group = Group::first(&[request, fanout, envelope(2, "grant")]).unwrap();
    assert_eq!(group.count, 2);
    assert!(matches!(group.route, Route::Approvals { .. }));
    assert!(matches!(
        Group::first(&[envelope(1, "approval_escalate")])
            .unwrap()
            .route,
        Route::Approvals { .. }
    ));
    let group = Group::first(&[
        envelope(1, "approval_decision"),
        envelope(2, "approval_decision"),
    ])
    .unwrap();
    assert_eq!(group.count, 1);
    assert!(matches!(group.route, Route::Reply(_)));
    assert!(matches!(
        Group::first(&[envelope(1, "approval_cancel")])
            .unwrap()
            .route,
        Route::Cancel(_)
    ));
}
