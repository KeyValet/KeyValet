//! Control transport crosses real helper IPC before a runtime or binding exists. OS peer/code
//! inspection is injected at the connector; no installed helper, privilege or GUI is needed.
use super::*;
use kv_core::remote::{keys::DeviceKeyProvider, relay::*, relay_control::*, *};
use kv_helper::remote::{ipc::CallerContext, relay_control, server};
use kv_ipc::remote::Caller;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cold_helper_registration_and_signing_cross_real_control_ipc_without_session_tokens() {
    let directory = tempfile::tempdir().unwrap();
    let endpoint = directory.path().join("cold-helper.sock");
    let listener = tokio::net::UnixListener::bind(&endpoint).unwrap();
    let serving = tokio::spawn(async move {
        let mut connections = tokio::task::JoinSet::new();
        loop {
            let (stream, _) = listener.accept().await.unwrap();
            connections.spawn(async move {
                let (reader, writer) = stream.into_split();
                server::serve(
                    reader,
                    writer,
                    CallerContext::authenticated(Caller::RelayClient, 501, 0, 210),
                    None,
                )
                .await
                .unwrap();
            });
            while connections.try_join_next().is_some() {}
        }
    });
    let (url, relay) = kv_server::spawn_test_relay();
    let helper = helper::Helper::for_test(endpoint, true);
    let (shutdown, receiver) = tokio::sync::watch::channel(false);
    let config = directory.path().join("not-created.toml");
    let queue = directory.path().join("queue");
    let running = tokio::spawn({
        let config = config.clone();
        let queue = queue.clone();
        async move { crate::app::run(&config, &queue, helper, receiver).await }
    });
    let key = Arc::new(SoftwareDeviceKey::generate_p256());
    let local = DeviceRecord {
        device_id: "dev-cold-control".into(),
        label: "Cold executor".into(),
        os: Os::Linux,
        key_kind: KeyKind::Software,
        dk_pub: key.public_jwk().unwrap(),
        dk_sig: kv_core::remote::Optional::Missing,
        ak_q: None,
        ak_s: None,
        caps: vec![Capability::Execute],
        attestation: None,
        extra: Extra::new(),
    };
    let registered = tokio::time::timeout(
        Duration::from_secs(10),
        relay_control::hub().submit(
            url.to_string(),
            None,
            RelayControlCommand::Register(RegisterDeviceRequest {
                device: local.clone(),
                push_token: Optional::Missing,
            }),
            None,
        ),
    )
    .await
    .unwrap()
    .unwrap();
    let RelayControlResult::Registered(registered) = registered else {
        panic!("wrong registration shape");
    };
    assert_eq!(registered.device_id, local.device_id);
    assert!(registered.recovery_code.as_value().is_some());
    let authenticated = tokio::time::timeout(
        Duration::from_secs(10),
        relay_control::hub().submit(
            url.to_string(),
            None,
            RelayControlCommand::Authenticate(local.clone()),
            Some(key),
        ),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(
        serde_json::to_value(&authenticated).unwrap(),
        json!({"kind":"authenticated",
        "value":{"account_id":registered.account_id}})
    );
    assert!(!serde_json::to_string(&authenticated)
        .unwrap()
        .contains("session_token"));
    assert!(
        !queue.exists(),
        "unbound control mode must not open the envelope spool"
    );
    let pending = tokio::time::timeout(
        Duration::from_secs(10),
        relay_control::hub().submit(
            url.to_string(),
            Some(local.device_id),
            RelayControlCommand::Pending,
            None,
        ),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(pending, RelayControlResult::Pending(Vec::new()));
    shutdown.send(true).unwrap();
    tokio::time::timeout(Duration::from_secs(5), running)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    serving.abort();
    relay.shutdown().await;
}

#[tokio::test]
async fn unbound_service_waits_and_reloads_a_changed_binding_without_losing_controls() {
    let helper = FakeHelper::start(events(), false).await;
    let first_state = RelayState::new(&helper);
    let first = FakeRelay::start(first_state.clone()).await;
    let second_state = RelayState::new(&helper);
    let second = FakeRelay::start(second_state.clone()).await;
    let directory = tempfile::tempdir().unwrap();
    let config = directory.path().join("relay-client.toml");
    let queue = directory.path().join("queue");
    let (shutdown, receiver) = tokio::sync::watch::channel(false);
    let running = tokio::spawn({
        let config = config.clone();
        let queue = queue.clone();
        let helper = helper.client(false);
        async move { crate::app::run(&config, &queue, helper, receiver).await }
    });
    wait_until(|| {
        helper
            .events
            .lock()
            .unwrap()
            .iter()
            .any(|event| event == "control-poll")
    })
    .await;
    assert!(!queue.exists());
    for (relay, state) in [(&first, &first_state), (&second, &second_state)] {
        let binding = relay.config();
        fs::write(
            &config,
            format!(
                "relay_url='{}'\ndevice_id='{}'\naccount_id='{}'\n",
                binding.relay_url, binding.device_id, binding.account_id
            ),
        )
        .unwrap();
        wait_until(|| state.data.lock().unwrap().connections > 0).await;
        assert!(queue.join("queue.lock").is_file());
        assert!(!running.is_finished());
    }
    shutdown.send(true).unwrap();
    tokio::time::timeout(Duration::from_secs(5), running)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    first.stop().await;
    second.stop().await;
}

async fn wait_until(check: impl Fn() -> bool) {
    let until = tokio::time::Instant::now() + Duration::from_secs(5);
    while !check() {
        assert!(
            tokio::time::Instant::now() < until,
            "control/binding did not progress"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

#[test]
fn incomplete_binding_is_distinct_from_invalid_configuration() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("relay-client.toml");
    assert!(Config::load_optional(&path).unwrap().is_none());
    fs::write(&path, "relay_url='https://relay.example.com'\n").unwrap();
    assert!(Config::load_optional(&path).unwrap().is_none());
    for invalid in [
        "relay_url='http://relay.example.com'",
        "relay_url='https://relay.example.com'\nprivate_key='secret'",
        "relay_url='https://relay.example.com'\ndevice_id='dangling-device'",
        "relay_url='https://relay.example.com'\ndevice_id=''\naccount_id='acct'",
    ] {
        fs::write(&path, invalid).unwrap();
        assert!(Config::load_optional(&path).is_err());
    }
}
