use std::{
    collections::{BTreeMap, VecDeque},
    net::{Ipv4Addr, SocketAddr},
    path::PathBuf,
    sync::{Arc, Mutex},
    time::Duration,
};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use futures_util::{SinkExt, StreamExt};
use kv_core::remote::{
    keys::{DeviceKeyProvider, SoftwareDeviceKey},
    SignatureAlgorithm,
};
use kv_ipc::remote::{self, RelayStatusParams};
use serde::{Deserialize, Serialize};
use serde_json::{json, value::RawValue, Value};
use tempfile::TempDir;
use tokio::{
    io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader},
    net::{TcpSocket, TcpStream},
    sync::{broadcast, watch, Notify},
    task::{JoinHandle, JoinSet},
    time::Instant,
};
use tokio_tungstenite::tungstenite::{
    handshake::server::{Request, Response},
    Message,
};

use crate::{
    client::{Client, Timing},
    config::Config,
    envelope::Envelope,
    helper::{self, Helper},
    queue::Queue,
    transport::{unix_now, Relay, SUBPROTOCOL},
};

pub type Events = Arc<Mutex<Vec<String>>>;

pub fn event(events: &Events, name: impl Into<String>) {
    events.lock().unwrap().push(name.into());
}

pub struct HelperData {
    pub device_id: String,
    pub account_id: String,
    pub reply_overrides: BTreeMap<String, Value>,
    pub outgoing: VecDeque<Vec<Envelope>>,
    pub received: Vec<String>,
    pub statuses: Vec<RelayStatusParams>,
    pub signed: Vec<Vec<u8>>,
    pub receipts: Vec<remote::RelayOutboundAckParams<Envelope>>,
    pub receipt_failures: VecDeque<remote::OutboundStage>,
    pub retired_prefixes: VecDeque<usize>,
    pub ack: Option<bool>,
    pub inbound_delay: Duration,
}

pub struct FakeHelper {
    pub data: Arc<Mutex<HelperData>>,
    pub key: Arc<SoftwareDeviceKey>,
    pub endpoint: PathBuf,
    pub events: Events,
    wake: Arc<Notify>,
    task: JoinHandle<()>,
    _directory: TempDir,
}

impl FakeHelper {
    pub async fn start(events: Events, handshake: bool) -> Self {
        let directory = tempfile::tempdir().unwrap();
        #[cfg(unix)]
        let endpoint = directory.path().join("helper.sock");
        #[cfg(windows)]
        let endpoint: PathBuf = format!(
            r"\\.\pipe\keyvalet-w3-{}-{}",
            std::process::id(),
            directory.path().file_name().unwrap().to_string_lossy()
        )
        .into();
        let key = Arc::new(SoftwareDeviceKey::from_p256_bytes(&[1; 32]).unwrap());
        let data = Arc::new(Mutex::new(HelperData {
            device_id: "dev-client".into(),
            account_id: "acct-test".into(),
            reply_overrides: BTreeMap::new(),
            outgoing: VecDeque::new(),
            received: Vec::new(),
            statuses: Vec::new(),
            signed: Vec::new(),
            receipts: Vec::new(),
            receipt_failures: VecDeque::new(),
            retired_prefixes: VecDeque::new(),
            ack: Some(true),
            inbound_delay: Duration::ZERO,
        }));
        let wake = Arc::new(Notify::new());
        let task_data = data.clone();
        let task_key = key.clone();
        let task_events = events.clone();
        let task_wake = wake.clone();
        #[cfg(unix)]
        let listener = tokio::net::UnixListener::bind(&endpoint).unwrap();
        #[cfg(windows)]
        let first = tokio::net::windows::named_pipe::ServerOptions::new()
            .first_pipe_instance(true)
            .create(&endpoint)
            .unwrap();
        #[cfg(windows)]
        let pipe_name = endpoint.clone();
        let task = tokio::spawn(async move {
            let mut workers = JoinSet::new();
            #[cfg(windows)]
            let mut pipe = first;
            loop {
                #[cfg(unix)]
                let (stream, _) = listener.accept().await.unwrap();
                #[cfg(windows)]
                let stream = {
                    pipe.connect().await.unwrap();
                    let next = tokio::net::windows::named_pipe::ServerOptions::new()
                        .create(&pipe_name)
                        .unwrap();
                    std::mem::replace(&mut pipe, next)
                };
                workers.spawn(serve_helper(
                    stream,
                    task_data.clone(),
                    task_key.clone(),
                    task_events.clone(),
                    task_wake.clone(),
                    handshake,
                ));
                while workers.try_join_next().is_some() {}
            }
        });
        Self {
            data,
            key,
            endpoint,
            events,
            wake,
            task,
            _directory: directory,
        }
    }

    pub fn client(&self, handshake: bool) -> Helper {
        Helper::for_test(self.endpoint.clone(), handshake)
    }

    pub fn enqueue(&self, envelopes: Vec<Envelope>) {
        self.data.lock().unwrap().outgoing.push_back(envelopes);
        self.wake.notify_one();
    }
}

impl Drop for FakeHelper {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn serve_helper(
    stream: impl AsyncRead + AsyncWrite + Unpin,
    data: Arc<Mutex<HelperData>>,
    key: Arc<SoftwareDeviceKey>,
    events: Events,
    wake: Arc<Notify>,
    handshake: bool,
) {
    #[derive(Deserialize)]
    struct Wire {
        op: String,
        params: Box<RawValue>,
    }
    let mut stream = BufReader::new(stream);
    if handshake {
        let selection: Value = helper::read_json(&mut stream).await.unwrap();
        assert_eq!(selection, json!({"op":"relay","protocol":4}));
        event(&events, "select-relay");
        if helper::write_json(
            &mut stream,
            &kv_ipc::ReadyMessage::Ready {
                ready: kv_ipc::True,
                protocol: kv_ipc::PROTOCOL_VERSION,
            },
        )
        .await
        .is_err()
        {
            return;
        }
    }
    let Ok(request) = helper::read_json::<Wire>(&mut stream).await else {
        return;
    };
    let overridden = data
        .lock()
        .unwrap()
        .reply_overrides
        .get(&request.op)
        .cloned();
    if let Some(reply) = overridden {
        event(&events, format!("override:{}", request.op));
        let _ = helper::write_json(&mut stream, &reply).await;
        return;
    }
    let result = match request.op.as_str() {
        remote::RELAY_CONTROL_POLL => {
            event(&events, "control-poll");
            tokio::time::sleep(Duration::from_millis(30)).await;
            remote::Response::ok(json!({"request":null}))
        }
        helper::IDENTITY_OP => {
            event(&events, "identity");
            let data = data.lock().unwrap();
            remote::Response::ok(json!({"dk_pub":key.public_jwk().unwrap(),
                "device_id":data.device_id,"account_id":data.account_id}))
        }
        remote::RELAY_OUTBOUND_ACK => {
            let params: remote::RelayOutboundAckParams<Envelope> =
                serde_json::from_str(request.params.get()).unwrap();
            let mut data = data.lock().unwrap();
            let stage = params.stage;
            data.receipts.push(params);
            if data.receipt_failures.front() == Some(&stage) {
                data.receipt_failures.pop_front();
                remote::Response::err("state_unavailable", "state_unavailable")
            } else {
                let count = if stage == remote::OutboundStage::Inspect {
                    data.retired_prefixes.pop_front().unwrap_or(0)
                } else {
                    0
                };
                remote::Response::ok(json!({"retired_count":count}))
            }
        }
        remote::SIGN_IDENTITY => {
            let params: remote::SignIdentityParams =
                serde_json::from_str(request.params.get()).unwrap();
            let payload = URL_SAFE_NO_PAD.decode(params.payload_b64).unwrap();
            data.lock().unwrap().signed.push(payload.clone());
            event(&events, "sign");
            remote::Response::ok(json!({"sig_b64":URL_SAFE_NO_PAD.encode(
                key.sign(SignatureAlgorithm::ES256, &payload).unwrap())}))
        }
        remote::RELAY_OUTBOUND_POLL => {
            let params: remote::RelayOutboundPollParams =
                serde_json::from_str(request.params.get()).unwrap();
            assert_eq!(params.max_wait_ms, 30_000);
            let mut batch = data.lock().unwrap().outgoing.pop_front();
            if batch.is_none() {
                tokio::select! { _ = wake.notified() => {}, _ = tokio::time::sleep(Duration::from_millis(200)) => {} }
                batch = data.lock().unwrap().outgoing.pop_front();
            }
            let response = remote::Response::ok(remote::RelayOutboundPollResult {
                envelopes: batch.unwrap_or_default(),
                extra: remote::Extra::new(),
            });
            let _ = helper::write_json(&mut stream, &response).await;
            return;
        }
        remote::RELAY_INBOUND => {
            let params: remote::RelayInboundParams<Envelope> =
                serde_json::from_str(request.params.get()).unwrap();
            let id = id(&params.envelope);
            let (delay, ack) = {
                let mut data = data.lock().unwrap();
                data.received.push(params.envelope.0.get().into());
                (data.inbound_delay, data.ack)
            };
            event(&events, format!("inbound:{id}"));
            tokio::time::sleep(delay).await;
            match ack {
                Some(ack) => remote::Response::ok(json!({"ack":ack})),
                None => remote::Response::err("rejected", "must not escape into client logs"),
            }
        }
        remote::RELAY_STATUS => {
            let params: RelayStatusParams = serde_json::from_str(request.params.get()).unwrap();
            event(&events, format!("status:{}", params.connected));
            data.lock().unwrap().statuses.push(params);
            remote::Response::ok(json!({}))
        }
        _ => panic!("unexpected helper operation"),
    };
    let _ = helper::write_json(&mut stream, &result).await;
}

pub fn envelope(number: u32, kind: &str) -> Envelope {
    serde_json::from_value(json!({"v":1,"type":kind,"id":format!("message-{number}"),
        "account":"acct-test","from":"dev-client","to":"dev-peer","created_at":unix_now(),
        "exp":unix_now()+3600,"enc":"AQID","ct":"ZW5jcnlwdGVk","sig":"c2ln",
        "future":{"opaque":[1,2,3]}}))
    .unwrap()
}

pub fn id(envelope: &Envelope) -> String {
    let value: Value = serde_json::from_str(envelope.0.get()).unwrap();
    value["id"].as_str().unwrap_or("missing-id").into()
}

#[derive(Clone)]
pub struct Failure {
    pub path: &'static str,
    pub status: u16,
    pub retry_after: Option<u64>,
}

pub struct RelayData {
    pub waiting: Vec<Envelope>,
    pub received: Vec<String>,
    pub acknowledgments: Vec<String>,
    pub attempts: Vec<(Instant, Vec<String>)>,
    pub failures: VecDeque<Failure>,
    pub connections: usize,
    pub pings: usize,
    pub pong: bool,
    pub partial_accept: bool,
    pub session_lifetime: i64,
}

#[derive(Clone)]
pub struct RelayState {
    pub data: Arc<Mutex<RelayData>>,
    pub events: Events,
    pub key: Arc<SoftwareDeviceKey>,
    frames: broadcast::Sender<String>,
}

impl RelayState {
    pub fn new(helper: &FakeHelper) -> Self {
        let (frames, _) = broadcast::channel(64);
        Self {
            data: Arc::new(Mutex::new(RelayData {
                waiting: Vec::new(),
                received: Vec::new(),
                acknowledgments: Vec::new(),
                attempts: Vec::new(),
                failures: VecDeque::new(),
                connections: 0,
                pings: 0,
                pong: true,
                partial_accept: false,
                session_lifetime: 86400,
            })),
            events: helper.events.clone(),
            key: helper.key.clone(),
            frames,
        }
    }

    pub fn push(&self, envelope: Envelope) {
        self.data.lock().unwrap().waiting.push(envelope.clone());
        let text = format!("{{\"t\":\"envelope\",\"envelope\":{}}}", envelope.0.get());
        let _ = self.frames.send(text);
    }
}

pub struct FakeRelay {
    pub address: SocketAddr,
    shutdown: watch::Sender<bool>,
    task: JoinHandle<()>,
}

impl FakeRelay {
    pub async fn start(state: RelayState) -> Self {
        Self::at(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)), state).await
    }

    pub async fn at(address: SocketAddr, state: RelayState) -> Self {
        let socket = TcpSocket::new_v4().unwrap();
        socket.set_reuseaddr(true).unwrap();
        socket.bind(address).unwrap();
        let listener = socket.listen(128).unwrap();
        let address = listener.local_addr().unwrap();
        let (shutdown, mut receiver) = watch::channel(false);
        let task = tokio::spawn(async move {
            let mut workers = JoinSet::new();
            loop {
                tokio::select! {
                    _ = receiver.changed() => break,
                    accepted = listener.accept() => {
                        let (stream, _) = accepted.unwrap();
                        workers.spawn(serve_relay(stream, state.clone()));
                    }
                    _ = workers.join_next(), if !workers.is_empty() => {},
                }
            }
            workers.abort_all();
            while workers.join_next().await.is_some() {}
        });
        Self {
            address,
            shutdown,
            task,
        }
    }

    pub async fn stop(self) {
        self.shutdown.send(true).unwrap();
        self.task.await.unwrap();
    }

    pub fn config(&self) -> Config {
        Config {
            relay_url: format!("http://{}/", self.address),
            device_id: "dev-client".into(),
            account_id: "acct-test".into(),
        }
    }
}

async fn serve_relay(mut stream: TcpStream, state: RelayState) {
    let mut peek = [0u8; 4096];
    loop {
        let count = stream.peek(&mut peek).await.unwrap();
        if count == 0 {
            return;
        }
        if peek[..count].contains(&b'\n') {
            break;
        }
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
    if peek.starts_with(b"GET /v1/presence ") {
        let Ok(mut socket) = tokio_tungstenite::accept_hdr_async(stream, accept_headers).await
        else {
            return;
        };
        let mut frames = state.frames.subscribe();
        state.data.lock().unwrap().connections += 1;
        event(&state.events, "ws");
        loop {
            tokio::select! {
                frame = frames.recv() => {
                    if socket.send(Message::Text(frame.unwrap().into())).await.is_err() { break; }
                }
                message = socket.next() => {
                    match message {
                        Some(Ok(Message::Text(text))) => {
                            assert_eq!(serde_json::from_str::<Value>(&text).unwrap(), json!({"t":"ping"}));
                            let pong = { let mut data = state.data.lock().unwrap(); data.pings += 1; data.pong };
                            if pong && socket.send(Message::Text("{\"t\":\"pong\"}".into())).await.is_err() { break; }
                        }
                        Some(Ok(Message::Ping(bytes))) => { let _ = socket.send(Message::Pong(bytes)).await; }
                        _ => break,
                    }
                }
            }
        }
        return;
    }
    let mut stream = BufReader::new(&mut stream);
    let mut request = String::new();
    stream.read_line(&mut request).await.unwrap();
    let path = request.split_whitespace().nth(1).unwrap().to_string();
    let mut length = 0;
    let mut authorization = String::new();
    loop {
        let mut header = String::new();
        stream.read_line(&mut header).await.unwrap();
        if header == "\r\n" {
            break;
        }
        let (name, value) = header.split_once(':').unwrap();
        if name.eq_ignore_ascii_case("content-length") {
            length = value.trim().parse::<usize>().unwrap();
        }
        if name.eq_ignore_ascii_case("authorization") {
            authorization = value.trim().into();
        }
    }
    let mut body = vec![0u8; length];
    stream.read_exact(&mut body).await.unwrap();
    let body: &[u8] = if body.is_empty() { b"{}" } else { &body };
    if !path.starts_with("/v1/auth/") {
        assert!(authorization.starts_with("Device session-"));
    }
    let failure = {
        let mut data = state.data.lock().unwrap();
        if data
            .failures
            .front()
            .is_some_and(|failure| failure.path == path)
        {
            data.failures.pop_front()
        } else {
            None
        }
    };
    if path == "/v1/messages" || path == "/v1/approvals" {
        #[derive(Deserialize)]
        struct Outgoing {
            envelopes: Vec<Envelope>,
        }
        let outgoing: Outgoing = serde_json::from_slice(body).unwrap();
        state
            .data
            .lock()
            .unwrap()
            .attempts
            .push((Instant::now(), outgoing.envelopes.iter().map(id).collect()));
        event(&state.events, "post");
    }
    let mut raw_body = None;
    let (status, result, retry_after) = if let Some(failure) = failure {
        (
            failure.status,
            json!({"error":{"code":"rate_limited","message":"never log this body"}}),
            failure.retry_after,
        )
    } else {
        let result = match path.as_str() {
            "/v1/auth/challenge" => {
                assert_eq!(
                    serde_json::from_slice::<Value>(body).unwrap()["device_id"],
                    "dev-client"
                );
                event(&state.events, "challenge");
                json!({"challenge":URL_SAFE_NO_PAD.encode([9;32]),"exp":unix_now()+60})
            }
            "/v1/auth/verify" => {
                let value: Value = serde_json::from_slice(body).unwrap();
                let challenge = URL_SAFE_NO_PAD
                    .decode(value["challenge"].as_str().unwrap())
                    .unwrap();
                let sig = URL_SAFE_NO_PAD
                    .decode(value["sig"].as_str().unwrap())
                    .unwrap();
                kv_core::remote::keys::verify_signature(
                    SignatureAlgorithm::ES256,
                    &state.key.public_jwk().unwrap(),
                    &challenge,
                    &sig,
                )
                .unwrap();
                event(&state.events, "verify");
                json!({"session_token":"session-memory-only","exp":unix_now()+state.data.lock().unwrap().session_lifetime})
            }
            "/v1/approvals?state=waiting" => {
                event(&state.events, "waiting");
                #[derive(Serialize)]
                struct Waiting<'a> {
                    envelopes: &'a [Envelope],
                }
                // Do not convert RawValue through Value: waiting must retain exactly the same
                // opaque bytes as WS delivery, regardless of which reaches the helper first.
                raw_body = Some(
                    serde_json::to_vec(&Waiting {
                        envelopes: &state.data.lock().unwrap().waiting,
                    })
                    .unwrap(),
                );
                Value::Null
            }
            "/v1/messages/ack" => {
                let value: Value = serde_json::from_slice(body).unwrap();
                let ids: Vec<String> = serde_json::from_value(value["ids"].clone()).unwrap();
                let mut data = state.data.lock().unwrap();
                for id in &ids {
                    event(&state.events, format!("ack:{id}"));
                }
                data.waiting.retain(|envelope| !ids.contains(&id(envelope)));
                data.acknowledgments.extend(ids);
                json!({"ok":true})
            }
            "/v1/messages" | "/v1/approvals" => {
                #[derive(Deserialize)]
                struct Outgoing {
                    envelopes: Vec<Envelope>,
                }
                let outgoing: Outgoing = serde_json::from_slice(body).unwrap();
                let mut data = state.data.lock().unwrap();
                let count = outgoing.envelopes.len();
                if data.partial_accept {
                    json!({"accepted":count.saturating_sub(1)})
                } else {
                    for envelope in outgoing.envelopes {
                        if !data.received.iter().any(|raw| {
                            let previous: Envelope = serde_json::from_str(raw).unwrap();
                            id(&previous) == id(&envelope)
                        }) {
                            data.received.push(envelope.0.get().into());
                        }
                    }
                    json!({"accepted":count})
                }
            }
            _ => panic!("unexpected relay path"),
        };
        (200, result, None)
    };
    let body = raw_body.unwrap_or_else(|| serde_json::to_vec(&result).unwrap());
    let cooldown = retry_after
        .map(|seconds| format!("Retry-After: {seconds}\r\n"))
        .unwrap_or_default();
    let head = format!("HTTP/1.1 {status} Result\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n{cooldown}\r\n", body.len());
    let _ = stream.get_mut().write_all(head.as_bytes()).await;
    let _ = stream.get_mut().write_all(&body).await;
}

// Tungstenite fixes this callback's error type to its HTTP error response.
#[allow(clippy::result_large_err)]
fn accept_headers(
    request: &Request,
    mut response: Response,
) -> std::result::Result<Response, tokio_tungstenite::tungstenite::handshake::server::ErrorResponse>
{
    assert_eq!(request.headers()["Sec-WebSocket-Protocol"], SUBPROTOCOL);
    assert!(request.headers()["Authorization"]
        .to_str()
        .unwrap()
        .starts_with("Device session-"));
    response
        .headers_mut()
        .insert("Sec-WebSocket-Protocol", SUBPROTOCOL.parse().unwrap());
    Ok(response)
}

pub fn fast_timing() -> Timing {
    Timing {
        heartbeat: Duration::from_millis(150),
        status: Duration::from_millis(100),
        initial_backoff: Duration::from_millis(20),
        maximum_backoff: Duration::from_millis(160),
    }
}

pub struct RunningClient {
    shutdown: watch::Sender<bool>,
    task: JoinHandle<crate::error::Result<()>>,
}

impl RunningClient {
    pub fn start(helper: Helper, config: Config, queue: Queue, timing: Timing) -> Self {
        let client = Client::new(helper, Relay::new(&config).unwrap(), queue).with_timing(timing);
        let (shutdown, receiver) = watch::channel(false);
        let task = tokio::spawn(async move { client.run(receiver).await });
        Self { shutdown, task }
    }
    pub async fn stop(self) {
        self.shutdown.send(true).unwrap();
        tokio::time::timeout(Duration::from_secs(3), self.task)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
    }
}

pub async fn wait_for(condition: impl FnMut() -> bool) {
    wait_for_timeout(Duration::from_secs(5), condition).await;
}

pub async fn wait_for_timeout(timeout: Duration, mut condition: impl FnMut() -> bool) {
    tokio::time::timeout(timeout, async {
        while !condition() {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("test condition timed out");
}

pub async fn wait_for_queue_empty(queue: &Queue) {
    tokio::time::timeout(Duration::from_secs(5), async {
        while queue.front().await.unwrap().is_some() {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("relay acceptance was not committed to the queue");
}

pub fn received_ids(state: &RelayState) -> Vec<String> {
    state
        .data
        .lock()
        .unwrap()
        .received
        .iter()
        .map(|raw| id(&serde_json::from_str(raw).unwrap()))
        .collect()
}
