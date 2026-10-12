// Integration tests use only ephemeral listeners, software keys and repository schemas.
mod interfaces;
mod push;
mod recovery;
pub(crate) mod regions;
mod review;

pub(crate) struct Fixture {
    pub state: Arc<state::State>,
    pub principal: state::Principal,
    pub envelope: kv_core::remote::Envelope,
}

pub(crate) fn fixture() -> Fixture {
    let state = state::State::new(Connection::open_in_memory().unwrap(), true).unwrap();
    let mut device = Device::new("fixture", false);
    device.account = "acct_fixture".into();
    device.token = state::random_token(32);
    state
        .with(|data, now| {
            data.db.execute(
                "INSERT INTO accounts(id,created_at,recovery_hash) VALUES(?1,?2,'test-only')",
                rusqlite::params![device.account, now],
            )?;
            state::insert_device(&data.db, &device.account, &device.record, None, now)?;
            data.db.execute(
                "INSERT INTO sessions(token_hash,device_id,exp) VALUES(?1,?2,?3)",
                rusqlite::params![
                    sha256_hex(device.token.as_bytes()),
                    device.record.device_id,
                    now + state::SESSION_TTL
                ],
            )?;
            Ok(())
        })
        .unwrap();
    let principal = state::Principal {
        account: device.account.clone(),
        device: device.record.clone(),
        token_hash: sha256_hex(device.token.as_bytes()),
    };
    let envelope = device.seal(
        &device,
        &state::ulid(now()),
        EnvelopeType::Grant,
        now() + 900,
        &json!({"private":"fixture-only encrypted payload"}),
    );
    Fixture {
        state,
        principal,
        envelope,
    }
}
use super::*;
use futures_util::{SinkExt, StreamExt};
use kv_core::remote::canonical::{jcs, sha256_hex};
use kv_core::remote::keys::{decode_b64, encode_b64};
use kv_core::remote::{
    envelope, pairing, Capability, DeviceKeyProvider, DeviceRecord, Envelope, EnvelopeHeader,
    EnvelopeType, Extra, KeyKind, Os, PairConfirm, SignatureAlgorithm, SoftwareDeviceKey,
};
use reqwest::{Method, StatusCode};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};
use tokio::net::TcpStream;
use tokio_tungstenite::tungstenite::{client::IntoClientRequest, Message};
use tokio_tungstenite::{connect_async, MaybeTlsStream, WebSocketStream};

type Socket = WebSocketStream<MaybeTlsStream<TcpStream>>;

fn schema(name: &str, value: &Value) {
    static SCHEMAS: OnceLock<Mutex<HashMap<String, jsonschema::JSONSchema>>> = OnceLock::new();
    let mut schemas = SCHEMAS.get_or_init(Default::default).lock().unwrap();
    let compiled = schemas.entry(name.into()).or_insert_with(|| {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../kv-core/schemas/remote")
            .join(format!("{name}.schema.json"));
        let raw: Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
        jsonschema::JSONSchema::compile(&raw).unwrap()
    });
    assert!(compiled.is_valid(value), "invalid {name} shape: {value}");
}

struct Client {
    base: Url,
    http: reqwest::Client,
}

impl Client {
    fn new(base: Url) -> Self {
        Self {
            base,
            http: reqwest::Client::new(),
        }
    }

    async fn call(
        &self,
        method: Method,
        path: &str,
        token: Option<&str>,
        body: Option<Value>,
    ) -> (StatusCode, Value) {
        let mut request = self
            .http
            .request(method.clone(), self.base.join(path).unwrap());
        if let Some(token) = token {
            request = request.header("authorization", format!("Device {token}"));
        }
        if let Some(body) = body {
            request = request.json(&body);
        }
        let response = request.send().await.unwrap();
        let status = response.status();
        let value: Value = response.json().await.unwrap();
        if !status.is_success() {
            schema("relay_error_response", &value);
            assert_eq!(value.as_object().unwrap().len(), 1);
            assert_eq!(value["error"].as_object().unwrap().len(), 2);
        } else {
            let shape = match (method, path) {
                (Method::POST, "/v1/devices") => "register_device_response",
                (Method::POST, "/v1/auth/challenge") => "challenge_response",
                (Method::POST, "/v1/auth/verify") => "auth_verify_response",
                (Method::POST, "/v1/recovery") => "recover_account_response",
                (Method::POST, "/v1/pair/start") => "relay_pair_start_response",
                (Method::POST, "/v1/pair/complete") => "relay_pair_complete_response",
                (Method::POST, "/v1/approvals" | "/v1/messages") => "accepted_response",
                (Method::GET, "/v1/health") => "health_response",
                (Method::GET, _) => "envelopes_response",
                _ => "ok_response",
            };
            schema(shape, &value);
        }
        (status, value)
    }

    async fn post(&self, path: &str, token: Option<&str>, body: Value) -> Value {
        let (status, body) = self.call(Method::POST, path, token, Some(body)).await;
        assert_eq!(status, StatusCode::OK, "{path}: {body}");
        body
    }

    async fn login(&self, device: &Device) -> String {
        let request = json!({"device_id":device.record.device_id});
        schema("challenge_request", &request);
        let challenge = self.post("/v1/auth/challenge", None, request).await;
        let bytes = decode_b64(challenge["challenge"].as_str().unwrap()).unwrap();
        assert_eq!(bytes.len(), 32);
        let sig = device.dk.sign(SignatureAlgorithm::ES256, &bytes).unwrap();
        let request = json!({"device_id":device.record.device_id,"challenge":challenge["challenge"],"sig":encode_b64(&sig)});
        schema("auth_verify_request", &request);
        let response = self.post("/v1/auth/verify", None, request).await;
        let ttl = response["exp"].as_i64().unwrap() - challenge["exp"].as_i64().unwrap();
        assert!((state::SESSION_TTL - 60..=state::SESSION_TTL).contains(&ttl));
        response["session_token"].as_str().unwrap().into()
    }

    async fn register(&self, device: &mut Device) -> String {
        let request = serde_json::to_value(&device.record).unwrap();
        schema("register_device_request", &request);
        let response = self.post("/v1/devices", None, request).await;
        assert_eq!(response.as_object().unwrap().len(), 3);
        device.account = response["account_id"].as_str().unwrap().into();
        device.token = self.login(device).await;
        response["recovery_code"].as_str().unwrap().into()
    }

    async fn socket(&self, device: &Device) -> Socket {
        let mut url = self.base.join("/v1/presence").unwrap();
        url.set_scheme("ws").unwrap();
        let mut request = url.as_str().into_client_request().unwrap();
        request.headers_mut().insert(
            "authorization",
            format!("Device {}", device.token).parse().unwrap(),
        );
        request
            .headers_mut()
            .insert("sec-websocket-protocol", "kv-relay-v1".parse().unwrap());
        let (socket, response) = connect_async(request).await.unwrap();
        assert_eq!(response.headers()["sec-websocket-protocol"], "kv-relay-v1");
        socket
    }

    async fn pair(
        &self,
        initiator: &Device,
        joiner: &mut Device,
        registered: bool,
        socket: Option<&mut Socket>,
    ) {
        let token = state::random_token(16);
        let request = json!({"token_hash":sha256_hex(&decode_b64(&token).unwrap()),"initiator":initiator.record,"exp":now()+600});
        schema("relay_pair_start_request", &request);
        let start = self
            .post("/v1/pair/start", Some(&initiator.token), request)
            .await;
        let complete = json!({"token":token,"joiner":joiner.record});
        schema("relay_pair_complete_request", &complete);
        let response = self
            .post(
                "/v1/pair/complete",
                registered.then_some(joiner.token.as_str()),
                complete.clone(),
            )
            .await;
        assert_eq!(response["pairing_id"], start["pairing_id"]);
        assert_eq!(response["account_id"], initiator.account);
        assert_eq!(
            response["initiator"],
            serde_json::to_value(&initiator.record).unwrap()
        );
        if let Some(socket) = socket {
            let event = receive(socket).await;
            assert_eq!(
                event,
                json!({"t":"pair_accept","pairing_id":start["pairing_id"],"joiner":joiner.record})
            );
        }
        joiner.account = response["account_id"].as_str().unwrap().into();
        joiner.token = self.login(joiner).await;
        let sas = pairing::sas(
            &decode_b64(&token).unwrap(),
            &initiator.record.dk_pub,
            &joiner.record.dk_pub,
            joiner.record.ak_q.as_ref().map(|k| &k.r#pub),
            joiner.record.ak_s.as_ref().map(|k| &k.r#pub),
        )
        .unwrap();
        let request = json!({"pairing_id":start["pairing_id"],"confirm":joiner.confirm(&sas)});
        schema("pair_finish_request", &request);
        let response = self
            .post("/v1/pair/finish", Some(&joiner.token), request.clone())
            .await;
        assert_eq!(response, json!({"ok":true}));
        let before = self
            .call(
                Method::GET,
                "/v1/approvals?state=waiting",
                Some(&joiner.token),
                None,
            )
            .await;
        assert_eq!(before.0, StatusCode::FORBIDDEN);
        self.post(
            "/v1/pair/finish",
            Some(&initiator.token),
            json!({"pairing_id":start["pairing_id"],"confirm":initiator.confirm(&sas)}),
        )
        .await;
        let replay = self
            .call(
                Method::POST,
                "/v1/pair/finish",
                Some(&joiner.token),
                Some(request),
            )
            .await;
        assert_eq!(replay, (StatusCode::OK, json!({"ok":true})));
        let different_sas = if sas == "000000" { "000001" } else { "000000" };
        let changed = self
            .call(
                Method::POST,
                "/v1/pair/finish",
                Some(&joiner.token),
                Some(json!({"pairing_id":start["pairing_id"],"confirm":joiner.confirm(different_sas)})),
            )
            .await;
        assert_error(&changed, StatusCode::CONFLICT, "conflict");
        let invalid = self
            .call(
                Method::POST,
                "/v1/pair/finish",
                Some(&joiner.token),
                Some(json!({"pairing_id":start["pairing_id"],"confirm":{"sas":sas,"sig":"AA"}})),
            )
            .await;
        assert_error(&invalid, StatusCode::FORBIDDEN, "forbidden");
        let replay = self
            .call(Method::POST, "/v1/pair/complete", None, Some(complete))
            .await;
        assert_error(&replay, StatusCode::CONFLICT, "conflict");
    }
}

struct Device {
    record: DeviceRecord,
    dk: SoftwareDeviceKey,
    strong: Option<SoftwareDeviceKey>,
    token: String,
    account: String,
}

impl Device {
    fn new(name: &str, approver: bool) -> Self {
        let dk = SoftwareDeviceKey::generate_p256();
        let strong = approver.then(SoftwareDeviceKey::generate_p256);
        let quick = approver.then(SoftwareDeviceKey::generate_p256);
        let key = |key: &SoftwareDeviceKey| kv_core::remote::ApprovalKey {
            r#pub: key.public_jwk().unwrap(),
            alg: SignatureAlgorithm::ES256,
            extra: Extra::new(),
        };
        let record = DeviceRecord {
            device_id: format!("dev_{name}"),
            label: name.into(),
            os: Os::Linux,
            key_kind: KeyKind::Software,
            dk_pub: dk.public_jwk().unwrap(),
            dk_sig: kv_core::remote::Optional::Missing,
            ak_q: quick.as_ref().map(key),
            ak_s: strong.as_ref().map(key),
            caps: if approver {
                vec![Capability::ApproveQuick, Capability::ApproveStrong]
            } else {
                vec![Capability::Execute]
            },
            attestation: None,
            extra: Extra::new(),
        };
        Self {
            record,
            dk,
            strong,
            token: String::new(),
            account: String::new(),
        }
    }

    fn confirm(&self, sas: &str) -> PairConfirm {
        match &self.strong {
            Some(key) => {
                pairing::sign_confirm(sas, self.record.ak_s.as_ref().unwrap().alg, key).unwrap()
            }
            None => PairConfirm {
                sas: sas.into(),
                sig: String::new(),
                extra: Extra::new(),
            },
        }
    }

    fn seal(
        &self,
        to: &Device,
        id: &str,
        kind: EnvelopeType,
        exp: i64,
        payload: &Value,
    ) -> Envelope {
        envelope::seal(
            EnvelopeHeader {
                v: 1,
                r#type: kind,
                id: id.into(),
                account: self.account.clone(),
                from: self.record.device_id.clone(),
                to: to.record.device_id.clone(),
                created_at: now(),
                exp,
                extra: Extra::new(),
            },
            &serde_json::to_vec(payload).unwrap(),
            &to.record.dk_pub,
            &self.dk,
        )
        .unwrap()
    }
}

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

fn assert_error(response: &(StatusCode, Value), status: StatusCode, code: &str) {
    assert_eq!(response.0, status, "{}", response.1);
    assert_eq!(response.1["error"]["code"], code);
}

async fn receive(socket: &mut Socket) -> Value {
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            match socket.next().await.unwrap().unwrap() {
                Message::Text(text) => return serde_json::from_str(&text).unwrap(),
                Message::Ping(bytes) => socket.send(Message::Pong(bytes)).await.unwrap(),
                _ => {}
            }
        }
    })
    .await
    .expect("relay did not deliver a frame")
}

async fn flow(client: &Client, handle: &Handle, marker: &str) {
    assert_eq!(
        client.call(Method::GET, "/v1/health", None, None).await.1,
        json!({"ok":true,"version":env!("CARGO_PKG_VERSION")})
    );
    let mut executor = Device::new("executor", false);
    let recovery = client.register(&mut executor).await;
    let mut approver = Device::new("approver", true);
    client.register(&mut approver).await;
    assert_ne!(executor.account, approver.account);
    let mut executor_ws = client.socket(&executor).await;
    executor_ws
        .send(Message::Text(json!({"t":"ping"}).to_string().into()))
        .await
        .unwrap();
    let pong = receive(&mut executor_ws).await;
    schema("ws_frame", &pong);
    assert_eq!(pong, json!({"t":"pong"}));
    client
        .pair(&executor, &mut approver, true, Some(&mut executor_ws))
        .await;
    let mut other = Device::new("other", true);
    client
        .pair(&executor, &mut other, false, Some(&mut executor_ws))
        .await;
    let mut other_ws = client.socket(&other).await;
    let id = state::ulid(now());
    let exp = now() + 300;
    let payload = json!({"credential":format!("{marker}-credential"),"host":format!("{marker}.invalid"),
        "path":format!("/{marker}/private"),"agent":format!("{marker}-agent"),"purpose":format!("{marker}-purpose")});
    let request_a = executor.seal(&approver, &id, EnvelopeType::ApprovalRequest, exp, &payload);
    let request_b = executor.seal(&other, &id, EnvelopeType::ApprovalRequest, exp, &payload);
    assert_ne!(request_a.ct, request_b.ct);
    let request =
        json!({"id":id,"exp":exp,"envelopes":[request_a,request_b],"debug_plaintext":marker});
    schema("submit_approvals_request", &request);
    assert_eq!(
        client
            .post("/v1/approvals", Some(&executor.token), request)
            .await,
        json!({"accepted":2})
    );
    let queued = client
        .call(
            Method::GET,
            "/v1/approvals?state=waiting",
            Some(&approver.token),
            None,
        )
        .await
        .1;
    assert_eq!(queued, json!({"envelopes":[request_a]}));
    let own = client
        .call(
            Method::GET,
            "/v1/approvals?state=waiting",
            Some(&executor.token),
            None,
        )
        .await
        .1;
    assert_eq!(own, json!({"envelopes":[]}));
    let frame = receive(&mut other_ws).await;
    schema("ws_frame", &frame);
    assert_eq!(frame, json!({"t":"envelope","envelope":request_b}));
    let plaintext = envelope::open(
        &request_a,
        &approver.record.device_id,
        &approver.dk,
        &executor.record,
        now(),
    )
    .unwrap();
    assert_eq!(
        serde_json::from_slice::<Value>(&plaintext).unwrap(),
        payload
    );
    let reply = approver.seal(
        &executor,
        &id,
        EnvelopeType::ApprovalDecision,
        exp,
        &json!({"decision":"allow","reason":marker}),
    );
    let request = json!({"envelope":reply});
    schema("reply_approval_request", &request);
    assert_eq!(
        client
            .post(
                &format!("/v1/approvals/{id}/reply"),
                Some(&approver.token),
                request.clone()
            )
            .await,
        json!({"ok":true})
    );
    assert_eq!(
        receive(&mut executor_ws).await,
        json!({"t":"envelope","envelope":reply})
    );
    assert_eq!(
        receive(&mut other_ws).await,
        json!({"t":"approval_cancel","id":id})
    );
    assert_eq!(
        &client
            .call(
                Method::POST,
                &format!("/v1/approvals/{id}/reply"),
                Some(&approver.token),
                Some(request),
            )
            .await
            .1,
        &json!({"ok":true}),
    );
    assert_eq!(
        client
            .call(
                Method::GET,
                "/v1/approvals?state=waiting",
                Some(&other.token),
                None
            )
            .await
            .1,
        json!({"envelopes":[]})
    );

    // An offline non-approval message survives until a recipient-specific ack.
    let msg_id = state::ulid(now());
    let grant = executor.seal(
        &approver,
        &msg_id,
        EnvelopeType::Grant,
        now() + 300,
        &json!({"credential":marker,"scope":marker}),
    );
    let request = json!({"envelopes":[grant],"debug_plaintext":marker});
    schema("send_messages_request", &request);
    client
        .post("/v1/messages", Some(&executor.token), request.clone())
        .await;
    assert_eq!(
        &client
            .call(
                Method::POST,
                "/v1/messages",
                Some(&executor.token),
                Some(request),
            )
            .await
            .1,
        &json!({"accepted":1}),
    );
    let mut approver_ws = client.socket(&approver).await;
    assert_eq!(
        receive(&mut approver_ws).await,
        json!({"t":"envelope","envelope":grant})
    );
    assert_error(
        &client
            .call(
                Method::POST,
                "/v1/messages/ack",
                Some(&other.token),
                Some(json!({"ids":[msg_id]})),
            )
            .await,
        StatusCode::NOT_FOUND,
        "not_found",
    );
    approver_ws
        .send(Message::Text(
            json!({"t":"ack","id":msg_id}).to_string().into(),
        ))
        .await
        .unwrap();
    assert_eq!(
        receive(&mut approver_ws).await,
        json!({"t":"ack","id":msg_id})
    );
    let request = json!({"ids":[id]});
    schema("ack_messages_request", &request);
    client
        .post("/v1/messages/ack", Some(&executor.token), request)
        .await;

    let cancel_id = state::ulid(now());
    let cancel_request = executor.seal(
        &other,
        &cancel_id,
        EnvelopeType::ApprovalRequest,
        now() + 300,
        &payload,
    );
    client
        .post(
            "/v1/approvals",
            Some(&executor.token),
            json!({"id":cancel_id,"exp":cancel_request.exp,"envelopes":[cancel_request]}),
        )
        .await;
    receive(&mut other_ws).await;
    assert_error(
        &client
            .call(
                Method::POST,
                &format!("/v1/approvals/{cancel_id}/cancel"),
                Some(&other.token),
                Some(json!({})),
            )
            .await,
        StatusCode::FORBIDDEN,
        "forbidden",
    );
    assert_eq!(
        client
            .post(
                &format!("/v1/approvals/{cancel_id}/cancel"),
                Some(&executor.token),
                json!({})
            )
            .await,
        json!({"ok":true})
    );
    assert_eq!(
        receive(&mut other_ws).await,
        json!({"t":"approval_cancel","id":cancel_id})
    );

    let metrics = client
        .http
        .get(client.base.join("/metrics").unwrap())
        .header("authorization", format!("Device {}", executor.token))
        .send()
        .await
        .unwrap();
    assert_eq!(metrics.status(), StatusCode::OK);
    assert!(metrics
        .text()
        .await
        .unwrap()
        .contains("kv_relay_requests_total"));
    let request = json!({"by":"recovery","recovery_code":recovery});
    schema("delete_device_request", &request);
    assert_eq!(
        client
            .call(
                Method::DELETE,
                "/v1/devices/dev_other",
                Some(&executor.token),
                Some(request)
            )
            .await
            .1,
        json!({"ok":true})
    );
    assert_error(
        &client
            .call(
                Method::GET,
                "/v1/approvals?state=waiting",
                Some(&other.token),
                None,
            )
            .await,
        StatusCode::UNAUTHORIZED,
        "unauthorized",
    );
    handle.advance_time(Duration::from_secs(state::RETENTION as u64 + 301));
    let stats = handle.cleanup();
    assert!(stats.messages >= 4 && stats.approvals >= 2 && stats.sessions >= 2);
    handle.inspect(|db| {
        let count: i64 = db
            .query_row("SELECT COUNT(*) FROM messages", [], |r| r.get(0))
            .unwrap();
        assert_eq!(count, 0);
        let hashes: Vec<String> = db
            .prepare("SELECT recovery_hash FROM accounts")
            .unwrap()
            .query_map([], |r| r.get(0))
            .unwrap()
            .map(Result::unwrap)
            .collect();
        assert!(hashes.iter().all(|h| h.starts_with("$argon2id$")));
    });
}

#[tokio::test]
async fn endpoint_contract_and_complete_approval_flow() {
    let (base, relay) = spawn_test_relay();
    flow(&Client::new(base), &relay, "PRIVATE-FLOW-MARKER").await;
    relay.shutdown().await;
}

#[tokio::test]
async fn ciphertext_only_database_wal_and_logs() {
    let directory = tempfile::tempdir().unwrap();
    let marker = "NEVER-STORE-PLAINTEXT-6ee86c5c08d5420ab2126480212ab52e";
    let (base, relay) = spawn_test_relay_with_data(directory.path().join("relay.sqlite3"));
    flow(&Client::new(base), &relay, marker).await;
    // secure_delete and WAL may retain old pages; inspect both before checkpoint/shutdown.
    for entry in std::fs::read_dir(directory.path()).unwrap() {
        let bytes = std::fs::read(entry.unwrap().path()).unwrap();
        assert!(!bytes
            .windows(marker.len())
            .any(|window| window == marker.as_bytes()));
    }
    assert!(relay.logs().iter().all(|line| !line.contains(marker)));
    assert!(relay
        .logs()
        .iter()
        .all(|line| line.starts_with("event=") && line.contains(" count=")));
    relay.shutdown().await;
}

async fn two_devices(client: &Client) -> (Device, Device) {
    let mut executor = Device::new("executor", false);
    client.register(&mut executor).await;
    let mut approver = Device::new("approver", true);
    client.pair(&executor, &mut approver, false, None).await;
    (executor, approver)
}

#[tokio::test]
async fn auth_errors_challenge_replay_expiry_and_renewal() {
    let (base, relay) = spawn_test_relay();
    let client = Client::new(base);
    for path in [
        "/v1/approvals?state=waiting",
        "/v1/presence",
        "/metrics",
        "/v1/messages/ack",
    ] {
        assert_error(
            &client.call(Method::GET, path, None, None).await,
            StatusCode::UNAUTHORIZED,
            "unauthorized",
        );
    }
    let mut device = Device::new("auth", false);
    client.register(&mut device).await;
    let challenge = client
        .post(
            "/v1/auth/challenge",
            None,
            json!({"device_id":device.record.device_id}),
        )
        .await;
    let request =
        json!({"device_id":device.record.device_id,"challenge":challenge["challenge"],"sig":"AA"});
    assert_error(
        &client
            .call(Method::POST, "/v1/auth/verify", None, Some(request.clone()))
            .await,
        StatusCode::UNAUTHORIZED,
        "unauthorized",
    );
    let mut valid = request;
    valid["sig"] = encode_b64(
        &device
            .dk
            .sign(
                SignatureAlgorithm::ES256,
                &decode_b64(challenge["challenge"].as_str().unwrap()).unwrap(),
            )
            .unwrap(),
    )
    .into();
    let response = client.post("/v1/auth/verify", None, valid.clone()).await;
    assert_ne!(response["session_token"], device.token);
    assert_error(
        &client
            .call(Method::POST, "/v1/auth/verify", None, Some(valid))
            .await,
        StatusCode::UNAUTHORIZED,
        "unauthorized",
    );
    let challenge = client
        .post(
            "/v1/auth/challenge",
            None,
            json!({"device_id":device.record.device_id}),
        )
        .await;
    relay.advance_time(Duration::from_secs(61));
    assert_error(&client.call(Method::POST,"/v1/auth/verify",None,Some(json!({"device_id":device.record.device_id,"challenge":challenge["challenge"],"sig":"AA"}))).await,
        StatusCode::GONE,"expired");
    relay.advance_time(Duration::from_secs(state::SESSION_TTL as u64));
    assert_error(
        &client
            .call(
                Method::GET,
                "/v1/approvals?state=waiting",
                Some(&device.token),
                None,
            )
            .await,
        StatusCode::UNAUTHORIZED,
        "unauthorized",
    );
    // A new signed challenge renews the session without a password or recovery code.
    let challenge = client
        .post(
            "/v1/auth/challenge",
            None,
            json!({"device_id":device.record.device_id}),
        )
        .await;
    let sig = device
        .dk
        .sign(
            SignatureAlgorithm::ES256,
            &decode_b64(challenge["challenge"].as_str().unwrap()).unwrap(),
        )
        .unwrap();
    let response=client.post("/v1/auth/verify",None,json!({"device_id":device.record.device_id,"challenge":challenge["challenge"],"sig":encode_b64(&sig)})).await;
    assert_eq!(
        client
            .call(
                Method::GET,
                "/v1/approvals?state=waiting",
                response["session_token"].as_str(),
                None
            )
            .await
            .0,
        StatusCode::OK
    );
    relay.shutdown().await;
}

#[tokio::test]
async fn invalid_envelopes_batch_atomicity_and_error_shapes() {
    let (base, relay) = spawn_test_relay();
    let client = Client::new(base);
    let (executor, approver) = two_devices(&client).await;
    let mut outsider = Device::new("outsider", true);
    client.register(&mut outsider).await;
    let id = state::ulid(now());
    let valid = executor.seal(
        &approver,
        &id,
        EnvelopeType::Directive,
        now() + 300,
        &json!({"private":"private"}),
    );
    let mut bad = valid.clone();
    bad.sig = "AA".into();
    assert_error(
        &client
            .call(
                Method::POST,
                "/v1/messages",
                Some(&executor.token),
                Some(json!({"envelopes":[valid,bad]})),
            )
            .await,
        StatusCode::BAD_REQUEST,
        "bad_envelope",
    );
    relay.inspect(|db| {
        assert_eq!(
            db.query_row("SELECT COUNT(*) FROM messages", [], |r| r.get::<_, i64>(0))
                .unwrap(),
            0
        )
    });
    let outside = executor.seal(
        &outsider,
        &state::ulid(now()),
        EnvelopeType::Grant,
        now() + 300,
        &json!({}),
    );
    assert_error(
        &client
            .call(
                Method::POST,
                "/v1/messages",
                Some(&executor.token),
                Some(json!({"envelopes":[outside]})),
            )
            .await,
        StatusCode::FORBIDDEN,
        "forbidden",
    );
    let mut wrong_sender = valid.clone();
    wrong_sender.from = approver.record.device_id.clone();
    assert_error(
        &client
            .call(
                Method::POST,
                "/v1/messages",
                Some(&executor.token),
                Some(json!({"envelopes":[wrong_sender]})),
            )
            .await,
        StatusCode::FORBIDDEN,
        "forbidden",
    );
    let mut expired = valid.clone();
    expired.exp = now() - 1;
    expired.created_at = now() - 10;
    assert_error(
        &client
            .call(
                Method::POST,
                "/v1/messages",
                Some(&executor.token),
                Some(json!({"envelopes":[expired]})),
            )
            .await,
        StatusCode::GONE,
        "expired",
    );
    let mut oversized = valid.clone();
    oversized.ct = "A".repeat(80 * 1024);
    assert_error(
        &client
            .call(
                Method::POST,
                "/v1/messages",
                Some(&executor.token),
                Some(json!({"envelopes":[oversized]})),
            )
            .await,
        StatusCode::PAYLOAD_TOO_LARGE,
        "payload_too_large",
    );
    assert_error(
        &client
            .call(
                Method::POST,
                "/v1/messages",
                Some(&executor.token),
                Some(json!({"envelopes":[],"oversize":"X".repeat(1024*1024)})),
            )
            .await,
        StatusCode::PAYLOAD_TOO_LARGE,
        "payload_too_large",
    );
    assert_error(
        &client
            .call(
                Method::GET,
                "/v1/approvals?state=resolved",
                Some(&executor.token),
                None,
            )
            .await,
        StatusCode::BAD_REQUEST,
        "bad_envelope",
    );
    assert_error(
        &client
            .call(Method::GET, "/unknown", Some(&executor.token), None)
            .await,
        StatusCode::NOT_FOUND,
        "not_found",
    );
    let response = client
        .http
        .post(client.base.join("/v1/messages").unwrap())
        .header("authorization", format!("Device {}", executor.token))
        .header("content-type", "application/json")
        .body("{\"envelopes\":[],\"envelopes\":[]}")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    schema(
        "relay_error_response",
        &response.json::<Value>().await.unwrap(),
    );
    let mut url = client.base.join("/v1/presence").unwrap();
    url.set_scheme("ws").unwrap();
    let mut request = url.as_str().into_client_request().unwrap();
    request.headers_mut().insert(
        "authorization",
        format!("Device {}", executor.token).parse().unwrap(),
    );
    let error = connect_async(request).await.unwrap_err();
    if let tokio_tungstenite::tungstenite::Error::Http(response) = error {
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        schema(
            "relay_error_response",
            &serde_json::from_slice::<Value>(response.body().as_ref().unwrap()).unwrap(),
        );
    } else {
        panic!("expected handshake rejection");
    }
    relay.shutdown().await;
}

#[tokio::test]
async fn strong_revocation_requires_a_fresh_signed_proof() {
    let (base, relay) = spawn_test_relay();
    let client = Client::new(base);
    let mut executor = Device::new("executor", false);
    client.register(&mut executor).await;
    let mut approver = Device::new("approver", true);
    let strong = SoftwareDeviceKey::generate_rsa2048().unwrap();
    approver.record.ak_s = Some(kv_core::remote::ApprovalKey {
        r#pub: strong.public_jwk().unwrap(),
        alg: SignatureAlgorithm::RS256,
        extra: Extra::new(),
    });
    approver.strong = Some(strong);
    client.pair(&executor, &mut approver, false, None).await;
    let path = format!("/v1/devices/{}", executor.record.device_id);
    assert_error(
        &client
            .call(
                Method::DELETE,
                &path,
                Some(&approver.token),
                Some(json!({"by":"device"})),
            )
            .await,
        StatusCode::FORBIDDEN,
        "forbidden",
    );
    let challenge = client
        .post(
            "/v1/auth/challenge",
            None,
            json!({"device_id":approver.record.device_id}),
        )
        .await;
    let payload = json!({"action":"revoke_device","account":approver.account,"by":approver.record.device_id,
        "device_id":executor.record.device_id,"challenge":challenge["challenge"]});
    let sig = approver
        .strong
        .as_ref()
        .unwrap()
        .sign(
            approver.record.ak_s.as_ref().unwrap().alg,
            &jcs(&payload).unwrap(),
        )
        .unwrap();
    let response = client
        .http
        .delete(client.base.join(&path).unwrap())
        .header("authorization", format!("Device {}", approver.token))
        .header("x-kv-challenge", challenge["challenge"].as_str().unwrap())
        .header("x-kv-strong-signature", encode_b64(&sig))
        .json(&json!({"by":"device"}))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.json::<Value>().await.unwrap(), json!({"ok":true}));
    assert_error(
        &client
            .call(
                Method::GET,
                "/v1/approvals?state=waiting",
                Some(&executor.token),
                None,
            )
            .await,
        StatusCode::UNAUTHORIZED,
        "unauthorized",
    );
    relay.shutdown().await;
}

#[tokio::test]
async fn approval_message_and_pending_limits() {
    let (base, relay) = spawn_test_relay();
    let client = Client::new(base);
    let (executor, approver) = two_devices(&client).await;
    for index in 0..=60 {
        let id = state::ulid(now());
        let exp = now() + 300;
        let envelope = executor.seal(
            &approver,
            &id,
            EnvelopeType::ApprovalRequest,
            exp,
            &json!({}),
        );
        let response = client
            .call(
                Method::POST,
                "/v1/approvals",
                Some(&executor.token),
                Some(json!({"id":id,"exp":exp,"envelopes":[envelope]})),
            )
            .await;
        if index == 60 {
            assert_error(&response, StatusCode::TOO_MANY_REQUESTS, "rate_limited");
        } else {
            assert_eq!(response.0, StatusCode::OK);
            client
                .post(
                    &format!("/v1/approvals/{id}/cancel"),
                    Some(&executor.token),
                    json!({}),
                )
                .await;
        }
    }
    relay.advance_time(Duration::from_secs(61));
    // Two acknowledged batches consume exactly 600 messages in a sliding minute.
    for _ in 0..2 {
        let envelopes: Vec<_> = (0..300)
            .map(|_| {
                executor.seal(
                    &approver,
                    &state::ulid(now()),
                    EnvelopeType::Grant,
                    now() + 300,
                    &json!({}),
                )
            })
            .collect();
        assert_eq!(
            client
                .post(
                    "/v1/messages",
                    Some(&executor.token),
                    json!({"envelopes":envelopes})
                )
                .await,
            json!({"accepted":300})
        );
        let ids: Vec<_> = envelopes.iter().map(|e| e.id.clone()).collect();
        client
            .post(
                "/v1/messages/ack",
                Some(&approver.token),
                json!({"ids":ids}),
            )
            .await;
    }
    let envelope = executor.seal(
        &approver,
        &state::ulid(now()),
        EnvelopeType::Grant,
        now() + 300,
        &json!({}),
    );
    assert_error(
        &client
            .call(
                Method::POST,
                "/v1/messages",
                Some(&executor.token),
                Some(json!({"envelopes":[envelope]})),
            )
            .await,
        StatusCode::TOO_MANY_REQUESTS,
        "rate_limited",
    );
    relay.advance_time(Duration::from_secs(61));
    let envelopes: Vec<_> = (0..500)
        .map(|_| {
            executor.seal(
                &approver,
                &state::ulid(now()),
                EnvelopeType::Grant,
                now() + 300,
                &json!({}),
            )
        })
        .collect();
    assert_eq!(
        client
            .post(
                "/v1/messages",
                Some(&executor.token),
                json!({"envelopes":envelopes})
            )
            .await,
        json!({"accepted":500})
    );
    let id = state::ulid(now());
    let envelope = executor.seal(
        &approver,
        &id,
        EnvelopeType::ApprovalRequest,
        now() + 300,
        &json!({}),
    );
    assert_error(
        &client
            .call(
                Method::POST,
                "/v1/approvals",
                Some(&executor.token),
                Some(json!({"id":id,"exp":envelope.exp,"envelopes":[envelope]})),
            )
            .await,
        StatusCode::TOO_MANY_REQUESTS,
        "rate_limited",
    );
    relay.shutdown().await;
}

#[test]
fn only_ipv4_local_nginx_may_supply_cloudflare_ip() {
    let mut headers = axum::http::HeaderMap::new();
    headers.insert("cf-connecting-ip", "203.0.113.7".parse().unwrap());
    assert_eq!(
        state::client_ip("127.0.0.1:40000".parse().unwrap(), &headers).to_string(),
        "203.0.113.7"
    );
    for peer in ["192.0.2.8:40000", "127.0.0.2:40000", "[::1]:40000"] {
        let peer: SocketAddr = peer.parse().unwrap();
        assert_eq!(state::client_ip(peer, &headers), peer.ip());
    }
    headers.insert(
        "cf-connecting-ip",
        "203.0.113.7, 198.51.100.1".parse().unwrap(),
    );
    assert_eq!(
        state::client_ip("127.0.0.1:40000".parse().unwrap(), &headers).to_string(),
        "127.0.0.1"
    );
    assert_eq!(HEARTBEAT, Duration::from_secs(30));
    assert_eq!(IDLE_TIMEOUT, Duration::from_secs(100));
}

#[tokio::test]
async fn cleanup_retains_until_seven_days_and_expires_waiting() {
    let (base, relay) = spawn_test_relay();
    let client = Client::new(base);
    let (executor, approver) = two_devices(&client).await;
    let id = state::ulid(now());
    let envelope = executor.seal(
        &approver,
        &id,
        EnvelopeType::ApprovalRequest,
        now() + 10,
        &json!({}),
    );
    client
        .post(
            "/v1/approvals",
            Some(&executor.token),
            json!({"id":id,"exp":envelope.exp,"envelopes":[envelope]}),
        )
        .await;
    let mid = state::ulid(now());
    let envelope = executor.seal(
        &approver,
        &mid,
        EnvelopeType::Grant,
        now() + 300,
        &json!({}),
    );
    client
        .post(
            "/v1/messages",
            Some(&executor.token),
            json!({"envelopes":[envelope]}),
        )
        .await;
    client
        .post(
            "/v1/messages/ack",
            Some(&approver.token),
            json!({"ids":[mid]}),
        )
        .await;
    relay.advance_time(Duration::from_secs(11));
    let stats = relay.cleanup();
    assert_eq!(stats.expired_approvals, 1);
    assert_eq!(stats.messages, 0);
    assert_error(
        &client
            .call(
                Method::POST,
                &format!("/v1/approvals/{id}/cancel"),
                Some(&executor.token),
                Some(json!({})),
            )
            .await,
        StatusCode::GONE,
        "expired",
    );
    relay.advance_time(Duration::from_secs(state::RETENTION as u64 - 12));
    assert_eq!(relay.cleanup().messages, 0);
    relay.advance_time(Duration::from_secs(12));
    let stats = relay.cleanup();
    assert_eq!(stats.approvals, 1);
    assert_eq!(stats.messages, 2);
    relay.shutdown().await;
}

#[tokio::test]
async fn websocket_submission_ack_and_reconnect() {
    let (base, relay) = spawn_test_relay();
    let client = Client::new(base);
    let (executor, approver) = two_devices(&client).await;
    let mut from = client.socket(&executor).await;
    let id = state::ulid(now());
    let envelope = executor.seal(
        &approver,
        &id,
        EnvelopeType::PresenceHint,
        now() + 300,
        &json!({"state":"idle"}),
    );
    from.send(Message::Text(
        json!({"t":"envelope","envelope":envelope})
            .to_string()
            .into(),
    ))
    .await
    .unwrap();
    assert_eq!(receive(&mut from).await, json!({"t":"ack","id":id}));
    let mut to = client.socket(&approver).await;
    assert_eq!(
        receive(&mut to).await,
        json!({"t":"envelope","envelope":envelope})
    );
    to.close(None).await.unwrap();
    let mut to = client.socket(&approver).await;
    assert_eq!(
        receive(&mut to).await,
        json!({"t":"envelope","envelope":envelope})
    );
    client
        .post(
            "/v1/messages/ack",
            Some(&approver.token),
            json!({"ids":[id]}),
        )
        .await;
    to.close(None).await.unwrap();
    let mut to = client.socket(&approver).await;
    to.send(Message::Text(json!({"t":"ping"}).to_string().into()))
        .await
        .unwrap();
    assert_eq!(receive(&mut to).await, json!({"t":"pong"}));
    relay.shutdown().await;
}

#[tokio::test]
async fn concurrent_replies_resolve_once_and_invalid_signature_does_not_resolve() {
    let (base, relay) = spawn_test_relay();
    let client = Client::new(base);
    let (executor, approver) = two_devices(&client).await;
    let mut other = Device::new("other", true);
    client.pair(&executor, &mut other, false, None).await;
    let id = state::ulid(now());
    let exp = now() + 300;
    let requests = [
        executor.seal(
            &approver,
            &id,
            EnvelopeType::ApprovalRequest,
            exp,
            &json!({}),
        ),
        executor.seal(&other, &id, EnvelopeType::ApprovalRequest, exp, &json!({})),
    ];
    client
        .post(
            "/v1/approvals",
            Some(&executor.token),
            json!({"id":id,"exp":exp,"envelopes":requests}),
        )
        .await;
    let a = approver.seal(
        &executor,
        &id,
        EnvelopeType::ApprovalDecision,
        exp,
        &json!({"decision":"allow"}),
    );
    let b = other.seal(
        &executor,
        &id,
        EnvelopeType::ApprovalDecision,
        exp,
        &json!({"decision":"deny"}),
    );
    let mut invalid = a.clone();
    invalid.sig = "AA".into();
    let path = format!("/v1/approvals/{id}/reply");
    assert_error(
        &client
            .call(
                Method::POST,
                &path,
                Some(&approver.token),
                Some(json!({"envelope":invalid})),
            )
            .await,
        StatusCode::BAD_REQUEST,
        "bad_envelope",
    );
    let (a, b) = tokio::join!(
        client.call(
            Method::POST,
            &path,
            Some(&approver.token),
            Some(json!({"envelope":a}))
        ),
        client.call(
            Method::POST,
            &path,
            Some(&other.token),
            Some(json!({"envelope":b}))
        )
    );
    assert!(
        (a.0 == StatusCode::OK && b.0 == StatusCode::CONFLICT)
            || (b.0 == StatusCode::OK && a.0 == StatusCode::CONFLICT)
    );
    relay.inspect(|db| {
        assert_eq!(
            db.query_row("SELECT state FROM approvals WHERE id=?1", [&id], |r| r
                .get::<_, String>(
                0
            ))
            .unwrap(),
            "resolved"
        );
        assert_eq!(
            db.query_row(
                "SELECT COUNT(*) FROM messages WHERE id=?1 AND type='approval_decision'",
                [&id],
                |r| r.get::<_, i64>(0)
            )
            .unwrap(),
            1
        );
    });
    relay.shutdown().await;
}

#[tokio::test]
async fn unacknowledged_ciphertext_survives_a_restart() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("relay.sqlite3");
    let (base, relay) = spawn_test_relay_with_data(&path);
    let client = Client::new(base);
    let (executor, approver) = two_devices(&client).await;
    let id = state::ulid(now());
    let mut envelope = executor.seal(
        &approver,
        &id,
        EnvelopeType::DirectiveResult,
        now() + 300,
        &json!({}),
    );
    // Unknown signed fields and future versions remain transportable for receiver-side ack.
    envelope.v = 2;
    envelope
        .extra
        .insert("future_metadata".into(), id.clone().into());
    envelope.sig = encode_b64(
        &executor
            .dk
            .sign(
                SignatureAlgorithm::ES256,
                &envelope.signature_payload().unwrap(),
            )
            .unwrap(),
    );
    client
        .post(
            "/v1/messages",
            Some(&executor.token),
            json!({"envelopes":[envelope]}),
        )
        .await;
    relay.inspect(|db| {
        assert_eq!(
            db.query_row("PRAGMA journal_mode", [], |r| r.get::<_, String>(0))
                .unwrap(),
            "wal"
        )
    });
    relay.shutdown().await;
    let (base, relay) = spawn_test_relay_with_data(&path);
    let client = Client::new(base);
    let mut socket = client.socket(&approver).await;
    assert_eq!(
        receive(&mut socket).await,
        json!({"t":"envelope","envelope":envelope})
    );
    client
        .post(
            "/v1/messages/ack",
            Some(&approver.token),
            json!({"ids":[id]}),
        )
        .await;
    relay.shutdown().await;
}

#[tokio::test]
async fn background_worker_expires_pairing_tokens() {
    let (base, relay) = spawn_test_relay();
    let client = Client::new(base);
    let mut executor = Device::new("executor", false);
    client.register(&mut executor).await;
    let token = state::random_token(16);
    let request = json!({"token_hash":sha256_hex(&decode_b64(&token).unwrap()),"initiator":executor.record,"exp":now()+600});
    let pairing = client
        .post("/v1/pair/start", Some(&executor.token), request)
        .await;
    relay.advance_time(Duration::from_secs(601));
    tokio::time::timeout(Duration::from_secs(35),async {
        loop {
            let expired=relay.inspect(|db|db.query_row("SELECT state='expired' AND token_hash IS NULL FROM pairings WHERE pairing_id=?1",
                [pairing["pairing_id"].as_str().unwrap()],|r|r.get::<_,bool>(0)).unwrap());
            if expired { break; }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
    }).await.expect("background cleanup did not run");
    let joiner = Device::new("joiner", true);
    assert_error(
        &client
            .call(
                Method::POST,
                "/v1/pair/complete",
                None,
                Some(json!({"token":token,"joiner":joiner.record})),
            )
            .await,
        StatusCode::GONE,
        "expired",
    );
    relay.shutdown().await;
}

#[tokio::test]
async fn heartbeat_tolerates_thirty_seconds_and_disconnects_after_one_hundred() {
    let (base, relay) = spawn_test_relay();
    let client = Client::new(base);
    let mut device = Device::new("heartbeat", false);
    client.register(&mut device).await;
    let mut socket = client.socket(&device).await;
    socket
        .send(Message::Text(json!({"t":"ping"}).to_string().into()))
        .await
        .unwrap();
    assert_eq!(receive(&mut socket).await, json!({"t":"pong"}));
    let start = tokio::time::Instant::now();
    // Do not poll the client: tungstenite would automatically answer control pings.
    tokio::time::sleep(Duration::from_secs(31)).await;
    assert_eq!(
        relay.state.with(|data, _| Ok(data.presence.len())).unwrap(),
        1
    );
    tokio::time::timeout(Duration::from_secs(76), async {
        while relay.state.with(|data, _| Ok(data.presence.len())).unwrap() != 0 {
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
    })
    .await
    .expect("relay did not close an unresponsive client");
    assert!(start.elapsed() >= Duration::from_secs(100));
    relay.shutdown().await;
}
