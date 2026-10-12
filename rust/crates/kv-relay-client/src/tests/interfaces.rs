//! Real W1 providers, W2 HTTP/WS, W3 transport, W4 state and W5 MCP/hook contracts.
use super::*;
use kv_core::remote::ApprovalLevel;
use kv_core::remote::{
    self as core, keys::DeviceKeyProvider, ApprovalKey, Capability, DeviceRecord, Extra, KeyKind,
    Os, Presence, ScopeOption, SignatureAlgorithm, SoftwareDeviceKey, Tier,
};
use kv_helper::remote::{
    self as backend, ipc::CallerContext, server, ApprovalConfig, ApprovalInput, AuditSink,
    DeviceMirror, Execution, FullRequest, RemoteHelper, RequestRunner, Services, Store,
    SystemClock,
};
use kv_ipc::remote::{Caller, Op, Request};
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};

struct PlatformKey(SoftwareDeviceKey);
impl kv_ipc::remote::DeviceKeyProvider for PlatformKey {
    fn sign(
        &self,
        alg: SignatureAlgorithm,
        payload: &[u8],
    ) -> Result<Vec<u8>, kv_ipc::remote::DeviceKeyError> {
        self.0
            .sign(alg, payload)
            .map_err(|_| kv_ipc::remote::DeviceKeyError::OperationFailed)
    }
    fn ecdh(
        &self,
        peer: &[u8],
    ) -> Result<kv_ipc::remote::SharedSecret, kv_ipc::remote::DeviceKeyError> {
        self.0
            .ecdh(peer)
            .map_err(|_| kv_ipc::remote::DeviceKeyError::OperationFailed)
    }
    fn public_jwk(&self) -> Result<Value, kv_ipc::remote::DeviceKeyError> {
        serde_json::to_value(self.0.public_jwk().unwrap())
            .map_err(|_| kv_ipc::remote::DeviceKeyError::InvalidKey)
    }
    fn presence_kind(&self) -> &str {
        "none"
    }
    fn key_kind(&self) -> &str {
        "software"
    }
}

type StoredKey = kv_platform::device_key::software::SoftwareFileKey<PlatformKey>;
fn stored_key(path: &std::path::Path) -> Arc<StoredKey> {
    let factory = |bytes: &[u8; 32]| {
        SoftwareDeviceKey::from_p256_bytes(bytes)
            .map(PlatformKey)
            .map_err(|_| kv_ipc::remote::DeviceKeyError::InvalidKey)
    };
    drop(StoredKey::create(path, factory).unwrap());
    Arc::new(StoredKey::open(path, factory).unwrap())
}

struct Directory(Vec<(DeviceRecord, bool)>);
impl DeviceMirror for Directory {
    fn replace(&self, _: &str, records: &[(DeviceRecord, bool)]) -> backend::Result<()> {
        self.verify("", records)
    }
    fn verify(&self, _: &str, records: &[(DeviceRecord, bool)]) -> backend::Result<()> {
        let mut expected = self.0.clone();
        let mut actual = records.to_vec();
        expected.sort_by(|a, b| a.0.device_id.cmp(&b.0.device_id));
        actual.sort_by(|a, b| a.0.device_id.cmp(&b.0.device_id));
        if expected == actual {
            Ok(())
        } else {
            Err(backend::Error("device_directory_mismatch"))
        }
    }
}
struct Audit;
impl AuditSink for Audit {
    fn append(&self, _: serde_json::Map<String, Value>) -> backend::Result<()> {
        Ok(())
    }
}
struct Probe;
impl core::PresenceProbe for Probe {
    fn state(&self) -> kv_ipc::remote::PresenceState {
        kv_ipc::remote::PresenceState {
            state: Presence::Away,
            since: transport::unix_now(),
            signals: kv_platform::presence::unavailable_signals(),
            extra: Default::default(),
        }
    }
}
struct Runner(AtomicUsize);
impl RequestRunner for Runner {
    fn execute(
        &self,
        request: Execution,
    ) -> Pin<Box<dyn Future<Output = backend::Result<Value>> + Send + '_>> {
        Box::pin(async move {
            assert_eq!(
                request.full_request.params().unwrap()["body"],
                "ORIGINAL-PRIVATE-REQUEST"
            );
            self.0.fetch_add(1, Ordering::SeqCst);
            Ok(json!({"status":200,"headers":{},"body":"original-result"}))
        })
    }
    fn agent_alive(&self, _: u32, _: u32, _: &str) -> bool {
        true
    }
    fn lock_sessions(&self) -> backend::Result<()> {
        Ok(())
    }
    fn local_authorize(
        &self,
        _: &'static str,
        _: Value,
    ) -> Pin<Box<dyn Future<Output = backend::Result<ApprovalLevel>> + Send + '_>> {
        Box::pin(async { Ok(ApprovalLevel::Strong) })
    }
}

struct RealHelper {
    endpoint: std::path::PathBuf,
    task: tokio::task::JoinHandle<()>,
    _directory: tempfile::TempDir,
}
impl RealHelper {
    async fn start(backend: Arc<RemoteHelper>, role: Caller) -> Self {
        let directory = tempfile::tempdir().unwrap();
        let endpoint = directory.path().join("helper.sock");
        let listener = tokio::net::UnixListener::bind(&endpoint).unwrap();
        let task = tokio::spawn(async move {
            let mut workers = tokio::task::JoinSet::new();
            loop {
                let (stream, _) = listener.accept().await.unwrap();
                let backend = backend.clone();
                workers.spawn(async move {
                    let (reader, writer) = stream.into_split();
                    let _ = server::serve(
                        reader,
                        writer,
                        CallerContext::authenticated(role, 501, 0, 210),
                        Some(backend),
                    )
                    .await;
                });
                while workers.try_join_next().is_some() {}
            }
        });
        Self {
            endpoint,
            task,
            _directory: directory,
        }
    }
    fn client(&self) -> helper::Helper {
        helper::Helper::for_test(self.endpoint.clone(), true)
    }
}

struct AgentSink(std::path::PathBuf);
impl kv_agent::presence::PresenceSink for AgentSink {
    fn send(&mut self, request: &Request) -> std::io::Result<()> {
        use std::io::{BufRead, Write};
        let mut connection = std::os::unix::net::UnixStream::connect(&self.0)?;
        connection.set_read_timeout(Some(Duration::from_secs(5)))?;
        let mut bytes = serde_json::to_vec(request)?;
        bytes.push(b'\n');
        connection.write_all(&bytes)?;
        let mut response = String::new();
        std::io::BufReader::new(connection).read_line(&mut response)?;
        if serde_json::from_str::<Value>(&response)?["ok"] == true {
            Ok(())
        } else {
            Err(std::io::Error::other("presence rejected"))
        }
    }
}
impl Drop for RealHelper {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn post(base: &reqwest::Url, path: &str, token: Option<&str>, body: Value) -> Value {
    let mut request = reqwest::Client::new()
        .post(base.join(path).unwrap())
        .json(&body);
    if let Some(token) = token {
        request = request.header("Authorization", format!("Device {token}"));
    }
    let response = request.send().await.unwrap();
    let status = response.status();
    let value: Value = response.json().await.unwrap();
    assert!(status.is_success(), "{path}: {value}");
    value
}
async fn login(base: &reqwest::Url, record: &DeviceRecord, key: &dyn DeviceKeyProvider) -> String {
    let challenge = post(
        base,
        "v1/auth/challenge",
        None,
        json!({"device_id":record.device_id}),
    )
    .await;
    let signature = key
        .sign(
            SignatureAlgorithm::ES256,
            &core::keys::decode_b64(challenge["challenge"].as_str().unwrap()).unwrap(),
        )
        .unwrap();
    let result = post(
        base,
        "v1/auth/verify",
        None,
        json!({"device_id":record.device_id,
        "challenge":challenge["challenge"],"sig":core::keys::encode_b64(&signature)}),
    )
    .await;
    result["session_token"].as_str().unwrap().into()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn w1_to_w5_real_protocol_approval_executes_once_and_mcp_consumes_once() {
    let keys = tempfile::tempdir().unwrap();
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(keys.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let executor_key = stored_key(&keys.path().join("executor.key"));
    let approver_key = stored_key(&keys.path().join("approver.key"));
    let strong = Arc::new(SoftwareDeviceKey::from_p256_bytes(&[3; 32]).unwrap());
    let quick = Arc::new(SoftwareDeviceKey::from_p256_bytes(&[4; 32]).unwrap());
    let executor = DeviceRecord {
        device_id: "dev-executor".into(),
        label: "Executor".into(),
        os: Os::Linux,
        key_kind: KeyKind::Software,
        dk_pub: executor_key.public_jwk().unwrap(),
        dk_sig: kv_core::remote::Optional::Missing,
        ak_q: None,
        ak_s: None,
        caps: vec![Capability::Execute],
        attestation: None,
        extra: Extra::new(),
    };
    let approval_key = ApprovalKey {
        r#pub: strong.public_jwk().unwrap(),
        alg: SignatureAlgorithm::ES256,
        extra: Extra::new(),
    };
    let approver = DeviceRecord {
        device_id: "dev-approver".into(),
        label: "Approver".into(),
        os: Os::Macos,
        key_kind: KeyKind::Software,
        dk_pub: approver_key.public_jwk().unwrap(),
        dk_sig: kv_core::remote::Optional::Missing,
        ak_q: Some(ApprovalKey {
            r#pub: quick.public_jwk().unwrap(),
            alg: SignatureAlgorithm::ES256,
            extra: Extra::new(),
        }),
        ak_s: Some(approval_key),
        caps: vec![Capability::ApproveQuick, Capability::ApproveStrong],
        attestation: None,
        extra: Extra::new(),
    };
    let (base, relay_server) = kv_server::spawn_test_relay();
    let registered = post(
        &base,
        "v1/devices",
        None,
        serde_json::to_value(&executor).unwrap(),
    )
    .await;
    let account = registered["account_id"].as_str().unwrap().to_owned();
    let executor_token = login(&base, &executor, executor_key.as_ref()).await;
    let token = core::keys::encode_b64(&[19; 16]);
    let pairing = post(
        &base,
        "v1/pair/start",
        Some(&executor_token),
        json!({"token_hash":core::canonical::sha256_hex(&[19;16]),
        "initiator":executor,"exp":transport::unix_now()+600}),
    )
    .await;
    post(
        &base,
        "v1/pair/complete",
        None,
        json!({"token":token,"joiner":approver}),
    )
    .await;
    let approver_token = login(&base, &approver, approver_key.as_ref()).await;
    let sas = core::pairing::sas(
        &[19; 16],
        &executor.dk_pub,
        &approver.dk_pub,
        Some(&approver.ak_q.as_ref().unwrap().r#pub),
        Some(&approver.ak_s.as_ref().unwrap().r#pub),
    )
    .unwrap();
    post(&base,"v1/pair/finish",Some(&approver_token),json!({"pairing_id":pairing["pairing_id"],
        "confirm":core::pairing::sign_confirm(&sas,SignatureAlgorithm::ES256,strong.as_ref()).unwrap()})).await;
    post(
        &base,
        "v1/pair/finish",
        Some(&executor_token),
        json!({"pairing_id":pairing["pairing_id"],"confirm":{"sas":sas,"sig":""}}),
    )
    .await;
    let directory = Arc::new(Directory(vec![
        (executor.clone(), false),
        (approver.clone(), false),
    ]));
    let runner = Arc::new(Runner(AtomicUsize::new(0)));
    let make_helper = |local: DeviceRecord,
                       identity: Arc<dyn DeviceKeyProvider + Send + Sync>,
                       approving: bool| {
        let store = Store::memory().unwrap();
        store
            .restore_verified_directory(
                &account,
                &directory.0,
                directory.as_ref(),
                transport::unix_now(),
            )
            .unwrap();
        RemoteHelper::new(
            store,
            local,
            account.clone(),
            ApprovalConfig::default(),
            Services {
                identity,
                quick: approving.then(|| quick.clone() as Arc<dyn DeviceKeyProvider + Send + Sync>),
                strong: approving
                    .then(|| strong.clone() as Arc<dyn DeviceKeyProvider + Send + Sync>),
                presence: Arc::new(Probe),
                mirror: directory.clone(),
                audit: Arc::new(Audit),
                runner: runner.clone(),
                clock: Arc::new(SystemClock),
            },
        )
        .unwrap()
    };
    let executing = make_helper(executor.clone(), executor_key, false);
    let approving = make_helper(approver.clone(), approver_key, true);
    let executor_ipc = RealHelper::start(executing.clone(), Caller::RelayClient).await;
    let approver_ipc = RealHelper::start(approving.clone(), Caller::RelayClient).await;
    let agent_ipc = RealHelper::start(approving.clone(), Caller::ApprovalAgent).await;
    let executor_spool = tempfile::tempdir().unwrap();
    let approver_spool = tempfile::tempdir().unwrap();
    let executor_queue = Queue::open(executor_spool.path()).unwrap();
    let approver_queue = Queue::open(approver_spool.path()).unwrap();
    let config = |device: &str| Config {
        relay_url: base.to_string(),
        device_id: device.into(),
        account_id: account.clone(),
    };
    let executor_client = RunningClient::start(
        executor_ipc.client(),
        config(&executor.device_id),
        executor_queue.clone(),
        fast_timing(),
    );
    let approver_client = RunningClient::start(
        approver_ipc.client(),
        config(&approver.device_id),
        approver_queue.clone(),
        fast_timing(),
    );
    let agent_endpoint = agent_ipc.endpoint.clone();
    let device_id = approver.device_id.clone();
    tokio::task::spawn_blocking(move || {
        let mut reporter = kv_agent::presence::PresenceReporter::new(device_id);
        let mut sink = AgentSink(agent_endpoint);
        assert!(reporter
            .update(&Probe, &mut sink, transport::unix_now())
            .unwrap());
    })
    .await
    .unwrap();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        let status = executing
            .handle(
                CallerContext::authenticated(Caller::CliOwner, 501, 0, 210),
                Request {
                    op: Op::Status,
                    params: json!({}),
                    extra: Extra::new(),
                },
            )
            .await;
        if serde_json::to_value(status).unwrap()["result"]["approvers"][0]["online"] == true {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "W1 presence did not cross W4/W3/W2"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let fixture: Value = serde_json::from_slice(
        &fs::read(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../kv-core/testdata/remote/decision_valid.json"),
        )
        .unwrap(),
    )
    .unwrap();
    let mut canonical: core::canonical::CanonicalRequest =
        serde_json::from_value(fixture["canonical"].clone()).unwrap();
    canonical.requester = executor.device_id.clone();
    let uid = canonical.agent.uid;
    let pid = canonical.agent.pid;
    let request = executing
        .submit(ApprovalInput {
            canonical,
            credential: serde_json::from_value(fixture["request"]["credential"].clone()).unwrap(),
            operation: serde_json::from_value(fixture["request"]["operation"].clone()).unwrap(),
            tier: Tier::T1,
            min_level: ApprovalLevel::Strong,
            scope_options: vec![ScopeOption::PerUse],
            requested_scope: ScopeOption::PerUse,
            session_id: "interface-session".into(),
            full_request: FullRequest::new(
                "httpRequest",
                json!({"body":"ORIGINAL-PRIVATE-REQUEST"})
                    .as_object()
                    .unwrap()
                    .clone(),
            )
            .unwrap(),
            auto_allowed: false,
            local_channel_available: false,
        })
        .unwrap();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        let pending = approving
            .handle(
                CallerContext::authenticated(Caller::CliOwner, uid, pid, 210),
                Request {
                    op: Op::PendingList,
                    params: json!({}),
                    extra: Extra::new(),
                },
            )
            .await;
        if serde_json::to_value(pending).unwrap()["result"]["pending"]
            .as_array()
            .is_some_and(|p| !p.is_empty())
        {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "signed approval request did not reach real helper"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let hook = executing
        .handle(
            CallerContext::authenticated(Caller::Hook, uid, pid, 210),
            Request {
                op: Op::PendingForAgent,
                params: json!({"agent_pid":pid}),
                extra: Extra::new(),
            },
        )
        .await;
    assert_eq!(
        serde_json::to_value(hook).unwrap()["result"]["pending"][0]["approval_id"],
        request.approval_id
    );
    let decision=approving.handle(CallerContext::authenticated(Caller::CliOwner,uid,pid,210),Request { op:Op::Decide,
        params:json!({"approval_id":request.approval_id,"decision":"allow","level":"strong","scope":{"mode":"per_use","level":"credential","until":0}}),extra:Extra::new() }).await;
    assert_eq!(serde_json::to_value(decision).unwrap()["ok"], true);
    let (mcp_stream, helper_stream) = tokio::io::duplex(65536);
    let helper = executing.clone();
    let serving = tokio::spawn(async move {
        let (reader, writer) = tokio::io::split(helper_stream);
        server::serve(
            reader,
            writer,
            CallerContext::authenticated(Caller::Mcp, uid, pid, 210),
            Some(helper),
        )
        .await
    });
    let session = kv_mcp::session::HelperSession::with_test_transport(
        kv_mcp::approval::ApprovalConfig::default(),
        mcp_stream,
    )
    .await;
    let params =
        json!({"approval_id":request.approval_id,"max_wait_ms":5000,"runtime_budget_s":60})
            .as_object()
            .unwrap()
            .clone();
    let result = session
        .remote_request(kv_ipc::remote::WAIT, params.clone(), Duration::from_secs(6))
        .await
        .unwrap();
    assert_eq!(result["status"], "ok");
    assert_eq!(result["result"]["body"], "original-result");
    let again = session
        .remote_request(kv_ipc::remote::WAIT, params, Duration::from_secs(2))
        .await
        .unwrap();
    assert_eq!(again["status"], "already_consumed");
    assert_eq!(runner.0.load(Ordering::SeqCst), 1);
    wait_for_queue_empty(&executor_queue).await;
    wait_for_queue_empty(&approver_queue).await;
    executor_client.stop().await;
    approver_client.stop().await;
    serving.abort();
    relay_server.shutdown().await;
}
