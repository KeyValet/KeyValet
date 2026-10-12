//! CLI and desktop projections are exercised against real helper handlers and crypto.
use super::*;
use kv_core::remote::canonical::CanonicalRequest;
use kv_helper::remote::{
    self as helper, ApprovalConfig, ApprovalInput, Clock, Execution, FullRequest, RemoteHelper,
    Services, Store,
};
use std::future::Future;
use std::pin::Pin;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc, Mutex,
};

struct Mirror(Mutex<Vec<(DeviceRecord, bool)>>);
impl helper::DeviceMirror for Mirror {
    fn replace(&self, _: &str, records: &[(DeviceRecord, bool)]) -> helper::Result<()> {
        *self.0.lock().unwrap() = records.to_vec();
        Ok(())
    }
    fn verify(&self, _: &str, records: &[(DeviceRecord, bool)]) -> helper::Result<()> {
        let mut expected = self.0.lock().unwrap().clone();
        expected.sort_by(|a, b| a.0.device_id.cmp(&b.0.device_id));
        let mut actual = records.to_vec();
        actual.sort_by(|a, b| a.0.device_id.cmp(&b.0.device_id));
        if expected == actual {
            Ok(())
        } else {
            Err(helper::Error("device_directory_mismatch"))
        }
    }
}
struct Audit;
impl helper::AuditSink for Audit {
    fn append(&self, _: Extra) -> helper::Result<()> {
        Ok(())
    }
}
struct Presence;
impl PresenceProbe for Presence {
    fn state(&self) -> kv_core::remote::traits::PresenceState {
        kv_core::remote::traits::PresenceState {
            state: kv_core::remote::Presence::Away,
            since: helper::SystemClock.now(),
            signals: kv_platform::presence::unavailable_signals(),
            extra: Extra::new(),
        }
    }
}
struct Runner(AtomicUsize);
impl helper::RequestRunner for Runner {
    fn execute(
        &self,
        _: Execution,
    ) -> Pin<Box<dyn Future<Output = helper::Result<Value>> + Send + '_>> {
        Box::pin(async {
            self.0.fetch_add(1, Ordering::SeqCst);
            Ok(json!({"executed":true}))
        })
    }
    fn agent_alive(&self, _: u32, _: u32, _: &str) -> bool {
        true
    }
    fn lock_sessions(&self) -> helper::Result<()> {
        Ok(())
    }
    fn local_authorize(
        &self,
        _: &'static str,
        _: Value,
    ) -> Pin<Box<dyn Future<Output = helper::Result<ApprovalLevel>> + Send + '_>> {
        Box::pin(async { Ok(ApprovalLevel::Strong) })
    }
}

fn fixture() -> Value {
    serde_json::from_slice(
        &std::fs::read(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../kv-core/testdata/remote/decision_valid.json"),
        )
        .unwrap(),
    )
    .unwrap()
}
fn key(name: &str) -> Arc<SoftwareDeviceKey> {
    let scalar = kv_core::remote::keys::decode_b64(
        fixture()["keys"][name]["private_scalar"].as_str().unwrap(),
    )
    .unwrap();
    Arc::new(SoftwareDeviceKey::from_p256_bytes(&scalar).unwrap())
}

struct LiveHost {
    runtime: tokio::runtime::Runtime,
    approver: Arc<RemoteHelper>,
    executor: Arc<RemoteHelper>,
    runner: Arc<Runner>,
    directory: tempfile::TempDir,
    calls: Vec<Request>,
    outputs: Vec<Success>,
    hooks: Vec<(String, String)>,
    confirmation: Option<String>,
    waits: usize,
    approve_on_wait: Option<String>,
}
impl LiveHost {
    fn new() -> Self {
        let runtime = tokio::runtime::Runtime::new().unwrap();
        let mut approver: DeviceRecord =
            serde_json::from_value(fixture()["device"].clone()).unwrap();
        approver.key_kind = KeyKind::Software;
        let executor = DeviceRecord {
            device_id: "dev_srv".into(),
            label: "srv".into(),
            os: Os::Linux,
            key_kind: KeyKind::Software,
            dk_pub: key("sender").public_jwk().unwrap(),
            dk_sig: kv_core::remote::Optional::Missing,
            ak_q: None,
            ak_s: None,
            caps: vec![Capability::Execute],
            attestation: None,
            extra: Extra::new(),
        };
        let runner = Arc::new(Runner(AtomicUsize::new(0)));
        let create = |local: DeviceRecord,
                      identity: Arc<SoftwareDeviceKey>,
                      quick: Option<Arc<SoftwareDeviceKey>>,
                      strong: Option<Arc<SoftwareDeviceKey>>| {
            let records = vec![(approver.clone(), false), (executor.clone(), false)];
            let mirror = Arc::new(Mirror(Mutex::new(records.clone())));
            let store = Store::memory().unwrap();
            store
                .restore_verified_directory(
                    "account",
                    &records,
                    &*mirror,
                    helper::SystemClock.now(),
                )
                .unwrap();
            RemoteHelper::new(
                store,
                local,
                "account".into(),
                ApprovalConfig::default(),
                Services {
                    identity,
                    quick: quick.map(|key| key as Arc<dyn DeviceKeyProvider + Send + Sync>),
                    strong: strong.map(|key| key as Arc<dyn DeviceKeyProvider + Send + Sync>),
                    presence: Arc::new(Presence),
                    mirror,
                    audit: Arc::new(Audit),
                    runner: runner.clone(),
                    clock: Arc::new(helper::SystemClock),
                },
            )
            .unwrap()
        };
        let server = create(executor.clone(), key("sender"), None, None);
        let owner = create(
            approver.clone(),
            key("recipient"),
            Some(key("quick")),
            Some(key("strong")),
        );
        Self {
            runtime,
            approver: owner,
            executor: server,
            runner,
            directory: tempfile::tempdir().unwrap(),
            calls: Vec::new(),
            outputs: Vec::new(),
            hooks: Vec::new(),
            confirmation: Some("srv".into()),
            waits: 0,
            approve_on_wait: None,
        }
    }
    fn args(command: &str) -> Vec<String> {
        command.split_whitespace().map(str::to_owned).collect()
    }
    fn invoke(&mut self, command: &str) -> Result<()> {
        run(self, &Self::args(command))
    }
    async fn pump(approver: &Arc<RemoteHelper>, executor: &Arc<RemoteHelper>) -> Result<()> {
        for (from, to) in [(approver, executor), (executor, approver)] {
            let envelopes = from.outbound_poll(0).await.map_err(|_| Error::protocol())?;
            for envelope in &envelopes {
                to.inbound(envelope.clone())
                    .await
                    .map_err(|_| Error::protocol())?;
            }
            if !envelopes.is_empty() {
                for stage in ["spooled", "accepted"] {
                    let response = from
                        .handle(
                            helper::ipc::CallerContext::authenticated(
                                Caller::RelayClient,
                                501,
                                0,
                                210,
                            ),
                            Request {
                                op: Op::RelayOutboundAck,
                                params: json!({"envelopes":envelopes,"stage":stage}),
                                extra: Extra::new(),
                            },
                        )
                        .await;
                    if matches!(response, Response::Err { .. }) {
                        return Err(Error::protocol());
                    }
                }
            }
        }
        Ok(())
    }
    fn submit(&mut self) -> String {
        self.submit_scopes(vec![ScopeOption::PerUse])
    }
    fn submit_scopes(&mut self, scopes: Vec<ScopeOption>) -> String {
        let data = fixture();
        let canonical: CanonicalRequest =
            serde_json::from_value(data["canonical"].clone()).unwrap();
        let request = self
            .executor
            .submit(ApprovalInput {
                canonical,
                credential: serde_json::from_value(data["request"]["credential"].clone()).unwrap(),
                operation: serde_json::from_value(data["request"]["operation"].clone()).unwrap(),
                tier: Tier::T1,
                min_level: ApprovalLevel::Quick,
                scope_options: scopes,
                requested_scope: ScopeOption::PerUse,
                session_id: "session".into(),
                full_request: FullRequest::new(
                    "proxy",
                    json!({"body":"synthetic-test-body"})
                        .as_object()
                        .unwrap()
                        .clone(),
                )
                .unwrap(),
                auto_allowed: false,
                local_channel_available: false,
            })
            .unwrap();
        self.runtime
            .block_on(Self::pump(&self.approver, &self.executor))
            .unwrap();
        request.approval_id
    }
}
impl Host for LiveHost {
    fn verify(&mut self) -> Result<()> {
        Ok(())
    }
    fn exchange(&mut self, request: Request) -> Result<Response> {
        self.calls.push(request.clone());
        let helper = self.approver.clone();
        let executor = self.executor.clone();
        self.runtime.block_on(async move {
            let response = helper.handle(helper::ipc::CallerContext::authenticated(Caller::CliOwner,501,4242,210),request);
            tokio::pin!(response);
            loop {
                tokio::select! {
                    result=&mut response=> { Self::pump(&helper,&executor).await?;return Ok(result); },
                    _=tokio::time::sleep(Duration::from_millis(5))=>Self::pump(&helper,&executor).await?,
                }
            }
        })
    }
    fn now(&self) -> i64 {
        helper::SystemClock.now()
    }
    fn config_path(&self) -> Result<PathBuf> {
        Ok(self.directory.path().join("relay-client.toml"))
    }
    fn install_root(&self) -> Result<PathBuf> {
        Ok(self.directory.path().into())
    }
    fn confirmation(&mut self, _: &str, _: Duration) -> Result<Option<String>> {
        Ok(self.confirmation.clone())
    }
    fn notice(&mut self, _: &str) -> Result<()> {
        Ok(())
    }
    fn emit(&mut self, value: &Success, _: bool) -> Result<()> {
        let encoded = serde_json::to_string(&output::JsonSuccess {
            ok: true,
            output: value.clone(),
        })
        .unwrap();
        let decoded: output::JsonSuccess = serde_json::from_str(&encoded).unwrap();
        self.outputs.push(decoded.output);
        Ok(())
    }
    fn wait(&mut self, _: Duration) -> bool {
        self.waits += 1;
        if let Some(id) = self.approve_on_wait.take() {
            self.exchange(Request { op:Op::Decide,params:json!({"approval_id":id,"decision":"allow",
                "scope":{"mode":"per_use","level":"credential","until":0},"scope_option":"per_use"}),extra:Extra::new() }).unwrap();
        }
        self.waits < 3
    }
    fn health(&mut self, _: &str) -> Result<relay::Health> {
        Err(Error::protocol())
    }
    fn hook(&mut self, _: &str, id: &str, summary: &str) -> Result<()> {
        self.hooks.push((id.into(), summary.into()));
        Ok(())
    }
    fn protection(&mut self) -> Result<Value> {
        Ok(json!({}))
    }
}

impl kv_agent::remote::Helper for LiveHost {
    fn exchange(&mut self, request: &Request) -> kv_agent::remote::Result<Value> {
        let response = Host::exchange(self, request.clone())
            .map_err(|_| kv_agent::remote::Error::HelperUnavailable)?;
        serde_json::to_value(response).map_err(|_| kv_agent::remote::Error::InvalidResponse)
    }
}

struct DesktopDialog {
    labels: usize,
}
impl kv_agent::remote::Dialog for DesktopDialog {
    fn approval(
        &mut self,
        _: &kv_agent::remote::ApprovalView,
    ) -> kv_agent::remote::Result<kv_agent::remote::Selection> {
        Ok(kv_agent::remote::Selection::Allow {
            scope: "per_use".into(),
        })
    }
    fn pairing(
        &mut self,
        _: &kv_agent::remote::view::PairingView,
    ) -> kv_agent::remote::Result<bool> {
        Ok(true)
    }
    fn confirm_label(
        &mut self,
        view: &kv_agent::remote::view::ConfirmationView,
    ) -> kv_agent::remote::Result<Option<String>> {
        self.labels += 1;
        Ok(Some(view.label.clone()))
    }
}
struct StrongProof {
    local: DeviceRecord,
}

#[test]
fn a_signed_executor_snapshot_exposes_and_revokes_an_approval_derived_grant() {
    let mut host = LiveHost::new();
    let id = host.submit_scopes(vec![ScopeOption::PerUse, ScopeOption::Remember1h]);
    host.invoke(&format!("approve {id} --scope remember:1h"))
        .unwrap();
    host.invoke("remote srv grants --json").unwrap();
    host.invoke("grant list --json").unwrap();
    let Success::Grants(ledger) = host.outputs.last().unwrap() else {
        panic!()
    };
    let derived = ledger
        .grants
        .iter()
        .find(|g| g.jti == format!("approval:{id}"))
        .unwrap();
    assert_eq!(derived.sig.as_deref(), Some(""));
    assert_eq!(derived.extra["authority"], "approval_decision");
    assert_eq!(derived.extra["usage_status"], "snapshot");
    host.executor
        .revoke_grant(&format!("approval:{id}"), "local")
        .unwrap();
    host.invoke("remote srv grants --json").unwrap();
    host.invoke("grant list --json").unwrap();
    let Success::Grants(ledger) = host.outputs.last().unwrap() else {
        panic!()
    };
    assert!(ledger
        .grants
        .iter()
        .find(|g| g.jti == format!("approval:{id}"))
        .unwrap()
        .extra["revoked_at"]
        .is_number());
    host.invoke(&format!("grant revoke approval:{id} --json"))
        .unwrap();
    host.invoke("grant list --json").unwrap();
    let Success::Grants(ledger) = host.outputs.last().unwrap() else {
        panic!()
    };
    assert!(ledger
        .grants
        .iter()
        .find(|g| g.jti == format!("approval:{id}"))
        .unwrap()
        .extra["revoked_at"]
        .is_number());
}
impl kv_agent::remote::flows::StrongAuthorization for StrongProof {
    fn authorize(&mut self, binding: &Value) -> kv_agent::remote::Result<()> {
        let approval = self.local.ak_s.as_ref().unwrap();
        let signature = kv_core::remote::keys::sign_object(binding, approval.alg, &*key("strong"))
            .map_err(|_| kv_agent::remote::Error::KeyUnavailable)?;
        kv_core::remote::keys::verify_object(binding, &signature, approval)
            .map_err(|_| kv_agent::remote::Error::KeyUnavailable)
    }
}

#[test]
fn desktop_approval_and_owner_plans_work_with_the_real_helper_contract() {
    use kv_agent::remote::flows::{DirectivePlan, DirectiveState, GrantPlan};
    use kv_agent::remote::{ApprovalFlow, ApprovalView, DisplayContext, Platform};
    let mut host = LiveHost::new();
    let id = host.submit();
    let pending = Host::exchange(
        &mut host,
        Request {
            op: Op::PendingList,
            params: json!({}),
            extra: Extra::new(),
        },
    )
    .unwrap();
    let pending = serde_json::to_value(pending).unwrap();
    let view = ApprovalView::new(
        &pending["result"]["pending"][0],
        DisplayContext {
            now: host.now(),
            ..Default::default()
        },
        Platform::Macos,
    )
    .unwrap();
    let mut dialog = DesktopDialog { labels: 0 };
    let now = host.now();
    ApprovalFlow::run(&view, &mut dialog, &mut host, &|| now).unwrap();
    assert_eq!(host.runner.0.load(Ordering::SeqCst), 1);
    assert!(host
        .calls
        .iter()
        .any(|r| r.op == Op::Decide && r.params["approval_id"] == id));
    let local: DeviceRecord = serde_json::from_value(fixture()["device"].clone()).unwrap();
    let local_value = serde_json::to_value(&local).unwrap();
    let executor = json!({"device_id":"dev_srv","label":"srv","caps":["execute"]});
    let mut strong = StrongProof { local };
    let plan = GrantPlan::settings(
        json!({"jti":"preview-only","aud":"dev_srv",
        "scope":{"level":"device","max_tier":"T2"}}),
        &local_value,
        &executor,
        host.now(),
        true,
        Platform::Macos,
    )
    .unwrap();
    let grant: Grant =
        serde_json::from_value(plan.issue(&mut dialog, &mut host, &mut strong).unwrap()).unwrap();
    assert_ne!(grant.jti, "preview-only");
    assert_eq!(dialog.labels, 2);
    assert_eq!(grant.confirm.as_value().map(String::as_str), Some("srv"));
    kv_core::remote::validation::verify_grant(
        &grant,
        "dev_srv",
        "srv",
        &strong.local,
        ApprovalLevel::Strong,
        host.now(),
    )
    .unwrap();
    let state = DirectiveState {
        mode: Some("per_credential".into()),
        unlock_ttl_s: Some(43200),
        classes: Default::default(),
    };
    let plan = DirectivePlan::new(
        json!({"id":"preview-only","nonce":"preview-nonce","aud":"dev_srv",
        "op":"set_mode","args":{"mode":"per_use"},"exp":host.now()+60}),
        &local_value,
        &executor,
        &state,
        host.now(),
        Platform::Macos,
    )
    .unwrap();
    assert_eq!(
        plan.issue(&mut dialog, &mut host, &mut strong).unwrap()["ok"],
        true
    );
    assert_eq!(host.executor.mode().unwrap(), "per_use");
    for request in host
        .calls
        .iter()
        .filter(|r| matches!(r.op, Op::GrantIssue | Op::DirectiveIssue))
    {
        for private in ["iss", "jti", "id", "nonce", "sig", "iss_alg"] {
            assert!(request.params.get(private).is_none());
        }
    }
}

#[test]
fn cli_grant_directive_confirmation_and_revoke_work_with_a_real_helper() {
    let mut host = LiveHost::new();
    host.invoke("remote srv mode per_use --json").unwrap();
    assert_eq!(host.executor.mode().unwrap(), "per_use");
    host.invoke("remote srv allow --credential github/default --until 1h --json")
        .unwrap();
    let Success::GrantsIssued { grants } = host.outputs.last().unwrap() else {
        panic!("missing grant");
    };
    let jti = grants[0].jti.clone();
    kv_core::remote::validation::verify_grant(
        &grants[0],
        "dev_srv",
        "srv",
        &serde_json::from_value(fixture()["device"].clone()).unwrap(),
        ApprovalLevel::Strong,
        host.now(),
    )
    .unwrap();
    host.invoke("grant list --json").unwrap();
    assert!(
        matches!(host.outputs.last(),Some(Success::Grants(list)) if list.grants.iter().any(|grant|grant.jti==jti))
    );
    host.invoke(&format!("grant revoke {jti} --json")).unwrap();
    host.invoke("remote srv grants --json").unwrap();
    let Success::Remote { results } = host.outputs.last().unwrap() else {
        panic!("missing executor result");
    };
    assert!(results[0].result.state["grants"][0]["revoked_at"].is_number());
    host.invoke("remote srv unattended --include-sensitive --until 1h --json")
        .unwrap();
    let issues = host
        .calls
        .iter()
        .filter(|request| request.op == Op::GrantIssue)
        .collect::<Vec<_>>();
    assert_eq!(issues.len(), 3);
    assert!(issues.iter().all(|request| ["iss", "iss_alg", "jti", "sig"]
        .iter()
        .all(|field| request.params.get(field).is_none())));
    assert!(issues[1].params.get("confirmation_token").is_none());
    assert!(issues[2].params["confirmation_token"].is_string());
    assert_eq!(issues[2].params["confirm"], "srv");
    host.invoke("remote srv status --json").unwrap();
    let Success::Remote { results } = host.outputs.last().unwrap() else {
        panic!("missing status");
    };
    assert_eq!(results[0].result.state["unattended"], true);
    host.invoke("grant revoke-all --json").unwrap();
    host.invoke("remote srv status --json").unwrap();
    let Success::Remote { results } = host.outputs.last().unwrap() else {
        panic!("missing status");
    };
    assert_eq!(results[0].result.state["unattended"], false);
}

#[test]
fn a_live_watch_observes_signed_decisions_and_runs_the_owner_hook_once() {
    let mut host = LiveHost::new();
    let id = host.submit();
    host.approve_on_wait = Some(id.clone());
    host.invoke("approvals --watch --on-approve owner-hook --json")
        .unwrap();
    assert_eq!(host.hooks.len(), 1);
    assert_eq!(host.hooks[0].0, id);
    assert!(!host.hooks[0].1.is_empty());
    assert_eq!(host.runner.0.load(Ordering::SeqCst), 1);
    assert!(host
        .calls
        .iter()
        .any(|request| request.op == Op::PendingList));
    assert!(host
        .calls
        .iter()
        .any(|request| request.op == Op::Decide && request.params.get("level").is_none()));
}
