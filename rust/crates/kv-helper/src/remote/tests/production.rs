//! Production adapters use real encrypted storage and an injected process/kernel boundary.

use super::*;
use crate::remote::bootstrap::{Environment, Options};
#[cfg(unix)]
use crate::remote::production::{
    ProcessIdentity, Processes, ProductionRunner, SessionExecutor, Task,
};
#[cfg(unix)]
use kv_vault::Vault;
#[cfg(unix)]
use std::time::Duration;

#[test]
fn authenticated_bootstrap_reopens_the_same_identity_and_rejects_metadata_rollback() {
    let fixture = Harness::new();
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("remote");
    let keys = crate::remote::platform_keys::SoftwareKeys;
    let master = crate::remote::metadata_master::IdentityMaster { keys: &keys };
    let environment = || Environment {
        master: &master,
        factory: &keys,
        runner: fixture.runner.clone(),
        presence: fixture.presence.clone(),
        clock: fixture.clock.clone(),
    };
    let backend = crate::remote::bootstrap::open(
        Options {
            path: &path,
            initialize: Some((
                "account",
                "CI executor",
                "synthetic-test-passphrase-42",
                Os::Linux,
            )),
            config: ApprovalConfig::default(),
        },
        environment(),
    )
    .unwrap();
    let id = backend.helper.local.device_id.clone();
    let certificate =
        kv_proxy::certificates::CertificateAuthority::open(&backend.metadata).unwrap();
    let public = certificate.certificate().to_owned();
    drop(certificate);
    drop(backend);
    let reopened = crate::remote::bootstrap::open(
        Options {
            path: &path,
            initialize: None,
            config: ApprovalConfig::default(),
        },
        environment(),
    )
    .unwrap();
    assert_eq!(reopened.helper.local.device_id, id);
    assert_eq!(
        kv_proxy::certificates::CertificateAuthority::open(&reopened.metadata)
            .unwrap()
            .certificate(),
        public
    );
    assert!(!path.join("master.key").exists());
    let old = reopened
        .metadata
        .authenticated_metadata("remote_directory")
        .unwrap()
        .unwrap();
    let records = vec![
        (reopened.helper.local.clone(), false),
        (fixture.peer.clone(), true),
    ];
    reopened
        .helper
        .services
        .mirror
        .replace("account", &records)
        .unwrap();
    assert!(reopened
        .helper
        .services
        .mirror
        .replace("account", &[(reopened.helper.local.clone(), false)])
        .is_err());
    let current = reopened
        .metadata
        .authenticated_metadata("remote_directory")
        .unwrap()
        .unwrap();
    reopened
        .metadata
        .replace_authenticated_metadata("remote_directory", Some(&current), old)
        .unwrap();
    assert!(reopened
        .helper
        .services
        .mirror
        .verify("account", &records)
        .is_err());
}

#[cfg(unix)]
struct Kernel(Mutex<ProcessIdentity>);
#[cfg(unix)]
impl Processes for Kernel {
    fn inspect(&self, pid: u32) -> Result<ProcessIdentity> {
        let identity = self.0.lock().unwrap().clone();
        if pid != identity.pid {
            return Err(Error("agent_unavailable"));
        }
        Ok(identity)
    }
}
#[cfg(unix)]
struct Executor {
    vault: Arc<Vault>,
    context: kv_core::ClientContext,
    closed: AtomicBool,
    calls: AtomicUsize,
}
#[cfg(unix)]
impl SessionExecutor for Executor {
    fn vault(&self) -> &Vault {
        &self.vault
    }
    fn context(&self) -> &kv_core::ClientContext {
        &self.context
    }
    fn execute(
        &self,
        op: kv_ipc::Op,
        params: Map<String, Value>,
        binding: String,
    ) -> Task<'_, Value> {
        Box::pin(async move {
            self.calls.fetch_add(1, Ordering::SeqCst);
            kv_core::dispatch::dispatch_approved::<NoGate, NoConfirm>(
                &self.vault,
                op,
                &params,
                &binding,
                &self.context,
                None,
                &NoConfirm,
            )
            .await
            .map_err(|_| Error("credential_operation_failed"))
        })
    }
    fn authorize(&self, _: String) -> Task<'_, ApprovalLevel> {
        Box::pin(async { Ok(ApprovalLevel::Strong) })
    }
    fn close(&self) {
        self.closed.store(true, Ordering::SeqCst);
        self.vault.close();
    }
}

#[cfg(unix)]
struct NoGate;
#[cfg(unix)]
impl kv_core::AuthorizeGate for NoGate {
    async fn authorize(&self, _: &str) -> std::result::Result<(), String> {
        panic!("verified remote execution must not invoke a native prompt")
    }
}
#[cfg(unix)]
struct NoConfirm;
#[cfg(unix)]
impl kv_platform::Confirmer for NoConfirm {
    async fn confirm(&self, _: &str, _: &str) -> bool {
        panic!("use operations must not invoke an administration dialog")
    }
}

#[tokio::test]
#[cfg(unix)]
async fn production_leases_bind_pid_start_executable_and_full_credential_request() {
    use std::os::unix::fs::PermissionsExt;
    let directory = tempfile::tempdir().unwrap();
    let vault = Vault::new(directory.path().join("vault"));
    vault.prepare().unwrap();
    std::fs::write(vault.dir.join("master.key"), [7; 32]).unwrap();
    std::fs::set_permissions(
        vault.dir.join("master.key"),
        std::fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    vault.init_legacy().unwrap();
    vault
        .set(kv_vault::SetParams {
            r#type: "api_key".into(),
            name: "service".into(),
            value: Some("synthetic-secret".into()),
            ..Default::default()
        })
        .unwrap();
    let kernel = Arc::new(Kernel(Mutex::new(ProcessIdentity {
        uid: 501,
        pid: 4242,
        start_time: 1234,
        exe_sha256: "a".repeat(64),
    })));
    let runner = ProductionRunner::new(kernel.clone());
    let executor = Arc::new(Executor {
        vault: Arc::new(vault),
        context: kv_core::ClientContext {
            client: Some("CI agent".into()),
            ..Default::default()
        },
        closed: AtomicBool::new(false),
        calls: AtomicUsize::new(0),
    });
    assert!(runner
        .attach(
            "wrong".into(),
            502,
            4242,
            Duration::from_secs(100),
            executor.clone()
        )
        .is_err());
    runner
        .attach(
            "session".into(),
            501,
            4242,
            Duration::from_secs(100),
            executor.clone(),
        )
        .unwrap();
    let h = Harness::new();
    let params = json!({"type":"api_key","name":"service","purpose":"Test credential binding","runtime_budget_s":50,"agent":{"uid":0},"frontend":{"tool":"credential_export_file","op":"get","options":{}}}).as_object().unwrap().clone();
    let (mut input, _, _) = runner
        .prepare(&h.helper, "session", "get", params, false)
        .unwrap();
    assert_eq!(input.tier, Tier::T2);
    assert_eq!(input.canonical.agent.pid, 4242);
    assert_eq!(input.canonical.agent.uid, 501);
    assert!(!input.full_request.params().unwrap().contains_key("agent"));
    // The legacy core digest excludes display-only purpose. The remote helper's
    // full execution digest additionally binds it and all continuation metadata.
    let mut changed = input.full_request.params().unwrap();
    changed.insert("purpose".into(), json!("A different purpose"));
    assert_ne!(
        input.full_request.binding_digest().unwrap(),
        FullRequest::new("get", changed)
            .unwrap()
            .binding_digest()
            .unwrap()
    );
    input
        .canonical
        .extra
        .insert("session_id".into(), json!("session"));
    let original = input.canonical.clone();
    let value = runner
        .execute(Execution {
            approval_id: "01J00000000000000000000000".into(),
            canonical: input.canonical,
            full_request: input.full_request,
        })
        .await
        .unwrap();
    assert_eq!(value["value"], "synthetic-secret");
    assert_eq!(executor.calls.load(Ordering::SeqCst), 1);
    assert!(runner
        .prepare(&h.helper, "session", "delete", Map::new(), false)
        .is_err());
    assert!(runner.rebind(&original, "missing").is_err());
    kernel.0.lock().unwrap().start_time += 1;
    runner.sweep();
    assert!(executor.closed.load(Ordering::SeqCst));
    assert!(!runner.agent_alive(501, 4242, &"a".repeat(64)));
}

#[tokio::test]
#[cfg(unix)]
async fn production_gateway_retries_join_one_ticket_and_release_terminal_entries() {
    use kv_proxy::approval::ApprovalProvider;
    let mut h = Harness::new();
    let directory = tempfile::tempdir().unwrap();
    let vault = Vault::new(directory.path().join("vault"));
    vault.prepare().unwrap();
    std::fs::write(vault.dir.join("master.key"), [7; 32]).unwrap();
    kv_platform::fs::set_private_permissions(&vault.dir.join("master.key")).unwrap();
    vault.init_legacy().unwrap();
    vault
        .set(kv_vault::SetParams {
            r#type: "api_key".into(),
            name: "service".into(),
            value: Some("synthetic-secret".into()),
            http: Some(kv_vault::HttpConfig {
                inject: None,
                allowed_hosts: vec!["api.example.com".into()],
                proxy_only: true,
                test: None,
            }),
            ..Default::default()
        })
        .unwrap();
    let runner = ProductionRunner::new(Arc::new(Kernel(Mutex::new(ProcessIdentity {
        uid: 501,
        pid: 4242,
        start_time: 1234,
        exe_sha256: "a".repeat(64),
    }))));
    let executor = Arc::new(Executor {
        vault: Arc::new(vault),
        context: kv_core::ClientContext {
            client: Some("CI agent".into()),
            ..Default::default()
        },
        closed: AtomicBool::new(false),
        calls: AtomicUsize::new(0),
    });
    runner
        .attach(
            "session".into(),
            501,
            4242,
            Duration::from_secs(600),
            executor.clone(),
        )
        .unwrap();
    let store = Store::memory().unwrap();
    store
        .insert_device(&h.peer, "account", h.clock.now())
        .unwrap();
    h.helper = RemoteHelper::new(
        store,
        h.helper.local.clone(),
        "account".into(),
        ApprovalConfig::default(),
        Services {
            identity: key("sender"),
            quick: None,
            strong: None,
            runner: runner.clone(),
            clock: h.clock.clone(),
            presence: h.presence.clone(),
            mirror: h.mirror.clone(),
            audit: h.audit.clone(),
        },
    )
    .unwrap();
    let provider =
        super::super::gateway::Provider::new(h.helper.clone(), runner, "session".into(), 501, 4242);
    let request = kv_proxy::approval::ApprovalRequest {
        credential_type: "api_key".into(),
        credential_name: "service".into(),
        method: "POST".into(),
        url: "https://api.example.com/v1/use".into(),
        headers: std::collections::HashMap::from([(
            "content-type".into(),
            "application/octet-stream".into(),
        )]),
        body: vec![0, 255, 13, 10].into(),
        purpose: Some("CI binary request".into()),
    };
    let (first, retry) = tokio::join!(
        provider.authorize(request.clone()),
        provider.authorize(request.clone())
    );
    let first = first.unwrap();
    assert_eq!(first["approval_id"], retry.unwrap()["approval_id"]);
    assert_eq!(
        h.helper.lock().unwrap().store.pending_ids().unwrap().len(),
        1
    );
    let id = first["approval_id"].as_str().unwrap();
    let pending = h.helper.lock().unwrap().store.pending(id).unwrap();
    assert_eq!(
        pending.canonical.body_sha256.as_deref(),
        Some(sha256_hex(&request.body).as_str())
    );
    assert_eq!(pending.request.operation.as_ref().unwrap().body_bytes, 4);
    let decision = h.decision(&pending.request, ApprovalLevel::Strong, ScopeMode::PerUse);
    h.helper
        .inbound(h.envelope(EnvelopeType::ApprovalDecision, id, &decision))
        .await
        .unwrap();
    let allowed = provider
        .wait(id.into(), Duration::from_secs(1))
        .await
        .unwrap();
    assert_eq!(allowed["status"], "ok");
    assert!(allowed.get("result").is_none());
    assert_eq!(
        executor.calls.load(Ordering::SeqCst),
        0,
        "the gateway, not the helper, sends HTTP"
    );
    assert_eq!(
        provider.wait(id.into(), Duration::ZERO).await.unwrap()["status"],
        "already_consumed"
    );
    let next = provider.authorize(request.clone()).await.unwrap();
    assert_ne!(first["approval_id"], next["approval_id"]);
    h.clock.0.fetch_add(601, Ordering::SeqCst);
    let after_expiry = provider.authorize(request).await.unwrap();
    assert_ne!(next["approval_id"], after_expiry["approval_id"]);
}

#[tokio::test]
#[cfg(unix)]
async fn a_signed_remote_decision_releases_the_real_gateway_binary_request_once() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    struct Loopback;
    impl Drop for Loopback {
        fn drop(&mut self) {
            kv_proxy::allow_insecure_loopback_for_tests(false);
        }
    }
    kv_proxy::allow_insecure_loopback_for_tests(true);
    let _loopback = Loopback;
    let mut h = Harness::new();
    let upstream = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = upstream.local_addr().unwrap();
    let upstream_task = tokio::spawn(async move {
        let (mut stream, _) = upstream.accept().await.unwrap();
        let mut headers = Vec::new();
        while !headers.ends_with(b"\r\n\r\n") {
            headers.push(stream.read_u8().await.unwrap());
            assert!(headers.len() < 16384);
        }
        let headers = String::from_utf8(headers).unwrap().to_ascii_lowercase();
        assert!(headers.starts_with("post /v1/use http/1.1\r\n"));
        assert!(headers.contains("authorization: bearer synthetic-secret\r\n"));
        let mut body = [0; 4];
        stream.read_exact(&mut body).await.unwrap();
        assert_eq!(body, [0, 255, 13, 10]);
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 8\r\nConnection: close\r\n\r\noriginal")
            .await
            .unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(100), upstream.accept())
                .await
                .is_err()
        );
    });
    let directory = tempfile::tempdir().unwrap();
    let vault = Arc::new(Vault::new(directory.path().join("vault")));
    vault.prepare().unwrap();
    std::fs::write(vault.dir.join("master.key"), [7; 32]).unwrap();
    kv_platform::fs::set_private_permissions(&vault.dir.join("master.key")).unwrap();
    vault.init_legacy().unwrap();
    vault
        .set(kv_vault::SetParams {
            r#type: "api_key".into(),
            name: "service".into(),
            value: Some("synthetic-secret".into()),
            http: Some(kv_vault::HttpConfig {
                inject: Some(kv_vault::InjectRule {
                    headers: Some(std::collections::HashMap::from([(
                        "Authorization".into(),
                        "Bearer {{value}}".into(),
                    )])),
                    ..Default::default()
                }),
                allowed_hosts: vec!["127.0.0.1".into()],
                proxy_only: true,
                test: None,
            }),
            ..Default::default()
        })
        .unwrap();
    let runner = ProductionRunner::new(Arc::new(Kernel(Mutex::new(ProcessIdentity {
        uid: 501,
        pid: 4242,
        start_time: 1234,
        exe_sha256: "a".repeat(64),
    }))));
    let executor = Arc::new(Executor {
        vault: vault.clone(),
        context: kv_core::ClientContext::default(),
        closed: AtomicBool::new(false),
        calls: AtomicUsize::new(0),
    });
    runner
        .attach(
            "session".into(),
            501,
            4242,
            Duration::from_secs(600),
            executor.clone(),
        )
        .unwrap();
    let store = Store::memory().unwrap();
    store
        .insert_device(&h.peer, "account", h.clock.now())
        .unwrap();
    h.helper = RemoteHelper::new(
        store,
        h.helper.local.clone(),
        "account".into(),
        ApprovalConfig::default(),
        Services {
            identity: key("sender"),
            quick: None,
            strong: None,
            runner: runner.clone(),
            clock: h.clock.clone(),
            presence: h.presence.clone(),
            mirror: h.mirror.clone(),
            audit: h.audit.clone(),
        },
    )
    .unwrap();
    let provider = Arc::new(super::super::gateway::Provider::new(
        h.helper.clone(),
        runner,
        "session".into(),
        501,
        4242,
    ));
    let gateway = kv_proxy::gateway::Gateway::new(vault, Arc::new(|_| {}), None).with_approval(
        kv_proxy::approval::ApprovalLayer {
            provider,
            http_wait: Duration::from_secs(5),
            notice: None,
        },
    );
    let opened = gateway
        .open("api_key", "service", Some("CI signed binary request"))
        .await
        .unwrap();
    let downstream = tokio::spawn(async move {
        let mut stream = tokio::net::TcpStream::connect(("127.0.0.1", opened.port))
            .await
            .unwrap();
        stream.write_all(format!("POST /{address}/v1/use HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nAuthorization: Bearer {}\r\nContent-Length: 4\r\nConnection: close\r\n\r\n", opened.port, opened.token).as_bytes()).await.unwrap();
        stream.write_all(&[0, 255, 13, 10]).await.unwrap();
        let mut response = Vec::new();
        stream.read_to_end(&mut response).await.unwrap();
        response
    });
    let id = tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if let Some(id) = h
                .helper
                .lock()
                .unwrap()
                .store
                .pending_ids()
                .unwrap()
                .first()
            {
                break id.clone();
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    let pending = h.helper.lock().unwrap().store.pending(&id).unwrap();
    let decision = h.decision(&pending.request, ApprovalLevel::Strong, ScopeMode::PerUse);
    h.helper
        .inbound(h.envelope(EnvelopeType::ApprovalDecision, &id, &decision))
        .await
        .unwrap();
    let response = tokio::time::timeout(Duration::from_secs(5), downstream)
        .await
        .unwrap()
        .unwrap();
    assert!(response.starts_with(b"HTTP/1.1 200 OK\r\n"));
    assert!(response.windows(8).any(|window| window == b"original"));
    assert_eq!(executor.calls.load(Ordering::SeqCst), 0);
    assert_eq!(
        h.helper.wait(&id, 0, 10, 501, 4242).await.unwrap().status,
        ToolStatus::AlreadyConsumed
    );
    upstream_task.await.unwrap();
    gateway.shutdown().await;
}

#[tokio::test]
async fn local_timeout_and_unavailable_prompts_remain_pending_not_denied() {
    struct LocalFailure(Option<Error>);
    impl RequestRunner for LocalFailure {
        fn execute(
            &self,
            _: Execution,
        ) -> Pin<Box<dyn Future<Output = Result<Value>> + Send + '_>> {
            Box::pin(async { panic!("failed authorization must never execute") })
        }
        fn agent_alive(&self, _: u32, _: u32, _: &str) -> bool {
            true
        }
        fn lock_sessions(&self) -> Result<()> {
            Ok(())
        }
        fn local_authorize(
            &self,
            _: &'static str,
            _: Value,
        ) -> Pin<Box<dyn Future<Output = Result<ApprovalLevel>> + Send + '_>> {
            Box::pin(async move {
                match self.0 {
                    Some(error) => Err(error),
                    None => std::future::pending().await,
                }
            })
        }
    }
    for (error, expected) in [
        (Some(Error("local_approval_denied")), "approval_denied"),
        (Some(Error("local_approval_timeout")), "approval_pending"),
        (
            Some(Error("local_approval_unavailable")),
            "approval_pending",
        ),
        (None, "approval_pending"),
    ] {
        let mut h = Harness::new();
        let store = Store::memory().unwrap();
        store
            .insert_device(&h.peer, "account", h.clock.now())
            .unwrap();
        h.helper = RemoteHelper::new(
            store,
            h.helper.local.clone(),
            "account".into(),
            ApprovalConfig {
                prefer: Preference::Local,
                ..Default::default()
            },
            Services {
                identity: key("sender"),
                quick: None,
                strong: None,
                runner: Arc::new(LocalFailure(error)),
                clock: h.clock.clone(),
                presence: h.presence.clone(),
                mirror: h.mirror.clone(),
                audit: h.audit.clone(),
            },
        )
        .unwrap();
        let mut input = h.input(Tier::T2, "local deadline");
        input.local_channel_available = true;
        let result = h
            .helper
            .run(input, Vec::new(), Vec::new(), 0)
            .await
            .unwrap();
        let result = serde_json::to_value(result).unwrap();
        assert_eq!(result["status"], expected);
        assert_eq!(
            result["approval_id"].is_string(),
            expected == "approval_pending"
        );
    }
}
