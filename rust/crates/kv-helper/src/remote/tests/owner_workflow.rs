//! Anonymous bootstrap, pairing and owner controls use the real HTTP relay and helper.
use super::*;
use crate::remote::bootstrap::{Backend, Environment, KeyFactory, Options};
use crate::remote::pairing_relay::{parse_uri, Registration, RelayApi};
use kv_core::remote::keys::encode_b64;
use kv_core::remote::relay::*;
use kv_platform::device_key::KeyRole;
use std::path::PathBuf;
use std::time::Duration;

struct Keys {
    approver: bool,
}
impl KeyFactory for Keys {
    fn create(&self, role: KeyRole) -> Result<(crate::remote::bootstrap::DeviceKey, Value)> {
        let (key, scalar) = SoftwareDeviceKey::generate_p256_material();
        Ok((
            Arc::new(key),
            json!({"role":role.as_str(),"scalar":kv_core::remote::keys::encode_b64(scalar.as_ref())}),
        ))
    }
    fn load(&self, role: KeyRole, metadata: Value) -> Result<crate::remote::bootstrap::DeviceKey> {
        if metadata["role"] != role.as_str() {
            return Err(Error("invalid_key_metadata"));
        }
        let scalar = zeroize::Zeroizing::new(decode_b64(
            metadata["scalar"]
                .as_str()
                .ok_or(Error("invalid_key_metadata"))?,
        )?);
        Ok(Arc::new(SoftwareDeviceKey::from_p256_bytes(&scalar)?))
    }
    fn approval_roles(&self) -> &[KeyRole] {
        if self.approver {
            &[KeyRole::Quick, KeyRole::Strong]
        } else {
            &[]
        }
    }
}

async fn bootstrap(
    path: PathBuf,
    registration: Arc<Registration>,
    approver: bool,
) -> (Backend, RegisterDeviceResponse) {
    tokio::task::spawn_blocking(move || {
        let h = Harness::new();
        h.clock
            .0
            .store(crate::remote::SystemClock.now(), Ordering::SeqCst);
        let keys = Keys { approver };
        let master = crate::remote::metadata_master::IdentityMaster { keys: &keys };
        let (backend, registered) = crate::remote::bootstrap::open_registered(
            Options {
                path: &path,
                initialize: Some((
                    "",
                    if approver { "CI Mac" } else { "CI server" },
                    "test-recovery-password-42",
                    if approver { Os::Macos } else { Os::Linux },
                )),
                config: ApprovalConfig::default(),
            },
            Environment {
                master: &master,
                factory: &keys,
                runner: h.runner.clone(),
                presence: h.presence.clone(),
                clock: Arc::new(crate::remote::SystemClock),
            },
            &*registration,
        )
        .unwrap();
        let registered = registered.unwrap();
        (backend, registered)
    })
    .await
    .unwrap()
}

async fn rpc(helper: &Arc<RemoteHelper>, op: Op, params: Value) -> Value {
    serde_json::to_value(
        helper
            .handle(
                CallerContext::authenticated(Caller::CliOwner, 501, 4242, 210),
                Request {
                    op,
                    params,
                    extra: Extra::new(),
                },
            )
            .await,
    )
    .unwrap()
}

fn legacy_backend(path: &std::path::Path, initialize: bool) -> Backend {
    let h = Harness::new();
    let keys = Keys { approver: true };
    let master = crate::remote::metadata_master::IdentityMaster { keys: &keys };
    crate::remote::bootstrap::open(
        Options {
            path,
            initialize: initialize.then_some((
                "legacy-account",
                "CI approver",
                "test-recovery-password-42",
                Os::Macos,
            )),
            config: ApprovalConfig::default(),
        },
        Environment {
            master: &master,
            factory: &keys,
            runner: h.runner,
            presence: h.presence,
            clock: Arc::new(crate::remote::SystemClock),
        },
    )
    .unwrap()
}

#[tokio::test]
#[cfg_attr(
    windows,
    ignore = "Requires privileged Windows vault ownership; run as LocalSystem with --ignored"
)]
async fn encrypted_directory_rename_preserves_keys_and_survives_restart() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("remote");
    let backend = legacy_backend(&path, true);
    let local = backend.helper.local.clone();
    let result = rpc(
        &backend.helper,
        Op::DevicesRename,
        json!({"device_id":local.device_id,"label":"Updated label"}),
    )
    .await;
    assert_eq!(result["ok"], true, "{result}");
    drop(backend);
    let reopened = legacy_backend(&path, false);
    assert_eq!(reopened.helper.local.label, "Updated label");
    assert_eq!(reopened.helper.local.dk_pub, local.dk_pub);
    assert_eq!(reopened.helper.local.ak_s, local.ak_s);
}

#[tokio::test]
#[cfg_attr(
    windows,
    ignore = "Requires privileged Windows vault ownership; run as LocalSystem with --ignored"
)]
async fn encrypted_executor_label_updates_both_t2_confirmation_rounds_and_verification() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("remote");
    let backend = legacy_backend(&path, true);
    let result = rpc(
        &backend.helper,
        Op::DirectiveIssue,
        json!({"kind":"directive","aud":backend.helper.local.device_id,
        "op":"set_device_label","args":{"label":"New executor"}}),
    )
    .await;
    assert_eq!(result["ok"], true, "{result}");
    let mut request = json!({"source":"settings","kind":"grant","aud":backend.helper.local.device_id,
        "scope":{"level":"device","max_tier":"T2"},"nbf":0,"exp":null,"origin":"settings"});
    for _ in 0..2 {
        let prepared = rpc(&backend.helper, Op::GrantIssue, request.clone()).await;
        assert_eq!(prepared["result"]["label"], "New executor", "{prepared}");
        request["confirm"] = prepared["result"]["label"].clone();
        request["confirmation_token"] = prepared["result"]["confirmation_token"].clone();
    }
    let issued = rpc(&backend.helper, Op::GrantIssue, request).await;
    assert_eq!(issued["ok"], true, "{issued}");
    let grant: Grant = serde_json::from_value(issued["result"]["grant"].clone()).unwrap();
    kv_core::remote::validation::verify_grant(
        &grant,
        &backend.helper.local.device_id,
        "New executor",
        &backend.helper.local,
        ApprovalLevel::Strong,
        backend.helper.services.clock.now(),
    )
    .unwrap();
    drop(backend);
    let reopened = legacy_backend(&path, false);
    kv_core::remote::validation::verify_grant(
        &grant,
        &reopened.helper.local.device_id,
        "New executor",
        &reopened.helper.local,
        ApprovalLevel::Strong,
        reopened.helper.services.clock.now(),
    )
    .unwrap();
}

#[test]
#[cfg_attr(
    windows,
    ignore = "Requires privileged Windows vault ownership; run as LocalSystem with --ignored"
)]
fn encrypted_directory_journal_recovers_both_sides_of_sqlite_commit() {
    for committed in [false, true] {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("remote");
        let backend = legacy_backend(&path, true);
        let original = backend.helper.local.clone();
        {
            let state = backend.helper.lock().unwrap();
            let tx = state.store.db.unchecked_transaction().unwrap();
            backend
                .helper
                .rename_device_rows(&state, &original.device_id, "Recovered label")
                .unwrap();
            let update = backend.helper.stage_directory(&state).unwrap();
            if committed {
                tx.commit().unwrap();
            } else {
                drop(tx);
            }
            // Simulate process death: no guard destructor or mirror publication runs.
            std::mem::forget(update);
        }
        drop(backend);
        let reopened = legacy_backend(&path, false);
        assert_eq!(
            reopened.helper.local.label,
            if committed {
                "Recovered label"
            } else {
                original.label.as_str()
            }
        );
        assert_eq!(
            reopened
                .metadata
                .authenticated_metadata("remote_directory_update")
                .unwrap(),
            Some(Value::Null)
        );
    }
}

#[tokio::test]
#[cfg_attr(
    windows,
    ignore = "Requires privileged Windows vault ownership; run as LocalSystem with --ignored"
)]
async fn audit_failure_does_not_publish_a_directory_change() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("remote");
    let backend = legacy_backend(&path, true);
    let local = backend.helper.local.clone();
    backend.helper.lock().unwrap().store.db.execute_batch("CREATE TRIGGER fail_review_audit BEFORE INSERT ON remote_audit BEGIN SELECT RAISE(ABORT,'audit fault'); END;").unwrap();
    let failed = rpc(
        &backend.helper,
        Op::DevicesRename,
        json!({"device_id":local.device_id,"label":"Rejected label"}),
    )
    .await;
    assert_eq!(failed["ok"], false);
    backend
        .helper
        .lock()
        .unwrap()
        .store
        .db
        .execute_batch("DROP TRIGGER fail_review_audit")
        .unwrap();
    drop(backend);
    assert_eq!(legacy_backend(&path, false).helper.local, local);
}

#[cfg_attr(
    windows,
    ignore = "Requires privileged Windows vault ownership; run this module as LocalSystem with --ignored"
)]
#[test]
fn failed_registration_can_reopen_the_original_encrypted_providers() {
    struct Offline(Mutex<Option<DeviceRecord>>);
    impl crate::remote::bootstrap::Registrar for Offline {
        fn register(&self, local: &DeviceRecord) -> Result<RegisterDeviceResponse> {
            *self.0.lock().unwrap() = Some(local.clone());
            Err(Error("relay_unreachable"))
        }
    }
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("remote");
    let h = Harness::new();
    let keys = Keys { approver: true };
    let master = crate::remote::metadata_master::IdentityMaster { keys: &keys };
    let offline = Offline(Mutex::new(None));
    let error = crate::remote::bootstrap::open_registered(
        Options {
            path: &path,
            initialize: Some(("", "CI Mac", "test-recovery-password-42", Os::Macos)),
            config: ApprovalConfig::default(),
        },
        Environment {
            master: &master,
            factory: &keys,
            runner: h.runner,
            presence: h.presence,
            clock: Arc::new(crate::remote::SystemClock),
        },
        &offline,
    )
    .err()
    .unwrap();
    assert_eq!(error.code(), "relay_unreachable");
    let reopened = legacy_backend(&path, false);
    assert_eq!(
        Some(reopened.helper.local.clone()),
        *offline.0.lock().unwrap()
    );
    assert!(reopened.helper.account.starts_with("unregistered:"));
    crate::remote::bootstrap::freeze_unpaired(&reopened.helper).unwrap();
}

#[cfg_attr(
    windows,
    ignore = "Requires privileged Windows vault ownership; run this module as LocalSystem with --ignored"
)]
#[test]
fn singleton_account_rebinding_preserves_keys_and_recovers_a_journal() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("remote");
    let backend = legacy_backend(&path, true);
    let local = backend.helper.local.clone();
    let keys = backend
        .metadata
        .authenticated_metadata("remote_identity")
        .unwrap()
        .unwrap();
    crate::remote::bootstrap::freeze_unpaired(&backend.helper).unwrap();
    assert_eq!(
        backend.helper.mode().unwrap_err().code(),
        "remote_identity_changed"
    );
    // Interrupt after the authenticated journal and encrypted records, before SQLite changes.
    crate::remote::bootstrap::rebind_account(&backend.metadata, "relay-account", &local).unwrap();
    drop(backend);
    let reopened = legacy_backend(&path, false);
    assert_eq!(reopened.helper.account, "relay-account");
    assert_eq!(reopened.helper.local, local);
    let restored = reopened
        .metadata
        .authenticated_metadata("remote_identity")
        .unwrap()
        .unwrap();
    for name in ["identity", "quick", "strong"] {
        assert_eq!(restored[name], keys[name]);
    }
    assert_eq!(
        reopened
            .metadata
            .authenticated_metadata("remote_account_rebinding")
            .unwrap(),
        Some(Value::Null)
    );
    assert_eq!(
        reopened
            .helper
            .lock()
            .unwrap()
            .store
            .device(&local.device_id, "relay-account")
            .unwrap(),
        local
    );
    let mut pending = Harness::new().input(Tier::T1, "pending");
    pending.canonical.requester = local.device_id;
    reopened.helper.submit(pending).unwrap();
    assert_eq!(
        crate::remote::bootstrap::freeze_unpaired(&reopened.helper)
            .unwrap_err()
            .code(),
        "pairing_requires_unpaired_device"
    );
}

#[cfg_attr(
    windows,
    ignore = "Requires privileged Windows vault ownership; run this module as LocalSystem with --ignored"
)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_existing_unused_identity_joins_the_relay_without_replacing_keys() {
    let directory = tempfile::tempdir().unwrap();
    let (url, handle) = kv_server::spawn_test_relay();
    let relay = RelayApi::new(url.as_str()).unwrap();
    let registration = Arc::new(Registration {
        relay: relay.clone(),
        join_token: None,
        joined: Mutex::new(None),
        runtime: tokio::runtime::Handle::current(),
    });
    let (executor, _) = bootstrap(directory.path().join("executor"), registration, false).await;
    let started = executor
        .helper
        .pair_start_with_relay(relay.clone())
        .await
        .unwrap();
    let path = directory.path().join("existing");
    let creating = path.clone();
    let existing = tokio::task::spawn_blocking(move || legacy_backend(&creating, true))
        .await
        .unwrap();
    let local = existing.helper.local.clone();
    let original_key = existing.helper.services.identity.public_jwk().unwrap();
    let (_, token) = parse_uri(started.extra["uri"].as_str().unwrap()).unwrap();
    crate::remote::bootstrap::freeze_unpaired(&existing.helper).unwrap();
    let joined: PairCompleteResponse = relay
        .post(
            "v1/pair/complete",
            &PairCompleteRequest {
                token: encode_b64(&token),
                joiner: local.clone(),
                extra: Extra::new(),
            },
            None,
        )
        .await
        .unwrap();
    let account = joined.account_id.as_value().unwrap().clone();
    let original = existing.helper.clone();
    let metadata = existing.metadata.clone();
    let helper = tokio::task::spawn_blocking(move || {
        crate::remote::bootstrap::rebind_backend(&original, metadata, &path, &account)
    })
    .await
    .unwrap()
    .unwrap();
    assert_eq!(helper.local, local);
    assert_eq!(helper.services.identity.public_jwk().unwrap(), original_key);
    let sas = helper.join_network(relay, token, joined).await.unwrap().sas;
    until("existing identity SAS did not arrive", || {
        executor
            .helper
            .pairing_status(&executor.helper.lock().unwrap())
            .unwrap()["sas"]
            == sas
    })
    .await;
    for participant in [&helper, &executor.helper] {
        assert_eq!(
            rpc(
                participant,
                Op::PairConfirm,
                json!({"sas":sas,"confirmed":true})
            )
            .await["ok"],
            true
        );
    }
    until("existing identity pairing did not finish", || {
        [&helper, &executor.helper]
            .iter()
            .all(|h| h.lock().unwrap().pairing.is_none())
    })
    .await;
    assert_eq!(
        crate::remote::bootstrap::freeze_unpaired(&helper)
            .unwrap_err()
            .code(),
        "pairing_requires_unpaired_device"
    );
    handle.shutdown().await;
}

async fn until(description: &'static str, mut condition: impl FnMut() -> bool) {
    tokio::time::timeout(Duration::from_secs(20), async {
        while !condition() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect(description);
}

async fn add_executor(owner: &Backend, relay: &RelayApi, path: PathBuf, exclude: bool) -> Backend {
    let started = owner
        .helper
        .pair_start_network(relay.url.as_str())
        .await
        .unwrap();
    let token =
        zeroize::Zeroizing::new(decode_b64(started.extra["token"].as_str().unwrap()).unwrap());
    let registration = Arc::new(Registration {
        relay: relay.clone(),
        join_token: Some(token.clone()),
        joined: Mutex::new(None),
        runtime: tokio::runtime::Handle::current(),
    });
    let (executor, _) = bootstrap(path, registration.clone(), false).await;
    let response = registration.joined.lock().unwrap().take().unwrap();
    let joined = executor
        .helper
        .join_network(relay.clone(), token, response)
        .await
        .unwrap();
    let accepted = tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            let status = owner
                .helper
                .pairing_status(&owner.helper.lock().unwrap())
                .unwrap();
            assert!(
                status["error"].is_null(),
                "Pairing failed before SAS: {}",
                status["error"]
            );
            if status["sas"] == joined.sas {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await;
    assert!(
        accepted.is_ok(),
        "Approver SAS delivery timed out; state: {}",
        owner
            .helper
            .pairing_status(&owner.helper.lock().unwrap())
            .unwrap()
    );
    for helper in [&owner.helper, &executor.helper] {
        let result = rpc(
            helper,
            Op::PairConfirm,
            json!({"sas":joined.sas,"confirmed":true,"exclude_global":exclude}),
        )
        .await;
        assert_eq!(result["ok"], true, "{result}");
    }
    until("executor pairing did not finish", || {
        [&owner.helper, &executor.helper]
            .iter()
            .all(|helper| helper.lock().unwrap().pairing.is_none())
    })
    .await;
    executor
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[cfg_attr(
    windows,
    ignore = "Requires privileged Windows vault ownership; run as LocalSystem with --ignored"
)]
async fn remote_rename_updates_the_authenticated_label_for_t2_and_next_pairing() {
    let directory = tempfile::tempdir().unwrap();
    let (url, server) = kv_server::spawn_test_relay();
    let relay = RelayApi::new(url.as_str()).unwrap();
    let registration = Arc::new(Registration {
        relay: relay.clone(),
        join_token: None,
        joined: Mutex::new(None),
        runtime: tokio::runtime::Handle::current(),
    });
    let (owner, _) = bootstrap(directory.path().join("owner"), registration, true).await;
    owner
        .helper
        .lock()
        .unwrap()
        .store
        .set_setting(
            "relay_url",
            &url.as_str(),
            "local",
            crate::remote::SystemClock.now(),
        )
        .unwrap();
    let path = directory.path().join("executor");
    let executor = add_executor(&owner, &relay, path.clone(), false).await;
    let owner_token = relay
        .authenticate(&owner.helper.local, owner.helper.services.identity.clone())
        .await
        .unwrap();
    let executor_token = relay
        .authenticate(
            &executor.helper.local,
            executor.helper.services.identity.clone(),
        )
        .await
        .unwrap();
    let renamed = exchange_through_relay(
        &owner.helper,
        &executor.helper,
        &relay,
        (&owner_token, &executor_token),
        Op::DevicesRename,
        json!({"device_id":executor.helper.local.device_id,"label":"Renamed executor"}),
    )
    .await;
    assert_eq!(renamed["ok"], true, "{renamed}");
    assert_eq!(
        owner
            .helper
            .lock()
            .unwrap()
            .store
            .device(&executor.helper.local.device_id, &owner.helper.account)
            .unwrap()
            .label,
        "Renamed executor"
    );
    let mut intent = json!({"source":"settings","kind":"grant","aud":executor.helper.local.device_id,
        "scope":{"level":"device","max_tier":"T2"},"nbf":0,"exp":null,"origin":"settings"});
    for _ in 0..2 {
        let prepared = rpc(&owner.helper, Op::GrantIssue, intent.clone()).await;
        assert_eq!(
            prepared["result"]["label"], "Renamed executor",
            "{prepared}"
        );
        intent["confirm"] = prepared["result"]["label"].clone();
        intent["confirmation_token"] = prepared["result"]["confirmation_token"].clone();
    }
    let issued = rpc(&owner.helper, Op::GrantIssue, intent).await;
    assert_eq!(issued["ok"], true, "{issued}");
    deliver(&owner.helper, &relay, &owner_token).await.unwrap();
    deliver(&executor.helper, &relay, &executor_token)
        .await
        .unwrap();
    let grant: Grant = serde_json::from_value(issued["result"]["grant"].clone()).unwrap();
    let installed: String = executor
        .helper
        .lock()
        .unwrap()
        .store
        .db
        .query_row(
            "SELECT object_json FROM grants WHERE jti=?1",
            [&grant.jti],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(serde_json::from_str::<Grant>(&installed).unwrap(), grant);
    drop(executor);
    let reopened = legacy_backend(&path, false);
    assert_eq!(reopened.helper.local.label, "Renamed executor");
    kv_core::remote::validation::verify_grant(
        &grant,
        &reopened.helper.local.device_id,
        &reopened.helper.local.label,
        &owner.helper.local,
        ApprovalLevel::Strong,
        crate::remote::SystemClock.now(),
    )
    .unwrap();
    reopened
        .helper
        .pair_start_network(url.as_str())
        .await
        .unwrap();
    server.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[cfg_attr(
    windows,
    ignore = "Requires privileged Windows vault ownership; run as LocalSystem with --ignored"
)]
async fn strong_device_revocation_deletes_relay_registration_and_invalidates_both_executors() {
    let directory = tempfile::tempdir().unwrap();
    let (url, server) = kv_server::spawn_test_relay();
    let relay = RelayApi::new(url.as_str()).unwrap();
    let registration = Arc::new(Registration {
        relay: relay.clone(),
        join_token: None,
        joined: Mutex::new(None),
        runtime: tokio::runtime::Handle::current(),
    });
    let (owner, _) = bootstrap(directory.path().join("owner"), registration, true).await;
    owner
        .helper
        .lock()
        .unwrap()
        .store
        .set_setting(
            "relay_url",
            &url.as_str(),
            "local",
            crate::remote::SystemClock.now(),
        )
        .unwrap();
    let grant=rpc(&owner.helper,Op::GrantIssue,json!({"source":"settings","kind":"grant","aud":"*","scope":{"level":"global","max_tier":"T1"},
        "nbf":0,"exp":null,"origin":"settings"})).await;
    assert_eq!(grant["ok"], true, "{grant}");
    let first = add_executor(&owner, &relay, directory.path().join("first"), false).await;
    let second = add_executor(&owner, &relay, directory.path().join("second"), false).await;
    let owner_token = relay
        .authenticate(&owner.helper.local, owner.helper.services.identity.clone())
        .await
        .unwrap();
    let outgoing = owner.helper.outbound_poll(0).await.unwrap();
    for envelope in &outgoing {
        let _: AcceptedResponse = relay
            .post(
                "v1/messages",
                &SendMessagesRequest {
                    envelopes: vec![envelope.clone()],
                    extra: Extra::new(),
                },
                Some(&owner_token),
            )
            .await
            .unwrap();
    }
    owner
        .helper
        .outbound_ack(kv_ipc::remote::RelayOutboundAckParams {
            envelopes: outgoing.clone(),
            stage: kv_ipc::remote::OutboundStage::Accepted,
            extra: Extra::new(),
        })
        .unwrap();
    let first_token = relay
        .authenticate(&first.helper.local, first.helper.services.identity.clone())
        .await
        .unwrap();
    let second_token = relay
        .authenticate(
            &second.helper.local,
            second.helper.services.identity.clone(),
        )
        .await
        .unwrap();
    for (executor, token) in [(&first, &first_token), (&second, &second_token)] {
        deliver(&executor.helper, &relay, token).await.unwrap();
        assert_eq!(
            executor
                .helper
                .grant_list_locked(&executor.helper.lock().unwrap())
                .unwrap()
                .len(),
            1
        );
    }
    // Four preceding pairing/grant messages plus 595 identical retries fill the budget.
    for count in [500, 95] {
        let _: AcceptedResponse = relay
            .post(
                "v1/messages",
                &SendMessagesRequest {
                    envelopes: vec![outgoing[0].clone(); count],
                    extra: Extra::new(),
                },
                Some(&owner_token),
            )
            .await
            .unwrap();
    }
    let failed = rpc(
        &owner.helper,
        Op::DevicesRevoke,
        json!({"device_id":owner.helper.local.device_id}),
    )
    .await;
    assert_eq!(failed["error"]["code"], "rate_limited", "{failed}");
    assert_eq!(
        owner
            .helper
            .lock()
            .unwrap()
            .store
            .device(&owner.helper.local.device_id, &owner.helper.account)
            .unwrap_err()
            .code(),
        "revoked_device"
    );
    assert_eq!(owner.helper.outbound_poll(0).await.unwrap().len(), 2);
    assert!(!server.inspect(|db| db
        .query_row(
            "SELECT revoked_at IS NOT NULL FROM devices WHERE id=?1",
            [&owner.helper.local.device_id],
            |r| r.get::<_, bool>(0)
        )
        .unwrap()));
    server.advance_time(std::time::Duration::from_secs(61));
    let result = rpc(
        &owner.helper,
        Op::DevicesRevoke,
        json!({"device_id":owner.helper.local.device_id}),
    )
    .await;
    assert_eq!(result["ok"], true, "{result}");
    assert!(server.inspect(|db| db
        .query_row(
            "SELECT revoked_at IS NOT NULL FROM devices WHERE id=?1",
            [&owner.helper.local.device_id],
            |r| r.get::<_, bool>(0)
        )
        .unwrap()));
    for (executor, token) in [(&first, &first_token), (&second, &second_token)] {
        deliver(&executor.helper, &relay, token).await.unwrap();
        let state = executor.helper.lock().unwrap();
        assert_eq!(
            state
                .store
                .device(&owner.helper.local.device_id, &executor.helper.account)
                .unwrap_err()
                .code(),
            "revoked_device"
        );
        assert!(executor
            .helper
            .grant_list_locked(&state)
            .unwrap()
            .iter()
            .all(|g| g["revoked_at"].is_number()));
    }
    // Once complete, repeated owner requests do not sign or contact a deleted identity.
    assert_eq!(
        rpc(
            &owner.helper,
            Op::DevicesRevoke,
            json!({"device_id":owner.helper.local.device_id})
        )
        .await["ok"],
        true
    );
    server.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[cfg_attr(
    windows,
    ignore = "Requires privileged Windows vault ownership; run as LocalSystem with --ignored"
)]
async fn executor_revocation_delivers_strong_proof_before_closing_its_online_relay_session() {
    let directory = tempfile::tempdir().unwrap();
    let (url, server) = kv_server::spawn_test_relay();
    let relay = RelayApi::new(url.as_str()).unwrap();
    let registration = Arc::new(Registration {
        relay: relay.clone(),
        join_token: None,
        joined: Mutex::new(None),
        runtime: tokio::runtime::Handle::current(),
    });
    let (owner, _) = bootstrap(directory.path().join("owner"), registration, true).await;
    owner
        .helper
        .lock()
        .unwrap()
        .store
        .set_setting(
            "relay_url",
            &url.as_str(),
            "local",
            crate::remote::SystemClock.now(),
        )
        .unwrap();
    let executor = add_executor(&owner, &relay, directory.path().join("executor"), false).await;
    assert!(executor.helper.local.ak_s.is_none());
    let owner_session = relay
        .authenticate(&owner.helper.local, owner.helper.services.identity.clone())
        .await
        .unwrap();
    let executor_session = relay
        .authenticate(
            &executor.helper.local,
            executor.helper.services.identity.clone(),
        )
        .await
        .unwrap();
    let issued = rpc(&owner.helper, Op::GrantIssue, json!({"source":"settings","kind":"grant",
        "aud":executor.helper.local.device_id,"scope":{"level":"device","max_tier":"T1"},
        "nbf":owner.helper.services.clock.now(),"exp":owner.helper.services.clock.now()+3600,"origin":"settings"})).await;
    assert_eq!(issued["ok"], true);
    deliver(&owner.helper, &relay, &owner_session)
        .await
        .unwrap();
    // This keeps the target's authenticated WebSocket open, matching an online ndu.
    deliver(&executor.helper, &relay, &executor_session)
        .await
        .unwrap();
    assert_eq!(
        executor
            .helper
            .grant_list_locked(&executor.helper.lock().unwrap())
            .unwrap()
            .len(),
        1
    );

    let revoked = rpc(
        &owner.helper,
        Op::DevicesRevoke,
        json!({"device_id":executor.helper.local.device_id}),
    )
    .await;
    assert_eq!(revoked["ok"], true);
    assert!(server.inspect(|db| db
        .query_row(
            "SELECT revoked_at IS NOT NULL FROM devices WHERE id=?1",
            [&executor.helper.local.device_id],
            |row| row.get::<_, bool>(0)
        )
        .unwrap()));
    let received = relay.pending(&executor_session).await;
    assert!(
        received.is_ok(),
        "the online executor received no encrypted revocation before relay disconnect"
    );
    let received = received.unwrap();
    assert!(received
        .iter()
        .any(|envelope| envelope.r#type == EnvelopeType::DeviceRevoke
            && envelope.to == executor.helper.local.device_id));
    for envelope in received {
        deliver_inbound(&executor.helper, envelope).await.unwrap();
    }
    {
        let state = executor.helper.lock().unwrap();
        assert_eq!(
            state
                .store
                .device(&executor.helper.local.device_id, &executor.helper.account)
                .unwrap_err()
                .code(),
            "revoked_device"
        );
        assert!(executor
            .helper
            .grant_list_locked(&state)
            .unwrap()
            .iter()
            .all(|grant| grant["revoked_at"].is_number()));
    }
    server.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[cfg_attr(
    windows,
    ignore = "Requires privileged Windows vault ownership; run as LocalSystem with --ignored"
)]
async fn pairing_exclusion_is_signed_and_blocks_existing_and_future_global_grants() {
    let directory = tempfile::tempdir().unwrap();
    let (url, server) = kv_server::spawn_test_relay();
    let relay = RelayApi::new(url.as_str()).unwrap();
    let registration = Arc::new(Registration {
        relay: relay.clone(),
        join_token: None,
        joined: Mutex::new(None),
        runtime: tokio::runtime::Handle::current(),
    });
    let (owner, _) = bootstrap(directory.path().join("owner"), registration, true).await;
    let grant=rpc(&owner.helper,Op::GrantIssue,json!({"source":"settings","kind":"grant","aud":"*","scope":{"level":"global","max_tier":"T1"},
        "nbf":0,"exp":null,"origin":"settings"})).await;
    assert_eq!(grant["ok"], true);
    let executor = add_executor(&owner, &relay, directory.path().join("excluded"), true).await;
    assert_eq!(
        executor
            .helper
            .lock()
            .unwrap()
            .store
            .setting::<bool>(&format!("global_excluded:{}", owner.helper.local.device_id))
            .unwrap(),
        Some(true)
    );
    assert!(!owner
        .helper
        .outbound_poll(0)
        .await
        .unwrap()
        .iter()
        .any(|envelope| envelope.to == executor.helper.local.device_id
            && envelope.r#type == EnvelopeType::Grant));
    let next=rpc(&owner.helper,Op::GrantIssue,json!({"source":"settings","kind":"grant","aud":"*","scope":{"level":"global","max_tier":"T1"},
        "nbf":0,"exp":null,"origin":"settings"})).await;
    assert_eq!(next["ok"], true);
    assert!(!owner
        .helper
        .outbound_poll(0)
        .await
        .unwrap()
        .iter()
        .any(|envelope| envelope.to == executor.helper.local.device_id));
    server.shutdown().await;
}

async fn deliver_inbound(helper: &Arc<RemoteHelper>, envelope: Envelope) -> Result<()> {
    let response = serde_json::to_value(
        helper
            .handle(
                CallerContext::authenticated(Caller::RelayClient, 501, 4242, 210),
                Request {
                    op: Op::RelayInbound,
                    params: json!({"envelope":envelope}),
                    extra: Extra::new(),
                },
            )
            .await,
    )?;
    if response["ok"] == true && response["result"]["ack"] == true {
        Ok(())
    } else {
        Err(Error("test_relay_inbound_unacked"))
    }
}

#[tokio::test]
async fn r3a_late_pair_confirm_is_rejected_and_delivery_can_be_acknowledged() {
    let h = Harness::new();
    let before = directory(&h.helper.lock().unwrap().store).unwrap();
    let envelope = h.envelope(EnvelopeType::PairConfirm, "completed-pair", &json!({}));
    deliver_inbound(&h.helper, envelope).await.unwrap();
    assert_eq!(directory(&h.helper.lock().unwrap().store).unwrap(), before);
    assert!(h.helper.lock().unwrap().pairing.is_none());
    assert!(h
        .audit
        .entries
        .lock()
        .unwrap()
        .iter()
        .any(
            |entry| entry["op"] == "remote_message_rejected" && entry["reason"] == "unknown_token"
        ));
    h.audit.fail.store(true, Ordering::SeqCst);
    let unavailable = h.envelope(
        EnvelopeType::PairConfirm,
        "audit-unavailable-pair",
        &json!({}),
    );
    assert!(deliver_inbound(&h.helper, unavailable).await.is_err());
}

async fn deliver(helper: &Arc<RemoteHelper>, bridge: &RelayApi, _device: &str) -> Result<()> {
    let relay = bridge.transport.clone();
    let authenticated = relay
        .authenticate(&helper.local, |challenge| async move {
            let bytes = kv_core::remote::keys::decode_b64(&challenge)?;
            Ok(encode_b64(
                &helper
                    .services
                    .identity
                    .sign(SignatureAlgorithm::ES256, &bytes)?,
            ))
        })
        .await
        .map_err(|error| {
            eprintln!("test relay delivery failed: {}", error.0);
            Error(error.0)
        })?;
    let session = authenticated.as_str();
    let outgoing = helper.outbound_poll(0).await?;
    // Model the relay spool handoff before acknowledging network acceptance.
    if !outgoing.is_empty() {
        helper.outbound_ack(kv_ipc::remote::RelayOutboundAckParams {
            envelopes: outgoing.clone(),
            stage: kv_ipc::remote::OutboundStage::Spooled,
            extra: Extra::new(),
        })?;
    }
    for envelope in &outgoing {
        match envelope.r#type {
            EnvelopeType::ApprovalRequest => {
                let _: AcceptedResponse = relay
                    .post(
                        "v1/approvals",
                        &SubmitApprovalsRequest {
                            id: envelope.id.clone(),
                            exp: envelope.exp,
                            envelopes: vec![envelope.clone()],
                            extra: Extra::new(),
                        },
                        Some(session),
                    )
                    .await
                    .map_err(|error| {
                        eprintln!("test relay delivery failed: {}", error.0);
                        Error(error.0)
                    })?;
            }
            EnvelopeType::ApprovalDecision => {
                let _: OkResponse = relay
                    .post(
                        &format!("v1/approvals/{}/reply", envelope.id),
                        &ReplyApprovalRequest {
                            envelope: envelope.clone(),
                            extra: Extra::new(),
                        },
                        Some(session),
                    )
                    .await
                    .map_err(|error| {
                        eprintln!("test relay delivery failed: {}", error.0);
                        Error(error.0)
                    })?;
            }
            EnvelopeType::ApprovalCancel => {
                let _: OkResponse = relay
                    .post(
                        &format!("v1/approvals/{}/cancel", envelope.id),
                        &ReplyApprovalRequest {
                            envelope: envelope.clone(),
                            extra: Extra::new(),
                        },
                        Some(session),
                    )
                    .await
                    .map_err(|error| {
                        eprintln!("test relay delivery failed: {}", error.0);
                        Error(error.0)
                    })?;
            }
            _ => {
                let _: AcceptedResponse = relay
                    .post(
                        "v1/messages",
                        &SendMessagesRequest {
                            envelopes: vec![envelope.clone()],
                            extra: Extra::new(),
                        },
                        Some(session),
                    )
                    .await
                    .map_err(|error| {
                        eprintln!("test relay delivery failed: {}", error.0);
                        Error(error.0)
                    })?;
            }
        }
    }
    if !outgoing.is_empty() {
        helper.outbound_ack(kv_ipc::remote::RelayOutboundAckParams {
            envelopes: outgoing,
            stage: kv_ipc::remote::OutboundStage::Accepted,
            extra: Extra::new(),
        })?;
    }
    for envelope in relay
        .pending(session)
        .await
        .expect("authenticated WebSocket receive failed")
    {
        let id = envelope.id.clone();
        let kind = envelope.r#type.as_str().to_owned();
        deliver_inbound(helper, envelope).await?;
        let _: OkResponse = relay
            .post(
                "v1/messages/ack",
                &AckMessagesRequest {
                    ids: vec![id],
                    kind: Optional::Value(kind),
                    extra: Extra::new(),
                },
                Some(session),
            )
            .await
            .map_err(|error| {
                eprintln!("test relay acknowledgment failed: {}", error.0);
                Error(error.0)
            })?;
    }
    Ok(())
}

async fn exchange_through_relay(
    approver: &Arc<RemoteHelper>,
    executor: &Arc<RemoteHelper>,
    relay: &RelayApi,
    sessions: (&str, &str),
    op: Op,
    params: Value,
) -> Value {
    let helper = approver.clone();
    let running = tokio::spawn(async move { rpc(&helper, op, params).await });
    let deadline = tokio::time::Instant::now() + Duration::from_secs(8);
    loop {
        deliver(approver, relay, sessions.0).await.unwrap();
        deliver(executor, relay, sessions.1).await.unwrap();
        if running.is_finished() {
            return running.await.unwrap();
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "owner command did not receive its authenticated reply"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

#[cfg_attr(
    windows,
    ignore = "Requires privileged Windows vault ownership; run this module as LocalSystem with --ignored"
)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn anonymous_pairing_approval_grant_budget_and_revoke_use_real_modules() {
    let directory = tempfile::tempdir().unwrap();
    let (url, relay_handle) =
        kv_server::spawn_test_relay_with_data(directory.path().join("relay.sqlite"));
    let relay = RelayApi::new(url.as_str()).unwrap();
    let registration = Arc::new(Registration {
        relay: relay.clone(),
        join_token: None,
        joined: Mutex::new(None),
        runtime: tokio::runtime::Handle::current(),
    });
    let (executor, registered) =
        bootstrap(directory.path().join("executor"), registration, false).await;
    let recovery = registered.recovery_code.as_value().unwrap().clone();
    assert!(!registered.account_id.is_empty());
    assert_eq!(registered.device_id, executor.helper.local.device_id);
    executor
        .helper
        .lock()
        .unwrap()
        .store
        .set_setting(
            "relay_url",
            &url.as_str(),
            "local",
            crate::remote::SystemClock.now(),
        )
        .unwrap();
    let started = rpc(
        &executor.helper,
        Op::PairStart,
        json!({"relay_url":url.as_str()}),
    )
    .await;
    assert_eq!(started["ok"], true, "helper operation rejected");
    let (join_relay, token) = parse_uri(started["result"]["uri"].as_str().unwrap()).unwrap();
    let joining = Arc::new(Registration {
        relay: join_relay.clone(),
        join_token: Some(token.clone()),
        joined: Mutex::new(None),
        runtime: tokio::runtime::Handle::current(),
    });
    let (approver, joined) =
        bootstrap(directory.path().join("approver"), joining.clone(), true).await;
    assert_eq!(joined.account_id, registered.account_id);
    assert!(joined.recovery_code.is_missing());
    let response = joining.joined.lock().unwrap().take().unwrap();
    let joined = approver
        .helper
        .join_network(join_relay, token, response)
        .await
        .unwrap();
    until("executor did not receive the pairing SAS", || {
        let state = executor.helper.lock().unwrap();
        executor.helper.pairing_status(&state).unwrap()["sas"].as_str() == Some(joined.sas.as_str())
    })
    .await;
    for helper in [&approver.helper, &executor.helper] {
        let result = rpc(
            helper,
            Op::PairConfirm,
            json!({"sas":joined.sas,"confirmed":true}),
        )
        .await;
        assert_eq!(result["ok"], true, "helper operation rejected");
    }
    until("both helpers did not complete pairing", || {
        [&approver.helper, &executor.helper]
            .iter()
            .all(|helper| helper.lock().unwrap().pairing.is_none())
    })
    .await;
    assert_eq!(
        executor
            .helper
            .lock()
            .unwrap()
            .store
            .device(&approver.helper.local.device_id, &registered.account_id)
            .unwrap(),
        approver.helper.local
    );
    assert_eq!(
        approver
            .helper
            .lock()
            .unwrap()
            .store
            .device(&executor.helper.local.device_id, &registered.account_id)
            .unwrap(),
        executor.helper.local
    );
    relay_handle.inspect(|db| {
        assert_eq!(
            db.query_row("SELECT state FROM pairings", [], |r| r.get::<_, String>(0))
                .unwrap(),
            "finished"
        )
    });
    let replay: Result<PairCompleteResponse> = relay
        .post(
            "v1/pair/complete",
            &PairCompleteRequest {
                token: started["result"]["token"].as_str().unwrap().into(),
                joiner: approver.helper.local.clone(),
                extra: Extra::new(),
            },
            None,
        )
        .await;
    assert_eq!(replay.unwrap_err().code(), "replay");

    let executor_session = relay
        .authenticate(
            &executor.helper.local,
            executor.helper.services.identity.clone(),
        )
        .await
        .unwrap();
    let approver_session = relay
        .authenticate(
            &approver.helper.local,
            approver.helper.services.identity.clone(),
        )
        .await
        .unwrap();
    let fixture = Harness::new();
    let mut input = fixture.input(Tier::T1, "OWNER_FLOW_SECRET_BODY_8bd1453e");
    input.canonical.requester = executor.helper.local.device_id.clone();
    let approval = executor.helper.submit(input).unwrap();
    deliver(&executor.helper, &relay, &executor_session)
        .await
        .unwrap();
    deliver(&approver.helper, &relay, &approver_session)
        .await
        .unwrap();
    let pending = rpc(&approver.helper, Op::PendingList, json!({})).await;
    assert_eq!(
        pending["result"]["pending"][0]["approval_id"],
        approval.approval_id
    );
    let allowed = rpc(
        &approver.helper,
        Op::Decide,
        json!({"approval_id":approval.approval_id,"decision":"allow",
        "scope":{"mode":"per_use","level":"credential","until":0},"scope_option":"per_use"}),
    )
    .await;
    assert_eq!(allowed["ok"], true, "helper operation rejected");
    deliver(&approver.helper, &relay, &approver_session)
        .await
        .unwrap();
    deliver(&executor.helper, &relay, &executor_session)
        .await
        .unwrap();
    let result = executor
        .helper
        .wait(&approval.approval_id, 1000, 210, 501, 4242)
        .await
        .unwrap();
    assert_eq!(result.status, ToolStatus::Ok);
    assert_eq!(
        executor
            .helper
            .wait(&approval.approval_id, 0, 210, 501, 4242)
            .await
            .unwrap()
            .status,
        ToolStatus::AlreadyConsumed
    );
    let history = rpc(&approver.helper, Op::PendingList, json!({})).await;
    assert_eq!(
        history["result"]["recent"][0]["approval_id"],
        approval.approval_id
    );

    let issued = rpc(&approver.helper,Op::GrantIssue,json!({"source":"preauthorization","kind":"grant","aud":executor.helper.local.device_id,
        "scope":{"level":"credential","credential":"github/default","max_tier":"T1"},
        "budget":{"calls":3,"per":"1h"},"nbf":approver.helper.services.clock.now(),"exp":approver.helper.services.clock.now()+3600,"origin":"settings"})).await;
    assert_eq!(issued["ok"], true, "helper operation rejected");
    let jti = issued["result"]["grant"]["jti"]
        .as_str()
        .unwrap()
        .to_owned();
    deliver(&approver.helper, &relay, &approver_session)
        .await
        .unwrap();
    deliver(&executor.helper, &relay, &executor_session)
        .await
        .unwrap();
    let mut canonical = fixture.input(Tier::T1, "same-body").canonical;
    canonical.requester = executor.helper.local.device_id.clone();
    let usage = GrantUse {
        canonical,
        tier: Tier::T1,
        template_allowed_hosts: vec!["api.github.com".into()],
        policy_allowed_methods: vec!["POST".into()],
        body_bytes: 1,
        session_id: "session".into(),
    };
    assert_eq!(
        executor.helper.cover_and_debit(&usage).unwrap().jtis,
        vec![jti.clone()]
    );
    let queried = exchange_through_relay(&approver.helper,&executor.helper,&relay,(&approver_session,&executor_session),Op::DirectiveIssue,
        json!({"kind":"directive","aud":executor.helper.local.device_id,"op":"query_grants","args":{}})).await;
    assert_eq!(queried["ok"], true, "helper operation rejected");
    let ledger = rpc(&approver.helper, Op::GrantList, json!({})).await;
    assert_eq!(
        ledger["result"]["grants"][0]["usage"]["budget_left"]["calls_left"],
        2
    );
    assert_eq!(ledger["result"]["grants"][0]["usage"]["uses_n"], 1);
    let revoked = exchange_through_relay(
        &approver.helper,
        &executor.helper,
        &relay,
        (&approver_session, &executor_session),
        Op::GrantRevoke,
        json!({"jti":jti}),
    )
    .await;
    assert_eq!(revoked["ok"], true, "helper operation rejected");
    assert!(executor
        .helper
        .cover_and_debit(&usage)
        .unwrap()
        .jtis
        .is_empty());
    assert!(
        rpc(&approver.helper, Op::GrantList, json!({})).await["result"]["grants"][0]["revoked_at"]
            .is_number()
    );
    for helper in [&approver.helper, &executor.helper] {
        assert!(helper
            .audit_entries()
            .unwrap()
            .iter()
            .any(|entry| entry["op"] == "grant_revoked" && entry["jti"] == jti));
    }
    let logs = relay_handle.logs().join("\n");
    assert!(!logs.contains(&recovery));
    assert!(!logs.contains("OWNER_FLOW_SECRET_BODY_8bd1453e"));
    relay_handle.inspect(|db| db.execute_batch("PRAGMA wal_checkpoint(TRUNCATE)").unwrap());
    let database = std::fs::read(directory.path().join("relay.sqlite")).unwrap();
    assert!(!database
        .windows(b"OWNER_FLOW_SECRET_BODY_8bd1453e".len())
        .any(|bytes| bytes == b"OWNER_FLOW_SECRET_BODY_8bd1453e"));
    relay_handle.shutdown().await;
}
