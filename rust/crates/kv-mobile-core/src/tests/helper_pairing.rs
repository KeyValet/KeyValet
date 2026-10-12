//! The phone and the executor run their actual pairing implementations through W2's relay.
use super::*;
use kv_helper::remote::{self as helper, RequestRunner};
use std::{future::Future, pin::Pin, sync::Mutex, time::Duration};

#[test]
fn pairing_notice_counts_only_live_global_grants() {
    let phone = Fixture::new();
    let mut input = grant_input(&phone);
    input.device_id = "*".into();
    input.scope = "global".into();
    for index in 0..4 {
        phone.authorize();
        let id = phone.core.issue_grant(&input).unwrap();
        phone
            .core
            .store
            .transaction(|db| {
                let mut issued: crate::engine::IssuedGrant =
                    phone.core.store.get(db, "issued_grants", &id)?.unwrap();
                match index {
                    1 => issued.grant.exp = Some(now() - 1),
                    2 => issued.revoked = true,
                    3 => issued.grant.aud = phone.peer.device_id.clone(),
                    _ => {}
                }
                phone.core.store.put(db, "issued_grants", &id, &issued, 0)
            })
            .unwrap();
    }
    let candidate = Candidate {
        peer: phone.peer.clone(),
        account: "acct_test".into(),
        pairing_id: new_id(),
        sas: "123456".into(),
        exp: now() + 300,
        local_confirm: None,
        peer_confirmed: false,
        exclude_global: false,
        peer_exclude_global: false,
        accept: None,
        confirmation_envelope: None,
        finish_sent: false,
        token_hash: None,
    };
    assert_eq!(
        phone.core.save_candidate(&candidate).unwrap().global_grants,
        1
    );
}

#[test]
fn pairing_checks_the_full_signed_peer_key_set_and_does_not_trust_an_unconfirmed_peer() {
    let phone = Fixture::new();
    phone
        .core
        .store
        .transaction(|db| Store::delete(db, "peers", &phone.peer.device_id))
        .unwrap();
    let q = SoftwareDeviceKey::generate_p256();
    let s = SoftwareDeviceKey::generate_p256();
    let mut original = phone.peer.clone();
    original.ak_q = Some(ApprovalKey {
        alg: SignatureAlgorithm::ES256,
        r#pub: q.public_jwk().unwrap(),
        extra: Extra::new(),
    });
    original.ak_s = Some(ApprovalKey {
        alg: SignatureAlgorithm::ES256,
        r#pub: s.public_jwk().unwrap(),
        extra: Extra::new(),
    });
    original
        .caps
        .extend([Capability::ApproveQuick, Capability::ApproveStrong]);
    let mut proposed = original.clone();
    proposed.ak_q.as_mut().unwrap().r#pub =
        SoftwareDeviceKey::generate_p256().public_jwk().unwrap();
    let sas = remote::pairing::device_sas(&[3; 16], &proposed, phone.core.device()).unwrap();
    let mut candidate = Candidate {
        peer: proposed,
        account: "acct_test".into(),
        pairing_id: new_id(),
        sas: sas.clone(),
        exp: now() + 300,
        local_confirm: None,
        peer_confirmed: false,
        exclude_global: false,
        peer_exclude_global: false,
        accept: None,
        confirmation_envelope: None,
        finish_sent: false,
        token_hash: None,
    };
    phone.core.save_candidate(&candidate).unwrap();
    let mut confirm = PairConfirm {
        sas,
        sig: String::new(),
        extra: json!({"device":original,"exclude_global":true})
            .as_object()
            .unwrap()
            .clone(),
    };
    confirm.sig = remote::keys::sign_object(&confirm, SignatureAlgorithm::ES256, &s).unwrap();
    let message = phone.envelope(
        EnvelopeType::PairConfirm,
        &candidate.pairing_id,
        &confirm,
        now() + 300,
    );
    assert_eq!(
        phone
            .core
            .receive(&serde_json::to_vec(&message).unwrap())
            .unwrap_err()
            .0,
        "pair_key_mismatch"
    );
    assert!(!phone.core.candidate().unwrap().peer_confirmed);
    candidate.peer = original;
    phone.core.save_candidate(&candidate).unwrap();
    phone
        .core
        .receive(&serde_json::to_vec(&message).unwrap())
        .unwrap();
    assert!(phone.core.candidate().unwrap().peer_confirmed);
    assert!(phone.core.candidate().unwrap().peer_exclude_global);
    assert!(
        phone.core.peer(&phone.peer.device_id).is_err(),
        "a peer confirmation alone cannot commit trust"
    );
}

#[test]
fn signed_grant_pages_are_accumulated_and_queue_one_bound_continuation() {
    let f = Fixture::new();
    let id = f
        .core
        .directive(
            &f.peer.device_id,
            DirectiveOp::QueryGrants,
            Extra::new(),
            "",
        )
        .unwrap();
    let response=DirectiveResult {id:id.clone(),ok:true,error:None,state:json!({"grants":[{"jti":"first","iss":f.core.device().device_id,
        "aud":f.peer.device_id,"exp":null,"scope":{"level":"device","max_tier":"T1"},"origin":"settings","revoked_at":null}],"next_cursor":"first"}).as_object().unwrap().clone(),extra:Extra::new()};
    f.receive(EnvelopeType::DirectiveResult, &id, &response, now() + 60)
        .unwrap();
    let outbound = f.core.outbound().unwrap();
    let next = outbound
        .iter()
        .find_map(|(_, envelope)| {
            let raw = remote::envelope::open(
                envelope,
                &f.peer.device_id,
                f.executor.as_ref(),
                f.core.device(),
                now(),
            )
            .unwrap();
            let directive: Directive = from_json(&raw).unwrap();
            (directive.args.get("after") == Some(&json!("first"))).then_some(directive)
        })
        .unwrap();
    verify_object(&next, &next.sig, f.core.device().ak_q.as_ref().unwrap()).unwrap();
    let final_page=DirectiveResult {id:next.id.clone(),ok:true,error:None,state:json!({"grants":[{"jti":"second","exp":null,
        "scope":{"level":"device","max_tier":"T1"},"origin":"settings","revoked_at":null}],"next_cursor":null}).as_object().unwrap().clone(),extra:Extra::new()};
    f.receive(
        EnvelopeType::DirectiveResult,
        &next.id,
        &final_page,
        now() + 60,
    )
    .unwrap();
    assert_eq!(f.core.snapshot().unwrap().devices[0].grants.len(), 2);
    assert_eq!(f.core.outbound().unwrap().len(), outbound.len());
}

struct Mirror(Mutex<Vec<(DeviceRecord, bool)>>);
impl helper::DeviceMirror for Mirror {
    fn replace(&self, _: &str, records: &[(DeviceRecord, bool)]) -> helper::Result<()> {
        *self.0.lock().unwrap() = records.to_vec();
        Ok(())
    }
    fn verify(&self, _: &str, records: &[(DeviceRecord, bool)]) -> helper::Result<()> {
        if *self.0.lock().unwrap() == records {
            Ok(())
        } else {
            Err(helper::Error("device_directory_mismatch"))
        }
    }
}
struct Boundary;
impl helper::AuditSink for Boundary {
    fn append(&self, _: serde_json::Map<String, Value>) -> helper::Result<()> {
        Ok(())
    }
}
impl RequestRunner for Boundary {
    fn execute(
        &self,
        _: helper::Execution,
    ) -> Pin<Box<dyn Future<Output = helper::Result<Value>> + Send + '_>> {
        Box::pin(async { Err(helper::Error("unused")) })
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
impl PresenceProbe for Boundary {
    fn state(&self) -> remote::traits::PresenceState {
        serde_json::from_value(json!({"state":"away","since":0,"signals":{}})).unwrap()
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn phone_pairs_with_the_actual_helper_and_waits_for_its_confirmation() {
    let phone = Fixture::new();
    phone
        .core
        .store
        .transaction(|db| Store::delete(db, "peers", &phone.peer.device_id))
        .unwrap();
    let (base, server) = kv_server::spawn_test_relay();
    // Run the real relay control transport in-process. CI has no installed relay worker.
    let hub = helper::relay_control::hub();
    let transport = kv_relay_client::control_transport::RelayApi::new(base.as_str()).unwrap();
    let worker = tokio::spawn(async move {
        use kv_core::remote::relay_control::*;
        loop {
            let Some(job) = hub
                .poll(RelayControlPollParams { max_wait_ms: 100 })
                .await
                .unwrap()
                .request
            else {
                continue;
            };
            let result = kv_relay_client::controls::execute(&transport, &job, |challenge| async {
                let signed = hub
                    .sign(RelayControlSignParams {
                        id: job.id.clone(),
                        payload_b64: challenge,
                    })
                    .map_err(|error| kv_relay_client::Error(error.code()))?;
                Ok(signed["sig_b64"].as_str().unwrap().to_owned())
            })
            .await;
            hub.complete(RelayControlCompleteParams { id: job.id, result })
                .unwrap();
        }
    });
    let http = reqwest::Client::new();
    let dk = Arc::new(SoftwareDeviceKey::generate_p256());
    let executor = DeviceRecord {
        device_id: format!("dev_{}", new_id()),
        label: "Real helper executor".into(),
        os: Os::Linux,
        key_kind: KeyKind::Software,
        dk_pub: dk.public_jwk().unwrap(),
        dk_sig: kv_core::remote::Optional::Missing,
        ak_q: None,
        ak_s: None,
        caps: vec![Capability::Execute],
        attestation: None,
        extra: Extra::new(),
    };
    let registered = post(
        &http,
        &base,
        "v1/devices",
        None,
        serde_json::to_value(&executor).unwrap(),
    )
    .await;
    let account = registered["account_id"].as_str().unwrap();
    let mirror = Arc::new(Mirror(Mutex::new(vec![(executor.clone(), false)])));
    let store = helper::Store::memory().unwrap();
    store
        .restore_verified_directory(
            account,
            &[(executor.clone(), false)],
            mirror.as_ref(),
            now(),
        )
        .unwrap();
    let helper = helper::RemoteHelper::new(
        store,
        executor.clone(),
        account.into(),
        helper::ApprovalConfig::default(),
        helper::Services {
            identity: dk,
            quick: None,
            strong: None,
            presence: Arc::new(Boundary),
            runner: Arc::new(Boundary),
            audit: Arc::new(Boundary),
            mirror,
            clock: Arc::new(helper::SystemClock),
        },
    )
    .unwrap();
    let started = helper.pair_start_network(base.as_str()).await.unwrap();
    let relay = Arc::new(Relay::new(phone.core.clone()).unwrap());
    let paired = relay
        .begin_pair_at(
            base.clone(),
            decode_b64(started.extra["token"].as_str().unwrap()).unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(paired.expires_at, started.extra["expires_at"]);
    let first_accept = phone.core.candidate().unwrap().accept.unwrap();
    let retried = relay
        .begin_pair_at(
            base.clone(),
            decode_b64(started.extra["token"].as_str().unwrap()).unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(retried.pairing_id, paired.pairing_id);
    assert_eq!(
        phone.core.candidate().unwrap().accept.unwrap(),
        first_accept
    );
    assert!(phone.core.peer(&executor.device_id).is_err());
    let context = kv_helper::remote::ipc::CallerContext::authenticated(
        remote::ipc::Caller::CliOwner,
        501,
        4242,
        60,
    );
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let status = helper
                .handle(
                    context,
                    remote::ipc::Request {
                        op: remote::ipc::Op::Status,
                        params: json!({}),
                        extra: Default::default(),
                    },
                )
                .await;
            if serde_json::to_value(status).unwrap()["result"]["pairing"]["sas"] == paired.sas {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap();
    phone.authorize();
    let confirmation = {
        let relay = relay.clone();
        let sas = paired.sas.clone();
        tokio::spawn(async move { relay.confirm_pair(&sas, false).await })
    };
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(
        !confirmation.is_finished(),
        "phone must wait for the executor's confirmation"
    );
    // This is the authenticated owner terminal operation, not an HTTP finish surrogate.
    let confirmed = helper
        .handle(
            context,
            remote::ipc::Request {
                op: remote::ipc::Op::PairConfirm,
                params: json!({"sas":paired.sas,"confirmed":true}),
                extra: Default::default(),
            },
        )
        .await;
    assert_eq!(serde_json::to_value(confirmed).unwrap()["ok"], true);
    tokio::time::timeout(Duration::from_secs(5), confirmation)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(
        phone.core.peer(&executor.device_id).unwrap().dk_pub,
        executor.dk_pub
    );
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let status = helper
                .handle(
                    context,
                    remote::ipc::Request {
                        op: remote::ipc::Op::Status,
                        params: json!({}),
                        extra: Default::default(),
                    },
                )
                .await;
            if serde_json::to_value(status).unwrap()["result"]["pairing"]["state"] == "completed" {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap();
    worker.abort();
    let _ = worker.await;
    server.shutdown().await;
}
