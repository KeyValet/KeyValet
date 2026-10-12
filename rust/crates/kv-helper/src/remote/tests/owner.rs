//! Real helper handlers and signatures validate the owner projections.
use super::boundaries::signing_harness;
use super::*;
use kv_core::remote::ipc::{GrantIntent, GrantSource};
use rusqlite::OptionalExtension;

#[tokio::test]
async fn the_private_approval_ui_uses_real_helper_signatures_and_cancel_keeps_it_pending() {
    use crate::remote::production::{OwnerUi, ProcessIdentity, Processes, ProductionRunner, Task};
    struct NoProcesses;
    impl Processes for NoProcesses {
        fn inspect(&self, _: u32) -> Result<ProcessIdentity> {
            Err(Error("process_unavailable"))
        }
    }
    struct Ui {
        cancel: bool,
        calls: Mutex<Vec<Value>>,
    }
    impl OwnerUi for Ui {
        fn request(&self, op: &'static str, fields: Value) -> Task<'_, Value> {
            if op == "remote_wake" {
                self.calls.lock().unwrap().push(json!({"op":op}));
                return Box::pin(async { Ok(json!({"ok":true})) });
            }
            assert_eq!(op, "remote_approval");
            self.calls.lock().unwrap().push(fields.clone());
            Box::pin(async move {
                if self.cancel {
                    Ok(json!({"ok":false}))
                } else {
                    Ok(
                        json!({"ok":true,"params":{"approval_id":fields["request"]["approval_id"],
                    "decision":"allow","scope":{"mode":"per_use","level":"credential","until":0},"scope_option":"per_use"}}),
                    )
                }
            })
        }
    }
    for cancel in [false, true] {
        let h = signing_harness();
        let ui = Arc::new(Ui {
            cancel,
            calls: Mutex::new(Vec::new()),
        });
        let runner = ProductionRunner::new(Arc::new(NoProcesses));
        runner.set_owner_ui(Some(ui.clone())).unwrap();
        let store = Store::memory().unwrap();
        let records = directory(&h.helper.lock().unwrap().store).unwrap();
        *h.mirror.0.lock().unwrap() = records.clone();
        store
            .restore_verified_directory(
                &h.helper.account,
                &records,
                &*h.helper.services.mirror,
                h.clock.now(),
            )
            .unwrap();
        let helper = RemoteHelper::new(
            store,
            h.helper.local.clone(),
            h.helper.account.clone(),
            h.helper.config.clone(),
            Services {
                identity: h.helper.services.identity.clone(),
                quick: h.helper.services.quick.clone(),
                strong: h.helper.services.strong.clone(),
                presence: h.presence.clone(),
                mirror: h.mirror.clone(),
                audit: h.audit.clone(),
                runner,
                clock: h.clock.clone(),
            },
        )
        .unwrap();
        let mut request: ApprovalRequest =
            serde_json::from_value(fixture("decision_valid.json")["request"].clone()).unwrap();
        request.requester.device_id = h.peer.device_id.clone();
        request.delivery.mode = DeliveryMode::Banner;
        helper
            .inbound(h.envelope(
                EnvelopeType::ApprovalRequest,
                &request.approval_id,
                &request,
            ))
            .await
            .unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            while helper
                .lock()
                .unwrap()
                .presenting
                .contains(&request.approval_id)
            {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert_eq!(ui.calls.lock().unwrap().len(), 1);
        let messages = helper.outbound_poll(0).await.unwrap();
        if cancel {
            assert!(messages.is_empty());
            assert!(helper
                .lock()
                .unwrap()
                .inbound_requests
                .contains_key(&request.approval_id));
        } else {
            let envelope = messages
                .iter()
                .find(|e| e.r#type == EnvelopeType::ApprovalDecision)
                .unwrap();
            let decision: ApprovalDecision = from_json(
                &kv_core::remote::envelope::open(
                    envelope,
                    &h.peer.device_id,
                    &*key("recipient"),
                    &helper.local,
                    h.clock.now(),
                )
                .unwrap(),
            )
            .unwrap();
            kv_core::remote::keys::verify_object(
                &decision,
                &decision.sig,
                helper.local.ak_q.as_ref().unwrap(),
            )
            .unwrap();
            assert!(!helper
                .lock()
                .unwrap()
                .inbound_requests
                .contains_key(&request.approval_id));
        }
        for presence in [Presence::Away, Presence::Present, Presence::Present] {
            let now = h.clock.0.fetch_add(1, Ordering::SeqCst) + 1;
            let response = serde_json::to_value(helper.handle(CallerContext::authenticated(Caller::ApprovalAgent,501,4242,210),
                Request { op:Op::PresenceUpdate,params:json!({"device_id":helper.local.device_id,"state":presence,"since":now,"sent_at":now}),extra:Extra::new() }).await).unwrap();
            assert_eq!(response["ok"], true);
        }
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            while ui.calls.lock().unwrap().len() < 2 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert_eq!(
            ui.calls
                .lock()
                .unwrap()
                .iter()
                .filter(|value| value["op"] == "remote_wake")
                .count(),
            1
        );
    }
}

fn intent(h: &Harness, tier: Tier) -> GrantIntent {
    GrantIntent {
        source: GrantSource::Settings,
        kind: GrantKind::Grant,
        aud: h.peer.device_id.clone(),
        scope: GrantScope {
            level: GrantScopeLevel::Credential,
            credential: Optional::Value("github/default".into()),
            hosts: Optional::Missing,
            methods: Optional::Missing,
            paths: Optional::Missing,
            agent: Optional::Missing,
            max_tier: tier,
            extra: Extra::new(),
        },
        budget: Some(Budget {
            calls: 5,
            per: BudgetPeriod::OneHour,
            bytes: Optional::Missing,
            extra: Extra::new(),
        }),
        nbf: h.clock.now(),
        exp: Some(h.clock.now() + 3600),
        origin: "settings".into(),
        confirm: None,
        confirmation_token: None,
    }
}

fn issued(h: &Harness) -> usize {
    h.helper
        .lock()
        .unwrap()
        .store
        .db
        .query_row("SELECT COUNT(*) FROM issued_grants", [], |r| r.get(0))
        .unwrap()
}

#[tokio::test]
async fn global_t1_reaches_a_future_paired_executor_and_pending_revokes_block_fanout() {
    for revoking in [false, true] {
        let h = signing_harness();
        let mut draft = intent(&h, Tier::T1);
        draft.aud = "*".into();
        draft.scope.level = GrantScopeLevel::Global;
        draft.scope.credential = Optional::Missing;
        let result = h
            .exchange(Caller::CliOwner, Op::GrantIssue, json!(draft))
            .await;
        assert_eq!(result["ok"], true);
        let jti = result["result"]["grant"]["jti"].as_str().unwrap();
        if revoking {
            h.helper
                .lock()
                .unwrap()
                .store
                .db
                .execute(
                    "INSERT INTO issued_grant_revocations(jti,requested_at) VALUES(?1,?2)",
                    params![jti, h.clock.now()],
                )
                .unwrap();
        }
        let started = h.helper.pair_start("https://relay.example.com").unwrap();
        let mut candidate = h.peer.clone();
        candidate.device_id = "future-executor".into();
        candidate.caps.push(Capability::Execute);
        let sas = h
            .helper
            .pair_complete(PairAccept {
                token: started.extra["token"].as_str().unwrap().into(),
                joiner: candidate.clone(),
                extra: Extra::new(),
            })
            .unwrap()
            .sas;
        h.helper
            .pair_confirm_terminal(&PairConfirm {
                sas: sas.clone(),
                sig: String::new(),
                extra: Extra::new(),
            })
            .unwrap();
        let confirm = kv_core::remote::pairing::sign_confirm(
            &sas,
            SignatureAlgorithm::ES256,
            &*key("strong"),
        )
        .unwrap();
        h.helper.pair_confirm_signed(&confirm).unwrap();
        let messages = h.helper.outbound_poll(0).await.unwrap();
        let sent = messages
            .iter()
            .filter(|e| e.to == candidate.device_id && e.r#type == EnvelopeType::Grant)
            .collect::<Vec<_>>();
        assert_eq!(sent.len(), usize::from(!revoking));
        if let Some(envelope) = sent.first() {
            let grant: Grant = from_json(
                &kv_core::remote::envelope::open(
                    envelope,
                    &candidate.device_id,
                    &*key("recipient"),
                    &h.helper.local,
                    h.clock.now(),
                )
                .unwrap(),
            )
            .unwrap();
            kv_core::remote::validation::verify_grant(
                &grant,
                &candidate.device_id,
                &candidate.label,
                &h.helper.local,
                ApprovalLevel::Strong,
                h.clock.now(),
            )
            .unwrap();
        }
    }
}

#[tokio::test]
async fn standing_t2_consumes_two_distinct_confirmations_with_one_deadline() {
    let h = signing_harness();
    let mut draft = intent(&h, Tier::T2);
    draft.exp = None;
    let first = h
        .exchange(Caller::CliOwner, Op::GrantIssue, json!(draft))
        .await;
    assert_eq!(first["result"]["confirmations_left"], 2);
    draft.confirm = Some(h.peer.label.clone());
    draft.confirmation_token = first["result"]["confirmation_token"]
        .as_str()
        .map(str::to_owned);
    let second = h
        .exchange(Caller::CliOwner, Op::GrantIssue, json!(draft))
        .await;
    assert_eq!(second["result"]["confirmations_left"], 1);
    assert_eq!(
        second["result"]["expires_at"],
        first["result"]["expires_at"]
    );
    assert_ne!(
        second["result"]["confirmation_token"],
        first["result"]["confirmation_token"]
    );
    assert_eq!(issued(&h), 0);
    assert_eq!(
        h.exchange(Caller::CliOwner, Op::GrantIssue, json!(draft))
            .await["ok"],
        false
    );
    draft.confirmation_token = second["result"]["confirmation_token"]
        .as_str()
        .map(str::to_owned);
    let issued_result = h
        .exchange(Caller::CliOwner, Op::GrantIssue, json!(draft))
        .await;
    assert_eq!(issued_result["ok"], true);
    assert_eq!(issued_result["result"]["grant"]["confirm"], h.peer.label);
    assert_eq!(issued(&h), 1);
}

#[tokio::test]
async fn interrupted_revoke_stays_pending_until_an_authenticated_executor_reply() {
    let h = signing_harness();
    let issued = h
        .exchange(
            Caller::CliOwner,
            Op::GrantIssue,
            json!(intent(&h, Tier::T1)),
        )
        .await;
    let jti = issued["result"]["grant"]["jti"]
        .as_str()
        .unwrap()
        .to_owned();
    let helper = h.helper.clone();
    let revoking = jti.clone();
    let job = tokio::spawn(async move { helper.revoke_owner_grant(&revoking).await });
    let id = tokio::time::timeout(std::time::Duration::from_secs(2), async {
        loop {
            let id: Option<String> = h
                .helper
                .lock()
                .unwrap()
                .store
                .db
                .query_row(
                    "SELECT id FROM issued_directives WHERE op='revoke_grant'",
                    [],
                    |r| r.get(0),
                )
                .optional()
                .unwrap();
            if let Some(id) = id {
                break id;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    job.abort();
    let _ = job.await;
    let ledger = h.exchange(Caller::CliOwner, Op::GrantList, json!({})).await;
    assert_eq!(ledger["result"]["grants"][0]["revocation_pending"], true);
    assert!(ledger["result"]["grants"][0]["revoked_at"].is_null());
    let result = json!({"id":id,"ok":true,"error":null,"state":{}});
    h.helper
        .inbound(h.envelope(EnvelopeType::DirectiveResult, &id, &result))
        .await
        .unwrap();
    let ledger = h.exchange(Caller::CliOwner, Op::GrantList, json!({})).await;
    assert_eq!(ledger["result"]["grants"][0]["revocation_pending"], false);
    assert!(ledger["result"]["grants"][0]["revoked_at"].is_number());
    h.helper.revoke_owner_grant(&jti).await.unwrap();
    assert_eq!(
        h.helper
            .inbound(h.envelope(EnvelopeType::DirectiveResult, &id, &result))
            .await
            .unwrap_err()
            .code(),
        "already_consumed"
    );
}

#[tokio::test]
async fn t2_preparation_is_not_a_grant_and_final_confirmation_is_bound_and_once_only() {
    for variant in 0..7 {
        let h = signing_harness();
        let mut draft = intent(&h, Tier::T2);
        let prepared = h
            .exchange(Caller::CliOwner, Op::GrantIssue, json!(draft))
            .await;
        assert_eq!(prepared["ok"], true, "helper operation rejected");
        assert_eq!(issued(&h), 0);
        assert!(h.helper.outbound_poll(0).await.unwrap().is_empty());
        let token = prepared["result"]["confirmation_token"]
            .as_str()
            .unwrap()
            .to_owned();
        assert!(prepared["result"]["expires_at"].as_i64().unwrap() <= h.clock.now() + 120);
        draft.confirmation_token = Some(token.clone());
        draft.confirm = Some(h.peer.label.clone());
        let mut context = CallerContext::authenticated(Caller::CliOwner, 501, 4242, 210);
        match variant {
            0 => {}
            1 => draft.confirm = Some("wrong label".into()),
            2 => draft.scope.credential = Optional::Value("other/default".into()),
            3 => context = CallerContext::authenticated(Caller::CliOwner, 999, 4242, 210),
            4 => context = CallerContext::authenticated(Caller::CliOwner, 501, 9999, 210),
            5 => h.clock.0.store(h.clock.now() + 121, Ordering::SeqCst),
            _ => draft.confirmation_token = Some("wrong token".into()),
        }
        let response = serde_json::to_value(
            h.helper
                .handle(
                    context,
                    Request {
                        op: Op::GrantIssue,
                        params: json!(draft),
                        extra: Extra::new(),
                    },
                )
                .await,
        )
        .unwrap();
        if variant == 0 {
            assert_eq!(response["ok"], true, "helper operation rejected");
            let grant: Grant = serde_json::from_value(response["result"]["grant"].clone()).unwrap();
            kv_core::remote::validation::verify_grant(
                &grant,
                &h.peer.device_id,
                &h.peer.label,
                &h.helper.local,
                ApprovalLevel::Strong,
                h.clock.now(),
            )
            .unwrap();
            assert_eq!(grant.confirm.as_value(), Some(&h.peer.label));
            assert_eq!(issued(&h), 1);
        } else {
            assert_eq!(response["ok"], false, "helper operation rejected");
            assert_eq!(issued(&h), 0);
        }
        draft.confirmation_token = Some(token);
        if variant != 6 {
            assert_eq!(
                h.exchange(Caller::CliOwner, Op::GrantIssue, json!(draft))
                    .await["ok"],
                false
            );
        }
    }
}

#[tokio::test]
async fn owner_fields_cannot_supply_issuer_identity_or_lower_grant_authority() {
    let h = signing_harness();
    for field in ["iss", "iss_alg", "sig", "nonce", "jti"] {
        let mut draft = json!(intent(&h, Tier::T1));
        draft[field] = json!("forged");
        assert_eq!(
            h.exchange(Caller::CliOwner, Op::GrantIssue, draft).await["ok"],
            false
        );
    }
    let mut draft = intent(&h, Tier::T2);
    draft.source = GrantSource::Preauthorization;
    assert_eq!(
        h.exchange(Caller::CliOwner, Op::GrantIssue, json!(draft))
            .await["ok"],
        false
    );
    *h.runner.level.lock().unwrap() = ApprovalLevel::Quick;
    assert_eq!(
        h.exchange(
            Caller::CliOwner,
            Op::GrantIssue,
            json!(intent(&h, Tier::T1))
        )
        .await["error"]["code"],
        "insufficient_level"
    );
    assert_eq!(issued(&h), 0);
}

#[tokio::test]
async fn helper_anchors_remember_after_authorization_and_signs_the_denial_reason() {
    for deny in [false, true] {
        let h = signing_harness();
        let mut request: ApprovalRequest =
            serde_json::from_value(fixture("decision_valid.json")["request"].clone()).unwrap();
        request.approval_id = "owner-incoming".into();
        request.requester.device_id = h.peer.device_id.clone();
        request.scope_options.push(ScopeOption::Remember1h);
        h.helper
            .inbound(h.envelope(
                EnvelopeType::ApprovalRequest,
                &request.approval_id,
                &request,
            ))
            .await
            .unwrap();
        let clock = h.clock.clone();
        *h.runner.after_authorize.lock().unwrap() = Some(Box::new(move || {
            clock.0.fetch_add(20, Ordering::SeqCst);
        }));
        let params = json!({"approval_id":request.approval_id,"decision":if deny {"deny"} else {"allow"},
            "scope":{"mode":"remember","level":"credential","until":0},"scope_option":"remember:1h",
            "reason":if deny {Some("Owner declined this operation")} else {None}});
        let response = h.exchange(Caller::CliOwner, Op::Decide, params).await;
        assert_eq!(response["ok"], true, "helper operation rejected");
        let envelope = h
            .helper
            .outbound_poll(0)
            .await
            .unwrap()
            .into_iter()
            .find(|envelope| envelope.r#type == EnvelopeType::ApprovalDecision)
            .unwrap();
        let plaintext = kv_core::remote::envelope::open(
            &envelope,
            &h.peer.device_id,
            &*key("recipient"),
            &h.helper.local,
            h.clock.now(),
        )
        .unwrap();
        let decision: ApprovalDecision = from_json(&plaintext).unwrap();
        assert_eq!(decision.scope.until, decision.issued_at + 3600);
        assert_eq!(decision.issued_at, h.clock.now());
        assert_eq!(
            decision.reason.as_value().map(String::as_str),
            if deny {
                Some("Owner declined this operation")
            } else {
                None
            }
        );
        kv_core::remote::keys::verify_object(
            &decision,
            &decision.sig,
            h.helper.local.ak_q.as_ref().unwrap(),
        )
        .unwrap();
        let history = h
            .exchange(Caller::CliOwner, Op::PendingList, json!({}))
            .await;
        assert_eq!(
            history["result"]["recent"][0]["approval_id"],
            request.approval_id
        );
        assert!(
            h.exchange(Caller::Mcp, Op::PendingList, json!({})).await["result"]
                .get("recent")
                .is_none()
        );
        assert_eq!(
            h.exchange(
                Caller::CliOwner,
                Op::Decide,
                json!({"approval_id":request.approval_id,"decision":"allow",
            "scope":{"mode":"per_use","level":"credential","until":0}})
            )
            .await["ok"],
            false
        );
    }
}

#[tokio::test]
async fn local_and_remote_settings_share_a_transaction_and_invalidate_stale_local_proposals() {
    use super::workflow::signed_directive;
    let h = Harness::new();
    let vault = tempfile::tempdir().unwrap();
    let _binding = crate::remote::settings::install(&h.helper, vault.path()).unwrap();
    let initial = kv_core::settings::read_settings(vault.path());
    let local = kv_core::settings::Settings {
        grant_mode: kv_core::settings::GrantMode::PerSession,
        ..initial.clone()
    };
    assert!(kv_core::settings::compare_and_write_settings(vault.path(), &initial, &local).unwrap());
    assert_eq!(h.helper.mode().unwrap(), "per_session");
    let directive = signed_directive(
        &h,
        DirectiveOp::SetMode,
        json!({"mode":"per_use"}),
        ApprovalLevel::Quick,
    );
    h.helper
        .apply_directive(&directive, ApprovalLevel::Quick)
        .unwrap();
    assert_eq!(
        kv_core::settings::read_settings(vault.path()).grant_mode,
        kv_core::settings::GrantMode::PerUse
    );
    assert!(!kv_core::settings::compare_and_write_settings(vault.path(), &local, &local).unwrap());
    let entries = h.helper.audit_entries().unwrap();
    assert!(entries
        .iter()
        .any(|entry| entry["op"] == "setting_changed" && entry["by"] == "local"));
    assert!(entries.iter().any(|entry| entry["op"] == "setting_changed"
        && entry["by"] == format!("remote:{}", h.peer.device_id)));
    assert!(!vault.path().join("settings.json").exists());
}
