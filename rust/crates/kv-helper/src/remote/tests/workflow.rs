use super::*;

pub(super) fn present_signals() -> kv_ipc::remote::PresenceSignals {
    kv_ipc::remote::PresenceSignals {
        graphical_session: Some(true),
        session_active: Some(true),
        screen_locked: Some(false),
        screensaver_active: Some(false),
        idle_seconds: Some(0),
        display_connected: Some(true),
        display_awake: Some(true),
        remote_session_active: Some(false),
        approval_channel_available: Some(true),
        extra: Extra::new(),
    }
}

#[tokio::test]
async fn presence_fanout_silent_escalation_and_phone_override() {
    for missing in 0..9 {
        let h = Harness::new();
        let mut signals = present_signals();
        match missing {
            0 => signals.graphical_session = None,
            1 => signals.session_active = None,
            2 => signals.screen_locked = None,
            3 => signals.screensaver_active = None,
            4 => signals.idle_seconds = None,
            5 => signals.display_connected = None,
            6 => signals.display_awake = None,
            7 => signals.remote_session_active = None,
            _ => signals.approval_channel_available = None,
        }
        *h.presence.0.lock().unwrap() = PresenceState {
            state: Presence::Present,
            since: h.clock.now(),
            signals,
            extra: Extra::new(),
        };
        h.helper.submit(h.input(Tier::T1, "A")).unwrap();
        let envelopes = h.helper.outbound_poll(0).await.unwrap();
        let plaintext = kv_core::remote::envelope::open(
            &envelopes[0],
            &h.peer.device_id,
            key("recipient").as_ref(),
            &h.helper.local,
            h.clock.now(),
        )
        .unwrap();
        assert_eq!(
            from_json::<ApprovalRequest>(&plaintext)
                .unwrap()
                .delivery
                .mode,
            DeliveryMode::Banner
        );
    }
    let h = Harness::new();
    *h.presence.0.lock().unwrap() = PresenceState {
        state: Presence::Present,
        since: h.clock.now(),
        signals: present_signals(),
        extra: Extra::new(),
    };
    let mut phone = h.peer.clone();
    phone.device_id = "dev_phone".into();
    phone.os = Os::Ios;
    h.helper
        .lock()
        .unwrap()
        .store
        .insert_device(&phone, "account", h.clock.now())
        .unwrap();
    let request = h.helper.submit(h.input(Tier::T2, "A")).unwrap();
    assert_eq!(request.min_level, ApprovalLevel::Strong);
    let envelopes = h.helper.outbound_poll(0).await.unwrap();
    assert_eq!(envelopes.len(), 2);
    h.spooled(&envelopes);
    for envelope in envelopes {
        let plaintext = kv_core::remote::envelope::open(
            &envelope,
            &envelope.to,
            key("recipient").as_ref(),
            &h.helper.local,
            h.clock.now(),
        )
        .unwrap();
        assert_eq!(
            from_json::<ApprovalRequest>(&plaintext)
                .unwrap()
                .delivery
                .mode,
            DeliveryMode::Silent
        );
    }
    h.presence.0.lock().unwrap().state = Presence::Away;
    h.clock.0.fetch_add(30, Ordering::SeqCst);
    h.helper.tick().unwrap();
    let escalations = h.helper.outbound_poll(0).await.unwrap();
    assert_eq!(escalations.len(), 2);
    h.spooled(&escalations);
    assert!(escalations
        .iter()
        .all(|envelope| envelope.id == request.approval_id
            && envelope.r#type == EnvelopeType::ApprovalEscalate));
    h.helper.tick().unwrap();
    assert!(h.helper.outbound_poll(0).await.unwrap().is_empty());
    h.helper
        .lock()
        .unwrap()
        .store
        .set_setting("notify", &NotifyPolicy::AlwaysPhone, "local", h.clock.now())
        .unwrap();
    h.presence.0.lock().unwrap().state = Presence::Present;
    h.helper.submit(h.input(Tier::T1, "B")).unwrap();
    for envelope in h.helper.outbound_poll(0).await.unwrap() {
        let plaintext = kv_core::remote::envelope::open(
            &envelope,
            &envelope.to,
            key("recipient").as_ref(),
            &h.helper.local,
            h.clock.now(),
        )
        .unwrap();
        assert_eq!(
            from_json::<ApprovalRequest>(&plaintext)
                .unwrap()
                .delivery
                .mode,
            if envelope.to == phone.device_id {
                DeliveryMode::Banner
            } else {
                DeliveryMode::Silent
            }
        );
    }
}

pub(super) fn signed_grant(h: &Harness, id: &str, tier: Tier, calls: u64) -> Grant {
    let mut grant: Grant =
        serde_json::from_value(fixture("grant_standing_t1.json")["grant"].clone()).unwrap();
    grant.jti = id.into();
    grant.scope.max_tier = tier;
    grant.scope.level = GrantScopeLevel::Credential;
    grant.scope.credential = Optional::Value("github/default".into());
    grant.scope.hosts = Optional::Value(vec!["api.github.com".into()]);
    grant.scope.methods = Optional::Value(vec!["POST".into()]);
    grant.scope.paths = Optional::Value(vec!["/repos/*/demo/**".into()]);
    grant.budget = Optional::Value(Budget {
        calls,
        per: BudgetPeriod::OneHour,
        bytes: Optional::Value(100),
        extra: Extra::new(),
    });
    grant.nbf = h.clock.now();
    grant.exp = Some(h.clock.now() + 3600);
    grant.origin = "settings".into();
    grant.confirm = Optional::Value("srv".into());
    grant.sig = sign_object(&grant, SignatureAlgorithm::ES256, key("strong").as_ref()).unwrap();
    grant
}

fn usage(h: &Harness, tier: Tier) -> GrantUse {
    let input = h.input(tier, "A");
    GrantUse {
        canonical: from_json(&input.canonical.canonical_bytes().unwrap()).unwrap(),
        tier,
        template_allowed_hosts: vec!["api.github.com".into()],
        policy_allowed_methods: vec!["POST".into()],
        body_bytes: 15,
        session_id: "session".into(),
    }
}

#[test]
fn grants_debit_every_budget_without_combining_tiers_and_audit_unattended_t2() {
    let h = Harness::new();
    h.helper
        .install_grant(&signed_grant(&h, "low", Tier::T1, 2), ApprovalLevel::Strong)
        .unwrap();
    h.helper
        .install_grant(
            &signed_grant(&h, "high", Tier::T2, 3),
            ApprovalLevel::Strong,
        )
        .unwrap();
    let coverage = h.helper.cover_and_debit(&usage(&h, Tier::T1)).unwrap();
    assert_eq!(coverage.jtis, vec!["high", "low"]);
    assert_eq!(coverage.max_tier, Some(Tier::T1));
    assert_eq!(
        h.helper.cover_and_debit(&usage(&h, Tier::T2)).unwrap().jtis,
        vec!["high"]
    );
    assert!(h
        .helper
        .audit_entries()
        .unwrap()
        .iter()
        .any(|entry| entry["op"] == "unattended_t2"));
    assert_eq!(
        h.helper
            .cover_and_debit(&usage(&h, Tier::T1))
            .unwrap()
            .jtis
            .len(),
        2
    );
    assert!(h
        .helper
        .cover_and_debit(&usage(&h, Tier::T1))
        .unwrap()
        .jtis
        .is_empty());
    assert!(h
        .helper
        .audit_entries()
        .unwrap()
        .iter()
        .any(|entry| entry["op"] == "grant_exhausted"));
    h.helper.revoke_grant("high", "local").unwrap();
    assert_eq!(
        h.helper
            .install_grant(
                &signed_grant(&h, "high", Tier::T2, 3),
                ApprovalLevel::Strong
            )
            .unwrap_err(),
        Error("revoked_grant")
    );
    h.reason("revoked_grant");
    for mutate in 0..6 {
        let h = Harness::new();
        h.helper
            .install_grant(
                &signed_grant(&h, "match", Tier::T1, 2),
                ApprovalLevel::Strong,
            )
            .unwrap();
        let mut request = usage(&h, Tier::T1);
        match mutate {
            0 => request.canonical.credential = Some("other/default".into()),
            1 => request.canonical.host = Some("evil.example".into()),
            2 => request.canonical.method = Some("DELETE".into()),
            3 => request.canonical.path = Some("/admin/danger".into()),
            4 => request.template_allowed_hosts.clear(),
            _ => request.policy_allowed_methods.clear(),
        }
        assert!(h.helper.cover_and_debit(&request).unwrap().jtis.is_empty());
    }
}

#[tokio::test]
async fn scope_mapping_session_bounds_and_merged_request_grants() {
    for (mode, level, until, expected_level, expected_exp) in [
        (
            ScopeMode::PerCredential,
            DecisionScopeLevel::Credential,
            0,
            GrantScopeLevel::Credential,
            Some(1760243212),
        ),
        (
            ScopeMode::PerSession,
            DecisionScopeLevel::Device,
            0,
            GrantScopeLevel::Device,
            Some(1760243212),
        ),
        (
            ScopeMode::Remember,
            DecisionScopeLevel::Credential,
            1760203612,
            GrantScopeLevel::Credential,
            Some(1760203612),
        ),
        (
            ScopeMode::Standing,
            DecisionScopeLevel::Device,
            0,
            GrantScopeLevel::Device,
            None,
        ),
    ] {
        let h = Harness::new();
        let request = h.helper.submit(h.input(Tier::T1, "A")).unwrap();
        let mut decision = h.decision(&request, ApprovalLevel::Strong, mode);
        decision.scope.level = level;
        decision.scope.until = until;
        decision.sig =
            sign_object(&decision, SignatureAlgorithm::ES256, key("strong").as_ref()).unwrap();
        h.helper.lock().unwrap().full.clear();
        h.helper
            .inbound(h.envelope(
                EnvelopeType::ApprovalDecision,
                &request.approval_id,
                &decision,
            ))
            .await
            .unwrap();
        let state = h.helper.lock().unwrap();
        let grants = h.helper.grant_list_locked(&state).unwrap();
        assert_eq!(grants.len(), 1);
        assert_eq!(
            grants[0]["scope"]["level"],
            serde_json::to_value(expected_level).unwrap()
        );
        assert_eq!(grants[0]["exp"], json!(expected_exp));
        drop(state);
        let mut other_session = usage(&h, Tier::T1);
        other_session.session_id = "another-session".into();
        if matches!(mode, ScopeMode::PerCredential | ScopeMode::PerSession) {
            assert!(h
                .helper
                .cover_and_debit(&other_session)
                .unwrap()
                .jtis
                .is_empty());
        }
    }
    let h = Harness::new();
    let first = h.helper.submit(h.input(Tier::T1, "same")).unwrap();
    h.helper.submit(h.input(Tier::T1, "same")).unwrap();
    let merged = h.helper.submit(h.input(Tier::T1, "same")).unwrap();
    assert_eq!(first.approval_id, merged.approval_id);
    assert_eq!(merged.merged_count, 3);
    let decision = h.decision(&merged, ApprovalLevel::Quick, ScopeMode::PerUse);
    h.helper.lock().unwrap().full.clear();
    h.helper
        .inbound(h.envelope(
            EnvelopeType::ApprovalDecision,
            &merged.approval_id,
            &decision,
        ))
        .await
        .unwrap();
    assert_eq!(
        h.helper
            .grant_list_locked(&h.helper.lock().unwrap())
            .unwrap()[0]["exp"],
        h.clock.now() + 30
    );
    let h = Harness::new();
    assert_ne!(
        h.helper
            .submit(h.input(Tier::T2, "same"))
            .unwrap()
            .approval_id,
        h.helper
            .submit(h.input(Tier::T2, "same"))
            .unwrap()
            .approval_id
    );
    let h = Harness::new();
    assert_ne!(
        h.helper.submit(h.input(Tier::T1, "A")).unwrap().approval_id,
        h.helper.submit(h.input(Tier::T1, "B")).unwrap().approval_id
    );
}

pub(super) fn signed_directive(
    h: &Harness,
    op: DirectiveOp,
    args: Value,
    level: ApprovalLevel,
) -> Directive {
    let mut directive: Directive =
        serde_json::from_value(fixture("directive_tighten_quick_ok.json")["directive"].clone())
            .unwrap();
    directive.id = super::super::engine::new_id(h.clock.now()).unwrap();
    directive.nonce = super::super::engine::random_nonce().unwrap();
    directive.op = op;
    directive.args = args.as_object().unwrap().clone();
    directive.exp = h.clock.now() + 600;
    directive.sig = sign_object(
        &directive,
        SignatureAlgorithm::ES256,
        key(if level == ApprovalLevel::Strong {
            "strong"
        } else {
            "quick"
        })
        .as_ref(),
    )
    .unwrap();
    directive
}

#[test]
fn directives_share_settings_and_obey_levels_nonce_and_expiration() {
    let h = Harness::new();
    {
        let state = h.helper.lock().unwrap();
        state
            .store
            .insert_device(&h.helper.local, &h.helper.account, h.clock.now())
            .unwrap();
        h.mirror
            .replace(&h.helper.account, &directory(&state.store).unwrap())
            .unwrap();
    }
    let tighten = signed_directive(
        &h,
        DirectiveOp::SetMode,
        json!({"mode":"per_use"}),
        ApprovalLevel::Quick,
    );
    h.helper
        .apply_directive(&tighten, ApprovalLevel::Quick)
        .unwrap();
    assert_eq!(h.helper.mode().unwrap(), "per_use");
    assert_eq!(
        h.helper
            .apply_directive(&tighten, ApprovalLevel::Quick)
            .unwrap_err(),
        Error("replay")
    );
    h.reason("replay");
    let loosen = signed_directive(
        &h,
        DirectiveOp::SetMode,
        json!({"mode":"per_session"}),
        ApprovalLevel::Strong,
    );
    h.helper
        .apply_directive(&loosen, ApprovalLevel::Strong)
        .unwrap();
    assert_eq!(h.helper.mode().unwrap(), "per_session");
    h.helper
        .set_mode_local("per_credential", ApprovalLevel::Quick)
        .unwrap();
    assert_eq!(h.helper.mode().unwrap(), "per_credential");
    for (op, args, level) in [
        (
            DirectiveOp::SetUnlockTtl,
            json!({"seconds":60}),
            ApprovalLevel::Quick,
        ),
        (
            DirectiveOp::SetClass,
            json!({"name":"test","match":{"host":"api.github.com"},"exp_s":1800}),
            ApprovalLevel::Strong,
        ),
        (
            DirectiveOp::SetClass,
            json!({"name":"test","match":{"host":"api.github.com"},"exp_s":900}),
            ApprovalLevel::Quick,
        ),
        (
            DirectiveOp::SetDeviceLabel,
            json!({"label":"new server"}),
            ApprovalLevel::Strong,
        ),
        (
            DirectiveOp::Notify,
            json!({"policy":"both"}),
            ApprovalLevel::Quick,
        ),
        (DirectiveOp::QueryStatus, json!({}), ApprovalLevel::Quick),
        (DirectiveOp::QueryPending, json!({}), ApprovalLevel::Quick),
        (DirectiveOp::QueryGrants, json!({}), ApprovalLevel::Quick),
        (
            DirectiveOp::QueryAudit,
            json!({"since":0,"limit":200}),
            ApprovalLevel::Quick,
        ),
    ] {
        let result = h
            .helper
            .apply_directive(&signed_directive(&h, op, args, level), level)
            .unwrap();
        assert!(result.ok);
        if op == DirectiveOp::QueryAudit {
            let encoded = encode(&result).unwrap();
            assert!(!encoded.contains("canonical_json"));
            assert!(!encoded.contains("args_json"));
            assert!(!encoded.contains("ct\""));
        }
    }
    let mut expired = signed_directive(
        &h,
        DirectiveOp::QueryStatus,
        json!({}),
        ApprovalLevel::Quick,
    );
    expired.exp = h.clock.now() - 1;
    expired.sig = sign_object(&expired, SignatureAlgorithm::ES256, key("quick").as_ref()).unwrap();
    assert_eq!(
        h.helper
            .apply_directive(&expired, ApprovalLevel::Quick)
            .unwrap_err(),
        Error("expired")
    );
    h.reason("expired");
    let danger = signed_directive(
        &h,
        DirectiveOp::RevokeDevice,
        json!({"device_id":h.peer.device_id}),
        ApprovalLevel::Strong,
    );
    assert_eq!(
        h.helper
            .apply_directive(&danger, ApprovalLevel::Strong)
            .unwrap_err(),
        Error("secondary_confirmation_required")
    );
    h.reason("secondary_confirmation_required");
}

#[tokio::test]
async fn device_revocation_and_lock_invalidate_unused_approvals_and_all_grants() {
    let h = Harness::new();
    h.helper
        .install_grant(
            &signed_grant(&h, "grant", Tier::T1, 3),
            ApprovalLevel::Strong,
        )
        .unwrap();
    let request = h.helper.submit(h.input(Tier::T1, "A")).unwrap();
    h.helper.lock().unwrap().full.clear();
    let decision = h.decision(&request, ApprovalLevel::Quick, ScopeMode::PerCredential);
    h.helper
        .inbound(h.envelope(
            EnvelopeType::ApprovalDecision,
            &request.approval_id,
            &decision,
        ))
        .await
        .unwrap();
    h.helper.revoke_device(&h.peer.device_id, "local").unwrap();
    assert!(h
        .helper
        .cover_and_debit(&usage(&h, Tier::T1))
        .unwrap()
        .jtis
        .is_empty());
    assert_eq!(
        h.helper
            .lock()
            .unwrap()
            .store
            .pending(&request.approval_id)
            .unwrap()
            .state,
        PendingState::Cancelled
    );
    assert_eq!(h.runner.calls.load(Ordering::SeqCst), 0);
    let h = Harness::new();
    h.helper
        .install_grant(
            &signed_grant(&h, "grant", Tier::T1, 3),
            ApprovalLevel::Strong,
        )
        .unwrap();
    h.helper.submit(h.input(Tier::T1, "A")).unwrap();
    h.helper
        .apply_directive(
            &signed_directive(&h, DirectiveOp::Lock, json!({}), ApprovalLevel::Quick),
            ApprovalLevel::Quick,
        )
        .unwrap();
    assert!(h.runner.locked.load(Ordering::SeqCst));
    assert!(h.helper.lock().unwrap().full.is_empty());
    assert!(h
        .helper
        .grant_list_locked(&h.helper.lock().unwrap())
        .unwrap()
        .iter()
        .all(|grant| grant["revoked_at"].is_i64()));
}

#[test]
fn configuration_runtime_and_http_budgets_are_bounded() {
    let config=ApprovalConfig::from_toml("[approval]\nprefer='remote'\n[[approval.class]]\nname='deploy'\nmatch.credential='deploy/*'\nexp_s=86400\n").unwrap();
    assert_eq!(config.prefer, Preference::Remote);
    for (runtime, budget) in [(180, 60), (50, 40), (60, 50), (120, 60), (10, 0), (0, 0)] {
        assert_eq!(config.call_budget_s(runtime), budget);
    }
    assert_eq!(config.wait_budget_ms(600000, 50), 40000);
    assert_eq!(config.http_budget_s(Some(600)), 540);
    assert_eq!(config.http_budget_s(None), 55);
    assert!(ApprovalConfig::from_toml("[approval]\ndefault_exp_s=86401").is_err());
    assert!(FullRequest::new(
        "proxy",
        json!({"body":"a".repeat(1024*1024)})
            .as_object()
            .unwrap()
            .clone()
    )
    .is_err());
}

#[tokio::test]
async fn future_fields_preserve_authority_and_v2_envelopes_ack_without_processing() {
    let h = Harness::new();
    let mut device = h.peer.clone();
    device.key_kind = KeyKind::Unknown("future-hardware".into());
    device.attestation =
        Some(serde_json::from_value(json!({"kind":"future-attestation","doc":null})).unwrap());
    h.helper
        .lock()
        .unwrap()
        .store
        .db
        .execute(
            "UPDATE devices SET record_json=?1 WHERE id=?2",
            params![encode(&device).unwrap(), device.device_id],
        )
        .unwrap();
    assert_eq!(
        h.helper
            .lock()
            .unwrap()
            .store
            .device(&device.device_id, "account")
            .unwrap(),
        device
    );
    assert_eq!(
        h.exchange(Caller::Mcp, Op::Status, json!({})).await["result"]["approvers"][0]
            ["attestation"],
        "unverified"
    );
    let mut grant = signed_grant(&h, "future", Tier::T1, 1);
    grant
        .extra
        .insert("unknown-top".into(), json!({"retain":true,"nullable":null}));
    grant.sig = sign_object(&grant, SignatureAlgorithm::ES256, key("strong").as_ref()).unwrap();
    h.helper
        .install_grant(&grant, ApprovalLevel::Strong)
        .unwrap();
    let mut directive = signed_directive(
        &h,
        DirectiveOp::QueryStatus,
        json!({}),
        ApprovalLevel::Quick,
    );
    directive
        .extra
        .insert("unknown-top".into(), json!({"retain":true}));
    directive.sig =
        sign_object(&directive, SignatureAlgorithm::ES256, key("quick").as_ref()).unwrap();
    h.helper
        .apply_directive(&directive, ApprovalLevel::Quick)
        .unwrap();
    let mut envelope = h.envelope(EnvelopeType::Directive, &directive.id, &directive);
    envelope.v = 2;
    assert_eq!(
        h.exchange(
            Caller::RelayClient,
            Op::RelayInbound,
            json!({"envelope":envelope})
        )
        .await["result"]["ack"],
        true
    );
    h.reason("unsupported_version");
}

#[tokio::test]
async fn audit_failure_rolls_back_authority_and_does_not_execute() {
    let h = Harness::new();
    let request = h.helper.submit(h.input(Tier::T1, "A")).unwrap();
    let decision = h.decision(&request, ApprovalLevel::Quick, ScopeMode::PerCredential);
    h.audit.fail.store(true, Ordering::SeqCst);
    assert_eq!(
        h.helper
            .inbound(h.envelope(
                EnvelopeType::ApprovalDecision,
                &request.approval_id,
                &decision
            ))
            .await
            .unwrap_err(),
        Error("audit_unavailable")
    );
    let state = h.helper.lock().unwrap();
    assert_eq!(
        state.store.pending(&request.approval_id).unwrap().state,
        PendingState::Waiting
    );
    assert_eq!(
        state
            .store
            .db
            .query_row("SELECT COUNT(*) FROM grants", [], |r| r.get::<_, u64>(0))
            .unwrap(),
        0
    );
    assert_eq!(
        state
            .store
            .db
            .query_row("SELECT COUNT(*) FROM nonces", [], |r| r.get::<_, u64>(0))
            .unwrap(),
        0
    );
    assert_eq!(h.runner.calls.load(Ordering::SeqCst), 0);
}

#[test]
fn audit_chain_binds_every_entry_in_order() {
    let h = Harness::new();
    h.helper
        .set_mode_local("per_use", ApprovalLevel::Quick)
        .unwrap();
    h.helper
        .set_mode_local("per_credential", ApprovalLevel::Strong)
        .unwrap();
    let mut previous = "0".repeat(64);
    for entry in h.audit.entries.lock().unwrap().iter() {
        assert_eq!(entry["remote_prev_hash"], previous);
        let mut raw = entry.clone();
        let hash = raw.as_object_mut().unwrap().remove("remote_hash").unwrap();
        raw.as_object_mut().unwrap().remove("remote_prev_hash");
        let mut bytes = previous.as_bytes().to_vec();
        bytes.extend(jcs(&raw).unwrap());
        previous = sha256_hex(&bytes);
        assert_eq!(hash, previous);
    }
}
