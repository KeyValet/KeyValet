use super::flows::*;
use super::view::*;
use super::*;
use kv_ipc::remote::{
    DeviceKeyError, DeviceKeyProvider, Presence, PresenceProbe, PresenceState, Request,
    SignatureAlgorithm,
};
use serde_json::{json, Value};
use std::cell::RefCell;
use std::rc::Rc;

fn en(_: &str, en: &str) -> String {
    en.into()
}
fn zh(zh: &str, _: &str) -> String {
    zh.into()
}
fn samples() -> Value {
    serde_json::from_str(
        &std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../kv-core/testdata/remote/schema_samples.json"),
        )
        .unwrap(),
    )
    .unwrap()
}
fn sample(name: &str) -> Value {
    samples()["samples"]
        .as_array()
        .unwrap()
        .iter()
        .find(|v| v["type"] == name)
        .unwrap()["value"]
        .clone()
}
fn context() -> DisplayContext {
    DisplayContext {
        now: 1760200000,
        ..Default::default()
    }
}
fn view(request: &Value) -> ApprovalView {
    ApprovalView::with_text(request, context(), Platform::Macos, en).unwrap()
}

#[test]
fn operation_is_primary_and_only_public_fields_reach_the_renderer() {
    let mut request = sample("ApprovalRequest");
    for key in ["secret", "headers", "body", "vault_path"] {
        request[key] = json!("FORBIDDEN");
    }
    request["requester"]["protection"]["attestation"] = json!({"doc":"FORBIDDEN"});
    request["operation"]["body"] = json!("FORBIDDEN");
    let view = view(&request);
    assert!(
        view.title.contains("srv")
            && view.title.contains("claude-code")
            && view.title.contains("GitHub")
    );
    assert_eq!(view.summary, request["operation"]["summary"]);
    let payload = view.payload().to_string();
    for forbidden in [
        "FORBIDDEN",
        request["digest"].as_str().unwrap(),
        request["nonce"].as_str().unwrap(),
        "vault_path",
        "query_keys",
    ] {
        assert!(!payload.contains(forbidden));
    }
    assert!(view
        .rows
        .iter()
        .any(|row| row.label == "Agent's description" && row.secondary));
    assert!(
        payload.contains("Proxy only")
            && payload.contains("oauth2")
            && payload.contains("/home/u/proj")
    );
    assert_eq!(view.scopes[view.selected].value, request["requested_scope"]);
    assert_eq!(view.original, request);
}

#[test]
fn all_kinds_tiers_protection_and_localized_buttons() {
    for kind in ["use", "unlock", "admin"] {
        for tier in ["T0", "T1", "T2"] {
            let mut request = sample("ApprovalRequest");
            request["kind"] = json!(kind);
            request["tier"] = json!(tier);
            if kind == "unlock" {
                request["credential"] = Value::Null;
                request["operation"] = Value::Null;
            }
            if kind == "admin" {
                request["operation"]["summary"] = json!("admin.add_device");
                request["credential"] = Value::Null;
            }
            if tier == "T2" {
                request["scope_options"] = json!(["per_use"]);
                request["requested_scope"] = json!("per_use");
            }
            for protection in [
                "tpm2",
                "secure_enclave",
                "windows_hello",
                "software_key",
                "future",
            ] {
                request["requester"]["protection"]["kind"] = json!(protection);
                let view = view(&request);
                assert_eq!(
                    view.scopes[view.selected].level,
                    if kind != "use" || tier == "T2" {
                        Level::Strong
                    } else {
                        Level::Quick
                    }
                );
                assert!(view
                    .rows
                    .iter()
                    .any(|row| row.label == "Risk" && row.red == (tier == "T2")));
                if protection == "software_key" || protection == "future" {
                    assert!(view.rows.iter().any(|r| r.label == "Protection" && r.red));
                }
            }
            let chinese =
                ApprovalView::with_text(&request, context(), Platform::Windows, zh).unwrap();
            assert!(chinese.rows.iter().any(|row| row.label == "agent 自述"));
            assert!(chinese.title.contains("请求使用"));
            if tier == "T2" {
                assert!(chinese
                    .rows
                    .iter()
                    .any(|row| row.red && row.value.contains("不能预授权")));
            }
        }
    }
    let mut request = sample("ApprovalRequest");
    request["min_level"] = json!("strong");
    assert!(view(&request)
        .scopes
        .iter()
        .all(|s| s.level == Level::Strong));
    request["operation"]["summary"] = json!("");
    assert!(view(&request).summary.starts_with("POST api.github.com/"));
    request["credential"]["proxy_only"] = json!(false);
    assert!(view(&request)
        .payload()
        .to_string()
        .contains("Direct use allowed"));
}

#[test]
fn anomalies_and_unattended_are_separate_context() {
    let mut request = sample("ApprovalRequest");
    request["merged_count"] = json!(8);
    for skew in [-61, 61, i64::MIN] {
        let ctx = DisplayContext {
            clock_skew_s: Some(skew),
            backlog_count: 9,
            created_at: Some(1760199400),
            unattended: true,
            ..context()
        };
        let view = ApprovalView::with_text(&request, ctx, Platform::Macos, en).unwrap();
        assert!(view.title_red && view.title.starts_with("Unattended"));
        assert!(view
            .rows
            .iter()
            .any(|row| row.label == "Clock offset" && row.red));
        assert!(view
            .rows
            .iter()
            .any(|row| row.value.contains("8 requests merged")));
        assert!(view
            .rows
            .iter()
            .any(|row| row.value.contains("10 minutes ago")));
    }
    for skew in [-60, 0, 60] {
        let view = ApprovalView::with_text(
            &request,
            DisplayContext {
                clock_skew_s: Some(skew),
                ..context()
            },
            Platform::Macos,
            en,
        )
        .unwrap();
        assert!(!view.rows.iter().any(|row| row.label == "Clock offset"));
    }
    let view = ApprovalView::with_text(
        &request,
        DisplayContext {
            backlog_count: 2,
            ..context()
        },
        Platform::Macos,
        en,
    )
    .unwrap();
    assert!(view.rows.iter().any(|row| row.label == "Backlog"));
    assert!(DisplayContext::from_json(&json!({"clock_skew_s":"bad"})).is_err());
    assert!(DisplayContext::from_json(&json!({"backlog_count":-1})).is_err());
    assert!(DisplayContext::from_json(&json!({"unattended":"yes"})).is_err());
    assert!(DisplayContext::from_json(&json!({})).unwrap().now > 0);
}

#[test]
fn malformed_requests_fail_closed_without_rendering() {
    let base = sample("ApprovalRequest");
    for (pointer, bad) in [
        ("/kind", json!("future")),
        ("/tier", json!("T3")),
        ("/min_level", json!("none")),
        ("/exp", json!(0)),
        ("/scope_options", json!([])),
        ("/scope_options", json!(["per_use", "per_use"])),
        ("/scope_options", json!(["unattended"])),
        ("/requested_scope", json!("unattended")),
        ("/operation/path", json!("/issues?token=secret")),
        ("/purpose", json!("\u{202e}fake")),
        ("/merged_count", json!(0)),
        ("/agent/pid", json!(u64::MAX)),
        ("/credential/proxy_only", json!("true")),
        ("/operation/body_bytes", json!(-1)),
        ("/requester/protection", json!("tpm2")),
    ] {
        let mut request = base.clone();
        *request.pointer_mut(pointer).unwrap() = bad;
        assert!(
            ApprovalView::with_text(&request, context(), Platform::Macos, en).is_err(),
            "{pointer}"
        );
    }
    let mut request = base.clone();
    request["tier"] = json!("T2");
    assert!(ApprovalView::new(&request, context(), Platform::Macos).is_err());
    request = base.clone();
    request["kind"] = json!("unlock");
    assert!(ApprovalView::new(&request, context(), Platform::Macos).is_err());
    request = base;
    request["purpose"] = json!("x".repeat(8193));
    assert!(ApprovalView::new(&request, context(), Platform::Macos).is_err());
    assert!(ApprovalView::new(&Value::Null, context(), Platform::Macos).is_err());
}

#[test]
fn every_offered_scope_maps_to_decision_and_grant() {
    let request = sample("ApprovalRequest");
    let issuer = sample("DeviceRecord");
    let view = view(&request);
    for (scope, mode, level, hours) in [
        ("per_use", "per_use", "credential", 0),
        ("per_credential", "per_credential", "credential", 0),
        ("per_session", "per_session", "device", 0),
        ("remember:1h", "remember", "credential", 1),
        ("remember:8h", "remember", "credential", 8),
        ("remember:24h", "remember", "credential", 24),
        ("standing:credential", "standing", "credential", 0),
        ("standing:device", "standing", "device", 0),
    ] {
        let params = ApprovalFlow::decision_params(
            &view,
            Selection::Allow {
                scope: scope.into(),
            },
            context().now,
        )
        .unwrap();
        assert_eq!(params["scope"]["mode"], mode);
        assert_eq!(params["scope"]["level"], level);
        assert_eq!(
            params["scope"]["until"],
            if hours > 0 {
                context().now + hours * 3600
            } else {
                0
            }
        );
        assert_eq!(
            params["level"],
            if scope.starts_with("standing:") {
                "strong"
            } else {
                "quick"
            }
        );
        let typed: kv_ipc::remote::DecideParams = serde_json::from_value(params).unwrap();
        assert_eq!(typed.approval_id, request["approval_id"]);
        let grant = grant_for_scope(
            &request,
            scope,
            &issuer,
            "test",
            context().now,
            context().now + 600,
        )
        .unwrap();
        if scope == "per_use" {
            assert!(grant.is_none());
            continue;
        }
        let grant = grant.unwrap();
        assert_eq!(grant["scope"]["level"], level);
        assert_eq!(grant["scope"]["max_tier"], "T1");
        assert_eq!(
            grant["exp"],
            if scope.starts_with("standing:") {
                Value::Null
            } else {
                json!(context().now + if hours > 0 { hours * 3600 } else { 600 })
            }
        );
    }
    assert!(decision_scope("remember:2h", 0).is_err());
    assert!(decision_scope("remember:24h", i64::MAX).is_err());
    assert!(grant_for_scope(
        &request,
        "per_credential",
        &issuer,
        "test",
        context().now,
        0
    )
    .is_err());
    assert!(grant_for_scope(&request, "standing:global", &issuer, "test", 0, 100).is_err());
    let mut t2 = request;
    t2["tier"] = json!("T2");
    assert!(grant_for_scope(&t2, "per_credential", &issuer, "test", 0, 100).is_err());
}

struct FakeDialog {
    selection: Selection,
    labels: Vec<Option<String>>,
    pair: bool,
    events: Rc<RefCell<Vec<&'static str>>>,
}
impl FakeDialog {
    fn new() -> Self {
        Self {
            selection: Selection::Allow {
                scope: "per_use".into(),
            },
            labels: vec![Some("srv".into()), Some("srv".into())],
            pair: true,
            events: Default::default(),
        }
    }
}
impl Dialog for FakeDialog {
    fn confirm_global(&mut self, view: &GlobalGrantView) -> Result<bool> {
        assert!(view.message.contains("future") || view.message.contains("以后"));
        self.events.borrow_mut().push("global");
        Ok(self.pair)
    }
    fn approval(&mut self, _: &ApprovalView) -> Result<Selection> {
        Ok(self.selection.clone())
    }
    fn pairing(&mut self, _: &PairingView) -> Result<bool> {
        self.events.borrow_mut().push("pair");
        Ok(self.pair)
    }
    fn confirm_label(&mut self, _: &ConfirmationView) -> Result<Option<String>> {
        self.events.borrow_mut().push("label");
        Ok(self.labels.remove(0))
    }
}
struct FakeHelper {
    requests: Vec<Request>,
    response: Value,
}
impl FakeHelper {
    fn new(result: Value) -> Self {
        Self {
            requests: vec![],
            response: json!({"ok":true,"result":result}),
        }
    }
}
impl Helper for FakeHelper {
    fn exchange(&mut self, request: &Request) -> Result<Value> {
        self.requests.push(request.clone());
        if self.response["ok"] == true
            && request.op == kv_ipc::remote::Op::GrantIssue
            && request.params["scope"]["max_tier"] == "T2"
        {
            let first = request.params.get("confirmation_token").is_none();
            let second = request.params["exp"].is_null()
                && request.params["confirmation_token"] == "first-token";
            if first || second {
                return Ok(
                    json!({"ok":true,"result":{"confirmation_token":if first {"first-token"} else {"second-token"},
                    "expires_at":super::view::unix_seconds()+120,"device_id":request.params["aud"],"label":"srv",
                    "confirmations_left":if first && request.params["exp"].is_null(){2}else{1}}}),
                );
            }
        }
        Ok(self.response.clone())
    }
}
struct Gate {
    fail: bool,
    events: Rc<RefCell<Vec<&'static str>>>,
}
impl StrongAuthorization for Gate {
    fn authorize(&mut self, _: &Value) -> Result<()> {
        self.events.borrow_mut().push("strong");
        if self.fail {
            Err(Error::KeyUnavailable)
        } else {
            Ok(())
        }
    }
}

#[test]
fn approval_cancel_deny_expiry_and_helper_failure_never_send_allow() {
    let view = view(&sample("ApprovalRequest"));
    let mut dialog = FakeDialog::new();
    let mut helper = FakeHelper::new(json!({"sent":true}));
    ApprovalFlow::run(&view, &mut dialog, &mut helper, &|| context().now).unwrap();
    assert_eq!(helper.requests[0].op, kv_ipc::remote::Op::Decide);
    dialog.selection = Selection::Deny {
        reason: Some("Please inspect the operation".into()),
    };
    ApprovalFlow::run(&view, &mut dialog, &mut helper, &|| context().now).unwrap();
    assert_eq!(helper.requests[1].params["decision"], "deny");
    assert_eq!(
        helper.requests[1].params["reason"],
        "Please inspect the operation"
    );
    dialog.selection = Selection::Cancel;
    assert_eq!(
        ApprovalFlow::run(&view, &mut dialog, &mut helper, &|| context().now),
        Err(Error::Cancelled)
    );
    dialog.selection = Selection::Allow {
        scope: "standing:global".into(),
    };
    assert_eq!(
        ApprovalFlow::run(&view, &mut dialog, &mut helper, &|| context().now),
        Err(Error::InvalidScope)
    );
    dialog.selection = Selection::Allow {
        scope: "per_use".into(),
    };
    assert_eq!(
        ApprovalFlow::run(&view, &mut dialog, &mut helper, &|| i64::MAX),
        Err(Error::Expired)
    );
    assert_eq!(helper.requests.len(), 2);
    helper.response = json!({"ok":false,"error":{"message":"FORBIDDEN"}});
    assert_eq!(
        ApprovalFlow::run(&view, &mut dialog, &mut helper, &|| context().now),
        Err(Error::HelperUnavailable)
    );
    helper.response = json!({"ok":true,"result":{}});
    assert_eq!(
        ApprovalFlow::run(&view, &mut dialog, &mut helper, &|| context().now),
        Err(Error::InvalidResponse)
    );
    for reason in ["too\nlong".into(), "x".repeat(513)] {
        assert!(ApprovalFlow::decision_params(
            &view,
            Selection::Deny {
                reason: Some(reason)
            },
            context().now
        )
        .is_err());
    }
}

#[test]
fn directive_direction_matches_w0_contract_for_every_op() {
    let mut state = DirectiveState {
        mode: Some("per_credential".into()),
        unlock_ttl_s: Some(3600),
        ..Default::default()
    };
    state
        .classes
        .insert("batch".into(), (json!({"host":"example.com"}), 600));
    for (op, args, level) in [
        ("set_mode", json!({"mode":"per_use"}), Level::Quick),
        ("set_mode", json!({"mode":"per_session"}), Level::Strong),
        ("set_unlock_ttl", json!({"seconds":600}), Level::Quick),
        ("set_unlock_ttl", json!({"seconds":7200}), Level::Strong),
        (
            "set_class",
            json!({"name":"batch","match":{"host":"example.com"},"exp_s":300}),
            Level::Quick,
        ),
        (
            "set_class",
            json!({"name":"batch","match":{"host":"other.com"},"exp_s":300}),
            Level::Strong,
        ),
        (
            "set_class",
            json!({"name":"batch","match":{"host":"example.com"},"exp_s":900}),
            Level::Strong,
        ),
        ("set_device_label", json!({"label":"new"}), Level::Strong),
        (
            "revoke_device",
            json!({"device_id":"dev_old"}),
            Level::Strong,
        ),
        ("revoke_grant", json!({"jti":"ticket"}), Level::Quick),
        ("revoke_all_grants", json!({}), Level::Quick),
        ("lock", json!({}), Level::Quick),
        ("cancel_approval", json!({"approval_id":"a"}), Level::Quick),
        ("query_status", json!({}), Level::Quick),
        ("query_pending", json!({}), Level::Quick),
        ("query_grants", json!({}), Level::Quick),
        ("query_audit", json!({"since":0,"limit":200}), Level::Quick),
        ("notify", json!({"policy":"both"}), Level::Quick),
    ] {
        assert_eq!(directive_level(op, &args, &state), Ok(level), "{op}");
    }
    assert_eq!(
        directive_level(
            "set_mode",
            &json!({"mode":"per_use"}),
            &DirectiveState::default()
        ),
        Err(Error::MissingState)
    );
    assert_eq!(
        directive_level(
            "set_unlock_ttl",
            &json!({"seconds":1}),
            &DirectiveState::default()
        ),
        Err(Error::MissingState)
    );
    for (op, args) in [
        ("unknown", json!({})),
        ("set_mode", json!({"mode":"anything"})),
        ("set_unlock_ttl", json!({"seconds":0})),
        ("set_class", json!({"name":"x","match":{},"exp_s":0})),
        ("query_audit", json!({"since":0,"limit":201})),
        ("notify", json!({"policy":"never"})),
    ] {
        assert!(directive_level(op, &args, &state).is_err());
    }
    state.mode = Some("remember:8h".into());
    assert_eq!(
        directive_level("set_mode", &json!({"mode":"remember:1h"}), &state),
        Ok(Level::Quick)
    );
    assert_eq!(
        directive_level("set_mode", &json!({"mode":"remember:24h"}), &state),
        Ok(Level::Strong)
    );
    assert_eq!(
        directive_level("set_mode", &json!({"mode":"remember:0h"}), &state),
        Ok(Level::Strong)
    );
}

fn executor() -> Value {
    json!({"device_id":"dev_srv","label":"srv","caps":["execute"]})
}
fn grant(tier: &str) -> Value {
    json!({"jti":"01J9W000000000000000000003","aud":"dev_srv","scope":{"level":"device","max_tier":tier}})
}
#[test]
fn unattended_requires_strong_then_exact_label_and_standing_requires_it_twice() {
    let local = sample("DeviceRecord");
    let executor = executor();
    for standing in [false, true] {
        let plan = GrantPlan::settings(
            grant("T2"),
            &local,
            &executor,
            100,
            standing,
            Platform::Macos,
        )
        .unwrap();
        assert_eq!(
            plan.unsigned["exp"],
            if standing {
                Value::Null
            } else {
                json!(100 + 604800)
            }
        );
        let mut dialog = FakeDialog::new();
        let mut gate = Gate {
            fail: false,
            events: dialog.events.clone(),
        };
        let mut helper = FakeHelper::new(json!({"grant":{"sig":"signed"}}));
        plan.issue(&mut dialog, &mut helper, &mut gate).unwrap();
        assert_eq!(
            *dialog.events.borrow(),
            if standing {
                vec!["strong", "label", "label"]
            } else {
                vec!["strong", "label"]
            }
        );
        assert!(helper.requests[0].params.get("confirm").is_none());
        assert_eq!(helper.requests.last().unwrap().params["confirm"], "srv");
        assert_eq!(helper.requests.len(), if standing { 3 } else { 2 });
        assert!(helper.requests[0].params.get("sig").is_none());
    }
    for typed in [None, Some("SRV".into()), Some(" srv".into())] {
        let plan = GrantPlan::settings(grant("T2"), &local, &executor, 100, false, Platform::Macos)
            .unwrap();
        let mut dialog = FakeDialog::new();
        dialog.labels = vec![typed];
        let mut gate = Gate {
            fail: false,
            events: dialog.events.clone(),
        };
        let mut helper = FakeHelper::new(json!({}));
        assert_eq!(
            plan.issue(&mut dialog, &mut helper, &mut gate),
            Err(Error::ConfirmationRequired)
        );
        assert_eq!(helper.requests.len(), 1);
        assert!(helper.requests[0].params.get("confirm").is_none());
    }
    let plan =
        GrantPlan::settings(grant("T1"), &local, &executor, 100, true, Platform::Windows).unwrap();
    let mut dialog = FakeDialog::new();
    let mut gate = Gate {
        fail: true,
        events: dialog.events.clone(),
    };
    let mut helper = FakeHelper::new(json!({}));
    assert_eq!(
        plan.issue(&mut dialog, &mut helper, &mut gate),
        Err(Error::KeyUnavailable)
    );
    assert!(helper.requests.is_empty());
    assert_eq!(*dialog.events.borrow(), vec!["strong"]);
    let mut global = grant("T2");
    global["aud"] = json!("*");
    global["scope"]["level"] = json!("global");
    assert!(GrantPlan::settings(global, &local, &executor, 100, true, Platform::Macos).is_err());
}

#[test]
fn wake_batch_caps_five_across_multiple_deliveries() {
    let mut queue = queue::WakeQueue::default();
    let mut requests = Vec::new();
    for index in 0..12 {
        let mut request = sample("ApprovalRequest");
        request["approval_id"] = json!(format!("request{index}"));
        request["delivery"]["mode"] = json!(if index == 0 { "silent" } else { "banner" });
        requests.push(request);
    }
    let first = queue.enqueue(&requests, context().now).unwrap();
    assert_eq!(first.popups.len(), 5);
    assert_eq!(first.remaining_ids.len(), 7);
    assert!(queue
        .enqueue(&requests, context().now)
        .unwrap()
        .popups
        .is_empty());
    let mut extra = requests[1].clone();
    extra["approval_id"] = json!("extra");
    assert_eq!(
        queue
            .enqueue(&[extra], context().now)
            .unwrap()
            .remaining_ids,
        vec!["extra"]
    );
    queue.wake();
    assert_eq!(
        queue
            .enqueue(&requests, context().now)
            .unwrap()
            .popups
            .len(),
        5
    );
    queue.wake();
    assert!(queue
        .enqueue(&requests, i64::MAX)
        .unwrap()
        .popups
        .is_empty());
}

struct Provider {
    jwk: Value,
    fail: bool,
    signs: RefCell<Vec<Vec<u8>>>,
}
impl DeviceKeyProvider for Provider {
    fn sign(
        &self,
        _: SignatureAlgorithm,
        payload: &[u8],
    ) -> std::result::Result<Vec<u8>, DeviceKeyError> {
        self.signs.borrow_mut().push(payload.to_vec());
        if self.fail {
            Err(DeviceKeyError::Unavailable)
        } else {
            Ok(vec![1; 64])
        }
    }
    fn ecdh(&self, _: &[u8]) -> std::result::Result<zeroize::Zeroizing<[u8; 32]>, DeviceKeyError> {
        Err(DeviceKeyError::UnsupportedAlgorithm)
    }
    fn public_jwk(&self) -> std::result::Result<Value, DeviceKeyError> {
        if self.jwk.is_null() {
            Err(DeviceKeyError::Unavailable)
        } else {
            Ok(self.jwk.clone())
        }
    }
    fn presence_kind(&self) -> &str {
        "touchid"
    }
    fn key_kind(&self) -> &str {
        "secure_enclave"
    }
}
struct Crypto(bool);
impl ObjectCrypto for Crypto {
    fn canonical_unsigned(&self, value: &Value) -> Result<Vec<u8>> {
        Ok(value.to_string().into_bytes())
    }
    fn verify(&self, _: SignatureAlgorithm, _: &Value, _: &[u8], _: &[u8]) -> Result<()> {
        if self.0 {
            Ok(())
        } else {
            Err(Error::KeyUnavailable)
        }
    }
}
#[test]
fn sas_object_is_signed_by_the_pinned_strong_key() {
    let local = sample("DeviceRecord");
    let peer = executor();
    let mut peer = peer;
    peer["os"] = json!("linux");
    peer["key_kind"] = json!("tpm2");
    let mut provider = Provider {
        jwk: local["ak_s"]["pub"].clone(),
        fail: false,
        signs: Default::default(),
    };
    let flow = PairingFlow {
        local: &local,
        peer: &peer,
        sas: "012345",
        platform: Platform::Macos,
    };
    let mut dialog = FakeDialog::new();
    let mut helper = FakeHelper::new(json!({}));
    flow.run(&mut dialog, &mut helper, &provider, &Crypto(true))
        .unwrap();
    assert_eq!(provider.signs.borrow()[0], br#"{"sas":"012345"}"#);
    assert_eq!(helper.requests[0].op, kv_ipc::remote::Op::PairConfirm);
    dialog.pair = false;
    assert_eq!(
        flow.run(&mut dialog, &mut helper, &provider, &Crypto(true)),
        Err(Error::Cancelled)
    );
    dialog.pair = true;
    provider.fail = true;
    assert_eq!(
        flow.run(&mut dialog, &mut helper, &provider, &Crypto(true)),
        Err(Error::KeyUnavailable)
    );
    provider.fail = false;
    assert_eq!(
        flow.run(&mut dialog, &mut helper, &provider, &Crypto(false)),
        Err(Error::KeyUnavailable)
    );
    provider.jwk = json!({});
    assert_eq!(
        flow.run(&mut dialog, &mut helper, &provider, &Crypto(true)),
        Err(Error::KeyUnavailable)
    );
    assert_eq!(helper.requests.len(), 1);
    for sas in ["12345", "1234567", "１２３", "abcdef"] {
        assert!(PairingView::new(&peer, sas, Platform::Windows).is_err());
    }
    let mut gate = KeyAuthorization {
        provider: &provider,
        local: &local,
        crypto: &Crypto(true),
    };
    assert_eq!(gate.authorize(&json!({})), Err(Error::KeyUnavailable));
}

#[test]
fn presence_uses_the_w1_probe_and_sends_only_coarse_state() {
    struct Probe(RefCell<PresenceState>);
    impl PresenceProbe for Probe {
        fn state(&self) -> PresenceState {
            self.0.borrow().clone()
        }
    }
    struct Sink(Vec<Request>);
    impl crate::presence::PresenceSink for Sink {
        fn send(&mut self, request: &Request) -> std::io::Result<()> {
            self.0.push(request.clone());
            Ok(())
        }
    }
    let probe = Probe(RefCell::new(PresenceState {
        state: Presence::Away,
        since: 10,
        signals: serde_json::from_value(json!({})).unwrap(),
        extra: Default::default(),
    }));
    let mut sink = Sink(vec![]);
    let mut reporter = crate::presence::PresenceReporter::new("dev_mac".into());
    assert!(reporter.update(&probe, &mut sink, 10).unwrap());
    assert!(!reporter.update(&probe, &mut sink, 14).unwrap());
    probe.0.borrow_mut().state = Presence::Present;
    probe.0.borrow_mut().since = 15;
    assert!(reporter.update(&probe, &mut sink, 20).unwrap());
    assert!(sink
        .0
        .iter()
        .all(|r| r.op == kv_ipc::remote::Op::PresenceUpdate && r.params.get("signals").is_none()));
}

#[test]
fn mutated_presentation_cannot_change_signed_authority() {
    let mut request = sample("ApprovalRequest");
    request["tier"] = json!("T2");
    request["scope_options"] = json!(["per_use"]);
    request["requested_scope"] = json!("per_use");
    let mut view = view(&request);
    view.scopes[0].level = Level::Quick;
    view.selected = usize::MAX;
    let params =
        ApprovalFlow::decision_params(&view, Selection::Deny { reason: None }, context().now)
            .unwrap();
    assert_eq!(params["level"], "strong");
    view.scopes[0].value = "standing:device".into();
    assert_eq!(
        ApprovalFlow::decision_params(
            &view,
            Selection::Allow {
                scope: "standing:device".into()
            },
            context().now
        ),
        Err(Error::InvalidScope)
    );
}

#[test]
fn desktop_dispatch_enforces_one_wake_budget_and_allows_silent_escalation() {
    let now = context().now;
    let mut admission = queue::DesktopAdmission::default();
    assert!(!admission.admit(&json!({"op":"remote_wake"}), now).unwrap());
    let mut request = sample("ApprovalRequest");
    request["delivery"]["mode"] = json!("silent");
    let mut input = json!({"op":"remote_approval","request":request,"context":{"backlog_count":8}});
    assert!(!admission.admit(&input, now).unwrap());
    input["request"]["delivery"]["mode"] = json!("banner");
    for index in 0..8 {
        input["request"]["approval_id"] = json!(format!("pending{index}"));
        assert_eq!(admission.admit(&input, now).unwrap(), index < 5);
        assert!(!admission.admit(&input, now).unwrap());
    }
    admission.admit(&json!({"op":"remote_wake"}), now).unwrap();
    assert!(admission.admit(&input, now).unwrap());
    input["request"]["exp"] = json!(now - 1);
    assert_eq!(admission.admit(&input, now), Err(Error::Expired));
    assert!(admission.admit(&json!({"op":"device_key"}), now).unwrap());
    let mut queue = queue::WakeQueue::default();
    request["delivery"]["mode"] = json!("silent");
    assert!(queue
        .enqueue(&[request.clone()], now)
        .unwrap()
        .popups
        .is_empty());
    request["delivery"]["mode"] = json!("banner");
    assert_eq!(
        queue
            .enqueue(&[request.clone(), request], now)
            .unwrap()
            .popups
            .len(),
        1
    );
}

#[test]
fn grant_settings_reject_invalid_boundaries_and_global_requires_warning_and_strong() {
    let local = sample("DeviceRecord");
    let executor = executor();
    for (pointer, bad) in [
        ("/aud", json!("other")),
        ("/scope/level", json!("future")),
        ("/scope/max_tier", json!("T3")),
        ("/jti", Value::Null),
    ] {
        let mut input = grant("T1");
        *input.pointer_mut(pointer).unwrap() = bad;
        assert!(
            GrantPlan::settings(input, &local, &executor, 100, false, Platform::Macos).is_err()
        );
    }
    for extra in [
        json!({"exp":null}),
        json!({"exp":100}),
        json!({"sig":"signed"}),
        json!({"budget":{"calls":0,"per":"1h"}}),
        json!({"budget":{"calls":5,"per":"2h"}}),
    ] {
        let mut input = grant("T1");
        input
            .as_object_mut()
            .unwrap()
            .extend(extra.as_object().unwrap().clone());
        assert!(
            GrantPlan::settings(input, &local, &executor, 100, false, Platform::Macos).is_err()
        );
    }
    let mut input = grant("T1");
    input["scope"]["level"] = json!("credential");
    assert!(GrantPlan::settings(
        input.clone(),
        &local,
        &executor,
        100,
        false,
        Platform::Macos
    )
    .is_err());
    input["scope"]["credential"] = json!("github");
    input["budget"] = json!({"calls":5,"per":"24h"});
    input["confirm"] = json!("untrusted");
    let plan = GrantPlan::settings(input, &local, &executor, 100, false, Platform::Macos).unwrap();
    assert_eq!(plan.unsigned["exp"], 100 + 86400);
    assert!(plan.unsigned.get("confirm").is_none());
    let mut global = grant("T1");
    global["aud"] = json!("*");
    global["scope"]["level"] = json!("global");
    for confirmed in [false, true] {
        let plan = GrantPlan::settings(
            global.clone(),
            &local,
            &executor,
            100,
            true,
            Platform::Windows,
        )
        .unwrap();
        let mut dialog = FakeDialog::new();
        dialog.pair = confirmed;
        let mut gate = Gate {
            fail: false,
            events: dialog.events.clone(),
        };
        let mut helper = FakeHelper::new(json!({"grant":{"sig":"signed"}}));
        let result = plan.issue(&mut dialog, &mut helper, &mut gate);
        if confirmed {
            assert!(result.is_ok());
            assert_eq!(*dialog.events.borrow(), vec!["global", "strong"]);
        } else {
            assert_eq!(result, Err(Error::Cancelled));
            assert!(helper.requests.is_empty());
        }
    }
}

#[test]
fn directive_plans_bind_algorithm_expiry_and_confirmation_before_helper() {
    let mut local = sample("DeviceRecord");
    local["ak_s"]["alg"] = json!("RS256");
    let state = DirectiveState {
        mode: Some("per_credential".into()),
        ..Default::default()
    };
    let executor = executor();
    for (op, args, level) in [
        ("lock", json!({}), Level::Quick),
        ("set_mode", json!({"mode":"per_session"}), Level::Strong),
        (
            "revoke_device",
            json!({"device_id":"dev_old","confirm":"untrusted"}),
            Level::Strong,
        ),
    ] {
        let input =
            json!({"id":"directive","aud":"dev_srv","op":op,"args":args,"exp":200,"nonce":"nonce"});
        let plan = DirectivePlan::new(
            input.clone(),
            &local,
            &executor,
            &state,
            100,
            Platform::Windows,
        )
        .unwrap();
        assert_eq!(plan.level, level);
        assert_eq!(
            plan.unsigned["iss_alg"],
            if level == Level::Quick {
                "ES256"
            } else {
                "RS256"
            }
        );
        let mut dialog = FakeDialog::new();
        let mut gate = Gate {
            fail: false,
            events: dialog.events.clone(),
        };
        let mut helper = FakeHelper::new(json!({"result":{"ok":true}}));
        plan.issue(&mut dialog, &mut helper, &mut gate).unwrap();
        assert_eq!(helper.requests[0].op, kv_ipc::remote::Op::DirectiveIssue);
        if op == "revoke_device" {
            assert_eq!(*dialog.events.borrow(), vec!["strong", "label"]);
            assert_eq!(helper.requests[0].params["args"]["confirm"], "srv");
            let view = ConfirmationView::revocation("srv").unwrap();
            assert!(view.message.contains("revoke") || view.message.contains("吊销"));
        } else {
            assert_eq!(
                *dialog.events.borrow(),
                if level == Level::Strong {
                    vec!["strong"]
                } else {
                    vec![]
                }
            );
        }
        for (key, bad) in [
            ("exp", json!(99)),
            ("exp", json!(701)),
            ("aud", json!("other")),
            ("sig", json!("signed")),
            ("nonce", Value::Null),
        ] {
            let mut malformed = input.clone();
            malformed[key] = bad;
            assert!(
                DirectivePlan::new(malformed, &local, &executor, &state, 100, Platform::Macos)
                    .is_err()
            );
        }
    }
    let input = json!({"id":"directive","aud":"dev_srv","op":"set_mode","args":{"mode":"per_session"},"exp":200,"nonce":"nonce"});
    let plan = DirectivePlan::new(input, &local, &executor, &state, 100, Platform::Macos).unwrap();
    let mut dialog = FakeDialog::new();
    let mut gate = Gate {
        fail: true,
        events: dialog.events.clone(),
    };
    let mut helper = FakeHelper::new(json!({"result":{"ok":true}}));
    assert_eq!(
        plan.issue(&mut dialog, &mut helper, &mut gate),
        Err(Error::KeyUnavailable)
    );
    assert!(helper.requests.is_empty());
}

#[test]
fn strong_gate_rejects_failed_signatures_and_wrong_local_key() {
    let local = sample("DeviceRecord");
    let mut provider = Provider {
        jwk: local["ak_s"]["pub"].clone(),
        fail: false,
        signs: Default::default(),
    };
    for (fail, verify, expected) in [
        (false, true, Ok(())),
        (true, true, Err(Error::KeyUnavailable)),
        (false, false, Err(Error::KeyUnavailable)),
    ] {
        provider.fail = fail;
        let mut gate = KeyAuthorization {
            provider: &provider,
            local: &local,
            crypto: &Crypto(verify),
        };
        assert_eq!(gate.authorize(&json!({"grant":"binding"})), expected);
    }
    assert!(provider
        .signs
        .borrow()
        .iter()
        .all(|bytes| bytes == b"{\"grant\":\"binding\"}"));
    let mut missing = local;
    missing["caps"] = json!([]);
    assert!(approval_key(&missing, Level::Strong).is_err());
    missing["caps"] = json!(["approve_strong"]);
    missing["ak_s"]["alg"] = json!("future");
    assert!(approval_key(&missing, Level::Strong).is_err());
    missing["ak_s"]["alg"] = json!("ES256");
    missing["ak_s"]["pub"] = Value::Null;
    assert!(approval_key(&missing, Level::Strong).is_err());
}

#[test]
fn dialog_dispatch_preserves_choices_confirmation_and_cancellation() {
    let now = unix_seconds();
    let mut request = sample("ApprovalRequest");
    request["exp"] = json!(now + 600);
    let input = json!({"op":"remote_approval","request":request,"context":{"now":now}});
    let mut dialog = FakeDialog::new();
    for platform in [Platform::Macos, Platform::Windows] {
        let reply = handle_dialog(&input, &mut dialog, platform).unwrap();
        assert_eq!(reply["params"]["scope"]["mode"], "per_use");
        assert_eq!(reply["params"]["decision"], "allow");
        dialog.selection = Selection::Deny { reason: None };
        assert_eq!(
            handle_dialog(&input, &mut dialog, platform).unwrap()["params"]["decision"],
            "deny"
        );
        dialog.selection = Selection::Cancel;
        assert_eq!(
            handle_dialog(&input, &mut dialog, platform),
            Err(Error::Cancelled)
        );
        dialog.selection = Selection::Allow {
            scope: "per_use".into(),
        };
    }
    let peer = sample("DeviceRecord");
    let pair = json!({"op":"remote_pair","peer":peer,"sas":"012345"});
    for confirmed in [true, false] {
        dialog.pair = confirmed;
        assert_eq!(
            handle_dialog(&pair, &mut dialog, Platform::Windows).unwrap()["confirmed"],
            confirmed
        );
        assert_eq!(
            handle_dialog(
                &json!({"op":"remote_confirm_global"}),
                &mut dialog,
                Platform::Macos
            )
            .unwrap()["confirmed"],
            confirmed
        );
    }
    for action in ["unattended", "revoke_device"] {
        for (typed, confirmed) in [
            (Some("srv".into()), true),
            (Some("SRV".into()), false),
            (None, false),
        ] {
            dialog.labels = vec![typed];
            let confirmation =
                json!({"op":"remote_confirm_label","action":action,"label":"srv","standing":true});
            assert_eq!(
                handle_dialog(&confirmation, &mut dialog, Platform::Macos).unwrap()["confirmed"],
                confirmed
            );
        }
    }
    assert_eq!(
        handle_dialog(&json!({"op":"unknown"}), &mut dialog, Platform::Macos),
        Err(Error::InvalidRequest)
    );
    assert_eq!(
        handle_dialog(
            &json!({"op":"remote_pair","peer":peer,"sas":"abcdef"}),
            &mut dialog,
            Platform::Macos
        ),
        Err(Error::InvalidRequest)
    );
    assert_eq!(
        handle_dialog(
            &json!({"op":"remote_confirm_label","label":""}),
            &mut dialog,
            Platform::Macos
        ),
        Err(Error::InvalidRequest)
    );
}

#[test]
fn native_payloads_and_default_global_confirmation_fail_closed() {
    struct WithoutGlobal;
    impl Dialog for WithoutGlobal {
        fn approval(&mut self, _: &ApprovalView) -> Result<Selection> {
            Err(Error::UiUnavailable)
        }
        fn pairing(&mut self, _: &PairingView) -> Result<bool> {
            Err(Error::UiUnavailable)
        }
        fn confirm_label(&mut self, _: &ConfirmationView) -> Result<Option<String>> {
            Err(Error::UiUnavailable)
        }
    }
    assert_eq!(
        WithoutGlobal.confirm_global(&GlobalGrantView::new(Platform::Macos)),
        Err(Error::UiUnavailable)
    );
    for platform in [Platform::Macos, Platform::Windows] {
        let pair = PairingView::new(&sample("DeviceRecord"), "000007", platform)
            .unwrap()
            .payload();
        assert_eq!(pair["summary"], "000007");
        assert!(pair["allow_label"]
            .as_str()
            .unwrap()
            .contains(platform.authentication()));
        assert_eq!(
            GlobalGrantView::new(platform).payload()["kind"],
            "global_grant"
        );
        for standing in [false, true] {
            let payload = ConfirmationView::new("srv", platform, standing)
                .unwrap()
                .payload();
            assert_eq!(payload["label"], "srv");
            assert_eq!(payload["title_red"], true);
        }
    }
    assert_eq!(
        ConfirmationView::revocation("srv").unwrap().payload()["kind"],
        "confirmation"
    );
    assert!(ConfirmationView::new(" \t", Platform::Macos, false).is_err());
    assert!(ConfirmationView::revocation(" \n").is_err());
    for value in ["\0hidden", "\u{2066}hidden"] {
        assert!(display_text(value).is_err());
    }
    let mut bad_peer = sample("DeviceRecord");
    bad_peer["caps"] = json!([true]);
    assert!(PairingView::new(&bad_peer, "000007", Platform::Macos).is_err());
    let codes = [
        (Error::InvalidRequest, "invalid_remote_request"),
        (Error::InvalidScope, "invalid_remote_scope"),
        (Error::Expired, "remote_request_expired"),
        (Error::MissingState, "remote_setting_unavailable"),
        (Error::Cancelled, "remote_action_cancelled"),
        (
            Error::ConfirmationRequired,
            "secondary_confirmation_required",
        ),
        (Error::KeyUnavailable, "approval_key_unavailable"),
        (Error::HelperUnavailable, "remote_helper_unavailable"),
        (Error::InvalidResponse, "invalid_remote_response"),
        (Error::UiUnavailable, "remote_ui_unavailable"),
    ];
    for (error, code) in codes {
        assert_eq!(error.to_string(), code);
    }
    assert_eq!(DisplayContext::from_json(&json!({"now":100,"created_at":null,"clock_skew_s":null,"backlog_count":0,"unattended":false})).unwrap().now, 100);
}

#[test]
fn denial_without_per_use_uses_the_original_default_and_omits_blank_reason() {
    let mut request = sample("ApprovalRequest");
    request["scope_options"] = json!(["per_session", "standing:device"]);
    request["requested_scope"] = json!("per_session");
    let params = ApprovalFlow::decision_params(
        &view(&request),
        Selection::Deny {
            reason: Some("  ".into()),
        },
        context().now,
    )
    .unwrap();
    assert_eq!(params["scope"]["mode"], "per_session");
    assert!(params.get("reason").is_none());
}

#[test]
fn failed_batch_does_not_consume_popup_budget_and_unknown_delivery_is_rejected() {
    let now = context().now;
    let mut request = sample("ApprovalRequest");
    request["delivery"]["mode"] = json!("banner");
    let mut invalid = request.clone();
    invalid["approval_id"] = json!("invalid");
    invalid["delivery"]["mode"] = json!("unknown");
    let mut queue = queue::WakeQueue::default();
    assert!(queue
        .enqueue(&[request.clone(), invalid.clone()], now)
        .is_err());
    assert_eq!(
        queue
            .enqueue(std::slice::from_ref(&request), now)
            .unwrap()
            .popups
            .len(),
        1
    );
    let mut admission = queue::DesktopAdmission::default();
    assert_eq!(
        admission.admit(&json!({"op":"remote_approval","request":invalid}), now),
        Err(Error::InvalidRequest)
    );
    assert!(admission
        .admit(&json!({"op":"remote_approval","request":request}), now)
        .unwrap());
    assert!(queue
        .enqueue(&[json!({"approval_id":"invalid","exp":"bad"})], now)
        .is_err());
}

#[test]
fn grant_preview_and_settings_validate_issuer_executor_and_expiry() {
    let local = sample("DeviceRecord");
    let mut request = sample("ApprovalRequest");
    request["min_level"] = json!("strong");
    let preview = grant_for_scope(
        &request,
        "per_session",
        &local,
        "preview",
        context().now,
        context().now + 60,
    )
    .unwrap()
    .unwrap();
    assert_eq!(preview["iss_alg"], "ES256");
    assert!(grant_for_scope(&json!({}), "per_session", &local, "preview", 100, 200).is_err());
    let mut incapable = executor();
    incapable["caps"] = json!([]);
    assert!(
        GrantPlan::settings(grant("T1"), &local, &incapable, 100, false, Platform::Macos).is_err()
    );
    let mut empty_credential = grant("T1");
    empty_credential["scope"]["level"] = json!("credential");
    empty_credential["scope"]["credential"] = json!("");
    assert!(GrantPlan::settings(
        empty_credential,
        &local,
        &executor(),
        100,
        false,
        Platform::Macos
    )
    .is_err());
    assert!(GrantPlan::settings(
        grant("T1"),
        &local,
        &executor(),
        i64::MAX,
        false,
        Platform::Macos
    )
    .is_err());
    let plan = GrantPlan::settings(
        grant("T0"),
        &local,
        &executor(),
        100,
        false,
        Platform::Macos,
    )
    .unwrap();
    assert_eq!(plan.unsigned()["nbf"], 100);
    let mut dialog = FakeDialog::new();
    let mut gate = Gate {
        fail: false,
        events: dialog.events.clone(),
    };
    let mut helper = FakeHelper::new(json!({"grant":{"sig":""}}));
    assert_eq!(
        plan.issue(&mut dialog, &mut helper, &mut gate),
        Err(Error::InvalidResponse)
    );
}

#[test]
fn helper_transport_and_rejected_directive_results_propagate_static_errors() {
    struct Unavailable;
    impl Helper for Unavailable {
        fn exchange(&mut self, _: &Request) -> Result<Value> {
            Err(Error::HelperUnavailable)
        }
    }
    let local = sample("DeviceRecord");
    let peer = sample("DeviceRecord");
    let provider = Provider {
        jwk: local["ak_s"]["pub"].clone(),
        fail: false,
        signs: Default::default(),
    };
    let flow = PairingFlow {
        peer: &peer,
        local: &local,
        sas: "000007",
        platform: Platform::Windows,
    };
    let mut dialog = FakeDialog::new();
    assert_eq!(
        flow.run(&mut dialog, &mut Unavailable, &provider, &Crypto(true)),
        Err(Error::HelperUnavailable)
    );
    let mut helper = FakeHelper {
        requests: vec![],
        response: json!({"ok":true}),
    };
    assert_eq!(
        flow.run(&mut dialog, &mut helper, &provider, &Crypto(true)),
        Err(Error::InvalidResponse)
    );
    for result in [
        json!({"result":{"ok":false,"error":"FORBIDDEN"}}),
        json!({"result":null}),
        json!({"result":{"ok":"true"}}),
    ] {
        let plan = DirectivePlan::new(
            json!({"id":"d","aud":"dev_srv","op":"lock","args":{},"exp":200,"nonce":"n"}),
            &local,
            &executor(),
            &DirectiveState::default(),
            100,
            Platform::Windows,
        )
        .unwrap();
        assert_eq!(plan.required_level(), Level::Quick);
        assert_eq!(plan.unsigned()["op"], "lock");
        let mut gate = Gate {
            fail: false,
            events: dialog.events.clone(),
        };
        let mut helper = FakeHelper::new(result.clone());
        let expected = if result["result"]["ok"] == false {
            Error::HelperUnavailable
        } else {
            Error::InvalidResponse
        };
        assert_eq!(
            plan.issue(&mut dialog, &mut helper, &mut gate),
            Err(expected)
        );
        assert!(dialog.events.borrow().iter().all(|event| *event == "pair"));
    }
    assert_eq!(
        directive_level("lock", &Value::Null, &DirectiveState::default()),
        Err(Error::InvalidRequest)
    );
    assert_eq!(
        directive_level(
            "set_device_label",
            &json!({"label":""}),
            &DirectiveState::default()
        ),
        Err(Error::InvalidRequest)
    );
}

#[test]
fn native_dialog_driver_validates_replies_without_a_gui_session() {
    use native::{NativeDialog, NativeUi};
    use std::path::{Path, PathBuf};
    struct Ui {
        reply: Result<Value>,
        seen: Vec<(Value, Option<PathBuf>)>,
    }
    impl NativeUi for Ui {
        fn show(&mut self, payload: &Value, screenshot: Option<&Path>) -> Result<Value> {
            self.seen
                .push((payload.clone(), screenshot.map(Path::to_owned)));
            self.reply.clone()
        }
    }
    let view = view(&sample("ApprovalRequest"));
    let pair = PairingView::new(&sample("DeviceRecord"), "000007", Platform::Macos).unwrap();
    let label = ConfirmationView::new("srv", Platform::Macos, false).unwrap();
    let global = GlobalGrantView::new(Platform::Macos);
    let mut dialog = NativeDialog::new(Ui {
        reply: Ok(json!({"decision":"allow","selected":view.selected})),
        seen: vec![],
    });
    assert_eq!(
        dialog.approval(&view).unwrap(),
        Selection::Allow {
            scope: view.scopes[view.selected].value.clone()
        }
    );
    for (reply, expected) in [
        (
            json!({"decision":"deny","reason":"inspect"}),
            Ok(Selection::Deny {
                reason: Some("inspect".into()),
            }),
        ),
        (json!({"decision":"cancel"}), Ok(Selection::Cancel)),
        (json!({"decision":"future"}), Err(Error::InvalidResponse)),
        (
            json!({"decision":"allow","selected":-1}),
            Err(Error::InvalidResponse),
        ),
        (
            json!({"decision":"allow","selected":900}),
            Err(Error::InvalidResponse),
        ),
    ] {
        dialog.backend.reply = Ok(reply);
        assert_eq!(dialog.approval(&view), expected);
    }
    for confirmed in [true, false] {
        dialog.backend.reply = Ok(json!({"confirmed":confirmed,"text":"srv"}));
        assert_eq!(dialog.pairing(&pair), Ok(confirmed));
        assert_eq!(dialog.confirm_global(&global), Ok(confirmed));
        assert_eq!(
            dialog.confirm_label(&label),
            Ok(confirmed.then(|| "srv".into()))
        );
    }
    dialog.backend.reply = Ok(json!({"confirmed":true}));
    assert_eq!(dialog.confirm_label(&label), Err(Error::InvalidResponse));
    dialog.backend.reply = Ok(json!({"confirmed":"true"}));
    assert_eq!(dialog.pairing(&pair), Err(Error::InvalidResponse));
    let path = Path::new("w6-preview.png");
    dialog.preview(&view, path).unwrap();
    dialog.preview_pairing(&pair, path).unwrap();
    assert_eq!(
        dialog.backend.seen.last().unwrap(),
        &(pair.payload(), Some(path.to_owned()))
    );
    dialog.backend.reply = Err(Error::UiUnavailable);
    assert_eq!(dialog.preview(&view, path), Err(Error::UiUnavailable));
    assert_eq!(dialog.approval(&view), Err(Error::UiUnavailable));
}

#[test]
fn raw_native_bridge_bounds_output_and_passes_only_public_payload() {
    use native::{NativeBridge, NativeUi, RawDialog};
    use std::path::Path;
    struct Abi {
        code: i32,
        length: usize,
        bytes: Vec<u8>,
        calls: RefCell<Vec<(Value, Vec<u8>)>>,
    }
    impl RawDialog for Abi {
        fn call(&self, input: &[u8], output: &mut [u8], length: &mut usize, preview: &[u8]) -> i32 {
            self.calls
                .borrow_mut()
                .push((serde_json::from_slice(input).unwrap(), preview.to_vec()));
            output[..self.bytes.len()].copy_from_slice(&self.bytes);
            *length = self.length;
            self.code
        }
    }
    let payload = view(&sample("ApprovalRequest")).payload();
    for (code, bytes, length, expected) in [
        (0, b"{}".to_vec(), 2, Ok(json!({}))),
        (-50, vec![], 0, Err(Error::UiUnavailable)),
        (0, vec![], 8193, Err(Error::UiUnavailable)),
        (0, b"bad".to_vec(), 3, Err(Error::InvalidResponse)),
    ] {
        let mut bridge = NativeBridge(Abi {
            code,
            bytes,
            length,
            calls: Default::default(),
        });
        assert_eq!(bridge.show(&payload, None), expected);
        assert_eq!(
            bridge.show(&payload, Some(Path::new("w6-preview.png"))),
            expected
        );
        let calls = bridge.0.calls.borrow();
        assert_eq!(calls[0], (payload.clone(), vec![]));
        assert_eq!(calls[1], (payload.clone(), b"w6-preview.png".to_vec()));
        assert!(calls[0].0.get("digest").is_none());
    }
}

#[test]
fn native_button_policy_rechecks_labels_and_keeps_unavailable_requests_pending() {
    use native::{button_reply, Button};
    for (button, expected) in [
        (Button::Allow, "allow"),
        (Button::Deny, "deny"),
        (Button::Cancel, "cancel"),
    ] {
        for unavailable in [false, true] {
            let reply = button_reply(
                &json!({"kind":"approval"}),
                button,
                3,
                "inspect",
                unavailable,
            );
            assert_eq!(
                reply["decision"],
                if unavailable { "cancel" } else { expected }
            );
            assert_eq!(reply["selected"], 3);
            assert_eq!(reply["reason"], "inspect");
        }
    }
    for kind in ["pairing", "global_grant", "confirmation"] {
        let model = json!({"kind":kind,"label":"srv"});
        for typed in ["srv", "SRV", ""] {
            let reply = button_reply(&model, Button::Allow, -1, typed, false);
            assert_eq!(reply["confirmed"], kind != "confirmation" || typed == "srv");
            assert_eq!(
                button_reply(&model, Button::Deny, 0, typed, false)["confirmed"],
                false
            );
            assert_eq!(
                button_reply(&model, Button::Allow, 0, typed, true)["confirmed"],
                false
            );
        }
    }
}

#[test]
fn agent_session_rejects_malformed_ui_output_and_preserves_routing() {
    use agent::{ui_reply, AgentSession, Route};
    let mut session = AgentSession::default();
    assert!(matches!(
        session.route(&json!({"op":"device_key"}), context().now),
        Route::Existing
    ));
    for op in [
        "remote_pair",
        "remote_confirm_label",
        "remote_confirm_global",
    ] {
        assert!(matches!(
            session.route(&json!({"op":op}), context().now),
            Route::Dialog
        ));
    }
    let Route::Reply(wake) = session.route(&json!({"id":1,"op":"remote_wake"}), context().now)
    else {
        panic!("wake must not create UI")
    };
    assert_eq!(wake, json!({"id":1,"ok":true,"deferred":false}));
    let request = sample("ApprovalRequest");
    let Route::Reply(silent) = session.route(
        &json!({"id":2,"op":"remote_approval","request":request}),
        context().now,
    ) else {
        panic!("silent must not create UI")
    };
    assert_eq!(silent["deferred"], true);
    let Route::Reply(invalid) = session.route(
        &json!({"id":3,"op":"remote_approval","request":null}),
        context().now,
    ) else {
        panic!("invalid request must not create UI")
    };
    assert_eq!(invalid["error"], "invalid_remote_request");
    let mut banner = request;
    banner["delivery"]["mode"] = json!("banner");
    assert!(matches!(
        session.route(
            &json!({"op":"remote_approval","request":banner}),
            context().now
        ),
        Route::Dialog
    ));
    for result in [
        Ok(Value::Null),
        Ok(json!([])),
        Ok(json!(true)),
        Ok(json!("FORBIDDEN")),
        Ok(json!({"ok":"true"})),
        Err(Error::InvalidResponse),
    ] {
        assert_eq!(
            ui_reply(u64::MAX, result),
            json!({"id":u64::MAX,"ok":false,"error":"remote_ui_unavailable"})
        );
    }
    assert_eq!(
        ui_reply(u64::MAX, Ok(json!({"id":0,"ok":true,"confirmed":false}))),
        json!({"id":u64::MAX,"ok":true,"confirmed":false})
    );
}

#[test]
fn agent_frame_reader_handles_fragmentation_limits_and_io_errors() {
    use std::io::{self, BufRead, BufReader, Read};
    let mut reader = BufReader::with_capacity(2, &b"{\"ok\":true}\n{\"ok\":false}\n"[..]);
    assert_eq!(agent::read(&mut reader).unwrap(), Some(json!({"ok":true})));
    assert_eq!(agent::read(&mut reader).unwrap(), Some(json!({"ok":false})));
    assert_eq!(agent::read(&mut reader).unwrap(), None);
    for mut bytes in [b"{}".as_slice(), b"bad\n".as_slice()] {
        assert!(agent::read(&mut bytes).is_err());
    }
    let value = json!({"pad":"x".repeat(kv_ipc::agent::MAX_LINE_BYTES - 11)});
    let encoded = kv_ipc::agent::encode_line(&value);
    assert_eq!(encoded.len(), kv_ipc::agent::MAX_LINE_BYTES);
    assert_eq!(agent::read(&mut encoded.as_slice()).unwrap(), Some(value));
    assert!(agent::read(&mut &vec![b'x'; kv_ipc::agent::MAX_LINE_BYTES + 1][..]).is_err());
    struct BufferedErrorReader(Vec<u8>);
    impl Read for BufferedErrorReader {
        fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
            Err(io::ErrorKind::TimedOut.into())
        }
    }
    impl BufRead for BufferedErrorReader {
        fn fill_buf(&mut self) -> io::Result<&[u8]> {
            if self.0.is_empty() {
                Err(io::ErrorKind::TimedOut.into())
            } else {
                Ok(&self.0)
            }
        }
        fn consume(&mut self, count: usize) {
            self.0.drain(..count);
        }
    }
    let mut unavailable = BufferedErrorReader(b"{}\n".to_vec());
    assert_eq!(agent::read(&mut unavailable).unwrap(), Some(json!({})));
    assert_eq!(
        agent::read(&mut unavailable).unwrap_err().kind(),
        io::ErrorKind::TimedOut
    );
}

#[test]
fn agent_connection_retries_with_bounded_backoff_and_registered_presence_only() {
    use agent::{Connection, ConnectionSource};
    use std::collections::VecDeque;
    use std::io;
    use std::time::Duration;
    enum Attempt {
        Unavailable,
        HelloError,
        Reply(Value),
    }
    struct Channel {
        reply: Option<Value>,
        events: Rc<RefCell<Vec<String>>>,
    }
    impl Connection for Channel {
        fn hello(&mut self) -> io::Result<Value> {
            self.reply
                .take()
                .ok_or_else(|| io::ErrorKind::TimedOut.into())
        }
        fn start_presence(&mut self, id: &str) {
            self.events.borrow_mut().push(format!("presence:{id}"));
        }
        fn serve(&mut self) -> io::Result<()> {
            self.events.borrow_mut().push("serve".into());
            Err(io::ErrorKind::BrokenPipe.into())
        }
    }
    struct Source {
        attempts: VecDeque<Attempt>,
        events: Rc<RefCell<Vec<String>>>,
        delays: Vec<u64>,
    }
    impl ConnectionSource for Source {
        fn connect(&mut self) -> io::Result<Box<dyn Connection>> {
            let reply = match self.attempts.pop_front().unwrap() {
                Attempt::Unavailable => return Err(io::ErrorKind::ConnectionRefused.into()),
                Attempt::HelloError => None,
                Attempt::Reply(reply) => Some(reply),
            };
            Ok(Box::new(Channel {
                reply,
                events: self.events.clone(),
            }))
        }
        fn wait(&mut self, delay: Duration) -> bool {
            self.delays.push(delay.as_secs());
            !self.attempts.is_empty()
        }
    }
    let mut source = Source {
        attempts: VecDeque::from([
            Attempt::Unavailable,
            Attempt::HelloError,
            Attempt::Reply(json!({"ok":false})),
            Attempt::Unavailable,
            Attempt::Unavailable,
            Attempt::Reply(json!({"ok":true,"device_id":"dev_mac"})),
            Attempt::Reply(json!({"ok":true,"device_id":""})),
            Attempt::Reply(json!({"ok":true})),
        ]),
        events: Default::default(),
        delays: vec![],
    };
    assert_eq!(agent::run(&mut source, Duration::from_secs(5)), 0);
    assert_eq!(source.delays, vec![1, 2, 4, 5, 5, 1, 1, 1]);
    assert_eq!(
        *source.events.borrow(),
        vec!["presence:dev_mac", "serve", "serve", "serve"]
    );
    source.attempts.push_back(Attempt::Reply(
        json!({"ok":false,"reason":"not-allowed-user"}),
    ));
    let previous = source.delays.len();
    assert_eq!(agent::run(&mut source, Duration::from_secs(5)), 0);
    assert_eq!(source.delays.len(), previous);
}

#[test]
fn missing_key_metadata_and_canonicalization_failure_never_prompt_or_send() {
    let local = sample("DeviceRecord");
    let peer = sample("DeviceRecord");
    let mut provider = Provider {
        jwk: Value::Null,
        fail: false,
        signs: Default::default(),
    };
    let mut helper = FakeHelper::new(json!({}));
    let mut dialog = FakeDialog::new();
    let flow = PairingFlow {
        local: &local,
        peer: &peer,
        sas: "000007",
        platform: Platform::Macos,
    };
    assert_eq!(
        flow.run(&mut dialog, &mut helper, &provider, &Crypto(true)),
        Err(Error::KeyUnavailable)
    );
    let mut gate = KeyAuthorization {
        provider: &provider,
        local: &local,
        crypto: &Crypto(true),
    };
    assert_eq!(gate.authorize(&json!({})), Err(Error::KeyUnavailable));
    assert!(dialog.events.borrow().is_empty());
    struct InvalidCanonical;
    impl ObjectCrypto for InvalidCanonical {
        fn canonical_unsigned(&self, _: &Value) -> Result<Vec<u8>> {
            Err(Error::InvalidRequest)
        }
        fn verify(&self, _: SignatureAlgorithm, _: &Value, _: &[u8], _: &[u8]) -> Result<()> {
            Err(Error::KeyUnavailable)
        }
    }
    provider.jwk = local["ak_s"]["pub"].clone();
    let mut gate = KeyAuthorization {
        provider: &provider,
        local: &local,
        crypto: &InvalidCanonical,
    };
    assert_eq!(gate.authorize(&json!({})), Err(Error::InvalidRequest));
    assert!(provider.signs.borrow().is_empty());
    assert!(helper.requests.is_empty());
}

#[test]
fn grant_and_directive_plans_reject_missing_or_wrongly_typed_authority() {
    let local = sample("DeviceRecord");
    let request = sample("ApprovalRequest");
    for key in ["device_id", "caps", "ak_s"] {
        let mut invalid = local.clone();
        invalid.as_object_mut().unwrap().remove(key);
        assert!(GrantPlan::settings(
            grant("T1"),
            &invalid,
            &executor(),
            100,
            false,
            Platform::Macos
        )
        .is_err());
    }
    for key in ["jti", "aud", "scope"] {
        let mut invalid = grant("T1");
        invalid.as_object_mut().unwrap().remove(key);
        assert!(
            GrantPlan::settings(invalid, &local, &executor(), 100, false, Platform::Macos).is_err()
        );
    }
    assert!(GrantPlan::settings(
        Value::Null,
        &local,
        &executor(),
        100,
        false,
        Platform::Macos
    )
    .is_err());
    let mut incomplete = request;
    incomplete["credential"] = Value::Null;
    assert!(grant_for_scope(
        &incomplete,
        "per_credential",
        &local,
        "jti",
        context().now,
        context().now + 60
    )
    .is_err());
    let mut admin = sample("ApprovalRequest");
    admin["kind"] = json!("admin");
    let mut strong_only = local.clone();
    strong_only["caps"] = json!(["approve_strong"]);
    assert!(grant_for_scope(
        &admin,
        "per_session",
        &strong_only,
        "jti",
        context().now,
        context().now + 60
    )
    .unwrap()
    .is_some());
    let state = DirectiveState::default();
    for unsigned in [
        Value::Null,
        json!({"aud":"dev_srv","op":"lock","args":{},"exp":null}),
        json!({"aud":"dev_srv","op":"lock","args":{},"exp":200,"id":"d"}),
    ] {
        assert!(
            DirectivePlan::new(unsigned, &local, &executor(), &state, 100, Platform::Macos)
                .is_err()
        );
    }
    for (op, args) in [
        ("set_unlock_ttl", json!({"seconds":86401})),
        ("set_class", json!({"name":"batch","match":null,"exp_s":1})),
        (
            "set_class",
            json!({"name":"batch","match":{},"exp_s":86401}),
        ),
        ("query_audit", json!({"since":"bad","limit":1})),
    ] {
        assert_eq!(
            directive_level(op, &args, &state),
            Err(Error::InvalidRequest)
        );
    }
}

#[test]
fn dialog_stdio_handles_preview_bounded_input_and_all_io_failures_without_gui() {
    use native::{NativeDialog, NativeUi};
    use std::io::{self, Read, Write};
    use std::path::{Path, PathBuf};
    use stdio::Mode;
    struct Io {
        input: io::Cursor<Vec<u8>>,
        output: Vec<u8>,
        fail_read: bool,
        fail_write: bool,
        fail_flush: bool,
    }
    impl Io {
        fn new(bytes: Vec<u8>) -> Self {
            Self {
                input: io::Cursor::new(bytes),
                output: vec![],
                fail_read: false,
                fail_write: false,
                fail_flush: false,
            }
        }
    }
    impl Read for Io {
        fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
            if self.fail_read {
                Err(io::ErrorKind::BrokenPipe.into())
            } else {
                self.input.read(bytes)
            }
        }
    }
    impl Write for Io {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            if self.fail_write {
                Err(io::ErrorKind::BrokenPipe.into())
            } else {
                self.output.extend(bytes);
                Ok(bytes.len())
            }
        }
        fn flush(&mut self) -> io::Result<()> {
            if self.fail_flush {
                Err(io::ErrorKind::BrokenPipe.into())
            } else {
                Ok(())
            }
        }
    }
    type DisplayedRequests = Rc<RefCell<Vec<(Value, Option<PathBuf>)>>>;
    struct Ui(DisplayedRequests);
    impl NativeUi for Ui {
        fn show(&mut self, value: &Value, preview: Option<&Path>) -> Result<Value> {
            self.0
                .borrow_mut()
                .push((value.clone(), preview.map(Path::to_owned)));
            Ok(json!({"decision":"allow","selected":0,"confirmed":true,"text":"srv"}))
        }
    }
    let now = unix_seconds();
    let mut request = sample("ApprovalRequest");
    request["exp"] = json!(now + 600);
    let input = json!({"op":"remote_approval","request":request,"context":{"now":now}});
    let calls = Rc::new(RefCell::new(vec![]));
    let mut dialog = NativeDialog::new(Ui(calls.clone()));
    let mut reader = Io::new(serde_json::to_vec(&input).unwrap());
    let mut writer = Io::new(vec![]);
    stdio::run(
        &mut reader,
        &mut writer,
        Mode::Dialog,
        Platform::Macos,
        &mut dialog,
    )
    .unwrap();
    assert_eq!(
        serde_json::from_slice::<Value>(&writer.output).unwrap()["params"]["decision"],
        "allow"
    );
    let path = Path::new("w6-preview.png");
    for preview in [
        input.clone(),
        json!({"op":"remote_pair","peer":sample("DeviceRecord"),"sas":"000007"}),
    ] {
        let mut reader = Io::new(serde_json::to_vec(&preview).unwrap());
        let mut writer = Io::new(vec![]);
        stdio::run(
            &mut reader,
            &mut writer,
            Mode::Preview(path),
            Platform::Windows,
            &mut dialog,
        )
        .unwrap();
        assert!(writer.output.is_empty());
        assert_eq!(calls.borrow().last().unwrap().1.as_deref(), Some(path));
    }
    let invalid_pair = serde_json::to_vec(
        &json!({"op":"remote_pair","peer":sample("DeviceRecord"),"sas":"wrong"}),
    )
    .unwrap();
    assert_eq!(
        stdio::run(
            &mut Io::new(invalid_pair),
            &mut Io::new(vec![]),
            Mode::Preview(path),
            Platform::Macos,
            &mut dialog
        ),
        Err(Error::InvalidRequest)
    );
    for invalid in [
        json!({"op":"remote_pair","peer":{},"sas":null}),
        json!({"op":"remote_pair","peer":null,"sas":"000007"}),
        json!({"request":null}),
        json!({"request":input["request"],"context":{"backlog_count":-1}}),
    ] {
        assert!(stdio::run(
            &mut Io::new(serde_json::to_vec(&invalid).unwrap()),
            &mut Io::new(vec![]),
            Mode::Preview(path),
            Platform::Macos,
            &mut dialog
        )
        .is_err());
    }
    for bytes in [
        vec![],
        b"bad".to_vec(),
        vec![b'x'; kv_ipc::agent::MAX_LINE_BYTES + 1],
    ] {
        assert_eq!(
            stdio::run(
                &mut Io::new(bytes),
                &mut Io::new(vec![]),
                Mode::Dialog,
                Platform::Macos,
                &mut dialog
            ),
            Err(Error::InvalidRequest)
        );
    }
    let mut reader = Io::new(vec![]);
    reader.fail_read = true;
    assert_eq!(
        stdio::run(
            &mut reader,
            &mut writer,
            Mode::Dialog,
            Platform::Macos,
            &mut dialog
        ),
        Err(Error::InvalidRequest)
    );
    for (fail_write, fail_flush) in [(true, false), (false, true)] {
        let mut reader = Io::new(serde_json::to_vec(&input).unwrap());
        let mut writer = Io::new(vec![]);
        writer.fail_write = fail_write;
        writer.fail_flush = fail_flush;
        assert_eq!(
            stdio::run(
                &mut reader,
                &mut writer,
                Mode::Dialog,
                Platform::Macos,
                &mut dialog
            ),
            Err(Error::UiUnavailable)
        );
    }
}
