use super::*;
use std::collections::VecDeque;

#[path = "audit_tests.rs"]
mod audit_tests;
#[path = "review_tests.rs"]
mod review_tests;

const NOW: i64 = 1791648000;
const URI: &str = "kv-pair://relay.example.com/AAAAAAAAAAAAAAAAAAAAAAAAAA";

#[test]
fn r3a_rejoin_is_an_explicit_owner_intent_and_still_requires_sas_confirmation() {
    let dir = tempfile::tempdir().unwrap();
    let mut host = Fake::new(dir.path());
    host.answers.push_back(Some("y".into()));
    run(&mut host, &["pair", "--rejoin", URI, "--json"]).unwrap();
    assert_eq!(host.ops(), [Op::PairComplete, Op::PairConfirm]);
    assert_eq!(host.requests[0].params, json!({"uri":URI,"rejoin":true}));
    assert_eq!(
        host.requests[1].params,
        json!({"sas":"123456","confirmed":true})
    );

    let mut host = Fake::new(dir.path());
    host.answers.push_back(Some("n".into()));
    assert_eq!(
        run(&mut host, &["pair", "--rejoin", URI]).unwrap_err().code,
        "user_cancelled"
    );
    assert_eq!(host.ops(), [Op::PairComplete]);
    for args in [
        vec!["pair", "--rejoin"],
        vec!["pair", "--rejoin", "--new"],
        vec!["pair", "--rejoin", "--resume"],
    ] {
        let mut host = Fake::new(dir.path());
        assert!(run(&mut host, &args).is_err());
        assert!(host.ops().is_empty());
    }
}

#[test]
fn r3a_cli_finite_t2_does_not_issue_after_only_the_first_label() {
    for second in [None, Some("wrong")] {
        let dir = tempfile::tempdir().unwrap();
        let mut host = Fake::new(dir.path());
        host.replies.extend([
            (Op::DevicesList, Response::ok(json!({"devices":host.directory}))),
            (Op::GrantIssue, Response::ok(json!({"confirmation_token":"test-first-proof","expires_at":NOW+120,"device_id":"dev_srv","label":"srv","confirmations_left":2}))),
            (Op::GrantIssue, Response::ok(json!({"confirmation_token":"test-second-proof","expires_at":NOW+120,"device_id":"dev_srv","label":"srv","confirmations_left":1}))),
        ]);
        host.answers
            .extend([Some("srv".into()), second.map(str::to_owned)]);
        let error = run(
            &mut host,
            &[
                "remote",
                "srv",
                "unattended",
                "--include-sensitive",
                "--until",
                "1h",
            ],
        )
        .unwrap_err();
        assert_eq!(error.code, "user_cancelled");
        assert_eq!(
            host.ops(),
            [Op::DevicesList, Op::GrantIssue, Op::GrantIssue]
        );
    }
}

#[test]
fn r3a_cli_rejects_changed_or_reused_second_confirmation_before_signing() {
    for (field, value) in [
        ("confirmation_token", json!("test-first-proof")),
        ("confirmation_token", json!("")),
        ("expires_at", json!(NOW + 121)),
        ("expires_at", json!(NOW + 119)),
        ("device_id", json!("dev_other")),
        ("label", json!("other")),
        ("confirmations_left", json!(2)),
    ] {
        let dir = tempfile::tempdir().unwrap();
        let mut host = Fake::new(dir.path());
        let mut second = json!({"confirmation_token":"test-second-proof","expires_at":NOW+120,
            "device_id":"dev_srv","label":"srv","confirmations_left":1});
        second[field] = value;
        host.replies.extend([
            (
                Op::DevicesList,
                Response::ok(json!({"devices":host.directory})),
            ),
            (
                Op::GrantIssue,
                Response::ok(
                    json!({"confirmation_token":"test-first-proof","expires_at":NOW+120,
                "device_id":"dev_srv","label":"srv","confirmations_left":2}),
                ),
            ),
            (Op::GrantIssue, Response::ok(second)),
        ]);
        host.answers
            .extend([Some("srv".into()), Some("srv".into())]);
        let error = run(
            &mut host,
            &[
                "remote",
                "srv",
                "unattended",
                "--include-sensitive",
                "--until",
                "1h",
            ],
        )
        .unwrap_err();
        assert_eq!(error.code, "invalid_response");
        assert_eq!(
            host.ops(),
            [Op::DevicesList, Op::GrantIssue, Op::GrantIssue]
        );
        assert_eq!(host.answers.len(), 1);
    }
}

#[test]
fn r3a_nested_remote_grant_revoke_all_uses_the_same_owner_directive() {
    let dir = tempfile::tempdir().unwrap();
    let mut host = Fake::new(dir.path());
    run(
        &mut host,
        &["remote", "srv", "grant", "revoke-all", "--json"],
    )
    .unwrap();
    assert_eq!(host.ops(), [Op::DevicesList, Op::DirectiveIssue]);
    assert_eq!(host.requests[1].params["op"], "revoke_all_grants");
    assert_eq!(host.requests[1].params["aud"], "dev_srv");
    for key in ["sig", "iss", "nonce", "exp"] {
        assert!(host.requests[1].params.get(key).is_none());
    }
    for extra in ["extra", "--sig", "--yes"] {
        let mut host = Fake::new(dir.path());
        assert!(run(&mut host, &["remote", "srv", "grant", "revoke-all", extra]).is_err());
        assert!(host.ops().is_empty());
    }
}

#[test]
fn r3a_pair_resume_confirms_the_live_sas_without_redeeming_a_token_again() {
    let dir = tempfile::tempdir().unwrap();
    let mut host = Fake::new(dir.path());
    host.replies.extend([
        (Op::Status, Response::ok(json!({"pairing":{"state":"pending","sas":"123456","expires_at":NOW+60,"global_grants":0}}))),
        (Op::PairConfirm, Response::ok(json!({}))),
        (Op::Status, Response::ok(json!({"pairing":{"state":"completed"}}))),
    ]);
    host.answers.push_back(Some("y".into()));
    let result = run(&mut host, &["pair", "--resume", "--json"]).unwrap();
    assert_eq!(json!(result)["result"]["paired"], true);
    assert_eq!(host.ops(), [Op::Status, Op::PairConfirm, Op::Status]);
    assert_eq!(
        host.requests[1].params,
        json!({"sas":"123456","confirmed":true})
    );
    for pairing in [json!(null), json!({"sas":"123456","expires_at":NOW-1})] {
        let mut host = Fake::new(dir.path());
        host.replies
            .push_back((Op::Status, Response::ok(json!({"pairing":pairing}))));
        assert!(run(&mut host, &["pair", "--resume"]).is_err());
        assert_eq!(host.ops(), [Op::Status]);
    }
    let mut host = Fake::new(dir.path());
    host.replies.push_back((
        Op::Status,
        Response::ok(json!({"pairing":{"sas":"123456","expires_at":NOW+60}})),
    ));
    host.answers.push_back(Some("n".into()));
    assert!(run(&mut host, &["pair", "--resume"]).is_err());
    assert_eq!(host.ops(), [Op::Status]);
}

#[test]
fn pairing_global_grants_notice_and_exclusion_are_typed_and_explicit() {
    for (choice, expected) in [
        (Some("e"), Some(true)),
        (Some(""), Some(false)),
        (Some("bad"), None),
        (None, None),
    ] {
        let dir = tempfile::tempdir().unwrap();
        let mut host = Fake::new(dir.path());
        host.replies.push_back((
            Op::PairStart,
            Response::ok(json!({"sas":"123456","uri":URI,"expires_at":NOW+600,"global_grants":2})),
        ));
        host.answers
            .extend([Some("y".into()), choice.map(str::to_owned)]);
        let result = run(&mut host, &["pair", "--new", "--json"]);
        assert!(host
            .emitted
            .iter()
            .any(|value| matches!(value.output, Success::PairGlobalGrants { count: 2 })));
        let notice = Success::PairGlobalGrants { count: 2 };
        assert!(output::render(&notice, false, true).contains('2'));
        let encoded = serde_json::to_string(&output::JsonSuccess {
            ok: true,
            output: notice.clone(),
        })
        .unwrap();
        let decoded: output::JsonSuccess = serde_json::from_str(&encoded).unwrap();
        assert_eq!(decoded.output, notice);
        if let Some(exclude) = expected {
            assert!(result.is_ok());
            let request = host
                .requests
                .iter()
                .find(|r| r.op == Op::PairConfirm)
                .unwrap();
            assert_eq!(
                request
                    .params
                    .get("exclude_global")
                    .and_then(Value::as_bool)
                    .unwrap_or(false),
                exclude
            );
        } else {
            assert!(result.is_err());
            assert!(!host.ops().contains(&Op::PairConfirm));
        }
    }
}

#[test]
fn global_grant_choice_expiration_and_output_failures_do_not_confirm_pairing() {
    for expires in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let mut host = Fake::new(dir.path());
        host.replies.push_back((
            Op::PairStart,
            Response::ok(json!({"sas":"123456","uri":URI,"expires_at":NOW+600,"global_grants":2})),
        ));
        host.answers.extend([Some("y".into()), Some("e".into())]);
        if expires {
            host.confirmation_advances.extend([0, 600]);
        } else {
            host.fail_emit_at = Some(3);
        }
        let failure = run(&mut host, &["pair", "--new", "--json"]).unwrap_err();
        assert_eq!(
            failure.code,
            if expires {
                "pair_timeout"
            } else {
                "invalid_response"
            }
        );
        assert!(!host.ops().contains(&Op::PairConfirm));
    }
}

#[test]
fn grant_page_failures_do_not_render_an_incomplete_list() {
    for (first, next) in [
        (
            json!({"grants":[],"next_cursor":"cursor"}),
            json!({"ok":false,"error":"denied","state":{}}),
        ),
        (
            json!({"grants":[],"next_cursor":"cursor"}),
            json!({"ok":true,"state":{}}),
        ),
        (
            json!({"next_cursor":"cursor"}),
            json!({"ok":true,"state":{"grants":[]}}),
        ),
        (
            json!({"grants":[],"next_cursor":"cursor"}),
            json!({"ok":true,"state":null}),
        ),
    ] {
        let dir = tempfile::tempdir().unwrap();
        let mut host = Fake::new(dir.path());
        host.replies.extend([
            (Op::DevicesList, Response::ok(json!({"devices":host.directory}))),
            (Op::DirectiveIssue, Response::ok(json!({"result":{"id":"first","ok":true,"error":null,"state":first}}))),
            (Op::DirectiveIssue, Response::ok(json!({"result":{"id":"next", "error":null, "ok":next["ok"],"state":next["state"]}}))),
        ]);
        assert_eq!(
            run(&mut host, &["remote", "srv", "grants", "--json"])
                .unwrap_err()
                .code,
            "invalid_response"
        );
        assert_eq!(
            host.requests
                .iter()
                .filter(|request| request.op == Op::DirectiveIssue)
                .count(),
            2
        );
    }
}

#[test]
fn local_and_remote_grant_lists_follow_cursors_and_reject_loops() {
    for remote in [false, true] {
        for looped in [false, true] {
            let dir = tempfile::tempdir().unwrap();
            let mut host = Fake::new(dir.path());
            let grants = |id: &str| json!([{"jti":id,"aud":"dev_srv","exp":null}]);
            if remote {
                host.replies.push_back((
                    Op::DevicesList,
                    Response::ok(json!({"devices":host.directory})),
                ));
                for (id, cursor) in [
                    ("first", Some("first")),
                    ("second", if looped { Some("first") } else { None }),
                ] {
                    host.replies.push_back((Op::DirectiveIssue,Response::ok(json!({"result":{"id":id,"ok":true,"error":null,"state":{"grants":grants(id),"next_cursor":cursor}}}))));
                }
            } else {
                for (id, cursor) in [
                    ("first", Some("first")),
                    ("second", if looped { Some("first") } else { None }),
                ] {
                    host.replies.push_back((
                        Op::GrantList,
                        Response::ok(json!({"grants":grants(id),"next_cursor":cursor})),
                    ));
                }
            }
            let result = run(
                &mut host,
                if remote {
                    &["remote", "srv", "grants", "--json"]
                } else {
                    &["grant", "list", "--json"]
                },
            );
            if looped {
                assert!(result.is_err());
            } else {
                match result.unwrap() {
                    Success::Grants(list) => assert_eq!(list.grants.len(), 2),
                    Success::Remote { results } => assert_eq!(
                        results[0].result.state["grants"].as_array().unwrap().len(),
                        2
                    ),
                    _ => panic!("unexpected list output"),
                }
            }
            let continuation = host
                .requests
                .iter()
                .rev()
                .find(|r| {
                    r.op == if remote {
                        Op::DirectiveIssue
                    } else {
                        Op::GrantList
                    }
                })
                .unwrap();
            assert_eq!(
                if remote {
                    &continuation.params["args"]["after"]
                } else {
                    &continuation.params["after"]
                },
                "first"
            );
        }
    }
}

fn record(id: &str, label: &str, execute: bool) -> DeviceRecord {
    serde_json::from_value(json!({"device_id":id,"label":label,"os":"linux","key_kind":"software",
        "dk_pub":{"kty":"EC","crv":"P-256","x":"public-x","y":"public-y"},
        "ak_q":null,"ak_s":null,"attestation":null,"caps":if execute {vec!["execute"]} else {vec!["approve_quick","approve_strong"]}})).unwrap()
}

#[test]
fn account_recovery_reads_a_secret_passes_only_an_intent_and_persists_public_binding() {
    let directory = tempfile::tempdir().unwrap();
    let mut fake = Fake::new(directory.path());
    let old = kv_core::remote::keys::encode_b64(&[1; 32]);
    let new = kv_core::remote::keys::encode_b64(&[2; 32]);
    fake.answers.push_back(Some(old.clone()));
    let result = kv_ipc::remote::AccountRecoverResult {
        binding: kv_core::remote::ipc::RelayBinding {
            relay_url: "https://relay.example.com".into(),
            device_id: "dev_restored".into(),
            account_id: "acct_restored".into(),
        },
        recovery_code: new.clone(),
    };
    fake.replies.push_back((
        Op::AccountRecover,
        Response::ok(serde_json::to_value(&result).unwrap()),
    ));
    let argv: Vec<String> = ["relay", "recover", "acct_restored", "--software", "--json"]
        .into_iter()
        .map(str::to_owned)
        .collect();
    super::run(&mut fake, &argv).unwrap();
    assert_eq!(fake.ops(), [Op::AccountRecover]);
    assert_eq!(
        fake.requests[0].params,
        json!({"account_id":"acct_restored","recovery_code":old,
        "relay_url":"https://relay.example.com","software":true})
    );
    assert!(!serde_json::to_string(&argv).unwrap().contains(&old));
    assert!(!format!("{result:?}").contains(&new));
    assert!(matches!(&fake.emitted[0].output,Success::RelayRecovered(value) if value == &result));
    assert_eq!(
        relay::Config::read(&fake.config)
            .unwrap()
            .account_id
            .as_deref(),
        Some("acct_restored")
    );
    assert!(output::render(&fake.emitted[0].output, false, false).contains(&new));
}

#[test]
fn account_recovery_rejects_missing_secrets_arguments_and_a_substituted_binding() {
    for (answer, exit) in [(None, 6), (Some("bad-code".to_owned()), 2)] {
        let directory = tempfile::tempdir().unwrap();
        let mut fake = Fake::new(directory.path());
        fake.answers.push_back(answer);
        let args: Vec<String> = ["relay", "recover", "acct_restored"]
            .into_iter()
            .map(str::to_owned)
            .collect();
        assert_eq!(super::run(&mut fake, &args).unwrap_err().exit_code(), exit);
        assert!(fake.requests.is_empty());
    }
    let invalid: Vec<String> = [
        "relay",
        "recover",
        "acct_restored",
        "--recovery-code",
        "secret",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect();
    assert_eq!(Invocation::parse(&invalid).unwrap_err().exit_code(), 2);
    let directory = tempfile::tempdir().unwrap();
    let mut fake = Fake::new(directory.path());
    fake.answers
        .push_back(Some(kv_core::remote::keys::encode_b64(&[1; 32])));
    fake.replies.push_back((Op::AccountRecover,Response::ok(json!({"binding":{
        "relay_url":"https://relay.example.com","device_id":"dev_restored","account_id":"substituted"},
        "recovery_code":kv_core::remote::keys::encode_b64(&[2;32])}))));
    let argv: Vec<String> = ["relay", "recover", "acct_restored"]
        .into_iter()
        .map(str::to_owned)
        .collect();
    assert_eq!(super::run(&mut fake, &argv).unwrap_err().exit_code(), 3);
    assert_eq!(
        relay::Config::read(&fake.config)
            .unwrap()
            .account_id
            .as_deref(),
        Some("acct_test")
    );
}

struct Fake {
    directory: Vec<DeviceRecord>,
    requests: Vec<Request>,
    replies: VecDeque<(Op, Response)>,
    pending: VecDeque<Value>,
    answers: VecDeque<Option<String>>,
    emitted: Vec<output::JsonSuccess>,
    hooks: Vec<(String, String, String)>,
    notices: Vec<String>,
    waits: usize,
    now: i64,
    config: PathBuf,
    root: PathBuf,
    health_url: Option<String>,
    verified: usize,
    fail: Option<&'static str>,
    confirmation_advances: VecDeque<i64>,
    confirmation_deadlines: HashMap<String, i64>,
    fail_emit_at: Option<usize>,
}

impl Fake {
    fn new(dir: &std::path::Path) -> Self {
        let config = dir.join("relay-client.toml");
        std::fs::write(&config,"relay_url='https://relay.example.com'\ndevice_id='dev_local'\naccount_id='acct_test'\n").unwrap();
        Self {
            directory: vec![
                record("dev_srv", "srv", true),
                record("dev_other", "other", true),
            ],
            requests: vec![],
            replies: VecDeque::new(),
            pending: VecDeque::new(),
            answers: VecDeque::new(),
            emitted: vec![],
            hooks: vec![],
            notices: vec![],
            waits: 0,
            now: NOW,
            config,
            root: dir.join("root"),
            health_url: None,
            verified: 0,
            fail: None,
            confirmation_advances: VecDeque::new(),
            confirmation_deadlines: HashMap::new(),
            fail_emit_at: None,
        }
    }

    fn ops(&self) -> Vec<Op> {
        self.requests.iter().map(|r| r.op).collect()
    }

    fn fault(&self, method: &str) -> Result<()> {
        if self.fail == Some(method) {
            Err(Error::new(
                "injected_failure",
                "测试故障",
                "Injected failure",
            ))
        } else {
            Ok(())
        }
    }

    fn default_reply(&mut self, request: &Request) -> Response {
        let value = match request.op {
            Op::DevicesList => json!({"devices":self.directory}),
            Op::DevicesRevoke | Op::DevicesRename | Op::GrantRevoke | Op::PairConfirm => json!({}),
            Op::PendingList => self
                .pending
                .pop_front()
                .unwrap_or_else(|| json!({"pending":[],"recent":[]})),
            Op::Decide => {
                // The helper chooses authorization. No CLI tier/algorithm/signature is accepted.
                assert!(request.params.get("level").is_none());
                json!({"sent":true})
            }
            Op::GrantIssue => {
                let intent: GrantIntent = serde_json::from_value(request.params.clone()).unwrap();
                for key in ["sig", "iss", "iss_alg", "jti"] {
                    assert!(request.params.get(key).is_none());
                }
                if intent.scope.max_tier == Tier::T2 && intent.confirm.is_none() {
                    let label = self
                        .directory
                        .iter()
                        .find(|d| d.device_id == intent.aud)
                        .unwrap()
                        .label
                        .clone();
                    self.confirmation_deadlines
                        .insert(intent.aud.clone(), self.now + 120);
                    return Response::ok(
                        json!({"confirmation_token":"one-use-helper-token","expires_at":self.now+120,"device_id":intent.aud,"label":label,"confirmations_left":2}),
                    );
                }
                if intent.scope.max_tier == Tier::T2 {
                    if intent.confirmation_token.as_deref() == Some("one-use-helper-token") {
                        let expires_at = self
                            .confirmation_deadlines
                            .get(&intent.aud)
                            .copied()
                            .unwrap_or(NOW + 120);
                        return Response::ok(
                            json!({"confirmation_token":"one-use-helper-second-token","expires_at":expires_at,
                            "device_id":intent.aud,"label":intent.confirm,"confirmations_left":1}),
                        );
                    }
                    assert_eq!(
                        intent.confirmation_token.as_deref(),
                        Some("one-use-helper-second-token")
                    );
                }
                let grant = Grant {
                    kind: intent.kind,
                    jti: "jti_helper".into(),
                    iss: "dev_local".into(),
                    iss_alg: SignatureAlgorithm::RS256,
                    iss_kind: IssuerKind::Device,
                    aud: intent.aud,
                    scope: intent.scope,
                    budget: intent.budget.map_or(Optional::Missing, Optional::Value),
                    nbf: intent.nbf,
                    exp: intent.exp,
                    origin: intent.origin,
                    confirm: intent.confirm.map_or(Optional::Missing, Optional::Value),
                    sig: "helper-signature".into(),
                    extra: Extra::new(),
                };
                json!({"grant":grant})
            }
            Op::GrantList => json!({"grants":[]}),
            Op::DirectiveIssue => {
                let _: DirectiveIntent = serde_json::from_value(request.params.clone()).unwrap();
                for key in ["sig", "iss", "iss_alg", "id", "nonce", "level"] {
                    assert!(request.params.get(key).is_none());
                }
                json!({"result":{"id":"directive_helper","ok":true,"error":null,"state":{"mode":"per_use"}}})
            }
            Op::PairStart => json!({"sas":"123456","uri":URI,"expires_at":self.now+600}),
            Op::PairComplete => json!({"sas":"123456","expires_at":self.now+600}),
            Op::Status => {
                json!({"relay":"connected","approvers":[],"pending_n":1,"grants_n":2,"unattended":false,"runtime_budget_s":50,"pairing":{"sas":"123456"}})
            }
            _ => panic!("Not a CLI operation: {:?}", request.op),
        };
        Response::ok(value)
    }
}

impl Host for Fake {
    fn verify(&mut self) -> Result<()> {
        self.verified += 1;
        self.fault("verify")
    }
    fn exchange(&mut self, request: Request) -> Result<Response> {
        self.fault("exchange")?;
        assert!(allowed_ops(Caller::CliOwner).contains(&request.op));
        let bytes = serde_json::to_vec(&request).unwrap();
        let decoded: Request = kv_core::remote::canonical::from_json(&bytes).unwrap();
        assert_eq!(decoded.op, request.op);
        let reply = if let Some((op, _)) = self.replies.front() {
            assert_eq!(*op, request.op);
            self.replies.pop_front().unwrap().1
        } else {
            self.default_reply(&request)
        };
        self.requests.push(request);
        Ok(reply)
    }
    fn now(&self) -> i64 {
        self.now
    }
    fn config_path(&self) -> Result<PathBuf> {
        self.fault("config_path")?;
        Ok(self.config.clone())
    }
    fn install_root(&self) -> Result<PathBuf> {
        self.fault("install_root")?;
        Ok(self.root.clone())
    }
    fn confirmation(&mut self, _: &str, _: Duration) -> Result<Option<String>> {
        self.fault("confirmation")?;
        self.now += self.confirmation_advances.pop_front().unwrap_or_default();
        Ok(self.answers.pop_front().flatten())
    }
    fn notice(&mut self, text: &str) -> Result<()> {
        self.fault("notice")?;
        self.notices.push(text.into());
        Ok(())
    }
    fn emit(&mut self, value: &Success, _: bool) -> Result<()> {
        self.fault("emit")?;
        if self.fail_emit_at == Some(self.emitted.len() + 1) {
            return Err(Error::protocol());
        }
        let json = output::JsonSuccess {
            ok: !matches!(value, Success::Audit(report) if !report.consistent),
            output: value.clone(),
        };
        let round_trip: output::JsonSuccess =
            serde_json::from_str(&serde_json::to_string(&json).unwrap()).unwrap();
        assert_eq!(round_trip.output, *value);
        self.emitted.push(json);
        Ok(())
    }
    fn wait(&mut self, _: Duration) -> bool {
        self.now += 1;
        if self.waits == 0 {
            false
        } else {
            self.waits -= 1;
            true
        }
    }
    fn health(&mut self, url: &str) -> Result<relay::Health> {
        self.fault("health")?;
        self.health_url = Some(url.into());
        Ok(relay::Health {
            ok: true,
            version: "0.3.0".into(),
        })
    }
    fn hook(&mut self, cmd: &str, id: &str, summary: &str) -> Result<()> {
        self.fault("hook")?;
        self.hooks.push((cmd.into(), id.into(), summary.into()));
        Ok(())
    }
    fn protection(&mut self) -> Result<Value> {
        self.fault("protection")?;
        Ok(json!({"provider":"software_key"}))
    }
}

fn parse(args: &[&str]) -> Result<Invocation> {
    Invocation::parse(&args.iter().map(|s| s.to_string()).collect::<Vec<_>>())
}
fn run(fake: &mut Fake, args: &[&str]) -> Result<Success> {
    execute(fake, &parse(args)?)
}

#[test]
fn all_table_commands_use_only_cli_ops_and_round_trip_json() {
    let cases: &[(&[&str], &[Op])] = &[
        (&["devices", "list"], &[Op::DevicesList]),
        (&["devices", "revoke", "dev_srv"], &[Op::DevicesRevoke]),
        (
            &["devices", "rename", "dev_srv", "build"],
            &[Op::DevicesRename],
        ),
        (&["approvals"], &[Op::PendingList]),
        (&["approve", "approval_test"], &[Op::Decide]),
        (
            &["approve", "approval_test", "--scope", "remember:8h"],
            &[Op::Decide],
        ),
        (
            &["deny", "approval_test", "--reason", "not allowed"],
            &[Op::Decide],
        ),
        (
            &[
                "grant",
                "--to",
                "srv",
                "--credential",
                "github/default",
                "--hosts",
                "api.github.com",
                "--methods",
                "GET,POST",
                "--paths",
                "/repos/u/**",
                "--agent",
                "claude-code:/home/u/proj",
                "--budget",
                "500/24h",
                "--until",
                "2026-10-18T00:00+08:00",
            ],
            &[Op::DevicesList, Op::GrantIssue],
        ),
        (&["grant", "list"], &[Op::GrantList]),
        (&["grant", "revoke", "jti_test"], &[Op::GrantRevoke]),
        (
            &["grant", "revoke-all"],
            &[Op::DevicesList, Op::DirectiveIssue, Op::DirectiveIssue],
        ),
        (
            &["remote", "srv", "mode", "per_use"],
            &[Op::DevicesList, Op::DirectiveIssue],
        ),
        (
            &["remote", "srv", "mode", "remember:8h"],
            &[Op::DevicesList, Op::DirectiveIssue],
        ),
        (
            &[
                "remote",
                "srv",
                "allow",
                "--credential",
                "github/default",
                "--until",
                "1h",
            ],
            &[Op::DevicesList, Op::GrantIssue],
        ),
        (
            &["remote", "srv", "allow", "--all", "--standing"],
            &[Op::DevicesList, Op::GrantIssue],
        ),
        (
            &[
                "remote",
                "srv",
                "unattended",
                "--include-sensitive",
                "--until",
                "7d",
            ],
            &[
                Op::DevicesList,
                Op::GrantIssue,
                Op::GrantIssue,
                Op::GrantIssue,
            ],
        ),
        (
            &["remote", "srv", "lock"],
            &[Op::DevicesList, Op::DirectiveIssue],
        ),
        (
            &["remote", "srv", "unlock-ttl", "6h"],
            &[Op::DevicesList, Op::DirectiveIssue],
        ),
        (
            &[
                "remote",
                "srv",
                "class",
                "batch",
                "--credential",
                "github/*",
                "--host",
                "api.github.com",
                "--exp",
                "12h",
            ],
            &[Op::DevicesList, Op::DirectiveIssue],
        ),
        (
            &["remote", "srv", "label", "build"],
            &[Op::DevicesList, Op::DirectiveIssue],
        ),
        (
            &["remote", "srv", "notify", "both"],
            &[Op::DevicesList, Op::DirectiveIssue],
        ),
        (
            &["remote", "srv", "status"],
            &[Op::DevicesList, Op::DirectiveIssue],
        ),
        (
            &["remote", "srv", "pending"],
            &[Op::DevicesList, Op::DirectiveIssue],
        ),
        (
            &["remote", "srv", "grants"],
            &[Op::DevicesList, Op::DirectiveIssue],
        ),
        (
            &["remote", "srv", "audit", "--since", "24h"],
            &[Op::DevicesList, Op::DirectiveIssue],
        ),
        (
            &["remote", "srv", "grant", "revoke", "jti_test"],
            &[Op::DevicesList, Op::DirectiveIssue],
        ),
        (
            &["remote", "srv", "revoke-all"],
            &[Op::DevicesList, Op::DirectiveIssue],
        ),
        (&["status", "--summary"], &[Op::Status, Op::DevicesList]),
        (&["pair", "--new"], &[Op::PairStart, Op::PairConfirm]),
        (&["pair", URI], &[Op::PairComplete, Op::PairConfirm]),
    ];
    for (args, ops) in cases {
        let temp = tempfile::tempdir().unwrap();
        let mut fake = Fake::new(temp.path());
        fake.answers.push_back(Some(
            if args.contains(&"unattended") {
                "srv"
            } else {
                "y"
            }
            .into(),
        ));
        if args.contains(&"unattended") {
            fake.answers.push_back(Some("srv".into()));
        }
        let result = run(&mut fake, args).unwrap_or_else(|e| panic!("{args:?}: {e:?}"));
        assert_eq!(fake.ops(), *ops, "{args:?}");
        fake.emit(&result, true).unwrap();
        assert!(!output::render(&result, false, false).contains("\u{1b}"));
        if args.first() == Some(&"deny") {
            assert_eq!(fake.requests[0].params["reason"], "not allowed");
        }
        if args.contains(&"audit") {
            assert_eq!(fake.requests[1].params["args"]["since"], NOW - 86400);
        }
        if args.contains(&"unattended") {
            assert_eq!(fake.requests[2].params["confirm"], "srv");
            assert_eq!(fake.requests[2].params["scope"]["max_tier"], "T2");
        }
    }
}

#[test]
fn unattended_requires_exact_interactive_confirmation_and_cannot_be_scripted() {
    for answer in [None, Some("yes"), Some("wrong"), Some("srv ")] {
        let temp = tempfile::tempdir().unwrap();
        let mut fake = Fake::new(temp.path());
        fake.answers.push_back(answer.map(str::to_owned));
        let err = run(
            &mut fake,
            &[
                "remote",
                "srv",
                "unattended",
                "--include-sensitive",
                "--until",
                "7d",
                "--json",
            ],
        )
        .unwrap_err();
        assert_eq!(err.exit_code(), 6);
        assert_eq!(fake.ops(), [Op::DevicesList, Op::GrantIssue]);
        assert!(fake.requests[1].params.get("confirm").is_none());
    }
    for args in [
        vec!["remote", "srv", "unattended", "--until", "7d"],
        vec!["remote", "srv", "unattended", "--include-sensitive"],
        vec![
            "remote",
            "srv",
            "unattended",
            "--include-sensitive",
            "--until",
            "7d",
            "--yes",
        ],
        vec![
            "remote",
            "srv",
            "unattended",
            "--include-sensitive",
            "--until",
            "7d",
            "--standing",
        ],
    ] {
        assert_eq!(parse(&args).unwrap_err().exit_code(), 2);
    }
}

#[test]
fn grant_intents_preserve_command_source_for_helper_authorization() {
    let temp = tempfile::tempdir().unwrap();
    let mut requests = Vec::new();
    for (argv, source) in [
        (
            vec![
                "grant",
                "--to",
                "srv",
                "--credential",
                "api/demo",
                "--until",
                "1h",
            ],
            "preauthorization",
        ),
        (
            vec![
                "remote",
                "srv",
                "allow",
                "--credential",
                "api/demo",
                "--until",
                "1h",
            ],
            "settings",
        ),
    ] {
        let mut fake = Fake::new(temp.path());
        let result = run(&mut fake, &argv).unwrap();
        assert_eq!(fake.requests[1].params["source"], source);
        assert!(fake.requests[1].params.get("level").is_none());
        let Success::GrantsIssued { grants } = result else {
            panic!("Expected an issued Grant");
        };
        assert!(serde_json::to_value(&grants[0])
            .unwrap()
            .get("source")
            .is_none());
        let mut request = fake.requests[1].params.clone();
        request.as_object_mut().unwrap().remove("source");
        requests.push(request);
    }
    // Identical scope does not tell the CLI which authorization level the helper requires.
    assert_eq!(requests[0], requests[1]);
}

#[test]
fn unattended_confirmation_uses_helper_label_and_rejects_invalid_preparations() {
    let argv = [
        "remote",
        "srv",
        "unattended",
        "--include-sensitive",
        "--until",
        "7d",
    ];
    let prepared = json!({"confirmation_token":"one-use-helper-token","expires_at":NOW+120,
        "device_id":"dev_srv","label":"renamed-executor","confirmations_left":2});
    let temp = tempfile::tempdir().unwrap();
    let mut fake = Fake::new(temp.path());
    fake.replies.push_back((
        Op::DevicesList,
        Response::ok(json!({"devices":fake.directory})),
    ));
    fake.replies
        .push_back((Op::GrantIssue, Response::ok(prepared.clone())));
    fake.answers.extend([
        Some("renamed-executor".into()),
        Some("renamed-executor".into()),
    ]);
    run(&mut fake, &argv).unwrap();
    assert_eq!(fake.requests[2].params["confirm"], "renamed-executor");

    for (field, value) in [
        ("device_id", json!("dev_other")),
        ("label", json!("")),
        ("label", json!("hidden\nlabel")),
        ("confirmation_token", json!("")),
        ("confirmation_token", json!("x".repeat(257))),
    ] {
        let mut invalid = prepared.clone();
        invalid[field] = value;
        let mut fake = Fake::new(temp.path());
        fake.replies.push_back((
            Op::DevicesList,
            Response::ok(json!({"devices":fake.directory})),
        ));
        fake.replies
            .push_back((Op::GrantIssue, Response::ok(invalid)));
        fake.answers.push_back(Some("renamed-executor".into()));
        assert_eq!(run(&mut fake, &argv).unwrap_err().code, "invalid_response");
        assert_eq!(fake.ops(), [Op::DevicesList, Op::GrantIssue]);
        assert_eq!(fake.answers.len(), 1);
    }
}

#[test]
fn targets_prefer_ids_reject_ambiguous_labels_and_filter_revoked_devices() {
    let directory = vec![
        record("same", "one", true),
        record("dev_two", "same", true),
        record("dev_three", "same", true),
    ];
    assert_eq!(resolve("same", &directory).unwrap()[0].device_id, "same");
    assert_eq!(resolve("missing", &directory).unwrap_err().exit_code(), 2);
    let mut directory = directory;
    directory[0].label = "same".into();
    assert_eq!(
        resolve("one", &directory).unwrap_err().code,
        "unknown_device"
    );
    directory[0].device_id = "dev_one".into();
    assert_eq!(
        resolve("same", &directory).unwrap_err().code,
        "ambiguous_device"
    );
    directory[0].extra.insert("revoked".into(), json!(true));
    assert_eq!(resolve("*", &directory).unwrap().len(), 2);
}

#[test]
fn helper_errors_preserve_contract_exit_codes() {
    for (code, exit) in [
        ("forbidden", 3),
        ("insufficient_level", 3),
        ("pair_sas_mismatch", 3),
        ("directive_result_timeout", 4),
        ("expired", 4),
        ("relay_offline", 5),
        ("relay_unavailable", 5),
        ("relay_busy", 5),
        ("remote_unavailable", 5),
        ("strong_cancelled", 6),
        ("authentication_cancelled", 6),
    ] {
        let temp = tempfile::tempdir().unwrap();
        let mut fake = Fake::new(temp.path());
        fake.replies.push_back((
            Op::Decide,
            Response::err(code, "untrusted helper text \u{1b}[31m"),
        ));
        let error = run(&mut fake, &["approve", "approval_test"]).unwrap_err();
        assert_eq!(error.exit_code(), exit);
        assert_eq!(error.code, code);
        assert!(!error.message.contains("\u{1b}"));
    }
}

#[test]
fn parser_snapshots_preserve_argument_and_scope_shapes() {
    let snapshots: Vec<Value> =
        serde_json::from_str(include_str!("../../tests/snapshots/remote-parser.json")).unwrap();
    for case in snapshots {
        let args: Vec<String> = serde_json::from_value(case["argv"].clone()).unwrap();
        let parsed = Invocation::parse(&args).unwrap();
        assert_eq!(json!(parsed), case["parsed"], "{args:?}");
        let round_trip: Invocation = serde_json::from_value(case["parsed"].clone()).unwrap();
        assert_eq!(round_trip, parsed);
    }
    let invalid: Vec<Value> =
        serde_json::from_str(include_str!("../../tests/snapshots/remote-invalid.json")).unwrap();
    for case in invalid {
        let argv: Vec<String> = serde_json::from_value(case["argv"].clone()).unwrap();
        let error = Invocation::parse(&argv).unwrap_err();
        assert_eq!(error.code, case["code"].as_str().unwrap());
        assert_eq!(
            error.exit_code(),
            case["exit_code"].as_i64().unwrap() as i32
        );
        assert_eq!(
            shape(&json!({"ok":false,"error":error})),
            json!({"ok":"boolean","error":{"code":"string","message":"string"}})
        );
    }
}

#[test]
fn r3b_remote_audit_limit_matches_the_receiver_bound() {
    for limit in ["1", "200"] {
        let arguments = ["remote", "srv", "audit", "--limit", limit].map(str::to_owned);
        assert!(Invocation::parse(&arguments).is_ok());
    }
    for limit in ["0", "201", "1000", "1001"] {
        let arguments = ["remote", "srv", "audit", "--limit", limit].map(str::to_owned);
        assert!(Invocation::parse(&arguments).is_err());
    }
}

#[test]
fn invalid_arguments_never_reach_the_helper() {
    let cases: &[&[&str]] = &[
        &[],
        &["remote"],
        &["remote", "srv"],
        &["remote", "srv", "unknown"],
        &["remote", "srv", "lock", "extra"],
        &["remote", "srv", "lock", "--oops"],
        &["remote", "srv", "mode", "remember:0h"],
        &["remote", "srv", "mode", "remember:1d"],
        &["remote", "srv", "notify", "sometimes"],
        &["remote", "srv", "unlock-ttl", "-1h"],
        &["remote", "srv", "class", "batch"],
        &["remote", "srv", "class", "batch", "--exp", "4s"],
        &["remote", "srv", "audit", "--limit", "0"],
        &["remote", "srv", "audit", "--limit", "1001"],
        &[
            "remote",
            "srv",
            "allow",
            "--all",
            "--credential",
            "github/default",
        ],
        &[
            "remote",
            "srv",
            "allow",
            "--all",
            "--standing",
            "--until",
            "1h",
        ],
        &["remote", "srv", "allow", "--credential", "bad"],
        &[
            "remote",
            "srv",
            "allow",
            "--credential",
            "github/default",
            "--hosts",
            "https://api.github.com",
        ],
        &[
            "remote",
            "srv",
            "allow",
            "--credential",
            "github/default",
            "--methods",
            "get",
        ],
        &[
            "remote",
            "srv",
            "allow",
            "--credential",
            "github/default",
            "--paths",
            "relative",
        ],
        &["grant", "--to", "srv", "--credential", "github/default"],
        &[
            "grant",
            "--to",
            "srv",
            "--credential",
            "github/default",
            "--until",
            "1h",
            "--budget",
            "0/24h",
        ],
        &[
            "grant",
            "--to",
            "srv",
            "--credential",
            "github/default",
            "--until",
            "1h",
            "--budget",
            "500/2d",
        ],
        &[
            "grant",
            "--to",
            "srv",
            "--credential",
            "github/default",
            "--until",
            "1h",
            "--hosts",
            "api.github.com,",
        ],
        &["grant", "list", "extra"],
        &["devices", "list", "--json", "--json"],
        &["devices", "revoke", "*"],
        &["devices", "rename", "dev_srv"],
        &["devices", "rename", "dev_srv", "bad\u{1b}"],
        &["deny", "approval_test", "--scope", "per_use"],
        &["approve", "approval_test", "--scope", "remember:2h"],
        &["approvals", "--watch", "--watch"],
        &[
            "relay",
            "install",
            "--public-url",
            "https://relay.example.com",
            "--listen",
            "0.0.0.0:8787",
        ],
        &[
            "relay",
            "install",
            "--public-url",
            "https://relay.example.com",
            "--listen",
            "127.0.0.1:0",
        ],
        &[
            "relay",
            "install",
            "--public-url",
            "https://relay.example.com",
            "--data",
            "relative",
        ],
        &[
            "relay",
            "install",
            "--public-url",
            "https://relay.example.com",
            "--data",
            "/tmp/../root",
        ],
        &[
            "relay",
            "install",
            "--public-url",
            "https://relay.example.com/path",
        ],
        &["relay", "install", "--public-url", "http://127.0.0.1:8787"],
        &[
            "relay",
            "set-url",
            "https://user:password@relay.example.com",
        ],
        &[
            "relay",
            "status",
            "--public-url",
            "https://relay.example.com?token=secret",
        ],
        &["pair", "--new", URI],
        &[
            "pair",
            "kv-pair://relay.example.com/AAAAAAAAAAAAAAAAAAAAAAAAAB",
        ],
        &["status", "--summary", "extra"],
    ];
    for args in cases {
        let temp = tempfile::tempdir().unwrap();
        let mut fake = Fake::new(temp.path());
        let error = run(&mut fake, args).unwrap_err();
        assert_eq!(error.exit_code(), 2, "{args:?}: {error:?}");
        assert!(fake.requests.is_empty());
    }
}

#[test]
fn durations_and_rfc3339_validate_calendar_offsets_and_overflow() {
    for (text, seconds) in [("1s", 1), ("2m", 120), ("3h", 10800), ("7d", 604800)] {
        assert_eq!(args::duration(text).unwrap(), seconds);
    }
    for text in [
        "",
        "0s",
        "-1h",
        "2.5h",
        "1H",
        "1💥",
        "18446744073709551615d",
    ] {
        assert!(args::duration(text).is_err(), "{text}");
    }
    assert_eq!(args::until("1970-01-01T00:00Z", -1).unwrap(), 0);
    assert_eq!(
        args::until("1970-01-01T00:00:00+08:00", -28801).unwrap(),
        -28800
    );
    assert_eq!(args::until("1970-01-01T00:00:01-01:30", 0).unwrap(), 5401);
    assert_eq!(args::since("24h", NOW).unwrap(), NOW - 86400);
    assert_eq!(args::until("1h", NOW).unwrap(), NOW + 3600);
    for date in [
        "2025-02-29T00:00Z",
        "2026-13-01T00:00Z",
        "2026-04-31T00:00Z",
        "2026-01-00T00:00Z",
        "2026-01-01T24:00Z",
        "2026-01-01T00:60Z",
        "2026-01-01T00:00:60Z",
        "2026-01-01T00:00",
        "2026-01-01T00:00+24:00",
        "💥2026-01-01T00:00Z",
    ] {
        assert!(args::until(date, 0).is_err(), "{date}");
    }
    assert!(args::until("2024-02-29T00:00Z", 0).is_ok());
    assert!(args::until("1h", i64::MAX).is_err());
    assert!(args::until("2026-01-01T00:00Z", NOW).is_err());
    assert!(args::since("2026-12-01T00:00Z", NOW).is_err());
    assert!(args::since("1h", i64::MIN).is_err());
}

#[test]
fn expired_grants_and_confirmation_tokens_are_never_issued() {
    let temp = tempfile::tempdir().unwrap();
    let mut fake = Fake::new(temp.path());
    let error = run(
        &mut fake,
        &[
            "remote",
            "srv",
            "allow",
            "--all",
            "--until",
            "2020-01-01T00:00Z",
        ],
    )
    .unwrap_err();
    assert_eq!(error.exit_code(), 2);
    assert_eq!(fake.ops(), [Op::DevicesList]);
    let mut fake = Fake::new(temp.path());
    fake.replies.push_back((
        Op::DevicesList,
        Response::ok(json!({"devices":fake.directory})),
    ));
    fake.replies.push_back((
        Op::GrantIssue,
        Response::ok(json!({"confirmation_token":"expired","expires_at":NOW,"device_id":"dev_srv","label":"srv"})),
    ));
    fake.answers.push_back(Some("srv".into()));
    assert_eq!(
        run(
            &mut fake,
            &[
                "remote",
                "srv",
                "unattended",
                "--include-sensitive",
                "--until",
                "7d"
            ]
        )
        .unwrap_err()
        .exit_code(),
        4
    );
    assert_eq!(fake.ops(), [Op::DevicesList, Op::GrantIssue]);
    assert_eq!(fake.answers.len(), 1);
}

#[test]
fn wildcard_grants_include_future_executors_but_t2_requires_each_label() {
    let temp = tempfile::tempdir().unwrap();
    let mut fake = Fake::new(temp.path());
    run(&mut fake, &["remote", "*", "allow", "--all", "--standing"]).unwrap();
    assert_eq!(fake.requests[1].params["aud"], "*");
    assert_eq!(fake.requests[1].params["scope"]["level"], "global");
    assert_eq!(fake.notices.len(), 1);
    let mut fake = Fake::new(temp.path());
    fake.answers.extend([
        Some("srv".into()),
        Some("srv".into()),
        Some("other".into()),
        Some("other".into()),
    ]);
    let Success::GrantsIssued { grants } = run(
        &mut fake,
        &[
            "remote",
            "*",
            "unattended",
            "--include-sensitive",
            "--until",
            "7d",
        ],
    )
    .unwrap() else {
        panic!()
    };
    assert_eq!(grants.len(), 2);
    assert_eq!(grants[0].aud, "dev_srv");
    assert_eq!(grants[1].aud, "dev_other");
    assert_eq!(
        fake.ops(),
        [
            Op::DevicesList,
            Op::GrantIssue,
            Op::GrantIssue,
            Op::GrantIssue,
            Op::GrantIssue,
            Op::GrantIssue,
            Op::GrantIssue
        ]
    );
}

#[test]
fn pairing_polls_displays_sas_and_rejects_cancel_timeout_mismatch() {
    let temp = tempfile::tempdir().unwrap();
    let mut fake = Fake::new(temp.path());
    fake.replies.push_back((
        Op::PairStart,
        Response::ok(json!({"uri":URI,"sas":"","expires_at":NOW+600})),
    ));
    fake.waits = 1;
    fake.answers.push_back(Some("Y".into()));
    let result = run(&mut fake, &["pair", "--new", "--json"]).unwrap();
    assert_eq!(fake.ops(), [Op::PairStart, Op::Status, Op::PairConfirm]);
    assert_eq!(fake.emitted.len(), 2);
    assert_eq!(json!(result)["result"]["paired"], true);
    assert_eq!(
        fake.requests[2].params,
        json!({"sas":"123456","confirmed":true})
    );
    for answer in [None, Some("n"), Some("yes"), Some("wrong")] {
        let mut fake = Fake::new(temp.path());
        fake.answers.push_back(answer.map(str::to_owned));
        assert_eq!(run(&mut fake, &["pair", URI]).unwrap_err().exit_code(), 6);
        assert_eq!(fake.ops(), [Op::PairComplete]);
    }
    let mut fake = Fake::new(temp.path());
    fake.replies.push_back((
        Op::PairStart,
        Response::ok(json!({"uri":URI,"sas":"","expires_at":NOW})),
    ));
    assert_eq!(
        run(&mut fake, &["pair", "--new"]).unwrap_err().exit_code(),
        4
    );
    let mut fake = Fake::new(temp.path());
    fake.answers.push_back(Some("y".into()));
    fake.replies
        .push_back((Op::PairComplete, Response::ok(json!({"sas":"123456"}))));
    fake.replies.push_back((
        Op::PairConfirm,
        Response::err("pair_sas_mismatch", "ignored"),
    ));
    assert_eq!(
        run(&mut fake, &["pair", URI]).unwrap_err().code,
        "pair_sas_mismatch"
    );
    let mut fake = Fake::new(temp.path());
    fake.replies
        .push_back((Op::PairComplete, Response::ok(json!({"sas":"12\u{1b}456"}))));
    assert_eq!(
        run(&mut fake, &["pair", URI]).unwrap_err().code,
        "invalid_response"
    );
}

#[test]
fn pairing_saves_only_public_binding_and_waits_for_both_confirmations() {
    let temp = tempfile::tempdir().unwrap();
    let mut fake = Fake::new(temp.path());
    let binding = json!({"relay_url":"https://relay.example.com","device_id":"registered-device","account_id":"registered-account"});
    fake.replies.push_back((
        Op::PairStart,
        Response::ok(
            json!({"uri":URI,"sas":"123456","binding":binding,"recovery_code":"one-time-recovery"}),
        ),
    ));
    fake.replies
        .push_back((Op::PairConfirm, Response::ok(json!({}))));
    fake.replies.push_back((
        Op::Status,
        Response::ok(json!({"pairing":{"state":"waiting"}})),
    ));
    fake.replies.push_back((
        Op::Status,
        Response::ok(json!({"pairing":{"state":"completed"}})),
    ));
    fake.waits = 1;
    fake.answers.push_back(Some("y".into()));
    assert_eq!(
        json!(run(&mut fake, &["pair", "--new", "--json"]).unwrap())["result"]["paired"],
        true
    );
    assert_eq!(
        fake.ops(),
        [Op::PairStart, Op::PairConfirm, Op::Status, Op::Status]
    );
    assert!(
        matches!(&fake.emitted[0].output,Success::PairRecovery{recovery_code,account_id:Some(account)} if recovery_code=="one-time-recovery" && account=="registered-account")
    );
    let public = std::fs::read_to_string(&fake.config).unwrap();
    assert!(public.contains("registered-device") && public.contains("registered-account"));
    assert!(!public.contains("recovery") && !public.contains("private"));
    let mut fake = Fake::new(temp.path());
    fake.replies.push_back((Op::PairStart,Response::ok(json!({"sas":"","binding":binding,"recovery_code":"one-time-recovery","pair_error":"relay_unreachable"}))));
    assert_eq!(
        run(&mut fake, &["pair", "--new"]).unwrap_err().exit_code(),
        5
    );
    assert_eq!(fake.emitted.len(), 1);
    assert_eq!(fake.ops(), [Op::PairStart]);
}

#[test]
fn pairing_recovery_and_completion_failures_preserve_the_owner_boundary() {
    let temp = tempfile::tempdir().unwrap();
    for code in ["".to_owned(), "invalid\ncode".to_owned(), "x".repeat(257)] {
        let mut fake = Fake::new(temp.path());
        fake.replies.push_back((
            Op::PairStart,
            Response::ok(json!({"sas":"123456","uri":URI,"recovery_code":code})),
        ));
        assert_eq!(
            run(&mut fake, &["pair", "--new"]).unwrap_err().code,
            "invalid_response"
        );
        assert!(fake.emitted.is_empty());
    }
    let mut fake = Fake::new(temp.path());
    fake.replies.push_back((
        Op::PairStart,
        Response::ok(json!({"sas":"123456","uri":URI,"recovery_code":"once"})),
    ));
    fake.fail_emit_at = Some(1);
    assert!(run(&mut fake, &["pair", "--new"]).is_err());
    assert_eq!(fake.ops(), [Op::PairStart]);
    let binding = json!({"relay_url":"https://relay.example.com","device_id":"device","account_id":"account"});
    for variant in 0..3 {
        let mut fake = Fake::new(temp.path());
        fake.answers.push_back(Some("y".into()));
        fake.waits = usize::from(variant == 1);
        fake.replies.push_back((Op::PairStart,Response::ok(json!({"sas":"123456","uri":URI,"binding":binding,"expires_at":NOW+if variant==1 {1} else {600}}))));
        fake.replies
            .push_back((Op::PairConfirm, Response::ok(json!({}))));
        for _ in 0..2 {
            fake.replies.push_back((
                Op::Status,
                Response::ok(if variant == 0 {
                    json!({"pairing":{"error":"pair_sas_mismatch"}})
                } else {
                    json!({"pairing":{"state":"waiting"}})
                }),
            ));
        }
        assert_eq!(
            run(&mut fake, &["pair", "--new"]).unwrap_err().code,
            ["pair_sas_mismatch", "pair_timeout", "user_cancelled"][variant]
        );
    }
    let recovery = Success::PairRecovery {
        recovery_code: "once\u{1b}red".into(),
        account_id: Some("account\u{1b}id".into()),
    };
    let displayed = output::render(&recovery, false, false);
    assert!(!displayed.contains('\u{1b}'));
    assert!(displayed.contains("once"));
    let path = temp.path().join("fresh-binding.toml");
    let mut binding: kv_core::remote::ipc::RelayBinding = serde_json::from_value(binding).unwrap();
    relay::Config::set_binding(&path, &binding).unwrap();
    assert_eq!(
        relay::Config::read(&path).unwrap().device_id.as_deref(),
        Some("device")
    );
    for value in ["".into(), "x".repeat(257), "bad\naccount".into()] {
        binding.account_id = value;
        assert!(relay::Config::set_binding(&path, &binding).is_err());
    }
}

#[test]
fn watch_hooks_only_new_observed_approvals_once_and_never_denials_or_removals() {
    let temp = tempfile::tempdir().unwrap();
    let mut fake = Fake::new(temp.path());
    let history = json!({"approval_id":"old","decision":"allow","summary":"old metadata"});
    fake.pending.extend([
        json!({"pending":[{"approval_id":"new","summary":"GET /repos/u","state":"waiting"},{"approval_id":"denied","summary":"DELETE /repos/u"},{"approval_id":"expired","summary":"unused"}],"recent":[history]}),
        json!({"pending":[],"recent":[history,{"approval_id":"new","decision":"allow"},{"approval_id":"denied","decision":"deny"}]}),
        json!({"pending":[],"recent":[history,{"approval_id":"new","decision":"allow"},{"approval_id":"denied","decision":"deny"}]}),
    ]);
    fake.waits = 2;
    run(
        &mut fake,
        &["approvals", "--on-approve", "my-command", "--json"],
    )
    .unwrap();
    assert_eq!(
        fake.ops(),
        [Op::PendingList, Op::PendingList, Op::PendingList]
    );
    assert_eq!(
        fake.hooks,
        [("my-command".into(), "new".into(), "GET /repos/u".into())]
    );
    assert_eq!(fake.emitted.len(), 2);
}

#[test]
fn watch_history_sequence_prevents_replaying_rotated_history() {
    let temp = tempfile::tempdir().unwrap();
    let mut fake = Fake::new(temp.path());
    fake.pending.extend([
        json!({"pending":[{"approval_id":"new","summary":"GET /owner"}],"recent":[{"approval_id":"old","decision":"allow","decision_seq":20}]}),
        json!({"pending":[],"recent":[{"approval_id":"new","decision":"allow","decision_seq":21}]}),
        json!({"pending":[],"recent":[]}),
        json!({"pending":[{"approval_id":"new","summary":"GET /owner"}],"recent":[{"approval_id":"new","decision":"allow","decision_seq":21}]}),
    ]);
    fake.waits = 3;
    run(&mut fake, &["approvals", "--on-approve", "owner-hook"]).unwrap();
    assert_eq!(
        fake.hooks,
        [("owner-hook".into(), "new".into(), "GET /owner".into())]
    );
}

#[test]
fn invalid_or_denied_helper_responses_fail_closed() {
    let temp = tempfile::tempdir().unwrap();
    let mut fake = Fake::new(temp.path());
    fake.replies
        .push_back((Op::Decide, Response::ok(json!({"sent":false}))));
    assert_eq!(
        run(&mut fake, &["approve", "approval_test"])
            .unwrap_err()
            .code,
        "invalid_response"
    );
    let mut fake = Fake::new(temp.path());
    fake.replies.push_back((
        Op::DevicesList,
        Response::ok(json!({"devices":fake.directory})),
    ));
    fake.replies.push_back((
        Op::DirectiveIssue,
        Response::ok(
            json!({"result":{"id":"id","ok":false,"error":"insufficient_level","state":{}}}),
        ),
    ));
    assert_eq!(
        run(&mut fake, &["remote", "srv", "lock"])
            .unwrap_err()
            .exit_code(),
        3
    );
    let mut fake = Fake::new(temp.path());
    fake.replies
        .push_back((Op::DevicesList, Response::ok(json!({"devices":"invalid"}))));
    assert_eq!(
        run(&mut fake, &["devices", "list"])
            .unwrap_err()
            .exit_code(),
        3
    );
}

#[test]
fn relay_install_writes_w2_assets_and_preserves_client_identity() {
    let temp = tempfile::tempdir().unwrap();
    let mut fake = Fake::new(temp.path());
    let result = run(
        &mut fake,
        &[
            "relay",
            "install",
            "--public-url",
            "https://new.example.com",
            "--listen",
            "127.0.0.1:8788",
            "--data",
            "/var/lib/my relay%$data",
        ],
    )
    .unwrap();
    let Success::RelayInstall(result) = result else {
        panic!()
    };
    let service = std::fs::read_to_string(result.service).unwrap();
    assert!(service.contains("Restart=always"));
    assert!(service.contains("User=keyvalet-relay-server"));
    assert!(service.contains("--listen 127.0.0.1:8788 --data \"/var/lib/my relay%%$$data\""));
    assert!(service.contains("ReadWritePaths=\"/var/lib/my relay%%$data\""));
    let nginx = std::fs::read_to_string(result.nginx).unwrap();
    for part in [
        "server_name new.example.com;",
        "proxy_pass http://127.0.0.1:8788;",
        "proxy_read_timeout 90s;",
        "client_max_body_size 1m;",
        "proxy_set_header Upgrade $http_upgrade;",
        "origin.pem",
        "origin.key",
        "# ssl_verify_client on;",
    ] {
        assert!(nginx.contains(part), "{part}");
    }
    let config = relay::Config::read(&fake.config).unwrap();
    assert_eq!(config.relay_url, "https://new.example.com");
    assert_eq!(config.device_id.as_deref(), Some("dev_local"));
    assert_eq!(config.account_id.as_deref(), Some("acct_test"));
    assert!(fake.requests.is_empty());
    run(&mut fake, &["relay", "status"]).unwrap();
    assert_eq!(fake.health_url.as_deref(), Some("https://new.example.com"));
    run(&mut fake, &["relay", "set-url", "https://last.example.com"]).unwrap();
    assert_eq!(
        relay::Config::read(&fake.config).unwrap().relay_url,
        "https://last.example.com"
    );
}

#[test]
fn config_rejects_unknown_private_fields_and_atomic_writes_do_not_follow_symlinks() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("relay-client.toml");
    for text in [
        "relay_url='https://relay.example.com'\nprivate_key='secret'",
        "relay_url='https://relay.example.com'\nrelay_url='https://other.example.com'",
        "relay_url=123",
        "relay_url='https://relay.example.com' garbage",
        "relay_url='https://relay.example.com'\ndevice_id=''",
        "[relay]\nrelay_url='https://relay.example.com'",
    ] {
        std::fs::write(&path, text).unwrap();
        assert!(relay::Config::set_url(&path, "https://new.example.com").is_err());
        assert_eq!(std::fs::read_to_string(&path).unwrap(), text);
    }
    std::fs::write(&path,"# comment\n relay_url = \"https://relay.example.com\" # inline\n device_id='dev_test'\n account_id=\"acct_test\"\n").unwrap();
    relay::Config::set_url(&path, "https://new.example.com").unwrap();
    assert_eq!(
        relay::Config::read(&path).unwrap().device_id.as_deref(),
        Some("dev_test")
    );
    #[cfg(unix)]
    {
        let other = temp.path().join("private");
        std::fs::write(&other, "unchanged").unwrap();
        let link = temp.path().join("link");
        std::os::unix::fs::symlink(&other, &link).unwrap();
        assert_eq!(
            relay::atomic_write(&link, "overwrite").unwrap_err().code,
            "unsafe_path"
        );
        assert_eq!(std::fs::read_to_string(other).unwrap(), "unchanged");
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
}

#[test]
fn relay_url_and_health_validation_are_bounded_and_allow_only_loopback_http() {
    for text in [
        "https://relay.example.com",
        "https://relay.example.com/base/",
        "http://127.0.0.1:8787",
        "http://[::1]:8787",
    ] {
        assert!(relay::RelayUrl::parse(text).is_ok(), "{text}");
    }
    for text in [
        "http://localhost:8787",
        "http://192.0.2.1",
        "ftp://relay.example.com",
        "https://",
        "https://relay.example.com:0",
        "https://relay.example.com:bad",
        "https://relay.example.com\r\nHeader: value",
        "https://-invalid.com",
        "https://a..b",
        "https://relay.example.com/../x",
    ] {
        assert!(relay::RelayUrl::parse(text).is_err(), "{text}");
    }
    assert_eq!(
        relay::RelayUrl::parse("https://relay.example.com/base/")
            .unwrap()
            .health_url(),
        "https://relay.example.com/base/v1/health"
    );
    assert_eq!(
        relay::RelayUrl::parse("https://relay.example.com/base//v1")
            .unwrap()
            .health_url(),
        "https://relay.example.com/base//v1/v1/health"
    );
    assert!(relay::parse_health(br#"{"ok":true,"version":"0.3.0"}"#).is_ok());
    for bytes in [
        b"{}".as_slice(),
        br#"{"ok":false,"version":"0.3.0"}"#,
        br#"{"ok":true,"version":""}"#,
    ] {
        assert_eq!(relay::parse_health(bytes).unwrap_err().exit_code(), 5);
    }
    assert!(relay::parse_health(&vec![b'a'; 64 * 1024 + 1]).is_err());
}

#[test]
fn chunked_health_responses_support_extensions_and_reject_truncated_framing() {
    use std::io::{Read, Write};
    let body = r#"{"ok":true,"version":"0.3.0"}"#;
    let (first, second) = body.split_at(8);
    let chunks = format!(
        "{:x};health=yes\r\n{first}\r\n{:x}\r\n{second}\r\n",
        first.len(),
        second.len()
    );
    let cases = [
        (format!("{chunks}0\r\n\r\n"), true),
        (format!("{chunks}0\r\nX-Health: ready\r\n\r\n"), true),
        (format!("{chunks}0\r\n"), false),
        (format!("{chunks}0\r\ninvalid-trailer\r\n\r\n"), false),
        (format!("{chunks}0\r\n\r\nextra"), false),
        (
            format!("{:x}\r\n{body}\r\n0\r\n\r\n", body.len() + 1),
            false,
        ),
        ("ffffffffffffffffffffffff\r\n".into(), false),
        ("not-hex\r\n".into(), false),
    ];
    for (response, valid) in cases {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let worker = std::thread::spawn(move || {
            let (mut socket, _) = listener.accept().unwrap();
            let mut request = Vec::new();
            while !request.ends_with(b"\r\n\r\n") {
                let mut byte = [0];
                socket.read_exact(&mut byte).unwrap();
                request.push(byte[0]);
                assert!(request.len() <= 4096);
            }
            assert!(request.starts_with(b"GET /v1/health HTTP/1.1\r\n"));
            write!(socket, "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n{response}").unwrap();
        });
        let url = relay::RelayUrl::parse(&format!("http://{address}")).unwrap();
        let result = system::http_health(&url);
        if valid {
            assert!(result.unwrap().ok);
        } else {
            assert_eq!(result.unwrap_err().exit_code(), 5);
        }
        worker.join().unwrap();
    }
}

#[test]
fn loopback_health_and_fake_helper_socket_use_real_http_and_ipc_framing() {
    use std::io::{Read, Write};
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let thread = std::thread::spawn(move || {
        let (mut socket, _) = listener.accept().unwrap();
        let mut request = Vec::new();
        while !request.ends_with(b"\r\n\r\n") {
            let mut byte = [0];
            socket.read_exact(&mut byte).unwrap();
            request.push(byte[0]);
            assert!(request.len() <= 4096);
        }
        assert!(std::str::from_utf8(&request)
            .unwrap()
            .starts_with("GET /v1/health HTTP/1.1\r\n"));
        let body = r#"{"ok":true,"version":"0.3.0"}"#;
        write!(
            socket,
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        )
        .unwrap();
    });
    let url = relay::RelayUrl::parse(&format!("http://{address}")).unwrap();
    assert!(system::http_health(&url).unwrap().ok);
    thread.join().unwrap();
    #[cfg(unix)]
    {
        use std::io::BufRead;
        let (mut client, server) = std::os::unix::net::UnixStream::pair().unwrap();
        let worker = std::thread::spawn(move || {
            let mut reader = std::io::BufReader::new(server);
            let mut line = String::new();
            reader.read_line(&mut line).unwrap();
            let request: Request = serde_json::from_str(&line).unwrap();
            assert_eq!(request.op, Op::Decide);
            reader
                .get_mut()
                .write_all(b"{\"ok\":true,\"result\":{\"sent\":true}}\n")
                .unwrap();
        });
        let request = Request {
            op: Op::Decide,
            params: json!({"approval_id":"approval_test","decision":"allow","scope":"per_use"}),
            extra: Extra::new(),
        };
        assert!(matches!(
            system::exchange_stream(&mut client, &request).unwrap(),
            Response::Ok { .. }
        ));
        worker.join().unwrap();
    }
}

#[test]
fn response_framing_rejects_truncation_duplicates_and_oversized_frames() {
    struct Stream {
        reply: std::io::Cursor<Vec<u8>>,
        written: Vec<u8>,
    }
    impl std::io::Read for Stream {
        fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
            self.reply.read(out)
        }
    }
    impl std::io::Write for Stream {
        fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
            self.written.extend(b);
            Ok(b.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let request = Request {
        op: Op::Status,
        params: json!({}),
        extra: Extra::new(),
    };
    for reply in [
        b"{\"ok\":true,\"result\":{}}".to_vec(),
        b"{\"ok\":true,\"ok\":false,\"result\":{}}\n".to_vec(),
        vec![b'a'; 1024 * 1024 + 1],
        b"null\n".to_vec(),
    ] {
        let mut stream = Stream {
            reply: std::io::Cursor::new(reply),
            written: vec![],
        };
        assert_eq!(
            system::exchange_stream(&mut stream, &request)
                .unwrap_err()
                .code,
            "invalid_response"
        );
        assert_eq!(stream.written.last(), Some(&b'\n'));
    }
}

fn shape(value: &Value) -> Value {
    match value {
        Value::Null => json!("null"),
        Value::Bool(_) => json!("boolean"),
        Value::Number(_) => json!("number"),
        Value::String(_) => json!("string"),
        Value::Array(array) => json!(array.first().map(shape).into_iter().collect::<Vec<_>>()),
        Value::Object(object) => Value::Object(
            object
                .iter()
                .map(|(key, value)| {
                    (
                        key.clone(),
                        if key == "command" {
                            value.clone()
                        } else {
                            shape(value)
                        },
                    )
                })
                .collect(),
        ),
    }
}

#[test]
fn every_success_variant_has_a_stable_json_schema_snapshot() {
    let cases: &[&[&str]] = &[
        &["remote", "--help"],
        &[
            "relay",
            "install",
            "--public-url",
            "https://relay.example.com",
        ],
        &["relay", "status"],
        &["relay", "set-url", "https://relay.example.com"],
        &["pair", "--new"],
        &["devices", "list"],
        &["devices", "revoke", "dev_srv"],
        &["devices", "rename", "dev_srv", "build"],
        &["approvals"],
        &["approve", "approval_test"],
        &["remote", "srv", "allow", "--all", "--until", "1h"],
        &["grant", "list"],
        &["grant", "revoke", "jti_test"],
        &["remote", "srv", "lock"],
        &["status", "--summary"],
    ];
    let expected: Value = serde_json::from_str(include_str!(
        "../../tests/snapshots/remote-json-schema.json"
    ))
    .unwrap();
    let mut actual = serde_json::Map::new();
    for args in cases {
        let temp = tempfile::tempdir().unwrap();
        let mut fake = Fake::new(temp.path());
        fake.answers.push_back(Some("y".into()));
        let result = run(&mut fake, args).unwrap();
        let body = output::JsonSuccess {
            ok: true,
            output: result,
        };
        let value = json!(body);
        let key = value["command"].as_str().unwrap().to_owned();
        let round_trip: output::JsonSuccess = serde_json::from_value(value.clone()).unwrap();
        assert_eq!(json!(round_trip), value);
        actual.insert(key, shape(&value));
    }
    assert_eq!(Value::Object(actual), expected);
}

#[test]
fn wildcard_t2_cancellation_never_issues_a_partial_grant() {
    let temp = tempfile::tempdir().unwrap();
    let mut fake = Fake::new(temp.path());
    fake.answers.extend([Some("srv".into()), None]);
    assert_eq!(
        run(
            &mut fake,
            &[
                "remote",
                "*",
                "unattended",
                "--include-sensitive",
                "--until",
                "7d"
            ]
        )
        .unwrap_err()
        .exit_code(),
        6
    );
    assert_eq!(
        fake.ops(),
        [Op::DevicesList, Op::GrantIssue, Op::GrantIssue]
    );
    assert!(fake
        .requests
        .iter()
        .skip(1)
        .all(|r| r.params["confirmation_token"] != "one-use-helper-second-token"));
}

#[test]
fn wildcard_failure_reports_completed_devices_and_local_status_survives_offline_helper() {
    let temp = tempfile::tempdir().unwrap();
    let mut fake = Fake::new(temp.path());
    fake.replies.extend([
        (
            Op::DevicesList,
            Response::ok(json!({"devices":fake.directory})),
        ),
        (
            Op::DirectiveIssue,
            Response::ok(json!({"result":{"id":"id","ok":true,"error":null,"state":{}}})),
        ),
        (Op::DirectiveIssue, Response::err("forbidden", "ignored")),
    ]);
    let error = run(&mut fake, &["remote", "*", "lock"]).unwrap_err();
    assert_eq!(error.exit_code(), 3);
    assert_eq!(error.completed_devices, ["dev_srv"]);
    assert_eq!(json!(error)["completed_devices"], json!(["dev_srv"]));
    for code in ["remote_unavailable", "forbidden", "ipc_unavailable"] {
        let mut fake = Fake::new(temp.path());
        fake.replies
            .push_back((Op::Status, Response::err(code, "ignored")));
        let result = run(&mut fake, &["status", "--summary"]).unwrap();
        assert_eq!(json!(result)["result"]["remote"], Value::Null);
        assert_eq!(
            json!(result)["result"]["protection"]["provider"],
            "software_key"
        );
        assert_eq!(fake.ops(), [Op::Status]);
        let rendered = output::render(&result, false, true);
        assert!(rendered.contains(&kv_i18n::t("relay：", "Relay:")));
        assert!(rendered.contains(&kv_i18n::t(
            "未知（远程 helper 未就绪）",
            "unknown (remote helper unavailable)"
        )));
    }
}

#[test]
fn terminal_metadata_is_escaped_but_json_remains_lossless() {
    assert_eq!(
        output::terminal_text("host\u{1b}[31m\nlabel"),
        "host?[31m?label"
    );
    let temp = tempfile::tempdir().unwrap();
    let mut fake = Fake::new(temp.path());
    fake.directory[0].label = "host\u{1b}[31m".into();
    let result = run(&mut fake, &["devices", "list"]).unwrap();
    assert!(!output::render(&result, false, false).contains('\u{1b}'));
    assert_eq!(
        json!(result)["result"]["devices"][0]["label"],
        "host\u{1b}[31m"
    );
    let mut fake = Fake::new(temp.path());
    fake.replies.push_back((Op::Status,Response::ok(json!({"relay":"connected","approvers":[],"pending_n":0,"grants_n":1,"unattended":true,"runtime_budget_s":50}))));
    let result = run(&mut fake, &["status", "--summary"]).unwrap();
    assert!(output::render(&result, true, true).contains("\u{1b}[31m"));
    assert!(!output::render(&result, false, true).contains('\u{1b}'));
    let mut fake = Fake::new(temp.path());
    fake.replies.extend([
        (
            Op::DevicesList,
            Response::ok(json!({"devices":fake.directory})),
        ),
        (
            Op::DirectiveIssue,
            Response::ok(json!({"result":{"id":"query","ok":true,
            "error":null,"state":{"unattended":true}}})),
        ),
    ]);
    let result = run(&mut fake, &["remote", "srv", "status"]).unwrap();
    assert!(output::render(&result, true, false).contains("\u{1b}[31m"));
    assert!(!output::render(&result, false, false).contains('\u{1b}'));
    assert_eq!(
        json!(result)["result"]["results"][0]["result"]["state"]["unattended"],
        true
    );
}
