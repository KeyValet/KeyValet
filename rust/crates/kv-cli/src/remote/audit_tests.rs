use super::*;
use kv_core::remote::audit::{AuditHead, AuditPage};

#[test]
fn r3a_remote_archive_requires_the_pinned_old_key_and_signed_successor_head() {
    use kv_core::remote::keys::{sign_object, DeviceKeyProvider, SoftwareDeviceKey};
    use kv_core::remote::SignatureAlgorithm;
    let dir = tempfile::tempdir().unwrap();
    let fake = Fake::new(dir.path());
    let old_key = SoftwareDeviceKey::from_p256_bytes(&[1; 32]).unwrap();
    let next_key = SoftwareDeviceKey::from_p256_bytes(&[2; 32]).unwrap();
    let mut old = fake.directory[0].clone();
    old.device_id = "dev_old".into();
    old.dk_pub = old_key.public_jwk().unwrap();
    let mut next = old.clone();
    next.device_id = "dev_new".into();
    next.dk_pub = next_key.public_jwk().unwrap();
    let archived: AuditPage = serde_json::from_value(page("dev_old", vec![], 0, None)).unwrap();
    let mut proof = json!({"domain":"keyvalet.audit-archive.v1","account":archived.account_id,
        "predecessor":old,"successor":next,"head":archived.head});
    proof["sig"] = json!(sign_object(&proof, SignatureAlgorithm::ES256, &old_key).unwrap());
    assert!(audit::verify_archive(&next, &archived, &[proof.clone()], &[old.clone()]).is_ok());
    assert!(audit::verify_archive(&next, &archived, &[proof.clone()], &[]).is_err());
    for field in [
        "head",
        "successor",
        "predecessor",
        "account",
        "domain",
        "sig",
    ] {
        let mut bad = proof.clone();
        match field {
            "head" => bad["head"]["hash"] = json!("f".repeat(64)),
            "successor" => bad["successor"]["device_id"] = json!("substituted"),
            "predecessor" => bad["predecessor"]["dk_pub"] = json!(next.dk_pub),
            "account" => bad["account"] = json!("foreign-account"),
            "domain" => bad["domain"] = json!("grant"),
            "sig" => bad["sig"] = json!("invalid"),
            _ => unreachable!(),
        }
        assert!(
            audit::verify_archive(&next, &archived, &[bad], &[old.clone()]).is_err(),
            "{field}"
        );
    }
}

#[test]
fn archived_audit_rejects_untrusted_selectors_and_wrong_history_identity() {
    for variant in 0..6 {
        let dir = tempfile::tempdir().unwrap();
        let mut fake = Fake::new(dir.path());
        let mut current = page("dev_new", vec![], 0, None);
        current["archived_devices"] = match variant {
            0 => json!(["dev_old", "dev_old"]),
            1 => json!(["dev_new"]),
            2 => json!([""]),
            3 => json!(false),
            _ => json!(["dev_old"]),
        };
        fake.replies
            .push_back((Op::AuditList, Response::ok(current)));
        if variant >= 4 {
            let mut old = page(
                if variant == 4 {
                    "dev_foreign"
                } else {
                    "dev_old"
                },
                vec![],
                0,
                None,
            );
            if variant == 5 {
                old["account_id"] = json!("another_account");
            }
            fake.replies.push_back((Op::AuditList, Response::ok(old)));
        }
        assert!(invoke(&mut fake, &["audit", "--remote", "--json"]).is_err());
        assert!(fake.emitted.is_empty());
        assert!(fake
            .requests
            .iter()
            .all(|request| request.op == Op::AuditList));
    }
}

#[test]
fn r3a_rejoined_endpoint_keeps_the_old_identity_audit_in_the_full_comparison() {
    let dir = tempfile::tempdir().unwrap();
    let mut fake = Fake::new(dir.path());
    fake.directory.truncate(1);
    let mut current = page("dev_new", vec![], 0, None);
    current["archived_devices"] = json!(["dev_old"]);
    fake.replies.extend([
        (Op::AuditList, Response::ok(current)),
        (Op::AuditList, Response::ok(page("dev_old", vec![json!({"op":"directive_issued","id":"old-query","peer":"dev_srv","directive_op":"query_grants","directive_hash":"original-digest","audit_seq":1,"ts_unix":NOW-60})], 1, None))),
        (Op::DevicesList, Response::ok(json!({"devices":fake.directory}))),
        (Op::DirectiveIssue, Response::ok(json!({"result":{"id":"query","ok":true,"state":page("dev_srv", vec![], 0, None)}}))),
    ]);
    assert_eq!(
        invoke(&mut fake, &["audit", "--remote", "--json"])
            .unwrap_err()
            .exit_code(),
        3
    );
    let Success::Audit(report) = &fake.emitted[0].output else {
        panic!("missing report")
    };
    assert_eq!(report.comparison.findings.len(), 1);
    assert_eq!(report.comparison.findings[0].issuer, "dev_old");
    assert_eq!(report.comparison.findings[0].id, "old-query");
    assert_eq!(fake.requests[1].params["history_device"], "dev_old");
}

#[test]
fn remote_archived_audit_is_queried_through_current_peer_and_validated() {
    use kv_core::remote::keys::{sign_object, DeviceKeyProvider, SoftwareDeviceKey};
    use kv_core::remote::SignatureAlgorithm;
    for variant in 0..6 {
        let dir = tempfile::tempdir().unwrap();
        let mut fake = Fake::new(dir.path());
        fake.directory.truncate(1);
        let old_key = SoftwareDeviceKey::from_p256_bytes(&[1; 32]).unwrap();
        let next_key = SoftwareDeviceKey::from_p256_bytes(&[2; 32]).unwrap();
        fake.directory[0].dk_pub = next_key.public_jwk().unwrap();
        let mut old = fake.directory[0].clone();
        old.device_id = "dev_old".into();
        old.dk_pub = old_key.public_jwk().unwrap();
        let issued = json!({"op":"directive_issued","id":"old-query","peer":"dev_old",
            "directive_op":"query_grants","directive_hash":"original-digest",
            "audit_seq":1,"ts_unix":NOW-60});
        let received = json!({"op":"directive_applied","id":"old-query","iss":"dev_local",
            "directive_op":"query_grants","directive_hash":"original-digest",
            "audit_seq":1,"ts_unix":NOW-50});
        let mut current = page("dev_srv", vec![], 0, None);
        current["archived_devices"] = json!(["dev_old"]);
        let mut archived = page("dev_old", vec![received], 1, None);
        let mut proof = json!({"domain":"keyvalet.audit-archive.v1","account":"acct_test",
            "predecessor":old,"successor":fake.directory[0],"head":archived["head"]});
        proof["sig"] = json!(sign_object(&proof, SignatureAlgorithm::ES256, &old_key).unwrap());
        current["archive_proofs"] = json!([proof]);
        let mut local = page("dev_local", vec![issued], 1, None);
        local["history_directory"] = json!([old]);
        match variant {
            1 => archived["device_id"] = json!("dev_foreign"),
            2 => archived["account_id"] = json!("another_account"),
            3 => archived["archived_devices"] = json!(["nested_history"]),
            4 => {
                current.as_object_mut().unwrap().remove("archive_proofs");
            }
            5 => current["archive_proofs"][0]["sig"] = json!("invalid"),
            _ => {}
        }
        fake.replies.extend([
            (Op::AuditList, Response::ok(local)),
            (
                Op::DevicesList,
                Response::ok(json!({"devices":fake.directory})),
            ),
            (
                Op::DirectiveIssue,
                Response::ok(json!({"result":{"id":"current-query","ok":true,"state":current}})),
            ),
            (
                Op::DirectiveIssue,
                Response::ok(json!({"result":{"id":"history-query","ok":true,"state":archived}})),
            ),
        ]);
        let result = invoke(&mut fake, &["audit", "--remote", "--json"]);
        let Success::Audit(report) = &fake.emitted[0].output else {
            panic!("missing audit report")
        };
        if variant == 0 {
            assert!(
                result.is_ok(),
                "audit unavailable: {:?}; comparison: {:?}",
                report.unavailable,
                report.comparison
            );
            assert!(report.consistent);
            assert_eq!(report.comparison.matched, 1);
        } else {
            assert_eq!(result.unwrap_err().exit_code(), 3);
            assert!(!report.consistent);
            assert_eq!(report.unavailable.len(), 1);
            assert_eq!(report.comparison.matched, 0);
        }
        assert_eq!(fake.requests[3].params["aud"], "dev_srv");
        assert_eq!(fake.requests[3].params["args"]["history_device"], "dev_old");
    }
}

#[test]
fn r3a_directive_wait_timeout_requires_readback_before_retry() {
    let message = output::error_message("directive_result_timeout");
    assert!(message.contains("status/grants"));
    assert!(message.contains("audit"));
    assert_ne!(message, output::error_message("expired"));
}

#[test]
fn r3a_audit_keeps_unconfirmed_directives_visible_and_binds_timeout_facts() {
    for variant in 0..7 {
        let dir = tempfile::tempdir().unwrap();
        let mut fake = Fake::new(dir.path());
        fake.directory.truncate(1);
        let issued = json!({"op":"directive_issued","id":"old-query","peer":"dev_srv",
            "directive_op":"query_grants","directive_hash":"original-digest","audit_seq":1,"ts_unix":NOW-60});
        let mut entries = vec![issued];
        if variant != 0 {
            let mut timeout = json!({"op":"directive_wait_timeout","id":"old-query","peer":"dev_srv",
                "directive_op":"query_grants","directive_hash":"original-digest",
                "reason":"directive_result_timeout","state":"unconfirmed","audit_seq":2,"ts_unix":NOW-50,
                "credential_value":"synthetic-context-must-not-export"});
            match variant {
                3 => timeout["id"] = json!("another-command"),
                4 => timeout["peer"] = json!("another-peer"),
                5 => timeout["directive_hash"] = json!("another-digest"),
                6 => timeout["directive_op"] = json!("lock"),
                _ => {}
            }
            entries.push(timeout);
        }
        if variant == 2 {
            entries.push(
                json!({"op":"directive_result","id":"old-query","peer":"dev_srv",
                "ok":true,"audit_seq":3,"ts_unix":NOW-40}),
            );
        }
        fake.replies.push_back((
            Op::AuditList,
            Response::ok(page(
                "dev_local",
                entries.clone(),
                entries.len() as u64,
                None,
            )),
        ));
        fake.replies.push_back((
            Op::DevicesList,
            Response::ok(json!({"devices":fake.directory})),
        ));
        fake.replies.push_back((
            Op::DirectiveIssue,
            Response::ok(json!({"result":{"id":"query","ok":true,"error":null,
            "state":page("dev_srv",vec![],0,None)}})),
        ));
        let error = invoke(&mut fake, &["audit", "--remote", "--json"]).unwrap_err();
        assert_eq!(error.exit_code(), 3);
        let Success::Audit(report) = &fake.emitted[0].output else {
            panic!("missing report")
        };
        assert!(!report.consistent);
        assert_eq!(report.comparison.matched, 0);
        assert_eq!(report.comparison.findings.len(), 1);
        assert_eq!(
            report.comparison.findings[0].problem,
            "missing_receiver_record"
        );
        let metadata = serde_json::to_value(report).unwrap();
        let outcome = &metadata["directive_outcomes"][0];
        assert_eq!(outcome["id"], "old-query", "variant={variant}");
        assert_eq!(outcome["directive_op"], "query_grants");
        assert_eq!(outcome["wait_timeout_recorded"], matches!(variant, 1 | 2));
        assert_eq!(
            outcome["result_ok"],
            if variant == 2 {
                json!(true)
            } else {
                Value::Null
            }
        );
        assert!(!metadata
            .to_string()
            .contains("synthetic-context-must-not-export"));
        let rendered = output::render(&fake.emitted[0].output, false, false);
        assert!(rendered.contains("old-query"));
        assert!(rendered.contains("missing_receiver_record"));
        if variant == 0 {
            assert!(
                rendered.contains("执行结果未确认")
                    || rendered.contains("execution is unconfirmed")
            );
        }
    }
}

#[test]
fn r3a_unauthenticated_audit_cannot_explain_a_directive_outcome() {
    let dir = tempfile::tempdir().unwrap();
    let mut fake = Fake::new(dir.path());
    fake.directory.truncate(1);
    let mut local = page(
        "dev_local",
        vec![
            json!({"op":"directive_issued","id":"old-query","peer":"dev_srv","directive_op":"query_grants",
            "directive_hash":"original-digest","audit_seq":1,"ts_unix":NOW}),
            json!({"op":"directive_wait_timeout","id":"old-query","peer":"dev_srv","directive_op":"query_grants",
            "directive_hash":"original-digest","state":"unconfirmed","reason":"directive_result_timeout",
            "audit_seq":2,"ts_unix":NOW}),
        ],
        2,
        None,
    );
    local["checkpoint"] = json!("untrusted-checkpoint");
    fake.replies.push_back((Op::AuditList, Response::ok(local)));
    fake.replies.push_back((
        Op::DevicesList,
        Response::ok(json!({"devices":fake.directory})),
    ));
    fake.replies.push_back((
        Op::DirectiveIssue,
        Response::ok(json!({"result":{"id":"query","ok":true,"error":null,
        "state":page("dev_srv",vec![],0,None)}})),
    ));
    assert_eq!(
        invoke(&mut fake, &["audit", "--remote", "--json"])
            .unwrap_err()
            .exit_code(),
        3
    );
    let Success::Audit(report) = &fake.emitted[0].output else {
        panic!("missing report")
    };
    assert!(report.directive_outcomes.is_empty());
    assert_eq!(report.comparison.findings.len(), 1);
    assert_eq!(report.unavailable[0].1, "audit_checkpoint_unavailable");
}

fn invoke(fake: &mut Fake, args: &[&str]) -> Result<()> {
    super::super::run(
        fake,
        &args.iter().map(|arg| (*arg).into()).collect::<Vec<_>>(),
    )
}

fn page(device: &str, entries: Vec<Value>, through: u64, cursor: Option<u64>) -> Value {
    json!(AuditPage {
        account_id: "acct_test".into(),
        device_id: device.into(),
        entries,
        through,
        next_cursor: cursor,
        head: AuditHead {
            seq: through,
            hash: "a".repeat(64)
        },
        checkpoint: "vault_authenticated_metadata".into(),
        history_complete: true
    })
}

#[test]
fn remote_audit_reports_matches_missing_records_differences_and_unreachable_endpoints() {
    for scenario in 0..5 {
        let dir = tempfile::tempdir().unwrap();
        let mut fake = Fake::new(dir.path());
        fake.directory.truncate(1);
        let issued = json!({"op":"remote_approval_issued","approval_id":"a","peer":"dev_srv","digest":"d","approval_level":"strong","decision":"allow","decision_hash":"h","audit_seq":1,"ts_unix":NOW-60});
        let mut received = json!({"op":"remote_approval_accepted","approval_id":"a","approver_device":"dev_local","digest":"d","approval_level":"strong","decision":"allow","decision_hash":"h","audit_seq":1,"ts_unix":NOW-60});
        if scenario == 2 {
            received["digest"] = json!("different");
        }
        fake.replies.push_back((
            Op::AuditList,
            Response::ok(page("dev_local", vec![issued], 1, None)),
        ));
        fake.replies.push_back((
            Op::DevicesList,
            Response::ok(json!({"devices":fake.directory})),
        ));
        let response = if scenario == 3 {
            Response::err("relay_unreachable", "untrusted detail")
        } else {
            let mut remote = page(
                "dev_srv",
                if scenario == 1 {
                    vec![]
                } else {
                    vec![received]
                },
                1,
                None,
            );
            if scenario == 4 {
                remote["history_complete"] = json!(false);
            }
            Response::ok(json!({"result":{"id":"query","ok":true,"error":null,"state":remote}}))
        };
        fake.replies.push_back((Op::DirectiveIssue, response));
        let result = invoke(
            &mut fake,
            &["audit", "--remote", "--since", "24h", "--json"],
        );
        assert_eq!(result.is_ok(), scenario == 0);
        assert!(
            !fake.emitted.is_empty(),
            "scenario={scenario}, result={result:?}"
        );
        let Success::Audit(report) = &fake.emitted[0].output else {
            panic!("missing audit report")
        };
        assert_eq!(report.consistent, scenario == 0);
        assert_eq!(fake.emitted[0].ok, scenario == 0);
        assert!(!output::render(&fake.emitted[0].output, false, false).is_empty());
        if scenario == 0 {
            assert_eq!(report.comparison.matched, 1);
        }
        if scenario == 1 {
            assert_eq!(
                report.comparison.findings[0].problem,
                "missing_receiver_record"
            );
        }
        if scenario == 2 {
            assert_eq!(report.comparison.findings[0].fields, vec!["digest"]);
        }
        if scenario >= 3 {
            assert!(!report.unavailable.is_empty());
        }
        assert_eq!(fake.requests[0].params["since"], NOW - 24 * 60 * 60);
    }
}

#[test]
fn audit_fetches_all_pages_with_a_fixed_head_and_rejects_a_repeated_cursor() {
    for valid in [true, false] {
        let dir = tempfile::tempdir().unwrap();
        let mut fake = Fake::new(dir.path());
        fake.directory.clear();
        let entry = |seq| json!({"op":"event","audit_seq":seq,"ts_unix":NOW});
        fake.replies.push_back((
            Op::AuditList,
            Response::ok(page("dev_local", vec![entry(1)], 2, Some(1))),
        ));
        fake.replies.push_back((
            Op::AuditList,
            Response::ok(page(
                "dev_local",
                vec![entry(if valid { 2 } else { 1 })],
                2,
                None,
            )),
        ));
        if valid {
            fake.replies
                .push_back((Op::DevicesList, Response::ok(json!({"devices":[]}))));
        }
        let result = invoke(&mut fake, &["audit", "--remote", "--limit", "1"]);
        assert_eq!(result.is_ok(), valid);
        assert_eq!(fake.requests[1].params["through"], 2);
        assert_eq!(fake.requests[1].params["after"], 1);
        if !valid {
            assert!(fake.emitted.is_empty());
        }
    }
}

#[test]
fn audit_flags_are_strict_and_plain_audit_remains_on_the_local_entrypoint() {
    assert!(!handles(&["audit".into(), "50".into()]));
    assert!(handles(&["audit".into(), "--remote".into()]));
    for args in [
        ["audit", "--remote", "--limit", "0"],
        ["audit", "--remote", "--limit", "201"],
        ["audit", "--remote", "--since", "invalid"],
        ["audit", "--remote", "--limit", "NaN"],
    ] {
        assert!(Invocation::parse(&args.map(str::to_owned)).is_err());
    }
    assert!(Invocation::parse(&["audit".into(), "--since".into(), "24h".into()]).is_err());
}

#[test]
fn audit_page_shape_order_time_and_cursor_bounds_fail_before_output() {
    let entry = |seq| json!({"op":"event","audit_seq":seq,"ts_unix":NOW});
    let base = page("dev_local", vec![entry(1)], 2, None);
    let mut cases = Vec::new();
    for (field, value) in [
        ("account_id", json!("")),
        ("device_id", json!("")),
        ("head", json!({"seq":2,"hash":"short"})),
        ("head", json!({"seq":2,"hash":"z".repeat(64)})),
        ("head", json!({"seq":1,"hash":"a".repeat(64)})),
    ] {
        let mut bad = base.clone();
        bad[field] = value;
        cases.push(bad);
    }
    for entries in [
        vec![json!({"ts_unix":NOW})],
        vec![entry(0)],
        vec![entry(3)],
        vec![json!({"audit_seq":1,"ts_unix":NOW-100_000})],
        vec![json!({"audit_seq":1})],
    ] {
        let mut bad = base.clone();
        bad["entries"] = json!(entries);
        cases.push(bad);
    }
    cases.extend([
        page("dev_local", vec![], 2, Some(1)),
        page("dev_local", vec![entry(1)], 2, Some(0)),
        page("dev_local", vec![entry(2)], 2, Some(2)),
    ]);
    for bad in cases {
        let directory = tempfile::tempdir().unwrap();
        let mut fake = Fake::new(directory.path());
        fake.replies.push_back((Op::AuditList, Response::ok(bad)));
        assert!(invoke(&mut fake, &["audit", "--remote", "--since", "24h"]).is_err());
        assert!(fake.emitted.is_empty());
        assert_eq!(fake.ops(), [Op::AuditList]);
    }
    let directory = tempfile::tempdir().unwrap();
    let mut fake = Fake::new(directory.path());
    fake.replies.push_back((
        Op::AuditList,
        Response::ok(page("dev_local", vec![entry(1), entry(2)], 2, None)),
    ));
    assert_eq!(
        invoke(&mut fake, &["audit", "--remote", "--limit", "1"])
            .unwrap_err()
            .code,
        "audit_incomplete"
    );
}

#[test]
fn audit_pagination_pins_the_complete_original_snapshot_and_bounds_total_entries() {
    let entry = |seq| json!({"op":"event","audit_seq":seq,"ts_unix":NOW});
    for (field, value) in [
        ("account_id", json!("changed")),
        ("device_id", json!("changed")),
        ("head", json!({"seq":3,"hash":"b".repeat(64)})),
        ("checkpoint", json!("changed")),
        ("history_complete", json!(false)),
    ] {
        let directory = tempfile::tempdir().unwrap();
        let mut fake = Fake::new(directory.path());
        fake.replies.push_back((
            Op::AuditList,
            Response::ok(page("dev_local", vec![entry(1)], 3, Some(1))),
        ));
        let mut changed = page("dev_local", vec![entry(2)], 3, None);
        changed[field] = value;
        fake.replies
            .push_back((Op::AuditList, Response::ok(changed)));
        assert!(invoke(&mut fake, &["audit", "--remote"]).is_err());
        assert!(fake.emitted.is_empty());
    }
    let directory = tempfile::tempdir().unwrap();
    let mut fake = Fake::new(directory.path());
    for batch in 0..501_u64 {
        let end = (batch + 1) * 200;
        fake.replies.push_back((
            Op::AuditList,
            Response::ok(page(
                "dev_local",
                ((batch * 200 + 1)..=end).map(entry).collect(),
                100_200,
                if end < 100_200 { Some(end) } else { None },
            )),
        ));
    }
    assert_eq!(
        invoke(&mut fake, &["audit", "--remote", "--limit", "200"])
            .unwrap_err()
            .code,
        "audit_incomplete"
    );
    assert!(fake.emitted.is_empty());
    assert_eq!(fake.requests.len(), 501);
}

#[test]
fn audit_peer_failures_and_checkpoint_gaps_render_as_incomplete_reports() {
    for variant in 0..6 {
        let directory = tempfile::tempdir().unwrap();
        let mut fake = Fake::new(directory.path());
        fake.directory.truncate(1);
        fake.replies.push_back((
            Op::AuditList,
            Response::ok(page("dev_local", vec![], 0, None)),
        ));
        let response = match variant {
            0 | 1 => {
                json!({"result":{"id":"query","ok":false,"error":if variant==0 {json!("forbidden")} else {Value::Null},"state":{}}})
            }
            _ => {
                let mut remote = page(
                    if variant == 2 {
                        "substituted"
                    } else {
                        "dev_srv"
                    },
                    vec![],
                    0,
                    None,
                );
                if variant == 3 {
                    remote["account_id"] = json!("foreign-account");
                }
                if variant == 4 {
                    remote["checkpoint"] = json!("untrusted");
                }
                if variant == 5 {
                    remote = json!({});
                }
                json!({"result":{"id":"query","ok":true,"error":null,"state":remote}})
            }
        };
        fake.replies.push_back((
            Op::DevicesList,
            Response::ok(json!({"devices":fake.directory})),
        ));
        fake.replies
            .push_back((Op::DirectiveIssue, Response::ok(response)));
        assert_eq!(
            invoke(&mut fake, &["audit", "--remote", "--device", "srv"])
                .unwrap_err()
                .exit_code(),
            3
        );
        let result = &fake.emitted[0].output;
        let Success::Audit(report) = result else {
            panic!("missing report")
        };
        assert!(!report.consistent);
        assert!(!report.unavailable.is_empty());
        assert!(!output::render(result, false, false).is_empty());
        let encoded = serde_json::to_string(&fake.emitted[0]).unwrap();
        assert_eq!(
            serde_json::from_str::<output::JsonSuccess>(&encoded)
                .unwrap()
                .output,
            *result
        );
    }
}

#[test]
fn audit_skips_own_and_revoked_peers_and_filters_only_outside_selected_relationships() {
    let directory = tempfile::tempdir().unwrap();
    let mut fake = Fake::new(directory.path());
    let mut own = fake.directory[0].clone();
    own.device_id = "dev_local".into();
    let mut revoked = fake.directory[1].clone();
    revoked.extra.insert("revoked".into(), json!(true));
    fake.directory = vec![own, revoked];
    fake.replies.push_back((
        Op::AuditList,
        Response::ok(page("dev_local", vec![], 0, None)),
    ));
    fake.replies.push_back((
        Op::DevicesList,
        Response::ok(json!({"devices":fake.directory})),
    ));
    assert!(invoke(&mut fake, &["audit", "--remote"]).is_err());
    assert_eq!(fake.ops(), [Op::AuditList, Op::DevicesList]);
    let Success::Audit(report) = &fake.emitted[0].output else {
        panic!("missing report")
    };
    assert_eq!(report.unavailable.len(), 1);
    assert_eq!(report.unavailable[0].1, "revoked_device");

    let mut fake = Fake::new(directory.path());
    fake.directory.truncate(1);
    let issued = json!({"op":"remote_approval_issued","approval_id":"outside","peer":"dev_unselected","digest":"d","approval_level":"strong","decision":"allow","decision_hash":"h","audit_seq":1,"ts_unix":NOW});
    fake.replies.push_back((
        Op::AuditList,
        Response::ok(page("dev_local", vec![issued], 1, None)),
    ));
    fake.replies.push_back((
        Op::DevicesList,
        Response::ok(json!({"devices":fake.directory})),
    ));
    fake.replies.push_back((Op::DirectiveIssue,Response::ok(json!({"result":{"id":"query","ok":true,"error":null,"state":page("dev_srv",vec![],0,None)}}))));
    invoke(&mut fake, &["audit", "--remote", "--device", "dev_srv"]).unwrap();
    assert!(!output::render(&fake.emitted[0].output, false, false).is_empty());
}
