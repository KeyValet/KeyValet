use super::*;
use kv_core::remote::audit::{AuditHead, AuditPage};

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
    ] {
        assert!(Invocation::parse(&args.map(str::to_owned)).is_err());
    }
}
