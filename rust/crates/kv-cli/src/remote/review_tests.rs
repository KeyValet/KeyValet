use super::super::*;
use super::{parse, run, Fake, NOW, URI};
use std::io::{Cursor, Read, Write};

fn argv(values: &[&str]) -> Vec<String> {
    values.iter().map(|v| (*v).into()).collect()
}

#[test]
fn system_entry_help_and_argument_errors_do_not_require_an_installation() {
    assert_eq!(run_system(&argv(&["remote", "--help", "--json"])), 0);
    assert_eq!(run_system(&argv(&["remote", "srv", "--json"])), 2);
    assert_eq!(run_system(&argv(&["remote", "srv"])), 2);
}

#[test]
fn command_driver_validates_then_authenticates_then_emits_once() {
    let temp = tempfile::tempdir().unwrap();
    let mut fake = Fake::new(temp.path());
    fake.fail = Some("verify");
    super::super::run(&mut fake, &argv(&["remote", "--help", "--json"])).unwrap();
    assert_eq!(fake.verified, 0);
    assert_eq!(fake.emitted.len(), 1);
    assert!(super::super::run(&mut fake, &argv(&["remote", "srv"])).is_err());
    assert_eq!(fake.verified, 0);
    assert_eq!(
        super::super::run(&mut fake, &argv(&["devices", "list"]))
            .unwrap_err()
            .code,
        "injected_failure"
    );
    assert_eq!(fake.verified, 1);
    assert!(fake.requests.is_empty());
    fake.fail = None;
    super::super::run(&mut fake, &argv(&["status", "--summary", "--json"])).unwrap();
    assert_eq!(fake.verified, 2);
    assert_eq!(fake.ops(), [Op::Status, Op::DevicesList]);
    assert_eq!(fake.emitted.len(), 2);
    let mut fake = Fake::new(temp.path());
    super::super::run(&mut fake, &argv(&["approvals", "--watch", "--json"])).unwrap();
    assert_eq!(fake.emitted.len(), 1);
    for (method, args) in [
        ("exchange", vec!["devices", "list"]),
        ("emit", vec!["devices", "list"]),
        ("config_path", vec!["relay", "status"]),
        (
            "install_root",
            vec![
                "relay",
                "install",
                "--public-url",
                "https://relay.example.com",
            ],
        ),
        ("health", vec!["relay", "status"]),
        ("protection", vec!["status"]),
        ("notice", vec!["remote", "*", "allow", "--all"]),
        ("confirmation", vec!["pair", URI]),
    ] {
        let mut fake = Fake::new(temp.path());
        fake.fail = Some(method);
        assert_eq!(
            super::super::run(&mut fake, &argv(&args)).unwrap_err().code,
            "injected_failure",
            "{method}"
        );
    }
}

#[test]
fn rotated_history_cannot_execute_a_hook_twice() {
    let temp = tempfile::tempdir().unwrap();
    let pending = json!({"pending":[{"approval_id":"once","operation":{"summary":"GET /repo"}}]});
    let approved = json!({"pending":[],"recent":[{"approval_id":"once","decision":"allow"}]});
    let mut fake = Fake::new(temp.path());
    fake.pending.extend([
        pending.clone(),
        approved.clone(),
        json!({"pending":[]}),
        pending.clone(),
        approved.clone(),
    ]);
    fake.waits = 4;
    run(&mut fake, &["approvals", "--on-approve", "owner-command"]).unwrap();
    assert_eq!(
        fake.hooks,
        [("owner-command".into(), "once".into(), "GET /repo".into())]
    );
    let mut fake = Fake::new(temp.path());
    fake.pending.extend([pending, approved]);
    fake.waits = 1;
    fake.fail = Some("hook");
    assert_eq!(
        run(&mut fake, &["approvals", "--on-approve", "owner-command"])
            .unwrap_err()
            .code,
        "injected_failure"
    );
    assert!(fake.hooks.is_empty());
}

#[test]
fn pairing_rejects_missing_uri_poll_errors_and_elapsed_confirmation() {
    let temp = tempfile::tempdir().unwrap();
    let mut fake = Fake::new(temp.path());
    fake.fail = Some("emit");
    assert_eq!(
        run(&mut fake, &["pair", "--new"]).unwrap_err().code,
        "injected_failure"
    );
    for (reply, code) in [
        (json!({"sas":"123456"}), "invalid_response"),
        (json!({"uri":URI,"sas":"12345"}), "invalid_response"),
        (json!({"uri":URI,"sas":"12345x"}), "invalid_response"),
    ] {
        let mut fake = Fake::new(temp.path());
        fake.replies.push_back((Op::PairStart, Response::ok(reply)));
        assert_eq!(run(&mut fake, &["pair", "--new"]).unwrap_err().code, code);
        assert_eq!(fake.ops(), [Op::PairStart]);
    }
    let mut fake = Fake::new(temp.path());
    fake.replies
        .push_back((Op::PairStart, Response::ok(json!({"uri":URI,"sas":""}))));
    assert_eq!(
        run(&mut fake, &["pair", "--new"]).unwrap_err().exit_code(),
        6
    );
    for code in ["pair_sas_mismatch", "unknown_token"] {
        let mut fake = Fake::new(temp.path());
        fake.waits = 1;
        fake.replies.extend([
            (Op::PairStart, Response::ok(json!({"uri":URI,"sas":""}))),
            (Op::Status, Response::ok(json!({"pairing":{"error":code}}))),
        ]);
        assert_eq!(run(&mut fake, &["pair", "--new"]).unwrap_err().code, code);
        assert_eq!(fake.ops(), [Op::PairStart, Op::Status]);
    }
    let mut fake = Fake::new(temp.path());
    fake.answers.push_back(Some("y".into()));
    fake.confirmation_advances.push_back(600);
    assert_eq!(run(&mut fake, &["pair", URI]).unwrap_err().exit_code(), 4);
    assert_eq!(fake.ops(), [Op::PairComplete]);
    // A polling response without pairing state must keep waiting, not fabricate SAS.
    let mut fake = Fake::new(temp.path());
    fake.waits = 2;
    fake.replies.extend([
        (
            Op::PairStart,
            Response::ok(json!({"uri":URI,"sas":"","expires_at":NOW+2})),
        ),
        (Op::Status, Response::ok(json!({}))),
        (Op::Status, Response::ok(json!({}))),
    ]);
    assert_eq!(
        run(&mut fake, &["pair", "--new"]).unwrap_err().exit_code(),
        4
    );
}

fn prepared(id: &str, label: &str, expires: i64) -> Response {
    Response::ok(
        json!({"confirmation_token":"one-use-helper-token","expires_at":expires,"device_id":id,"label":label}),
    )
}

#[test]
fn confirmation_lifetime_is_bounded_and_all_drafts_remain_live() {
    let temp = tempfile::tempdir().unwrap();
    let args = [
        "remote",
        "srv",
        "unattended",
        "--include-sensitive",
        "--until",
        "7d",
    ];
    let mut fake = Fake::new(temp.path());
    fake.replies.extend([
        (
            Op::DevicesList,
            Response::ok(json!({"devices":fake.directory})),
        ),
        (Op::GrantIssue, prepared("dev_srv", "srv", NOW + 121)),
    ]);
    assert_eq!(run(&mut fake, &args).unwrap_err().code, "invalid_response");
    assert_eq!(fake.ops(), [Op::DevicesList, Op::GrantIssue]);
    let mut fake = Fake::new(temp.path());
    fake.answers.push_back(Some("srv".into()));
    fake.confirmation_advances.push_back(120);
    assert_eq!(run(&mut fake, &args).unwrap_err().exit_code(), 4);
    assert_eq!(fake.ops(), [Op::DevicesList, Op::GrantIssue]);
    let mut fake = Fake::new(temp.path());
    fake.answers
        .extend([Some("srv".into()), Some("other".into())]);
    fake.confirmation_advances.extend([119, 1]);
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
        4
    );
    assert_eq!(
        fake.ops(),
        [Op::DevicesList, Op::GrantIssue, Op::GrantIssue]
    );
    let mut fake = Fake::new(temp.path());
    fake.answers.push_back(Some("srv".into()));
    fake.confirmation_advances.push_back(1);
    assert_eq!(
        run(
            &mut fake,
            &[
                "remote",
                "srv",
                "unattended",
                "--include-sensitive",
                "--until",
                "1s"
            ]
        )
        .unwrap_err()
        .exit_code(),
        4
    );
    assert_eq!(fake.ops(), [Op::DevicesList, Op::GrantIssue]);
}

#[test]
fn partial_rejections_and_malformed_internal_intents_fail_explicitly() {
    let temp = tempfile::tempdir().unwrap();
    let mut fake = Fake::new(temp.path());
    let _: Error = call::<Extra>(&mut fake, Op::SignIdentity, json!({})).unwrap_err();
    assert!(fake.requests.is_empty());
    let mut fake = Fake::new(temp.path());
    fake.replies.extend([
        (
            Op::DevicesList,
            Response::ok(json!({"devices":fake.directory})),
        ),
        (
            Op::DirectiveIssue,
            Response::ok(json!({"result":{"id":"first","ok":true,"error":null,"state":{}}})),
        ),
        (
            Op::DirectiveIssue,
            Response::ok(json!({"result":{"id":"second","ok":false,"error":null,"state":{}}})),
        ),
    ]);
    let error = run(&mut fake, &["remote", "*", "lock"]).unwrap_err();
    assert_eq!(error.code, "executor_rejected");
    assert_eq!(error.completed_devices, ["dev_srv"]);
    let mut fake = Fake::new(temp.path());
    fake.answers
        .extend([Some("srv".into()), Some("other".into())]);
    let mut first = Fake::new(temp.path());
    let Success::GrantsIssued { grants } =
        run(&mut first, &["remote", "srv", "allow", "--all"]).unwrap()
    else {
        panic!()
    };
    fake.replies.extend([
        (
            Op::DevicesList,
            Response::ok(json!({"devices":fake.directory})),
        ),
        (Op::GrantIssue, prepared("dev_srv", "srv", NOW + 120)),
        (Op::GrantIssue, prepared("dev_other", "other", NOW + 120)),
        (Op::GrantIssue, Response::ok(json!({"grant":grants[0]}))),
        (Op::GrantIssue, Response::err("forbidden", "untrusted")),
    ]);
    let error = run(
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
    .unwrap_err();
    assert_eq!(error.completed_devices, ["dev_srv"]);
    let mut fake = Fake::new(temp.path());
    fake.replies
        .push_back((Op::Status, Response::err("forbidden", "untrusted")));
    assert_eq!(run(&mut fake, &["status"]).unwrap_err().exit_code(), 3);
    let mut fake = Fake::new(temp.path());
    let invocation = Invocation {
        json: false,
        command: Command::Directive {
            target: "srv".into(),
            op: DirectiveOp::QueryAudit,
            args: Extra::new(),
        },
    };
    assert_eq!(
        execute(&mut fake, &invocation).unwrap_err().code,
        "invalid_response"
    );
    assert!(fake.requests.is_empty());
}

#[test]
fn parser_boundary_cases_preserve_strict_validation_and_legacy_routing() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().to_str().unwrap();
    let parsed = parse(&[
        "relay",
        "install",
        "--public-url=https://relay.example.com",
        "--root",
        root,
    ])
    .unwrap();
    assert!(matches!(
        parsed.command,
        Command::RelayInstall { root: Some(_), .. }
    ));
    for values in [
        vec!["approve", "id", "--scope=per_use"],
        vec!["remote", "srv", "unlock-ttl", "6"],
        vec!["remote", "srv", "revoke-all"],
        vec!["remote", "srv", "audit"],
        vec!["remote", "srv", "class", "batch", "--exp", "7d"],
    ] {
        assert!(parse(&values).is_ok(), "{values:?}");
    }
    for values in [
        vec![],
        vec!["unknown"],
        vec!["devices", "unknown"],
        vec!["relay"],
        vec!["relay", "unknown"],
        vec!["approve", "id", "--scope"],
        vec![
            "approve",
            "id",
            "--scope",
            "per_use",
            "--scope",
            "per_session",
        ],
        vec![
            "relay",
            "install",
            "--public-url",
            "https://relay.example.com",
            "unexpected",
        ],
        vec![
            "relay",
            "install",
            "--public-url",
            "https://relay.example.com",
            "--listen",
            "bad",
        ],
        vec![
            "relay",
            "install",
            "--public-url",
            "https://relay.example.com",
            "--root",
            "relative",
        ],
        vec![
            "remote",
            "srv",
            "unattended",
            "--include-sensitive",
            "--credential",
            "github/default",
            "--until",
            "1h",
        ],
        vec![
            "grant",
            "--to",
            "srv",
            "--credential",
            "github/default",
            "--until",
            "1h",
            "--budget",
            "123",
        ],
        vec!["remote", "srv", "grant", "list"],
        vec!["pair", "https://relay.example.com"],
        vec!["pair", "kv-pair://relay.example.com"],
    ] {
        assert_eq!(parse(&values).unwrap_err().exit_code(), 2, "{values:?}");
    }
    let parent = temp.path().join("../escape");
    assert!(parse(&[
        "relay",
        "install",
        "--public-url",
        "https://relay.example.com",
        "--root",
        parent.to_str().unwrap()
    ])
    .is_err());
    for (values, expected) in [
        (vec!["approve", "42"], true),
        (vec!["approve", "0"], false),
        (vec!["approve", "no-pid"], false),
        (vec!["deny", "42"], false),
        (vec!["approve", "42", "--json"], false),
        (vec![], false),
    ] {
        assert_eq!(args::pid_approval(&argv(&values)), expected);
    }
    assert!(handles(&argv(&["approve", "42", "--json"])));
    assert!(!handles(&argv(&["not-remote"])));
    assert!(!handles(&[]));
    assert!(handles(&argv(&["--json", "devices", "list"])));
    assert!(args::duration("s").is_err());
    assert!(args::until("2026-1x-01T00:00Z", 0).is_err());
    assert!(args::until("2026-01-01T00:00:", 0).is_err());
    assert!(args::until("2026-01-01T00:00X", 0).is_err());
    assert!(args::until("2026-01-01T00:00+00:60", 0).is_err());
    assert_eq!(args::since("1970-01-01T00:00Z", NOW).unwrap(), 0);
    assert!(args::scope("remember:1h", i64::MAX).is_err());
    for topic in [
        "relay",
        "pair",
        "devices",
        "approvals",
        "approve",
        "deny",
        "grant",
        "status",
        "protection",
        "remote",
    ] {
        assert!(args::help(topic).contains("--json"));
    }
    assert!(usage().contains("--json"));
}

#[test]
fn multi_line_error_propagation_does_not_issue_followup_operations() {
    let temp = tempfile::tempdir().unwrap();
    let mut fake = Fake::new(temp.path());
    fake.replies
        .push_back((Op::DevicesRename, Response::err("forbidden", "untrusted")));
    assert_eq!(
        run(&mut fake, &["devices", "rename", "dev_srv", "new"])
            .unwrap_err()
            .exit_code(),
        3
    );
    let mut fake = Fake::new(temp.path());
    fake.replies.push_back((
        Op::PairComplete,
        Response::ok(json!({"uri":URI,"sas":"123456"})),
    ));
    fake.fail_emit_at = Some(2);
    assert_eq!(
        run(&mut fake, &["pair", URI]).unwrap_err().code,
        "invalid_response"
    );
    assert_eq!(fake.ops(), [Op::PairComplete]);
    for values in [
        vec!["relay", "install", "--unknown"],
        vec!["remote", "srv", "unlock-ttl", "0"],
    ] {
        assert_eq!(parse(&values).unwrap_err().exit_code(), 2);
    }
}

#[test]
fn rfc3339_fractional_seconds_and_lowercase_separators_round_down() {
    let epoch = args::until("2026-10-18T00:00:00Z", 0).unwrap();
    for (text, expected) in [
        ("2026-10-18T00:00:00.1Z", epoch),
        ("2026-10-18t00:00:00.123456789z", epoch),
        ("2026-10-18T00:00:00.999+08:00", epoch - 28800),
        ("2026-10-18t00:00z", epoch),
    ] {
        assert_eq!(args::until(text, 0).unwrap(), expected);
        assert_eq!(args::since(text, epoch + 1).unwrap(), expected);
        assert!(parse(&[
            "grant",
            "--to",
            "srv",
            "--credential",
            "github/default",
            "--until",
            text
        ])
        .is_ok());
    }
    for text in [
        "2026-10-18T00:00:00.Z",
        "2026-10-18T00:00.5Z",
        "2026-10-18T00:00:00.1Q",
        "2026-10-18T00:00:00.1",
        "2026-10-18T00:00:00.1e2Z",
    ] {
        assert_eq!(args::until(text, 0).unwrap_err().exit_code(), 2);
    }
}

#[test]
fn human_rendering_covers_nonempty_lists_fallbacks_and_structured_errors() {
    let temp = tempfile::tempdir().unwrap();
    for values in [
        vec![
            "relay",
            "install",
            "--public-url",
            "https://relay.example.com",
        ],
        vec!["relay", "status"],
        vec!["relay", "set-url", "https://relay.example.com"],
        vec!["remote", "--help"],
    ] {
        let mut fake = Fake::new(temp.path());
        let value = run(&mut fake, &values).unwrap();
        assert!(!output::render(&value, false, false).is_empty());
    }
    let mut fake = Fake::new(temp.path());
    fake.directory[0]
        .extra
        .insert("revoked".into(), json!(true));
    let output = run(&mut fake, &["devices", "list"]).unwrap();
    assert!(output::render(&output, false, false).contains("dev_srv"));
    let pending: Pending = serde_json::from_value(json!({"pending":[
        {"approval_id":"explicit","summary":"explicit summary"},
        {"approval_id":"nested","operation":{"summary":"nested summary"}},
        {"approval_id":"empty"}, {"approval_id":"nonstring","operation":{"summary":null}}
    ],"recent":[{"approval_id":"allowed","decision":"allow","summary":"history summary"},{"approval_id":"denied","decision":"deny"}]})).unwrap();
    assert_eq!(
        pending
            .pending
            .iter()
            .map(|p| p.summary())
            .collect::<Vec<_>>(),
        ["explicit summary", "nested summary", "", ""]
    );
    let rendered = output::render(&Success::Approvals(pending), false, false);
    for text in [
        "explicit summary",
        "nested summary",
        "allowed",
        "denied",
        "waiting",
    ] {
        assert!(rendered.contains(text));
    }
    let mut source = Fake::new(temp.path());
    let Success::GrantsIssued { grants } =
        run(&mut source, &["remote", "srv", "allow", "--all"]).unwrap()
    else {
        panic!()
    };
    let mut standing = grants[0].clone();
    standing.jti = "standing_id".into();
    standing.exp = None;
    let mut timed = grants[0].clone();
    timed.jti = "timed_id".into();
    timed.exp = Some(123);
    timed.extra.insert("remaining_calls".into(), json!(2));
    let grants = serde_json::from_value(json!({"grants":[standing,timed]})).unwrap();
    let rendered = output::render(&Success::Grants(grants), false, false);
    assert!(rendered.contains("standing_id"));
    assert!(rendered.contains("123"));
    assert!(rendered.contains("remaining_calls"));
    let value = Success::Status { protection:json!({}), remote:Some(serde_json::from_value(json!({"relay":"connected","approvers":[],"pending_n":0,"grants_n":0,"unattended":false,"runtime_budget_s":0})).unwrap()), remote_error:None, paired_devices_n:None };
    assert!(!output::render(&value, false, false).is_empty());
    let error = Error {
        code: "forbidden".into(),
        message: "rejected\n\u{1b}".into(),
        completed_devices: vec!["dev_one\n".into()],
    };
    let human = output::render_error(&error, false);
    assert!(human.contains("dev_one?"));
    assert!(!human.contains('\u{1b}'));
    let encoded = output::render_error(&error, true);
    let decoded: Value = serde_json::from_str(&encoded).unwrap();
    assert_eq!(decoded["ok"], false);
    assert_eq!(
        serde_json::from_value::<Error>(decoded["error"].clone()).unwrap(),
        error
    );
    assert!(!output::render_error(&Error::cancelled(), false).contains("dev_one"));
    for code in [
        "pair_sas_mismatch",
        "unknown_token",
        "secondary_confirmation_required",
        "timeout",
        "ipc_unavailable",
        "untrusted\u{1b}",
    ] {
        assert!(!output::error_message(code).contains('\u{1b}'));
    }
    // Display schemas include both local-only status and all three pairing updates.
    for value in [
        Success::Status {
            protection: json!({}),
            remote: None,
            remote_error: None,
            paired_devices_n: None,
        },
        Success::Pair {
            uri: None,
            sas: None,
            paired: false,
        },
        Success::Pair {
            uri: Some(URI.into()),
            sas: None,
            paired: false,
        },
        Success::Pair {
            uri: None,
            sas: Some("123456".into()),
            paired: true,
        },
    ] {
        assert!(!output::render(&value, false, true).is_empty());
    }
}

struct Wire {
    incoming: Cursor<Vec<u8>>,
    outgoing: Vec<u8>,
    read_error: Option<std::io::ErrorKind>,
    write_error: Option<std::io::ErrorKind>,
}

impl Wire {
    fn new(bytes: impl Into<Vec<u8>>) -> Self {
        Self {
            incoming: Cursor::new(bytes.into()),
            outgoing: vec![],
            read_error: None,
            write_error: None,
        }
    }
}

impl Read for Wire {
    fn read(&mut self, bytes: &mut [u8]) -> std::io::Result<usize> {
        if let Some(error) = self.read_error {
            return Err(error.into());
        }
        self.incoming.read(bytes)
    }
}

impl Write for Wire {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if let Some(error) = self.write_error {
            return Err(error.into());
        }
        self.outgoing.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[test]
fn wire_errors_are_bounded_and_protocol_failures_are_not_timeouts() {
    let request = Request {
        op: Op::Status,
        params: json!({}),
        extra: Extra::new(),
    };
    let mut wire = Wire::new(b"{\"ok\":true,\"result\":{}}\n".to_vec());
    assert!(transport::exchange_stream(&mut wire, &request).is_ok());
    assert_eq!(
        serde_json::from_slice::<Request>(&wire.outgoing)
            .unwrap()
            .op,
        Op::Status
    );
    for response in [b"not-json\n".as_slice(), b"{}"] {
        let mut wire = Wire::new(response.to_vec());
        assert_eq!(
            transport::exchange_stream(&mut wire, &request)
                .unwrap_err()
                .code,
            "invalid_response"
        );
    }
    let mut closed = Wire::new(Vec::new());
    assert_eq!(
        transport::exchange_stream(&mut closed, &request)
            .unwrap_err()
            .code,
        "ipc_unavailable"
    );
    for (kind, code) in [
        (std::io::ErrorKind::TimedOut, "timeout"),
        (std::io::ErrorKind::WouldBlock, "timeout"),
        (std::io::ErrorKind::BrokenPipe, "ipc_unavailable"),
    ] {
        for write in [false, true] {
            let mut wire = Wire::new(Vec::new());
            if write {
                wire.write_error = Some(kind);
            } else {
                wire.read_error = Some(kind);
            }
            assert_eq!(
                transport::exchange_stream(&mut wire, &request)
                    .unwrap_err()
                    .code,
                code
            );
        }
    }
    let request = Request {
        params: json!({"padding":"x".repeat(transport::FRAME_LIMIT as usize)}),
        ..request
    };
    let mut wire = Wire::new(Vec::new());
    assert_eq!(
        transport::exchange_stream(&mut wire, &request)
            .unwrap_err()
            .exit_code(),
        2
    );
    assert!(wire.outgoing.is_empty());
    // The framing limit includes the newline on every platform.
    let seed = json!({"ok":true,"result":{"padding":""}});
    let padding = transport::FRAME_LIMIT as usize - serde_json::to_vec(&seed).unwrap().len() - 1;
    let mut response =
        serde_json::to_vec(&json!({"ok":true,"result":{"padding":"x".repeat(padding)}})).unwrap();
    response.push(b'\n');
    assert_eq!(response.len(), transport::FRAME_LIMIT as usize);
    assert!(transport::decode_response(&response).is_ok());
    response.insert(response.len() - 1, b' ');
    assert_eq!(
        transport::decode_response(&response).unwrap_err().code,
        "invalid_response"
    );
}

#[test]
fn health_transport_rejects_io_header_and_chunk_encoding_failures() {
    let url = relay::RelayUrl::parse("http://127.0.0.1:8787/base").unwrap();
    let origin = relay::RelayUrl::parse("http://127.0.0.1:8787").unwrap();
    let mut wire =
        Wire::new(b"HTTP/1.1 200 OK\r\n\r\n{\"ok\":true,\"version\":\"0.3.0\"}".to_vec());
    assert!(transport::http_health(&mut wire, &origin).unwrap().ok);
    assert!(wire.outgoing.starts_with(b"GET /v1/health HTTP/1.1\r\n"));
    let body = r#"{"ok":true,"version":"0.3.0"}"#;
    for response in [
        format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{body}"),
        format!(
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n{:x}\r\n{body}\r\n0\r\n\r\n",
            body.len()
        ),
    ] {
        let mut wire = Wire::new(response.into_bytes());
        assert_eq!(
            transport::http_health(&mut wire, &url).unwrap().version,
            "0.3.0"
        );
    }
    for write in [false, true] {
        let mut wire = Wire::new(Vec::new());
        if write {
            wire.write_error = Some(std::io::ErrorKind::BrokenPipe);
        } else {
            wire.read_error = Some(std::io::ErrorKind::TimedOut);
        }
        assert_eq!(
            transport::http_health(&mut wire, &url)
                .unwrap_err()
                .exit_code(),
            5
        );
    }
    for response in [
        vec![b'x'; 64 * 1024 + 1],
        b"no header terminator".to_vec(),
        b"HTTP/1.1 503 Unavailable\r\n\r\n{}".to_vec(),
        b"HTTP/1.1 \xff\r\n\r\n{}".to_vec(),
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n\xff\r\n".to_vec(),
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n1\r\nx??0\r\n\r\n".to_vec(),
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nmissing-size-terminator".to_vec(),
        b"\r\n\r\n".to_vec(),
    ] {
        let mut wire = Wire::new(response);
        assert_eq!(
            transport::http_health(&mut wire, &url)
                .unwrap_err()
                .exit_code(),
            5
        );
        assert!(wire
            .outgoing
            .starts_with(b"GET /base/v1/health HTTP/1.1\r\nHost: 127.0.0.1:8787\r\n"));
    }
}

#[test]
fn config_and_install_failures_preserve_existing_data() {
    let temp = tempfile::tempdir().unwrap();
    assert!(relay::Config::read(&temp.path().join("missing")).is_err());
    let path = temp.path().join("relay-client.toml");
    relay::Config::set_url(&path, "https://relay.example.com").unwrap();
    let config = relay::Config::read(&path).unwrap();
    assert_eq!(config.relay_url, "https://relay.example.com");
    assert!(config.device_id.is_none());
    assert!(config.account_id.is_none());
    std::fs::write(&path, "x".repeat(16 * 1024 + 1)).unwrap();
    assert!(relay::Config::read(&path).is_err());
    std::fs::write(&path, b"\xff").unwrap();
    assert!(relay::Config::read(&path).is_err());
    std::fs::write(&path, "relay_url=\"https://relay.example.com\\q\"\n").unwrap();
    assert!(relay::Config::read(&path).is_err());
    for content in [
        "relay_url='https://relay.example.com",
        "relay_url=\"https://relay.example.com",
        "relay_url=bare",
        "relay_url='https://relay.example.com' trailing",
        "relay_url='https://relay.example.com'\ndevice_id=''",
        "relay_url='https://relay.example.com'\ndevice_id='a\n'",
    ] {
        std::fs::write(&path, content).unwrap();
        assert!(relay::Config::read(&path).is_err(), "{content}");
    }
    let too_long = format!(
        "relay_url='https://relay.example.com'\ndevice_id='{}'",
        "x".repeat(257)
    );
    std::fs::write(&path, &too_long).unwrap();
    assert!(relay::Config::read(&path).is_err());
    assert_eq!(std::fs::read_to_string(&path).unwrap(), too_long);
    assert!(relay::atomic_write(std::path::Path::new("/"), "unused").is_err());
    let blocker = temp.path().join("blocker");
    std::fs::write(&blocker, "keep").unwrap();
    assert!(relay::atomic_write(&blocker.join("child"), "unused").is_err());
    assert_eq!(std::fs::read_to_string(&blocker).unwrap(), "keep");
    let directory = temp.path().join("directory");
    std::fs::create_dir(&directory).unwrap();
    assert!(relay::atomic_write(&directory, "unused").is_err());
    let mut fake = Fake::new(temp.path());
    let staging = fake.root.to_string_lossy().into_owned();
    run(
        &mut fake,
        &[
            "relay",
            "install",
            "--root",
            &staging,
            "--public-url",
            "https://relay.example.com",
        ],
    )
    .unwrap();
    assert_eq!(fake.ops(), []);
    let mut fake = Fake::new(temp.path());
    fake.root = blocker;
    assert!(run(
        &mut fake,
        &[
            "relay",
            "install",
            "--public-url",
            "https://relay.example.com"
        ]
    )
    .is_err());
}

#[test]
fn relay_urls_validate_brackets_ports_hosts_and_health_metadata() {
    for url in [
        "https://[not-ipv6]",
        "https://[::1",
        "https://[::1]tail",
        "https://[::1]:0",
        "https://bad_host",
        "https://",
        "https://a.;x",
        "https://relay.example.com/.",
    ] {
        assert!(relay::RelayUrl::parse(url).is_err(), "{url}");
    }
    assert_eq!(relay::RelayUrl::parse("https://[::1]").unwrap().port, 443);
    assert_eq!(
        relay::RelayUrl::parse("https://relay.example.com")
            .unwrap()
            .health_url(),
        "https://relay.example.com/v1/health"
    );
    for version in ["x".repeat(129), "version\n".into()] {
        assert_eq!(
            relay::parse_health(
                &serde_json::to_vec(&json!({"ok":true,"version":version})).unwrap()
            )
            .unwrap_err()
            .exit_code(),
            5
        );
    }
}
