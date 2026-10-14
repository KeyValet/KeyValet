use super::*;
use crate::remote::bootstrap::{Backend, Environment, Options};
use kv_core::remote::audit::AuditHead;

#[tokio::test]
async fn r3a_directive_wait_timeout_is_bound_and_keeps_late_verified_results() {
    use super::boundaries::signing_harness;
    use super::workflow::signed_directive;

    let h = signing_harness();
    let mut directive = signed_directive(
        &h,
        DirectiveOp::QueryGrants,
        json!({"test_context":"synthetic-context-must-not-export"}),
        ApprovalLevel::Quick,
    );
    directive.iss = h.helper.local.device_id.clone();
    directive.aud = h.peer.device_id.clone();
    let id = directive.id.clone();
    let response = h
        .exchange(
            Caller::CliOwner,
            Op::DirectiveIssue,
            json!(kv_core::remote::ipc::Unsigned(directive)),
        )
        .await;
    assert_eq!(response["error"]["code"], "directive_result_timeout");

    let object: String = h
        .helper
        .lock()
        .unwrap()
        .store
        .db
        .query_row(
            "SELECT object_json FROM issued_directive_objects WHERE id=?1",
            [&id],
            |row| row.get(0),
        )
        .unwrap();
    let original: Directive = serde_json::from_str(&object).unwrap();
    let entries = h.helper.audit_entries().unwrap();
    let timeouts: Vec<_> = entries
        .iter()
        .filter(|entry| entry["op"] == "directive_wait_timeout")
        .collect();
    assert_eq!(timeouts.len(), 1, "missing command-bound wait outcome");
    let entry = timeouts[0];
    assert_eq!(entry["id"], id);
    assert_eq!(entry["peer"], h.peer.device_id);
    assert_eq!(entry["directive_op"], "query_grants");
    assert_eq!(
        entry["directive_hash"],
        sha256_hex(&jcs(&original).unwrap())
    );
    assert_eq!(entry["reason"], "directive_result_timeout");
    assert_eq!(entry["state"], "unconfirmed");
    assert!(
        entry.get("ok").is_none(),
        "a wait timeout is not an executor rejection"
    );
    let exported = kv_core::remote::audit::metadata(entry).to_string();
    assert_eq!(serde_json::from_str::<Value>(&exported).unwrap()["id"], id);
    for secret in [
        "synthetic-context-must-not-export",
        &original.nonce,
        &original.sig,
    ] {
        assert!(!exported.contains(secret));
    }
    let outcome: Option<bool> = h
        .helper
        .lock()
        .unwrap()
        .store
        .db
        .query_row(
            "SELECT result_ok FROM issued_directives WHERE id=?1",
            [&id],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(outcome, None);
    assert!(h
        .helper
        .outbound_poll(0)
        .await
        .unwrap()
        .iter()
        .any(|envelope| envelope.id == id));

    // The timeout ends this caller's wait; it must not consume a future real result.
    let result = DirectiveResult {
        id: id.clone(),
        ok: true,
        error: None,
        state: json!({"grants":[]}).as_object().unwrap().clone(),
        extra: Extra::new(),
    };
    h.helper
        .inbound(h.envelope(EnvelopeType::DirectiveResult, &id, &result))
        .await
        .unwrap();
    let outcome: Option<bool> = h
        .helper
        .lock()
        .unwrap()
        .store
        .db
        .query_row(
            "SELECT result_ok FROM issued_directives WHERE id=?1",
            [&id],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(outcome, Some(true));
    assert_eq!(
        h.helper
            .inbound(h.envelope(EnvelopeType::DirectiveResult, &id, &result))
            .await
            .unwrap_err()
            .code(),
        "already_consumed"
    );
    let comparison = kv_core::remote::audit::compare(&[
        (
            h.helper.local.device_id.clone(),
            h.helper.audit_entries().unwrap(),
        ),
        (h.peer.device_id.clone(), vec![]),
    ]);
    assert_eq!(comparison.matched, 0);
    assert_eq!(comparison.findings.len(), 1);
    assert_eq!(comparison.findings[0].problem, "missing_receiver_record");
}

#[tokio::test]
async fn r3a_directive_timeout_audit_failure_preserves_pending_and_late_failure_result() {
    use super::boundaries::signing_harness;
    use super::workflow::signed_directive;

    let h = signing_harness();
    let mut directive = signed_directive(
        &h,
        DirectiveOp::QueryGrants,
        json!({}),
        ApprovalLevel::Quick,
    );
    directive.iss = h.helper.local.device_id.clone();
    directive.aud = h.peer.device_id.clone();
    let id = directive.id.clone();
    let helper = h.helper.clone();
    let job = tokio::spawn(async move {
        helper
            .handle(
                CallerContext::authenticated(Caller::CliOwner, 501, 4242, 50),
                Request {
                    op: Op::DirectiveIssue,
                    params: json!(kv_core::remote::ipc::Unsigned(directive)),
                    extra: Extra::new(),
                },
            )
            .await
    });
    let queued = h.helper.outbound_poll(500).await.unwrap();
    assert!(queued.iter().any(|envelope| envelope.id == id));
    h.audit.fail.store(true, Ordering::SeqCst);
    let reply = serde_json::to_value(job.await.unwrap()).unwrap();
    assert_eq!(reply["error"]["code"], "audit_unavailable");
    h.audit.fail.store(false, Ordering::SeqCst);
    assert!(!h
        .helper
        .audit_entries()
        .unwrap()
        .iter()
        .any(|entry| entry["op"] == "directive_wait_timeout"));
    let pending: Option<bool> = h
        .helper
        .lock()
        .unwrap()
        .store
        .db
        .query_row(
            "SELECT result_ok FROM issued_directives WHERE id=?1",
            [&id],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(pending, None);
    assert!(h
        .helper
        .outbound_poll(0)
        .await
        .unwrap()
        .iter()
        .any(|envelope| envelope.id == id));
    let result = DirectiveResult {
        id: id.clone(),
        ok: false,
        error: Some("expired".into()),
        state: Extra::new(),
        extra: Extra::new(),
    };
    h.helper
        .inbound(h.envelope(EnvelopeType::DirectiveResult, &id, &result))
        .await
        .unwrap();
    let recorded: Option<bool> = h
        .helper
        .lock()
        .unwrap()
        .store
        .db
        .query_row(
            "SELECT result_ok FROM issued_directives WHERE id=?1",
            [&id],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(recorded, Some(false));
}

fn backend(path: &std::path::Path) -> Backend {
    let h = Harness::new();
    let keys = crate::remote::platform_keys::SoftwareKeys;
    let master = crate::remote::metadata_master::IdentityMaster { keys: &keys };
    crate::remote::bootstrap::open(
        Options {
            path,
            initialize: Some((
                "account",
                "CI executor",
                "synthetic-test-passphrase-42",
                Os::Linux,
            )),
            config: ApprovalConfig::default(),
        },
        Environment {
            master: &master,
            factory: &keys,
            runner: h.runner,
            presence: h.presence,
            clock: h.clock,
        },
    )
    .unwrap()
}

#[test]
fn r3a_local_settings_commit_keeps_the_authenticated_audit_checkpoint_current() {
    let directory = tempfile::tempdir().unwrap();
    let b = backend(&directory.path().join("remote"));
    let _settings = crate::remote::settings::install(&b.helper, &b.metadata.dir).unwrap();
    b.helper
        .set_mode_local("per_session", ApprovalLevel::Strong)
        .unwrap();
    let expected = b.helper.local_settings().unwrap();
    let mut next = expected.clone();
    next.grant_mode = kv_core::settings::GrantMode::PerUse;
    kv_core::compare_and_write_settings(&b.metadata.dir, &expected, &next).unwrap();
    assert_eq!(b.helper.local_settings().unwrap(), next);
    let state = b.helper.lock().unwrap();
    let head = state.store.audit_head().unwrap();
    b.metadata.verify_checkpoint(&head).unwrap();
    b.metadata
        .verify_records(&state.store.audit_records().unwrap())
        .unwrap();
    // The next authenticated transaction, such as a delivered Grant, must still commit.
    b.helper
        .audit(&state, "after_local_settings", json!({}))
        .unwrap();
    b.metadata
        .verify_checkpoint(&state.store.audit_head().unwrap())
        .unwrap();
}

#[test]
fn committed_audit_rejects_sqlite_suffix_rollback_and_missing_vault_receipts() {
    let directory = tempfile::tempdir().unwrap();
    let b = backend(&directory.path().join("remote"));
    let state = b.helper.lock().unwrap();
    b.helper.audit(&state, "test_a", json!({})).unwrap();
    b.helper.audit(&state, "test_b", json!({})).unwrap();
    let head = state.store.audit_head().unwrap();
    assert_eq!(head.seq, 2);
    b.metadata.verify_checkpoint(&head).unwrap();
    // The remaining chain is internally valid; the independently committed head rejects it.
    state
        .store
        .db
        .execute("DELETE FROM remote_audit WHERE seq=2", [])
        .unwrap();
    state.store.verify_audit().unwrap();
    assert_eq!(
        b.metadata
            .verify_checkpoint(&state.store.audit_head().unwrap()),
        Err(Error("audit_checkpoint_mismatch"))
    );
    drop(state);
    drop(b);

    let b = backend(&directory.path().join("other"));
    let state = b.helper.lock().unwrap();
    for op in ["a", "b", "c"] {
        b.helper.audit(&state, op, json!({})).unwrap();
    }
    let audit = b.metadata.dir.join("audit.log");
    let lines = std::fs::read_to_string(&audit).unwrap();
    let retained = lines
        .lines()
        .filter(|line| !line.contains("\"audit_seq\":2"))
        .collect::<Vec<_>>()
        .join("\n")
        + "\n";
    std::fs::write(&audit, retained).unwrap();
    b.metadata
        .verify_checkpoint(&state.store.audit_head().unwrap())
        .unwrap();
    assert_eq!(
        b.metadata
            .verify_records(&state.store.audit_records().unwrap()),
        Err(Error("audit_receipt_missing"))
    );
}

#[test]
fn pending_checkpoint_recovers_committed_or_aborted_sqlite_transactions() {
    for committed in [false, true] {
        let directory = tempfile::tempdir().unwrap();
        let b = backend(&directory.path().join("remote"));
        let state = b.helper.lock().unwrap();
        let old = state.store.audit_head().unwrap();
        let tx = state.store.db.unchecked_transaction().unwrap();
        state
            .store
            .audit(
                &*b.metadata,
                json!({"op":"interrupted"}).as_object().unwrap().clone(),
                100,
            )
            .unwrap();
        let next = state.store.audit_head().unwrap();
        b.metadata.prepare_checkpoint(&old, &next).unwrap();
        if committed {
            tx.commit().unwrap();
        } else {
            drop(tx);
        }
        let actual = state.store.audit_head().unwrap();
        assert_eq!(
            actual,
            if committed {
                next
            } else {
                AuditHead::default()
            }
        );
        b.metadata.verify_checkpoint(&actual).unwrap();
        b.metadata
            .verify_records(&state.store.audit_records().unwrap())
            .unwrap();
        b.helper.audit(&state, "after_restart", json!({})).unwrap();
    }
}

#[test]
fn audit_pages_are_bounded_and_keep_a_stable_snapshot_while_new_entries_arrive() {
    let h = Harness::new();
    let state = h.helper.lock().unwrap();
    for _ in 0..205 {
        h.helper
            .audit(&state, "event", json!({"credential":"must-not-export"}))
            .unwrap();
    }
    let mut args = QueryAuditArgs {
        since: 0,
        limit: 200,
        extra: Extra::new(),
    };
    let first = state
        .store
        .audit_page(
            &args,
            &h.helper.account,
            &h.helper.local.device_id,
            &*h.audit,
        )
        .unwrap();
    assert!(first.next_cursor.is_some());
    assert!(serde_json::to_vec(&first).unwrap().len() < 48 * 1024);
    assert!(!serde_json::to_string(&first)
        .unwrap()
        .contains("must-not-export"));
    h.helper.audit(&state, "newer", json!({})).unwrap();
    let mut count = first.entries.len();
    let mut cursor = first.next_cursor;
    while let Some(after) = cursor {
        args.extra = json!({"after":after,"through":first.through})
            .as_object()
            .unwrap()
            .clone();
        let page = state
            .store
            .audit_page(
                &args,
                &h.helper.account,
                &h.helper.local.device_id,
                &*h.audit,
            )
            .unwrap();
        assert_eq!(page.head, first.head);
        count += page.entries.len();
        cursor = page.next_cursor;
    }
    assert_eq!(count, 205);
    state
        .store
        .db
        .execute(
            "UPDATE remote_audit SET entry_hash='tampered' WHERE seq=1",
            [],
        )
        .unwrap();
    assert!(state
        .store
        .audit_page(
            &args,
            &h.helper.account,
            &h.helper.local.device_id,
            &*h.audit
        )
        .is_err());
}
