use super::*;
use crate::remote::bootstrap::{Backend, Environment, Options};
use kv_core::remote::audit::AuditHead;

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
