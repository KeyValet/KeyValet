use super::workflow::{signed_directive, signed_grant};
use super::*;
use rusqlite::hooks::{AuthContext, Authorization};

/// Fail one SQLite authorization at a time, then allow the rejection audit to be stored.
/// This exercises real SQL transactions rather than a mock that reproduces their logic.
pub(super) fn deny_once(helper: &RemoteHelper, at: usize) -> Arc<AtomicBool> {
    let denied = Arc::new(AtomicBool::new(false));
    let observed = denied.clone();
    let mut count = 0;
    helper
        .lock()
        .unwrap()
        .store
        .db
        .authorizer(Some(move |_: AuthContext<'_>| {
            count += 1;
            if count == at {
                observed.store(true, Ordering::SeqCst);
                Authorization::Deny
            } else {
                Authorization::Allow
            }
        }));
    denied
}

#[tokio::test]
async fn sqlite_failures_reject_and_audit_without_executing_or_installing_partial_authority() {
    for operation in 0..5 {
        let mut failures = 0;
        for at in 1..500 {
            let h = Harness::new();
            h.runner.alive.store(false, Ordering::SeqCst);
            let grant = signed_grant(&h, "faulted", Tier::T1, 3);
            let directive = signed_directive(
                &h,
                DirectiveOp::SetMode,
                json!({"mode":"per_use"}),
                ApprovalLevel::Quick,
            );
            let request =
                (operation == 2).then(|| h.helper.submit(h.input(Tier::T1, "A")).unwrap());
            if operation == 3 || operation == 4 {
                h.helper
                    .install_grant(&grant, ApprovalLevel::Strong)
                    .unwrap();
            }
            let usage = GrantUse {
                canonical: h.input(Tier::T1, "A").canonical,
                tier: Tier::T1,
                template_allowed_hosts: vec!["api.github.com".into()],
                policy_allowed_methods: vec![h.input(Tier::T1, "A").canonical.method.unwrap()],
                body_bytes: 1,
                session_id: "session".into(),
            };
            let denied = deny_once(&h.helper, at);
            let result: Result<()> = match operation {
                0 => h.helper.submit(h.input(Tier::T1, "A")).map(|_| ()),
                1 => h.helper.install_grant(&grant, ApprovalLevel::Strong),
                2 => {
                    let request = request.as_ref().unwrap();
                    let decision = h.decision(request, ApprovalLevel::Quick, ScopeMode::PerUse);
                    h.helper
                        .inbound(h.envelope(
                            EnvelopeType::ApprovalDecision,
                            &request.approval_id,
                            &decision,
                        ))
                        .await
                }
                3 => h.helper.cover_and_debit(&usage).and_then(|coverage| {
                    if denied.load(Ordering::SeqCst) {
                        assert!(coverage.jtis.is_empty());
                        // An unavailable issuer invalidates this candidate, so an empty
                        // coverage set is also a denial. Its reason must still be audited.
                        h.reason("state_unavailable");
                        Err(Error("state_unavailable"))
                    } else {
                        Ok(())
                    }
                }),
                _ => h
                    .helper
                    .apply_directive(&directive, ApprovalLevel::Quick)
                    .map(|_| ()),
            };
            if !denied.load(Ordering::SeqCst) {
                result.unwrap();
                break;
            }
            failures += 1;
            let error = match result {
                Err(error) => error,
                Ok(()) => panic!("operation {operation}, fail {at}: SQLite denial was ignored"),
            };
            assert_eq!(
                error.code(),
                "state_unavailable",
                "operation {operation}, fail {at}"
            );
            h.reason("state_unavailable");
            assert_eq!(h.runner.calls.load(Ordering::SeqCst), 0);
            let state = h.helper.lock().unwrap();
            if operation == 0 {
                assert!(state.full.is_empty());
                assert!(state.store.pending_ids().unwrap().is_empty());
            } else if operation == 1 {
                assert_eq!(
                    state
                        .store
                        .db
                        .query_row("SELECT COUNT(*) FROM grants", [], |r| r.get::<_, u32>(0))
                        .unwrap(),
                    0
                );
            } else if operation == 4 {
                assert_eq!(
                    state.store.setting::<String>("mode").unwrap().unwrap(),
                    "per_credential"
                );
                assert_eq!(
                    state
                        .store
                        .db
                        .query_row("SELECT COUNT(*) FROM nonces", [], |r| r.get::<_, u32>(0))
                        .unwrap(),
                    0
                );
            }
        }
        assert!(
            failures > 10,
            "operation {operation} did not exercise its SQL path"
        );
    }
}

#[test]
fn non_constraint_nonce_failure_and_audit_hash_corruption_are_detected() {
    let store = Store::memory().unwrap();
    store.db.execute_batch("DROP TABLE nonces").unwrap();
    assert_eq!(
        store.consume_nonce("n", "d", 1, 2).unwrap_err().code(),
        "state_unavailable"
    );
    let h = Harness::new();
    h.helper.submit(h.input(Tier::T1, "A")).unwrap();
    let state = h.helper.lock().unwrap();
    state
        .store
        .db
        .execute("UPDATE remote_audit SET entry_hash=?1", ["0".repeat(64)])
        .unwrap();
    assert_eq!(
        state.store.verify_audit().unwrap_err().code(),
        "audit_chain_mismatch"
    );
}
