use super::*;
use kv_core::remote::audit::AuditPage;

#[test]
fn authenticated_audit_queries_preserve_paging_and_reject_unsigned_or_replayed_directives() {
    let mut f = Fixture::new();
    let q = SoftwareDeviceKey::generate_p256();
    f.peer.ak_q = Some(ApprovalKey {
        r#pub: q.public_jwk().unwrap(),
        alg: SignatureAlgorithm::ES256,
        extra: Extra::new(),
    });
    f.peer.caps.push(Capability::ApproveQuick);
    f.core
        .store
        .transaction(|db| {
            f.core
                .store
                .put(db, "peers", &f.peer.device_id, &f.peer, 0)?;
            for _ in 0..205 {
                f.core.audit_event(
                    db,
                    json!({"op":"remote_approval_issued","body":"must-not-export"}),
                )?;
            }
            Ok(())
        })
        .unwrap();
    let mut directive = Directive {
        kind: DirectiveKind::Directive,
        id: new_id(),
        iss: f.peer.device_id.clone(),
        iss_alg: SignatureAlgorithm::ES256,
        iss_kind: IssuerKind::Device,
        aud: f.core.own.device_id.clone(),
        op: DirectiveOp::QueryAudit,
        args: json!({"since":0,"limit":100}).as_object().unwrap().clone(),
        nonce: crate::engine::random_nonce(),
        exp: now() + 300,
        sig: String::new(),
        extra: Extra::new(),
    };
    directive.sig = remote::keys::sign_object(&directive, SignatureAlgorithm::ES256, &q).unwrap();
    f.receive(
        EnvelopeType::Directive,
        &directive.id,
        &directive,
        directive.exp,
    )
    .unwrap();
    let out = f.core.outbound().unwrap();
    let (_, reply) = out
        .iter()
        .find(|(_, e)| e.r#type == EnvelopeType::DirectiveResult)
        .unwrap();
    let plaintext =
        remote::envelope::open(reply, &f.peer.device_id, &*f.executor, &f.core.own, now()).unwrap();
    let response: DirectiveResult = from_json(&plaintext).unwrap();
    let page: AuditPage = serde_json::from_value(Value::Object(response.state)).unwrap();
    assert_eq!(page.entries.len(), 100);
    assert_eq!(page.through, 205);
    assert!(page.next_cursor.is_some());
    assert!(!String::from_utf8_lossy(&plaintext).contains("must-not-export"));
    let mut replay = directive.clone();
    replay.id = new_id();
    replay.sig = remote::keys::sign_object(&replay, SignatureAlgorithm::ES256, &q).unwrap();
    assert!(f
        .receive(EnvelopeType::Directive, &replay.id, &replay, replay.exp)
        .is_err());
    directive.id = new_id();
    directive.nonce = crate::engine::random_nonce();
    directive.sig.clear();
    assert!(f
        .receive(
            EnvelopeType::Directive,
            &directive.id,
            &directive,
            directive.exp
        )
        .is_err());
    f.core
        .store
        .transaction(|db| {
            crate::Store::delete(db, "audit", "00000000000000000002")?;
            assert!(f
                .core
                .audit_page(
                    db,
                    &QueryAuditArgs {
                        since: 0,
                        limit: 100,
                        extra: Extra::new()
                    }
                )
                .is_err());
            Ok(())
        })
        .unwrap();
}
