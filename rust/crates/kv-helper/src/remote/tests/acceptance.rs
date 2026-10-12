//! Restart and expiry checks at the helper/relay transport boundary.
use super::*;
use kv_ipc::remote::{OutboundStage, RelayOutboundAckParams};

fn receipt(envelopes: Vec<Envelope>, stage: OutboundStage) -> RelayOutboundAckParams<Envelope> {
    RelayOutboundAckParams {
        envelopes,
        stage,
        extra: Extra::new(),
    }
}

#[tokio::test]
async fn lost_poll_is_replayed_and_durable_spool_and_accept_receipts_survive_helper_restart() {
    let temp = tempfile::tempdir().unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let path = temp.path().join("remote.sqlite3");
    let now = fixture("decision_valid.json")["now"].as_i64().unwrap();
    let envelope = {
        let h = Harness::with(Store::persistence_fixture(&path).unwrap(), now, true);
        let envelope = h.envelope(EnvelopeType::PresenceHint, "restart", &json!({}));
        h.helper.lock().unwrap().store.queue(&envelope).unwrap();
        for _ in 0..2 {
            assert_eq!(
                h.helper.outbound_poll(0).await.unwrap(),
                vec![envelope.clone()]
            );
        }
        h.audit.fail.store(true, Ordering::SeqCst);
        assert_eq!(
            h.helper
                .outbound_ack(receipt(vec![envelope.clone()], OutboundStage::Spooled))
                .unwrap_err()
                .code(),
            "audit_unavailable"
        );
        h.audit.fail.store(false, Ordering::SeqCst);
        assert_eq!(
            h.helper.outbound_poll(0).await.unwrap(),
            vec![envelope.clone()]
        );
        h.spooled(std::slice::from_ref(&envelope));
        envelope
    };
    {
        let peer =
            serde_json::from_value(fixture("decision_valid.json")["device"].clone()).unwrap();
        let h = Harness::from_store(Store::persistence_fixture(&path).unwrap(), now + 1, peer);
        assert!(h.helper.outbound_poll(0).await.unwrap().is_empty());
        assert_eq!(
            h.helper
                .outbound_ack(receipt(vec![envelope.clone()], OutboundStage::Inspect))
                .unwrap(),
            0
        );
        h.helper
            .outbound_ack(receipt(vec![envelope.clone()], OutboundStage::Accepted))
            .unwrap();
    }
    let peer = serde_json::from_value(fixture("decision_valid.json")["device"].clone()).unwrap();
    let h = Harness::from_store(Store::persistence_fixture(&path).unwrap(), now + 2, peer);
    assert_eq!(
        h.helper
            .outbound_ack(receipt(vec![envelope], OutboundStage::Inspect))
            .unwrap(),
        1
    );
    assert!(h.helper.outbound_poll(0).await.unwrap().is_empty());
}

#[tokio::test]
async fn cancellation_has_a_live_delivery_window_even_after_the_approval_expires() {
    for expired in [false, true] {
        let h = Harness::new();
        let request = h.helper.submit(h.input(Tier::T1, "original")).unwrap();
        let first = h.helper.outbound_poll(0).await.unwrap();
        h.spooled(&first);
        h.clock
            .0
            .store(request.exp + if expired { 1 } else { -1 }, Ordering::SeqCst);
        if expired {
            h.helper.tick().unwrap();
            assert_eq!(
                h.helper
                    .lock()
                    .unwrap()
                    .store
                    .pending(&request.approval_id)
                    .unwrap()
                    .state,
                PendingState::Expired
            );
        } else {
            h.helper
                .cancel_locked(
                    &mut h.helper.lock().unwrap(),
                    &request.approval_id,
                    PendingState::Cancelled,
                )
                .unwrap();
        }
        let outgoing = h.helper.outbound_poll(0).await.unwrap();
        assert_eq!(outgoing.len(), 1);
        assert_eq!(outgoing[0].r#type, EnvelopeType::ApprovalCancel);
        assert_eq!(outgoing[0].id, request.approval_id);
        assert_eq!(outgoing[0].exp, h.clock.now() + 60);
        assert!(outgoing[0].exp > outgoing[0].created_at);
        assert!(h.helper.lock().unwrap().full.is_empty());
    }
}
