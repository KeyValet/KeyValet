//! Durable, ciphertext-bound transport receipts. No receipt grants execution authority.
use super::store::{encode, PendingState};
use super::{Error, RemoteHelper, Result};
use kv_core::remote::canonical::sha256_hex;
use kv_core::remote::{Envelope, EnvelopeType};
use kv_ipc::remote::{OutboundStage, RelayOutboundAckParams};
use rusqlite::{params, OptionalExtension};
use serde_json::json;

impl RemoteHelper {
    pub(crate) fn outbound_ack(&self, params: RelayOutboundAckParams<Envelope>) -> Result<usize> {
        if params.envelopes.is_empty() || params.envelopes.len() > 64 {
            return Err(Error("invalid_outbox_receipt"));
        }
        let state = self.lock()?;
        let tx = state.store.transaction(self.services.audit.as_ref())?;
        let mut retired = 0;
        for envelope in &params.envelopes {
            let encoded = encode(envelope)?;
            let hash = sha256_hex(encoded.as_bytes());
            let receipt: Option<String> = tx
                .query_row(
                    "SELECT stage FROM remote_outbox_receipts WHERE envelope_hash=?1",
                    [&hash],
                    |row| row.get(0),
                )
                .optional()?;
            let exists: bool = tx.query_row(
                "SELECT EXISTS(SELECT 1 FROM remote_outbox WHERE envelope_json=?1)",
                [&encoded],
                |row| row.get(0),
            )?;
            if !exists && receipt.is_none() {
                return Err(Error("unknown_outbox_receipt"));
            }
            let stage = match params.stage {
                OutboundStage::Spooled => {
                    if receipt.as_deref().is_some_and(|r| r != "pending") {
                        continue;
                    }
                    "spooled"
                }
                OutboundStage::Accepted => "accepted",
                OutboundStage::Inspect => {
                    let obsolete = if matches!(
                        envelope.r#type,
                        EnvelopeType::ApprovalRequest | EnvelopeType::ApprovalEscalate
                    ) {
                        state.store.pending(&envelope.id)?.state != PendingState::Waiting
                    } else {
                        false
                    };
                    if !obsolete
                        && envelope.exp >= self.services.clock.now()
                        && !matches!(receipt.as_deref(), Some("accepted" | "retired"))
                    {
                        break;
                    }
                    retired += 1;
                    "retired"
                }
            };
            tx.execute(
                "INSERT INTO remote_outbox_receipts(envelope_hash,stage,exp) VALUES(?1,?2,?3)
                ON CONFLICT(envelope_hash) DO UPDATE SET stage=excluded.stage",
                params![hash, stage, envelope.exp],
            )?;
            if stage != "spooled" {
                tx.execute(
                    "DELETE FROM remote_outbox WHERE envelope_json=?1",
                    [&encoded],
                )?;
            }
        }
        if params.stage != OutboundStage::Inspect || retired != 0 {
            self.audit(&state, "relay_outbox_receipt",
                json!({"stage":params.stage,"count":params.envelopes.len(),"retired_count":retired}))?;
        }
        tx.commit()?;
        Ok(retired)
    }
}
