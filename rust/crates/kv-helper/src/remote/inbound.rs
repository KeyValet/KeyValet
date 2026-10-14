//! Relay ACK follows durable acceptance; the vault checkpoint authenticates recovery.

use super::engine::State;
use super::store::{decode, encode};
use super::{Error, RemoteHelper, Result, Store};
use kv_core::remote::canonical::{jcs, sha256_hex};
use kv_core::remote::keys::{decode_b64, verify_identity_signature};
use kv_core::remote::*;
use rusqlite::{params, OptionalExtension};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::{HashMap, HashSet};

#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct InboundApproval {
    pub request: ApprovalRequest,
    pub envelope: Envelope,
    pub received_at: i64,
    pub escalated: bool,
}

impl Store {
    pub(crate) fn inbound_approval(&self, id: &str) -> Result<Option<(InboundApproval, String)>> {
        let row: Option<(String, String)> = self
            .db
            .query_row(
                "SELECT object_json,state FROM inbound_approvals WHERE id=?1",
                [id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        row.map(|(object, state)| Ok((decode(&object)?, state)))
            .transpose()
    }

    /// Call only after audit chain, vault checkpoint/records and directory verification.
    /// The receipt binds plaintext to the envelope that was verified and decrypted before
    /// acceptance. Public-key verification needs no agent-backed ECDH on daemon startup.
    pub(crate) fn restore_inbound(
        &self,
        local: &str,
        account: &str,
        now: i64,
    ) -> Result<(HashMap<String, ApprovalRequest>, HashSet<String>)> {
        let mut receipts = HashMap::new();
        for entry in self.audit_entries()? {
            if entry["op"] == "remote_inbound_saved" {
                let id = entry["approval_id"]
                    .as_str()
                    .ok_or(Error("inbound_state_mismatch"))?
                    .to_owned();
                receipts.insert(id, entry);
            }
        }
        let mut pending = HashMap::new();
        let mut escalated = HashSet::new();
        let mut statement = self
            .db
            .prepare("SELECT id,peer,object_json,state,exp,receipt_seq FROM inbound_approvals")?;
        let rows = statement.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, i64>(4)?,
                row.get::<_, u64>(5)?,
            ))
        })?;
        for row in rows {
            let (id, peer, object, state, exp, sequence) = row?;
            let saved: InboundApproval = decode(&object)?;
            let receipt = receipts.get(&id).ok_or(Error("inbound_state_mismatch"))?;
            if receipt["account_id"] != account
                || receipt["source_device"] != local
                || receipt["peer"] != peer
                || receipt["state"] != state
                || receipt["audit_seq"].as_u64() != Some(sequence)
                || receipt["inbound_hash"] != sha256_hex(&jcs(&saved)?)
                || saved.request.approval_id != id
                || saved.request.requester.device_id != peer
                || saved.request.exp != exp
                || saved.envelope.id != id
                || saved.envelope.from != peer
                || saved.envelope.to != local
                || saved.envelope.account != account
                || saved.envelope.v != 1
                || saved.envelope.r#type != EnvelopeType::ApprovalRequest
                || saved.request.exp > saved.envelope.exp
                || !matches!(
                    state.as_str(),
                    "waiting" | "issued" | "cancelled" | "expired"
                )
            {
                return Err(Error("inbound_state_mismatch"));
            }
            if state != "waiting" || exp < now {
                continue;
            }
            let device = match self.device(&peer, account) {
                Ok(device) => device,
                Err(error) if matches!(error.code(), "revoked_device" | "unpaired_device") => {
                    continue;
                }
                Err(error) => return Err(error),
            };
            if !device.caps.contains(&Capability::Execute) {
                return Err(Error("unsupported_authority"));
            }
            verify_identity_signature(
                &device,
                &saved.envelope.signature_payload()?,
                &decode_b64(&saved.envelope.sig)?,
            )?;
            let issued: bool = self.db.query_row(
                "SELECT EXISTS(SELECT 1 FROM issued_approvals WHERE approval_id=?1)",
                [&id],
                |row| row.get(0),
            )?;
            if !issued {
                if saved.escalated {
                    escalated.insert(id.clone());
                }
                pending.insert(id, saved.request);
            }
        }
        Ok((pending, escalated))
    }
}

impl RemoteHelper {
    /// The caller's transaction publishes the row and vault receipt together, before ACK.
    pub(crate) fn save_inbound_state(
        &self,
        state: &State,
        saved: &InboundApproval,
        status: &str,
    ) -> Result<()> {
        if state.store.db.is_autocommit() {
            return Err(Error("state_unavailable"));
        }
        self.audit(
            state,
            "remote_inbound_saved",
            json!({"approval_id":saved.request.approval_id,
                "peer":saved.envelope.from,"state":status,"inbound_hash":sha256_hex(&jcs(saved)?)}),
        )?;
        state.store.db.execute(
            "INSERT INTO inbound_approvals(id,peer,object_json,state,exp,receipt_seq)
             VALUES(?1,?2,?3,?4,?5,?6)
             ON CONFLICT(id) DO UPDATE SET object_json=excluded.object_json,state=excluded.state,
             receipt_seq=excluded.receipt_seq",
            params![
                saved.request.approval_id,
                saved.envelope.from,
                encode(saved)?,
                status,
                saved.request.exp,
                state.store.audit_head()?.seq,
            ],
        )?;
        Ok(())
    }
}
