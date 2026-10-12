//! Strong revocation proofs are durable; transport retries never manufacture new authority.
use super::engine::directory;
use super::store::{decode, encode};
use super::{Error, RemoteHelper, Result};
use kv_core::remote::{self as remote, keys::encode_b64, relay::*, *};
use rusqlite::{params, OptionalExtension};
use serde_json::json;

impl RemoteHelper {
    pub(crate) async fn revoke_owner_device(&self, id: &str) -> Result<()> {
        let url = self.lock()?.store.setting::<String>("relay_url")?;
        let Some(url) = url else {
            self.authorize_strong("revoke_device", json!({"device_id":id}))
                .await?;
            return self.revoke_device(id, "local");
        };
        let relay = super::pairing_relay::RelayApi::new(&url)?;
        let done: Option<bool> = self
            .lock()?
            .store
            .db
            .query_row(
                "SELECT relay_done FROM device_revocations WHERE device_id=?1",
                [id],
                |r| r.get(0),
            )
            .optional()?;
        if done == Some(true) {
            return Ok(());
        }
        let token = relay
            .authenticate(&self.local, self.services.identity.clone())
            .await?;
        let mut proof = None;
        let mut signature = None;
        if done != Some(true) {
            let records = directory(&self.lock()?.store)?;
            let target = records
                .iter()
                .find(|(record, _)| record.device_id == id)
                .ok_or(Error("unknown_device"))?;
            self.authorize_strong(
                "revoke_device",
                json!({"device_id":id,"label":target.0.label}),
            )
            .await?;
            let challenge: ChallengeResponse = relay
                .post(
                    "v1/auth/challenge",
                    &ChallengeRequest {
                        device_id: self.local.device_id.clone(),
                        extra: Extra::new(),
                    },
                    None,
                )
                .await?;
            if challenge.exp <= self.services.clock.now()
                || remote::keys::decode_b64(&challenge.challenge)?.len() != 32
            {
                return Err(Error("invalid_identity_challenge"));
            }
            let body = DeviceDeleteProof {
                action: DeviceDeleteAction::RevokeDevice,
                account: self.account.clone(),
                by: self.local.device_id.clone(),
                device_id: id.into(),
                challenge: challenge.challenge,
                extra: Extra::new(),
            };
            let key = remote::validation::approval_key(&self.local, ApprovalLevel::Strong)?;
            let sig = encode_b64(
                &self
                    .approval_provider(ApprovalLevel::Strong)?
                    .sign(key.alg, &remote::canonical::jcs(&body)?)?,
            );
            let revoke = DeviceRevoke {
                device_id: id.into(),
                extra: json!({"proof":body,"sig":sig}).as_object().unwrap().clone(),
            };
            remote::validation::verify_device_revoke(&revoke, &self.local, &self.account)?;
            if done.is_none() {
                let mut state = self.lock()?;
                let tx = state.store.transaction(self.services.audit.as_ref())?;
                tx.execute(
                    "INSERT INTO device_revocations(device_id,body_json) VALUES(?1,?2)",
                    params![id, encode(&revoke)?],
                )?;
                for peer in records
                    .iter()
                    .filter(|(peer, revoked)| {
                        !revoked && peer.device_id != self.local.device_id && peer.device_id != id
                    })
                    .map(|(peer, _)| peer)
                {
                    // Revocations only tighten authority and remain deliverable to offline peers.
                    let envelope = self.seal(
                        peer,
                        EnvelopeType::DeviceRevoke,
                        &super::engine::new_id(self.services.clock.now())?,
                        remote::canonical::MAX_SAFE_INTEGER as i64,
                        &revoke,
                    )?;
                    state.store.queue(&envelope)?;
                    tx.execute("INSERT INTO device_revocation_targets(device_id,peer,envelope_json) VALUES(?1,?2,?3)",params![id,peer.device_id,encode(&envelope)?])?;
                }
                let cancelled = self.revoke_device_rows(&state, id, "local")?;
                let update = self.stage_directory(&state)?;
                self.audit(
                    &state,
                    "device_revocation_requested",
                    json!({"device_id":id}),
                )?;
                tx.commit()?;
                update.commit()?;
                Self::clear_revoked_device_state(&mut state, id, cancelled);
            }
            proof = Some(body);
            signature = Some(sig);
        }
        let envelopes = {
            let state = self.lock()?;
            let mut query=state.store.db.prepare("SELECT envelope_json FROM device_revocation_targets WHERE device_id=?1 ORDER BY peer")?;
            let entries = query
                .query_map([id], |r| r.get::<_, String>(0))?
                .collect::<std::result::Result<Vec<_>, _>>()?;
            entries
                .iter()
                .map(|value| decode::<Envelope>(value))
                .collect::<Result<Vec<_>>>()?
                .into_iter()
                .filter(|envelope| state.store.device(&envelope.to, &self.account).is_ok())
                .collect::<Vec<_>>()
        };
        for batch in envelopes.chunks(64) {
            let reply: AcceptedResponse = relay
                .post(
                    "v1/messages",
                    &SendMessagesRequest {
                        envelopes: batch.to_vec(),
                        extra: Extra::new(),
                    },
                    Some(&token),
                )
                .await?;
            if reply.accepted != batch.len() as u64 {
                return Err(Error("invalid_remote_response"));
            }
            self.outbound_ack(kv_ipc::remote::RelayOutboundAckParams {
                envelopes: batch.to_vec(),
                stage: kv_ipc::remote::OutboundStage::Accepted,
                extra: Extra::new(),
            })?;
        }
        if let Some(proof) = proof {
            relay
                .delete_device(
                    id,
                    &token,
                    &proof.challenge,
                    signature.as_deref().ok_or(Error("invalid_state"))?,
                )
                .await?;
            self.lock()?.store.db.execute(
                "UPDATE device_revocations SET relay_done=1 WHERE device_id=?1",
                [id],
            )?;
        }
        Ok(())
    }
}
