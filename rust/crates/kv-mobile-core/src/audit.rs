//! Persistent metadata audit, separate from the short UI activity history.
use crate::{engine::MobileCore, now, Error, Result};
use kv_core::remote::{
    audit::{metadata, AuditHead, AuditPage},
    canonical::{jcs, sha256_hex},
    *,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

#[derive(Serialize, Deserialize)]
struct Record {
    head: AuditHead,
    previous: String,
    entry: Value,
}

impl MobileCore {
    pub(crate) fn audit_event(&self, db: &rusqlite::Connection, mut entry: Value) -> Result<()> {
        let old: AuditHead = self
            .store
            .get(db, "meta", "audit_head")?
            .unwrap_or_default();
        let seq = old.seq.checked_add(1).ok_or(Error("audit_integrity"))?;
        entry["ts_unix"] = json!(now());
        entry["audit_seq"] = json!(seq);
        entry["account_id"] = json!(self.account_in(db)?);
        entry["source_device"] = json!(self.own.device_id);
        let mut bytes = old.hash.as_bytes().to_vec();
        bytes.extend(jcs(&entry)?);
        let head = AuditHead {
            seq,
            hash: sha256_hex(&bytes),
        };
        self.store.put(
            db,
            "audit",
            &format!("{seq:020}"),
            &Record {
                head: head.clone(),
                previous: old.hash,
                entry,
            },
            0,
        )?;
        self.store.put(db, "meta", "audit_head", &head, 0)
    }

    pub(crate) fn account_in(&self, db: &rusqlite::Connection) -> Result<String> {
        self.store
            .get(db, "meta", "account")?
            .ok_or(Error("pairing_required"))
    }

    pub(crate) fn audit_page(
        &self,
        db: &rusqlite::Connection,
        args: &QueryAuditArgs,
    ) -> Result<AuditPage> {
        let records = self.store.list::<Record>(db, "audit")?;
        let head: AuditHead = self
            .store
            .get(db, "meta", "audit_head")?
            .unwrap_or_default();
        let cursor = |key: &str| -> Result<Option<u64>> {
            args.extra
                .get(key)
                .map(|v| v.as_u64().ok_or(Error("invalid_page")))
                .transpose()
        };
        let after = cursor("after")?.unwrap_or(0);
        let through = cursor("through")?.unwrap_or(head.seq);
        if args.limit == 0 || args.limit > 200 || after > through || through > head.seq {
            return Err(Error("invalid_page"));
        }
        let mut previous = AuditHead::default();
        let mut frozen = AuditHead::default();
        let mut entries = Vec::new();
        let mut bytes = 1024;
        let mut more = false;
        for (key, record) in records {
            let mut binding = previous.hash.as_bytes().to_vec();
            binding.extend(jcs(&record.entry)?);
            if record.head.seq != previous.seq + 1
                || key != format!("{:020}", record.head.seq)
                || record.previous != previous.hash
                || record.head.hash != sha256_hex(&binding)
                || record.entry["audit_seq"].as_u64() != Some(record.head.seq)
            {
                return Err(Error("audit_integrity"));
            }
            if record.head.seq == through {
                frozen = record.head.clone();
            }
            if record.head.seq > after
                && record.head.seq <= through
                && record.entry["ts_unix"]
                    .as_i64()
                    .is_some_and(|ts| ts >= args.since)
                && !more
            {
                let mut entry = metadata(&record.entry);
                entry["remote_hash"] = json!(record.head.hash);
                entry["remote_prev_hash"] = json!(record.previous);
                let size = serde_json::to_vec(&entry)?.len();
                if entries.len() >= args.limit as usize || bytes + size > 48 * 1024 {
                    if entries.is_empty() {
                        return Err(Error("audit_record_too_large"));
                    }
                    more = true;
                } else {
                    bytes += size;
                    entries.push(entry);
                }
            }
            previous = record.head;
        }
        if previous != head {
            return Err(Error("audit_integrity"));
        }
        let next_cursor = if more {
            entries.last().and_then(|entry| entry["audit_seq"].as_u64())
        } else {
            None
        };
        Ok(AuditPage {
            account_id: self.account_in(db)?,
            device_id: self.own.device_id.clone(),
            entries,
            through,
            next_cursor,
            head: frozen,
            checkpoint: "encrypted_store".into(),
            history_complete: !self
                .store
                .get::<bool>(db, "meta", "audit_history_incomplete")?
                .unwrap_or(true)
                || self
                    .store
                    .get::<i64>(db, "meta", "audit_started_at")?
                    .is_some_and(|start| args.since >= start),
        })
    }

    pub(crate) fn answer_audit(
        &self,
        db: &rusqlite::Connection,
        envelope: &Envelope,
        peer: &DeviceRecord,
        directive: &Directive,
    ) -> Result<()> {
        if directive.op != DirectiveOp::QueryAudit
            || directive.id != envelope.id
            || directive.aud != self.own.device_id
        {
            return Err(Error("invalid_audit_query"));
        }
        let current = kv_core::remote::validation::DirectiveState::default();
        let verified = [ApprovalLevel::Quick, ApprovalLevel::Strong]
            .into_iter()
            .any(|level| {
                kv_core::remote::validation::verify_directive(
                    directive,
                    &self.own.device_id,
                    peer,
                    level,
                    now(),
                    &current,
                )
                .is_ok()
            });
        if !verified {
            return Err(Error("verification_failed"));
        }
        let nonce_key = format!("{}:{}", peer.device_id, directive.nonce);
        if self
            .store
            .get::<bool>(db, "audit_nonces", &nonce_key)?
            .is_some()
        {
            return Err(Error("replay_conflict"));
        }
        let args: QueryAuditArgs = directive.args_as()?;
        let page = self.audit_page(db, &args)?;
        let response = DirectiveResult {
            id: directive.id.clone(),
            ok: true,
            error: None,
            state: serde_json::to_value(page)?
                .as_object()
                .cloned()
                .ok_or(Error("invalid_message"))?,
            extra: Extra::new(),
        };
        let reply = kv_core::remote::envelope::seal(
            EnvelopeHeader {
                v: 1,
                r#type: EnvelopeType::DirectiveResult,
                id: directive.id.clone(),
                account: self.account_in(db)?,
                from: self.own.device_id.clone(),
                to: peer.device_id.clone(),
                created_at: now(),
                exp: directive.exp,
                extra: Extra::new(),
            },
            &jcs(&response)?,
            &peer.dk_pub,
            self.keys.identity.as_ref(),
        )?;
        self.enqueue(db, &reply)?;
        self.store.put(
            db,
            "audit_nonces",
            &nonce_key,
            &true,
            directive.exp.saturating_add(60),
        )?;
        self.audit_event(db,json!({"op":"directive_applied","id":directive.id,"iss":directive.iss,"directive_op":directive.op,"ok":true}))
    }
}
