//! Independent authenticated commit checkpoints, with recovery of interrupted publication.
use super::{Error, Result};
use kv_core::remote::audit::AuditHead;
use kv_core::remote::canonical::{jcs, sha256_hex};
use kv_vault::Vault;
use serde::{Deserialize, Serialize};
use serde_json::Value;

const KEY: &str = "remote_audit_checkpoint";

pub(super) fn verify_records(vault: &Vault, records: &[Value]) -> Result<()> {
    use std::collections::{HashMap, HashSet};
    let committed: HashMap<&str, &Value> = records
        .iter()
        .filter_map(|entry| entry["remote_hash"].as_str().map(|hash| (hash, entry)))
        .collect();
    let mut retained = HashSet::new();
    let mut first = None;
    for mut entry in vault
        .read_audit_records()
        .map_err(|_| Error("audit_unavailable"))?
    {
        let Some(hash) = entry["remote_hash"].as_str().map(str::to_owned) else {
            continue;
        };
        let Some(expected) = committed.get(hash.as_str()) else {
            continue;
        }; // Durable evidence of an aborted transaction is retained.
        let object = entry
            .as_object_mut()
            .ok_or(Error("audit_receipt_mismatch"))?;
        object.remove("ts");
        object.remove("pid");
        let mut expected = (*expected).clone();
        expected
            .as_object_mut()
            .ok_or(Error("audit_receipt_mismatch"))?
            .remove("legacy_seq");
        if entry != expected {
            return Err(Error("audit_receipt_mismatch"));
        }
        let seq = expected["audit_seq"]
            .as_u64()
            .or_else(|| {
                records
                    .iter()
                    .position(|r| r["remote_hash"] == expected["remote_hash"])
                    .map(|i| i as u64 + 1)
            })
            .ok_or(Error("audit_receipt_mismatch"))?;
        first = Some(first.map_or(seq, |old: u64| old.min(seq)));
        retained.insert(hash);
    }
    if let Some(first) = first {
        for (index, entry) in records.iter().enumerate() {
            if index as u64 + 1 >= first
                && !retained.contains(
                    entry["remote_hash"]
                        .as_str()
                        .ok_or(Error("audit_receipt_mismatch"))?,
                )
            {
                return Err(Error("audit_receipt_missing"));
            }
        }
    } else if !records.is_empty() {
        return Err(Error("audit_receipt_missing"));
    }
    Ok(())
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Checkpoint {
    version: u32,
    committed: AuditHead,
    pending: Option<AuditHead>,
}

fn read(vault: &Vault) -> Result<Option<Value>> {
    vault
        .authenticated_metadata(KEY)
        .map_err(|_| Error("audit_unavailable"))
}

fn decode(value: &Value) -> Result<Checkpoint> {
    let checkpoint: Checkpoint =
        serde_json::from_value(value.clone()).map_err(|_| Error("audit_checkpoint_mismatch"))?;
    if checkpoint.version != 1 {
        return Err(Error("audit_checkpoint_mismatch"));
    }
    Ok(checkpoint)
}

fn write(vault: &Vault, old: Option<&Value>, checkpoint: Checkpoint) -> Result<()> {
    vault
        .replace_authenticated_metadata(KEY, old, serde_json::to_value(checkpoint)?)
        .map_err(|_| Error("audit_unavailable"))
}

fn receipt(vault: &Vault, head: &AuditHead) -> Result<()> {
    if head.seq == 0 {
        return if *head == AuditHead::default() {
            Ok(())
        } else {
            Err(Error("audit_checkpoint_mismatch"))
        };
    }
    for entry in vault
        .read_audit_records()
        .map_err(|_| Error("audit_unavailable"))?
    {
        if entry.get("remote_hash").and_then(Value::as_str) != Some(&head.hash) {
            continue;
        }
        let mut entry = entry
            .as_object()
            .cloned()
            .ok_or(Error("audit_receipt_mismatch"))?;
        let previous = entry
            .remove("remote_prev_hash")
            .and_then(|v| v.as_str().map(str::to_owned))
            .ok_or(Error("audit_receipt_mismatch"))?;
        entry.remove("remote_hash");
        entry.remove("ts");
        entry.remove("pid");
        let mut bytes = previous.into_bytes();
        bytes.extend(jcs(&entry)?);
        if sha256_hex(&bytes) != head.hash {
            return Err(Error("audit_receipt_mismatch"));
        }
        return Ok(());
    }
    Err(Error("audit_receipt_missing"))
}

pub(super) fn verify(vault: &Vault, head: &AuditHead) -> Result<()> {
    let old = read(vault)?;
    if let Some(value) = &old {
        let mut checkpoint = decode(value)?;
        if checkpoint.pending.as_ref() == Some(head) {
            receipt(vault, head)?;
            checkpoint.committed = head.clone();
            checkpoint.pending = None;
            return write(vault, old.as_ref(), checkpoint);
        }
        if checkpoint.committed != *head {
            return Err(Error("audit_checkpoint_mismatch"));
        }
        receipt(vault, head)?;
        if checkpoint.pending.take().is_some() {
            write(vault, old.as_ref(), checkpoint)?;
        }
        Ok(())
    } else {
        // Upgrade legacy databases only when their verified tip also exists in the vault log.
        if head.seq == 0
            && vault
                .read_audit_records()
                .map_err(|_| Error("audit_unavailable"))?
                .iter()
                .any(|entry| entry.get("remote_hash").is_some())
        {
            return Err(Error("audit_checkpoint_mismatch"));
        }
        receipt(vault, head)?;
        write(
            vault,
            None,
            Checkpoint {
                version: 1,
                committed: head.clone(),
                pending: None,
            },
        )
    }
}

pub(super) fn prepare(vault: &Vault, old_head: &AuditHead, next: &AuditHead) -> Result<()> {
    let old = read(vault)?.ok_or(Error("audit_checkpoint_mismatch"))?;
    let mut checkpoint = decode(&old)?;
    // A previous committed publication may have failed. Reconcile it before another write.
    if checkpoint.pending.as_ref() == Some(old_head) {
        checkpoint.committed = old_head.clone();
    }
    if checkpoint.committed != *old_head {
        return Err(Error("audit_checkpoint_mismatch"));
    }
    if old_head == next {
        return Ok(());
    }
    checkpoint.pending = Some(next.clone());
    write(vault, Some(&old), checkpoint)
}

pub(super) fn commit(vault: &Vault, head: &AuditHead) -> Result<()> {
    let old = read(vault)?.ok_or(Error("audit_checkpoint_mismatch"))?;
    let mut checkpoint = decode(&old)?;
    if checkpoint.committed == *head && checkpoint.pending.is_none() {
        return Ok(());
    }
    if checkpoint.pending.as_ref() != Some(head) {
        return Err(Error("audit_checkpoint_mismatch"));
    }
    checkpoint.committed = head.clone();
    checkpoint.pending = None;
    write(vault, Some(&old), checkpoint)
}

pub(super) fn abort(vault: &Vault, head: &AuditHead) -> Result<()> {
    let old = read(vault)?.ok_or(Error("audit_checkpoint_mismatch"))?;
    let mut checkpoint = decode(&old)?;
    if checkpoint.committed != *head {
        return Err(Error("audit_checkpoint_mismatch"));
    }
    if checkpoint.pending.take().is_some() {
        write(vault, Some(&old), checkpoint)?;
    }
    Ok(())
}
