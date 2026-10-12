use super::engine::validate_device;
use super::{AuditSink, Error, Result};
use kv_core::remote::audit::AuditHead;
use kv_core::remote::canonical::{from_json, jcs, sha256_hex, CanonicalRequest};
use kv_core::remote::*;
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use std::path::Path;

pub struct Store {
    pub(crate) db: Connection,
}

/// SQLite decides commit; the vault journal makes checkpoint publication recoverable.
pub(crate) struct AuditTransaction<'a> {
    tx: Option<rusqlite::Transaction<'a>>,
    store: &'a Store,
    sink: &'a dyn AuditSink,
    old: AuditHead,
    committed: bool,
    prepared: bool,
}

impl AuditTransaction<'_> {
    pub fn commit(mut self) -> Result<()> {
        let next = self.store.audit_head()?;
        if next != self.old {
            self.sink.prepare_checkpoint(&self.old, &next)?;
            self.prepared = true;
        }
        self.tx
            .take()
            .expect("transaction is owned until commit")
            .commit()?;
        self.committed = true;
        if self.prepared {
            self.sink.commit_checkpoint(&next)?;
        }
        Ok(())
    }
}

impl std::ops::Deref for AuditTransaction<'_> {
    type Target = Connection;
    fn deref(&self) -> &Connection {
        &self.store.db
    }
}

impl Drop for AuditTransaction<'_> {
    fn drop(&mut self) {
        // Roll back SQLite before discarding a prepared checkpoint.
        self.tx.take();
        if self.prepared && !self.committed {
            let _ = self.sink.abort_checkpoint(&self.old);
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PendingState {
    Waiting,
    Approved,
    ApprovedUnused,
    Executed,
    Denied,
    Expired,
    Cancelled,
}

impl PendingState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Waiting => "waiting",
            Self::Approved => "approved",
            Self::ApprovedUnused => "approved_unused",
            Self::Executed => "executed",
            Self::Denied => "denied",
            Self::Expired => "expired",
            Self::Cancelled => "cancelled",
        }
    }

    fn parse(text: &str) -> Result<Self> {
        Ok(match text {
            "waiting" => Self::Waiting,
            "approved" => Self::Approved,
            "approved_unused" => Self::ApprovedUnused,
            "executed" => Self::Executed,
            "denied" => Self::Denied,
            "expired" => Self::Expired,
            "cancelled" => Self::Cancelled,
            _ => return Err(Error("invalid_pending_state")),
        })
    }
}

pub(crate) struct Pending {
    pub request: ApprovalRequest,
    pub canonical: CanonicalRequest,
    pub state: PendingState,
    pub created_at: i64,
    pub session_id: String,
    pub decision: Option<ApprovalDecision>,
    pub claimed_at: Option<i64>,
    pub epoch: u64,
}

impl Store {
    pub(crate) fn transaction<'a>(
        &'a self,
        sink: &'a dyn AuditSink,
    ) -> Result<AuditTransaction<'a>> {
        let tx = self.db.unchecked_transaction()?;
        let old = self.audit_head()?;
        Ok(AuditTransaction {
            tx: Some(tx),
            store: self,
            sink,
            old,
            committed: false,
            prepared: false,
        })
    }

    pub(crate) fn audit_head(&self) -> Result<AuditHead> {
        Ok(self
            .db
            .query_row(
                "SELECT seq,entry_hash FROM remote_audit ORDER BY seq DESC LIMIT 1",
                [],
                |row| {
                    Ok(AuditHead {
                        seq: row.get(0)?,
                        hash: row.get(1)?,
                    })
                },
            )
            .optional()?
            .unwrap_or_default())
    }
    /// Bootstrap a fresh database only from the vault's authenticated directory. This is an
    /// in-process integration API, never an IPC operation or a substitute for SAS verification.
    pub fn restore_verified_directory(
        &self,
        account: &str,
        records: &[(DeviceRecord, bool)],
        mirror: &dyn super::DeviceMirror,
        now: i64,
    ) -> Result<()> {
        mirror.verify(account, records)?;
        let count: u64 = self
            .db
            .query_row("SELECT COUNT(*) FROM devices", [], |r| r.get(0))?;
        if count != 0 || account.is_empty() {
            return Err(Error("device_directory_mismatch"));
        }
        let tx = self.db.unchecked_transaction()?;
        for (device, revoked) in records {
            validate_device(device)?;
            self.insert_device(device, account, now)?;
            if *revoked {
                self.db.execute(
                    "UPDATE devices SET revoked_at=?1,trust='revoked' WHERE id=?2",
                    params![now, device.device_id],
                )?;
            }
        }
        tx.commit()?;
        Ok(())
    }

    pub fn memory() -> Result<Self> {
        Self::initialize(Connection::open_in_memory()?)
    }

    #[cfg(test)]
    pub(super) fn persistence_fixture(path: &Path) -> Result<Self> {
        // Restart tests exercise SQLite durability with fake services in an ordinary tempdir.
        // Privileged path checks remain in open() and its separate security tests.
        Self::initialize(Connection::open(path)?)
    }

    pub fn open(path: &Path) -> Result<Self> {
        let parent = path.parent().ok_or(Error("invalid_state_path"))?;
        let meta = std::fs::symlink_metadata(parent).map_err(|_| Error("state_unavailable"))?;
        // symlink_metadata never reports a symlink as a directory.
        if !meta.is_dir() {
            return Err(Error("untrusted_state_directory"));
        }
        #[cfg(windows)]
        kv_platform::fs::ensure_private_dir(parent)
            .map_err(|_| Error("untrusted_state_directory"))?;
        let mut options = std::fs::OpenOptions::new();
        options.read(true).write(true).create(true).truncate(false);
        #[cfg(unix)]
        {
            use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
            if !unix_private(meta.uid(), meta.mode(), unsafe { libc::geteuid() }) {
                return Err(Error("untrusted_state_directory"));
            }
            options
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
        }
        let file = options.open(path).map_err(|_| Error("state_unavailable"))?;
        let meta = file.metadata().map_err(|_| Error("state_unavailable"))?;
        validate_file(&meta)?;
        #[cfg(windows)]
        if kv_platform::trust::untrusted_reason(path).is_some() {
            return Err(Error("untrusted_state_file"));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if !unix_private(meta.uid(), meta.mode(), unsafe { libc::geteuid() }) {
                return Err(Error("untrusted_state_file"));
            }
        }
        kv_platform::fs::set_private_permissions(path).map_err(|_| Error("state_unavailable"))?;
        Self::initialize(Connection::open(path)?)
    }

    fn initialize(db: Connection) -> Result<Self> {
        db.busy_timeout(std::time::Duration::from_secs(5))?;
        db.execute_batch(include_str!("schema.sql"))?;
        db.execute(
            "INSERT OR IGNORE INTO approval_history(approval_id)
            SELECT approval_id FROM issued_approvals ORDER BY issued_at,approval_id",
            [],
        )?;
        Ok(Self { db })
    }

    pub(crate) fn device(&self, id: &str, account: &str) -> Result<DeviceRecord> {
        let row: Option<(String, String, Option<i64>, String)> = self
            .db
            .query_row(
                "SELECT record_json, trust, revoked_at, account_id FROM devices WHERE id = ?1",
                [id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .optional()?;
        let Some((record, trust, revoked_at, stored_account)) = row else {
            return Err(Error("unpaired_device"));
        };
        if revoked_at.is_some() || trust == "revoked" {
            return Err(Error("revoked_device"));
        }
        if stored_account != account || !matches!(trust.as_str(), "verified_sas" | "recovery") {
            return Err(Error("untrusted_device"));
        }
        decode(&record)
    }

    pub(crate) fn devices(&self, account: &str) -> Result<Vec<DeviceRecord>> {
        let mut statement = self.db.prepare(
            "SELECT record_json FROM devices WHERE account_id = ?1 AND revoked_at IS NULL
             AND trust IN ('verified_sas', 'recovery') ORDER BY id",
        )?;
        let rows = statement.query_map([account], |row| row.get::<_, String>(0))?;
        rows.map(|row| decode(&row?)).collect()
    }

    pub(crate) fn insert_device(
        &self,
        device: &DeviceRecord,
        account: &str,
        now: i64,
    ) -> Result<()> {
        self.db.execute(
            "INSERT INTO devices (id, account_id, label, os, key_kind, dk_pub, akq_pub, akq_alg,
             aks_pub, aks_alg, caps, attestation, trust, added_at, record_json)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, 'verified_sas', ?13, ?14)",
            params![
                device.device_id,
                account,
                device.label,
                device.os.as_str(),
                device.key_kind.as_str(),
                encode(&device.dk_pub)?,
                device.ak_q.as_ref().map(|k| encode(&k.r#pub)).transpose()?,
                device.ak_q.as_ref().map(|k| algorithm(k.alg)),
                device.ak_s.as_ref().map(|k| encode(&k.r#pub)).transpose()?,
                device.ak_s.as_ref().map(|k| algorithm(k.alg)),
                encode(&device.caps)?,
                device.attestation.as_ref().map(encode).transpose()?,
                now,
                encode(device)?
            ],
        )?;
        Ok(())
    }

    pub(crate) fn pending(&self, id: &str) -> Result<Pending> {
        let row = self.db.query_row(
            "SELECT request_json, canonical_json, state, created_at, session_id, decision_json, claimed_at, epoch
             FROM pending_approvals WHERE id = ?1",
            [id],
            |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?, r.get::<_, String>(2)?,
                r.get::<_, i64>(3)?, r.get::<_, String>(4)?, r.get::<_, Option<String>>(5)?,
                r.get::<_, Option<i64>>(6)?, r.get::<_, u64>(7)?)),
        ).optional()?.ok_or(Error("not_waiting"))?;
        Ok(Pending {
            request: decode(&row.0)?,
            canonical: decode(&row.1)?,
            state: PendingState::parse(&row.2)?,
            created_at: row.3,
            session_id: row.4,
            decision: row.5.as_deref().map(decode).transpose()?,
            claimed_at: row.6,
            epoch: row.7,
        })
    }

    pub(crate) fn pending_ids(&self) -> Result<Vec<String>> {
        let mut statement = self
            .db
            .prepare("SELECT id FROM pending_approvals ORDER BY created_at, id")?;
        let rows = statement.query_map([], |row| row.get(0))?;
        rows.collect::<std::result::Result<_, _>>()
            .map_err(Into::into)
    }

    pub(crate) fn setting<T: for<'de> Deserialize<'de>>(&self, key: &str) -> Result<Option<T>> {
        self.db
            .query_row(
                "SELECT value_json FROM settings WHERE key = ?1",
                [key],
                |row| row.get::<_, String>(0),
            )
            .optional()?
            .as_deref()
            .map(decode)
            .transpose()
    }

    /// Transport notifications and Stop queries use the same authenticated agent filter.
    pub(crate) fn pending_ids_for_agent(&self, agent_pid: u32, now: i64) -> Result<Vec<String>> {
        let mut statement = self.db.prepare(
            "SELECT id FROM pending_approvals WHERE exp>=?1 AND agent_pid=?2 ORDER BY created_at, id",
        )?;
        let rows = statement.query_map(params![now, agent_pid], |row| row.get(0))?;
        rows.collect::<std::result::Result<_, _>>()
            .map_err(Into::into)
    }

    pub(crate) fn set_setting(
        &self,
        key: &str,
        value: &impl Serialize,
        by: &str,
        now: i64,
    ) -> Result<()> {
        self.db.execute(
            "INSERT INTO settings (key, value_json, set_by, set_at) VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(key) DO UPDATE SET value_json=excluded.value_json, set_by=excluded.set_by, set_at=excluded.set_at",
            params![key, encode(value)?, by, now],
        )?;
        Ok(())
    }

    pub(crate) fn consume_nonce(
        &self,
        nonce: &str,
        digest: &str,
        now: i64,
        exp: i64,
    ) -> Result<()> {
        match self.db.execute(
            "INSERT OR FAIL INTO nonces (nonce, digest, used_at, exp) VALUES (?1, ?2, ?3, ?4)",
            params![nonce, digest, now, exp],
        ) {
            Ok(_) => Ok(()),
            Err(rusqlite::Error::SqliteFailure(error, _))
                if error.code == rusqlite::ErrorCode::ConstraintViolation =>
            {
                Err(Error("replay"))
            }
            Err(error) => Err(error.into()),
        }
    }

    pub(crate) fn queue(&self, envelope: &Envelope) -> Result<()> {
        let encoded = encode(envelope)?;
        self.db.execute(
            "INSERT INTO remote_outbox (envelope_json, exp) VALUES (?1, ?2)",
            params![encoded, envelope.exp],
        )?;
        self.db.execute("INSERT OR IGNORE INTO remote_outbox_receipts(envelope_hash,stage,exp) VALUES(?1,'pending',?2)",
            params![sha256_hex(encoded.as_bytes()), envelope.exp])?;
        Ok(())
    }

    pub(crate) fn audit(
        &self,
        sink: &dyn AuditSink,
        mut entry: Map<String, Value>,
        now: i64,
    ) -> Result<()> {
        let transaction = if self.db.is_autocommit() {
            Some(self.transaction(sink)?)
        } else {
            None
        };
        let seq = self
            .audit_head()?
            .seq
            .checked_add(1)
            .ok_or(Error("audit_chain_mismatch"))?;
        entry.insert("ts_unix".into(), json!(now));
        entry.insert("audit_seq".into(), json!(seq));
        let previous: String = self
            .db
            .query_row(
                "SELECT entry_hash FROM remote_audit ORDER BY seq DESC LIMIT 1",
                [],
                |r| r.get(0),
            )
            .optional()?
            .unwrap_or_else(|| "0".repeat(64));
        let bytes = jcs(&entry)?;
        let mut binding = previous.as_bytes().to_vec();
        binding.extend_from_slice(&bytes);
        let hash = sha256_hex(&binding);
        self.db.execute(
            "INSERT INTO remote_audit (seq, entry_json, prev_hash, entry_hash) VALUES (?4, ?1, ?2, ?3)",
            params![
                String::from_utf8(bytes).expect("JCS is UTF-8"),
                previous,
                hash, seq
            ],
        )?;
        entry.insert("remote_prev_hash".into(), json!(previous));
        entry.insert("remote_hash".into(), json!(hash));
        sink.append(entry).map_err(|_| Error("audit_unavailable"))?;
        if let Some(transaction) = transaction {
            transaction.commit()?;
        }
        Ok(())
    }

    pub fn audit_entries(&self) -> Result<Vec<Value>> {
        let mut statement = self
            .db
            .prepare("SELECT entry_json FROM remote_audit ORDER BY seq")?;
        let rows = statement.query_map([], |r| r.get::<_, String>(0))?;
        rows.map(|row| decode(&row?)).collect()
    }

    pub(crate) fn audit_records(&self) -> Result<Vec<Value>> {
        let mut statement = self
            .db
            .prepare("SELECT seq,entry_json,prev_hash,entry_hash FROM remote_audit ORDER BY seq")?;
        let rows = statement.query_map([], |r| {
            Ok((
                r.get::<_, u64>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, String>(3)?,
            ))
        })?;
        rows.map(|r| {
            let (seq, entry, previous, hash) = r?;
            let mut entry: Value = decode(&entry)?;
            entry["remote_hash"] = json!(hash);
            entry["remote_prev_hash"] = json!(previous);
            // Legacy entries predate audit_seq; their original hash remains unchanged.
            if entry.get("audit_seq").is_none() {
                entry["legacy_seq"] = json!(seq);
            }
            Ok(entry)
        })
        .collect()
    }

    pub(crate) fn audit_page(
        &self,
        args: &QueryAuditArgs,
        account: &str,
        device: &str,
        sink: &dyn AuditSink,
    ) -> Result<kv_core::remote::audit::AuditPage> {
        self.verify_audit()?;
        let current = self.audit_head()?;
        sink.verify_checkpoint(&current)?;
        sink.verify_records(&self.audit_records()?)?;
        let cursor = |key: &str| -> Result<Option<u64>> {
            args.extra
                .get(key)
                .map(|v| {
                    v.as_u64()
                        .filter(|n| *n <= 9_007_199_254_740_991)
                        .ok_or(Error("invalid_page"))
                })
                .transpose()
        };
        let after = cursor("after")?.unwrap_or(0);
        let through = cursor("through")?.unwrap_or(current.seq);
        if args.limit == 0 || args.limit > 200 || after > through || through > current.seq {
            return Err(Error("invalid_page"));
        }
        let head = if through == 0 {
            AuditHead::default()
        } else {
            self.db.query_row(
                "SELECT seq,entry_hash FROM remote_audit WHERE seq=?1",
                [through],
                |row| {
                    Ok(AuditHead {
                        seq: row.get(0)?,
                        hash: row.get(1)?,
                    })
                },
            )?
        };
        let mut statement = self.db.prepare("SELECT seq,entry_json,prev_hash,entry_hash FROM remote_audit
            WHERE seq>?1 AND seq<=?2 AND json_extract(entry_json,'$.ts_unix')>=?3 ORDER BY seq LIMIT ?4")?;
        let rows =
            statement.query_map(params![after, through, args.since, args.limit + 1], |row| {
                Ok((
                    row.get::<_, u64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                ))
            })?;
        let mut entries = Vec::new();
        let mut bytes = 1024;
        let mut more = false;
        for row in rows {
            let (seq, entry, previous, hash) = row?;
            let mut entry = kv_core::remote::audit::metadata(&decode::<Value>(&entry)?);
            entry["audit_seq"] = json!(seq);
            entry["remote_hash"] = json!(hash);
            entry["remote_prev_hash"] = json!(previous);
            let size = serde_json::to_vec(&entry)?.len();
            if entries.len() >= args.limit as usize || bytes + size > 48 * 1024 {
                if entries.is_empty() {
                    return Err(Error("audit_record_too_large"));
                }
                more = true;
                break;
            }
            bytes += size;
            entries.push(entry);
        }
        let next_cursor = if more {
            entries.last().and_then(|v| v["audit_seq"].as_u64())
        } else {
            None
        };
        Ok(kv_core::remote::audit::AuditPage {
            account_id: account.into(),
            device_id: device.into(),
            entries,
            through,
            next_cursor,
            head,
            checkpoint: sink.checkpoint_kind().into(),
            history_complete: true,
        })
    }

    pub(crate) fn verify_audit(&self) -> Result<()> {
        let mut statement = self.db.prepare(
            "SELECT entry_json, prev_hash, entry_hash, seq FROM remote_audit ORDER BY seq",
        )?;
        let rows = statement.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, u64>(3)?,
            ))
        })?;
        let mut previous = "0".repeat(64);
        let mut sequence = 0;
        for row in rows {
            let (entry, prev_hash, hash, seq) = row?;
            let value: Value = decode(&entry)?;
            let mut binding = previous.as_bytes().to_vec();
            binding.extend_from_slice(&jcs(&value)?);
            if seq != sequence + 1
                || value
                    .get("audit_seq")
                    .is_some_and(|v| v.as_u64() != Some(seq))
                || prev_hash != previous
                || hash != sha256_hex(&binding)
            {
                return Err(Error("audit_chain_mismatch"));
            }
            previous = hash;
            sequence = seq;
        }
        Ok(())
    }
}

pub(crate) fn encode<T: Serialize + ?Sized>(value: &T) -> Result<String> {
    // W0 JCS always emits UTF-8; caller serialization errors are returned by jcs above.
    Ok(String::from_utf8(jcs(value)?).expect("JCS is UTF-8"))
}

pub(crate) fn decode<T: for<'de> Deserialize<'de>>(value: &str) -> Result<T> {
    from_json(value.as_bytes()).map_err(Into::into)
}

pub(crate) fn algorithm(alg: SignatureAlgorithm) -> &'static str {
    match alg {
        SignatureAlgorithm::ES256 => "ES256",
        SignatureAlgorithm::RS256 => "RS256",
    }
}

pub(crate) fn validate_file(metadata: &std::fs::Metadata) -> Result<()> {
    if metadata.is_file() {
        Ok(())
    } else {
        Err(Error("untrusted_state_file"))
    }
}

#[cfg(unix)]
pub(crate) fn unix_private(owner: u32, permissions: u32, service_uid: u32) -> bool {
    owner == service_uid && permissions & 0o077 == 0
}
