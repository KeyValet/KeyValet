use crate::error::{ApiError, Result};
use axum::http::HeaderMap;
use kv_core::remote::canonical::{from_json, jcs, sha256_hex};
use kv_core::remote::keys::{encode_b64, p256_public_sec1, rsa_public_key};
use kv_core::remote::{Capability, DeviceRecord, Envelope, SignatureAlgorithm};
use rand_core::{OsRng, RngCore};
use rusqlite::{params, Connection, OptionalExtension, Row, ToSql};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::mpsc;

pub const SESSION_TTL: i64 = 24 * 60 * 60;
pub const PAIR_TTL: i64 = 10 * 60;
pub const RETENTION: i64 = 7 * 24 * 60 * 60;
pub const HEARTBEAT: Duration = Duration::from_secs(30);
pub const IDLE_TIMEOUT: Duration = Duration::from_secs(100);
pub const MAX_PENDING: i64 = 500;

pub(crate) struct State {
    pub accounts: crate::account::Accounts,
    pub data: Mutex<Data>,
    offset: AtomicI64,
    test_clock: AtomicI64,
    pub requests: AtomicU64,
    pub log: Mutex<Vec<String>>,
    pub capture_logs: bool,
    pub recovery: Arc<dyn crate::auth::RecoveryPasswords>,
}

impl State {
    pub fn new(db: Connection, capture_logs: bool) -> Result<Arc<Self>> {
        Self::new_with_accounts(db, capture_logs, crate::account::AccountConfig::default())
    }

    pub fn new_with_accounts(
        db: Connection,
        capture_logs: bool,
        config: crate::account::AccountConfig,
    ) -> Result<Arc<Self>> {
        // SQLite returns SQLITE_OK for a valid connection and a fixed busy handler.
        db.busy_timeout(Duration::from_secs(5))
            .expect("an open SQLite connection accepts a fixed busy timeout");
        db.pragma_update(None, "journal_mode", "WAL")?;
        db.execute_batch(include_str!("schema.sql"))?;
        Ok(Arc::new(Self {
            accounts: crate::account::Accounts::new(config.clone()),
            data: Mutex::new(Data {
                account_login_required: config.required,
                db,
                challenges: HashMap::new(),
                rates: HashMap::new(),
                presence: HashMap::new(),
            }),
            offset: AtomicI64::new(0),
            test_clock: AtomicI64::new(0),
            requests: AtomicU64::new(0),
            log: Mutex::new(Vec::new()),
            capture_logs,
            recovery: Arc::new(crate::auth::ArgonPasswords),
        }))
    }

    pub fn now(&self) -> i64 {
        let fixed = self.test_clock.load(Ordering::Relaxed);
        if fixed != 0 {
            return fixed + self.offset.load(Ordering::Relaxed);
        }
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64
            + self.offset.load(Ordering::Relaxed)
    }
    pub(crate) fn freeze_test_clock(&self) -> i64 {
        assert!(
            self.capture_logs,
            "fixed clocks are available only in the test harness"
        );
        let now = self.now();
        self.test_clock
            .store(now - self.offset.load(Ordering::Relaxed), Ordering::Relaxed);
        now
    }

    pub fn advance(&self, seconds: i64) {
        self.offset.fetch_add(seconds, Ordering::Relaxed);
    }

    pub fn with<T>(&self, f: impl FnOnce(&mut Data, i64) -> Result<T>) -> Result<T> {
        let mut data = self.data.lock().map_err(|_| ApiError::conflict())?;
        f(&mut data, self.now())
    }

    pub fn event(&self, event: &'static str, count: usize) {
        // Only compile-time event names and numeric metadata enter logs.
        let line = format!("event={event} count={count}");
        if self.capture_logs {
            if let Ok(mut log) = self.log.lock() {
                log.push(line);
            }
        } else {
            eprintln!("{line}");
        }
    }
}

pub(crate) struct Challenge {
    pub hash: String,
    pub exp: i64,
}

pub(crate) struct Presence {
    pub connection: String,
    pub sender: mpsc::Sender<Outbound>,
}

pub(crate) enum Outbound {
    Frame(Value),
    Close,
}

pub(crate) struct Data {
    pub account_login_required: bool,
    pub db: Connection,
    pub challenges: HashMap<String, Challenge>,
    rates: HashMap<String, Vec<(i64, u32)>>,
    pub presence: HashMap<String, Presence>,
}

#[derive(Clone)]
pub(crate) struct Principal {
    pub account: String,
    pub device: DeviceRecord,
    pub token_hash: String,
}

impl Data {
    pub fn authenticate(&self, headers: &HeaderMap, now: i64) -> Result<Principal> {
        let token = headers
            .get("authorization")
            .and_then(|h| h.to_str().ok())
            .and_then(|h| h.strip_prefix("Device "))
            .filter(|t| t.len() == 43)
            .ok_or_else(ApiError::unauthorized)?;
        let token_hash = sha256_hex(token.as_bytes());
        let row: Option<(String, Vec<u8>)> = self
            .db
            .query_row(
                "SELECT d.account_id, d.record FROM sessions s JOIN devices d ON d.id=s.device_id
             WHERE s.token_hash=?1 AND s.exp>=?2 AND d.revoked_at IS NULL",
                params![token_hash, now],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        let (account, record) = row.ok_or_else(ApiError::unauthorized)?;
        let device: DeviceRecord = from_json(&record)?;
        if self.account_login_required && crate::account::is_mobile(&device) {
            let valid: bool = self.db.query_row("SELECT EXISTS(SELECT 1 FROM device_session_users ds JOIN account_sessions s ON s.token_hash=ds.account_session JOIN device_users u ON u.device_id=s.device_id WHERE ds.token_hash=?1 AND s.device_id=?2 AND s.user_id=u.user_id AND s.exp>?3)", params![token_hash,device.device_id,now], |r|r.get(0))?;
            if !valid {
                return Err(ApiError::unauthorized());
            }
        }
        Ok(Principal {
            account,
            device,
            token_hash,
        })
    }

    pub fn ready(&self, device: &str) -> Result<bool> {
        device_ready(&self.db, device)
    }

    pub fn check(&self, principal: &Principal, now: i64, ready: bool) -> Result<()> {
        if self.account_login_required && crate::account::is_mobile(&principal.device) {
            let valid: bool = self.db.query_row("SELECT EXISTS(SELECT 1 FROM device_session_users ds JOIN account_sessions s ON s.token_hash=ds.account_session WHERE ds.token_hash=?1 AND s.device_id=?2 AND s.exp>=?3)",params![principal.token_hash,principal.device.device_id,now],|r|r.get(0))?;
            if !valid {
                return Err(ApiError::unauthorized());
            }
        }
        let valid: bool = self.db.query_row(
            "SELECT EXISTS(SELECT 1 FROM sessions s JOIN devices d ON d.id=s.device_id
             WHERE s.token_hash=?1 AND s.exp>=?2 AND d.revoked_at IS NULL AND d.account_id=?3)",
            params![principal.token_hash, now, principal.account],
            |row| row.get(0),
        )?;
        if !valid {
            return Err(ApiError::unauthorized());
        }
        if ready && !self.ready(&principal.device.device_id)? {
            return Err(ApiError::forbidden());
        }
        Ok(())
    }

    pub fn rate(&mut self, key: String, now: i64, cost: u32, limit: u32) -> Result<()> {
        // Sliding windows avoid a double burst at minute boundaries.
        self.rates.retain(|_, samples| {
            samples.retain(|(time, _)| *time > now - 60);
            !samples.is_empty()
        });
        let samples = self.rates.entry(key).or_default();
        let used: u32 = samples.iter().map(|(_, cost)| *cost).sum();
        if cost > limit.saturating_sub(used) {
            return Err(ApiError::rate_limited());
        }
        samples.push((now, cost));
        Ok(())
    }

    pub fn send(&mut self, device: &str, frame: Value) -> bool {
        if let Some(entry) = self.presence.get(device) {
            if entry.sender.try_send(Outbound::Frame(frame)).is_ok() {
                return true;
            }
            // A slow consumer reconnects and replays its durable inbox.
            self.presence.remove(device);
        }
        false
    }

    pub fn deliver(&mut self, envelope: &Envelope, now: i64) {
        if self.send(&envelope.to, json!({"t":"envelope", "envelope":envelope})) {
            // Acceptance was already committed. A tracking failure must not turn
            // a successful durable submission into a retryable HTTP error.
            let _ = self.db.execute(
                "UPDATE messages SET delivered_at=COALESCE(delivered_at,?1)
                 WHERE account_id=?2 AND id=?3 AND to_device=?4 AND type=?5",
                params![
                    now,
                    envelope.account,
                    envelope.id,
                    envelope.to,
                    envelope.r#type.as_str()
                ],
            );
        }
    }

    pub fn disconnect(&mut self, device: &str) {
        if let Some(entry) = self.presence.remove(device) {
            let _ = entry.sender.try_send(Outbound::Close);
        }
    }

    /// Called after revocation or account migration, rather than a socket replacement.
    pub fn invalidate_device(&mut self, device: &str) {
        self.disconnect(device);
        self.challenges.remove(device);
    }
}

pub(crate) fn device_ready(db: &Connection, device: &str) -> Result<bool> {
    Ok(!db.query_row(
        "SELECT EXISTS(SELECT 1 FROM pairings WHERE joiner_device=?1 AND state IN ('accepted','expired'))",
        [device], |row| row.get::<_, bool>(0),
    )?)
}

/// Collect a query before its statement or transaction is released. All storage
/// errors cross the same sanitized boundary, including binding and row decoding.
pub(crate) fn query_rows<T>(
    db: &Connection,
    sql: &str,
    params: &[&dyn ToSql],
    read: fn(&Row<'_>) -> rusqlite::Result<T>,
) -> Result<Vec<T>> {
    let mut query = db.prepare(sql)?;
    let rows = query.query_map(params, read)?;
    Ok(rows.collect::<std::result::Result<Vec<_>, _>>()?)
}

pub(crate) fn client_ip(peer: SocketAddr, headers: &HeaderMap) -> IpAddr {
    if peer.ip() == IpAddr::V4(Ipv4Addr::LOCALHOST) {
        if headers.get_all("cf-connecting-ip").iter().count() != 1 {
            return peer.ip();
        }
        if let Some(ip) = headers
            .get("cf-connecting-ip")
            .and_then(|h| h.to_str().ok())
            .and_then(|h| h.parse::<IpAddr>().ok())
        {
            return ip;
        }
    }
    peer.ip()
}

pub(crate) fn random_token(bytes: usize) -> String {
    let mut token = vec![0; bytes];
    OsRng.fill_bytes(&mut token);
    encode_b64(&token)
}

pub(crate) fn ulid(now: i64) -> String {
    let mut bytes = [0; 16];
    OsRng.fill_bytes(&mut bytes[6..]);
    bytes[..6].copy_from_slice(&(now.max(0) as u64 * 1000).to_be_bytes()[2..]);
    let mut value = u128::from_be_bytes(bytes);
    let mut text = [b'0'; 26];
    for ch in text.iter_mut().rev() {
        *ch = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ"[(value & 31) as usize];
        value >>= 5;
    }
    String::from_utf8(text.to_vec()).unwrap()
}

pub(crate) fn valid_id(id: &str) -> bool {
    id.len() == 26
        && id.as_bytes()[0] <= b'7'
        && id
            .bytes()
            .all(|ch| b"0123456789ABCDEFGHJKMNPQRSTVWXYZ".contains(&ch))
}

pub(crate) fn device(db: &Connection, id: &str) -> Result<(String, DeviceRecord)> {
    let row: Option<(String, Vec<u8>)> = db
        .query_row(
            "SELECT account_id, record FROM devices WHERE id=?1 AND revoked_at IS NULL",
            [id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    let (account, record) = row.ok_or_else(ApiError::not_found)?;
    Ok((account, from_json(&record)?))
}

pub(crate) fn validate_device(record: &DeviceRecord) -> Result<()> {
    if record.device_id.is_empty()
        || record.device_id.len() > 128
        || !record
            .device_id
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"_-".contains(&c))
        || record.label.len() > 256
        || record.caps.len() > 32
    {
        return Err(ApiError::bad());
    }
    p256_public_sec1(&record.dk_pub)?;
    let identity = kv_core::remote::keys::identity_verifying_jwk(record)?;
    for key in [&record.ak_q, &record.ak_s].into_iter().flatten() {
        match key.alg {
            SignatureAlgorithm::ES256 => {
                p256_public_sec1(&key.r#pub)?;
            }
            SignatureAlgorithm::RS256 => {
                rsa_public_key(&key.r#pub)?;
            }
        }
        if jcs(&key.r#pub)? == jcs(&record.dk_pub)? || jcs(&key.r#pub)? == jcs(identity)? {
            return Err(ApiError::bad());
        }
    }
    if record.ak_q.is_some() && record.ak_s.is_some() && record.ak_q == record.ak_s {
        return Err(ApiError::bad());
    }
    if (record.caps.contains(&Capability::ApproveStrong) && record.ak_s.is_none())
        || (record.caps.contains(&Capability::ApproveQuick) && record.ak_q.is_none())
    {
        return Err(ApiError::bad());
    }
    Ok(())
}

pub(crate) fn insert_device(
    db: &Connection,
    account: &str,
    record: &DeviceRecord,
    push: Option<&Value>,
    now: i64,
) -> Result<()> {
    let key =
        |key: &Option<kv_core::remote::ApprovalKey>| -> Result<(Option<String>, Option<String>)> {
            Ok(match key {
                Some(key) => (
                    Some(String::from_utf8(jcs(&key.r#pub)?).expect("canonical JSON is UTF-8")),
                    Some(
                        serde_json::to_value(key.alg)
                            .expect("signature algorithms have an infallible JSON representation")
                            .as_str()
                            .expect("a signature algorithm serializes as a string")
                            .into(),
                    ),
                ),
                None => (None, None),
            })
        };
    let (akq_pub, akq_alg) = key(&record.ak_q)?;
    let (aks_pub, aks_alg) = key(&record.ak_s)?;
    db.execute(
        "INSERT INTO devices(id,account_id,dk_pub,akq_pub,akq_alg,aks_pub,aks_alg,key_kind,
         attestation,os,caps,label,created_at,record,push_token) VALUES
         (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15)",
        params![
            record.device_id,
            account,
            String::from_utf8(jcs(&record.dk_pub)?).expect("canonical JSON is UTF-8"),
            akq_pub,
            akq_alg,
            aks_pub,
            aks_alg,
            record.key_kind.as_str(),
            record
                .attestation
                .as_ref()
                .map(|value| serde_json::to_vec(value).expect("JSON values serialize to bytes")),
            record.os.as_str(),
            serde_json::to_string(&record.caps).expect("capabilities serialize as strings"),
            record.label,
            now,
            serde_json::to_vec(record).expect("device records contain only JSON values"),
            push.map(|value| serde_json::to_vec(value).expect("JSON values serialize to bytes"))
        ],
    )?;
    Ok(())
}
