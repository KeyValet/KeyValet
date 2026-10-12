//! Durable metadata-only push dispatch. Ciphertext is never opened or inspected here.
use crate::error::{ApiError, Result};
use crate::state::State;
use kv_core::remote::{DeliveryMode, Envelope, EnvelopeType};
use reqwest::StatusCode;
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{sync::Arc, time::Duration};
use url::Url;
use zeroize::Zeroizing;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Hint {
    mode: DeliveryMode,
}

pub(crate) fn hint(envelope: &Envelope) -> Result<Option<DeliveryMode>> {
    let mode = envelope
        .extra
        .get("push")
        .map(|value| {
            serde_json::from_value::<Hint>(value.clone())
                .map(|hint| hint.mode)
                .map_err(|_| ApiError::bad())
        })
        .transpose()?;
    // PresenceHint is end-to-end encrypted. WS connectivity is not human presence.
    // The executor signs the delivery hint after applying §6.10; older requests
    // without that hint wake conservatively. Control-plane updates are silent.
    let mode = match (&envelope.r#type, mode) {
        (EnvelopeType::ApprovalRequest, mode) => mode.unwrap_or(DeliveryMode::Banner),
        (EnvelopeType::ApprovalEscalate, mode) => mode.unwrap_or(DeliveryMode::Banner),
        (
            EnvelopeType::ApprovalCancel
            | EnvelopeType::Directive
            | EnvelopeType::DirectiveResult
            | EnvelopeType::Grant
            | EnvelopeType::DeviceRevoke,
            mode,
        ) => mode.unwrap_or(DeliveryMode::Silent),
        (_, None) => return Ok(None),
        _ => return Err(ApiError::bad()),
    };
    match (&envelope.r#type, mode) {
        (EnvelopeType::ApprovalRequest, _)
        | (EnvelopeType::ApprovalEscalate, DeliveryMode::Banner)
        | (
            EnvelopeType::ApprovalCancel
            | EnvelopeType::Directive
            | EnvelopeType::DirectiveResult
            | EnvelopeType::Grant
            | EnvelopeType::DeviceRevoke,
            DeliveryMode::Silent,
        ) => Ok(Some(mode)),
        _ => Err(ApiError::bad()),
    }
}

pub(crate) fn enqueue(db: &Connection, envelope: &Envelope, now: i64) -> Result<()> {
    let Some(mode) = hint(envelope)? else {
        return Ok(());
    };
    let mode = match mode {
        DeliveryMode::Silent => "silent",
        DeliveryMode::Banner => "banner",
    };
    // The FK binds each job to the exact durable, outer-signature-verified envelope.
    db.execute(
        "INSERT OR IGNORE INTO push_jobs(account_id,id,to_device,type,mode,next_attempt,expires_at)
        SELECT ?1,?2,?3,?4,?5,0,MIN(?6,?7) FROM devices
        WHERE id=?3 AND revoked_at IS NULL AND os IN ('ios','android')",
        params![
            envelope.account,
            envelope.id,
            envelope.to,
            envelope.r#type.as_str(),
            mode,
            envelope.exp,
            now.saturating_add(120)
        ],
    )?;
    Ok(())
}

pub(crate) struct Transport {
    http: reqwest::Client,
    url: Url,
    bearer: Zeroizing<String>,
}

impl Transport {
    pub(crate) fn new(url: Url, bearer: String) -> std::io::Result<Arc<Self>> {
        if url.scheme() != "http"
            || url.host_str() != Some("127.0.0.1")
            || url.port_or_known_default() == Some(0)
            || url.path() != "/v1/push"
            || url.query().is_some()
            || url.fragment().is_some()
            || !url.username().is_empty()
            || url.password().is_some()
            || !(32..=256).contains(&bearer.len())
            || bearer.chars().any(char::is_control)
        {
            return Err(std::io::Error::other("invalid loopback push configuration"));
        }
        let http = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(28))
            .build()
            .map_err(|_| std::io::Error::other("cannot initialize push transport"))?;
        Ok(Arc::new(Self {
            http,
            url,
            bearer: Zeroizing::new(bearer),
        }))
    }

    pub(crate) fn from_env() -> std::io::Result<Option<Arc<Self>>> {
        let url = std::env::var("KEYVALET_PUSH_URL").ok();
        let file = std::env::var_os("KV_PUSH_RELAY_BEARER_FILE");
        match (url, file) {
            (None, None) => Ok(None),
            (Some(url), Some(file)) => {
                let bearer = Zeroizing::new(
                    std::fs::read_to_string(file)
                        .map_err(|_| std::io::Error::other("cannot read push relay credential"))?,
                );
                let url =
                    Url::parse(&url).map_err(|_| std::io::Error::other("invalid push URL"))?;
                Self::new(url, bearer.trim().to_owned()).map(Some)
            }
            _ => Err(std::io::Error::other(
                "configure both push URL and relay credential file",
            )),
        }
    }

    pub(crate) async fn drain(&self, state: &State) -> Result<PushStats> {
        let (jobs, mut stats) = state.with(lease)?;
        for job in jobs {
            stats.attempted += 1;
            let response = self
                .http
                .post(self.url.clone())
                .bearer_auth(self.bearer.as_str())
                .json(
                    &json!({"device_push_token":job.token,"approval_id":job.id,"to":job.to,
                    "delivery":{"mode":job.mode}}),
                )
                .send()
                .await;
            let status = response.as_ref().ok().map(|response| response.status());
            let retry_after = response
                .as_ref()
                .ok()
                .and_then(|response| response.headers().get("retry-after"))
                .and_then(|value| value.to_str().ok()?.parse::<i64>().ok())
                .unwrap_or(60)
                .clamp(60, 3600);
            state.with(|data, now| {
                match status {
                    Some(code) if code.is_success() => {
                        remove(&data.db, &job)?;
                        stats.sent += 1;
                    }
                    Some(StatusCode::GONE) => {
                        // A delayed invalid-token result must never erase a newer rotated token.
                        stats.tokens_removed += data.db.execute(
                            "UPDATE devices SET push_token=NULL WHERE id=?1 AND push_token=?2",
                            params![job.to, job.token_bytes],
                        )?;
                        remove(&data.db, &job)?;
                        stats.dropped += 1;
                    }
                    Some(code)
                        if code.is_client_error() && code != StatusCode::TOO_MANY_REQUESTS =>
                    {
                        remove(&data.db, &job)?;
                        stats.dropped += 1;
                    }
                    _ if now >= job.expires || job.attempts >= 4 => {
                        remove(&data.db, &job)?;
                        stats.dropped += 1;
                    }
                    _ => {
                        let delay = if status == Some(StatusCode::TOO_MANY_REQUESTS) {
                            retry_after
                        } else {
                            1_i64 << (job.attempts - 1)
                        };
                        data.db.execute(
                            "UPDATE push_jobs SET next_attempt=?1 WHERE account_id=?2
                            AND id=?3 AND to_device=?4 AND type=?5",
                            params![
                                now.saturating_add(delay),
                                job.account,
                                job.id,
                                job.to,
                                job.kind
                            ],
                        )?;
                        stats.retried += 1;
                    }
                }
                Ok(())
            })?;
        }
        state.event("push_sent", stats.sent);
        state.event("push_retry", stats.retried);
        state.event("push_dropped", stats.dropped);
        state.event("push_no_token", stats.skipped_no_token);
        state.event("push_ws_connected", stats.ws_connected);
        state.event("push_tokens_removed", stats.tokens_removed);
        Ok(stats)
    }
}

#[derive(Default, Debug, Serialize)]
pub struct PushStats {
    pub attempted: usize,
    pub sent: usize,
    pub retried: usize,
    pub dropped: usize,
    pub tokens_removed: usize,
    pub skipped_no_token: usize,
    pub ws_connected: usize,
}

struct Job {
    account: String,
    id: String,
    to: String,
    kind: String,
    mode: String,
    attempts: u32,
    expires: i64,
    token: Value,
    token_bytes: Vec<u8>,
}

/// Runs before expired account-session rows are deleted, and before every dispatch.
/// Device sessions are renewable; only losing the human session removes a mobile token.
pub(crate) fn cleanup_tokens(db: &Connection, now: i64, require_account: bool) -> Result<usize> {
    Ok(db.execute(
        "UPDATE devices SET push_token=NULL WHERE push_token IS NOT NULL AND
        (revoked_at IS NOT NULL OR (?2 AND os IN ('ios','android') AND NOT EXISTS
          (SELECT 1 FROM account_sessions s WHERE s.device_id=devices.id AND s.exp>?1)))",
        params![now, require_account],
    )?)
}

fn lease(data: &mut crate::state::Data, now: i64) -> Result<(Vec<Job>, PushStats)> {
    let mut stats = PushStats::default();
    let tx = data.db.transaction()?;
    stats.tokens_removed = cleanup_tokens(&tx, now, data.account_login_required)?;
    // Superseded requests must not wake a phone after the signed cancellation is queued.
    tx.execute("DELETE FROM push_jobs WHERE expires_at<?1 OR NOT EXISTS
        (SELECT 1 FROM devices d WHERE d.id=push_jobs.to_device AND d.revoked_at IS NULL)
        OR (type IN ('approval_request','approval_escalate') AND NOT EXISTS (SELECT 1 FROM approvals a
            WHERE a.account_id=push_jobs.account_id AND a.id=push_jobs.id AND a.state='waiting'))
        OR (type='approval_request' AND EXISTS (SELECT 1 FROM messages m
            WHERE m.account_id=push_jobs.account_id AND m.id=push_jobs.id
            AND m.to_device=push_jobs.to_device AND m.type='approval_escalate'))",[now])?;
    stats.skipped_no_token = tx.execute(
        "DELETE FROM push_jobs WHERE NOT EXISTS
        (SELECT 1 FROM devices d WHERE d.id=push_jobs.to_device AND d.push_token IS NOT NULL)",
        [],
    )?;
    let mut jobs = Vec::new();
    {
        let mut statement = tx.prepare("SELECT p.account_id,p.id,p.to_device,p.type,p.mode,p.attempts,p.expires_at,d.push_token
            FROM push_jobs p JOIN devices d ON d.id=p.to_device
            WHERE p.next_attempt<=?1 AND d.push_token IS NOT NULL
            ORDER BY p.next_attempt,p.id,p.type LIMIT 8")?;
        let rows = statement.query_map([now], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, u32>(5)?,
                row.get::<_, i64>(6)?,
                row.get::<_, Vec<u8>>(7)?,
            ))
        })?;
        for row in rows {
            let (account, id, to, kind, mode, attempts, expires, token_bytes) = row?;
            let token: Value = serde_json::from_slice(&token_bytes).map_err(|_| ApiError::bad())?;
            // Only the typed token and public delivery metadata cross the dispatcher boundary.
            stats.ws_connected += usize::from(data.presence.contains_key(&to));
            jobs.push(Job {
                account,
                id,
                to,
                kind,
                mode,
                attempts: attempts + 1,
                expires,
                token,
                token_bytes,
            });
        }
    }
    for job in &jobs {
        tx.execute(
            "UPDATE push_jobs SET attempts=attempts+1,next_attempt=?1 WHERE account_id=?2
            AND id=?3 AND to_device=?4 AND type=?5",
            params![now + 30, job.account, job.id, job.to, job.kind],
        )?;
    }
    tx.commit()?;
    Ok((jobs, stats))
}

fn remove(db: &Connection, job: &Job) -> Result<()> {
    db.execute(
        "DELETE FROM push_jobs WHERE account_id=?1 AND id=?2 AND to_device=?3 AND type=?4",
        params![job.account, job.id, job.to, job.kind],
    )?;
    Ok(())
}

#[cfg(test)]
#[path = "push_tests.rs"]
mod tests;
