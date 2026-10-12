use crate::error::{ApiError, Result};
use crate::http::Wire;
use crate::state::{
    client_ip, device, insert_device, ulid, validate_device, State as RelayState, PAIR_TTL,
};
use axum::extract::{ConnectInfo, State};
use axum::http::HeaderMap;
use axum::Json;
use kv_core::remote::canonical::{from_json, sha256_hex};
use kv_core::remote::keys::{decode_b64, verify_object};
use kv_core::remote::relay::*;
use kv_core::remote::{Capability, DeviceRecord, Extra, Optional};
use rusqlite::{params, OptionalExtension};
use serde_json::json;
use std::net::SocketAddr;
use std::sync::Arc;

struct PairingState {
    account: String,
    initiator: String,
    joiner: Option<String>,
    status: String,
    exp: i64,
    initiator_finished: bool,
    joiner_finished: bool,
    sas_hash: Option<String>,
}

pub(crate) async fn start(
    State(state): State<Arc<RelayState>>,
    headers: HeaderMap,
    Wire(request): Wire<PairStartRequest>,
) -> Result<Json<PairStartResponse>> {
    let response = state.with(|data, now| {
        let principal = data.authenticate(&headers, now)?;
        data.check(&principal, now, true)?;
        data.rate(format!("pair:{}", principal.device.device_id), now, 1, 10)?;
        validate_device(&request.initiator)?;
        if !kv_core::remote::validation::same_device_authority(&request.initiator, &principal.device) || request.token_hash.len() != 64
            || !request.token_hash.bytes().all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c)) {
            return Err(ApiError::bad());
        }
        if request.exp <= now { return Err(ApiError::expired()); }
        if request.exp > now + PAIR_TTL { return Err(ApiError::bad()); }
        let pairing_id = ulid(now);
        let tx = data.db.transaction()?;
        let used: bool = tx.query_row("SELECT EXISTS(SELECT 1 FROM used_pair_tokens WHERE token_hash=?1)",
            [&request.token_hash], |row| row.get(0))?;
        if used { return Err(ApiError::conflict()); }
        let pending: i64 = tx.query_row("SELECT COUNT(*) FROM pairings WHERE account_id=?1 AND state IN ('offered','accepted') AND exp>=?2",
            params![principal.account, now], |row| row.get(0))?;
        if pending >= 10 { return Err(ApiError::rate_limited()); }
        tx.execute("INSERT INTO used_pair_tokens(token_hash,exp) VALUES(?1,?2)", params![request.token_hash, request.exp])?;
        tx.execute("INSERT INTO pairings(pairing_id,token_hash,account_id,initiator_device,initiator_pubs,state,exp)
            VALUES(?1,?2,?3,?4,?5,'offered',?6)", params![pairing_id, request.token_hash, principal.account,
            principal.device.device_id, serde_json::to_vec(&request.initiator).expect("device records contain only JSON values"), request.exp])?;
        tx.commit()?;
        Ok(PairStartResponse { pairing_id, extra: Extra::new() })
    })?;
    Ok(Json(response))
}

pub(crate) async fn complete(
    State(state): State<Arc<RelayState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Wire(request): Wire<PairCompleteRequest>,
) -> Result<Json<PairCompleteResponse>> {
    validate_device(&request.joiner)?;
    let token = decode_b64(&request.token)?;
    if token.len() != 16 {
        return Err(ApiError::bad());
    }
    let token_hash = sha256_hex(&token);
    let response = state.with(|data, now| {
        data.rate(format!("pair_complete:{}", client_ip(peer, &headers)), now, 1, 60)?;
        let row: Option<(String, String, Vec<u8>, String, i64)> = data.db.query_row(
            "SELECT pairing_id,account_id,initiator_pubs,state,exp FROM pairings WHERE token_hash=?1",
            [&token_hash], |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?,row.get(3)?,row.get(4)?)),
        ).optional()?;
        let (pairing_id, account, initiator, status, exp) = match row {
            Some(row) => row,
            None => {
                let used: Option<i64> = data.db.query_row("SELECT exp FROM used_pair_tokens WHERE token_hash=?1", [&token_hash], |row| row.get(0)).optional()?;
                return Err(match used {
                    Some(exp) if exp < now => ApiError::expired(),
                    Some(_) => ApiError::conflict(),
                    None => ApiError::not_found(),
                });
            }
        };
        if exp < now || status == "expired" { return Err(ApiError::expired()); }
        if status != "offered" { return Err(ApiError::conflict()); }
        let initiator: DeviceRecord = from_json(&initiator)?;
        let (initiator_account, _) = device(&data.db, &initiator.device_id)?;
        if initiator_account != account || request.joiner.device_id == initiator.device_id { return Err(ApiError::forbidden()); }
        let exists: bool = data.db.query_row("SELECT EXISTS(SELECT 1 FROM devices WHERE id=?1)", [&request.joiner.device_id], |row| row.get(0))?;
        if data.account_login_required && crate::account::is_mobile(&request.joiner) && !exists { return Err(ApiError::unauthorized()); }
        let previous = if exists {
            // A pre-registered singleton may join only with proof of its own DK session.
            let joiner = data.authenticate(&headers, now)?;
            data.check(&joiner, now, true)?;
            if !kv_core::remote::validation::same_device_authority(&joiner.device, &request.joiner) || joiner.account == account { return Err(ApiError::forbidden()); }
            let siblings: i64 = data.db.query_row("SELECT COUNT(*) FROM devices WHERE account_id=?1", [&joiner.account], |row| row.get(0))?;
            let history: i64 = data.db.query_row("SELECT (SELECT COUNT(*) FROM messages WHERE account_id=?1) +
                (SELECT COUNT(*) FROM pairings WHERE account_id=?1) + (SELECT COUNT(*) FROM approvals WHERE account_id=?1)", [&joiner.account], |row| row.get(0))?;
            if siblings != 1 || history != 0 { return Err(ApiError::conflict()); }
            Some(joiner.account)
        } else { None };
        let tx = data.db.transaction()?;
        if let Some(owner) = crate::account::device_owner(&tx, &request.joiner.device_id)? {
            if crate::account::account_owner(&tx,&account)?.is_some_and(|existing| existing != owner) { return Err(ApiError::forbidden()); }
        } else if data.account_login_required && crate::account::is_mobile(&request.joiner) { return Err(ApiError::unauthorized()); }
        if let Some(previous) = previous {
            tx.execute("UPDATE devices SET account_id=?1 WHERE id=?2", params![account, request.joiner.device_id])?;
            tx.execute("DELETE FROM sessions WHERE device_id=?1", [&request.joiner.device_id])?;
            tx.execute("DELETE FROM accounts WHERE id=?1", [&previous])?;
        } else {
            insert_device(&tx, &account, &request.joiner, None, now)?;
        }
        tx.execute("UPDATE pairings SET joiner_pubs=?1,joiner_device=?2,state='accepted' WHERE pairing_id=?3",
            params![serde_json::to_vec(&request.joiner).expect("device records contain only JSON values"), request.joiner.device_id, pairing_id])?;
        tx.commit()?;
        data.invalidate_device(&request.joiner.device_id);
        // Relay metadata is deliberately distinct from a device-signed E2E Envelope.
        data.send(&initiator.device_id, json!({"t":"pair_accept", "pairing_id":pairing_id, "joiner":request.joiner}));
        // The joiner needs the account routing id before it can send its first envelope.
        Ok(PairCompleteResponse { pairing_id, initiator,
            account_id: Optional::Value(account), extra: json!({"expires_at":exp}).as_object().unwrap().clone() })
    })?;
    Ok(Json(response))
}

pub(crate) async fn finish(
    State(state): State<Arc<RelayState>>,
    headers: HeaderMap,
    Wire(request): Wire<PairFinishRequest>,
) -> Result<Json<OkResponse>> {
    state.with(|data, now| {
        let principal = data.authenticate(&headers, now)?;
        data.check(&principal, now, false)?;
        let row: Option<PairingState> = data.db.query_row(
            "SELECT account_id,initiator_device,joiner_device,state,exp,initiator_finished,joiner_finished,sas_hash
             FROM pairings WHERE pairing_id=?1", [&request.pairing_id],
            |row| Ok(PairingState { account: row.get(0)?, initiator: row.get(1)?, joiner: row.get(2)?,
                status: row.get(3)?, exp: row.get(4)?, initiator_finished: row.get(5)?,
                joiner_finished: row.get(6)?, sas_hash: row.get(7)? }),
        ).optional()?;
        let PairingState { account, initiator, joiner, status, exp, initiator_finished, joiner_finished, sas_hash } = row.ok_or_else(ApiError::not_found)?;
        if account != principal.account { return Err(ApiError::forbidden()); }
        if exp < now || status == "expired" { return Err(ApiError::expired()); }
        if status != "accepted" && status != "finished" { return Err(ApiError::conflict()); }
        let joiner = joiner.ok_or_else(ApiError::conflict)?;
        let is_initiator = principal.device.device_id == initiator;
        if !is_initiator && joiner != principal.device.device_id { return Err(ApiError::forbidden()); }
        if request.confirm.sas.len() != 6 || !request.confirm.sas.bytes().all(|b| b.is_ascii_digit()) { return Err(ApiError::bad()); }
        if principal.device.caps.contains(&Capability::ApproveStrong) {
            let key = principal.device.ak_s.as_ref().ok_or_else(ApiError::forbidden)?;
            verify_object(&request.confirm, &request.confirm.sig, key).map_err(|_| ApiError::forbidden())?;
        } else if !principal.device.caps.contains(&Capability::Execute) || !request.confirm.sig.is_empty() {
            return Err(ApiError::forbidden());
        }
        let hash = sha256_hex(request.confirm.sas.as_bytes());
        // A lost HTTP response must not strand a cryptographically confirmed device.
        // Membership and the Strong proof were checked above; retries cannot change the SAS.
        if (is_initiator && initiator_finished) || (!is_initiator && joiner_finished) {
            return if sas_hash.as_deref()==Some(hash.as_str()) {Ok(())} else {Err(ApiError::conflict())};
        }
        if status=="finished" {return Err(ApiError::conflict());}
        if sas_hash.is_some_and(|expected| expected != hash) {
            // A six-digit SAS is safe only with one attempt. A valid, mismatched
            // confirmation permanently aborts this pairing and its pending membership.
            let tx = data.db.transaction()?;
            tx.execute("UPDATE pairings SET state='expired',token_hash=NULL WHERE pairing_id=?1", [&request.pairing_id])?;
            tx.execute("UPDATE devices SET revoked_at=?1 WHERE id=?2", params![now, joiner])?;
            tx.execute("DELETE FROM sessions WHERE device_id=?1", [&joiner])?;
            tx.commit()?;
            data.invalidate_device(&joiner);
            return Err(ApiError::conflict());
        }
        let done = if is_initiator { joiner_finished } else { initiator_finished };
        let tx=data.db.transaction()?;
        if let Some(owner)=crate::account::device_owner(&tx,&joiner)? {
            if crate::account::account_owner(&tx,&account)?.is_some_and(|existing|existing!=owner) { return Err(ApiError::forbidden()); }
            // Scanning a code never claims an executor. Both SAS confirmations must commit.
            if done { tx.execute("INSERT OR IGNORE INTO account_owners(account_id,user_id) VALUES(?1,?2)",params![account,owner])?; }
        }
        tx.execute("UPDATE pairings SET initiator_finished=?1,joiner_finished=?2,sas_hash=?3,
            state=?4,token_hash=CASE WHEN ?4='finished' THEN NULL ELSE token_hash END WHERE pairing_id=?5",
            params![initiator_finished || is_initiator, joiner_finished || !is_initiator, hash,
                if done { "finished" } else { "accepted" }, request.pairing_id])?;
        tx.commit()?;
        Ok(())
    })?;
    state.event("pair_confirmed", 1);
    Ok(Json(OkResponse {
        ok: true,
        extra: Extra::new(),
    }))
}
