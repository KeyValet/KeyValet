use crate::error::{ApiError, Result};
use crate::http::Wire;
use crate::messages::cancel_frames;
use crate::state::{
    client_ip, device, insert_device, query_rows, random_token, validate_device, Challenge,
    State as RelayState, SESSION_TTL,
};
use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::Argon2;
use axum::extract::{ConnectInfo, Path, State};
use axum::http::HeaderMap;
use axum::Json;
use kv_core::remote::canonical::{jcs, sha256_hex};
use kv_core::remote::keys::{decode_b64, verify_identity_signature, verify_signature};
use kv_core::remote::relay::*;
use kv_core::remote::{Capability, Extra, Optional};
use rand_core::OsRng;
use rusqlite::{params, OptionalExtension};
use std::net::SocketAddr;
use std::sync::Arc;
use zeroize::Zeroizing;

/// The CPU-bound password boundary is separate from account mutation so expiry
/// and revocation are checked again after expensive recovery verification.
pub(crate) trait RecoveryPasswords: Send + Sync {
    fn hash(&self, code: &str) -> Result<String>;
    fn verify(&self, code: &str, hash: &str) -> Result<()>;
}

pub(crate) struct ArgonPasswords;

impl RecoveryPasswords for ArgonPasswords {
    fn hash(&self, code: &str) -> Result<String> {
        Argon2::default()
            .hash_password(code.as_bytes(), &SaltString::generate(&mut OsRng))
            .map(|hash| hash.to_string())
            .map_err(ApiError::from)
    }

    fn verify(&self, code: &str, hash: &str) -> Result<()> {
        let hash = PasswordHash::new(hash).map_err(ApiError::from)?;
        Argon2::default()
            .verify_password(code.as_bytes(), &hash)
            .map_err(|_| ApiError::forbidden())
    }
}

async fn password_work<T: Send + 'static>(
    work: impl FnOnce() -> Result<T> + Send + 'static,
) -> Result<T> {
    match tokio::task::spawn_blocking(work).await {
        Ok(result) => result,
        Err(error) => Err(error.into()),
    }
}

pub(crate) async fn recover(
    State(state): State<Arc<RelayState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Wire(mut request): Wire<RecoverAccountRequest>,
) -> Result<Json<RecoverAccountResponse>> {
    let code = Zeroizing::new(std::mem::take(&mut request.recovery_code));
    let replacement = Zeroizing::new(std::mem::take(&mut request.new_recovery_code));
    if request.account_id.is_empty()
        || request.account_id.len() > 128
        || request.account_id.chars().any(char::is_control)
        || code.len() != 43
        || replacement.len() != 43
        || replacement == code
        || decode_b64(&replacement).map_or(true, |bytes| bytes.len() != 32)
        || decode_b64(&code).is_err()
        || decode_b64(&request.nonce).map_or(true, |bytes| bytes.len() != 32)
    {
        return Err(ApiError::bad());
    }
    validate_device(&request.device)?;
    // Human account login remains a separate requirement for managed mobile enrollment.
    if state.accounts.config.required && crate::account::is_mobile(&request.device) {
        return Err(ApiError::unauthorized());
    }
    let hash = state.with(|data, now| {
        data.rate(
            format!("recovery-ip:{}", client_ip(peer, &headers)),
            now,
            1,
            10,
        )?;
        data.rate(
            format!("recovery-account:{}", request.account_id),
            now,
            1,
            5,
        )?;
        data.rate("recovery-global".into(), now, 1, 60)?;
        data.db
            .query_row(
                "SELECT recovery_hash FROM accounts WHERE id=?1 AND recovery_hash<>''",
                [&request.account_id],
                |row| row.get::<_, String>(0),
            )
            .optional()?
            .ok_or_else(ApiError::forbidden)
    })?;
    let proof = jcs(&RecoverAccountProof {
        action: RecoverAccountAction::RecoverAccount,
        account_id: request.account_id.clone(),
        device: request.device.clone(),
        nonce: request.nonce,
        new_recovery_code_hash: sha256_hex(replacement.as_bytes()),
    })?;
    verify_identity_signature(&request.device, &proof, &decode_b64(&request.sig)?)
        .map_err(|_| ApiError::forbidden())?;
    let expected = hash.clone();
    let passwords = state.recovery.clone();
    let recovery_code = replacement.to_string();
    let next_hash = password_work(move || {
        passwords.verify(&code, &hash)?;
        passwords.hash(&replacement)
    })
    .await?;
    state.with(|data, now| {
        let tx = data.db.transaction()?;
        // Compare-and-swap after Argon work makes the code single-use, including concurrent calls.
        let changed = tx.execute(
            "UPDATE accounts SET recovery_hash=?1 WHERE id=?2 AND recovery_hash=?3",
            params![next_hash, request.account_id, expected],
        )?;
        if changed != 1 { return Err(ApiError::forbidden()); }
        let devices = query_rows(&tx, "SELECT id FROM devices WHERE account_id=?1",
            &[&request.account_id], |row| row.get::<_, String>(0))?;
        tx.execute("DELETE FROM sessions WHERE device_id IN (SELECT id FROM devices WHERE account_id=?1)", [&request.account_id])?;
        tx.execute("DELETE FROM account_sessions WHERE device_id IN (SELECT id FROM devices WHERE account_id=?1)", [&request.account_id])?;
        tx.execute("UPDATE devices SET revoked_at=COALESCE(revoked_at,?1),push_token=NULL WHERE account_id=?2", params![now,request.account_id])?;
        tx.execute("UPDATE approvals SET state='cancelled',resolved_at=?1 WHERE account_id=?2 AND state='waiting'", params![now,request.account_id])?;
        tx.execute("DELETE FROM messages WHERE account_id=?1", [&request.account_id])?;
        tx.execute("INSERT OR IGNORE INTO used_pair_tokens(token_hash,exp) SELECT token_hash,exp FROM pairings WHERE account_id=?1 AND token_hash IS NOT NULL", [&request.account_id])?;
        tx.execute("UPDATE pairings SET state='expired',token_hash=NULL WHERE account_id=?1", [&request.account_id])?;
        insert_device(&tx, &request.account_id, &request.device, None, now)?;
        tx.commit()?;
        for device in devices { data.invalidate_device(&device); }
        Ok(())
    })?;
    state.event("account_recovered", 1);
    Ok(Json(RecoverAccountResponse {
        ok: true,
        account_id: request.account_id,
        device_id: request.device.device_id,
        recovery_code,
    }))
}

pub(crate) async fn register(
    State(state): State<Arc<RelayState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Wire(request): Wire<RegisterDeviceRequest>,
) -> Result<Json<RegisterDeviceResponse>> {
    validate_device(&request.device)?;
    if state.accounts.config.required && crate::account::is_mobile(&request.device) {
        return Err(ApiError::unauthorized());
    }
    state.with(|data, now| {
        data.rate(
            format!("register:{}", client_ip(peer, &headers)),
            now,
            1,
            10,
        )
    })?;
    let code = Zeroizing::new(random_token(32));
    let recovery_code = code.to_string();
    let passwords = state.recovery.clone();
    let hash = password_work(move || passwords.hash(&code)).await?;
    let response = state.with(|data, now| {
        let account = format!("acct_{}", random_token(16));
        let tx = data.db.transaction()?;
        tx.execute(
            "INSERT INTO accounts(id,created_at,recovery_hash) VALUES(?1,?2,?3)",
            params![account, now, hash],
        )?;
        insert_device(
            &tx,
            &account,
            &request.device,
            request.push_token.as_value(),
            now,
        )?;
        tx.commit()?;
        Ok(RegisterDeviceResponse {
            account_id: account,
            device_id: request.device.device_id,
            recovery_code: Optional::Value(recovery_code),
            extra: Extra::new(),
        })
    })?;
    state.event("device_registered", 1);
    Ok(Json(response))
}

pub(crate) async fn challenge(
    State(state): State<Arc<RelayState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Wire(request): Wire<ChallengeRequest>,
) -> Result<Json<ChallengeResponse>> {
    let response = state.with(|data, now| {
        data.rate(format!("auth:{}", client_ip(peer, &headers)), now, 1, 60)?;
        let (_, record) =
            device(&data.db, &request.device_id).map_err(|_| ApiError::unauthorized())?;
        if data.account_login_required {
            crate::account::require_device_user(&data.db, &record, &headers, now)?;
        }
        data.challenges.retain(|_, challenge| challenge.exp >= now);
        let challenge = random_token(32);
        let exp = now + 60;
        data.challenges.insert(
            request.device_id,
            Challenge {
                hash: sha256_hex(challenge.as_bytes()),
                exp,
            },
        );
        Ok(ChallengeResponse {
            challenge,
            exp,
            extra: Extra::new(),
        })
    })?;
    Ok(Json(response))
}

pub(crate) async fn verify(
    State(state): State<Arc<RelayState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Wire(request): Wire<AuthVerifyRequest>,
) -> Result<Json<AuthVerifyResponse>> {
    let response = state.with(|data, now| {
        data.rate(format!("auth:{}", client_ip(peer, &headers)), now, 1, 60)?;
        let (account, record) =
            device(&data.db, &request.device_id).map_err(|_| ApiError::unauthorized())?;
        let user_session = if data.account_login_required {
            crate::account::require_device_user(&data.db, &record, &headers, now)?
        } else {
            None
        };
        check_challenge(data, &request.device_id, &request.challenge, now)?;
        let challenge = decode_b64(&request.challenge).map_err(|_| ApiError::unauthorized())?;
        if challenge.len() != 32 {
            return Err(ApiError::unauthorized());
        }
        verify_identity_signature(
            &record,
            &challenge,
            &decode_b64(&request.sig).map_err(|_| ApiError::unauthorized())?,
        )
        .map_err(|_| ApiError::unauthorized())?;
        let token = random_token(32);
        let exp = now + SESSION_TTL;
        let tx = data.db.transaction()?;
        tx.execute(
            "INSERT INTO sessions(token_hash,device_id,exp) VALUES(?1,?2,?3)",
            params![sha256_hex(token.as_bytes()), request.device_id, exp],
        )?;
        if let Some(user_session) = user_session {
            tx.execute(
                "INSERT INTO device_session_users(token_hash,account_session) VALUES(?1,?2)",
                params![sha256_hex(token.as_bytes()), user_session],
            )?;
        }
        tx.commit()?;
        data.challenges.remove(&request.device_id);
        Ok(AuthVerifyResponse {
            session_token: token,
            exp,
            extra: serde_json::json!({"account_id":account})
                .as_object()
                .unwrap()
                .clone(),
        })
    })?;
    Ok(Json(response))
}

pub(crate) fn check_challenge(
    data: &crate::state::Data,
    device: &str,
    value: &str,
    now: i64,
) -> Result<()> {
    let challenge = data
        .challenges
        .get(device)
        .ok_or_else(ApiError::unauthorized)?;
    if challenge.exp < now {
        return Err(ApiError::expired());
    }
    if challenge.hash != sha256_hex(value.as_bytes()) {
        return Err(ApiError::unauthorized());
    }
    Ok(())
}

pub(crate) async fn revoke(
    State(state): State<Arc<RelayState>>,
    Path(id): Path<String>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Wire(request): Wire<DeleteDeviceRequest>,
) -> Result<Json<OkResponse>> {
    let recovery_hash = state.with(|data, now| {
        let principal = data.authenticate(&headers, now)?;
        data.check(&principal, now, true)?;
        let (account, _) = device(&data.db, &id)?;
        if account != principal.account {
            return Err(ApiError::forbidden());
        }
        data.rate(format!("revoke:{}", client_ip(peer, &headers)), now, 1, 10)?;
        match request.by {
            DeleteDeviceBy::Recovery => Ok(Some(data.db.query_row(
                "SELECT recovery_hash FROM accounts WHERE id=?1",
                [&account],
                |row| row.get::<_, String>(0),
            )?)),
            DeleteDeviceBy::Device => {
                if !principal.device.caps.contains(&Capability::ApproveStrong) {
                    return Err(ApiError::forbidden());
                }
                let key = principal
                    .device
                    .ak_s
                    .as_ref()
                    .ok_or_else(ApiError::forbidden)?;
                let challenge = headers
                    .get(STRONG_CHALLENGE_HEADER)
                    .and_then(|h| h.to_str().ok())
                    .ok_or_else(ApiError::forbidden)?;
                check_challenge(data, &principal.device.device_id, challenge, now)?;
                let sig = headers
                    .get(STRONG_SIGNATURE_HEADER)
                    .and_then(|h| h.to_str().ok())
                    .ok_or_else(ApiError::forbidden)?;
                let payload = jcs(&DeviceDeleteProof {
                    action: DeviceDeleteAction::RevokeDevice,
                    account: account.clone(),
                    by: principal.device.device_id.clone(),
                    device_id: id.clone(),
                    challenge: challenge.into(),
                    extra: Extra::new(),
                })
                .expect("the revocation payload contains only strings");
                verify_signature(key.alg, &key.r#pub, &payload, &decode_b64(sig)?)
                    .map_err(|_| ApiError::forbidden())?;
                // Proof and mutation share one critical section. A failed SQL
                // transaction leaves the one-use challenge available for retry.
                revoke_device(data, &account, &id, now)?;
                data.challenges.remove(&principal.device.device_id);
                Ok(None)
            }
        }
    })?;
    if let Some(hash) = recovery_hash {
        let code = Zeroizing::new(
            request
                .recovery_code
                .as_value()
                .ok_or_else(ApiError::forbidden)?
                .clone(),
        );
        let passwords = state.recovery.clone();
        password_work(move || passwords.verify(&code, &hash)).await?;
        state.with(|data, now| {
            let principal = data.authenticate(&headers, now)?;
            data.check(&principal, now, true)?;
            let (account, _) = device(&data.db, &id)?;
            if account != principal.account {
                return Err(ApiError::forbidden());
            }
            revoke_device(data, &account, &id, now)
        })?;
    }
    state.event("device_revoked", 1);
    Ok(Json(OkResponse {
        ok: true,
        extra: Extra::new(),
    }))
}

fn revoke_device(data: &mut crate::state::Data, account: &str, id: &str, now: i64) -> Result<()> {
    let tx = data.db.transaction()?;
    let cancelled = query_rows(
        &tx,
        "SELECT id FROM approvals WHERE account_id=?1 AND requester=?2 AND state='waiting'",
        params![account, id],
        |row| row.get::<_, String>(0),
    )?;
    let mut notifications = Vec::new();
    for approval in cancelled {
        notifications.extend(cancel_frames(&tx, account, &approval, None)?);
    }
    tx.execute(
        "UPDATE devices SET revoked_at=?1 WHERE id=?2",
        params![now, id],
    )?;
    tx.execute("DELETE FROM sessions WHERE device_id=?1", [id])?;
    tx.execute("UPDATE approvals SET state='cancelled',resolved_at=?1 WHERE requester=?2 AND state='waiting'", params![now, id])?;
    tx.commit()?;
    data.invalidate_device(id);
    for (recipient, frame) in notifications {
        data.send(&recipient, frame);
    }
    Ok(())
}
