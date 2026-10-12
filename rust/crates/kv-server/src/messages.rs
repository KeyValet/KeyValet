use crate::error::{ApiError, Result};
use crate::http::Wire;
use crate::state::{
    device, device_ready, query_rows, valid_id, Data, Principal, State as RelayState, MAX_PENDING,
};
use axum::extract::{OriginalUri, Path, State};
use axum::http::HeaderMap;
use axum::Json;
use kv_core::remote::canonical::{from_json, MAX_SAFE_INTEGER};
use kv_core::remote::envelope::MAX_ENVELOPE_BYTES;
use kv_core::remote::keys::{decode_b64, parse_sec1, verify_identity_signature};
use kv_core::remote::relay::*;
use kv_core::remote::{Envelope, EnvelopeType, Extra};
use rusqlite::{params, Connection, OptionalExtension};
use serde_json::{json, Value};
use std::collections::HashSet;
use std::sync::Arc;

fn validate(db: &Connection, principal: &Principal, envelope: &Envelope, now: i64) -> Result<()> {
    if serde_json::to_vec(envelope)
        .expect("envelopes contain only JSON values")
        .len()
        > MAX_ENVELOPE_BYTES
    {
        return Err(ApiError::too_large());
    }
    if !valid_id(&envelope.id)
        || envelope.created_at.unsigned_abs() > MAX_SAFE_INTEGER
        || envelope.exp.unsigned_abs() > MAX_SAFE_INTEGER
        || envelope.exp < envelope.created_at
    {
        return Err(ApiError::bad());
    }
    if envelope.exp < now {
        return Err(ApiError::expired());
    }
    if envelope.from != principal.device.device_id || envelope.account != principal.account {
        return Err(ApiError::forbidden());
    }
    let (recipient_account, _) = device(db, &envelope.to)?;
    if recipient_account != principal.account {
        return Err(ApiError::forbidden());
    }
    parse_sec1(&decode_b64(&envelope.enc)?)?;
    // kv-core decodes ciphertext only to verify its outer signature. It is never opened or parsed.
    verify_identity_signature(
        &principal.device,
        &envelope.signature_payload()?,
        &decode_b64(&envelope.sig)?,
    )?;
    crate::push::hint(envelope)?;
    Ok(())
}

#[cfg(test)]
#[path = "unit_tests/messages.rs"]
mod tests;

fn existing(db: &Connection, envelope: &Envelope) -> Result<bool> {
    let previous: Option<Vec<u8>> = db.query_row(
        "SELECT envelope FROM messages WHERE account_id=?1 AND id=?2 AND to_device=?3 AND type=?4",
        params![envelope.account, envelope.id, envelope.to, envelope.r#type.as_str()], |row| row.get(0),
    ).optional()?;
    match previous {
        None => Ok(false),
        Some(previous) if from_json::<Envelope>(&previous)? == *envelope => Ok(true),
        Some(_) => Err(ApiError::conflict()),
    }
}

fn insert(db: &Connection, envelope: &Envelope, now: i64) -> Result<bool> {
    if existing(db, envelope)? {
        return Ok(false);
    }
    db.execute(
        "INSERT INTO messages(id,account_id,from_device,to_device,type,envelope,created_at,exp)
        VALUES(?1,?2,?3,?4,?5,?6,?7,?8)",
        params![
            envelope.id,
            envelope.account,
            envelope.from,
            envelope.to,
            envelope.r#type.as_str(),
            serde_json::to_vec(envelope).expect("envelopes contain only JSON values"),
            envelope.created_at,
            envelope.exp
        ],
    )?;
    crate::push::enqueue(db, envelope, now)?;
    Ok(true)
}

fn pending(db: &Connection, account: &str, now: i64) -> Result<i64> {
    Ok(db.query_row(
        "SELECT
        (SELECT COUNT(*) FROM approvals WHERE account_id=?1 AND state='waiting' AND exp>=?2) +
        (SELECT COUNT(*) FROM messages WHERE account_id=?1 AND acked_at IS NULL AND exp>=?2
            AND type NOT IN ('approval_request','approval_escalate'))",
        params![account, now],
        |row| row.get(0),
    )?)
}

fn approval_type(kind: &EnvelopeType) -> bool {
    matches!(
        kind,
        EnvelopeType::ApprovalRequest
            | EnvelopeType::ApprovalEscalate
            | EnvelopeType::ApprovalDecision
            | EnvelopeType::ApprovalCancel
    )
}

fn pairing_type(kind: &EnvelopeType) -> bool {
    matches!(
        kind,
        EnvelopeType::PairOffer | EnvelopeType::PairAccept | EnvelopeType::PairConfirm
    )
}

pub(crate) fn send_messages(
    data: &mut Data,
    principal: &Principal,
    envelopes: &[Envelope],
    now: i64,
) -> Result<()> {
    data.check(principal, now, false)?;
    let ready = data.ready(&principal.device.device_id)?;
    if envelopes.is_empty() {
        return Err(ApiError::bad());
    }
    if envelopes.len() > MAX_PENDING as usize {
        return Err(ApiError::rate_limited());
    }
    data.rate(
        format!("messages:{}", principal.device.device_id),
        now,
        envelopes.len() as u32,
        600,
    )?;
    let tx = data.db.transaction()?;
    let mut fresh = Vec::new();
    for envelope in envelopes {
        if approval_type(&envelope.r#type) {
            return Err(ApiError::bad());
        }
        validate(&tx, principal, envelope, now)?;
        // Pending joiners may exchange only pairing ciphertext with their exact partner.
        let restricted = !device_ready(&tx, &envelope.to)?;
        if !ready || restricted {
            let partner: bool = tx.query_row("SELECT EXISTS(SELECT 1 FROM pairings WHERE state='accepted'
                AND exp>=?3 AND ((initiator_device=?1 AND joiner_device=?2) OR (initiator_device=?2 AND joiner_device=?1)))",
                params![envelope.from, envelope.to, now], |row| row.get(0))?;
            if !pairing_type(&envelope.r#type) || !partner {
                return Err(ApiError::forbidden());
            }
        }
        if insert(&tx, envelope, now)? {
            fresh.push(envelope);
        }
    }
    if pending(&tx, &principal.account, now)? > MAX_PENDING {
        return Err(ApiError::rate_limited());
    }
    tx.commit()?;
    for envelope in fresh {
        data.deliver(envelope, now);
    }
    Ok(())
}

pub(crate) async fn messages(
    State(state): State<Arc<RelayState>>,
    headers: HeaderMap,
    Wire(request): Wire<SendMessagesRequest>,
) -> Result<Json<AcceptedResponse>> {
    state.with(|data, now| {
        let principal = data.authenticate(&headers, now)?;
        send_messages(data, &principal, &request.envelopes, now)
    })?;
    state.event("messages_accepted", request.envelopes.len());
    Ok(Json(AcceptedResponse {
        accepted: request.envelopes.len() as u64,
        extra: Extra::new(),
    }))
}

pub(crate) async fn submit(
    State(state): State<Arc<RelayState>>,
    headers: HeaderMap,
    Wire(request): Wire<SubmitApprovalsRequest>,
) -> Result<Json<AcceptedResponse>> {
    state.with(|data, now| {
        let principal = data.authenticate(&headers, now)?;
        data.check(&principal, now, true)?;
        if request.exp < now { return Err(ApiError::expired()); }
        if request.envelopes.is_empty() || !valid_id(&request.id) { return Err(ApiError::bad()); }
        if request.envelopes.len() > MAX_PENDING as usize { return Err(ApiError::rate_limited()); }
        data.rate(format!("approvals:{}", principal.device.device_id), now, 1, 60)?;
        let tx = data.db.transaction()?;
        let mut recipients = HashSet::new();
        let kind = &request.envelopes[0].r#type;
        if !matches!(kind, EnvelopeType::ApprovalRequest | EnvelopeType::ApprovalEscalate) { return Err(ApiError::bad()); }
        for envelope in &request.envelopes {
            if envelope.v != 1 || envelope.id != request.id || envelope.exp != request.exp
                || &envelope.r#type != kind || !recipients.insert(&envelope.to) { return Err(ApiError::bad()); }
            validate(&tx, &principal, envelope, now)?;
            let ready = device_ready(&tx, &envelope.to)?;
            if !ready { return Err(ApiError::forbidden()); }
        }
        let prior: Option<(String, String, i64)> = tx.query_row(
            "SELECT requester,state,exp FROM approvals WHERE account_id=?1 AND id=?2",
            params![principal.account, request.id], |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?))).optional()?;
        let mut fresh = Vec::new();
        for envelope in &request.envelopes {
            if !existing(&tx, envelope)? { fresh.push(envelope); }
        }
        if let Some((requester, status, exp)) = &prior {
            if requester != &principal.device.device_id || *exp != request.exp { return Err(ApiError::forbidden()); }
            if status != "waiting" && !fresh.is_empty() { return Err(ApiError::conflict()); }
        }
        if *kind == EnvelopeType::ApprovalRequest && prior.is_none() {
            tx.execute("INSERT INTO approvals(id,account_id,requester,state,exp) VALUES(?1,?2,?3,'waiting',?4)",
                params![request.id, principal.account, principal.device.device_id, request.exp])?;
        } else if *kind == EnvelopeType::ApprovalEscalate {
            if prior.is_none() { return Err(ApiError::not_found()); }
            for envelope in &request.envelopes {
                if !is_recipient(&tx, &principal.account, &request.id, &envelope.to)? { return Err(ApiError::forbidden()); }
            }
        }
        for envelope in &fresh { insert(&tx, envelope, now)?; }
        if pending(&tx, &principal.account, now)? > MAX_PENDING { return Err(ApiError::rate_limited()); }
        tx.commit()?;
        for envelope in fresh { data.deliver(envelope, now); }
        Ok(())
    })?;
    state.event("approval_accepted", request.envelopes.len());
    Ok(Json(AcceptedResponse {
        accepted: request.envelopes.len() as u64,
        extra: Extra::new(),
    }))
}

fn get_approval(db: &Connection, account: &str, id: &str, now: i64) -> Result<(String, i64)> {
    let row: Option<(String, String, i64)> = db
        .query_row(
            "SELECT requester,state,exp FROM approvals WHERE account_id=?1 AND id=?2",
            params![account, id],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()?;
    let (requester, status, exp) = row.ok_or_else(ApiError::not_found)?;
    if exp < now || status == "expired" {
        return Err(ApiError::expired());
    }
    if status != "waiting" {
        return Err(ApiError::conflict());
    }
    Ok((requester, exp))
}

fn is_recipient(db: &Connection, account: &str, id: &str, device: &str) -> Result<bool> {
    Ok(db.query_row("SELECT EXISTS(SELECT 1 FROM messages WHERE account_id=?1 AND id=?2 AND to_device=?3 AND type='approval_request')",
        params![account, id, device], |row| row.get(0))?)
}

pub(crate) fn cancel_frames(
    db: &Connection,
    account: &str,
    id: &str,
    except: Option<&str>,
) -> Result<Vec<(String, Value)>> {
    let recipients = query_rows(db, "SELECT DISTINCT to_device FROM messages WHERE account_id=?1 AND id=?2 AND type='approval_request'",
        params![account, id], |row| row.get::<_, String>(0))?;
    Ok(recipients
        .into_iter()
        .filter(|device| Some(device.as_str()) != except)
        .map(|device| (device, json!({"t":"approval_cancel", "id":id})))
        .collect())
}

pub(crate) async fn reply(
    State(state): State<Arc<RelayState>>,
    Path(id): Path<String>,
    headers: HeaderMap,
    Wire(request): Wire<ReplyApprovalRequest>,
) -> Result<Json<OkResponse>> {
    state.with(|data, now| {
        let principal = data.authenticate(&headers, now)?;
        data.check(&principal, now, true)?;
        data.rate(format!("messages:{}", principal.device.device_id), now, 1, 600)?;
        let tx = data.db.transaction()?;
        let envelope = &request.envelope;
        if envelope.v != 1 || envelope.id != id || envelope.r#type != EnvelopeType::ApprovalDecision { return Err(ApiError::bad()); }
        validate(&tx, &principal, envelope, now)?;
        if existing(&tx, envelope)? { return Ok(()); }
        let (requester, exp) = get_approval(&tx, &principal.account, &id, now)?;
        if !is_recipient(&tx, &principal.account, &id, &principal.device.device_id)? { return Err(ApiError::forbidden()); }
        if envelope.v != 1 || envelope.id != id || envelope.to != requester || envelope.exp > exp
            || envelope.r#type != EnvelopeType::ApprovalDecision { return Err(ApiError::bad()); }
        validate(&tx, &principal, envelope, now)?;
        insert(&tx, envelope, now)?;
        tx.execute("UPDATE approvals SET state='resolved',resolved_by=?1,resolved_at=?2 WHERE account_id=?3 AND id=?4 AND state='waiting'",
            params![principal.device.device_id, now, principal.account, id])?;
        let cancellations = cancel_frames(&tx, &principal.account, &id, Some(&principal.device.device_id))?;
        tx.commit()?;
        data.deliver(envelope, now);
        for (device, frame) in cancellations { data.send(&device, frame); }
        Ok(())
    })?;
    state.event("approval_resolved", 1);
    Ok(Json(OkResponse {
        ok: true,
        extra: Extra::new(),
    }))
}

pub(crate) async fn cancel(
    State(state): State<Arc<RelayState>>,
    Path(id): Path<String>,
    headers: HeaderMap,
    Wire(request): Wire<Value>,
) -> Result<Json<OkResponse>> {
    let object = request.as_object().ok_or_else(ApiError::bad)?;
    if object.keys().any(|key| key != "envelope") {
        return Err(ApiError::bad());
    }
    let envelope = object
        .get("envelope")
        .map(|value| {
            from_json::<Envelope>(
                &serde_json::to_vec(value).expect("request contains only JSON values"),
            )
        })
        .transpose()?;
    state.with(|data, now| {
        let principal = data.authenticate(&headers, now)?;
        data.check(&principal, now, true)?;
        let tx = data.db.transaction()?;
        let (requester, status, exp): (String,String,i64) = tx.query_row(
            "SELECT requester,state,exp FROM approvals WHERE account_id=?1 AND id=?2",
            params![principal.account,id], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?))).optional()?.ok_or_else(ApiError::not_found)?;
        if requester != principal.device.device_id {
            return Err(ApiError::forbidden());
        }
        let fresh = if let Some(envelope) = &envelope {
            if envelope.v != 1 || envelope.id != id || envelope.r#type != EnvelopeType::ApprovalCancel
                || !is_recipient(&tx,&principal.account,&id,&envelope.to)? { return Err(ApiError::bad()); }
            validate(&tx,&principal,envelope,now)?;
            insert(&tx,envelope,now)?
        } else {
            if exp < now || status == "expired" { return Err(ApiError::expired()); }
            if status == "resolved" { return Err(ApiError::conflict()); }
            false
        };
        let cancellations = cancel_frames(&tx, &principal.account, &id, None)?;
        tx.execute(
            "UPDATE approvals SET state='cancelled',resolved_at=?1 WHERE account_id=?2 AND id=?3 AND state='waiting'",
            params![now, principal.account, id],
        )?;
        tx.commit()?;
        if fresh { data.deliver(envelope.as_ref().expect("only signed cancellation inserts"), now); }
        for (device, frame) in cancellations {
            data.send(&device, frame);
        }
        Ok(())
    })?;
    Ok(Json(OkResponse {
        ok: true,
        extra: Extra::new(),
    }))
}

pub(crate) async fn waiting(
    State(state): State<Arc<RelayState>>,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
) -> Result<Json<EnvelopesResponse>> {
    let query: Vec<_> =
        url::form_urlencoded::parse(uri.query().unwrap_or_default().as_bytes()).collect();
    if query.len() != 1 || query[0].0 != "state" || query[0].1 != "waiting" {
        return Err(ApiError::bad());
    }
    let envelopes = state.with(|data, now| {
        let principal = data.authenticate(&headers, now)?;
        data.check(&principal, now, true)?;
        let envelopes = {
            let blobs = query_rows(&data.db, "SELECT m.envelope FROM messages m JOIN approvals a ON a.id=m.id AND a.account_id=m.account_id
                WHERE m.to_device=?1 AND m.account_id=?2 AND a.state='waiting' AND a.exp>=?3 AND m.exp>=?3
                AND m.type IN ('approval_request','approval_escalate') ORDER BY m.created_at,m.id,m.type",
                params![principal.device.device_id, principal.account, now], |row| row.get::<_, Vec<u8>>(0))?;
            blobs.iter().map(|blob| from_json::<Envelope>(blob).map_err(ApiError::from)).collect::<Result<Vec<_>>>()?
        };
        for envelope in &envelopes {
            data.db.execute("UPDATE messages SET delivered_at=COALESCE(delivered_at,?1) WHERE account_id=?2 AND id=?3 AND to_device=?4 AND type=?5",
                params![now, envelope.account, envelope.id, envelope.to, envelope.r#type.as_str()])?;
        }
        Ok(envelopes)
    })?;
    Ok(Json(EnvelopesResponse {
        envelopes,
        extra: Extra::new(),
    }))
}

pub(crate) fn acknowledge(
    data: &mut Data,
    principal: &Principal,
    ids: &[String],
    kind: Option<&str>,
    now: i64,
) -> Result<()> {
    data.check(principal, now, false)?;
    if ids.len() > 500 || ids.iter().any(|id| !valid_id(id)) {
        return Err(ApiError::bad());
    }
    let tx = data.db.transaction()?;
    for id in ids {
        let count = tx.execute("UPDATE messages SET delivered_at=COALESCE(delivered_at,?1),acked_at=COALESCE(acked_at,?1)
            WHERE account_id=?2 AND id=?3 AND to_device=?4 AND (?5 IS NULL OR type=?5)",
            params![now, principal.account, id, principal.device.device_id,kind])?;
        if count == 0 {
            return Err(ApiError::not_found());
        }
    }
    tx.commit()?;
    Ok(())
}

pub(crate) async fn ack(
    State(state): State<Arc<RelayState>>,
    headers: HeaderMap,
    Wire(request): Wire<AckMessagesRequest>,
) -> Result<Json<OkResponse>> {
    state.with(|data, now| {
        let principal = data.authenticate(&headers, now)?;
        let kind = match &request.kind {
            kv_core::remote::Optional::Missing => None,
            kv_core::remote::Optional::Value(kind) => Some(kind.as_str()),
            kv_core::remote::Optional::Null => return Err(ApiError::bad()),
        };
        acknowledge(data, &principal, &request.ids, kind, now)
    })?;
    Ok(Json(OkResponse {
        ok: true,
        extra: Extra::new(),
    }))
}
