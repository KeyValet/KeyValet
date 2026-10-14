use super::canonical::CanonicalRequest;
use super::keys::verify_object;
use super::*;
use std::collections::BTreeMap;

pub fn same_device_authority(a: &DeviceRecord, b: &DeviceRecord) -> bool {
    let mut candidate = b.clone();
    candidate.label.clone_from(&a.label);
    *a == candidate
}

pub trait NonceStore {
    /// Atomically inserts a nonce, returning Replay on conflict.
    fn consume(&mut self, nonce: &str, digest: &str, exp: Timestamp) -> Result<()>;
}

/// A revocation is monotonic and authorizes only its exact device/account pair.
/// Its Strong proof is shared with relay deletion; a DK signature alone is insufficient.
pub fn verify_device_revoke(
    value: &DeviceRevoke,
    sender: &DeviceRecord,
    account: &str,
) -> Result<()> {
    let proof: super::relay::DeviceDeleteProof = serde_json::from_value(
        value
            .extra
            .get("proof")
            .cloned()
            .ok_or(RemoteError::InvalidDirective)?,
    )
    .map_err(|_| RemoteError::InvalidDirective)?;
    if proof.device_id != value.device_id
        || proof.by != sender.device_id
        || proof.account != account
        || super::keys::decode_b64(&proof.challenge)?.len() != 32
    {
        return Err(RemoteError::InvalidDirective);
    }
    let sig = value
        .extra
        .get("sig")
        .and_then(serde_json::Value::as_str)
        .ok_or(RemoteError::InvalidDirective)?;
    verify_object(&proof, sig, approval_key(sender, ApprovalLevel::Strong)?)
}

pub fn approval_key(device: &DeviceRecord, level: ApprovalLevel) -> Result<&ApprovalKey> {
    let (key, capability) = match level {
        ApprovalLevel::Quick => (&device.ak_q, Capability::ApproveQuick),
        ApprovalLevel::Strong => (&device.ak_s, Capability::ApproveStrong),
    };
    if !device.caps.contains(&capability) {
        return Err(RemoteError::UnsupportedAuthority);
    }
    key.as_ref().ok_or(RemoteError::InvalidKey)
}

/// The helper checks pending state, pairing and revocation before calling this verifier.
pub fn verify_decision(
    decision: &ApprovalDecision,
    request: &ApprovalRequest,
    canonical: &CanonicalRequest,
    device: &DeviceRecord,
    now: Timestamp,
) -> Result<()> {
    if request.exp < now {
        return Err(RemoteError::Expired);
    }
    if decision.approval_id != request.approval_id {
        return Err(RemoteError::NotWaiting);
    }
    if canonical.digest()? != request.digest || decision.digest != request.digest {
        return Err(RemoteError::DigestMismatch);
    }
    if decision.nonce != request.nonce || canonical.nonce != request.nonce {
        return Err(RemoteError::NonceMismatch);
    }
    if canonical.exp != request.exp
        || canonical.kind != request.kind
        || canonical.requester != request.requester.device_id
    {
        return Err(RemoteError::DigestMismatch);
    }
    let required = if request.kind != ApprovalKind::Use
        || request.tier == Tier::T2
        || decision.scope.mode == ScopeMode::Standing
    {
        ApprovalLevel::Strong
    } else {
        request.min_level
    };
    if decision.level < required {
        return Err(RemoteError::InsufficientLevel);
    }
    if decision.approver_kind != ApproverKind::Device || decision.quorum.as_value().is_some() {
        return Err(RemoteError::UnsupportedAuthority);
    }
    if decision.approver != device.device_id {
        return Err(RemoteError::WrongSender);
    }
    verify_object(
        decision,
        &decision.sig,
        approval_key(device, decision.level)?,
    )?;
    validate_scope(decision, request)
}

pub fn verify_and_consume_decision(
    decision: &ApprovalDecision,
    request: &ApprovalRequest,
    canonical: &CanonicalRequest,
    device: &DeviceRecord,
    now: Timestamp,
    nonces: &mut impl NonceStore,
) -> Result<()> {
    verify_decision(decision, request, canonical, device, now)?;
    nonces.consume(&decision.nonce, &decision.digest, request.exp)
}

fn validate_scope(decision: &ApprovalDecision, request: &ApprovalRequest) -> Result<()> {
    if request.tier == Tier::T2 && decision.scope.mode != ScopeMode::PerUse {
        return Err(RemoteError::InvalidScope);
    }
    let option = match decision.scope.mode {
        ScopeMode::PerUse => ScopeOption::PerUse,
        ScopeMode::PerCredential if decision.scope.level == DecisionScopeLevel::Credential => {
            ScopeOption::PerCredential
        }
        ScopeMode::PerSession => ScopeOption::PerSession,
        ScopeMode::Remember if decision.scope.level == DecisionScopeLevel::Credential => {
            // CONTRACT: A.2–A.3 / §7.6: remember bounds use issued_at and an exact offered duration.
            match decision.scope.until.checked_sub(decision.issued_at) {
                Some(3600) => ScopeOption::Remember1h,
                Some(28800) => ScopeOption::Remember8h,
                Some(86400) => ScopeOption::Remember24h,
                _ => return Err(RemoteError::InvalidScope),
            }
        }
        ScopeMode::Standing => match decision.scope.level {
            DecisionScopeLevel::Credential => ScopeOption::StandingCredential,
            DecisionScopeLevel::Device => ScopeOption::StandingDevice,
        },
        _ => return Err(RemoteError::InvalidScope),
    };
    if !request.scope_options.contains(&option) {
        return Err(RemoteError::InvalidScope);
    }
    Ok(())
}

pub fn verify_grant(
    grant: &Grant,
    audience: &str,
    audience_label: &str,
    device: &DeviceRecord,
    level: ApprovalLevel,
    now: Timestamp,
) -> Result<()> {
    if grant.iss_kind != IssuerKind::Device {
        return Err(RemoteError::UnsupportedAuthority);
    }
    if grant.iss != device.device_id {
        return Err(RemoteError::WrongSender);
    }
    let key = approval_key(device, level)?;
    if grant.iss_alg != key.alg {
        return Err(RemoteError::UnsupportedAlgorithm);
    }
    verify_object(grant, &grant.sig, key)?;
    if grant.aud != audience && grant.aud != "*" {
        return Err(RemoteError::WrongRecipient);
    }
    if grant.nbf > now || grant.exp.is_some_and(|exp| exp < now) {
        return Err(RemoteError::Expired);
    }
    if grant.scope.level == GrantScopeLevel::Global && grant.aud != "*" {
        return Err(RemoteError::InvalidGrant);
    }
    if grant.scope.level == GrantScopeLevel::Credential
        && grant
            .scope
            .credential
            .as_value()
            .is_none_or(String::is_empty)
    {
        return Err(RemoteError::InvalidGrant);
    }
    if (grant.exp.is_none() || grant.scope.max_tier == Tier::T2 || grant.origin == "settings")
        && level != ApprovalLevel::Strong
    {
        return Err(RemoteError::InsufficientLevel);
    }
    // K4: every T2 grant binds one current executor label, including finite grants.
    if grant.scope.max_tier == Tier::T2
        && (grant.origin != "settings"
            || grant.aud == "*"
            || grant.scope.level == GrantScopeLevel::Global
            || grant.confirm.as_value().map(String::as_str) != Some(audience_label))
    {
        return Err(RemoteError::InvalidGrant);
    }
    Ok(())
}

pub fn grant_allows_tier(grant: &Grant, tier: Tier) -> bool {
    tier <= grant.scope.max_tier
}

#[derive(Debug, Clone, Default)]
pub struct DirectiveState {
    pub mode: Option<String>,
    pub unlock_ttl_s: Option<u64>,
    pub classes: BTreeMap<String, (serde_json::Value, u64)>,
}

pub fn directive_required_level(
    directive: &Directive,
    current: &DirectiveState,
) -> Result<ApprovalLevel> {
    let args = &directive.args;
    let invalid = || RemoteError::InvalidDirective;
    let text = |field: &str| {
        args.get(field)
            .and_then(serde_json::Value::as_str)
            .ok_or_else(invalid)
    };
    let integer = |field: &str| {
        args.get(field)
            .and_then(serde_json::Value::as_u64)
            .ok_or_else(invalid)
    };
    Ok(match directive.op {
        DirectiveOp::SetMode => {
            let next = mode_rank(text("mode")?)?;
            let previous = mode_rank(current.mode.as_deref().ok_or(RemoteError::MissingState)?)?;
            if next < previous {
                ApprovalLevel::Strong
            } else {
                ApprovalLevel::Quick
            }
        }
        DirectiveOp::SetUnlockTtl => {
            let next = integer("seconds")?;
            if next == 0 || next > 86400 {
                return Err(invalid());
            }
            if next > current.unlock_ttl_s.ok_or(RemoteError::MissingState)? {
                ApprovalLevel::Strong
            } else {
                ApprovalLevel::Quick
            }
        }
        DirectiveOp::SetClass => {
            let name = text("name")?;
            let exp = integer("exp_s")?;
            if exp == 0 || exp > 86400 {
                return Err(invalid());
            }
            let next_match = args
                .get("match")
                .filter(|value| value.is_object())
                .ok_or_else(invalid)?;
            match current.classes.get(name) {
                Some((previous_match, previous_exp))
                    if previous_match == next_match && exp <= *previous_exp =>
                {
                    ApprovalLevel::Quick
                }
                _ => ApprovalLevel::Strong,
            }
        }
        DirectiveOp::SetDeviceLabel => {
            if text("label")?.is_empty() {
                return Err(invalid());
            }
            // CONTRACT: §3.2 / A.5: renaming a trusted device is an admin change.
            ApprovalLevel::Strong
        }
        DirectiveOp::RevokeDevice => {
            text("device_id")?;
            ApprovalLevel::Strong
        }
        DirectiveOp::RevokeGrant => {
            text("jti")?;
            ApprovalLevel::Quick
        }
        DirectiveOp::CancelApproval => {
            text("approval_id")?;
            ApprovalLevel::Quick
        }
        DirectiveOp::Notify => {
            if !matches!(text("policy")?, "prefer-local" | "always-phone" | "both") {
                return Err(invalid());
            }
            // CONTRACT: §6.10.6 / A.5: notification policy changes only delivery, never authority.
            ApprovalLevel::Quick
        }
        DirectiveOp::QueryAudit => {
            args.get("since")
                .and_then(serde_json::Value::as_i64)
                .ok_or_else(invalid)?;
            if integer("limit")? > 200 {
                return Err(invalid());
            }
            for name in ["after", "through"] {
                if args
                    .get(name)
                    .is_some_and(|value| value.as_u64().is_none_or(|n| n > 9_007_199_254_740_991))
                {
                    return Err(invalid());
                }
            }
            ApprovalLevel::Quick
        }
        DirectiveOp::RevokeAllGrants
        | DirectiveOp::Lock
        | DirectiveOp::QueryStatus
        | DirectiveOp::QueryPending
        | DirectiveOp::QueryGrants => ApprovalLevel::Quick,
    })
}

// CONTRACT: §7.5 / A.5: remember:Nh, integer hours; zero means standing as in existing settings.
fn mode_rank(mode: &str) -> Result<(u8, u64)> {
    Ok(match mode {
        "per_use" => (3, 0),
        "per_credential" => (2, 0),
        "per_session" => (1, 0),
        _ => {
            let hours = mode
                .strip_prefix("remember:")
                .and_then(|value| value.strip_suffix('h'))
                .and_then(|value| value.parse::<u64>().ok())
                .ok_or(RemoteError::InvalidDirective)?;
            (0, if hours == 0 { 0 } else { u64::MAX - hours })
        }
    })
}

pub fn verify_directive(
    directive: &Directive,
    audience: &str,
    device: &DeviceRecord,
    level: ApprovalLevel,
    now: Timestamp,
    current: &DirectiveState,
) -> Result<()> {
    // CONTRACT: §7.5 / A.5: signing level is out-of-band; helper supplies the verified key selection.
    if directive.iss_kind != IssuerKind::Device {
        return Err(RemoteError::UnsupportedAuthority);
    }
    if directive.iss != device.device_id {
        return Err(RemoteError::WrongSender);
    }
    let key = approval_key(device, level)?;
    if directive.iss_alg != key.alg {
        return Err(RemoteError::UnsupportedAlgorithm);
    }
    verify_object(directive, &directive.sig, key)?;
    if directive.aud != audience && directive.aud != "*" {
        return Err(RemoteError::WrongRecipient);
    }
    if directive.exp < now {
        return Err(RemoteError::Expired);
    }
    if level < directive_required_level(directive, current)? {
        return Err(RemoteError::InsufficientLevel);
    }
    Ok(())
}
