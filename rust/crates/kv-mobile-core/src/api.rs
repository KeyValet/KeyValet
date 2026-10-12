//! flutter_rust_bridge scans only this module and display types; protocol objects stay private.
use crate::{
    ffi,
    view::{AccountView, GrantInput, PairingView, SignInOptions, Snapshot},
    Error, Result,
};
use kv_core::remote::{DirectiveOp, Extra};

pub async fn snapshot() -> std::result::Result<Snapshot, String> {
    ffi::core()
        .and_then(|core| core.snapshot())
        .map_err(|e| e.to_string())
}
pub async fn start_foreground() -> std::result::Result<(), String> {
    ffi::core()
        .and_then(|core| core.ensure_login())
        .map_err(|e| e.to_string())?;
    let relay = ffi::relay().map_err(|e| e.to_string())?;
    relay.start();
    Ok(())
}
pub async fn stop_foreground() -> std::result::Result<(), String> {
    ffi::relay().map_err(|e| e.to_string())?.stop();
    Ok(())
}
pub async fn begin_pair(uri: String) -> std::result::Result<PairingView, String> {
    ffi::relay()
        .map_err(|e| e.to_string())?
        .begin_pair(&uri)
        .await
        .map_err(|e| e.to_string())
}
pub async fn confirm_pair(sas: String, exclude_global: bool) -> std::result::Result<(), String> {
    ffi::relay()
        .map_err(|e| e.to_string())?
        .confirm_pair(&sas, exclude_global)
        .await
        .map_err(|e| e.to_string())
}
pub async fn decide(
    id: String,
    scope: String,
    allow: bool,
    reason: String,
) -> std::result::Result<(), String> {
    let core = ffi::core().map_err(|e| e.to_string())?;
    core.decide(&id, &scope, allow, &reason, false)
        .map_err(|e| e.to_string())?;
    // Signing commits the durable outbox. Offline delivery is a queued state, not a denial.
    let _ = ffi::relay().map_err(|e| e.to_string())?.flush().await;
    Ok(())
}
pub async fn issue_grant(input: GrantInput) -> std::result::Result<(), String> {
    ffi::core()
        .map_err(|e| e.to_string())?
        .issue_grant(&input)
        .map_err(|e| e.to_string())?;
    let _ = ffi::relay().map_err(|e| e.to_string())?.flush().await;
    Ok(())
}
pub async fn directive(
    device_id: String,
    op: String,
    value: String,
    confirmation: String,
) -> std::result::Result<(), String> {
    if op == "revoke_device" {
        return ffi::relay()
            .map_err(|e| e.to_string())?
            .revoke_device(&device_id, &confirmation)
            .await
            .map_err(|e| e.to_string());
    }
    let (op, args) = directive_args(&op, &value).map_err(|e| e.to_string())?;
    ffi::core()
        .map_err(|e| e.to_string())?
        .directive(&device_id, op, args, &confirmation)
        .map_err(|e| e.to_string())?;
    let _ = ffi::relay().map_err(|e| e.to_string())?.flush().await;
    Ok(())
}
pub async fn preferences(
    away: bool,
    notifications: bool,
    locale: String,
) -> std::result::Result<(), String> {
    ffi::core()
        .and_then(|core| core.set_preferences(away, notifications, &locale))
        .map_err(|e| e.to_string())
}
pub async fn account_status() -> std::result::Result<AccountView, String> {
    ffi::core()
        .and_then(|core| core.account_view())
        .map_err(|e| e.to_string())
}
pub async fn restore_account() -> std::result::Result<AccountView, String> {
    ffi::relay()
        .map_err(|e| e.to_string())?
        .account_restore()
        .await
        .map_err(|e| e.to_string())
}
pub async fn begin_sign_in(provider: String) -> std::result::Result<SignInOptions, String> {
    ffi::relay()
        .map_err(|e| e.to_string())?
        .account_begin(&provider)
        .await
        .map_err(|e| e.to_string())
}
pub async fn complete_sign_in(
    attempt_id: String,
    identity_token: String,
    returned_state: String,
    display_name: String,
) -> std::result::Result<AccountView, String> {
    ffi::relay()
        .map_err(|e| e.to_string())?
        .account_finish(&attempt_id, &identity_token, &returned_state, &display_name)
        .await
        .map_err(|e| e.to_string())
}
pub async fn sign_out() -> std::result::Result<(), String> {
    ffi::relay()
        .map_err(|e| e.to_string())?
        .account_logout()
        .await
        .map_err(|e| e.to_string())
}
pub async fn diagnostics() -> std::result::Result<String, String> {
    ffi::core()
        .and_then(|core| core.diagnostic())
        .map_err(|e| e.to_string())
}

pub(crate) fn directive_args(op: &str, value: &str) -> Result<(DirectiveOp, Extra)> {
    let op: DirectiveOp =
        serde_json::from_value(op.into()).map_err(|_| Error("invalid_directive"))?;
    let args = match op {
        DirectiveOp::SetMode => serde_json::json!({"mode":value}),
        DirectiveOp::RevokeGrant => serde_json::json!({"jti":value}),
        DirectiveOp::CancelApproval => serde_json::json!({"approval_id":value}),
        DirectiveOp::RevokeDevice => serde_json::json!({"device_id":value}),
        DirectiveOp::SetDeviceLabel => serde_json::json!({"label":value}),
        DirectiveOp::Notify => serde_json::json!({"policy":value}),
        DirectiveOp::SetUnlockTtl => {
            serde_json::json!({"seconds":value.parse::<u64>().map_err(|_|Error("invalid_directive"))?})
        }
        DirectiveOp::QueryAudit => serde_json::json!({"since":crate::now()-86400,"limit":100}),
        DirectiveOp::SetClass => return Err(Error("advanced_settings_read_only")),
        _ => serde_json::json!({}),
    };
    Ok((
        op,
        args.as_object().ok_or(Error("invalid_directive"))?.clone(),
    ))
}
