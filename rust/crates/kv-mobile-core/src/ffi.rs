//! Versioned, synchronous C JSON ABI for native background workers. Never invoke on a UI thread.
use crate::{hardware::NativeKey, Error, MobileCore, MobileKeys, Relay, Result};
use kv_core::remote::{canonical::from_json, Os};
use serde::Deserialize;
use std::{
    ffi::{c_char, CStr, CString},
    path::Path,
    sync::{Arc, Mutex, OnceLock},
};

/// Slots: 0=DK, 1=AK_q, 2=AK_s. Operations: 0=SEC1 public (65), 1=ES256 raw (64), 2=ECDH x (32).
/// The native implementation must be process-lifetime and thread-safe. Strong signing MUST
/// be gated by the native key's ACL/CryptoObject, even when called outside Flutter.
pub type KvKeyCallback = unsafe extern "C" fn(u32, u32, *const u8, usize, *mut u8, usize) -> isize;
static INITIALIZATION: Mutex<()> = Mutex::new(());
static CORE: OnceLock<Arc<MobileCore>> = OnceLock::new();
static RELAY: OnceLock<Arc<Relay>> = OnceLock::new();
static RUNTIME: OnceLock<tokio::runtime::Runtime> = OnceLock::new();
pub(crate) fn core() -> Result<Arc<MobileCore>> {
    CORE.get().cloned().ok_or(Error("native_setup_required"))
}
pub(crate) fn relay() -> Result<Arc<Relay>> {
    RELAY.get().cloned().ok_or(Error("native_setup_required"))
}
fn runtime() -> Result<&'static tokio::runtime::Runtime> {
    if let Some(runtime) = RUNTIME.get() {
        return Ok(runtime);
    }
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .map_err(|_| Error("runtime_unavailable"))?;
    let _ = RUNTIME.set(runtime);
    RUNTIME.get().ok_or(Error("runtime_unavailable"))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Boot {
    directory: String,
    label: String,
    os: Os,
    key_kind: String,
}

/// # Safety
/// `config` is a valid NUL-terminated UTF-8 string (<=16 KiB). `callback` satisfies KvKeyCallback.
/// The returned string is owned by Rust and must be released once with kv_mobile_free.
#[no_mangle]
pub unsafe extern "C" fn kv_mobile_open(
    config: *const c_char,
    callback: Option<KvKeyCallback>,
) -> *mut c_char {
    guarded(|| {
        // SAFETY: validated non-null before reading; the remaining contract is the caller's.
        let _initialization = INITIALIZATION
            .lock()
            .map_err(|_| Error("native_setup_failed"))?;
        let config: Boot = from_json(unsafe { input(config, 16 * 1024)? }.as_bytes())?;
        let callback = callback.ok_or(Error("native_key_callback_missing"))?;
        if !matches!(config.os, Os::Ios | Os::Android) {
            return Err(Error("mobile_platform_required"));
        }
        if CORE.get().is_none() {
            let key = |slot| {
                Arc::new(NativeKey {
                    slot,
                    callback,
                    kind: config.key_kind.clone(),
                }) as crate::engine::Key
            };
            let core = Arc::new(MobileCore::open(
                Path::new(&config.directory),
                MobileKeys {
                    identity: key(0),
                    quick: key(1),
                    strong: key(2),
                },
                &config.label,
                config.os,
            )?);
            let relay = Relay::new(core.clone())?;
            core.require_account_login();
            CORE.set(core).map_err(|_| Error("already_initialized"))?;
            RELAY.set(relay).map_err(|_| Error("already_initialized"))?;
        }
        runtime()?;
        Ok(serde_json::json!({"ready":true,"abi":1}))
    })
}

#[derive(Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
enum NativeCommand {
    AccountStatus,
    Snapshot,
    Notifications,
    Sync,
    Diagnostics,
    PushToken { platform: String, token: String },
    QuickDecision { approval_id: String, allow: bool },
}

/// # Safety
/// `command` is a valid NUL-terminated UTF-8 string (<=16 KiB). Invoke from a native worker.
/// The returned JSON uses the same public Rust display types as flutter_rust_bridge.
#[no_mangle]
pub unsafe extern "C" fn kv_mobile_call(command: *const c_char) -> *mut c_char {
    guarded(|| {
        // SAFETY: the caller contract supplies a live C string; input rejects a null pointer.
        let command: NativeCommand = from_json(unsafe { input(command, 16 * 1024)? }.as_bytes())?;
        match command {
            NativeCommand::AccountStatus => Ok(serde_json::to_value(core()?.account_view()?)?),
            NativeCommand::PushToken { platform, token } => {
                if !matches!(platform.as_str(), "apns" | "fcm")
                    || token.is_empty()
                    || token.len() > 4096
                    || token.chars().any(char::is_control)
                {
                    return Err(Error("invalid_push_token"));
                }
                let core = core()?;
                core.store.transaction(|db| {
                    crate::Store::delete(db, "meta", "uploaded_push_token")?;
                    core.store.put(
                        db,
                        "meta",
                        "push_token",
                        &serde_json::json!({"platform":platform,"token":token}),
                        0,
                    )
                })?;
                // The encrypted token remains queued when signed out or offline.
                let relay = relay()?;
                let _ = runtime()?.block_on(relay.retry_logouts());
                let _ = runtime()?.block_on(relay.sync_push_token());
                Ok(serde_json::json!({"stored":true}))
            }
            NativeCommand::Snapshot => Ok(serde_json::to_value(core()?.snapshot()?)?),
            NativeCommand::Notifications => Ok(serde_json::to_value(core()?.notifications()?)?),
            NativeCommand::Diagnostics => Ok(core()?.diagnostic()?.into()),
            NativeCommand::Sync => Ok(serde_json::to_value(
                runtime()?.block_on(relay()?.sync_background())?,
            )?),
            NativeCommand::QuickDecision { approval_id, allow } => {
                core()?.decide(&approval_id, "per_use", allow, "", true)?;
                let _ = runtime()?.block_on(relay()?.flush());
                Ok(serde_json::json!({"queued":true}))
            }
        }
    })
}

/// # Safety
/// `pointer` is null or was returned by kv_mobile_open/kv_mobile_call and not previously freed.
#[no_mangle]
pub unsafe extern "C" fn kv_mobile_free(pointer: *mut c_char) {
    if !pointer.is_null() {
        // SAFETY: ownership is transferred back under the public ABI contract.
        drop(unsafe { CString::from_raw(pointer) });
    }
}

unsafe fn input<'a>(pointer: *const c_char, limit: usize) -> Result<&'a str> {
    if pointer.is_null() {
        return Err(Error("invalid_command"));
    }
    // SAFETY: the public ABI requires a readable NUL-terminated C string.
    let bytes = unsafe { CStr::from_ptr(pointer) }.to_bytes();
    if bytes.len() > limit {
        return Err(Error("command_too_large"));
    }
    std::str::from_utf8(bytes).map_err(|_| Error("invalid_command"))
}
fn guarded(f: impl FnOnce() -> Result<serde_json::Value>) -> *mut c_char {
    let value = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(f)) {
        Ok(Ok(value)) => serde_json::json!({"ok":true,"result":value}),
        Ok(Err(error)) => serde_json::json!({"ok":false,"error":error.0}),
        Err(_) => serde_json::json!({"ok":false,"error":"internal_error"}),
    };
    CString::new(value.to_string())
        .expect("JSON escapes NUL")
        .into_raw()
}
