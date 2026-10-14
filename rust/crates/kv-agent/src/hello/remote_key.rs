use super::{buffer_bytes, delete, public_key, wait};
use crate::hello_logic::{Budget, CreationGuard, Reply};
use kv_platform::device_key::agent::{encode_reply, validate_metadata, MAX_SIGN_PAYLOAD};
use kv_platform::device_key::{decode_b64, encode_b64, DeviceKeyError, KeyRole, Result};
use rsa::traits::PublicKeyParts;
use serde_json::{json, Value};
use windows::core::HSTRING;
use windows::Security::Credentials::{
    KeyCredential, KeyCredentialCreationOption, KeyCredentialManager, KeyCredentialStatus,
};
use windows::Security::Cryptography::CryptographicBuffer;

#[cfg(test)]
std::thread_local! {
    static SIGN_STATUS: std::cell::Cell<Option<i32>> = const { std::cell::Cell::new(None) };
}

fn jwk(key: &KeyCredential) -> Result<Value> {
    let der = public_key(key).map_err(|_| DeviceKeyError::InvalidKey)?;
    let public = crate::hello_crypto::public_key(&der).map_err(|_| DeviceKeyError::InvalidKey)?;
    Ok(
        json!({"kty":"RSA","n":encode_b64(&public.n().to_bytes_be()),"e":encode_b64(&public.e().to_bytes_be())}),
    )
}
fn create(budget: &Budget) -> Result<Value> {
    let id: [u8; 16] = rand::random();
    let name = format!(
        "keyvalet.remote.strong.{}",
        id.iter().map(|b| format!("{b:02x}")).collect::<String>()
    );
    let result = KeyCredentialManager::RequestCreateAsync(
        &HSTRING::from(&name),
        KeyCredentialCreationOption::FailIfExists,
    )
    .and_then(|op| wait(op, budget))
    .map_err(|_| DeviceKeyError::Unavailable)?;
    if result
        .Status()
        .map_err(|_| DeviceKeyError::OperationFailed)?
        != KeyCredentialStatus::Success
    {
        return Err(DeviceKeyError::OperationFailed);
    }
    let cleanup = CreationGuard::new(|| {
        let _ = delete(&name);
    });
    let key = result
        .Credential()
        .map_err(|_| DeviceKeyError::OperationFailed)?;
    let metadata = json!({"version":1,"role":"strong","key_kind":"windows_hello","key_name":name,"public_jwk":jwk(&key)?});
    validate_metadata(&metadata, KeyRole::Strong)?;
    cleanup.commit();
    Ok(metadata)
}
fn sign(metadata: &Value, data: &[u8], budget: &Budget) -> Result<Vec<u8>> {
    #[cfg(test)]
    SIGN_STATUS.with(|status| status.set(None));
    validate_metadata(metadata, KeyRole::Strong)?;
    if data.len() > MAX_SIGN_PAYLOAD {
        return Err(DeviceKeyError::OperationFailed);
    }
    let result = KeyCredentialManager::OpenAsync(&HSTRING::from(
        metadata["key_name"]
            .as_str()
            .ok_or(DeviceKeyError::InvalidKey)?,
    ))
    .and_then(|op| wait(op, budget))
    .map_err(|_| DeviceKeyError::Unavailable)?;
    if result
        .Status()
        .map_err(|_| DeviceKeyError::OperationFailed)?
        != KeyCredentialStatus::Success
    {
        return Err(DeviceKeyError::Unavailable);
    }
    let key = result
        .Credential()
        .map_err(|_| DeviceKeyError::OperationFailed)?;
    if jwk(&key)? != metadata["public_jwk"] {
        return Err(DeviceKeyError::InvalidKey);
    }
    // CONTRACT: §3.1: Hello hashes the message and signs RS256; do not prehash or reuse the vault challenge.
    let input = CryptographicBuffer::CreateFromByteArray(data)
        .map_err(|_| DeviceKeyError::OperationFailed)?;
    let operation = key.RequestSignAsync(&input).map_err(|error| {
        #[cfg(test)]
        eprintln!("HELLO_SIGN submit_hresult={:08x}", error.code().0 as u32);
        #[cfg(not(test))]
        let _ = error;
        DeviceKeyError::OperationFailed
    })?;
    let result = wait(operation, budget).map_err(|error| {
        #[cfg(test)]
        eprintln!("HELLO_SIGN wait_hresult={:08x}", error.code().0 as u32);
        #[cfg(not(test))]
        let _ = error;
        DeviceKeyError::OperationFailed
    })?;
    let status = result
        .Status()
        .map_err(|_| DeviceKeyError::OperationFailed)?;
    #[cfg(test)]
    {
        SIGN_STATUS.with(|observed| observed.set(Some(status.0)));
        eprintln!("HELLO_SIGN result_status={}", status.0);
    }
    if status != KeyCredentialStatus::Success {
        return Err(DeviceKeyError::OperationFailed);
    }
    let signature = buffer_bytes(
        &result
            .Result()
            .map_err(|_| DeviceKeyError::OperationFailed)?,
    )
    .map_err(|_| DeviceKeyError::OperationFailed)?;
    if signature.len() != 256 {
        return Err(DeviceKeyError::OperationFailed);
    }
    crate::hello_crypto::verify(
        &public_key(&key).map_err(|_| DeviceKeyError::InvalidKey)?,
        data,
        &signature,
    )
    .map_err(|_| DeviceKeyError::OperationFailed)?;
    Ok(signature)
}
fn execute(request: &Value) -> Result<zeroize::Zeroizing<Vec<u8>>> {
    if request["role"] != "strong" {
        return Err(DeviceKeyError::InvalidKey);
    }
    let budget = Budget::new();
    if !KeyCredentialManager::IsSupportedAsync()
        .and_then(|op| wait(op, &budget))
        .map_err(|_| DeviceKeyError::Unavailable)?
    {
        return Err(DeviceKeyError::Unavailable);
    }
    match request["operation"].as_str() {
        Some("create") => {
            if request.get("metadata").is_some_and(|v| !v.is_null())
                || request.get("data").is_some_and(|v| v != "")
            {
                return Err(DeviceKeyError::InvalidKey);
            }
            let metadata = create(&budget)?;
            encode_reply(&[], &metadata)
        }
        Some("sign") => {
            let data = decode_b64(request["data"].as_str().ok_or(DeviceKeyError::InvalidKey)?)?;
            let signature = sign(&request["metadata"], &data, &budget)?;
            encode_reply(&signature, &request["metadata"])
        }
        _ => Err(DeviceKeyError::UnsupportedAlgorithm),
    }
}
pub(super) fn handle(request: &Value) -> Reply {
    let id = request["id"].as_u64().unwrap_or(0);
    if request["operation"] == "capabilities" {
        return (
            kv_ipc::agent::reply(
                id,
                &[
                    ("ok", json!(true)),
                    (
                        "device_key_protocol",
                        json!(kv_platform::device_key::agent::DEVICE_KEY_PROTOCOL),
                    ),
                ],
            ),
            None,
            None,
        );
    }
    match execute(request) {
        Ok(bytes) => {
            let mut payload =
                zeroize::Zeroizing::new([0u8; kv_ipc::agent::MAX_ENCLAVE_PAYLOAD + 1]);
            let length = bytes.len();
            payload[..length].copy_from_slice(&bytes);
            (
                kv_ipc::agent::reply(id, &[("ok", json!(true)), ("len", json!(length))]),
                Some((payload, length)),
                None,
            )
        }
        Err(error) => crate::hello_logic::deny(id, error.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    /// Run as the unelevated vault owner on Windows 11 with Hello configured:
    /// CARGO_TARGET_DIR=target-w1 cargo test -p kv-agent remote_hello_roundtrip -- --ignored
    #[test]
    #[ignore = "Requires Windows Hello and an interactive PIN/biometric prompt"]
    fn remote_hello_roundtrip() {
        unsafe {
            windows::Win32::System::WinRT::RoInitialize(
                windows::Win32::System::WinRT::RO_INIT_MULTITHREADED,
            )
            .unwrap();
        }
        let _apartment = CreationGuard::new(|| unsafe {
            windows::Win32::System::WinRT::RoUninitialize();
        });
        let metadata = create(&Budget::new()).unwrap();
        let name = metadata["key_name"].as_str().unwrap().to_owned();
        let _cleanup = CreationGuard::new(|| {
            let _ = delete(&name);
        });
        assert_eq!(
            sign(&metadata, b"KeyValet remote approval test", &Budget::new())
                .unwrap()
                .len(),
            256
        );
    }

    /// Copy the kv-agent binary test executable to the owner desktop and set
    /// R3B_STRONG_EXCHANGE to an isolated directory shared with the SYSTEM PCP fixture.
    /// The operator approves creation/Strong/repeat, then explicitly cancels the gated sign.
    #[test]
    #[ignore = "Requires owner desktop Windows Hello, a concurrent SYSTEM fixture and explicit cancellation"]
    fn remote_hello_t2_software_executor() {
        use kv_agent::remote::{
            native::NativeDialog, windows::WinUi, ApprovalFlow, ApprovalView, Dialog,
            DisplayContext, Platform,
        };
        use kv_core::remote::{self, canonical};
        use std::time::{Duration, Instant};

        let directory = std::path::PathBuf::from(
            std::env::var_os("R3B_STRONG_EXCHANGE").expect("explicit fixture directory required"),
        );
        let output = std::path::PathBuf::from(
            std::env::var_os("R3B_STRONG_OUTPUT")
                .expect("explicit owner output directory required"),
        );
        let _failure_signal = CreationGuard::new(|| {
            let reply = output.join("owner-result.json");
            if !reply.exists() {
                // Release the SYSTEM fixture's PCP guards promptly if any owner assertion fails.
                let _ = std::fs::write(reply, b"{\"cancelled\":false,\"owner_failed\":true}");
            }
        });
        let started = Instant::now();
        let publish = |name: &str, value: &Value| {
            std::fs::write(
                output.join(format!("{name}.tmp")),
                canonical::jcs(value).unwrap(),
            )
            .unwrap();
            std::fs::rename(
                output.join(format!("{name}.tmp")),
                output.join(format!("{name}.json")),
            )
            .unwrap();
        };
        let progress = |stage: &str| {
            publish(
                "owner-progress",
                &json!({"stage":stage,"elapsed_ms":started.elapsed().as_secs_f64()*1000.0}),
            )
        };
        let staged = std::env::var("R3B_STRONG_STAGE_GATES").as_deref() == Ok("1");
        let stage_gate = |name: &str| {
            while !directory
                .join(format!("continue-{name}"))
                .try_exists()
                .unwrap()
            {
                assert!(started.elapsed() < Duration::from_secs(800));
                std::thread::sleep(Duration::from_millis(100));
            }
        };
        while !directory.join("input.json").try_exists().unwrap() {
            assert!(
                started.elapsed() < Duration::from_secs(60),
                "SYSTEM fixture did not start"
            );
            std::thread::sleep(Duration::from_millis(100));
        }
        let input = std::fs::read(directory.join("input.json")).unwrap();
        assert!(input.len() <= 64 * 1024);
        let input: Value = canonical::from_json(&input).unwrap();
        let request: remote::ApprovalRequest =
            serde_json::from_value(input["request"].clone()).unwrap();
        assert_eq!(request.tier, remote::Tier::T2);
        unsafe {
            windows::Win32::System::WinRT::RoInitialize(
                windows::Win32::System::WinRT::RO_INIT_MULTITHREADED,
            )
            .unwrap()
        };
        let _uninitialize =
            CreationGuard::new(|| unsafe { windows::Win32::System::WinRT::RoUninitialize() });
        let timer = Instant::now();
        let supported = KeyCredentialManager::IsSupportedAsync()
            .and_then(|op| wait(op, &Budget::new()))
            .unwrap();
        assert!(supported);
        let support_ms = timer.elapsed().as_secs_f64() * 1000.0;
        publish(
            "owner-support-result",
            &json!({"supported":supported,"milliseconds":support_ms}),
        );
        progress("creating_ak_s");
        let timer = Instant::now();
        let metadata = create(&Budget::new()).unwrap();
        let create_ms = timer.elapsed().as_secs_f64() * 1000.0;
        let name = metadata["key_name"].as_str().unwrap().to_owned();
        let cleanup = CreationGuard::new(|| {
            let _ = delete(&name);
        });
        // Public alias/JWK ledger permits precise cleanup after a console/task interruption.
        publish("owner-key-metadata", &metadata);
        publish(
            "owner-create-result",
            &json!({"alg":"RS256","milliseconds":create_ms}),
        );
        let mut record: remote::DeviceRecord =
            serde_json::from_value(input["device"].clone()).unwrap();
        record.ak_s = Some(remote::ApprovalKey {
            r#pub: serde_json::from_value(metadata["public_jwk"].clone()).unwrap(),
            alg: remote::SignatureAlgorithm::RS256,
            extra: remote::Extra::new(),
        });
        record.caps.push(remote::Capability::ApproveStrong);
        progress("t2_approval_dialog");
        let timer = Instant::now();
        let view = ApprovalView::new(
            &input["request"],
            DisplayContext {
                now: kv_agent::remote::view::unix_seconds(),
                ..Default::default()
            },
            Platform::Windows,
        )
        .unwrap();
        let selection = NativeDialog::new(WinUi).approval(&view).unwrap();
        let params =
            ApprovalFlow::decision_params(&view, selection, kv_agent::remote::view::unix_seconds())
                .unwrap();
        assert_eq!(params["decision"], "allow");
        assert_eq!(params["level"], "strong");
        let dialog_ms = timer.elapsed().as_secs_f64() * 1000.0;
        publish(
            "owner-dialog-result",
            &json!({"decision":"allow","level":"strong","milliseconds":dialog_ms}),
        );
        let mut decision: remote::ApprovalDecision =
            serde_json::from_value(input["decision"].clone()).unwrap();
        decision.level = remote::ApprovalLevel::Strong;
        decision.digest = request.digest.clone();
        decision.issued_at = kv_agent::remote::view::unix_seconds();
        decision.scope = serde_json::from_value(params["scope"].clone()).unwrap();
        if staged {
            progress("waiting_strong_signal");
            stage_gate("strong");
        }
        progress("strong_sign");
        let timer = Instant::now();
        decision.sig = remote::keys::encode_b64(
            &sign(
                &metadata,
                &canonical::signed_payload(&decision).unwrap(),
                &Budget::new(),
            )
            .unwrap(),
        );
        let sign_ms = timer.elapsed().as_secs_f64() * 1000.0;
        let canonical_request: canonical::CanonicalRequest =
            serde_json::from_value(input["canonical"].clone()).unwrap();
        remote::validation::verify_decision(
            &decision,
            &request,
            &canonical_request,
            &record,
            kv_agent::remote::view::unix_seconds(),
        )
        .unwrap();
        publish(
            "owner-strong-result",
            &json!({"ak_s":record.ak_s,"decision":decision,"milliseconds":sign_ms}),
        );
        let native_repeat = std::env::var("R3B_STRONG_SKIP_REPEAT").as_deref() != Ok("1");
        let mut repeated = decision.clone();
        let repeat_ms = if native_repeat {
            if staged {
                progress("waiting_repeat_signal");
                stage_gate("repeat");
            }
            progress("repeat_sign");
            let timer = Instant::now();
            repeated.sig = remote::keys::encode_b64(
                &sign(
                    &metadata,
                    &canonical::signed_payload(&repeated).unwrap(),
                    &Budget::new(),
                )
                .unwrap(),
            );
            Some(timer.elapsed().as_secs_f64() * 1000.0)
        } else {
            // An already-tested repeat need not prompt again; replay the same signed
            // decision for the executor's duplicate-nonce negative case.
            None
        };
        remote::validation::verify_decision(
            &repeated,
            &request,
            &canonical_request,
            &record,
            kv_agent::remote::view::unix_seconds(),
        )
        .unwrap();
        publish(
            "owner-repeat-result",
            &json!({"decision":repeated,"milliseconds":repeat_ms,"native_repeat":native_repeat}),
        );
        let mut cancel_attempts = Vec::new();
        let mut cancellation = None;
        for attempt in 1..=3 {
            let gate = if attempt == 1 {
                progress("waiting_cancel_signal");
                "cancel".to_owned()
            } else {
                progress("waiting_cancel_retry_signal");
                format!("cancel-{attempt}")
            };
            stage_gate(&gate);
            progress("cancel_sign");
            let timer = Instant::now();
            let cancelled = sign(
                &metadata,
                &canonical::signed_payload(&decision).unwrap(),
                &Budget::new(),
            );
            let cancel_ms = timer.elapsed().as_secs_f64() * 1000.0;
            let status = SIGN_STATUS.with(std::cell::Cell::get);
            let user_cancelled =
                cancelled.is_err() && status == Some(KeyCredentialStatus::UserCanceled.0);
            cancel_attempts.push(json!({"attempt":attempt,"status":status,
                "cancelled":user_cancelled,"milliseconds":cancel_ms}));
            publish("owner-cancel-attempts", &json!(cancel_attempts));
            if user_cancelled {
                cancellation = Some((status, cancel_ms));
                break;
            }
            // A mistaken approval is recorded as failed cancellation and discarded.
            // Only an explicit new operator gate can retry; all other failures reject.
            assert!(cancelled.is_ok() && status == Some(KeyCredentialStatus::Success.0));
        }
        let (status, cancel_ms) = cancellation.expect("an actual UserCanceled result is required");
        delete(&name).unwrap();
        cleanup.commit();
        let missing = KeyCredentialManager::OpenAsync(&HSTRING::from(&name))
            .and_then(|op| wait(op, &Budget::new()))
            .unwrap();
        assert_eq!(missing.Status().unwrap(), KeyCredentialStatus::NotFound);
        publish(
            "owner-result",
            &json!({"ak_s":record.ak_s,"decision":decision,"repeated_decision":repeated,"cancelled":true,
            "cancel_status":status,"cancel_attempts":cancel_attempts,"native_repeat":native_repeat,"hello_cleanup":true,"timings":{"supported":supported,"support_ms":support_ms,"create_ms":create_ms,
                "dialog_ms":dialog_ms,"strong_sign_ms":sign_ms,"repeat_sign_ms":repeat_ms,"cancel_ms":cancel_ms}}),
        );
        progress("complete");
    }
}
