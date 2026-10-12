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
    let result = key
        .RequestSignAsync(&input)
        .and_then(|op| wait(op, budget))
        .map_err(|_| DeviceKeyError::OperationFailed)?;
    if result
        .Status()
        .map_err(|_| DeviceKeyError::OperationFailed)?
        != KeyCredentialStatus::Success
    {
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
}
