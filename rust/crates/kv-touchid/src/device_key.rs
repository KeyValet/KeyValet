use kv_ipc::remote::DeviceKeyError;
use kv_platform::device_key::agent::{
    enclave_blob, encode_reply, MAX_DEVICE_REQUEST_BYTES, MAX_SIGN_PAYLOAD,
};
use kv_platform::device_key::{decode_b64, encode_b64, p256_jwk, KeyRole, Result};
use serde_json::{json, Value};
use std::io::{IsTerminal, Read, Write};
use zeroize::Zeroizing;

extern "C" {
    fn kv_device_key(
        operation: i32,
        role: i32,
        blob: *const u8,
        blob_len: usize,
        input: *const u8,
        input_len: usize,
        output_blob: *mut u8,
        output_blob_len: *mut usize,
        output_public: *mut u8,
        output_data: *mut u8,
        output_data_len: *mut usize,
    ) -> i32;
}

struct EnclaveOutput {
    blob: Zeroizing<[u8; 4096]>,
    blob_len: usize,
    public: [u8; 65],
    data: Zeroizing<[u8; 256]>,
    data_len: usize,
}

trait EnclaveBridge {
    fn operate(
        &self,
        operation: i32,
        role: KeyRole,
        blob: &[u8],
        input: &[u8],
    ) -> Result<EnclaveOutput>;
}

type EnclaveCall = unsafe extern "C" fn(
    i32,
    i32,
    *const u8,
    usize,
    *const u8,
    usize,
    *mut u8,
    *mut usize,
    *mut u8,
    *mut u8,
    *mut usize,
) -> i32;
struct NativeBridge(EnclaveCall);
impl EnclaveBridge for NativeBridge {
    fn operate(
        &self,
        operation: i32,
        role: KeyRole,
        blob: &[u8],
        input: &[u8],
    ) -> Result<EnclaveOutput> {
        let mut output = EnclaveOutput {
            blob: Zeroizing::new([0; 4096]),
            blob_len: 4096,
            public: [0; 65],
            data: Zeroizing::new([0; 256]),
            data_len: 256,
        };
        let status = unsafe {
            (self.0)(
                operation,
                match role {
                    KeyRole::Identity => 0,
                    KeyRole::Quick => 1,
                    KeyRole::Strong => 2,
                },
                blob.as_ptr(),
                blob.len(),
                input.as_ptr(),
                input.len(),
                output.blob.as_mut_ptr(),
                &mut output.blob_len,
                output.public.as_mut_ptr(),
                output.data.as_mut_ptr(),
                &mut output.data_len,
            )
        };
        if status != 0 {
            return Err(DeviceKeyError::OperationFailed);
        }
        Ok(output)
    }
}

pub fn execute(request: &Value) -> Result<Zeroizing<Vec<u8>>> {
    execute_with(request, &NativeBridge(kv_device_key))
}

fn execute_with(request: &Value, bridge: &impl EnclaveBridge) -> Result<Zeroizing<Vec<u8>>> {
    let role = KeyRole::parse(request["role"].as_str().ok_or(DeviceKeyError::InvalidKey)?)?;
    let operation = match request["operation"].as_str() {
        Some("create") => 0,
        Some("sign") => 1,
        Some("ecdh") => 2,
        _ => return Err(DeviceKeyError::InvalidKey),
    };
    let metadata = request.get("metadata").cloned().unwrap_or(Value::Null);
    let blob = if operation == 0 {
        if !metadata.is_null() {
            return Err(DeviceKeyError::InvalidKey);
        }
        Zeroizing::new(Vec::new())
    } else {
        enclave_blob(&metadata, role)?
    };
    let input = match request.get("data") {
        None if operation == 0 => Zeroizing::new(Vec::new()),
        Some(Value::String(data)) => decode_b64(data)?,
        _ => return Err(DeviceKeyError::InvalidKey),
    };
    if input.len() > MAX_SIGN_PAYLOAD
        || (operation == 2 && (input.len() != 65 || input[0] != 4))
        || (operation == 0 && !input.is_empty())
    {
        return Err(DeviceKeyError::InvalidKey);
    }
    let EnclaveOutput {
        blob: new_blob,
        blob_len: blob_length,
        public,
        data,
        data_len: data_length,
    } = bridge.operate(operation, role, &blob, &input)?;
    if !(1..=new_blob.len()).contains(&blob_length)
        || data_length
            != match operation {
                0 => 0,
                1 => 64,
                _ => 32,
            }
    {
        return Err(DeviceKeyError::OperationFailed);
    }
    let new_metadata = json!({
        "version":1,"role":role.as_str(),"key_kind":"secure_enclave",
        "key_blob":encode_b64(&new_blob[..blob_length]), "public_jwk":p256_jwk(&public)?
    });
    if operation != 0 && new_metadata != metadata {
        return Err(DeviceKeyError::InvalidKey);
    }
    encode_reply(&data[..data_length], &new_metadata)
}

pub fn run() -> Result<()> {
    if std::io::stdout().is_terminal() {
        return Err(DeviceKeyError::Unavailable);
    }
    let mut stdout = std::mem::ManuallyDrop::new(unsafe {
        <std::fs::File as std::os::fd::FromRawFd>::from_raw_fd(1)
    });
    run_with(&mut std::io::stdin(), &mut *stdout, execute)
}

pub fn exit_code(result: Result<()>) -> i32 {
    match result {
        Ok(()) => 0,
        Err(error) => {
            eprintln!("{error}");
            1
        }
    }
}

fn run_with(
    reader: &mut impl Read,
    writer: &mut impl Write,
    execute: impl FnOnce(&Value) -> Result<Zeroizing<Vec<u8>>>,
) -> Result<()> {
    let mut input = Zeroizing::new(Vec::new());
    reader
        .take(MAX_DEVICE_REQUEST_BYTES as u64 + 1)
        .read_to_end(&mut input)
        .map_err(|_| DeviceKeyError::OperationFailed)?;
    if input.len() > MAX_DEVICE_REQUEST_BYTES {
        return Err(DeviceKeyError::InvalidKey);
    }
    let request = serde_json::from_slice(&input).map_err(|_| DeviceKeyError::InvalidKey)?;
    let output = execute(&request)?;
    writer
        .write_all(&output)
        .map_err(|_| DeviceKeyError::OperationFailed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use kv_platform::device_key::agent::decode_reply;
    use kv_platform::device_key::jwk_point;
    use std::cell::Cell;

    #[test]
    fn cli_exit_status_preserves_success_and_hardware_failure() {
        assert_eq!(exit_code(Ok(())), 0);
        assert_eq!(exit_code(Err(DeviceKeyError::Unavailable)), 1);
        assert_eq!(exit_code(Err(DeviceKeyError::OperationFailed)), 1);
    }

    struct FakeBridge<F>(F);
    impl<F: Fn(i32, KeyRole, &[u8], &[u8]) -> Result<EnclaveOutput>> EnclaveBridge for FakeBridge<F> {
        fn operate(
            &self,
            operation: i32,
            role: KeyRole,
            blob: &[u8],
            input: &[u8],
        ) -> Result<EnclaveOutput> {
            (self.0)(operation, role, blob, input)
        }
    }

    fn public() -> [u8; 65] {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../kv-core/testdata/remote/test_keys.json");
        let vector: Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
        jwk_point(&vector["sender"]["public_jwk"])
            .unwrap()
            .try_into()
            .unwrap()
    }
    fn output(operation: i32) -> EnclaveOutput {
        let mut blob = Zeroizing::new([0; 4096]);
        blob[0] = 1;
        EnclaveOutput {
            blob,
            blob_len: 1,
            public: public(),
            data: Zeroizing::new([7; 256]),
            data_len: match operation {
                0 => 0,
                1 => 64,
                _ => 32,
            },
        }
    }
    fn metadata(role: KeyRole) -> Value {
        json!({"version":1,"role":role.as_str(),"key_kind":"secure_enclave","key_blob":"AQ","public_jwk":p256_jwk(&public()).unwrap()})
    }

    unsafe extern "C" fn fake_ffi(
        operation: i32,
        role: i32,
        blob: *const u8,
        blob_len: usize,
        input: *const u8,
        input_len: usize,
        output_blob: *mut u8,
        output_blob_len: *mut usize,
        output_public: *mut u8,
        output_data: *mut u8,
        output_data_len: *mut usize,
    ) -> i32 {
        if operation == 99 {
            return 1;
        }
        assert!((0..3).contains(&role));
        assert!(blob_len == 0 || unsafe { std::slice::from_raw_parts(blob, blob_len) } == [1]);
        if operation == 1 {
            assert!(unsafe { std::slice::from_raw_parts(input, input_len) } == b"payload");
        }
        let result = output(operation);
        unsafe {
            assert_eq!(*output_blob_len, 4096);
            assert_eq!(*output_data_len, 256);
            std::ptr::copy_nonoverlapping(result.blob.as_ptr(), output_blob, result.blob_len);
            std::ptr::copy_nonoverlapping(result.public.as_ptr(), output_public, 65);
            std::ptr::copy_nonoverlapping(result.data.as_ptr(), output_data, result.data_len);
            *output_blob_len = result.blob_len;
            *output_data_len = result.data_len;
        }
        0
    }

    #[test]
    fn native_abi_marshals_every_role_and_propagates_status_without_hardware() {
        let bridge = NativeBridge(fake_ffi);
        for role in [KeyRole::Identity, KeyRole::Quick, KeyRole::Strong] {
            for (operation, name) in [(0, "create"), (1, "sign"), (2, "ecdh")] {
                let mut request = json!({"role":role.as_str(),"operation":name});
                if operation != 0 {
                    request["metadata"] = metadata(role);
                    let point = public();
                    request["data"] =
                        json!(encode_b64(if operation == 1 { b"payload" } else { &point }));
                }
                assert!(execute_with(&request, &bridge).is_ok());
            }
        }
        assert!(matches!(
            bridge.operate(99, KeyRole::Identity, &[], &[]),
            Err(DeviceKeyError::OperationFailed)
        ));
    }

    #[test]
    fn injected_bridge_accepts_all_roles_and_preserves_the_pinned_key() {
        for role in [KeyRole::Identity, KeyRole::Quick, KeyRole::Strong] {
            for (operation, name, input) in [
                (0, "create", vec![]),
                (1, "sign", vec![5; MAX_SIGN_PAYLOAD]),
                (2, "ecdh", public().to_vec()),
            ] {
                let calls = Cell::new(0);
                let bridge = FakeBridge(|op, passed_role, blob: &[u8], data: &[u8]| {
                    calls.set(calls.get() + 1);
                    assert_eq!(op, operation);
                    assert_eq!(passed_role, role);
                    assert!(data == input);
                    assert_eq!(blob, if operation == 0 { &[][..] } else { &[1][..] });
                    Ok(output(operation))
                });
                let mut request = json!({"role":role.as_str(),"operation":name});
                if operation != 0 {
                    request["metadata"] = metadata(role);
                    request["data"] = json!(encode_b64(&input));
                }
                let reply = execute_with(&request, &bridge).unwrap();
                let (data, actual_metadata) = decode_reply(&reply).unwrap();
                assert_eq!(actual_metadata, metadata(role));
                assert_eq!(
                    data.len(),
                    match operation {
                        0 => 0,
                        1 => 64,
                        _ => 32,
                    }
                );
                assert_eq!(calls.get(), 1);
            }
        }
    }

    #[test]
    fn native_failure_invalid_lengths_points_and_metadata_substitution_fail_closed() {
        let request = json!({"role":"identity","operation":"sign","metadata":metadata(KeyRole::Identity),"data":""});
        let failure = FakeBridge(|_, _, _: &[u8], _: &[u8]| Err(DeviceKeyError::Unavailable));
        assert_eq!(
            execute_with(&request, &failure),
            Err(DeviceKeyError::Unavailable)
        );
        for invalid in 0..7 {
            let bridge = FakeBridge(|op, _, _: &[u8], _: &[u8]| {
                let mut out = output(op);
                match invalid {
                    0 => out.blob_len = 0,
                    1 => out.blob_len = 4097,
                    2 => out.data_len = 63,
                    3 => out.data_len = 257,
                    4 => out.public[0] = 3,
                    5 => out.public[1] ^= 1,
                    _ => out.blob[0] = 2,
                }
                Ok(out)
            });
            assert!(execute_with(&request, &bridge).is_err());
        }
    }

    #[test]
    fn malformed_and_oversized_requests_never_reach_the_bridge() {
        let bridge =
            FakeBridge(|_, _, _: &[u8], _: &[u8]| panic!("invalid input reached hardware"));
        for request in [
            json!({"role":"identity","operation":"unknown"}),
            json!({"role":"identity","operation":"create","metadata":{}}),
            json!({"role":"identity","operation":"create","data":0}),
            json!({"role":"identity","operation":"create","data":"!"}),
            json!({"role":"identity","operation":"sign","metadata":metadata(KeyRole::Identity)}),
            json!({"role":"identity","operation":"ecdh","metadata":metadata(KeyRole::Identity),"data":""}),
            json!({"role":"identity","operation":"ecdh","metadata":metadata(KeyRole::Identity),"data":encode_b64(&[3;65])}),
            json!({"role":"identity","operation":"sign","metadata":metadata(KeyRole::Identity),"data":encode_b64(&vec![0;MAX_SIGN_PAYLOAD+1])}),
        ] {
            assert_eq!(
                execute_with(&request, &bridge),
                Err(DeviceKeyError::InvalidKey)
            );
        }
        let bridge = FakeBridge(|op, _, _: &[u8], _: &[u8]| Ok(output(op)));
        assert!(execute_with(
            &json!({"role":"identity","operation":"create","data":"","metadata":null}),
            &bridge
        )
        .is_ok());
    }

    #[test]
    fn stdio_protocol_is_bounded_and_propagates_read_and_write_failures() {
        struct Failure;
        impl Read for Failure {
            fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
                Err(std::io::Error::other("read failed"))
            }
        }
        impl Write for Failure {
            fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
                Err(std::io::Error::other("write failed"))
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let execute = |_: &Value| Ok(Zeroizing::new(vec![1, 2, 3]));
        let mut reply = Vec::new();
        assert_eq!(
            run_with(&mut Failure, &mut reply, execute),
            Err(DeviceKeyError::OperationFailed)
        );
        assert_eq!(
            run_with(
                &mut &[b' '; MAX_DEVICE_REQUEST_BYTES + 1][..],
                &mut reply,
                execute
            ),
            Err(DeviceKeyError::InvalidKey)
        );
        assert_eq!(
            run_with(&mut b"!".as_slice(), &mut reply, execute),
            Err(DeviceKeyError::InvalidKey)
        );
        assert_eq!(
            run_with(&mut b"{}".as_slice(), &mut Failure, execute),
            Err(DeviceKeyError::OperationFailed)
        );
        assert_eq!(
            run_with(&mut b"{}".as_slice(), &mut reply, |_| Err(
                DeviceKeyError::Unavailable
            )),
            Err(DeviceKeyError::Unavailable)
        );
        run_with(&mut b"{}".as_slice(), &mut reply, execute).unwrap();
        assert!(reply == [1, 2, 3]);
    }

    #[test]
    fn malformed_requests_are_rejected_before_hardware() {
        for request in [
            json!({}),
            json!({"role":"other","operation":"create"}),
            json!({"role":"identity","operation":"ecdh","metadata":{}}),
            json!({"role":"identity","operation":"create","data":"AQ"}),
        ] {
            assert!(execute(&request).is_err());
        }
    }

    /// Run on an unlocked Apple Silicon Mac as a regular GUI user:
    /// CARGO_TARGET_DIR=target-w1 cargo test -p kv-touchid remote_se_roundtrip -- --ignored
    #[test]
    #[ignore = "Requires an unlocked macOS GUI session and Secure Enclave"]
    fn remote_se_roundtrip() {
        let left = execute(&json!({"role":"identity","operation":"create"})).unwrap();
        let right = execute(&json!({"role":"quick","operation":"create"})).unwrap();
        let (_, left) = decode_reply(&left).unwrap();
        let (_, right) = decode_reply(&right).unwrap();
        assert_ne!(left["public_jwk"], right["public_jwk"]);
        let derive = |own: &Value, peer: &Value| {
            execute(
                &json!({"role":own["role"],"operation":"ecdh","metadata":own,
                "data":encode_b64(&jwk_point(&peer["public_jwk"]).unwrap())}),
            )
            .unwrap()
        };
        let a = derive(&left, &right);
        let b = derive(&right, &left);
        assert!(decode_reply(&a).unwrap().0 == decode_reply(&b).unwrap().0);
        let signature = execute(&json!({"role":"identity","operation":"sign","metadata":left,"data":encode_b64(b"remote test")})).unwrap();
        assert_eq!(decode_reply(&signature).unwrap().0.len(), 64);
    }

    /// Run with the same command and filter remote_se_strong on the Mac owner session;
    /// complete the OS user-presence prompt. Cancellation must return an error.
    #[test]
    #[ignore = "Requires Secure Enclave and an interactive Touch ID or password prompt"]
    fn remote_se_strong() {
        let created = execute(&json!({"role":"strong","operation":"create"})).unwrap();
        let (_, metadata) = decode_reply(&created).unwrap();
        assert!(execute(&json!({"role":"strong","operation":"sign","metadata":metadata,"data":encode_b64(b"remote strong test")})).is_ok());
    }
}
