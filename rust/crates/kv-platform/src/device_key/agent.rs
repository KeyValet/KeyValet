//! Device-key operations over the existing authenticated agent connection.
use super::jwk_point;
use super::{
    decode_b64, key_name_valid, DeviceKeyError, DeviceKeyProvider, KeyRole, Result,
    SignatureAlgorithm,
};
use crate::agent::{AgentHub, AgentKey, REQUEST_TIMEOUT};
use serde_json::{json, Value};
use std::sync::Arc;
use zeroize::Zeroizing;

pub const MAX_SIGN_PAYLOAD: usize = 128 * 1024;
pub const MAX_DEVICE_REQUEST_BYTES: usize = MAX_SIGN_PAYLOAD.div_ceil(3) * 4 + 8192;
pub const DEVICE_KEY_PROTOCOL: u64 = 1;

// CONTRACT: §5 / Appendix A.1: large envelope signatures use bounded binary input after the agent header.
pub fn input_length(request: &Value) -> Result<Option<usize>> {
    match request.get("input_len") {
        None => Ok(None),
        Some(value) if request["op"] == "device_key" && request.get("data").is_none() => {
            let length = value.as_u64().ok_or(DeviceKeyError::InvalidKey)?;
            if length == 0 || length > MAX_SIGN_PAYLOAD as u64 {
                return Err(DeviceKeyError::InvalidKey);
            }
            Ok(Some(length as usize))
        }
        _ => Err(DeviceKeyError::InvalidKey),
    }
}

pub trait KeyTransport {
    fn exchange(&self, request: Value) -> Result<Zeroizing<Vec<u8>>>;
}

pub struct AgentTransport {
    pub hub: Arc<AgentHub>,
    pub owner: AgentKey,
}

impl KeyTransport for AgentTransport {
    fn exchange(&self, mut request: Value) -> Result<Zeroizing<Vec<u8>>> {
        let object = request.as_object_mut().ok_or(DeviceKeyError::InvalidKey)?;
        let input = if let Some(data) = object.get("data") {
            let bytes = decode_b64(data.as_str().ok_or(DeviceKeyError::InvalidKey)?)?;
            if bytes.len() > MAX_SIGN_PAYLOAD {
                return Err(DeviceKeyError::InvalidKey);
            }
            if !bytes.is_empty() {
                object.remove("data");
                object.insert("input_len".into(), json!(bytes.len()));
                Some(bytes)
            } else {
                None
            }
        } else {
            None
        };
        let runtime =
            tokio::runtime::Handle::try_current().map_err(|_| DeviceKeyError::Unavailable)?;
        if runtime.runtime_flavor() != tokio::runtime::RuntimeFlavor::MultiThread {
            return Err(DeviceKeyError::Unavailable);
        }
        tokio::task::block_in_place(|| {
            runtime.block_on(async {
                let prompt = self.hub.prompt_lock(&self.owner);
                let _prompt = prompt.lock().await;
                let (header, payload) = self
                    .hub
                    .request_with_input(
                        &self.owner,
                        request,
                        input.as_deref().map(Vec::as_slice),
                        REQUEST_TIMEOUT,
                    )
                    .await
                    .map_err(|_| DeviceKeyError::Unavailable)?;
                if header["ok"] != true {
                    return Err(match header["error"].as_str() {
                        Some("key_operation_cancelled") => DeviceKeyError::OperationCancelled,
                        Some("key_authentication_failed") => DeviceKeyError::AuthenticationFailed,
                        _ => DeviceKeyError::OperationFailed,
                    });
                }
                let (bytes, len) = payload.ok_or(DeviceKeyError::OperationFailed)?;
                Ok(Zeroizing::new(bytes[..len].to_vec()))
            })
        })
    }
}

pub struct AgentDeviceKey<T> {
    transport: T,
    metadata: Value,
    role: KeyRole,
}

impl<T: KeyTransport> AgentDeviceKey<T> {
    pub fn create(transport: T, role: KeyRole) -> Result<Self> {
        #[cfg(windows)]
        if role != KeyRole::Strong {
            return Err(DeviceKeyError::UnsupportedAlgorithm);
        }
        let output = transport
            .exchange(json!({"op":"device_key","operation":"create","role":role.as_str()}))?;
        let (data, metadata) = decode_reply(&output)?;
        if !data.is_empty() {
            return Err(DeviceKeyError::InvalidKey);
        }
        Self::from_authenticated_metadata(transport, role, metadata)
    }

    // CONTRACT: §3.2 / §13.1: the helper authenticates the stored role and key blob with vault AEAD.
    pub fn from_authenticated_metadata(
        transport: T,
        role: KeyRole,
        metadata: Value,
    ) -> Result<Self> {
        validate_metadata(&metadata, role)?;
        Ok(Self {
            transport,
            role,
            metadata,
        })
    }

    pub fn metadata(&self) -> &Value {
        &self.metadata
    }

    fn operate(&self, operation: &str, data: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        let response = self.transport.exchange(json!({
            "op":"device_key", "operation":operation, "role":self.role.as_str(),
            "metadata":self.metadata, "data":super::encode_b64(data)
        }))?;
        let (result, metadata) = decode_reply(&response)?;
        if metadata != self.metadata {
            return Err(DeviceKeyError::InvalidKey);
        }
        Ok(Zeroizing::new(result.to_vec()))
    }
}

pub fn validate_metadata(metadata: &Value, role: KeyRole) -> Result<()> {
    validate_metadata_for_platform(metadata, role, cfg!(windows))
}

fn validate_metadata_for_platform(metadata: &Value, role: KeyRole, windows: bool) -> Result<()> {
    if !windows {
        return enclave_blob(metadata, role).map(|_| ());
    }
    validate_header(metadata, role)?;
    if role != KeyRole::Strong
        || metadata["key_kind"] != "windows_hello"
        || metadata["public_jwk"]["kty"] != "RSA"
    {
        return Err(DeviceKeyError::InvalidKey);
    }
    let name = metadata["key_name"]
        .as_str()
        .ok_or(DeviceKeyError::InvalidKey)?;
    if !key_name_valid(name, role) {
        return Err(DeviceKeyError::InvalidKey);
    }
    let n = decode_b64(
        metadata["public_jwk"]["n"]
            .as_str()
            .ok_or(DeviceKeyError::InvalidKey)?,
    )?;
    let e = decode_b64(
        metadata["public_jwk"]["e"]
            .as_str()
            .ok_or(DeviceKeyError::InvalidKey)?,
    )?;
    if n.len() != 256 || n[0] < 128 || e.as_slice() != [1, 0, 1] {
        return Err(DeviceKeyError::InvalidKey);
    }
    Ok(())
}

fn validate_header(metadata: &Value, role: KeyRole) -> Result<()> {
    if metadata["version"] != 1 || metadata["role"] != role.as_str() {
        return Err(DeviceKeyError::InvalidKey);
    }
    let public = &metadata["public_jwk"];
    if !public.is_object()
        || ["d", "p", "q", "dp", "dq", "qi", "oth", "k"]
            .iter()
            .any(|field| public.get(field).is_some())
    {
        return Err(DeviceKeyError::InvalidKey);
    }
    Ok(())
}

pub fn enclave_blob(metadata: &Value, role: KeyRole) -> Result<Zeroizing<Vec<u8>>> {
    validate_header(metadata, role)?;
    if metadata["key_kind"] != "secure_enclave" {
        return Err(DeviceKeyError::InvalidKey);
    }
    let blob = decode_b64(
        metadata["key_blob"]
            .as_str()
            .ok_or(DeviceKeyError::InvalidKey)?,
    )?;
    if blob.is_empty() || blob.len() > 4096 {
        return Err(DeviceKeyError::InvalidKey);
    }
    jwk_point(&metadata["public_jwk"])?;
    Ok(blob)
}

// CONTRACT: §3.1: reuse agent framing; a binary result precedes opaque authenticated metadata.
pub fn encode_reply(data: &[u8], metadata: &Value) -> Result<Zeroizing<Vec<u8>>> {
    let json = serde_json::to_vec(metadata).map_err(|_| DeviceKeyError::OperationFailed)?;
    if data.len() > 256 || data.len() + json.len() + 4 > kv_ipc::agent::MAX_ENCLAVE_PAYLOAD {
        return Err(DeviceKeyError::InvalidKey);
    }
    let mut reply = Zeroizing::new((data.len() as u32).to_be_bytes().to_vec());
    reply.extend_from_slice(data);
    reply.extend_from_slice(&json);
    Ok(reply)
}

pub fn decode_reply(bytes: &[u8]) -> Result<(&[u8], Value)> {
    if bytes.len() < 5 || bytes.len() > kv_ipc::agent::MAX_ENCLAVE_PAYLOAD {
        return Err(DeviceKeyError::InvalidKey);
    }
    let len = u32::from_be_bytes(bytes[..4].try_into().unwrap()) as usize;
    if len > 256 || len + 4 >= bytes.len() {
        return Err(DeviceKeyError::InvalidKey);
    }
    let metadata =
        serde_json::from_slice(&bytes[4 + len..]).map_err(|_| DeviceKeyError::InvalidKey)?;
    Ok((&bytes[4..4 + len], metadata))
}

impl<T: KeyTransport> DeviceKeyProvider for AgentDeviceKey<T> {
    fn sign(&self, alg: SignatureAlgorithm, payload: &[u8]) -> Result<Vec<u8>> {
        #[cfg(windows)]
        let expected = SignatureAlgorithm::RS256;
        #[cfg(target_os = "macos")]
        let expected = SignatureAlgorithm::ES256;
        if alg != expected {
            return Err(DeviceKeyError::UnsupportedAlgorithm);
        }
        if payload.len() > MAX_SIGN_PAYLOAD {
            return Err(DeviceKeyError::OperationFailed);
        }
        let signature = self.operate("sign", payload)?;
        if signature.len() != if cfg!(windows) { 256 } else { 64 } {
            return Err(DeviceKeyError::OperationFailed);
        }
        Ok(signature.to_vec())
    }
    #[cfg(windows)]
    fn ecdh(&self, _: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
        Err(DeviceKeyError::UnsupportedAlgorithm)
    }
    #[cfg(target_os = "macos")]
    fn ecdh(&self, peer_pub: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
        if peer_pub.len() != 65 || peer_pub[0] != 4 {
            return Err(DeviceKeyError::InvalidKey);
        }
        let secret = self.operate("ecdh", peer_pub)?;
        Ok(Zeroizing::new(
            secret
                .as_slice()
                .try_into()
                .map_err(|_| DeviceKeyError::OperationFailed)?,
        ))
    }
    fn public_jwk(&self) -> Result<Value> {
        Ok(self.metadata["public_jwk"].clone())
    }
    fn presence_kind(&self) -> &str {
        self.role.presence_kind()
    }
    fn key_kind(&self) -> &str {
        self.metadata["key_kind"].as_str().unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};

    fn enclave_metadata(role: KeyRole) -> Value {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../kv-core/testdata/remote/test_keys.json");
        let vector: Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
        json!({"version":1,"role":role.as_str(),"key_kind":"secure_enclave",
            "key_blob":"AQ","public_jwk":vector["sender"]["public_jwk"]})
    }

    fn hello_metadata() -> Value {
        json!({"version":1,"role":"strong","key_kind":"windows_hello",
            "key_name":format!("keyvalet.remote.strong.{}", "0".repeat(32)),
            "public_jwk":{"kty":"RSA","n":super::super::encode_b64(&[0xff;256]),"e":"AQAB"}})
    }

    fn native_metadata(role: KeyRole) -> Value {
        if cfg!(windows) {
            hello_metadata()
        } else {
            enclave_metadata(role)
        }
    }

    struct Scripted {
        reply: RefCell<Result<Zeroizing<Vec<u8>>>>,
        requests: RefCell<Vec<Value>>,
    }
    impl Scripted {
        fn new(data: &[u8], metadata: &Value) -> Self {
            Self {
                reply: RefCell::new(encode_reply(data, metadata)),
                requests: RefCell::new(Vec::new()),
            }
        }
    }
    impl KeyTransport for Scripted {
        fn exchange(&self, request: Value) -> Result<Zeroizing<Vec<u8>>> {
            self.requests.borrow_mut().push(request);
            self.reply.borrow().clone()
        }
    }
    struct Broken;
    impl KeyTransport for Broken {
        fn exchange(&self, _: Value) -> Result<Zeroizing<Vec<u8>>> {
            Err(DeviceKeyError::Unavailable)
        }
    }
    #[test]
    fn absent_hardware_and_invalid_framing_fail_closed() {
        assert!(AgentDeviceKey::create(Broken, KeyRole::Strong).is_err());
        for bytes in [
            vec![],
            vec![0; 4],
            vec![0, 0, 1, 1, b'{', b'}'],
            vec![0, 0, 0, 1, 4],
        ] {
            assert!(decode_reply(&bytes).is_err());
        }
        let metadata = json!({"version":1});
        let encoded = encode_reply(&[1, 2, 3], &metadata).unwrap();
        let (data, decoded) = decode_reply(&encoded).unwrap();
        assert_eq!(data, [1, 2, 3]);
        assert_eq!(decoded, metadata);
        assert!(encode_reply(&[0; 257], &metadata).is_err());
    }

    #[test]
    fn binary_input_headers_are_bounded_and_unambiguous() {
        assert_eq!(
            input_length(&json!({"op":"device_key","input_len":MAX_SIGN_PAYLOAD})),
            Ok(Some(MAX_SIGN_PAYLOAD))
        );
        assert_eq!(input_length(&json!({"op":"device_key"})), Ok(None));
        for request in [
            json!({"op":"enclave","input_len":32}),
            json!({"op":"device_key","input_len":0}),
            json!({"op":"device_key","input_len":MAX_SIGN_PAYLOAD+1}),
            json!({"op":"device_key","input_len":-1}),
            json!({"op":"device_key","input_len":"32"}),
            json!({"op":"device_key","input_len":32,"data":"AA"}),
        ] {
            assert!(input_length(&request).is_err());
        }
    }

    #[test]
    fn metadata_checks_both_platforms_and_rejects_private_or_substituted_fields() {
        for (windows, metadata) in [
            (false, enclave_metadata(KeyRole::Strong)),
            (true, hello_metadata()),
        ] {
            assert_eq!(
                validate_metadata_for_platform(&metadata, KeyRole::Strong, windows),
                Ok(())
            );
            for (field, value) in [
                ("version", json!(2)),
                ("role", json!("identity")),
                ("key_kind", json!("software")),
                ("public_jwk", Value::Null),
            ] {
                let mut invalid = metadata.clone();
                invalid[field] = value;
                assert_eq!(
                    validate_metadata_for_platform(&invalid, KeyRole::Strong, windows),
                    Err(DeviceKeyError::InvalidKey)
                );
            }
            for field in ["d", "p", "q", "dp", "dq", "qi", "oth", "k"] {
                let mut invalid = metadata.clone();
                invalid["public_jwk"][field] = Value::Null;
                assert_eq!(
                    validate_metadata_for_platform(&invalid, KeyRole::Strong, windows),
                    Err(DeviceKeyError::InvalidKey)
                );
            }
        }
        let enclave = enclave_metadata(KeyRole::Quick);
        for value in [
            Value::Null,
            json!(""),
            json!("!"),
            json!(super::super::encode_b64(&[0; 4097])),
        ] {
            let mut invalid = enclave.clone();
            invalid["key_blob"] = value;
            assert_eq!(
                validate_metadata_for_platform(&invalid, KeyRole::Quick, false),
                Err(DeviceKeyError::InvalidKey)
            );
        }
        let mut invalid = enclave.clone();
        invalid["public_jwk"]["x"] = json!("AQ");
        assert_eq!(
            validate_metadata_for_platform(&invalid, KeyRole::Quick, false),
            Err(DeviceKeyError::InvalidKey)
        );
        let hello = hello_metadata();
        let mut wrong_role = hello.clone();
        wrong_role["role"] = json!("quick");
        assert_eq!(
            validate_metadata_for_platform(&wrong_role, KeyRole::Quick, true),
            Err(DeviceKeyError::InvalidKey)
        );
        for value in [
            Value::Null,
            json!("keyvalet.vault.strong"),
            json!("keyvalet.remote.strong."),
        ] {
            let mut invalid = hello.clone();
            invalid["key_name"] = value;
            assert_eq!(
                validate_metadata_for_platform(&invalid, KeyRole::Strong, true),
                Err(DeviceKeyError::InvalidKey)
            );
        }
        for (field, value) in [
            ("kty", json!("EC")),
            ("n", Value::Null),
            ("n", json!("!")),
            ("n", json!("AQ")),
            ("n", json!(super::super::encode_b64(&[1; 256]))),
            ("e", Value::Null),
            ("e", json!("!")),
            ("e", json!("Aw")),
        ] {
            let mut invalid = hello.clone();
            invalid["public_jwk"][field] = value;
            assert_eq!(
                validate_metadata_for_platform(&invalid, KeyRole::Strong, true),
                Err(DeviceKeyError::InvalidKey)
            );
        }
    }

    #[test]
    fn provider_pins_metadata_and_rejects_wrong_algorithms_sizes_and_replies() {
        let role = KeyRole::Strong;
        let metadata = native_metadata(role);
        let key = AgentDeviceKey::create(Scripted::new(&[], &metadata), role).unwrap();
        assert_eq!(key.metadata(), &metadata);
        assert_eq!(key.public_jwk().unwrap(), metadata["public_jwk"]);
        assert_eq!(key.presence_kind(), role.presence_kind());
        assert_eq!(
            key.key_kind(),
            if cfg!(windows) {
                "windows_hello"
            } else {
                "secure_enclave"
            }
        );
        let (alg, other, size) = if cfg!(windows) {
            (SignatureAlgorithm::RS256, SignatureAlgorithm::ES256, 256)
        } else {
            (SignatureAlgorithm::ES256, SignatureAlgorithm::RS256, 64)
        };
        *key.transport.reply.borrow_mut() = encode_reply(&vec![7; size], &metadata);
        assert_eq!(key.sign(alg, b"payload").unwrap(), vec![7; size]);
        let last = key.transport.requests.borrow().last().unwrap().clone();
        assert_eq!(last["operation"], "sign");
        assert_eq!(last["metadata"], metadata);
        assert_eq!(last["data"], super::super::encode_b64(b"payload"));
        let calls = key.transport.requests.borrow().len();
        assert_eq!(
            key.sign(other, b"payload"),
            Err(DeviceKeyError::UnsupportedAlgorithm)
        );
        assert_eq!(
            key.sign(alg, &vec![0; MAX_SIGN_PAYLOAD + 1]),
            Err(DeviceKeyError::OperationFailed)
        );
        assert_eq!(key.transport.requests.borrow().len(), calls);
        *key.transport.reply.borrow_mut() = encode_reply(&[0; 1], &metadata);
        assert_eq!(
            key.sign(alg, b"payload"),
            Err(DeviceKeyError::OperationFailed)
        );
        let mut changed = metadata.clone();
        changed["version"] = json!(2);
        *key.transport.reply.borrow_mut() = encode_reply(&vec![7; size], &changed);
        assert_eq!(key.sign(alg, b"payload"), Err(DeviceKeyError::InvalidKey));
        *key.transport.reply.borrow_mut() = Ok(Zeroizing::new(vec![0; 4]));
        assert_eq!(key.sign(alg, b"payload"), Err(DeviceKeyError::InvalidKey));
        *key.transport.reply.borrow_mut() = Err(DeviceKeyError::Unavailable);
        assert_eq!(key.sign(alg, b"payload"), Err(DeviceKeyError::Unavailable));
        assert!(AgentDeviceKey::create(Scripted::new(&[1], &metadata), role).is_err());
        assert!(AgentDeviceKey::from_authenticated_metadata(Broken, role, json!({})).is_err());
        #[cfg(windows)]
        {
            assert_eq!(
                key.ecdh(&[4; 65]),
                Err(DeviceKeyError::UnsupportedAlgorithm)
            );
            assert!(AgentDeviceKey::create(Broken, KeyRole::Identity).is_err());
        }
        #[cfg(target_os = "macos")]
        {
            for point in [vec![], vec![3; 65], vec![4; 64]] {
                assert_eq!(key.ecdh(&point), Err(DeviceKeyError::InvalidKey));
            }
            *key.transport.reply.borrow_mut() = encode_reply(&[9; 32], &metadata);
            assert!(key.ecdh(&[4; 65]).unwrap().as_slice() == [9; 32]);
            *key.transport.reply.borrow_mut() = encode_reply(&[9; 31], &metadata);
            assert_eq!(key.ecdh(&[4; 65]), Err(DeviceKeyError::OperationFailed));
        }
    }

    #[test]
    fn reply_bounds_include_metadata_and_reject_invalid_json() {
        assert!(decode_reply(&vec![0; kv_ipc::agent::MAX_ENCLAVE_PAYLOAD + 1]).is_err());
        assert!(decode_reply(&[0, 0, 0, 0, b'!']).is_err());
        assert!(encode_reply(&[], &json!("x".repeat(kv_ipc::agent::MAX_ENCLAVE_PAYLOAD))).is_err());
        let metadata = json!("x".repeat(kv_ipc::agent::MAX_ENCLAVE_PAYLOAD - 6));
        let encoded = encode_reply(&[], &metadata).unwrap();
        assert_eq!(encoded.len(), kv_ipc::agent::MAX_ENCLAVE_PAYLOAD);
        assert_eq!(decode_reply(&encoded).unwrap().1, metadata);
    }

    fn transport() -> AgentTransport {
        AgentTransport {
            hub: AgentHub::new(),
            owner: AgentKey::default(),
        }
    }

    #[test]
    fn transport_rejects_invalid_data_and_missing_runtime_without_contacting_agent() {
        let transport = transport();
        for request in [
            json!(null),
            json!([]),
            json!({"data":1}),
            json!({"data":"!"}),
            json!({"data":super::super::encode_b64(&vec![0;MAX_SIGN_PAYLOAD+1])}),
        ] {
            assert_eq!(transport.exchange(request), Err(DeviceKeyError::InvalidKey));
        }
        assert_eq!(
            transport.exchange(json!({"op":"device_key"})),
            Err(DeviceKeyError::Unavailable)
        );
    }

    #[tokio::test]
    async fn transport_rejects_single_thread_runtime() {
        assert_eq!(
            transport().exchange(json!({"op":"device_key"})),
            Err(DeviceKeyError::Unavailable)
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn r3a_se_failure_keeps_typed_facts_from_the_private_agent() {
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
        for (code, expected) in [
            ("key_operation_cancelled", "key_operation_cancelled"),
            ("key_authentication_failed", "key_authentication_failed"),
            ("cancelled from arbitrary prose", "key_operation_failed"),
            ("denied", "key_operation_failed"),
        ] {
            let transport = transport();
            let (stream, peer) = tokio::io::duplex(1024);
            #[allow(clippy::clone_on_copy)]
            transport
                .hub
                .register(transport.owner.clone(), stream, "signed");
            let agent = tokio::spawn(async move {
                let mut peer = BufReader::new(peer);
                let mut line = String::new();
                peer.read_line(&mut line).await.unwrap();
                let request: Value = serde_json::from_str(&line).unwrap();
                peer.get_mut()
                    .write_all(&kv_ipc::agent::encode_line(
                        &json!({"id":request["id"],"ok":false,"error":code}),
                    ))
                    .await
                    .unwrap();
            });
            let Err(error) = transport.exchange(json!({"op":"device_key","operation":"sign"}))
            else {
                panic!("failed agent replies must never return signature material");
            };
            assert_eq!(error.to_string(), expected);
            agent.await.unwrap();
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn transport_sends_bounded_binary_input_and_only_accepts_successful_binary_replies() {
        for (input, ok, payload) in [
            (Some(vec![7; 80 * 1024]), true, true),
            (Some(vec![]), true, true),
            (None, false, false),
            (None, true, false),
        ] {
            let transport = transport();
            let (stream, peer) = tokio::io::duplex(1024);
            #[allow(clippy::clone_on_copy)]
            transport
                .hub
                .register(transport.owner.clone(), stream, "signed");
            let expected = input.clone();
            let agent = tokio::spawn(async move {
                let mut peer = BufReader::new(peer);
                if expected.as_ref().is_some_and(|v| !v.is_empty()) {
                    let mut line = String::new();
                    peer.read_line(&mut line).await.unwrap();
                    let request: Value = serde_json::from_str(&line).unwrap();
                    assert_eq!(request["operation"], "capabilities");
                    peer.get_mut().write_all(&kv_ipc::agent::encode_line(&json!({"id":request["id"],"ok":true,"device_key_protocol":DEVICE_KEY_PROTOCOL}))).await.unwrap();
                }
                let mut line = String::new();
                peer.read_line(&mut line).await.unwrap();
                let request: Value = serde_json::from_str(&line).unwrap();
                match expected {
                    Some(bytes) if !bytes.is_empty() => {
                        assert_eq!(request["input_len"], bytes.len());
                        assert!(request.get("data").is_none());
                        let mut received = vec![0; bytes.len()];
                        peer.read_exact(&mut received).await.unwrap();
                        assert!(received == bytes);
                    }
                    Some(_) => assert_eq!(request["data"], ""),
                    None => assert!(request.get("data").is_none()),
                }
                let mut header = json!({"id":request["id"],"ok":ok});
                if payload {
                    header["len"] = json!(3);
                }
                peer.get_mut()
                    .write_all(&kv_ipc::agent::encode_line(&header))
                    .await
                    .unwrap();
                if payload {
                    peer.get_mut().write_all(&[1, 2, 3]).await.unwrap();
                }
            });
            let mut request = json!({"op":"device_key","operation":"sign"});
            if let Some(input) = input {
                request["data"] = json!(super::super::encode_b64(&input));
            }
            let result = transport.exchange(request);
            if ok && payload {
                assert!(result.unwrap().as_slice() == [1, 2, 3]);
            } else {
                assert_eq!(result, Err(DeviceKeyError::OperationFailed));
            }
            agent.await.unwrap();
        }
        let transport = transport();
        assert_eq!(
            transport.exchange(json!({"op":"device_key","input_len":1})),
            Err(DeviceKeyError::Unavailable)
        );
    }
}
