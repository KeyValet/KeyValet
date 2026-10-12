use kv_core::remote::{self as core, DeviceKeyProvider as CoreProvider, SoftwareDeviceKey};
use kv_ipc::remote::{DeviceKeyError, DeviceKeyProvider, SignatureAlgorithm};
use serde_json::{json, Value};
use zeroize::Zeroizing;

#[cfg(target_os = "macos")]
mod linux {
    pub fn trusted_command(_: &str) -> std::io::Result<std::process::Command> {
        Err(std::io::Error::other("Linux command runner unavailable"))
    }
}
#[cfg(target_os = "macos")]
mod remote_process {
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/remote_process.rs"
    ));
}
#[cfg(target_os = "macos")]
mod device_key {
    pub use kv_platform::device_key::*;
    pub mod tpm {
        include!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/src/device_key/tpm.rs"
        ));
    }
}

struct W0Key(SoftwareDeviceKey);
impl DeviceKeyProvider for W0Key {
    fn sign(&self, alg: SignatureAlgorithm, payload: &[u8]) -> Result<Vec<u8>, DeviceKeyError> {
        CoreProvider::sign(&self.0, alg, payload).map_err(|_| DeviceKeyError::OperationFailed)
    }
    fn ecdh(&self, peer: &[u8]) -> Result<Zeroizing<[u8; 32]>, DeviceKeyError> {
        CoreProvider::ecdh(&self.0, peer).map_err(|_| DeviceKeyError::InvalidKey)
    }
    fn public_jwk(&self) -> Result<Value, DeviceKeyError> {
        serde_json::to_value(
            CoreProvider::public_jwk(&self.0).map_err(|_| DeviceKeyError::InvalidKey)?,
        )
        .map_err(|_| DeviceKeyError::InvalidKey)
    }
    fn presence_kind(&self) -> &str {
        "none"
    }
    fn key_kind(&self) -> &str {
        "software"
    }
}
fn fixture(name: &str) -> Value {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../kv-core/testdata/remote")
        .join(name);
    serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap()
}
fn fixed(keys: &Value, name: &str) -> W0Key {
    W0Key(
        SoftwareDeviceKey::from_p256_bytes(
            &core::keys::decode_b64(keys[name]["private_scalar"].as_str().unwrap()).unwrap(),
        )
        .unwrap(),
    )
}
fn hex(value: &str) -> Vec<u8> {
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|bytes| u8::from_str_radix(std::str::from_utf8(bytes).unwrap(), 16).unwrap())
        .collect()
}

#[cfg(unix)]
#[test]
fn explicit_software_storage_uses_w0_for_signing_and_ecdh() {
    use kv_platform::device_key::software::SoftwareFileKey;
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let path = dir.path().join("remote.key");
    let factory = |bytes: &[u8; 32]| {
        SoftwareDeviceKey::from_p256_bytes(bytes)
            .map(W0Key)
            .map_err(|_| DeviceKeyError::InvalidKey)
    };
    let created = SoftwareFileKey::create(&path, factory).unwrap();
    let opened = SoftwareFileKey::open(&path, factory).unwrap();
    let public = CoreProvider::public_jwk(&opened).unwrap();
    let payload = b"KeyValet W0/W1 interoperability";
    core::keys::verify_signature(
        SignatureAlgorithm::ES256,
        &public,
        payload,
        &DeviceKeyProvider::sign(&created, SignatureAlgorithm::ES256, payload).unwrap(),
    )
    .unwrap();
    let peer = fixed(&fixture("test_keys.json"), "recipient");
    let a = DeviceKeyProvider::ecdh(
        &opened,
        &core::keys::p256_public_sec1(&CoreProvider::public_jwk(&peer).unwrap()).unwrap(),
    )
    .unwrap();
    let b =
        DeviceKeyProvider::ecdh(&peer, &core::keys::p256_public_sec1(&public).unwrap()).unwrap();
    assert!(*a == *b);
    assert_eq!(DeviceKeyProvider::key_kind(&opened), "software");
}

#[test]
fn w0_provider_uses_rfc9180_keypairs_and_envelope_expectations() {
    let vector = fixture("rfc9180_p256_base.json");
    let recipient =
        W0Key(SoftwareDeviceKey::from_p256_bytes(&hex(vector["skRm"].as_str().unwrap())).unwrap());
    let enc = hex(vector["expect"]["enc"].as_str().unwrap());
    let dh = DeviceKeyProvider::ecdh(&recipient, &enc).unwrap();
    let ephemeral =
        W0Key(SoftwareDeviceKey::from_p256_bytes(&hex(vector["skEm"].as_str().unwrap())).unwrap());
    let peer = hex(vector["pkRm"].as_str().unwrap());
    assert_eq!(
        core::keys::p256_public_sec1(&CoreProvider::public_jwk(&ephemeral).unwrap()).unwrap(),
        hex(vector["expect"]["pkEm"].as_str().unwrap())
    );
    assert_eq!(
        core::keys::p256_public_sec1(&CoreProvider::public_jwk(&recipient).unwrap()).unwrap(),
        hex(vector["expect"]["pkRm"].as_str().unwrap())
    );
    assert!(*dh == *DeviceKeyProvider::ecdh(&ephemeral, &peer).unwrap());
    let vector = fixture("envelope_roundtrip.json");
    let envelope: core::Envelope = serde_json::from_value(vector["envelope"].clone()).unwrap();
    let sender: core::DeviceRecord = serde_json::from_value(vector["sender"].clone()).unwrap();
    let recipient = fixed(&vector["keys"], "recipient");
    let plaintext = core::envelope::open(
        &envelope,
        &envelope.to,
        &recipient,
        &sender,
        vector["now"].as_i64().unwrap(),
    )
    .unwrap();
    assert!(plaintext.as_slice() == vector["expect"]["plaintext"].as_str().unwrap().as_bytes());
    assert_eq!(
        core::envelope::verify(&envelope, &sender.dk_pub).is_ok(),
        vector["expect"]["signature_ok"].as_bool().unwrap()
    );
}

#[test]
fn hello_rs256_verifier_accepts_w0_software_and_vector_signatures() {
    use rsa::pkcs8::EncodePublicKey;
    let keys = fixture("test_keys.json");
    let software = SoftwareDeviceKey::from_rsa_pkcs8_der(
        &core::keys::decode_b64(keys["rsa_pkcs8_der"].as_str().unwrap()).unwrap(),
    )
    .unwrap();
    let public = CoreProvider::public_jwk(&software).unwrap();
    let der = core::keys::rsa_public_key(&public)
        .unwrap()
        .to_public_key_der()
        .unwrap();
    let payload = b"An approval message longer than the vault's fixed challenge";
    let signature = CoreProvider::sign(&software, SignatureAlgorithm::RS256, payload).unwrap();
    kv_agent::hello_signature::verify(der.as_bytes(), payload, &signature).unwrap();
    assert!(
        kv_agent::hello_signature::verify(der.as_bytes(), b"changed approval", &signature).is_err()
    );
    let vector = fixture("rs256_decision.json");
    let payload = core::canonical::signed_payload(&vector["decision"]).unwrap();
    let signature = core::keys::decode_b64(vector["decision"]["sig"].as_str().unwrap()).unwrap();
    assert_eq!(
        kv_agent::hello_signature::verify(der.as_bytes(), &payload, &signature).is_ok(),
        vector["expect"]["ok"].as_bool().unwrap()
    );
}

#[cfg(target_os = "macos")]
#[test]
fn agent_providers_use_w0_signatures_ecdh_and_role_pinning() {
    use kv_platform::device_key::{
        agent::{encode_reply, AgentDeviceKey, KeyTransport},
        KeyRole,
    };
    struct Fake {
        key: W0Key,
        role: KeyRole,
        altered: bool,
    }
    impl KeyTransport for Fake {
        fn exchange(&self, request: Value) -> Result<Zeroizing<Vec<u8>>, DeviceKeyError> {
            let mut metadata = json!({"version":1,"role":self.role.as_str(),"key_kind":"secure_enclave",
                "key_blob":"AA","public_jwk":DeviceKeyProvider::public_jwk(&self.key)?});
            let data = match request["operation"].as_str() {
                Some("create") => Zeroizing::new(vec![]),
                Some("sign") => Zeroizing::new(DeviceKeyProvider::sign(
                    &self.key,
                    SignatureAlgorithm::ES256,
                    &core::keys::decode_b64(request["data"].as_str().unwrap()).unwrap(),
                )?),
                Some("ecdh") => Zeroizing::new(
                    DeviceKeyProvider::ecdh(
                        &self.key,
                        &core::keys::decode_b64(request["data"].as_str().unwrap()).unwrap(),
                    )?
                    .to_vec(),
                ),
                _ => return Err(DeviceKeyError::OperationFailed),
            };
            if self.altered && request["operation"] != "create" {
                metadata["role"] = json!("strong");
            }
            encode_reply(&data, &metadata)
        }
    }
    for role in [KeyRole::Identity, KeyRole::Quick, KeyRole::Strong] {
        let key = AgentDeviceKey::create(
            Fake {
                key: fixed(&fixture("test_keys.json"), "sender"),
                role,
                altered: false,
            },
            role,
        )
        .unwrap();
        let public = CoreProvider::public_jwk(&key).unwrap();
        let signature =
            DeviceKeyProvider::sign(&key, SignatureAlgorithm::ES256, b"remote fixture").unwrap();
        core::keys::verify_signature(
            SignatureAlgorithm::ES256,
            &public,
            b"remote fixture",
            &signature,
        )
        .unwrap();
        assert_eq!(
            DeviceKeyProvider::sign(&key, SignatureAlgorithm::RS256, b"fixture"),
            Err(DeviceKeyError::UnsupportedAlgorithm)
        );
        let peer = fixed(&fixture("test_keys.json"), "recipient");
        let a = DeviceKeyProvider::ecdh(
            &key,
            &core::keys::p256_public_sec1(&CoreProvider::public_jwk(&peer).unwrap()).unwrap(),
        )
        .unwrap();
        let b = DeviceKeyProvider::ecdh(&peer, &core::keys::p256_public_sec1(&public).unwrap())
            .unwrap();
        assert!(*a == *b);
    }
    let altered = AgentDeviceKey::create(
        Fake {
            key: fixed(&fixture("test_keys.json"), "sender"),
            role: KeyRole::Identity,
            altered: true,
        },
        KeyRole::Identity,
    )
    .unwrap();
    assert_eq!(
        DeviceKeyProvider::sign(&altered, SignatureAlgorithm::ES256, b"fixture"),
        Err(DeviceKeyError::InvalidKey)
    );
}

#[cfg(target_os = "macos")]
struct Child;
#[cfg(target_os = "macos")]
impl kv_platform::device_key::agent::KeyTransport for Child {
    fn exchange(&self, request: Value) -> Result<Zeroizing<Vec<u8>>, DeviceKeyError> {
        use std::io::{Read, Write};
        use std::process::{Command, Stdio};
        let binary = std::path::Path::new(&std::env::var_os("CARGO_TARGET_DIR").unwrap())
            .join("debug/kv-touchid");
        let mut child = Command::new(binary)
            .arg("--device-key")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|_| DeviceKeyError::Unavailable)?;
        child
            .stdin
            .take()
            .unwrap()
            .write_all(&serde_json::to_vec(&request).unwrap())
            .map_err(|_| DeviceKeyError::OperationFailed)?;
        let mut bytes = Zeroizing::new(Vec::new());
        child
            .stdout
            .take()
            .unwrap()
            .take(8193)
            .read_to_end(&mut bytes)
            .map_err(|_| DeviceKeyError::OperationFailed)?;
        if !child
            .wait()
            .map_err(|_| DeviceKeyError::OperationFailed)?
            .success()
            || bytes.len() > 8192
        {
            return Err(DeviceKeyError::OperationFailed);
        }
        Ok(bytes)
    }
}

/// CARGO_TARGET_DIR=target-w1 python3 crates/kv-platform/tests/support/check_w0.py --ignored remote_se_w0
/// Run from an unlocked Apple Silicon Mac owner GUI session. Keys are disposable.
#[cfg(target_os = "macos")]
#[test]
#[ignore = "Requires Secure Enclave and an unlocked GUI session"]
fn remote_se_w0() {
    use kv_platform::device_key::{agent::AgentDeviceKey, KeyRole};
    for role in [KeyRole::Identity, KeyRole::Quick] {
        let key = AgentDeviceKey::create(Child, role).unwrap();
        let public = CoreProvider::public_jwk(&key).unwrap();
        for payload in [b"W0/W1 SE signature".to_vec(), vec![42; 80 * 1024]] {
            let signature =
                DeviceKeyProvider::sign(&key, SignatureAlgorithm::ES256, &payload).unwrap();
            core::keys::verify_signature(SignatureAlgorithm::ES256, &public, &payload, &signature)
                .unwrap();
        }
        hardware_matches_w0(&key);
    }
}

/// Run from the unlocked Mac owner GUI session and complete the OS user-presence prompt.
/// CARGO_TARGET_DIR=target-w1 python3 crates/kv-platform/tests/support/check_w0.py --ignored remote_se_strong_w0
#[cfg(target_os = "macos")]
#[test]
#[ignore = "Requires Secure Enclave and an interactive Touch ID or password prompt"]
fn remote_se_strong_w0() {
    use kv_platform::device_key::{agent::AgentDeviceKey, KeyRole};
    let key = AgentDeviceKey::create(Child, KeyRole::Strong).unwrap();
    let payload = b"W0/W1 Strong approval signature";
    let signature = DeviceKeyProvider::sign(&key, SignatureAlgorithm::ES256, payload).unwrap();
    core::keys::verify_signature(
        SignatureAlgorithm::ES256,
        &CoreProvider::public_jwk(&key).unwrap(),
        payload,
        &signature,
    )
    .unwrap();
}

fn hardware_matches_w0(key: &dyn DeviceKeyProvider) {
    let public = CoreProvider::public_jwk(key).unwrap();
    let payload = b"W0 hardware interoperability";
    let signature = DeviceKeyProvider::sign(key, SignatureAlgorithm::ES256, payload).unwrap();
    core::keys::verify_signature(SignatureAlgorithm::ES256, &public, payload, &signature).unwrap();
    let peer = fixed(&fixture("test_keys.json"), "recipient");
    let a = DeviceKeyProvider::ecdh(
        key,
        &core::keys::p256_public_sec1(&CoreProvider::public_jwk(&peer).unwrap()).unwrap(),
    )
    .unwrap();
    let b =
        DeviceKeyProvider::ecdh(&peer, &core::keys::p256_public_sec1(&public).unwrap()).unwrap();
    assert!(*a == *b);
    let (enc, ct) = core::hpke::seal(
        &fixed(&fixture("test_keys.json"), "sender"),
        &core::keys::p256_public_sec1(&public).unwrap(),
        b"aad",
        payload,
    )
    .unwrap();
    assert!(core::hpke::open(key, &enc, b"aad", &ct).unwrap().as_slice() == payload);
}

/// Run on Linux as the TPM-authorized service user with /dev/tpmrm0 and trusted tpm2-tools.
/// CARGO_TARGET_DIR=target-w1 python3 crates/kv-platform/tests/support/check_w0.py --ignored remote_tpm_w0
#[cfg(target_os = "linux")]
#[test]
#[ignore = "Requires TPM 2.0 and trusted tpm2-tools"]
fn remote_tpm_w0() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let key = kv_platform::device_key::tpm::TpmDeviceKey::create(
        dir.path().into(),
        kv_platform::device_key::tpm::TrustedTpm,
    )
    .unwrap();
    hardware_matches_w0(&key);
}

/// Run on Windows 11 + TPM 2.0 from a LocalSystem worker terminal, after service startup.
/// CARGO_TARGET_DIR=target-w1 python3 crates/kv-platform/tests/support/check_w0.py --ignored remote_pcp_w0
#[cfg(windows)]
#[test]
#[ignore = "Requires Windows 11, TPM 2.0 and LocalSystem"]
fn remote_pcp_w0() {
    use kv_platform::device_key::{windows::PcpDeviceKey, KeyRole};
    struct Cleanup(Option<PcpDeviceKey>);
    impl Drop for Cleanup {
        fn drop(&mut self) {
            if let Some(key) = self.0.take() {
                let _ = key.delete();
            }
        }
    }
    let key = Cleanup(Some(PcpDeviceKey::create(KeyRole::Identity).unwrap()));
    hardware_matches_w0(key.0.as_ref().unwrap());
}
