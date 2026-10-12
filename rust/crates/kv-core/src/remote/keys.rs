use super::types::*;
use super::{RemoteError, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use p256::elliptic_curve::sec1::ToEncodedPoint;
use rand_core::OsRng;
use rsa::pkcs8::DecodePrivateKey;
use rsa::traits::PublicKeyParts;
use rsa::{BigUint, RsaPrivateKey, RsaPublicKey};
use sha2::Sha256;
use zeroize::Zeroizing;

pub trait MessageSigner {
    fn sign(&self, alg: SignatureAlgorithm, payload: &[u8]) -> Result<Vec<u8>>;
}

// CONTRACT: §3.1 / A.1: hardware providers return raw P-256 ECDH x, big-endian, padded to 32 bytes.
pub trait EcdhProvider {
    fn public_sec1(&self) -> Result<Vec<u8>>;
    fn ecdh(&self, peer_pub: &[u8]) -> Result<Zeroizing<[u8; 32]>>;
}

pub trait DeviceKeyProvider {
    fn sign(&self, alg: SignatureAlgorithm, payload: &[u8]) -> Result<Vec<u8>>;
    fn ecdh(&self, peer_pub: &[u8]) -> Result<Zeroizing<[u8; 32]>>;
    fn public_jwk(&self) -> Result<PublicJwk>;
    fn identity_sign_jwk(&self) -> Result<Option<PublicJwk>> {
        Ok(None)
    }
    fn presence_kind(&self) -> PresenceKind;
    fn key_kind(&self) -> KeyKind;
}

/// The metadata vault uses a separate KDF domain and a public, randomly generated peer point.
pub fn metadata_master_key(
    identity: &dyn DeviceKeyProvider,
    peer: &[u8],
) -> Result<Zeroizing<[u8; 32]>> {
    let shared = identity.ecdh(peer)?;
    let mut output = Zeroizing::new([0u8; 32]);
    hkdf::Hkdf::<Sha256>::new(None, shared.as_ref())
        .expand(b"keyvalet/remote-metadata/master/v1", output.as_mut())
        .map_err(|_| RemoteError::InvalidKey)?;
    Ok(output)
}

// CONTRACT: §3.1 / §13.1: this adapter lets kv-platform implement the IPC-level hardware interface.
impl<T: kv_ipc::remote::DeviceKeyProvider + ?Sized> DeviceKeyProvider for T {
    fn sign(&self, alg: SignatureAlgorithm, payload: &[u8]) -> Result<Vec<u8>> {
        kv_ipc::remote::DeviceKeyProvider::sign(self, alg, payload).map_err(provider_error)
    }
    fn ecdh(&self, peer_pub: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
        kv_ipc::remote::DeviceKeyProvider::ecdh(self, peer_pub).map_err(provider_error)
    }
    fn public_jwk(&self) -> Result<PublicJwk> {
        let jwk = kv_ipc::remote::DeviceKeyProvider::public_jwk(self).map_err(provider_error)?;
        serde_json::from_value(jwk).map_err(|_| RemoteError::InvalidKey)
    }
    fn identity_sign_jwk(&self) -> Result<Option<PublicJwk>> {
        kv_ipc::remote::DeviceKeyProvider::identity_sign_jwk(self)
            .map_err(provider_error)?
            .map(|jwk| serde_json::from_value(jwk).map_err(|_| RemoteError::InvalidKey))
            .transpose()
    }
    fn presence_kind(&self) -> PresenceKind {
        let kind = kv_ipc::remote::DeviceKeyProvider::presence_kind(self);
        serde_json::from_value(serde_json::Value::String(kind.into()))
            .unwrap_or_else(|_| PresenceKind::Unknown(kind.into()))
    }
    fn key_kind(&self) -> KeyKind {
        let kind = kv_ipc::remote::DeviceKeyProvider::key_kind(self);
        serde_json::from_value(serde_json::Value::String(kind.into()))
            .unwrap_or_else(|_| KeyKind::Unknown(kind.into()))
    }
}

fn provider_error(error: kv_ipc::remote::DeviceKeyError) -> RemoteError {
    match error {
        kv_ipc::remote::DeviceKeyError::InvalidKey => RemoteError::InvalidKey,
        kv_ipc::remote::DeviceKeyError::Unavailable => RemoteError::KeyUnavailable,
        kv_ipc::remote::DeviceKeyError::UnsupportedAlgorithm => RemoteError::UnsupportedAlgorithm,
        kv_ipc::remote::DeviceKeyError::OperationFailed => RemoteError::KeyOperationFailed,
    }
}

impl<T: DeviceKeyProvider + ?Sized> MessageSigner for T {
    fn sign(&self, alg: SignatureAlgorithm, payload: &[u8]) -> Result<Vec<u8>> {
        DeviceKeyProvider::sign(self, alg, payload)
    }
}

impl<T: DeviceKeyProvider + ?Sized> EcdhProvider for T {
    fn public_sec1(&self) -> Result<Vec<u8>> {
        p256_public_sec1(&self.public_jwk()?)
    }
    fn ecdh(&self, peer_pub: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
        DeviceKeyProvider::ecdh(self, peer_pub)
    }
}

enum SoftwareKey {
    P256(p256::SecretKey),
    Rsa(Box<RsaPrivateKey>),
}

pub struct SoftwareDeviceKey(SoftwareKey);

pub struct SoftwareDeviceKeyProvider(SoftwareDeviceKey);

impl SoftwareDeviceKey {
    /// Adapt an explicitly selected software key to the lower-layer hardware interface.
    pub fn into_provider(self) -> SoftwareDeviceKeyProvider {
        SoftwareDeviceKeyProvider(self)
    }

    pub fn generate_p256() -> Self {
        Self(SoftwareKey::P256(p256::SecretKey::random(&mut OsRng)))
    }

    /// Provision explicit software identity material for storage inside an authenticated vault.
    pub fn generate_p256_material() -> (Self, Zeroizing<[u8; 32]>) {
        let key = p256::SecretKey::random(&mut OsRng);
        let bytes = Zeroizing::new(key.to_bytes().into());
        (Self(SoftwareKey::P256(key)), bytes)
    }

    pub fn from_p256_bytes(bytes: &[u8]) -> Result<Self> {
        p256::SecretKey::from_slice(bytes)
            .map(|key| Self(SoftwareKey::P256(key)))
            .map_err(|_| RemoteError::InvalidKey)
    }

    pub fn generate_rsa2048() -> Result<Self> {
        RsaPrivateKey::new(&mut OsRng, 2048)
            .map(|key| Self(SoftwareKey::Rsa(Box::new(key))))
            .map_err(|_| RemoteError::InvalidKey)
    }

    pub fn from_rsa_pkcs8_der(bytes: &[u8]) -> Result<Self> {
        let key = RsaPrivateKey::from_pkcs8_der(bytes).map_err(|_| RemoteError::InvalidKey)?;
        key.validate().map_err(|_| RemoteError::InvalidKey)?;
        if key.n().bits() != 2048 {
            return Err(RemoteError::InvalidKey);
        }
        Ok(Self(SoftwareKey::Rsa(Box::new(key))))
    }
}

// CONTRACT: §13.1 / Appendix F: consumers share the IPC provider without a core dependency cycle.
impl kv_ipc::remote::DeviceKeyProvider for SoftwareDeviceKeyProvider {
    fn sign(
        &self,
        alg: SignatureAlgorithm,
        payload: &[u8],
    ) -> std::result::Result<Vec<u8>, kv_ipc::remote::DeviceKeyError> {
        DeviceKeyProvider::sign(&self.0, alg, payload).map_err(software_provider_error)
    }

    fn ecdh(
        &self,
        peer_pub: &[u8],
    ) -> std::result::Result<Zeroizing<[u8; 32]>, kv_ipc::remote::DeviceKeyError> {
        DeviceKeyProvider::ecdh(&self.0, peer_pub).map_err(software_provider_error)
    }

    fn public_jwk(&self) -> std::result::Result<serde_json::Value, kv_ipc::remote::DeviceKeyError> {
        let jwk = DeviceKeyProvider::public_jwk(&self.0).map_err(software_provider_error)?;
        serde_json::to_value(jwk).map_err(|_| kv_ipc::remote::DeviceKeyError::InvalidKey)
    }

    fn presence_kind(&self) -> &str {
        "none"
    }

    fn key_kind(&self) -> &str {
        "software"
    }
}

fn software_provider_error(error: RemoteError) -> kv_ipc::remote::DeviceKeyError {
    use kv_ipc::remote::DeviceKeyError;
    match error {
        RemoteError::InvalidKey | RemoteError::InvalidEncoding => DeviceKeyError::InvalidKey,
        RemoteError::UnsupportedAlgorithm => DeviceKeyError::UnsupportedAlgorithm,
        RemoteError::KeyUnavailable => DeviceKeyError::Unavailable,
        _ => DeviceKeyError::OperationFailed,
    }
}

impl DeviceKeyProvider for SoftwareDeviceKey {
    fn sign(&self, alg: SignatureAlgorithm, payload: &[u8]) -> Result<Vec<u8>> {
        use p256::ecdsa::signature::{SignatureEncoding, Signer};
        match (&self.0, alg) {
            (SoftwareKey::P256(key), SignatureAlgorithm::ES256) => {
                let key = p256::ecdsa::SigningKey::from(key);
                let sig: p256::ecdsa::Signature = key
                    .try_sign(payload)
                    .map_err(|_| RemoteError::InvalidSignature)?;
                Ok(sig.to_bytes().to_vec())
            }
            (SoftwareKey::Rsa(key), SignatureAlgorithm::RS256) => {
                let signer = rsa::pkcs1v15::SigningKey::<Sha256>::new(key.as_ref().clone());
                signer
                    .try_sign(payload)
                    .map(|sig| sig.to_vec())
                    .map_err(|_| RemoteError::InvalidSignature)
            }
            _ => Err(RemoteError::UnsupportedAlgorithm),
        }
    }

    fn ecdh(&self, peer_pub: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
        match &self.0 {
            SoftwareKey::P256(key) => {
                let public = parse_sec1(peer_pub)?;
                let shared =
                    p256::ecdh::diffie_hellman(key.to_nonzero_scalar(), public.as_affine());
                Ok(Zeroizing::new((*shared.raw_secret_bytes()).into()))
            }
            SoftwareKey::Rsa(_) => Err(RemoteError::UnsupportedAlgorithm),
        }
    }

    fn public_jwk(&self) -> Result<PublicJwk> {
        Ok(match &self.0 {
            SoftwareKey::P256(key) => {
                let point = key.public_key().to_encoded_point(false);
                PublicJwk {
                    kty: "EC".into(),
                    crv: Optional::Value("P-256".into()),
                    x: Optional::Value(encode_b64(point.x().ok_or(RemoteError::InvalidKey)?)),
                    y: Optional::Value(encode_b64(point.y().ok_or(RemoteError::InvalidKey)?)),
                    n: Optional::Missing,
                    e: Optional::Missing,
                    extra: Extra::new(),
                }
            }
            SoftwareKey::Rsa(key) => PublicJwk {
                kty: "RSA".into(),
                crv: Optional::Missing,
                x: Optional::Missing,
                y: Optional::Missing,
                n: Optional::Value(encode_b64(&key.n().to_bytes_be())),
                e: Optional::Value(encode_b64(&key.e().to_bytes_be())),
                extra: Extra::new(),
            },
        })
    }

    fn presence_kind(&self) -> PresenceKind {
        PresenceKind::None
    }
    fn key_kind(&self) -> KeyKind {
        KeyKind::Software
    }
}

pub fn encode_b64(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

pub fn decode_b64(text: &str) -> Result<Vec<u8>> {
    URL_SAFE_NO_PAD
        .decode(text)
        .map_err(|_| RemoteError::InvalidEncoding)
}

pub fn parse_sec1(bytes: &[u8]) -> Result<p256::PublicKey> {
    if bytes.len() != 65 || bytes[0] != 4 {
        return Err(RemoteError::InvalidKey);
    }
    p256::PublicKey::from_sec1_bytes(bytes).map_err(|_| RemoteError::InvalidKey)
}

fn public_only(jwk: &PublicJwk) -> Result<()> {
    if ["d", "p", "q", "dp", "dq", "qi", "oth", "k"]
        .iter()
        .any(|key| jwk.extra.contains_key(*key))
    {
        return Err(RemoteError::InvalidKey);
    }
    Ok(())
}

pub fn p256_public_sec1(jwk: &PublicJwk) -> Result<Vec<u8>> {
    public_only(jwk)?;
    if jwk.kty != "EC" || jwk.crv.as_value().map(String::as_str) != Some("P-256") {
        return Err(RemoteError::InvalidKey);
    }
    let x = decode_b64(jwk.x.as_value().ok_or(RemoteError::InvalidKey)?)?;
    let y = decode_b64(jwk.y.as_value().ok_or(RemoteError::InvalidKey)?)?;
    if x.len() != 32 || y.len() != 32 {
        return Err(RemoteError::InvalidKey);
    }
    let mut bytes = vec![4];
    bytes.extend(x);
    bytes.extend(y);
    parse_sec1(&bytes)?;
    Ok(bytes)
}

pub fn rsa_public_key(jwk: &PublicJwk) -> Result<RsaPublicKey> {
    public_only(jwk)?;
    if jwk.kty != "RSA" {
        return Err(RemoteError::InvalidKey);
    }
    let n = decode_b64(jwk.n.as_value().ok_or(RemoteError::InvalidKey)?)?;
    let e = decode_b64(jwk.e.as_value().ok_or(RemoteError::InvalidKey)?)?;
    if n.len() != 256 || n[0] < 128 || e.is_empty() || e[0] == 0 || e.len() > 4 {
        return Err(RemoteError::InvalidKey);
    }
    RsaPublicKey::new(BigUint::from_bytes_be(&n), BigUint::from_bytes_be(&e))
        .map_err(|_| RemoteError::InvalidKey)
}

pub fn verify_signature(
    alg: SignatureAlgorithm,
    key: &PublicJwk,
    payload: &[u8],
    signature: &[u8],
) -> Result<()> {
    use p256::ecdsa::signature::Verifier;
    match alg {
        SignatureAlgorithm::ES256 => {
            let verifier = p256::ecdsa::VerifyingKey::from_sec1_bytes(&p256_public_sec1(key)?)
                .map_err(|_| RemoteError::InvalidKey)?;
            let sig = p256::ecdsa::Signature::from_slice(signature)
                .map_err(|_| RemoteError::InvalidSignature)?;
            verifier
                .verify(payload, &sig)
                .map_err(|_| RemoteError::InvalidSignature)
        }
        SignatureAlgorithm::RS256 => {
            let verifier = rsa::pkcs1v15::VerifyingKey::<Sha256>::new(rsa_public_key(key)?);
            let sig = rsa::pkcs1v15::Signature::try_from(signature)
                .map_err(|_| RemoteError::InvalidSignature)?;
            verifier
                .verify(payload, &sig)
                .map_err(|_| RemoteError::InvalidSignature)
        }
    }
}

/// K1: a present dk_sig is authoritative. Malformed/null/unsupported keys never use dk_pub.
pub fn identity_verifying_jwk(device: &DeviceRecord) -> Result<&PublicJwk> {
    let public = match &device.dk_sig {
        Optional::Missing => &device.dk_pub,
        Optional::Value(key) if key.alg == SignatureAlgorithm::ES256 => &key.r#pub,
        Optional::Value(_) => return Err(RemoteError::UnsupportedAlgorithm),
        Optional::Null => return Err(RemoteError::InvalidKey),
    };
    p256_public_sec1(public)?;
    Ok(public)
}

/// Verify every device identity signature using the authenticated device record.
pub fn verify_identity_signature(
    device: &DeviceRecord,
    payload: &[u8],
    signature: &[u8],
) -> Result<()> {
    verify_signature(
        SignatureAlgorithm::ES256,
        identity_verifying_jwk(device)?,
        payload,
        signature,
    )
}

/// Pin both HPKE and identity signing keys when reopening authenticated provider metadata.
pub fn verify_identity_provider(
    device: &DeviceRecord,
    provider: &dyn DeviceKeyProvider,
) -> Result<()> {
    identity_verifying_jwk(device)?;
    if provider.public_jwk()? != device.dk_pub
        || provider.identity_sign_jwk()?.as_ref() != device.dk_sig.as_value().map(|key| &key.r#pub)
    {
        return Err(RemoteError::WrongSender);
    }
    Ok(())
}

pub fn sign_object<T: serde::Serialize>(
    value: &T,
    alg: SignatureAlgorithm,
    signer: &(impl MessageSigner + ?Sized),
) -> Result<String> {
    Ok(encode_b64(
        &signer.sign(alg, &super::canonical::signed_payload(value)?)?,
    ))
}

pub fn verify_object<T: serde::Serialize>(
    value: &T,
    signature: &str,
    key: &ApprovalKey,
) -> Result<()> {
    verify_signature(
        key.alg,
        &key.r#pub,
        &super::canonical::signed_payload(value)?,
        &decode_b64(signature)?,
    )
}

#[cfg(test)]
mod identity_tests {
    use super::super::canonical::{from_json, jcs, sha256_hex};
    use super::*;
    use serde_json::{json, Value};

    fn fixture(name: &str) -> Value {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("testdata/remote")
            .join(name);
        from_json(&std::fs::read(path).unwrap()).unwrap()
    }
    fn record(value: &Value) -> DeviceRecord {
        serde_json::from_value(value.clone()).unwrap()
    }
    fn outcome(result: Result<()>) -> Value {
        match result {
            Ok(()) => json!({"ok":true}),
            Err(error) => json!({"error":error.code()}),
        }
    }

    #[test]
    fn device_record_with_dk_sig_vectors() {
        for name in [
            "device_record_with_dk_sig_valid.json",
            "device_record_with_dk_sig_legacy.json",
        ] {
            let vector = fixture(name);
            let device = record(&vector["device"]);
            let bytes = jcs(&device).unwrap();
            assert_eq!(
                String::from_utf8(bytes.clone()).unwrap(),
                vector["expect"]["canonical"],
                "{name}"
            );
            if let Some(expected) = vector["expect"].get("digest") {
                assert_eq!(sha256_hex(&bytes), *expected, "{name}");
            }
            let payload = jcs(&vector["proof"]).unwrap();
            let signature = decode_b64(vector["sig"].as_str().unwrap()).unwrap();
            assert_eq!(
                outcome(verify_identity_signature(&device, &payload, &signature)),
                json!({"ok":vector["expect"]["ok"]}),
                "{name}"
            );
            assert_eq!(
                serde_json::to_value(&device).unwrap(),
                vector["device"],
                "{name}"
            );
        }
        let vector = fixture("device_record_with_dk_sig_wrong_dk.json");
        let device = record(&vector["device"]);
        let payload = vector["payload"].as_str().unwrap().as_bytes();
        let signature = decode_b64(vector["sig"].as_str().unwrap()).unwrap();
        assert_eq!(
            verify_identity_signature(&device, payload, &signature).is_ok(),
            vector["expect"]["identity_ok"]
        );
        assert_eq!(
            verify_signature(
                SignatureAlgorithm::ES256,
                &device.dk_pub,
                payload,
                &signature
            )
            .unwrap_err()
            .code(),
            vector["expect"]["dk_error"]
        );
        let vector = fixture("device_record_with_dk_sig_tampered.json");
        assert_eq!(
            outcome(verify_identity_signature(
                &record(&vector["device"]),
                &jcs(&vector["proof"]).unwrap(),
                &decode_b64(vector["sig"].as_str().unwrap()).unwrap()
            )),
            vector["expect"]
        );
    }

    #[test]
    fn device_record_with_dk_sig_envelope_keeps_hpke_key_and_legacy_vectors() {
        let vector = fixture("device_record_with_dk_sig_envelope.json");
        let keys = fixture("test_keys.json");
        let recipient = SoftwareDeviceKey::from_p256_bytes(
            &decode_b64(keys["recipient"]["private_scalar"].as_str().unwrap()).unwrap(),
        )
        .unwrap();
        let sender = record(&vector["sender"]);
        let envelope: super::super::Envelope =
            serde_json::from_value(vector["envelope"].clone()).unwrap();
        assert_eq!(
            super::super::envelope::verify(&envelope, &sender.dk_pub)
                .unwrap_err()
                .code(),
            vector["expect"]["dk_error"]
        );
        let opened = super::super::envelope::open(
            &envelope,
            vector["recipient"]["device_id"].as_str().unwrap(),
            &recipient,
            &sender,
            vector["now"].as_i64().unwrap(),
        );
        assert_eq!(opened.is_ok(), vector["expect"]["open_ok"]);
        assert_eq!(
            String::from_utf8(opened.unwrap().to_vec()).unwrap(),
            vector["expect"]["plaintext"]
        );
    }

    #[test]
    fn present_invalid_identity_key_never_uses_dk_or_approval_keys() {
        let vector = fixture("device_record_with_dk_sig_valid.json");
        let mut device = record(&vector["device"]);
        let keys = fixture("test_keys.json");
        let dk = SoftwareDeviceKey::from_p256_bytes(
            &decode_b64(keys["recipient"]["private_scalar"].as_str().unwrap()).unwrap(),
        )
        .unwrap();
        let payload = b"identity challenge";
        let dk_signature =
            DeviceKeyProvider::sign(&dk, SignatureAlgorithm::ES256, payload).unwrap();
        assert!(verify_identity_signature(&device, payload, &dk_signature).is_err());
        let valid = device.dk_sig.clone();
        device.dk_sig = Optional::Null;
        assert!(verify_identity_signature(&device, payload, &dk_signature).is_err());
        device.dk_sig = valid.clone();
        if let Optional::Value(key) = &mut device.dk_sig {
            key.alg = SignatureAlgorithm::RS256;
        }
        assert!(verify_identity_signature(&device, payload, &dk_signature).is_err());
        device.dk_sig = valid.clone();
        if let Optional::Value(key) = &mut device.dk_sig {
            key.r#pub = serde_json::from_value(keys["rsa_public_jwk"].clone()).unwrap();
        }
        assert!(verify_identity_signature(&device, payload, &dk_signature).is_err());
        device.dk_sig = valid;
        if let Optional::Value(key) = &mut device.dk_sig {
            key.r#pub.extra.insert("d".into(), json!("private"));
        }
        assert!(verify_identity_signature(&device, payload, &dk_signature).is_err());
        device.dk_sig = Optional::Missing;
        verify_identity_signature(&device, payload, &dk_signature).unwrap();
    }

    #[test]
    fn dk_sig_schema_covers_nested_device_records_and_preserves_extensions() {
        let vector = fixture("device_record_with_dk_sig_valid.json");
        for (schema, value) in [
            ("device_record", vector["device"].clone()),
            ("register_device_request", vector["device"].clone()),
            (
                "relay_pair_start_request",
                json!({"token_hash":"0".repeat(64),"initiator":vector["device"],"exp":1760200600}),
            ),
            (
                "relay_pair_complete_request",
                json!({"token":"A".repeat(22),"joiner":vector["device"]}),
            ),
        ] {
            let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("schemas/remote")
                .join(format!("{schema}.schema.json"));
            let document: Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
            let validator = jsonschema::JSONSchema::options()
                .with_draft(jsonschema::Draft::Draft7)
                .compile(&document)
                .unwrap();
            assert!(validator.is_valid(&value), "{schema}");
        }
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("schemas/remote/device_record.schema.json");
        let document: Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
        let validator = jsonschema::JSONSchema::options()
            .with_draft(jsonschema::Draft::Draft7)
            .compile(&document)
            .unwrap();
        for bad in [
            Value::Null,
            json!({"pub":vector["device"]["dk_pub"],"alg":"RS256"}),
            json!({"pub":fixture("test_keys.json")["rsa_public_jwk"],"alg":"ES256"}),
        ] {
            let mut device = vector["device"].clone();
            device["dk_sig"] = bad;
            assert!(!validator.is_valid(&device));
        }
        let a = record(&vector["device"]);
        let mut b = a.clone();
        b.dk_sig = Optional::Missing;
        assert!(!super::super::validation::same_device_authority(&a, &b));
        b = a.clone();
        if let Optional::Value(key) = &mut b.dk_sig {
            key.extra
                .insert("future_key".into(), json!({"binding":"tampered"}));
        }
        assert!(!super::super::validation::same_device_authority(&a, &b));
    }
}
