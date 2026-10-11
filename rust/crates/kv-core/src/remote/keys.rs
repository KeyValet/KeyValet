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
    fn presence_kind(&self) -> PresenceKind;
    fn key_kind(&self) -> KeyKind;
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

impl SoftwareDeviceKey {
    pub fn generate_p256() -> Self {
        Self(SoftwareKey::P256(p256::SecretKey::random(&mut OsRng)))
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
