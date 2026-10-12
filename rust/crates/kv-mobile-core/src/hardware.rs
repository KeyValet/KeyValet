//! The callback is native-only. Dart never receives its address or a signing operation.
use crate::ffi::KvKeyCallback;
use kv_core::remote::{
    keys::encode_b64, DeviceKeyProvider, Extra, KeyKind, Optional, PresenceKind, PublicJwk,
    RemoteError, SignatureAlgorithm,
};
use zeroize::Zeroizing;

pub(crate) struct NativeKey {
    pub slot: u32,
    pub callback: KvKeyCallback,
    pub kind: String,
}
impl NativeKey {
    fn operation(
        &self,
        op: u32,
        input: &[u8],
        size: usize,
    ) -> kv_core::remote::Result<Zeroizing<Vec<u8>>> {
        let mut output = Zeroizing::new(vec![0; size]);
        // SAFETY: kv_mobile_open requires a process-lifetime, thread-safe native callback.
        let length = unsafe {
            (self.callback)(
                self.slot,
                op,
                input.as_ptr(),
                input.len(),
                output.as_mut_ptr(),
                output.len(),
            )
        };
        if length < 0 || length as usize != size {
            return Err(RemoteError::KeyOperationFailed);
        }
        Ok(output)
    }
}
impl DeviceKeyProvider for NativeKey {
    fn sign(&self, alg: SignatureAlgorithm, payload: &[u8]) -> kv_core::remote::Result<Vec<u8>> {
        if alg != SignatureAlgorithm::ES256 {
            return Err(RemoteError::UnsupportedAlgorithm);
        }
        let signature = self.operation(1, payload, 64)?.to_vec();
        // Detect a stale key alias, wrong native key slot or malformed SDK signature before
        // a decision consumes pending state. This does not replace the hardware ACL.
        kv_core::remote::keys::verify_signature(alg, &self.public_jwk()?, payload, &signature)
            .map_err(|_| RemoteError::KeyOperationFailed)?;
        Ok(signature)
    }
    fn ecdh(&self, peer: &[u8]) -> kv_core::remote::Result<Zeroizing<[u8; 32]>> {
        if self.slot != 0 {
            return Err(RemoteError::UnsupportedAlgorithm);
        }
        let secret = self.operation(2, peer, 32)?;
        let mut output = Zeroizing::new([0; 32]);
        output.copy_from_slice(&secret);
        Ok(output)
    }
    fn public_jwk(&self) -> kv_core::remote::Result<PublicJwk> {
        let public = self.operation(0, &[], 65)?;
        kv_core::remote::keys::parse_sec1(&public)?;
        Ok(PublicJwk {
            kty: "EC".into(),
            crv: Optional::Value("P-256".into()),
            x: Optional::Value(encode_b64(&public[1..33])),
            y: Optional::Value(encode_b64(&public[33..])),
            n: Optional::Missing,
            e: Optional::Missing,
            extra: Extra::new(),
        })
    }
    fn presence_kind(&self) -> PresenceKind {
        if self.slot == 2 {
            PresenceKind::Biometric
        } else if self.slot == 1 {
            PresenceKind::Unlocked
        } else {
            PresenceKind::None
        }
    }
    fn key_kind(&self) -> KeyKind {
        serde_json::from_value(self.kind.clone().into())
            .unwrap_or(KeyKind::Unknown(self.kind.clone()))
    }
}
