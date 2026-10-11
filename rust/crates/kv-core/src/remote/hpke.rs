use super::keys::{parse_sec1, EcdhProvider};
use super::{RemoteError, Result};
use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes128Gcm, Nonce};
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

pub const INFO: &[u8] = b"keyvalet/envelope/v1";
pub const MAX_PLAINTEXT_BYTES: usize = 64 * 1024;
pub const TAG_BYTES: usize = 16;
const KEM_SUITE: &[u8] = b"KEM\x00\x10";
const HPKE_SUITE: &[u8] = b"HPKE\x00\x10\x00\x01\x00\x01";

// CONTRACT: §3.1 / A.1 / Appendix F: only base mode and the P-256/SHA-256/AES-128 suite.
pub fn seal(
    ephemeral: &impl EcdhProvider,
    recipient_pub: &[u8],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<(Vec<u8>, Vec<u8>)> {
    if plaintext.len() > MAX_PLAINTEXT_BYTES {
        return Err(RemoteError::PayloadTooLarge);
    }
    let enc = ephemeral.public_sec1()?;
    let shared = kem_shared(ephemeral, recipient_pub, &enc, recipient_pub)?;
    let mut context = BaseContext::new(shared.as_ref(), INFO)?;
    Ok((enc, context.seal(aad, plaintext)?))
}

pub fn open(
    recipient: &(impl EcdhProvider + ?Sized),
    enc: &[u8],
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    if ciphertext.len() > MAX_PLAINTEXT_BYTES + TAG_BYTES {
        return Err(RemoteError::PayloadTooLarge);
    }
    if ciphertext.len() < TAG_BYTES {
        return Err(RemoteError::DecryptionFailed);
    }
    let recipient_pub = recipient.public_sec1()?;
    let shared = kem_shared(recipient, enc, enc, &recipient_pub)?;
    BaseContext::new(shared.as_ref(), INFO)?.open(aad, ciphertext)
}

fn extract(suite: &[u8], salt: &[u8], label: &[u8], ikm: &[u8]) -> Zeroizing<[u8; 32]> {
    let mut input = Zeroizing::new(Vec::new());
    input.extend_from_slice(b"HPKE-v1");
    input.extend_from_slice(suite);
    input.extend_from_slice(label);
    input.extend_from_slice(ikm);
    let (prk, _) = Hkdf::<Sha256>::extract(Some(salt), &input);
    Zeroizing::new(prk.into())
}

fn expand<const N: usize>(
    suite: &[u8],
    prk: &[u8],
    label: &[u8],
    info: &[u8],
) -> Result<Zeroizing<[u8; N]>> {
    let mut input = Vec::new();
    input.extend_from_slice(&(N as u16).to_be_bytes());
    input.extend_from_slice(b"HPKE-v1");
    input.extend_from_slice(suite);
    input.extend_from_slice(label);
    input.extend_from_slice(info);
    let mut output = Zeroizing::new([0; N]);
    Hkdf::<Sha256>::from_prk(prk)
        .map_err(|_| RemoteError::InvalidKey)?
        .expand(&input, output.as_mut())
        .map_err(|_| RemoteError::InvalidKey)?;
    Ok(output)
}

fn kem_shared(
    provider: &(impl EcdhProvider + ?Sized),
    peer: &[u8],
    enc: &[u8],
    recipient_pub: &[u8],
) -> Result<Zeroizing<[u8; 32]>> {
    parse_sec1(peer)?;
    parse_sec1(enc)?;
    parse_sec1(recipient_pub)?;
    let dh = provider.ecdh(peer)?;
    let mut kem_context = enc.to_vec();
    kem_context.extend_from_slice(recipient_pub);
    let prk = extract(KEM_SUITE, b"", b"eae_prk", dh.as_ref());
    expand(KEM_SUITE, prk.as_ref(), b"shared_secret", &kem_context)
}

struct BaseContext {
    key: Zeroizing<[u8; 16]>,
    base_nonce: Zeroizing<[u8; 12]>,
    sequence: u64,
    #[cfg(test)]
    exporter_secret: Zeroizing<[u8; 32]>,
    #[cfg(test)]
    secret: Zeroizing<[u8; 32]>,
    #[cfg(test)]
    schedule_context: Vec<u8>,
}

impl BaseContext {
    fn new(shared: &[u8], info: &[u8]) -> Result<Self> {
        let psk_hash = extract(HPKE_SUITE, b"", b"psk_id_hash", b"");
        let info_hash = extract(HPKE_SUITE, b"", b"info_hash", info);
        let mut schedule_context = vec![0];
        schedule_context.extend_from_slice(psk_hash.as_ref());
        schedule_context.extend_from_slice(info_hash.as_ref());
        let secret = extract(HPKE_SUITE, shared, b"secret", b"");
        Ok(Self {
            key: expand(HPKE_SUITE, secret.as_ref(), b"key", &schedule_context)?,
            base_nonce: expand(
                HPKE_SUITE,
                secret.as_ref(),
                b"base_nonce",
                &schedule_context,
            )?,
            sequence: 0,
            #[cfg(test)]
            exporter_secret: expand(HPKE_SUITE, secret.as_ref(), b"exp", &schedule_context)?,
            #[cfg(test)]
            secret,
            #[cfg(test)]
            schedule_context,
        })
    }

    fn nonce(&self) -> [u8; 12] {
        let mut nonce = *self.base_nonce;
        for (byte, sequence) in nonce[4..].iter_mut().zip(self.sequence.to_be_bytes()) {
            *byte ^= sequence;
        }
        nonce
    }

    fn seal(&mut self, aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
        let next = self
            .sequence
            .checked_add(1)
            .ok_or(RemoteError::PayloadTooLarge)?;
        let result = Aes128Gcm::new_from_slice(self.key.as_ref())
            .map_err(|_| RemoteError::InvalidKey)?
            .encrypt(
                Nonce::from_slice(&self.nonce()),
                Payload {
                    msg: plaintext,
                    aad,
                },
            )
            .map_err(|_| RemoteError::DecryptionFailed)?;
        self.sequence = next;
        Ok(result)
    }

    fn open(&mut self, aad: &[u8], ciphertext: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        let next = self
            .sequence
            .checked_add(1)
            .ok_or(RemoteError::PayloadTooLarge)?;
        let result = Aes128Gcm::new_from_slice(self.key.as_ref())
            .map_err(|_| RemoteError::InvalidKey)?
            .decrypt(
                Nonce::from_slice(&self.nonce()),
                Payload {
                    msg: ciphertext,
                    aad,
                },
            )
            .map_err(|_| RemoteError::DecryptionFailed)?;
        self.sequence = next;
        Ok(Zeroizing::new(result))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::remote::keys::SoftwareDeviceKey;
    use serde_json::{json, Value};

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }
    fn unhex(value: &Value) -> Vec<u8> {
        value
            .as_str()
            .unwrap()
            .as_bytes()
            .as_chunks::<2>()
            .0
            .iter()
            .map(|b| u8::from_str_radix(std::str::from_utf8(b).unwrap(), 16).unwrap())
            .collect()
    }

    #[test]
    fn rfc9180_official_base_vector_and_hpke_crate_agree() {
        use ::hpke::{Deserializable, Kem as KemTrait, OpModeR, OpModeS, Serializable};
        type Kem = ::hpke::kem::DhP256HkdfSha256;
        type Kdf = ::hpke::kdf::HkdfSha256;
        type Aead = ::hpke::aead::AesGcm128;
        let file = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("testdata/remote/rfc9180_p256_base.json");
        let vector: Value = serde_json::from_slice(&std::fs::read(file).unwrap()).unwrap();
        let ephemeral = SoftwareDeviceKey::from_p256_bytes(&unhex(&vector["skEm"])).unwrap();
        let recipient = SoftwareDeviceKey::from_p256_bytes(&unhex(&vector["skRm"])).unwrap();
        let enc = ephemeral.public_sec1().unwrap();
        let recipient_pub = recipient.public_sec1().unwrap();
        let shared = kem_shared(&ephemeral, &recipient_pub, &enc, &recipient_pub).unwrap();
        let received_shared = kem_shared(&recipient, &enc, &enc, &recipient_pub).unwrap();
        let mut sender = BaseContext::new(shared.as_ref(), &unhex(&vector["info"])).unwrap();
        let mut receiver =
            BaseContext::new(received_shared.as_ref(), &unhex(&vector["info"])).unwrap();
        let (derived_e, derived_epub) = Kem::derive_keypair(&unhex(&vector["ikmE"]));
        let (derived_r, derived_rpub) = Kem::derive_keypair(&unhex(&vector["ikmR"]));
        let sk_r = <Kem as KemTrait>::PrivateKey::from_bytes(&unhex(&vector["skRm"])).unwrap();
        let hpke_enc = <Kem as KemTrait>::EncappedKey::from_bytes(&enc).unwrap();
        let mut reference_receiver = ::hpke::setup_receiver::<Aead, Kdf, Kem>(
            &OpModeR::Base,
            &sk_r,
            &hpke_enc,
            &unhex(&vector["info"]),
        )
        .unwrap();
        struct FixedRng(Vec<u8>);
        impl rand_core::RngCore for FixedRng {
            fn next_u32(&mut self) -> u32 {
                unreachable!()
            }
            fn next_u64(&mut self) -> u64 {
                unreachable!()
            }
            fn fill_bytes(&mut self, bytes: &mut [u8]) {
                bytes.copy_from_slice(&self.0);
            }
            fn try_fill_bytes(
                &mut self,
                bytes: &mut [u8],
            ) -> std::result::Result<(), rand_core::Error> {
                self.fill_bytes(bytes);
                Ok(())
            }
        }
        impl rand_core::CryptoRng for FixedRng {}
        let (reference_enc, mut reference_sender) = ::hpke::setup_sender::<Aead, Kdf, Kem, _>(
            &OpModeS::Base,
            &derived_rpub,
            &unhex(&vector["info"]),
            &mut FixedRng(unhex(&vector["ikmE"])),
        )
        .unwrap();
        let mut observed = json!({
            "enc": hex(&enc), "pkEm": hex(&ephemeral.public_sec1().unwrap()), "pkRm": hex(&recipient_pub),
            "shared_secret": hex(shared.as_ref()), "received_shared_secret": hex(received_shared.as_ref()),
            "key": hex(sender.key.as_ref()), "base_nonce": hex(sender.base_nonce.as_ref()),
            "secret": hex(sender.secret.as_ref()), "key_schedule_context": hex(&sender.schedule_context),
            "exporter_secret": hex(sender.exporter_secret.as_ref()),
            "reference_enc": hex(&reference_enc.to_bytes()),
            "derived_skEm": hex(&derived_e.to_bytes()), "derived_pkEm": hex(&derived_epub.to_bytes()),
            "derived_skRm": hex(&derived_r.to_bytes()), "derived_pkRm": hex(&derived_rpub.to_bytes()),
        });
        let mut encryptions = Vec::new();
        for encryption in vector["encryptions"].as_array().unwrap() {
            let plaintext = unhex(&encryption["pt"]);
            let aad = unhex(&encryption["aad"]);
            let nonce = sender.nonce();
            let ciphertext = sender.seal(&aad, &plaintext).unwrap();
            let reference_ct = reference_sender.seal(&plaintext, &aad).unwrap();
            let opened = receiver.open(&aad, &ciphertext).unwrap();
            let reference_pt = reference_receiver.open(&ciphertext, &aad).unwrap();
            encryptions.push(json!({"nonce": hex(&nonce), "ct": hex(&ciphertext), "reference_ct": hex(&reference_ct), "pt": hex(&opened), "reference_pt": hex(&reference_pt)}));
        }
        let mut exports = Vec::new();
        for export in vector["exports"].as_array().unwrap() {
            let context = unhex(&export["exporter_context"]);
            let bytes = expand::<32>(
                HPKE_SUITE,
                sender.exporter_secret.as_ref(),
                b"sec",
                &context,
            )
            .unwrap();
            let mut reference = [0; 32];
            reference_sender.export(&context, &mut reference).unwrap();
            exports.push(json!({"exported_value":hex(bytes.as_ref()), "reference_exported_value":hex(&reference)}));
        }
        observed["encryptions"] = json!(encryptions);
        observed["exports"] = json!(exports);
        assert!(
            observed == vector["expect"],
            "RFC 9180 official vector mismatch"
        );
    }
}
