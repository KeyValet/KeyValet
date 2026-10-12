use kv_agent::remote::{
    flows::{Helper, ObjectCrypto, PairingFlow},
    view::{ConfirmationView, GlobalGrantView, PairingView},
    ApprovalView, Dialog, Error, Platform, Result, Selection,
};
use kv_core::remote::{self, DeviceKeyProvider, SignatureAlgorithm, SoftwareDeviceKey};
use serde_json::{json, Value};

fn fixture(name: &str) -> Value {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../kv-core/testdata/remote")
        .join(name);
    serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap()
}

struct W0Crypto;
impl ObjectCrypto for W0Crypto {
    fn canonical_unsigned(&self, value: &Value) -> Result<Vec<u8>> {
        remote::canonical::signed_payload(value).map_err(|_| Error::InvalidRequest)
    }
    fn verify(
        &self,
        alg: SignatureAlgorithm,
        jwk: &Value,
        payload: &[u8],
        signature: &[u8],
    ) -> Result<()> {
        let key = serde_json::from_value(jwk.clone()).map_err(|_| Error::InvalidResponse)?;
        remote::keys::verify_signature(alg, &key, payload, signature)
            .map_err(|_| Error::KeyUnavailable)
    }
}

struct Confirm;
impl Dialog for Confirm {
    fn approval(&mut self, _: &ApprovalView) -> Result<Selection> {
        Err(Error::UiUnavailable)
    }
    fn pairing(&mut self, _: &PairingView) -> Result<bool> {
        Ok(true)
    }
    fn confirm_label(&mut self, _: &ConfirmationView) -> Result<Option<String>> {
        Err(Error::UiUnavailable)
    }
    fn confirm_global(&mut self, _: &GlobalGrantView) -> Result<bool> {
        Err(Error::UiUnavailable)
    }
}

struct RelayVerifier {
    key: remote::ApprovalKey,
    sas: String,
    calls: usize,
}
impl Helper for RelayVerifier {
    fn exchange(&mut self, request: &kv_ipc::remote::Request) -> Result<Value> {
        assert_eq!(request.op, kv_ipc::remote::Op::PairConfirm);
        let confirmation: remote::PairConfirm =
            serde_json::from_value(request.params.clone()).map_err(|_| Error::InvalidRequest)?;
        remote::pairing::verify_confirm(&confirmation, &self.sas, &self.key)
            .map_err(|_| Error::InvalidResponse)?;
        let mut tampered = confirmation;
        tampered.extra.insert("future".into(), json!(true));
        assert!(remote::pairing::verify_confirm(&tampered, &self.sas, &self.key).is_err());
        self.calls += 1;
        Ok(json!({"ok":true,"result":{}}))
    }
}

#[test]
fn desktop_pairing_matches_the_w0_verifier_for_es256_and_rs256() {
    let pairing = fixture("pair_sas.json");
    let keys = fixture("test_keys.json");
    for alg in [SignatureAlgorithm::ES256, SignatureAlgorithm::RS256] {
        let key = match alg {
            SignatureAlgorithm::ES256 => SoftwareDeviceKey::from_p256_bytes(
                &remote::keys::decode_b64(keys["strong"]["private_scalar"].as_str().unwrap())
                    .unwrap(),
            )
            .unwrap(),
            SignatureAlgorithm::RS256 => SoftwareDeviceKey::from_rsa_pkcs8_der(
                &remote::keys::decode_b64(keys["rsa_pkcs8_der"].as_str().unwrap()).unwrap(),
            )
            .unwrap(),
        };
        let mut local = pairing["joiner"].clone();
        local["ak_s"]["pub"] = serde_json::to_value(key.public_jwk().unwrap()).unwrap();
        local["ak_s"]["alg"] = json!(alg);
        let mut verifier = RelayVerifier {
            key: serde_json::from_value(local["ak_s"].clone()).unwrap(),
            sas: pairing["expect"]["sas"].as_str().unwrap().into(),
            calls: 0,
        };
        PairingFlow {
            peer: &pairing["initiator"],
            local: &local,
            sas: &verifier.sas.clone(),
            platform: Platform::Macos,
        }
        .run(&mut Confirm, &mut verifier, &key.into_provider(), &W0Crypto)
        .unwrap();
        assert_eq!(verifier.calls, 1);
    }
}
