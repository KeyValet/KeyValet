use kv_core::remote::canonical::{self, CanonicalRequest};
use kv_core::remote::keys::{decode_b64, encode_b64, sign_object, verify_object};
use kv_core::remote::validation::{self, DirectiveState, NonceStore};
use kv_core::remote::*;
use serde_json::{json, Value};
use std::collections::BTreeSet;
use std::path::Path;

#[path = "remote_support/schemas.rs"]
mod schemas;

fn load(name: &str) -> Value {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("testdata/remote")
        .join(name);
    canonical::parse_json(&std::fs::read(path).unwrap()).unwrap()
}

fn decode<T: serde::de::DeserializeOwned>(value: &Value) -> T {
    serde_json::from_value(value.clone()).unwrap()
}

fn key(keys: &Value, name: &str) -> SoftwareDeviceKey {
    if name == "rsa" {
        SoftwareDeviceKey::from_rsa_pkcs8_der(
            &decode_b64(keys["rsa_pkcs8_der"].as_str().unwrap()).unwrap(),
        )
        .unwrap()
    } else {
        SoftwareDeviceKey::from_p256_bytes(
            &decode_b64(keys[name]["private_scalar"].as_str().unwrap()).unwrap(),
        )
        .unwrap()
    }
}

fn outcome(result: kv_core::remote::Result<()>) -> Value {
    match result {
        Ok(()) => json!({"ok": true}),
        Err(error) => json!({"error": error.code()}),
    }
}

fn check(name: &str, observed: Value, expected: &Value) {
    // Failure output contains the fixture name only, never keys, ciphertext or request contents.
    assert!(observed == *expected, "remote vector mismatch: {name}");
}

#[test]
fn jcs_and_digest_vectors() {
    for name in ["jcs.json", "path_normalization.json"] {
        let vector = load(name);
        let observed: Vec<_> = vector["cases"]
            .as_array()
            .unwrap()
            .iter()
            .map(|case| {
                if name == "jcs.json" {
                    match canonical::canonicalize_json(case["json"].as_str().unwrap().as_bytes()) {
                        Ok(bytes) => json!({"canonical": String::from_utf8(bytes).unwrap()}),
                        Err(error) => json!({"error": error.code()}),
                    }
                } else {
                    match canonical::normalize_path(case["path"].as_str().unwrap()) {
                        Ok(path) => json!({"path": path}),
                        Err(error) => json!({"error": error.code()}),
                    }
                }
            })
            .collect();
        check(name, json!(observed), &vector["expect"]);
    }
    let vector = load("jcs_numbers.json");
    let observed: Vec<_> = vector["cases"]
        .as_array()
        .unwrap()
        .iter()
        .map(|case| {
            let bits = u64::from_str_radix(case["bits"].as_str().unwrap(), 16).unwrap();
            match canonical::jcs(&f64::from_bits(bits)) {
                Ok(bytes) => json!({"canonical": String::from_utf8(bytes).unwrap()}),
                Err(error) => json!({"error": error.code()}),
            }
        })
        .collect();
    check("jcs_numbers.json", json!(observed), &vector["expect"]);
    let vector = load("approval_request_digest.json");
    let input: CanonicalRequest = decode(&vector["input"]);
    check(
        "approval_request_digest.json",
        json!({"canonical": String::from_utf8(input.canonical_bytes().unwrap()).unwrap(), "digest": input.digest().unwrap()}),
        &vector["expect"],
    );
}

#[test]
fn software_keys_use_the_same_interface_as_hardware_providers() {
    let vector = load("test_keys.json");
    let mut roundtrips = serde_json::Map::new();
    for name in [
        "sender",
        "recipient",
        "quick",
        "strong",
        "wrong",
        "ephemeral",
    ] {
        let provider = key(&vector, name);
        let payload = b"keyvalet test signature";
        let sig = DeviceKeyProvider::sign(&provider, SignatureAlgorithm::ES256, payload).unwrap();
        roundtrips.insert(
            name.into(),
            json!(kv_core::remote::keys::verify_signature(
                SignatureAlgorithm::ES256,
                &provider.public_jwk().unwrap(),
                payload,
                &sig
            )
            .is_ok()),
        );
    }
    let rsa = key(&vector, "rsa");
    let payload = b"keyvalet RSA test signature";
    let sig = DeviceKeyProvider::sign(&rsa, SignatureAlgorithm::RS256, payload).unwrap();
    let p256 = key(&vector, "sender");
    let observed = json!({"p256_roundtrips": roundtrips, "rsa_roundtrip": kv_core::remote::keys::verify_signature(SignatureAlgorithm::RS256, &rsa.public_jwk().unwrap(), payload, &sig).is_ok(),
        "rsa_ecdh_error": DeviceKeyProvider::ecdh(&rsa, &EcdhProvider::public_sec1(&p256).unwrap()).unwrap_err().code(),
        "p256_wrong_algorithm": DeviceKeyProvider::sign(&p256, SignatureAlgorithm::RS256, payload).unwrap_err().code(),
        "presence": p256.presence_kind().as_str(), "key_kind": p256.key_kind().as_str()});
    check("test_keys.json", observed, &vector["expect"]);
}

#[test]
fn platform_provider_adapter_needs_only_the_ipc_interface() {
    struct PlatformProvider(SoftwareDeviceKey);
    impl kv_ipc::remote::DeviceKeyProvider for PlatformProvider {
        fn sign(
            &self,
            alg: SignatureAlgorithm,
            payload: &[u8],
        ) -> std::result::Result<Vec<u8>, kv_ipc::remote::DeviceKeyError> {
            DeviceKeyProvider::sign(&self.0, alg, payload)
                .map_err(|_| kv_ipc::remote::DeviceKeyError::OperationFailed)
        }
        fn ecdh(
            &self,
            peer_pub: &[u8],
        ) -> std::result::Result<zeroize::Zeroizing<[u8; 32]>, kv_ipc::remote::DeviceKeyError>
        {
            DeviceKeyProvider::ecdh(&self.0, peer_pub)
                .map_err(|_| kv_ipc::remote::DeviceKeyError::OperationFailed)
        }
        fn public_jwk(&self) -> std::result::Result<Value, kv_ipc::remote::DeviceKeyError> {
            serde_json::to_value(
                self.0
                    .public_jwk()
                    .map_err(|_| kv_ipc::remote::DeviceKeyError::Unavailable)?,
            )
            .map_err(|_| kv_ipc::remote::DeviceKeyError::OperationFailed)
        }
        fn presence_kind(&self) -> &str {
            "unlocked"
        }
        fn key_kind(&self) -> &str {
            "tpm2"
        }
    }
    struct Unavailable;
    impl kv_ipc::remote::DeviceKeyProvider for Unavailable {
        fn sign(
            &self,
            _alg: SignatureAlgorithm,
            _payload: &[u8],
        ) -> std::result::Result<Vec<u8>, kv_ipc::remote::DeviceKeyError> {
            Err(kv_ipc::remote::DeviceKeyError::Unavailable)
        }
        fn ecdh(
            &self,
            _peer_pub: &[u8],
        ) -> std::result::Result<zeroize::Zeroizing<[u8; 32]>, kv_ipc::remote::DeviceKeyError>
        {
            Err(kv_ipc::remote::DeviceKeyError::Unavailable)
        }
        fn public_jwk(&self) -> std::result::Result<Value, kv_ipc::remote::DeviceKeyError> {
            Err(kv_ipc::remote::DeviceKeyError::Unavailable)
        }
        fn presence_kind(&self) -> &str {
            "none"
        }
        fn key_kind(&self) -> &str {
            "tpm2"
        }
    }
    let vector = load("provider_adapter.json");
    let provider = PlatformProvider(key(&vector["keys"], "recipient"));
    let record: DeviceRecord = decode(&vector["recipient"]);
    let payload = b"hardware interface test";
    let signature = DeviceKeyProvider::sign(&provider, SignatureAlgorithm::ES256, payload).unwrap();
    let plaintext = envelope::open(
        &decode(&vector["envelope"]),
        "dev_mac",
        &provider,
        &decode(&vector["sender"]),
        vector["now"].as_i64().unwrap(),
    )
    .unwrap();
    let expected_plaintext = load("envelope_roundtrip.json");
    let observed = json!({"sign_ok": kv_core::remote::keys::verify_signature(SignatureAlgorithm::ES256, &record.dk_pub, payload, &signature).is_ok(),
        "open_ok": plaintext.as_slice() == expected_plaintext["expect"]["plaintext"].as_str().unwrap().as_bytes(),
        "public_jwk_ok": DeviceKeyProvider::public_jwk(&provider).unwrap() == record.dk_pub,
        "presence": DeviceKeyProvider::presence_kind(&provider).as_str(), "key_kind": DeviceKeyProvider::key_kind(&provider).as_str(),
        "error": DeviceKeyProvider::sign(&Unavailable, SignatureAlgorithm::ES256, payload).unwrap_err().code()});
    check("provider_adapter.json", observed, &vector["expect"]);
}

#[test]
fn envelope_vector_opens_in_both_implementations() {
    let vector = load("envelope_roundtrip.json");
    let sender = key(&vector["keys"], "sender");
    let recipient = key(&vector["keys"], "recipient");
    let header: EnvelopeHeader = decode(&vector["header"]);
    let recipient_record: DeviceRecord = decode(&vector["recipient"]);
    let sealed = envelope::seal_with_ephemeral(
        header,
        vector["plaintext"].as_str().unwrap().as_bytes(),
        &recipient_record.dk_pub,
        &sender,
        key(&vector["keys"], "ephemeral"),
    )
    .unwrap();
    let input: Envelope = decode(&vector["envelope"]);
    let sender_record: DeviceRecord = decode(&vector["sender"]);
    let opened = envelope::open(
        &input,
        &recipient_record.device_id,
        &recipient,
        &sender_record,
        vector["now"].as_i64().unwrap(),
    )
    .unwrap();
    use ::hpke::{Deserializable, OpModeR};
    type Kem = ::hpke::kem::DhP256HkdfSha256;
    type Aead = ::hpke::aead::AesGcm128;
    type Kdf = ::hpke::kdf::HkdfSha256;
    let sk = <Kem as ::hpke::Kem>::PrivateKey::from_bytes(
        &decode_b64(
            vector["keys"]["recipient"]["private_scalar"]
                .as_str()
                .unwrap(),
        )
        .unwrap(),
    )
    .unwrap();
    let enc =
        <Kem as ::hpke::Kem>::EncappedKey::from_bytes(&decode_b64(&sealed.enc).unwrap()).unwrap();
    let mut reference =
        ::hpke::setup_receiver::<Aead, Kdf, Kem>(&OpModeR::Base, &sk, &enc, hpke::INFO).unwrap();
    let reference_plaintext = reference
        .open(&decode_b64(&sealed.ct).unwrap(), &sealed.aad().unwrap())
        .unwrap();
    let observed = json!({"aad": String::from_utf8(sealed.aad().unwrap()).unwrap(), "ciphertext_len": decode_b64(&sealed.ct).unwrap().len(), "enc": sealed.enc, "ct": sealed.ct,
        "plaintext": String::from_utf8(opened.to_vec()).unwrap(), "signature_ok": envelope::verify(&input, &sender_record.dk_pub).is_ok() && envelope::verify(&sealed, &sender_record.dk_pub).is_ok() && reference_plaintext == vector["plaintext"].as_str().unwrap().as_bytes()});
    check("envelope_roundtrip.json", observed, &vector["expect"]);
}

#[test]
fn every_header_field_and_ciphertext_is_authenticated() {
    let vector = load("envelope_tampering.json");
    let recipient = key(&vector["keys"], "recipient");
    let observed: Vec<_> = vector["cases"]
        .as_array()
        .unwrap()
        .iter()
        .map(|case| {
            let input: Envelope = decode(&case["envelope"]);
            let result = hpke::open(
                &recipient,
                &decode_b64(&input.enc).unwrap(),
                &input.aad().unwrap(),
                &decode_b64(&input.ct).unwrap(),
            );
            json!({"hpke_error": result.unwrap_err().code()})
        })
        .collect();
    check(
        "envelope_tampering.json",
        json!(observed),
        &vector["expect"],
    );
}

#[test]
fn unsupported_and_invalid_envelopes_fail_closed() {
    let vector = load("envelope_rejections.json");
    let recipient = key(&vector["keys"], "recipient");
    let sender: DeviceRecord = decode(&vector["sender"]);
    let input: Envelope = decode(&vector["envelope"]);
    let now = vector["now"].as_i64().unwrap();
    let mut observed = serde_json::Map::new();
    for (name, envelope, recipient_id, clock) in [
        (
            "unsupported_version",
            {
                let mut e = input.clone();
                e.v = 2;
                e
            },
            "dev_mac",
            now,
        ),
        (
            "unknown_type",
            {
                let mut e = input.clone();
                e.r#type = EnvelopeType::Unknown("future".into());
                e
            },
            "dev_mac",
            now,
        ),
        ("wrong_recipient", input.clone(), "dev_other", now),
        (
            "wrong_sender",
            {
                let mut e = input.clone();
                e.from = "dev_other".into();
                e
            },
            "dev_mac",
            now,
        ),
        ("expired", input.clone(), "dev_mac", input.exp + 1),
        (
            "bad_signature",
            {
                let mut e = input.clone();
                e.sig = encode_b64(&[0; 64]);
                e
            },
            "dev_mac",
            now,
        ),
    ] {
        observed.insert(
            name.into(),
            json!(
                envelope::open(&envelope, recipient_id, &recipient, &sender, clock)
                    .unwrap_err()
                    .code()
            ),
        );
    }
    let mut large = input.header();
    large.extra.clear();
    let oversized = envelope::seal(
        large,
        &vec![0; hpke::MAX_PLAINTEXT_BYTES + 1],
        &recipient.public_jwk().unwrap(),
        &key(&vector["keys"], "sender"),
    );
    observed.insert("oversize".into(), json!(oversized.unwrap_err().code()));
    observed.insert(
        "malformed_point".into(),
        json!(hpke::open(&recipient, &[0; 65], b"", &[0; 16])
            .unwrap_err()
            .code()),
    );
    check(
        "envelope_rejections.json",
        Value::Object(observed),
        &vector["expect"],
    );
}

#[derive(Default)]
struct MemoryNonces(BTreeSet<String>);
impl NonceStore for MemoryNonces {
    fn consume(
        &mut self,
        nonce: &str,
        _digest: &str,
        _exp: Timestamp,
    ) -> kv_core::remote::Result<()> {
        if self.0.insert(nonce.into()) {
            Ok(())
        } else {
            Err(RemoteError::Replay)
        }
    }
}

#[test]
fn appendix_f_decision_vectors() {
    for name in [
        "decision_valid.json",
        "decision_wrong_key.json",
        "rs256_decision.json",
        "decision_replayed.json",
    ] {
        let vector = load(name);
        let decision: ApprovalDecision = decode(&vector["decision"]);
        let request: ApprovalRequest = decode(&vector["request"]);
        let canonical: CanonicalRequest = decode(&vector["canonical"]);
        let device: DeviceRecord = decode(&vector["device"]);
        let mut nonces = MemoryNonces::default();
        let verify = |nonces: &mut MemoryNonces| {
            outcome(validation::verify_and_consume_decision(
                &decision,
                &request,
                &canonical,
                &device,
                vector["now"].as_i64().unwrap(),
                nonces,
            ))
        };
        let observed = if name == "decision_replayed.json" {
            json!({"attempts": [verify(&mut nonces), verify(&mut nonces)], "consumed": nonces.0.len()})
        } else {
            verify(&mut nonces)
        };
        check(name, observed, &vector["expect"]);
    }
    let vector = load("decision_validation_cases.json");
    let canonical: CanonicalRequest = decode(&vector["canonical"]);
    let observed: Vec<_> = vector["cases"]
        .as_array()
        .unwrap()
        .iter()
        .map(|case| {
            outcome(validation::verify_decision(
                &decode(&case["decision"]),
                &decode(&case["request"]),
                &canonical,
                &decode(&case["device"]),
                case["now"].as_i64().unwrap(),
            ))
        })
        .collect();
    check(
        "decision_validation_cases.json",
        json!(observed),
        &vector["expect"],
    );
}

#[test]
fn appendix_f_grant_vectors() {
    for name in ["grant_standing_t1.json", "grant_t2_requires_settings.json"] {
        let vector = load(name);
        let grant: Grant = decode(&vector["grant"]);
        let mut observed = outcome(validation::verify_grant(
            &grant,
            vector["audience"].as_str().unwrap(),
            vector["audience_label"].as_str().unwrap(),
            &decode(&vector["device"]),
            decode(&vector["level"]),
            vector["now"].as_i64().unwrap(),
        ));
        if name == "grant_standing_t1.json" {
            observed["covers_t1"] = json!(validation::grant_allows_tier(&grant, Tier::T1));
            observed["covers_t2"] = json!(validation::grant_allows_tier(&grant, Tier::T2));
        }
        check(name, observed, &vector["expect"]);
    }
    let vector = load("grant_validation_cases.json");
    let observed: Vec<_> = vector["cases"]
        .as_array()
        .unwrap()
        .iter()
        .map(|case| {
            outcome(validation::verify_grant(
                &decode(&case["grant"]),
                vector["audience"].as_str().unwrap(),
                vector["audience_label"].as_str().unwrap(),
                &decode(&case["device"]),
                decode(&case["level"]),
                vector["now"].as_i64().unwrap(),
            ))
        })
        .collect();
    check(
        "grant_validation_cases.json",
        json!(observed),
        &vector["expect"],
    );
}

#[test]
fn appendix_f_directive_vectors() {
    for name in [
        "directive_tighten_quick_ok.json",
        "directive_loosen_quick_rejected.json",
    ] {
        let vector = load(name);
        let state = DirectiveState {
            mode: vector["current"]["mode"].as_str().map(str::to_owned),
            ..Default::default()
        };
        let observed = outcome(validation::verify_directive(
            &decode(&vector["directive"]),
            vector["audience"].as_str().unwrap(),
            &decode(&vector["device"]),
            decode(&vector["level"]),
            vector["now"].as_i64().unwrap(),
            &state,
        ));
        check(name, observed, &vector["expect"]);
    }
}

#[test]
fn appendix_f_pairing_vector() {
    let vector = load("pair_sas.json");
    let initiator: DeviceRecord = decode(&vector["initiator"]);
    let joiner: DeviceRecord = decode(&vector["joiner"]);
    let token = decode_b64(vector["token"].as_str().unwrap()).unwrap();
    let quick = joiner.ak_q.as_ref().map(|key| &key.r#pub);
    let strong = joiner.ak_s.as_ref().map(|key| &key.r#pub);
    let sas = pairing::sas(&token, &initiator.dk_pub, &joiner.dk_pub, quick, strong).unwrap();
    let swapped = pairing::sas(&token, &joiner.dk_pub, &initiator.dk_pub, quick, strong).unwrap();
    let confirm: PairConfirm = decode(&vector["confirm"]);
    let generated = pairing::sign_confirm(
        &sas,
        SignatureAlgorithm::ES256,
        &key(&vector["keys"], "strong"),
    )
    .unwrap();
    let strong_key = joiner.ak_s.as_ref().unwrap();
    check(
        "pair_sas.json",
        json!({"sas": sas, "swapped_sas": swapped, "confirm_ok": pairing::verify_confirm(&confirm, &sas, strong_key).is_ok() && pairing::verify_confirm(&generated, &sas, strong_key).is_ok()}),
        &vector["expect"],
    );
}

#[test]
fn every_wire_object_roundtrips_and_validates_against_its_schema() {
    let vector = load("schema_samples.json");
    let mut observed = serde_json::Map::new();
    for sample in vector["samples"].as_array().unwrap() {
        let name = sample["type"].as_str().unwrap();
        let schema_path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("schemas/remote")
            .join(sample["schema"].as_str().unwrap());
        let schema: Value = serde_json::from_slice(&std::fs::read(schema_path).unwrap()).unwrap();
        let validator = jsonschema::JSONSchema::compile(&schema).unwrap();
        let serialized = schemas::roundtrip(name, sample["value"].clone()).unwrap();
        let mut extended = sample["value"].clone();
        extended["x_unknown"] = json!({"nested": [true, null, {"future": "value"}]});
        let extended_roundtrip = schemas::roundtrip(name, extended.clone()).unwrap();
        observed.insert(name.into(), json!({"valid": validator.is_valid(&serialized), "roundtrip": serialized == sample["value"], "extra_roundtrip": extended == extended_roundtrip}));
    }
    let files = std::fs::read_dir(Path::new(env!("CARGO_MANIFEST_DIR")).join("schemas/remote"))
        .unwrap()
        .count();
    check(
        "schema_samples.json",
        json!({"schemas": files, "samples": observed}),
        &vector["expect"],
    );
    let vector = load("schema_rejections.json");
    let observed: Vec<_> = vector["samples"]
        .as_array()
        .unwrap()
        .iter()
        .map(|sample| {
            let schema_path = Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("schemas/remote")
                .join(sample["schema"].as_str().unwrap());
            let schema: Value =
                serde_json::from_slice(&std::fs::read(schema_path).unwrap()).unwrap();
            jsonschema::JSONSchema::compile(&schema)
                .unwrap()
                .is_valid(&sample["value"])
        })
        .collect();
    check("schema_rejections.json", json!(observed), &vector["expect"]);
}

#[test]
fn lossless_unknown_fields_participate_in_signatures() {
    let vector = load("decision_valid.json");
    let mut decision: ApprovalDecision = decode(&vector["decision"]);
    let provider = key(&vector["keys"], "quick");
    decision.sig = sign_object(&decision, SignatureAlgorithm::ES256, &provider).unwrap();
    let device: DeviceRecord = decode(&vector["device"]);
    let original = outcome(verify_object(
        &decision,
        &decision.sig,
        device.ak_q.as_ref().unwrap(),
    ));
    check(
        "decision_valid.json software signing",
        original,
        &vector["expect"],
    );
    decision
        .extra
        .insert("future_binding".into(), json!({"flag": false}));
    let wrong = load("decision_wrong_key.json");
    check(
        "decision unknown-field tampering",
        outcome(verify_object(
            &decision,
            &decision.sig,
            device.ak_q.as_ref().unwrap(),
        )),
        &wrong["expect"],
    );
}
