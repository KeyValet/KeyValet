//! Standalone compatibility tests compile the current W0 source without adding dependencies.
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use kv_ipc::remote::{DeviceKeyError, DeviceKeyProvider, Request, SignatureAlgorithm};
use serde_json::{json, Value};
use w6_w0::remote;
use w6_w0::ui::{self as ui, flows::*, view::*, Dialog, Error, Result, Selection};

fn fixture(name: &str) -> Value {
    serde_json::from_slice(
        &std::fs::read(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../kv-core/testdata/remote")
                .join(name),
        )
        .unwrap(),
    )
    .unwrap()
}
fn sample(name: &str) -> Value {
    fixture("schema_samples.json")["samples"]
        .as_array()
        .unwrap()
        .iter()
        .find(|sample| sample["type"] == name)
        .unwrap()["value"]
        .clone()
}
struct Software(remote::SoftwareDeviceKey);
impl DeviceKeyProvider for Software {
    fn sign(
        &self,
        alg: SignatureAlgorithm,
        payload: &[u8],
    ) -> std::result::Result<Vec<u8>, DeviceKeyError> {
        remote::DeviceKeyProvider::sign(&self.0, core_alg(alg), payload)
            .map_err(|_| DeviceKeyError::OperationFailed)
    }
    fn ecdh(
        &self,
        peer: &[u8],
    ) -> std::result::Result<zeroize::Zeroizing<[u8; 32]>, DeviceKeyError> {
        remote::DeviceKeyProvider::ecdh(&self.0, peer)
            .map(|secret| zeroize::Zeroizing::new(*secret))
            .map_err(|_| DeviceKeyError::OperationFailed)
    }
    fn public_jwk(&self) -> std::result::Result<Value, DeviceKeyError> {
        let key = remote::DeviceKeyProvider::public_jwk(&self.0)
            .map_err(|_| DeviceKeyError::InvalidKey)?;
        serde_json::from_slice(
            &remote::canonical::jcs(&key).map_err(|_| DeviceKeyError::InvalidKey)?,
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
struct W0Crypto;
fn core_alg(alg: SignatureAlgorithm) -> remote::SignatureAlgorithm {
    match alg {
        SignatureAlgorithm::ES256 => remote::SignatureAlgorithm::ES256,
        SignatureAlgorithm::RS256 => remote::SignatureAlgorithm::RS256,
    }
}
impl ObjectCrypto for W0Crypto {
    fn canonical_unsigned(&self, value: &Value) -> Result<Vec<u8>> {
        let value = remote::canonical::parse_json(value.to_string().as_bytes())
            .map_err(|_| Error::InvalidRequest)?;
        remote::canonical::signed_payload(&value).map_err(|_| Error::InvalidRequest)
    }
    fn verify(
        &self,
        alg: SignatureAlgorithm,
        jwk: &Value,
        payload: &[u8],
        signature: &[u8],
    ) -> Result<()> {
        let key: remote::PublicJwk = remote::canonical::from_json(jwk.to_string().as_bytes())
            .map_err(|_| Error::InvalidRequest)?;
        remote::keys::verify_signature(core_alg(alg), &key, payload, signature)
            .map_err(|_| Error::KeyUnavailable)
    }
}
struct Choice(String);
impl Dialog for Choice {
    fn approval(&mut self, _: &ApprovalView) -> Result<Selection> {
        Ok(Selection::Allow {
            scope: self.0.clone(),
        })
    }
    fn pairing(&mut self, _: &PairingView) -> Result<bool> {
        Ok(true)
    }
    fn confirm_label(&mut self, view: &ConfirmationView) -> Result<Option<String>> {
        Ok(Some(view.label.clone()))
    }
}
struct SignedHelper<'a> {
    key: &'a Software,
    alg: SignatureAlgorithm,
    request: Value,
    last: Value,
}
impl Helper for SignedHelper<'_> {
    fn exchange(&mut self, input: &Request) -> Result<Value> {
        let mut value = match input.op {
            kv_ipc::remote::Op::Decide => {
                json!({"approval_id":input.params["approval_id"],"digest":self.request["digest"],"nonce":self.request["nonce"],
                "decision":input.params["decision"],"level":input.params["level"],"scope":input.params["scope"],"approver":"dev_mac","approver_kind":"device","quorum":null,"issued_at":1760200000})
            }
            kv_ipc::remote::Op::PairConfirm => {
                self.last = input.params.clone();
                return Ok(json!({"ok":true,"result":{}}));
            }
            _ => input.params.clone(),
        };
        let payload = W0Crypto.canonical_unsigned(&value)?;
        value["sig"] = json!(URL_SAFE_NO_PAD.encode(
            self.key
                .sign(self.alg, &payload)
                .map_err(|_| Error::KeyUnavailable)?
        ));
        self.last = value.clone();
        Ok(
            json!({"ok":true,"result":if input.op==kv_ipc::remote::Op::GrantIssue{json!({"grant":value})}else{json!({"sent":true})}}),
        )
    }
}
fn software(role: &str) -> Software {
    let keys = fixture("test_keys.json");
    Software(if role == "rsa" {
        remote::SoftwareDeviceKey::from_rsa_pkcs8_der(
            &URL_SAFE_NO_PAD
                .decode(keys["rsa_pkcs8_der"].as_str().unwrap())
                .unwrap(),
        )
        .unwrap()
    } else {
        remote::SoftwareDeviceKey::from_p256_bytes(
            &URL_SAFE_NO_PAD
                .decode(keys[role]["private_scalar"].as_str().unwrap())
                .unwrap(),
        )
        .unwrap()
    })
}

#[test]
fn typed_w0_requests_and_all_decisions_share_the_current_contract() {
    let request: remote::ApprovalRequest =
        remote::canonical::from_json(sample("ApprovalRequest").to_string().as_bytes()).unwrap();
    let json = serde_json::from_slice(&remote::canonical::jcs(&request).unwrap()).unwrap();
    let view = ApprovalView::new(
        &json,
        DisplayContext {
            now: 1760200000,
            ..Default::default()
        },
        Platform::Macos,
    )
    .unwrap();
    let local: remote::DeviceRecord =
        remote::canonical::from_json(sample("DeviceRecord").to_string().as_bytes()).unwrap();
    for choice in &view.scopes {
        let key = software(if choice.level == ui::Level::Strong {
            "strong"
        } else {
            "quick"
        });
        let mut helper = SignedHelper {
            key: &key,
            alg: SignatureAlgorithm::ES256,
            request: json.clone(),
            last: Value::Null,
        };
        ApprovalFlow::run(
            &view,
            &mut Choice(choice.value.clone()),
            &mut helper,
            &|| 1760200000,
        )
        .unwrap();
        let decision: remote::ApprovalDecision =
            remote::canonical::from_json(helper.last.to_string().as_bytes()).unwrap();
        remote::keys::verify_object(
            &decision,
            &decision.sig,
            remote::validation::approval_key(&local, decision.level).unwrap(),
        )
        .unwrap();
        let typed: remote::DecisionScope = remote::canonical::from_json(
            decision_scope(&choice.value, 1760200000)
                .unwrap()
                .to_string()
                .as_bytes(),
        )
        .unwrap();
        assert_eq!(typed, decision.scope);
        if let Some(value) = grant_for_scope(
            &json,
            &choice.value,
            &sample("DeviceRecord"),
            "01J9W000000000000000000003",
            1760200000,
            1760200600,
        )
        .unwrap()
        {
            let mut value = value;
            value["sig"] = json!("");
            let _: remote::Grant =
                remote::canonical::from_json(value.to_string().as_bytes()).unwrap();
        }
    }
}

#[test]
fn pairing_and_unattended_grants_use_w0_software_es256_and_rs256() {
    let pairing = fixture("pair_sas.json");
    for alg in [SignatureAlgorithm::ES256, SignatureAlgorithm::RS256] {
        let provider = software(if alg == SignatureAlgorithm::ES256 {
            "strong"
        } else {
            "rsa"
        });
        let mut local = pairing["joiner"].clone();
        local["ak_s"]["alg"] = json!(alg);
        local["ak_s"]["pub"] = provider.public_jwk().unwrap();
        let mut helper = SignedHelper {
            key: &provider,
            alg,
            request: sample("ApprovalRequest"),
            last: Value::Null,
        };
        PairingFlow {
            peer: &pairing["initiator"],
            local: &local,
            sas: pairing["expect"]["sas"].as_str().unwrap(),
            platform: Platform::Macos,
        }
        .run(
            &mut Choice("per_use".into()),
            &mut helper,
            &provider,
            &W0Crypto,
        )
        .unwrap();
        let confirmation: remote::PairConfirm =
            remote::canonical::from_json(helper.last.to_string().as_bytes()).unwrap();
        let key: remote::ApprovalKey =
            remote::canonical::from_json(local["ak_s"].to_string().as_bytes()).unwrap();
        remote::pairing::verify_confirm(
            &confirmation,
            pairing["expect"]["sas"].as_str().unwrap(),
            &key,
        )
        .unwrap();
        let mut tampered = confirmation;
        tampered.extra.insert("extension".into(), json!(true));
        assert!(remote::pairing::verify_confirm(
            &tampered,
            pairing["expect"]["sas"].as_str().unwrap(),
            &key,
        )
        .is_err());
        let input = json!({"jti":"01J9W000000000000000000003","aud":"dev_srv","scope":{"level":"device","max_tier":"T2"}});
        let mut gate = KeyAuthorization {
            provider: &provider,
            local: &local,
            crypto: &W0Crypto,
        };
        GrantPlan::settings(
            input,
            &local,
            &pairing["initiator"],
            1760200000,
            false,
            Platform::Macos,
        )
        .unwrap()
        .issue(&mut Choice("per_use".into()), &mut helper, &mut gate)
        .unwrap();
        let grant: remote::Grant =
            remote::canonical::from_json(helper.last.to_string().as_bytes()).unwrap();
        let local: remote::DeviceRecord =
            remote::canonical::from_json(local.to_string().as_bytes()).unwrap();
        remote::validation::verify_grant(
            &grant,
            "dev_srv",
            "srv",
            &local,
            remote::ApprovalLevel::Strong,
            1760200000,
        )
        .unwrap();
    }
}

#[test]
fn directive_classification_matches_w0_for_all_vector_cases() {
    for name in [
        "directive_tighten_quick_ok.json",
        "directive_loosen_quick_rejected.json",
    ] {
        let vector = fixture(name);
        let directive: remote::Directive =
            remote::canonical::from_json(vector["directive"].to_string().as_bytes()).unwrap();
        let current = remote::validation::DirectiveState {
            mode: Some("per_credential".into()),
            ..Default::default()
        };
        let w0 = remote::validation::directive_required_level(&directive, &current).unwrap();
        let ui = directive_level(
            vector["directive"]["op"].as_str().unwrap(),
            &vector["directive"]["args"],
            &DirectiveState {
                mode: current.mode,
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(
            ui.as_str(),
            if w0 == remote::ApprovalLevel::Strong {
                "strong"
            } else {
                "quick"
            }
        );
    }
}
