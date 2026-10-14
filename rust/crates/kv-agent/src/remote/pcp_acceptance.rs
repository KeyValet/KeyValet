//! Opt-in native SYSTEM acceptance. Ordinary CI never creates machine keys or touches an install.
use kv_core::remote::{self, DeviceKeyProvider, Optional, SignatureAlgorithm, SoftwareDeviceKey};
use kv_platform::device_key::{windows::PcpDeviceKey, KeyRole};
use serde_json::{json, Value};

struct Cleanup(Option<PcpDeviceKey>);
impl Cleanup {
    fn key(&self) -> &PcpDeviceKey {
        self.0.as_ref().unwrap()
    }
    fn delete(&mut self) {
        self.0.take().unwrap().delete().unwrap();
    }
}
impl Drop for Cleanup {
    fn drop(&mut self) {
        if let Some(key) = self.0.take() {
            let _ = key.delete();
        }
    }
}
fn fixture(name: &str) -> Value {
    // Native test executables can be copied to a physical PC without installing Rust/source.
    let text = match name {
        "decision_valid.json" => {
            include_str!("../../../kv-core/testdata/remote/decision_valid.json")
        }
        "test_keys.json" => include_str!("../../../kv-core/testdata/remote/test_keys.json"),
        "envelope_roundtrip.json" => {
            include_str!("../../../kv-core/testdata/remote/envelope_roundtrip.json")
        }
        _ => panic!("unknown native fixture"),
    };
    remote::canonical::from_json(text.as_bytes()).unwrap()
}

/// Run the native kv-agent library test binary under LocalSystem, after service startup.
/// scripts/test-windows-remote-keys.ps1 locates and runs this ignored test in a SYSTEM task.
#[test]
#[ignore = "Requires Windows 11 TPM 2.0, LocalSystem, and optional installed read-only status probe"]
fn windows_pcp_k1_native_acceptance() {
    let began = std::time::Instant::now();
    let mut identity = Cleanup(Some(PcpDeviceKey::create(KeyRole::Identity).unwrap()));
    let mut quick = Cleanup(Some(PcpDeviceKey::create(KeyRole::Quick).unwrap()));
    let metadata = identity.key().metadata().clone();
    let loaded = PcpDeviceKey::from_authenticated_metadata(metadata.clone()).unwrap();
    let vector = fixture("decision_valid.json");
    let mut record: remote::DeviceRecord =
        serde_json::from_value(vector["device"].clone()).unwrap();
    record.os = remote::Os::Windows;
    record.key_kind = remote::KeyKind::PcpTpm;
    record.dk_pub = loaded.public_jwk().unwrap();
    record.dk_sig = Optional::Value(remote::ApprovalKey {
        r#pub: loaded.identity_sign_jwk().unwrap().unwrap(),
        alg: SignatureAlgorithm::ES256,
        extra: remote::Extra::new(),
    });
    record.ak_q = Some(remote::ApprovalKey {
        r#pub: quick.key().public_jwk().unwrap(),
        alg: SignatureAlgorithm::ES256,
        extra: remote::Extra::new(),
    });
    record.ak_s = None;
    record.caps = vec![remote::Capability::ApproveQuick];
    remote::keys::verify_identity_provider(&record, &loaded).unwrap();
    assert_ne!(record.dk_pub, record.dk_sig.as_value().unwrap().r#pub);
    let challenge = b"R2-B native identity challenge";
    let signature = loaded.sign(SignatureAlgorithm::ES256, challenge).unwrap();
    remote::verify_identity_signature(&record, challenge, &signature).unwrap();
    assert!(remote::keys::verify_signature(
        SignatureAlgorithm::ES256,
        &record.dk_pub,
        challenge,
        &signature
    )
    .is_err());

    let keys = fixture("test_keys.json");
    let executor_key = SoftwareDeviceKey::from_p256_bytes(
        &remote::keys::decode_b64(keys["sender"]["private_scalar"].as_str().unwrap()).unwrap(),
    )
    .unwrap();
    let executor: remote::DeviceRecord =
        serde_json::from_value(fixture("envelope_roundtrip.json")["sender"].clone()).unwrap();
    let raw = loaded
        .ecdh(&remote::keys::p256_public_sec1(&executor.dk_pub).unwrap())
        .unwrap();
    let reciprocal = executor_key
        .ecdh(&remote::keys::p256_public_sec1(&record.dk_pub).unwrap())
        .unwrap();
    assert_eq!(*raw, *reciprocal);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let mut request: remote::ApprovalRequest =
        serde_json::from_value(vector["request"].clone()).unwrap();
    let mut canonical: remote::canonical::CanonicalRequest =
        serde_json::from_value(vector["canonical"].clone()).unwrap();
    canonical.exp = now + 300;
    request.exp = canonical.exp;
    request.digest = canonical.digest().unwrap();
    let header = |from: &str, to: &str, kind| remote::EnvelopeHeader {
        v: 1,
        r#type: kind,
        id: request.approval_id.clone(),
        account: "acct_r2b_fixture".into(),
        from: from.into(),
        to: to.into(),
        created_at: now,
        exp: now + 300,
        extra: remote::Extra::new(),
    };
    let request_envelope = remote::envelope::seal(
        header(
            &executor.device_id,
            &record.device_id,
            remote::EnvelopeType::ApprovalRequest,
        ),
        &remote::canonical::jcs(&request).unwrap(),
        &record.dk_pub,
        &executor_key,
    )
    .unwrap();
    let request_started = std::time::Instant::now();
    let plaintext = remote::envelope::open(
        &request_envelope,
        &record.device_id,
        &loaded,
        &executor,
        now,
    )
    .unwrap();
    let received: remote::ApprovalRequest = remote::canonical::from_json(&plaintext).unwrap();
    assert_eq!(received, request);
    let mut decision: remote::ApprovalDecision =
        serde_json::from_value(vector["decision"].clone()).unwrap();
    decision.digest = request.digest.clone();
    decision.issued_at = now;
    decision.sig =
        remote::keys::sign_object(&decision, SignatureAlgorithm::ES256, quick.key()).unwrap();
    let decision_envelope = remote::envelope::seal(
        header(
            &record.device_id,
            &executor.device_id,
            remote::EnvelopeType::ApprovalDecision,
        ),
        &remote::canonical::jcs(&decision).unwrap(),
        &executor.dk_pub,
        &loaded,
    )
    .unwrap();
    let plaintext = remote::envelope::open(
        &decision_envelope,
        &executor.device_id,
        &executor_key,
        &record,
        now,
    )
    .unwrap();
    let received: remote::ApprovalDecision = remote::canonical::from_json(&plaintext).unwrap();
    remote::validation::verify_decision(&received, &request, &canonical, &record, now).unwrap();
    let quick_fixture_ms = request_started.elapsed().as_secs_f64() * 1000.0;
    assert!(remote::keys::verify_signature(
        SignatureAlgorithm::ES256,
        &record.dk_sig.as_value().unwrap().r#pub,
        &remote::canonical::signed_payload(&decision).unwrap(),
        &remote::keys::decode_b64(&decision.sig).unwrap()
    )
    .is_err());

    let status = kv_platform::device_key::windows::identity_key_status();
    assert_eq!(status["pcp_ecdh"], true);
    assert_eq!(status["pcp_ecdsa"], true);
    // The script explicitly supplies the installed CLI path; absent means a pure hardware test.
    let installed = if let Some(cli) = std::env::var_os("R2B_INSTALLED_CLI") {
        let output = std::process::Command::new(&cli)
            .args(["status", "--summary"])
            .output()
            .unwrap();
        assert!(output.status.success());
        let summary = String::from_utf8(output.stdout).unwrap();
        assert!(summary.contains("pcp_ecdh=present") && summary.contains("pcp_ecdsa=present"));
        Some(summary)
    } else {
        None
    };
    let strong = std::env::var_os("R3B_STRONG_EXCHANGE").map(|directory| {
        strong_exchange(
            std::path::Path::new(&directory),
            &record,
            &request,
            &canonical,
            &decision,
            &loaded,
            &executor_key,
        )
    });
    drop(loaded);
    identity.delete();
    quick.delete();
    assert!(PcpDeviceKey::from_authenticated_metadata(metadata).is_err());
    let report = json!({"context":"LocalSystem","key_kind":"pcp_tpm","software_fallback":false,
        "pcp_ecdh":true,"pcp_ecdsa":true,"reopen":true,"identity_signature_bytes":signature.len(),
        "raw_secret_bytes":raw.len(),"raw_secret_matches_software":true,"hpke_roundtrip":true,
        "quick_fixture":{"verified":true,"alg":"ES256","milliseconds":quick_fixture_ms},
        "strong_fixture":strong.unwrap_or_else(|| json!({"status":"not_requested","alg":"RS256"})),"cleanup":true,
        "status":status,"installed_summary":installed,"milliseconds":began.elapsed().as_secs_f64()*1000.0});
    if let Some(path) = std::env::var_os("R2B_NATIVE_REPORT") {
        std::fs::write(path, serde_json::to_vec_pretty(&report).unwrap()).unwrap();
    }
    println!("R2B_NATIVE {}", serde_json::to_string(&report).unwrap());
}

fn strong_exchange(
    directory: &std::path::Path,
    record: &remote::DeviceRecord,
    request: &remote::ApprovalRequest,
    canonical: &remote::canonical::CanonicalRequest,
    decision: &remote::ApprovalDecision,
    identity: &PcpDeviceKey,
    executor_key: &SoftwareDeviceKey,
) -> Value {
    let began = std::time::Instant::now();
    let now = crate::remote::view::unix_seconds();
    let mut request: remote::ApprovalRequest = serde_json::from_value(
        crate::remote::tests::per_use_strong_fixture(serde_json::to_value(request).unwrap()),
    )
    .unwrap();
    let mut canonical = canonical.clone();
    canonical.exp = now + 900;
    request.exp = canonical.exp;
    request.digest = canonical.digest().unwrap();
    let executor: remote::DeviceRecord =
        serde_json::from_value(fixture("envelope_roundtrip.json")["sender"].clone()).unwrap();
    let header = |from: &str, to: &str, kind| remote::EnvelopeHeader {
        v: 1,
        r#type: kind,
        id: request.approval_id.clone(),
        account: "acct_r3b_fixture".into(),
        from: from.into(),
        to: to.into(),
        created_at: now,
        exp: request.exp,
        extra: remote::Extra::new(),
    };
    let sealed = remote::envelope::seal(
        header(
            &executor.device_id,
            &record.device_id,
            remote::EnvelopeType::ApprovalRequest,
        ),
        &remote::canonical::jcs(&request).unwrap(),
        &record.dk_pub,
        executor_key,
    )
    .unwrap();
    let opened =
        remote::envelope::open(&sealed, &record.device_id, identity, &executor, now).unwrap();
    let received: remote::ApprovalRequest = remote::canonical::from_json(&opened).unwrap();
    assert_eq!(received, request);
    let input =
        json!({"device":record,"request":received,"canonical":canonical,"decision":decision});
    std::fs::write(
        directory.join("input.tmp"),
        remote::canonical::jcs(&input).unwrap(),
    )
    .unwrap();
    std::fs::rename(directory.join("input.tmp"), directory.join("input.json")).unwrap();
    let output = std::path::PathBuf::from(
        std::env::var_os("R3B_STRONG_OUTPUT").expect("explicit owner output directory required"),
    );
    let reply = output.join("owner-result.json");
    let signed = output.join("owner-strong-result.json");
    let repeated_reply = output.join("owner-repeat-result.json");
    while !signed.try_exists().unwrap() || !repeated_reply.try_exists().unwrap() {
        assert!(
            !reply.try_exists().unwrap(),
            "owner failed before publishing signed decisions"
        );
        assert!(
            began.elapsed() < std::time::Duration::from_secs(850),
            "owner Strong fixture timed out; PCP guards will clean up"
        );
        std::thread::sleep(std::time::Duration::from_millis(250));
    }
    let bytes = std::fs::read(signed).unwrap();
    assert!(bytes.len() <= 64 * 1024);
    let result: Value = remote::canonical::from_json(&bytes).unwrap();
    let mut approver = record.clone();
    approver.ak_s = Some(serde_json::from_value(result["ak_s"].clone()).unwrap());
    assert_eq!(
        approver.ak_s.as_ref().unwrap().alg,
        SignatureAlgorithm::RS256
    );
    approver.caps.push(remote::Capability::ApproveStrong);
    let decision: remote::ApprovalDecision =
        serde_json::from_value(result["decision"].clone()).unwrap();
    let repeated_bytes = std::fs::read(repeated_reply).unwrap();
    assert!(repeated_bytes.len() <= 64 * 1024);
    let repeated_result: Value = remote::canonical::from_json(&repeated_bytes).unwrap();
    let repeated: remote::ApprovalDecision =
        serde_json::from_value(repeated_result["decision"].clone()).unwrap();
    let verification_started = std::time::Instant::now();
    let envelope = remote::envelope::seal(
        header(
            &approver.device_id,
            &executor.device_id,
            remote::EnvelopeType::ApprovalDecision,
        ),
        &remote::canonical::jcs(&decision).unwrap(),
        &executor.dk_pub,
        identity,
    )
    .unwrap();
    let plaintext = remote::envelope::open(
        &envelope,
        &executor.device_id,
        executor_key,
        &approver,
        crate::remote::view::unix_seconds(),
    )
    .unwrap();
    let decision: remote::ApprovalDecision = remote::canonical::from_json(&plaintext).unwrap();
    let verify_now = crate::remote::view::unix_seconds();
    #[derive(Default)]
    struct Nonces(std::collections::HashSet<String>);
    impl remote::validation::NonceStore for Nonces {
        fn consume(&mut self, nonce: &str, _: &str, _: i64) -> remote::Result<()> {
            if self.0.insert(nonce.to_owned()) {
                Ok(())
            } else {
                Err(remote::RemoteError::Replay)
            }
        }
    }
    let mut nonces = Nonces::default();
    remote::validation::verify_and_consume_decision(
        &decision,
        &request,
        &canonical,
        &approver,
        verify_now,
        &mut nonces,
    )
    .unwrap();
    assert!(matches!(
        remote::validation::verify_and_consume_decision(
            &repeated,
            &request,
            &canonical,
            &approver,
            verify_now,
            &mut nonces
        ),
        Err(remote::RemoteError::Replay)
    ));
    let mut changed = decision.clone();
    changed.digest = "0".repeat(64);
    assert!(remote::validation::verify_decision(
        &changed, &request, &canonical, &approver, verify_now
    )
    .is_err());
    let mut quick = decision.clone();
    quick.level = remote::ApprovalLevel::Quick;
    assert!(matches!(
        remote::validation::verify_decision(&quick, &request, &canonical, &approver, verify_now),
        Err(remote::RemoteError::InsufficientLevel)
    ));
    let mut wrong = approver.clone();
    wrong.ak_s.as_mut().unwrap().alg = SignatureAlgorithm::ES256;
    assert!(remote::validation::verify_decision(
        &decision, &request, &canonical, &wrong, verify_now
    )
    .is_err());
    let mut verified = json!({"status":"passed","tier":"T2","alg":"RS256","signature_bytes":remote::keys::decode_b64(&decision.sig).unwrap().len(),
        "hpke_roundtrip":true,"accepted_nonces":1,"replay_rejected":true,"digest_tamper_rejected":true,"quick_t2_rejected":true,
        "wrong_record_alg_rejected":true,"verification_ms":verification_started.elapsed().as_secs_f64()*1000.0,
        "milliseconds":began.elapsed().as_secs_f64()*1000.0});
    std::fs::write(
        directory.join("strong-verified.json"),
        remote::canonical::jcs(&verified).unwrap(),
    )
    .unwrap();
    while !reply.try_exists().unwrap() {
        assert!(began.elapsed() < std::time::Duration::from_secs(850));
        std::thread::sleep(std::time::Duration::from_millis(250));
    }
    let bytes = std::fs::read(reply).unwrap();
    assert!(bytes.len() <= 64 * 1024);
    let result: Value = remote::canonical::from_json(&bytes).unwrap();
    assert_eq!(result["cancelled"], true);
    assert_eq!(result["cancel_status"], 3);
    assert_eq!(result["hello_cleanup"], true);
    verified["hello"] = result["timings"].clone();
    verified["cancel_status"] = result["cancel_status"].clone();
    verified["cancel_attempts"] = result["cancel_attempts"].clone();
    verified["hello_cleanup"] = json!(true);
    verified["native_repeat"] = result["native_repeat"].clone();
    verified
}
