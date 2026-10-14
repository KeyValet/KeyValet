use super::canonical::jcs;
use super::*;
use rsa::BigUint;
use sha2::{Digest, Sha256};

/// Existing executor-initiated vectors retain their joiner key ordering.
/// When a Strong approver initiates and a pure executor joins, bind the approver's keys.
pub fn device_sas(token: &[u8], initiator: &DeviceRecord, joiner: &DeviceRecord) -> Result<String> {
    super::keys::identity_verifying_jwk(initiator)?;
    super::keys::identity_verifying_jwk(joiner)?;
    let approver = if joiner.ak_s.is_some() {
        joiner
    } else {
        initiator
    };
    if approver.ak_s.is_none() {
        return Err(RemoteError::InsufficientLevel);
    }
    if initiator.dk_sig.as_value().is_some() || joiner.dk_sig.as_value().is_some() {
        if token.len() != 16 {
            return Err(RemoteError::InvalidEncoding);
        }
        // A split identity must bind both ECDH and signing public keys. Legacy records keep
        // their existing vectors; an old client cannot silently confirm the split shape.
        let identities = |record: &DeviceRecord| {
            jcs(&serde_json::json!({
                "dk_pub":record.dk_pub,"dk_sig":record.dk_sig.as_value(),
            }))
        };
        let mut records = [identities(initiator)?, identities(joiner)?];
        records.sort();
        let mut input = b"keyvalet-pair-v1-split-identity".to_vec();
        input.extend_from_slice(token);
        for record in records {
            input.extend(record);
        }
        input.extend(jcs(&approver.ak_q.as_ref().map(|key| &key.r#pub))?);
        input.extend(jcs(&approver.ak_s.as_ref().map(|key| &key.r#pub))?);
        let decimal = BigUint::from_bytes_be(&Sha256::digest(input)).to_str_radix(10);
        return Ok(format!("{decimal:0>6}")[..6].into());
    }
    sas(
        token,
        &initiator.dk_pub,
        &joiner.dk_pub,
        approver.ak_q.as_ref().map(|key| &key.r#pub),
        approver.ak_s.as_ref().map(|key| &key.r#pub),
    )
}

// CONTRACT: A.7: sort JCS bytes, raw 16-byte token, null for absent keys, decimal prefix padded to six.
pub fn sas(
    token: &[u8],
    a: &PublicJwk,
    b: &PublicJwk,
    approval_quick: Option<&PublicJwk>,
    approval_strong: Option<&PublicJwk>,
) -> Result<String> {
    if token.len() != 16 {
        return Err(RemoteError::InvalidEncoding);
    }
    let mut identities = [jcs(a)?, jcs(b)?];
    identities.sort();
    let mut input = b"keyvalet-pair-v1".to_vec();
    input.extend_from_slice(token);
    for identity in identities {
        input.extend(identity);
    }
    input.extend(jcs(&approval_quick)?);
    input.extend(jcs(&approval_strong)?);
    let decimal = BigUint::from_bytes_be(&Sha256::digest(input)).to_str_radix(10);
    let decimal = format!("{decimal:0>6}");
    Ok(decimal[..6].into())
}

// CONTRACT: Appendix A preamble / A.7: sign the SAS object with JCS, including unknown extensions.
pub fn sign_confirm(
    sas: &str,
    alg: SignatureAlgorithm,
    signer: &(impl MessageSigner + ?Sized),
) -> Result<PairConfirm> {
    validate_sas(sas)?;
    let mut confirm = PairConfirm {
        sas: sas.into(),
        sig: String::new(),
        extra: Extra::new(),
    };
    confirm.sig = super::keys::sign_object(&confirm, alg, signer)?;
    Ok(confirm)
}

pub fn verify_confirm(
    confirm: &PairConfirm,
    expected_sas: &str,
    strong_key: &ApprovalKey,
) -> Result<()> {
    validate_sas(&confirm.sas)?;
    if confirm.sas != expected_sas {
        return Err(RemoteError::DigestMismatch);
    }
    super::keys::verify_object(confirm, &confirm.sig, strong_key)
}

fn validate_sas(sas: &str) -> Result<()> {
    if sas.len() != 6 || !sas.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(RemoteError::InvalidEncoding);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn record(seed: u8, approve: bool) -> DeviceRecord {
        let public = |seed| {
            SoftwareDeviceKey::from_p256_bytes(&[seed; 32])
                .unwrap()
                .public_jwk()
                .unwrap()
        };
        let approval = |seed| ApprovalKey {
            r#pub: public(seed),
            alg: SignatureAlgorithm::ES256,
            extra: Extra::new(),
        };
        DeviceRecord {
            device_id: format!("dev_{seed}"),
            label: format!("device {seed}"),
            os: Os::Linux,
            key_kind: KeyKind::Software,
            dk_pub: public(seed),
            dk_sig: Optional::Missing,
            ak_q: approve.then(|| approval(seed + 1)),
            ak_s: approve.then(|| approval(seed + 2)),
            caps: if approve {
                vec![Capability::ApproveQuick, Capability::ApproveStrong]
            } else {
                vec![Capability::Execute]
            },
            attestation: None,
            extra: Extra::new(),
        }
    }
    #[test]
    fn split_identity_sas_binds_both_keys_and_preserves_legacy_vectors() {
        let mut executor = record(1, false);
        let mut approver = record(4, true);
        let token = [7; 16];
        let legacy = sas(
            &token,
            &executor.dk_pub,
            &approver.dk_pub,
            approver.ak_q.as_ref().map(|key| &key.r#pub),
            approver.ak_s.as_ref().map(|key| &key.r#pub),
        )
        .unwrap();
        assert_eq!(device_sas(&token, &executor, &approver).unwrap(), legacy);
        executor.dk_sig = Optional::Value(ApprovalKey {
            r#pub: record(9, false).dk_pub,
            alg: SignatureAlgorithm::ES256,
            extra: Extra::new(),
        });
        let bound = device_sas(&token, &executor, &approver).unwrap();
        assert_ne!(bound, legacy);
        assert_eq!(bound.len(), 6);
        executor.dk_sig = Optional::Value(ApprovalKey {
            r#pub: record(10, false).dk_pub,
            alg: SignatureAlgorithm::ES256,
            extra: Extra::new(),
        });
        assert_ne!(device_sas(&token, &executor, &approver).unwrap(), bound);
        assert!(device_sas(&token[..15], &executor, &approver).is_err());
        approver.ak_s = None;
        assert!(device_sas(&token, &executor, &approver).is_err());
    }
}
