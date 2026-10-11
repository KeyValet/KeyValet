use super::canonical::jcs;
use super::*;
use rsa::BigUint;
use sha2::{Digest, Sha256};

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
