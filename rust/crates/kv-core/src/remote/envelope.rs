use super::canonical::jcs;
use super::keys::{decode_b64, encode_b64, p256_public_sec1, verify_signature};
use super::*;
use zeroize::Zeroizing;

pub const MAX_ENVELOPE_BYTES: usize = 80 * 1024;

impl Envelope {
    pub fn header(&self) -> EnvelopeHeader {
        EnvelopeHeader {
            v: self.v,
            r#type: self.r#type.clone(),
            id: self.id.clone(),
            account: self.account.clone(),
            from: self.from.clone(),
            to: self.to.clone(),
            created_at: self.created_at,
            exp: self.exp,
            extra: self.extra.clone(),
        }
    }

    pub fn aad(&self) -> Result<Vec<u8>> {
        aad(&self.header())
    }

    pub fn signature_payload(&self) -> Result<Vec<u8>> {
        let mut payload = self.aad()?;
        payload.extend(decode_b64(&self.ct)?);
        Ok(payload)
    }
}

pub fn aad(header: &EnvelopeHeader) -> Result<Vec<u8>> {
    // CONTRACT: A.1 / §13.2: unknown header extensions are included; transport fields are reserved.
    if [
        "v",
        "type",
        "id",
        "account",
        "from",
        "to",
        "created_at",
        "exp",
        "enc",
        "ct",
        "sig",
    ]
    .iter()
    .any(|field| header.extra.contains_key(*field))
    {
        return Err(RemoteError::InvalidJson);
    }
    jcs(header)
}

pub fn seal(
    header: EnvelopeHeader,
    plaintext: &[u8],
    recipient: &PublicJwk,
    signer: &(impl MessageSigner + ?Sized),
) -> Result<Envelope> {
    seal_with_ephemeral(
        header,
        plaintext,
        recipient,
        signer,
        SoftwareDeviceKey::generate_p256(),
    )
}

/// The ephemeral provider must refer to a fresh, single-use key.
pub fn seal_with_ephemeral(
    header: EnvelopeHeader,
    plaintext: &[u8],
    recipient: &PublicJwk,
    signer: &(impl MessageSigner + ?Sized),
    ephemeral: impl EcdhProvider,
) -> Result<Envelope> {
    if header.v != 1 {
        return Err(RemoteError::UnsupportedVersion);
    }
    if matches!(header.r#type, EnvelopeType::Unknown(_)) {
        return Err(RemoteError::UnsupportedType);
    }
    let aad = aad(&header)?;
    let (enc, ct) = hpke::seal(&ephemeral, &p256_public_sec1(recipient)?, &aad, plaintext)?;
    let mut signature_payload = aad;
    signature_payload.extend_from_slice(&ct);
    let sig = signer.sign(SignatureAlgorithm::ES256, &signature_payload)?;
    let envelope = Envelope {
        v: header.v,
        r#type: header.r#type,
        id: header.id,
        account: header.account,
        from: header.from,
        to: header.to,
        created_at: header.created_at,
        exp: header.exp,
        enc: encode_b64(&enc),
        ct: encode_b64(&ct),
        sig: encode_b64(&sig),
        extra: header.extra,
    };
    if serde_json::to_vec(&envelope)
        .map_err(|_| RemoteError::InvalidJson)?
        .len()
        > MAX_ENVELOPE_BYTES
    {
        return Err(RemoteError::PayloadTooLarge);
    }
    Ok(envelope)
}

pub fn verify(envelope: &Envelope, sender: &PublicJwk) -> Result<()> {
    verify_signature(
        SignatureAlgorithm::ES256,
        sender,
        &envelope.signature_payload()?,
        &decode_b64(&envelope.sig)?,
    )
}

/// The caller must supply a paired, unrevoked sender from its trusted device directory.
pub fn open(
    envelope: &Envelope,
    recipient_id: &str,
    recipient: &(impl EcdhProvider + ?Sized),
    sender: &DeviceRecord,
    now: Timestamp,
) -> Result<Zeroizing<Vec<u8>>> {
    if envelope.v != 1 {
        return Err(RemoteError::UnsupportedVersion);
    }
    if matches!(envelope.r#type, EnvelopeType::Unknown(_)) {
        return Err(RemoteError::UnsupportedType);
    }
    if envelope.to != recipient_id {
        return Err(RemoteError::WrongRecipient);
    }
    if envelope.from != sender.device_id {
        return Err(RemoteError::WrongSender);
    }
    if envelope.exp < now {
        return Err(RemoteError::Expired);
    }
    if serde_json::to_vec(envelope)
        .map_err(|_| RemoteError::InvalidJson)?
        .len()
        > MAX_ENVELOPE_BYTES
    {
        return Err(RemoteError::PayloadTooLarge);
    }
    verify_identity_signature(
        sender,
        &envelope.signature_payload()?,
        &decode_b64(&envelope.sig)?,
    )?;
    hpke::open(
        recipient,
        &decode_b64(&envelope.enc)?,
        &envelope.aad()?,
        &decode_b64(&envelope.ct)?,
    )
}
