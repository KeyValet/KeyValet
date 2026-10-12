//! Relay API wire objects from Appendix B.

use super::*;
use serde::{Deserialize, Serialize};

pub const WS_SUBPROTOCOL: &str = "kv-relay-v1";
pub const STRONG_CHALLENGE_HEADER: &str = "x-kv-challenge";
pub const STRONG_SIGNATURE_HEADER: &str = "x-kv-strong-signature";

macro_rules! object {
    ($name:ident { $($field:ident: $ty:ty),* $(,)? }) => {
        #[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
        pub struct $name { $(pub $field: $ty,)* #[serde(flatten)] pub extra: Extra }
    };
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct RegisterDeviceRequest {
    #[serde(flatten)]
    pub device: DeviceRecord,
    // CONTRACT: Appendix B does not define push_token's provider shape; preserve it as opaque JSON.
    #[serde(default, skip_serializing_if = "Optional::is_missing")]
    pub push_token: Optional<serde_json::Value>,
}

impl<'de> Deserialize<'de> for RegisterDeviceRequest {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Self, D::Error> {
        // CONTRACT: Appendix B: remove registration-only fields before DeviceRecord captures extras.
        let mut value = serde_json::Value::deserialize(deserializer)?;
        let object = value
            .as_object_mut()
            .ok_or_else(|| serde::de::Error::custom("invalid device registration"))?;
        let push_token = match object.remove("push_token") {
            None => Optional::Missing,
            Some(serde_json::Value::Null) => Optional::Null,
            Some(value) => Optional::Value(value),
        };
        let device = serde_json::from_value(value)
            .map_err(|_| serde::de::Error::custom("invalid device record"))?;
        Ok(Self { device, push_token })
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RegisterDeviceResponse {
    pub account_id: String,
    pub device_id: String,
    #[serde(default, skip_serializing_if = "Optional::is_missing")]
    pub recovery_code: Optional<String>,
    #[serde(flatten)]
    pub extra: Extra,
}

object!(ChallengeRequest { device_id: String });
object!(ChallengeResponse {
    challenge: String,
    exp: Timestamp
});
object!(AuthVerifyRequest {
    device_id: String,
    challenge: String,
    sig: String
});
object!(AuthVerifyResponse {
    session_token: String,
    exp: Timestamp
});

/// A recovery code authorizes replacing all relay devices without an existing session.
/// The replacement DK signs the complete proof, binding the new keys and account.
#[derive(Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoverAccountRequest {
    pub account_id: String,
    pub recovery_code: String,
    pub new_recovery_code: String,
    pub device: DeviceRecord,
    pub nonce: String,
    pub sig: String,
}

impl std::fmt::Debug for RecoverAccountRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RecoverAccountRequest")
            .field("account_id", &self.account_id)
            .field("device_id", &self.device.device_id)
            .finish_non_exhaustive()
    }
}

impl RecoverAccountRequest {
    pub fn signed(
        account_id: String,
        recovery_code: String,
        device: DeviceRecord,
        key: &dyn DeviceKeyProvider,
    ) -> super::Result<Self> {
        use rand_core::RngCore;
        super::keys::verify_identity_provider(&device, key)?;
        let mut random = [0; 32];
        rand_core::OsRng.fill_bytes(&mut random);
        let nonce = super::keys::encode_b64(&random);
        rand_core::OsRng.fill_bytes(&mut random);
        let new_recovery_code = super::keys::encode_b64(&random);
        let proof = RecoverAccountProof {
            action: RecoverAccountAction::RecoverAccount,
            account_id: account_id.clone(),
            device: device.clone(),
            nonce: nonce.clone(),
            new_recovery_code_hash: super::canonical::sha256_hex(new_recovery_code.as_bytes()),
        };
        let sig = key.sign(SignatureAlgorithm::ES256, &super::canonical::jcs(&proof)?)?;
        Ok(Self {
            account_id,
            recovery_code,
            new_recovery_code,
            device,
            nonce,
            sig: super::keys::encode_b64(&sig),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoverAccountProof {
    pub action: RecoverAccountAction,
    pub account_id: String,
    pub device: DeviceRecord,
    pub nonce: String,
    pub new_recovery_code_hash: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoverAccountAction {
    RecoverAccount,
}

#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct RecoverAccountResponse {
    pub ok: bool,
    pub account_id: String,
    pub device_id: String,
    pub recovery_code: String,
}

impl std::fmt::Debug for RecoverAccountResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RecoverAccountResponse")
            .field("ok", &self.ok)
            .field("account_id", &self.account_id)
            .field("device_id", &self.device_id)
            .finish_non_exhaustive()
    }
}
object!(PairStartRequest {
    token_hash: String,
    initiator: DeviceRecord,
    exp: Timestamp
});
object!(PairStartResponse { pairing_id: String });
object!(PairCompleteRequest {
    token: String,
    joiner: DeviceRecord
});
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PairCompleteResponse {
    pub pairing_id: String,
    pub initiator: DeviceRecord,
    // CONTRACT: Appendix B / W2: migration returns the destination routing account.
    #[serde(default, skip_serializing_if = "Optional::is_missing")]
    pub account_id: Optional<String>,
    #[serde(flatten)]
    pub extra: Extra,
}
object!(PairFinishRequest {
    pairing_id: String,
    confirm: PairConfirm
});
object!(SubmitApprovalsRequest { id: String, exp: Timestamp, envelopes: Vec<Envelope> });
object!(ReplyApprovalRequest { envelope: Envelope });
object!(EnvelopesResponse { envelopes: Vec<Envelope> });
object!(SendMessagesRequest { envelopes: Vec<Envelope> });
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AckMessagesRequest {
    pub ids: Vec<String>,
    // A shared approval id identifies several distinct ciphertext types. Legacy callers may
    // omit this selector; relay-client always names the type actually accepted by the helper.
    #[serde(default, rename = "type", skip_serializing_if = "Optional::is_missing")]
    pub kind: Optional<String>,
    #[serde(flatten)]
    pub extra: Extra,
}
object!(AcceptedResponse { accepted: u64 });
object!(OkResponse { ok: bool });
object!(HealthResponse {
    ok: bool,
    version: String
});

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeleteDeviceBy {
    Device,
    Recovery,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeviceDeleteAction {
    RevokeDevice,
}

// CONTRACT: Appendix B / W2: AK_s signs this fresh challenge-bound JCS deletion proof.
object!(DeviceDeleteProof {
    action: DeviceDeleteAction,
    account: String,
    by: String,
    device_id: String,
    challenge: String
});

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DeleteDeviceRequest {
    pub by: DeleteDeviceBy,
    #[serde(default, skip_serializing_if = "Optional::is_missing")]
    pub recovery_code: Optional<String>,
    #[serde(flatten)]
    pub extra: Extra,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    Unauthorized,
    Forbidden,
    NotFound,
    RateLimited,
    PayloadTooLarge,
    BadEnvelope,
    Expired,
    Conflict,
}

object!(Error {
    code: ErrorCode,
    message: String
});
object!(ErrorResponse { error: Error });

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "t", rename_all = "snake_case")]
pub enum WsFrame {
    Ping {
        #[serde(flatten)]
        extra: Extra,
    },
    Pong {
        #[serde(flatten)]
        extra: Extra,
    },
    Ack {
        id: String,
        #[serde(flatten)]
        extra: Extra,
    },
    Envelope {
        envelope: Box<Envelope>,
        #[serde(flatten)]
        extra: Extra,
    },
    // CONTRACT: Appendix B / W2: unsigned relay hints never authorize device operations.
    PairAccept {
        pairing_id: String,
        joiner: Box<DeviceRecord>,
        #[serde(flatten)]
        extra: Extra,
    },
    ApprovalCancel {
        id: String,
        #[serde(flatten)]
        extra: Extra,
    },
}
