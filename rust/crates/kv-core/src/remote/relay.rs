//! Relay API wire objects from Appendix B.

use super::*;
use serde::{Deserialize, Serialize};

pub const WS_SUBPROTOCOL: &str = "kv-relay-v1";

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
object!(PairCompleteResponse {
    pairing_id: String,
    initiator: DeviceRecord
});
object!(PairFinishRequest {
    pairing_id: String,
    confirm: PairConfirm
});
object!(SubmitApprovalsRequest { id: String, exp: Timestamp, envelopes: Vec<Envelope> });
object!(ReplyApprovalRequest { envelope: Envelope });
object!(EnvelopesResponse { envelopes: Vec<Envelope> });
object!(SendMessagesRequest { envelopes: Vec<Envelope> });
object!(AckMessagesRequest { ids: Vec<String> });
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
}
