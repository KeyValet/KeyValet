//! Typed helper-to-relay-client control transport. Requests contain public device records and
//! sealed envelopes; the helper never receives HTTP session tokens or a network socket.
use super::{relay::*, DeviceRecord, Envelope};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RelayControlJob {
    pub id: String,
    pub relay_url: String,
    pub device_id: Option<String>,
    pub command: RelayControlCommand,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(
    tag = "op",
    content = "params",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum RelayControlCommand {
    Authenticate(DeviceRecord),
    Register(RegisterDeviceRequest),
    RecoverAccount(RecoverAccountRequest),
    PairStart(PairStartRequest),
    PairComplete(PairCompleteRequest),
    PairFinish(PairFinishRequest),
    Messages(SendMessagesRequest),
    Ack(AckMessagesRequest),
    Challenge(ChallengeRequest),
    Pending,
    DeleteDevice {
        device_id: String,
        challenge: String,
        sig: String,
    },
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    content = "value",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum RelayControlResult {
    Authenticated { account_id: String },
    Registered(RegisterDeviceResponse),
    Recovered(RecoverAccountResponse),
    PairStarted(PairStartResponse),
    PairCompleted(Box<PairCompleteResponse>),
    Accepted(AcceptedResponse),
    Ok(OkResponse),
    Challenge(ChallengeResponse),
    Pending(Vec<Envelope>),
    Failure(RelayControlError),
}

/// Only fixed codes cross the control boundary. Arbitrary HTTP bodies never become logs or
/// helper audit fields.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RelayControlError {
    BadEnvelope,
    Unauthorized,
    Forbidden,
    UnknownToken,
    Replay,
    Expired,
    PayloadTooLarge,
    RateLimited,
    RelayUnreachable,
    InvalidRemoteResponse,
    InvalidIdentityChallenge,
}
impl RelayControlError {
    pub fn code(self) -> &'static str {
        match self {
            Self::BadEnvelope => "bad_envelope",
            Self::Unauthorized => "unauthorized",
            Self::Forbidden => "forbidden",
            Self::UnknownToken => "unknown_token",
            Self::Replay => "replay",
            Self::Expired => "expired",
            Self::PayloadTooLarge => "payload_too_large",
            Self::RateLimited => "rate_limited",
            Self::RelayUnreachable => "relay_unreachable",
            Self::InvalidRemoteResponse => "invalid_remote_response",
            Self::InvalidIdentityChallenge => "invalid_identity_challenge",
        }
    }
    pub fn from_code(code: &str) -> Self {
        match code {
            "bad_envelope" => Self::BadEnvelope,
            "unauthorized" => Self::Unauthorized,
            "forbidden" => Self::Forbidden,
            "unknown_token" => Self::UnknownToken,
            "replay" => Self::Replay,
            "expired" => Self::Expired,
            "payload_too_large" => Self::PayloadTooLarge,
            "rate_limited" => Self::RateLimited,
            "invalid_remote_response" => Self::InvalidRemoteResponse,
            "invalid_identity_challenge" => Self::InvalidIdentityChallenge,
            _ => Self::RelayUnreachable,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RelayControlPollParams {
    pub max_wait_ms: u64,
}
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RelayControlPollResult {
    pub request: Option<RelayControlJob>,
}
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RelayControlCompleteParams {
    pub id: String,
    pub result: RelayControlResult,
}
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RelayControlSignParams {
    pub id: String,
    pub payload_b64: String,
}
