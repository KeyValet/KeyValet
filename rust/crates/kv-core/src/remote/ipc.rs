use super::*;
pub use kv_ipc::remote::{allowed_ops, Caller, Op, Request, Response, CALLER_OPS, OPS};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

// CONTRACT: Appendix C: unsigned Grant/Directive inputs omit sig; signing lives in the helper.
#[derive(Debug, Clone, PartialEq)]
pub struct Unsigned<T>(pub T);

impl<T: Serialize> Serialize for Unsigned<T> {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        let mut value = serde_json::to_value(&self.0).map_err(serde::ser::Error::custom)?;
        value
            .as_object_mut()
            .ok_or_else(|| serde::ser::Error::custom("expected unsigned object"))?
            .remove("sig");
        value.serialize(serializer)
    }
}

impl<'de, T: serde::de::DeserializeOwned> Deserialize<'de> for Unsigned<T> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        let mut value = serde_json::Value::deserialize(deserializer)?;
        let object = value
            .as_object_mut()
            .ok_or_else(|| serde::de::Error::custom("expected unsigned object"))?;
        if object.contains_key("sig") {
            return Err(serde::de::Error::custom("unsigned input contains sig"));
        }
        object.insert("sig".into(), serde_json::Value::String(String::new()));
        serde_json::from_value(value)
            .map(Self)
            .map_err(|_| serde::de::Error::custom("invalid unsigned object"))
    }
}

pub type RelayInboundParams = kv_ipc::remote::RelayInboundParams<Envelope>;
pub type RelayInboundRequest = kv_ipc::remote::RelayInboundRequest<Envelope>;
pub type RelayOutboundPollResult = kv_ipc::remote::RelayOutboundPollResult<Envelope>;
pub type PresenceUpdateRequest = kv_ipc::remote::PresenceUpdateRequest<PresenceHint>;
pub type PendingListResult = kv_ipc::remote::PendingListResult<ApprovalRequest>;
pub type DecideParams = kv_ipc::remote::DecideParams<DecisionScope, Decision, ApprovalLevel>;
pub type DecideRequest = kv_ipc::remote::DecideRequest<DecisionScope, Decision, ApprovalLevel>;
pub type GrantIssueRequest = kv_ipc::remote::GrantIssueRequest<Unsigned<Grant>>;
pub type GrantIssueResult = kv_ipc::remote::GrantIssueResult<Grant>;
pub type GrantListResult = kv_ipc::remote::GrantListResult<Grant>;
pub type DirectiveIssueRequest = kv_ipc::remote::DirectiveIssueRequest<Unsigned<Directive>>;
pub type DirectiveIssueResult = kv_ipc::remote::DirectiveIssueResult<DirectiveResult>;
pub type PairStartRequest = kv_ipc::remote::PairStartRequest<PairOffer>;
pub type PairCompleteRequest = kv_ipc::remote::PairCompleteRequest<PairAccept>;
pub type PairConfirmRequest = kv_ipc::remote::PairConfirmRequest<PairConfirm>;
pub type DevicesListResult = kv_ipc::remote::DevicesListResult<DeviceRecord>;
pub type WaitResponse = Response<ToolResult>;
