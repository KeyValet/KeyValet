//! IPC v4 remote namespace. The helper authenticates the caller before applying this table.

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

pub type Extra = Map<String, Value>;
pub type SharedSecret = zeroize::Zeroizing<[u8; 32]>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SignatureAlgorithm {
    ES256,
    RS256,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Presence {
    Present,
    Idle,
    Away,
}

// CONTRACT: §3.1 / §13.1: kv-platform already depends on kv-ipc; it cannot depend on kv-core.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceKeyError {
    InvalidKey,
    Unavailable,
    UnsupportedAlgorithm,
    OperationFailed,
}

impl std::fmt::Display for DeviceKeyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::InvalidKey => "invalid_key",
            Self::Unavailable => "key_unavailable",
            Self::UnsupportedAlgorithm => "unsupported_algorithm",
            Self::OperationFailed => "key_operation_failed",
        })
    }
}

impl std::error::Error for DeviceKeyError {}

pub trait DeviceKeyProvider {
    fn sign(&self, alg: SignatureAlgorithm, payload: &[u8]) -> Result<Vec<u8>, DeviceKeyError>;
    fn ecdh(&self, peer_pub: &[u8]) -> Result<zeroize::Zeroizing<[u8; 32]>, DeviceKeyError>;
    fn public_jwk(&self) -> Result<Value, DeviceKeyError>;
    /// Separate identity signing public key, when the provider uses a dedicated ECDSA key.
    fn identity_sign_jwk(&self) -> Result<Option<Value>, DeviceKeyError> {
        Ok(None)
    }
    fn presence_kind(&self) -> &str;
    fn key_kind(&self) -> &str;
}

// CONTRACT: §6.10.1: retain all raw signals, including missing platform values and extensions.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PresenceSignals {
    pub graphical_session: Option<bool>,
    pub session_active: Option<bool>,
    pub screen_locked: Option<bool>,
    pub screensaver_active: Option<bool>,
    pub idle_seconds: Option<u64>,
    pub display_connected: Option<bool>,
    pub display_awake: Option<bool>,
    pub remote_session_active: Option<bool>,
    pub approval_channel_available: Option<bool>,
    #[serde(flatten)]
    pub extra: Extra,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PresenceState {
    pub state: Presence,
    pub since: i64,
    pub signals: PresenceSignals,
    #[serde(flatten)]
    pub extra: Extra,
}

pub trait PresenceProbe {
    fn state(&self) -> PresenceState;
}

macro_rules! operations {
    ($($variant:ident, $constant:ident, $wire:literal;)+) => {
        $(pub const $constant: &str = $wire;)+
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
        pub enum Op { $(#[serde(rename = $wire)] $variant,)+ }
        pub const OPS: &[Op] = &[$(Op::$variant,)+];
        impl Op {
            pub fn as_str(self) -> &'static str { match self { $(Self::$variant => $constant,)+ } }
            pub fn parse(value: &str) -> Option<Self> { OPS.iter().copied().find(|op| op.as_str() == value) }
        }
    };
}

operations! {
    RelayInbound, RELAY_INBOUND, "remote.relay.inbound";
    RelayOutboundPoll, RELAY_OUTBOUND_POLL, "remote.relay.outbound.poll";
    RelayStatus, RELAY_STATUS, "remote.relay.status";
    SignIdentity, SIGN_IDENTITY, "remote.sign_identity";
    PresenceUpdate, PRESENCE_UPDATE, "remote.presence.update";
    PendingList, PENDING_LIST, "remote.pending.list";
    PendingForAgent, PENDING_FOR_AGENT, "remote.pending.for_agent";
    PendingStopBlock, PENDING_STOP_BLOCK, "remote.pending.stop_block";
    Wait, WAIT, "remote.wait";
    Decide, DECIDE, "remote.decide";
    GrantIssue, GRANT_ISSUE, "remote.grant.issue";
    GrantList, GRANT_LIST, "remote.grant.list";
    GrantRevoke, GRANT_REVOKE, "remote.grant.revoke";
    DirectiveIssue, DIRECTIVE_ISSUE, "remote.directive.issue";
    PairStart, PAIR_START, "remote.pair.start";
    PairComplete, PAIR_COMPLETE, "remote.pair.complete";
    PairConfirm, PAIR_CONFIRM, "remote.pair.confirm";
    AccountRecover, ACCOUNT_RECOVER, "remote.account.recover";
    DevicesList, DEVICES_LIST, "remote.devices.list";
    DevicesRevoke, DEVICES_REVOKE, "remote.devices.revoke";
    DevicesRename, DEVICES_RENAME, "remote.devices.rename";
    Status, STATUS, "remote.status";
    AuditList, AUDIT_LIST, "remote.audit.list";
    RelayIdentity, RELAY_IDENTITY, "remote.relay.identity";
    RelayOutboundAck, RELAY_OUTBOUND_ACK, "remote.relay.outbound.ack";
    RelayControlPoll, RELAY_CONTROL_POLL, "remote.relay.control.poll";
    RelayControlComplete, RELAY_CONTROL_COMPLETE, "remote.relay.control.complete";
    RelayControlSign, RELAY_CONTROL_SIGN, "remote.relay.control.sign";
    ClientTimeoutObserved, CLIENT_TIMEOUT_OBSERVED, "remote.client_timeout_observed";
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Caller {
    RelayClient,
    Hook,
    Mcp,
    CliOwner,
    ApprovalAgent,
}

/// Non-consuming helper notification; it carries no credential or execution result.
pub const APPROVAL_RESOLVED: &str = "remote.approval.resolved";

pub const RELAY_OPS: &[Op] = &[
    Op::RelayInbound,
    Op::RelayOutboundPoll,
    Op::RelayStatus,
    Op::SignIdentity,
    Op::RelayIdentity,
    Op::RelayOutboundAck,
    Op::RelayControlPoll,
    Op::RelayControlComplete,
    Op::RelayControlSign,
];
pub const HOOK_OPS: &[Op] = &[Op::PendingForAgent, Op::PendingStopBlock];
pub const MCP_OPS: &[Op] = &[
    Op::Wait,
    Op::PendingList,
    Op::Status,
    Op::ClientTimeoutObserved,
];
// CONTRACT: Appendix C: use the explicit per-op callers; privileged channels are separate roles.
pub const CLI_OPS: &[Op] = &[
    Op::AccountRecover,
    Op::AuditList,
    Op::PendingList,
    Op::Decide,
    Op::GrantIssue,
    Op::GrantList,
    Op::GrantRevoke,
    Op::DirectiveIssue,
    Op::PairStart,
    Op::PairComplete,
    Op::PairConfirm,
    Op::DevicesList,
    Op::DevicesRevoke,
    Op::DevicesRename,
    Op::Status,
];
pub const AGENT_OPS: &[Op] = &[
    Op::PresenceUpdate,
    Op::Decide,
    Op::GrantIssue,
    Op::DirectiveIssue,
    Op::PairStart,
    Op::PairComplete,
    Op::PairConfirm,
];
pub const CALLER_OPS: &[(Caller, &[Op])] = &[
    (Caller::RelayClient, RELAY_OPS),
    (Caller::Hook, HOOK_OPS),
    (Caller::Mcp, MCP_OPS),
    (Caller::CliOwner, CLI_OPS),
    (Caller::ApprovalAgent, AGENT_OPS),
];

pub fn allowed_ops(caller: Caller) -> &'static [Op] {
    match caller {
        Caller::RelayClient => RELAY_OPS,
        Caller::Hook => HOOK_OPS,
        Caller::Mcp => MCP_OPS,
        Caller::CliOwner => CLI_OPS,
        Caller::ApprovalAgent => AGENT_OPS,
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Request<P = Value> {
    pub op: Op,
    pub params: P,
    #[serde(flatten)]
    pub extra: Extra,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Response<R = Value> {
    Ok {
        ok: crate::True,
        result: R,
        #[serde(flatten)]
        extra: Extra,
    },
    Err {
        ok: crate::False,
        error: Error,
        #[serde(flatten)]
        extra: Extra,
    },
}

impl<R> Response<R> {
    pub fn ok(result: R) -> Self {
        Self::Ok {
            ok: crate::True,
            result,
            extra: Extra::new(),
        }
    }
    pub fn err(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self::Err {
            ok: crate::False,
            error: Error {
                code: code.into(),
                message: message.into(),
                extra: Extra::new(),
            },
            extra: Extra::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Error {
    pub code: String,
    pub message: String,
    #[serde(flatten)]
    pub extra: Extra,
}

macro_rules! object {
    ($name:ident { $($field:ident: $ty:ty),* $(,)? }) => {
        #[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
        pub struct $name { $(pub $field: $ty,)* #[serde(flatten)] pub extra: Extra }
    };
}

object!(Empty {});
object!(RelayOutboundPollParams { max_wait_ms: u64 });
object!(RelayStatusParams { connected: bool, last_error: Option<String>, since: i64 });
object!(SignIdentityParams {
    payload_b64: String
});
object!(SignIdentityResult { sig_b64: String });
object!(RelayIdentityResult {
    dk_pub: Value,
    device_id: String,
    account_id: String
});
object!(RelayOutboundAckResult {
    retired_count: usize
});

/// Only the helper decides whether a queued prefix is obsolete. A transport receipt grants
/// no authorization and is bound to the complete ciphertext envelope, including extensions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OutboundStage {
    Spooled,
    Accepted,
    Inspect,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelayOutboundAckParams<E = Value> {
    pub envelopes: Vec<E>,
    pub stage: OutboundStage,
    #[serde(flatten)]
    pub extra: Extra,
}
object!(PendingForAgentParams { agent_pid: u32 });
object!(ApprovalIdParams {
    approval_id: String
});
object!(PendingStopBlockResult {
    allowed: bool,
    blocks_left: u32
});
object!(WaitParams {
    approval_id: String,
    max_wait_ms: u64
});
object!(GrantRevokeParams { jti: String });
// CONTRACT: Appendix C: abbreviated device params identify a device by device_id.
object!(DeviceIdParams { device_id: String });
object!(DeviceRenameParams {
    device_id: String,
    label: String
});
object!(PairSasResult { sas: String });
object!(PendingForAgentEntry {
    approval_id: String,
    expires_at: i64,
    stop_hook_blocks: u32
});
object!(PendingForAgentResult { pending: Vec<PendingForAgentEntry> });
object!(StatusApprover {
    label: String,
    online: bool
});
object!(StatusResult { relay: RelayConnection, approvers: Vec<StatusApprover>, pending_n: u64, grants_n: u64, unattended: bool, runtime_budget_s: u32 });

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RelayConnection {
    Connected,
    Offline,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelayInboundParams<E = Value> {
    pub envelope: E,
    #[serde(flatten)]
    pub extra: Extra,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelayInboundResult {
    pub ack: crate::True,
    #[serde(flatten)]
    pub extra: Extra,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelayOutboundPollResult<E = Value> {
    pub envelopes: Vec<E>,
    #[serde(flatten)]
    pub extra: Extra,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PendingListParams {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_pid: Option<u32>,
    #[serde(flatten)]
    pub extra: Extra,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingListResult<R = Value> {
    pub pending: Vec<R>,
    #[serde(flatten)]
    pub extra: Extra,
}

// CONTRACT: Appendix C: decision/level stay strings here; kv-core supplies closed wire enum aliases.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecideParams<S = Value, D = String, L = String> {
    pub approval_id: String,
    pub decision: D,
    pub scope: S,
    pub level: L,
    #[serde(flatten)]
    pub extra: Extra,
}

/// Owner projections contain requests, never issuer identity or signature material.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(
    deny_unknown_fields,
    bound(deserialize = "S: Deserialize<'de>, D: Deserialize<'de>, L: Deserialize<'de>")
)]
pub struct DecideIntent<S = Value, D = String, L = String> {
    pub approval_id: String,
    pub decision: D,
    pub scope: S,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope_option: Option<String>,
    /// Compatibility hint: the helper may increase, but never lower, its selected level.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub level: Option<L>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GrantSource {
    Preauthorization,
    Settings,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(
    deny_unknown_fields,
    bound(deserialize = "S: Deserialize<'de>, B: Deserialize<'de>, K: Deserialize<'de>")
)]
pub struct GrantIntent<S = Value, B = Value, K = String> {
    pub source: GrantSource,
    pub kind: K,
    pub aud: String,
    pub scope: S,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub budget: Option<B>,
    pub nbf: i64,
    pub exp: Option<i64>,
    pub origin: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub confirm: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub confirmation_token: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GrantConfirmation {
    pub confirmation_token: String,
    pub expires_at: i64,
    pub device_id: String,
    pub label: String,
    #[serde(default = "one_confirmation")]
    pub confirmations_left: u8,
}

fn one_confirmation() -> u8 {
    1
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DirectiveIntent<O = String, K = String> {
    pub kind: K,
    pub aud: String,
    pub op: O,
    pub args: Extra,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PairJoinIntent {
    pub uri: String,
}

#[derive(Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccountRecoverIntent {
    pub account_id: String,
    pub recovery_code: String,
    pub relay_url: String,
    #[serde(default)]
    pub software: bool,
}

#[derive(Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccountRecoverResult {
    pub binding: RelayBinding,
    pub recovery_code: String,
}
impl std::fmt::Debug for AccountRecoverResult {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AccountRecoverResult")
            .field("binding", &self.binding)
            .field("recovery_code", &"[redacted]")
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PairConfirmIntent {
    pub sas: String,
    pub confirmed: bool,
    #[serde(default, skip_serializing_if = "is_false")]
    pub exclude_global: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RelayBinding {
    pub relay_url: String,
    pub device_id: String,
    pub account_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecideResult {
    pub sent: crate::True,
    #[serde(flatten)]
    pub extra: Extra,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GrantIssueResult<G = Value> {
    pub grant: G,
    #[serde(flatten)]
    pub extra: Extra,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GrantListResult<G = Value> {
    pub grants: Vec<G>,
    #[serde(flatten)]
    pub extra: Extra,
}

/// List entries carry metadata, not reusable signed authorization objects.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GrantMetadata {
    pub jti: String,
    pub aud: String,
    pub exp: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sig: Option<String>,
    #[serde(flatten)]
    pub extra: Extra,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct GrantListParams {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub after: Option<String>,
    #[serde(skip_serializing_if = "default_page_limit")]
    pub limit: u16,
}
fn default_page_limit(limit: &u16) -> bool {
    *limit == 50
}
fn is_false(value: &bool) -> bool {
    !value
}
impl Default for GrantListParams {
    fn default() -> Self {
        Self {
            after: None,
            limit: 50,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DirectiveIssueResult<R = Value> {
    pub result: R,
    #[serde(flatten)]
    pub extra: Extra,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DevicesListResult<D = Value> {
    pub devices: Vec<D>,
    #[serde(flatten)]
    pub extra: Extra,
}

pub type RelayInboundRequest<E = Value> = Request<RelayInboundParams<E>>;
pub type RelayIdentityRequest = Request<Empty>;
pub type RelayOutboundAckRequest<E = Value> = Request<RelayOutboundAckParams<E>>;
pub type RelayOutboundPollRequest = Request<RelayOutboundPollParams>;
pub type RelayStatusRequest = Request<RelayStatusParams>;
pub type SignIdentityRequest = Request<SignIdentityParams>;
pub type PresenceUpdateRequest<P = Value> = Request<P>;
pub type PendingListRequest = Request<PendingListParams>;
pub type PendingForAgentRequest = Request<PendingForAgentParams>;
pub type PendingStopBlockRequest = Request<ApprovalIdParams>;
pub type WaitRequest = Request<WaitParams>;
pub type DecideRequest<S = Value, D = String, L = String> = Request<DecideParams<S, D, L>>;
pub type GrantIssueRequest<G = Value> = Request<G>;
pub type GrantListRequest = Request<GrantListParams>;
pub type GrantRevokeRequest = Request<GrantRevokeParams>;
pub type DirectiveIssueRequest<D = Value> = Request<D>;
pub type PairStartRequest<P = Value> = Request<P>;
pub type PairCompleteRequest<P = Value> = Request<P>;
pub type PairConfirmRequest<P = Value> = Request<P>;
pub type DevicesListRequest = Request<Empty>;
pub type DevicesRevokeRequest = Request<DeviceIdParams>;
pub type DevicesRenameRequest = Request<DeviceRenameParams>;
pub type StatusRequest = Request<Empty>;

#[cfg(test)]
mod metadata_tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn grant_metadata_preserves_signature_presence_without_fabricating_one() {
        for value in [
            json!({"jti":"id","aud":"device","exp":null,"sig":"signature","scope":{}}),
            json!({"jti":"id","aud":"device","exp":null,"sig":"","authority":"approval_decision"}),
            json!({"jti":"id","aud":"device","exp":null,"object_omitted":true}),
        ] {
            let metadata: GrantMetadata = serde_json::from_value(value.clone()).unwrap();
            assert_eq!(serde_json::to_value(metadata).unwrap(), value);
        }
        let params: GrantListParams = serde_json::from_value(json!({})).unwrap();
        assert_eq!(params.limit, 50);
        assert_eq!(serde_json::to_value(params).unwrap(), json!({}));
        assert!(serde_json::from_value::<GrantListParams>(json!({"unknown":true})).is_err());
    }
}
