use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::{Map, Value};

pub type Extra = Map<String, Value>;
pub type Timestamp = i64;
pub use kv_ipc::remote::{Presence, SignatureAlgorithm};

// CONTRACT: Appendix A / §13.2: missing optional fields and explicit null sign differently.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum Optional<T> {
    #[default]
    Missing,
    Null,
    Value(T),
}

impl<T> Optional<T> {
    pub fn is_missing(&self) -> bool {
        matches!(self, Self::Missing)
    }

    pub fn as_value(&self) -> Option<&T> {
        match self {
            Self::Value(value) => Some(value),
            _ => None,
        }
    }
}

impl<T: Serialize> Serialize for Optional<T> {
    fn serialize<S: Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        match self {
            Self::Value(value) => value.serialize(s),
            Self::Missing | Self::Null => s.serialize_none(),
        }
    }
}

impl<'de, T: Deserialize<'de>> Deserialize<'de> for Optional<T> {
    fn deserialize<D: Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        Ok(match Option::<T>::deserialize(d)? {
            Some(value) => Self::Value(value),
            None => Self::Null,
        })
    }
}

fn nullable<'de, D, T>(d: D) -> std::result::Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(d)
}

// CONTRACT: §13.1–13.2 and A.1–A.7: preserve descriptive/future values without granting authority.
macro_rules! open_enum {
    ($name:ident { $($variant:ident => $wire:literal),+ $(,)? }) => {
        #[derive(Debug, Clone, PartialEq, Eq, Hash)]
        pub enum $name { $($variant,)+ Unknown(String) }

        impl $name {
            pub fn as_str(&self) -> &str {
                match self { $(Self::$variant => $wire,)+ Self::Unknown(value) => value }
            }
        }

        impl Serialize for $name {
            fn serialize<S: Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
                s.serialize_str(self.as_str())
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
                let value = String::deserialize(d)?;
                Ok(match value.as_str() { $($wire => Self::$variant,)+ _ => Self::Unknown(value) })
            }
        }
    };
}

open_enum!(EnvelopeType {
    ApprovalRequest => "approval_request", ApprovalEscalate => "approval_escalate",
    ApprovalDecision => "approval_decision", ApprovalCancel => "approval_cancel", Grant => "grant",
    Directive => "directive", DirectiveResult => "directive_result", PresenceHint => "presence_hint",
    DeviceRevoke => "device_revoke", PairOffer => "pair_offer", PairAccept => "pair_accept", PairConfirm => "pair_confirm"
});
open_enum!(ProtectionKind {
    Tpm2 => "tpm2", SecureEnclave => "secure_enclave", WindowsHello => "windows_hello",
    SoftwareKey => "software_key", NitroEnclave => "nitro_enclave", RemoteHelper => "remote_helper", CloudWorker => "cloud_worker"
});
open_enum!(KeyKind {
    SecureEnclave => "secure_enclave", Tpm2 => "tpm2", PcpTpm => "pcp_tpm", WindowsHello => "windows_hello",
    Software => "software", NitroEnclaveEphemeral => "nitro_enclave_ephemeral", KmsAsymmetric => "kms_asymmetric",
    Webcrypto => "webcrypto", YubikeyPiv => "yubikey_piv"
});
open_enum!(AttestationKind { AppAttest => "app_attest", NitroNsm => "nitro_nsm", TpmQuote => "tpm_quote", None => "none" });
open_enum!(Os { Linux => "linux", Macos => "macos", Windows => "windows", Ios => "ios", Android => "android" });
open_enum!(AgentRuntime {
    ClaudeCode => "claude-code", Codex => "codex", Cursor => "cursor", GeminiCli => "gemini-cli",
    Devin => "devin", Grok => "grok", Http => "http", UnknownRuntime => "unknown"
});
open_enum!(CredentialKind {
    Static => "static", Oauth2 => "oauth2", GoogleServiceAccount => "google_service_account",
    GithubApp => "github_app", Jwt => "jwt", Totp => "totp", Aws => "aws"
});
open_enum!(Capability { Execute => "execute", ApproveQuick => "approve_quick", ApproveStrong => "approve_strong", Sync => "sync", ExecuteIsolated => "execute_isolated" });
open_enum!(ApproverKind { Device => "device", Service => "service" });
open_enum!(IssuerKind { Device => "device", Service => "service", Org => "org" });
open_enum!(PresenceKind {
    None => "none", Unlocked => "unlocked", TouchId => "touchid", WindowsHello => "windows_hello",
    Biometric => "biometric", Polkit => "polkit"
});

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalKind {
    Unlock,
    Use,
    Admin,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Tier {
    T0,
    T1,
    T2,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalLevel {
    Quick,
    Strong,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Decision {
    Allow,
    Deny,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScopeMode {
    PerUse,
    PerCredential,
    PerSession,
    Remember,
    Standing,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DecisionScopeLevel {
    Credential,
    Device,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GrantScopeLevel {
    Credential,
    Device,
    Global,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ScopeOption {
    #[serde(rename = "per_use")]
    PerUse,
    #[serde(rename = "per_credential")]
    PerCredential,
    #[serde(rename = "per_session")]
    PerSession,
    #[serde(rename = "remember:1h")]
    Remember1h,
    #[serde(rename = "remember:8h")]
    Remember8h,
    #[serde(rename = "remember:24h")]
    Remember24h,
    #[serde(rename = "standing:credential")]
    StandingCredential,
    #[serde(rename = "standing:device")]
    StandingDevice,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeliveryMode {
    Banner,
    Silent,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BudgetPeriod {
    #[serde(rename = "1h")]
    OneHour,
    #[serde(rename = "24h")]
    OneDay,
    #[serde(rename = "7d")]
    SevenDays,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GrantKind {
    Grant,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DirectiveKind {
    Directive,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum NotifyPolicy {
    PreferLocal,
    AlwaysPhone,
    Both,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DirectiveOp {
    SetMode,
    RevokeGrant,
    RevokeAllGrants,
    Lock,
    SetUnlockTtl,
    SetClass,
    SetDeviceLabel,
    RevokeDevice,
    Notify,
    QueryStatus,
    QueryPending,
    QueryGrants,
    QueryAudit,
    CancelApproval,
}

#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct Envelope {
    pub v: u32,
    pub r#type: EnvelopeType,
    pub id: String,
    pub account: String,
    pub from: String,
    pub to: String,
    pub created_at: Timestamp,
    pub exp: Timestamp,
    pub enc: String,
    pub ct: String,
    pub sig: String,
    #[serde(flatten)]
    pub extra: Extra,
}

impl std::fmt::Debug for Envelope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Envelope")
            .field("v", &self.v)
            .field("type", &self.r#type)
            .field("id", &self.id)
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EnvelopeHeader {
    pub v: u32,
    pub r#type: EnvelopeType,
    pub id: String,
    pub account: String,
    pub from: String,
    pub to: String,
    pub created_at: Timestamp,
    pub exp: Timestamp,
    #[serde(flatten)]
    pub extra: Extra,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Attestation {
    pub kind: AttestationKind,
    pub doc: Value,
    #[serde(flatten)]
    pub extra: Extra,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Protection {
    pub kind: ProtectionKind,
    #[serde(default, skip_serializing_if = "Optional::is_missing")]
    pub attestation: Optional<Attestation>,
    #[serde(flatten)]
    pub extra: Extra,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Requester {
    pub device_id: String,
    pub label: String,
    pub os: Os,
    pub protection: Protection,
    #[serde(flatten)]
    pub extra: Extra,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Agent {
    pub runtime: AgentRuntime,
    pub cwd: String,
    pub user: String,
    pub pid: u32,
    #[serde(flatten)]
    pub extra: Extra,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Credential {
    pub r#ref: String,
    pub kind: CredentialKind,
    pub display: String,
    pub proxy_only: bool,
    #[serde(flatten)]
    pub extra: Extra,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Operation {
    pub summary: String,
    pub method: String,
    pub host: String,
    pub path: String,
    pub query_keys: Vec<String>,
    pub body_bytes: u64,
    #[serde(flatten)]
    pub extra: Extra,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Delivery {
    pub mode: DeliveryMode,
    pub escalate_after_s: u32,
    #[serde(flatten)]
    pub extra: Extra,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ApprovalRequest {
    pub approval_id: String,
    pub kind: ApprovalKind,
    pub digest: String,
    pub nonce: String,
    pub exp: Timestamp,
    pub requester: Requester,
    pub agent: Agent,
    #[serde(deserialize_with = "nullable")]
    pub credential: Option<Credential>,
    #[serde(deserialize_with = "nullable")]
    pub operation: Option<Operation>,
    pub purpose: String,
    pub tier: Tier,
    pub min_level: ApprovalLevel,
    pub scope_options: Vec<ScopeOption>,
    pub requested_scope: ScopeOption,
    pub merged_count: u32,
    pub delivery: Delivery,
    #[serde(flatten)]
    pub extra: Extra,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DecisionScope {
    pub mode: ScopeMode,
    pub level: DecisionScopeLevel,
    pub until: Timestamp,
    #[serde(flatten)]
    pub extra: Extra,
}

// CONTRACT: §13.1 / A.3: quorum signature entries remain opaque until their binding is specified.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Quorum {
    pub m: u32,
    pub n: u32,
    pub sigs: Vec<Value>,
    #[serde(flatten)]
    pub extra: Extra,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ApprovalDecision {
    pub approval_id: String,
    pub digest: String,
    pub nonce: String,
    pub decision: Decision,
    pub level: ApprovalLevel,
    pub scope: DecisionScope,
    pub approver: String,
    pub approver_kind: ApproverKind,
    #[serde(default, skip_serializing_if = "Optional::is_missing")]
    pub quorum: Optional<Quorum>,
    pub issued_at: Timestamp,
    #[serde(default, skip_serializing_if = "Optional::is_missing")]
    pub reason: Optional<String>,
    pub sig: String,
    #[serde(flatten)]
    pub extra: Extra,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GrantScope {
    pub level: GrantScopeLevel,
    #[serde(default, skip_serializing_if = "Optional::is_missing")]
    pub credential: Optional<String>,
    #[serde(default, skip_serializing_if = "Optional::is_missing")]
    pub hosts: Optional<Vec<String>>,
    #[serde(default, skip_serializing_if = "Optional::is_missing")]
    pub methods: Optional<Vec<String>>,
    #[serde(default, skip_serializing_if = "Optional::is_missing")]
    pub paths: Optional<Vec<String>>,
    #[serde(default, skip_serializing_if = "Optional::is_missing")]
    pub agent: Optional<String>,
    pub max_tier: Tier,
    #[serde(flatten)]
    pub extra: Extra,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Budget {
    pub calls: u64,
    pub per: BudgetPeriod,
    #[serde(default, skip_serializing_if = "Optional::is_missing")]
    pub bytes: Optional<u64>,
    #[serde(flatten)]
    pub extra: Extra,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Grant {
    pub kind: GrantKind,
    pub jti: String,
    pub iss: String,
    pub iss_alg: SignatureAlgorithm,
    pub iss_kind: IssuerKind,
    pub aud: String,
    pub scope: GrantScope,
    #[serde(default, skip_serializing_if = "Optional::is_missing")]
    pub budget: Optional<Budget>,
    pub nbf: Timestamp,
    #[serde(deserialize_with = "nullable")]
    pub exp: Option<Timestamp>,
    pub origin: String,
    #[serde(default, skip_serializing_if = "Optional::is_missing")]
    pub confirm: Optional<String>,
    pub sig: String,
    #[serde(flatten)]
    pub extra: Extra,
}

// CONTRACT: A.5: args stays lossless; typed argument views are validated against op before use.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Directive {
    pub kind: DirectiveKind,
    pub id: String,
    pub iss: String,
    pub iss_alg: SignatureAlgorithm,
    pub iss_kind: IssuerKind,
    pub aud: String,
    pub op: DirectiveOp,
    pub args: Extra,
    pub nonce: String,
    pub exp: Timestamp,
    pub sig: String,
    #[serde(flatten)]
    pub extra: Extra,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DirectiveResult {
    pub id: String,
    pub ok: bool,
    #[serde(deserialize_with = "nullable")]
    pub error: Option<String>,
    pub state: Extra,
    #[serde(flatten)]
    pub extra: Extra,
}

macro_rules! args_object {
    ($name:ident { $($field:ident: $ty:ty),* $(,)? }) => {
        #[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
        pub struct $name { $(pub $field: $ty,)* #[serde(flatten)] pub extra: Extra }
    };
}

args_object!(EmptyArgs {});
args_object!(SetModeArgs { mode: String });
args_object!(RevokeGrantArgs { jti: String });
args_object!(SetUnlockTtlArgs { seconds: u64 });
args_object!(SetClassArgs {
    name: String,
    r#match: Extra,
    exp_s: u64
});
args_object!(SetDeviceLabelArgs { label: String });
args_object!(RevokeDeviceArgs { device_id: String });
args_object!(NotifyArgs {
    policy: NotifyPolicy
});
args_object!(QueryAuditArgs {
    since: Timestamp,
    limit: u32
});
args_object!(CancelApprovalArgs {
    approval_id: String
});

impl Directive {
    pub fn args_as<T: serde::de::DeserializeOwned>(&self) -> super::Result<T> {
        serde_json::from_value(Value::Object(self.args.clone()))
            .map_err(|_| super::RemoteError::InvalidDirective)
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PresenceHint {
    pub device_id: String,
    pub state: Presence,
    pub since: Timestamp,
    pub sent_at: Timestamp,
    #[serde(flatten)]
    pub extra: Extra,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PublicJwk {
    pub kty: String,
    #[serde(default, skip_serializing_if = "Optional::is_missing")]
    pub crv: Optional<String>,
    #[serde(default, skip_serializing_if = "Optional::is_missing")]
    pub x: Optional<String>,
    #[serde(default, skip_serializing_if = "Optional::is_missing")]
    pub y: Optional<String>,
    #[serde(default, skip_serializing_if = "Optional::is_missing")]
    pub n: Optional<String>,
    #[serde(default, skip_serializing_if = "Optional::is_missing")]
    pub e: Optional<String>,
    #[serde(flatten)]
    pub extra: Extra,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ApprovalKey {
    pub r#pub: PublicJwk,
    pub alg: SignatureAlgorithm,
    #[serde(flatten)]
    pub extra: Extra,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DeviceRecord {
    pub device_id: String,
    pub label: String,
    pub os: Os,
    pub key_kind: KeyKind,
    pub dk_pub: PublicJwk,
    /// K1: optional dedicated P-256/ES256 identity key; dk_pub remains the HPKE key.
    #[serde(default, skip_serializing_if = "Optional::is_missing")]
    pub dk_sig: Optional<ApprovalKey>,
    #[serde(deserialize_with = "nullable")]
    pub ak_q: Option<ApprovalKey>,
    #[serde(deserialize_with = "nullable")]
    pub ak_s: Option<ApprovalKey>,
    pub caps: Vec<Capability>,
    #[serde(deserialize_with = "nullable")]
    pub attestation: Option<Attestation>,
    #[serde(flatten)]
    pub extra: Extra,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PairOffer {
    pub token_hash: String,
    pub initiator: DeviceRecord,
    #[serde(flatten)]
    pub extra: Extra,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PairAccept {
    pub token: String,
    pub joiner: DeviceRecord,
    #[serde(flatten)]
    pub extra: Extra,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PairConfirm {
    pub sas: String,
    pub sig: String,
    #[serde(flatten)]
    pub extra: Extra,
}

// CONTRACT: §6.10.3 / A.1: control notifications carry only the affected approval/device id.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ApprovalEscalate {
    pub approval_id: String,
    #[serde(flatten)]
    pub extra: Extra,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ApprovalCancel {
    pub approval_id: String,
    #[serde(flatten)]
    pub extra: Extra,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DeviceRevoke {
    pub device_id: String,
    #[serde(flatten)]
    pub extra: Extra,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ToolStatus {
    Ok,
    ApprovalPending,
    ApprovalDenied,
    ApprovalExpired,
    NoApprover,
    ApprovedRetryRequired,
    StillPending,
    AlreadyConsumed,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ToolApprover {
    pub label: String,
    pub online: bool,
    #[serde(flatten)]
    pub extra: Extra,
}

// CONTRACT: A.8: status-dependent tool fields are omitted when they do not apply.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ToolResult {
    pub status: ToolStatus,
    #[serde(default, skip_serializing_if = "Optional::is_missing")]
    pub approval_id: Optional<String>,
    #[serde(default, skip_serializing_if = "Optional::is_missing")]
    pub expires_at: Optional<Timestamp>,
    #[serde(default, skip_serializing_if = "Optional::is_missing")]
    pub approver: Optional<ToolApprover>,
    #[serde(default, skip_serializing_if = "Optional::is_missing")]
    pub wait_tool: Optional<String>,
    #[serde(default, skip_serializing_if = "Optional::is_missing")]
    pub next_steps: Optional<String>,
    #[serde(default, skip_serializing_if = "Optional::is_missing")]
    pub result: Optional<Value>,
    #[serde(flatten)]
    pub extra: Extra,
}
