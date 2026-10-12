//! These public types are shared by generated Dart bindings and the native C JSON ABI.
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct AccountView {
    pub signed_in: bool,
    pub user_id: String,
    pub provider: String,
    pub email: String,
    pub display_name: String,
    pub expires_at: i64,
    pub relay_url: String,
    pub locale: String,
    pub google_available: bool,
    pub apple_available: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SignInOptions {
    pub attempt_id: String,
    pub provider: String,
    pub nonce_hash: String,
    pub state: String,
    pub google_web_client_id: String,
    pub google_ios_client_id: String,
    pub apple_services_id: String,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Snapshot {
    pub pending: Vec<ApprovalView>,
    pub devices: Vec<DeviceView>,
    pub activity: Vec<ActivityView>,
    pub settings: SettingsView,
    pub connected: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ApprovalView {
    pub id: String,
    pub kind: String,
    pub requester_id: String,
    pub requester_label: String,
    pub os: String,
    pub protection: String,
    pub software_warning: bool,
    pub runtime: String,
    pub cwd: String,
    pub user: String,
    pub agent_pid: u32,
    pub credential_ref: String,
    pub credential_name: String,
    pub credential_kind: String,
    pub proxy_only: bool,
    pub summary: String,
    pub method: String,
    pub host: String,
    pub path: String,
    pub query_keys: Vec<String>,
    pub body_bytes: u32,
    pub purpose: String,
    pub tier: String,
    pub strong: bool,
    pub scope_options: Vec<String>,
    pub requested_scope: String,
    pub merged_count: u32,
    pub expires_at: i64,
    pub created_at: i64,
    pub clock_skew: bool,
    pub banner: bool,
    pub escalated: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct DeviceView {
    pub id: String,
    pub label: String,
    pub os: String,
    pub protection: String,
    pub online: bool,
    pub mode: String,
    pub unlock_ttl_s: u32,
    pub unattended: bool,
    pub unattended_count: u32,
    pub grants: Vec<GrantView>,
    pub recent_activity: Vec<ActivityView>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct GrantView {
    pub id: String,
    pub credential: String,
    pub level: String,
    pub max_tier: String,
    pub expires_at: Option<i64>,
    pub origin: String,
    pub remaining_calls: Option<u32>,
    pub pending_delivery: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ActivityView {
    pub id: String,
    pub device_id: String,
    pub kind: String,
    pub summary: String,
    pub at: i64,
    pub delivered: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SettingsView {
    pub relay_url: String,
    pub away_from_computer: bool,
    pub notifications: bool,
    pub locale: String,
}
impl Default for SettingsView {
    fn default() -> Self {
        Self {
            relay_url: crate::RELAY_URL.into(),
            away_from_computer: false,
            notifications: true,
            locale: "en".into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PairingView {
    pub pairing_id: String,
    pub peer_label: String,
    pub sas: String,
    pub expires_at: i64,
    pub global_grants: u32,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NotificationView {
    pub approval_id: String,
    pub title: String,
    pub body: String,
    pub banner: bool,
    pub quick_allowed: bool,
    pub expires_at: i64,
    pub cancel: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GrantInput {
    pub device_id: String,
    pub credential: String,
    pub scope: String,
    pub hours: u32,
    pub standing: bool,
    pub sensitive: bool,
    pub confirmation: String,
    pub calls: u32,
}
