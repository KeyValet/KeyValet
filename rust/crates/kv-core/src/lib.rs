//! Session authorization and request dispatch: the glue between kv-ipc's wire protocol and
//! kv-vault's storage. Direct port of src/helper/dispatch.ts, settings.ts, and auth-gate.ts.

#[cfg(feature = "desktop")]
pub mod auth_gate;
#[cfg(feature = "desktop")]
pub mod dispatch;
#[cfg(feature = "desktop")]
pub mod prompt;
#[cfg(feature = "remote")]
pub mod remote;
#[cfg(feature = "desktop")]
pub mod settings;
#[cfg(feature = "desktop")]
pub mod summarize;

pub use kv_ipc::{AuthMessage, PROTOCOL_VERSION};

#[cfg(feature = "desktop")]
pub use auth_gate::{cooldown_remaining, touch_id_gate, GateResult};
#[cfg(feature = "desktop")]
pub use dispatch::{
    cred_key, dispatch, resolve_hint, set_static, AuthorizeGate, ClientContext, JsonMap,
    SessionAuth, TouchIdSessionGate,
};
#[cfg(feature = "desktop")]
pub use kv_platform::{AuthOutcome, Authenticator, Confirmer};
#[cfg(feature = "desktop")]
pub use settings::{
    compare_and_write_settings, is_loosening, parse_mode, read_settings, remember_active,
    remember_until, stricter, write_settings, GrantMode, Settings, GRANT_MODES,
};
