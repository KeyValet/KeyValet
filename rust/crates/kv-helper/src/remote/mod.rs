//! The helper owns authorization. Relay and UI processes only transport or display data.

mod audit;
pub mod bootstrap;
mod config;
mod directives;
mod directory;
mod engine;
pub mod gateway;
mod grants;
mod inbound;
pub mod ipc;
mod metadata_master;
mod outbox;
mod owner;
mod pages;
mod pairing;
mod pairing_relay;
pub mod pipeline;
pub mod platform_keys;
mod process;
#[cfg(any(target_os = "linux", test))]
mod process_observer;
pub mod production;
mod recovery;
mod rejoin;
mod relay_config;
pub mod relay_control;
mod revocations;
pub mod server;
pub mod settings;
pub mod startup;
mod store;

pub use config::{ApprovalClass, ApprovalConfig, ClassMatch, Preference};
pub use engine::{
    AuditSink, Clock, DeviceMirror, Execution, FullRequest, RemoteDevice, RemoteHelper,
    RequestRunner, Services, SystemClock,
};
pub use grants::{Coverage, GrantUse};
pub use pipeline::{ApprovalInput, Selection};
pub use store::Store;

use kv_core::remote::RemoteError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Error(pub &'static str);

impl Error {
    pub fn code(self) -> &'static str {
        self.0
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.0)
    }
}

impl std::error::Error for Error {}

impl From<RemoteError> for Error {
    fn from(error: RemoteError) -> Self {
        Self(error.code())
    }
}

impl From<rusqlite::Error> for Error {
    fn from(_: rusqlite::Error) -> Self {
        // SQLite errors can contain SQL or parameters. Only fixed reason codes cross IPC.
        Self("state_unavailable")
    }
}

impl From<serde_json::Error> for Error {
    fn from(_: serde_json::Error) -> Self {
        Self("invalid_json")
    }
}

pub type Result<T> = std::result::Result<T, Error>;

#[cfg(test)]
mod tests;
