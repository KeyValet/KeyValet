#[cfg(target_os = "macos")]
pub mod presence {
    include!("../../kv-agent/src/presence.rs");
}
#[cfg(target_os = "macos")]
#[path = "../../kv-agent/src/remote/mod.rs"]
pub mod remote;
#[cfg(target_os = "macos")]
pub mod remote_dialog;
