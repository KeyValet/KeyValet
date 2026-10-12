//! Fixed relay locations are shared with helper-side peer verification and service integration.

use std::path::PathBuf;

use crate::error::Result;
use kv_platform::paths;

#[cfg(unix)]
mod native;
#[cfg(target_os = "macos")]
use native::user_home;
#[cfg(unix)]
pub use native::verify_helper;
#[cfg(target_os = "linux")]
pub use native::verify_runtime_account;

#[cfg(target_os = "linux")]
pub fn config_path() -> Result<PathBuf> {
    Ok(paths::RELAY_CONFIG.into())
}

#[cfg(target_os = "macos")]
pub fn config_path() -> Result<PathBuf> {
    Ok(user_home()?.join("Library/Application Support/KeyValet/relay-client.toml"))
}

#[cfg(windows)]
pub fn config_path() -> Result<PathBuf> {
    Ok(paths::RELAY_CONFIG.into())
}

#[cfg(target_os = "linux")]
pub fn queue_path() -> Result<PathBuf> {
    Ok(paths::RELAY_QUEUE.into())
}

#[cfg(target_os = "macos")]
pub fn queue_path() -> Result<PathBuf> {
    Ok(config_path()?.with_file_name("relay-queue"))
}

#[cfg(windows)]
pub fn queue_path() -> Result<PathBuf> {
    Ok(paths::RELAY_QUEUE.into())
}

#[cfg(target_os = "linux")]
pub fn helper_endpoint() -> PathBuf {
    paths::RELAY_SOCKET.into()
}

#[cfg(target_os = "macos")]
pub fn helper_endpoint() -> PathBuf {
    paths::RELAY_SOCKET.into()
}

#[cfg(windows)]
pub fn helper_endpoint() -> PathBuf {
    paths::RELAY_PIPE.into()
}

#[cfg(windows)]
pub fn service_name() -> String {
    paths::RELAY_SERVICE_NAME.into()
}

#[cfg(any(target_os = "macos", windows))]
pub fn verify_runtime_account() -> Result<()> {
    Ok(())
}
