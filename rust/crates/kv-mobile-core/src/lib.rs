//! The mobile trust boundary. Only display models and user intents cross into Dart.

mod account;
pub mod api;
mod audit;
mod engine;
mod ffi;
mod frb_generated;
mod hardware;
mod relay;
mod store;
pub mod view;

pub use engine::{MobileCore, MobileKeys};
pub use ffi::{kv_mobile_call, kv_mobile_free, kv_mobile_open, KvKeyCallback};
pub use relay::{PairUri, Relay};
pub use store::Store;
pub(crate) const RELAY_URL: &str = "https://relay.keyvalet.dev/";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Error(pub &'static str);
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.0)
    }
}
impl std::error::Error for Error {}
impl From<kv_core::remote::RemoteError> for Error {
    fn from(error: kv_core::remote::RemoteError) -> Self {
        match error {
            kv_core::remote::RemoteError::KeyUnavailable
            | kv_core::remote::RemoteError::KeyOperationFailed => Self("hardware_unavailable"),
            _ => Self("verification_failed"),
        }
    }
}
impl From<rusqlite::Error> for Error {
    fn from(_: rusqlite::Error) -> Self {
        Self("storage_unavailable")
    }
}
impl From<std::io::Error> for Error {
    fn from(_: std::io::Error) -> Self {
        Self("storage_unavailable")
    }
}
impl From<serde_json::Error> for Error {
    fn from(_: serde_json::Error) -> Self {
        Self("invalid_message")
    }
}
pub type Result<T> = std::result::Result<T, Error>;

pub(crate) fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
        .min(i64::MAX as u64) as i64
}
pub(crate) fn new_id() -> String {
    use rand_core::RngCore;
    let mut raw = [0_u8; 16];
    raw[..6].copy_from_slice(&((now() as u64).saturating_mul(1000)).to_be_bytes()[2..]);
    rand_core::OsRng.fill_bytes(&mut raw[6..]);
    let mut value = u128::from_be_bytes(raw);
    let mut out = [b'0'; 26];
    for byte in out.iter_mut().rev() {
        *byte = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ"[(value & 31) as usize];
        value >>= 5;
    }
    String::from_utf8(out.to_vec()).expect("ULID alphabet is ASCII")
}

#[cfg(test)]
mod tests;
