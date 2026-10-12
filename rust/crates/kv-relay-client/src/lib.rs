//! Reusable, unprivileged control transport. Keys and decrypted protocol bodies belong to the
//! helper and are deliberately absent from this API.
pub mod control_transport;
pub mod controls;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Error(pub &'static str);
pub type Result<T> = std::result::Result<T, Error>;
impl From<kv_core::remote::RemoteError> for Error {
    fn from(error: kv_core::remote::RemoteError) -> Self {
        Self(error.code())
    }
}
impl From<serde_json::Error> for Error {
    fn from(_: serde_json::Error) -> Self {
        Self("invalid_remote_response")
    }
}
