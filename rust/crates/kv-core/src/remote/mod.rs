//! Remote approval contracts and platform-independent cryptography.

pub mod canonical;
pub mod envelope;
mod error;
pub mod hpke;
pub mod ipc;
pub mod keys;
pub mod pairing;
pub mod relay;
pub mod traits;
pub mod types;
pub mod validation;

pub use error::{RemoteError, Result};
pub use keys::{DeviceKeyProvider, EcdhProvider, MessageSigner, SoftwareDeviceKey};
pub use traits::{Approver, Executor, PresenceProbe};
pub use types::*;
