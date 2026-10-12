//! Remote approval contracts and platform-independent cryptography.

pub mod audit;
pub mod canonical;
pub mod envelope;
mod error;
pub mod hpke;
pub mod ipc;
pub mod keys;
pub mod pairing;
pub mod relay;
pub mod relay_control;
pub mod traits;
pub mod types;
pub mod validation;

pub use error::{RemoteError, Result};
pub use keys::{
    verify_identity_signature, DeviceKeyProvider, EcdhProvider, MessageSigner, SoftwareDeviceKey,
    SoftwareDeviceKeyProvider,
};
pub use traits::{Approver, Executor, PresenceProbe};
pub use types::*;
