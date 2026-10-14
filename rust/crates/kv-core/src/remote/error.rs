use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RemoteError {
    InvalidJson,
    InvalidEncoding,
    InvalidKey,
    KeyUnavailable,
    KeyOperationFailed,
    KeyOperationCancelled,
    KeyAuthenticationFailed,
    UnsupportedAlgorithm,
    InvalidSignature,
    DecryptionFailed,
    PayloadTooLarge,
    UnsupportedVersion,
    UnsupportedType,
    Expired,
    WrongRecipient,
    WrongSender,
    UnsupportedAuthority,
    DigestMismatch,
    NonceMismatch,
    InsufficientLevel,
    InvalidScope,
    InvalidGrant,
    InvalidDirective,
    MissingState,
    Replay,
    NotWaiting,
}

impl RemoteError {
    pub fn code(self) -> &'static str {
        match self {
            Self::InvalidJson => "invalid_json",
            Self::InvalidEncoding => "invalid_encoding",
            Self::InvalidKey => "invalid_key",
            Self::KeyUnavailable => "key_unavailable",
            Self::KeyOperationFailed => "key_operation_failed",
            Self::KeyOperationCancelled => "key_operation_cancelled",
            Self::KeyAuthenticationFailed => "key_authentication_failed",
            Self::UnsupportedAlgorithm => "unsupported_algorithm",
            Self::InvalidSignature => "invalid_signature",
            Self::DecryptionFailed => "decryption_failed",
            Self::PayloadTooLarge => "payload_too_large",
            Self::UnsupportedVersion => "unsupported_version",
            Self::UnsupportedType => "unsupported_type",
            Self::Expired => "expired",
            Self::WrongRecipient => "wrong_recipient",
            Self::WrongSender => "wrong_sender",
            Self::UnsupportedAuthority => "unsupported_authority",
            Self::DigestMismatch => "digest_mismatch",
            Self::NonceMismatch => "nonce_mismatch",
            Self::InsufficientLevel => "insufficient_level",
            Self::InvalidScope => "invalid_scope",
            Self::InvalidGrant => "invalid_grant",
            Self::InvalidDirective => "invalid_directive",
            Self::MissingState => "missing_state",
            Self::Replay => "replay",
            Self::NotWaiting => "not_waiting",
        }
    }
}

impl fmt::Display for RemoteError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.code())
    }
}

impl std::error::Error for RemoteError {}

pub type Result<T> = std::result::Result<T, RemoteError>;
