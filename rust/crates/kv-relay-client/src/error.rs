//! Errors contain transport categories, never peer-provided bodies or envelopes.

use std::{fmt, io, time::Duration};

#[derive(Debug)]
pub enum Error {
    Config,
    HelperUnavailable,
    HelperUntrusted,
    HelperProtocol,
    HelperRejected,
    IdentityUnavailable,
    Network,
    RelayProtocol,
    RelayHttp {
        status: u16,
        retry_after: Option<Duration>,
    },
    Queue(io::Error),
    QueueCorrupt,
    QueueBusy,
}

impl Error {
    pub fn retry_after(&self) -> Option<Duration> {
        match self {
            Self::RelayHttp { retry_after, .. } => *retry_after,
            _ => None,
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Config => f.write_str("invalid_relay_configuration"),
            Self::HelperUnavailable => f.write_str("helper_unavailable"),
            Self::HelperUntrusted => f.write_str("helper_untrusted"),
            Self::HelperProtocol => f.write_str("helper_protocol_error"),
            Self::HelperRejected => f.write_str("helper_rejected_request"),
            Self::IdentityUnavailable => f.write_str("identity_key_unavailable"),
            Self::Network => f.write_str("relay_unreachable"),
            Self::RelayProtocol => f.write_str("relay_protocol_error"),
            Self::RelayHttp { status, .. } => write!(f, "relay_http_{status}"),
            Self::Queue(error) => write!(f, "queue_io_error ({:?})", error.kind()),
            Self::QueueCorrupt => f.write_str("queue_corrupt"),
            Self::QueueBusy => f.write_str("queue_in_use"),
        }
    }
}

impl std::error::Error for Error {}
impl From<io::Error> for Error {
    fn from(value: io::Error) -> Self {
        Self::Queue(value)
    }
}

pub type Result<T> = std::result::Result<T, Error>;
