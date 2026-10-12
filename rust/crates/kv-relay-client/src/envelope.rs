//! Preserve the exact envelope JSON, including future fields. No cryptography or policy lives here.

use serde::{Deserialize, Serialize};
use serde_json::value::RawValue;

use crate::error::{Error, Result};

pub const MAX_ENVELOPE_BYTES: usize = 80 * 1024;

#[derive(Clone, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Envelope(pub Box<RawValue>);

#[derive(Deserialize)]
pub struct Header {
    pub id: String,
    #[serde(rename = "type")]
    pub kind: String,
    pub exp: i64,
}

impl Envelope {
    pub fn header(&self) -> Result<Header> {
        serde_json::from_str(self.0.get()).map_err(|_| Error::RelayProtocol)
    }

    /// The trusted helper supplies encrypted envelopes. Check framing before persisting them;
    /// version, expiration, signatures and all authorization decisions remain with the helper.
    pub fn validate_for_queue(&self) -> Result<()> {
        #[derive(Deserialize)]
        struct Ciphertext<'a> {
            v: u64,
            account: &'a str,
            from: &'a str,
            to: &'a str,
            created_at: i64,
            enc: &'a str,
            ct: &'a str,
            sig: &'a str,
        }
        if self.0.get().len() > MAX_ENVELOPE_BYTES {
            return Err(Error::HelperProtocol);
        }
        let ciphertext: Ciphertext<'_> =
            serde_json::from_str(self.0.get()).map_err(|_| Error::HelperProtocol)?;
        let header = self.header().map_err(|_| Error::HelperProtocol)?;
        let _ = (ciphertext.v, ciphertext.created_at);
        if header.id.is_empty()
            || header.kind.is_empty()
            || [ciphertext.account, ciphertext.from, ciphertext.to]
                .iter()
                .any(|field| field.is_empty())
            || [ciphertext.enc, ciphertext.ct, ciphertext.sig]
                .iter()
                .any(|field| {
                    field.is_empty()
                        || !field
                            .bytes()
                            .all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_')
                })
        {
            return Err(Error::HelperProtocol);
        }
        Ok(())
    }
}
