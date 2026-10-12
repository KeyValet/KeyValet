//! Bounded JSON-lines IPC v4. Each unary exchange owns a connection, so long polling cannot
//! block inbound acknowledgments, identity signing or status updates.

use std::{path::PathBuf, time::Duration};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use kv_ipc::remote::{self, Extra, Op};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use tokio::io::{
    AsyncBufRead, AsyncBufReadExt, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader,
};

use crate::{
    envelope::Envelope,
    error::{Error, Result},
    platform,
};

pub const POLL_WAIT: Duration = Duration::from_secs(30);
const IPC_TIMEOUT: Duration = Duration::from_secs(5);
#[cfg(test)]
pub const IDENTITY_OP: &str = remote::RELAY_IDENTITY;

mod native;

trait Stream: tokio::io::AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: tokio::io::AsyncRead + AsyncWrite + Unpin + Send> Stream for T {}

#[derive(Clone)]
pub struct Helper {
    endpoint: PathBuf,
    relay_handshake: bool,
    #[cfg(test)]
    fake_peer: bool,
}

#[cfg(test)]
#[path = "tests/helper.rs"]
mod coverage_tests;

impl Helper {
    pub fn new() -> Self {
        Self {
            endpoint: platform::helper_endpoint(),
            relay_handshake: cfg!(target_os = "macos"),
            #[cfg(test)]
            fake_peer: false,
        }
    }

    #[cfg(test)]
    pub fn for_test(endpoint: PathBuf, relay_handshake: bool) -> Self {
        Self {
            endpoint,
            relay_handshake,
            fake_peer: true,
        }
    }

    async fn connect(&self) -> Result<Box<dyn Stream>> {
        #[cfg(unix)]
        {
            let stream = tokio::net::UnixStream::connect(&self.endpoint)
                .await
                .map_err(|_| Error::HelperUnavailable)?;
            native::verify(
                stream,
                #[cfg(test)]
                self.fake_peer,
            )
            .await
        }
        #[cfg(windows)]
        {
            native::connect(
                &self.endpoint,
                #[cfg(test)]
                self.fake_peer,
            )
            .await
        }
    }

    async fn exchange<R: DeserializeOwned>(
        &self,
        request: &impl Serialize,
        wait: Duration,
    ) -> Result<R> {
        tokio::time::timeout(wait + IPC_TIMEOUT, async {
            self.exchange_on(self.connect().await?, request).await
        })
        .await
        .map_err(|_| Error::HelperUnavailable)?
    }

    async fn exchange_on<R: DeserializeOwned>(
        &self,
        stream: Box<dyn Stream>,
        request: &impl Serialize,
    ) -> Result<R> {
        let mut stream = BufReader::new(stream);
        if self.relay_handshake {
            // The authenticated relay role selects this subprotocol before remote operations.
            write_json(
                &mut stream,
                &serde_json::json!({ "op": "relay", "protocol": kv_ipc::PROTOCOL_VERSION }),
            )
            .await?;
            let ready: kv_ipc::ReadyMessage = read_json(&mut stream).await?;
            if !matches!(ready, kv_ipc::ReadyMessage::Ready { protocol, .. }
                if protocol == kv_ipc::PROTOCOL_VERSION)
            {
                return Err(Error::HelperProtocol);
            }
        }
        write_json(&mut stream, request).await?;
        // W0's untagged Response buffers through serde Content, which cannot preserve
        // RawValue envelopes. Decode the wrapper first, then its original result bytes.
        #[derive(Deserialize)]
        struct WireResponse {
            ok: bool,
            #[serde(default)]
            result: Option<Box<serde_json::value::RawValue>>,
            #[serde(default)]
            error: Option<remote::Error>,
        }
        let response: WireResponse = read_json(&mut stream).await?;
        match (response.ok, response.result, response.error) {
            (true, Some(result), None) => {
                serde_json::from_str(result.get()).map_err(|_| Error::HelperProtocol)
            }
            // Never put the helper's arbitrary message/code into a log or relay status.
            (false, None, Some(_)) => Err(Error::HelperRejected),
            _ => Err(Error::HelperProtocol),
        }
    }

    async fn request<P: Serialize, R: DeserializeOwned>(
        &self,
        op: Op,
        params: P,
        wait: Duration,
    ) -> Result<R> {
        self.exchange(
            &remote::Request {
                op,
                params,
                extra: Extra::new(),
            },
            wait,
        )
        .await
    }

    pub async fn identity(&self) -> Result<remote::RelayIdentityResult> {
        let result: remote::RelayIdentityResult = self
            .request(
                Op::RelayIdentity,
                remote::Empty {
                    extra: Extra::new(),
                },
                Duration::ZERO,
            )
            .await
            .map_err(|_| Error::IdentityUnavailable)?;
        // Identity keys are P-256. Only check the public representation, never sign or verify here.
        if result.dk_pub["kty"] != "EC"
            || result.dk_pub["crv"] != "P-256"
            || result.dk_pub.get("d").is_some()
            || ["x", "y"].iter().any(|field| {
                result.dk_pub[*field]
                    .as_str()
                    .and_then(|value| URL_SAFE_NO_PAD.decode(value).ok())
                    .is_none_or(|bytes| bytes.len() != 32)
            })
        {
            return Err(Error::IdentityUnavailable);
        }
        Ok(result)
    }
    pub async fn control_poll(
        &self,
    ) -> Result<kv_core::remote::relay_control::RelayControlPollResult> {
        self.request(
            Op::RelayControlPoll,
            kv_core::remote::relay_control::RelayControlPollParams {
                max_wait_ms: 30_000,
            },
            POLL_WAIT,
        )
        .await
    }
    pub async fn control_complete(
        &self,
        params: kv_core::remote::relay_control::RelayControlCompleteParams,
    ) -> Result<()> {
        let _: kv_core::remote::relay::OkResponse = self
            .request(Op::RelayControlComplete, params, Duration::ZERO)
            .await?;
        Ok(())
    }
    pub async fn control_sign(&self, id: String, payload_b64: String) -> Result<String> {
        let result: remote::SignIdentityResult = self
            .request(
                Op::RelayControlSign,
                kv_core::remote::relay_control::RelayControlSignParams { id, payload_b64 },
                Duration::ZERO,
            )
            .await?;
        Ok(result.sig_b64)
    }

    pub async fn receipt(
        &self,
        envelopes: &[Envelope],
        stage: remote::OutboundStage,
    ) -> Result<usize> {
        let result: remote::RelayOutboundAckResult = self
            .request(
                Op::RelayOutboundAck,
                remote::RelayOutboundAckParams {
                    envelopes: envelopes.to_vec(),
                    stage,
                    extra: Extra::new(),
                },
                Duration::ZERO,
            )
            .await?;
        if result.retired_count > envelopes.len()
            || (stage != remote::OutboundStage::Inspect && result.retired_count != 0)
        {
            return Err(Error::HelperProtocol);
        }
        Ok(result.retired_count)
    }

    pub async fn sign(&self, challenge: String) -> Result<String> {
        let result: remote::SignIdentityResult = self
            .request(
                Op::SignIdentity,
                remote::SignIdentityParams {
                    payload_b64: challenge,
                    extra: Extra::new(),
                },
                Duration::ZERO,
            )
            .await
            .map_err(|_| Error::IdentityUnavailable)?;
        if URL_SAFE_NO_PAD.decode(&result.sig_b64).is_err() || result.sig_b64.is_empty() {
            return Err(Error::HelperProtocol);
        }
        Ok(result.sig_b64)
    }

    pub async fn poll(&self) -> Result<Vec<Envelope>> {
        let result: remote::RelayOutboundPollResult<Envelope> = self
            .request(
                Op::RelayOutboundPoll,
                remote::RelayOutboundPollParams {
                    max_wait_ms: POLL_WAIT.as_millis() as u64,
                    extra: Extra::new(),
                },
                POLL_WAIT,
            )
            .await?;
        Ok(result.envelopes)
    }

    pub async fn inbound(&self, envelope: Envelope) -> Result<()> {
        let _: remote::RelayInboundResult = self
            .request(
                Op::RelayInbound,
                remote::RelayInboundParams {
                    envelope,
                    extra: Extra::new(),
                },
                Duration::ZERO,
            )
            .await?;
        // RelayInboundResult requires the literal true. False, errors and EOF never authorize ack.
        Ok(())
    }

    pub async fn status(&self, state: remote::RelayStatusParams) -> Result<()> {
        let _: remote::Empty = self.request(Op::RelayStatus, state, Duration::ZERO).await?;
        Ok(())
    }
}

pub async fn write_json(
    writer: &mut (impl AsyncWrite + Unpin),
    value: &impl Serialize,
) -> Result<()> {
    let mut bytes = serde_json::to_vec(value).map_err(|_| Error::HelperProtocol)?;
    if bytes.len() >= kv_ipc::MAX_LINE_BYTES {
        return Err(Error::HelperProtocol);
    }
    bytes.push(b'\n');
    writer
        .write_all(&bytes)
        .await
        .map_err(|_| Error::HelperUnavailable)?;
    writer.flush().await.map_err(|_| Error::HelperUnavailable)
}

pub async fn read_json<R: DeserializeOwned>(reader: &mut (impl AsyncBufRead + Unpin)) -> Result<R> {
    let mut bytes = Vec::new();
    let count = reader
        .take(kv_ipc::MAX_LINE_BYTES as u64 + 1)
        .read_until(b'\n', &mut bytes)
        .await
        .map_err(|_| Error::HelperUnavailable)?;
    if count == 0 || count > kv_ipc::MAX_LINE_BYTES || bytes.last() != Some(&b'\n') {
        return Err(Error::HelperProtocol);
    }
    serde_json::from_slice(&bytes).map_err(|_| Error::HelperProtocol)
}
