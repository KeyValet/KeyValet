//! Relay HTTP and WebSocket transport. Tokens stay in memory and errors omit response bodies.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use futures_util::StreamExt;
use reqwest::{header, Url};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use tokio::net::TcpStream;
use tokio_tungstenite::{
    tungstenite::{self, client::IntoClientRequest},
    MaybeTlsStream, WebSocketStream,
};

use crate::{
    config::Config,
    envelope::{Envelope, MAX_ENVELOPE_BYTES},
    error::{Error, Result},
    helper::Helper,
};

pub const SUBPROTOCOL: &str = "kv-relay-v1";
pub const NETWORK_TIMEOUT: Duration = Duration::from_secs(10);
pub type Socket = WebSocketStream<MaybeTlsStream<TcpStream>>;

pub fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

pub struct Session {
    token: String,
    pub exp: i64,
}

#[derive(Clone)]
pub struct Relay {
    http: reqwest::Client,
    base: Url,
    device_id: String,
    account_id: String,
}

#[derive(Deserialize)]
struct Challenge {
    challenge: String,
    exp: i64,
}

#[derive(Deserialize)]
struct Verify {
    session_token: String,
    exp: i64,
}

#[derive(Deserialize)]
struct Envelopes {
    envelopes: Vec<Envelope>,
}

#[derive(Deserialize)]
struct Accepted {
    accepted: usize,
}

#[derive(Deserialize)]
struct OkResponse {
    ok: bool,
}

#[derive(Serialize)]
struct Approvals<'a> {
    id: &'a str,
    exp: i64,
    envelopes: &'a [Envelope],
}

#[derive(Serialize)]
struct Messages<'a> {
    envelopes: &'a [Envelope],
}

#[derive(Serialize)]
struct Reply<'a> {
    envelope: &'a Envelope,
}

#[derive(PartialEq, Eq)]
pub enum Route {
    Approvals { id: String, exp: i64, kind: String },
    Reply(String),
    Cancel(String),
    Messages,
}

fn route(envelope: &Envelope) -> Result<Route> {
    let header = envelope.header()?;
    Ok(match header.kind.as_str() {
        "approval_request" | "approval_escalate" => Route::Approvals {
            id: header.id,
            exp: header.exp,
            kind: header.kind,
        },
        // W2 binds reply/cancel routing to the public envelope id, without opening ciphertext.
        "approval_decision" => Route::Reply(header.id),
        "approval_cancel" => Route::Cancel(header.id),
        _ => Route::Messages,
    })
}

pub struct Group {
    pub count: usize,
    pub route: Route,
}

impl Group {
    /// Consecutive fanout envelopes share one approval POST. Replies and cancellations are unary.
    pub fn first(envelopes: &[Envelope]) -> Result<Self> {
        let first = envelopes.first().ok_or(Error::QueueCorrupt)?;
        let first_route = route(first)?;
        if matches!(first_route, Route::Reply(_) | Route::Cancel(_)) {
            return Ok(Self {
                count: 1,
                route: first_route,
            });
        }
        let mut count = 0;
        for envelope in envelopes {
            if route(envelope)? != first_route {
                break;
            }
            count += 1;
        }
        Ok(Self {
            count,
            route: first_route,
        })
    }
}

impl Relay {
    pub fn new(config: &Config) -> Result<Self> {
        // Workspace feature unification can enable both rustls providers. Tungstenite's
        // default TLS builder needs an explicit process default; preserve any existing one.
        let _ = rustls::crypto::ring::default_provider().install_default();
        Ok(Self {
            http: reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .connect_timeout(Duration::from_secs(5))
                .timeout(NETWORK_TIMEOUT)
                .build()
                .map_err(|_| Error::Config)?,
            base: config.base_url()?,
            device_id: config.device_id.clone(),
            account_id: config.account_id.clone(),
        })
    }

    fn url(&self, suffix: &str) -> Result<Url> {
        self.base.join(suffix).map_err(|_| Error::Config)
    }

    fn authorized(
        &self,
        request: reqwest::RequestBuilder,
        session: &Session,
    ) -> Result<reqwest::RequestBuilder> {
        let mut auth = header::HeaderValue::from_str(&format!("Device {}", session.token))
            .map_err(|_| Error::RelayProtocol)?;
        auth.set_sensitive(true);
        Ok(request.header(header::AUTHORIZATION, auth))
    }

    async fn response<R: DeserializeOwned>(
        request: reqwest::RequestBuilder,
        limit: usize,
    ) -> Result<R> {
        let response = request.send().await.map_err(|_| Error::Network)?;
        if !response.status().is_success() {
            return Err(Error::RelayHttp {
                status: response.status().as_u16(),
                retry_after: retry_after(response.headers()),
            });
        }
        if response
            .content_length()
            .is_some_and(|length| length > limit as u64)
        {
            return Err(Error::RelayProtocol);
        }
        let mut body = Vec::new();
        let mut stream = response.bytes_stream();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(|_| Error::Network)?;
            if body.len().saturating_add(chunk.len()) > limit {
                return Err(Error::RelayProtocol);
            }
            body.extend_from_slice(&chunk);
        }
        serde_json::from_slice(&body).map_err(|_| Error::RelayProtocol)
    }

    pub async fn authenticate(&self, helper: &Helper) -> Result<Session> {
        let identity = helper.identity().await?;
        if identity.device_id != self.device_id || identity.account_id != self.account_id {
            return Err(Error::IdentityUnavailable);
        }
        let challenge: Challenge = Self::response(
            self.http
                .post(self.url("v1/auth/challenge")?)
                .json(&serde_json::json!({ "device_id": self.device_id })),
            8192,
        )
        .await?;
        if challenge.exp <= unix_now()
            || URL_SAFE_NO_PAD
                .decode(&challenge.challenge)
                .ok()
                .is_none_or(|bytes| bytes.len() != 32)
        {
            return Err(Error::RelayProtocol);
        }
        // Appendix A/C encode binary fields as unpadded base64url. The helper decodes and signs
        // the raw 32-byte challenge, never the encoded string or a client-selected algorithm.
        let sig = helper.sign(challenge.challenge.clone()).await?;
        let verify: Verify = Self::response(
            self.http
                .post(self.url("v1/auth/verify")?)
                .json(&serde_json::json!({ "device_id": self.device_id,
                    "challenge": challenge.challenge, "sig": sig })),
            8192,
        )
        .await?;
        if verify.session_token.is_empty()
            || verify.session_token.len() > 4096
            || verify.exp <= unix_now() + 60
        {
            return Err(Error::RelayProtocol);
        }
        Ok(Session {
            token: verify.session_token,
            exp: verify.exp,
        })
    }

    pub async fn socket(&self, session: &Session) -> Result<Socket> {
        let mut url = self.url("v1/presence")?;
        url.set_scheme(if self.base.scheme() == "https" {
            "wss"
        } else {
            "ws"
        })
        .map_err(|_| Error::Config)?;
        let mut request = url
            .as_str()
            .into_client_request()
            .map_err(|_| Error::Config)?;
        let mut auth =
            tungstenite::http::HeaderValue::from_str(&format!("Device {}", session.token))
                .map_err(|_| Error::RelayProtocol)?;
        auth.set_sensitive(true);
        request.headers_mut().insert("Authorization", auth);
        request.headers_mut().insert(
            "Sec-WebSocket-Protocol",
            SUBPROTOCOL.parse().map_err(|_| Error::Config)?,
        );
        let mut settings = tungstenite::protocol::WebSocketConfig::default();
        settings.max_message_size = Some(kv_ipc::MAX_LINE_BYTES);
        settings.max_frame_size = Some(kv_ipc::MAX_LINE_BYTES);
        let (socket, _) = tokio::time::timeout(
            NETWORK_TIMEOUT,
            tokio_tungstenite::connect_async_with_config(request, Some(settings), false),
        )
        .await
        .map_err(|_| Error::Network)?
        .map_err(|error| match error {
            tungstenite::Error::Http(response) => Error::RelayHttp {
                status: response.status().as_u16(),
                retry_after: retry_after(response.headers()),
            },
            tungstenite::Error::Protocol(_) => Error::RelayProtocol,
            _ => Error::Network,
        })?;
        // Tungstenite rejects a missing or different protocol before returning this socket.
        Ok(socket)
    }

    pub async fn waiting(&self, session: &Session) -> Result<Vec<Envelope>> {
        let result: Envelopes = Self::response(
            self.authorized(
                self.http.get(self.url("v1/approvals?state=waiting")?),
                session,
            )?,
            500 * (MAX_ENVELOPE_BYTES + 1024),
        )
        .await?;
        Ok(result.envelopes)
    }

    pub async fn ack(&self, session: &Session, id: &str, kind: &str) -> Result<()> {
        let result: OkResponse = Self::response(
            self.authorized(self.http.post(self.url("v1/messages/ack")?), session)?
                .json(&serde_json::json!({ "ids": [id], "type": kind })),
            8192,
        )
        .await?;
        if result.ok {
            Ok(())
        } else {
            Err(Error::RelayProtocol)
        }
    }

    pub async fn send(
        &self,
        session: &Session,
        group: &Group,
        envelopes: &[Envelope],
    ) -> Result<()> {
        if envelopes.is_empty() || group.count != envelopes.len() {
            return Err(Error::QueueCorrupt);
        }
        let request = match &group.route {
            Route::Approvals { id, exp, .. } => {
                self.http.post(self.url("v1/approvals")?).json(&Approvals {
                    id,
                    exp: *exp,
                    envelopes,
                })
            }
            Route::Messages => self
                .http
                .post(self.url("v1/messages")?)
                .json(&Messages { envelopes }),
            Route::Reply(id) | Route::Cancel(id) => {
                let mut url = self.url("v1/approvals/")?;
                url.path_segments_mut()
                    .map_err(|_| Error::Config)?
                    .pop_if_empty()
                    .push(id)
                    .push(if matches!(&group.route, Route::Reply(_)) {
                        "reply"
                    } else {
                        "cancel"
                    });
                let request = self.http.post(url);
                let request = request.json(&Reply {
                    envelope: &envelopes[0],
                });
                let result: OkResponse =
                    Self::response(self.authorized(request, session)?, 8192).await?;
                return if result.ok {
                    Ok(())
                } else {
                    Err(Error::RelayProtocol)
                };
            }
        };
        let accepted: Accepted = Self::response(self.authorized(request, session)?, 8192).await?;
        if accepted.accepted != envelopes.len() {
            return Err(Error::RelayProtocol);
        }
        Ok(())
    }
}

pub fn retry_after(headers: &header::HeaderMap) -> Option<Duration> {
    let text = headers.get(header::RETRY_AFTER)?.to_str().ok()?;
    let delay = if let Ok(seconds) = text.parse::<u64>() {
        Duration::from_secs(seconds)
    } else {
        httpdate::parse_http_date(text)
            .ok()?
            .duration_since(SystemTime::now())
            .unwrap_or_default()
    };
    // Never let an untrusted header overflow an Instant.
    Some(delay.min(Duration::from_secs(24 * 60 * 60)))
}

#[cfg(test)]
#[path = "tests/transport.rs"]
mod coverage_tests;
