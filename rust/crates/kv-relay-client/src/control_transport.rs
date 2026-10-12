//! Relay-client control transport carries only public records and encrypted envelopes.

use crate::{Error, Result};
use futures_util::{SinkExt, StreamExt};
use kv_core::remote::canonical::from_json;
use kv_core::remote::keys::decode_b64;
use kv_core::remote::relay::*;
use kv_core::remote::*;
use reqwest::{Client, Url};
use serde::{de::DeserializeOwned, Serialize};
use std::sync::Arc;
use tokio_tungstenite::{
    tungstenite::{client::IntoClientRequest, protocol::WebSocketConfig, Message},
    MaybeTlsStream, WebSocketStream,
};
use zeroize::Zeroizing;

type Socket = WebSocketStream<MaybeTlsStream<tokio::net::TcpStream>>;
type Sessions = std::collections::HashMap<String, (Zeroizing<String>, i64)>;
type Sockets = std::collections::HashMap<String, Socket>;

#[derive(Clone)]
pub struct RelayApi {
    pub url: Url,
    client: Client,
    accounts: Arc<tokio::sync::Mutex<std::collections::HashMap<String, String>>>,
    sessions: Arc<tokio::sync::Mutex<Sessions>>,
    sockets: Arc<tokio::sync::Mutex<Sockets>>,
}

impl RelayApi {
    pub fn new(url: &str) -> Result<Self> {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let url = Url::parse(url).map_err(|_| Error("invalid_relay_url"))?;
        let loopback = url
            .host_str()
            .and_then(|host| {
                host.trim_matches(['[', ']'])
                    .parse::<std::net::IpAddr>()
                    .ok()
            })
            .is_some_and(|ip| ip.is_loopback());
        if !(url.scheme() == "https" || (url.scheme() == "http" && loopback))
            || url.host_str().is_none()
            || !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
            || url.path() != "/"
            || (url.scheme() == "https" && url.port_or_known_default() != Some(443))
        {
            return Err(Error("invalid_relay_url"));
        }
        let client = Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .connect_timeout(std::time::Duration::from_secs(5))
            .timeout(std::time::Duration::from_secs(15))
            .build()
            .map_err(|_| Error("relay_unreachable"))?;
        Ok(Self {
            url,
            client,
            accounts: Arc::new(tokio::sync::Mutex::new(Default::default())),
            sessions: Arc::new(tokio::sync::Mutex::new(Default::default())),
            sockets: Arc::new(tokio::sync::Mutex::new(Default::default())),
        })
    }

    pub async fn post<T: Serialize + ?Sized, R: DeserializeOwned>(
        &self,
        path: &str,
        value: &T,
        token: Option<&str>,
    ) -> Result<R> {
        let mut request = self
            .client
            .post(
                self.url
                    .join(path)
                    .map_err(|_| Error("invalid_relay_url"))?,
            )
            .json(value);
        if let Some(token) = token {
            request = request.header(reqwest::header::AUTHORIZATION, Self::authorization(token)?);
        }
        let response = request
            .send()
            .await
            .map_err(|_| Error("relay_unreachable"))?;
        if let Some(token) = token {
            if response.status() == reqwest::StatusCode::UNAUTHORIZED
                || (matches!(path, "v1/pair/finish" | "v1/pair/complete")
                    && response.status().is_success())
            {
                self.forget_session(token).await;
            }
        }
        Self::response(response).await
    }

    /// Recovery authenticates with its one-use code and replacement DK, without a session.
    pub async fn recover_account(
        &self,
        request: &RecoverAccountRequest,
    ) -> Result<RecoverAccountResponse> {
        let response: RecoverAccountResponse = self.post("v1/recovery", request, None).await?;
        if !response.ok
            || response.account_id != request.account_id
            || response.device_id != request.device.device_id
            || decode_b64(&response.recovery_code).map_or(true, |code| code.len() != 32)
            || response.recovery_code != request.new_recovery_code
        {
            return Err(Error("invalid_remote_response"));
        }
        // Use the same lock order as authenticate(); revoked sessions must not remain cached.
        let mut sessions = self.sessions.lock().await;
        let mut accounts = self.accounts.lock().await;
        let revoked = accounts
            .iter()
            .filter(|(_, account)| **account == response.account_id)
            .map(|(device, _)| device.clone())
            .collect::<Vec<_>>();
        let mut sockets = self.sockets.lock().await;
        for device in revoked {
            if let Some((token, _)) = sessions.remove(&device) {
                sockets.remove(token.as_str());
            }
            accounts.remove(&device);
        }
        Ok(response)
    }

    async fn forget_session(&self, token: &str) {
        self.sessions
            .lock()
            .await
            .retain(|_, (cached, _)| cached.as_str() != token);
    }

    pub async fn delete_device(
        &self,
        id: &str,
        token: &str,
        challenge: &str,
        sig: &str,
    ) -> Result<()> {
        let path = format!("v1/devices/{}", url_id(id));
        let response = self
            .client
            .delete(
                self.url
                    .join(&path)
                    .map_err(|_| Error("invalid_relay_url"))?,
            )
            .header(reqwest::header::AUTHORIZATION, Self::authorization(token)?)
            .header(STRONG_CHALLENGE_HEADER, challenge)
            .header(STRONG_SIGNATURE_HEADER, sig)
            .json(&DeleteDeviceRequest {
                by: DeleteDeviceBy::Device,
                recovery_code: Optional::Missing,
                extra: Extra::new(),
            })
            .send()
            .await
            .map_err(|_| Error("relay_unreachable"))?;
        if response.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(());
        }
        let response: OkResponse = Self::response(response).await?;
        if response.ok {
            Ok(())
        } else {
            Err(Error("invalid_remote_response"))
        }
    }

    pub async fn pending(&self, token: &str) -> Result<Vec<Envelope>> {
        // CONTRACT: Appendix B: pairing and general envelopes are replayed over /v1/presence.
        for _ in 0..2 {
            let mut sockets = self.sockets.lock().await;
            if !sockets.contains_key(token) {
                let mut url = self
                    .url
                    .join("v1/presence")
                    .map_err(|_| Error("invalid_relay_url"))?;
                let scheme = if url.scheme() == "https" { "wss" } else { "ws" };
                url.set_scheme(scheme)
                    .map_err(|_| Error("invalid_relay_url"))?;
                let mut request = url
                    .as_str()
                    .into_client_request()
                    .map_err(|_| Error("relay_unreachable"))?;
                request
                    .headers_mut()
                    .insert("authorization", Self::authorization(token)?);
                request.headers_mut().insert(
                    "sec-websocket-protocol",
                    WS_SUBPROTOCOL
                        .parse()
                        .map_err(|_| Error("relay_unreachable"))?,
                );
                let limit = kv_core::remote::envelope::MAX_ENVELOPE_BYTES + 4096;
                let config = WebSocketConfig::default()
                    .max_message_size(Some(limit))
                    .max_frame_size(Some(limit));
                let (socket, response) = tokio::time::timeout(
                    std::time::Duration::from_secs(10),
                    tokio_tungstenite::connect_async_with_config(request, Some(config), false),
                )
                .await
                .map_err(|_| Error("relay_unreachable"))?
                .map_err(|_| Error("relay_unreachable"))?;
                if response
                    .headers()
                    .get("sec-websocket-protocol")
                    .and_then(|value| value.to_str().ok())
                    != Some(WS_SUBPROTOCOL)
                {
                    return Err(Error("invalid_remote_response"));
                }
                sockets.insert(token.into(), socket);
            }
            let socket = sockets.get_mut(token).ok_or(Error("relay_unreachable"))?;
            let mut envelopes = Vec::new();
            let mut closed = false;
            // Each frame is bounded to 68 KiB; eight frames fit the 1 MiB IPC completion.
            for _ in 0..8 {
                let message =
                    match tokio::time::timeout(std::time::Duration::from_millis(50), socket.next())
                        .await
                    {
                        Err(_) => break,
                        Ok(Some(Ok(message))) => message,
                        _ => {
                            closed = true;
                            break;
                        }
                    };
                match message {
                    Message::Text(text) => match from_json::<WsFrame>(text.as_bytes())? {
                        WsFrame::Envelope { envelope, .. } => envelopes.push(*envelope),
                        WsFrame::Ping { .. } => socket
                            .send(Message::Text("{\"t\":\"pong\"}".into()))
                            .await
                            .map_err(|_| Error("relay_unreachable"))?,
                        _ => {}
                    },
                    Message::Ping(bytes) => socket
                        .send(Message::Pong(bytes))
                        .await
                        .map_err(|_| Error("relay_unreachable"))?,
                    Message::Close(_) => {
                        closed = true;
                        break;
                    }
                    _ => {}
                }
            }
            if closed {
                sockets.remove(token);
                if envelopes.is_empty() {
                    continue;
                }
            }
            return Ok(envelopes);
        }
        Err(Error("relay_unreachable"))
    }

    fn authorization(token: &str) -> Result<reqwest::header::HeaderValue> {
        // CONTRACT: Appendix B: relay sessions use Device authentication, never Bearer.
        let mut value = reqwest::header::HeaderValue::from_str(&format!("Device {token}"))
            .map_err(|_| Error("invalid_remote_response"))?;
        value.set_sensitive(true);
        Ok(value)
    }

    async fn response<R: DeserializeOwned>(mut response: reqwest::Response) -> Result<R> {
        let status = response.status();
        let mut bytes = Zeroizing::new(Vec::new());
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|_| Error("relay_unreachable"))?
        {
            if bytes.len().saturating_add(chunk.len()) > 1024 * 1024 {
                return Err(Error("payload_too_large"));
            }
            bytes.extend_from_slice(&chunk);
        }
        if !status.is_success() {
            return Err(Error(match status.as_u16() {
                400 => "bad_envelope",
                401 => "unauthorized",
                403 => "forbidden",
                404 => "unknown_token",
                409 => "replay",
                410 => "expired",
                413 => "payload_too_large",
                429 => "rate_limited",
                _ => "relay_unreachable",
            }));
        }
        from_json(&bytes).map_err(Into::into)
    }

    pub async fn authenticate<F, Fut>(
        &self,
        local: &DeviceRecord,
        sign: F,
    ) -> Result<Zeroizing<String>>
    where
        F: FnOnce(String) -> Fut,
        Fut: std::future::Future<Output = Result<String>>,
    {
        let mut sessions = self.sessions.lock().await;
        let now = unix_now();
        sessions.retain(|_, (_, exp)| *exp > now.saturating_add(60));
        if let Some((token, _)) = sessions.get(&local.device_id) {
            return Ok(token.clone());
        }
        let challenge: ChallengeResponse = self
            .post(
                "v1/auth/challenge",
                &ChallengeRequest {
                    device_id: local.device_id.clone(),
                    extra: Extra::new(),
                },
                None,
            )
            .await?;
        let bytes = decode_b64(&challenge.challenge)?;
        if bytes.len() != 32 || challenge.exp <= now {
            return Err(Error("invalid_identity_challenge"));
        }
        let sig = sign(challenge.challenge.clone()).await?;
        kv_core::remote::verify_identity_signature(local, &bytes, &decode_b64(&sig)?)?;
        let response: AuthVerifyResponse = self
            .post(
                "v1/auth/verify",
                &AuthVerifyRequest {
                    device_id: local.device_id.clone(),
                    challenge: challenge.challenge,
                    sig,
                    extra: Extra::new(),
                },
                None,
            )
            .await?;
        if response.session_token.len() != 43 || response.exp <= now {
            return Err(Error("invalid_remote_response"));
        }
        let token = Zeroizing::new(response.session_token);
        if let Some(account) = response
            .extra
            .get("account_id")
            .and_then(serde_json::Value::as_str)
        {
            if account.is_empty() || account.len() > 256 || account.chars().any(char::is_control) {
                return Err(Error("invalid_remote_response"));
            }
            self.accounts
                .lock()
                .await
                .insert(local.device_id.clone(), account.into());
        }
        sessions.insert(local.device_id.clone(), (token.clone(), response.exp));
        Ok(token)
    }

    pub async fn account(&self, device_id: &str) -> Result<String> {
        self.accounts
            .lock()
            .await
            .get(device_id)
            .cloned()
            .ok_or(Error("invalid_remote_response"))
    }
    pub async fn session(&self, device_id: &str) -> Result<Zeroizing<String>> {
        self.sessions
            .lock()
            .await
            .get(device_id)
            .filter(|(_, exp)| *exp > unix_now())
            .map(|(token, _)| token.clone())
            .ok_or(Error("unauthorized"))
    }
}

fn url_id(id: &str) -> String {
    reqwest::Url::parse("https://relay.invalid/")
        .map(|mut url| {
            url.path_segments_mut()
                .expect("fixed HTTPS origin")
                .push(id);
            url.path().trim_start_matches('/').to_owned()
        })
        .expect("fixed HTTPS origin")
}

fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|time| time.as_secs() as i64)
        .unwrap_or(0)
}
