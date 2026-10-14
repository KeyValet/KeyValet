//! Foreground and native background transports share the same authentication and inbox.
use crate::{
    engine::Candidate,
    now,
    view::{NotificationView, PairingView},
    Error, MobileCore, Result,
};
use futures_util::{SinkExt, StreamExt};
use kv_core::remote::{
    self as remote,
    canonical::from_json,
    keys::{decode_b64, encode_b64},
    relay::*,
    *,
};
use reqwest::header::{HeaderValue, AUTHORIZATION};
use serde::{de::DeserializeOwned, Serialize};
use std::{
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};
use tokio_tungstenite::{
    tungstenite::{client::IntoClientRequest, protocol::WebSocketConfig, Message},
    MaybeTlsStream, WebSocketStream,
};
use url::Url;

pub struct PairUri {
    pub relay: Url,
    pub token: Vec<u8>,
}
impl PairUri {
    pub fn parse(text: &str) -> Result<Self> {
        if text.len() > 2048 {
            return Err(Error("invalid_pair_uri"));
        }
        let url = Url::parse(text).map_err(|_| Error("invalid_pair_uri"))?;
        if url.scheme() != "kv-pair"
            || !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
        {
            return Err(Error("invalid_pair_uri"));
        }
        let mut token = [0_u8; 16];
        let mut bits = 0_u32;
        let mut count = 0;
        let mut index = 0;
        let encoded = url
            .path()
            .strip_prefix('/')
            .ok_or(Error("invalid_pair_uri"))?;
        if encoded.len() != 26 {
            return Err(Error("invalid_pair_uri"));
        }
        for c in encoded.bytes() {
            let value = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
                .iter()
                .position(|v| *v == c.to_ascii_uppercase())
                .ok_or(Error("invalid_pair_uri"))? as u32;
            bits = (bits << 5) | value;
            count += 5;
            if count >= 8 {
                count -= 8;
                if index >= 16 {
                    return Err(Error("invalid_pair_uri"));
                }
                token[index] = (bits >> count) as u8;
                index += 1;
            }
        }
        if index != 16 || bits & ((1 << count) - 1) != 0 {
            return Err(Error("invalid_pair_uri"));
        }
        let host = url.host_str().ok_or(Error("invalid_pair_uri"))?;
        let authority = if let Some(port) = url.port() {
            format!("{host}:{port}")
        } else {
            host.into()
        };
        let relay = validate_url(&format!("https://{authority}/"))?;
        Ok(Self {
            relay,
            token: token.to_vec(),
        })
    }
}

pub fn validate_url(text: &str) -> Result<Url> {
    let url = Url::parse(text).map_err(|_| Error("invalid_relay_url"))?;
    let loopback = url
        .host_str()
        .and_then(|h| h.parse::<std::net::IpAddr>().ok())
        .is_some_and(|ip| ip.is_loopback());
    if !matches!(url.scheme(), "https" | "http")
        || (url.scheme() == "http" && !loopback)
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || url.path() != "/"
    {
        return Err(Error("invalid_relay_url"));
    }
    Ok(url)
}
pub(crate) fn validate_app_relay(text: &str, allow_test_relay: bool) -> Result<Url> {
    let url = validate_url(text)?;
    let loopback = url
        .host_str()
        .and_then(|host| host.parse::<std::net::IpAddr>().ok())
        .is_some_and(|ip| ip.is_loopback());
    if url.as_str() != crate::RELAY_URL && !(allow_test_relay && url.scheme() == "http" && loopback)
    {
        return Err(Error("fixed_relay"));
    }
    Ok(url)
}

pub struct Relay {
    pub(crate) core: Arc<MobileCore>,
    http: reqwest::Client,
    session: Mutex<Option<(String, i64)>>,
    authentication: tokio::sync::Mutex<()>,
    sending: tokio::sync::Mutex<()>,
    generation: AtomicU64,
    task: Mutex<Option<tokio::task::JoinHandle<()>>>,
}
pub(crate) type Socket = WebSocketStream<MaybeTlsStream<tokio::net::TcpStream>>;
impl Relay {
    pub fn new(core: Arc<MobileCore>) -> Result<Arc<Self>> {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let http = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(12))
            .build()
            .map_err(|_| Error("network_unavailable"))?;
        Ok(Arc::new(Self {
            core,
            http,
            session: Mutex::new(None),
            authentication: tokio::sync::Mutex::new(()),
            sending: tokio::sync::Mutex::new(()),
            generation: AtomicU64::new(0),
            task: Mutex::new(None),
        }))
    }
    fn url(&self, path: &str) -> Result<Url> {
        validate_app_relay(&self.core.settings()?.relay_url, cfg!(test))?
            .join(path)
            .map_err(|_| Error("invalid_relay_url"))
    }
    pub(crate) fn clear_device_session(&self) -> Result<()> {
        self.stop();
        *self.session.lock().map_err(|_| Error("invalid_session"))? = None;
        Ok(())
    }
    fn user_header(&self) -> Result<Option<HeaderValue>> {
        self.core.ensure_login()?;
        self.core
            .login_session()?
            .map(|session| {
                let mut header = HeaderValue::from_str(&session.session_token)
                    .map_err(|_| Error("invalid_session"))?;
                header.set_sensitive(true);
                Ok(header)
            })
            .transpose()
    }
    pub(crate) async fn account_request(
        &self,
        method: reqwest::Method,
        path: &str,
        body: Option<serde_json::Value>,
        token: Option<&str>,
    ) -> Result<serde_json::Value> {
        let mut request = self.http.request(method, self.url(path)?);
        if let Some(token) = token {
            let mut header = HeaderValue::from_str(&format!("Bearer {token}"))
                .map_err(|_| Error("invalid_session"))?;
            header.set_sensitive(true);
            request = request.header(AUTHORIZATION, header);
        }
        if let Some(body) = body {
            request = request.json(&body);
        }
        let mut response = request
            .send()
            .await
            .map_err(|_| Error("network_unavailable"))?;
        let status = response.status().as_u16();
        let mut bytes = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|_| Error("network_unavailable"))?
        {
            if bytes.len() + chunk.len() > 64 * 1024 {
                return Err(Error("response_too_large"));
            }
            bytes.extend(chunk);
        }
        if !(200..300).contains(&status) {
            let body = from_json::<serde_json::Value>(&bytes).unwrap_or_default();
            return Err(Error(match (status, body["error"]["code"].as_str()) {
                (_, Some("provider_not_configured")) | (404, _) => "login_configuration_required",
                (401, _) if path == "v1/account/providers" => "login_configuration_required",
                (401, _) => "login_required",
                (403 | 409, _) => "login_account_conflict",
                (429, _) => "rate_limited",
                (500..=599, _) => "relay_unavailable",
                _ => "login_failed",
            }));
        }
        Ok(from_json(&bytes)?)
    }
    async fn request<T: DeserializeOwned>(
        &self,
        method: reqwest::Method,
        path: &str,
        body: Option<serde_json::Value>,
        authenticated: bool,
    ) -> Result<T> {
        let mut request = self.http.request(method, self.url(path)?);
        if authenticated {
            let token = self.authenticate().await?;
            let mut auth = HeaderValue::from_str(&format!("Device {token}"))
                .map_err(|_| Error("invalid_session"))?;
            auth.set_sensitive(true);
            request = request.header(AUTHORIZATION, auth);
            if let Some(header) = self.user_header()? {
                request = request.header("x-keyvalet-user-session", header);
            }
        }
        if let Some(body) = body {
            request = request.json(&body);
        }
        let mut response = request
            .send()
            .await
            .map_err(|_| Error("network_unavailable"))?;
        if !response.status().is_success() {
            if response.status().as_u16() == 401 {
                *self.session.lock().map_err(|_| Error("invalid_session"))? = None;
            }
            return Err(Error(match response.status().as_u16() {
                429 => "rate_limited",
                500..=599 => "relay_unavailable",
                401 => "authentication_failed",
                _ => "relay_rejected",
            }));
        }
        let mut bytes = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|_| Error("network_unavailable"))?
        {
            if bytes.len() + chunk.len() > 4 * 1024 * 1024 {
                return Err(Error("response_too_large"));
            }
            bytes.extend(chunk);
        }
        Ok(from_json(&bytes)?)
    }
    async fn post<T: DeserializeOwned>(
        &self,
        path: &str,
        value: &impl Serialize,
        auth: bool,
    ) -> Result<T> {
        self.request(
            reqwest::Method::POST,
            path,
            Some(serde_json::to_value(value)?),
            auth,
        )
        .await
    }
    pub async fn authenticate(&self) -> Result<String> {
        // A challenge is single use. Foreground flushes and native actions share this
        // client and must not replace each other's challenge while signing it.
        let _authentication = self.authentication.lock().await;
        self.core.ensure_login()?;
        let user_session = self.core.login_session()?;
        let user_header = user_session
            .as_ref()
            .map(|session| {
                let mut header = HeaderValue::from_str(&session.session_token)
                    .map_err(|_| Error("invalid_session"))?;
                header.set_sensitive(true);
                Ok::<_, Error>(header)
            })
            .transpose()?;
        if let Some((token, exp)) = self
            .session
            .lock()
            .map_err(|_| Error("invalid_session"))?
            .clone()
        {
            if exp > now() + 30 {
                return Ok(token);
            }
        }
        // This path deliberately performs HTTP directly, avoiding recursive auth futures.
        let mut request = self
            .http
            .post(self.url("v1/auth/challenge")?)
            .json(&ChallengeRequest {
                device_id: self.core.own.device_id.clone(),
                extra: Extra::new(),
            });
        if let Some(header) = user_header.clone() {
            request = request.header("x-keyvalet-user-session", header);
        }
        let response = request
            .send()
            .await
            .map_err(|_| Error("network_unavailable"))?;
        if response.status().as_u16() == 401 {
            if let Some(session) = &user_session {
                self.core.clear_login_if(&session.session_token)?;
            }
            return Err(Error("login_required"));
        }
        let challenge: ChallengeResponse = decode_response(response, 16 * 1024).await?;
        let raw = decode_b64(&challenge.challenge)?;
        if raw.len() != 32 || challenge.exp <= now() || challenge.exp > now() + 120 {
            return Err(Error("invalid_challenge"));
        }
        let sig = self
            .core
            .keys
            .identity
            .sign(SignatureAlgorithm::ES256, &raw)?;
        let mut request = self
            .http
            .post(self.url("v1/auth/verify")?)
            .json(&AuthVerifyRequest {
                device_id: self.core.own.device_id.clone(),
                challenge: challenge.challenge,
                sig: encode_b64(&sig),
                extra: Extra::new(),
            });
        if let Some(header) = user_header {
            request = request.header("x-keyvalet-user-session", header);
        }
        let response = request
            .send()
            .await
            .map_err(|_| Error("network_unavailable"))?;
        if response.status().as_u16() == 401 {
            if let Some(session) = &user_session {
                self.core.clear_login_if(&session.session_token)?;
            }
            return Err(Error("login_required"));
        }
        let verified: AuthVerifyResponse = decode_response(response, 16 * 1024).await?;
        if verified.exp <= now() + 30
            || verified.session_token.is_empty()
            || verified.session_token.len() > 4096
            || verified.session_token.chars().any(char::is_control)
        {
            return Err(Error("invalid_session"));
        }
        let current = self.core.login_session()?;
        if current.as_ref().map(|s| &s.session_token)
            != user_session.as_ref().map(|s| &s.session_token)
        {
            return Err(Error("authentication_failed"));
        }
        *self.session.lock().map_err(|_| Error("invalid_session"))? =
            Some((verified.session_token.clone(), verified.exp));
        Ok(verified.session_token)
    }
    pub async fn begin_pair(&self, uri: &str) -> Result<PairingView> {
        let uri = PairUri::parse(uri)?;
        self.begin_pair_at(uri.relay, uri.token).await
    }
    /// Also supports loopback software peers in CI without adding a production key fallback.
    pub async fn begin_pair_at(&self, base: Url, token: Vec<u8>) -> Result<PairingView> {
        self.core.ensure_login()?;
        if token.len() != 16 {
            return Err(Error("invalid_pair_uri"));
        }
        self.core.set_relay(base.as_str())?;
        self.core.ensure_login()?;
        let token_hash = remote::canonical::sha256_hex(&token);
        if let Ok(candidate) = self.core.candidate() {
            if candidate.exp > now() && candidate.token_hash.as_deref() == Some(token_hash.as_str())
            {
                if let Some(accept) = &candidate.accept {
                    self.send_pairing(accept).await?;
                }
                return self.core.save_candidate(&candidate);
            }
        }
        let registered = self
            .core
            .store
            .transaction(|db| self.core.store.get::<bool>(db, "meta", "registered"))?
            .unwrap_or(false);
        if !registered {
            let _: RegisterDeviceResponse = self
                .post(
                    "v1/devices",
                    &RegisterDeviceRequest {
                        device: self.core.own.clone(),
                        push_token: self.core.store.transaction(|db| {
                            Ok(self
                                .core
                                .store
                                .get(db, "meta", "push_token")?
                                .map(Optional::Value)
                                .unwrap_or(Optional::Missing))
                        })?,
                    },
                    false,
                )
                .await?;
            self.core
                .store
                .transaction(|db| self.core.store.put(db, "meta", "registered", &true, 0))?;
        }
        let completed: PairCompleteResponse = self
            .post(
                "v1/pair/complete",
                &PairCompleteRequest {
                    token: encode_b64(&token),
                    joiner: self.core.own.clone(),
                    extra: Extra::new(),
                },
                true,
            )
            .await?;
        *self.session.lock().map_err(|_| Error("invalid_session"))? = None;
        let account = completed
            .account_id
            .as_value()
            .filter(|s| !s.is_empty() && s.len() < 128)
            .ok_or(Error("relay_account_missing"))?;
        let sas = remote::pairing::device_sas(&token, &completed.initiator, &self.core.own)?;
        let exp = completed
            .extra
            .get("expires_at")
            .and_then(serde_json::Value::as_i64)
            .filter(|exp| *exp > now() && *exp <= now() + 600)
            .ok_or(Error("invalid_pair_expiration"))?;
        let mut candidate = Candidate {
            peer: completed.initiator,
            account: account.into(),
            pairing_id: completed.pairing_id,
            sas,
            exp,
            local_confirm: None,
            peer_confirmed: false,
            exclude_global: false,
            peer_exclude_global: false,
            accept: None,
            confirmation_envelope: None,
            finish_sent: false,
            token_hash: Some(token_hash),
        };
        candidate.accept = Some(self.core.pairing_envelope(
            &candidate,
            EnvelopeType::PairAccept,
            &PairAccept {
                token: encode_b64(&token),
                joiner: self.core.own.clone(),
                extra: Extra::new(),
            },
        )?);
        let view = self.core.save_candidate(&candidate)?;
        self.send_pairing(candidate.accept.as_ref().ok_or(Error("pairing_required"))?)
            .await?;
        Ok(view)
    }
    pub async fn confirm_pair(&self, sas: &str, exclude_global: bool) -> Result<()> {
        self.core.ensure_login()?;
        let mut candidate = self.core.candidate()?;
        if candidate.exp <= now() || candidate.sas != sas {
            return Err(Error("sas_mismatch"));
        }
        if candidate.local_confirm.is_none() {
            let mut confirm = PairConfirm {
                sas: sas.into(),
                sig: String::new(),
                extra: serde_json::json!({"device":self.core.own,"exclude_global":exclude_global})
                    .as_object()
                    .unwrap()
                    .clone(),
            };
            confirm.sig = remote::keys::sign_object(
                &confirm,
                SignatureAlgorithm::ES256,
                self.core.keys.strong.as_ref(),
            )?;
            let envelope =
                self.core
                    .pairing_envelope(&candidate, EnvelopeType::PairConfirm, &confirm)?;
            candidate = self.core.store.transaction(|db| {
                let mut current: Candidate = self
                    .core
                    .store
                    .get(db, "meta", "candidate")?
                    .ok_or(Error("pairing_required"))?;
                if current.sas != sas || current.exp <= now() || current.peer != candidate.peer {
                    return Err(Error("sas_mismatch"));
                }
                current.local_confirm = Some(confirm);
                current.confirmation_envelope = Some(envelope);
                current.exclude_global = exclude_global;
                self.core
                    .store
                    .put(db, "meta", "candidate", &current, current.exp)?;
                Ok(current)
            })?;
        } else if candidate.exclude_global != exclude_global {
            return Err(Error("confirmation_changed"));
        }
        if let Some(accept) = &candidate.accept {
            self.send_pairing(accept).await?;
        }
        self.send_pairing(
            candidate
                .confirmation_envelope
                .as_ref()
                .ok_or(Error("pairing_required"))?,
        )
        .await?;
        if !candidate.finish_sent {
            let response: OkResponse = self
                .post(
                    "v1/pair/finish",
                    &PairFinishRequest {
                        pairing_id: candidate.pairing_id.clone(),
                        confirm: candidate
                            .local_confirm
                            .clone()
                            .ok_or(Error("pairing_required"))?,
                        extra: Extra::new(),
                    },
                    true,
                )
                .await?;
            if !response.ok {
                return Err(Error("relay_rejected"));
            }
            self.core.store.transaction(|db| {
                let mut current: Candidate = self
                    .core
                    .store
                    .get(db, "meta", "candidate")?
                    .ok_or(Error("pairing_required"))?;
                current.finish_sent = true;
                self.core
                    .store
                    .put(db, "meta", "candidate", &current, current.exp)
            })?;
        }
        // The live foreground transport owns its socket. A cold test/background caller can
        // use a temporary socket, but never competes with an active foreground connection.
        let running = self
            .task
            .lock()
            .map_err(|_| Error("storage_busy"))?
            .as_ref()
            .is_some_and(|task| !task.is_finished());
        let mut socket = if running {
            None
        } else {
            Some(self.socket().await?)
        };
        loop {
            let current = self.core.candidate()?;
            if current.exp <= now() {
                return Err(Error("pairing_expired"));
            }
            if current.peer_confirmed {
                return self.core.trust_candidate(
                    &current,
                    current.exclude_global || current.peer_exclude_global,
                );
            }
            if let Some(socket) = socket.as_mut() {
                match tokio::time::timeout(Duration::from_millis(100), socket.next()).await {
                    Ok(Some(Ok(Message::Text(text)))) => {
                        let frame: serde_json::Value = from_json(text.as_bytes())?;
                        if frame["t"] == "envelope" {
                            self.deliver(serde_json::from_value(frame["envelope"].clone())?, false)
                                .await?;
                        }
                    }
                    Ok(Some(Ok(Message::Ping(bytes)))) => {
                        socket
                            .send(Message::Pong(bytes))
                            .await
                            .map_err(|_| Error("network_unavailable"))?;
                    }
                    Ok(Some(Ok(Message::Close(_)))) | Ok(None) | Ok(Some(Err(_))) => {
                        return Err(Error("network_unavailable"))
                    }
                    _ => {}
                }
            } else {
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        }
    }

    async fn send_pairing(&self, envelope: &Envelope) -> Result<()> {
        let reply: AcceptedResponse = self
            .post(
                "v1/messages",
                &SendMessagesRequest {
                    envelopes: vec![envelope.clone()],
                    extra: Extra::new(),
                },
                true,
            )
            .await?;
        if reply.accepted != 1 {
            return Err(Error("relay_protocol"));
        }
        Ok(())
    }
    pub async fn revoke_device(&self, id: &str, confirmation: &str) -> Result<()> {
        self.core.ensure_login()?;
        if self.core.peer(id)?.label != confirmation {
            return Err(Error("confirmation_required"));
        }
        let challenge: ChallengeResponse = self
            .post(
                "v1/auth/challenge",
                &ChallengeRequest {
                    device_id: self.core.own.device_id.clone(),
                    extra: Extra::new(),
                },
                true,
            )
            .await?;
        if challenge.exp <= now()
            || challenge.exp > now() + 120
            || decode_b64(&challenge.challenge)?.len() != 32
        {
            return Err(Error("invalid_challenge"));
        }
        let payload = remote::canonical::jcs(&DeviceDeleteProof {
            action: DeviceDeleteAction::RevokeDevice,
            account: self.core.account()?,
            by: self.core.own.device_id.clone(),
            device_id: id.into(),
            challenge: challenge.challenge.clone(),
            extra: Extra::new(),
        })?;
        let signature = self
            .core
            .keys
            .strong
            .sign(SignatureAlgorithm::ES256, &payload)?;
        let proof: DeviceDeleteProof = from_json(&payload)?;
        let revoke = DeviceRevoke {
            device_id: id.into(),
            extra: serde_json::json!({"proof":proof,"sig":encode_b64(&signature)})
                .as_object()
                .unwrap()
                .clone(),
        };
        remote::validation::verify_device_revoke(&revoke, &self.core.own, &self.core.account()?)?;
        let peers = self
            .core
            .store
            .transaction(|db| self.core.store.list::<DeviceRecord>(db, "peers"))?;
        let mut controls = Vec::new();
        for (_, peer) in peers.into_iter().filter(|(_, peer)| peer.device_id != id) {
            controls.push(self.core.pairing_envelope(
                &Candidate {
                    peer,
                    account: self.core.account()?,
                    pairing_id: String::new(),
                    sas: String::new(),
                    exp: remote::canonical::MAX_SAFE_INTEGER as i64,
                    local_confirm: None,
                    peer_confirmed: false,
                    exclude_global: false,
                    peer_exclude_global: false,
                    accept: None,
                    confirmation_envelope: None,
                    finish_sent: false,
                    token_hash: None,
                },
                EnvelopeType::DeviceRevoke,
                &revoke,
            )?);
        }
        self.core.store.transaction(|db| {
            for control in &controls {
                self.core.enqueue(db, control)?;
            }
            Ok(())
        })?;
        let token = self.authenticate().await?;
        let encoded = url::form_urlencoded::byte_serialize(id.as_bytes()).collect::<String>();
        let response = self
            .http
            .delete(self.url(&format!("v1/devices/{encoded}"))?)
            .header(AUTHORIZATION, format!("Device {token}"))
            .header(STRONG_CHALLENGE_HEADER, &challenge.challenge)
            .header(STRONG_SIGNATURE_HEADER, encode_b64(&signature))
            .json(&DeleteDeviceRequest {
                by: DeleteDeviceBy::Device,
                recovery_code: Optional::Missing,
                extra: Extra::new(),
            })
            .send()
            .await
            .map_err(|_| Error("network_unavailable"))?;
        let result: OkResponse = decode_response(response, 16 * 1024).await?;
        if !result.ok {
            return Err(Error("relay_rejected"));
        }
        self.core.store.transaction(|db| {
            crate::Store::delete(db, "peers", id)?;
            for (key, envelope) in self.core.store.list::<Envelope>(db, "outbox")? {
                if envelope.to == id {
                    crate::Store::delete(db, "outbox", &key)?;
                }
            }
            Ok(())
        })
    }
    async fn socket(&self) -> Result<Socket> {
        let token = self.authenticate().await?;
        let mut url = self.url("v1/presence")?;
        let scheme = if url.scheme() == "https" { "wss" } else { "ws" };
        url.set_scheme(scheme)
            .map_err(|_| Error("invalid_relay_url"))?;
        let mut request = url
            .as_str()
            .into_client_request()
            .map_err(|_| Error("invalid_relay_url"))?;
        request.headers_mut().insert(
            "sec-websocket-protocol",
            HeaderValue::from_static(WS_SUBPROTOCOL),
        );
        let mut auth = HeaderValue::from_str(&format!("Device {token}"))
            .map_err(|_| Error("invalid_session"))?;
        auth.set_sensitive(true);
        request.headers_mut().insert(AUTHORIZATION, auth);
        let config = WebSocketConfig::default()
            .max_message_size(Some(84 * 1024))
            .max_frame_size(Some(84 * 1024));
        let (socket, response) = match tokio_tungstenite::connect_async_with_config(
            request,
            Some(config),
            false,
        )
        .await
        {
            Ok(result) => result,
            Err(tokio_tungstenite::tungstenite::Error::Http(response)) => {
                return Err(Error(match response.status().as_u16() {
                    401 | 403 => {
                        *self.session.lock().map_err(|_| Error("invalid_session"))? = None;
                        // An explicit refusal is never an offline notification fallback.
                        let _ = self.account_restore().await;
                        self.core.ensure_login()?;
                        "authentication_failed"
                    }
                    429 => "rate_limited",
                    500..=599 => "relay_unavailable",
                    _ => "relay_rejected",
                }));
            }
            Err(_) => return Err(Error("network_unavailable")),
        };
        if response
            .headers()
            .get("sec-websocket-protocol")
            .and_then(|v| v.to_str().ok())
            != Some(WS_SUBPROTOCOL)
        {
            return Err(Error("relay_protocol"));
        }
        Ok(socket)
    }
    async fn deliver(
        &self,
        envelope: Envelope,
        background: bool,
    ) -> Result<Option<NotificationView>> {
        let notification = match self.core.receive(&serde_json::to_vec(&envelope)?) {
            Ok(notification) => notification,
            Err(error)
                if matches!(
                    error.0,
                    "hardware_unavailable"
                        | "storage_unavailable"
                        | "storage_busy"
                        | "storage_integrity"
                        | "pairing_pending"
                ) =>
            {
                return Err(error);
            }
            Err(error) => {
                self.core.reject(&envelope, error.0)?;
                None
            }
        };
        let acknowledged = self
            .post::<OkResponse>(
                "v1/messages/ack",
                &AckMessagesRequest {
                    ids: vec![envelope.id],
                    kind: Optional::Value(envelope.r#type.as_str().into()),
                    extra: Extra::new(),
                },
                true,
            )
            .await
            .and_then(|reply| {
                if reply.ok {
                    Ok(())
                } else {
                    Err(Error("relay_protocol"))
                }
            });
        // The state transaction precedes ack. Foreground transport reconnects on failure;
        // a native background worker must still display or cancel the authenticated plan.
        if !background {
            acknowledged?;
        }
        Ok(notification)
    }
    pub async fn flush(&self) -> Result<()> {
        self.flush_count(16).await
    }
    async fn flush_count(&self, count: usize) -> Result<()> {
        self.core.ensure_login()?;
        let _sending = self.sending.lock().await;
        self.sync_push_token().await?;
        for (key, envelope) in self.core.outbound()?.into_iter().take(count) {
            if envelope.r#type == EnvelopeType::ApprovalDecision {
                let id = url::form_urlencoded::byte_serialize(envelope.id.as_bytes())
                    .collect::<String>();
                let response: OkResponse = self
                    .post(
                        &format!("v1/approvals/{id}/reply"),
                        &ReplyApprovalRequest {
                            envelope: envelope.clone(),
                            extra: Extra::new(),
                        },
                        true,
                    )
                    .await?;
                if !response.ok {
                    return Err(Error("relay_protocol"));
                }
            } else {
                let response: AcceptedResponse = self
                    .post(
                        "v1/messages",
                        &SendMessagesRequest {
                            envelopes: vec![envelope.clone()],
                            extra: Extra::new(),
                        },
                        true,
                    )
                    .await?;
                if response.accepted != 1 {
                    return Err(Error("relay_protocol"));
                }
            }
            self.core.accepted(&key, &envelope)?;
        }
        Ok(())
    }
    pub(crate) async fn sync_push_token(&self) -> Result<()> {
        self.core.ensure_login()?;
        let uploading_session = self.core.login_session()?;
        let token: Option<serde_json::Value> = self
            .core
            .store
            .transaction(|db| self.core.store.get(db, "meta", "push_token"))?;
        let Some(token) = token else {
            return Ok(());
        };
        let digest = remote::canonical::sha256_hex(&remote::canonical::jcs(&token)?);
        if self
            .core
            .store
            .transaction(|db| {
                self.core
                    .store
                    .get::<String>(db, "meta", "uploaded_push_token")
            })?
            .as_deref()
            == Some(&digest)
        {
            return Ok(());
        }
        let _: serde_json::Value = self.post("v1/devices/push-token", &token, true).await?;
        self.core.store.transaction(|db| {
            self.core.ensure_login_in(db)?;
            let current_session: Option<crate::account::Session> =
                self.core.store.get(db, "meta", "account_session")?;
            if current_session.as_ref().map(|s| &s.session_token)
                != uploading_session.as_ref().map(|s| &s.session_token)
            {
                return Ok(());
            }
            let current: Option<serde_json::Value> =
                self.core.store.get(db, "meta", "push_token")?;
            if current.as_ref() != Some(&token) {
                return Ok(());
            }
            self.core
                .store
                .put(db, "meta", "uploaded_push_token", &digest, 0)
        })
    }
    pub async fn sync_background(&self) -> Result<Vec<NotificationView>> {
        Ok(self.sync_background_status().await?.0)
    }
    pub(crate) async fn sync_background_status(&self) -> Result<(Vec<NotificationView>, bool)> {
        let _ = self.retry_logouts().await;
        self.core.ensure_login()?;
        // HTTPS inbox recovery must not depend on a WebSocket upgrade succeeding.
        // A restored mobile network can allow the pull while WS is still unavailable.
        match self.pull_waiting(true).await {
            Ok(()) => {}
            Err(error)
                if matches!(
                    error.0,
                    "network_unavailable" | "rate_limited" | "relay_unavailable"
                ) =>
            {
                return Ok((self.core.notifications()?, true));
            }
            Err(error) if error.0 == "authentication_failed" => {
                // A refused HTTPS pull has the same fail-closed account boundary
                // as a refused WS upgrade, including locally clearing a revoked login.
                let _ = self.account_restore().await;
                self.core.ensure_login()?;
                return Err(error);
            }
            Err(error) => return Err(error),
        }
        // Firebase can deliver while Flutter's foreground socket is alive. Opening
        // another socket would evict that connection and repeatedly race reconnects.
        let running = self
            .task
            .lock()
            .map_err(|_| Error("storage_busy"))?
            .as_ref()
            .is_some_and(|task| !task.is_finished());
        if running {
            return Ok((self.core.notifications()?, false));
        }
        let mut socket = match self.socket().await {
            Ok(socket) => socket,
            Err(error)
                if matches!(
                    error.0,
                    "network_unavailable" | "rate_limited" | "relay_unavailable"
                ) =>
            {
                // A push can arrive after the transport becomes unavailable. Cached display
                // plans were already authenticated by Rust and retain their original expiry.
                return Ok((self.core.notifications()?, true));
            }
            Err(error) => return Err(error),
        };
        let mut notifications = Vec::new();
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        loop {
            let timeout = deadline
                .saturating_duration_since(tokio::time::Instant::now())
                .min(Duration::from_millis(800));
            if timeout.is_zero() {
                break;
            }
            let frame = match tokio::time::timeout(timeout, socket.next()).await {
                Ok(Some(Ok(frame))) => frame,
                _ => break,
            };
            if let Message::Text(text) = frame {
                let wire: serde_json::Value = from_json(text.as_bytes())?;
                if wire["t"] == "envelope" {
                    let envelope = serde_json::from_value(wire["envelope"].clone())?;
                    if let Some(notification) = self.deliver(envelope, true).await? {
                        notifications.push(notification);
                    }
                }
            }
        }
        let _ = socket.close(None).await;
        // An unrelated outbound retry must not suppress a newly authenticated notification.
        let retry = self.flush().await.is_err();
        for cached in self.core.notifications()? {
            // The transaction snapshot wins over intermediate frames: request -> cancel
            // or request -> escalate can arrive before an ack transport failure.
            notifications.retain(|v| v.approval_id != cached.approval_id);
            notifications.push(cached);
        }
        Ok((notifications, retry))
    }
    pub fn start(self: &Arc<Self>) {
        if self.core.ensure_login().is_err() {
            return;
        }
        let Ok(mut task) = self.task.lock() else {
            return;
        };
        if task.as_ref().is_some_and(|t| !t.is_finished()) {
            return;
        }
        let generation = self.generation.fetch_add(1, Ordering::SeqCst) + 1;
        let relay = self.clone();
        *task = Some(tokio::spawn(async move {
            let mut backoff = 1;
            while relay.generation.load(Ordering::SeqCst) == generation {
                if relay.foreground(generation).await.is_ok()
                    || relay.core.connected.swap(false, Ordering::Relaxed)
                {
                    backoff = 1;
                }
                relay.core.connected.store(false, Ordering::Relaxed);
                tokio::time::sleep(Duration::from_secs(backoff)).await;
                backoff = (backoff * 2).min(60);
            }
        }));
    }
    pub fn stop(&self) {
        self.generation.fetch_add(1, Ordering::SeqCst);
        if let Ok(mut task) = self.task.lock() {
            if let Some(task) = task.take() {
                task.abort();
            }
        }
        self.core.connected.store(false, Ordering::Relaxed);
    }
    async fn foreground(&self, generation: u64) -> Result<()> {
        let _ = self.retry_logouts().await;
        let mut socket = self.socket().await?;
        if self.core.candidate().is_err() {
            self.pull_waiting(false).await?;
        }
        self.core.connected.store(true, Ordering::Relaxed);
        let mut heartbeat = tokio::time::interval(Duration::from_secs(30));
        let mut polling = tokio::time::interval(Duration::from_secs(1));
        let mut last_pong = tokio::time::Instant::now();
        let mut flushing = Box::pin(std::future::pending::<Result<()>>())
            as std::pin::Pin<Box<dyn std::future::Future<Output = Result<()>> + Send>>;
        let mut flush_active = false;
        loop {
            if self.generation.load(Ordering::SeqCst) != generation {
                return Ok(());
            }
            self.core.ensure_login()?;
            tokio::select! {
                _=polling.tick(),if !flush_active=>{ flushing=Box::pin(self.flush_count(1)); flush_active=true; },
                result=&mut flushing,if flush_active=>{result?;flush_active=false;flushing=Box::pin(std::future::pending());},
                _=heartbeat.tick()=>{
                    if last_pong.elapsed()>Duration::from_secs(65) { return Err(Error("heartbeat_timeout")); }
                    socket.send(Message::Text("{\"t\":\"ping\"}".into())).await.map_err(|_|Error("network_unavailable"))?;
                },
                frame=socket.next()=>{
                    match frame {
                        Some(Ok(Message::Text(text)))=>{
                            let wire:serde_json::Value=from_json(text.as_bytes())?;
                            match wire["t"].as_str() {
                                Some("envelope")=>{ self.deliver(serde_json::from_value(wire["envelope"].clone())?, false).await?; },
                                Some("pong")=>last_pong=tokio::time::Instant::now(),
                                Some("ack"|"approval_cancel"|"pair_accept")=>{},
                                _=>return Err(Error("relay_protocol")),
                            }
                        }
                        Some(Ok(Message::Ping(bytes)))=>{ socket.send(Message::Pong(bytes)).await.map_err(|_|Error("network_unavailable"))?; },
                        Some(Ok(Message::Pong(_)))=>last_pong=tokio::time::Instant::now(),
                        _=>return Err(Error("network_unavailable")),
                    }
                }
            }
        }
    }

    async fn pull_waiting(&self, background: bool) -> Result<()> {
        let waiting: EnvelopesResponse = self
            .request(
                reqwest::Method::GET,
                "v1/approvals?state=waiting",
                None,
                true,
            )
            .await?;
        for envelope in waiting.envelopes {
            self.deliver(envelope, background).await?;
        }
        Ok(())
    }
}

async fn decode_response<T: DeserializeOwned>(
    mut response: reqwest::Response,
    limit: usize,
) -> Result<T> {
    if !response.status().is_success() {
        return Err(Error(match response.status().as_u16() {
            429 => "rate_limited",
            500..=599 => "relay_unavailable",
            _ => "relay_rejected",
        }));
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| Error("network_unavailable"))?
    {
        if bytes.len() + chunk.len() > limit {
            return Err(Error("response_too_large"));
        }
        bytes.extend(chunk);
    }
    Ok(from_json(&bytes)?)
}
