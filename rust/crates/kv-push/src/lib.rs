//! Metadata-only APNs/FCM dispatch. Approval bodies and envelopes are rejected.
use axum::{
    extract::{DefaultBodyLimit, State},
    http::{HeaderMap, StatusCode},
    routing::post,
    Json, Router,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use p256::ecdsa::{signature::Signer, Signature, SigningKey};
use p256::pkcs8::DecodePrivateKey;
use rsa::{signature::SignatureEncoding, traits::PublicKeyParts, RsaPrivateKey};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::sync::Mutex;
use zeroize::Zeroizing;

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    Silent,
    Banner,
}
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Delivery {
    pub mode: Mode,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(tag = "platform", rename_all = "snake_case", deny_unknown_fields)]
pub enum PushToken {
    Apns { token: String },
    Fcm { token: String },
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PushRequest {
    pub device_push_token: PushToken,
    pub approval_id: String,
    pub to: String,
    pub delivery: Delivery,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Error {
    Invalid,
    Configuration,
    Provider,
    Throttled { retry_after_s: u64 },
    InvalidToken,
}
impl PushRequest {
    pub fn validate(&self) -> Result<(), Error> {
        if self.to.is_empty()
            || self.to.len() > 128
            || !self
                .to
                .bytes()
                .all(|v| v.is_ascii_alphanumeric() || b"_-".contains(&v))
            || self.approval_id.len() != 26
            || !self
                .approval_id
                .bytes()
                .all(|v| b"0123456789ABCDEFGHJKMNPQRSTVWXYZ".contains(&v))
            || self.approval_id.as_bytes()[0] > b'7'
        {
            return Err(Error::Invalid);
        }
        match &self.device_push_token {
            PushToken::Apns { token }
                if token.len() == 64 && token.bytes().all(|v| v.is_ascii_hexdigit()) =>
            {
                Ok(())
            }
            PushToken::Fcm { token }
                if (16..=4096).contains(&token.len())
                    && token
                        .bytes()
                        .all(|v| v.is_ascii_alphanumeric() || b"-_:".contains(&v)) =>
            {
                Ok(())
            }
            _ => Err(Error::Invalid),
        }
    }
    pub fn apns_payload(&self) -> Value {
        // A passive generic alert invokes the NSE. Only authenticated Rust display plans
        // may elevate it; an unavailable/timed-out extension must not produce a banner.
        json!({"aps":{"mutable-content":1,"interruption-level":"passive","alert":{"title":"KeyValet","body":"Approval update / 审批更新"}},
            "approval_id":self.approval_id,"to":self.to,"delivery":{"mode":self.delivery.mode}})
    }
    pub fn fcm_payload(&self, token: &str) -> Value {
        json!({"message":{"token":token,"data":{"approval_id":self.approval_id,
            "to":self.to,"delivery.mode":if self.delivery.mode==Mode::Silent {"silent"} else {"banner"}},
            "android":{"priority":"high","ttl":"120s","collapse_key":self.approval_id}}})
    }
}
fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
fn signing_input(header: Value, claims: Value) -> Result<String, Error> {
    Ok(format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).map_err(|_| Error::Configuration)?),
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).map_err(|_| Error::Configuration)?)
    ))
}
pub struct ApnsConfig {
    pub team: String,
    pub key_id: String,
    pub topic: String,
    pub sandbox: bool,
    pub key: SigningKey,
}
pub struct FcmConfig {
    pub project: String,
    pub email: String,
    pub key: RsaPrivateKey,
}
pub struct Dispatcher {
    http: reqwest::Client,
    apns: Option<ApnsConfig>,
    fcm: Option<FcmConfig>,
    access: Mutex<Option<(Zeroizing<String>, u64)>>,
    apns_url: String,
    fcm_url: String,
    oauth_url: String,
}
impl Dispatcher {
    pub fn new(apns: Option<ApnsConfig>, fcm: Option<FcmConfig>) -> Result<Self, Error> {
        let http = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(12))
            .connect_timeout(Duration::from_secs(5))
            .build()
            .map_err(|_| Error::Configuration)?;
        let apns_url = if apns.as_ref().is_some_and(|c| c.sandbox) {
            "https://api.sandbox.push.apple.com/3/device/"
        } else {
            "https://api.push.apple.com/3/device/"
        }
        .into();
        let fcm_url = format!(
            "https://fcm.googleapis.com/v1/projects/{}/messages:send",
            fcm.as_ref().map(|c| c.project.as_str()).unwrap_or("")
        );
        Ok(Self {
            http,
            apns,
            fcm,
            access: Mutex::new(None),
            apns_url,
            fcm_url,
            oauth_url: "https://oauth2.googleapis.com/token".into(),
        })
    }
    fn apns_auth(config: &ApnsConfig) -> Result<Zeroizing<String>, Error> {
        let input = signing_input(
            json!({"alg":"ES256","kid":config.key_id}),
            json!({"iss":config.team,"iat":now()}),
        )?;
        let signature: Signature = config.key.sign(input.as_bytes());
        Ok(Zeroizing::new(format!(
            "{input}.{}",
            URL_SAFE_NO_PAD.encode(signature.to_bytes())
        )))
    }
    async fn fcm_auth(&self, config: &FcmConfig) -> Result<Zeroizing<String>, Error> {
        let mut cache = self.access.lock().await;
        if let Some((token, exp)) = &*cache {
            if *exp > now() + 60 {
                return Ok(token.clone());
            }
        }
        let input = signing_input(
            json!({"alg":"RS256","typ":"JWT"}),
            json!({"iss":config.email,
            "scope":"https://www.googleapis.com/auth/firebase.messaging","aud":"https://oauth2.googleapis.com/token","iat":now(),"exp":now()+3600}),
        )?;
        let signature = rsa::pkcs1v15::SigningKey::<sha2::Sha256>::new(config.key.clone())
            .sign(input.as_bytes());
        let assertion = Zeroizing::new(format!(
            "{input}.{}",
            URL_SAFE_NO_PAD.encode(signature.to_bytes())
        ));
        let response = self
            .http
            .post(&self.oauth_url)
            .form(&[
                ("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer"),
                ("assertion", assertion.as_str()),
            ])
            .send()
            .await
            .map_err(|_| Error::Provider)?;
        check_status(response.status())?;
        let value = bounded_json(response).await?;
        let token = value["access_token"]
            .as_str()
            .filter(|s| !s.is_empty() && s.len() <= 4096 && !s.chars().any(char::is_control))
            .ok_or(Error::Provider)?;
        let expires = value["expires_in"]
            .as_u64()
            .filter(|v| *v > 60 && *v <= 3600)
            .ok_or(Error::Provider)?;
        let token = Zeroizing::new(token.to_string());
        *cache = Some((token.clone(), now() + expires));
        Ok(token)
    }
    pub async fn send(&self, request: &PushRequest) -> Result<(), Error> {
        request.validate()?;
        let response = match &request.device_push_token {
            PushToken::Apns { token } => {
                let config = self.apns.as_ref().ok_or(Error::Configuration)?;
                self.http
                    .post(format!("{}{token}", self.apns_url))
                    .bearer_auth(Self::apns_auth(config)?.as_str())
                    .header("apns-topic", &config.topic)
                    .header("apns-push-type", "alert")
                    .header(
                        "apns-priority",
                        if request.delivery.mode == Mode::Silent {
                            "5"
                        } else {
                            "10"
                        },
                    )
                    .header("apns-expiration", (now() + 120).to_string())
                    .header("apns-collapse-id", &request.approval_id)
                    .json(&request.apns_payload())
                    .send()
                    .await
            }
            PushToken::Fcm { token } => {
                let config = self.fcm.as_ref().ok_or(Error::Configuration)?;
                self.http
                    .post(&self.fcm_url)
                    .bearer_auth(self.fcm_auth(config).await?.as_str())
                    .json(&request.fcm_payload(token))
                    .send()
                    .await
            }
        }
        .map_err(|_| Error::Provider)?;
        delivery_result(
            response,
            matches!(request.device_push_token, PushToken::Apns { .. }),
        )
        .await
    }
}
fn check_status(status: reqwest::StatusCode) -> Result<(), Error> {
    if status.is_success() {
        Ok(())
    } else if status.as_u16() == 429 {
        Err(Error::Throttled { retry_after_s: 60 })
    } else {
        Err(Error::Provider)
    }
}
async fn delivery_result(response: reqwest::Response, apns: bool) -> Result<(), Error> {
    let status = response.status();
    if status.as_u16() == 429 {
        let retry_after_s = response
            .headers()
            .get("retry-after")
            .map_or(60, |value| {
                value
                    .to_str()
                    .ok()
                    .and_then(|text| text.parse::<u64>().ok())
                    .unwrap_or(120)
            })
            .clamp(60, 3600);
        return Err(Error::Throttled { retry_after_s });
    }
    if status.is_success() {
        return Ok(());
    }
    if matches!(status.as_u16(), 400 | 404 | 410) {
        let value = bounded_json(response).await?;
        let invalid = if apns {
            matches!(
                value["reason"].as_str(),
                Some("BadDeviceToken" | "DeviceTokenNotForTopic" | "Unregistered")
            )
        } else {
            value["error"]["details"].as_array().is_some_and(|details| {
                details.iter().any(|detail| {
                    detail["@type"] == "type.googleapis.com/google.firebase.fcm.v1.FcmError"
                        && detail["errorCode"] == "UNREGISTERED"
                })
            })
        };
        if invalid {
            return Err(Error::InvalidToken);
        }
    }
    Err(Error::Provider)
}
async fn bounded_json(mut response: reqwest::Response) -> Result<Value, Error> {
    let mut bytes = Zeroizing::new(Vec::new());
    while let Some(chunk) = response.chunk().await.map_err(|_| Error::Provider)? {
        if bytes.len() + chunk.len() > 16 * 1024 {
            return Err(Error::Provider);
        }
        bytes.extend(chunk);
    }
    serde_json::from_slice(&bytes).map_err(|_| Error::Provider)
}
struct Service {
    dispatch: Dispatcher,
    bearer: Zeroizing<String>,
}
pub fn router(dispatch: Dispatcher, bearer: String) -> Result<Router, Error> {
    if bearer.len() < 32 || bearer.len() > 256 || bearer.chars().any(char::is_control) {
        return Err(Error::Configuration);
    }
    Ok(Router::new()
        .route("/v1/push", post(receive))
        .layer(DefaultBodyLimit::max(8192))
        .with_state(Arc::new(Service {
            dispatch,
            bearer: Zeroizing::new(bearer),
        })))
}
async fn receive(
    State(state): State<Arc<Service>>,
    headers: HeaderMap,
    Json(request): Json<PushRequest>,
) -> axum::response::Response {
    use axum::response::IntoResponse;
    let supplied = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .unwrap_or("");
    let mismatch = supplied
        .bytes()
        .zip(state.bearer.bytes())
        .fold(0_u8, |acc, (a, b)| acc | (a ^ b));
    if supplied.len() != state.bearer.len() || mismatch != 0 {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    let result = state.dispatch.send(&request).await;
    // Never print the request or provider body. Provider URLs contain full APNs tokens.
    // HTTP 410 is the authenticated synchronous callback to relay; its CAS cleanup
    // binds it to the token in this exact request, preserving concurrent rotations.
    let token = match &request.device_push_token {
        PushToken::Apns { token } | PushToken::Fcm { token } => token,
    };
    let suffix: String = token
        .chars()
        .rev()
        .take(6)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect();
    let event = match result {
        Ok(()) => "sent",
        Err(Error::InvalidToken) => "invalid_token",
        Err(Error::Throttled { .. }) => "throttled",
        Err(Error::Invalid) => "invalid_request",
        _ => "provider_unavailable",
    };
    if request.validate().is_ok() {
        eprintln!("kv_push event={event} token_suffix={suffix}");
    }
    match result {
        Ok(()) => StatusCode::ACCEPTED.into_response(),
        Err(Error::Invalid) => StatusCode::BAD_REQUEST.into_response(),
        Err(Error::InvalidToken) => StatusCode::GONE.into_response(),
        Err(Error::Throttled { retry_after_s }) => (
            StatusCode::TOO_MANY_REQUESTS,
            [("retry-after", retry_after_s.to_string())],
        )
            .into_response(),
        _ => StatusCode::BAD_GATEWAY.into_response(),
    }
}
pub fn load_apns(
    path: &std::path::Path,
    team: String,
    key_id: String,
    topic: String,
    sandbox: bool,
) -> Result<ApnsConfig, Error> {
    let pem = Zeroizing::new(std::fs::read_to_string(path).map_err(|_| Error::Configuration)?);
    let key = SigningKey::from_pkcs8_pem(&pem).map_err(|_| Error::Configuration)?;
    if [team.as_str(), key_id.as_str(), topic.as_str()]
        .iter()
        .any(|s| s.is_empty() || s.len() > 200 || s.chars().any(char::is_control))
    {
        return Err(Error::Configuration);
    }
    Ok(ApnsConfig {
        team,
        key_id,
        topic,
        sandbox,
        key,
    })
}
pub fn load_fcm(path: &std::path::Path) -> Result<FcmConfig, Error> {
    let bytes = Zeroizing::new(std::fs::read(path).map_err(|_| Error::Configuration)?);
    if bytes.len() > 16 * 1024 {
        return Err(Error::Configuration);
    }
    let value: Value = serde_json::from_slice(&bytes).map_err(|_| Error::Configuration)?;
    let project = value["project_id"]
        .as_str()
        .filter(|s| {
            !s.is_empty()
                && s.len() <= 100
                && s.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-')
        })
        .ok_or(Error::Configuration)?
        .to_string();
    let email = value["client_email"]
        .as_str()
        .filter(|s| s.len() <= 256 && s.contains('@'))
        .ok_or(Error::Configuration)?
        .to_string();
    let key =
        RsaPrivateKey::from_pkcs8_pem(value["private_key"].as_str().ok_or(Error::Configuration)?)
            .map_err(|_| Error::Configuration)?;
    if key.size() < 256 {
        return Err(Error::Configuration);
    }
    Ok(FcmConfig {
        project,
        email,
        key,
    })
}
#[cfg(test)]
mod tests;
