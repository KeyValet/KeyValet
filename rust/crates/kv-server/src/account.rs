//! Human sign-in augments device authentication; it never grants an approval key.
use crate::{
    error::ApiError,
    http::Wire,
    state::{self, State as RelayState},
};
use axum::{
    body::to_bytes,
    extract::{ConnectInfo, Request, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use kv_core::remote::{
    canonical::{from_json, jcs, sha256_hex},
    keys::{decode_b64, verify_identity_signature, verify_signature},
    DeviceRecord, Os, PublicJwk, SignatureAlgorithm,
};
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{collections::HashMap, net::SocketAddr, sync::Arc, time::Duration};
use tokio::sync::Mutex;

pub const USER_HEADER: &str = "x-keyvalet-user-session";
const ATTEMPT_TTL: i64 = 600;
const USER_TTL: i64 = 30 * 86400;

/// Public OAuth application identifiers only. No provider private key is needed to verify ID tokens.
#[derive(Clone, Default)]
pub struct AccountConfig {
    pub required: bool,
    pub google_web_client_id: String,
    pub google_ios_client_id: String,
    pub google_android_client_id: String,
    pub apple_app_id: String,
    pub apple_services_id: String,
}
impl AccountConfig {
    pub fn from_env() -> Self {
        let read = |key| std::env::var(key).unwrap_or_default();
        Self {
            required: true,
            google_web_client_id: read("KEYVALET_GOOGLE_WEB_CLIENT_ID"),
            google_ios_client_id: read("KEYVALET_GOOGLE_IOS_CLIENT_ID"),
            google_android_client_id: read("KEYVALET_GOOGLE_ANDROID_CLIENT_ID"),
            apple_app_id: read("KEYVALET_APPLE_APP_ID"),
            apple_services_id: read("KEYVALET_APPLE_SERVICES_ID"),
        }
    }
    fn enabled(&self, provider: &str, os: Os) -> bool {
        match provider {
            "google" => {
                !self.google_web_client_id.is_empty()
                    && (os != Os::Ios || !self.google_ios_client_id.is_empty())
            }
            "apple" => match os {
                Os::Ios => !self.apple_app_id.is_empty(),
                Os::Android => !self.apple_services_id.is_empty(),
                _ => false,
            },
            _ => false,
        }
    }
}

pub(crate) struct Accounts {
    pub config: AccountConfig,
    http: reqwest::Client,
    keys: Mutex<HashMap<String, (i64, Vec<PublicJwk>)>>,
}
impl Accounts {
    pub(crate) fn seed_test_keys(&self, keys: Vec<(String, Vec<PublicJwk>)>, now: i64) {
        let mut cache = self.keys.try_lock().expect("fresh test issuer cache");
        for (provider, keys) in keys {
            cache.insert(provider, (now, keys));
        }
    }
    pub fn new(config: AccountConfig) -> Self {
        Self {
            config,
            http: reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .connect_timeout(Duration::from_secs(5))
                .timeout(Duration::from_secs(12))
                .build()
                .expect("fixed OAuth HTTP client configuration"),
            keys: Mutex::new(HashMap::new()),
        }
    }
    async fn signing_key(&self, provider: &str, kid: &str, now: i64) -> AccountResult<PublicJwk> {
        let mut cache = self.keys.lock().await;
        if let Some((fetched, keys)) = cache.get(provider) {
            if now - fetched < 3600 {
                if let Some(key) = keys
                    .iter()
                    .find(|key| key.extra.get("kid").and_then(Value::as_str) == Some(kid))
                {
                    return Ok(key.clone());
                }
                if now - fetched < 60 {
                    return Err(AccountError::invalid());
                }
            }
        }
        let url = match provider {
            "google" => "https://www.googleapis.com/oauth2/v3/certs",
            "apple" => "https://appleid.apple.com/auth/keys",
            _ => return Err(AccountError::invalid()),
        };
        let mut response = self
            .http
            .get(url)
            .send()
            .await
            .map_err(|_| AccountError::unavailable())?;
        if !response.status().is_success() {
            return Err(AccountError::unavailable());
        }
        let mut bytes = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|_| AccountError::unavailable())?
        {
            if bytes.len() + chunk.len() > 65536 {
                return Err(AccountError::unavailable());
            }
            bytes.extend(chunk);
        }
        #[derive(Deserialize)]
        struct Keys {
            keys: Vec<PublicJwk>,
        }
        let keys: Keys = from_json(&bytes).map_err(|_| AccountError::unavailable())?;
        if keys.keys.is_empty() || keys.keys.len() > 32 {
            return Err(AccountError::unavailable());
        }
        let key = keys
            .keys
            .iter()
            .find(|key| key.extra.get("kid").and_then(Value::as_str) == Some(kid))
            .cloned();
        cache.insert(provider.into(), (now, keys.keys));
        key.ok_or_else(AccountError::invalid)
    }
}

#[derive(Debug)]
pub(crate) struct AccountError {
    status: StatusCode,
    code: &'static str,
}
type AccountResult<T> = std::result::Result<T, AccountError>;
impl AccountError {
    fn invalid() -> Self {
        Self {
            status: StatusCode::UNAUTHORIZED,
            code: "invalid_identity",
        }
    }
    fn unavailable() -> Self {
        Self {
            status: StatusCode::SERVICE_UNAVAILABLE,
            code: "provider_unavailable",
        }
    }
}
impl From<ApiError> for AccountError {
    fn from(error: ApiError) -> Self {
        use kv_core::remote::relay::ErrorCode;
        let status = match error.code {
            ErrorCode::Unauthorized => StatusCode::UNAUTHORIZED,
            ErrorCode::Forbidden => StatusCode::FORBIDDEN,
            ErrorCode::Expired => StatusCode::UNAUTHORIZED,
            ErrorCode::RateLimited => StatusCode::TOO_MANY_REQUESTS,
            ErrorCode::Conflict => StatusCode::CONFLICT,
            _ => StatusCode::BAD_REQUEST,
        };
        Self {
            status,
            code: if status == StatusCode::CONFLICT {
                "account_conflict"
            } else {
                "login_rejected"
            },
        }
    }
}
impl IntoResponse for AccountError {
    fn into_response(self) -> Response {
        (
            self.status,
            Json(json!({"error":{"code":self.code,"message":"Sign-in could not be completed."}})),
        )
            .into_response()
    }
}

pub(crate) async fn providers(State(state): State<Arc<RelayState>>) -> Json<Value> {
    let c = &state.accounts.config;
    Json(
        json!({"google":!c.google_web_client_id.is_empty(),"apple":!c.apple_app_id.is_empty() || !c.apple_services_id.is_empty(),
        "google_web_client_id":c.google_web_client_id,"google_ios_client_id":c.google_ios_client_id,
        "apple_app_id":c.apple_app_id,"apple_services_id":c.apple_services_id,"apple_callback_url":"https://relay.keyvalet.dev/v1/account/apple/callback"}),
    )
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct StartRequest {
    provider: String,
    device: DeviceRecord,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PushToken {
    platform: String,
    token: String,
}
pub(crate) async fn push_token(
    State(state): State<Arc<RelayState>>,
    headers: HeaderMap,
    Wire(push): Wire<PushToken>,
) -> crate::error::Result<Json<Value>> {
    if push.token.is_empty() || push.token.len() > 4096 || push.token.chars().any(char::is_control)
    {
        return Err(ApiError::bad());
    }
    state.with(|data, now| {
        let principal = data.authenticate(&headers, now)?;
        data.check(&principal, now, true)?;
        if !matches!(
            (&principal.device.os, push.platform.as_str()),
            (Os::Ios, "apns") | (Os::Android, "fcm")
        ) {
            return Err(ApiError::bad());
        }
        let value = serde_json::to_vec(&json!({"platform":push.platform,"token":push.token}))
            .map_err(|_| ApiError::bad())?;
        crate::push::install_lifecycle_triggers(&data.db)?;
        data.db.execute(
            "UPDATE devices SET push_token=?1 WHERE id=?2 AND revoked_at IS NULL",
            params![value, principal.device.device_id],
        )?;
        Ok(Json(json!({"ok":true})))
    })
}
pub(crate) async fn remove_push_token(
    State(state): State<Arc<RelayState>>,
    headers: HeaderMap,
) -> crate::error::Result<Json<Value>> {
    state.with(|data, now| {
        let principal = data.authenticate(&headers, now)?;
        data.check(&principal, now, true)?;
        data.db.execute(
            "UPDATE devices SET push_token=NULL WHERE id=?1",
            [&principal.device.device_id],
        )?;
        data.db.execute(
            "DELETE FROM push_jobs WHERE to_device=?1",
            [&principal.device.device_id],
        )?;
        Ok(())
    })?;
    Ok(Json(json!({"ok":true})))
}

pub(crate) async fn begin(
    State(state): State<Arc<RelayState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Wire(request): Wire<StartRequest>,
) -> AccountResult<Json<Value>> {
    state::validate_device(&request.device)?;
    if !is_mobile(&request.device)
        || !state
            .accounts
            .config
            .enabled(&request.provider, request.device.os.clone())
    {
        return Err(AccountError {
            status: StatusCode::SERVICE_UNAVAILABLE,
            code: "provider_not_configured",
        });
    }
    let response = state.with(|data, now| {
        data.rate(format!("login:{}", state::client_ip(peer, &headers)), now, 1, 20)?;
        data.db.execute("DELETE FROM login_attempts WHERE exp<?1", [now])?;
        let id = state::random_token(32);
        let nonce = state::random_token(32);
        let login_state = format!("kv.app.{}", state::random_token(32));
        data.db.execute("INSERT INTO login_attempts(id,provider,nonce_hash,state,device,exp) VALUES(?1,?2,?3,?4,?5,?6)",
            params![id,request.provider,sha256_hex(nonce.as_bytes()),login_state,serde_json::to_vec(&request.device).map_err(|_|ApiError::bad())?,now+ATTEMPT_TTL])?;
        Ok(json!({"attempt_id":id,"nonce_hash":sha256_hex(nonce.as_bytes()),"state":login_state,"expires_at":now+ATTEMPT_TTL}))
    })?;
    Ok(Json(response))
}

#[derive(Serialize)]
pub struct LoginProof<'a> {
    pub purpose: &'a str,
    pub attempt_id: &'a str,
    pub provider: &'a str,
    pub device_id: &'a str,
    pub identity_token_hash: &'a str,
    pub state: &'a str,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct FinishRequest {
    attempt_id: String,
    identity_token: String,
    state: String,
    signature: String,
    #[serde(default)]
    display_name: String,
}
struct VerifiedIdentity {
    subject: String,
    email: String,
    name: String,
}

fn verify_token(
    token: &str,
    key: &PublicJwk,
    provider: &str,
    audience: &str,
    presenters: &[&str],
    nonce_hash: &str,
    now: i64,
) -> AccountResult<VerifiedIdentity> {
    if token.len() > 8192 || token.chars().any(char::is_control) {
        return Err(AccountError::invalid());
    }
    let parts: Vec<_> = token.split('.').collect();
    if parts.len() != 3 {
        return Err(AccountError::invalid());
    }
    let header: Value = from_json(&decode_b64(parts[0]).map_err(|_| AccountError::invalid())?)
        .map_err(|_| AccountError::invalid())?;
    if header["alg"] != "RS256"
        || key.kty != "RSA"
        || key.extra.get("use").is_some_and(|use_| use_ != "sig")
        || key.extra.get("alg").is_some_and(|alg| alg != "RS256")
        || header.get("jku").is_some()
        || header.get("jwk").is_some()
        || header.get("crit").is_some()
    {
        return Err(AccountError::invalid());
    }
    verify_signature(
        SignatureAlgorithm::RS256,
        key,
        format!("{}.{}", parts[0], parts[1]).as_bytes(),
        &decode_b64(parts[2]).map_err(|_| AccountError::invalid())?,
    )
    .map_err(|_| AccountError::invalid())?;
    let claims: Value = from_json(&decode_b64(parts[1]).map_err(|_| AccountError::invalid())?)
        .map_err(|_| AccountError::invalid())?;
    let issuer = claims["iss"].as_str().unwrap_or("");
    let valid_issuer = match provider {
        "google" => matches!(
            issuer,
            "https://accounts.google.com" | "accounts.google.com"
        ),
        "apple" => issuer == "https://appleid.apple.com",
        _ => false,
    };
    let exp = claims["exp"].as_i64().unwrap_or(0);
    let iat = claims["iat"].as_i64().unwrap_or(i64::MAX);
    let sub = claims["sub"].as_str().unwrap_or("");
    if !valid_issuer
        || claims["aud"] != audience
        || exp <= now
        || iat > now + 60
        || iat < now - 86400
        || exp <= iat
        || exp - iat > 86400
        || claims
            .get("nbf")
            .is_some_and(|v| v.as_i64().is_none_or(|n| n > now + 60))
        || sub.is_empty()
        || sub.len() > 255
        || sub.chars().any(char::is_control)
        || claims
            .get("azp")
            .is_some_and(|v| v.as_str().is_none_or(|azp| !presenters.contains(&azp)))
        || (provider == "apple" && claims["nonce"] != nonce_hash)
    {
        return Err(AccountError::invalid());
    }
    let verified = claims["email_verified"] == true
        || (provider == "apple" && claims["email_verified"] == "true");
    let email = claims["email"].as_str().unwrap_or("");
    if !verified
        || email.len() > 320
        || !email.contains('@')
        || email.chars().any(char::is_whitespace)
        || email.chars().any(char::is_control)
    {
        return Err(AccountError::invalid());
    }
    Ok(VerifiedIdentity {
        subject: sub.into(),
        email: email.to_lowercase(),
        name: clean_name(claims["name"].as_str().unwrap_or("")),
    })
}
fn clean_name(value: &str) -> String {
    value
        .chars()
        .filter(|c| !c.is_control())
        .take(64)
        .collect::<String>()
        .trim()
        .into()
}

pub(crate) async fn finish(
    State(state): State<Arc<RelayState>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Wire(request): Wire<FinishRequest>,
) -> AccountResult<Json<Value>> {
    if request.identity_token.len() > 8192 || request.attempt_id.len() != 43 {
        return Err(AccountError::invalid());
    }
    let (provider, nonce_hash, login_state, record) = state.with(|data, now| {
        data.rate(format!("login_finish:{}",state::client_ip(peer,&headers)),now,1,20)?;
        data.db.query_row("SELECT provider,nonce_hash,state,device FROM login_attempts WHERE id=?1 AND exp>?2", params![request.attempt_id,now],
            |row| Ok((row.get::<_,String>(0)?,row.get::<_,String>(1)?,row.get::<_,String>(2)?,row.get::<_,Vec<u8>>(3)?))).optional()?.ok_or_else(ApiError::unauthorized)
    })?;
    let device: DeviceRecord = from_json(&record).map_err(|_| AccountError::invalid())?;
    if request.state != login_state {
        return Err(AccountError::invalid());
    }
    let digest = sha256_hex(request.identity_token.as_bytes());
    let proof = jcs(&LoginProof {
        purpose: "keyvalet-account-login-v1",
        attempt_id: &request.attempt_id,
        provider: &provider,
        device_id: &device.device_id,
        identity_token_hash: &digest,
        state: &login_state,
    })
    .map_err(|_| AccountError::invalid())?;
    verify_identity_signature(
        &device,
        &proof,
        &decode_b64(&request.signature).map_err(|_| AccountError::invalid())?,
    )
    .map_err(|_| AccountError::invalid())?;
    let head = request
        .identity_token
        .split('.')
        .next()
        .ok_or_else(AccountError::invalid)?;
    let header: Value = from_json(&decode_b64(head).map_err(|_| AccountError::invalid())?)
        .map_err(|_| AccountError::invalid())?;
    let kid = header["kid"]
        .as_str()
        .filter(|kid| !kid.is_empty() && kid.len() <= 128)
        .ok_or_else(AccountError::invalid)?;
    let key = state
        .accounts
        .signing_key(&provider, kid, state.now())
        .await?;
    let c = &state.accounts.config;
    let audience = match provider.as_str() {
        "google" => &c.google_web_client_id,
        "apple" if device.os == Os::Ios => &c.apple_app_id,
        "apple" => &c.apple_services_id,
        _ => return Err(AccountError::invalid()),
    };
    let presenters: Vec<&str> = if provider == "google" {
        vec![
            &c.google_web_client_id,
            &c.google_ios_client_id,
            &c.google_android_client_id,
        ]
    } else {
        vec![audience]
    };
    let identity = verify_token(
        &request.identity_token,
        &key,
        &provider,
        audience,
        &presenters,
        &nonce_hash,
        state.now(),
    )?;
    let token = state::random_token(32);
    let response = state.with(|data,now| {
        let tx = data.db.transaction()?;
        if tx.execute("DELETE FROM login_attempts WHERE id=?1 AND state=?2 AND exp>?3",params![request.attempt_id,login_state,now])? != 1 { return Err(ApiError::unauthorized()); }
        let existing: Option<String> = tx.query_row("SELECT id FROM login_users WHERE provider=?1 AND subject=?2",params![provider,identity.subject],|r|r.get(0)).optional()?;
        let user = existing.unwrap_or_else(|| format!("usr_{}",state::random_token(16)));
        let display_name = if identity.name.is_empty() { clean_name(&request.display_name) } else { identity.name.clone() };
        tx.execute("INSERT INTO login_users(id,provider,subject,email,display_name,created_at) VALUES(?1,?2,?3,?4,?5,?6)
            ON CONFLICT(provider,subject) DO UPDATE SET email=excluded.email,display_name=CASE WHEN excluded.display_name='' THEN login_users.display_name ELSE excluded.display_name END",
            params![user,provider,identity.subject,identity.email,display_name,now])?;
        let existing_device = tx.query_row("SELECT account_id,record,revoked_at FROM devices WHERE id=?1",[&device.device_id],|r|Ok((r.get::<_,String>(0)?,r.get::<_,Vec<u8>>(1)?,r.get::<_,Option<i64>>(2)?))).optional()?;
        let account = if let Some((account, bytes, revoked)) = existing_device {
            if revoked.is_some() || from_json::<DeviceRecord>(&bytes)? != device { return Err(ApiError::forbidden()); }
            account
        } else {
            let account = format!("acct_{}",state::random_token(16));
            // No recovery secret is returned or substituted for human sign-in.
            tx.execute("INSERT INTO accounts(id,created_at,recovery_hash) VALUES(?1,?2,'')",params![account,now])?;
            state::insert_device(&tx,&account,&device,None,now)?;
            account
        };
        for previous in [device_owner(&tx,&device.device_id)?, account_owner(&tx,&account)?].into_iter().flatten() {
            if previous != user { return Err(ApiError::conflict()); }
        }
        tx.execute("INSERT OR IGNORE INTO device_users(device_id,user_id) VALUES(?1,?2)",params![device.device_id,user])?;
        if state::device_ready(&tx,&device.device_id)? {
            tx.execute("INSERT OR IGNORE INTO account_owners(account_id,user_id) VALUES(?1,?2)",params![account,user])?;
        }
        // A phone keeps one live human session, including across process restarts.
        tx.execute("DELETE FROM sessions WHERE device_id=?1",[&device.device_id])?;
        tx.execute("DELETE FROM account_sessions WHERE device_id=?1",[&device.device_id])?;
        tx.execute("INSERT INTO account_sessions(token_hash,user_id,device_id,exp,created_at) VALUES(?1,?2,?3,?4,?5)",params![sha256_hex(token.as_bytes()),user,device.device_id,now+USER_TTL,now])?;
        tx.commit()?;
        data.invalidate_device(&device.device_id);
        Ok(json!({"session_token":token,"expires_at":now+USER_TTL,"account_id":account,
            "user":{"id":user,"provider":provider,"email":identity.email,"display_name":display_name}}))
    })?;
    state.event("account_signed_in", 1);
    Ok(Json(response))
}

pub(crate) fn is_mobile(device: &DeviceRecord) -> bool {
    matches!(device.os, Os::Ios | Os::Android)
}
pub(crate) fn device_owner(db: &Connection, id: &str) -> crate::error::Result<Option<String>> {
    Ok(db
        .query_row(
            "SELECT user_id FROM device_users WHERE device_id=?1",
            [id],
            |r| r.get(0),
        )
        .optional()?)
}
pub(crate) fn account_owner(db: &Connection, id: &str) -> crate::error::Result<Option<String>> {
    Ok(db
        .query_row(
            "SELECT user_id FROM account_owners WHERE account_id=?1",
            [id],
            |r| r.get(0),
        )
        .optional()?)
}
pub(crate) fn require_device_user(
    db: &Connection,
    device: &DeviceRecord,
    headers: &HeaderMap,
    now: i64,
) -> crate::error::Result<Option<String>> {
    if !is_mobile(device) {
        return Ok(None);
    }
    let raw = headers
        .get(USER_HEADER)
        .and_then(|v| v.to_str().ok())
        .filter(|v| v.len() == 43)
        .ok_or_else(ApiError::unauthorized)?;
    let hash = sha256_hex(raw.as_bytes());
    let exists: bool = db.query_row("SELECT EXISTS(SELECT 1 FROM account_sessions s JOIN device_users u ON u.device_id=s.device_id WHERE s.token_hash=?1 AND s.device_id=?2 AND s.user_id=u.user_id AND s.exp>?3)",params![hash,device.device_id,now],|r|r.get(0))?;
    if !exists {
        return Err(ApiError::unauthorized());
    }
    Ok(Some(hash))
}
fn bearer(headers: &HeaderMap) -> crate::error::Result<String> {
    headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .filter(|v| v.len() == 43)
        .map(|token| sha256_hex(token.as_bytes()))
        .ok_or_else(ApiError::unauthorized)
}
pub(crate) async fn session(
    State(state): State<Arc<RelayState>>,
    headers: HeaderMap,
) -> AccountResult<Json<Value>> {
    let hash = bearer(&headers)?;
    Ok(Json(state.with(|data,now| {
        data.db.query_row("SELECT u.id,u.provider,u.email,u.display_name,s.exp FROM account_sessions s JOIN login_users u ON u.id=s.user_id JOIN devices d ON d.id=s.device_id WHERE s.token_hash=?1 AND s.exp>?2 AND d.revoked_at IS NULL",params![hash,now],|r| Ok(json!({"user":{"id":r.get::<_,String>(0)?,"provider":r.get::<_,String>(1)?,"email":r.get::<_,String>(2)?,"display_name":r.get::<_,String>(3)?},"expires_at":r.get::<_,i64>(4)?}))).optional()?.ok_or_else(ApiError::unauthorized)
    })?))
}
pub(crate) async fn logout(
    State(state): State<Arc<RelayState>>,
    headers: HeaderMap,
) -> AccountResult<Json<Value>> {
    let hash = bearer(&headers)?;
    state.with(|data,now| {
        let device: String = data.db.query_row("SELECT device_id FROM account_sessions WHERE token_hash=?1 AND exp>?2",params![hash,now],|r|r.get(0)).optional()?.ok_or_else(ApiError::unauthorized)?;
        let tx = data.db.transaction()?;
        tx.execute("DELETE FROM sessions WHERE token_hash IN (SELECT token_hash FROM device_session_users WHERE account_session=?1)",[&hash])?;
        tx.execute("DELETE FROM account_sessions WHERE token_hash=?1",[&hash])?;
        tx.execute("UPDATE devices SET push_token=NULL WHERE id=?1",[&device])?;
        tx.commit()?;
        data.invalidate_device(&device);
        Ok(())
    })?;
    Ok(Json(json!({"ok":true})))
}

/// Apple's Android form_post callback returns only to the fixed app component.
pub(crate) async fn apple_callback(
    State(state): State<Arc<RelayState>>,
    request: Request,
) -> AccountResult<Response> {
    if request
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .is_none_or(|v| v.split(';').next() != Some("application/x-www-form-urlencoded"))
    {
        return Err(AccountError::invalid());
    }
    let body = to_bytes(request.into_body(), 16384)
        .await
        .map_err(|_| AccountError::invalid())?;
    let mut values = HashMap::new();
    for (key, value) in url::form_urlencoded::parse(&body) {
        if values
            .insert(key.into_owned(), value.into_owned())
            .is_some()
        {
            return Err(AccountError::invalid());
        }
    }
    let login_state = values.get("state").ok_or_else(AccountError::invalid)?;
    state.with(|data,now| {
        let valid: bool = data.db.query_row("SELECT EXISTS(SELECT 1 FROM login_attempts WHERE state=?1 AND provider='apple' AND exp>?2)",params![login_state,now],|r|r.get(0))?;
        if valid { Ok(()) } else { Err(ApiError::unauthorized()) }
    })?;
    let mut query = url::form_urlencoded::Serializer::new(String::new());
    for key in ["state", "code", "id_token", "error", "error_description"] {
        if let Some(value) = values.get(key) {
            if value.len() > 8192 {
                return Err(AccountError::invalid());
            }
            query.append_pair(key, value);
        }
    }
    let target = format!(
        "intent://callback?{}#Intent;package=dev.keyvalet.mobile;scheme=signinwithapple;end",
        query.finish()
    );
    let mut response = StatusCode::SEE_OTHER.into_response();
    response.headers_mut().insert(
        "location",
        target.parse().map_err(|_| AccountError::invalid())?,
    );
    response
        .headers_mut()
        .insert("cache-control", "no-store".parse().unwrap());
    response
        .headers_mut()
        .insert("referrer-policy", "no-referrer".parse().unwrap());
    Ok(response)
}

#[cfg(test)]
#[path = "unit_tests/account.rs"]
mod tests;
