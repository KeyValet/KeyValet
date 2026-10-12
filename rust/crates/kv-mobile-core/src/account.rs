//! Verified human sessions stay in hardware-derived encrypted storage, outside Dart.
use crate::{
    now,
    relay::Relay,
    view::{AccountView, SignInOptions},
    Error, MobileCore, Result,
};
use kv_core::remote::{
    canonical::{jcs, sha256_hex},
    keys::encode_b64,
    Os,
};
use serde::{Deserialize, Serialize};
use std::sync::atomic::Ordering;
use zeroize::Zeroize;

#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct User {
    pub id: String,
    pub provider: String,
    pub email: String,
    pub display_name: String,
}
#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct Session {
    pub session_token: String,
    pub expires_at: i64,
    pub user: User,
    pub relay_url: String,
}
impl Drop for Session {
    fn drop(&mut self) {
        self.session_token.zeroize();
    }
}
#[derive(Deserialize)]
struct LoginResponse {
    session_token: String,
    expires_at: i64,
    account_id: String,
    user: User,
}
#[derive(Clone, Serialize, Deserialize, Default)]
pub(crate) struct Providers {
    pub google: bool,
    pub apple: bool,
    pub google_web_client_id: String,
    pub google_ios_client_id: String,
    pub apple_app_id: String,
    pub apple_services_id: String,
}
#[derive(Clone, Serialize, Deserialize)]
struct Attempt {
    id: String,
    provider: String,
    state: String,
    nonce_hash: String,
    exp: i64,
    relay_url: String,
}

impl MobileCore {
    pub(crate) fn require_account_login(&self) {
        self.login_required.store(true, Ordering::SeqCst);
    }
    pub(crate) fn login_session(&self) -> Result<Option<Session>> {
        self.store
            .transaction(|db| self.store.get(db, "meta", "account_session"))
    }
    pub(crate) fn ensure_login(&self) -> Result<()> {
        self.store.transaction(|db| self.ensure_login_in(db))
    }
    pub(crate) fn ensure_login_in(&self, db: &rusqlite::Connection) -> Result<()> {
        if !self.login_required.load(Ordering::SeqCst) {
            return Ok(());
        }
        let session: Session = self
            .store
            .get(db, "meta", "account_session")?
            .ok_or(Error("login_required"))?;
        let settings: crate::view::SettingsView = self
            .store
            .get(db, "meta", "settings")?
            .ok_or(Error("storage_integrity"))?;
        if session.expires_at <= now() || session.relay_url != settings.relay_url {
            return Err(Error("login_required"));
        }
        Ok(())
    }
    pub fn account_view(&self) -> Result<AccountView> {
        let settings = self.settings()?;
        let session = self
            .login_session()?
            .filter(|s| s.expires_at > now() && s.relay_url == settings.relay_url);
        let providers: Providers = self.store.transaction(|db| {
            Ok(self
                .store
                .get(db, "meta", "login_providers")?
                .unwrap_or_default())
        })?;
        let mut view = AccountView {
            relay_url: settings.relay_url,
            locale: settings.locale,
            google_available: providers.google
                && !providers.google_web_client_id.is_empty()
                && (self.own.os != Os::Ios || !providers.google_ios_client_id.is_empty()),
            apple_available: providers.apple
                && if self.own.os == Os::Ios {
                    !providers.apple_app_id.is_empty()
                } else {
                    !providers.apple_services_id.is_empty()
                },
            ..AccountView::default()
        };
        if let Some(session) = session {
            view.signed_in = true;
            view.user_id = session.user.id.clone();
            view.email = session.user.email.clone();
            view.display_name = session.user.display_name.clone();
            view.provider = session.user.provider.clone();
            view.expires_at = session.expires_at;
        }
        Ok(view)
    }
    pub(crate) fn clear_login(&self) -> Result<()> {
        self.store.transaction(|db| {
            crate::Store::delete(db, "meta", "account_session")?;
            crate::Store::delete(db, "meta", "uploaded_push_token")?;
            crate::Store::delete(db, "meta", "uploaded_push_token")?;
            crate::Store::delete(db, "meta", "login_attempt")
        })?;
        self.connected.store(false, Ordering::SeqCst);
        Ok(())
    }
    pub(crate) fn clear_login_if(&self, token: &str) -> Result<()> {
        let removed = self.store.transaction(|db| {
            let current: Option<Session> = self.store.get(db, "meta", "account_session")?;
            if current
                .as_ref()
                .is_some_and(|session| session.session_token == token)
            {
                crate::Store::delete(db, "meta", "account_session")?;
                crate::Store::delete(db, "meta", "uploaded_push_token")?;
                crate::Store::delete(db, "meta", "uploaded_push_token")?;
                return Ok(true);
            }
            Ok(false)
        })?;
        if removed {
            self.connected.store(false, Ordering::SeqCst);
        }
        Ok(())
    }
}

impl Relay {
    pub async fn account_restore(&self) -> Result<AccountView> {
        if let Some(session) = self.core.login_session()? {
            if session.expires_at <= now() || session.relay_url != self.core.settings()?.relay_url {
                self.core.clear_login_if(&session.session_token)?;
            } else {
                let response = self
                    .account_request(
                        reqwest::Method::GET,
                        "v1/account/session",
                        None,
                        Some(&session.session_token),
                    )
                    .await;
                match response {
                    Ok(value) => {
                        let user: User = serde_json::from_value(value["user"].clone())?;
                        if user.id != session.user.id
                            || value["expires_at"].as_i64() != Some(session.expires_at)
                        {
                            self.core.clear_login_if(&session.session_token)?;
                            return Err(Error("invalid_login_session"));
                        }
                    }
                    Err(Error("login_required")) => {
                        self.core.clear_login_if(&session.session_token)?;
                    }
                    Err(error)
                        if matches!(error.0, "network_unavailable" | "relay_unavailable") => {}
                    Err(error) => return Err(error),
                }
            }
        }
        // Provider availability is display-only. It never substitutes for a verified session.
        if let Ok(value) = self
            .account_request(reqwest::Method::GET, "v1/account/providers", None, None)
            .await
        {
            let providers: Providers = serde_json::from_value(value)?;
            self.core.store.transaction(|db| {
                self.core
                    .store
                    .put(db, "meta", "login_providers", &providers, 0)
            })?;
        }
        self.core.account_view()
    }
    pub async fn account_begin(&self, provider: &str) -> Result<SignInOptions> {
        if !matches!(provider, "google" | "apple") {
            return Err(Error("invalid_login_provider"));
        }
        let value = self
            .account_request(reqwest::Method::GET, "v1/account/providers", None, None)
            .await?;
        let providers: Providers = serde_json::from_value(value)?;
        self.core.store.transaction(|db| {
            self.core
                .store
                .put(db, "meta", "login_providers", &providers, 0)
        })?;
        let availability = self.core.account_view()?;
        if (provider == "google" && !availability.google_available)
            || (provider == "apple" && !availability.apple_available)
        {
            return Err(Error("login_configuration_required"));
        }
        let relay_url = self.core.settings()?.relay_url;
        let value = self
            .account_request(
                reqwest::Method::POST,
                "v1/account/begin",
                Some(serde_json::json!({"provider":provider,"device":self.core.device()})),
                None,
            )
            .await?;
        let id = value["attempt_id"]
            .as_str()
            .ok_or(Error("invalid_login_attempt"))?;
        let state = value["state"]
            .as_str()
            .ok_or(Error("invalid_login_attempt"))?;
        let nonce = value["nonce_hash"]
            .as_str()
            .ok_or(Error("invalid_login_attempt"))?;
        let exp = value["expires_at"]
            .as_i64()
            .ok_or(Error("invalid_login_attempt"))?;
        if id.len() != 43
            || !state.starts_with("kv.app.")
            || state.len() > 128
            || nonce.len() != 64
            || !nonce.bytes().all(|b| b.is_ascii_hexdigit())
            || exp <= now()
            || exp > now() + 660
        {
            return Err(Error("invalid_login_attempt"));
        }
        let attempt = Attempt {
            id: id.into(),
            provider: provider.into(),
            state: state.into(),
            nonce_hash: nonce.into(),
            exp,
            relay_url,
        };
        self.core.store.transaction(|db| {
            self.core
                .store
                .put(db, "meta", "login_attempt", &attempt, exp)
        })?;
        Ok(SignInOptions {
            attempt_id: attempt.id,
            provider: provider.into(),
            nonce_hash: attempt.nonce_hash,
            state: attempt.state,
            google_web_client_id: providers.google_web_client_id,
            google_ios_client_id: providers.google_ios_client_id,
            apple_services_id: providers.apple_services_id,
        })
    }
    pub async fn account_finish(
        &self,
        attempt_id: &str,
        identity_token: &str,
        returned_state: &str,
        display_name: &str,
    ) -> Result<AccountView> {
        let attempt: Attempt = self.core.store.transaction(|db| {
            self.core
                .store
                .get(db, "meta", "login_attempt")?
                .ok_or(Error("login_attempt_expired"))
        })?;
        if attempt.id != attempt_id
            || attempt.exp <= now()
            || attempt.relay_url != self.core.settings()?.relay_url
            || identity_token.is_empty()
            || identity_token.len() > 8192
            || (attempt.provider == "apple" && returned_state != attempt.state)
        {
            return Err(Error("invalid_login_attempt"));
        }
        let proof = serde_json::json!({"purpose":"keyvalet-account-login-v1","attempt_id":attempt.id,"provider":attempt.provider,
            "device_id":self.core.device().device_id,"identity_token_hash":sha256_hex(identity_token.as_bytes()),"state":attempt.state});
        let signature = self
            .core
            .keys
            .identity
            .sign(kv_core::remote::SignatureAlgorithm::ES256, &jcs(&proof)?)?;
        let value=self.account_request(reqwest::Method::POST,"v1/account/finish",Some(serde_json::json!({
            "attempt_id":attempt.id,"identity_token":identity_token,"state":attempt.state,"signature":encode_b64(&signature),"display_name":display_name})),None).await?;
        let response: LoginResponse = serde_json::from_value(value)?;
        if response.session_token.len() != 43
            || response.user.id.is_empty()
            || !matches!(response.user.provider.as_str(), "apple" | "google")
            || response.user.provider != attempt.provider
            || response.expires_at <= now()
            || response.expires_at > now() + 31 * 86400
            || response.account_id.is_empty()
        {
            return Err(Error("invalid_login_session"));
        }
        let session = Session {
            session_token: response.session_token,
            expires_at: response.expires_at,
            user: response.user,
            relay_url: attempt.relay_url.clone(),
        };
        let committed = self.core.store.transaction(|db| {
            let current: Attempt = self
                .core
                .store
                .get(db, "meta", "login_attempt")?
                .ok_or(Error("login_attempt_expired"))?;
            if current.id != attempt.id {
                return Err(Error("login_attempt_expired"));
            }
            if self
                .core
                .store
                .get::<String>(db, "meta", "login_owner")?
                .is_some_and(|owner| owner != session.user.id)
            {
                return Err(Error("login_account_conflict"));
            }
            self.core
                .store
                .put(db, "meta", "account_session", &session, 0)?;
            self.core
                .store
                .put(db, "meta", "login_owner", &session.user.id, 0)?;
            self.core
                .store
                .put(db, "meta", "account", &response.account_id, 0)?;
            self.core.store.put(db, "meta", "registered", &true, 0)?;
            crate::Store::delete(db, "meta", "uploaded_push_token")?;
            crate::Store::delete(db, "meta", "login_attempt")
        });
        if let Err(error) = committed {
            // A logout can win while the provider response is in flight.
            // Revoke the unused session instead of resurrecting local credentials.
            let _ = self
                .account_request(
                    reqwest::Method::POST,
                    "v1/account/logout",
                    Some(serde_json::json!({})),
                    Some(&session.session_token),
                )
                .await;
            return Err(error);
        }
        self.clear_device_session()?;
        let _ = self.sync_push_token().await;
        self.core.account_view()
    }
    pub async fn account_logout(&self) -> Result<()> {
        let session = self.core.login_session()?;
        self.stop();
        if let Some(session) = &session {
            // A network outage during logout must not lose the remote token removal.
            // This encrypted credential can only revoke its own old session.
            self.core.store.transaction(|db| {
                self.core.store.put(
                    db,
                    "logout_pending",
                    &sha256_hex(session.session_token.as_bytes()),
                    session,
                    session.expires_at,
                )
            })?;
        }
        self.core.clear_login()?;
        self.clear_device_session()?;
        let _ = self.retry_logouts().await;
        Ok(())
    }

    pub(crate) async fn retry_logouts(&self) -> Result<()> {
        let pending = self.core.store.transaction(|db| {
            crate::Store::expire(db, now())?;
            self.core.store.list::<Session>(db, "logout_pending")
        })?;
        for (id, session) in pending {
            let result = self
                .account_request(
                    reqwest::Method::POST,
                    "v1/account/logout",
                    Some(serde_json::json!({})),
                    Some(&session.session_token),
                )
                .await;
            match result {
                Ok(_) | Err(Error("login_required")) => self
                    .core
                    .store
                    .transaction(|db| crate::Store::delete(db, "logout_pending", &id))?,
                Err(error) => return Err(error),
            }
        }
        Ok(())
    }
}
