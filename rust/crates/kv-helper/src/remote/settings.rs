//! Local settings operations and signed remote changes share the helper's SQLite transaction.

use super::{Error, RemoteHelper, Result};
use kv_core::settings::{GrantMode, Settings, SettingsBackend, SettingsBinding};
use serde_json::json;
use std::sync::{Arc, Weak};

struct Backend {
    helper: Weak<RemoteHelper>,
    production: bool,
}
impl Backend {
    fn helper(&self) -> std::io::Result<Arc<RemoteHelper>> {
        if self.production {
            if let Some(helper) = super::server::runtime() {
                return Ok(helper);
            }
        }
        self.helper.upgrade().ok_or_else(unavailable)
    }
}
fn unavailable() -> std::io::Error {
    std::io::Error::other("remote settings unavailable")
}

impl SettingsBackend for Backend {
    fn read(&self) -> std::io::Result<Settings> {
        let helper = self.helper()?;
        helper.local_settings().map_err(|_| unavailable())
    }
    fn compare_and_write(&self, expected: &Settings, next: &Settings) -> std::io::Result<bool> {
        let helper = self.helper()?;
        let state = helper.lock().map_err(|_| unavailable())?;
        let current = helper.settings_locked(&state).map_err(|_| unavailable())?;
        if current != *expected {
            return Ok(false);
        }
        let tx = state
            .store
            .transaction(helper.services.audit.as_ref())
            .map_err(|_| unavailable())?;
        helper
            .write_settings_locked(&state, next, "local")
            .map_err(|_| unavailable())?;
        tx.commit().map_err(|_| unavailable())?;
        Ok(true)
    }
}

pub fn install(helper: &Arc<RemoteHelper>, vault: &std::path::Path) -> Result<SettingsBinding> {
    {
        let state = helper.lock()?;
        if state.store.setting::<Settings>("local_settings")?.is_none() {
            let mut initial = kv_core::settings::read_settings(vault);
            let mode = state
                .store
                .setting::<String>("mode")?
                .unwrap_or_else(|| "per_credential".into());
            if mode != "per_credential" {
                initial = mode_settings(&mode, &initial, helper.services.clock.now())?;
            }
            state.store.set_setting(
                "local_settings",
                &initial,
                "local",
                helper.services.clock.now(),
            )?;
            state.store.set_setting(
                "mode",
                &mode_text(&initial),
                "local",
                helper.services.clock.now(),
            )?;
        }
    }
    kv_core::settings::install_backend(
        vault,
        Arc::new(Backend {
            helper: Arc::downgrade(helper),
            production: vault == std::path::Path::new(kv_platform::paths::VAULT_DIR),
        }),
    )
    .map_err(|_| Error("settings_unavailable"))
}

impl RemoteHelper {
    pub fn local_settings(&self) -> Result<Settings> {
        self.settings_locked(&*self.lock()?)
    }
    pub(crate) fn settings_locked(&self, state: &super::engine::State) -> Result<Settings> {
        let initial = Settings {
            grant_mode: GrantMode::PerCredential,
            remember_hours: 8.0,
            remember_until: None,
        };
        match state.store.setting::<Settings>("local_settings")? {
            Some(settings) => Ok(settings),
            None => mode_settings(
                &state
                    .store
                    .setting::<String>("mode")?
                    .unwrap_or_else(|| "per_credential".into()),
                &initial,
                self.services.clock.now(),
            ),
        }
    }
    pub(crate) fn write_settings_locked(
        &self,
        state: &super::engine::State,
        next: &Settings,
        by: &str,
    ) -> Result<()> {
        if !next.remember_hours.is_finite()
            || !(0.0..=8760.0).contains(&next.remember_hours)
            || next
                .remember_until
                .is_some_and(|until| !until.is_finite() || until < 0.0)
        {
            return Err(Error("invalid_settings"));
        }
        let now = self.services.clock.now();
        state.store.set_setting("local_settings", next, by, now)?;
        state.store.set_setting("mode", &mode_text(next), by, now)?;
        self.audit(state, "setting_changed", json!({"key":"mode","by":by}))
    }
    pub(crate) fn change_mode_locked(
        &self,
        state: &super::engine::State,
        mode: &str,
        by: &str,
    ) -> Result<()> {
        let current = self.settings_locked(state)?;
        let next = mode_settings(mode, &current, self.services.clock.now())?;
        self.write_settings_locked(state, &next, by)
    }
}

fn mode_settings(mode: &str, previous: &Settings, now: i64) -> Result<Settings> {
    if let Some(hours) = mode
        .strip_prefix("remember:")
        .and_then(|text| text.strip_suffix('h'))
    {
        let hours: f64 = hours.parse().map_err(|_| Error("invalid_settings"))?;
        if !hours.is_finite() || !(0.0..=8760.0).contains(&hours) {
            return Err(Error("invalid_settings"));
        }
        return Ok(Settings {
            grant_mode: GrantMode::Remember,
            remember_hours: hours,
            remember_until: Some(kv_core::settings::remember_until(
                hours,
                now as f64 * 1000.0,
            )),
        });
    }
    let grant_mode = kv_core::settings::parse_mode(mode).ok_or(Error("invalid_settings"))?;
    Ok(Settings {
        grant_mode,
        remember_hours: previous.remember_hours,
        remember_until: None,
    })
}

pub fn mode_text(settings: &Settings) -> String {
    if settings.grant_mode == GrantMode::Remember {
        format!("remember:{}h", settings.remember_hours)
    } else {
        settings.grant_mode.as_str().into()
    }
}

/// Called only on the privileged management channel after executable and OS peer checks.
pub async fn control(
    context: super::ipc::CallerContext,
    params: serde_json::Value,
) -> Result<Settings> {
    if context.role() != kv_ipc::remote::Caller::CliOwner {
        return Err(Error("forbidden"));
    }
    let helper = super::server::runtime().ok_or(Error("remote_unavailable"))?;
    let current = helper.local_settings()?;
    let mut next = if let Some(value) = params.get("next") {
        let expected: Settings = serde_json::from_value(params["expected"].clone())?;
        if expected != current {
            return Err(Error("settings_changed"));
        }
        serde_json::from_value(value.clone())?
    } else {
        current.clone()
    };
    if params["forget"] == true {
        next.remember_until = None;
    } else {
        if let Some(mode) = params["grant_mode"].as_str() {
            next.grant_mode =
                kv_core::settings::parse_mode(mode).ok_or(Error("invalid_settings"))?;
            next.remember_until = None;
        }
        if let Some(hours) = params["remember_hours"].as_f64() {
            next.remember_hours = hours;
        }
    }
    if params.as_object().is_none_or(|params| params.is_empty()) {
        return Ok(current);
    }
    if kv_core::settings::is_loosening(&current, &next) && helper.local.ak_s.is_some() {
        helper
            .authorize_strong("local_settings", json!({"settings":next}))
            .await?;
        let proof = json!({"action":"local_settings","settings":next,"nonce":super::engine::random_nonce()?});
        let key = kv_core::remote::validation::approval_key(
            &helper.local,
            kv_core::remote::ApprovalLevel::Strong,
        )?;
        let sig = kv_core::remote::keys::sign_object(
            &proof,
            key.alg,
            helper.approval_provider(kv_core::remote::ApprovalLevel::Strong)?,
        )?;
        kv_core::remote::keys::verify_object(&proof, &sig, key)?;
    }
    let state = helper.lock()?;
    if helper.settings_locked(&state)? != current {
        return Err(Error("settings_changed"));
    }
    let tx = state.store.transaction(helper.services.audit.as_ref())?;
    helper.write_settings_locked(&state, &next, "local")?;
    tx.commit()?;
    Ok(next)
}
