//! Privileged setup and loading of the production remote backend.

use super::bootstrap::{self, KeyFactory};
use super::production::{ProductionRunner, SystemProcesses};
use super::{ApprovalConfig, Error, Result, SystemClock};
use kv_core::remote::{Optional, Os, Presence, PresenceProbe};
use kv_ipc::remote::PresenceState;
use serde_json::{json, Value};
use std::path::PathBuf;
use std::sync::{Arc, Mutex, OnceLock};
use zeroize::Zeroizing;

static STARTUP: OnceLock<Arc<Startup>> = OnceLock::new();

struct UnknownPresence;
impl PresenceProbe for UnknownPresence {
    fn state(&self) -> PresenceState {
        PresenceState {
            state: Presence::Away,
            since: kv_platform::presence::unix_seconds(),
            signals: kv_platform::presence::unavailable_signals(),
            extra: Default::default(),
        }
    }
}

struct SelectedKeys<'a> {
    native: &'a dyn KeyFactory,
    software: bool,
}
impl KeyFactory for SelectedKeys<'_> {
    fn create(
        &self,
        role: kv_platform::device_key::KeyRole,
    ) -> Result<(bootstrap::DeviceKey, Value)> {
        if self.software {
            super::platform_keys::SoftwareKeys.create(role)
        } else {
            self.native.create(role)
        }
    }
    fn load(
        &self,
        role: kv_platform::device_key::KeyRole,
        metadata: Value,
    ) -> Result<bootstrap::DeviceKey> {
        if metadata["mode"] == "software" {
            super::platform_keys::SoftwareKeys.load(role, metadata)
        } else {
            self.native.load(role, metadata)
        }
    }
    fn approval_roles(&self) -> &[kv_platform::device_key::KeyRole] {
        if self.software {
            &[]
        } else {
            self.native.approval_roles()
        }
    }
}

pub struct Startup {
    pub directory: PathBuf,
    pub keys: Arc<dyn KeyFactory>,
    pub os: Os,
    pub owner_uid: u32,
    serial: Mutex<()>,
    pair_serial: tokio::sync::Mutex<()>,
    metadata: Mutex<Option<Arc<kv_vault::Vault>>>,
}

impl Startup {
    fn open_registered(
        &self,
        registration: &super::pairing_relay::Registration,
    ) -> Result<(
        bootstrap::Backend,
        Option<kv_core::remote::relay::RegisterDeviceResponse>,
    )> {
        self.open_enrolled(registration, &registration.relay, false)
    }

    fn open_enrolled(
        &self,
        registrar: &dyn bootstrap::Registrar,
        relay: &super::pairing_relay::RelayApi,
        software: bool,
    ) -> Result<(
        bootstrap::Backend,
        Option<kv_core::remote::relay::RegisterDeviceResponse>,
    )> {
        let _serial = self.serial.lock().map_err(|_| Error("state_unavailable"))?;
        if super::server::runtime().is_some() || self.directory.join("vault.enc").exists() {
            return Err(Error("remote_already_initialized"));
        }
        let runner = ProductionRunner::new(Arc::new(SystemProcesses));
        runner.set_owner_ui(self.keys.owner_ui())?;
        let keys = SelectedKeys {
            native: &*self.keys,
            software,
        };
        let master = super::metadata_master::IdentityMaster { keys: &keys };
        let password = Zeroizing::new(super::engine::random_nonce()?);
        let label = self
            .directory
            .parent()
            .and_then(|p| p.file_name())
            .and_then(|p| p.to_str())
            .unwrap_or("KeyValet");
        let (backend, response) = bootstrap::open_registered(
            bootstrap::Options {
                path: &self.directory,
                initialize: Some(("", label, &password, self.os.clone())),
                config: read_config()?,
            },
            bootstrap::Environment {
                master: &master,
                factory: &keys,
                runner: runner.clone(),
                presence: Arc::new(UnknownPresence),
                clock: Arc::new(SystemClock),
            },
            registrar,
        )?;
        backend.helper.lock()?.store.set_setting(
            "relay_url",
            &relay.url.as_str().trim_end_matches('/'),
            "local",
            kv_platform::presence::unix_seconds(),
        )?;
        let authority = Arc::new(
            kv_proxy::certificates::CertificateAuthority::open(&backend.metadata)
                .map_err(|_| Error("proxy_certificate_unavailable"))?,
        );
        super::server::install_production_runtime(backend.helper.clone(), runner, authority)?;
        *self
            .metadata
            .lock()
            .map_err(|_| Error("state_unavailable"))? = Some(backend.metadata.clone());
        Ok((backend, response))
    }
    pub fn new(directory: PathBuf, keys: Arc<dyn KeyFactory>, os: Os, owner_uid: u32) -> Arc<Self> {
        Arc::new(Self {
            directory,
            keys,
            os,
            owner_uid,
            serial: Mutex::new(()),
            pair_serial: tokio::sync::Mutex::new(()),
            metadata: Mutex::new(None),
        })
    }
    fn open(&self, initialize: Option<(&str, &str, &str, bool)>) -> Result<()> {
        let _serial = self.serial.lock().map_err(|_| Error("state_unavailable"))?;
        if super::server::runtime().is_some() {
            return Err(Error("remote_already_initialized"));
        }
        let keys = SelectedKeys {
            native: &*self.keys,
            software: initialize.is_some_and(|(_, _, _, software)| software),
        };
        let config = read_config()?;
        let runner = ProductionRunner::new(Arc::new(SystemProcesses));
        runner.set_owner_ui(self.keys.owner_ui())?;
        let master = super::metadata_master::IdentityMaster { keys: &keys };
        let backend = bootstrap::open(
            bootstrap::Options {
                path: &self.directory,
                initialize: initialize.map(|(account, label, password, _)| {
                    (account, label, password, self.os.clone())
                }),
                config,
            },
            bootstrap::Environment {
                master: &master,
                factory: &keys,
                runner: runner.clone(),
                presence: Arc::new(UnknownPresence),
                clock: Arc::new(SystemClock),
            },
        )?;
        let authority = Arc::new(
            kv_proxy::certificates::CertificateAuthority::open(&backend.metadata)
                .map_err(|_| Error("proxy_certificate_unavailable"))?,
        );
        super::server::install_production_runtime(backend.helper, runner, authority)?;
        *self
            .metadata
            .lock()
            .map_err(|_| Error("state_unavailable"))? = Some(backend.metadata);
        Ok(())
    }
    pub async fn load_existing(self: &Arc<Self>) -> Result<()> {
        if !self.directory.join("vault.enc").exists() || super::server::runtime().is_some() {
            return Ok(());
        }
        let startup = self.clone();
        tokio::task::spawn_blocking(move || startup.open(None))
            .await
            .map_err(|_| Error("remote_metadata_unavailable"))?
    }
}

pub fn install(startup: Arc<Startup>) -> Result<()> {
    STARTUP
        .set(startup)
        .map_err(|_| Error("remote_already_initialized"))
}

pub fn current() -> Option<Arc<Startup>> {
    STARTUP.get().cloned()
}

/// An existing unused device can register or join with its original DK and approval keys.
pub(crate) async fn pair_existing(
    helper: Arc<super::RemoteHelper>,
    context: super::ipc::CallerContext,
    op: kv_ipc::remote::Op,
    value: Value,
) -> Result<Value> {
    use kv_core::remote::relay::*;
    let startup = current().ok_or(Error("remote_unavailable"))?;
    if context.role() != kv_ipc::remote::Caller::CliOwner || context.uid() != startup.owner_uid {
        return Err(Error("forbidden"));
    }
    let _serial = startup.pair_serial.lock().await;
    if !super::server::runtime().is_some_and(|current| Arc::ptr_eq(&current, &helper)) {
        return Err(Error("remote_identity_changed"));
    }
    let (relay, token) = if op == kv_ipc::remote::Op::PairComplete {
        let intent: kv_ipc::remote::PairJoinIntent = serde_json::from_value(value)?;
        let (relay, token) = super::pairing_relay::parse_uri(&intent.uri)?;
        (relay, Some(token))
    } else {
        (
            super::pairing_relay::RelayApi::new(
                value["relay_url"]
                    .as_str()
                    .ok_or(Error("invalid_relay_url"))?,
            )?,
            None,
        )
    };
    let mut frozen = false;
    if token.is_some() {
        bootstrap::freeze_unpaired(&helper)?;
        frozen = true;
    }
    let registration = async {
        let session = match relay
            .authenticate(&helper.local, helper.services.identity.clone())
            .await
        {
            Ok(session) => Some(session),
            Err(error) if matches!(error.code(), "unauthorized" | "unknown_token") => None,
            Err(error) => return Err(error),
        };
        if let Some(token) = &token {
            let joined: PairCompleteResponse = relay
                .post(
                    "v1/pair/complete",
                    &PairCompleteRequest {
                        token: kv_core::remote::keys::encode_b64(token),
                        joiner: helper.local.clone(),
                        extra: Default::default(),
                    },
                    session.as_deref().map(String::as_str),
                )
                .await?;
            let account = joined
                .account_id
                .as_value()
                .cloned()
                .ok_or(Error("invalid_remote_response"))?;
            Ok((account, None, Some(joined)))
        } else if session.is_some() {
            Ok((relay.account(&helper.local.device_id).await?, None, None))
        } else {
            bootstrap::freeze_unpaired(&helper)?;
            frozen = true;
            let registered: RegisterDeviceResponse = relay
                .post(
                    "v1/devices",
                    &RegisterDeviceRequest {
                        device: helper.local.clone(),
                        push_token: Optional::Missing,
                    },
                    None,
                )
                .await?;
            if registered.device_id != helper.local.device_id {
                return Err(Error("invalid_remote_response"));
            }
            Ok((
                registered.account_id,
                registered.recovery_code.as_value().cloned(),
                None,
            ))
        }
    }
    .await;
    let (account, recovery, joined) = match registration {
        Ok(value) => value,
        Err(error) => {
            if frozen {
                bootstrap::resume_unpaired(&helper);
            }
            return Err(error);
        }
    };
    let next = if frozen || account != helper.account {
        if !frozen {
            bootstrap::freeze_unpaired(&helper)?;
        }
        let vault = startup
            .metadata
            .lock()
            .map_err(|_| Error("state_unavailable"))?
            .clone()
            .ok_or(Error("remote_metadata_unavailable"))?;
        let original = helper.clone();
        let path = startup.directory.clone();
        let next = tokio::task::spawn_blocking(move || {
            bootstrap::rebind_backend(&original, vault, &path, &account)
        })
        .await
        .map_err(|_| Error("remote_metadata_unavailable"))??;
        super::server::replace_helper(&helper, next.clone())?;
        next
    } else {
        helper
    };
    next.lock()?.store.set_setting(
        "relay_url",
        &relay.url.as_str().trim_end_matches('/'),
        "local",
        next.services.clock.now(),
    )?;
    let pairing = if let (Some(token), Some(joined)) = (token, joined) {
        next.join_network(relay.clone(), token, joined).await
    } else {
        next.pair_start_with_relay(relay.clone()).await
    };
    let mut result = match pairing {
        Ok(result) => result,
        Err(error) => kv_ipc::remote::PairSasResult {
            sas: String::new(),
            extra: json!({"pair_error":error.code()})
                .as_object()
                .unwrap()
                .clone(),
        },
    };
    result.extra.insert(
        "binding".into(),
        json!({"relay_url":relay.url.as_str().trim_end_matches('/'),
        "device_id":next.local.device_id,"account_id":next.account}),
    );
    if let Some(code) = recovery {
        result.extra.insert("recovery_code".into(), json!(code));
    }
    Ok(serde_json::to_value(result)?)
}

/// Fresh pairing initializes an anonymous identity without a caller-invented account id.
pub async fn initialize_pair(
    context: super::ipc::CallerContext,
    op: kv_ipc::remote::Op,
    value: Value,
) -> Result<Value> {
    let startup = current().ok_or(Error("remote_unavailable"))?;
    if context.role() != kv_ipc::remote::Caller::CliOwner || context.uid() != startup.owner_uid {
        return Err(Error("forbidden"));
    }
    let (relay, join_token) = if op == kv_ipc::remote::Op::PairComplete {
        let intent: kv_ipc::remote::PairJoinIntent = serde_json::from_value(value)?;
        let (relay, token) = super::pairing_relay::parse_uri(&intent.uri)?;
        (relay, Some(token))
    } else {
        let url = value["relay_url"]
            .as_str()
            .ok_or(Error("invalid_relay_url"))?;
        (super::pairing_relay::RelayApi::new(url)?, None)
    };
    let registration = Arc::new(super::pairing_relay::Registration {
        relay: relay.clone(),
        join_token,
        joined: Mutex::new(None),
        runtime: tokio::runtime::Handle::current(),
    });
    let initializing = registration.clone();
    let creating = startup.clone();
    let initialized = tokio::task::spawn_blocking(move || creating.open_registered(&initializing))
        .await
        .map_err(|_| Error("remote_metadata_unavailable"))?;
    let (backend, registered) = match initialized {
        Ok(backend) => backend,
        Err(error) => {
            // Registration failure leaves reusable encrypted providers, never substitute keys.
            let _ = startup.load_existing().await;
            return Err(error);
        }
    };
    let pairing = async {
        if op == kv_ipc::remote::Op::PairComplete {
            let response = registration
                .joined
                .lock()
                .map_err(|_| Error("state_unavailable"))?
                .take()
                .ok_or(Error("invalid_remote_response"))?;
            backend
                .helper
                .join_network(
                    relay.clone(),
                    registration
                        .join_token
                        .as_ref()
                        .ok_or(Error("unknown_token"))?
                        .clone(),
                    response,
                )
                .await
        } else {
            backend.helper.pair_start_with_relay(relay.clone()).await
        }
    }
    .await;
    let mut result = match pairing {
        Ok(result) => result,
        Err(error) => kv_ipc::remote::PairSasResult {
            sas: String::new(),
            extra: json!({"pair_error":error.code()})
                .as_object()
                .unwrap()
                .clone(),
        },
    };
    result.extra.insert(
        "binding".into(),
        json!({"relay_url":relay.url.as_str().trim_end_matches('/'),
        "device_id":backend.helper.local.device_id,"account_id":backend.helper.account}),
    );
    if let Some(response) = registered {
        if let Optional::Value(code) = response.recovery_code {
            result.extra.insert("recovery_code".into(), json!(code));
        }
    }
    Ok(serde_json::to_value(result)?)
}

/// Recovery is accepted only from the installed owner CLI; a new DK proves the replacement.
pub(crate) async fn recover(
    context: super::ipc::CallerContext,
    helper: Option<Arc<super::RemoteHelper>>,
    params: Value,
) -> Result<Value> {
    let startup = current().ok_or(Error("remote_unavailable"))?;
    if context.role() != kv_ipc::remote::Caller::CliOwner || context.uid() != startup.owner_uid {
        return Err(Error("forbidden"));
    }
    let params = kv_vault::SecretJson(params);
    let intent: kv_ipc::remote::AccountRecoverIntent = serde_json::from_value(params.clone())?;
    let software = intent.software;
    let recovery = Arc::new(super::recovery::Recovery::new(intent)?);
    let _pairing = startup.pair_serial.lock().await;
    let (next, registered) = if let Some(helper) = helper {
        let vault = startup
            .metadata
            .lock()
            .map_err(|_| Error("state_unavailable"))?
            .clone()
            .ok_or(Error("remote_metadata_unavailable"))?;
        let prepared = kv_vault::SecretJson(
            vault
                .authenticated_metadata("remote_recovery_prepared")
                .map_err(|_| Error("remote_metadata_unavailable"))?
                .unwrap_or(Value::Null),
        );
        let resume =
            helper.account == recovery.account && prepared["account_id"] == recovery.account;
        if !resume && !helper.account.starts_with("unregistered:") {
            return Err(Error("remote_already_initialized"));
        }
        if !resume {
            bootstrap::freeze_unpaired(&helper)?;
        }
        let enrolling = recovery.clone();
        let original = helper.clone();
        let path = startup.directory.clone();
        let result = tokio::task::spawn_blocking(move || {
            let registered =
                enrolling.enroll(&original.local, original.services.identity.clone(), &vault)?;
            let next = if resume {
                original.clone()
            } else {
                bootstrap::rebind_backend(&original, vault, &path, &registered.account_id)?
            };
            Ok((next, registered))
        })
        .await
        .map_err(|_| Error("remote_metadata_unavailable"))?;
        match result {
            Ok((next, registered)) => {
                if !resume {
                    super::server::replace_helper(&helper, next.clone())?;
                }
                (next, registered)
            }
            Err(error) => {
                if !resume {
                    bootstrap::resume_unpaired(&helper);
                }
                return Err(error);
            }
        }
    } else {
        let opening = startup.clone();
        let enrolling = recovery.clone();
        let result = tokio::task::spawn_blocking(move || {
            let keys = SelectedKeys {
                native: &*opening.keys,
                software,
            };
            let registrar = super::recovery::Enrollment {
                recovery: &enrolling,
                factory: &keys,
            };
            opening.open_enrolled(&registrar, &enrolling.relay, software)
        })
        .await
        .map_err(|_| Error("remote_metadata_unavailable"))?;
        match result {
            Ok((backend, Some(registered))) => (backend.helper, registered),
            Ok(_) => return Err(Error("invalid_remote_response")),
            Err(error) => {
                let _ = startup.load_existing().await;
                return Err(error);
            }
        }
    };
    next.lock()?.store.set_setting(
        "relay_url",
        &recovery.relay.url.as_str().trim_end_matches('/'),
        "local",
        next.services.clock.now(),
    )?;
    let code = registered
        .recovery_code
        .as_value()
        .cloned()
        .ok_or(Error("invalid_remote_response"))?;
    Ok(serde_json::to_value(
        kv_ipc::remote::AccountRecoverResult {
            binding: kv_ipc::remote::RelayBinding {
                relay_url: recovery.relay.url.as_str().trim_end_matches('/').into(),
                device_id: next.local.device_id.clone(),
                account_id: next.account.clone(),
            },
            recovery_code: code,
        },
    )?)
}

/// A signed management CLI may initialize keys only after its owner confirms local setup.
pub async fn initialize(context: super::ipc::CallerContext, params: Value) -> Result<Value> {
    let params = kv_vault::SecretJson(params);
    let result = async {
        let startup = STARTUP.get().cloned().ok_or(Error("remote_unavailable"))?;
        if context.role() != kv_ipc::remote::Caller::CliOwner
            || context.uid() != startup.owner_uid
            || params["confirmed"] != true
        {
            return Err(Error("forbidden"));
        }
        let account = params["account_id"]
            .as_str()
            .ok_or(Error("invalid_bootstrap"))?
            .to_owned();
        let label = params["label"]
            .as_str()
            .ok_or(Error("invalid_bootstrap"))?
            .to_owned();
        let password = Zeroizing::new(
            params["recovery_password"]
                .as_str()
                .ok_or(Error("invalid_bootstrap"))?
                .to_owned(),
        );
        let software = params["software"].as_bool().unwrap_or(false);
        tokio::task::spawn_blocking(move || {
            startup.open(Some((&account, &label, &password, software)))
        })
        .await
        .map_err(|_| Error("remote_metadata_unavailable"))??;
        Ok(json!({"initialized":true}))
    }
    .await;
    result
}

fn read_config() -> Result<ApprovalConfig> {
    #[cfg(unix)]
    let path = std::path::PathBuf::from("/etc/keyvalet/helper.toml");
    #[cfg(windows)]
    let path = std::path::PathBuf::from(kv_platform::paths::VAULT_DIR).join("helper.toml");
    if !path.exists() {
        return Ok(ApprovalConfig::default());
    }
    if kv_platform::trust::untrusted_reason(&path).is_some() {
        return Err(Error("untrusted_approval_config"));
    }
    let text = std::fs::read_to_string(path).map_err(|_| Error("invalid_approval_config"))?;
    if text.len() > 64 * 1024 {
        return Err(Error("invalid_approval_config"));
    }
    ApprovalConfig::from_toml(&text)
}
