//! Explicit production key selection. Hardware errors never choose software keys.

use super::bootstrap::{DeviceKey, KeyFactory};
use super::{Error, Result};
use kv_platform::device_key::KeyRole;
use serde_json::{json, Value};
use std::sync::Arc;

pub struct SoftwareKeys;
impl KeyFactory for SoftwareKeys {
    fn create(&self, role: KeyRole) -> Result<(DeviceKey, Value)> {
        if role != KeyRole::Identity {
            return Err(Error("unsupported_key_role"));
        }
        let (key, bytes) = kv_core::remote::keys::SoftwareDeviceKey::generate_p256_material();
        Ok((
            Arc::new(key),
            json!({"version":1,"role":"identity","mode":"software","scalar":kv_core::remote::keys::encode_b64(bytes.as_ref())}),
        ))
    }
    fn load(&self, role: KeyRole, mut metadata: Value) -> Result<DeviceKey> {
        let result = (|| {
            if role != KeyRole::Identity
                || metadata["version"] != 1
                || metadata["role"] != "identity"
                || metadata["mode"] != "software"
            {
                return Err(Error("invalid_key_metadata"));
            }
            let bytes = zeroize::Zeroizing::new(kv_core::remote::keys::decode_b64(
                metadata["scalar"]
                    .as_str()
                    .ok_or(Error("invalid_key_metadata"))?,
            )?);
            let key = kv_core::remote::keys::SoftwareDeviceKey::from_p256_bytes(&bytes)?;
            Ok(Arc::new(key) as DeviceKey)
        })();
        kv_vault::scrub_json(&mut metadata);
        result
    }
    fn approval_roles(&self) -> &[KeyRole] {
        &[]
    }
}

#[cfg(any(target_os = "macos", windows))]
pub struct AgentKeys {
    pub hub: Arc<kv_platform::agent::AgentHub>,
    pub owner: kv_platform::agent::AgentKey,
}

#[cfg(any(target_os = "macos", windows))]
impl AgentKeys {
    fn transport(&self) -> kv_platform::device_key::agent::AgentTransport {
        #[cfg(target_os = "macos")]
        let owner = self.owner;
        #[cfg(windows)]
        let owner = self.owner.clone();
        kv_platform::device_key::agent::AgentTransport {
            hub: self.hub.clone(),
            owner,
        }
    }
}

#[cfg(any(target_os = "macos", windows))]
impl KeyFactory for AgentKeys {
    fn owner_ui(&self) -> Option<Arc<dyn super::production::OwnerUi>> {
        #[cfg(target_os = "macos")]
        let owner = self.owner;
        #[cfg(windows)]
        let owner = self.owner.clone();
        Some(Arc::new(AgentUi {
            hub: self.hub.clone(),
            owner,
        }))
    }
    fn create(&self, role: KeyRole) -> Result<(DeviceKey, Value)> {
        #[cfg(windows)]
        if matches!(role, KeyRole::Identity | KeyRole::Quick) {
            let key = kv_platform::device_key::windows::PcpDeviceKey::create(role)
                .map_err(|_| Error("key_unavailable"))?;
            let metadata = key.metadata().clone();
            return Ok((Arc::new(key), metadata));
        }
        let key = kv_platform::device_key::agent::AgentDeviceKey::create(self.transport(), role)
            .map_err(|_| Error("key_unavailable"))?;
        let metadata = key.metadata().clone();
        Ok((Arc::new(key), metadata))
    }
    fn load(&self, role: KeyRole, metadata: Value) -> Result<DeviceKey> {
        #[cfg(windows)]
        if matches!(role, KeyRole::Identity | KeyRole::Quick) {
            return Ok(Arc::new(
                kv_platform::device_key::windows::PcpDeviceKey::from_authenticated_metadata(
                    metadata,
                )
                .map_err(|_| Error("key_unavailable"))?,
            ));
        }
        Ok(Arc::new(
            kv_platform::device_key::agent::AgentDeviceKey::from_authenticated_metadata(
                self.transport(),
                role,
                metadata,
            )
            .map_err(|_| Error("key_unavailable"))?,
        ))
    }
    fn approval_roles(&self) -> &[KeyRole] {
        #[cfg(target_os = "macos")]
        {
            &[KeyRole::Quick, KeyRole::Strong]
        }
        #[cfg(windows)]
        {
            &[KeyRole::Quick, KeyRole::Strong]
        }
    }
}

#[cfg(any(target_os = "macos", windows))]
struct AgentUi {
    hub: Arc<kv_platform::agent::AgentHub>,
    owner: kv_platform::agent::AgentKey,
}
#[cfg(any(target_os = "macos", windows))]
impl super::production::OwnerUi for AgentUi {
    fn request(&self, op: &'static str, fields: Value) -> super::production::Task<'_, Value> {
        Box::pin(async move {
            let mut fields = fields.as_object().cloned().ok_or(Error("invalid_json"))?;
            fields.insert("op".into(), json!(op));
            let (reply, payload) = self
                .hub
                .request_dialog(
                    &self.owner,
                    Value::Object(fields),
                    kv_platform::agent::REQUEST_TIMEOUT,
                )
                .await
                .map_err(|_| Error("remote_ui_unavailable"))?;
            if payload.is_some() {
                return Err(Error("invalid_remote_response"));
            }
            Ok(reply)
        })
    }
}

#[cfg(target_os = "linux")]
pub struct TpmKeys {
    pub directory: std::path::PathBuf,
}
#[cfg(target_os = "linux")]
impl KeyFactory for TpmKeys {
    fn create(&self, role: KeyRole) -> Result<(DeviceKey, Value)> {
        if role != KeyRole::Identity {
            return Err(Error("unsupported_key_role"));
        }
        let key = kv_platform::device_key::tpm::TpmDeviceKey::create(
            self.directory.clone(),
            kv_platform::device_key::tpm::TrustedTpm,
        )
        .map_err(|_| Error("key_unavailable"))?;
        let metadata = key.metadata().clone();
        Ok((Arc::new(key), metadata))
    }
    fn load(&self, role: KeyRole, metadata: Value) -> Result<DeviceKey> {
        if role != KeyRole::Identity {
            return Err(Error("unsupported_key_role"));
        }
        Ok(Arc::new(
            kv_platform::device_key::tpm::TpmDeviceKey::from_authenticated_metadata(
                self.directory.clone(),
                kv_platform::device_key::tpm::TrustedTpm,
                metadata,
            )
            .map_err(|_| Error("key_unavailable"))?,
        ))
    }
    fn approval_roles(&self) -> &[KeyRole] {
        &[]
    }
}
