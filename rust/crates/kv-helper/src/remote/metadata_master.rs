//! A dedicated background metadata key; credential UMKs never use this provider.

use super::bootstrap::KeyFactory;
use kv_core::remote::keys::{metadata_master_key, p256_public_sec1};
use kv_core::remote::{DeviceKeyProvider, SoftwareDeviceKey};
use kv_platform::device_key::KeyRole;
use kv_vault::{EnclaveKey, EnclaveMetadata, MasterKey, MasterKeyProvider, VaultError};

pub struct IdentityMaster<'a> {
    pub keys: &'a dyn KeyFactory,
}

fn unavailable() -> VaultError {
    VaultError::new("设备身份密钥不可用", "Device identity key is unavailable")
}

impl MasterKeyProvider for IdentityMaster<'_> {
    fn create(&self, _: &str) -> kv_vault::Result<EnclaveKey> {
        let (identity, metadata) = self
            .keys
            .create(KeyRole::Identity)
            .map_err(|_| unavailable())?;
        let peer = p256_public_sec1(
            &SoftwareDeviceKey::generate_p256()
                .public_jwk()
                .map_err(|_| unavailable())?,
        )
        .map_err(|_| unavailable())?;
        let key = metadata_master_key(&*identity, &peer).map_err(|_| unavailable())?;
        Ok(EnclaveKey {
            key,
            metadata: EnclaveMetadata::device_identity(&metadata, &peer)?,
        })
    }
    fn unlock(&self, metadata: &EnclaveMetadata, _: &str) -> kv_vault::Result<MasterKey> {
        if metadata.version != 5 {
            return Err(unavailable());
        }
        let (mut blob, peer) = metadata.decode()?;
        let stored = serde_json::from_slice(&blob).map_err(|_| unavailable());
        use zeroize::Zeroize;
        blob.zeroize();
        let identity = self
            .keys
            .load(KeyRole::Identity, stored?)
            .map_err(|_| unavailable())?;
        metadata_master_key(&*identity, &peer).map_err(|_| unavailable())
    }
}
