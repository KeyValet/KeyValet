//! Owner-only anonymous account recovery with a durable new DK and encrypted replacement code.
use super::{
    bootstrap::{DeviceKey, Registrar},
    pairing_relay::RelayApi,
    Error, Result,
};
use kv_core::remote::{
    canonical::{jcs, sha256_hex},
    keys::{decode_b64, encode_b64},
    relay::*,
    *,
};
use kv_ipc::remote::AccountRecoverIntent;
use kv_vault::Vault;
use serde_json::json;
use zeroize::Zeroizing;

pub(crate) struct Recovery {
    pub relay: RelayApi,
    pub account: String,
    code: Zeroizing<String>,
    runtime: tokio::runtime::Handle,
}
impl Recovery {
    pub fn new(intent: AccountRecoverIntent) -> Result<Self> {
        if intent.account_id.is_empty()
            || intent.account_id.len() > 256
            || intent.account_id.chars().any(char::is_control)
            || decode_b64(&intent.recovery_code).map_or(true, |code| code.len() != 32)
        {
            return Err(Error("invalid_recovery"));
        }
        Ok(Self {
            relay: RelayApi::new(&intent.relay_url)?,
            account: intent.account_id,
            code: Zeroizing::new(intent.recovery_code),
            runtime: tokio::runtime::Handle::current(),
        })
    }
    pub fn enroll(
        &self,
        local: &DeviceRecord,
        key: DeviceKey,
        vault: &Vault,
    ) -> Result<RegisterDeviceResponse> {
        let mut request = RecoverAccountRequest::signed(
            self.account.clone(),
            self.code.to_string(),
            local.clone(),
            key.as_ref(),
        )?;
        let previous = kv_vault::SecretJson(
            vault
                .authenticated_metadata("remote_recovery_prepared")
                .map_err(|_| Error("remote_metadata_unavailable"))?
                .unwrap_or(serde_json::Value::Null),
        );
        if !previous.is_null() {
            if previous["account_id"] != self.account
                || previous["relay_url"] != self.relay.url.as_str()
                || previous["device_id"] != local.device_id
            {
                return Err(Error("recovery_in_progress"));
            }
            request.new_recovery_code = previous["recovery_code"]
                .as_str()
                .filter(|code| decode_b64(code).is_ok_and(|bytes| bytes.len() == 32))
                .ok_or(Error("remote_metadata_unavailable"))?
                .into();
            request.sig = encode_b64(&key.sign(
                SignatureAlgorithm::ES256,
                &jcs(&RecoverAccountProof {
                    action: RecoverAccountAction::RecoverAccount,
                    account_id: request.account_id.clone(),
                    device: local.clone(),
                    nonce: request.nonce.clone(),
                    new_recovery_code_hash: sha256_hex(request.new_recovery_code.as_bytes()),
                })?,
            )?);
        } else {
            // Persist before HTTP. Losing the response cannot also lose the replacement code.
            let prepared = kv_vault::SecretJson(json!({"account_id":self.account,
                "relay_url":self.relay.url.as_str(),"device_id":local.device_id,
                "recovery_code":request.new_recovery_code}));
            vault
                .replace_authenticated_metadata("remote_recovery_prepared", None, prepared.clone())
                .map_err(|_| Error("remote_metadata_unavailable"))?;
        }
        let code = Zeroizing::new(request.new_recovery_code.clone());
        let request = kv_vault::SecretJson(serde_json::to_value(request)?);
        self.runtime.block_on(async {
            // Resume a committed recovery after an interrupted reply or local publication.
            let authenticated = self.relay.authenticate(local, key.clone()).await;
            if authenticated.is_ok() && self.relay.account(&local.device_id).await? == self.account
            {
                return Ok(RegisterDeviceResponse {
                    account_id: self.account.clone(),
                    device_id: local.device_id.clone(),
                    recovery_code: Optional::Value(code.to_string()),
                    extra: Extra::new(),
                });
            }
            let recovered: std::result::Result<RecoverAccountResponse, Error> =
                self.relay.post("v1/recovery", &*request, None).await;
            // The bound new DK, rather than an untrusted HTTP success body, confirms enrollment.
            self.relay.authenticate(local, key).await?;
            if self.relay.account(&local.device_id).await? != self.account {
                return Err(Error("identity_account_mismatch"));
            }
            if let Ok(response) = recovered {
                if !response.ok
                    || response.account_id != self.account
                    || response.device_id != local.device_id
                    || response.recovery_code != *code
                {
                    return Err(Error("invalid_remote_response"));
                }
            }
            Ok(RegisterDeviceResponse {
                account_id: self.account.clone(),
                device_id: local.device_id.clone(),
                recovery_code: Optional::Value(code.to_string()),
                extra: Extra::new(),
            })
        })
    }
}

pub(crate) struct Enrollment<'a> {
    pub recovery: &'a Recovery,
    pub factory: &'a dyn super::bootstrap::KeyFactory,
}
impl Registrar for Enrollment<'_> {
    fn register(&self, _local: &DeviceRecord) -> Result<RegisterDeviceResponse> {
        Err(Error("forbidden"))
    }
    fn register_with_identity(
        &self,
        local: &DeviceRecord,
        _key: &dyn DeviceKeyProvider,
        vault: &Vault,
    ) -> Result<RegisterDeviceResponse> {
        let metadata = kv_vault::SecretJson(
            vault
                .authenticated_metadata("remote_identity")
                .map_err(|_| Error("remote_metadata_unavailable"))?
                .ok_or(Error("remote_identity_missing"))?,
        );
        let key = self.factory.load(
            kv_platform::device_key::KeyRole::Identity,
            metadata["identity"].clone(),
        )?;
        self.recovery.enroll(local, key, vault)
    }
}
