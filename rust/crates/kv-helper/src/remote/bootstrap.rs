//! Production identity bootstrap and the authenticated device-directory mirror.

use super::{ApprovalConfig, Clock, DeviceMirror, Error, RemoteHelper, Result, Services, Store};
use kv_core::remote::keys::DeviceKeyProvider;
use kv_core::remote::{Capability, DeviceRecord, Os};
use kv_platform::device_key::KeyRole;
use kv_vault::{MasterKeyProvider, Vault};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::path::Path;
use std::sync::{Arc, Mutex};

pub type DeviceKey = Arc<dyn DeviceKeyProvider + Send + Sync>;

/// Hardware creation/loading belongs to the real platform runner; CI injects this boundary.
pub trait KeyFactory: Send + Sync {
    fn owner_ui(&self) -> Option<Arc<dyn super::production::OwnerUi>> {
        None
    }
    fn create(&self, role: KeyRole) -> Result<(DeviceKey, Value)>;
    fn load(&self, role: KeyRole, metadata: Value) -> Result<DeviceKey>;
    fn approval_roles(&self) -> &[KeyRole];
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Identity {
    version: u32,
    account: String,
    local: DeviceRecord,
    identity: Value,
    quick: Option<Value>,
    strong: Option<Value>,
}

impl Drop for Identity {
    fn drop(&mut self) {
        kv_vault::scrub_json(&mut self.identity);
        if let Some(value) = &mut self.quick {
            kv_vault::scrub_json(value);
        }
        if let Some(value) = &mut self.strong {
            kv_vault::scrub_json(value);
        }
    }
}

#[derive(Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
struct Directory {
    version: u32,
    revision: u64,
    account: String,
    records: Vec<(DeviceRecord, bool)>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DirectoryJournal {
    id: String,
    old: Directory,
    next: Directory,
}

pub struct VaultMirror {
    vault: Arc<Vault>,
    directory: Mutex<Directory>,
}

impl DeviceMirror for VaultMirror {
    fn prepare(&self, account: &str, records: &[(DeviceRecord, bool)], id: &str) -> Result<bool> {
        let current = self
            .directory
            .lock()
            .map_err(|_| Error("state_unavailable"))?;
        if current.account != account || !retains_tombstones(&current.records, records) {
            return Err(Error("device_directory_mismatch"));
        }
        if current.records == records {
            return Ok(false);
        }
        let old = self
            .vault
            .authenticated_metadata("remote_directory_update")
            .map_err(|_| Error("remote_metadata_unavailable"))?;
        if old.as_ref().is_some_and(|value| !value.is_null()) {
            return Err(Error("directory_update_pending"));
        }
        let next = Directory {
            revision: current
                .revision
                .checked_add(1)
                .ok_or(Error("state_unavailable"))?,
            records: records.to_vec(),
            ..current.clone()
        };
        self.vault
            .replace_authenticated_metadata(
                "remote_directory_update",
                old.as_ref(),
                serde_json::to_value(DirectoryJournal {
                    id: id.into(),
                    old: current.clone(),
                    next,
                })?,
            )
            .map_err(|_| Error("remote_metadata_unavailable"))?;
        Ok(true)
    }

    fn commit(&self, id: &str) -> Result<()> {
        let mut current = self
            .directory
            .lock()
            .map_err(|_| Error("state_unavailable"))?;
        if let Some(journal) = read_directory_journal(&self.vault)? {
            if journal.id != id {
                return Err(Error("device_directory_mismatch"));
            }
            publish_directory(&self.vault, &journal)?;
            *current = journal.next;
        }
        Ok(())
    }

    fn abort(&self, id: &str) -> Result<()> {
        if let Some(journal) = read_directory_journal(&self.vault)? {
            if journal.id != id {
                return Err(Error("device_directory_mismatch"));
            }
            clear_directory_journal(&self.vault, &journal)?;
        }
        Ok(())
    }
    fn replace(&self, account: &str, records: &[(DeviceRecord, bool)]) -> Result<()> {
        let mut current = self
            .directory
            .lock()
            .map_err(|_| Error("state_unavailable"))?;
        if current.account != account || !retains_tombstones(&current.records, records) {
            return Err(Error("device_directory_mismatch"));
        }
        let next = Directory {
            revision: current
                .revision
                .checked_add(1)
                .ok_or(Error("state_unavailable"))?,
            records: records.to_vec(),
            ..current.clone()
        };
        let old = serde_json::to_value(&*current)?;
        self.vault
            .replace_authenticated_metadata(
                "remote_directory",
                Some(&old),
                serde_json::to_value(&next)?,
            )
            .map_err(|_| Error("device_directory_mismatch"))?;
        *current = next;
        Ok(())
    }

    fn verify(&self, account: &str, records: &[(DeviceRecord, bool)]) -> Result<()> {
        let stored = self
            .vault
            .authenticated_metadata("remote_directory")
            .map_err(|_| Error("device_directory_mismatch"))?
            .ok_or(Error("device_directory_mismatch"))?;
        let directory: Directory = serde_json::from_value(stored)?;
        let current = self
            .directory
            .lock()
            .map_err(|_| Error("state_unavailable"))?;
        let mut expected = records.to_vec();
        expected.sort_by(|a, b| a.0.device_id.cmp(&b.0.device_id));
        let mut actual = directory.records.clone();
        actual.sort_by(|a, b| a.0.device_id.cmp(&b.0.device_id));
        if directory.version != 1
            || directory.account != account
            || directory.revision != current.revision
            || actual != expected
        {
            return Err(Error("device_directory_mismatch"));
        }
        Ok(())
    }
}

fn retains_tombstones(old: &[(DeviceRecord, bool)], next: &[(DeviceRecord, bool)]) -> bool {
    old.iter().all(|(record, revoked)| {
        next.iter().any(|(candidate, next_revoked)| {
            candidate.device_id == record.device_id
                && super::directory::same_authority(record, candidate)
                && (!revoked || *next_revoked)
        })
    })
}

fn read_directory_journal(vault: &Vault) -> Result<Option<DirectoryJournal>> {
    vault
        .authenticated_metadata("remote_directory_update")
        .map_err(|_| Error("remote_metadata_unavailable"))?
        .filter(|value| !value.is_null())
        .map(serde_json::from_value)
        .transpose()
        .map_err(Into::into)
}

fn clear_directory_journal(vault: &Vault, journal: &DirectoryJournal) -> Result<()> {
    vault
        .replace_authenticated_metadata(
            "remote_directory_update",
            Some(&serde_json::to_value(journal)?),
            Value::Null,
        )
        .map_err(|_| Error("remote_metadata_unavailable"))
}

fn publish_directory(vault: &Vault, journal: &DirectoryJournal) -> Result<()> {
    if journal.next.account != journal.old.account
        || journal.next.revision
            != journal
                .old
                .revision
                .checked_add(1)
                .ok_or(Error("state_unavailable"))?
        || !retains_tombstones(&journal.old.records, &journal.next.records)
    {
        return Err(Error("device_directory_mismatch"));
    }
    let current = vault
        .authenticated_metadata("remote_directory")
        .map_err(|_| Error("remote_metadata_unavailable"))?
        .ok_or(Error("device_directory_mismatch"))?;
    if current != serde_json::to_value(&journal.old)?
        && current != serde_json::to_value(&journal.next)?
    {
        return Err(Error("device_directory_mismatch"));
    }
    vault
        .replace_authenticated_metadata(
            "remote_directory",
            Some(&current),
            serde_json::to_value(&journal.next)?,
        )
        .map_err(|_| Error("remote_metadata_unavailable"))?;
    clear_directory_journal(vault, journal)
}

fn recover_directory(vault: &Vault, store: &Store) -> Result<()> {
    if let Some(journal) = read_directory_journal(vault)? {
        let committed: bool = store.db.query_row(
            "SELECT EXISTS(SELECT 1 FROM directory_commits WHERE id=?1)",
            [&journal.id],
            |row| row.get(0),
        )?;
        if committed {
            publish_directory(vault, &journal)?;
        } else {
            clear_directory_journal(vault, &journal)?;
        }
    }
    Ok(())
}

pub(crate) fn verify_revoked_archive(
    vault: Arc<Vault>,
    store: &Store,
) -> Result<(DeviceRecord, String)> {
    let identity: Identity = serde_json::from_value(
        vault
            .authenticated_metadata("remote_identity")
            .map_err(|_| Error("remote_metadata_unavailable"))?
            .ok_or(Error("remote_identity_missing"))?,
    )?;
    let directory: Directory = serde_json::from_value(
        vault
            .authenticated_metadata("remote_directory")
            .map_err(|_| Error("remote_metadata_unavailable"))?
            .ok_or(Error("device_directory_mismatch"))?,
    )?;
    if identity.version != 1
        || directory.version != 1
        || identity.account != directory.account
        || !directory.records.iter().any(|(record, revoked)| {
            *revoked && super::directory::same_authority(&identity.local, record)
        })
        || read_directory_journal(&vault)?.is_some()
    {
        return Err(Error("rejoin_requires_revoked_device"));
    }
    store.verify_audit()?;
    super::AuditSink::verify_checkpoint(vault.as_ref(), &store.audit_head()?)?;
    super::AuditSink::verify_records(vault.as_ref(), &store.audit_records()?)?;
    let mirror = VaultMirror {
        vault,
        directory: Mutex::new(directory),
    };
    mirror.verify(&identity.account, &super::engine::directory(store)?)?;
    Ok((identity.local.clone(), identity.account.clone()))
}

pub struct Options<'a> {
    pub path: &'a Path,
    pub initialize: Option<(&'a str, &'a str, &'a str, Os)>,
    pub config: ApprovalConfig,
}

pub struct Environment<'a> {
    pub master: &'a dyn MasterKeyProvider,
    pub factory: &'a dyn KeyFactory,
    pub runner: Arc<dyn super::RequestRunner>,
    pub presence: Arc<dyn kv_core::remote::PresenceProbe + Send + Sync>,
    pub clock: Arc<dyn Clock>,
}

pub struct Backend {
    pub helper: Arc<RemoteHelper>,
    pub metadata: Arc<Vault>,
}

pub trait Registrar: Send + Sync {
    /// Only public records leave the helper; keys are generated before this call.
    fn register(
        &self,
        local: &DeviceRecord,
    ) -> Result<kv_core::remote::relay::RegisterDeviceResponse>;
    fn register_with_identity(
        &self,
        local: &DeviceRecord,
        _identity: &dyn DeviceKeyProvider,
        _metadata: &Vault,
    ) -> Result<kv_core::remote::relay::RegisterDeviceResponse> {
        self.register(local)
    }
}

/// The metadata vault has a separate master key; caching it never caches the credential UMK.
/// Initial creation is explicit. Missing or corrupt identity metadata is never regenerated.
pub fn open(options: Options<'_>, environment: Environment<'_>) -> Result<Backend> {
    open_inner(options, environment, None, false).map(|(backend, _)| backend)
}

/// A tombstoned identity may expose owner status/audit and prepare a fresh pairing.
/// IPC restricts this backend to those maintenance operations; authority is not restored.
pub(crate) fn open_for_management(
    options: Options<'_>,
    environment: Environment<'_>,
) -> Result<Backend> {
    if options.initialize.is_some() {
        return Err(Error("invalid_bootstrap"));
    }
    open_inner(options, environment, None, true).map(|(backend, _)| backend)
}

pub fn open_registered(
    options: Options<'_>,
    environment: Environment<'_>,
    registrar: &dyn Registrar,
) -> Result<(
    Backend,
    Option<kv_core::remote::relay::RegisterDeviceResponse>,
)> {
    open_inner(options, environment, Some(registrar), false)
}

fn open_inner(
    options: Options<'_>,
    environment: Environment<'_>,
    registrar: Option<&dyn Registrar>,
    management: bool,
) -> Result<(
    Backend,
    Option<kv_core::remote::relay::RegisterDeviceResponse>,
)> {
    let Options {
        path,
        initialize,
        config,
    } = options;
    let Environment {
        master,
        factory,
        runner,
        presence,
        clock,
    } = environment;
    let vault = Arc::new(Vault::new(path));
    vault
        .prepare()
        .map_err(|_| Error("remote_metadata_unavailable"))?;
    let mut registration = None;
    if let Some((account, label, recovery_password, os)) = initialize {
        if (account.is_empty() && registrar.is_none())
            || account.len() > 300
            || label.is_empty()
            || label.len() > 100
            || account.chars().chain(label.chars()).any(char::is_control)
        {
            return Err(Error("invalid_bootstrap"));
        }
        vault
            .initialize_enclave(
                master,
                recovery_password,
                "Initialize remote approval identity",
            )
            .map_err(|_| Error("remote_metadata_unavailable"))?;
        vault
            .init_with_provider(master, "Load remote approval identity")
            .map_err(|_| Error("remote_metadata_unavailable"))?;
        let (identity_key, identity_blob) = factory.create(KeyRole::Identity)?;
        let mut local = DeviceRecord {
            device_id: super::engine::new_id(clock.now())?,
            label: label.into(),
            os,
            key_kind: identity_key.key_kind(),
            dk_pub: identity_key.public_jwk()?,
            dk_sig: identity_key.identity_sign_jwk()?.map_or(
                kv_core::remote::Optional::Missing,
                |public| {
                    kv_core::remote::Optional::Value(kv_core::remote::ApprovalKey {
                        r#pub: public,
                        alg: kv_core::remote::SignatureAlgorithm::ES256,
                        extra: Default::default(),
                    })
                },
            ),
            ak_q: None,
            ak_s: None,
            caps: vec![Capability::Execute],
            attestation: None,
            extra: Default::default(),
        };
        let mut quick = None;
        let mut strong = None;
        for role in factory.approval_roles() {
            let (key, blob) = factory.create(*role)?;
            let public = key.public_jwk()?;
            let approval = kv_core::remote::ApprovalKey {
                alg: if public.kty == "RSA" {
                    kv_core::remote::SignatureAlgorithm::RS256
                } else {
                    kv_core::remote::SignatureAlgorithm::ES256
                },
                r#pub: public,
                extra: Default::default(),
            };
            match role {
                KeyRole::Quick => {
                    local.ak_q = Some(approval);
                    local.caps.push(Capability::ApproveQuick);
                    quick = Some(blob);
                }
                KeyRole::Strong => {
                    local.ak_s = Some(approval);
                    local.caps.push(Capability::ApproveStrong);
                    strong = Some(blob);
                }
                KeyRole::Identity => return Err(Error("invalid_bootstrap")),
            }
        }
        super::engine::validate_device(&local)?;
        // Persist the generated providers before network I/O. A failed registration can
        // retry with the same keys; this local placeholder never leaves the helper.
        let account = if account.is_empty() {
            format!("unregistered:{}", local.device_id)
        } else {
            account.to_owned()
        };
        let identity = Identity {
            version: 1,
            account: account.clone(),
            local: local.clone(),
            identity: identity_blob,
            quick,
            strong,
        };
        vault
            .replace_authenticated_metadata(
                "remote_identity",
                None,
                serde_json::to_value(identity)?,
            )
            .map_err(|_| Error("remote_metadata_unavailable"))?;
        let directory = Directory {
            version: 1,
            revision: 0,
            account,
            records: vec![(local.clone(), false)],
        };
        vault
            .replace_authenticated_metadata(
                "remote_directory",
                None,
                serde_json::to_value(directory)?,
            )
            .map_err(|_| Error("remote_metadata_unavailable"))?;
        if let Some(registrar) = registrar {
            let registered =
                registrar.register_with_identity(&local, identity_key.as_ref(), &vault)?;
            if registered.device_id != local.device_id {
                return Err(Error("invalid_remote_response"));
            }
            rebind_account(&vault, &registered.account_id, &local)?;
            registration = Some(registered);
        }
    } else {
        vault
            .init_with_provider(master, "Load remote approval identity")
            .map_err(|_| Error("remote_metadata_unavailable"))?;
    }
    complete_account_rebinding(&vault)?;
    let state_path = path.join("approvals.sqlite3");
    let fresh = !state_path.exists();
    let store = Store::open(&state_path)?;
    recover_directory(&vault, &store)?;
    let mut identity: Identity = serde_json::from_value(
        vault
            .authenticated_metadata("remote_identity")
            .map_err(|_| Error("remote_metadata_unavailable"))?
            .ok_or(Error("remote_identity_missing"))?,
    )?;
    let directory: Directory = serde_json::from_value(
        vault
            .authenticated_metadata("remote_directory")
            .map_err(|_| Error("remote_metadata_unavailable"))?
            .ok_or(Error("device_directory_mismatch"))?,
    )?;
    if identity.version != 1
        || directory.version != 1
        || identity.account != directory.account
        || !directory.records.iter().any(|(record, revoked)| {
            (management || !revoked) && super::directory::same_authority(&identity.local, record)
        })
    {
        return Err(Error("device_directory_mismatch"));
    }
    identity.local.label.clone_from(
        &directory
            .records
            .iter()
            .find(|(record, _)| record.device_id == identity.local.device_id)
            .ok_or(Error("device_directory_mismatch"))?
            .0
            .label,
    );
    let identity_key = factory.load(KeyRole::Identity, identity.identity.clone())?;
    let quick = identity
        .quick
        .as_ref()
        .cloned()
        .map(|blob| factory.load(KeyRole::Quick, blob))
        .transpose()?;
    let strong = identity
        .strong
        .as_ref()
        .cloned()
        .map(|blob| factory.load(KeyRole::Strong, blob))
        .transpose()?;
    let records = directory.records.clone();
    let mirror = Arc::new(VaultMirror {
        vault: vault.clone(),
        directory: Mutex::new(directory),
    });
    if fresh {
        store.restore_verified_directory(&identity.account, &records, &*mirror, clock.now())?;
    }
    if let Some(journal) = vault
        .authenticated_metadata("remote_account_rebinding")
        .map_err(|_| Error("remote_metadata_unavailable"))?
        .filter(|value| value.is_object())
    {
        let from = journal["from"]
            .as_str()
            .ok_or(Error("device_directory_mismatch"))?;
        let count: u64 = store
            .db
            .query_row("SELECT COUNT(*) FROM devices", [], |row| row.get(0))?;
        if count != 1 {
            return Err(Error("device_directory_mismatch"));
        }
        let changed = store.db.execute(
            "UPDATE devices SET account_id=?1 WHERE id=?2 AND account_id IN (?1,?3)",
            rusqlite::params![identity.account, identity.local.device_id, from],
        )?;
        if changed != 1 {
            return Err(Error("device_directory_mismatch"));
        }
        vault
            .replace_authenticated_metadata("remote_account_rebinding", Some(&journal), Value::Null)
            .map_err(|_| Error("remote_metadata_unavailable"))?;
    }
    let services = Services {
        identity: identity_key,
        quick,
        strong,
        presence,
        mirror,
        audit: vault.clone(),
        runner,
        clock,
    };
    let local_revoked = records.iter().any(|(record, revoked)| {
        *revoked && super::directory::same_authority(&identity.local, record)
    });
    let helper = RemoteHelper::new(
        store,
        identity.local.clone(),
        identity.account.clone(),
        config,
        services,
    )?;
    helper.lock()?.management_only = local_revoked;
    helper.services.audit.append(
        json!({"op":"remote_bootstrap","ok":true})
            .as_object()
            .unwrap()
            .clone(),
    )?;
    Ok((
        Backend {
            helper,
            metadata: vault,
        },
        registration,
    ))
}

/// Changing routing account is allowed only before this identity has trusted another device.
pub(crate) fn rebind_account(vault: &Vault, account: &str, local: &DeviceRecord) -> Result<()> {
    let identity: Identity = serde_json::from_value(
        vault
            .authenticated_metadata("remote_identity")
            .map_err(|_| Error("remote_metadata_unavailable"))?
            .ok_or(Error("remote_metadata_unavailable"))?,
    )?;
    let directory: Directory = serde_json::from_value(
        vault
            .authenticated_metadata("remote_directory")
            .map_err(|_| Error("remote_metadata_unavailable"))?
            .ok_or(Error("remote_metadata_unavailable"))?,
    )?;
    if !super::directory::same_authority(&identity.local, local)
        || directory.records.len() != 1
        || directory.records[0].1
        || !super::directory::same_authority(local, &directory.records[0].0)
        || account.is_empty()
        || account.len() > 256
        || account.chars().any(char::is_control)
    {
        return Err(Error("pairing_requires_unpaired_device"));
    }
    let old = vault
        .authenticated_metadata("remote_account_rebinding")
        .map_err(|_| Error("remote_metadata_unavailable"))?;
    let journal = json!({"from":identity.account,"to":account,"device_id":local.device_id});
    vault
        .replace_authenticated_metadata("remote_account_rebinding", old.as_ref(), journal)
        .map_err(|_| Error("remote_metadata_unavailable"))?;
    complete_account_rebinding(vault)
}

/// Freeze an unused singleton before a relay changes its routing account.
pub(crate) fn freeze_unpaired(helper: &RemoteHelper) -> Result<()> {
    let mut state = helper.lock()?;
    let records = super::engine::directory(&state.store)?;
    if records.len() != 1
        || records[0].1
        || !super::directory::same_authority(&helper.local, &records[0].0)
        || state.pairing.is_some()
        || !state.full.is_empty()
        || !state.results.is_empty()
        || !state.confirmations.is_empty()
        || !state.inbound_requests.is_empty()
    {
        return Err(Error("pairing_requires_unpaired_device"));
    }
    let used: bool = state.store.db.query_row(
        "SELECT EXISTS(SELECT 1 FROM pending_approvals UNION ALL SELECT 1 FROM grants
        UNION ALL SELECT 1 FROM issued_grants UNION ALL SELECT 1 FROM issued_approvals
        UNION ALL SELECT 1 FROM issued_directives UNION ALL SELECT 1 FROM directives
        UNION ALL SELECT 1 FROM nonces UNION ALL SELECT 1 FROM remote_outbox)",
        [],
        |row| row.get(0),
    )?;
    if used {
        return Err(Error("pairing_requires_unpaired_device"));
    }
    state.retired = true;
    Ok(())
}

pub(crate) fn resume_unpaired(helper: &RemoteHelper) {
    if let Ok(mut state) = super::engine::blocking_lock(&helper.state) {
        state.retired = false;
    }
}

/// Reuse the original providers and authenticated metadata; never generate replacement keys.
pub(crate) fn rebind_backend(
    helper: &Arc<RemoteHelper>,
    vault: Arc<Vault>,
    path: &Path,
    account: &str,
) -> Result<Arc<RemoteHelper>> {
    if !super::engine::blocking_lock(&helper.state)
        .map_err(|_| Error("state_unavailable"))?
        .retired
    {
        return Err(Error("pairing_requires_unpaired_device"));
    }
    rebind_account(&vault, account, &helper.local)?;
    let directory: Directory = serde_json::from_value(
        vault
            .authenticated_metadata("remote_directory")
            .map_err(|_| Error("remote_metadata_unavailable"))?
            .ok_or(Error("device_directory_mismatch"))?,
    )?;
    let store = Store::open(&path.join("approvals.sqlite3"))?;
    let changed = store.db.execute(
        "UPDATE devices SET account_id=?1 WHERE id=?2 AND account_id IN (?1,?3)",
        rusqlite::params![account, helper.local.device_id, helper.account],
    )?;
    if changed != 1 {
        return Err(Error("device_directory_mismatch"));
    }
    let journal = vault
        .authenticated_metadata("remote_account_rebinding")
        .map_err(|_| Error("remote_metadata_unavailable"))?
        .ok_or(Error("device_directory_mismatch"))?;
    vault
        .replace_authenticated_metadata("remote_account_rebinding", Some(&journal), Value::Null)
        .map_err(|_| Error("remote_metadata_unavailable"))?;
    let local = store.device(&helper.local.device_id, account)?;
    RemoteHelper::new(
        store,
        local,
        account.into(),
        helper.config.clone(),
        Services {
            identity: helper.services.identity.clone(),
            quick: helper.services.quick.clone(),
            strong: helper.services.strong.clone(),
            presence: helper.services.presence.clone(),
            runner: helper.services.runner.clone(),
            clock: helper.services.clock.clone(),
            audit: vault.clone(),
            mirror: Arc::new(VaultMirror {
                vault,
                directory: Mutex::new(directory),
            }),
        },
    )
}

fn complete_account_rebinding(vault: &Vault) -> Result<()> {
    let Some(journal) = vault
        .authenticated_metadata("remote_account_rebinding")
        .map_err(|_| Error("remote_metadata_unavailable"))?
        .filter(|value| value.is_object())
    else {
        return Ok(());
    };
    let mut identity: Identity = serde_json::from_value(
        vault
            .authenticated_metadata("remote_identity")
            .map_err(|_| Error("remote_metadata_unavailable"))?
            .ok_or(Error("remote_metadata_unavailable"))?,
    )?;
    let mut directory: Directory = serde_json::from_value(
        vault
            .authenticated_metadata("remote_directory")
            .map_err(|_| Error("remote_metadata_unavailable"))?
            .ok_or(Error("remote_metadata_unavailable"))?,
    )?;
    let from = journal["from"]
        .as_str()
        .ok_or(Error("device_directory_mismatch"))?;
    let to = journal["to"]
        .as_str()
        .ok_or(Error("device_directory_mismatch"))?;
    if to.is_empty()
        || to.len() > 256
        || to.chars().any(char::is_control)
        || journal["device_id"] != identity.local.device_id
        || directory.records.len() != 1
        || directory.records[0].1
        || !super::directory::same_authority(&identity.local, &directory.records[0].0)
        || ![from, to].contains(&identity.account.as_str())
        || ![from, to].contains(&directory.account.as_str())
    {
        return Err(Error("device_directory_mismatch"));
    }
    let old = kv_vault::SecretJson(serde_json::to_value(&identity)?);
    identity.account = to.into();
    identity
        .local
        .label
        .clone_from(&directory.records[0].0.label);
    vault
        .replace_authenticated_metadata(
            "remote_identity",
            Some(&old.0),
            serde_json::to_value(&identity)?,
        )
        .map_err(|_| Error("remote_metadata_unavailable"))?;
    let old = serde_json::to_value(&directory)?;
    directory.account = to.into();
    vault
        .replace_authenticated_metadata(
            "remote_directory",
            Some(&old),
            serde_json::to_value(&directory)?,
        )
        .map_err(|_| Error("remote_metadata_unavailable"))?;
    Ok(())
}
