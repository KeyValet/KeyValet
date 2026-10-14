//! A revoked device rejoins with a fresh identity; its authenticated ledger is retained.
use super::bootstrap::{self, Backend, Environment, Options};
use super::engine::State;
use super::{Error, RemoteHelper, Result, Store};
use kv_core::remote::{audit::AuditHead, DeviceRecord, QueryAuditArgs};
use kv_vault::Vault;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use zeroize::Zeroizing;

const METADATA: &str = "remote_generations";
const MAX_GENERATIONS: usize = 16;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Archived {
    generation: Option<String>,
    device: DeviceRecord,
    head: AuditHead,
    proof: Value,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Generations {
    version: u32,
    account: String,
    active: String,
    archives: Vec<Archived>,
}

pub(crate) struct Archive {
    device: String,
    account: String,
    head: AuditHead,
    store: Store,
    metadata: Arc<Vault>,
    proof: Value,
}

fn generation_path(root: &Path, generation: &str) -> Result<PathBuf> {
    // 128 bits in canonical uppercase Crockford base32, matching new_id().
    // The leading digit cannot overflow the ULID's 128-bit representation.
    const ALPHABET: &[u8] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
    if generation.len() != 26
        || generation.as_bytes()[0] > b'7'
        || !generation.bytes().all(|byte| ALPHABET.contains(&byte))
    {
        return Err(Error("invalid_remote_generation"));
    }
    let parent = root.join("generations");
    let path = parent.join(generation);
    for directory in [&parent, &path] {
        match std::fs::symlink_metadata(directory) {
            Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => (),
            Ok(_) => return Err(Error("invalid_remote_generation")),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => (),
            Err(_) => return Err(Error("remote_metadata_unavailable")),
        }
    }
    Ok(path)
}

fn catalog(root: &Path, anchor: &Vault) -> Result<Option<Generations>> {
    let Some(value) = anchor
        .authenticated_metadata(METADATA)
        .map_err(|_| Error("remote_metadata_unavailable"))?
    else {
        return Ok(None);
    };
    let state: Generations = serde_json::from_value(value)?;
    let identity = kv_vault::SecretJson(
        anchor
            .authenticated_metadata("remote_identity")
            .map_err(|_| Error("remote_metadata_unavailable"))?
            .ok_or(Error("remote_identity_missing"))?,
    );
    let mut devices = std::collections::HashSet::new();
    let mut paths = std::collections::HashSet::new();
    if state.version != 1
        || state.account.is_empty()
        || identity["account"] != state.account
        || state.archives.is_empty()
        || state.archives.len() > MAX_GENERATIONS
    {
        return Err(Error("invalid_remote_generation"));
    }
    generation_path(root, &state.active)?;
    for entry in &state.archives {
        if !devices.insert(&entry.device.device_id)
            || !paths.insert(&entry.generation)
            || entry.generation.as_deref() == Some(&state.active)
        {
            return Err(Error("invalid_remote_generation"));
        }
        if let Some(generation) = &entry.generation {
            generation_path(root, generation)?;
        }
    }
    if state.archives[0].generation.is_some()
        || identity["local"]["device_id"] != state.archives[0].device.device_id
    {
        return Err(Error("invalid_remote_generation"));
    }
    Ok(Some(state))
}

pub(crate) fn active_path(root: &Path, anchor: &Vault) -> Result<PathBuf> {
    match catalog(root, anchor)? {
        Some(state) => {
            let path = generation_path(root, &state.active)?;
            if !path.join("vault.enc").is_file() {
                return Err(Error("remote_identity_missing"));
            }
            Ok(path)
        }
        None => Ok(root.to_owned()),
    }
}

pub(crate) fn account(root: &Path, anchor: &Vault) -> Result<Option<String>> {
    Ok(catalog(root, anchor)?.map(|state| state.account))
}

pub(crate) fn attach(
    root: &Path,
    anchor: Arc<Vault>,
    helper: &RemoteHelper,
    master: &dyn kv_vault::MasterKeyProvider,
) -> Result<()> {
    let Some(catalog) = catalog(root, &anchor)? else {
        return Ok(());
    };
    if catalog.account != helper.account {
        return Err(Error("account_mismatch"));
    }
    let mut archives = Vec::new();
    let successors = catalog
        .archives
        .iter()
        .skip(1)
        .map(|entry| entry.device.clone())
        .chain(std::iter::once(helper.local.clone()))
        .collect::<Vec<_>>();
    for (entry, successor) in catalog.archives.into_iter().zip(successors) {
        let path = entry
            .generation
            .as_deref()
            .map(|id| generation_path(root, id))
            .transpose()?
            .unwrap_or_else(|| root.to_owned());
        let metadata = if entry.generation.is_none() {
            anchor.clone()
        } else {
            let vault = Arc::new(Vault::new(&path));
            vault
                .init_with_provider(master, "Verify archived remote ledger")
                .map_err(|_| Error("remote_metadata_unavailable"))?;
            vault
        };
        let store = Store::open(&path.join("approvals.sqlite3"))?;
        let (device, account) = bootstrap::verify_revoked_archive(metadata.clone(), &store)?;
        if !super::directory::same_authority(&device, &entry.device)
            || account != helper.account
            || store.audit_head()? != entry.head
        {
            return Err(Error("archived_audit_mismatch"));
        }
        let mut proof = entry.proof.clone();
        let signature = proof
            .as_object_mut()
            .and_then(|object| object.remove("sig"))
            .and_then(|value| value.as_str().map(str::to_owned))
            .ok_or(Error("archived_audit_mismatch"))?;
        let predecessor: DeviceRecord = serde_json::from_value(proof["predecessor"].clone())?;
        let signed_successor: DeviceRecord = serde_json::from_value(proof["successor"].clone())?;
        if proof["domain"] != "keyvalet.audit-archive.v1"
            || proof["account"] != account
            || !super::directory::same_authority(&predecessor, &device)
            || !super::directory::same_authority(&signed_successor, &successor)
            || proof["head"] != json!(entry.head)
        {
            return Err(Error("archived_audit_mismatch"));
        }
        kv_core::remote::keys::verify_identity_signature(
            &device,
            &kv_core::remote::canonical::jcs(&proof)?,
            &kv_core::remote::keys::decode_b64(&signature)?,
        )?;
        archives.push(Archive {
            device: device.device_id,
            account,
            head: entry.head,
            store,
            metadata,
            proof: entry.proof,
        });
    }
    helper.lock()?.archives = archives;
    Ok(())
}

pub(crate) fn create(
    root: &Path,
    anchor: &Vault,
    current: &RemoteHelper,
    environment: Environment<'_>,
) -> Result<Backend> {
    let mut state = current.lock()?;
    let records = super::engine::directory(&state.store)?;
    current.services.mirror.verify(&current.account, &records)?;
    if !records.iter().any(|(device, revoked)| {
        *revoked && super::directory::same_authority(device, &current.local)
    }) {
        return Err(Error("rejoin_requires_revoked_device"));
    }
    state.store.verify_audit()?;
    current
        .services
        .audit
        .verify_checkpoint(&state.store.audit_head()?)?;
    current
        .services
        .audit
        .verify_records(&state.store.audit_records()?)?;
    if !state.executing.is_empty() {
        return Err(Error("rejoin_execution_in_progress"));
    }
    let previous = catalog(root, anchor)?;
    if previous.as_ref().is_some_and(|catalog| {
        catalog.account != current.account || catalog.archives.len() >= MAX_GENERATIONS
    }) {
        return Err(Error("invalid_remote_generation"));
    }
    let generation = super::engine::new_id(environment.clock.now())?;
    let path = generation_path(root, &generation)?;
    Vault::new(root.join("generations"))
        .prepare()
        .map_err(|_| Error("remote_metadata_unavailable"))?;
    let password = Zeroizing::new(super::engine::random_nonce()?);
    let backend = bootstrap::open(
        Options {
            path: &path,
            initialize: Some((
                &current.account,
                &current.local.label,
                &password,
                current.local.os.clone(),
            )),
            config: current.config.clone(),
        },
        environment,
    )?;
    backend.helper.lock()?.store.set_setting(
        "mode",
        &"per_use",
        "local",
        backend.helper.services.clock.now(),
    )?;
    let mut archives = previous
        .as_ref()
        .map(|catalog| catalog.archives.clone())
        .unwrap_or_default();
    let head = state.store.audit_head()?;
    let mut proof = json!({"domain":"keyvalet.audit-archive.v1","account":current.account,
        "predecessor":current.local,"successor":backend.helper.local,"head":head});
    let signature = current.services.identity.sign(
        kv_core::remote::SignatureAlgorithm::ES256,
        &kv_core::remote::canonical::jcs(&proof)?,
    )?;
    kv_core::remote::keys::verify_identity_signature(
        &current.local,
        &kv_core::remote::canonical::jcs(&proof)?,
        &signature,
    )?;
    proof["sig"] = json!(kv_core::remote::keys::encode_b64(&signature));
    archives.push(Archived {
        generation: previous.as_ref().map(|catalog| catalog.active.clone()),
        device: current.local.clone(),
        head,
        proof,
    });
    let next = Generations {
        version: 1,
        account: current.account.clone(),
        active: generation,
        archives,
    };
    let expected = previous.as_ref().map(serde_json::to_value).transpose()?;
    anchor
        .replace_authenticated_metadata(METADATA, expected.as_ref(), serde_json::to_value(next)?)
        .map_err(|_| Error("remote_metadata_unavailable"))?;
    // No network operation precedes publication. A failed join resumes this same new DK.
    state.retired = true;
    Ok(backend)
}

pub(crate) fn audit_page(
    helper: &RemoteHelper,
    state: &State,
    args: &QueryAuditArgs,
) -> Result<Value> {
    if let Some(device) = args.extra.get("history_device") {
        let device = device.as_str().ok_or(Error("invalid_page"))?;
        let archive = state
            .archives
            .iter()
            .find(|archive| archive.device == device)
            .ok_or(Error("unknown_audit_archive"))?;
        if archive.store.audit_head()? != archive.head {
            return Err(Error("archived_audit_mismatch"));
        }
        bootstrap::verify_revoked_archive(archive.metadata.clone(), &archive.store)?;
        return Ok(serde_json::to_value(archive.store.audit_page(
            args,
            &archive.account,
            &archive.device,
            archive.metadata.as_ref(),
        )?)?);
    }
    let mut page = serde_json::to_value(state.store.audit_page(
        args,
        &helper.account,
        &helper.local.device_id,
        helper.services.audit.as_ref(),
    )?)?;
    if !state.archives.is_empty() {
        page["archived_devices"] = json!(state
            .archives
            .iter()
            .map(|archive| &archive.device)
            .collect::<Vec<_>>());
        page["archive_proofs"] = json!(state
            .archives
            .iter()
            .map(|archive| &archive.proof)
            .collect::<Vec<_>>());
        if args.extra.get("include_history_directory") == Some(&json!(true)) {
            let mut records = std::collections::BTreeMap::new();
            for archive in &state.archives {
                bootstrap::verify_revoked_archive(archive.metadata.clone(), &archive.store)?;
                for (record, _) in super::engine::directory(&archive.store)? {
                    if let Some(previous) = records.insert(record.device_id.clone(), record.clone())
                    {
                        if !super::directory::same_authority(&record, &previous) {
                            return Err(Error("archived_audit_mismatch"));
                        }
                    }
                }
            }
            if records.len() > 512 {
                return Err(Error("audit_metadata_too_large"));
            }
            page["history_directory"] = json!(records.into_values().collect::<Vec<_>>());
        }
    }
    Ok(page)
}

#[cfg(test)]
mod generation_tests {
    use super::*;

    #[test]
    fn generation_paths_require_canonical_bounded_identifiers() {
        let root = tempfile::tempdir().unwrap();
        for valid in ["00000000000000000000000000", "7ZZZZZZZZZZZZZZZZZZZZZZZZZ"] {
            assert_eq!(
                generation_path(root.path(), valid).unwrap(),
                root.path().join("generations").join(valid)
            );
        }
        for invalid in [
            "",
            "0000000000000000000000000",
            "000000000000000000000000000",
            "8ZZZZZZZZZZZZZZZZZZZZZZZZZ",
            "0ZZZZZZZZZZZZZZZZZZZZZZZZz",
            "../00000000000000000000000",
        ] {
            assert!(generation_path(root.path(), invalid).is_err());
        }
        for alias in ['I', 'L', 'O', 'U'] {
            let invalid = format!("0{}", alias.to_string().repeat(25));
            assert_eq!(invalid.len(), 26);
            assert!(generation_path(root.path(), &invalid).is_err());
        }
    }
}
