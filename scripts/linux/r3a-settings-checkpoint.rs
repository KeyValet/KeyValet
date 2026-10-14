//! One-time owner maintenance for the observed R3-A local settings publication gap.
//! This is not called by the runtime or exposed over IPC.
use kv_core::remote::audit::AuditHead;
use kv_core::remote::canonical::{jcs, sha256_hex};
use kv_helper::remote::{Error, Result};
use kv_vault::Vault;
use serde_json::{json, Value};

mod bootstrap {
    pub use kv_helper::remote::bootstrap::KeyFactory;
}
#[path = "../../rust/crates/kv-helper/src/remote/metadata_master.rs"]
mod metadata_master;
#[path = "../../rust/crates/kv-helper/src/remote/audit.rs"]
mod audit;

fn validate_gap(
    vault: &Vault,
    records: &[Value],
    old: &AuditHead,
    next: &AuditHead,
    account: &str,
    device: &str,
) -> Result<()> {
    let checkpoint = vault
        .authenticated_metadata("remote_audit_checkpoint")
        .map_err(|_| Error("audit_unavailable"))?
        .ok_or(Error("audit_checkpoint_mismatch"))?;
    if checkpoint["version"] != 1
        || !checkpoint["pending"].is_null()
        || serde_json::from_value::<AuditHead>(checkpoint["committed"].clone())? != *old
        || old.seq.checked_add(1) != Some(next.seq)
    {
        return Err(Error("unexpected_checkpoint_gap"));
    }
    let mut previous = AuditHead::default();
    let mut anchored = old.seq == 0 && *old == previous;
    for record in records {
        let seq = record["audit_seq"]
            .as_u64()
            .or_else(|| record["legacy_seq"].as_u64())
            .ok_or(Error("audit_chain_mismatch"))?;
        let mut body = record
            .as_object()
            .cloned()
            .ok_or(Error("audit_chain_mismatch"))?;
        let hash = body
            .remove("remote_hash")
            .and_then(|v| v.as_str().map(str::to_owned))
            .ok_or(Error("audit_chain_mismatch"))?;
        let prev_hash = body
            .remove("remote_prev_hash")
            .and_then(|v| v.as_str().map(str::to_owned))
            .ok_or(Error("audit_chain_mismatch"))?;
        body.remove("legacy_seq");
        let mut bytes = previous.hash.as_bytes().to_vec();
        bytes.extend(jcs(&body)?);
        if previous.seq.checked_add(1) != Some(seq)
            || prev_hash != previous.hash
            || sha256_hex(&bytes) != hash
        {
            return Err(Error("audit_chain_mismatch"));
        }
        previous = AuditHead { seq, hash };
        if previous == *old {
            anchored = true;
        }
    }
    let last = records.last().ok_or(Error("unexpected_checkpoint_gap"))?;
    if !anchored || previous != *next {
        return Err(Error("unexpected_checkpoint_gap"));
    }
    if last["op"] != "setting_changed"
        || last["key"] != "mode"
        || last["by"] != "local"
        || last["account_id"] != account
        || last["source_device"] != device
    {
        return Err(Error("unexpected_settings_record"));
    }
    // A matching SQLite chain alone cannot authorize maintenance.
    audit::verify(vault, old)?;
    audit::verify_records(vault, records)?;
    Ok(())
}

fn reconcile(
    vault: &Vault,
    records: &[Value],
    old: &AuditHead,
    next: &AuditHead,
    account: &str,
    device: &str,
    apply: bool,
) -> Result<()> {
    validate_gap(vault, records, old, next, account, device)?;
    if apply {
        vault
            .audit(json!({"op":"owner_settings_checkpoint_repair","before":old,"after":next,
                "device_id":device,"account_id":account,"mode":"per_use"})
                .as_object().unwrap().clone())
            .map_err(|_| Error("audit_unavailable"))?;
        // Publish the observed committed record through the existing journal protocol.
        audit::prepare(vault, old, next)?;
        audit::commit(vault, next)?;
        audit::verify(vault, next)?;
        audit::verify_records(vault, records)?;
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn run() -> Result<()> {
    use rusqlite::{Connection, OpenFlags};
    use std::path::Path;
    let args: Vec<_> = std::env::args().skip(1).collect();
    let apply = match args.as_slice() {
        [arg] if arg == "--dry-run" => false,
        [arg] if arg == "--apply" => true,
        _ => return Err(Error("invalid_maintenance_arguments")),
    };
    if unsafe { libc::getuid() } != 994 || unsafe { libc::geteuid() } != 994 {
        return Err(Error("maintenance_requires_existing_service_uid"));
    }
    let path = Path::new("/var/lib/keyvalet/remote");
    let keys = kv_helper::remote::platform_keys::TpmKeys { directory: path.into() };
    let master = metadata_master::IdentityMaster { keys: &keys };
    let vault = Vault::new(path);
    vault.init_with_provider(&master, "R3-A: verify the existing remote metadata identity")
        .map_err(|_| Error("remote_metadata_unavailable"))?;
    let db = Connection::open_with_flags(path.join("approvals.sqlite3"), OpenFlags::SQLITE_OPEN_READ_ONLY)?;
    let mut statement = db.prepare("SELECT seq,entry_json,prev_hash,entry_hash FROM remote_audit ORDER BY seq")?;
    let rows = statement.query_map([], |row| Ok((row.get::<_,u64>(0)?,row.get::<_,String>(1)?,row.get::<_,String>(2)?,row.get::<_,String>(3)?)))?;
    let mut records = Vec::new();
    for row in rows {
        let (seq, entry, previous, hash) = row?;
        let mut value: Value = serde_json::from_str(&entry)?;
        if value.get("audit_seq").is_none() { value["legacy_seq"] = json!(seq); }
        value["remote_prev_hash"] = json!(previous);
        value["remote_hash"] = json!(hash);
        records.push(value);
    }
    let settings: Value = serde_json::from_str(&db.query_row("SELECT value_json FROM settings WHERE key='local_settings'",[],|r|r.get::<_,String>(0))?)?;
    if settings["grant_mode"] != "per_use" || settings["remember_hours"].as_f64() != Some(8.0)
        || !settings["remember_until"].is_null() {
        return Err(Error("unexpected_live_settings"));
    }
    let old = AuditHead { seq:1942, hash:"ecfed0d505afcc9d386e95d470605e2d6375abd9fea502a572bcde76b6bfd3aa".into() };
    let next = AuditHead { seq:1943, hash:"c72316c8b3720e802a8af1de3fd95df7954d1e42d0af1fd6f4c9f6a05dd147b2".into() };
    reconcile(&vault,&records,&old,&next,"acct_zeP4_V8iHJdLbzJrDU3rfQ","01M4S8KJ48BSMNK1S4BEGT07FC",apply)?;
    println!("{}",json!({"ok":true,"apply":apply,"records_verified":records.len(),"before":old,"after":next,"secret_values_in_evidence":false}));
    Ok(())
}

#[cfg(target_os = "linux")]
fn main() {
    if let Err(error) = run() {
        eprintln!("{}", json!({"ok":false,"fixed_error":error.code()}));
        std::process::exit(1);
    }
}
#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("This one-time maintenance command is Linux-only");
    std::process::exit(1);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> (tempfile::TempDir, Vault, Vec<Value>, AuditHead, AuditHead) {
        let temp = tempfile::tempdir().unwrap();
        let keys = kv_helper::remote::platform_keys::SoftwareKeys;
        let master = metadata_master::IdentityMaster { keys: &keys };
        let vault = Vault::new(temp.path().join("remote"));
        vault.prepare().unwrap();
        vault.initialize_enclave(&master,"synthetic-fixture-passphrase-42","CI fixture").unwrap();
        vault.init_with_provider(&master,"CI fixture").unwrap();
        let mut records = Vec::new();
        let mut previous = AuditHead::default();
        audit::verify(&vault,&previous).unwrap();
        for seq in 1..=2 {
            let mut record = json!({"op":"setting_changed","key":"mode","by":"local",
                "account_id":"fixture-account","source_device":"fixture-device","audit_seq":seq,"ts_unix":100+seq});
            let mut bytes = previous.hash.as_bytes().to_vec();bytes.extend(jcs(&record).unwrap());
            let next = AuditHead { seq,hash:sha256_hex(&bytes) };
            record["remote_prev_hash"]=json!(previous.hash);record["remote_hash"]=json!(next.hash);
            vault.audit(record.as_object().unwrap().clone()).unwrap();
            if seq==1 { audit::prepare(&vault,&previous,&next).unwrap();audit::commit(&vault,&next).unwrap(); }
            records.push(record);previous=next;
        }
        let old = AuditHead { seq:1,hash:records[0]["remote_hash"].as_str().unwrap().into() };
        (temp,vault,records,old,previous)
    }

    #[test]
    fn dry_run_leaves_the_gap_rejected_until_explicit_application() {
        let (_temp,vault,records,old,next)=fixture();
        let before=vault.authenticated_metadata("remote_audit_checkpoint").unwrap();
        reconcile(&vault,&records,&old,&next,"fixture-account","fixture-device",false).unwrap();
        assert_eq!(before,vault.authenticated_metadata("remote_audit_checkpoint").unwrap());
        assert_eq!(audit::verify(&vault,&next),Err(Error("audit_checkpoint_mismatch")));
        reconcile(&vault,&records,&old,&next,"fixture-account","fixture-device",true).unwrap();
        audit::verify(&vault,&next).unwrap();
        audit::verify_records(&vault,&records).unwrap();
    }

    #[test]
    fn forged_or_unrelated_suffix_and_wrong_anchors_are_rejected() {
        let (_temp,vault,records,old,next)=fixture();
        let before=vault.authenticated_metadata("remote_audit_checkpoint").unwrap();
        let mut forged=records.clone();forged[1]["op"]=json!("grant_installed");
        assert!(validate_gap(&vault,&forged,&old,&next,"fixture-account","fixture-device").is_err());
        assert!(validate_gap(&vault,&records,&AuditHead::default(),&next,"fixture-account","fixture-device").is_err());
        assert!(validate_gap(&vault,&records,&old,&next,"other-account","fixture-device").is_err());
        assert_eq!(before,vault.authenticated_metadata("remote_audit_checkpoint").unwrap());
    }

    #[test]
    fn sqlite_hashes_without_independent_receipts_cannot_authorize_repair() {
        let (_temp,vault,records,old,next)=fixture();
        let before=vault.authenticated_metadata("remote_audit_checkpoint").unwrap();
        let file=vault.dir.join("audit.log");
        let text=std::fs::read_to_string(&file).unwrap();
        let retained=text.lines().filter(|line|!line.contains("\"audit_seq\":2")).collect::<Vec<_>>().join("\n")+"\n";
        std::fs::write(file,retained).unwrap();
        assert_eq!(validate_gap(&vault,&records,&old,&next,"fixture-account","fixture-device"),Err(Error("audit_receipt_missing")));
        assert_eq!(before,vault.authenticated_metadata("remote_audit_checkpoint").unwrap());
    }
}
