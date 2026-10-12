//! Bounded metadata pages remain below the encrypted-envelope transport limit.
use super::{Error, Result};
use kv_ipc::remote::GrantListParams;
use serde_json::{json, Value};

pub(crate) fn validate(params: &GrantListParams) -> Result<()> {
    if !(1..=100).contains(&params.limit)
        || params
            .after
            .as_ref()
            .is_some_and(|id| id.len() > 256 || id.chars().any(char::is_control))
    {
        return Err(Error("invalid_page"));
    }
    Ok(())
}

pub(crate) fn page(mut entries: Vec<Value>, params: &GrantListParams) -> Result<Value> {
    validate(params)?;
    entries.sort_by(|a, b| a["jti"].as_str().cmp(&b["jti"].as_str()));
    let mut grants = Vec::new();
    let mut bytes = 1024;
    let mut more = false;
    for mut entry in entries {
        let id = entry["jti"]
            .as_str()
            .ok_or(Error("invalid_grant"))?
            .to_owned();
        if id.len() > 256 || id.chars().any(char::is_control) {
            return Err(Error("invalid_grant"));
        }
        if params.after.as_ref().is_some_and(|after| id <= *after) {
            continue;
        }
        if grants.len() >= usize::from(params.limit) {
            more = true;
            break;
        }
        let mut size = serde_json::to_vec(&entry)?.len();
        if size > 40 * 1024 {
            // A summary is explicitly a projection: never attach a signature to modified data.
            let text = |name: &str| {
                entry[name]
                    .as_str()
                    .unwrap_or("")
                    .chars()
                    .take(256)
                    .collect::<String>()
            };
            entry = json!({"jti":id,"iss":text("iss"),"aud":text("aud"),"exp":entry["exp"],
                "nbf":entry["nbf"],"revoked_at":entry["revoked_at"],"origin":text("origin"),
                "scope":{"level":entry["scope"]["level"],"max_tier":entry["scope"]["max_tier"]},
                "budget_left":{"calls_left":entry["budget_left"]["calls_left"].as_u64()},"uses_n":entry["uses_n"].as_u64(),"last_used_at":entry["last_used_at"].as_i64(),
                "object_omitted":true});
            size = serde_json::to_vec(&entry)?.len();
        }
        if bytes + size > 48 * 1024 {
            more = true;
            break;
        }
        bytes += size;
        grants.push(entry);
    }
    let next = if more {
        grants
            .last()
            .and_then(|g| g["jti"].as_str())
            .map(str::to_owned)
    } else {
        None
    };
    Ok(json!({"grants":grants,"next_cursor":next}))
}
