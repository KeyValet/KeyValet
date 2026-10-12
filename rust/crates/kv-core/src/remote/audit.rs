//! Metadata-only audit snapshots and correlation of independently authenticated endpoints.
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditHead {
    pub seq: u64,
    pub hash: String,
}

impl Default for AuditHead {
    fn default() -> Self {
        Self {
            seq: 0,
            hash: "0".repeat(64),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AuditPage {
    pub account_id: String,
    pub device_id: String,
    pub entries: Vec<Value>,
    pub through: u64,
    pub next_cursor: Option<u64>,
    pub head: AuditHead,
    /// Describes the independent checkpoint, rather than promising hardware anti-rollback.
    pub checkpoint: String,
    #[serde(default)]
    pub history_complete: bool,
}

pub fn metadata(entry: &Value) -> Value {
    let mut result = serde_json::Map::new();
    for key in [
        "op",
        "ts_unix",
        "ok",
        "reason",
        "approval_id",
        "id",
        "digest",
        "tier",
        "min_level",
        "agent_pid",
        "approver_device",
        "approval_level",
        "approval_latency_ms",
        "approval_path",
        "unattended_t2",
        "relay_clock_skew_s",
        "state",
        "jti",
        "jtis",
        "iss",
        "aud",
        "peer",
        "recipients",
        "decision",
        "max_tier",
        "directive_op",
        "key",
        "by",
        "device_id",
        "account_id",
        "audit_seq",
        "decision_hash",
        "grant_hash",
        "directive_hash",
        "remote_hash",
        "remote_prev_hash",
    ] {
        if let Some(value) = entry.get(key) {
            result.insert(key.into(), value.clone());
        }
    }
    Value::Object(result)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditFinding {
    pub kind: String,
    pub id: String,
    pub issuer: String,
    pub receiver: String,
    pub problem: String,
    pub fields: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct AuditComparison {
    pub matched: usize,
    pub findings: Vec<AuditFinding>,
}

type Key = (String, String, String, String);
type Sides<'a> = (Vec<&'a Value>, Vec<&'a Value>);

/// The caller must separately report missing endpoints or incomplete snapshots.
pub fn compare(snapshots: &[(String, Vec<Value>)]) -> AuditComparison {
    let mut groups: BTreeMap<Key, Sides<'_>> = BTreeMap::new();
    for (source, entries) in snapshots {
        for entry in entries {
            let text = |field: &str| entry[field].as_str().unwrap_or("");
            let (kind, id, issuer, receiver, issued) = match text("op") {
                "remote_approval_issued" => (
                    "approval",
                    text("approval_id"),
                    source.as_str(),
                    text("peer"),
                    true,
                ),
                "remote_approval_accepted" | "remote_approval_denied" => (
                    "approval",
                    text("approval_id"),
                    text("approver_device"),
                    source.as_str(),
                    false,
                ),
                "grant_issued" => ("grant", text("jti"), source.as_str(), text("aud"), true),
                "grant_installed" if entry.get("approval_id").is_none() => {
                    ("grant", text("jti"), text("iss"), source.as_str(), false)
                }
                "directive_issued" if text("directive_op") != "query_audit" => {
                    ("directive", text("id"), source.as_str(), text("peer"), true)
                }
                "directive_applied" if text("directive_op") != "query_audit" => {
                    ("directive", text("id"), text("iss"), source.as_str(), false)
                }
                _ => continue,
            };
            let receivers: Vec<&str> = if issued && receiver == "*" {
                let mut receivers = std::collections::BTreeSet::new();
                if let Some(recipients) = entry["recipients"].as_array() {
                    receivers.extend(recipients.iter().filter_map(Value::as_str));
                } else {
                    receivers.insert("");
                }
                // Global grants can reach executors paired after issuance as well.
                for (source, entries) in snapshots {
                    if entries.iter().any(|e| {
                        e["op"] == "grant_installed" && e["jti"] == id && e["iss"] == issuer
                    }) {
                        receivers.insert(source);
                    }
                }
                receivers.into_iter().collect()
            } else {
                vec![receiver]
            };
            for receiver in receivers {
                let sides = groups
                    .entry((kind.into(), id.into(), issuer.into(), receiver.into()))
                    .or_default();
                if issued {
                    sides.0.push(entry);
                } else {
                    sides.1.push(entry);
                }
            }
        }
    }
    let mut result = AuditComparison::default();
    for ((kind, id, issuer, receiver), (issued, received)) in groups {
        let mut fields = Vec::new();
        let problem = if id.is_empty() || issuer.is_empty() || receiver.is_empty() {
            "missing_binding"
        } else if issued.is_empty() {
            "missing_issuer_record"
        } else if received.is_empty() {
            "missing_receiver_record"
        } else if issued.len() != 1 || received.len() != 1 {
            "duplicate_record"
        } else {
            let expected: &[&str] = match kind.as_str() {
                "approval" => &["digest", "approval_level", "decision", "decision_hash"],
                "grant" => &["max_tier", "grant_hash"],
                _ => &["directive_op", "directive_hash"],
            };
            for field in expected {
                let a = issued[0].get(*field);
                let b = received[0].get(*field);
                if a.is_none() || b.is_none() || a != b {
                    fields.push((*field).into());
                }
            }
            if fields.is_empty() {
                result.matched += 1;
                continue;
            }
            "field_mismatch"
        };
        result.findings.push(AuditFinding {
            kind,
            id,
            issuer,
            receiver,
            problem: problem.into(),
            fields,
        });
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn correlates_routes_and_detects_missing_duplicate_and_different_records() {
        let issued = json!({"op":"remote_approval_issued","approval_id":"a","peer":"srv","digest":"d","approval_level":"strong","decision":"allow","decision_hash":"h"});
        let accepted = json!({"op":"remote_approval_accepted","approval_id":"a","approver_device":"phone","digest":"d","approval_level":"strong","decision":"allow","decision_hash":"h"});
        let check = |entries: Vec<Value>| {
            compare(&[
                ("phone".into(), vec![issued.clone()]),
                ("srv".into(), entries),
            ])
        };
        assert_eq!(check(vec![accepted.clone()]).matched, 1);
        assert_eq!(check(vec![]).findings[0].problem, "missing_receiver_record");
        assert_eq!(
            check(vec![accepted.clone(), accepted.clone()]).findings[0].problem,
            "duplicate_record"
        );
        let mut changed = accepted.clone();
        changed["digest"] = json!("other");
        assert_eq!(check(vec![changed]).findings[0].fields, vec!["digest"]);
        assert_eq!(
            compare(&[("srv".into(), vec![accepted])]).findings[0].problem,
            "missing_issuer_record"
        );
    }

    #[test]
    fn global_grants_and_directives_are_compared_without_exporting_request_data() {
        let result = compare(&[
            (
                "phone".into(),
                vec![
                    json!({"op":"grant_issued","jti":"g","aud":"*","recipients":["srv"],"max_tier":"T2","grant_hash":"h"}),
                    json!({"op":"directive_issued","id":"d","peer":"srv","directive_op":"lock","directive_hash":"h"}),
                ],
            ),
            (
                "srv".into(),
                vec![
                    json!({"op":"grant_installed","jti":"g","iss":"phone","max_tier":"T2","grant_hash":"h"}),
                    json!({"op":"directive_applied","id":"d","iss":"phone","directive_op":"lock","directive_hash":"h"}),
                ],
            ),
        ]);
        assert_eq!(result.matched, 2);
        assert!(result.findings.is_empty());
        assert_eq!(
            metadata(&json!({"op":"use","secret":"s","body":"b"})),
            json!({"op":"use"})
        );
    }
}
