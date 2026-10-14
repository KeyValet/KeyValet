use super::*;
use kv_core::remote::audit::{compare, AuditComparison, AuditHead, AuditPage};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct DirectiveOutcome {
    pub id: String,
    pub issuer: String,
    pub receiver: String,
    pub directive_op: kv_core::remote::DirectiveOp,
    pub wait_timeout_recorded: bool,
    pub result_ok: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct Endpoint {
    device_id: String,
    head: AuditHead,
    checkpoint: String,
    entries: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct Report {
    pub consistent: bool,
    pub comparison: AuditComparison,
    pub unavailable: Vec<(String, String)>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub directive_outcomes: Vec<DirectiveOutcome>,
    endpoints: Vec<Endpoint>,
}

fn directive_outcomes(
    comparison: &AuditComparison,
    snapshots: &[(String, Vec<Value>)],
    authenticated: &HashSet<String>,
) -> Vec<DirectiveOutcome> {
    let mut indexed: HashMap<(&str, &str, &str), Vec<&Value>> = HashMap::new();
    for (source, entries) in snapshots {
        if !authenticated.contains(source) {
            continue;
        }
        for entry in entries {
            if !matches!(
                entry["op"].as_str(),
                Some("directive_issued" | "directive_wait_timeout" | "directive_result")
            ) {
                continue;
            }
            if let (Some(id), Some(peer)) = (entry["id"].as_str(), entry["peer"].as_str()) {
                indexed
                    .entry((source.as_str(), id, peer))
                    .or_default()
                    .push(entry);
            }
        }
    }
    comparison
        .findings
        .iter()
        .filter(|finding| {
            finding.kind == "directive"
                && finding.problem == "missing_receiver_record"
                && authenticated.contains(&finding.issuer)
        })
        .filter_map(|finding| {
            let entries = indexed.get(&(
                finding.issuer.as_str(),
                finding.id.as_str(),
                finding.receiver.as_str(),
            ))?;
            let issued = entries
                .iter()
                .filter(|entry| {
                    entry["op"] == "directive_issued"
                        && entry["id"] == finding.id
                        && entry["peer"] == finding.receiver
                })
                .collect::<Vec<_>>();
            if issued.len() != 1 {
                return None;
            }
            let issued = issued[0];
            let operation = serde_json::from_value(issued["directive_op"].clone()).ok()?;
            let hash = issued["directive_hash"]
                .as_str()
                .filter(|value| !value.is_empty())?;
            let wait_timeout_recorded = entries.iter().any(|entry| {
                entry["op"] == "directive_wait_timeout"
                    && entry["id"] == finding.id
                    && entry["peer"] == finding.receiver
                    && entry["directive_op"] == issued["directive_op"]
                    && entry["directive_hash"] == hash
                    && entry["state"] == "unconfirmed"
                    && entry["reason"] == "directive_result_timeout"
            });
            let results = entries
                .iter()
                .filter(|entry| {
                    entry["op"] == "directive_result"
                        && entry["id"] == finding.id
                        && entry["peer"] == finding.receiver
                })
                .collect::<Vec<_>>();
            Some(DirectiveOutcome {
                id: finding.id.clone(),
                issuer: finding.issuer.clone(),
                receiver: finding.receiver.clone(),
                directive_op: operation,
                wait_timeout_recorded,
                result_ok: if results.len() == 1 {
                    results[0]["ok"].as_bool()
                } else {
                    None
                },
            })
        })
        .collect()
}

struct Snapshot {
    page: AuditPage,
    archives: Vec<String>,
    proofs: Vec<Value>,
    history_directory: Vec<DeviceRecord>,
}

pub(super) fn verify_archive(
    peer: &DeviceRecord,
    page: &AuditPage,
    proofs: &[Value],
    known: &[DeviceRecord],
) -> Result<()> {
    let mut current = known
        .iter()
        .find(|device| device.device_id == page.device_id)
        .cloned()
        .ok_or_else(Error::protocol)?;
    let mut seen = HashSet::new();
    for index in 0..16 {
        if !seen.insert(current.device_id.clone()) {
            return Err(Error::protocol());
        }
        let candidates = proofs
            .iter()
            .filter(|proof| proof["predecessor"]["device_id"] == current.device_id)
            .collect::<Vec<_>>();
        if candidates.len() != 1 {
            return Err(Error::protocol());
        }
        let mut body = candidates[0].clone();
        let signature = body
            .as_object_mut()
            .and_then(|object| object.remove("sig"))
            .and_then(|value| value.as_str().map(str::to_owned))
            .ok_or_else(Error::protocol)?;
        let predecessor: DeviceRecord =
            serde_json::from_value(body["predecessor"].clone()).map_err(|_| Error::protocol())?;
        let successor: DeviceRecord =
            serde_json::from_value(body["successor"].clone()).map_err(|_| Error::protocol())?;
        if body["domain"] != "keyvalet.audit-archive.v1"
            || body["account"] != page.account_id
            || !kv_core::remote::validation::same_device_authority(&current, &predecessor)
            || (index == 0 && body["head"] != json!(page.head))
        {
            return Err(Error::protocol());
        }
        kv_core::remote::keys::verify_identity_signature(
            &predecessor,
            &kv_core::remote::canonical::jcs(&body).map_err(|_| Error::protocol())?,
            &kv_core::remote::keys::decode_b64(&signature).map_err(|_| Error::protocol())?,
        )
        .map_err(|_| Error::protocol())?;
        if kv_core::remote::validation::same_device_authority(&successor, peer) {
            return Ok(());
        }
        current = successor;
    }
    Err(Error::protocol())
}

fn snapshot(
    host: &mut impl Host,
    peer: Option<&str>,
    history: Option<&str>,
    since: i64,
    limit: u32,
) -> Result<Snapshot> {
    let mut all = Vec::new();
    let mut after = 0;
    let mut frozen: Option<AuditPage> = None;
    let mut archives = None;
    let mut frozen_metadata = None;
    loop {
        let mut args = json!({"since":since,"limit":limit,"after":after});
        if peer.is_none() && history.is_none() {
            args["include_history_directory"] = json!(true);
        }
        if let Some(first) = &frozen {
            args["through"] = json!(first.through);
        }
        if let Some(history) = history {
            args["history_device"] = json!(history);
        }
        let value: Value = if let Some(peer) = peer {
            let reply: kv_core::remote::ipc::DirectiveIssueResult = call(
                host,
                Op::DirectiveIssue,
                json!({"kind":"directive","aud":peer,"op":"query_audit","args":args}),
            )?;
            if !reply.result.ok {
                return Err(Error {
                    code: reply
                        .result
                        .error
                        .unwrap_or_else(|| "audit_rejected".into()),
                    message: kv_i18n::t("审计查询被拒绝", "Audit query rejected"),
                    completed_devices: vec![],
                });
            }
            Value::Object(reply.result.state)
        } else {
            call(host, Op::AuditList, args)?
        };
        let current_archives: Vec<String> = match value.get("archived_devices") {
            Some(value) => serde_json::from_value(value.clone()).map_err(|_| Error::protocol())?,
            None => vec![],
        };
        let proofs: Vec<Value> =
            serde_json::from_value(value.get("archive_proofs").cloned().unwrap_or(json!([])))
                .map_err(|_| Error::protocol())?;
        let history_directory: Vec<DeviceRecord> =
            serde_json::from_value(value.get("history_directory").cloned().unwrap_or(json!([])))
                .map_err(|_| Error::protocol())?;
        let metadata = (proofs.clone(), history_directory.clone());
        if proofs.len() > 16
            || history_directory.len() > 512
            || frozen_metadata
                .as_ref()
                .is_some_and(|first| first != &metadata)
        {
            return Err(Error::protocol());
        }
        if frozen_metadata.is_none() {
            frozen_metadata = Some(metadata);
        }
        let unique: std::collections::HashSet<_> = current_archives.iter().collect();
        if current_archives.len() > 16
            || unique.len() != current_archives.len()
            || current_archives
                .iter()
                .any(|id| id.is_empty() || id.len() > 1024)
            || archives
                .as_ref()
                .is_some_and(|first| first != &current_archives)
        {
            return Err(Error::protocol());
        }
        let page: AuditPage = serde_json::from_value(value).map_err(|_| Error::protocol())?;
        if page.account_id.is_empty()
            || page.device_id.is_empty()
            || page.head.hash.len() != 64
            || !page.head.hash.bytes().all(|ch| ch.is_ascii_hexdigit())
            || page.head.seq != page.through
            || history.or(peer).is_some_and(|id| page.device_id != id)
            || current_archives.contains(&page.device_id)
            || frozen.as_ref().is_some_and(|first| {
                first.account_id != page.account_id
                    || first.device_id != page.device_id
                    || first.head != page.head
                    || first.checkpoint != page.checkpoint
                    || first.history_complete != page.history_complete
            })
        {
            return Err(Error::protocol());
        }
        if archives.is_none() {
            archives = Some(current_archives);
        }
        for entry in &page.entries {
            let seq = entry["audit_seq"].as_u64().ok_or_else(Error::protocol)?;
            if seq <= after
                || seq > page.through
                || entry["ts_unix"].as_i64().is_none_or(|ts| ts < since)
            {
                return Err(Error::protocol());
            }
            after = seq;
        }
        if page.entries.len() > limit as usize || all.len() + page.entries.len() > 100_000 {
            return Err(Error::new(
                "audit_incomplete",
                "审计快照超过查询上限",
                "Audit snapshot exceeded the query bound",
            ));
        }
        all.extend(page.entries.iter().cloned());
        if let Some(cursor) = page.next_cursor {
            if page.entries.is_empty() || cursor != after || cursor >= page.through {
                return Err(Error::protocol());
            }
            if frozen.is_none() {
                frozen = Some(page);
            }
        } else {
            return Ok(Snapshot {
                page: AuditPage {
                    entries: all,
                    ..page
                },
                archives: archives.unwrap_or_default(),
                proofs,
                history_directory,
            });
        }
    }
}

pub(super) fn run(
    host: &mut impl Host,
    target: Option<&str>,
    since: i64,
    limit: u32,
) -> Result<Success> {
    let local = snapshot(host, None, None, since, limit)?;
    let account = local.page.account_id.clone();
    let own = local.page.device_id.clone();
    let mut known = local.history_directory;
    let mut pages = vec![local.page];
    for history in local.archives {
        let archived = snapshot(host, None, Some(&history), since, limit)?;
        if archived.page.account_id != account || !archived.archives.is_empty() {
            return Err(Error::protocol());
        }
        pages.push(archived.page);
    }
    let directory = devices(host)?;
    known.extend(directory.devices.iter().cloned());
    let peers = if let Some(target) = target {
        resolve(target, &directory.devices)?
    } else {
        directory.devices
    };
    let mut report = Report {
        consistent: false,
        comparison: AuditComparison::default(),
        unavailable: vec![],
        directive_outcomes: vec![],
        endpoints: vec![],
    };
    for peer in peers {
        if peer.device_id == own {
            continue;
        }
        if peer.extra.get("revoked") == Some(&Value::Bool(true)) {
            report
                .unavailable
                .push((peer.device_id, "revoked_device".into()));
            continue;
        }
        match snapshot(host, Some(&peer.device_id), None, since, limit) {
            Ok(snapshot) if snapshot.page.account_id == account => {
                pages.push(snapshot.page);
                for history in snapshot.archives {
                    match self::snapshot(host, Some(&peer.device_id), Some(&history), since, limit)
                    {
                        Ok(archived)
                            if archived.page.account_id == account
                                && archived.archives.is_empty()
                                && verify_archive(
                                    &peer,
                                    &archived.page,
                                    &snapshot.proofs,
                                    &known,
                                )
                                .is_ok() =>
                        {
                            pages.push(archived.page)
                        }
                        Ok(_) => report
                            .unavailable
                            .push((history, "account_or_history_mismatch".into())),
                        Err(error) => report.unavailable.push((history, error.code)),
                    }
                }
            }
            Ok(_) => report
                .unavailable
                .push((peer.device_id, "account_mismatch".into())),
            Err(error) => report.unavailable.push((peer.device_id, error.code)),
        }
    }
    let authenticated = pages
        .iter()
        .filter(|page| {
            page.history_complete
                && matches!(
                    page.checkpoint.as_str(),
                    "vault_authenticated_metadata" | "encrypted_store"
                )
        })
        .map(|page| page.device_id.clone())
        .collect();
    report.unavailable.retain(|(device, reason)| {
        reason != "revoked_device"
            || !pages.iter().any(|page| {
                &page.device_id == device
                    && page.history_complete
                    && matches!(
                        page.checkpoint.as_str(),
                        "vault_authenticated_metadata" | "encrypted_store"
                    )
            })
    });
    let snapshots = pages
        .into_iter()
        .map(|page| {
            if !matches!(
                page.checkpoint.as_str(),
                "vault_authenticated_metadata" | "encrypted_store"
            ) {
                report.unavailable.push((
                    page.device_id.clone(),
                    "audit_checkpoint_unavailable".into(),
                ));
            }
            if !page.history_complete {
                report
                    .unavailable
                    .push((page.device_id.clone(), "legacy_audit_history".into()));
            }
            report.endpoints.push(Endpoint {
                device_id: page.device_id.clone(),
                head: page.head,
                checkpoint: page.checkpoint,
                entries: page.entries.len(),
            });
            (page.device_id, page.entries)
        })
        .collect::<Vec<_>>();
    report.comparison = compare(&snapshots);
    if target.is_some() {
        let included: HashSet<_> = snapshots.iter().map(|(id, _)| id.as_str()).collect();
        report.comparison.findings.retain(|finding| {
            finding.problem == "missing_binding"
                || included.contains(finding.issuer.as_str())
                    && included.contains(finding.receiver.as_str())
        });
    }
    // Explain known wait/result facts without changing the core comparison, match
    // count, query window, original records or nonzero findings exit status.
    report.directive_outcomes = directive_outcomes(&report.comparison, &snapshots, &authenticated);
    report.consistent = report.unavailable.is_empty() && report.comparison.findings.is_empty();
    Ok(Success::Audit(report))
}
