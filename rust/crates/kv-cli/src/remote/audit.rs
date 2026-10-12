use super::*;
use kv_core::remote::audit::{compare, AuditComparison, AuditHead, AuditPage};
use serde::{Deserialize, Serialize};

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
    endpoints: Vec<Endpoint>,
}

fn snapshot(host: &mut impl Host, peer: Option<&str>, since: i64, limit: u32) -> Result<AuditPage> {
    let mut all = Vec::new();
    let mut after = 0;
    let mut frozen: Option<AuditPage> = None;
    loop {
        let mut args = json!({"since":since,"limit":limit,"after":after});
        if let Some(first) = &frozen {
            args["through"] = json!(first.through);
        }
        let page: AuditPage = if let Some(peer) = peer {
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
                    message: "Audit query rejected".into(),
                    completed_devices: vec![],
                });
            }
            serde_json::from_value(Value::Object(reply.result.state))
                .map_err(|_| Error::protocol())?
        } else {
            call(host, Op::AuditList, args)?
        };
        if page.account_id.is_empty()
            || page.device_id.is_empty()
            || page.head.hash.len() != 64
            || !page.head.hash.bytes().all(|ch| ch.is_ascii_hexdigit())
            || page.head.seq != page.through
            || peer.is_some_and(|id| page.device_id != id)
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
            return Ok(AuditPage {
                entries: all,
                ..page
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
    let local = snapshot(host, None, since, limit)?;
    let directory = devices(host)?;
    let peers = if let Some(target) = target {
        resolve(target, &directory.devices)?
    } else {
        directory.devices
    };
    let mut report = Report {
        consistent: false,
        comparison: AuditComparison::default(),
        unavailable: vec![],
        endpoints: vec![],
    };
    let account = local.account_id.clone();
    let own = local.device_id.clone();
    let mut pages = vec![local];
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
        match snapshot(host, Some(&peer.device_id), since, limit) {
            Ok(page) if page.account_id == account => pages.push(page),
            Ok(_) => report
                .unavailable
                .push((peer.device_id, "account_mismatch".into())),
            Err(error) => report.unavailable.push((peer.device_id, error.code)),
        }
    }
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
    report.consistent = report.unavailable.is_empty() && report.comparison.findings.is_empty();
    Ok(Success::Audit(report))
}
