use super::engine::{signing_level, State};
use super::pipeline::glob;
use super::store::{algorithm, decode, encode, Pending};
use super::{Error, RemoteHelper, Result};
use kv_core::remote::canonical::{jcs, normalize_path, sha256_hex, CanonicalRequest};
use kv_core::remote::validation::{approval_key, verify_decision, verify_grant};
use kv_core::remote::*;
use rusqlite::{params, OptionalExtension};
use serde_json::{json, Value};

pub struct GrantUse {
    pub canonical: CanonicalRequest,
    pub tier: Tier,
    pub template_allowed_hosts: Vec<String>,
    pub policy_allowed_methods: Vec<String>,
    pub body_bytes: u64,
    pub session_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Coverage {
    pub jtis: Vec<String>,
    pub max_tier: Option<Tier>,
    pub unattended_t2: bool,
}

impl RemoteHelper {
    /// Upgrade only tightens authority: old K4-incompatible tickets cannot become active again.
    pub(crate) fn invalidate_legacy_t2(&self) -> Result<()> {
        let state = self.lock()?;
        let label = self.label(&state)?;
        let candidates = {
            let mut statement = state.store.db.prepare(
                "SELECT object_json FROM grants WHERE max_tier='T2' AND revoked_at IS NULL",
            )?;
            let rows = statement.query_map([], |row| row.get::<_, String>(0))?;
            rows.collect::<std::result::Result<Vec<_>, _>>()?
        };
        let invalid = candidates
            .iter()
            .map(|object| decode::<Grant>(object))
            .collect::<Result<Vec<_>>>()?
            .into_iter()
            .filter(|grant| {
                grant.scope.max_tier == Tier::T2
                    && (grant.aud == "*"
                        || grant.scope.level == GrantScopeLevel::Global
                        || grant.confirm.as_value() != Some(&label))
            })
            .collect::<Vec<_>>();
        if invalid.is_empty() {
            return Ok(());
        }
        let now = self.services.clock.now();
        let transaction = state.store.transaction(self.services.audit.as_ref())?;
        for grant in invalid {
            transaction.execute(
                "UPDATE grants SET revoked_at=?1 WHERE jti=?2",
                params![now, grant.jti],
            )?;
            transaction.execute(
                "INSERT OR IGNORE INTO revoked_jti(jti,revoked_at) VALUES(?1,?2)",
                params![grant.jti, now],
            )?;
            self.audit(
                &state,
                "grant_invalidated",
                json!({"jti":grant.jti,"reason":"k4_t2_binding_required"}),
            )?;
        }
        transaction.commit()
    }

    pub fn install_grant(&self, grant: &Grant, level: ApprovalLevel) -> Result<()> {
        let state = self.lock()?;
        let result = (|| {
            let device = state.store.device(&grant.iss, &self.account)?;
            self.install_grant_locked(&state, grant, &device, Some(level))
        })();
        if let Err(error) = result {
            self.reject(&state, "grant_rejected", error, &grant.jti)?;
        }
        result
    }

    pub(crate) fn install_grant_locked(
        &self,
        state: &State,
        grant: &Grant,
        device: &DeviceRecord,
        level: Option<ApprovalLevel>,
    ) -> Result<()> {
        let now = self.services.clock.now();
        if grant.aud == "*"
            && state
                .store
                .setting::<bool>(&format!("global_excluded:{}", grant.iss))?
                .unwrap_or(false)
        {
            return Err(Error("global_grant_excluded"));
        }
        let level = match level {
            Some(level) => level,
            None => signing_level(grant, &grant.sig, grant.iss_alg, device)?,
        };
        verify_grant(
            grant,
            &self.local.device_id,
            &self.label(state)?,
            device,
            level,
            now,
        )?;
        if grant.jti.is_empty() {
            return Err(Error("invalid_grant"));
        }
        let transaction = state.store.transaction(self.services.audit.as_ref())?;
        self.save_grant(
            state,
            grant,
            &json!({"kind": "grant", "level": level}),
            None,
        )?;
        self.audit(
            state,
            "grant_installed",
            json!({"jti": grant.jti, "iss": grant.iss, "grant_hash":sha256_hex(&jcs(grant)?), "max_tier": grant.scope.max_tier,
            "unattended_t2": grant.scope.max_tier == Tier::T2}),
        )?;
        transaction.commit()?;
        Ok(())
    }

    pub(crate) fn save_grant(
        &self,
        state: &State,
        grant: &Grant,
        authority: &Value,
        session_id: Option<&str>,
    ) -> Result<()> {
        let revoked: bool = state.store.db.query_row(
            "SELECT EXISTS(SELECT 1 FROM revoked_jti WHERE jti=?1)",
            [&grant.jti],
            |r| r.get(0),
        )?;
        if revoked {
            return Err(Error("revoked_grant"));
        }
        let exists: bool = state.store.db.query_row(
            "SELECT EXISTS(SELECT 1 FROM grants WHERE jti=?1)",
            [&grant.jti],
            |r| r.get(0),
        )?;
        if exists {
            return Err(Error("replay"));
        }
        let string = |v: &Optional<Vec<String>>| v.as_value().map(encode).transpose();
        state.store.db.execute(
            "INSERT INTO grants (jti, iss, iss_alg, aud, level, credential, hosts_json, methods_json, paths_json,
             agent, max_tier, budget_json, budget_left_json, nbf, exp, origin, sig, installed_at, object_json, authority_json, session_id)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20, ?21)",
            params![grant.jti, grant.iss, algorithm(grant.iss_alg), grant.aud, encode(&grant.scope.level)?.trim_matches('"'),
                grant.scope.credential.as_value(), string(&grant.scope.hosts)?, string(&grant.scope.methods)?, string(&grant.scope.paths)?,
                grant.scope.agent.as_value(), encode(&grant.scope.max_tier)?.trim_matches('"'), grant.budget.as_value().map(encode).transpose()?,
                Option::<String>::None, grant.nbf, grant.exp, grant.origin, grant.sig, self.services.clock.now(), encode(grant)?, encode(authority)?, session_id],
        )?;
        Ok(())
    }

    pub(crate) fn derive_grant_locked(
        &self,
        state: &State,
        pending: &Pending,
        decision: &ApprovalDecision,
    ) -> Result<()> {
        let now = self.services.clock.now();
        let session = matches!(
            decision.scope.mode,
            ScopeMode::PerCredential | ScopeMode::PerSession
        );
        let ttl = state
            .store
            .setting::<u64>("unlock_ttl")?
            .unwrap_or(self.config.unlock_ttl_s);
        if pending.request.kind == ApprovalKind::Unlock {
            state.store.set_setting(
                &format!("unlock:{}", pending.session_id),
                &now.saturating_add(ttl as i64),
                &format!("remote:{}", decision.approver),
                now,
            )?;
            return Ok(());
        }
        if pending.request.kind != ApprovalKind::Use {
            return Ok(());
        }
        if decision.scope.mode == ScopeMode::PerUse && pending.request.merged_count <= 1 {
            return Ok(());
        }
        let device = state.store.device(&decision.approver, &self.account)?;
        let grant = derived_grant(pending, decision, &device, now, &self.local.device_id)?;
        self.save_grant(
            state,
            &grant,
            &json!({"kind": "approval_decision", "decision": decision,
            "request": pending.request, "canonical": pending.canonical, "verified_at": now}),
            session.then_some(pending.session_id.as_str()),
        )?;
        self.audit(state, "grant_installed", json!({"jti": grant.jti, "iss": grant.iss, "approval_id": decision.approval_id, "max_tier": Tier::T1}))
    }

    pub fn cover_and_debit(&self, usage: &GrantUse) -> Result<Coverage> {
        let result = self.cover_and_debit_inner(usage);
        if let Err(error) = result {
            let state = self.lock()?;
            self.reject(&state, "grant_rejected", error, "")?;
        }
        result
    }

    fn cover_and_debit_inner(&self, usage: &GrantUse) -> Result<Coverage> {
        let state = self.lock()?;
        self.ensure_execution_device_active(&state)?;
        let now = self.services.clock.now();
        let transaction = state.store.transaction(self.services.audit.as_ref())?;
        let rows = {
            let mut statement = transaction.prepare("SELECT object_json, authority_json, budget_left_json, session_id FROM grants
                WHERE revoked_at IS NULL AND nbf<=?1 AND (exp IS NULL OR exp>=?1) AND jti NOT IN (SELECT jti FROM revoked_jti) ORDER BY jti")?;
            let rows = statement.query_map([now], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, Option<String>>(2)?,
                    r.get::<_, Option<String>>(3)?,
                ))
            })?;
            rows.collect::<std::result::Result<Vec<_>, _>>()?
        };
        let mut matches = Vec::new();
        for (object, authority, left, session) in rows {
            let grant: Grant = decode(&object)?;
            let authority: Value = decode(&authority)?;
            let device = match state.store.device(&grant.iss, &self.account) {
                Ok(device) => device,
                Err(error) => {
                    self.reject(&state, "grant_rejected", error, &grant.jti)?;
                    continue;
                }
            };
            match authority["kind"].as_str() {
                Some("grant") => {
                    let level: ApprovalLevel = serde_json::from_value(authority["level"].clone())?;
                    if let Err(error) = verify_grant(
                        &grant,
                        &self.local.device_id,
                        &self.label(&state)?,
                        &device,
                        level,
                        now,
                    ) {
                        self.reject(&state, "grant_rejected", error.into(), &grant.jti)?;
                        continue;
                    }
                }
                Some("approval_decision") => {
                    let decision: ApprovalDecision =
                        serde_json::from_value(authority["decision"].clone())?;
                    let request: ApprovalRequest =
                        serde_json::from_value(authority["request"].clone())?;
                    let canonical: CanonicalRequest =
                        serde_json::from_value(authority["canonical"].clone())?;
                    let verified_at = authority["verified_at"]
                        .as_i64()
                        .ok_or(Error("invalid_grant"))?;
                    let pending = state.store.pending(&decision.approval_id)?;
                    let expected_session = matches!(
                        decision.scope.mode,
                        ScopeMode::PerCredential | ScopeMode::PerSession
                    )
                    .then_some(pending.session_id.as_str());
                    let authority_valid =
                        verify_decision(&decision, &request, &canonical, &device, verified_at)
                            .is_ok()
                            && decision.decision == Decision::Allow
                            && canonical == pending.canonical
                            && request == pending.request
                            && pending.decision.as_ref() == Some(&decision)
                            && session.as_deref() == expected_session
                            && derived_grant(
                                &pending,
                                &decision,
                                &device,
                                verified_at,
                                &self.local.device_id,
                            )? == grant;
                    if !authority_valid {
                        self.reject(&state, "grant_rejected", Error("invalid_grant"), &grant.jti)?;
                        continue;
                    }
                    if decision.scope.mode == ScopeMode::PerUse
                        && super::pipeline::retry_binding(&canonical)?
                            != super::pipeline::retry_binding(&usage.canonical)?
                    {
                        continue;
                    }
                }
                _ => {
                    self.reject(
                        &state,
                        "grant_rejected",
                        Error("unsupported_authority"),
                        &grant.jti,
                    )?;
                    continue;
                }
            }
            if session
                .as_ref()
                .is_some_and(|session| session != &usage.session_id)
                || !matches_scope(&grant, usage)?
            {
                continue;
            }
            let Some(left) = debit(&grant, left.as_deref(), usage.body_bytes, now)? else {
                continue;
            };
            matches.push((grant, left));
        }
        let max_tier = matches.iter().map(|(grant, _)| grant.scope.max_tier).min();
        let jtis = matches
            .iter()
            .map(|(grant, _)| grant.jti.clone())
            .collect::<Vec<_>>();
        for (grant, left) in &matches {
            transaction.execute(
                "INSERT INTO grant_use_stats(jti,uses_n,last_used_at) VALUES(?1,1,?2)
                ON CONFLICT(jti) DO UPDATE SET uses_n=uses_n+1,last_used_at=excluded.last_used_at",
                params![grant.jti, now],
            )?;
            if grant.budget.as_value().is_some() {
                transaction.execute(
                    "UPDATE grants SET budget_left_json=?1 WHERE jti=?2",
                    params![encode(left)?, grant.jti],
                )?;
                if left["calls_left"] == 0 || left["bytes_left"] == 0 {
                    self.audit(
                        &state,
                        "grant_exhausted",
                        json!({"jti": grant.jti, "iss": grant.iss}),
                    )?;
                }
            }
        }
        let unattended = usage.tier == Tier::T2 && !jtis.is_empty();
        if !jtis.is_empty() {
            self.audit(
                &state,
                "use",
                json!({"digest": usage.canonical.digest()?, "tier": usage.tier, "jtis": jtis,
                "approval_path": format!("grant:{}", jtis.join(",")), "unattended_t2": unattended}),
            )?;
            if unattended {
                self.audit(
                    &state,
                    "unattended_t2",
                    json!({"digest": usage.canonical.digest()?, "jtis": jtis}),
                )?;
            }
        }
        transaction.commit()?;
        Ok(Coverage {
            jtis,
            max_tier,
            unattended_t2: unattended,
        })
    }

    pub fn revoke_grant(&self, jti: &str, by: &str) -> Result<()> {
        let state = self.lock()?;
        let transaction = state.store.transaction(self.services.audit.as_ref())?;
        self.revoke_grant_locked(&state, jti, by)?;
        transaction.commit()?;
        Ok(())
    }

    pub(crate) fn revoke_grant_locked(&self, state: &State, jti: &str, by: &str) -> Result<()> {
        let now = self.services.clock.now();
        state.store.db.execute(
            "INSERT INTO revoked_jti (jti, revoked_at) VALUES (?1, ?2) ON CONFLICT(jti) DO NOTHING",
            params![jti, now],
        )?;
        state.store.db.execute(
            "UPDATE grants SET revoked_at=COALESCE(revoked_at, ?1) WHERE jti=?2",
            params![now, jti],
        )?;
        self.audit(state, "grant_revoked", json!({"jti": jti, "by": by}))
    }

    #[cfg(test)]
    pub(crate) fn grant_list_locked(&self, state: &State) -> Result<Vec<Value>> {
        self.installed_grants_page(state, &kv_ipc::remote::GrantListParams::default())
    }

    pub(crate) fn installed_grants_page(
        &self,
        state: &State,
        query: &kv_ipc::remote::GrantListParams,
    ) -> Result<Vec<Value>> {
        super::pages::validate(query)?;
        let mut statement = state.store.db.prepare("SELECT object_json, budget_left_json, revoked_at, authority_json FROM grants WHERE jti>?1 ORDER BY jti LIMIT ?2")?;
        let rows = statement.query_map(
            params![
                query.after.as_deref().unwrap_or(""),
                u32::from(query.limit) + 1
            ],
            |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, Option<String>>(1)?,
                    r.get::<_, Option<i64>>(2)?,
                    r.get::<_, String>(3)?,
                ))
            },
        )?;
        rows.map(|row| {
            let (object, left, revoked, authority) = row?;
            let mut grant: Value = decode(&object)?;
            grant.as_object_mut().ok_or(Error("invalid_grant"))?.insert(
                "budget_left".into(),
                left.as_deref()
                    .map(decode::<Value>)
                    .transpose()?
                    .unwrap_or(Value::Null),
            );
            grant["revoked_at"] = json!(revoked);
            grant["authority"] = decode::<Value>(&authority)?["kind"].clone();
            let usage: Option<(u64, i64)> = state
                .store
                .db
                .query_row(
                    "SELECT uses_n,last_used_at FROM grant_use_stats WHERE jti=?1",
                    [grant["jti"].as_str().ok_or(Error("invalid_grant"))?],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .optional()?;
            grant["uses_n"] = json!(usage.map_or(0, |entry| entry.0));
            grant["last_used_at"] = json!(usage.map(|entry| entry.1));
            grant["ledger"] = json!("installed");
            Ok(grant)
        })
        .collect()
    }
}

fn matches_scope(grant: &Grant, usage: &GrantUse) -> Result<bool> {
    if usage.canonical.kind != ApprovalKind::Use || usage.tier > grant.scope.max_tier {
        return Ok(false);
    }
    if grant.scope.level == GrantScopeLevel::Credential
        && grant.scope.credential.as_value() != usage.canonical.credential.as_ref()
    {
        return Ok(false);
    }
    if let Some(host) = &usage.canonical.host {
        let hosts = grant
            .scope
            .hosts
            .as_value()
            .unwrap_or(&usage.template_allowed_hosts);
        if !hosts
            .iter()
            .any(|allowed| allowed.eq_ignore_ascii_case(host))
            || !usage
                .template_allowed_hosts
                .iter()
                .any(|allowed| allowed.eq_ignore_ascii_case(host))
        {
            return Ok(false);
        }
    } else if grant.scope.hosts.as_value().is_some() {
        return Ok(false);
    }
    if let Some(method) = &usage.canonical.method {
        let methods = grant
            .scope
            .methods
            .as_value()
            .unwrap_or(&usage.policy_allowed_methods);
        if !methods.contains(method) || !usage.policy_allowed_methods.contains(method) {
            return Ok(false);
        }
    } else if grant.scope.methods.as_value().is_some() {
        return Ok(false);
    }
    if let Some(paths) = grant.scope.paths.as_value() {
        let Some(path) = &usage.canonical.path else {
            return Ok(false);
        };
        let normalized = normalize_path(path)?;
        if !paths.iter().any(|pattern| glob(pattern, &normalized)) {
            return Ok(false);
        }
    }
    if let Some(agent) = grant.scope.agent.as_value() {
        if *agent
            != format!(
                "{}:{}",
                usage.canonical.agent.runtime, usage.canonical.agent.repo_or_cwd
            )
        {
            return Ok(false);
        }
    }
    Ok(true)
}

fn debit(grant: &Grant, previous: Option<&str>, bytes: u64, now: i64) -> Result<Option<Value>> {
    let Some(budget) = grant.budget.as_value() else {
        return Ok(Some(Value::Null));
    };
    let period = match budget.per {
        BudgetPeriod::OneHour => 3600,
        BudgetPeriod::OneDay => 86400,
        BudgetPeriod::SevenDays => 604800,
    };
    let bucket = now.saturating_sub(grant.nbf) / period;
    let previous = previous.map(decode::<Value>).transpose()?;
    let same = previous
        .as_ref()
        .is_some_and(|value| value["bucket"].as_i64() == Some(bucket));
    let calls = if same {
        previous
            .as_ref()
            .and_then(|v| v["calls_left"].as_u64())
            .ok_or(Error("invalid_budget"))?
    } else {
        budget.calls
    };
    let byte_left = if same {
        previous.as_ref().and_then(|v| v["bytes_left"].as_u64())
    } else {
        budget.bytes.as_value().copied()
    };
    if calls == 0 || byte_left.is_some_and(|left| left < bytes) {
        return Ok(None);
    }
    Ok(Some(
        json!({"bucket": bucket, "calls_left": calls - 1, "bytes_left": byte_left.map(|left| left - bytes)}),
    ))
}

fn derived_grant(
    pending: &Pending,
    decision: &ApprovalDecision,
    device: &DeviceRecord,
    now: i64,
    audience: &str,
) -> Result<Grant> {
    let ttl = pending
        .canonical
        .extra
        .get("unlock_ttl_s")
        .and_then(Value::as_u64)
        .unwrap_or(43200);
    let level = if decision.scope.mode == ScopeMode::PerSession
        || decision.scope.level == DecisionScopeLevel::Device
    {
        GrantScopeLevel::Device
    } else {
        GrantScopeLevel::Credential
    };
    let exp = match decision.scope.mode {
        ScopeMode::Standing => None,
        ScopeMode::Remember => Some(decision.scope.until),
        ScopeMode::PerUse => Some(now.saturating_add(30)),
        _ => Some(now.saturating_add(ttl as i64)),
    };
    let limits = pending.canonical.extra.get("grant_limits");
    let hosts = limits
        .and_then(|v| v.get("hosts"))
        .map(|v| serde_json::from_value::<Vec<String>>(v.clone()))
        .transpose()?
        .or_else(|| pending.canonical.host.clone().map(|host| vec![host]));
    let methods = limits
        .and_then(|v| v.get("methods"))
        .map(|v| serde_json::from_value::<Vec<String>>(v.clone()))
        .transpose()?
        .or_else(|| pending.canonical.method.clone().map(|method| vec![method]));
    let grant = Grant {
        kind: GrantKind::Grant,
        jti: format!("approval:{}", decision.approval_id),
        iss: decision.approver.clone(),
        iss_alg: approval_key(device, decision.level)?.alg,
        iss_kind: IssuerKind::Device,
        aud: audience.into(),
        scope: GrantScope {
            level,
            credential: if level == GrantScopeLevel::Credential {
                Optional::Value(
                    pending
                        .canonical
                        .credential
                        .clone()
                        .ok_or(Error("invalid_scope"))?,
                )
            } else {
                Optional::Missing
            },
            hosts: hosts.map_or(Optional::Missing, Optional::Value),
            methods: methods.map_or(Optional::Missing, Optional::Value),
            paths: Optional::Missing,
            agent: Optional::Missing,
            max_tier: Tier::T1,
            extra: Extra::new(),
        },
        budget: Optional::Missing,
        nbf: now,
        exp,
        origin: format!("approval:{}", decision.approval_id),
        confirm: Optional::Missing,
        // This is an internal derived grant. Its authority is the original signed decision,
        // not a fabricated signature over the derived fields. It is never sent as a Grant.
        sig: String::new(),
        extra: Extra::new(),
    };
    Ok(grant)
}
