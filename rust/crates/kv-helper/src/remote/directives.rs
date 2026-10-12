use super::engine::{signing_level, State};
use super::store::{encode, PendingState};
use super::{Error, RemoteHelper, Result};
use kv_core::remote::canonical::{jcs, sha256_hex};
use kv_core::remote::keys::verify_object;
use kv_core::remote::validation::{approval_key, directive_required_level, DirectiveState};
use kv_core::remote::*;
use rusqlite::params;
use serde_json::{json, Value};

impl RemoteHelper {
    pub fn apply_directive(
        &self,
        directive: &Directive,
        level: ApprovalLevel,
    ) -> Result<DirectiveResult> {
        let mut state = self.lock()?;
        let result = (|| {
            let device = state.store.device(&directive.iss, &self.account)?;
            self.apply_directive_locked(&mut state, directive, &device, Some(level))
        })();
        if let Err(error) = result {
            self.audit(
                &state,
                "directive_rejected",
                json!({"id": directive.id, "iss": directive.iss,
                "directive_op": directive.op, "reason": error.code(), "ok": false}),
            )?;
        }
        drop(state);
        self.changed.notify_waiters();
        result
    }

    pub(crate) fn directive_state(&self, state: &State) -> Result<DirectiveState> {
        let classes = state
            .store
            .setting::<Value>("classes")?
            .unwrap_or_else(|| json!({}));
        let mut current = DirectiveState {
            mode: Some(
                state
                    .store
                    .setting::<String>("mode")?
                    .ok_or(Error("missing_state"))?,
            ),
            unlock_ttl_s: Some(
                state
                    .store
                    .setting::<u64>("unlock_ttl")?
                    .unwrap_or(self.config.unlock_ttl_s),
            ),
            classes: Default::default(),
        };
        for class in &self.config.class {
            current.classes.insert(
                class.name.clone(),
                (
                    json!({"credential": class.r#match.credential, "host": class.r#match.host}),
                    class.exp_s,
                ),
            );
        }
        for (name, class) in classes.as_object().ok_or(Error("invalid_approval_class"))? {
            current.classes.insert(
                name.clone(),
                (
                    class["match"].clone(),
                    class["exp_s"]
                        .as_u64()
                        .ok_or(Error("invalid_approval_class"))?,
                ),
            );
        }
        Ok(current)
    }

    pub(crate) fn apply_directive_locked(
        &self,
        state: &mut State,
        directive: &Directive,
        device: &DeviceRecord,
        level: Option<ApprovalLevel>,
    ) -> Result<DirectiveResult> {
        let now = self.services.clock.now();
        if directive.iss_kind != IssuerKind::Device {
            return Err(Error("unsupported_authority"));
        }
        if directive.iss != device.device_id {
            return Err(Error("wrong_sender"));
        }
        // §7.5: verify AK signature, then the direction's required level, then nonce, then exp.
        let level = match level {
            Some(level) => level,
            None => signing_level(directive, &directive.sig, directive.iss_alg, device)?,
        };
        let key = approval_key(device, level)?;
        if key.alg != directive.iss_alg {
            return Err(Error("unsupported_algorithm"));
        }
        verify_object(directive, &directive.sig, key)?;
        if directive.aud != self.local.device_id && directive.aud != "*" {
            return Err(Error("wrong_recipient"));
        }
        if level < directive_required_level(directive, &self.directive_state(state)?)? {
            return Err(Error("insufficient_level"));
        }
        if directive.op == DirectiveOp::RevokeDevice
            && directive.args.get("confirm").and_then(Value::as_str)
                != Some(self.label(state)?.as_str())
        {
            return Err(Error("secondary_confirmation_required"));
        }
        let transaction = state.store.transaction(self.services.audit.as_ref())?;
        state.store.consume_nonce(
            &directive.nonce,
            &sha256_hex(&jcs(directive)?),
            now,
            directive.exp,
        )?;
        if directive.exp < now {
            return Err(Error("expired"));
        }
        // Insert the id before executing. A different nonce cannot reuse a directive id.
        transaction.execute("INSERT INTO directives (id, iss, op, args_json, applied_at, ok) VALUES (?1, ?2, ?3, ?4, ?5, 1)",
            params![directive.id, directive.iss, encode(&directive.op)?.trim_matches('"'), encode(&directive.args)?, now])?;
        let by = format!("remote:{}", directive.iss);
        let mut cancelled = Vec::new();
        let value = match directive.op {
            DirectiveOp::SetMode => {
                let args: SetModeArgs = directive.args_as()?;
                self.setting_changed(state, "mode", &json!(args.mode), &by)?;
                json!({"mode": args.mode})
            }
            DirectiveOp::RevokeGrant => {
                let args: RevokeGrantArgs = directive.args_as()?;
                self.revoke_grant_locked(state, &args.jti, &by)?;
                json!({})
            }
            DirectiveOp::RevokeAllGrants => {
                self.revoke_all_locked(state, &by)?;
                json!({"grants_n": 0})
            }
            DirectiveOp::Lock => {
                let epoch = state
                    .store
                    .setting::<u64>("epoch")?
                    .unwrap_or(0)
                    .checked_add(1)
                    .ok_or(Error("state_unavailable"))?;
                state.store.set_setting("epoch", &epoch, &by, now)?;
                state
                    .store
                    .db
                    .execute("DELETE FROM settings WHERE key LIKE 'unlock:%'", [])?;
                self.revoke_all_locked(state, &by)?;
                // Session revocation is synchronous and cannot wait behind a user prompt.
                self.services.runner.lock_sessions()?;
                for id in state.store.pending_ids()? {
                    if !matches!(
                        state.store.pending(&id)?.state,
                        PendingState::Waiting
                            | PendingState::Approved
                            | PendingState::ApprovedUnused
                    ) {
                        continue;
                    }
                    self.cancel_in_transaction(state, &id, PendingState::Cancelled)?;
                    cancelled.push(id);
                }
                json!({"locked": true})
            }
            DirectiveOp::SetUnlockTtl => {
                let args: SetUnlockTtlArgs = directive.args_as()?;
                self.setting_changed(state, "unlock_ttl", &json!(args.seconds), &by)?;
                state.store.db.execute("UPDATE settings SET value_json=CAST(?1 AS TEXT) WHERE key LIKE 'unlock:%' AND CAST(value_json AS INTEGER)>?1",
                    [now.saturating_add(args.seconds as i64)])?;
                json!({"unlock_ttl_s": args.seconds})
            }
            DirectiveOp::SetClass => {
                let args: SetClassArgs = directive.args_as()?;
                if args.name.is_empty()
                    || args.r#match.is_empty()
                    || args.r#match.iter().any(|(key, value)| {
                        !matches!(key.as_str(), "credential" | "host") || !value.is_string()
                    })
                {
                    return Err(Error("invalid_approval_class"));
                }
                let mut classes = state
                    .store
                    .setting::<Value>("classes")?
                    .unwrap_or_else(|| json!({}));
                classes
                    .as_object_mut()
                    .ok_or(Error("invalid_approval_class"))?
                    .insert(
                        args.name,
                        json!({"match": args.r#match, "exp_s": args.exp_s}),
                    );
                self.setting_changed(state, "classes", &classes, &by)?;
                json!({"classes": classes})
            }
            DirectiveOp::SetDeviceLabel => {
                let args: SetDeviceLabelArgs = directive.args_as()?;
                self.rename_device_rows(state, &self.local.device_id, &args.label)?;
                self.setting_changed(state, "device_label", &json!(args.label), &by)?;
                json!({"label": args.label})
            }
            DirectiveOp::RevokeDevice => {
                let args: RevokeDeviceArgs = directive.args_as()?;
                self.revoke_device_rows(state, &args.device_id, &by)?;
                for id in state.store.pending_ids()? {
                    if state.store.pending(&id)?.state != PendingState::Cancelled {
                        continue;
                    }
                    cancelled.push(id);
                }
                json!({"revoked": args.device_id})
            }
            DirectiveOp::Notify => {
                let args: NotifyArgs = directive.args_as()?;
                self.setting_changed(state, "notify", &json!(args.policy), &by)?;
                json!({"notify": args.policy})
            }
            DirectiveOp::QueryStatus => self.status_locked(state, 60)?,
            DirectiveOp::QueryPending => json!({"pending": self.pending_summaries(state, None)?}),
            DirectiveOp::QueryGrants => {
                let query: kv_ipc::remote::GrantListParams = directive.args_as()?;
                super::pages::page(self.installed_grants_page(state, &query)?, &query)?
            }
            DirectiveOp::QueryAudit => {
                let args: QueryAuditArgs = directive.args_as()?;
                serde_json::to_value(state.store.audit_page(
                    &args,
                    &self.account,
                    &self.local.device_id,
                    self.services.audit.as_ref(),
                )?)?
            }
            DirectiveOp::CancelApproval => {
                let args: CancelApprovalArgs = directive.args_as()?;
                self.cancel_in_transaction(state, &args.approval_id, PendingState::Cancelled)?;
                cancelled.push(args.approval_id.clone());
                json!({"cancelled": args.approval_id})
            }
        };
        let directory_update = self.stage_directory(state)?;
        self.audit(state, "directive_applied", json!({"id": directive.id, "iss": directive.iss, "directive_op": directive.op, "ok": true, "directive_hash":kv_core::remote::canonical::sha256_hex(&jcs(directive)?)}))?;
        transaction.commit()?;
        directory_update.commit()?;
        // Publication interruptions are recoverable from the authenticated directory journal.
        for id in cancelled {
            state.full.remove(&id);
        }
        Ok(DirectiveResult {
            id: directive.id.clone(),
            ok: true,
            error: None,
            state: value.as_object().cloned().unwrap_or_default(),
            extra: Extra::new(),
        })
    }

    pub(crate) fn setting_changed(
        &self,
        state: &State,
        key: &str,
        value: &Value,
        by: &str,
    ) -> Result<()> {
        if key == "mode" {
            return self.change_mode_locked(
                state,
                value.as_str().ok_or(Error("invalid_settings"))?,
                by,
            );
        }
        state
            .store
            .set_setting(key, value, by, self.services.clock.now())?;
        self.audit(state, "setting_changed", json!({"key": key, "by": by}))
    }

    pub fn set_mode_local(&self, mode: &str, level: ApprovalLevel) -> Result<()> {
        let state = self.lock()?;
        let directive = Directive {
            kind: DirectiveKind::Directive,
            id: String::new(),
            iss: self.local.device_id.clone(),
            iss_alg: SignatureAlgorithm::ES256,
            iss_kind: IssuerKind::Device,
            aud: self.local.device_id.clone(),
            op: DirectiveOp::SetMode,
            args: json!({"mode": mode})
                .as_object()
                .cloned()
                .unwrap_or_default(),
            nonce: String::new(),
            exp: self.services.clock.now(),
            sig: String::new(),
            extra: Extra::new(),
        };
        let required = directive_required_level(&directive, &self.directive_state(&state)?)?;
        if level < required {
            self.reject(&state, "setting_rejected", Error("insufficient_level"), "")?;
            return Err(Error("insufficient_level"));
        }
        let transaction = state.store.transaction(self.services.audit.as_ref())?;
        self.setting_changed(&state, "mode", &json!(mode), "local")?;
        transaction.commit()?;
        Ok(())
    }

    pub fn mode(&self) -> Result<String> {
        self.lock()?
            .store
            .setting("mode")?
            .ok_or(Error("missing_state"))
    }

    fn revoke_all_locked(&self, state: &State, by: &str) -> Result<()> {
        let now = self.services.clock.now();
        state.store.db.execute("INSERT INTO revoked_jti (jti, revoked_at) SELECT jti, ?1 FROM grants WHERE revoked_at IS NULL ON CONFLICT(jti) DO NOTHING", [now])?;
        state.store.db.execute(
            "UPDATE grants SET revoked_at=?1 WHERE revoked_at IS NULL",
            [now],
        )?;
        self.audit(state, "grant_revoked", json!({"all": true, "by": by}))
    }

    pub fn revoke_device(&self, id: &str, by: &str) -> Result<()> {
        let mut state = self.lock()?;
        let result = (|| {
            let transaction = state.store.transaction(self.services.audit.as_ref())?;
            let cancelled = self.revoke_device_rows(&state, id, by)?;
            let directory_update = self.stage_directory(&state)?;
            transaction.commit()?;
            directory_update.commit()?;
            Ok(cancelled)
        })();
        match result {
            Ok(cancelled) => {
                Self::clear_revoked_device_state(&mut state, id, cancelled);
            }
            Err(error) => {
                self.reject(&state, "device_revoke_rejected", error, id)?;
                return Err(error);
            }
        }
        drop(state);
        self.changed.notify_waiters();
        Ok(())
    }

    pub(crate) fn clear_revoked_device_state(state: &mut State, id: &str, cancelled: Vec<String>) {
        state.hints.remove(id);
        state
            .inbound_requests
            .retain(|_, request| request.requester.device_id != id);
        for pending_id in cancelled {
            state.full.remove(&pending_id);
            if let Some(mut value) = state.results.remove(&pending_id) {
                kv_vault::scrub_json(&mut value);
            }
        }
    }

    pub(crate) fn revoke_device_rows(
        &self,
        state: &State,
        id: &str,
        by: &str,
    ) -> Result<Vec<String>> {
        let now = self.services.clock.now();
        let known: bool = state.store.db.query_row(
            "SELECT EXISTS(SELECT 1 FROM devices WHERE id=?1 AND account_id=?2)",
            params![id, self.account],
            |r| r.get(0),
        )?;
        if !known {
            return Err(Error("unpaired_device"));
        }
        state.store.db.execute(
            "UPDATE devices SET revoked_at=COALESCE(revoked_at,?1), trust='revoked' WHERE id=?2",
            params![now, id],
        )?;
        state.store.db.execute("INSERT INTO revoked_jti (jti, revoked_at) SELECT jti, ?1 FROM grants WHERE iss=?2 ON CONFLICT(jti) DO NOTHING", params![now, id])?;
        state.store.db.execute(
            "UPDATE grants SET revoked_at=?1 WHERE iss=?2 AND revoked_at IS NULL",
            params![now, id],
        )?;
        state.store.db.execute("UPDATE pending_approvals SET state='cancelled', resolved_at=?1 WHERE approver=?2 AND state IN ('approved','approved_unused')", params![now, id])?;
        self.audit(state, "device_revoked", json!({"device_id": id, "by": by}))?;
        let mut cancelled = Vec::new();
        for pending_id in state.store.pending_ids()? {
            if state.store.pending(&pending_id)?.state == PendingState::Cancelled {
                cancelled.push(pending_id);
            }
        }
        Ok(cancelled)
    }

    pub(crate) fn pending_summaries(
        &self,
        state: &State,
        agent_pid: Option<u32>,
    ) -> Result<Vec<Value>> {
        let mut summaries = Vec::new();
        for id in state.store.pending_ids()? {
            let pending = state.store.pending(&id)?;
            if matches!(
                pending.state,
                PendingState::Waiting | PendingState::Approved | PendingState::ApprovedUnused
            ) && agent_pid.is_none_or(|pid| pid == pending.canonical.agent.pid)
            {
                summaries.push(json!({"approval_id": id, "kind": pending.request.kind, "tier": pending.request.tier,
                    "summary": pending.request.operation.as_ref().map(|o| &o.summary), "expires_at": pending.request.exp,
                    "state": pending.state.as_str(), "agent_pid": pending.canonical.agent.pid}));
            }
        }
        Ok(summaries)
    }

    pub(crate) fn status_locked(&self, state: &State, runtime_budget_s: u64) -> Result<Value> {
        let now = self.services.clock.now();
        let peers = state.store.devices(&self.account)?;
        let approvers = peers.iter().filter(|peer| super::engine::is_approver(peer)).map(|peer| json!({"device_id": peer.device_id,
            "label": peer.label, "online": state.relay_connected && state.hints.get(&peer.device_id).is_some_and(|hint| now.saturating_sub(hint.received_at) <= 120), "attestation": "unverified"})).collect::<Vec<_>>();
        let grants: u64 = state.store.db.query_row("SELECT COUNT(*) FROM grants WHERE revoked_at IS NULL AND nbf<=?1 AND (exp IS NULL OR exp>=?1)", [now], |r| r.get(0))?;
        let unattended: bool = state.store.db.query_row("SELECT EXISTS(SELECT 1 FROM grants WHERE max_tier='T2' AND revoked_at IS NULL AND nbf<=?1 AND (exp IS NULL OR exp>=?1))", [now], |r| r.get(0))?;
        let issued_grants: u64 = state.store.db.query_row("SELECT COUNT(*) FROM issued_grants i WHERE revoked_at IS NULL AND (exp IS NULL OR exp>=?1)
            AND NOT EXISTS(SELECT 1 FROM grants g WHERE g.jti=i.jti AND g.revoked_at IS NULL AND g.nbf<=?1 AND (g.exp IS NULL OR g.exp>=?1))",[now],|r|r.get(0))?;
        let issued_unattended: bool = state.store.db.query_row("SELECT EXISTS(SELECT 1 FROM issued_grants WHERE max_tier='T2' AND revoked_at IS NULL AND (exp IS NULL OR exp>=?1))",[now],|r|r.get(0))?;
        let device_revocations_pending: u64 = state.store.db.query_row(
            "SELECT COUNT(*) FROM device_revocations WHERE relay_done=0",
            [],
            |r| r.get(0),
        )?;
        Ok(
            json!({"relay": if state.relay_connected { "connected" } else { "offline" }, "approvers": approvers,
            "pending_n": self.pending_summaries(state, None)?.len() + state.inbound_requests.len(), "grants_n": grants + issued_grants, "unattended": unattended || issued_unattended,
            "device_id":self.local.device_id,"account_id":self.account,
            "device_revocations_pending":device_revocations_pending,
            "runtime_budget_s": runtime_budget_s, "mode": state.store.setting::<String>("mode")?,
            "unlock_ttl_s": state.store.setting::<u64>("unlock_ttl")?.unwrap_or(self.config.unlock_ttl_s), "label": self.label(state)?,
            "approval": {"wait_in_call_s": self.config.wait_in_call_s,
                "wait_tool_max_s": self.config.wait_tool_max_s,
                "progress_interval_s": self.config.progress_interval_s}}),
        )
    }
}
