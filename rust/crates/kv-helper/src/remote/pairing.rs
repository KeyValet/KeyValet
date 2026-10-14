use super::engine::{random_nonce, validate_device, State};
use super::{Error, RemoteHelper, Result};
use kv_core::remote::canonical::{from_json, sha256_hex};
use kv_core::remote::keys::{decode_b64, encode_b64};
use kv_core::remote::*;
use serde_json::json;
use zeroize::Zeroizing;

pub(crate) struct Pairing {
    token: Zeroizing<Vec<u8>>,
    pub exp: i64,
    candidate: Option<DeviceRecord>,
    sas: Option<String>,
    terminal_confirmed: bool,
    strong_confirmed: bool,
    exclude_global: bool,
    peer_global_grants: u64,
    local_confirmation: Option<(PairConfirm, Envelope)>,
    pub transport: Option<super::pairing_relay::PairTransport>,
}

impl RemoteHelper {
    pub(crate) fn pairing_status(&self, state: &State) -> Result<serde_json::Value> {
        Ok(match &state.pairing {
            Some(pairing) => json!({"sas": pairing.sas, "expires_at": pairing.exp,
                "candidate": pairing.candidate, "terminal_confirmed":pairing.terminal_confirmed,
                "global_grants":pairing.peer_global_grants + if pairing.candidate.as_ref().is_some_and(|p|p.caps.contains(&Capability::Execute)) {self.global_grants_n(state)?} else {0}}),
            None => state.pair_result.clone().unwrap_or(serde_json::Value::Null),
        })
    }
    fn global_grants_n(&self, state: &State) -> Result<u64> {
        Ok(state.store.db.query_row("SELECT COUNT(*) FROM issued_grants g WHERE peer='*' AND revoked_at IS NULL
            AND (exp IS NULL OR exp>=?1) AND NOT EXISTS(SELECT 1 FROM issued_grant_revocations r WHERE r.jti=g.jti)",
            [self.services.clock.now()],|r|r.get(0))?)
    }
    /// The CLI renders the URI and QR code. Neither tokens nor SAS codes are audited.
    pub fn pair_start(&self, relay_url: &str) -> Result<kv_ipc::remote::PairSasResult> {
        let authority = relay_url
            .strip_prefix("https://")
            .ok_or(Error("invalid_relay_url"))?;
        if authority.is_empty() || authority.contains(['/', '?', '#', '@', ' ', '\\']) {
            return Err(Error("invalid_relay_url"));
        }
        let token_text = Zeroizing::new(random_nonce()?);
        let token = Zeroizing::new(decode_b64(&token_text)?);
        let now = self.services.clock.now();
        let offer = PairOffer {
            token_hash: sha256_hex(&token),
            initiator: self.local.clone(),
            extra: Extra::new(),
        };
        let uri = Zeroizing::new(format!("kv-pair://{authority}/{}", base32(&token)));
        let mut state = self.lock()?;
        state.pair_result = None;
        state.pairing = Some(Pairing {
            token,
            exp: now.saturating_add(600),
            candidate: None,
            sas: None,
            terminal_confirmed: false,
            strong_confirmed: false,
            exclude_global: false,
            peer_global_grants: 0,
            local_confirmation: None,
            transport: None,
        });
        self.audit(
            &state,
            "pair_started",
            json!({"expires_at": now.saturating_add(600)}),
        )?;
        Ok(kv_ipc::remote::PairSasResult { sas: String::new(), extra: json!({
            "offer": offer, "token": token_text.as_str(), "uri": uri.as_str(), "qr_data": uri.as_str(), "expires_at": now.saturating_add(600)
        }).as_object().cloned().unwrap_or_default() })
    }

    pub fn pair_complete(&self, accept: PairAccept) -> Result<kv_ipc::remote::PairSasResult> {
        let mut state = self.lock()?;
        let result = self.accept_pair_locked(&mut state, accept);
        if let Err(error) = result {
            self.pair_failed(&mut state, error)?;
        }
        result
    }

    /// Called only after the vault owner's terminal has displayed the SAS and received `y`.
    pub fn pair_confirm_terminal(&self, confirm: &PairConfirm) -> Result<()> {
        let mut state = self.lock()?;
        let result = (|| {
            let pairing = state.pairing.as_mut().ok_or(Error("unknown_token"))?;
            if pairing.exp < self.services.clock.now() {
                return Err(Error("expired"));
            }
            if !confirm.sig.is_empty() || pairing.sas.as_deref() != Some(&confirm.sas) {
                return Err(Error("pair_sas_mismatch"));
            }
            if pairing.terminal_confirmed {
                return Err(Error("replay"));
            }
            pairing.terminal_confirmed = true;
            pairing.exclude_global |= confirm.extra.get("exclude_global") == Some(&json!(true));
            self.finish_pair_locked(&mut state)
        })();
        if let Err(error) = result {
            self.pair_failed(&mut state, error)?;
        }
        result
    }

    pub fn pair_confirm_signed(&self, confirm: &PairConfirm) -> Result<()> {
        let mut state = self.lock()?;
        let result = self.confirm_signed_locked(&mut state, confirm);
        if let Err(error) = result {
            self.pair_failed(&mut state, error)?;
        }
        result
    }

    fn confirm_signed_locked(&self, state: &mut State, confirm: &PairConfirm) -> Result<()> {
        let pairing = state.pairing.as_mut().ok_or(Error("unknown_token"))?;
        if pairing.exp < self.services.clock.now() {
            return Err(Error("expired"));
        }
        let candidate = pairing
            .candidate
            .as_ref()
            .ok_or(Error("pair_not_accepted"))?;
        if pairing
            .transport
            .as_ref()
            .is_some_and(|transport| transport.joiner)
        {
            if pairing.terminal_confirmed {
                return Err(Error("replay"));
            }
            if let Some(key) = candidate.ak_s.as_ref() {
                kv_core::remote::pairing::verify_confirm(
                    confirm,
                    pairing.sas.as_deref().ok_or(Error("pair_not_accepted"))?,
                    key,
                )?;
                let record: DeviceRecord = serde_json::from_value(
                    confirm
                        .extra
                        .get("device")
                        .cloned()
                        .ok_or(Error("pair_key_mismatch"))?,
                )?;
                if !super::directory::same_authority(candidate, &record) {
                    return Err(Error("pair_key_mismatch"));
                }
                pairing.candidate.as_mut().unwrap().label = record.label;
            } else if !confirm.sig.is_empty()
                || pairing.sas.as_deref() != Some(confirm.sas.as_str())
            {
                return Err(Error("pair_sas_mismatch"));
            }
            pairing.terminal_confirmed = true;
            pairing.exclude_global |= confirm.extra.get("exclude_global") == Some(&json!(true));
            return self.finish_pair_locked(state);
        }
        if pairing.strong_confirmed {
            return Err(Error("replay"));
        }
        if let Some(key) = candidate.ak_s.as_ref() {
            kv_core::remote::pairing::verify_confirm(
                confirm,
                pairing.sas.as_deref().ok_or(Error("pair_not_accepted"))?,
                key,
            )
            .map_err(|error| {
                if error == RemoteError::DigestMismatch {
                    Error("pair_sas_mismatch")
                } else {
                    error.into()
                }
            })?;
        } else if self.local.ak_s.is_none()
            || !confirm.sig.is_empty()
            || pairing.sas.as_deref() != Some(confirm.sas.as_str())
        {
            return Err(Error("strong_key_required"));
        }
        if pairing.transport.is_some() {
            let record: DeviceRecord = serde_json::from_value(
                confirm
                    .extra
                    .get("device")
                    .cloned()
                    .ok_or(Error("pair_key_mismatch"))?,
            )?;
            if !super::directory::same_authority(candidate, &record) {
                return Err(Error("pair_key_mismatch"));
            }
            pairing.candidate.as_mut().unwrap().label = record.label;
        }
        pairing.strong_confirmed = true;
        pairing.exclude_global |= confirm.extra.get("exclude_global") == Some(&json!(true));
        self.finish_pair_locked(state)
    }

    pub(crate) fn receive_pairing(&self, state: &mut State, envelope: &Envelope) -> Result<()> {
        if state
            .pairing
            .as_ref()
            .and_then(|pairing| pairing.transport.as_ref())
            .is_some_and(|transport| transport.pairing_id != envelope.id)
        {
            return Err(Error("wrong_pairing"));
        }
        let result = (|| {
            let pairing = state.pairing.as_ref().ok_or(Error("unknown_token"))?;
            if pairing.exp < self.services.clock.now() || envelope.exp < self.services.clock.now() {
                return Err(Error("expired"));
            }
            if envelope.exp > pairing.exp {
                return Err(Error("invalid_pair_expiration"));
            }
            match envelope.r#type {
                EnvelopeType::PairAccept => {
                    if serde_json::to_vec(envelope)?.len()
                        > kv_core::remote::envelope::MAX_ENVELOPE_BYTES
                    {
                        return Err(Error("payload_too_large"));
                    }
                    // No directory authority exists yet. Decrypt only to obtain the proposed DK,
                    // then verify the envelope with it; SAS confirmation supplies the trust.
                    let plaintext = kv_core::remote::hpke::open(
                        self.services.identity.as_ref(),
                        &decode_b64(&envelope.enc)?,
                        &envelope.aad()?,
                        &decode_b64(&envelope.ct)?,
                    )?;
                    let accept: PairAccept = from_json(&plaintext)?;
                    if envelope.from != accept.joiner.device_id {
                        return Err(Error("wrong_sender"));
                    }
                    kv_core::remote::verify_identity_signature(
                        &accept.joiner,
                        &envelope.signature_payload()?,
                        &decode_b64(&envelope.sig)?,
                    )?;
                    if pairing.candidate.as_ref() == Some(&accept.joiner)
                        && decode_b64(&accept.token)?.as_slice() == pairing.token.as_slice()
                    {
                        return Ok(());
                    }
                    self.accept_pair_locked(state, accept).map(|_| ())
                }
                EnvelopeType::PairConfirm => {
                    let candidate = pairing
                        .candidate
                        .clone()
                        .ok_or(Error("pair_not_accepted"))?;
                    let plaintext = kv_core::remote::envelope::open(
                        envelope,
                        &self.local.device_id,
                        self.services.identity.as_ref(),
                        &candidate,
                        self.services.clock.now(),
                    )?;
                    let confirm: PairConfirm = from_json(&plaintext)?;
                    self.confirm_signed_locked(state, &confirm)
                }
                _ => Err(Error("unsupported_type")),
            }
        })();
        if let Err(error) = result {
            self.pair_failed(state, error)?;
        }
        result
    }

    fn accept_pair_locked(
        &self,
        state: &mut State,
        accept: PairAccept,
    ) -> Result<kv_ipc::remote::PairSasResult> {
        let pairing = state.pairing.as_mut().ok_or(Error("unknown_token"))?;
        if pairing.exp < self.services.clock.now() {
            return Err(Error("expired"));
        }
        if pairing.candidate.is_some() {
            return Err(Error("replay"));
        }
        let token = Zeroizing::new(decode_b64(&accept.token)?);
        let difference = token
            .iter()
            .zip(pairing.token.iter())
            .fold(0u8, |acc, (a, b)| acc | (a ^ b));
        if token.len() != 16 || difference != 0 {
            return Err(Error("unknown_token"));
        }
        validate_device(&accept.joiner)?;
        if accept.joiner.device_id.is_empty()
            || accept.joiner.device_id == self.local.device_id
            || !(accept.joiner.caps.contains(&Capability::ApproveStrong)
                || self.local.ak_s.is_some() && accept.joiner.caps.contains(&Capability::Execute))
        {
            return Err(Error("strong_key_required"));
        }
        let exists: bool = state.store.db.query_row(
            "SELECT EXISTS(SELECT 1 FROM devices WHERE id=?1)",
            [&accept.joiner.device_id],
            |row| row.get(0),
        )?;
        if exists {
            return Err(Error("device_already_known"));
        }
        let sas =
            kv_core::remote::pairing::device_sas(&pairing.token, &self.local, &accept.joiner)?;
        pairing.peer_global_grants = accept
            .extra
            .get("global_grants")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0)
            .min(100000);
        pairing.candidate = Some(accept.joiner);
        pairing.sas = Some(sas.clone());
        Ok(kv_ipc::remote::PairSasResult {
            sas,
            extra: Extra::new(),
        })
    }

    fn finish_pair_locked(&self, state: &mut State) -> Result<()> {
        let pairing = state.pairing.as_ref().ok_or(Error("unknown_token"))?;
        if !pairing.terminal_confirmed || !pairing.strong_confirmed {
            return Ok(());
        }
        let device = pairing
            .candidate
            .clone()
            .ok_or(Error("pair_not_accepted"))?;
        let transaction = state.store.transaction(self.services.audit.as_ref())?;
        state
            .store
            .insert_device(&device, &self.account, self.services.clock.now())?;
        let directory_update = self.stage_directory(state)?;
        if pairing.exclude_global {
            state.store.set_setting(
                &format!("global_excluded:{}", device.device_id),
                &true,
                "local",
                self.services.clock.now(),
            )?;
        } else {
            self.send_global_grants_locked(state, &device)?;
        }
        self.audit(
            state,
            "pair_completed",
            json!({"device_id": device.device_id}),
        )?;
        transaction.commit()?;
        directory_update.commit()?;
        if pairing.transport.is_some() {
            state.pair_result =
                Some(json!({"state":"completed","sas":pairing.sas,"device_id":device.device_id}));
        }
        state.pairing = None;
        self.changed.notify_waiters();
        Ok(())
    }

    pub(crate) fn pair_failed(&self, state: &mut State, error: Error) -> Result<()> {
        if state
            .pairing
            .as_ref()
            .is_some_and(|pairing| pairing.transport.is_some())
        {
            state.pair_result = Some(json!({"state":"failed","error":error.code()}));
        }
        state.pairing = None;
        self.audit(
            state,
            if error.code() == "pair_sas_mismatch" {
                "pair_sas_mismatch"
            } else {
                "pair_rejected"
            },
            json!({"ok": false, "reason": error.code()}),
        )
    }

    fn send_global_grants_locked(&self, state: &State, device: &DeviceRecord) -> Result<()> {
        if !device.caps.contains(&Capability::Execute) {
            return Ok(());
        }
        let now = self.services.clock.now();
        let mut stmt = state.store.db.prepare(
            "SELECT object_json FROM issued_grant_objects o JOIN issued_grants g USING(jti)
            WHERE g.peer='*' AND g.revoked_at IS NULL AND (g.exp IS NULL OR g.exp>=?1)
            AND NOT EXISTS(SELECT 1 FROM issued_grant_revocations r WHERE r.jti=g.jti)",
        )?;
        let grants = stmt
            .query_map([now], |r| r.get::<_, String>(0))?
            .map(|row| super::store::decode::<Grant>(&row?))
            .collect::<Result<Vec<_>>>()?;
        for grant in grants {
            kv_core::remote::validation::verify_grant(
                &grant,
                &device.device_id,
                &device.label,
                &self.local,
                ApprovalLevel::Strong,
                now,
            )?;
            state.store.queue(&self.seal(
                device,
                EnvelopeType::Grant,
                &grant.jti,
                grant.exp.unwrap_or_else(|| now.saturating_add(86400)),
                &grant,
            )?)?;
        }
        Ok(())
    }

    pub async fn pair_start_network(
        self: &std::sync::Arc<Self>,
        relay_url: &str,
    ) -> Result<kv_ipc::remote::PairSasResult> {
        let relay = super::pairing_relay::RelayApi::new(relay_url)?;
        self.pair_start_with_relay(relay).await
    }

    pub(crate) async fn pair_start_with_relay(
        self: &std::sync::Arc<Self>,
        relay: super::pairing_relay::RelayApi,
    ) -> Result<kv_ipc::remote::PairSasResult> {
        // The URI always uses kv-pair; loopback HTTP exists solely for the CI relay harness.
        let authority = relay
            .url
            .as_str()
            .split("://")
            .nth(1)
            .ok_or(Error("invalid_relay_url"))?
            .trim_end_matches('/');
        let result = self.pair_start(&format!("https://{authority}"))?;
        let expires_at = result.extra["expires_at"]
            .as_i64()
            .ok_or(Error("invalid_pair_expiration"))?;
        let token = result.extra["token"]
            .as_str()
            .ok_or(Error("unknown_token"))?;
        if self.local.ak_s.is_some() {
            let proof = json!({"action":"pair_start","device_id":self.local.device_id,
                "token_hash":sha256_hex(&decode_b64(token)?),"exp":expires_at});
            let authorized = async {
                self.authorize_strong("pair_start", proof.clone()).await?;
                let key =
                    kv_core::remote::validation::approval_key(&self.local, ApprovalLevel::Strong)?;
                let signature = kv_core::remote::keys::sign_object(
                    &proof,
                    key.alg,
                    self.approval_provider(ApprovalLevel::Strong)?,
                )?;
                kv_core::remote::keys::verify_object(&proof, &signature, key)?;
                Ok::<_, Error>(())
            }
            .await;
            if let Err(error) = authorized {
                self.pair_failed(&mut *self.lock()?, error)?;
                return Err(error);
            }
        }
        let session = relay
            .authenticate(&self.local, self.services.identity.clone())
            .await?;
        let response: kv_core::remote::relay::PairStartResponse = relay
            .post(
                "v1/pair/start",
                &kv_core::remote::relay::PairStartRequest {
                    token_hash: sha256_hex(&decode_b64(token)?),
                    initiator: self.local.clone(),
                    exp: expires_at,
                    extra: Extra::new(),
                },
                Some(&session),
            )
            .await?;
        {
            let mut state = self.lock()?;
            let pairing = state.pairing.as_mut().ok_or(Error("unknown_token"))?;
            if pairing.exp != expires_at || encode_b64(&pairing.token) != token {
                return Err(Error("wrong_pairing"));
            }
            pairing.transport = Some(super::pairing_relay::PairTransport {
                relay: relay.clone(),
                pairing_id: response.pairing_id,
                joiner: false,
            });
        }
        self.start_pair_poll(relay);
        Ok(result)
    }

    pub(crate) async fn join_network(
        self: &std::sync::Arc<Self>,
        relay: super::pairing_relay::RelayApi,
        token: Zeroizing<Vec<u8>>,
        response: kv_core::remote::relay::PairCompleteResponse,
    ) -> Result<kv_ipc::remote::PairSasResult> {
        validate_device(&response.initiator)?;
        if response.account_id.as_value() != Some(&self.account)
            || response.initiator.device_id == self.local.device_id
        {
            return Err(Error("wrong_account"));
        }
        let sas = kv_core::remote::pairing::device_sas(&token, &response.initiator, &self.local)?;
        let exp = response
            .extra
            .get("expires_at")
            .and_then(serde_json::Value::as_i64)
            .ok_or(Error("invalid_remote_response"))?;
        if exp <= self.services.clock.now() || exp > self.services.clock.now().saturating_add(600) {
            return Err(Error("expired"));
        }
        let session = relay
            .authenticate(&self.local, self.services.identity.clone())
            .await?;
        let envelope = self.seal(
            &response.initiator,
            EnvelopeType::PairAccept,
            &response.pairing_id,
            exp,
            &PairAccept {
                token: encode_b64(&token),
                joiner: self.local.clone(),
                extra: json!({"global_grants":self.global_grants_n(&*self.lock()?)?})
                    .as_object()
                    .unwrap()
                    .clone(),
            },
        )?;
        {
            let mut state = self.lock()?;
            state.pair_result = None;
            state.pairing = Some(Pairing {
                token,
                exp,
                candidate: Some(response.initiator),
                sas: Some(sas.clone()),
                terminal_confirmed: false,
                strong_confirmed: false,
                exclude_global: false,
                peer_global_grants: 0,
                local_confirmation: None,
                transport: Some(super::pairing_relay::PairTransport {
                    relay: relay.clone(),
                    pairing_id: response.pairing_id,
                    joiner: true,
                }),
            });
        }
        let _: kv_core::remote::relay::AcceptedResponse = relay
            .post(
                "v1/messages",
                &kv_core::remote::relay::SendMessagesRequest {
                    envelopes: vec![envelope],
                    extra: Extra::new(),
                },
                Some(&session),
            )
            .await?;
        self.start_pair_poll(relay);
        Ok(kv_ipc::remote::PairSasResult {
            sas,
            extra: json!({"expires_at":exp,"state":"waiting"})
                .as_object()
                .unwrap()
                .clone(),
        })
    }

    pub(crate) async fn pair_confirm_owner(
        &self,
        intent: kv_ipc::remote::PairConfirmIntent,
    ) -> Result<()> {
        if !intent.confirmed {
            return Err(Error("user_cancelled"));
        }
        let snapshot = {
            let state = self.lock()?;
            let pair = state.pairing.as_ref().ok_or(Error("unknown_token"))?;
            let transport = pair.transport.as_ref().ok_or(Error("unknown_token"))?;
            if pair.exp < self.services.clock.now() {
                return Err(Error("expired"));
            }
            if pair.sas.as_deref() != Some(intent.sas.as_str()) {
                return Err(Error("pair_sas_mismatch"));
            }
            (
                transport.relay.clone(),
                transport.pairing_id.clone(),
                transport.joiner,
                pair.candidate.clone().ok_or(Error("pair_not_accepted"))?,
                pair.exp,
                pair.local_confirmation.clone(),
            )
        };
        let (confirm, envelope) = if let Some(cached) = snapshot.5 {
            if cached.0.extra.get("exclude_global") != Some(&json!(intent.exclude_global)) {
                return Err(Error("confirmation_changed"));
            }
            cached
        } else {
            let mut local = self.local.clone();
            local.label = self.label(&*self.lock()?)?;
            let mut confirm = PairConfirm {
                sas: intent.sas.clone(),
                sig: String::new(),
                extra: json!({"exclude_global":intent.exclude_global,"device":local})
                    .as_object()
                    .unwrap()
                    .clone(),
            };
            let strong = self.local.ak_s.is_some();
            if strong {
                if self.services.runner.has_private_ui() {
                    let reply = self
                        .services
                        .runner
                        .private_ui("remote_pair", json!({"peer":snapshot.3,"sas":confirm.sas}))
                        .await?;
                    if reply["ok"] != true {
                        return Err(super::production::private_ui_error(&reply));
                    }
                    if reply["confirmed"] != true {
                        return Err(if reply["confirmed"] == false {
                            Error("user_cancelled")
                        } else {
                            Error("invalid_remote_response")
                        });
                    }
                } else {
                    self.authorize_strong(
                        "confirm_pair",
                        json!({"sas":confirm.sas,"device_id":snapshot.3.device_id}),
                    )
                    .await?;
                }
                let key =
                    kv_core::remote::validation::approval_key(&self.local, ApprovalLevel::Strong)?;
                confirm.sig = kv_core::remote::keys::sign_object(
                    &confirm,
                    key.alg,
                    self.approval_provider(ApprovalLevel::Strong)?,
                )?;
            } else if snapshot.2 && snapshot.3.ak_s.is_none() {
                return Err(Error("strong_key_required"));
            }
            let envelope = self.seal(
                &snapshot.3,
                EnvelopeType::PairConfirm,
                &snapshot.1,
                snapshot.4,
                &confirm,
            )?;
            let mut state = self.lock()?;
            let pair = state.pairing.as_mut().ok_or(Error("unknown_token"))?;
            if pair
                .transport
                .as_ref()
                .is_none_or(|transport| transport.pairing_id != snapshot.1)
                || pair.sas.as_deref() != Some(intent.sas.as_str())
                || pair.exp < self.services.clock.now()
            {
                return Err(Error("wrong_pairing"));
            }
            if let Some(cached) = &pair.local_confirmation {
                if cached.0.extra.get("exclude_global") != Some(&json!(intent.exclude_global)) {
                    return Err(Error("confirmation_changed"));
                }
                cached.clone()
            } else {
                pair.local_confirmation = Some((confirm.clone(), envelope.clone()));
                (confirm, envelope)
            }
        };
        let session = snapshot
            .0
            .authenticate(&self.local, self.services.identity.clone())
            .await?;
        let _: kv_core::remote::relay::AcceptedResponse = snapshot
            .0
            .post(
                "v1/messages",
                &kv_core::remote::relay::SendMessagesRequest {
                    envelopes: vec![envelope],
                    extra: Extra::new(),
                },
                Some(&session),
            )
            .await?;
        let _: kv_core::remote::relay::OkResponse = snapshot
            .0
            .post(
                "v1/pair/finish",
                &kv_core::remote::relay::PairFinishRequest {
                    pairing_id: snapshot.1.clone(),
                    confirm: confirm.clone(),
                    extra: Extra::new(),
                },
                Some(&session),
            )
            .await?;
        let mut state = self.lock()?;
        let pair = state.pairing.as_mut().ok_or(Error("unknown_token"))?;
        if pair
            .transport
            .as_ref()
            .is_none_or(|transport| transport.pairing_id != snapshot.1)
        {
            return Err(Error("wrong_pairing"));
        }
        pair.exclude_global |= intent.exclude_global;
        if pair.sas.as_deref() != Some(confirm.sas.as_str()) || pair.exp < self.services.clock.now()
        {
            return Err(Error("expired"));
        }
        if snapshot.2 {
            pair.strong_confirmed = true;
        } else {
            pair.terminal_confirmed = true;
        }
        self.finish_pair_locked(&mut state)
    }
}

pub(crate) fn base32(bytes: &[u8]) -> String {
    let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut output = String::new();
    let mut bits = 0u32;
    let mut remaining = 0;
    for byte in bytes {
        bits = (bits << 8) | u32::from(*byte);
        remaining += 8;
        while remaining >= 5 {
            remaining -= 5;
            output.push(alphabet[((bits >> remaining) & 31) as usize] as char);
        }
    }
    if remaining > 0 {
        output.push(alphabet[((bits << (5 - remaining)) & 31) as usize] as char);
    }
    output
}
