use super::view::{ConfirmationView, PairingView};
use super::{request, text, ApprovalView, Dialog, Error, Level, Platform, Result, Selection};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use kv_ipc::remote::{DeviceKeyProvider, Op, Request, SignatureAlgorithm};
use serde_json::{json, Value};

pub trait Helper {
    /// The real transport authenticates the helper and returns its complete response.
    fn exchange(&mut self, request: &Request) -> Result<Value>;
}

pub trait ObjectCrypto {
    /// Implement with W0's JCS and verification functions; never JSON.stringify a signature.
    fn canonical_unsigned(&self, value: &Value) -> Result<Vec<u8>>;
    fn verify(
        &self,
        alg: SignatureAlgorithm,
        jwk: &Value,
        payload: &[u8],
        signature: &[u8],
    ) -> Result<()>;
}

pub trait StrongAuthorization {
    /// Perform a fresh key-bound signature, including verification against the pinned AK_s.
    fn authorize(&mut self, binding: &Value) -> Result<()>;
}

pub struct KeyAuthorization<'a> {
    pub provider: &'a dyn DeviceKeyProvider,
    pub local: &'a Value,
    pub crypto: &'a dyn ObjectCrypto,
}
impl StrongAuthorization for KeyAuthorization<'_> {
    fn authorize(&mut self, binding: &Value) -> Result<()> {
        let (alg, jwk) = approval_key(self.local, Level::Strong)?;
        if self
            .provider
            .public_jwk()
            .map_err(|_| Error::KeyUnavailable)?
            != *jwk
        {
            return Err(Error::KeyUnavailable);
        }
        let payload = self.crypto.canonical_unsigned(binding)?;
        let signature = self
            .provider
            .sign(alg, &payload)
            .map_err(|_| Error::KeyUnavailable)?;
        self.crypto.verify(alg, jwk, &payload, &signature)
    }
}

pub struct ApprovalFlow;
impl ApprovalFlow {
    pub fn decision_params(view: &ApprovalView, selection: Selection, now: i64) -> Result<Value> {
        // CONTRACT: A.2 / Appendix C: authority comes from the original offered scopes.
        let validated = ApprovalView::new(
            &view.original,
            super::DisplayContext {
                now,
                ..Default::default()
            },
            Platform::Macos,
        )?;
        let view = &validated;
        let (decision, scope, reason) = match selection {
            Selection::Allow { scope } => ("allow", scope, None),
            Selection::Deny { reason } => {
                let scope = view
                    .scopes
                    .iter()
                    .find(|scope| scope.value == "per_use")
                    .or_else(|| view.scopes.get(view.selected))
                    .ok_or(Error::InvalidScope)?
                    .value
                    .clone();
                let reason = reason.filter(|text| !text.trim().is_empty());
                if reason
                    .as_ref()
                    .is_some_and(|s| s.chars().count() > 512 || s.chars().any(char::is_control))
                {
                    return Err(Error::InvalidRequest);
                }
                ("deny", scope, reason)
            }
            Selection::Cancel => return Err(Error::Cancelled),
        };
        let choice = view
            .scopes
            .iter()
            .find(|choice| choice.value == scope)
            .ok_or(Error::InvalidScope)?;
        let mut params = json!({"approval_id":text(&view.original,"approval_id")?,"decision":decision,
            "scope":decision_scope(&scope, now)?,"scope_option":scope,"level":choice.level.as_str()});
        if let Some(reason) = reason {
            params["reason"] = json!(reason);
        }
        Ok(params)
    }

    pub fn run(
        view: &ApprovalView,
        dialog: &mut dyn Dialog,
        helper: &mut dyn Helper,
        now: &dyn Fn() -> i64,
    ) -> Result<()> {
        let selection = dialog.approval(view)?;
        let params = Self::decision_params(view, selection, now())?;
        let result = exchange(helper, Op::Decide, params)?;
        if result["sent"] != true {
            return Err(Error::InvalidResponse);
        }
        Ok(())
    }
}

pub fn decision_scope(scope: &str, now: i64) -> Result<Value> {
    let (mode, level, seconds) = match scope {
        "per_use" => ("per_use", "credential", 0),
        "per_credential" => ("per_credential", "credential", 0),
        "per_session" => ("per_session", "device", 0),
        "remember:1h" => ("remember", "credential", 3600),
        "remember:8h" => ("remember", "credential", 28800),
        "remember:24h" => ("remember", "credential", 86400),
        "standing:credential" => ("standing", "credential", 0),
        "standing:device" => ("standing", "device", 0),
        _ => return Err(Error::InvalidScope),
    };
    let until = if seconds == 0 {
        0
    } else {
        now.checked_add(seconds).ok_or(Error::InvalidScope)?
    };
    Ok(json!({"mode":mode,"level":level,"until":until}))
}

// CONTRACT: §7.4 / A.3: this is a preview; the executor owns session lifetime and issuance.
pub fn grant_for_scope(
    request: &Value,
    scope: &str,
    issuer: &Value,
    jti: &str,
    now: i64,
    session_end: i64,
) -> Result<Option<Value>> {
    let offered = request["scope_options"]
        .as_array()
        .ok_or(Error::InvalidScope)?;
    if !offered.iter().any(|v| v == scope) || (request["tier"] == "T2" && scope != "per_use") {
        return Err(Error::InvalidScope);
    }
    let decision = decision_scope(scope, now)?;
    if scope == "per_use" {
        return Ok(None);
    }
    let signing_level = if scope.starts_with("standing:")
        || request["kind"] != "use"
        || request["min_level"] == "strong"
    {
        Level::Strong
    } else {
        Level::Quick
    };
    let (alg, _) = approval_key(issuer, signing_level)?;
    let exp = match decision["mode"].as_str() {
        Some("standing") => Value::Null,
        Some("remember") => decision["until"].clone(),
        _ if session_end > now => json!(session_end),
        _ => return Err(Error::MissingState),
    };
    let mut grant_scope = json!({"level":decision["level"],"max_tier":"T1"});
    if decision["level"] == "credential" {
        grant_scope["credential"] = json!(text(&request["credential"], "ref")?);
    }
    Ok(Some(
        json!({"kind":"grant","jti":jti,"iss":text(issuer,"device_id")?,"iss_alg":alg,"iss_kind":"device",
        "aud":text(&request["requester"],"device_id")?,"scope":grant_scope,"nbf":now,"exp":exp,
        "origin":format!("approval:{}",text(request,"approval_id")?)}),
    ))
}

pub struct PairingFlow<'a> {
    pub peer: &'a Value,
    pub local: &'a Value,
    pub sas: &'a str,
    pub platform: Platform,
}
impl PairingFlow<'_> {
    pub fn run(
        &self,
        dialog: &mut dyn Dialog,
        helper: &mut dyn Helper,
        provider: &dyn DeviceKeyProvider,
        crypto: &dyn ObjectCrypto,
    ) -> Result<()> {
        let view = PairingView::new(self.peer, self.sas, self.platform)?;
        let (alg, jwk) = approval_key(self.local, Level::Strong)?;
        if provider.public_jwk().map_err(|_| Error::KeyUnavailable)? != *jwk {
            return Err(Error::KeyUnavailable);
        }
        if !dialog.pairing(&view)? {
            return Err(Error::Cancelled);
        }
        // CONTRACT: Appendix A preamble / A.7: PairConfirm signs the complete JCS object.
        let mut confirmation = json!({"sas": self.sas});
        let payload = crypto.canonical_unsigned(&confirmation)?;
        let signature = provider
            .sign(alg, &payload)
            .map_err(|_| Error::KeyUnavailable)?;
        crypto.verify(alg, jwk, &payload, &signature)?;
        confirmation["sig"] = json!(URL_SAFE_NO_PAD.encode(signature));
        exchange(helper, Op::PairConfirm, confirmation)?;
        Ok(())
    }
}

pub fn approval_key(local: &Value, level: Level) -> Result<(SignatureAlgorithm, &Value)> {
    let (key, cap) = match level {
        Level::Quick => ("ak_q", "approve_quick"),
        Level::Strong => ("ak_s", "approve_strong"),
    };
    if !local["caps"]
        .as_array()
        .is_some_and(|caps| caps.iter().any(|value| value == cap))
    {
        return Err(Error::KeyUnavailable);
    }
    let key = &local[key];
    let alg = match key["alg"].as_str() {
        Some("ES256") => SignatureAlgorithm::ES256,
        Some("RS256") => SignatureAlgorithm::RS256,
        _ => return Err(Error::KeyUnavailable),
    };
    if !key["pub"].is_object() {
        return Err(Error::KeyUnavailable);
    }
    Ok((alg, &key["pub"]))
}

pub struct GrantPlan {
    pub(crate) unsigned: Value,
    executor_label: String,
    platform: Platform,
}
impl GrantPlan {
    pub fn unsigned(&self) -> &Value {
        &self.unsigned
    }
    // CONTRACT: §7.6 / A.4: separate settings flow; max_tier T2 never enters popup scopes.
    pub fn settings(
        mut unsigned: Value,
        local: &Value,
        executor: &Value,
        now: i64,
        standing: bool,
        platform: Platform,
    ) -> Result<Self> {
        if !unsigned.is_object() || unsigned.get("sig").is_some() {
            return Err(Error::InvalidRequest);
        }
        let (alg, _) = approval_key(local, Level::Strong)?;
        if !executor["caps"]
            .as_array()
            .is_some_and(|caps| caps.iter().any(|v| v == "execute"))
        {
            return Err(Error::InvalidScope);
        }
        let aud = text(&unsigned, "aud")?;
        let level = text(&unsigned["scope"], "level")?;
        let tier = text(&unsigned["scope"], "max_tier")?;
        let unattended = tier == "T2";
        if !matches!(tier, "T0" | "T1" | "T2")
            || !matches!(level, "credential" | "device" | "global")
            || (level == "global") != (aud == "*")
            || (aud != "*" && aud != text(executor, "device_id")?)
        {
            return Err(Error::InvalidScope);
        }
        if level == "credential" && text(&unsigned["scope"], "credential")?.is_empty() {
            return Err(Error::InvalidScope);
        }
        if tier == "T2" && aud == "*" {
            return Err(Error::InvalidScope);
        }
        if let Some(budget) = unsigned.get("budget").filter(|v| !v.is_null()) {
            if budget["calls"].as_u64().is_none_or(|n| n == 0)
                || !matches!(budget["per"].as_str(), Some("1h" | "24h" | "7d"))
            {
                return Err(Error::InvalidScope);
            }
        }
        unsigned["kind"] = json!("grant");
        unsigned["iss"] = json!(text(local, "device_id")?);
        unsigned["iss_alg"] = json!(alg);
        unsigned["iss_kind"] = json!("device");
        unsigned["origin"] = json!("settings");
        unsigned["nbf"] = json!(now);
        text(&unsigned, "jti")?;
        if standing {
            unsigned["exp"] = Value::Null;
        } else if unsigned.get("exp").is_none() {
            unsigned["exp"] = json!(now
                .checked_add(if unattended { 604800 } else { 86400 })
                .ok_or(Error::InvalidScope)?);
        }
        if !standing && unsigned["exp"].as_i64().is_none_or(|exp| exp <= now) {
            return Err(Error::InvalidScope);
        }
        unsigned.as_object_mut().unwrap().remove("confirm");
        let executor_label = super::display_text(text(executor, "label")?)?;
        Ok(Self {
            unsigned,
            executor_label,
            platform,
        })
    }

    pub fn issue(
        self,
        dialog: &mut dyn Dialog,
        helper: &mut dyn Helper,
        strong: &mut dyn StrongAuthorization,
    ) -> Result<Value> {
        // CONTRACT: product §6.1 / architecture §7.4: global includes future paired executors.
        if self.unsigned["aud"] == "*"
            && !dialog.confirm_global(&super::view::GlobalGrantView::new(self.platform))?
        {
            return Err(Error::Cancelled);
        }
        strong.authorize(&self.unsigned)?;
        let mut intent = json!({"source":"settings","kind":"grant","aud":self.unsigned["aud"],
            "scope":self.unsigned["scope"],"nbf":self.unsigned["nbf"],"exp":self.unsigned["exp"],"origin":"settings"});
        if let Some(budget) = self.unsigned.get("budget") {
            intent["budget"] = budget.clone();
        }
        if self.unsigned["scope"]["max_tier"] == "T2" {
            let rounds = if self.unsigned["exp"].is_null() { 2 } else { 1 };
            let mut prepared = exchange(helper, Op::GrantIssue, intent.clone())?;
            for round in 0..rounds {
                let proof: kv_ipc::remote::GrantConfirmation =
                    serde_json::from_value(prepared).map_err(|_| Error::InvalidResponse)?;
                let now = super::view::unix_seconds();
                if proof.device_id != self.unsigned["aud"]
                    || proof.label != self.executor_label
                    || proof.confirmation_token.is_empty()
                    || proof.confirmation_token.len() > 256
                    || proof.expires_at <= now
                    || proof.expires_at > now.saturating_add(120)
                    || proof.confirmations_left != rounds - round
                {
                    return Err(Error::InvalidResponse);
                }
                require_label(dialog, &proof.label, self.platform, round > 0)?;
                if super::view::unix_seconds() >= proof.expires_at {
                    return Err(Error::Expired);
                }
                intent["confirm"] = json!(proof.label);
                intent["confirmation_token"] = json!(proof.confirmation_token);
                prepared = exchange(helper, Op::GrantIssue, intent.clone())?;
            }
            return issued_grant(prepared);
        }
        issued_grant(exchange(helper, Op::GrantIssue, intent)?)
    }
}

#[derive(Default)]
pub struct DirectiveState {
    pub mode: Option<String>,
    pub unlock_ttl_s: Option<u64>,
    pub classes: std::collections::BTreeMap<String, (Value, u64)>,
}

pub fn directive_level(op: &str, args: &Value, state: &DirectiveState) -> Result<Level> {
    if !args.is_object() {
        return Err(Error::InvalidRequest);
    }
    let number = |key: &str| args[key].as_u64().ok_or(Error::InvalidRequest);
    Ok(match op {
        "set_mode" => {
            if mode_rank(text(args, "mode")?)?
                < mode_rank(state.mode.as_deref().ok_or(Error::MissingState)?)?
            {
                Level::Strong
            } else {
                Level::Quick
            }
        }
        "set_unlock_ttl" => {
            let next = number("seconds")?;
            if next == 0 || next > 86400 {
                return Err(Error::InvalidRequest);
            }
            if next > state.unlock_ttl_s.ok_or(Error::MissingState)? {
                Level::Strong
            } else {
                Level::Quick
            }
        }
        "set_class" => {
            let name = text(args, "name")?;
            let exp = number("exp_s")?;
            if exp == 0 || exp > 86400 || !args["match"].is_object() {
                return Err(Error::InvalidRequest);
            }
            match state.classes.get(name) {
                Some((previous, ttl)) if previous == &args["match"] && exp <= *ttl => Level::Quick,
                _ => Level::Strong,
            }
        }
        "set_device_label" => {
            if text(args, "label")?.is_empty() {
                return Err(Error::InvalidRequest);
            }
            Level::Strong
        }
        "revoke_device" => {
            text(args, "device_id")?;
            Level::Strong
        }
        "revoke_grant" => {
            text(args, "jti")?;
            Level::Quick
        }
        "cancel_approval" => {
            text(args, "approval_id")?;
            Level::Quick
        }
        "notify" => {
            if !matches!(
                text(args, "policy")?,
                "prefer-local" | "always-phone" | "both"
            ) {
                return Err(Error::InvalidRequest);
            }
            Level::Quick
        }
        "query_audit" => {
            args["since"].as_i64().ok_or(Error::InvalidRequest)?;
            if number("limit")? > 200 {
                return Err(Error::InvalidRequest);
            }
            Level::Quick
        }
        "lock" | "revoke_all_grants" | "query_status" | "query_pending" | "query_grants" => {
            Level::Quick
        }
        _ => return Err(Error::InvalidRequest),
    })
}

fn mode_rank(value: &str) -> Result<(u8, u64)> {
    Ok(match value {
        "per_use" => (3, 0),
        "per_credential" => (2, 0),
        "per_session" => (1, 0),
        _ => {
            let hours = value
                .strip_prefix("remember:")
                .and_then(|v| v.strip_suffix('h'))
                .and_then(|v| v.parse::<u64>().ok())
                .ok_or(Error::InvalidRequest)?;
            (0, if hours == 0 { 0 } else { u64::MAX - hours })
        }
    })
}

pub struct DirectivePlan {
    pub(crate) unsigned: Value,
    pub(crate) level: Level,
    executor_label: String,
}
impl DirectivePlan {
    pub fn unsigned(&self) -> &Value {
        &self.unsigned
    }
    pub fn required_level(&self) -> Level {
        self.level
    }
    pub fn new(
        mut unsigned: Value,
        local: &Value,
        executor: &Value,
        state: &DirectiveState,
        now: i64,
        _platform: Platform,
    ) -> Result<Self> {
        if !unsigned.is_object()
            || unsigned.get("sig").is_some()
            || unsigned["aud"] != executor["device_id"]
        {
            return Err(Error::InvalidRequest);
        }
        let level = directive_level(text(&unsigned, "op")?, &unsigned["args"], state)?;
        let (alg, _) = approval_key(local, level)?;
        let exp = unsigned["exp"].as_i64().ok_or(Error::InvalidRequest)?;
        if exp < now || exp > now.saturating_add(600) {
            return Err(Error::Expired);
        }
        text(&unsigned, "id")?;
        text(&unsigned, "nonce")?;
        unsigned["kind"] = json!("directive");
        unsigned["iss"] = json!(text(local, "device_id")?);
        unsigned["iss_alg"] = json!(alg);
        unsigned["iss_kind"] = json!("device");
        if unsigned["op"] == "revoke_device" {
            unsigned["args"]
                .as_object_mut()
                .ok_or(Error::InvalidRequest)?
                .remove("confirm");
        }
        Ok(Self {
            unsigned,
            level,
            executor_label: super::display_text(text(executor, "label")?)?,
        })
    }
    pub fn issue(
        mut self,
        dialog: &mut dyn Dialog,
        helper: &mut dyn Helper,
        strong: &mut dyn StrongAuthorization,
    ) -> Result<Value> {
        if self.level == Level::Strong {
            strong.authorize(&self.unsigned)?;
        }
        if self.unsigned["op"] == "revoke_device" {
            require_confirmation(dialog, &ConfirmationView::revocation(&self.executor_label)?)?;
            self.unsigned["args"]["confirm"] = json!(self.executor_label);
        }
        let result = exchange(
            helper,
            Op::DirectiveIssue,
            json!({"kind":"directive","aud":self.unsigned["aud"],
            "op":self.unsigned["op"],"args":self.unsigned["args"]}),
        )?;
        let result = result
            .get("result")
            .filter(|value| value["ok"].is_boolean())
            .ok_or(Error::InvalidResponse)?;
        if result["ok"] != true {
            return Err(Error::HelperUnavailable);
        }
        Ok(result.clone())
    }
}

fn require_label(
    dialog: &mut dyn Dialog,
    label: &str,
    platform: Platform,
    standing: bool,
) -> Result<()> {
    let view = ConfirmationView::new(label, platform, standing)?;
    require_confirmation(dialog, &view)
}

fn issued_grant(result: Value) -> Result<Value> {
    result
        .get("grant")
        .filter(|grant| grant["sig"].as_str().is_some_and(|sig| !sig.is_empty()))
        .cloned()
        .ok_or(Error::InvalidResponse)
}

fn require_confirmation(dialog: &mut dyn Dialog, view: &ConfirmationView) -> Result<()> {
    if dialog.confirm_label(view)?.as_deref() != Some(view.label.as_str()) {
        return Err(Error::ConfirmationRequired);
    }
    Ok(())
}

fn exchange(helper: &mut dyn Helper, op: Op, params: Value) -> Result<Value> {
    let response = helper.exchange(&request(op, params))?;
    if response["ok"] != true {
        return Err(Error::HelperUnavailable);
    }
    response
        .get("result")
        .cloned()
        .ok_or(Error::InvalidResponse)
}
