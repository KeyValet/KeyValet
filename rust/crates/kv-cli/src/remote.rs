//! Owner CLI for remote approval. Keys, signatures and authorization stay in the helper.

mod args;
mod audit;
#[cfg(test)]
mod live_helper_tests;
mod output;
mod relay;
pub(crate) mod system;
#[cfg(test)]
mod tests;
mod transport;

use args::{Command, Invocation};
use kv_core::remote::ipc::{allowed_ops, Caller, Op, Request, Response};
use kv_core::remote::ipc::{DirectiveIntent, GrantConfirmation, GrantIntent, GrantSource};
use kv_core::remote::*;
use output::{ApprovalHistory, Pending, Success};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::time::Duration;

type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(super) struct Error {
    pub code: String,
    pub message: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub completed_devices: Vec<String>,
}

impl Error {
    fn new(code: &str, zh: &str, en: &str) -> Self {
        Self {
            code: code.into(),
            message: kv_i18n::t(zh, en),
            completed_devices: Vec::new(),
        }
    }

    fn argument(zh: &str, en: &str) -> Self {
        Self::new("invalid_argument", zh, en)
    }

    fn protocol() -> Self {
        Self::new(
            "invalid_response",
            "helper 返回的消息格式不正确；请更新 KeyValet",
            "The helper response is invalid; update KeyValet",
        )
    }

    fn cancelled() -> Self {
        Self::new(
            "user_cancelled",
            "已取消；未发出授权",
            "Cancelled; no authorization was issued",
        )
    }

    fn exit_code(&self) -> i32 {
        match self.code.as_str() {
            "invalid_argument" | "unknown_device" | "ambiguous_device" => 2,
            "timeout" | "expired" | "pair_timeout" | "directive_result_timeout" => 4,
            "relay_unreachable" | "relay_unavailable" | "relay_busy" | "relay_offline"
            | "remote_unavailable" | "ipc_unavailable" => 5,
            "user_cancelled"
            | "strong_cancelled"
            | "authentication_cancelled"
            | "secondary_confirmation_required" => 6,
            _ => 3,
        }
    }
}

/// System dependencies are injected; tests never authenticate installed binaries or open a vault.
trait Host {
    fn verify(&mut self) -> Result<()>;
    fn configure(&mut self, _summary: bool) {}
    fn exchange(&mut self, request: Request) -> Result<Response>;
    fn now(&self) -> i64;
    fn config_path(&self) -> Result<PathBuf>;
    fn install_root(&self) -> Result<PathBuf>;
    fn confirmation(&mut self, prompt: &str, timeout: Duration) -> Result<Option<String>>;
    fn secret(&mut self, prompt: &str) -> Result<Option<String>> {
        self.confirmation(prompt, Duration::from_secs(180))
    }
    fn notice(&mut self, text: &str) -> Result<()>;
    fn emit(&mut self, value: &Success, json: bool) -> Result<()>;
    fn wait(&mut self, duration: Duration) -> bool;
    fn health(&mut self, url: &str) -> Result<relay::Health>;
    fn hook(&mut self, command: &str, id: &str, summary: &str) -> Result<()>;
    fn protection(&mut self) -> Result<Value>;
    fn set_url(&mut self, path: &std::path::Path, url: &str) -> Result<()> {
        relay::Config::set_url(path, url)
    }
    fn set_binding(
        &mut self,
        path: &std::path::Path,
        binding: &kv_core::remote::ipc::RelayBinding,
    ) -> Result<()> {
        relay::Config::set_binding(path, binding)
    }
    fn install(
        &mut self,
        root: &std::path::Path,
        listen: &str,
        data: &std::path::Path,
        url: &str,
    ) -> Result<relay::Installed> {
        relay::install(root, listen, data, url)
    }
}

fn call<T: DeserializeOwned>(host: &mut impl Host, op: Op, params: Value) -> Result<T> {
    if !allowed_ops(Caller::CliOwner).contains(&op) {
        return Err(Error::protocol());
    }
    let request = Request {
        op,
        params,
        extra: Extra::new(),
    };
    match host.exchange(request)? {
        Response::Ok { result, .. } => {
            serde_json::from_value(result).map_err(|_| Error::protocol())
        }
        Response::Err { error, .. } => Err(Error {
            message: output::error_message(&error.code),
            code: error.code,
            completed_devices: Vec::new(),
        }),
    }
}

fn devices(host: &mut impl Host) -> Result<kv_core::remote::ipc::DevicesListResult> {
    call(host, Op::DevicesList, json!({}))
}

fn resolve(target: &str, directory: &[DeviceRecord]) -> Result<Vec<DeviceRecord>> {
    let active: Vec<_> = directory
        .iter()
        .filter(|d| d.extra.get("revoked") != Some(&Value::Bool(true)))
        .collect();
    let selected = if target == "*" {
        active
            .into_iter()
            .filter(|d| d.caps.contains(&Capability::Execute))
            .collect::<Vec<_>>()
    } else if let Some(exact) = active.iter().find(|d| d.device_id == target) {
        vec![*exact]
    } else {
        active
            .into_iter()
            .filter(|d| d.label == target)
            .collect::<Vec<_>>()
    };
    if selected.is_empty() {
        return Err(Error::new(
            "unknown_device",
            "找不到目标设备；请运行 keyvalet devices list",
            "Device not found; run keyvalet devices list",
        ));
    }
    if target != "*" && selected.len() > 1 {
        return Err(Error::new(
            "ambiguous_device",
            "设备标签不唯一；请使用设备 id",
            "The device label is ambiguous; use a device id",
        ));
    }
    Ok(selected.into_iter().cloned().collect())
}

fn issue_directive(
    host: &mut impl Host,
    target: &str,
    op: DirectiveOp,
    args: Extra,
) -> Result<Success> {
    let directory = devices(host)?;
    let peers = resolve(target, &directory.devices)?;
    let mut results = Vec::new();
    for peer in peers {
        let intent = DirectiveIntent {
            kind: DirectiveKind::Directive,
            aud: peer.device_id.clone(),
            op,
            args: args.clone(),
        };
        let mut issued: kv_core::remote::ipc::DirectiveIssueResult =
            call(host, Op::DirectiveIssue, json!(intent)).map_err(|mut error| {
                error.completed_devices = results
                    .iter()
                    .map(|r: &output::DeviceResult| r.device_id.clone())
                    .collect();
                error
            })?;
        if !issued.result.ok {
            let code = issued
                .result
                .error
                .as_deref()
                .unwrap_or("executor_rejected");
            return Err(Error {
                code: code.into(),
                message: output::error_message(code),
                completed_devices: results.iter().map(|r| r.device_id.clone()).collect(),
            });
        }
        if op == DirectiveOp::QueryGrants {
            let mut seen = std::collections::HashSet::new();
            while let Some(cursor) = issued
                .result
                .state
                .get("next_cursor")
                .and_then(Value::as_str)
                .map(str::to_owned)
            {
                if !seen.insert(cursor.clone()) {
                    return Err(Error::protocol());
                }
                let page: kv_core::remote::ipc::DirectiveIssueResult = call(
                    host,
                    Op::DirectiveIssue,
                    json!({"kind":"directive","aud":peer.device_id,"op":op,"args":{"after":cursor}}),
                )?;
                if !page.result.ok {
                    return Err(Error::protocol());
                }
                let items = page
                    .result
                    .state
                    .get("grants")
                    .and_then(Value::as_array)
                    .ok_or_else(Error::protocol)?;
                issued
                    .result
                    .state
                    .get_mut("grants")
                    .and_then(Value::as_array_mut)
                    .ok_or_else(Error::protocol)?
                    .extend(items.iter().cloned());
                issued.result.state.insert(
                    "next_cursor".into(),
                    page.result
                        .state
                        .get("next_cursor")
                        .cloned()
                        .unwrap_or(Value::Null),
                );
            }
        }
        results.push(output::DeviceResult {
            device_id: peer.device_id,
            result: issued.result,
        });
    }
    Ok(Success::Remote { results })
}

fn issue_grant(
    host: &mut impl Host,
    target: &str,
    options: &args::GrantOptions,
    unattended: bool,
    preauthorization: bool,
) -> Result<Success> {
    let directory = devices(host)?;
    let peers = resolve(target, &directory.devices)?;
    if target == "*" && !unattended {
        host.notice(&kv_i18n::t(
            "此全局授权也会影响以后加入的执行端。",
            "This global grant also applies to executors paired in the future.",
        ))?;
    }
    let recipients = if unattended {
        peers
            .iter()
            .map(|p| (p.device_id.clone(), Some(p)))
            .collect::<Vec<_>>()
    } else {
        vec![(
            if target == "*" {
                "*".into()
            } else {
                peers[0].device_id.clone()
            },
            None,
        )]
    };
    let mut intents = Vec::new();
    let mut expirations = Vec::new();
    for (aud, peer) in recipients {
        let scope = GrantScope {
            level: if options.all {
                if aud == "*" {
                    GrantScopeLevel::Global
                } else {
                    GrantScopeLevel::Device
                }
            } else {
                GrantScopeLevel::Credential
            },
            credential: options
                .credential
                .clone()
                .map_or(Optional::Missing, Optional::Value),
            hosts: options
                .hosts
                .clone()
                .map_or(Optional::Missing, Optional::Value),
            methods: options
                .methods
                .clone()
                .map_or(Optional::Missing, Optional::Value),
            paths: options
                .paths
                .clone()
                .map_or(Optional::Missing, Optional::Value),
            agent: options
                .agent
                .clone()
                .map_or(Optional::Missing, Optional::Value),
            max_tier: if unattended { Tier::T2 } else { Tier::T1 },
            extra: Extra::new(),
        };
        let mut intent = GrantIntent {
            source: if preauthorization {
                GrantSource::Preauthorization
            } else {
                GrantSource::Settings
            },
            kind: GrantKind::Grant,
            aud,
            scope,
            budget: options.budget.clone(),
            nbf: host.now(),
            exp: options
                .until
                .as_ref()
                .map(|s| args::until(s, host.now()))
                .transpose()?,
            origin: "settings".into(),
            confirm: None,
            confirmation_token: None,
        };
        if let Some(peer) = peer {
            // Strong happens in the helper first. Its one-use token binds this exact draft;
            // preparing never signs, sends or installs a Grant.
            let mut prepared: GrantConfirmation = call(host, Op::GrantIssue, json!(intent))?;
            if prepared.confirmation_token.is_empty() || prepared.confirmation_token.len() > 256 {
                return Err(Error::protocol());
            }
            if prepared.device_id != peer.device_id
                || prepared.label.is_empty()
                || prepared.label.len() > 4096
                || prepared.label.chars().any(char::is_control)
            {
                return Err(Error::protocol());
            }
            let remaining = prepared.expires_at.saturating_sub(host.now());
            if remaining > 120 {
                return Err(Error::protocol());
            }
            if remaining <= 0 {
                return Err(Error::new(
                    "expired",
                    "二次确认已过期",
                    "Secondary confirmation has expired",
                ));
            }
            if prepared.confirmations_left != 2 {
                return Err(Error::protocol());
            }
            let label = output::terminal_text(&prepared.label);
            let prompt = kv_i18n::t(
                &format!("无人值守（含敏感操作）：请输入执行端标签 {label} 确认："),
                &format!("Unattended (including sensitive operations): type executor label {label} to confirm: "),
            );
            let answer = host.confirmation(&prompt, Duration::from_secs(remaining as u64))?;
            if answer.as_deref() != Some(prepared.label.as_str()) {
                return Err(Error::cancelled());
            }
            if host.now() >= prepared.expires_at
                || intent
                    .exp
                    .is_some_and(|expiration| host.now() >= expiration)
            {
                return Err(Error::new(
                    "expired",
                    "二次确认已过期",
                    "Secondary confirmation has expired",
                ));
            }
            intent.confirm = Some(prepared.label);
            intent.confirmation_token = Some(prepared.confirmation_token);
            let first_expiration = prepared.expires_at;
            prepared = call(host, Op::GrantIssue, json!(intent))?;
            if prepared.confirmations_left != 1
                || prepared.expires_at != first_expiration
                || prepared.device_id != peer.device_id
                || Some(&prepared.label) != intent.confirm.as_ref()
                || prepared.confirmation_token.is_empty()
                || prepared.confirmation_token.len() > 256
                || Some(&prepared.confirmation_token) == intent.confirmation_token.as_ref()
            {
                return Err(Error::protocol());
            }
            let remaining = first_expiration.saturating_sub(host.now());
            if remaining <= 0 {
                return Err(Error::new(
                    "expired",
                    "二次确认已过期",
                    "Secondary confirmation has expired",
                ));
            }
            let prompt = kv_i18n::t(
                &format!("无人值守（含敏感操作）：请再次输入执行端标签 {label} 确认（2/2）："),
                &format!("Unattended (including sensitive operations): type executor label {label} again (2/2): "),
            );
            let answer = host.confirmation(&prompt, Duration::from_secs(remaining as u64))?;
            if answer.as_deref() != Some(prepared.label.as_str()) {
                return Err(Error::cancelled());
            }
            if host.now() >= first_expiration {
                return Err(Error::new(
                    "expired",
                    "二次确认已过期",
                    "Secondary confirmation has expired",
                ));
            }
            intent.confirmation_token = Some(prepared.confirmation_token);
            expirations.push(first_expiration);
        }
        intents.push(intent);
    }
    // Confirm every selected executor before signing any wildcard T2 grant.
    if expirations.iter().any(|exp| host.now() >= *exp) {
        return Err(Error::new(
            "expired",
            "二次确认已过期",
            "Secondary confirmation has expired",
        ));
    }
    if intents
        .iter()
        .any(|intent| intent.exp.is_some_and(|exp| host.now() >= exp))
    {
        return Err(Error::new(
            "expired",
            "授权已到期；请重新发起",
            "The grant has expired; start again",
        ));
    }
    let mut grants = Vec::new();
    for intent in intents {
        let result: kv_core::remote::ipc::GrantIssueResult =
            call(host, Op::GrantIssue, json!(intent)).map_err(|mut error| {
                error.completed_devices = grants.iter().map(|g: &Grant| g.aud.clone()).collect();
                error
            })?;
        grants.push(result.grant);
    }
    Ok(Success::GrantsIssued { grants })
}

#[derive(Deserialize)]
struct PairStarted {
    sas: String,
    #[serde(default)]
    uri: Option<String>,
    #[serde(default)]
    expires_at: Option<i64>,
    #[serde(default)]
    binding: Option<kv_core::remote::ipc::RelayBinding>,
    #[serde(default)]
    recovery_code: Option<String>,
    #[serde(default)]
    pair_error: Option<String>,
    #[serde(default)]
    global_grants: u64,
}

fn pair(host: &mut impl Host, uri: Option<&str>, rejoin: bool, json: bool) -> Result<Success> {
    let mut started: PairStarted = if let Some(uri) = uri {
        // The helper parses the token and owns all key generation and Strong confirmation.
        let mut intent = json!({"uri":uri});
        if rejoin {
            intent["rejoin"] = json!(true);
        }
        call(host, Op::PairComplete, intent)?
    } else {
        let config = relay::Config::read(&host.config_path()?)?;
        call(host, Op::PairStart, json!({"relay_url":config.relay_url}))?
    };
    if let Some(code) = started.recovery_code.take() {
        if code.is_empty() || code.len() > 256 || code.chars().any(char::is_control) {
            return Err(Error::protocol());
        }
        host.emit(
            &Success::PairRecovery {
                recovery_code: code,
                account_id: started
                    .binding
                    .as_ref()
                    .map(|binding| binding.account_id.clone()),
            },
            json,
        )?;
    }
    if let Some(binding) = &started.binding {
        let path = host.config_path()?;
        host.set_binding(&path, binding)?;
    }
    if let Some(code) = started.pair_error {
        return Err(Error {
            message: output::error_message(&code),
            code,
            completed_devices: Vec::new(),
        });
    }
    if let Some(uri) = started.uri.as_deref().or(uri) {
        args::pair_uri(uri)?;
        host.emit(
            &Success::Pair {
                uri: Some(uri.to_owned()),
                sas: None,
                paired: false,
            },
            json,
        )?;
    } else {
        return Err(Error::protocol());
    }
    let wait_for_completion = started.binding.is_some();
    confirm_pair(host, started, json, wait_for_completion)
}

fn pair_resume(host: &mut impl Host, json: bool) -> Result<Success> {
    let status: Value = call(host, Op::Status, json!({}))?;
    let pairing = &status["pairing"];
    if let Some(code) = pairing["error"].as_str() {
        return Err(Error {
            code: code.into(),
            message: output::error_message(code),
            completed_devices: Vec::new(),
        });
    }
    if pairing["state"] == "completed" {
        return Ok(Success::Pair {
            uri: None,
            sas: None,
            paired: true,
        });
    }
    let expires = pairing["expires_at"].as_i64().ok_or_else(|| {
        Error::new(
            "pair_not_pending",
            "没有可以继续的配对",
            "There is no pending pairing to resume",
        )
    })?;
    let sas = pairing["sas"]
        .as_str()
        .filter(|sas| sas.len() == 6 && sas.bytes().all(|b| b.is_ascii_digit()))
        .ok_or_else(|| {
            Error::new(
                "pair_not_pending",
                "配对安全码尚未就绪",
                "The pending pairing safety code is not ready",
            )
        })?;
    let started = PairStarted {
        sas: sas.into(),
        expires_at: Some(expires),
        uri: None,
        binding: None,
        recovery_code: None,
        pair_error: None,
        global_grants: pairing["global_grants"].as_u64().unwrap_or(0),
    };
    // This is the same trusted owner confirmation and hardware signing path.
    // Never redeem a consumed token or extend the helper's original expiration.
    confirm_pair(host, started, json, true)
}

fn confirm_pair(
    host: &mut impl Host,
    mut started: PairStarted,
    json: bool,
    wait_for_completion: bool,
) -> Result<Success> {
    let expires = started
        .expires_at
        .unwrap_or_else(|| host.now().saturating_add(600))
        .min(host.now().saturating_add(600));
    while started.sas.is_empty() && host.now() < expires {
        if !host.wait(Duration::from_secs(1)) {
            return Err(Error::cancelled());
        }
        let status: Value = call(host, Op::Status, json!({}))?;
        if let Some(code) = status["pairing"]["error"].as_str() {
            return Err(Error {
                code: code.into(),
                message: output::error_message(code),
                completed_devices: Vec::new(),
            });
        }
        started.sas = status["pairing"]["sas"].as_str().unwrap_or("").into();
        started.global_grants = status["pairing"]["global_grants"].as_u64().unwrap_or(0);
    }
    if host.now() >= expires {
        return Err(Error::new(
            "pair_timeout",
            "配对超时；请重新运行 keyvalet pair --new",
            "Pairing timed out; run keyvalet pair --new again",
        ));
    }
    if started.sas.len() != 6 || !started.sas.bytes().all(|b| b.is_ascii_digit()) {
        return Err(Error::protocol());
    }
    host.emit(
        &Success::Pair {
            uri: None,
            sas: Some(started.sas.clone()),
            paired: false,
        },
        json,
    )?;
    let prompt = kv_i18n::t(
        "请核对两端安全码一致；确认配对？[y/N]：",
        "Check that both safety codes match; confirm pairing? [y/N]: ",
    );
    let answer = host.confirmation(&prompt, Duration::from_secs((expires - host.now()) as u64))?;
    if host.now() >= expires {
        return Err(Error::new(
            "pair_timeout",
            "配对超时；请重新发起配对",
            "Pairing timed out; start a new pairing",
        ));
    }
    if !answer.is_some_and(|s| s.eq_ignore_ascii_case("y")) {
        return Err(Error::cancelled());
    }
    let mut confirmation = json!({"sas":started.sas,"confirmed":true});
    if started.global_grants > 0 {
        host.emit(
            &Success::PairGlobalGrants {
                count: started.global_grants,
            },
            json,
        )?;
        let choice=host.confirmation(&kv_i18n::t("排除此设备的全局授权？输入 e 排除，回车保留：", "Exclude global grants on this device? Enter e to exclude, or press Enter to keep: "),
            Duration::from_secs((expires-host.now()).max(0) as u64))?;
        if host.now() >= expires {
            return Err(Error::new(
                "pair_timeout",
                "配对超时；请重新发起配对",
                "Pairing timed out; start a new pairing",
            ));
        }
        let choice = choice.ok_or_else(Error::cancelled)?;
        if choice.eq_ignore_ascii_case("e") {
            confirmation["exclude_global"] = json!(true);
        } else if !choice.is_empty() {
            return Err(Error::argument("请输入 e 或回车", "Enter e or press Enter"));
        }
    }
    let _: Extra = call(host, Op::PairConfirm, confirmation)?;
    if wait_for_completion {
        loop {
            let status: Value = call(host, Op::Status, json!({}))?;
            if status["pairing"]["state"] == "completed" {
                break;
            }
            if let Some(code) = status["pairing"]["error"].as_str() {
                return Err(Error {
                    code: code.into(),
                    message: output::error_message(code),
                    completed_devices: Vec::new(),
                });
            }
            if host.now() >= expires {
                return Err(Error::new(
                    "pair_timeout",
                    "配对超时；请重新发起配对",
                    "Pairing timed out; start a new pairing",
                ));
            }
            if !host.wait(Duration::from_secs(1)) {
                return Err(Error::cancelled());
            }
        }
    }
    Ok(Success::Pair {
        uri: None,
        sas: Some(started.sas),
        paired: true,
    })
}

fn approvals(host: &mut impl Host, watch: bool, hook: Option<&str>, json: bool) -> Result<Success> {
    let mut observed: HashMap<String, String> = HashMap::new();
    let mut executed = HashSet::new();
    let mut decision_cursor = 0u64;
    let mut previous = None;
    loop {
        let pending: Pending = call(host, Op::PendingList, json!({}))?;
        let current = Success::Approvals(pending.clone());
        if previous.as_ref() != Some(&current) {
            if !watch {
                return Ok(current);
            }
            host.emit(&current, json)?;
            previous = Some(current.clone());
        }
        if let Some(command) = hook {
            for ApprovalHistory {
                approval_id,
                decision,
                extra,
                ..
            } in &pending.recent
            {
                let sequence = extra.get("decision_seq").and_then(Value::as_u64);
                let unseen = sequence.map_or_else(
                    || !executed.contains(approval_id),
                    |seq| seq > decision_cursor,
                );
                if *decision == Decision::Allow && unseen {
                    if let Some(summary) = observed.get(approval_id) {
                        // Only an explicit decision for a request observed in this watch can trigger.
                        host.hook(command, approval_id, summary)?;
                        if sequence.is_none() {
                            executed.insert(approval_id.clone());
                        }
                    }
                }
            }
            decision_cursor = pending
                .recent
                .iter()
                .filter_map(|entry| entry.extra.get("decision_seq").and_then(Value::as_u64))
                .max()
                .unwrap_or(decision_cursor)
                .max(decision_cursor);
        }
        for request in &pending.pending {
            observed.insert(request.approval_id.clone(), request.summary());
        }
        let live: HashSet<_> = pending
            .pending
            .iter()
            .map(|p| &p.approval_id)
            .chain(pending.recent.iter().map(|p| &p.approval_id))
            .collect();
        observed.retain(|id, _| live.contains(id));
        // Keep completed IDs for this watch session even after history rotates out.
        // Reappearing history must never execute the owner's command twice.
        if !host.wait(Duration::from_secs(1)) {
            return Ok(current);
        }
    }
}

fn execute(host: &mut impl Host, invocation: &Invocation) -> Result<Success> {
    match &invocation.command {
        Command::Help(topic) => Ok(Success::Help {
            text: args::help(topic),
        }),
        Command::Audit {
            target,
            since,
            limit,
        } => {
            let since = since
                .as_deref()
                .map(|value| args::since(value, host.now()))
                .transpose()?
                .unwrap_or(0);
            audit::run(host, target.as_deref(), since, *limit)
        }
        Command::RelayInstall {
            listen,
            data,
            public_url,
            root,
        } => {
            let root = root
                .clone()
                .map(Ok)
                .unwrap_or_else(|| host.install_root())?;
            let result = host.install(&root, listen, data, public_url)?;
            let path = host.config_path()?;
            host.set_url(&path, public_url)?;
            Ok(Success::RelayInstall(result))
        }
        Command::RelayStatus { url } => {
            let base = url.clone().map(Ok).unwrap_or_else(|| {
                relay::Config::read(&host.config_path()?).map(|c| c.relay_url)
            })?;
            Ok(Success::RelayStatus(host.health(&base)?))
        }
        Command::RelaySetUrl { url } => {
            let path = host.config_path()?;
            host.set_url(&path, url)?;
            Ok(Success::RelaySetUrl {
                relay_url: url.clone(),
                config: path,
            })
        }
        Command::RelayRecover {
            account_id,
            url,
            software,
        } => {
            let base = url.clone().map(Ok).unwrap_or_else(|| {
                relay::Config::read(&host.config_path()?).map(|config| config.relay_url)
            })?;
            let code = zeroize::Zeroizing::new(
                host.secret(&kv_i18n::t("账户恢复码：", "Account recovery code: "))?
                    .ok_or_else(|| {
                        Error::new(
                            "user_cancelled",
                            "账户恢复已取消",
                            "Account recovery cancelled",
                        )
                    })?,
            );
            if kv_core::remote::keys::decode_b64(&code).map_or(true, |bytes| bytes.len() != 32) {
                return Err(Error::argument(
                    "恢复码必须是 32 字节的 base64url 字符串",
                    "The recovery code must be a 32-byte base64url value",
                ));
            }
            let intent = kv_ipc::remote::AccountRecoverIntent {
                account_id: account_id.clone(),
                recovery_code: code.to_string(),
                relay_url: base.clone(),
                software: *software,
            };
            let recovered: kv_ipc::remote::AccountRecoverResult =
                call(host, Op::AccountRecover, json!(intent))?;
            if recovered.binding.account_id != *account_id
                || recovered.binding.device_id.is_empty()
                || recovered.binding.relay_url != base
                || kv_core::remote::keys::decode_b64(&recovered.recovery_code)
                    .map_or(true, |bytes| bytes.len() != 32)
            {
                return Err(Error::protocol());
            }
            let path = host.config_path()?;
            host.set_binding(&path, &recovered.binding)?;
            Ok(Success::RelayRecovered(recovered))
        }
        Command::Pair { uri, rejoin } => pair(host, uri.as_deref(), *rejoin, invocation.json),
        Command::PairResume => pair_resume(host, invocation.json),
        Command::DevicesList => Ok(Success::Devices(devices(host)?)),
        Command::DevicesRevoke { id } => {
            let _: Extra = call(host, Op::DevicesRevoke, json!({"device_id":id}))?;
            Ok(Success::DeviceRevoked {
                device_id: id.clone(),
            })
        }
        Command::DevicesRename { id, label } => {
            let _: Extra = call(
                host,
                Op::DevicesRename,
                json!({"device_id":id,"label":label}),
            )?;
            Ok(Success::DeviceRenamed {
                device_id: id.clone(),
                label: label.clone(),
            })
        }
        Command::Approvals { watch, on_approve } => {
            approvals(host, *watch, on_approve.as_deref(), invocation.json)
        }
        Command::Decide {
            id,
            decision,
            scope,
            reason,
        } => {
            let mut params = json!({"approval_id":id,"decision":decision,
                "scope":args::scope(scope, host.now())?,"scope_option":scope});
            if let Some(reason) = reason {
                params["reason"] = json!(reason);
            }
            let sent: output::Sent = call(host, Op::Decide, params)?;
            if !sent.sent {
                return Err(Error::protocol());
            }
            Ok(Success::Decision {
                approval_id: id.clone(),
                decision: *decision,
                sent: true,
            })
        }
        Command::Grant {
            target,
            options,
            unattended,
            preauthorization,
        } => issue_grant(host, target, options, *unattended, *preauthorization),
        Command::GrantList => {
            let mut result: kv_ipc::remote::GrantListResult<output::ListedGrant> =
                call(host, Op::GrantList, json!({}))?;
            let mut seen = std::collections::HashSet::new();
            while let Some(cursor) = result
                .extra
                .get("next_cursor")
                .and_then(Value::as_str)
                .map(str::to_owned)
            {
                if !seen.insert(cursor.clone()) {
                    return Err(Error::protocol());
                }
                let page: kv_ipc::remote::GrantListResult<output::ListedGrant> =
                    call(host, Op::GrantList, json!({"after":cursor}))?;
                result.grants.extend(page.grants);
                result.extra = page.extra;
            }
            Ok(Success::Grants(result))
        }
        Command::GrantRevoke { jti } => {
            let _: Extra = call(host, Op::GrantRevoke, json!({"jti":jti}))?;
            Ok(Success::GrantRevoked { jti: jti.clone() })
        }
        Command::Directive { target, op, args } => {
            let mut args = args.clone();
            if *op == DirectiveOp::QueryAudit {
                let since = args
                    .remove("since_text")
                    .and_then(|v| v.as_str().map(str::to_owned))
                    .ok_or_else(Error::protocol)?;
                args.insert("since".into(), json!(args::since(&since, host.now())?));
            }
            issue_directive(host, target, *op, args)
        }
        Command::Status { summary } => {
            let protection = host.protection()?;
            let status: output::RemoteStatus = match call(host, Op::Status, json!({})) {
                Ok(status) => status,
                Err(error) if error.exit_code() == 5 || (*summary && error.code == "forbidden") => {
                    return Ok(Success::Status {
                        protection,
                        remote: None,
                        remote_error: Some(error),
                        paired_devices_n: None,
                    })
                }
                Err(error) => return Err(error),
            };
            let directory = devices(host)?;
            let paired_devices_n = directory
                .devices
                .iter()
                .filter(|d| d.extra.get("revoked") != Some(&Value::Bool(true)))
                .count();
            Ok(Success::Status {
                protection,
                remote: Some(status),
                remote_error: None,
                paired_devices_n: Some(paired_devices_n),
            })
        }
    }
}

pub(super) fn handles(argv: &[String]) -> bool {
    match argv
        .iter()
        .find(|a| a.as_str() != "--json")
        .map(String::as_str)
    {
        Some(
            "relay" | "pair" | "devices" | "approvals" | "deny" | "grant" | "remote" | "status"
            | "protection",
        ) => true,
        Some("approve") => !args::linux_pid_approval(argv),
        Some("audit") => argv.iter().any(|arg| arg == "--remote"),
        _ => false,
    }
}

pub(super) fn usage() -> String {
    kv_i18n::t(
        "\n远程审批：\n  relay install|status|set-url|recover 部署或指向 relay\n  pair --new | pair <kv-pair://...> 配对设备\n  devices list|revoke|rename        管理设备目录\n  approvals [--watch]               查看待处理审批\n  approve <id> | deny <id>          发送审批决定\n  grant ...|list|revoke|revoke-all  管理授权\n  remote <device|label|*> ...      远程设置；完整选项见 remote --help\n  audit --remote [--since 24h]      核对跨端审计，发现差异时退出码 3\n  所有远程命令支持 --json。",
        "\nRemote approval:\n  relay install|status|set-url|recover Deploy or select a relay\n  pair --new | pair <kv-pair://...> Pair devices\n  devices list|revoke|rename        Manage the device directory\n  approvals [--watch]               View pending approvals\n  approve <id> | deny <id>          Send an approval decision\n  grant ...|list|revoke|revoke-all  Manage grants\n  remote <device|label|*> ...      Remote settings; see remote --help\n  audit --remote [--since 24h]      Check audits across devices; findings exit with code 3\n  All remote commands support --json.",
    )
}

pub(super) fn run_system(argv: &[String]) -> i32 {
    system::run_system(argv)
}

fn run(host: &mut impl Host, argv: &[String]) -> Result<()> {
    let invocation = Invocation::parse(argv)?;
    host.configure(matches!(
        invocation.command,
        Command::Status { summary: true }
    ));
    if !matches!(invocation.command, Command::Help(_)) {
        host.verify()?;
    }
    let value = execute(host, &invocation)?;
    // Watch emits each update, including its final state, once.
    if !matches!(invocation.command, Command::Approvals { watch: true, .. }) {
        host.emit(&value, invocation.json)?;
    }
    if matches!(&value, Success::Audit(report) if !report.consistent) {
        return Err(Error::new(
            "audit_findings",
            "远程审计发现差异或查询不完整",
            "Remote audit found differences or incomplete snapshots",
        ));
    }
    Ok(())
}
